# irondirectory — Architecture & Decision Record

This document captures the foundational decisions for irondirectory. It is the
source of truth for *why* the project is shaped the way it is. Update it
whenever a decision changes.

## 1. Goal

A **FIPS-compliant, Active Directory–compatible identity provider** in Rust,
built on [`fastetcd`](https://github.com/glennswest/fastetcd). It plays the role
FreeIPA plays — an identity provider — rather than attempting a 100% byte-exact
Active Directory clone.

It is the **directory + KDC + DNS** half of an AD-compatible domain controller.
[`rocketsmbd`](https://github.com/glennswest/rocketsmbd) is the **SMB** half.

## 2. The two-project stack

```
        ┌──────────────────────────────┐      ┌──────────────────────────────┐
        │  irondirectory (this repo)   │      │  rocketsmbd (sister project) │
        │                              │      │                              │
        │  • LDAP v3 directory         │      │  • SMB2/3 file server        │
        │  • Kerberos KDC (issuer)     │◄────►│  • SYSVOL / NETLOGON shares  │
        │  • DNS SRV autodiscovery     │ krb5 │  • Kerberos AP-REQ acceptor  │
        │  • LDAPS (OpenSSL FIPS)      │tickets│   (roadmap #31–#37)          │
        └──────────────┬───────────────┘      └──────────────────────────────┘
                       │ etcd v3 gRPC (mTLS)
                       ▼
        ┌──────────────────────────────┐
        │  fastetcd — DEDICATED cluster │  (never the Kubernetes etcd)
        │  Raft · MVCC · Watch · Lease  │
        └──────────────────────────────┘
```

rocketsmbd's 0.7 roadmap adds a Kerberos acceptor (AP-REQ + keytab via an
external GSS library) precisely because "NTLM-only is not viable long term."
That acceptor needs a KDC to issue tickets — **irondirectory is that KDC.**

## 3. Decisions

### D1 — Backend: a dedicated fastetcd cluster
- The directory stores the `krbtgt` key, user password material (KDF output),
  and machine account secrets. This blast radius MUST be isolated from any
  Kubernetes control-plane etcd.
- A dedicated cluster gives independent mTLS/CA, encryption-at-rest, audit, and
  a backup/restore lifecycle decoupled from Kubernetes.
- **No change to fastetcd's key model is required** (see D2).

### D2 — DIT mapping: layer hierarchy above the flat keyspace
- etcd v3 is a flat keyspace but supports **prefix range scans**. The LDAP DIT
  maps to hierarchical key paths and subtree search becomes a prefix scan:
  - Object: `/iron/tree/dc=lo/dc=g10/ou=users/cn=alice` → serialized entry.
  - Subtree search under an OU: range scan over the OU's key prefix.
- **Secondary indexes** are companion keys maintained atomically with the object
  write inside a single etcd `Txn` (compare-and-set on revision):
  - `/iron/idx/<attr>/<value>/<dn>` → presence/equality lookups.
  - Substring/approx indexes layered as needed.
- **USN equivalent:** etcd MVCC `mod_revision` is the natural change sequence
  number for syncrepl/persistent-search.
- **Change notification:** etcd **Watch** drives LDAP persistent search /
  content-sync (RFC 4533) and DNS dynamic-update fan-out.
- **Leases:** etcd leases back session/ticket lifetime where appropriate.
- Because we use the `/iron/...` prefix and Kubernetes uses `/registry/...`,
  there is no key collision even on a shared cluster — but D1 mandates a
  separate cluster anyway.

### D3 — Consistency: embrace Raft strong consistency
- fastetcd is single-leader, quorum-committed (Raft). We adopt this directly.
- This is **stronger and simpler** than AD's multi-master, USN-reconciled,
  eventually-consistent replication. We do NOT reimplement DRS multi-master.
- Documented, deliberate divergence from AD. Multi-site = Raft quorum within a
  failure domain; cross-WAN topologies are a future concern, not a v1 goal.

### D4 — FIPS: OpenSSL 3.x FIPS provider via the `ossl` crate
- Standardize on the **OpenSSL 3.x FIPS provider**, matching `rocketsmbd`
  (its ROADMAP #29/#30). One validated crypto boundary across the whole
  identity stack is what a FIPS audit wants.
- Bind via the **`ossl` crate** — idiomatic OpenSSL 3 bindings with explicit
  provider/FIPS-mode handling — rather than the raw `openssl` FFI crate or
  aws-lc-rs. (aws-lc-rs is also FIPS 140-3 validated and remains the fallback
  if the C dependency ever needs to be shed.)
- **LDAPS / StartTLS:** TLS via OpenSSL (FIPS provider), not rustls+ring.
- **Kerberos enctypes:** AES only. Prefer RFC 8009
  (`aes256-cts-hmac-sha384-192`); `aes256-cts-hmac-sha1-96` acceptable
  (HMAC-SHA1 is FIPS-approved as an HMAC). **RC4-HMAC and DES disabled.**
- **No NTLM.** MD4/MD5/RC4 are non-FIPS and simply absent. Kerberos +
  SASL/GSSAPI only. (Mirrors rocketsmbd #30 making MD4/RC4 build-optional.)
- **Directory password storage:** FIPS-approved KDF (PBKDF2 via OpenSSL).

### D5 — Deployment: standalone or Kubernetes
- **Standalone:** irondirectory + a co-located/embedded dedicated fastetcd as a
  domain-controller appliance.
- **Kubernetes:** fastetcd as its own StatefulSet (it ships a Helm chart) +
  irondirectory as a Deployment, communicating over mTLS. Same binary; only the
  etcd connection string and topology differ.

### D7 — SSO surfaces
irondirectory is a self-contained IdP (no Keycloak dependency). It exposes
several SSO surfaces so different consumers integrate the way they prefer:

| Consumer | Mechanism | Tier | Notes |
|---|---|---|---|
| RHEL / Linux hosts | Kerberos TGT → GSSAPI/SPNEGO | 1 | Native; SSH/HTTP/NFS/SMB SSO |
| OpenShift (now) | LDAP identity provider | 1 | Direct bind; form login, no cross-app SSO |
| OpenShift (SSO) | **Native OIDC** (`iron-oidc`) | 1.5 | Token SSO; serves modern apps too |
| OpenShift (console) | RequestHeader + SPNEGO proxy | 1.5 | Kerberos desktop→console SSO (mod_auth_gssapi) |
| Windows | Domain join (Kerberos+PAC+DCE-RPC) | 2 | Full AD-join; see D6 |
| macOS | LDAP/krb5 bind **or** AD bind | 1 / 2 | Light path (Tier 1) or `dsconfigad` (Tier 2) |

- **Native OIDC** is a new crate (`iron-oidc`): a FIPS OAuth2/OpenID Connect
  authorization server. Self-contained — no external Keycloak runtime.
- **LDAP IdP** requires no new code beyond Tier 1; it is the day-one path.
- **SPNEGO** reuses the Tier 1 KDC; integration is an external authenticating
  proxy (RequestHeader IdP), documented rather than built here.
- Posix attributes (RFC 2307: `uidNumber`/`gidNumber`) or SID→uid mapping are
  required in the schema for RHEL/Mac login — part of the `iron-ldap` work.

### D6 — Client targets, phased
- **Tier 1 (Linux/Unix + Mac light path):** SSSD, MIT/Heimdal krb5, LDAP
  clients authenticate directly; RHEL and macOS get Kerberos SSO via LDAP+krb5
  bind. Complete, FIPS-clean IdP on its own (~20% of total work).
- **Tier 1.5 (app SSO):** `iron-oidc` OAuth2/OIDC server + LDAP IdP + SPNEGO
  proxy support — covers OpenShift and modern apps (see D7).
- **Tier 2 (Windows/Mac domain join):** rootDSE + real MS schema objects,
  SID/RID allocation, `nTSecurityDescriptor` ACLs, Kerberos **PAC** generation,
  SAMR/LSARPC/NETLOGON over DCE-RPC, SYSVOL via rocketsmbd. Enables Windows
  `Add-Computer` join and macOS `dsconfigad`. The hard ~80%.
- **Tier 3 (deferred/skip):** DRSUAPI replication with real Windows DCs, full
  Group Policy engine, multi-domain trusts/forests.

## 4. Known constraints / risks

- **etcd scale:** fastetcd/etcd targets small datasets (recommended DB size on
  the order of single-digit GB, full key index in RAM, ~1.5 MB request cap).
  Excellent for homelab / SMB / edge directories (thousands to low-millions of
  objects); not for an enterprise forest with tens of millions of objects.
- **The Tier 1 → Tier 2 cliff:** Linux-only is clean and small. Windows domain
  join pulls in DCE-RPC, PAC, NT security descriptors, and SMB/SYSVOL — the
  bulk of the effort.
- **fastetcd FIPS alignment:** fastetcd's own TLS currently uses the
  tonic/rustls default stack. For an end-to-end FIPS posture, fastetcd's
  transport crypto would also need to route through the OpenSSL FIPS provider.
  Track as a cross-project item against fastetcd, not here.

## 5. Open questions

- Embedded vs. external fastetcd for the standalone appliance form factor.
- Schema source: hand-curated AD-subset schema vs. importing the published MS
  schema definitions.
- SASL mechanism set for LDAP (GSSAPI mandatory; EXTERNAL for mTLS-bound certs?).
