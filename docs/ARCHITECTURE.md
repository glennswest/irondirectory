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
- **This does not imply a monolith.** D8/D9 extend it: the directory is many
  strongly-consistent partitions (one Raft cluster each), *federated* by trust +
  referrals + watch-fed aggregation — never one big tree, never multi-master.

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
- **Validated on target 2026-07-06** (roadmap #1): the `ossl` crate's own
  `fips` cargo feature is NOT what provides FIPS compliance here — it
  requires OpenSSL >= 4.0 and vendor-builds a non-CMVP-validated test
  module. The real path is `ossl` with `default-features = false, features
  = ["ossl-sys", "dynamic"]` (dynamically link system `libcrypto`), which
  picks up the OS's already-validated FIPS provider (Fedora/RHEL ship
  `/usr/lib64/ossl-modules/fips.so`, an active CMVP-certified build) via
  standard OpenSSL provider config — no kernel `fips=1` boot flag needed.
  Implemented as `crates/crypto` (`iron-crypto`); full writeup in
  `docs/FIPS.md`, including a memory-safety bug found in `ossl` 1.5.2's
  config-loading API and how this crate avoids it.

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
| iPadOS / iOS | MDM enrollment + Kerberos SSO extension, or OIDC | 1.5 | **No domain join** -- Apple removed AD-binding APIs from iOS entirely, there is no `dsconfigad` equivalent. An iPad's path in is an MDM profile configuring Apple's Kerberos SSO extension (Safari/per-app SSO against `iron-kdc`) or a native app/web login via `iron-oidc` -- reuses Tier 1/1.5 surfaces already built, not new server-side work, but the MDM-profile-authoring side is unbuilt. Flagged important; not yet scheduled as an issue. |

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

### D8 — Partitioning: multi-domain within a forest (FOUNDATIONAL, day one)
The directory is **never** a single monolithic tree. It is a set of partitions
(naming contexts), each its own strongly-consistent Raft cluster, federated by
trust + referrals + watch-fed aggregation. This must be load-bearing from the
first commit — retrofitting it later means rewriting the DN model, storage keys,
LDAP referral layer, rootDSE, and KDC realm model simultaneously.

**Mapping (mirrors AD's naming contexts):**

| AD partition | irondirectory | Replication scope | Consistency |
|---|---|---|---|
| Domain NC | one dedicated fastetcd Raft cluster | that domain's DCs only | Strong |
| Schema NC + Configuration NC | a forest-wide fastetcd cluster | whole forest | Strong (rare writes) |
| Global Catalog (port 3268/3269) | watch-fed read-only partial aggregate of every domain NC | forest | Eventual (staleness OK) |

**Federation primitives (the reusable building blocks):**
- **Kerberos cross-realm trust** — each domain partition is a Kerberos realm with
  its own `krbtgt`; parent/child trust = inter-realm keys
  (`krbtgt/CHILD@PARENT`), transitive referral tickets walk the trust path.
- **LDAP referrals** — superior (to parent) + subordinate (to children) knowledge
  references; cross-partition ops return a referral or are chased/chained
  (RFC 4511).
- **Watch-fed aggregator** — subscribes to each partition's etcd watch stream and
  maintains a read-only partial replica. Same code path serves the Global
  Catalog (D8) and the cross-forest GAL (D9).

**Data-model contract that MUST exist on day one (even with one partition):**
- `NamingContext` / `Partition` as a core type; a **PartitionRegistry** (the
  crossRef-equivalent, stored in the forest config partition) listing each NC,
  its base DN, its fastetcd cluster endpoints + mTLS creds, its Kerberos realm,
  and its parent/subordinate references.
- Storage keys are **partition-scoped**: `/iron/<partition-id>/tree/<rdn-path>`
  and `/iron/<partition-id>/idx/...`. No global single-suffix assumption.
  Different partitions resolve to different clusters via the registry.
- A **connection registry** maps partition-id → etcd endpoints, so the store
  layer is multi-cluster from the start.
- `iron-ldap` rootDSE publishes `namingContexts`, `defaultNamingContext`,
  `configurationNamingContext`, `schemaNamingContext`, `rootDomainNamingContext`
  from the first release; cross-NC operations emit referrals.
- `iron-kdc` is realm-per-partition with cross-realm key slots from the start.
- Schema is itself a partition (the schema NC), not hardcoded.

**Federation is in the base, not deferred.** The machinery — child-domain
provisioning, cross-realm trust key setup, LDAP referral chasing, and the
watch-fed GC/GAL aggregator — is built as first-class in the base so the code
paths are exercised from day one and cannot rot. What *is* deferred is the
**exhaustive test matrix** (see D10): proving breadth across many topologies,
trust-transitivity edge cases, GAL convergence, and real-AD interop. Build the
capability now with happy-path coverage; expand the proving suites later.

### D9 — Multi-forest federation: the holding-company topology
Real enterprises (e.g. an aerospace holding company with hundreds of
subsidiaries) run **many autonomous forests**, one per sub-organization, sharing
only a top-level identity/email namespace — NOT one giant forest.

**Why separate forests, deliberately:**
- The **forest is the security boundary** (not the domain). ITAR / export
  control / classified programs / contractual separation between subsidiaries
  require hard isolation: separate schema, separate enterprise admins, separate
  blast radius.
- M&A: acquired companies arrive with their own AD; you federate, never merge
  hundreds of forests.
- Divestiture: a subsidiary may be sold; clean separation is mandatory.

**Architecture — recurse D8's primitives one level up:**
- Each sub-organization is an autonomous forest (its own D8 structure: domains,
  schema/config, GC), on its own isolated fastetcd cluster(s). Reinforces D1.
- **Federated GAL** — the D8 watch-fed aggregator, scaled to forests: each forest
  publishes only **whitelisted attributes** (email, display name, …) to a
  top-level, read-only address book backing the shared `@holdco.com` GAL and
  cross-company people search. Shares *only* those attributes — **no
  directory-content leakage across the ITAR boundary.** This is a federated GAL,
  not a merged directory.
- **`iron-oidc` brokering as the cross-company SSO fabric** (ties to D7) —
  hundreds of forests cannot be full-mesh Kerberos trusts (N² trust links).
  Instead each forest is an OIDC IdP and a central broker federates them (the
  Entra pattern). Native Kerberos cross-forest trust is used **selectively**,
  hub-routed, only where Windows-native cross-org auth is actually required.
- The holding tier is a thin, centrally-operated service (federated GAL + OIDC
  broker) — often the *only* shared infrastructure across subsidiaries.

**Bonus — trust to a real AD:** the same Kerberos cross-realm / forest-trust
mechanism enables a one- or two-way trust with an existing Windows forest
(`CORP.EXAMPLE.COM`) — both a coexistence story and an incremental migration
path off Windows AD.

### D10 — Federation in the base; exhaustive testing deferred
Build the federation capability into the base build (D8/D9 machinery), with
**happy-path test coverage** from the start. Defer only the breadth-proving
suites — they validate coverage, they do not shape the architecture, and
standing them up early would gate the base on test infrastructure.

| Built in the base (with happy-path tests) | Deferred test suites |
|---|---|
| `iron-partition` registry + multi-cluster store | many-partition / many-cluster scale matrices |
| LDAP referral generation + chasing (one hop) | deep subordinate/superior referral chains |
| Cross-realm `krbtgt` keys + one-hop referral ticket | transitive multi-realm trust paths, shortcut trusts |
| Watch-fed GC/GAL aggregator (single subscriber) | hundreds-of-forests GAL convergence + staleness bounds |
| Child-domain provisioning (create partition+realm) | divestiture/teardown, re-parenting, conflict cases |
| `iron-oidc` brokering hook | cross-forest brokering at fan-out; selective-auth policy |
| (n/a) | **real Windows AD interop** (trust, GC, Kerberos PAC) |

Each base feature ships with at least one end-to-end happy-path test so the code
path is live and regression-guarded; the deferred column is tracked as a
dedicated testing phase, not as missing capability.

## 4. Known constraints / risks

- **Scale — what is NOT a limit (Go-etcd folklore that does not apply):**
  - *GC pauses / compaction jitter* — fastetcd is Rust, no GC. Upstream etcd's
    worst large-keyspace pain (stop-the-world pauses) is designed out.
  - *~8 GB DB ceiling* — an upstream operational guideline tied to bbolt mmap +
    defrag + GC, not a protocol limit. With the redb engine (on-disk B-tree),
    the dataset pages from disk and is not RAM-bound.
  - *~1.5 MB request cap* — a tunable etcd default; directory entries are
    KB-scale, so it is irrelevant here regardless.
- **Storage engine choice drives the memory profile:**
  - `redb` (default): on-disk B-tree; dataset > RAM is fine — use for a sizable
    directory.
  - `wal` / `iouring`: hold the full dataset in an in-memory `BTreeMap`
    (persisted via WAL; `iouring` drives the WAL through io_uring). RAM-bound by
    design — the latency tier for smaller/hot directories.
- **Scale — what IS fundamental (true of any single-Raft-group store):**
  - Writes serialize through one leader/log. Rust + io_uring + no-GC raise the
    ceiling well above Go etcd, but a ceiling exists; shard into multiple Raft
    groups only if ever reached.
  - Raft snapshot transfer/restore time grows with DB size — a recovery-window
    concern (far-behind follower), mitigated by streamed/chunked snapshots +
    NVMe, not a steady-state throughput issue.
- **Directory-layer concerns (ours, not etcd's):**
  - Write amplification from secondary indexes — each object write also writes
    its index keys in the same txn; bound the index set deliberately.
  - Very large multi-valued attributes (e.g. a 100k-member group) — chunk via
    AD-style linked-value/range retrieval rather than one oversized value.
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
