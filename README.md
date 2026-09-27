# irondirectory

A **FIPS-compliant, Active Directory–compatible identity provider** written in
Rust, built on top of [`fastetcd`](https://github.com/glennswest/fastetcd) (a
Rust implementation of the etcd v3 wire protocol with multi-node Raft).

irondirectory is the **directory + KDC + DNS** half of an AD-compatible domain
controller. Its sister project [`rocketsmbd`](https://github.com/glennswest/rocketsmbd)
provides the **SMB file-server** half (SYSVOL/NETLOGON shares, Kerberos service
acceptor). Together they form a clean-room, FIPS-clean alternative to a Windows
or Samba domain controller.

> **Status:** `v0.23.0` — Phases 0, 1 and 1.5 done, Phase 2 underway
> (Phase 2: `iron-partition`'s `sid`/`security_descriptor` modules, a real
> etcd-CAS RID pool, `iron-ldap` auto-stamping `objectSid` +
> a default `nTSecurityDescriptor` onto new `user`/`computer`/`group`
> entries, `iron-kdc` embedding a signed **Kerberos PAC** with
> group SIDs in every ticket, a new **`iron-rpc`** crate serving
> **SAMR/LSARPC/NETLOGON** — the Windows-join handshake itself,
> verified against real impacket-based clients including a
> cryptographically genuine NETLOGON secure channel, and a new
> **`iron-simulate`** crate driving concurrent, fully realistic
> join+login sequences for scale testing — Windows-join
> prerequisites, D6 Tier 2; RFC 3062 Password Modify and GSSAPI
> confidentiality for macOS `dsconfigad` bind — the kpasswd service on
> port 464 is not implemented yet, see #20). Phase 1.5's
> OpenShift LDAP identity provider and SPNEGO desktop→console SSO also
> ship, docs-only — see `docs/OPENSHIFT-LDAP-IDP.md` and
> `docs/OPENSHIFT-SPNEGO-SSO.md`). `iron-partition`
> (naming-context model), `iron-store` (partition-scoped DIT over fastetcd,
> mTLS connection harness), `iron-crypto` (FIPS crypto facade over `ossl`,
> incl. PBKDF2 password hashing, Kerberos AES key derivation/encryption, and
> **ES256 asymmetric signing**), `iron-ldap` (rootDSE, anonymous + authenticated
> bind, **SASL/GSSAPI bind**, search (present/equality/and/or/not
> filters; substring/ordering filters match nothing yet, #27), add/delete/modify/compare/modify-DN,
> StartTLS/LDAPS, **RFC 4532 WhoAmI**, **registry-driven cross-NC referrals
> chased one hop end-to-end**, AD/RFC 2307 schema validation), `iron-kdc`
> (Kerberos 5 KDC: AS-REQ/AS-REP with pre-auth,
> TGS-REQ/TGS-REP, keytab I/O + export, **cross-realm `krbtgt` keys +
> one-hop referral tickets chased end-to-end**), `iron-dns` (LDAP/Kerberos
> SRV record publishing via MicroDNS), `iron-config` (**child-domain
> provisioning**: persists the PartitionRegistry in the forest configuration
> partition, real LDAP + Kerberos referrals wired to it), `iron-gc`
> (**watch-fed Global Catalog / federated GAL aggregator**, ports 3268/3269:
> a live, continuously-updated partial replica across every domain partition
> in one forest, or across **several independent forests** behind a
> stricter cross-boundary attribute whitelist), and `iron-oidc` (**FIPS
> OAuth2/OpenID Connect authorization server**: discovery, JWKS,
> authorization code grant, ID tokens/userinfo, authenticating against the
> same LDAP directory) are real and
> verified against a live fastetcd cluster with real `openldap-clients`,
> `krb5-workstation`, `dig`, a full **SSSD** stack (`id_provider=ldap` +
> `auth_provider=krb5`, real `getent`/`id`/`su` end to end), a real `sshd`
> doing **GSSAPI SSO**, and real cross-project **`sec=krb5` SMB interop**
> against `rocketsmbd` — `iron-ldap` deployed redundantly (3 replicas +
> health-checked LB) at `ldap.g8.lo`. Architecture and decisions are
> recorded in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Documentation

- [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md): every binary's settings and
  defaults, ports, and how it ships (RPMs, systemd units)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): decision record (D1–D10)
- [`docs/FIPS.md`](docs/FIPS.md): OpenSSL FIPS provider setup and findings
- [`docs/OPENSHIFT-LDAP-IDP.md`](docs/OPENSHIFT-LDAP-IDP.md),
  [`docs/OPENSHIFT-OIDC-IDP.md`](docs/OPENSHIFT-OIDC-IDP.md),
  [`docs/OPENSHIFT-SPNEGO-SSO.md`](docs/OPENSHIFT-SPNEGO-SSO.md): OpenShift SSO

## What it is (and isn't)

This is **not** a 100% Active Directory clone (Samba spent ~20 years on that and
still isn't complete). It is an **AD-compatible identity provider** — the role
FreeIPA plays — done in Rust on your own consensus store, with FIPS as a
first-class design constraint rather than a bolt-on.

| Component | Protocol | Tier |
|---|---|---|
| Directory | LDAP v3 + AD-shaped schema | 1 |
| Authentication | Kerberos V KDC (AS/TGS), AES enctypes only | 1 |
| Service location | DNS SRV autodiscovery (`_ldap`, `_kerberos`) | 1 |
| Transport security | LDAPS / StartTLS (OpenSSL FIPS provider) | 1 |
| Windows join | rootDSE, MS schema, SID/RID, security descriptors, PAC | 2 |
| Remote mgmt | DCE/RPC: SAMR, LSARPC, NETLOGON | 2 |
| Replication | DRSUAPI multi-master with real Windows DCs | 3 (deferred) |
| Policy | Group Policy + SYSVOL (via rocketsmbd) | 3 (deferred) |

## Key design decisions

- **Backend:** a **dedicated** fastetcd cluster (never shared with a Kubernetes
  control-plane etcd — the directory holds `krbtgt`, password, and machine
  secrets).
- **Consistency:** embrace fastetcd's single-leader **Raft strong consistency**
  — stronger and simpler than AD's multi-master model. A deliberate divergence.
- **FIPS module:** **OpenSSL 3.x FIPS provider**, accessed via the **`ossl`
  crate** (idiomatic OpenSSL 3 bindings with explicit provider/FIPS handling),
  matching `rocketsmbd` so the whole identity stack validates against one
  crypto boundary.
- **Deployment:** today, **standalone**: per-daemon RPMs + systemd units
  on Fedora/RHEL VMs, talking to a dedicated fastetcd cluster in
  **plaintext** (the daemons have no fastetcd mTLS settings yet, #26).
  Kubernetes is planned as a stormcos golden run by irondirectory-operator
  (#25); nothing in this repo deploys to Kubernetes yet. Ports, settings and
  packaging: [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).
- **Partitioned from day one:** never a monolithic tree. The directory is many
  strongly-consistent partitions (one Raft cluster per naming context), federated
  by Kerberos trust + LDAP referrals + watch-fed aggregation. Scales from one
  domain to a multi-forest holding company (hundreds of autonomous forests
  sharing a federated GAL + OIDC brokering; forest = security boundary).
  The federated GAL is built (#13); cross-forest OIDC brokering is not yet.
- **No NTLM.** MD5/RC4 are non-FIPS and absent; Kerberos + SASL/GSSAPI only.
  One cited exception: `iron_crypto::md4` (pure Rust, outside the FIPS
  context) computes the NTOWF that MS-NRPC's NETLOGON secure channel
  requires; everything downstream of it is FIPS AES/HMAC-SHA256.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full rationale.

## License

Apache-2.0
