# irondirectory

A **FIPS-compliant, Active Directory–compatible identity provider** written in
Rust, built on top of [`fastetcd`](https://github.com/glennswest/fastetcd) (a
Rust implementation of the etcd v3 wire protocol with multi-node Raft).

irondirectory is the **directory + KDC + DNS** half of an AD-compatible domain
controller. Its sister project [`rocketsmbd`](https://github.com/glennswest/rocketsmbd)
provides the **SMB file-server** half (SYSVOL/NETLOGON shares, Kerberos service
acceptor). Together they form a clean-room, FIPS-clean alternative to a Windows
or Samba domain controller.

> **Status:** `v0.18.0` — Phase 0 done, Phase 1 underway (Phase 1.5's
> OpenShift LDAP identity provider and SPNEGO desktop→console SSO also
> ship, docs-only — see `docs/OPENSHIFT-LDAP-IDP.md` and
> `docs/OPENSHIFT-SPNEGO-SSO.md`). `iron-partition`
> (naming-context model), `iron-store` (partition-scoped DIT over fastetcd,
> mTLS connection harness), `iron-crypto` (FIPS crypto facade over `ossl`,
> incl. PBKDF2 password hashing, Kerberos AES key derivation/encryption, and
> **ES256 asymmetric signing**), `iron-ldap` (rootDSE, anonymous + authenticated
> bind, **SASL/GSSAPI bind**, search, add/delete/modify/compare/modify-DN,
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
- **Deployment:** runs **standalone** (DC appliance) or **in Kubernetes**
  (fastetcd StatefulSet + irondirectory Deployment over mTLS).
- **Partitioned from day one:** never a monolithic tree. The directory is many
  strongly-consistent partitions (one Raft cluster per naming context), federated
  by Kerberos trust + LDAP referrals + watch-fed aggregation. Scales from one
  domain to a multi-forest holding company (hundreds of autonomous forests
  sharing a federated GAL + OIDC brokering; forest = security boundary).
- **No NTLM.** MD4/MD5/RC4 are non-FIPS; Kerberos + SASL/GSSAPI only.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full rationale.

## License

Apache-2.0
