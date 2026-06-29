# CLAUDE.md — irondirectory

Project-specific context. Cross-project rules live in the parent `CLAUDE.md`.

## What this is

A FIPS-compliant, Active Directory–compatible identity provider in Rust, built
on `fastetcd`. The directory + KDC + DNS half of an AD-compatible DC; sister to
`rocketsmbd` (the SMB half). See `docs/ARCHITECTURE.md` for the decision record.

## Version

`0.1.0` — pre-implementation (docs/scaffolding only).

Version locations (keep in sync on every bump):
- `Cargo.toml` workspace `[workspace.package] version`
- `README.md` status line
- `CHANGELOG.md` release heading

## Locked decisions (see docs/ARCHITECTURE.md)

- **D1** Dedicated fastetcd cluster — never the Kubernetes etcd.
- **D2** DIT mapped above the flat keyspace via prefix scans + txn-maintained
  secondary indexes; no fastetcd key-model change.
- **D3** Raft strong consistency; no AD multi-master reimplementation.
- **D4** OpenSSL 3.x FIPS provider via the **`ossl` crate**. AES-only Kerberos.
  No NTLM/RC4/DES/MD4/MD5.
- **D5** Runs standalone or in Kubernetes.
- **D6** Tier 1 Linux/Mac(light) → Tier 1.5 app SSO → Tier 2 Windows/Mac join.
- **D7** SSO surfaces: RHEL native Kerberos; OpenShift via native OIDC
  (`iron-oidc`) + LDAP IdP + SPNEGO proxy. Self-contained, no Keycloak.
- **D8** Partitioning (multi-domain) is **FOUNDATIONAL, day one** — many
  strongly-consistent Raft clusters, one per naming context, federated by trust
  + referrals + watch-fed aggregation. Never a monolith.
- **D9** Multi-forest federation (holding-company topology): hundreds of
  autonomous forests sharing a federated GAL + OIDC brokering; forest = security
  boundary (ITAR/M&A). Recurses D8's primitives one level up.

## Foundational invariants (do NOT defer — see D8)

These MUST be load-bearing from the first crate, even when only one partition
exists. Adding them later means rewriting the DN model, storage keys, referral
layer, rootDSE, and KDC realm model at once.

1. `NamingContext`/`Partition` is a core type; nothing assumes a single suffix.
2. **PartitionRegistry** (crossRef-equivalent, in the forest config partition):
   base DN, fastetcd endpoints + mTLS, Kerberos realm, parent/subordinate refs.
3. Storage keys are partition-scoped: `/iron/<partition-id>/tree/<rdn-path>`,
   `/iron/<partition-id>/idx/...`. Partitions may live on different clusters.
4. Connection registry maps partition-id → etcd endpoints (multi-cluster store).
5. rootDSE publishes `namingContexts`/`defaultNamingContext`/`configuration`/
   `schema`/`rootDomain` NCs; cross-NC ops emit referrals.
6. KDC is realm-per-partition with cross-realm key slots.
7. Schema is itself a partition (schema NC), not hardcoded.

Deferred = operations only (provision child domain, establish trust, run
GC/GAL aggregator) — built on a model that already assumes N partitions.

## Work plan

### Phase 0 — Foundation (in progress)
- [x] Capture architecture & decisions (`docs/ARCHITECTURE.md`)
- [x] README, CHANGELOG, `.gitignore`, project CLAUDE.md
- [x] Cargo workspace skeleton (crate boundaries)
- [ ] Create GitHub repo + push
- [ ] Validate `ossl` crate + OpenSSL FIPS provider build on target platform
- [ ] fastetcd connection harness (etcd v3 gRPC client, mTLS) — spike

### Phase 1 — Tier 1 identity core (RHEL/Linux + Mac light path)
- [ ] `iron-partition`: `NamingContext`/`Partition` types, **PartitionRegistry**,
      connection registry (partition-id → fastetcd cluster). FOUNDATIONAL (D8) —
      built first; every other crate depends on it.
- [ ] `iron-store`: **partition-scoped** DIT-over-fastetcd (per-partition keys
      `/iron/<pid>/tree/...`, multi-cluster, DN encoding, entry serialization,
      secondary indexes, watch-driven change notification)
- [ ] `iron-ldap`: LDAP v3 server (bind, search, add/mod/del), rootDSE with
      `namingContexts`/config/schema/rootDomain NCs, **cross-NC referrals**,
      AD-shaped schema subset + RFC 2307 posix attrs (uidNumber/gidNumber),
      LDAPS/StartTLS via OpenSSL FIPS
- [ ] `iron-kdc`: Kerberos KDC (AS-REQ/TGS-REQ), **realm-per-partition** with
      cross-realm key slots, AES enctypes only, keytab
- [ ] `iron-dns`: SRV autodiscovery records (integrate with microdns where it
      makes sense)
- [ ] SASL/GSSAPI bind path; end-to-end SSSD + krb5 client validation
- [ ] RHEL enrollment (realmd/adcli or sssd krb5+ldap) + host keytab; verify
      GSSAPI SSO to SSH and rocketsmbd `sec=krb5`. macOS LDAP/krb5 bind.

### Phase 1.5 — App SSO (OpenShift + modern apps)  [D7]
- [ ] OpenShift **LDAP identity provider** (direct bind) — ship first, no new code
- [ ] `iron-oidc`: FIPS OAuth2/OpenID Connect authorization server; OpenShift
      OIDC IdP + token SSO for modern apps
- [ ] **SPNEGO** desktop→console SSO: RequestHeader IdP + mod_auth_gssapi proxy
      integration docs (reuses Tier 1 KDC)

### Phase 2 — Tier 2 Windows/Mac domain join (later)
- [ ] MS schema objects, rootDSE attrs, SID/RID allocation, `nTSecurityDescriptor`
- [ ] Kerberos PAC generation (group SIDs)
- [ ] SAMR/LSARPC/NETLOGON over DCE-RPC (the join handshake); SYSVOL via rocketsmbd
- [ ] Windows `Add-Computer` join + login; macOS `dsconfigad` bind

### Phase 2.5 — Federation operations (model already exists from Phase 1) [D8/D9]
- [ ] Provision additional child domains (new partition + Raft cluster + realm,
      registered in PartitionRegistry, superior/subordinate refs wired)
- [ ] Kerberos cross-realm trust provisioning (inter-realm `krbtgt` keys);
      transitive referral-ticket routing
- [ ] `iron-gc`: watch-fed Global Catalog aggregator (read-only partial replica,
      port 3268/3269) — reused for the D9 federated GAL
- [ ] Federated GAL: whitelisted-attribute publish from each forest → top-level
      read-only address book (no cross-boundary directory-content leakage)
- [ ] `iron-oidc` cross-forest brokering; selective hub-routed Kerberos trust
- [ ] Trust to a real Windows AD forest (coexistence + migration path)

### Phase 3 — deferred
- DRSUAPI multi-master interop with real Windows DCs, Group Policy engine,
  cross-forest selective-auth/SID-filtering hardening.

## Notes

- fastetcd lives at `../../project*/fastetcd` style sibling paths; it is etcd v3
  wire compatible (use the `etcd-client` crate or fastetcd's own client).
- Cross-project: an end-to-end FIPS posture also requires fastetcd's transport
  crypto to route through OpenSSL FIPS — file against fastetcd, don't fix here.
