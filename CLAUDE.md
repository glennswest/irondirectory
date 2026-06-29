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

## Work plan

### Phase 0 — Foundation (in progress)
- [x] Capture architecture & decisions (`docs/ARCHITECTURE.md`)
- [x] README, CHANGELOG, `.gitignore`, project CLAUDE.md
- [x] Cargo workspace skeleton (crate boundaries)
- [ ] Create GitHub repo + push
- [ ] Validate `ossl` crate + OpenSSL FIPS provider build on target platform
- [ ] fastetcd connection harness (etcd v3 gRPC client, mTLS) — spike

### Phase 1 — Tier 1 identity core (RHEL/Linux + Mac light path)
- [ ] `iron-store`: DIT-over-fastetcd (DN encoding, entry serialization,
      secondary indexes, watch-driven change notification)
- [ ] `iron-ldap`: LDAP v3 server (bind, search, add/mod/del, rootDSE),
      AD-shaped schema subset + RFC 2307 posix attrs (uidNumber/gidNumber),
      LDAPS/StartTLS via OpenSSL FIPS
- [ ] `iron-kdc`: Kerberos KDC (AS-REQ/TGS-REQ), AES enctypes only, keytab
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

### Phase 3 — deferred
- DRSUAPI multi-master interop, Group Policy engine, trusts/forests.

## Notes

- fastetcd lives at `../../project*/fastetcd` style sibling paths; it is etcd v3
  wire compatible (use the `etcd-client` crate or fastetcd's own client).
- Cross-project: an end-to-end FIPS posture also requires fastetcd's transport
  crypto to route through OpenSSL FIPS — file against fastetcd, don't fix here.
