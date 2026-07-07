# CLAUDE.md — irondirectory

Project-specific context. Cross-project rules live in the parent `CLAUDE.md`.

## What this is

A FIPS-compliant, Active Directory–compatible identity provider in Rust, built
on `fastetcd`. The directory + KDC + DNS half of an AD-compatible DC; sister to
`rocketsmbd` (the SMB half). See `docs/ARCHITECTURE.md` for the decision record.

## Version

`0.3.0` — Phase 0 done (#1 FIPS crypto, #2 connection harness), Phase 1
underway (#3 DIT layer, #4 iron-ldap: rootDSE/bind/search/add/delete/
modify/compare/LDAPS + authenticated bind via PBKDF2, redundant
deployment live on il1/il2/il3.g8.lo). See CHANGELOG.md for the running
list; Live infrastructure below has the verification details.

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
- **D10** Federation machinery is **in the base** (happy-path tested from day
  one); only the exhaustive proving test matrix is deferred — never the
  capability.

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
- [x] Create GitHub repo + push
- [x] Stand up the dedicated **fastetcd** backend (D1) — see Live infrastructure below
- [x] Unblock #2 — fastetcd#4/#5 fixed upstream (v0.7.0), dm1/dm2/dm3 rolling-
      upgraded to **v0.8.0** and verified: writes via every node forward/commit
      correctly, `GET /health` returns 200, DNS LB probe switched tcp→http.
- [x] Validate `ossl` crate + OpenSSL FIPS provider build on target platform
      (#1) — `crates/crypto` (`iron-crypto`), verified on dev.g8.lo against
      the real Red Hat–validated `fips.so`; see `docs/FIPS.md`.
- [x] fastetcd connection harness (etcd v3 gRPC client, mTLS) (#2) —
      `crates/store` (`iron-store`): `connect()` (plaintext or mTLS from a
      `ClusterRef`) + partition-scoped put/get/scan/watch on `iron_partition`
      keys. Plaintext path verified against the live dm1/dm2/dm3 cluster
      (`tests/live_cluster.rs`, put/get/scan/watch all pass). mTLS path
      verified against a throwaway single-node instance (client identity
      required and honored correctly by `iron-store`'s side) — but found
      **fastetcd doesn't actually enforce `--client-cert-auth`** (writes
      succeed with no client cert presented at all); filed upstream as
      fastetcd#6, not fixed here. The live cluster stays plaintext for now;
      do not flip it to `--client-cert-auth` expecting real enforcement
      until fastetcd#6 lands.

## Live infrastructure

**FIPS crypto (D4)** — `crates/crypto` (`iron-crypto`): digest/HMAC/AES-256-
GCM over the `ossl` crate, dynamically linked against the system OpenSSL
3.5 (NOT `ossl`'s own `fips` cargo feature — that needs OpenSSL >= 4.0 and
isn't CMVP-validated). `FipsContext::new()` verifies the OS's validated
`fips.so` provider is actually active and fails closed otherwise. Build/test
needs `openssl-devel` + `clang` + `OPENSSL_CONF` pointing at a config that
activates `fips.so` — see `docs/FIPS.md`. Verified on dev.g8.lo.

**iron-store connection harness (D1/D2)** — `crates/store` (`iron-store`):
`connect(&ClusterRef)` → `etcd_client::Client` (plaintext or mTLS), plus
partition-scoped `put_entry`/`get_entry`/`scan_subtree`/`watch_subtree` on
`iron_partition`'s key encoding. `tests/live_cluster.rs` (ignored by
default) is the spike against the real `etcd.g8.lo:2379` — run with
`cargo test -p iron-store --test live_cluster -- --ignored
--test-threads=1`. mTLS is validated separately (`tests/mtls_spike.rs`,
env-var-gated) since the live cluster has no TLS configured — see
fastetcd#6 (client-cert-auth doesn't actually enforce a client cert)
before ever turning TLS on there.

**iron-store DIT layer (D2/D8, #3)** — on top of the connection harness:
`model::Entry` (multi-valued attribute map, JSON-serialized value at each
entry key), `index::{put_entry_indexed, delete_entry_indexed,
lookup_by_index}` (secondary indexes at `/iron/<pid>/idx/...` kept
consistent with the entry via one etcd `Txn` per write — stale index
entries from a changed attribute value are removed atomically), and
`store::Store` (invariant #4's connection registry: resolves a DN to its
partition via `PartitionRegistry` and holds one connected client per
partition's cluster). `tests/indexed_entries.rs` (ignored by default) is
the spike against the live cluster — `cargo test -p iron-store --test
indexed_entries -- --ignored --test-threads=1`. Run these `--ignored`
tests from a host with a working route to the g8 node IPs (dev.g8.lo is
known-good — this Mac's tonic/hyper connector once failed with "No route
to host" against 192.168.8.41 despite plain `nc` succeeding; untriaged,
transient, unrelated to `iron-store`'s code).

**iron-ldap (D2/D8, #4 — first vertical slice)** — `crates/ldap`: LDAP v3
over `iron-store`. Built on `rasn`/`rasn-ldap` (RFC 4511 ASN.1 types +
BER codec, MIT/Apache-2.0, actively maintained) rather than hand-rolled
BER — only the outer message tag+length framing is hand-written
(`framing.rs`; the outer SEQUENCE tag is always a single byte, so this is
small and avoids depending on a third-party decoder's incomplete-vs-
malformed error semantics). Implemented: rootDSE (`namingContexts` from
`PartitionRegistry`), anonymous simple bind, search (base/one/subtree
scope; filter kinds present/equality/and/or/not — substrings/ordering/
approx/extensible conservatively evaluate false, not an error), add,
delete. Every op without an implementation still sends back a defined
error response (`UnwillingToPerform`/`ProtocolError`) rather than
dropping the request — found via `ldapwhoami` (sends an Extended WhoAmI
op) hanging forever until this was fixed. Verified end-to-end against
the live cluster with **real `openldap-clients`** (`ldapsearch`,
`ldapadd`, `ldapdelete`) via the throwaway `iron-ldapd` binary
(`cargo run -p iron-ldap --bin iron-ldapd -- 127.0.0.1:3890
http://etcd.g8.lo:2379 <pid> <base-dn> [ldaps-addr cert key]`) — not the
production entry point (`crates/server` isn't built yet).

**LDAPS (`tls.rs`, D4)** — via the plain `openssl` crate (rust-openssl's
full libssl bindings), **not** `ossl`/kryoptic (`iron-crypto`'s
dependency) — `ossl` only binds libcrypto's EVP APIs, no TLS state
machine at all. Dynamically links system libssl (no `vendored`), so it
resolves through the same OS-validated `fips.so` as `iron-crypto`
whenever `OPENSSL_CONF` activates it — same operational requirement, no
per-connection plumbing. Verified live under a FIPS-*only* provider set
(base+fips, no default — `crates/crypto/testdata/fips-dev.cnf`): real
`ldapsearch -H ldaps://` round-trips correctly. One real finding along
the way — OpenSSL 3.5's default TLS 1.3 group list offers a hybrid PQC
group (`X25519MLKEM768`) first, and `openssl list
-key-exchange-algorithms` under the FIPS-only provider set shows
X25519/X448 tagged `@ fips` — meaning the module *implements* them, not
that they're on the CMVP certificate's *approved* list (X25519 isn't a
NIST SP 800-56A curve). Rather than assert unverified compliance,
`build_acceptor` pins `set_groups_list("P-256:P-384:P-521")`; confirmed
via `openssl s_client -brief` the handshake now negotiates `ECDH,
prime256v1` (P-256) with `TLS_AES_256_GCM_SHA384` — unambiguous.
Remaining #4 scope: authenticated bind (needs a credential model),
modify/compare/modify-DN/extended ops, cross-NC referrals, AD-shaped
schema + RFC 2307 posix attrs, StartTLS (LDAPS/implicit-TLS is done;
StartTLS is the explicit-upgrade-on-389 variant, not yet built).

**iron-ldap redundancy (D1-shaped: N stateless replicas + health-checked
LB, not a Raft cluster like fastetcd)** — 3 dedicated VMs, **il1/il2/il3.g8.lo**
→ VMID 134/135/136 → 192.168.8.44/.45/.46, Terraform-provisioned
(`deploy/terragrunt/ldap/`, mirrors the etcd unit exactly). Each replica
independently connects to the *same* fastetcd cluster (`etcd.g8.lo:2379`,
partition `g10`) — no coordination between replicas, unlike fastetcd's
own Raft group. **Single endpoint: `ldap.g8.lo:389`** — MicroDNS
health-checked LB (3 A records, `deploy/dns/ldap-lb.sh`), probe is
`http :8080/` against iron-ldapd's real `/health`
(`crates/ldap/src/health.rs`, does a live fastetcd `Status` RPC, not just
TCP liveness). Verified: real `ldapsearch` against `ldap.g8.lo` and each
node individually; stopped `iron-ldapd` on il1 and confirmed queries via
`ldap.g8.lo` kept succeeding (client-side multi-A-record retry), then
restarted it — LB status back to `healthy: 6/6` (etcd + ldap groups).
Applied from `dev.g8.lo` (on the g8 LAN — this Mac's route to the Proxmox
API at `pve.g8.lo:8006` is intermittently unreachable, unrelated to any
code here); needed a fresh `PROXMOX_API_TOKEN` (created via `pveum user
token add root@pam terraform-cli`, since the existing `terraform`/
`irondir` tokens' secrets were never persisted anywhere retrievable —
Proxmox never re-displays a token secret after creation) and a new
`~/.ssh/id_rsa` keypair on dev.g8.lo authorized on `pve.g8.lo` (root.hcl
hardcodes `~/.ssh/id_rsa`, dev.g8.lo only had an ed25519 key).

**RPM distribution gap — resolved 2026-07-07:** cloud-init's `dnf install
<github release rpm url>` 404'd on il1/il2/il3 because irondirectory was
still a **private** repo (fastetcd's identical pattern works because
fastetcd is public) — worked around at the time by `scp`-ing the
already-built RPM from dev.g8.lo. Decision: **made irondirectory public**
(matching fastetcd/rocketsmbd), after scanning full git history for
secrets first (clean — only placeholder/example token strings, no real
credentials, no private key blocks). Confirmed the release asset is now
anonymously fetchable (`curl` 200). `deploy/terragrunt/ldap/`'s cloud-init
template's `dnf install <url>` now works as originally intended on a
fresh VM recreate — no more scp workaround needed.

**fastetcd backend (D1)** — dedicated 3-node **fastetcd** cluster (NOT upstream
etcd — fastetcd is the system under test; see memory), Proxmox VMs on g8, managed
by Terragrunt + the shared `terraform-modules//modules/proxmox-fedora-vm?ref=v0.1.0`
(`deploy/terragrunt/etcd/`; do NOT copy .tf — reference the pinned module).
- Nodes: dm1/dm2/dm3.g8.lo → VMID 131/132/133 → 192.168.8.41/.42/.43.
- **fastetcd `v0.8.1`**, installed from the released RPM via cloud-init
  (`dnf install <github release rpm url>`) — NEVER hand-built, never a container
  nested on the VM. RPM ships `/usr/bin/fastetcd` + `fastetcd.service`
  (reads `/etc/fastetcd/fastetcd.conf`). Config uses etcd-compatible `ETCD_*`
  env names (fastetcd reads them natively). Upgraded in place: v0.6.0 → v0.8.0
  (2026-07-06), then v0.8.0 → v0.8.1 (same day, rolling `dnf install <rpm
  url>`, followers first, leader last each time) — no data loss, no
  downtime; each node's postun `try-restart` picks up the new binary
  automatically. v0.8.1 fixes **fastetcd#6** (`--client-cert-auth` had no
  env binding, so `ETCD_CLIENT_CERT_AUTH` was silently ignored and never
  enforced) — found while validating `iron-store`'s mTLS path (#2). The
  live cluster is still plaintext (TLS not enabled here), but the bug
  that blocked ever safely turning it on is fixed.
- **Single endpoint for iron-store: `etcd.g8.lo:2379`** — MicroDNS health-checked
  LB (3 A records), reproducible via `deploy/dns/etcd-lb.sh`. Probe is **`http
  :2379/health`** (fastetcd#5 landed in v0.7.0); monitor confirms
  `healthy:3/3`. Failover verified against upstream etcd earlier; now HTTP
  probe green on fastetcd too.
- **fastetcd gaps found dogfooding v0.6.0, fixed upstream in v0.7.0 (now
  running v0.8.0), both verified against the live cluster 2026-07-06:**
  multi-node client writes (**fastetcd#4**) — put via dm1/dm2/dm3 all commit
  and replicate regardless of leader; HTTP `/health` (**fastetcd#5**) — 200
  from all three nodes.
- Keyspace prefix: `/iron/...` (Kubernetes etcd uses `/registry/...` — disjoint,
  separate cluster anyway per D1).
- Workstation: `brew install etcd` for a native (wire-compat) etcdctl;
  `ETCDCTL_ENDPOINTS=http://etcd.g8.lo:2379`.

### Phase 1 — Tier 1 identity core (RHEL/Linux + Mac light path)
- [x] `iron-partition`: `NamingContext`/`Partition` types, **PartitionRegistry**,
      connection registry (partition-id → fastetcd cluster). FOUNDATIONAL (D8) —
      built first; every other crate depends on it. *(DN, keys, registry, realm
      derivation; 23 tests, clippy-clean.)*
- [x] `iron-store`: **partition-scoped** DIT-over-fastetcd (#2/#3) — per-
      partition keys `/iron/<pid>/tree/...`, multi-cluster `Store`
      (DN→partition→client), DN encoding (via `iron_partition`), entry
      serialization (`model::Entry`), secondary indexes (`index::*`, one
      atomic `Txn` per write), watch-driven change notification
      (`entry::next_entry_change`). Verified against the live dm1/dm2/dm3
      cluster; see `docs/` note in Live infrastructure below.
- [~] `iron-ldap` (#4, in progress): LDAP v3 server. **Done:** rootDSE
      (`namingContexts`), anonymous bind, search (base/one/subtree scope,
      core filters), add, del, **LDAPS via OpenSSL** (pinned to NIST
      curves P-256/P-384/P-521, not OpenSSL's default TLS1.3 hybrid-PQC
      group) — verified with real `ldapsearch`/`ldapadd`/`ldapdelete`
      (incl. over `ldaps://`) against the live cluster. **Remaining:**
      authenticated bind, modify/compare/modify-DN/extended ops,
      cross-NC referrals, AD-shaped schema subset + RFC 2307 posix attrs
      (uidNumber/gidNumber), StartTLS (explicit upgrade on 389; LDAPS/
      implicit-TLS on its own port is done)
- [ ] `iron-kdc`: Kerberos KDC (AS-REQ/TGS-REQ), **realm-per-partition** with
      cross-realm key slots, AES enctypes only, keytab
- [ ] `iron-dns`: SRV autodiscovery records (integrate with microdns where it
      makes sense)
- [ ] SASL/GSSAPI bind path; end-to-end SSSD + krb5 client validation
- [ ] RHEL enrollment (realmd/adcli or sssd krb5+ldap) + host keytab; verify
      GSSAPI SSO to SSH and rocketsmbd `sec=krb5`. macOS LDAP/krb5 bind.

#### Phase 1 — federation machinery (IN THE BASE, D8/D9/D10)
Built as first-class in the base with **happy-path coverage** so the code paths
are live from day one. Exhaustive proving suites are deferred (see Testing).
- [ ] Child-domain provisioning: create partition + Raft cluster + realm, register
      in PartitionRegistry, wire superior/subordinate references
- [ ] LDAP referral generation + chasing (one hop) across naming contexts
- [ ] Kerberos cross-realm `krbtgt` keys + one-hop referral-ticket routing
- [ ] `iron-gc`: watch-fed Global Catalog aggregator (read-only partial replica,
      port 3268/3269); same engine powers the D9 federated GAL
- [ ] Federated GAL: whitelisted-attribute publish per forest → top-level
      read-only address book (no cross-boundary directory-content leakage)

### Phase 1.5 — App SSO (OpenShift + modern apps)  [D7]
- [ ] OpenShift **LDAP identity provider** (direct bind) — ship first, no new code
- [ ] `iron-oidc`: FIPS OAuth2/OpenID Connect authorization server; OpenShift
      OIDC IdP + token SSO for modern apps; cross-forest brokering hook (D9)
- [ ] **SPNEGO** desktop→console SSO: RequestHeader IdP + mod_auth_gssapi proxy
      integration docs (reuses Tier 1 KDC)

### Phase 2 — Tier 2 Windows/Mac domain join (later)
- [ ] MS schema objects, rootDSE attrs, SID/RID allocation, `nTSecurityDescriptor`
- [ ] Kerberos PAC generation (group SIDs)
- [ ] SAMR/LSARPC/NETLOGON over DCE-RPC (the join handshake); SYSVOL via rocketsmbd
- [ ] Windows `Add-Computer` join + login; macOS `dsconfigad` bind

### Deferred — exhaustive federation testing (D10), not capability
- [ ] Many-partition / many-cluster scale matrices
- [ ] Deep referral chains; transitive multi-realm trust paths, shortcut trusts
- [ ] Hundreds-of-forests GAL convergence + staleness bounds
- [ ] Divestiture/teardown, re-parenting, conflict cases
- [ ] Cross-forest brokering at fan-out; selective-auth policy
- [ ] **Real Windows AD interop** (trust, GC, Kerberos PAC)

### Phase 3 — deferred capability
- DRSUAPI multi-master interop with real Windows DCs, Group Policy engine,
  cross-forest selective-auth/SID-filtering hardening.

### Deployment TODO
- [ ] **OpenShift-based deployment** (Helm chart or Operator, per D5
      "standalone or Kubernetes" — mirror fastetcd's `deploy/charts/fastetcd`
      precedent). Container images per service; `iron-ldapd`'s real HTTP
      `/health` (`crates/ldap/src/health.rs`) reuses directly as a readiness/
      liveness probe. LDAP isn't HTTP, so exposure is a plain Service or a
      Route with TLS passthrough for LDAPS, not a normal HTTP Route.
      cert-manager for the LDAPS/OpenSSL-FIPS cert instead of hand-rolled dev
      certs. iron-ldap replicas are stateless (state lives in fastetcd's
      Raft) so no StatefulSet needed there, unlike fastetcd's own cluster.
      Not blocking current work — noted so it isn't forgotten once the
      VM-based deployment (Proxmox, see Live infrastructure above) matures.

## Notes

- fastetcd lives at `../../project*/fastetcd` style sibling paths; it is etcd v3
  wire compatible (use the `etcd-client` crate or fastetcd's own client).
- Cross-project: an end-to-end FIPS posture also requires fastetcd's transport
  crypto to route through OpenSSL FIPS — file against fastetcd, don't fix here.
