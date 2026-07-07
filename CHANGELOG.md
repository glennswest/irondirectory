# Changelog

All notable changes to irondirectory are documented here. Format follows the
cross-project convention; the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [v0.2.0] — 2026-07-07

### 2026-07-07
- **feat(ldap):** `iron-ldapd` is now a real deployable daemon, not just a
  spike binary: env-var config (`IRON_LDAP_*`, systemd `EnvironmentFile=`-
  friendly), a real HTTP `/health` on a separate port (does an actual
  fastetcd `Status` RPC via `Store::ping`, not just TCP liveness), RPM
  packaging (`cargo-generate-rpm`) + a systemd unit. Deliberately
  glibc-linked with system libssl dynamically linked (not fastetcd's
  musl-static pattern) — D4's FIPS posture needs the OS's validated
  `fips.so`, which a vendored/static OpenSSL would defeat; confirmed the
  generated RPM correctly declares `libssl.so.3`/`libcrypto.so.3` as
  runtime deps. Verified installed via `dnf install`: creates the
  `iron-ldapd` system user, binds privileged port 389 as non-root via
  `CAP_NET_BIND_SERVICE`, and answers real `ldapsearch` — all under
  systemd.
- **fix(store):** Fixed a real concurrency bug found while wiring up
  `iron-ldapd`'s multiple listeners (plaintext/LDAPS/health): awaiting
  them in a sequential `for` loop blocked forever on the first one, since
  each is an infinite accept loop. `futures::join_all` runs them
  concurrently instead.

### 2026-07-06
- **fix(deploy):** Rolling-upgraded the live dm1/dm2/dm3 cluster from
  fastetcd v0.8.0 to **v0.8.1**, which fixes fastetcd#6 (the bug found
  while validating `iron-store`'s mTLS path: `--client-cert-auth` had no
  env binding, so `ETCD_CLIENT_CERT_AUTH` was silently ignored and never
  enforced). Verified: all three nodes healthy post-upgrade, writes via
  every node still commit/replicate. Pinned
  `deploy/terragrunt/etcd/terragrunt.hcl` to v0.8.1. TLS itself remains
  off on the live cluster for now.
- **feat(ldap):** LDAPS for `iron-ldap` (part of #4, still open). Uses the
  plain `openssl` crate (rust-openssl's full libssl bindings) — not
  `ossl`/kryoptic, which only binds libcrypto's EVP APIs and has no TLS
  state machine. Dynamically links system libssl, so it resolves through
  the same OS-validated `fips.so` as `iron-crypto` whenever
  `OPENSSL_CONF` activates it. Verified live under a FIPS-only provider
  set (base+fips, no default): real `ldapsearch -H ldaps://` round-trips.
  Found and fixed a real gap along the way — OpenSSL 3.5's default TLS
  1.3 group list offers a hybrid PQC group (`X25519MLKEM768`) first, and
  the FIPS provider implements X25519/X448 (confirmed via `openssl list
  -key-exchange-algorithms`) without that meaning they're on the CMVP
  certificate's *approved* list (X25519 isn't a NIST SP 800-56A curve).
  `build_acceptor` now pins `set_groups_list("P-256:P-384:P-521")`;
  confirmed the handshake negotiates `ECDH, prime256v1` with
  `TLS_AES_256_GCM_SHA384` — unambiguous.
- **feat(ldap):** First vertical slice of roadmap #4 (still open —
  substantial scope remains). `crates/ldap` (`iron-ldap`): LDAP v3 over
  `iron-store`, built on `rasn`/`rasn-ldap` (RFC 4511 ASN.1 types + BER
  codec) rather than hand-rolled BER — only the message framing (tag+
  length header) is hand-written. Implemented: rootDSE (`namingContexts`
  from the `PartitionRegistry`), anonymous simple bind, search (base/
  one/subtree scope; present/equality/and/or/not filters), add, delete.
  Every unimplemented op (modify, compare, modify-DN, extended) now
  returns a defined error response instead of being silently dropped —
  found via `ldapwhoami` (sends an Extended WhoAmI request) hanging
  forever before that fix. Verified end-to-end against the live cluster
  with **real `openldap-clients`**: `ldapsearch` (rootDSE, base/one-level/
  subtree with an equality filter and attribute selection), `ldapadd`,
  `ldapdelete` — all pass, via the throwaway `iron-ldapd` binary (not the
  production entry point). `iron-store` gained `Store::scan_subtree` and
  `entry::dn_from_tree_key` to support this. Bumped workspace
  `rust-version` 1.82 → 1.85 (`rasn`/`rasn-ldap` use edition 2024).
  Remaining #4 scope: authenticated bind, modify/compare/modify-DN/
  extended ops, cross-NC referrals, AD-shaped schema + RFC 2307 posix
  attrs, LDAPS/StartTLS via `iron-crypto`'s FIPS provider.
- **feat(store):** Closed roadmap #3 — the real DIT layer on top of #2's
  connection harness. `model::Entry` (multi-valued attribute map,
  JSON-serialized). `index::{put_entry_indexed, delete_entry_indexed,
  lookup_by_index}`: secondary indexes at `/iron/<pid>/idx/...` kept
  consistent with the entry tree via one etcd `Txn` per write, so a stale
  index entry from a changed attribute value is removed atomically, not
  left dangling. `store::Store`: the multi-cluster connection registry
  (invariant #4) — resolves a DN to its partition via `PartitionRegistry`
  and holds one connected client per partition's cluster, so callers work
  directly on DNs. `entry::next_entry_change` decodes watch `Put` events
  into `Entry` rather than raw bytes. Verified against the live dm1/dm2/dm3
  cluster: put/get/delete roundtrip, index tracks an attribute value
  change (old index entry removed, new one present), typed watch decode —
  all pass (`tests/indexed_entries.rs`, `--ignored`).
- **feat(store):** Closed roadmap #2 — `crates/store` (`iron-store`):
  `connect()` turns a `ClusterRef` into a live `etcd_client::Client`
  (plaintext or mTLS), plus partition-scoped `put_entry`/`get_entry`/
  `scan_subtree`/`watch_subtree` on `iron_partition`'s key encoding.
  Plaintext path verified against the live dm1/dm2/dm3 cluster
  (`etcd.g8.lo:2379`): put/get roundtrip, subtree scan, and watch all pass.
  mTLS path verified against a throwaway single-node fastetcd instance —
  `iron-store`'s client-identity handling is correct, but this surfaced a
  real bug: fastetcd's `--client-cert-auth` doesn't actually require a
  client certificate (a `put` succeeds with no client cert presented at
  all, on both the gRPC KV path and `/health`). Filed upstream as
  fastetcd#6; the live cluster stays plaintext until that lands. Bumped
  `etcd-client` 0.14 → 0.19 (latest stable, `tls` feature enabled).
- **feat(crypto):** Closed roadmap #1 — validated the `ossl` crate against
  the target platform's real FIPS provider. Added `crates/crypto`
  (`iron-crypto`): digest (SHA-256/384/512), HMAC (SHA-256/512), and
  AES-256-GCM AEAD, all through `ossl` dynamically linked against system
  OpenSSL. Key finding: `ossl`'s own `fips` cargo feature is a dead end on
  this platform (requires OpenSSL >= 4.0, vendors a non-CMVP-validated test
  build) — real compliance comes from the OS's already-validated `fips.so`,
  loaded via standard OpenSSL provider config. `FipsContext::new()` checks
  `OSSL_PROVIDER_available` and fails closed if the fips provider isn't
  active, rather than silently running unvalidated crypto. Also found and
  worked around a memory-safety bug in `ossl` 1.5.2's
  `load_configuration_file` (non-NUL-terminated pointer passed to a C API).
  Full writeup: `docs/FIPS.md`. Verified with 7 passing known-answer/
  roundtrip tests on dev.g8.lo.
- **fix(deploy):** Rolling-upgraded the live dm1/dm2/dm3 cluster from fastetcd
  v0.6.0 to **v0.8.0** (followers first, leader last; `dnf install <rpm url>`,
  each node's postun `try-restart` picks up the new binary — no downtime, no
  data loss). Verified the two upstream fixes against the real cluster: a
  `put` via every node (leader or follower) now commits and replicates
  (fastetcd#4), and `GET :2379/health` returns 200 from all three
  (fastetcd#5).
- **fix(deploy):** `etcd.g8.lo` LB probe switched back **`tcp` → `http
  :2379/health`** now that fastetcd serves it; MicroDNS LB monitor reports
  `healthy: 3/3`.
- **chore:** Pinned `deploy/terragrunt/etcd/terragrunt.hcl`'s
  `fastetcd_version`/`fastetcd_rpm_url` to v0.8.0 so a future node recreate
  doesn't regress to the broken v0.6.0. Unblocks issue #2 (iron-store ↔
  fastetcd connection harness).

### 2026-07-01
- **feat(deploy):** Backend is now **fastetcd v0.6.0** (the system under test),
  not upstream etcd. Terragrunt recreates dm1/dm2/dm3 and cloud-init installs the
  **released fastetcd RPM** via `dnf` (no hand-build, no container nesting); the
  RPM's `fastetcd.service` reads `/etc/fastetcd/fastetcd.conf` with etcd-compatible
  `ETCD_*` env. 3-node Raft cluster formed; reads/health OK.
- **fix(deploy):** `etcd.g8.lo` LB probe switched `http` → **`tcp :2379`**
  (fastetcd has no HTTP `/health` — fastetcd#5); LB 3/3 healthy. Removed the bash
  `deploy/proxmox/ironetcd.sh` bootstrap (it installed *upstream etcd* — a footgun
  now that Terragrunt + the fastetcd RPM is the tool).
- **chore:** Filed dogfooding findings upstream — **fastetcd#4** (multi-node
  client writes fail: leader forwarding addr empty — BLOCKER for iron-store
  writes) and **fastetcd#5** (no HTTP `/health`). Created 20 roadmap issues on
  the irondirectory repo (Phase 0/1/1.5/2 + deferred D10), `roadmap` label.

### 2026-06-30
- **feat(deploy):** Single health-checked endpoint **`etcd.g8.lo:2379`** for the
  backend — 3 MicroDNS A records (.41/.42/.43), each with an etcd `http
  :2379/health` health_check; reproducible via `deploy/dns/etcd-lb.sh`. After the
  g8 MicroDNS LB monitor was enabled (mkube-generated config), **verified
  end-to-end failover**: stopping etcd on dm3 dropped .43 from resolution within
  ~3 probe cycles (service stayed up), and restarting it auto-rejoined — last-
  alive failsafe guarantees the name never returns NODATA. iron-store will use
  this single endpoint. Recorded the live backend in CLAUDE.md.

### 2026-06-29
- **feat(deploy):** Stood up irondirectory's dedicated etcd backend (D1) — 3
  Fedora 43 cloud VMs on Proxmox (dm1/dm2/dm3.g8.lo @ .41/.42/.43, VMIDs
  131-133), each with a dedicated /var/lib/etcd data disk, forming a healthy
  3-node etcd 3.6.12 Raft cluster (dm1 leader; put/get verified). DNS A+PTR
  records created in g8.lo. `ironetcd.sh` hardened: robust data-disk detection
  (btrfs-subvol-aware), simultaneous Type=notify start for quorum, node-side
  verify. Removed obsolete pve.gw.lo record from gw MicroDNS.

### 2026-06-29
- **feat:** `iron-partition` crate — the foundational naming-context model (D8).
  `Dn` (RFC 4514 parse/normalize/display, suffix-containment routing, serde);
  `Partition`/`PartitionId`/`ForestId`/`PartitionKind`/`ClusterRef`/`TlsRef` with
  realm-from-DN derivation; partition-scoped key encoding (`/iron/<pid>/tree/…`
  reverse-ordered so a subtree is a key prefix; escaped index keys);
  `PartitionRegistry` (crossRef-equivalent) with longest-suffix `resolve`,
  superior/subordinate navigation, per-forest schema/config lookup, and rootDSE
  naming-contexts listing. 23 unit tests, clippy-clean. First crate in the
  workspace; everything depends on it.
- **docs:** Federation moved INTO THE BASE (decision D10). The federation
  machinery — child-domain provisioning, LDAP referral chasing, cross-realm
  trust keys, the watch-fed GC/GAL aggregator, OIDC brokering hook — is built
  first-class in Phase 1 with happy-path coverage so code paths stay live.
  Only the exhaustive proving test matrix (many-partition scale, deep referral
  chains, transitive trust paths, GAL convergence, divestiture/teardown, real
  Windows AD interop) is deferred — capability is never deferred. Work plan
  reorganized accordingly; added an `iron-gc` crate.
- **docs:** Partitioning made FOUNDATIONAL (decisions D8 + D9). D8: multi-domain
  within a forest — each naming context is its own strongly-consistent Raft
  cluster, federated by Kerberos cross-realm trust + LDAP referrals + a watch-fed
  Global Catalog; never a monolithic tree. D9: multi-forest holding-company
  topology — hundreds of autonomous forests (forest = security boundary, ITAR/M&A)
  sharing a federated GAL + OIDC brokering. Added the day-one data-model contract
  (PartitionRegistry, partition-scoped keys, multi-cluster store, rootDSE naming
  contexts, realm-per-partition KDC), the `iron-partition`/`iron-gc` crates, and a
  Phase 2.5 federation-operations plan. Work plan reordered so `iron-partition` is
  built first and every crate is partition-aware from the start.
- **docs:** Corrected the backend scale analysis in ARCHITECTURE §4 — removed
  Go-etcd folklore (GC pauses, ~8 GB ceiling, 1.5 MB cap) that does not apply to
  a Rust + io_uring etcd; documented redb (on-disk, not RAM-bound) vs wal/iouring
  (in-memory) engine profiles; isolated the genuinely fundamental limits
  (single-Raft-group write serialization, snapshot recovery time) and the
  directory-layer concerns (index write amplification, large multi-valued attrs).

### 2026-06-29
- **docs:** SSO surfaces (decision D7) — RHEL native Kerberos/GSSAPI; OpenShift
  via native OIDC (`iron-oidc` crate), LDAP identity provider (day-one), and
  SPNEGO proxy; self-contained (no Keycloak). Added Tier 1.5 (app SSO) and
  posix/RFC 2307 schema attrs; clarified Windows/macOS domain join under Tier 2
  and macOS LDAP/krb5 light path under Tier 1.
- **docs:** Initial project scaffolding — README, architecture & decision
  record, project CLAUDE.md work plan, changelog, `.gitignore`, and Cargo
  workspace skeleton.
- **docs:** Recorded foundational decisions (see `docs/ARCHITECTURE.md`):
  dedicated fastetcd cluster (D1), DIT-over-flat-keyspace mapping (D2), Raft
  strong consistency (D3), OpenSSL 3.x FIPS provider via the `ossl` crate (D4),
  standalone-or-Kubernetes deployment (D5), and phased client targets (D6).
