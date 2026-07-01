# Changelog

All notable changes to irondirectory are documented here. Format follows the
cross-project convention; the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
