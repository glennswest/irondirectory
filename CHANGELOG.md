# Changelog

All notable changes to irondirectory are documented here. Format follows the
cross-project convention; the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [v0.16.0] — 2026-07-10

### 2026-07-10 (post-v0.15.0)
- **feat(ldap):** Implement RFC 4532's WhoAmI extended operation --
  found live during #14's verification (`ldapwhoami` failed against
  `il1.g8.lo` with "extended operations are not implemented yet").
  Each connection now tracks its current RFC 4513 §3 authzId
  (`bound_identity`), updated on every terminal bind outcome (left
  untouched mid-SASL-negotiation): `"dn:<dn>"` for simple bind,
  `"u:<principal>"` for GSSAPI, empty for anonymous.
  `handle_bind`/`handle_sasl_bind` now return this alongside the
  `BindResponse`.

Verified live against a disposable local `iron-ldapd` (anonymous,
correct-password, and wrong-password cases all behave correctly), then
deployed via a rolling rpm upgrade to the real `il1`/`il2`/`il3.g8.lo`
fleet (previously stuck on a stale `0.5.0` package), each host
confirmed `active` and re-verified with `ldapwhoami` + a plain rootDSE
search before moving to the next.

## [v0.15.0] — 2026-07-10

### 2026-07-10 (post-v0.14.0)
- **docs:** OpenShift LDAP identity provider (#14, D7) -- no new code,
  Phase 1.5's "ship first" SSO surface. `docs/OPENSHIFT-LDAP-IDP.md`
  documents the `OAuth` CR `identityProviders[].ldap` configuration
  (RFC 2255 `url` syntax, attribute mapping, TLS options) and
  reproduces `oauth-server`'s exact search-then-bind authentication
  sequence with `ldapsearch` against real, already-deployed
  `il1.g8.lo`: an anonymous search finds a test `posixAccount`/
  `inetOrgPerson` entry by `uid`, a bind with the correct password
  succeeds, and a bind with the wrong password fails closed with
  `Invalid credentials`. Found this deployment has no
  `IRON_LDAP_TLS_CERT`/`_KEY` configured (an ops gap, not code --
  documented as the `ldaps://` alternative) and that `ldapwhoami`
  fails with "extended operations are not implemented yet" (RFC 4532's
  WhoAmI operation, unrelated to OpenShift's plain-bind flow, tracked
  separately, not a blocker for this issue).

## [v0.14.0] — 2026-07-10

### 2026-07-10 (post-v0.13.0)
- **feat(gc):** Federated GAL support -- multi-forest aggregation
  (#13). `iron-gcd` now accepts `IRON_GC_FORESTS` (a `;`-separated list
  of additional forests' config-partition coordinates, same `|`-delimited
  convention as `IRON_LDAP_REFERRALS`) alongside the existing
  single-forest trio, loading and merging every configured forest's
  `PartitionRegistry` and spawning a watch task for every domain
  partition found across all of them into one shared `Aggregate`. No
  library changes were needed (`aggregate`/`watch`/`session` in
  `iron-gc` were already forest-agnostic from #12) -- the whole feature
  is new bootstrap logic in `iron-gcd`. Two forests colliding on the
  same partition id fails the merge loudly at startup rather than
  silently dropping one forest's naming contexts.

Verified live with two independent forests (`g13a`/`g13b`): a
per-forest GC configured with the default (broad) attribute whitelist
shows an internal-only attribute (`uidnumber`); a federated GAL
configured via `IRON_GC_FORESTS` with a deliberately stricter whitelist
(`objectclass,cn,mail`) aggregates entries from *both* forests but
correctly omits that same attribute from all of them -- proving no
cross-boundary directory-content leakage, not merely that aggregation
works. With both daemons running throughout, a new entry added
directly to one forest's cluster appeared in the federated GAL's
search immediately, no restart -- confirming the watch-fed liveness
established in #12 holds across a forest boundary too. One process,
snapshot topology (D10) -- adding a whole new forest still requires a
restart to pick up; many-forest scale and staleness-bound proving
remain deferred.

## [v0.13.0] — 2026-07-10

### 2026-07-10 (post-v0.12.0)
- **feat(gc):** New `iron-gc` crate: watch-fed Global Catalog aggregator
  (#12), ports 3268/3269. Subscribes to every `Domain`-kind partition
  in a forest's persisted `PartitionRegistry` (#9, `IRON_GC_CONFIG_*`
  env vars) and, for each, spawns a task that connects directly to
  that partition's cluster and maintains a live in-memory partial
  replica (`aggregate::Aggregate`) fed by a real etcd watch stream --
  not a one-time snapshot. Watching starts before the initial
  bootstrap scan so a write racing the bootstrap is re-applied
  (idempotent) rather than permanently missed. Attribute projection
  (the "partial" in partial replica) happens at ingest time, per D9's
  "no directory-content leakage" language -- a conservative default
  whitelist (`objectclass, cn, uid, mail, displayname, sn, givenname,
  uidnumber, gidnumber`), tunable via `IRON_GC_ATTRIBUTES`. Serves
  anonymous bind + read-only search reusing `iron-ldap`'s wire framing,
  filter matching, TLS acceptor, and rootDSE builder rather than
  reimplementing them; no write surface (add/delete/modify/compare/
  modify-DN) at all. Same engine intended to power #13's cross-forest
  federated GAL.

Verified live against a fresh two-partition forest (`g12gc` parent +
`g12gc-emea` child): a real `ldapsearch` subtree search from the root
sees entries from both partitions in one response; scoping the search
to the child partition alone returns only its entry; rootDSE's
`namingContexts` lists all three partitions. With `iron-gcd` left
running throughout, a new entry added via `iron-kdc-ctl set-password`
appeared in a later search with no daemon restart, and deleting an
entry directly (`fastetcd-ctl del`) was reflected just as live --
proving the aggregator is genuinely watch-fed, not a snapshot. One
forest, one process (D10) -- multi-forest aggregation and
staleness-bound/scale proving are out of scope for this issue.

## [v0.12.0] — 2026-07-10

### 2026-07-10 (post-v0.11.0)
- **feat(kdc):** Cross-realm `krbtgt` keys + one-hop referral tickets
  (#11). `iron-kdc`'s TGS-REQ handler (`tgs_exchange::referral_tgs_rep`)
  checks a new `AppState::topology: Option<PartitionRegistry>` (the
  #9/#10 persisted registry, loaded via new `IRON_KDC_CONFIG_*` env
  vars) when the client's requested realm doesn't match this KDC's
  own, and returns a referral TGT for a directly-trusted (one-hop)
  realm instead of failing closed with `KDC_ERR_S_PRINCIPAL_UNKNOWN`
  (RFC 4120 §3.3.3). New `iron-kdc-ctl set-cross-realm-key <to-realm>
  <from-realm> <secret>` provisions the shared inter-realm key using a
  new `principal::set_shared_key` (deterministic salt, unlike
  `set_password`'s random one) so two independent per-realm
  invocations derive byte-identical keys. `Partition.kdc_url` +
  `iron-config-ctl set-kdc-url` mirror the existing `ldap_url` pattern.
- **fix(kdc):** `set-cross-realm-key`'s principal name can't be derived
  from `IRON_KDC_REALM` -- the "to" realm's own configured realm *is*
  the peer name from the other side, so the "identical command on both
  KDCs" the tool promises was structurally impossible with that
  design. Both realms are now explicit command-line arguments.
- **fix(kdc):** The fixed command's DN construction still collided
  with the "to" realm's own ordinary `krbtgt/<realm>@<realm>` entry
  (same primary/instance components, no realm suffix in the `cn`),
  found live while provisioning the two-realm test forest -- whichever
  principal was written second silently clobbered the other's key.
  Fixed by folding `from_realm` into the `cn`.
- **fix(kdc):** verified live: a plain `set_password`'s random salt
  cannot be used for a *shared* secret between two independent KDCs
  (two calls with the same password would derive two different keys)
  -- `set_shared_key`'s deterministic salt (the principal name itself)
  fixes this by construction, not discovered as a live bug but
  documented here since it's the reason `set_shared_key` exists at all
  rather than reusing `set_password`.

Verified live with two real, independent `iron-kdcd` instances (realms
`G11REF.LO` + `EMEA.G11REF.LO`, wired into one forest via
`iron-config-ctl create-child`) and real `krb5-workstation`
`kinit`/`kvno`: `KRB5_TRACE` confirms a genuine two-hop chase -- TGS-REQ
to the parent KDC returns a referral ticket
`krbtgt/EMEA.G11REF.LO@G11REF.LO` (visible in `klist`), then a second
TGS-REQ using that ticket against the child KDC (found via the test
client's `[capaths]`) returns the real service ticket. Multi-hop
transitive trust-path walking and shortcut trusts are out of scope
(D10) -- one hop only.

## [v0.11.0] — 2026-07-10

### 2026-07-10 (post-v0.10.0)
- **feat(ldap):** Cross-NC referral generation is now wired to the
  persisted forest topology (#10), not just a static hand-maintained
  list. `iron-ldapd` loads the forest's `PartitionRegistry` at startup
  when `IRON_LDAP_CONFIG_FASTETCD_ENDPOINT`/`IRON_LDAP_CONFIG_PARTITION_ID`/
  `IRON_LDAP_CONFIG_BASE_DN` are set (`AppState::topology`,
  `AppState::own_partition_id`), and consults it before the existing
  `IRON_LDAP_REFERRALS` static fallback. New `session::Referrals<'a>`
  bundles both sources plus this instance's own partition id for a
  single request.
- **fix(ldap):** Registry-driven referrals never actually fired for the
  primary use case they exist for -- a search/add/delete/modify/compare/
  modify-DN against a child domain's own base DN. Root cause: a child's
  base DN (e.g. `dc=emea,dc=g9demo,dc=lo`) is *structurally* nested
  under its parent's (`dc=g9demo,dc=lo`), so the parent's own
  single-partition `Store` always "successfully" resolves it as its own
  (returning "no such entry", not `StoreError::NoPartitionFor`) --
  meaning the existing *reactive* referral check
  (`referral_for`/`store_error_result`, keyed off `NoPartitionFor`) was
  structurally unreachable for this case. Fixed with a new *proactive*
  check (`session::proactive_referral`) consulting the registry before
  any local Store call, inserted into all six read/write handlers.
  Verified live against two real fastetcd-backed `iron-ldapd`
  instances (parent + child domain): `ldapsearch` without `-C` now
  returns `result: 10 Referral` + `ref: ldap://<child>/...` for both an
  exact-DN base-object search and a subtree search rooted at the
  child's own base DN; with `-C`, the client automatically chases to
  real data on the child server.
- **fix(config):** `iron-config-ctl init-forest`, re-run against an
  already-bootstrapped forest, silently reset the root partition's
  `subordinates` to empty -- discovered live while standing up #10's
  two-server test, wiping the link `create-child` had previously
  established. Fixed: `init_forest` now loads the existing registry
  first and preserves `subordinates` from the prior record. New
  `add-subordinate` subcommand repairs already-damaged data (used live
  to restore the affected forest).

## [v0.10.0] — 2026-07-10

### 2026-07-10 (post-v0.9.0)
- **feat(config):** New `iron-config` crate + `iron-config-ctl` (#9) --
  persists the `PartitionRegistry` in the forest configuration
  partition (one JSON-blob record per partition; `Partition` already
  round-trips via serde, so no new encode/decode logic needed). New
  `Partition::configuration()` constructor in `iron-partition`.
  `init-forest` bootstraps a brand-new forest (configuration partition
  + root domain); `create-child` registers a child domain under an
  existing parent and updates its `subordinates` list bidirectionally;
  `show` inspects the live registry. Verified end to end against the
  real shared fastetcd cluster: superior/subordinate links and
  auto-derived realm persisted and reloaded correctly across separate
  process invocations; duplicate-id rejection confirmed.
- **fix(deploy):** Root-cause fix for a real incident where a
  pattern-guessed `vm_id` collided with an unrelated, important VM and
  `terraform destroy` deleted it -- `terraform-modules` v0.3.0 moves
  the module's allowed vm_id range to 2000-2100 (disjoint from every
  existing VM) with pool-scoped API token ACL enforcement (previously a
  `root@pam` token with no ACL boundary at all); new
  `get-free-vmid.sh` (canonical copy in `terraform-modules`) queries
  live Proxmox state before any `vm_id` is written into a
  `terragrunt.hcl`, with a lock against concurrent callers. Also
  created dedicated, isolated Proxmox storages for this automation's
  test VM disks and cloud-init snippets (`test-lvm-thin`,
  `terraform-snippets`) rather than sharing `local-lvm`/`local` with
  hand-created/production content -- `Datastore.AllocateSpace` isn't
  scoped by content type, so a shared-storage grant is a residual risk
  even with the vm_id/pool guardrails in place.

## [v0.9.0] — 2026-07-08

### 2026-07-08 (post-v0.8.0)
- **feat(kdc):** `iron-kdc-ctl export-keytab <principal> <output-file>`
  (#8) -- exposes the existing keytab-write code (built for #5, never
  had a CLI command in front of it) so a service principal's key can be
  handed to another daemon without ever transmitting the plaintext
  password. Verified real cross-project interop on two disposable VMs:
  a `host/<fqdn>@REALM` keytab let a real `sshd` authenticate a login
  via GSSAPI SSO (confirmed `Accepted gssapi-with-mic` in sshd's log,
  not a silent publickey fallback); a `cifs/<fqdn>@REALM` keytab let a
  real `rocketsmbd` (sister project) accept a `mount -t cifs -o
  sec=krb5` session with md5-verified 64 MiB read/write -- the first
  verification of `iron-kdc`'s Kerberos implementation against a GSS
  acceptor that isn't `iron-ldap` itself or MIT krb5's client tools.
  macOS LDAP/krb5 bind carved out to a separate issue (#22), deferred
  rather than tested on a daily-driver Mac.

## [v0.8.0] — 2026-07-08

### 2026-07-08 (post-v0.7.0)
- **feat(ldap):** SASL/GSSAPI bind (#7) -- `iron-ldap` acts as a GSS-API
  acceptor for the Kerberos V5 mechanism (RFC 4121) inside LDAP's SASL
  bind (RFC 4513 §5.2, RFC 4752): new `gssapi` module (RFC 2743 §3.1
  token framing, AP-REQ/AP-REP handling reusing `iron-kdc`'s own
  Kerberos crypto/message types, RFC 4121 §4.2.6.2 Wrap tokens for the
  security-layer negotiation), plus per-connection `SaslState` in
  `session.rs` tracking the multi-message handshake. Verified against a
  real `ldapsearch -Y GSSAPI` and a full SSSD stack (`id_provider=ldap`
  + `auth_provider=krb5`) on a disposable Fedora VM -- `getent`/`id`/`su`
  all working end to end, `su` obtaining a genuine cached TGT. Found and
  fixed three live interop bugs: an AP-REQ subkey wrongly substituted
  for the AP-REP's own (always ticket-session-key) encryption key; the
  AP-REP not echoing the client's own ctime/cusec (the actual proof of
  mutual auth); and two SSSD-specific config gaps (DNS resolver
  workaround, `ldap_id_use_start_tls = false`). Deliberately out of
  scope: channel binding, delegation, integrity/confidentiality
  security layers for LDAP traffic (StartTLS/LDAPS covers that).

## [v0.7.0] — 2026-07-08

### 2026-07-08 (post-v0.6.0)
- **feat(dns):** New `iron-dns` crate + `iron-dns-ctl` CLI (#6) --
  publishes `_ldap._tcp`/`_kerberos._udp`/`_kerberos._tcp` SRV
  autodiscovery records into MicroDNS's REST API (not a DNS server or
  protocol implementation of our own). Verified with real tools:
  `dig` against `_ldap._tcp.g8.lo` resolves the live il1/il2/il3
  deployment; a real `kinit` with `dns_lookup_kdc=true` and no explicit
  `kdc=` line discovered a throwaway KDC purely via the published
  `_kerberos._udp`/`_tcp.g8.lo` SRV records and obtained a genuine TGT.

## [v0.6.0] — 2026-07-08

### 2026-07-08
- **feat(crypto):** Kerberos 5 AES key derivation + encryption
  (`iron_crypto::kerberos`, #5) -- n-fold (RFC 3961), RFC 3962
  (aes128/256-cts-hmac-sha1-96) and RFC 8009
  (aes128/256-cts-hmac-sha{256,384}) enctypes, verified byte-exact
  against both RFCs' published test vectors. Found and documented two
  more FIPS PBKDF2 constraints along the way: minimum iteration count
  (1000) and minimum salt length (16 bytes) -- the latter is why
  `iron-kdc` always sends an explicit salt via PA-ETYPE-INFO2 rather
  than relying on a client-computed default.
- **feat(kdc):** New `iron-kdc` crate (#5) -- a from-scratch Kerberos 5
  KDC over `rasn-kerberos` (MIT/Apache-2.0, same org as `rasn-ldap`;
  every existing Rust Kerberos crypto/keytab crate is AGPL-3.0 and
  doesn't reach RFC 8009 anyway). AS-REQ/AS-REP with PA-ENC-TIMESTAMP
  pre-auth, TGS-REQ/TGS-REP for service tickets, hand-rolled MIT keytab
  I/O (verified bidirectionally against real `klist -k`/`ktutil`),
  `iron-kdcd` daemon + `iron-kdc-ctl` admin CLI, systemd unit.
  Cross-realm ticket decryption uses the presented ticket's own
  issuer (not always this realm's krbtgt), the structural piece
  referral chaining needs -- model-correct per D8, not live-tested
  beyond one realm (D10, no second realm/partition deployed yet).
  **Verified against real MIT krb5 tools** (`kinit`, `kvno`, `klist`):
  obtained a real TGT and a real service ticket end-to-end. Two real
  interop bugs found and fixed via live `kinit` + `gdb` + reading the
  actual krb5 1.22.2 source: PA-ETYPE-INFO2 must be one PaData
  covering every enctype (not one per enctype), and
  KDC_ERR_PREAUTH_REQUIRED's method-data needs a bare PA-ENC-TIMESTAMP
  marker entry alongside PA-ETYPE-INFO2 or the client never attempts
  the mechanism at all.

## [v0.5.0] — 2026-07-07

### 2026-07-07 (post-v0.4.0)
- **feat(ldap):** rootDSE now exposes the AD-shaped naming context
  attributes called for in #4's acceptance criteria --
  `defaultNamingContext`, `configurationNamingContext`,
  `schemaNamingContext`, `rootDomainNamingContext` -- alongside the
  existing `namingContexts`. New `PartitionRegistry::root_domain_partition`
  (the forest's `Domain`-kind partition with no superior).

## [v0.4.0] — 2026-07-07

### 2026-07-07 (post-v0.3.0)
- **feat(deploy):** Rolled the live il1/il2/il3 redundant deployment to
  v0.3.0 and enabled authenticated bind there: each node now has
  `/etc/iron-ldapd/fips.cnf` (activates the FIPS provider) and
  `OPENSSL_CONF` pointing at it. Verified authenticated bind (correct and
  wrong password) through the live `ldap.g8.lo` LB. Updated the Terraform
  cloud-init template to write this from boot for future VM recreates.
- **feat(ldap):** Modify-DN (leaf entries; refuses non-leaf moves with
  `NotAllowedOnNonLeaf`), StartTLS (new `Conn<S>` enum for in-place
  plaintext→TLS upgrade), cross-NC referrals (`IRON_LDAP_REFERRALS`),
  and built-in AD-shaped + RFC 2307 posix schema validation on add/modify
  (`ObjectClassViolation` on a missing MUST attribute). All verified with
  real `ldapmodrdn`/`ldapsearch -ZZ`/`ldapadd` against a live instance.

## [v0.3.0] — 2026-07-07

### 2026-07-07
- **feat(deploy):** LDAP redundancy: 3 dedicated VMs (il1/il2/il3.g8.lo),
  Terraform-provisioned (`deploy/terragrunt/ldap/`, mirrors the etcd
  unit), each running `iron-ldapd` independently against the shared
  fastetcd cluster (`etcd.g8.lo`) — no coordination between replicas,
  iron-ldap is stateless. Single endpoint `ldap.g8.lo:389` via a
  MicroDNS health-checked LB (`deploy/dns/ldap-lb.sh`) probing
  `iron-ldapd`'s real `/health`. Verified real `ldapsearch` against the
  LB name and each node; stopped one node's service and confirmed
  queries via the LB name kept succeeding, then restarted it.
- **chore:** Made the irondirectory repo **public** (matching fastetcd/
  rocketsmbd), resolving the RPM-distribution gap above — cloud-init's
  `dnf install <github release url>` needs anonymous access to the
  release asset, which a private repo doesn't allow. Scanned full git
  history for secrets first (clean: only placeholder token strings, no
  real credentials or private keys). Confirmed the release RPM is now
  fetchable anonymously.

## [v0.2.0] — 2026-07-07
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
