# CLAUDE.md — irondirectory

Project-specific context. Cross-project rules live in the parent `CLAUDE.md`.

## What this is

A FIPS-compliant, Active Directory–compatible identity provider in Rust, built
on `fastetcd`. The directory + KDC + DNS half of an AD-compatible DC; sister to
`rocketsmbd` (the SMB half). See `docs/ARCHITECTURE.md` for the decision record.

## Version

`0.8.0` — Phase 0 done (#1 FIPS crypto, #2 connection harness), Phase 1
underway (#3 DIT layer, #4 iron-ldap CLOSED: rootDSE/bind/search/add/
delete/modify/compare/modify-DN/StartTLS/LDAPS + authenticated bind via
PBKDF2 + cross-NC referrals + AD/RFC2307 schema validation, redundant
deployment live on il1/il2/il3.g8.lo; #5 iron-kdc CLOSED: AS-REQ/AS-REP
+ TGS-REQ/TGS-REP + keytab, verified against real kinit/kvno/klist;
#6 iron-dns CLOSED: LDAP/Kerberos SRV publishing via MicroDNS, verified
with real dig + kinit DNS autodiscovery; #7 SASL/GSSAPI bind CLOSED:
`iron-ldap` as a GSS-API acceptor over Kerberos V5, verified against
real `ldapsearch -Y GSSAPI` and a full SSSD stack -- getent/id/su all
working end to end against real iron-ldap + iron-kdc). See CHANGELOG.md
for the running list; Live infrastructure below has the verification
details.

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

**Authenticated bind rollout (v0.3.0):** the live il1/il2/il3 were
provisioned before authenticated bind existed, so their config had no
`OPENSSL_CONF` — `iron-ldap` correctly failed closed (logged a clear
warning, disabled authenticated bind/password-setting, kept anonymous
bind/search/add/delete/modify/compare working) rather than silently
running without FIPS. Rolling-upgraded to v0.3.0, then gave each node
`/etc/iron-ldapd/fips.cnf` (activates `/usr/lib64/ossl-modules/fips.so`)
+ `OPENSSL_CONF=/etc/iron-ldapd/fips.cnf` in its conf and restarted.
Verified authenticated bind (`ldapsearch -D ... -w ...`, both correct and
wrong password) through the live `ldap.g8.lo` LB. The Terraform
cloud-init template now writes `fips.cnf` + sets `OPENSSL_CONF` from
boot, so a fresh VM recreate gets this without a manual patch step.

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

**iron-kdc (D4/D8, #5)** — `crates/kdc`: Kerberos 5 KDC over the same DIT
`iron-ldap` serves (Kerberos material is extra attributes —
`krbprincipalname`/`krbsalt`/`krbkey` — on the same entries, not a
separate database; not yet wired to LDAP's own `userPassword` flow,
provisioned instead via the new `iron-kdc-ctl` admin CLI). Built on
`rasn-kerberos` (same `librasn/rasn` org/license as `rasn-ldap`) for
message types; crypto (`iron_crypto::kerberos`) and protocol logic are
hand-rolled — every existing Rust Kerberos crypto/keytab crate traces
back to a single AGPL-3.0 codebase and doesn't reach RFC 8009 anyway, so
there was nothing usable to build on for either piece. AES-only (D4) —
RFC 3962 (aes128/256-cts-hmac-sha1-96) and RFC 8009
(aes128/256-cts-hmac-sha{256,384}), verified byte-exact against both
RFCs' published test vectors before ever touching a live client.
AS-REQ/AS-REP with PA-ENC-TIMESTAMP pre-auth, TGS-REQ/TGS-REP for
service tickets, hand-rolled MIT keytab I/O (verified bidirectionally
against real `klist -k`/`ktutil`). Cross-realm ticket decryption looks
up the presented ticket's own issuer rather than assuming it's always
this realm's plain krbtgt — the structural piece referral chaining
needs (D8) — but is model-correct only, not live-tested beyond one
realm (D10: no second realm/partition is deployed yet to chain against).

**Verified against real MIT krb5 client tools** (`kinit`/`kvno`/`klist`,
`krb5-workstation` on dev.g8.lo): obtained a genuine TGT and a genuine
service ticket end-to-end. Found and fixed two real interop bugs this
way (impossible to catch with unit tests alone, since they're about
what a real client actually expects on the wire):
1. `PA-ETYPE-INFO2` must be **one** `PaData` whose value is a `SEQUENCE
   OF` every enctype offered — not one `PaData` per enctype. Diagnosed
   by hand-decoding the DER bytes from an `strace` capture of the live
   UDP response.
2. `KDC_ERR_PREAUTH_REQUIRED`'s `e-data` needs a **bare
   `PA-ENC-TIMESTAMP` marker entry** (type 2, empty value) alongside
   `PA-ETYPE-INFO2`, or the client silently never attempts the
   mechanism at all (`krb5_get_as_key_password`/
   `krb5_c_string_to_key_with_params` confirmed via `gdb` breakpoints
   to never even be called). Root-caused by downloading the real krb5
   1.22.2 source and reading `kdc_preauth_encts.c`'s `enc_ts_get`
   (always responds with `edata=NULL`) against `preauth2.c`'s
   `process_pa_data` dispatch logic on the client side.

Also found and documented two more FIPS `PBKDF2` constraints while
building the crypto layer (same brute-force-against-the-live-provider
method as the earlier minimum-password-length finding, see docs/FIPS.md):
a minimum iteration count of 1000, and a minimum salt length of 16
bytes — the latter is why `iron-kdc` always sends an explicit salt via
`PA-ETYPE-INFO2` rather than relying on the client's guessed default
(a Kerberos principal's default salt, realm+principal name, is
routinely shorter than that for a short realm).

Packaged (`iron-kdcd` + `iron-kdc-ctl` binaries, systemd unit) mirroring
`iron-ldapd`'s pattern; not yet deployed to dedicated redundant
infrastructure (only verified via throwaway instances on dev.g8.lo so
far) — see work plan for whether/when that happens.

**iron-dns (#6)** — `crates/dns`: not a DNS server of our own — MicroDNS
already serves every network this deploys to. `iron-dns`/`iron-dns-ctl`
is a thin publisher: given a domain/realm and target hosts, computes the
right `_ldap._tcp`/`_kerberos._udp`/`_kerberos._tcp` SRV records (RFC
2782, RFC 4120 §7.2.3.2) and pushes them via MicroDNS's REST API,
replacing the one-off shell-script pattern
(`deploy/dns/etcd-lb.sh`/`ldap-lb.sh`) with a real, reusable binary.
Record names are relative to the zone (confirmed against the live g8.lo
zone's existing `_etcd-server-ssl._tcp` records before assuming the wire
shape — MicroDNS supplies the zone's domain suffix itself). Published
real `_ldap._tcp.g8.lo` SRV records for the live il1/il2/il3 deployment
(verified via `dig`) and, for a throwaway KDC instance, real
`_kerberos._udp`/`_tcp.g8.lo` records — then ran real `kinit` with
`dns_lookup_kdc=true` and no explicit `kdc=` line and confirmed it
discovered the KDC purely via DNS and obtained a genuine TGT. The
Kerberos test records were removed afterward (pointed at a throwaway
instance); the LDAP records were kept (real, current infrastructure).

**SASL/GSSAPI bind (#7)** — `crates/ldap/src/gssapi/` (new module) +
`session.rs`: makes `iron-ldap` a GSS-API acceptor for the Kerberos V5
mechanism, wired into LDAP's SASL bind path (`AuthenticationChoice::Sasl`,
previously a stub returning `AuthMethodNotSupported`). `token.rs` hand-rolls
RFC 2743 §3.1's Initial Context Token framing (a fixed byte format, not a
`rasn`-decodable ASN.1 structure) — RFC 4121 §4.1 requires this framing on
*both* the AP-REQ and the acceptor's AP-REP response, overriding RFC 2743's
more general "optional for non-initial tokens" language. `accept.rs`
decrypts the presented AP-REQ's ticket under the target service
principal's own key (looked up via `iron-kdc`'s principal storage, added as
a dependency — same issuer-driven lookup pattern as cross-realm ticket
decryption in `iron-kdc`'s own TGS-REQ handler) and validates the
Authenticator's GSS checksum (type `0x8003`). `wrap.rs` implements RFC 4121
§4.2.6.2 Wrap tokens (without confidentiality) for RFC 4752's
security-layer negotiation — `iron-ldap` always advertises "no security
layer" only (StartTLS/LDAPS covers transport security instead).
`session.rs` tracks per-connection `SaslState` across the multi-message
GSSAPI handshake (AP-REQ → mutual-auth AP-REP → client ack → security-layer
negotiation → success).

Verified against a real `ldapsearch -Y GSSAPI` (real SASL username, real
search results over the negotiated "no security layer" session) — found
and fixed three live interop bugs no amount of unit testing would have
caught, each diagnosed via `tcpdump` + hand-decoding the actual wire bytes
or `KRB5_TRACE`: (1) the AP-REQ's Authenticator can assert a **subkey**
(RFC 4121 §2), which becomes the base key for all subsequent Wrap/Unwrap —
but NOT for the AP-REP's own encryption, which RFC 4120 §3.2.5 is explicit
must always use the raw ticket session key even when a subkey is present
(easy to conflate, since they're adjacent steps in the same exchange); (2)
the AP-REP must echo the client's own `ctime`/`cusec` from its Authenticator
(RFC 4120 §3.2.4), not a freshly generated timestamp — this is literally
the proof of mutual authentication the client checks on receipt.

Then verified the full "SSSD + krb5" half on a disposable Fedora VM
(`id_provider=ldap` + `auth_provider=krb5`, RFC 2307 posixAccount/
posixGroup schema): `getent passwd`/`id` resolve a real POSIX identity via
`iron-ldap`, and `su` (run as a genuinely unprivileged user, not root, to
force a real PAM challenge) prompts for and validates a real password
against `iron-kdc`, caching a genuine TGT (`klist` confirms it). Two SSSD-
specific interop findings, neither an `iron-ldap`/`iron-kdc` bug: SSSD's
own async DNS resolver failed to resolve names via `systemd-resolved`'s
stub listener (127.0.0.53) against MicroDNS — worked around with a direct
`/etc/resolv.conf` entry, plus `lookup_family_order = ipv4_only`; and SSSD
defaults to requiring StartTLS for a plain `ldap://` URI unless
`ldap_id_use_start_tls = false` is set explicitly (this test instance has
no TLS cert configured).

Deliberately scoped out (documented, not silent): channel binding
verification, delegation (`GSS_C_DELEG_FLAG`), and integrity/
confidentiality security layers for LDAP traffic itself.

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
- [x] `iron-ldap` (#4, CLOSED): LDAP v3 server, all acceptance criteria
      met, including v0.5.0's last fix (rootDSE `defaultNamingContext`/
      `configurationNamingContext`/`schemaNamingContext`/
      `rootDomainNamingContext`, not just `namingContexts` — config/
      schema partitions aren't provisioned yet, so those two stay absent
      until #9/#17 land, but the mechanism picks them up automatically).
      anonymous + **authenticated** bind
      (PBKDF2 via the FIPS provider, D4 — 210k iterations/SHA-256, fails
      closed if FIPS isn't active; found the provider enforces an
      undocumented 8-byte minimum password length), search (base/one/
      subtree scope, core filters), add, del, **modify** (add/delete/
      replace), **compare**, **modify-DN** (leaf entries; refuses
      non-leaf moves with the standard `NotAllowedOnNonLeaf`, not a
      stub), **StartTLS** (new `Conn<S>` enum for in-place plaintext→TLS
      upgrade) + **LDAPS via OpenSSL** (pinned to NIST curves
      P-256/P-384/P-521, not OpenSSL's default TLS1.3 hybrid-PQC group),
      **cross-NC referrals** (`IRON_LDAP_REFERRALS`, real `Referral`
      result code + LDAP URL), **AD-shaped + RFC 2307 posix schema
      validation** (`crates/ldap/src/schema.rs`, `ObjectClassViolation`
      on a missing MUST attribute) — all verified with real
      `ldapsearch`/`ldapadd`/`ldapmodify`/`ldapcompare`/`ldapdelete`/
      `ldapmodrdn` (incl. over `ldaps://`, `-ZZ` StartTLS, and
      authenticated bind) against a live instance and the redundant
      `il1/il2/il3` deployment. **Remaining (deliberately out of scope
      for this pass):** subtree rename (moving a non-leaf entry), other
      extended ops besides StartTLS, full schema-subentry publishing
      (`cn=subschema`) — schema is enforced but not yet discoverable by
      clients that query it
- [x] `iron-kdc` (#5, CLOSED): Kerberos KDC. AS-REQ/AS-REP with
      PA-ENC-TIMESTAMP pre-auth, TGS-REQ/TGS-REP, AES-only enctypes
      (RFC 3962 + RFC 8009, verified against published test vectors),
      keytab I/O (verified against real `klist -k`/`ktutil`), realm-per-
      partition with cross-realm ticket-issuer lookup (model-correct,
      D8; not live-tested beyond one realm, D10). Verified against real
      `kinit`/`kvno` -- found and fixed two live interop bugs
      (PA-ETYPE-INFO2 shape, missing PA-ENC-TIMESTAMP marker) that no
      amount of unit testing would have caught. **Remaining (deliberately
      out of scope for this pass):** subtree/replay-cache hardening,
      renewal/forwarding/user-to-user, dedicated redundant deployment
      (only verified via throwaway dev.g8.lo instances so far)
- [x] `iron-dns` (#6, CLOSED): `_ldap._tcp`/`_kerberos._udp`/
      `_kerberos._tcp` SRV record publishing via MicroDNS's REST API
      (not a DNS server of our own). Verified with real tools: `dig`
      against the live `_ldap._tcp.g8.lo` records resolves il1/il2/il3;
      a real `kinit` with `dns_lookup_kdc=true` and no explicit `kdc=`
      discovered a throwaway KDC purely via published SRV records and
      got a genuine TGT.
- [x] SASL/GSSAPI bind path; end-to-end SSSD + krb5 client validation (#7,
      CLOSED): `iron-ldap` acts as a GSS-API acceptor for the Kerberos V5
      mechanism (RFC 4121) inside LDAP's SASL bind (RFC 4513 §5.2, RFC
      4752) -- hand-rolled RFC 2743 §3.1 GSS token framing, AP-REQ/AP-REP
      handling (reusing `iron-kdc`'s own Kerberos crypto/message types --
      the same fundamental operation as TGS-REQ, just as an application
      server instead of a KDC), and RFC 4121 §4.2.6.2 Wrap tokens for the
      RFC 4752 security-layer negotiation (always "no security layer" --
      use StartTLS/LDAPS for transport security). Verified against a real
      `ldapsearch -Y GSSAPI` (real SASL username, real search results) and
      a full SSSD stack (`id_provider=ldap` + `auth_provider=krb5`) on a
      disposable Fedora VM: `getent passwd`/`id` resolve a real POSIX
      identity via `iron-ldap`, and `su` prompts for and validates a real
      password against `iron-kdc`, caching a genuine TGT. Found and fixed
      three live interop bugs unit tests couldn't have caught (see
      Live infrastructure below). **Remaining (deliberately out of
      scope):** channel binding verification, delegation
      (`GSS_C_DELEG_FLAG`), integrity/confidentiality security layers for
      LDAP traffic itself (StartTLS/LDAPS covers this instead).
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
