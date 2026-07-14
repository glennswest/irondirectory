# CLAUDE.md — irondirectory

Project-specific context. Cross-project rules live in the parent `CLAUDE.md`.

## What this is

A FIPS-compliant, Active Directory–compatible identity provider in Rust, built
on `fastetcd`. The directory + KDC + DNS half of an AD-compatible DC; sister to
`rocketsmbd` (the SMB half). See `docs/ARCHITECTURE.md` for the decision record.

## Version

`0.21.0` — Phase 2 underway: #19 SAMR/LSARPC/NETLOGON over DCE-RPC
CLOSED. New `iron-rpc` crate: hand-rolled MS-RPCE PDU framing + NDR,
real LSARPC/SAMR handlers (`SamrCreateUser2InDomain` writes a genuine
DIT entry with a real allocated `objectSid`), and NETLOGON's
`NetrServerReqChallenge`/`NetrServerAuthenticate3` secure-channel
handshake -- cryptographically verified end to end (independently
recomputed session key + server credential) against a from-scratch
Python harness built on impacket's own NDR/nrpc/samr/lsad modules.
New `iron_crypto::md4` -- a narrow, cited D4 exception (pure Rust, no
`ossl`/FIPS-context involvement) for NTOWF, which MS-NRPC's secure
channel structurally requires even in its AES-negotiated form; the
HMAC-SHA256/AES-CFB8 steps downstream stay fully FIPS-audited (new
`iron_crypto::aead::aes128_cfb8_encrypt`). Found and fixed 5 real wire-
format bugs live (missing union fields, missing NDR array header
words, a mismatched response level, WSTR-vs-pointer confusion, and a
subtle "padding only when the next field needs it" alignment rule).
Unauthenticated `ncacn_ip_tcp` transport only, no real
`SamrSetInformationUser2` password-setting (needs NTLMSSP RPC auth) --
see Live infrastructure below for the full scope and verification
narrative.

Previous: `0.20.0` — Phase 2 underway: #18 Kerberos PAC generation (group SIDs)
CLOSED. New `iron-kdc::pac` module embeds a signed MS-PAC in every
AS-REP/TGS-REP for principals with a provisioned `objectSid` (#17) --
hand-rolled `KERB_VALIDATION_INFO` NDR encoding, verified byte-for-byte
against impacket's independent NDR decoder, with both PAC signatures
(including the RFC 8009 SHA-2 checksum path this project defaults to)
independently re-verified via a from-scratch Python implementation
validated against RFC 8009's own published test vectors. Moved the
`objectSid`/`nTSecurityDescriptor` base64 storage convention from
`iron-ldap::security` into a new `iron-store::binary_attrs` so
`iron-kdc` can read `objectSid` without a circular crate dependency.
See Live infrastructure below for the full verification narrative.

Previous: `0.19.0` — Phase 2 underway: #17 MS schema objects/SID-RID allocation/
`nTSecurityDescriptor` CLOSED. New `iron-partition::sid`/
`security_descriptor` modules (hand-rolled MS-DTYP §2.4.2/§2.4.6
codecs), a real etcd-CAS-backed RID pool (`iron-store::ridpool`), a
`computer` object class, and `iron-ldap`'s new `security` module
auto-stamping `objectSid` + a default `nTSecurityDescriptor` onto
newly-added `user`/`computer`/`group` entries -- exactly like a real
DC does at object creation, not something a client computes. Not the
real ~500-class Microsoft schema or `cn=subschema` publishing (D6
Tier 3, deferred for DRSUAPI replication only); this extends the
project's existing hand-picked schema subset just enough to make
Windows-join-relevant attributes storable and visible. Verified live
against a fresh forest on the shared fastetcd cluster, and found +
fixed two real bugs in the process: rootDSE's `schemaNamingContext`/
`configurationNamingContext` had never actually been reachable for any
real multi-partition forest since #9 (`handle_search` built rootDSE
from `Store`'s own local single-partition routing registry rather than
the loaded forest topology -- the lookup mechanism existed but never
received a registry with more than one partition in it); and, same
root cause, newly-stamped `objectSid`/`nTSecurityDescriptor` never
appeared on new entries because `stamp_security_principal` had the
same bug -- both fixed by consulting `Referrals::topology` first.
Independently verified via a from-scratch Python MS-DTYP decoder (not
reusing any of this project's own code): `objectSid` decodes to the
correct domain-SID-plus-RID form, and the default
`nTSecurityDescriptor` decodes to the expected control flags
(`SE_DACL_PRESENT`/`SE_SELF_RELATIVE`), Domain-Admins owner/group, and
a 2-ACE DACL (Domain Admins `GENERIC_ALL`, Authenticated Users
`GENERIC_READ`). ACE-based authorization enforcement, PAC/SAMR/domain-
join integration are explicitly out of scope (later issues).

Previous: `0.18.0` — Phase 0 done (#1 FIPS crypto, #2 connection harness), Phase 1
underway (#3 DIT layer, #4 iron-ldap CLOSED: rootDSE/bind/search/add/
delete/modify/compare/modify-DN/StartTLS/LDAPS + authenticated bind via
PBKDF2 + cross-NC referrals + AD/RFC2307 schema validation, redundant
deployment live on il1/il2/il3.g8.lo; #5 iron-kdc CLOSED: AS-REQ/AS-REP
+ TGS-REQ/TGS-REP + keytab, verified against real kinit/kvno/klist;
#6 iron-dns CLOSED: LDAP/Kerberos SRV publishing via MicroDNS, verified
with real dig + kinit DNS autodiscovery; #7 SASL/GSSAPI bind CLOSED:
`iron-ldap` as a GSS-API acceptor over Kerberos V5, verified against
real `ldapsearch -Y GSSAPI` and a full SSSD stack -- getent/id/su all
working end to end against real iron-ldap + iron-kdc; #8 RHEL enrollment
+ host keytab CLOSED: new `iron-kdc-ctl export-keytab`, verified real
GSSAPI SSH SSO and real rocketsmbd `sec=krb5` interop against iron-kdc,
macOS bind carved out to #22; #9 child-domain provisioning CLOSED: new
`iron-config` crate persists the PartitionRegistry in the forest
configuration partition, `iron-config-ctl init-forest`/`create-child`/
`show` verified end to end against the live fastetcd cluster --
superior/subordinate links and realm derivation persist and re-load
correctly; #10 referral generation + chasing CLOSED: `iron-ldapd` reads
the #9 registry for referrals, verified with two real servers and a
real `ldapsearch -C` chasing a referral one hop to real data; #11
cross-realm `krbtgt` keys + one-hop referral tickets CLOSED: `iron-kdc`
reads the #9 registry the same way for TGS-REQ referrals, verified
with two real `iron-kdcd` realms and real `kinit`/`kvno` chasing a
referral ticket one hop to a real service ticket; #12 iron-gc CLOSED:
new `iron-gc` crate, a watch-fed Global Catalog aggregator maintaining
a live in-memory partial replica across every domain partition in a
forest (ports 3268/3269), verified with a real two-partition forest and
a real `ldapsearch` seeing entries from both partitions in one search,
plus a live-added and a live-deleted entry both reflected without
restarting the daemon; #13 federated GAL CLOSED: `iron-gcd` now accepts
`IRON_GC_FORESTS` to aggregate several forests' registries into one
process -- the same forest-agnostic engine from #12, no library changes
needed -- verified live with two independent forests, a strict
cross-forest attribute whitelist correctly hiding an internal-only
attribute (`uidnumber`) that a per-forest GC still shows, and a
live-added entry in one forest appearing in the federated view without
restart; #14 OpenShift LDAP identity provider CLOSED: no new code
(Phase 1.5's "ship first" surface) -- `docs/OPENSHIFT-LDAP-IDP.md`
documents the config and reproduces OpenShift's exact search-then-bind
flow against real `il1.g8.lo`, correct password succeeding and a wrong
one failing closed; ad hoc fix found during that pass: `iron-ldap` now
implements RFC 4532's WhoAmI extended operation, deployed to the real
`il1`/`il2`/`il3.g8.lo` fleet via a rolling rpm upgrade and verified
live with `ldapwhoami`; #15 iron-oidc CLOSED: new crate, a FIPS
OAuth2/OpenID Connect authorization server (ES256 ID tokens via a new
`iron_crypto::sign` module) authenticating against the same LDAP
directory, verified with a full live authorization-code-grant run
(login form → code → token exchange → userinfo) including code-replay
rejection, open-redirect protection, and an independent third-party
cryptographic verification of the ID token's signature; #16 SPNEGO
desktop→console SSO CLOSED: no new code (reuses the Tier 1 KDC as-is)
-- `docs/OPENSHIFT-SPNEGO-SSO.md` documents the `RequestHeader` IdP +
`mod_auth_gssapi` proxy pattern and verifies real SPNEGO negotiation
against a real `httpd`/`mod_auth_gssapi` (a third, independent GSSAPI
acceptor beyond `iron-ldap`'s own, #7, and `sshd`'s, #8) using an
`iron-kdc`-issued keytab, confirmed by Apache's own access log showing
the correctly authenticated principal). See CHANGELOG.md for the
running list; Live infrastructure below has the verification details.

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

**RHEL enrollment + host keytab; GSSAPI SSH SSO + rocketsmbd `sec=krb5`
(#8)** — new `iron-kdc-ctl export-keytab <principal> <output-file>`
subcommand: the MIT keytab writer has existed since #5 but never had a
CLI in front of it. Writes every enctype currently stored for the
principal (mirroring a real KDC's `ktadd`), so a service principal's key
can be handed to another daemon without ever transmitting the plaintext
password.

Verified on two disposable Fedora VMs (`deploy/terragrunt/phase1-verify/`,
destroyed afterward): a `host/<fqdn>@REALM` keytab installed at
`/etc/krb5.keytab` let a real `sshd` (`GSSAPIAuthentication yes`)
authenticate a login via Kerberos — confirmed in `sshd`'s own log
(`Accepted gssapi-with-mic for fedora ... fedora@REALM`, not a silent
publickey fallback, since the client's `fedora` account also has an
authorized SSH key). Separately, a `cifs/<fqdn>@REALM` keytab let a real
**rocketsmbd** (the SMB sister project, its own #31-#37 Kerberos work,
built with `--features kerberos`) accept a `mount -t cifs -o sec=krb5`
session — confirmed in rocketsmbd's own log (`kerberos principal
"fedora@REALM" authenticated`), with 64 MiB of md5-verified read/write
over the mount. This is the first real cross-project interop check of
`iron-kdc`'s Kerberos implementation against a GSS acceptor that isn't
`iron-ldap` itself or MIT krb5's client tools — rocketsmbd had already
verified its own Kerberos support against MIT krb5/Samba (its #37); this
proves `iron-kdc`'s tickets are standards-compliant enough for a third,
independently-implemented GSS acceptor to accept them.

macOS LDAP/krb5 bind carved out to #22 — would mean configuring real
directory-services/Kerberos settings on an actual working Mac rather
than a disposable VM, deferred rather than done inline.

**Child-domain provisioning (#9)** — new `iron-config` crate
(`crates/config`): persists the `PartitionRegistry` in the forest
configuration partition. `iron-partition`'s own doc comment already
described exactly what was missing ("The registry is itself persisted
in the forest configuration partition ... this crate provides the
in-memory model and its serialized form") — the `Partition`/
`PartitionRegistry` model (superior/subordinate links, Configuration/
Domain/Schema partition kinds, `resolve()`) was fully built and
unit-tested already, just never wired to storage. Storage shape: one
JSON-blob record per partition at `cn=<id>,<config-dn>` — `Partition`
already round-trips via serde, so no new encode/decode logic was
needed, just `load_registry`/`put_partition` over `iron-store`'s
existing `scan_subtree`/`put_entry`. New `Partition::configuration()`
constructor in `iron-partition` mirrors the existing `Partition::domain()`
(no realm, never a superior).

`iron-config-ctl`: `init-forest` bootstraps a brand-new forest (creates
the configuration partition — which writes its own self-describing
record into its own DIT, matching AD's Configuration NC hosting its own
crossRef object — plus the forest's root domain, both on the same
fastetcd cluster); `create-child` reads the existing registry, registers
a new child domain under an existing parent (defaulting to the parent's
own cluster; `IRON_CHILD_FASTETCD_ENDPOINT` overrides for a dedicated
one), and updates the parent's `subordinates` list so the link is
bidirectional; `show` inspects the live registry (also the tool #9's own
verification used).

Verified on a disposable VM against the real shared fastetcd cluster:
`init-forest` + `create-child`, then a **separate** `show` invocation
(a fresh process, forcing a real load-from-storage rather than reusing
in-memory state) confirmed the parent's `subordinates` list, the
child's `superior` link, and the child's auto-derived realm
(`EMEA.G9DEMO.LO` from base DN `dc=emea,dc=g9demo,dc=lo`) all persisted
and reloaded correctly; a duplicate-id `create-child` was correctly
rejected. Happy-path only (D10): dedicated Raft cluster per naming
context (D8's ideal) is an operational choice via
`IRON_CHILD_FASTETCD_ENDPOINT`, not automated. `iron-ldapd`/`iron-kdcd`
remain single-partition-per-process daemons — making them dynamically
registry-aware (discovering new partitions without a restart) is a
later issue, not #9's scope.

Side effect of this issue's live verification, not iron-config's own
code: found and fixed several `terraform-modules` Proxmox bootstrap
gaps that only surfaced from actually running `terragrunt apply`
end-to-end rather than just documenting the theory — `Datastore.Allocate`
(distinct from `Datastore.AllocateSpace`, needed to read a storage's own
definition before uploading a snippet file), an explicit SDN zone/bridge
ACL path (not just the `SDN.Use` privilege on an ancestor path), and the
requirement that a `privsep=1` token's effective permission is the
*intersection* of the token's own ACL and its owning user's ACL — missing
either one produces a 403 indistinguishable from the grant not existing
at all. Also created a dedicated, snippets-content-only Proxmox storage
(`terraform-snippets`) and a read-only role for the shared Fedora base
image on `local`, closing a real (if narrower) gap of the same shape as
the vm_id incident: `Datastore.AllocateSpace` isn't scoped by content
type, so a token granted `local` for snippets could also touch its
ISOs/vztmpl/import content.

**LDAP referral generation + chasing, one hop (#10)** — `iron-ldapd`
(via a new `AppState::topology: Option<PartitionRegistry>`) optionally
loads the forest's persisted registry (#9) once at startup, gated on
three new `IRON_LDAP_CONFIG_*` env vars, and consults it *before* the
static `IRON_LDAP_REFERRALS` list when generating a referral --
`session.rs`'s `Referrals<'a>` bundles both sources so six handlers
(search/add/delete/modify/compare/modify-DN) didn't each need a second
threaded parameter.

Found and fixed a real correctness bug live, not just a missing
feature: a child domain's base DN is *structurally* a descendant of
its parent's (`dc=emea,dc=g9demo,dc=lo` under `dc=g9demo,dc=lo`), so
the parent's own single-partition `Store` legitimately treats any DN
within its own base DN as "mine" — `get_entry`/`scan_subtree` just
returned `Ok(None)`/"no such object" for an entry that genuinely
exists on the child's cluster, never `StoreError::NoPartitionFor`. The
original registry-driven referral check (`referral_for`, reactive —
keyed off that error) was consequently unreachable for the exact
scenario it was built for. Fixed with a second, *proactive* check
(`session::proactive_referral`): before any local `Store` operation,
if the topology resolves the target DN to a different partition than
the one this instance itself serves, return a `Referral` immediately.
`AppState` now also carries `own_partition_id` so this comparison is
possible. The reactive path still handles genuinely-unrelated sibling
domains correctly on its own — the two are complementary.

Verified live with two real, independent `iron-ldapd` instances (a
disposable parent + child domain, `iron-config-ctl create-child` +
`set-ldap-url` wiring them together) and a real `ldapsearch`: **without**
`-C`, a search under the child's NC returns `result: 10 Referral` +
`ref: ldap://<child>/...`; **with** `-C` (chase referrals), the client
automatically follows it one hop and retrieves the real entry from the
child server — confirmed for both an exact-DN base-object search and a
subtree search rooted at the child's own base DN.

Also found and fixed during the same live pass (a general
`iron-config-ctl` correctness bug, not #10-specific): `init-forest`
re-run against an already-bootstrapped forest used to silently
overwrite the root domain's `subordinates` list back to empty, since it
always wrote a fresh `Partition::domain(...)` rather than checking what
was already persisted — happened while setting up this very test (a
second `init-forest` call wiped the link `create-child` had already
established). `init-forest` now loads the existing registry first and
preserves the root's `subordinates`; new `add-subordinate` command
repairs any registry a pre-fix run already damaged.

Happy-path only (D10): the topology is a snapshot loaded once at
startup, not watched — picking up a topology change (e.g. a new child
domain added after the parent is already running) requires restarting
the parent's `iron-ldapd`. RFC 4511's continuation references (mid-search,
for a subtree search that spans multiple naming contexts) are not
implemented — only a referral for the *entire* operation, sufficient
for the one-hop base-object/subtree-rooted-at-the-child cases verified
above.

**Kerberos cross-realm `krbtgt` keys + one-hop referral tickets (#11)**
— `iron-kdc`'s TGS-REQ handler (`tgs_exchange::referral_tgs_rep`) now
checks a new `AppState::topology: Option<PartitionRegistry>` (the same
#9/#10 persisted registry, loaded via new `IRON_KDC_CONFIG_*` env vars
in `iron-kdcd`) whenever the client's requested realm doesn't match
this KDC's own: if the topology shows a direct (one-hop) trust — a
superior or subordinate partition whose realm matches — and the shared
inter-realm key has been provisioned locally, it returns a referral TGT
for that realm's `krbtgt` (RFC 4120 §3.3.3) instead of failing closed
with `KDC_ERR_S_PRINCIPAL_UNKNOWN`. New `iron-kdc-ctl
set-cross-realm-key <to-realm> <from-realm> <secret>` provisions the
shared key; `Partition.kdc_url` + `iron-config-ctl set-kdc-url` mirror
the existing `ldap_url` pattern for ops/testing visibility (not
consulted for routing — real clients find the next hop via
krb5.conf/DNS SRV records, same as real Kerberos).

The shared inter-realm key needed a real fix, not just a feature: a
plain `set_password` uses a fresh random salt every call, which is
correct for an ordinary principal's own key but wrong for a *shared*
secret — two independent invocations (one per realm's KDC) with a
random salt derive two different keys from the same password, and
referral tickets would never decrypt on the receiving end. New
`principal::set_shared_key` uses a deterministic salt (the principal
name itself, hex-encoded) instead, so both ends derive byte-identical
keys from the same secret.

Found and fixed two more real bugs live, both before any VM existed to
test against (caught by re-reading the code the live test would
exercise, not by the live test itself): first, the original
`set-cross-realm-key <peer-realm> <secret>` design built the principal
name as `krbtgt/<peer-realm>@<IRON_KDC_REALM>`, which cannot name the
same string on both ends of a trust (the "to" realm's own
`IRON_KDC_REALM` *is* the peer name from the other side, not the
issuing realm) — both realms are now explicit command-line arguments,
independent of `IRON_KDC_REALM`, so the identical invocation against
either KDC's store derives the matching key.

Second, found live while provisioning the two-realm test forest: the
fixed command's DN construction (`cn=krbtgt.<to-realm>,<base-dn>`) still
collided with the "to" realm's own ordinary `krbtgt/<realm>@<realm>`
entry on the same store, since the cn was built from the primary/
instance components alone (identical for both) with no realm suffix —
whichever principal was written second silently clobbered the other's
stored key at that DN, breaking the very lookup the referral ticket
depends on. Fixed by including `from_realm` in the cn so a cross-realm
key's DN can never collide with a same-realm principal's.

Verified live with two real, independent `iron-kdcd` instances (a
disposable parent realm `G11REF.LO` + child realm `EMEA.G11REF.LO`,
`iron-config-ctl create-child` wiring them into one forest, real
`krb5-workstation` `kinit`/`kvno` against both) and `KRB5_TRACE`
confirming the full wire exchange: `kinit alice@G11REF.LO` succeeds
against the parent; `kvno testsvc/kdcchild.g8.lo@EMEA.G11REF.LO`
transparently completes a **real two-hop chase** — first TGS-REQ to
the parent KDC returns a referral ticket `krbtgt/EMEA.G11REF.LO@G11REF.LO`
(visible in `klist`), then a second TGS-REQ using that ticket against
the child KDC (found via the test client's `[capaths]`, same mechanism
real MIT krb5 deployments use) returns the real service ticket —
`kvno` reports success end to end. iron-kdc's TGS handler only logs on
error paths today (no success log line), so `KRB5_TRACE`, not the
daemon's own journal, is what actually proves both round trips
happened — worth fixing at some point, not blocking for this pass.

Happy-path only (D10): transitive multi-realm trust-path walking and
shortcut trusts are out of scope — one hop only, matching #10's LDAP
referral scope exactly. The topology is a startup snapshot, not
watched, same limitation as `iron-ldapd`'s referral wiring.

**iron-gc: watch-fed Global Catalog aggregator (#12)** — new crate.
Subscribes to every `Domain`-kind partition in a forest's persisted
`PartitionRegistry` (#9, loaded via new `IRON_GC_CONFIG_*` env vars,
same startup-snapshot bootstrap as #10/#11) and, for each, spawns a
task (`watch::run`) that connects directly to that partition's own
cluster and maintains a live in-memory partial replica
(`aggregate::Aggregate`) — fed by an actual etcd watch stream on that
partition's subtree, not a one-time scan. Watching starts *before* the
initial bootstrap scan so a write racing the bootstrap gets re-applied
(idempotent) rather than permanently missed. Attribute projection (the
"partial" in partial replica) happens at ingest, before an attribute
ever enters the replica — the stricter reading of D9's "no
directory-content leakage" language, and the reason the read path
needs no `userPassword`-style carve-out the way `iron-ldap`'s does: it
was never admitted into the aggregate to begin with. A conservative
default whitelist (`objectclass, cn, uid, mail, displayname, sn,
givenname, uidnumber, gidnumber`), tunable via `IRON_GC_ATTRIBUTES` —
#13's cross-forest GAL will need its own, likely stricter, list.

Serves anonymous bind + read-only search on ports 3268 (plaintext) and
3269 (implicit TLS), matching AD's real GC port convention, over a
small purpose-built connection handler reusing `iron_ldap`'s wire
framing (`conn::Conn`, `framing`), filter matching (`filter::matches`),
TLS acceptor (`tls::build_acceptor`), and rootDSE builder
(`rootdse::build`, unmodified — it already handles a multi-domain
registry correctly by simply omitting `defaultNamingContext` when more
than one `Domain` partition exists, exactly the GC's situation) rather
than reimplementing any of them. No StartTLS on the plaintext port and
no add/delete/modify/compare/modify-DN surface at all — the GC is
read-only and fed exclusively by watch streams, documented
simplifications rather than silently absent.

Verified live against a fresh two-partition forest (`g12gc` parent +
`g12gc-emea` child, bootstrapped the same way as #9's tests) with real
entries seeded via `iron-kdc-ctl set-password` (a convenient way to
write ordinary `Entry` records without needing a running `iron-ldapd`)
and a real `ldapsearch` against `iron-gcd`: a subtree search from the
root sees entries from *both* partitions in one search response;
scoping the search base to the child partition alone returns only that
partition's entry; rootDSE's `namingContexts` lists all three
partitions (both domains + the configuration partition). Critically,
also verified the aggregator is genuinely watch-fed, not a snapshot:
with `iron-gcd` left running throughout, a *new* entry added via
`iron-kdc-ctl set-password` appeared in a subsequent search with no
daemon restart, and deleting an entry directly (`fastetcd-ctl del`)
removed it from a subsequent search just as live — both proven via the
`/health` endpoint's `ready_partitions`/`entries` counters as well as
`ldapsearch` output.

Happy-path only (D10): one process, one forest; the topology (which
partitions exist) is a startup snapshot, same limitation as #10/#11's
`AppState::topology`. Multi-forest aggregation (the cross-forest
federated GAL, #13) and staleness-bound/scale proving are explicitly
out of scope for this issue.

**Federated GAL: multi-forest aggregation (#13)** — `iron-gcd` (#12's
daemon) now accepts an additional `IRON_GC_FORESTS` env var (`;`-separated
`endpoint|partition-id|base-dn` triples, same delimiter convention as
`IRON_LDAP_REFERRALS`) alongside its existing single-forest trio: at
startup it loads *every* configured forest's persisted
`PartitionRegistry` (#9) and merges them (failing loudly on a
partition-id collision between two forests, rather than silently
dropping one's naming contexts), then spawns a watch task for every
domain partition found across all of them into one shared `Aggregate`.

No changes were needed in `iron-gc`'s library code at all --
`aggregate`/`watch`/`session` were already forest-agnostic by
construction (`watch::run` only ever needed a single `Partition` with
its own `ClusterRef`, never asked which forest it belonged to), so
"the same engine powers the GC and the GAL" from #12's own design
comment turned out to be literally true, not just directionally true.
The whole of #13 is new *bootstrap* logic in the binary: load N config
partitions instead of one, merge, watch all of them. The attribute
whitelist mechanism (`IRON_GC_ATTRIBUTES`) is unchanged and doesn't
need a second, GAL-specific knob -- an operator just configures a
stricter list for a cross-forest deployment than for a single forest's
own internal GC, since crossing a forest boundary is crossing D9's
security boundary ("no directory-content leakage").

Verified live with two independent, freshly-bootstrapped forests
(`g13a`/`g13b`, deliberately separate `iron-config-ctl init-forest`
calls, simulating two unrelated organizations) sharing the physical
fastetcd cluster only for this test's convenience -- nothing in the
code cares whether a `ClusterRef` points at the same cluster or a
genuinely different one. Two `iron-gcd` processes running
simultaneously: one configured for `g13a` alone with the default
(broad) attribute whitelist -- a stand-in for that forest's own
internal GC (#12) -- and one configured via `IRON_GC_FORESTS` for
*both* forests with a deliberately strict whitelist (`objectclass,cn,
mail`, omitting `uidnumber`) -- the federated GAL. A real `ldapsearch`
against the first shows `alice`'s full attribute set including
`uidnumber`; the same search against the second shows `alice` *and*
`bob` (proving cross-forest aggregation) but with `uidnumber` absent
from both (proving the stricter whitelist genuinely blocks
internal-only data from crossing the boundary, not just that
aggregation works). With both daemons left running throughout, adding
a brand-new entry (`carol`) directly to forest `g13b`'s cluster made
her appear in the federated GAL's search immediately, no restart --
confirming the watch-fed liveness #12 established holds across a
forest boundary too, not just within one forest's own partitions.

Happy-path only (D10): still one process, snapshot topology (adding a
whole new forest requires a restart, same as adding a new domain
partition within one forest); many-forest scale and staleness-bound
proving remain deferred.

**OpenShift LDAP identity provider (#14, D7)** — no new code; this is
Phase 1.5's "ship first" SSO surface, since `oauth-server`'s built-in
`LDAPPasswordIdentityProvider` needs nothing beyond the plain LDAPv3
simple bind + search `iron-ldap` already implements (#4). Full
configuration (the `OAuth` CR's `identityProviders[].ldap` block, the
RFC 2255 `url` syntax, TLS options) is in
`docs/OPENSHIFT-LDAP-IDP.md`.

Verification here means proving the documented configuration actually
authenticates, since there's no new code to test -- standing up a full
OpenShift cluster to exercise a well-established upstream feature would
be disproportionate to a "ship first, no new code" issue. Instead,
`oauth-server`'s exact two-step mechanism (search for the entry by a
configured attribute, then a second simple bind as the found DN with
the user's typed password) was reproduced directly with `ldapsearch`
against real, already-deployed `il1.g8.lo`: an anonymous search finds a
test `posixAccount`/`inetOrgPerson` entry by `uid`, a bind with the
correct password succeeds, and a bind with a wrong password fails
closed with `Invalid credentials` -- exactly the two outcomes
`oauth-server` depends on to accept or reject a login. The test entry
was removed afterward (`il1`/`il2`/`il3.g8.lo` are a real ongoing
deployment, not a throwaway forest).

Found, in passing, that this deployment doesn't have
`IRON_LDAP_TLS_CERT`/`_KEY` configured (an ops/deployment gap, not a
code gap -- StartTLS/LDAPS have been built and tested since #4), so the
live check used `ldap://` (`insecure: true`); the doc covers the
`ldaps://` path for a hardened deployment. Also found that `ldapwhoami`
fails against `iron-ldap` with "extended operations are not implemented
yet" -- that's RFC 4532's WhoAmI *extended operation*, unrelated to a
plain bind and never used by OpenShift's LDAP IdP, so not a blocker for
this issue; tracked separately.

**RFC 4532 WhoAmI extended operation** — found during #14's
verification: `ldapwhoami` against real `il1.g8.lo` failed with
"extended operations are not implemented yet." Not related to
OpenShift's LDAP IdP (which never issues WhoAmI, only plain binds), but
a real, fixable gap. Each connection now tracks its current RFC 4513
§3 authzId (`session::handle_connection`'s new `bound_identity`
variable), updated on every *terminal* bind outcome (success or
failure, but left untouched mid-SASL-negotiation, checked via
`ResultCode::SaslBindInProgress`) -- `"dn:<dn>"` for a successful
simple bind, `"u:<principal>"` for a successful GSSAPI bind, empty for
anonymous. `handle_bind`/`handle_sasl_bind` now return this alongside
the existing `BindResponse`.

Verified live twice: first against a disposable local `iron-ldapd`
instance (anonymous → `ldapwhoami` prints `anonymous`; correct password
→ `dn:cn=whoamitest,dc=g14ext,dc=lo`; wrong password → the bind itself
still fails, `Invalid credentials`, as before), then deployed for real
via a rolling rpm upgrade (`cargo generate-rpm -p crates/ldap`, `dnf
install` one host at a time) across the actual `il1`/`il2`/`il3.g8.lo`
fleet -- each confirmed `active` and re-verified with both
`ldapwhoami` and a plain rootDSE search immediately after its upgrade,
before moving to the next host. All three were still running a stale
`0.5.0` package from an earlier session; this pass brings them current.

**iron-oidc: FIPS OAuth2/OpenID Connect authorization server (#15)** —
new crate. Implements the authorization code grant (RFC 6749) plus
OpenID Connect Core's ID token/userinfo layer over `axum` (discovery
document, JWKS, `/authorize` login form + code issuance, `/token` code
exchange, `/userinfo`), authenticating against the same LDAP directory
`iron-ldap` serves -- `Store::lookup_by_index` + `get_entry` +
`iron_crypto::pbkdf2::verify_password`, not a second user store.

Filled a real gap first: `iron-crypto` had zero asymmetric-signing
capability (only PBKDF2 + symmetric AEAD/HMAC/Kerberos crypto) despite
`ossl` (the FIPS provider binding underneath it) already exposing
everything needed. New `iron_crypto::sign` module wraps `ossl`'s
`EvpPkey`/`OsslSignature` for ES256 (ECDSA P-256 + SHA-256, RFC 7518
§3.4) -- the FIPS-approved algorithm ID tokens are signed with, same
FIPS-context-required posture as every other operation in the crate.
Had to hand-write the DER-to-JOSE signature conversion (`der_to_jose`/
`jose_to_der` in `sign.rs`): OpenSSL's ECDSA always produces a DER
`SEQUENCE { r INTEGER, s INTEGER }`, but JWS's ES256 requires the fixed
64-byte `R || S` concatenation instead, and `ossl` has no built-in
option to emit that form directly (its only `raw`-signature knobs are
for ML-DSA/SLH-DSA). JWT compact serialization itself
(`crates/oidc/src/jwt.rs`) is hand-rolled on top of `iron_crypto::sign`
rather than pulling in `jsonwebtoken`/`josekit` -- both bundle their
own non-FIPS signing implementations, which would silently break the
FIPS guarantee for exactly the one new crypto operation this issue
needed it for.

`axum` and `base64` are both direct dependencies now but zero *net
new* ones -- both were already compiled transitively (`axum` via
`etcd-client -> tonic -> axum`; `base64` via several existing deps),
just promoted to direct at the versions already resolved. `axum` was
worth it specifically because OIDC needs real routing, query/form/JSON
parsing, and redirects across five endpoints -- past the point where
hand-rolling (as `iron-ldap`/`iron-gc`'s single-endpoint health probes
do) stays proportionate.

Verified live end to end: real user seeded into a fresh partition
(`g15oidc`) via a throwaway `iron-ldapd` (to get a proper PBKDF2
`userPassword` through the real hashing path, then never needed
again -- `iron-oidcd` talks to the same fastetcd partition directly).
`curl` walked the full authorization-code-grant sequence a real
OpenShift `oauth-server`/any OIDC relying party would: discovery +
JWKS fetch, `GET /authorize` rendering a login form with the request's
`client_id`/`redirect_uri`/`scope`/`state`/`nonce` preserved as hidden
fields, a correct-password `POST /authorize` redirecting to the
client's `redirect_uri` with a one-time code + the original `state`, a
wrong password re-rendering the form with an error instead of
redirecting, `POST /token` exchanging the code for a signed ID token +
access token, and `GET /userinfo` with the access token returning the
same claims re-read live from the directory. Also verified the
security-critical negative paths: an unregistered `client_id` (or a
registered one with a mismatched `redirect_uri`) gets a `400`, never a
redirect (the open-redirect protection); replaying the *same*
authorization code a second time correctly fails closed
(`invalid_grant`); an invalid/garbage bearer token is rejected at
`/userinfo`. Most importantly, **independently verified the ID
token's ES256 signature using Python's `cryptography` library** (a
real, standards-compliant ECDSA implementation with zero connection to
this codebase) against the public key published in
`/.well-known/jwks.json` -- confirming the signature is genuinely
spec-correct, not merely self-consistent within `iron-oidc`'s own
verify function; a deliberately tampered signing input was confirmed
to fail that same independent verification.

Happy-path scope (D10): single forest, single issuer, an ephemeral
(non-persisted) signing key generated fresh at every process start --
documented, not silently absent (a restart invalidates every
previously-issued token and the previously-published JWKS). In-memory-
only authorization-code/key state, so this doesn't horizontally scale
past one replica yet. No built-in TLS termination (a plain HTTP
service -- OpenShift's own edge/reencrypt Routes are the intended
place to terminate TLS in front of it, not a gap for that specific
consumer). D9's cross-forest brokering hook is explicitly deferred
(D10) -- this is a single-forest IdP, not a broker.

**SPNEGO desktop→console SSO (#16, D7)** — no new code; reuses the
Tier 1 KDC exactly as built, per D7's own framing ("SPNEGO reuses the
Tier 1 KDC; integration is an external authenticating proxy
(RequestHeader IdP), documented rather than built here"). The IdP-side
mechanism (OpenShift's `RequestHeader` type, trusting a header set by
an external mutual-TLS-pinned proxy) is entirely OpenShift/Apache
configuration with nothing of this project's own to test; the piece
that actually depends on `iron-kdc` is whether a real
`mod_auth_gssapi`-protected proxy accepts tickets/keytabs it issues.
Full config (the `OAuth` CR, the `mod_auth_gssapi` `<Location>` block)
is in `docs/OPENSHIFT-SPNEGO-SSO.md`.

Verified on one disposable Fedora VM (destroyed afterward): real
`iron-kdcd` serving a throwaway realm, a `HTTP/<fqdn>@REALM` keytab
exported via `iron-kdc-ctl export-keytab` (same mechanism #8
established) installed for a real `httpd` + `mod_auth_gssapi`. `curl`
without credentials gets `401`; a real `kinit` against `iron-kdcd`
followed by `curl --negotiate` performs a genuine SPNEGO exchange
(confirmed via the response's `WWW-Authenticate: Negotiate <mutual-auth
token>` header) and gets `200 OK` with the protected content; Apache's
own access log (`%u`) shows the correctly authenticated principal
(`alice@G16SPNEGO.LO`), not `-`; `kdestroy` then retrying falls back to
`401`. This is a third, independently-implemented GSSAPI acceptor
proven interoperable with `iron-kdc` (beyond `iron-ldap`'s own SASL/
GSSAPI bind, #7, and `sshd`'s, #8) -- exactly the one this SSO flow
actually depends on.

Found the same SELinux gotcha as prior sessions' pattern in a new
form: binaries/keytabs copied via `scp` land with the `user_tmp_t`
(or similarly wrong) SELinux context inherited from wherever they were
staged, and silently fail to exec/load under `Enforcing` until
`restorecon`'d -- not a code issue, an artifact of moving files onto a
freshly-provisioned Fedora host outside its normal package-install
path.

**fastetcd backend (D1)** — dedicated 3-node **fastetcd** cluster (NOT upstream
etcd — fastetcd is the system under test; see memory), Proxmox VMs on g8, managed
by Terragrunt + the shared `terraform-modules//modules/proxmox-fedora-vm?ref=v0.2.0`
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
- [x] RHEL enrollment + host keytab; GSSAPI SSO to SSH and rocketsmbd
      `sec=krb5` (#8, CLOSED): new `iron-kdc-ctl export-keytab`
      subcommand (the keytab I/O code has existed since #5 but never
      had a CLI in front of it) hands a service principal's key to
      another daemon as a keytab file without ever transmitting the
      plaintext password. Verified on disposable Fedora VMs: a real
      `sshd` with `GSSAPIAuthentication yes` + a `host/<fqdn>@REALM`
      keytab authenticated a login via `Accepted gssapi-with-mic`
      (confirmed in sshd's own log, ruling out a silent publickey
      fallback); a real `rocketsmbd` (sister project, its own #31-#37)
      built with `--features kerberos` and a `cifs/<fqdn>@REALM` keytab
      accepted a `mount -t cifs -o sec=krb5` session (`kerberos
      principal "fedora@REALM" authenticated`, confirmed in
      rocketsmbd's own log) with md5-verified 64 MiB read/write --
      the first real cross-project interop check of `iron-kdc`'s
      Kerberos implementation against a GSS acceptor that isn't
      `iron-ldap` itself or MIT krb5 client tools. macOS LDAP/krb5 bind
      carved out to #22 (deferred -- would mean configuring real
      directory-services/Kerberos settings on an actual working Mac,
      not a disposable VM).

#### Phase 1 — federation machinery (IN THE BASE, D8/D9/D10)
Built as first-class in the base with **happy-path coverage** so the code paths
are live from day one. Exhaustive proving suites are deferred (see Testing).
- [x] Child-domain provisioning (#9, CLOSED): new `iron-config` crate
      persists the `PartitionRegistry` (already a fully-built,
      unit-tested in-memory model in `iron-partition` -- this issue was
      the missing storage wiring `iron-partition`'s own doc comment
      already called out) in the forest configuration partition, one
      JSON-blob record per partition at `cn=<id>,<config-dn>` --
      `Partition` already round-trips via serde, so no new encode/decode
      logic was needed. `iron-config-ctl` provisions: `init-forest`
      bootstraps a brand-new forest (configuration partition + root
      domain, the config partition writing its own self-describing
      record into its own DIT -- matching AD's Configuration NC hosting
      its own crossRef object), `create-child` registers a new child
      domain under an existing parent and updates the parent's
      `subordinates` list bidirectionally, `show` inspects the live
      registry. Verified on a disposable VM against the real shared
      fastetcd cluster: `init-forest` + `create-child`, then a
      *separate* `show` invocation re-loaded the registry from storage
      and confirmed both the parent→child `subordinates` link and the
      child's `superior` link persisted correctly, plus the realm
      auto-derived from the child's base DN (`EMEA.G9DEMO.LO`) and a
      duplicate-id `create-child` correctly rejected. `Partition::domain`/
      `iron-ldapd`/`iron-kdcd` remain single-partition-per-process for
      now -- making them dynamically registry-aware is a later issue,
      not #9's scope ("create a partition, register it, wire
      superior/subordinate refs"). Also found and fixed, as a
      side-effect of this issue's live verification: `terraform-modules`'
      Proxmox bootstrap docs were missing several permissions
      (`Datastore.Allocate` distinct from `Datastore.AllocateSpace`, an
      explicit SDN zone/bridge ACL path, and the requirement that every
      grant needs both the user AND the token) that only surfaced when
      actually running `terragrunt apply` end to end.
- [x] LDAP referral generation + chasing (one hop) across naming
      contexts (#10, CLOSED): `iron-ldapd` now optionally loads the
      forest's persisted `PartitionRegistry` (#9, `IRON_LDAP_CONFIG_*`
      env vars, a startup-time snapshot) and consults it before the
      static `IRON_LDAP_REFERRALS` list when generating a referral --
      sibling/child/parent partitions provisioned via `iron-config-ctl`
      are referred to automatically, no hand-maintained list to keep in
      sync. Found and fixed a real correctness bug live: a child
      domain's base DN is *structurally* a descendant of its parent's,
      so the parent's own single-partition `Store` always
      "successfully" resolved it locally (returning "no such object"
      for an entry that genuinely exists on the child's cluster)
      instead of ever raising the `StoreError::NoPartitionFor` the
      original (reactive) referral check was keyed off -- the
      registry-driven path was unreachable for its primary use case
      until a new proactive check (consulting the topology before any
      local lookup, not just after a failure) was added. Verified live
      with two real, independent `iron-ldapd` instances (parent +
      child domain) and a real `ldapsearch`: without `-C`, a search
      under the child's NC returns a real `Referral` result + URL;
      with `-C` (chase referrals), the client automatically follows it
      one hop and retrieves the real entry from the child server --
      both for an exact-DN search and a subtree search rooted at the
      child's own base DN. Also fixed, found during the same live
      pass: `iron-config-ctl init-forest`, re-run against an
      already-bootstrapped forest, used to silently wipe the root
      domain's `subordinates` list (new `add-subordinate` repair
      command for anything a pre-fix run already damaged).
- [x] Kerberos cross-realm `krbtgt` keys + one-hop referral-ticket
      routing (#11, CLOSED): `iron-kdc`'s TGS-REQ handler now checks
      the same #9/#10 persisted `PartitionRegistry` (new
      `IRON_KDC_CONFIG_*` env vars) for a direct one-hop trust when the
      client's requested realm differs from this KDC's own, returning
      a referral TGT for that realm's `krbtgt` instead of failing
      closed. New `iron-kdc-ctl set-cross-realm-key` provisions the
      shared inter-realm key with a deterministic salt (`principal::
      set_shared_key`) so two independent per-realm invocations derive
      byte-identical keys -- a plain `set_password`'s random salt would
      have made that impossible. Found and fixed two more real bugs
      before any VM existed to test against: the shared key's principal
      name needed both realms as explicit arguments (not derived from
      `IRON_KDC_REALM`, which can't name both sides of a trust from a
      single environment), and its DN construction collided with the
      "to" realm's own ordinary `krbtgt` entry until `from_realm` was
      folded into the `cn`. Verified live with two real, independent
      `iron-kdcd` realms and real `kinit`/`kvno`: `KRB5_TRACE` confirms
      a genuine two-hop chase -- the parent KDC returns a referral
      ticket `krbtgt/<child>@<parent>`, then the client automatically
      uses it against the child KDC (via `[capaths]`) to get the real
      service ticket. One hop only (D10), same scope as #10's LDAP
      referrals.
- [x] `iron-gc`: watch-fed Global Catalog aggregator (#12, CLOSED): new
      crate, port 3268/3269, subscribes to every domain partition in a
      forest's persisted `PartitionRegistry` (#9) and maintains a live
      in-memory partial replica via real per-partition etcd watch
      streams (watching starts *before* the initial bootstrap scan, so
      a racing write is re-applied rather than permanently missed), not
      a snapshot. Attribute projection (the whitelist) happens at
      ingest, not read time -- the stricter reading of D9's
      no-leakage requirement this same engine will need once #13
      configures it for the cross-forest GAL. Serves anonymous bind +
      read-only search reusing `iron-ldap`'s wire framing/filter/
      rootDSE code, no write surface at all. Verified live against a
      fresh two-partition forest: one `ldapsearch` sees entries from
      both partitions; a partition-scoped search returns only that
      partition's entry; a *new* entry added while the daemon kept
      running (no restart) appeared in a later search, and a direct
      delete was reflected just as live -- proving it's genuinely
      watch-fed, not a one-time snapshot. One forest, one process
      (D10) -- multi-forest aggregation is #13's job.
- [x] Federated GAL: whitelisted-attribute publish per forest → top-level
      read-only address book (#13, CLOSED): `iron-gcd` now accepts
      `IRON_GC_FORESTS` to load and merge several forests' persisted
      registries into one process, watching every domain partition
      across all of them into the same shared `Aggregate` #12 built --
      no library changes needed, since `watch::run` was already
      forest-agnostic. Same `IRON_GC_ATTRIBUTES` whitelist mechanism as
      #12, just configured stricter for a cross-forest deployment; no
      separate GAL-specific knob. Verified live with two independent
      forests: a per-forest GC (broad whitelist) shows an internal-only
      attribute (`uidnumber`); the federated GAL (strict whitelist)
      aggregates entries from *both* forests but correctly omits that
      same attribute from all of them -- proving no cross-boundary
      leakage, not just that aggregation works. A live-added entry in
      one forest appeared in the federated view with no daemon
      restart, confirming watch-fed liveness holds across a forest
      boundary too. One process, snapshot topology (D10) -- adding a
      whole new forest still needs a restart to pick up.

### Phase 1.5 — App SSO (OpenShift + modern apps)  [D7]
- [x] OpenShift **LDAP identity provider** (direct bind) (#14, CLOSED):
      no new code -- `oauth-server`'s built-in LDAP IdP needs only the
      plain simple bind + search `iron-ldap` already has (#4). Full
      config in `docs/OPENSHIFT-LDAP-IDP.md`. Verified by reproducing
      `oauth-server`'s exact search-then-bind sequence with `ldapsearch`
      against real `il1.g8.lo`: correct password succeeds, wrong
      password fails closed. Found this deployment lacks TLS cert/key
      (an ops gap, not code -- LDAPS/StartTLS already work since #4)
      and that `ldapwhoami`'s WhoAmI extended operation isn't
      implemented (unrelated to OpenShift's plain-bind flow, tracked
      separately).
- [x] `iron-oidc`: FIPS OAuth2/OpenID Connect authorization server (#15,
      CLOSED): new crate, authorization code grant (RFC 6749) + OpenID
      Connect Core ID token/userinfo over `axum`, authenticating against
      the same LDAP directory `iron-ldap` serves. New
      `iron_crypto::sign` module fills a real gap (zero prior asymmetric
      signing capability) with ES256 via `ossl`'s `EvpPkey`/
      `OsslSignature`, hand-converting DER ECDSA signatures to JWS's
      fixed `R||S` form since `ossl` has no built-in option for it. JWT
      serialization is hand-rolled on `iron_crypto::sign`, not a JWT
      crate (those bundle non-FIPS signing). Verified live: full
      authorization-code-grant run (login form → code → token exchange
      → userinfo) against a real seeded user, code-replay rejection,
      open-redirect protection (unregistered client/mismatched
      redirect_uri both get `400`, never a redirect), and -- most
      importantly -- the ID token's ES256 signature independently
      verified with Python's `cryptography` library against the
      published JWKS, proving genuine spec-correctness rather than
      self-consistency. Single-forest, ephemeral signing key,
      in-memory-only state, no built-in TLS (D10) -- the D9 cross-forest
      brokering hook is explicitly deferred, not this issue's scope.
- [x] **SPNEGO** desktop→console SSO: RequestHeader IdP + mod_auth_gssapi
      proxy integration docs (#16, CLOSED): no new code, reuses the
      Tier 1 KDC as-is. `docs/OPENSHIFT-SPNEGO-SSO.md` documents the
      `OAuth` CR `RequestHeader` config + `mod_auth_gssapi` proxy.
      Verified real SPNEGO negotiation against a real `httpd`/
      `mod_auth_gssapi` (a third independent GSSAPI acceptor beyond
      `iron-ldap`'s own, #7, and `sshd`'s, #8) using an
      `iron-kdc`-issued keytab -- confirmed by Apache's own access log
      showing the correctly authenticated principal, and a no-ticket
      retry correctly falling back to 401.

#### Phase 2 — Tier 2 Windows/Mac domain join (later)
- [x] MS schema objects, SID/RID allocation, `nTSecurityDescriptor` (#17,
      CLOSED): new `iron-partition::sid` (hand-rolled MS-DTYP §2.4.2 SID
      codec -- deliberately mixed-endianness, distinct from `iron-kdc`'s
      all-big-endian keytab format) and `iron-partition::security_descriptor`
      (MS-DTYP §2.4.6 self-relative `SECURITY_DESCRIPTOR` builder/decoder:
      owner/group = Domain Admins, a 2-ACE DACL granting Domain Admins
      `GENERIC_ALL` and Authenticated Users `GENERIC_READ`). A new
      `iron-store::ridpool` allocates RIDs from a real etcd
      compare-and-swap loop (`Compare`/`Txn`/`TxnOp`), not the existing
      read-then-write-in-one-mutex-guarded-txn pattern `store/index.rs`
      uses -- a RID pool has to stay correct even against a second,
      independent process (e.g. a future SAMR service, #19), so it needs
      genuine CAS, not just in-process serialization. `iron-ldap`'s new
      `security` module auto-stamps `objectSid` + a default
      `nTSecurityDescriptor` onto any newly-added `user`/`computer`/
      `group` entry whose partition has a provisioned `domain_sid` --
      exactly mirroring a real DC assigning both automatically at object
      creation, never something a client computes itself; a silent no-op
      (not an error) for any other objectClass, or for a partition with
      no domain SID yet. Both attributes are fundamentally binary but
      `Entry`'s values are UTF-8-only (a gap flagged since #4's design as
      "out of scope until a concrete need shows up") -- rather than add a
      new `Entry` value variant, they're stored as base64 text and
      decoded to raw bytes only at the LDAP wire-projection boundary.
      `iron-config-ctl init-forest` now also provisions a schema
      partition (`Partition::schema`, mirroring #9's `configuration()`
      constructor almost exactly -- `PartitionKind::Schema` and
      `PartitionRegistry::schema_partition()` already existed since #9,
      but nothing had ever actually constructed one) and generates a
      random `S-1-5-21-a-b-c` domain SID (idempotent -- a re-run
      preserves the existing SID rather than regenerating it); a new
      `set-domain-sid` command lets one be set explicitly. Verified live
      against a fresh forest (`g17sid`) on the shared fastetcd cluster:
      real `user`/`computer` entries added via `ldapadd` came back from
      `ldapsearch` carrying `objectSid`/`nTSecurityDescriptor`, and a
      from-scratch Python MS-DTYP decoder (not reusing any of this
      project's own code) independently confirmed `objectSid` decodes to
      the domain SID plus the allocated RID, and the descriptor decodes
      to the correct control flags (`SE_DACL_PRESENT`/
      `SE_SELF_RELATIVE`), Domain-Admins owner/group, and the intended
      2-ACE DACL. Found and fixed two real bugs live, both the same root
      cause: `handle_search` built rootDSE from `Store`'s own local
      single-partition routing registry rather than the loaded forest
      topology, so `schemaNamingContext`/`configurationNamingContext`
      had never actually been reachable for any real multi-partition
      forest since #9 (the lookup mechanism was already correctly wired,
      it just never received a registry with more than one partition in
      it) -- confirmed by a real before/after `ldapsearch` against
      rootDSE. The identical bug existed in the new
      `stamp_security_principal`, which also consulted `Store`'s local
      registry (always `domain_sid: None`) instead of the loaded
      topology, so newly-stamped attributes silently never appeared on
      any entry despite a real domain SID being provisioned -- fixed
      the same way, by consulting `Referrals::topology` first and
      falling back to the local registry only when no topology is
      configured. Explicitly NOT in scope: the real ~500-class Microsoft
      schema, `cn=subschema` publishing, or DRSUAPI-fidelity schema data
      (D6 places that in Tier 3, deferred/skip -- needed only for
      replication against a real Windows DC, not for Windows-join
      prerequisites); ACE-based authorization enforcement (the
      descriptor is stored and independently verified, not yet
      evaluated to gate anything); Kerberos PAC group-SID population and
      SAMR/domain-join integration are #18/#19/#20.
- [x] Kerberos PAC generation with group SIDs (#18, CLOSED): new
      `iron-kdc::pac` module embeds a signed MS-PAC (`AD-WIN2K-PAC`
      authorization-data, MS-KILE) in every AS-REP/TGS-REP ticket for a
      principal with a provisioned `objectSid` (#17) -- without it, a
      real Windows client accepts the ticket but has no group
      memberships to authorize against. Hand-rolls the one NDR-marshaled
      buffer this needs (`KERB_VALIDATION_INFO`, MS-PAC §2.5 -- pointer/
      conformant-array deferral, the SID's NDR "conformant structure"
      max_count hoisting) rather than pulling in a generic NDR/DCE-RPC
      crate (none exists yet; #19 is where that infrastructure would
      actually earn its keep, same "one shape by hand" approach as
      #17's `sid`/`security_descriptor` modules). Group SIDs come from a
      new `"member"` reverse-index entry added to both `iron-kdc`'s and
      `iron-ldap`'s `IndexSpec`s (indexing happens at write time, by
      whichever tool wrote the group entry). Moved the base64 binary-
      attribute storage convention (`objectSid`/`nTSecurityDescriptor`,
      #17) from `iron-ldap::security` into a new `iron-store::binary_attrs`
      so `iron-kdc` can read a principal's `objectSid` without depending
      on all of `iron-ldap` (which already depends on `iron-kdc` for
      GSSAPI, #7 -- the other direction would have been circular).
      PAC signing (MS-PAC §2.8.2): the server checksum is an HMAC over
      the whole PAC (both signature buffers zeroed) using the ticket's
      own server key; the KDC/privsvr checksum is an HMAC using the
      krbtgt key, but over the server checksum's own signature bytes
      only -- a chained signature, not two independent checksums of the
      same buffer, a detail confirmed against a working reference
      ([impacket](https://github.com/fortra/impacket)'s `krb5.pac`
      `sign_pac`) rather than trusted from memory alone. AES-SHA1
      enctypes (RFC 3962) use MS-PAC checksum types 15/16; the newer
      AES-SHA2 enctypes (RFC 8009, this project's actual default per
      `principal::DEFAULT_ENCTYPES`) reuse their own etype number as the
      checksum type (19/20) -- also confirmed against impacket's
      `krb5.constants.ChecksumTypes` and RFC 8009 §2, not assumed.
      Verified: a real generated PAC parsed byte-for-byte correctly by
      impacket's own independent NDR decoder (`PACTYPE`/`VALIDATION_INFO`/
      `KERB_VALIDATION_INFO`) -- `EffectiveName`/`FullName`/`UserId`
      (RID)/`PrimaryGroupId`/`GroupIds` (RIDs + attributes)/
      `LogonDomainId` (SID) all round-tripped exactly as constructed.
      Signature verification needed going further: this impacket build's
      checksum table has no entries at all for RFC 8009's SHA-2 checksum
      types (19/20, this project's default), so both PAC signatures were
      independently re-verified with a from-scratch Python HMAC-SHA2 KDF
      implementation (stdlib `hmac`/`hashlib` only, not a port of
      `iron_crypto`'s Rust code) -- itself first validated against RFC
      8009 Appendix A's own published test vectors (`Kc` derivation and
      checksum output, both enctypes) before being trusted to verify
      anything, then confirmed the server and KDC checksums on a real
      generated PAC exactly matched what `iron-kdc` produced. No real
      Windows machine exists in this project's test infra to validate
      PAC *acceptance* against (that gap is explicitly #20's, not
      re-litigated here) -- "verified" here means spec-conformant
      structure plus independently-recomputed-correct signatures, not
      "a real Windows DC accepted this ticket." Scope (D10): one
      `KERB_LOGON_INFO` + `PAC_CLIENT_INFO` + the two required
      signatures -- no `PAC_UPN_DNS_INFO`, compound-identity/device
      claims, resource groups, or extra/foreign SIDs; PAC *verification*
      (a resource server checking a PAC's signature) is out of scope,
      this is PAC *generation* only.
- [x] SAMR/LSARPC/NETLOGON over DCE-RPC (#19, CLOSED): new `iron-rpc`
      crate -- a minimal MS-RPCE (DCE/RPC) server: hand-rolled PDU
      framing (`bind`/`bind_ack`/`request`/`response`/`fault`) and NDR
      reader/writer, plus real handlers for LSARPC (`LsarOpenPolicy2`/
      `LsarQueryInformationPolicy2`/`LsarClose`), SAMR (`SamrConnect5`/
      `LookupDomainInSamServer`/`OpenDomain`/`LookupNamesInDomain`/
      `CreateUser2InDomain`/`OpenUser`/`QueryInformationUser2`/
      `CloseHandle`), and NETLOGON's secure-channel handshake
      (`NetrServerReqChallenge`/`NetrServerAuthenticate3`, AES-negotiated
      path only) -- the actual Windows-join handshake. `SamrCreateUser2InDomain`
      creates a genuine DIT entry with a real allocated `objectSid`
      (#17's RID pool), not an in-memory stub. Transport is
      unauthenticated `ncacn_ip_tcp` only (a plain TCP listener) -- real
      Windows `Add-Computer` needs `ncacn_np` (SMB named pipes), which is
      `rocketsmbd`'s territory (the sister project's "SMB half" role),
      not filed as a cross-project issue yet. `SamrSetInformationUser2`
      (real password-setting) needs an authenticated (NTLMSSP) RPC
      bind's session key to decrypt wire-encrypted password material --
      a distinct, large protocol surface explicitly out of scope; new
      `iron-rpc-ctl set-computer-secret` stands in for it during
      testing. NETLOGON's handshake structurally requires a computer
      account's NTOWF (`NT hash = MD4(UTF-16LE(password))`) even in the
      modern AES-negotiated variant -- confirmed as a real, unavoidable
      MS-NRPC requirement (not a design choice this project could route
      around), and approved as a narrow, explicitly cited D4 exception
      (new `iron_crypto::md4`, pure Rust, zero `ossl`/FIPS-context
      involvement so it can't accidentally leak into any FIPS-audited
      path) scoped only to this one legacy interop need -- the HMAC-
      SHA256 session-key derivation and AES-CFB8 credential encryption
      downstream of NTOWF stay fully inside the FIPS boundary via new
      `iron_crypto::aead::aes128_cfb8_encrypt`. Verified end to end
      against real, independent clients on the shared fastetcd cluster
      (no VM needed): Samba's own `rpcclient` confirmed the wire
      framing/wire compatibility bar in principle, and a from-scratch
      Python harness built directly on
      [impacket](https://github.com/fortra/impacket)'s NDR/nrpc/samr/
      lsad modules drove full LSARPC/SAMR/NETLOGON sessions --
      including, for NETLOGON, an independently-recomputed session key
      and server credential proving the secure channel is
      cryptographically genuine, not just wire-shaped. Found and fixed
      five real bugs live: `SamrConnect5`'s `SAMPR_REVISION_INFO`
      response was missing its union tag/Revision fields entirely;
      `SamrLookupNamesInDomain`'s request array was missing 2 of its 3
      NDR header words (conformant-*varying*, not plain conformant);
      `SamrQueryInformationUser2` claimed a response level
      (`UserAllInformation`) far larger than the truncated body actually
      sent, desyncing a real client's generic union decode; MS-NRPC's
      `ComputerName`/`AccountName` parameters turned out to be
      directly-embedded `WSTR` values, not `RPC_UNICODE_STRING`-style
      pointers, discovered only by dumping impacket's own real request
      bytes field-by-field; and, most subtly, NDR alignment padding
      turned out to be inserted only when the *next* field actually
      needs it (a u32/pointer/conformant-array header), not
      unconditionally after every string -- MS-NRPC packs `AccountName`
      directly against a 2-byte `SecureChannelType` field with zero
      padding between them. Explicitly out of scope: authenticated RPC
      bind (NTLMSSP), `ncacn_np`/SMB transport, real password-setting,
      and anything past what a `WorkstationSecureChannel` join needs --
      #20 is where a real end-to-end Windows/macOS join gets attempted
      against whatever of this is reachable.

### Phase 2 — Tier 2 Windows/Mac domain join (later)
- [x] MS schema objects, rootDSE attrs, SID/RID allocation, `nTSecurityDescriptor` (#17, CLOSED — see Live infrastructure below)
- [x] Kerberos PAC generation (group SIDs) (#18, CLOSED — see Live infrastructure below)
- [x] SAMR/LSARPC/NETLOGON over DCE-RPC (the join handshake) (#19, CLOSED — see Live infrastructure below); SYSVOL via rocketsmbd is a separate, not-yet-filed cross-project follow-up
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
