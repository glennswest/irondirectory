# CLAUDE.md — irondirectory

Project-specific context. Cross-project rules live in the parent `CLAUDE.md`.

## What this is

A FIPS-compliant, Active Directory–compatible identity provider in Rust, built
on `fastetcd`. The directory + KDC + DNS half of an AD-compatible DC; sister to
`rocketsmbd` (the SMB half). See `docs/ARCHITECTURE.md` for the decision record.

## Version

`0.23.0` — Phase 2 underway: #20 (Windows Add-Computer join + login;
macOS `dsconfigad` bind) still open, but substantial live-tested
progress this pass, all found by driving a REAL macOS client
(`glenns-mac-mini.g8.lo`, 192.168.8.100) against a fresh test forest
(`ironwintest`, realm `IRON.G8.LO`) and reading `log stream`/KDC-log
traces side by side with RFC 4120/4121/4752/3062: rootDSE was missing
`supportedSASLMechanisms`/`supportedCapabilities`/several AD-shaped
attributes (`dsconfigad` won't even attempt a bind without them); RFC
3062 Password Modify extended op implemented (how `dsconfigad` sets a
new computer account's Kerberos key over LDAP); TGS-REP wasn't
honoring the client's Authenticator subkey (RFC 4120 §5.5.1/§7.5.1 --
always used the TGT session key + usage 8, but the client always
supplies a subkey requiring usage 9, so the reply was undecryptable);
and the GSSAPI SASL security layer only ever offered integrity, never
confidentiality (RFC 4121 §4.2.4) -- `dsconfigad` accepts an
integrity-only bind, then fails with `GSS_S_BAD_QOP` the moment it
tries to seal the write that sets the new computer's Kerberos key.
Confidentiality is now implemented in `gssapi::wrap`, reusing
`kerberos::encrypt`/`decrypt` as the AEAD primitive. A live KDC debug
harness (two throwaway `eprintln!` instrumentation passes, both
removed before this commit) also re-tested the long-suspected "client
sometimes fails to decrypt an otherwise-valid AS-REP/TGS-REP"
flakiness from #20/#23: every server-side self-test (encrypt then
immediately re-decrypt the exact bytes sent) succeeded, and a new
`fresh_ctx_repro.rs` (6000+ runs) found zero concurrency failures in
`iron_crypto` -- current evidence points at client-side
(`opendirectoryd`) timing/probing nondeterminism, not a server defect,
so it's not being chased further right now. The bigger, confirmed
blocker for #20's *Windows* half: `iron-rpc` only supports
unauthenticated RPC binds, and `SamrSetInformationUser2` (setting a
computer account's password/Kerberos keys) needs an authenticated
(NTLMSSP/Schannel) bind's session key to decrypt the wire-encrypted
password material -- next up.

Previous: `0.22.0` — Phase 2 underway: #23 native Rust domain-join + login
simulation harness CLOSED (filed mid-session, not part of the
original #17-#22 backlog, after the user asked for "an accurate
simulation of windows server joining domain, and normal pc's joining
domain, so we can do scale testing"). New `iron-simulate` crate:
`iron-simulate join <count> [prefix]` / `login <count> <user> <pass>`
drives N concurrent full realistic sequences — LSARPC → SAMR →
(harness-only secret provisioning, standing in for real
`SamrSetInformationUser2`) → NETLOGON → Kerberos AS-REQ → TGS-REQ →
PAC-buffer verification — reusing `iron-rpc`'s NDR/PDU primitives for
the RPC client side and a brand-new from-scratch Kerberos *client*
(`krb_client.rs`; nothing in this workspace previously spoke Kerberos
as a client) built on the same `rasn`/`rasn-kerberos`/`iron_crypto`
foundation the server side uses. Found and fixed three real bugs live
(a hardcoded placeholder partition id silently reading/writing the
wrong etcd keyspace, a missing NDR alignment pad in the client's own
NETLOGON encoder mirroring an earlier server-side fix, and a
principal-name double-realm-append), plus one substantive one that
consumed most of the debugging time: `simulate_join`/`simulate_login`
were **re-deriving** the service principal's Kerberos key from
`service_password` + a *guessed* salt (`principal@realm`) to decrypt
the service ticket and check its PAC — but `principal::set_password`
always generates a fresh **random** salt unrelated to the principal
name, so the guessed salt silently produced the wrong key and failed
ticket decryption with a HMAC mismatch that read exactly like a real
crypto bug. Burned a long detour chasing it as a `FipsContext`-reuse/
OpenSSL-FIPS-provider issue (isolated two *genuine*, separately
confirmed FIPS provider constraints along the way — PBKDF2 needs a
password >= 8 bytes and a salt >= 16 bytes, both now covered by
`iron_crypto::kerberos` regression tests — but neither explained the
live failure) before re-reading `join.rs` closely enough to see the
actual bug: fixed by having the harness read the service principal's
*stored* key directly (mirroring how the KDC itself looks up a
principal's key) instead of re-deriving it. Verified end-to-end on
dev.g8.lo against live `iron-rpcd`/`iron-kdcd`: single join/login both
succeed with correct PAC buffers; a 25-concurrent-join scale run
surfaced **real, not-yet-fixed concurrency bugs** under load (RPC
`FAULT_UNK_IF` faults and a store read-after-write race — "no such
account after creation" — both intermittent, ~40% failure rate at
concurrency 25, 0% at concurrency <= 5) — exactly the class of finding
this harness was built to surface; not fixed in this pass, filed as #24.

Previous: `0.21.0` — Phase 2 underway: #19 SAMR/LSARPC/NETLOGON over DCE-RPC
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

## Last session (2026-09-27)

Issue triage done (#20/#21/#22/#24 still real; P1/P3/P3/P2). Docs refreshed
three times; the third pass filed #27 (substring/ordering filters match
nothing) and #28 (ARCHITECTURE D2's USN/persistent search/leases aren't
built). Earlier passes filed #26 (fastetcd mTLS) and added
`docs/CONFIGURATION.md`. Nothing in progress. Next: #20 (kpasswd/464 for
macOS; Schannel auth + `NetrServerPasswordSet2` for Windows) or #25
(operator golden + `iron-bootstrap`).

## Done (2026-09-28): #29 P0 build time on dev

Not compile time: a clean `cargo build && cargo test` is 31 s on dev
(`docs/build-timings/`). The long jobs were `iron-bootstrap`'s live test
waiting for fastetcd for ever (now 30 s) and `cargo test` crashing without
`OPENSSL_CONF` (now set by `.cargo/config.toml`).

## In progress (2026-11-10): #22 macOS light path (LDAPv3 plugin + Kerberos)

Needs a real Mac, which this VM cannot reach; per the owner's #20 decision
the owner runs the Mac side against the #25 stack. This pass:
- [x] `test/macos-ldap-e2e.sh`: the RFC2307-mapping lookups, LDAP bind auth
      and kinit, against real iron-ldapd/iron-kdcd (server half). PASS at
      7ea42cd. It found #58 (userPassword hash returned to anonymous
      searches that name it), fixed in 7ea42cd.
- [x] `docs/MACOS-LDAP-KERBEROS.md`: the runbook (provisioning + Mac steps;
      Mac steps not yet run on a Mac).
- [x] Filed #56: LDAP userPassword and Kerberos keys are separate passwords.
- [ ] Hand the Mac steps to the owner once a stack is reachable: #22 is
      `--after irondirectory#25`; then `wait-owner --action` with section 4
      of the runbook.

## Done (2026-10-06): #27 LDAP filters

Every RFC 4511 filter kind is evaluated by `crates/ldap/src/filter.rs`
(three-valued; AD bitwise rules; unknown rules Undefined), shared with
iron-gc; the size limit counts returned entries. `test/ldap-filters-e2e.sh`
checks each kind with real `ldapsearch` on iron-ldapd and iron-gcd.

## In progress (2026-11-10): #20 -- owner decided (issue comment)

macOS: wait for the golden + operator (#25); the owner runs dsconfigad from
the Mac against that. kpasswd/464 is already done and verified.
Windows: build the real path; test against a networked Windows VM
(stormrdp#18). This pass, buildable and verifiable here with impacket:
- [x] Zerologon (CVE-2020-1472) fixes: random server challenge; reject a
      client *challenge* whose first 5 bytes are equal (MS-NRPC 3.1.4.1 /
      Samba -- not the credential); NetrServerPasswordSet2 only over a
      Schannel binding; refuse an unencrypted length/confounder.
- [x] `iron_crypto::aead`: AES-128-CFB8 encrypt/decrypt with an IV.
- [x] `schannel.rs`: NL_AUTH_SHA2_SIGNATURE sign/verify, seal/unseal
      (known-answer vectors from impacket 0.13.1 `nrpc.SIGN`/`SEAL`).
- [x] `pdu.rs`: sec_trailer + auth_value on bind/bind_ack/request/response; bind_nak.
- [x] Netlogon Schannel (auth_type 68) bind via NL_AUTH_MESSAGE; secure
      channels per computer name across connections (in memory).
- [x] NetrServerPasswordSet2 (opnum 30): authenticator chain, NL_TRUST_PASSWORD
      decrypt, NTOWF + Kerberos keys (`IRON_RPC_REALM`).
- [x] `test/netlogon-schannel-e2e.sh`: impacket at PKT_INTEGRITY and
      PKT_PRIVACY, response signatures checked independently, kinit with the
      new password. **PASS on sc-build at e12514f (2026-11-10).**
Gotchas found: impacket without a domain sends a malformed NL_AUTH_MESSAGE
(flag 0x10 alone + "WORKGROUP\0host\0"); impacket reads each PDU in two
recv calls; MIT krb5.conf needs `REALM = {` on its own line.
Filed for the rest (2026-11-10): #52 CLDAP LDAP ping; #53 iron-rpcd behind
ncacn_np + authenticated SAMR AES password set; rocketsmbd#83 IPC$ pipe
forwarding. Windows VM: stormcentral#465. macOS: after #25.

## Done (2026-10-06): #27 LDAP filters

Every RFC 4511 filter kind is evaluated by `crates/ldap/src/filter.rs`
(three-valued; AD bitwise rules; unknown rules Undefined), shared with
iron-gc; the size limit counts returned entries. `test/ldap-filters-e2e.sh`
checks each kind with real `ldapsearch` on iron-ldapd and iron-gcd.

## Waiting on the owner (2026-10-06): #20

macOS half, server side done and verified on dev (`test/kpasswd-e2e.sh`):
kpasswd/464 (RFC 3244) in iron-kdc, checked with real MIT `kpasswd` (v1,
UDP+TCP) and impacket set-password (0xff80) on a computer created with
`ldapadd`, as `dsconfigad` does. Open, both owner calls (asked on #20):
- A real `dsconfigad` run needs the Mac (no access from this VM) and a
  stack it can reach on 88/389/464. The old ironwintest stack on dev was
  a root checkout, which the current rules forbid, so it is gone.
- Windows `Add-Computer` needs SAMR/LSA/NETLOGON over `ncacn_np` (SMB
  named pipes, rocketsmbd), a CLDAP LDAP ping (UDP 389), Netlogon
  Schannel + `NetrServerPasswordSet2` (plan below), and a Windows client
  VM. Proposed: split it out of #20 into separate issues.

## Done (2026-10-06): #24 concurrency failures under `iron-simulate join 25`

Root cause: fastetcd < 1.0.0 served default (linearizable) reads from a
follower's own state (fastetcd#10). Processes reaching `etcd.g8.lo` through
different members missed each other's writes: the harness missed SAMR's new
account, and NETLOGON missed the harness's NTOWF. iron-rpc reported both as
an unlogged `FAULT_UNK_IF`. `test/rpc-concurrency-e2e.sh` (throwaway
three-member cluster, daemons on member 1, harness on member 2) reproduces
it on v0.8.1 ("has no netlogonntowf" -> `STATUS_ACCESS_DENIED`) and passes
on v1.2.0. Fixed here: iron-rpc names its failures; iron-store retries reads
answered `UNAVAILABLE`. **The shared dm1/dm2/dm3 cluster is recorded as
v0.8.1. Upgrade it to >= 1.0.0 before anything runs against it again.** (It
didn't answer from dev on 2026-10-06.)

## Waiting on stormcentral#78 (2026-10-06): #25 irondirectory golden + iron-bootstrap

1. `crates/bootstrap` (`iron-bootstrap`): done (create-only forest registry,
   base entry, krbtgt, administrator; stays resident). `test/bootstrap-e2e.sh`.
2. The golden. **Owner decision (2026-09-28): `fips-base` golden + an
   `irondirectory` copy-on-write clone of it** (the four daemons, gnu/ossl
   dynamic; `/usr/bin/fastetcd` copied from the fastetcd golden; `fips.cnf`).
   Fedora's fips.so is not CMVP-certified (#30); UBI later.
   - [x] stormcos#172 implements both in `deploy/build-goldens.sh` (reads only
         `deploy/golden/fips.cnf` from here) and runs `test/golden-e2e.sh`
         in its stage harness: PASS on irondirectory@d4f7128.
   - [x] Removed `deploy/golden/build-root.sh` + `fastetcd.ref` (they built
         their own root and fastetcd, diverging from the decision).
   - [x] stormcentral#78 closed 2026-11-07: `irondirectory` (special) and
         `dirop` are in stormcentral's *seed*, but the live registry
         (`component list`) has neither until the master runs
         `component add`. `fips-base` has an image (golden-fips-base-4eec6688a200).
   - [ ] 2026-11-07: `component stage irondirectory` FAILS: the fastetcd
         input golden is mounted `Permission denied` for the build
         (`/build/in/<id>/fastetcd/`), so the recipe finds no fastetcd.
         Filed stormcentral#1311 (auto-filed stormcos#685); #25 proposed
         `--after stormcentral#1311`. `--no-wait` stages showed "passed" with
         no image, which is why this was hidden. Master noted for the live
         `component add irondirectory` / `dirop`. Re-run with
         `stormcentral component stage irondirectory` (no `--no-wait`, to see
         the output).
   - [ ] 2026-11-10: stormcentral#1311 fixed (afcaebd); the input now
         mounts. The stage (build 64c339f5fa96) now stops in stormcos's
         recipe: "this box is Fedora 44, fips-base is 43". stormcos's fix
         (fips-base to F44, or build the daemons against fips-base's root),
         tracked on stormcos#685. #25 proposed `--after stormcos#685`.
         Nothing to change here: the contract (gnu/dynamic, fips.cnf,
         test/golden-e2e.sh) is release-agnostic.
   - [x] 2026-11-10: stormcos#685 fixed (fips-base moved to Fedora 44,
         stormcos 29f4526). `component stage irondirectory` PASSED: image
         **golden-irondirectory-8e3810032552** (irondirectory@ac223d8, clone
         of golden-fips-base-3edb59c45a64, fastetcd 37343ace6c, Fedora 44,
         192M), release request stormcos#917. The production stage does not
         run test/golden-e2e.sh (only stormcos's stage-build.sh harness does,
         which passed on F44 in stormcos#685); no tool hands a sealed root to
         sc-build, so the in-pod check is the image's acceptance.
   - [x] 2026-11-10: the master ran `component add irondirectory` / `dirop`
         (stormcentral#1331 closed). `component list`: irondirectory special,
         golden-irondirectory-10c5f5f1433a (irondirectory@eec670f, fastetcd
         37343ace6c, Fedora 44). operator#1 no longer waits on #25.
   - [ ] The in-pod acceptance: irondirectory-operator#1's live short/medium
         test runs this golden in a pod; that closes #25. operator#1 waits on
         stormcos#922 (image.toml carries neither irondirectory nor dirop).
         #25 is `--after irondirectory-operator#1`. Nothing left to change here.

## Done (2026-11-07): #21 federation test matrix

`test/federation-scale-e2e.sh` passes on a build VM (dd01d4d): 25 children on
two clusters (GC, referral + chase to each, add/delete in ~130 ms); a
100-forest GAL converged in 486 ms, no krb* attribute crossing, add staleness
max 204 ms, delete max 118 ms. The rest was capability, split out: #46
transitive trust, #47 teardown/re-parenting, #48 OIDC brokering; Windows AD
interop with #20. Found #45 (anonymous LDAP writes, P1) -- when fixed, this
script's anonymous `ldapadd`/`ldapdelete` need a bind.

## Done (2026-11-08): #31 iron-crypto SIGSEGV without FIPS

OpenSSL's ssl config module (`ssl_conf`, in Fedora's system openssl.cnf)
crashed in `ssl_module_init` when contexts were loaded on several threads
at once. `FipsContext` creation and freeing now hold a process-wide lock.
`crates/crypto/src/lib.rs` tests reproduce it (10/10 aborts before the fix).

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
      Fedora's `fips.so` (the RHEL provider code, but not the CMVP-certified build, #30); see `docs/FIPS.md`.
- [x] fastetcd connection harness (etcd v3 gRPC client, mTLS) (#2) —
      `crates/store` (`iron-store`): `connect()` (plaintext or mTLS from a
      `ClusterRef`) + partition-scoped put/get/scan/watch on `iron_partition`
      keys. Plaintext path verified against the live dm1/dm2/dm3 cluster
      (`tests/live_cluster.rs`, put/get/scan/watch all pass). mTLS path
      verified against a throwaway single-node instance (client identity
      required and honored correctly by `iron-store`'s side) — but found
      **fastetcd didn't enforce `--client-cert-auth`** (writes succeeded
      with no client cert); filed as fastetcd#6, fixed upstream in v0.8.1
      (2026-07-07). `test/mtls-e2e.sh` (#32) checks enforcement and the
      mTLS round trip on the fastetcd the tests pin. The live cluster is
      still plaintext; what keeps the daemons on plaintext now is #26
      (every binary builds a plaintext `ClusterRef`), not fastetcd.

## Live infrastructure

Moved to [docs/live-infrastructure.md](docs/live-infrastructure.md) (CLAUDE.md is loaded into every session; its size made the session's context thrash). Nothing was dropped. Not loaded by default: `grep -n '^##' docs/live-infrastructure.md`, then read only the section you need. Write new intentions and progress there, not here.

## Notes

- fastetcd lives at `../../project*/fastetcd` style sibling paths; it is etcd v3
  wire compatible (use the `etcd-client` crate or fastetcd's own client).
- Cross-project: an end-to-end FIPS posture also requires fastetcd's transport
  crypto to route through OpenSSL FIPS — file against fastetcd, don't fix here.
