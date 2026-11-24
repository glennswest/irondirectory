# Configuration, ports and packaging

What each irondirectory binary reads, listens on and ships as, taken from the
code (`crates/*/src/bin/*.rs`, `crates/*/Cargo.toml`, `deploy/systemd/`). All
settings are environment variables. An empty value counts as unset.

## Common to every binary

- **fastetcd connection: plaintext or mTLS (#26).** Every
  `<PREFIX>_FASTETCD_ENDPOINT` (comma-separated for several members) has
  three companions, `<PREFIX>_FASTETCD_CA`, `_CERT` and `_KEY`: PEM file
  paths for the CA that signed fastetcd's certificate and this binary's
  client certificate and key, as fastetcd's `--client-cert-auth` requires.
  Set all three with `https://` endpoints, or none with `http://`
  endpoints; anything else (half the settings, a scheme that doesn't match)
  stops the binary at start rather than falling back to plaintext. The
  prefixes: `IRON_LDAP_FASTETCD`, `IRON_LDAP_CONFIG_FASTETCD`,
  `IRON_KDC_FASTETCD` (iron-kdcd and iron-kdc-ctl), `IRON_KDC_CONFIG_FASTETCD`,
  `IRON_GC_CONFIG_FASTETCD` (every forest in `IRON_GC_FORESTS` too),
  `IRON_OIDC_FASTETCD`, `IRON_RPC_FASTETCD` (iron-rpcd and iron-rpc-ctl),
  `IRON_BOOTSTRAP_FASTETCD`, `IRON_CONFIG_FASTETCD` and `IRON_CHILD_FASTETCD`
  (iron-config-ctl). **The forest registry stores each partition's cluster
  with its TLS paths** (iron-bootstrap and `iron-config-ctl
  init-forest`/`create-child` write them), and iron-gcd, which watches every
  partition the registry lists, reaches each with those paths: mount the
  certificates at the same paths everywhere. (iron-ldapd and iron-kdcd read
  the registry only to build referrals.) `iron-simulate` is a test harness and stays plaintext.
  `test/mtls-e2e.sh` checks it.
- **fastetcd >= 1.0.0.** Every read relies on etcd's default linearizable
  reads. Before 1.0.0 (fastetcd#10) a follower served them from its own
  state, so a process reading through one member missed what another had
  just written through a different one. Under concurrent domain joins this
  was #24. Reads that fastetcd answers `UNAVAILABLE` are retried for
  about 1.5 s; writes are not. `test/rpc-concurrency-e2e.sh` checks this
  against a three-member cluster.
- **FIPS:** `OPENSSL_CONF` must point at a config that activates the OS's
  `fips.so` provider (see [`FIPS.md`](FIPS.md);
  `crates/crypto/testdata/fips-dev.cnf` is an example). `iron-kdcd`,
  `iron-rpcd` and `iron-oidcd` refuse to start without it. `iron-ldapd` starts
  anyway but disables authenticated bind and password-setting.
  `iron-kdc-ctl` needs it for `set-password`/`set-cross-realm-key`.
- Logging: `tracing_subscriber::fmt` at INFO to stdout (the journal under
  systemd). `RUST_LOG` is ignored: the `env-filter` feature isn't enabled.

## Ports

| Binary | Default | Protocol | Setting |
|---|---|---|---|
| `iron-ldapd` | `0.0.0.0:389` | LDAP (+ StartTLS when a cert is set) | `IRON_LDAP_LISTEN` |
| `iron-ldapd` | `IRON_LDAP_LISTEN`'s address, UDP | CLDAP: the LDAP ping only (#52) | `IRON_LDAP_CLDAP_LISTEN` |
| `iron-ldapd` | off (e.g. `:636`) | LDAPS (implicit TLS) | `IRON_LDAP_LDAPS_LISTEN` |
| `iron-ldapd` | `0.0.0.0:8080` | HTTP `/health` (live fastetcd `Status` check) | `IRON_LDAP_HEALTH_LISTEN` |
| `iron-kdcd` | `0.0.0.0:88` | Kerberos, UDP and TCP | `IRON_KDC_LISTEN` |
| `iron-kdcd` | `0.0.0.0:464` | kpasswd (RFC 3244 change/set password), UDP and TCP | `IRON_KDC_KPASSWD_LISTEN` |
| `iron-gcd` | `0.0.0.0:3268` | Global Catalog LDAP, read-only | `IRON_GC_LISTEN` |
| `iron-gcd` | off (e.g. `:3269`) | Global Catalog LDAPS | `IRON_GC_LDAPS_LISTEN` |
| `iron-gcd` | `0.0.0.0:8080` | HTTP `/health` | `IRON_GC_HEALTH_LISTEN` |
| `iron-oidcd` | `0.0.0.0:8080` | HTTP (OIDC endpoints, no TLS, no `/health`) | `IRON_OIDC_LISTEN` |
| `iron-rpcd` | `0.0.0.0:445` | DCE/RPC `ncacn_ip_tcp`; Netlogon secure channel auth | `IRON_RPC_LISTEN` |
| `iron-rpcd` | unset (off) | DCE/RPC `ncacn_np`: a Unix socket rocketsmbd forwards SMB named pipes to (#53) | `IRON_RPC_PIPE_SOCKET` |

SMB itself is rocketsmbd's (it forwards `ncacn_np` pipes to `IRON_RPC_PIPE_SOCKET`).
Not served: a DNS server (SRV records are published into MicroDNS by
`iron-dns-ctl`).

**Three daemons default to 8080** (`iron-ldapd` health, `iron-gcd` health and
`iron-oidcd`). On one host, move all but one of them.

The systemd units for `iron-ldapd`, `iron-kdcd` and `iron-gcd` grant
`CAP_NET_BIND_SERVICE` so they can bind low ports as unprivileged users.
`iron-rpcd` has no unit; `:445` needs that capability or a high port
(testing uses `:13445`).

## iron-ldapd (LDAP v3 server)

| Setting | Default | Meaning |
|---|---|---|
| `IRON_LDAP_FASTETCD_ENDPOINT` | required | fastetcd endpoint |
| `IRON_LDAP_PARTITION_ID` | required | partition this instance serves |
| `IRON_LDAP_BASE_DN` | required | that partition's base DN |
| `IRON_LDAP_LISTEN` | `0.0.0.0:389` | plaintext LDAP |
| `IRON_LDAP_HEALTH_LISTEN` | `0.0.0.0:8080` | health probe |
| `IRON_LDAP_TLS_CERT`, `IRON_LDAP_TLS_KEY` | unset | set both or neither; enables StartTLS on the plaintext port |
| `IRON_LDAP_LDAPS_LISTEN` | unset | also opens an implicit-TLS port (needs cert and key) |
| `IRON_LDAP_REFERRALS` | unset | static referrals, `;`-separated `base-dn\|ldap-url` |
| `IRON_LDAP_CONFIG_FASTETCD_ENDPOINT`, `_CONFIG_PARTITION_ID`, `_CONFIG_BASE_DN` | unset | all three load the forest registry once at startup for registry-driven referrals (checked before `IRON_LDAP_REFERRALS`), multi-partition rootDSE and the LDAP ping |
| `IRON_LDAP_CLDAP_LISTEN` | `IRON_LDAP_LISTEN`'s address and port, on UDP | CLDAP listener for the LDAP ping; `off` opens none |
| `IRON_LDAP_DC_HOSTNAME` | the kernel host name | this DC's DNS name in the ping and rootDSE `dnsHostName`; a name with no dot is taken as a host in the domain; its first label (upper case, 15 characters) is the DC's NetBIOS name |
| `IRON_LDAP_DC_ADDRESS` | the address each ping reached | IPv4 address a `_WITH_IP` ping answer carries |

TLS is pinned to groups P-256/P-384/P-521.

Frame limits (finding 6bbcf7596b07), for iron-ldapd and iron-gcd alike: an
LDAP message is at most 10 MiB (AD's `MaxReceiveBuffer` default) and a SASL
security-layer buffer at most 10 MiB + 1 KiB, the receive size the GSSAPI
security-layer challenge advertises. A larger declared length closes the
connection as soon as its header arrives, before the payload is buffered. A
message that has started must be complete within 120 s, or the connection
is closed; a connection between messages may stay idle. These are constants
(`iron_ldap::framing`), not settings. `test/ldap-frame-limits-e2e.sh`.

The LDAP ping (#52, MS-ADTS 6.3.3) is how Windows finds a DC before it joins
or logs on: a search with base `""`, a filter of `DnsDomain`/`Host`/`User`/
`AAC`/`DomainSid`/`DomainGuid`/`NtVer` terms and the attribute `Netlogon`.
iron-ldapd answers it on CLDAP (UDP; the entry and the done in one datagram)
and over TCP with a `NETLOGON_SAM_LOGON_RESPONSE_EX`: flags PDC, LDAP, DS,
KDC, writable, closest, full-secret, DS_8/9/10 and the DNS-name bits (never
GC or time server), the domain GUID, the forest/domain/DC DNS names, the
NetBIOS names and `Default-First-Site-Name` (there are no sites yet). It is
built from this partition's record in the forest registry, so it needs
`IRON_LDAP_CONFIG_*` and a record with a domain GUID (`iron-bootstrap`
stores one; an older record gets one on its next run). Without them no
CLDAP port opens and a TCP ping is `unwillingToPerform`. A ping naming
another domain gets a done with no entry; a `User` that is unknown,
disabled, or not of a type `AAC` names gets opcode 25 (user unknown). Only
the `_EX` response form is built (`NtVer` with 5EX or 5EX_WITH_IP, which
Windows XP and later and Samba send). CLDAP answers nothing else
(`unwillingToPerform`). `test/cldap-ping-e2e.sh` checks it with Samba's
`net ads lookup` and a decoder written from the spec.

Extended operations (#63), each listed in rootDSE `supportedExtension` only
when it can run: StartTLS (RFC 4511 §4.14, needs the cert/key), Who am I
(RFC 4532), Password Modify (RFC 3062: sets the entry's Kerberos keys, needs
the FIPS provider and an authenticated bind; anonymous gets
`insufficientAccessRights`), Cancel (RFC 3909: a connection's requests are
handled in order, so a Cancel answers `tooLate` for an earlier operation,
`cannotCancel` for a bind/StartTLS/abandon/cancel, `noSuchOperation`
otherwise). Any other request name is answered `protocolError`
"unsupported extended operation <OID>". `test/ldap-exop-e2e.sh` checks each
with `ldapwhoami`, `ldappasswd` and raw BER.

Re-binds (#67): a bind on a connection with a SASL/GSSAPI security layer in
effect (integrity or confidentiality) is read through that layer and answered
through it. A failed bind, a simple or anonymous bind, or a GSSAPI bind that
selects no layer leaves the layer in effect (RFC 4513 §5.2.1.4, RFC 4422
§3.8); a GSSAPI bind that selects a layer replaces it from the next message
on.

Add (#71) creates only: an existing DN is `entryAlreadyExists`, never
overwritten, and the parent must exist (`noSuchObject`, matchedDN the nearest
existing ancestor) unless the entry is a naming context's head. A partition
registered with `iron-config-ctl init-forest`/`create-child` has no head entry
until one is added (`iron-bootstrap` creates its domain's).

Modify-DN (#67) renames or moves an entry with all its descendants. It is
create-then-delete, not one transaction: if a target DN is taken
(`entryAlreadyExists`), the entries it already created are removed again.
It refuses a `newSuperior` that does not exist (`noSuchObject`) or lies
under the entry (`unwillingToPerform`), and a move out of the naming context
or of a subtree holding a naming context's head (`affectsMultipleDSAs`).
`test/ldap-rebind-moddn-e2e.sh` checks both.

The KDC's credential attributes are never written over LDAP (#75): an Add
(attributes or RDN), a Modify (any operation) or a ModDN whose new RDN names
`krbKey`, `krbSalt`, `krbPwdHistory`, `netlogonNTOWF`, `krbPrincipalName` or
`pwdLastSet` (any case, any attribute option) is refused with
`unwillingToPerform` (53), naming the attribute, whoever is bound, and
nothing of it is applied. Keys and principal names are set only by Password
Modify (which derives `krbPrincipalName` from `sAMAccountName`), kpasswd,
`NetrServerPasswordSet2`/SAMR, and the operator tools and iron-bootstrap,
which write the store directly; an inter-realm trust key only by
`iron-kdc-ctl set-cross-realm-key`. The list is `iron_kdc::secret`
(`KEY_ATTRS` is the key-material subset #60 is to hide from searches).
`test/ldap-secret-write-e2e.sh`.

Known gaps (open issues): searches never return `userPassword` (#58), but
`iron-ldapd` and `iron-gcd` still return `krbkey`, `krbsalt` and
`netlogonntowf` to any bind (#60); add/delete/modify/modify-DN are accepted
from an anonymous bind (#45). `iron-rpcd`'s secure channels are per
process, so more than one replica breaks `NetrServerPasswordSet2` (#61).

## iron-kdcd (Kerberos KDC)

| Setting | Default | Meaning |
|---|---|---|
| `IRON_KDC_FASTETCD_ENDPOINT` | required | fastetcd endpoint |
| `IRON_KDC_PARTITION_ID` | required | partition |
| `IRON_KDC_BASE_DN` | required | base DN |
| `IRON_KDC_REALM` | required | realm, e.g. `G10.LO` |
| `IRON_KDC_LISTEN` | `0.0.0.0:88` | bound for both UDP and TCP |
| `IRON_KDC_KPASSWD_LISTEN` | `0.0.0.0:464` | kpasswd, UDP and TCP; `off` disables it. A failed bind stops the daemon, so an unprivileged test run sets a high port |
| `IRON_KDC_CONFIG_FASTETCD_ENDPOINT`, `_CONFIG_PARTITION_ID`, `_CONFIG_BASE_DN` | unset | forest registry: one-hop cross-realm referral tickets, and the domain SID a PAC needs (unset: tickets carry no PAC) |

Enctypes: AES only (RFC 3962, RFC 8009).

## iron-gcd (Global Catalog / federated GAL)

| Setting | Default | Meaning |
|---|---|---|
| `IRON_GC_CONFIG_FASTETCD_ENDPOINT`, `_CONFIG_PARTITION_ID`, `_CONFIG_BASE_DN` | — | one forest's registry |
| `IRON_GC_FORESTS` | unset | more forests, `;`-separated `endpoint\|partition-id\|base-dn` |
| `IRON_GC_LISTEN` | `0.0.0.0:3268` | plaintext GC |
| `IRON_GC_HEALTH_LISTEN` | `0.0.0.0:8080` | health probe |
| `IRON_GC_LDAPS_LISTEN` | unset | implicit-TLS port; needs `IRON_GC_TLS_CERT` and `IRON_GC_TLS_KEY` |
| `IRON_GC_ATTRIBUTES` | `objectclass,cn,uid,mail,displayname,sn,givenname,uidnumber,gidnumber` | whitelist, applied at ingest |

At least one forest must be configured (the trio, `IRON_GC_FORESTS`, or both).
There is no StartTLS on 3268, and nothing is writable.

## iron-oidcd (OAuth2 / OpenID Connect)

| Setting | Default | Meaning |
|---|---|---|
| `IRON_OIDC_FASTETCD_ENDPOINT`, `_PARTITION_ID`, `_BASE_DN` | required | directory to authenticate against |
| `IRON_OIDC_ISSUER` | required | external base URL clients use |
| `IRON_OIDC_CLIENTS` | required | `;`-separated `client_id\|client_secret\|redirect_uri` |
| `IRON_OIDC_LISTEN` | `0.0.0.0:8080` | HTTP listener |
| `IRON_OIDC_LOGIN_ATTRIBUTE` | `uid` | attribute the login name is matched against |
| `IRON_OIDC_CODE_TTL_SECS` | `60` | authorization-code lifetime |
| `IRON_OIDC_TOKEN_TTL_SECS` | `3600` | access/ID token lifetime |

Endpoints: `/.well-known/openid-configuration`, `/.well-known/jwks.json`,
`/authorize` (GET form, POST login), `/token`, `/userinfo`. The ES256 signing
key and all code/token state are in memory, so a restart invalidates issued
tokens and there is one replica only. See
[`OPENSHIFT-OIDC-IDP.md`](OPENSHIFT-OIDC-IDP.md).

## iron-rpcd (SAMR / LSARPC / NETLOGON)

| Setting | Default | Meaning |
|---|---|---|
| `IRON_RPC_FASTETCD_ENDPOINT`, `_PARTITION_ID`, `_BASE_DN` | required | domain partition |
| `IRON_RPC_DOMAIN_SID` | required | e.g. `S-1-5-21-…` (`iron-config-ctl show`) |
| `IRON_RPC_NETBIOS_NAME` | required | e.g. `G19RPC` |
| `IRON_RPC_DNS_DOMAIN` | required | e.g. `g19rpc.lo` |
| `IRON_RPC_REALM` | `IRON_RPC_DNS_DOMAIN` upper-cased | Kerberos realm: a computer's principal is `<account>@<realm>` |
| `IRON_RPC_DOMAIN_GUID` | unset (all zero) | the domain GUID (`iron-config-ctl show`): `LsarQueryInformationPolicy2`'s `DomainGuid`, the one the LDAP ping answers with (#52) |
| `IRON_RPC_LISTEN` | `0.0.0.0:445` | TCP listener |
| `IRON_RPC_PIPE_SOCKET` | unset (off) | path of the Unix stream socket for rocketsmbd's `[ipc] backend` (#53). Created mode 0660 (a stale socket there is replaced; any other file there is an error): give rocketsmbd its group and nobody else, since each pipe's preamble carries the SMB session key. |

**Named pipes (#53).** Windows reaches SAMR, LSARPC and NETLOGON over SMB
named pipes (`ncacn_np`, `\PIPE\samr` etc. on `IPC$`). rocketsmbd serves
SMB and forwards each opened pipe to `IRON_RPC_PIPE_SOCKET` with a preamble
(rocketsmbd `docs/IPC-PIPES.md`): the session's user, the SIDs from its
Kerberos PAC, and its session key. The same RPC is then served as over TCP,
with that user as the caller. A Domain Admin (a Kerberos session whose PAC
names RID 500 or the Domain Admins group, RID 512) may create accounts with
`SamrCreateUser2InDomain` (a `user` or a `computer` by `AccountType`) and set
a password with `SamrSetInformationUser2`/`SamrSetInformationUser` at level
31 (`UserInternal7InformationNew`, `SAMPR_ENCRYPTED_PASSWORD_AES`: AES-256-CBC
and HMAC-SHA-512 keyed from the SMB session key, MS-SAMR 3.2.2.4). The
account gets its NTOWF and Kerberos keys as from `NetrServerPasswordSet2`,
after the domain password policy (#70, as a reset); PasswordExpired sets
`pwdLastSet` to 0. Anyone else, an NTLM session included (no PAC), gets
`STATUS_ACCESS_DENIED`. The RC4 levels (23-26) answer
`STATUS_INVALID_INFO_CLASS` (D4). `SamrConnect5` advertises AES support.
`test/rpc-pipe-e2e.sh` runs Samba's `rpcclient` through rocketsmbd.

Binds are unauthenticated, or authenticated with the Netlogon secure
channel (auth type 68, `PKT_INTEGRITY` or `PKT_PRIVACY`, AES only) for a
computer that has run `NetrServerAuthenticate3`. Over that binding,
`NetrServerPasswordSet2` sets the computer's password: its NTOWF and its
Kerberos keys, so it can `kinit` (#20, `test/netlogon-schannel-e2e.sh`).
It is refused on an unauthenticated binding (Zerologon). Secure channels
live in the process's memory: a restart drops them, and clients set up a
new one. NTLMSSP and Kerberos RPC auth are not built. Over TCP, SAMR has no
caller and no session key: it sets no passwords, and its
`SamrCreateUser2InDomain` is still unauthenticated (#76); a computer's first
secret for a TCP-only setup comes from `iron-rpc-ctl set-computer-secret`.

## iron-bootstrap (first-boot provisioning, #25)

Creates whatever a new domain is missing, then stays resident (a pod
container with `restartPolicy: Always`); exits non-zero only on failure,
with the reason on stderr. Every write is create-only (an etcd transaction
guarded on the key not existing), so a restart does nothing and several
members of one directory can run it at once and agree on one domain SID.

| Setting | Default | Meaning |
|---|---|---|
| `IRON_BOOTSTRAP_FASTETCD_ENDPOINT` | required | fastetcd endpoint; retried every 2 s until it answers |
| `IRON_BOOTSTRAP_PARTITION_ID` | required | domain partition id, e.g. `corp` |
| `IRON_BOOTSTRAP_BASE_DN` | required | e.g. `dc=corp,dc=example,dc=lo` |
| `IRON_BOOTSTRAP_REALM` | required | e.g. `CORP.EXAMPLE.LO` (upper-cased) |
| `IRON_BOOTSTRAP_NETBIOS_NAME` | required | e.g. `CORP`, stored on the domain's registry record |
| `IRON_BOOTSTRAP_ADMIN_PASSWORD_FILE` | required | file holding the administrator password (trailing newlines dropped; at least 8 bytes, a FIPS PBKDF2 limit) |
| `IRON_BOOTSTRAP_ONESHOT` | unset | `1` exits 0 after provisioning instead of staying resident |

It needs `OPENSSL_CONF` (FIPS) like the daemons. What it creates, if absent:

| What | Where |
|---|---|
| configuration partition `<pid>-config` | `cn=configuration,<base>` (the forest registry, as `iron-config-ctl init-forest` writes it) |
| schema partition `<pid>-schema` | `cn=schema,cn=configuration,<base>` |
| root domain record `<pid>` | realm, NetBIOS name, a fresh `S-1-5-21-…` domain SID and a fresh domain GUID (#52; a record without one gets one) |
| base entry | `<base>`, `domainDNS`, `objectSid` = the domain SID |
| `krbtgt/<REALM>@<REALM>` | `cn=krbtgt,<base>`, random key, RID 502 |
| `administrator@<REALM>` | `cn=administrator,<base>`, RID 500, `userPassword` (LDAP bind) and Kerberos keys from the password file |

A stored record with a different realm or base DN for the same partition id
is reported as an error, never rewritten. Changing the password file later
does not change the stored password.

## Operator CLIs

| Binary | Settings | Commands |
|---|---|---|
| `iron-kdc-ctl` | `IRON_KDC_FASTETCD_ENDPOINT`, `_PARTITION_ID`, `_BASE_DN`, `_REALM` (all required) | `set-password`, `export-keytab`, `set-cross-realm-key` |
| `iron-config-ctl` | `IRON_CONFIG_FASTETCD_ENDPOINT` (always); `IRON_CONFIG_PARTITION_ID`, `IRON_CONFIG_BASE_DN` (every command except `init-forest`); optional `IRON_CONFIG_ROOT_LDAP_URL` (`init-forest`), `IRON_CONFIG_LDAP_URL` and `IRON_CHILD_FASTETCD_ENDPOINT` (`create-child`) | `init-forest`, `create-child`, `show`, `set-ldap-url`, `set-kdc-url`, `add-subordinate`, `set-domain-sid` |
| `iron-rpc-ctl` | `IRON_RPC_FASTETCD_ENDPOINT`, `_PARTITION_ID`, `_BASE_DN` | `set-computer-secret` (test stand-in for real password-setting) |
| `iron-dns-ctl` | none (arguments only) | `ldap\|kerberos <microdns-url> <domain-or-realm> <host:port>...`; `dc <microdns-url> <domain> <forest> <domain-guid> <dc-host> [ldap kdc kpasswd ports]` |
| `iron-simulate` | `IRON_SIM_RPC_ADDR`, `_KDC_ADDR`, `_PARTITION_ID`, `_BASE_DN`, `_REALM`, `_FASTETCD_ENDPOINT`, `_SERVICE_PRINCIPAL` (all required) | `join <count> [prefix]`, `login <count> <user> <pass>` |

`iron-dns-ctl dc` (#87) publishes the DC-locator SRV records a writable,
non-GC DC registers (MS-ADTS 6.3.2.3), which Windows' DsGetDcName looks up
before its LDAP ping: in the domain zone `_ldap._tcp`, `_ldap._tcp.<site>._sites`,
`_ldap._tcp.dc._msdcs`, `_ldap._tcp.<site>._sites.dc._msdcs`,
`_ldap._tcp.pdc._msdcs`, `_kerberos._tcp`/`_udp`, `_kerberos._tcp.<site>._sites`,
`_kerberos._tcp.dc._msdcs`, `_kerberos._tcp.<site>._sites.dc._msdcs`,
`_kpasswd._tcp`/`_udp`; in the forest zone `_ldap._tcp.<domain-guid>.domains._msdcs`.
The site is `Default-First-Site-Name` (the LDAP ping's). Names are published
lower-case. No GC records, and no A record for the DC host (that is the
network's DHCP or the operator's). The domain GUID is `iron-config-ctl show`'s.
`ldap`/`kerberos` alone are not enough for a Windows client (or Samba's
locator): `test/dc-locator-dns-e2e.sh`.

`iron-store`'s ignored mTLS test reads `IRON_STORE_MTLS_ENDPOINT`/`_CA`/`_CERT`/`_KEY`
(`test/mtls-e2e.sh` sets them).

## How it ships

RPMs are built with `cargo generate-rpm -p crates/<crate>` after
`cargo build --release`. They link dynamically against the system
glibc/libssl on purpose, so the OS's `fips.so` is the one in use: the
CMVP-certified module on RHEL, the same code uncertified on Fedora (#30).
There's no CI release workflow; RPMs are built by hand and attached to GitHub
releases. The Terraform cloud-init in `deploy/terragrunt/ldap/` installs
`iron-ldapd` from the release URL.

| RPM | Contents | Unit / config |
|---|---|---|
| `iron-ldapd` | `/usr/bin/iron-ldapd` | `iron-ldapd.service`, `EnvironmentFile=-/etc/iron-ldapd/iron-ldapd.conf` |
| `iron-kdcd` | `/usr/bin/iron-kdcd`, `/usr/bin/iron-kdc-ctl` | `iron-kdcd.service`, `/etc/iron-kdcd/iron-kdcd.conf` |
| `iron-gcd` | `/usr/bin/iron-gcd` | `iron-gcd.service`, `/etc/iron-gcd/iron-gcd.conf` |
| `iron-oidcd` | `/usr/bin/iron-oidcd` | `iron-oidcd.service`, `/etc/iron-oidcd/iron-oidcd.conf` |
| `iron-dns-ctl` | `/usr/bin/iron-dns-ctl` | none (operator tool) |

Each daemon RPM creates a system user of the same name, installs an example
config at `/usr/share/doc/<name>/<name>.conf.example`, and runs
`systemctl enable --now` on install. `iron-rpcd`, `iron-rpc-ctl`,
`iron-config-ctl` and `iron-simulate` are not packaged; run them from a
`cargo build`.

**Kubernetes: the `irondirectory` golden** (#25), run as rustkube pods by
irondirectory-operator. It's a Fedora root, not a static-musl build, so the
daemons link Fedora's own OpenSSL and its FIPS provider (D4). stormcos builds
it (`deploy/build-goldens.sh`, owner decision on #25): a copy-on-write clone
of the `fips-base` golden plus what this repo and the fastetcd golden supply:

| Path | What |
|---|---|
| `/usr/lib64/…`, `/usr/lib64/ossl-modules/fips.so` | from `fips-base`: Fedora `$FEDORA_RELEASE`'s `glibc`, `openssl-libs`, `ca-certificates`, installed by `dnf --installroot` |
| `/usr/bin/iron-ldapd`, `iron-kdcd`, `iron-kdc-ctl`, `iron-bootstrap` | glibc (`x86_64-unknown-linux-gnu`) release builds, `ossl` dynamic, on a host of the same Fedora release |
| `/usr/bin/fastetcd` | copied from the fastetcd golden, never rebuilt here |
| `/etc/irondirectory/fips.cnf` | `deploy/golden/fips.cnf`: `OPENSSL_CONF` for every daemon (FIPS + base providers only) |
| `/etc/irondirectory/golden.txt` | rpm versions, irondirectory commit, sha256 of each binary |
| `/var/lib/irondirectory`, `/tmp`, `/run` | empty |

The golden has no entrypoint or environment; the operator names every
command and setting. It is rebuilt when `FEDORA_RELEASE` changes (the
binaries must link that release's glibc and OpenSSL) or this repo changes.
Fedora's `fips.so` is the OpenSSL FIPS provider but not a CMVP-certified
module (#30). This repo's contract is `fips.cnf`, the gnu/dynamic build and
the file list above. `test/golden-e2e.sh <dir>` is its acceptance test. It runs fastetcd, iron-ldapd, iron-kdcd and
iron-bootstrap chrooted into the tree with an empty environment, checks
`ldapwhoami` and `kinit` for the administrator, then restarts everything on the
same data with a changed password file.
