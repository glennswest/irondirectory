# Configuration, ports and packaging

What each irondirectory binary reads, listens on and ships as, taken from the
code (`crates/*/src/bin/*.rs`, `crates/*/Cargo.toml`, `deploy/systemd/`). All
settings are environment variables. An empty value counts as unset.

## Common to every binary

- **fastetcd connection: plaintext only.** Every binary connects to its
  `*_FASTETCD_ENDPOINT` (e.g. `http://etcd.g8.lo:2379`) without TLS. `iron-store`
  can speak mTLS, but no binary exposes a CA/cert/key setting yet (#26).
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
| `iron-ldapd` | off (e.g. `:636`) | LDAPS (implicit TLS) | `IRON_LDAP_LDAPS_LISTEN` |
| `iron-ldapd` | `0.0.0.0:8080` | HTTP `/health` (live fastetcd `Status` check) | `IRON_LDAP_HEALTH_LISTEN` |
| `iron-kdcd` | `0.0.0.0:88` | Kerberos, UDP and TCP | `IRON_KDC_LISTEN` |
| `iron-gcd` | `0.0.0.0:3268` | Global Catalog LDAP, read-only | `IRON_GC_LISTEN` |
| `iron-gcd` | off (e.g. `:3269`) | Global Catalog LDAPS | `IRON_GC_LDAPS_LISTEN` |
| `iron-gcd` | `0.0.0.0:8080` | HTTP `/health` | `IRON_GC_HEALTH_LISTEN` |
| `iron-oidcd` | `0.0.0.0:8080` | HTTP (OIDC endpoints, no TLS, no `/health`) | `IRON_OIDC_LISTEN` |
| `iron-rpcd` | `0.0.0.0:445` | DCE/RPC `ncacn_ip_tcp`, unauthenticated binds | `IRON_RPC_LISTEN` |

Not served: kpasswd (464, RFC 3244; #20), `ncacn_np` over SMB, and a DNS
server (SRV records are published into MicroDNS by `iron-dns-ctl`).

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
| `IRON_LDAP_CONFIG_FASTETCD_ENDPOINT`, `_CONFIG_PARTITION_ID`, `_CONFIG_BASE_DN` | unset | all three load the forest registry once at startup for registry-driven referrals (checked before `IRON_LDAP_REFERRALS`) and multi-partition rootDSE |

TLS is pinned to groups P-256/P-384/P-521.

## iron-kdcd (Kerberos KDC)

| Setting | Default | Meaning |
|---|---|---|
| `IRON_KDC_FASTETCD_ENDPOINT` | required | fastetcd endpoint |
| `IRON_KDC_PARTITION_ID` | required | partition |
| `IRON_KDC_BASE_DN` | required | base DN |
| `IRON_KDC_REALM` | required | realm, e.g. `G10.LO` |
| `IRON_KDC_LISTEN` | `0.0.0.0:88` | bound for both UDP and TCP |
| `IRON_KDC_CONFIG_FASTETCD_ENDPOINT`, `_CONFIG_PARTITION_ID`, `_CONFIG_BASE_DN` | unset | forest registry for one-hop cross-realm referral tickets |

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
| `IRON_RPC_LISTEN` | `0.0.0.0:445` | TCP listener |

Unauthenticated binds only. There is no `SamrSetInformationUser2` or
`NetrServerPasswordSet2`, so a real Windows client cannot set its machine
password yet (#20).

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
| root domain record `<pid>` | realm, NetBIOS name, a fresh `S-1-5-21-…` domain SID |
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
| `iron-dns-ctl` | none (arguments only) | `ldap\|kerberos <microdns-url> <domain-or-realm> <host:port>...` |
| `iron-simulate` | `IRON_SIM_RPC_ADDR`, `_KDC_ADDR`, `_PARTITION_ID`, `_BASE_DN`, `_REALM`, `_FASTETCD_ENDPOINT`, `_SERVICE_PRINCIPAL` (all required) | `join <count> [prefix]`, `login <count> <user> <pass>` |

`iron-store`'s ignored mTLS test reads `IRON_STORE_MTLS_ENDPOINT`/`_CA`/`_CERT`/`_KEY`.

## How it ships

RPMs are built with `cargo generate-rpm -p crates/<crate>` after
`cargo build --release`. They link dynamically against the system
glibc/libssl on purpose, so the OS's validated `fips.so` is the one in use.
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
FIPS provider is Fedora's own validated `fips.so` (D4). `deploy/golden/build-root.sh <dir>`
assembles it:

| Path | What |
|---|---|
| `/usr/bin/fastetcd` | static musl, built from the tag in `deploy/golden/fastetcd.ref` (or `FASTETCD_BIN`) |
| `/usr/bin/iron-ldapd`, `iron-kdcd`, `iron-kdc-ctl`, `iron-bootstrap` | glibc release builds |
| `/usr/lib64/…`, `/usr/lib64/ossl-modules/fips.so` | Fedora `$FEDORA_RELEASE`'s `glibc` + `openssl-libs` and their dependencies, installed by `dnf --installroot` |
| `/etc/irondirectory/fips.cnf` | `OPENSSL_CONF` for every daemon (FIPS + base providers only) |
| `/etc/irondirectory/golden.txt` | Fedora release, rpm versions, both commits, sha256 of each binary |
| `/var/lib/irondirectory`, `/tmp`, `/run` | empty |

The golden has no entrypoint or environment; the operator names every
command and setting. It is rebuilt when `FEDORA_RELEASE` (default 43)
changes, and must be built on a host of that release, since the binaries
link against its glibc and OpenSSL. The script needs dnf5, rustup (with the
musl target), protoc, musl-gcc and a `/etc/subuid`/`/etc/subgid` range: dnf
runs as root inside a user namespace, no real root. `test/golden-e2e.sh <dir>`
is its acceptance test. It runs fastetcd, iron-ldapd, iron-kdcd and
iron-bootstrap chrooted into the tree with an empty environment, checks
`ldapwhoami` and `kinit` for the administrator, then restarts everything on the
same data with a changed password file.
