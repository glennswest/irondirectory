# FIPS / crypto backend

irondirectory's FIPS posture (decision D4) is: **all crypto goes through the
system's OpenSSL 3 FIPS provider**, bound from Rust via the `ossl` crate
(`crates/crypto`, package `iron-crypto`). Validated on `dev.g8.lo` (Fedora
43, OpenSSL 3.5.4) 2026-07-06 — see irondirectory#1.

## What "FIPS compliant" actually means here

FIPS 140 compliance comes from a **CMVP-validated crypto module** — you
cannot get there by compiling your own OpenSSL and calling it "FIPS." Two
things are true on a Red Hat–derived OpenSSL build (Fedora and RHEL share
the same FIPS provider code):

- The system already ships a validated FIPS provider:
  `/usr/lib64/ossl-modules/fips.so`, self-identifying as "Red Hat Enterprise
  Linux OpenSSL FIPS Provider" with an active CMVP certificate baked into
  the build (`REDHAT_FIPS_VENDOR`/`REDHAT_FIPS_VERSION` in `openssl version
  -a`).
- Loading it does **not** require the kernel `fips=1` boot flag or a
  reboot. That flag is for RHEL's system-wide FIPS certification scope
  (kernel RNG, dm-crypt, etc.); the OpenSSL provider itself just needs to be
  activated via standard OpenSSL provider configuration
  (`OPENSSL_CONF`/`openssl.cnf`), exactly like `openssl(1)` does.

Confirmed directly:

```sh
$ cat /tmp/fips.cnf
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
fips = fips_sect
base = base_sect
[base_sect]
activate = 1
[fips_sect]
module = /usr/lib64/ossl-modules/fips.so
activate = 1
tls1-prf-ems-check = 1

$ OPENSSL_CONF=/tmp/fips.cnf openssl list -providers
Providers:
  base    ... status: active
  fips
    name: Red Hat Enterprise Linux OpenSSL FIPS Provider
    version: 3.5.4-f4dc4677820c122d
    status: active

$ OPENSSL_CONF=/tmp/fips.cnf openssl dgst -provider fips -md5   # rejected
dgst: Unknown option or message digest: md5
```

## The `ossl` crate: two very different things named "fips"

The `ossl` crate (from `latchset/kryoptic`, by Simo Sorce — the same
reviewer who steered rocketsmbd toward it, see rocketsmbd#29) has a cargo
feature literally named `fips`. **Do not enable it.** It is unrelated to the
OS-validated provider above:

- `ossl`'s `fips` feature pulls in `ossl400` — **requires OpenSSL >= 4.0**,
  not the 3.5 this platform ships.
- With `default-features = false` (i.e. not `dynamic`), `ossl-sys` vendor-
  builds OpenSSL from source (`KRYOPTIC_OPENSSL_SOURCES` env var, `enable-
  fips` configure flag), producing its own `libfips.a`.
- That self-built module defaults to `KRYOPTIC_FIPS_BUILD=test` — i.e. it
  self-identifies as an explicitly **non-validated test build**, not a CMVP
  submission.

The correct build is `ossl`'s **default backend** (`ossl-sys`) with the
**`dynamic`** feature (link the system `libcrypto.so`) and the crate's
`fips` feature turned **off**:

```toml
ossl = { version = "1.5.2", default-features = false, features = ["ossl-sys", "dynamic"] }
```

This is exactly the pattern rocketsmbd landed on independently (rocketsmbd
uses the plain `openssl` crate rather than `ossl`, but the principle is
identical: dynamically link system OpenSSL, let the *OS* supply the
validated FIPS provider — don't try to vendor or self-build one).

## `iron-crypto` (`crates/crypto`)

Facade over `ossl`: digest (SHA-256/384/512), HMAC (SHA-256/512), and
AES-256-GCM AEAD. `FipsContext::new()`:

1. Creates a fresh `OSSL_LIB_CTX` and loads config via
   `load_default_configuration()` (i.e. via the `OPENSSL_CONF` env var or
   the system default `openssl.cnf`).
2. **Verifies** the `fips` provider is actually active
   (`OSSL_PROVIDER_available`) and returns `Error::FipsProviderNotActive`
   otherwise.

There is no code path in this crate that silently falls back to the
unvalidated default provider — either FIPS is active, or nothing runs.
Verified: unsetting `OPENSSL_CONF` makes every `iron-crypto` test fail
closed with that error, rather than passing against non-FIPS crypto.

### A bug found along the way

`ossl::OsslContext::load_configuration_file(Some(path))` passes
`path.as_os_str().as_encoded_bytes().as_ptr()` — a pointer into a Rust byte
slice that is **not NUL-terminated** — to `OSSL_LIB_CTX_load_config()`,
which expects a C string. This is an out-of-bounds read (confirmed: the
OpenSSL error message came back with fragments of unrelated heap memory
appended to the path). `iron-crypto` avoids this entirely by using
`load_default_configuration()` (passes `NULL`, which OpenSSL resolves via
`OPENSSL_CONF`/the compiled-in default path) instead of the path-taking
variant. Not filed upstream yet — worth doing if this crate sees more use.

## Running the test suite

Needs `openssl-devel` (Fedora/RHEL) or `libssl-dev` (Debian), plus `clang`
(for `ossl-sys`'s `bindgen`-generated FFI). A checked-in config (the one
above) lives at `crates/crypto/testdata/fips-dev.cnf`:

```sh
OPENSSL_CONF=$(pwd)/crates/crypto/testdata/fips-dev.cnf cargo test -p iron-crypto
```

## What's deliberately out of scope here

- Kerberos AES-CTS enctypes (RFC 3962 / RFC 8009) — `ossl::cipher` already
  exposes `EncAlg::AesCts(AesSize, AesCtsMode)`, so `iron-kdc` can build
  directly on `ossl` when that crate lands; no need to duplicate it in
  `iron-crypto` ahead of time.
- LDAPS/TLS — handled by the OpenSSL-backed TLS stack chosen for `iron-ldap`
  (not yet built), not by this crate.
- PBKDF2 password KDF (D4) — same: add when `iron-store`/`iron-ldap` need
  it, following the same `ossl`-dynamic, OS-FIPS-provider pattern.
