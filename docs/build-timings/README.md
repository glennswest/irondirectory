# Build timings (#29)

`cargo build --timings` and `cargo test --timings` reports from dev, where
`sc-build` builds this repo: a fresh volume per job (clean target dir, no
cache but cargo's downloads), `CARGO_BUILD_JOBS=4`, `CARGO_INCREMENTAL=0`,
rustc 1.95.0, 16 cores shared with other projects' builds (load average 26.8
during this run). Commit `096c737`, 2026-09-28.

| Step | Wall time |
|---|---|
| `cargo build --locked` (clean, 291 units) | 27 s |
| `cargo test --locked` (compile 324 test units + run every test) | 4 s |
| **Total `cargo build && cargo test`** | **31 s** |

Open the HTML files for the full charts:
[`2026-09-28-cargo-build.html`](2026-09-28-cargo-build.html),
[`2026-09-28-cargo-test.html`](2026-09-28-cargo-test.html).

## Where the time goes

Slowest units in the clean build (107 s of CPU across 291 units):

| Time | Unit |
|---|---|
| 9.0 s | `ring` 0.17.14 build script (compiles its C/asm) |
| 3.4 s | `tokio` |
| 3.3 s | `rustls` |
| 2.9 s | `rasn` |
| 2.7 s | `tonic` |
| 2.5 s | `bindgen` (for `ossl-sys`) |
| 2.3 s | `reqwest`, `h2` |
| 2.1 s | `rasn-derive` |

Critical path: `cc` → `ring` build script (9 s) → `ring` → `rustls` →
`tonic` → `etcd-client` → `iron-store` → `iron-oidc` → `iron-oidcd`. `ring`
comes in through `rustls` (etcd-client's `tls` feature and reqwest's
`rustls-tls`). Nothing here is worth restructuring: the whole build is under
half a minute.

## What the hour-long jobs actually were

Not compile time. There are no `[profile.*]` overrides (no fat LTO, no
`codegen-units = 1`), no build scripts of our own, and only minor duplicate
versions (`getrandom`, `hashbrown`, `itertools`, `shlex`, `windows-sys`).
What held slots:

- **A test that waits for ever.** `iron-bootstrap`'s live test called
  `wait_for_store`, which retries until fastetcd answers — correct for a pod
  waiting for its store, wrong for a test. Against an unreachable endpoint
  `cargo test -p iron-bootstrap …` never ended (the 56-minute job). With the
  per-project target dir dev used then, a concurrent `cargo build` of this
  repo waited on the same build-directory lock (the 1 h 37 m job). The test
  now gives fastetcd 30 s and fails.
- **`cargo test` crashed without a FIPS config.** Every `iron-crypto` test
  needs `OPENSSL_CONF`; without it the parallel test binary died with
  SIGSEGV. `.cargo/config.toml` now points it at
  `crates/crypto/testdata/fips-dev.cnf`, so a plain `cargo test` passes.

To re-measure: `sc-build 'cargo build --timings && cargo test --timings'`
(see the `SC_BUILD_OUT` note in `sc-build` for fetching the reports).
