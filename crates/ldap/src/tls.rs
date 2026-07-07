//! LDAPS (implicit TLS) via OpenSSL, per D4 ("TLS via OpenSSL FIPS
//! provider, not rustls+ring").
//!
//! Uses the plain `openssl` crate (rust-openssl's full libssl bindings),
//! not the `ossl` crate `iron-crypto` uses -- `ossl`/kryoptic only binds
//! libcrypto's EVP APIs and has no TLS state machine at all. `openssl`
//! dynamically links the system libssl/libcrypto by default (no
//! `vendored` feature enabled), so it resolves through the same
//! OS-validated `fips.so` provider as `iron-crypto` when the process's
//! `OPENSSL_CONF` activates it -- see `docs/FIPS.md`. There is no
//! per-connection plumbing needed for that; it's a property of how the
//! process is launched, not of this code.

use std::path::Path;

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

/// Builds an `SslAcceptor` for LDAPS from a PEM certificate + private key.
/// Uses Mozilla's "intermediate" TLS server profile (TLS 1.2 minimum,
/// AEAD-only cipher suites) -- every cipher it offers is FIPS-approved.
pub fn build_acceptor(
    cert_file: &Path,
    key_file: &Path,
) -> Result<SslAcceptor, openssl::error::ErrorStack> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    builder.set_certificate_file(cert_file, SslFiletype::PEM)?;
    builder.set_private_key_file(key_file, SslFiletype::PEM)?;
    builder.check_private_key()?;
    Ok(builder.build())
}
