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
///
/// Explicitly restricts the TLS 1.3 / ECDHE group list to the three NIST
/// curves (P-256/P-384/P-521). Left to its own defaults, OpenSSL 3.5's
/// server offers a TLS 1.3 hybrid PQC group first
/// (`X25519MLKEM768`) -- confirmed live against this exact FIPS provider:
/// `openssl list -key-exchange-algorithms` (with only base+fips loaded)
/// shows X25519/X448 as available `@ fips`. That means the module
/// *implements* them, not that they're on the CMVP certificate's list of
/// *approved* algorithms (X25519 is not a NIST SP 800-56A curve) -- and
/// that distinction isn't something to guess at from here. Pinning the
/// group list sidesteps the ambiguity entirely rather than asserting an
/// unverified compliance claim.
pub fn build_acceptor(
    cert_file: &Path,
    key_file: &Path,
) -> Result<SslAcceptor, openssl::error::ErrorStack> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    builder.set_certificate_file(cert_file, SslFiletype::PEM)?;
    builder.set_private_key_file(key_file, SslFiletype::PEM)?;
    builder.check_private_key()?;
    builder.set_groups_list("P-256:P-384:P-521")?;
    Ok(builder.build())
}
