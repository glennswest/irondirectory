//! LDAPS (implicit TLS) via OpenSSL, per D4 ("TLS via OpenSSL FIPS
//! provider, not rustls+ring").
//!
//! Uses the plain `openssl` crate (rust-openssl's full libssl bindings),
//! not the `ossl` crate `iron-crypto` uses -- `ossl`/kryoptic only binds
//! libcrypto's EVP APIs and has no TLS state machine at all. `openssl`
//! dynamically links the system libssl/libcrypto by default (no
//! `vendored` feature enabled), so it resolves through the same
//! OS `fips.so` provider as `iron-crypto` when the process's
//! `OPENSSL_CONF` activates it -- see `docs/FIPS.md`. There is no
//! per-connection plumbing needed for that; it's a property of how the
//! process is launched, not of this code.

use std::path::Path;

use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslRef};
use openssl::x509::X509Ref;

/// The `application_data` of a TLS connection's GSS channel bindings
/// (#65): `tls-server-end-point:` followed by the RFC 5929 §4.1 hash of
/// `cert` (our own certificate) -- the hash of its signature algorithm,
/// SHA-256 when that is MD5 or SHA-1 or the algorithm names no hash
/// (Ed25519), as OpenLDAP's `tlso_session_endpoint` does.
pub fn server_end_point(cert: &X509Ref) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let sig_hash = cert.signature_algorithm().object().nid().signature_algorithms().map(|a| a.digest);
    let md = match sig_hash {
        Some(Nid::MD5) | Some(Nid::SHA1) | None => MessageDigest::sha256(),
        Some(nid) => MessageDigest::from_nid(nid).unwrap_or_else(MessageDigest::sha256),
    };
    let mut out = b"tls-server-end-point:".to_vec();
    out.extend_from_slice(&cert.digest(md)?);
    Ok(out)
}

/// [`server_end_point`] of the certificate `ssl` presented, if any.
pub fn connection_binding(ssl: &SslRef) -> Option<Vec<u8>> {
    let cert = ssl.certificate()?;
    match server_end_point(cert) {
        Ok(b) => Some(b),
        Err(e) => {
            tracing::warn!("cannot hash our certificate for channel bindings: {e}");
            None
        }
    }
}

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
