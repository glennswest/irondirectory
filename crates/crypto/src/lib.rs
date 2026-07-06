//! FIPS crypto facade over the `ossl` crate (decision D4 — see
//! `docs/ARCHITECTURE.md` and `docs/FIPS.md`).
//!
//! Real FIPS 140 compliance comes from the OS-shipped, CMVP-validated
//! OpenSSL FIPS provider (`fips.so`), not from a cargo feature. The `ossl`
//! crate's own `fips` feature is a different thing entirely — it vendor-
//! builds OpenSSL >= 4.0 from source and produces a self-compiled, NOT
//! CMVP-validated module (`KRYOPTIC_FIPS_BUILD` defaults to `"test"`). This
//! crate never enables it; see `docs/FIPS.md` for the full writeup.

pub mod aead;
pub mod digest;
pub mod hmac;

use ossl::bindings::OSSL_PROVIDER_available;
use ossl::OsslContext;
use std::ffi::CStr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("OpenSSL operation failed")]
    Ossl,
    #[error("buffer size mismatch")]
    BufferSize,
    #[error(
        "the OpenSSL FIPS provider is not active in this process — set \
         OPENSSL_CONF to a config with [provider_sect] fips = fips_sect / \
         [fips_sect] activate = 1, module = /usr/lib64/ossl-modules/fips.so \
         (see docs/FIPS.md)"
    )]
    FipsProviderNotActive,
}

impl From<ossl::Error> for Error {
    fn from(_: ossl::Error) -> Self {
        Error::Ossl
    }
}

/// A library context with the FIPS provider verified active.
///
/// Loads via `OPENSSL_CONF` (or the system default `openssl.cnf`, which on
/// a FIPS-enabled host activates the `fips` provider). Deliberately does
/// NOT use `ossl::OsslContext::load_configuration_file` — that method
/// passes a non-NUL-terminated `OsStr` byte pointer to an OpenSSL C API
/// expecting a C string, an out-of-bounds-read bug in `ossl` 1.5.2. Use
/// `OPENSSL_CONF` (env var) instead, which routes through
/// `load_default_configuration` and avoids the bad code path entirely.
///
/// Construction FAILS if the `fips` provider isn't actually loaded and
/// active — this is deliberate. Every caller in this crate goes through
/// `FipsContext`, so there is no silent fallback to an unvalidated default
/// provider: either the FIPS module is active, or nothing runs.
pub struct FipsContext(OsslContext);

impl FipsContext {
    pub fn new() -> Result<Self, Error> {
        let mut ctx = OsslContext::new_lib_ctx();
        ctx.load_default_configuration().map_err(|_| Error::Ossl)?;

        let name = CStr::from_bytes_with_nul(b"fips\0").unwrap();
        let active = unsafe { OSSL_PROVIDER_available(ctx.ptr(), name.as_ptr()) };
        if active != 1 {
            return Err(Error::FipsProviderNotActive);
        }

        Ok(FipsContext(ctx))
    }

    pub(crate) fn inner(&self) -> &OsslContext {
        &self.0
    }
}
