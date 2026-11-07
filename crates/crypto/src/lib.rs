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
pub mod kerberos;
pub mod md4;
pub mod pbkdf2;
pub mod sign;

use ossl::bindings::{OSSL_LIB_CTX_load_config, OSSL_PROVIDER_available};
use ossl::OsslContext;
use std::ffi::CStr;
use std::mem::ManuallyDrop;
use std::sync::Mutex;

/// Serialises loading a config into a new library context, and freeing one
/// (#31). OpenSSL's ssl config module (an `ssl_conf` line, which Fedora's
/// system openssl.cnf has) keeps process-global state with no lock of its
/// own: two threads in `OSSL_LIB_CTX_load_config` at once crashed in
/// `ssl_module_init` (SIGSEGV/SIGABRT, about 1 run in 7 of the parallel
/// tests). Contexts are made once per daemon, so the lock costs nothing.
static CONTEXT_LIFECYCLE: Mutex<()> = Mutex::new(());

fn lifecycle_lock() -> std::sync::MutexGuard<'static, ()> {
    // Nothing guarded can be left half-done by a panic; ignore poisoning.
    CONTEXT_LIFECYCLE.lock().unwrap_or_else(|e| e.into_inner())
}

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
    #[error("password is {actual} bytes, shorter than the FIPS PBKDF2 minimum of {min}")]
    PasswordTooShort { min: usize, actual: usize },
    #[error("integrity check failed (Kerberos HMAC mismatch or tampered ciphertext)")]
    IntegrityCheckFailed,
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
pub struct FipsContext(ManuallyDrop<OsslContext>);

impl Drop for FipsContext {
    fn drop(&mut self) {
        let _guard = lifecycle_lock();
        // SAFETY: dropped exactly once, here; never used afterwards.
        unsafe { ManuallyDrop::drop(&mut self.0) };
    }
}

impl FipsContext {
    pub fn new() -> Result<Self, Error> {
        Self::with_config(None)
    }

    /// `new()` with an explicit config file instead of `OPENSSL_CONF`/the
    /// system default; `None` is exactly `new()`. Calls
    /// `OSSL_LIB_CTX_load_config` directly with a real C string (see the
    /// type's docs for why not `ossl`'s `load_configuration_file`).
    fn with_config(path: Option<&CStr>) -> Result<Self, Error> {
        let _guard = lifecycle_lock();
        // Declared after the guard, so on an error return it is freed
        // while the lock is still held.
        let ctx = OsslContext::new_lib_ctx();
        let filename = path.map_or(std::ptr::null(), CStr::as_ptr);
        if unsafe { OSSL_LIB_CTX_load_config(ctx.ptr(), filename) } != 1 {
            return Err(Error::Ossl);
        }

        let name = CStr::from_bytes_with_nul(b"fips\0").unwrap();
        let active = unsafe { OSSL_PROVIDER_available(ctx.ptr(), name.as_ptr()) };
        if active != 1 {
            return Err(Error::FipsProviderNotActive);
        }

        Ok(FipsContext(ManuallyDrop::new(ctx)))
    }

    pub(crate) fn inner(&self) -> &OsslContext {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::sync::Barrier;

    fn testdata(name: &str) -> CString {
        CString::new(format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    /// Creates (and drops) contexts from `config` on 16 threads at once, 25
    /// times each, released together by a barrier.
    fn contexts_on_many_threads(config: &str) -> Vec<Result<(), Error>> {
        const THREADS: usize = 16;
        let path = testdata(config);
        let barrier = Barrier::new(THREADS);
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    s.spawn(|| {
                        barrier.wait();
                        (0..25).map(|_| FipsContext::with_config(Some(&path)).map(drop)).collect::<Vec<_>>()
                    })
                })
                .collect();
            handles.into_iter().flat_map(|h| h.join().unwrap()).collect()
        })
    }

    /// #31: a config with an `ssl_conf` section (Fedora's system
    /// openssl.cnf has one) crashed in OpenSSL's ssl_module_init when
    /// several threads loaded it at once.
    #[test]
    fn contexts_from_an_ssl_conf_config_on_many_threads_all_have_fips() {
        let results = contexts_on_many_threads("fips-sslconf.cnf");
        assert_eq!(results.len(), 400);
        for r in results {
            assert!(r.is_ok(), "{:?}", r.err());
        }
    }

    /// #31's fail-closed path: without the FIPS provider every one of them
    /// is `FipsProviderNotActive`, and nothing crashes.
    #[test]
    fn contexts_without_fips_on_many_threads_fail_closed() {
        let results = contexts_on_many_threads("nofips-sslconf.cnf");
        assert_eq!(results.len(), 400);
        for r in results {
            assert!(matches!(r, Err(Error::FipsProviderNotActive)), "{r:?}");
        }
    }
}
