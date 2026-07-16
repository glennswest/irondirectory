//! Reproduces (or rules out) #20/#23's intermittent Kerberos decrypt
//! failure at its true boundary. The KDC's existing self-tests encrypt
//! and decrypt the TGS-REP enc-part with the *same* `FipsContext`, so
//! they only prove self-consistency -- a ciphertext that is internally
//! valid but wrong versus an independent decryptor passes them. A real
//! client (macOS Heimdal) decrypts our enc-part with a *different*
//! context entirely. This test mirrors that: encrypt with a freshly
//! created context (as `tgs_exchange.rs` does), then decrypt the result
//! with a *separate*, long-lived shared context, under heavy concurrency
//! -- exactly the KDC's live shape (a fresh per-request ticket context +
//! the shared `app.fips`). Any failure here is the bug; zero failures
//! across many runs rules the crypto layer out and points at the client
//! or the transport (e.g. UDP) instead.

use iron_crypto::kerberos::{self, Enctype};
use iron_crypto::FipsContext;
use std::sync::Arc;

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    // The shared, long-lived context -- stands in for the KDC's `app.fips`
    // that has already handled many prior operations.
    let shared = Arc::new(FipsContext::new().unwrap());

    let mut handles = Vec::new();
    for i in 0..400 {
        let shared = shared.clone();
        let enctype = if i % 2 == 0 { Enctype::Aes256CtsHmacSha1_96 } else { Enctype::Aes256CtsHmacSha384_192 };
        handles.push(tokio::spawn(async move {
            // A fresh per-request context, as tgs_exchange.rs creates for
            // the ticket/enc-part encrypts.
            let fresh = FipsContext::new().map_err(|e| format!("task {i}: fresh ctx: {e}"))?;
            // The "subkey" the client asserted -- random per request.
            let key: Vec<u8> = kerberos::random_bytes(&fresh, enctype.key_len()).map_err(|e| format!("task {i}: rand: {e}"))?;
            // A realistic TGS-REP enc-part payload size.
            let pt = format!("enc-tgs-rep-part-{i}-{}", "x".repeat(140)).into_bytes();

            // Encrypt with the FRESH context, usage 9 (subkey path).
            let ct = kerberos::encrypt(&fresh, enctype, &key, 9, &pt).map_err(|e| format!("task {i}: encrypt: {e}"))?;

            // Decrypt with the SHARED context (a DIFFERENT context) -- this
            // is the cross-context step the KDC self-test never exercises.
            match kerberos::decrypt(&shared, enctype, &key, 9, &ct) {
                Ok(got) if got == pt => Ok(()),
                Ok(_) => Err(format!("task {i}: cross-context plaintext MISMATCH ({enctype:?})")),
                Err(e) => Err(format!("task {i}: cross-context DECRYPT FAILED ({enctype:?}): {e}")),
            }
        }));
    }

    let (mut ok, mut fail) = (0u32, 0u32);
    for h in handles {
        match h.await.unwrap() {
            Ok(()) => ok += 1,
            Err(e) => {
                fail += 1;
                eprintln!("{e}");
            }
        }
    }
    println!("--- {ok} ok, {fail} failed (encrypt fresh-ctx -> decrypt shared-ctx, concurrent) ---");
    if fail > 0 {
        std::process::exit(1);
    }
}
