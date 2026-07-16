//! Companion to `concurrent_repro.rs`: tests the OTHER shared-state
//! hypothesis for #20/#23's live "client fails to decrypt an
//! otherwise-valid AS-REP/TGS-REP" flakiness -- not a shared
//! `FipsContext` (that one's ruled out by `concurrent_repro.rs`), but
//! `FipsContext::new()` ITSELF racing against 299 concurrent calls to
//! the same constructor, exactly as `as_exchange.rs`/`tgs_exchange.rs`
//! now do per-request. 6000+ runs across many invocations: always 0
//! failures -- this isn't a concurrency bug in `iron_crypto` either.
//! Live evidence since (a real KDC log's self-test: encrypting then
//! immediately re-decrypting the exact bytes sent to a real client
//! always succeeds) points elsewhere -- most likely client-side
//! (`opendirectoryd`) timing/probing behavior around which optional
//! SPNs it requests before giving up, not a server-side crypto defect.

use iron_crypto::kerberos::{self, Enctype};
use iron_crypto::FipsContext;

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let mut handles = Vec::new();
    for i in 0..300 {
        handles.push(tokio::spawn(async move {
            // Mirrors tgs_exchange.rs exactly: a FRESH FipsContext per
            // request, created concurrently with 299 other requests,
            // used once for a ticket encrypt/decrypt round-trip.
            let ctx = FipsContext::new().map_err(|e| format!("task {i}: FipsContext::new failed: {e}"))?;
            let enctype = Enctype::Aes256CtsHmacSha1_96;
            let key: Vec<u8> = (0..32).map(|b| (b + i as u8) as u8).collect();
            let plaintext = format!("enc-tgs-rep-part-{i}-payload-padding-out-to-a-reasonable-length").into_bytes();
            let cipher = kerberos::encrypt(&ctx, enctype, &key, 9, &plaintext).map_err(|e| format!("task {i}: encrypt failed: {e}"))?;
            match kerberos::decrypt(&ctx, enctype, &key, 9, &cipher) {
                Ok(pt) if pt == plaintext => Ok(()),
                Ok(_) => Err(format!("task {i}: plaintext mismatch")),
                Err(e) => Err(format!("task {i}: decrypt failed: {e}")),
            }
        }));
    }

    let mut ok = 0;
    let mut fail = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(()) => ok += 1,
            Err(e) => {
                fail += 1;
                eprintln!("{e}");
            }
        }
    }
    println!("--- {ok} ok, {fail} failed (concurrent fresh FipsContext::new per task) ---");
}
