use iron_crypto::kerberos::{self, Enctype};
use iron_crypto::FipsContext;
use std::sync::Arc;

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let ctx = Arc::new(FipsContext::new().unwrap());

    let mut handles = Vec::new();
    for i in 0..300 {
        let ctx = ctx.clone();
        let enctype = if i % 2 == 0 { Enctype::Aes256CtsHmacSha384_192 } else { Enctype::Aes256CtsHmacSha1_96 };
        handles.push(tokio::spawn(async move {
            // Mirrors one AS-REQ handling: string_to_key (client's preauth
            // key), decrypt the PA-ENC-TIMESTAMP (usage 1), a PAC-shaped
            // HMAC step, then encrypt the AS-REP (usage 3) -- all
            // concurrently with 299 other simulated requests on the SAME
            // shared FipsContext, alternating enctype families.
            let salt = format!("IRON.LOuser{i:04}0123456789abcdef"); // >=16 bytes always
            let password = format!("hunter2-user-{i}");
            let key = kerberos::string_to_key(&ctx, enctype, password.as_bytes(), salt.as_bytes(), None).unwrap();

            let ts_plaintext = format!("timestamp-{i}").into_bytes();
            let ts_cipher = kerberos::encrypt(&ctx, enctype, &key, 1, &ts_plaintext).unwrap();
            let decrypted_ts = match kerberos::decrypt(&ctx, enctype, &key, 1, &ts_cipher) {
                Ok(pt) => pt,
                Err(e) => return Err(format!("task {i}: PA-ENC-TIMESTAMP decrypt failed: {e}")),
            };
            if decrypted_ts != ts_plaintext {
                return Err(format!("task {i}: PA-ENC-TIMESTAMP mismatch"));
            }

            let _pac_hmac = iron_crypto::hmac::hmac_sha256(&ctx, &key[..16.min(key.len())], b"pac-shaped-input").unwrap();

            let as_rep_plaintext = format!("enc-as-rep-part-{i}-payload-padding-out-to-a-reasonable-length").into_bytes();
            let as_rep_cipher = kerberos::encrypt(&ctx, enctype, &key, 3, &as_rep_plaintext).unwrap();
            match kerberos::decrypt(&ctx, enctype, &key, 3, &as_rep_cipher) {
                Ok(pt) if pt == as_rep_plaintext => Ok(()),
                Ok(_) => Err(format!("task {i}: AS-REP plaintext mismatch")),
                Err(e) => Err(format!("task {i}: AS-REP decrypt failed: {e}")),
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
    println!("--- {ok} ok, {fail} failed (true concurrent access, mixed enctypes) ---");
}
