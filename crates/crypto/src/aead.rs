use crate::{Error, FipsContext};
use ossl::cipher::{AeadParams, AesSize, EncAlg, OsslCipher};
use ossl::OsslSecret;

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

/// AES-256-GCM encrypt. `out` must be `plaintext.len() + TAG_LEN` bytes;
/// the tag is appended after the ciphertext.
pub fn aes256_gcm_encrypt(
    ctx: &FipsContext,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() != plaintext.len() + TAG_LEN {
        return Err(Error::BufferSize);
    }

    let params = AeadParams::new(Some(aad.to_vec()), TAG_LEN, 0);
    let mut cipher = OsslCipher::new(
        ctx.inner(),
        EncAlg::AesGcm(AesSize::Aes256),
        true,
        OsslSecret::from_slice(key),
        Some(nonce.to_vec()),
        Some(params),
    )?;

    let (ct, tag_buf) = out.split_at_mut(plaintext.len());
    let mut n = cipher.update(plaintext, ct)?;
    n += cipher.finalize(&mut ct[n..])?;
    debug_assert_eq!(n, plaintext.len());
    cipher.get_tag(&mut tag_buf[..TAG_LEN])?;
    Ok(plaintext.len() + TAG_LEN)
}

/// AES-256-GCM decrypt + verify. `ciphertext` must include the trailing
/// TAG_LEN-byte tag. Returns the plaintext length written to `out`, or an
/// error if authentication fails.
pub fn aes256_gcm_decrypt(
    ctx: &FipsContext,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if ciphertext.len() < TAG_LEN {
        return Err(Error::BufferSize);
    }
    let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
    if out.len() != ct.len() {
        return Err(Error::BufferSize);
    }

    let params = AeadParams::new(Some(aad.to_vec()), TAG_LEN, 0);
    let mut cipher = OsslCipher::new(
        ctx.inner(),
        EncAlg::AesGcm(AesSize::Aes256),
        false,
        OsslSecret::from_slice(key),
        Some(nonce.to_vec()),
        Some(params),
    )?;
    cipher.set_tag(tag)?;

    let mut n = cipher.update(ct, out)?;
    n += cipher.finalize(&mut out[n..])?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cross-checked against Python's `cryptography` (OpenSSL-backed)
    // AESGCM(key=32 zero bytes).encrypt(nonce=12 zero bytes, pt, aad).
    #[test]
    fn aes256_gcm_roundtrip_matches_reference() {
        let ctx = FipsContext::new().unwrap();
        let key = [0u8; 32];
        let nonce = [0u8; NONCE_LEN];
        let aad = b"header";
        let pt = b"the quick brown fox";

        let mut ct = vec![0u8; pt.len() + TAG_LEN];
        aes256_gcm_encrypt(&ctx, &key, &nonce, aad, pt, &mut ct).unwrap();
        assert_eq!(
            hex::encode(&ct),
            "bacf251d3c15020d6c6ea7a1d584f338140f7befdc5b9b78275b09a5b7a00c8a94830d"
        );

        let mut decrypted = vec![0u8; pt.len()];
        aes256_gcm_decrypt(&ctx, &key, &nonce, aad, &ct, &mut decrypted).unwrap();
        assert_eq!(&decrypted, pt);
    }

    #[test]
    fn aes256_gcm_rejects_tampered_ciphertext() {
        let ctx = FipsContext::new().unwrap();
        let key = [0u8; 32];
        let nonce = [0u8; NONCE_LEN];
        let pt = b"the quick brown fox";

        let mut ct = vec![0u8; pt.len() + TAG_LEN];
        aes256_gcm_encrypt(&ctx, &key, &nonce, b"header", pt, &mut ct).unwrap();
        ct[0] ^= 0xff;

        let mut decrypted = vec![0u8; pt.len()];
        assert!(aes256_gcm_decrypt(&ctx, &key, &nonce, b"header", &ct, &mut decrypted).is_err());
    }
}
