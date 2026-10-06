use crate::{Error, FipsContext};
use ossl::cipher::{AeadParams, AesSize, EncAlg, OsslCipher};
use ossl::OsslSecret;

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

/// AES-128-CFB8 (8-bit feedback), zero IV -- MS-NRPC 3.1.4.4.1's
/// Netlogon credential-encryption primitive (#19). Not authenticated
/// (no tag) -- CFB8 is a streaming mode, used here only to encrypt an
/// 8-byte challenge/credential value under a session key both sides
/// already derived via `hmac::hmac_sha256`, not for confidentiality of
/// arbitrary data. Goes through the FIPS provider like every other
/// cipher in this crate -- AES-CFB8 is itself a FIPS-approved mode; only
/// the *key derivation* feeding into this (NTOWF, `crate::md4`) is the
/// cited D4 exception, not this function.
pub fn aes128_cfb8_encrypt(ctx: &FipsContext, key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, Error> {
    aes128_cfb8(ctx, key, &[0u8; 16], data, true)
}

/// AES-128-CFB8 with an explicit IV, encrypting or decrypting. MS-NRPC's
/// Netlogon secure channel seals RPC stubs with it (#20, 3.3.4.2.1: the IV
/// is the 8-byte sequence number twice).
pub fn aes128_cfb8(ctx: &FipsContext, key: &[u8; 16], iv: &[u8; 16], data: &[u8], encrypt: bool) -> Result<Vec<u8>, Error> {
    let mut cipher = OsslCipher::new(ctx.inner(), EncAlg::AesCfb8(AesSize::Aes128), encrypt, OsslSecret::from_slice(key), Some(iv.to_vec()), None)?;
    let mut out = vec![0u8; data.len() + 16];
    let mut n = cipher.update(data, &mut out)?;
    n += cipher.finalize(&mut out[n..])?;
    out.truncate(n);
    Ok(out)
}

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

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // NIST SP 800-38A, F.3.7/F.3.8 (CFB8-AES128).
    #[test]
    fn aes128_cfb8_matches_sp800_38a() {
        let ctx = FipsContext::new().unwrap();
        let key: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        let iv: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let pt = hex("6bc1bee22e409f96e93d7e117393172aae2d");
        let ct = hex("3b79424c9c0dd436bace9e0ed4586a4f32b9");
        assert_eq!(aes128_cfb8(&ctx, &key, &iv, &pt, true).unwrap(), ct);
        assert_eq!(aes128_cfb8(&ctx, &key, &iv, &ct, false).unwrap(), pt);
    }

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
