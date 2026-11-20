//! MS-SAMR 3.2.2.4 "AES Cipher Usage" (#53): the AEAD-AES-256-CBC-HMAC-SHA512
//! that protects a password in `SAMPR_ENCRYPTED_PASSWORD_AES` (2.2.6.32), as
//! `SamrSetInformationUser2` at `UserInternal7InformationNew` (31) carries it.
//!
//! The content encryption key (CEK) is the RPC connection's session key --
//! for `ncacn_np`, the SMB session's application key, which rocketsmbd hands
//! over in the pipe preamble ([`crate::pipe`]). From it:
//!
//! - encryption key = HMAC-SHA512(CEK, "Microsoft SAM encryption key
//!   AEAD-AES-256-CBC-HMAC-SHA512 16\0"), first 32 bytes;
//! - MAC key = HMAC-SHA512(CEK, "Microsoft SAM MAC key
//!   AEAD-AES-256-CBC-HMAC-SHA512 16\0");
//! - Cipher = AES-256-CBC(encryption key, IV = Salt, PKCS#7) of the 514-byte
//!   password buffer (u16 byte length, the UTF-16LE password, random fill);
//! - AuthData = HMAC-SHA512(MAC key, 0x01 || Salt || Cipher || 0x01).
//!
//! All FIPS-approved primitives through the provider (D4), unlike the RC4
//! levels (`UserInternal4/5`, 23-26), which are not served.
//! Known-answer tests: Samba's `lib/crypto/tests/test_gnutls_aead_aes_256_cbc_hmac_sha512.c`
//! vectors, taken from a Windows Server 2022 trace.

use iron_crypto::FipsContext;

const ENC_KEY_SALT: &[u8] = b"Microsoft SAM encryption key AEAD-AES-256-CBC-HMAC-SHA512 16\0";
const MAC_KEY_SALT: &[u8] = b"Microsoft SAM MAC key AEAD-AES-256-CBC-HMAC-SHA512 16\0";
const VERSION_BYTE: u8 = 1;
const VERSION_BYTE_LEN: u8 = 1;
/// The plaintext: a u16 length and 512 bytes of password + fill.
pub const BUFFER_LEN: usize = 514;

/// `SAMPR_ENCRYPTED_PASSWORD_AES` as it arrives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedPasswordAes {
    pub auth_data: [u8; 64],
    pub salt: [u8; 16],
    pub cipher: Vec<u8>,
    pub pbkdf2_iterations: u64,
}

fn keys(ctx: &FipsContext, cek: &[u8]) -> Result<([u8; 32], [u8; 64]), String> {
    let enc = iron_crypto::hmac::hmac_sha512(ctx, cek, ENC_KEY_SALT).map_err(|e| e.to_string())?;
    let mac = iron_crypto::hmac::hmac_sha512(ctx, cek, MAC_KEY_SALT).map_err(|e| e.to_string())?;
    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&enc[..32]);
    Ok((enc_key, mac))
}

fn auth_tag(ctx: &FipsContext, mac_key: &[u8; 64], salt: &[u8; 16], cipher: &[u8]) -> Result<[u8; 64], String> {
    let mut data = Vec::with_capacity(2 + salt.len() + cipher.len());
    data.push(VERSION_BYTE);
    data.extend_from_slice(salt);
    data.extend_from_slice(cipher);
    data.push(VERSION_BYTE_LEN);
    iron_crypto::hmac::hmac_sha512(ctx, mac_key, &data).map_err(|e| e.to_string())
}

/// Encrypts `plaintext` under `cek` with `salt` as the IV (the client's
/// side; used by the tests and by `iron-simulate`-style clients).
pub fn encrypt(ctx: &FipsContext, cek: &[u8], salt: [u8; 16], plaintext: &[u8]) -> Result<EncryptedPasswordAes, String> {
    let (enc_key, mac_key) = keys(ctx, cek)?;
    let cipher = iron_crypto::aead::aes256_cbc_pkcs7(ctx, &enc_key, &salt, plaintext, true).map_err(|e| e.to_string())?;
    let auth_data = auth_tag(ctx, &mac_key, &salt, &cipher)?;
    Ok(EncryptedPasswordAes { auth_data, salt, cipher, pbkdf2_iterations: 0 })
}

/// Checks the AuthData, then decrypts: the plaintext buffer, or why not.
pub fn decrypt(ctx: &FipsContext, cek: &[u8], enc: &EncryptedPasswordAes) -> Result<Vec<u8>, String> {
    if cek.is_empty() {
        return Err("no session key".into());
    }
    let (enc_key, mac_key) = keys(ctx, cek)?;
    let tag = auth_tag(ctx, &mac_key, &enc.salt, &enc.cipher)?;
    // Constant time: the tag is a MAC.
    if tag.iter().zip(enc.auth_data.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) != 0 {
        return Err("AuthData does not match: wrong session key or altered buffer".into());
    }
    iron_crypto::aead::aes256_cbc_pkcs7(ctx, &enc_key, &enc.salt, &enc.cipher, false).map_err(|_| "cipher does not decrypt".to_string())
}

/// The password bytes (UTF-16LE) in a decrypted 514-byte buffer.
pub fn password_from_buffer(buffer: &[u8]) -> Result<Vec<u8>, String> {
    if buffer.len() != BUFFER_LEN {
        return Err(format!("password buffer is {} bytes, not {BUFFER_LEN}", buffer.len()));
    }
    let len = u16::from_le_bytes([buffer[0], buffer[1]]) as usize;
    if len == 0 || len > BUFFER_LEN - 2 || len % 2 != 0 {
        return Err(format!("password length {len} is not a UTF-16 length within 512 bytes"));
    }
    Ok(buffer[2..2 + len].to_vec())
}

/// The 514-byte buffer for `password` (UTF-16LE), filled with `fill`.
pub fn buffer_for(password_utf16: &[u8], fill: &[u8]) -> Result<Vec<u8>, String> {
    if password_utf16.is_empty() || password_utf16.len() > BUFFER_LEN - 2 {
        return Err("password does not fit".into());
    }
    let mut b = Vec::with_capacity(BUFFER_LEN);
    b.extend_from_slice(&(password_utf16.len() as u16).to_le_bytes());
    b.extend_from_slice(password_utf16);
    b.extend(fill.iter().copied().cycle().take(BUFFER_LEN - b.len()));
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(parts: &[&str]) -> Vec<u8> {
        let s: String = parts.concat();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // Samba lib/crypto/tests/test_gnutls_aead_aes_256_cbc_hmac_sha512.c,
    // "from a Windows Server 2022 time trace".
    const SESSION_KEY: &str = "9617399ca7549e41c479714ba0895b0a";
    const SALT: &str = "ac9cadcb66ed2d05551318a9a56bf96f";
    const PLAINTEXT: &[&str] = &[
        "14005000610024002400770030007200640040003200c2347d217905ef88d711ece2ceb5d44d642d15790139b8b9895c",
        "4e71bdf0140c8772a5fa90be6255ad7fe97f0d20193a76beb2146d5b251c673a23451f7e36a095b7a7b133e1c4b6e62d",
        "d82fe7df01e8ba025436e9b65e00529e6400cb3c6d05437d019c221892e7a355656d2ea3536ec06726acaa98a4cbb449",
        "1360d4332c77585e5045aa1e0515185955ca143731ac63fc63a82aa999ec4987641d4edda3d0dc080017f42f9c4a17c7",
        "bd30b70e81e4d59431ffd6ccc6bb39cd72fea63d0d886840f8512be6c9aa84f3f46e5537bf5d87cea6804f8f8f7be830",
        "c32e24c73ef19fa677ca04beb5e1405943c530c8e7bfabfa8662d93a8ea93473207b611b0eca98eca1c178a9a76c8ce3",
        "217db990e2731a991d44a8d57f0a5947d0f56c14ff4a2920b5fce9f0a5359e1ca14cecb57d2d27ff7a4218b8534efbec",
        "b1c1652da4698556616d21668831dfba28c69af8b7f62a43ba9b8414cea9c9f5856f31898dfc252e98255a03f0b85d4a",
        "d44cc8624eeb07c85c9e6330fe9f0f96d0d770adcd84bc1e48a0201410a4b15b05369a6db01098bd8da2d1b2fa2337eb",
        "b00453cba1a9c488ddf980f5a9cd7bf8770b19844cef2c14a1dc9f2f41d0d033298ab9397ec97fe76364a47b4a6a33a7",
        "aaf6ca98c49b625bcd5382bff00b9ce7b2441b887161a1369e7a0a3c20d8ffa12366",
    ];
    const ENC_KEY: &str = "d9b28ba11574f65a73ea82ba993754251b2720aaa3f7d5238f02e6e7215bd2a9";
    const MAC_KEY: &[&str] = &["8a04466d5ee62db8329eabbea48b3f6c3c1ca1aab8ec9c43bc4b91356f3ac4e2", "629be8126373942a5947fcd8785d6d681b9f35319027c8ab888d80ad7beacdf5"];
    const AUTH_TAG: &[&str] = &["0a7aaf9ec16e0312517604b20117eb04f3dde3a790fdc0ca9631bf309ec5055a", "bca8c1ba568f975a4e2a140e4bf36d9a2a6ec35e9d510af6b21beee7f30930c9"];

    #[test]
    fn keys_match_windows() {
        let ctx = FipsContext::new().unwrap();
        let (enc, mac) = keys(&ctx, &hex(&[SESSION_KEY])).unwrap();
        assert_eq!(enc.to_vec(), hex(&[ENC_KEY]));
        assert_eq!(mac.to_vec(), hex(MAC_KEY));
    }

    #[test]
    fn encrypt_matches_windows_and_decrypts_back() {
        let ctx = FipsContext::new().unwrap();
        let cek = hex(&[SESSION_KEY]);
        let salt: [u8; 16] = hex(&[SALT]).try_into().unwrap();
        let pt = hex(PLAINTEXT);
        let enc = encrypt(&ctx, &cek, salt, &pt).unwrap();
        assert_eq!(enc.auth_data.to_vec(), hex(AUTH_TAG));
        assert_eq!(enc.cipher.len(), 528); // 514 + PKCS#7 to 33 blocks
        let back = decrypt(&ctx, &cek, &enc).unwrap();
        assert_eq!(back, pt);
        let pw = password_from_buffer(&back).unwrap();
        let units: Vec<u16> = pw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        assert_eq!(String::from_utf16(&units).unwrap(), "Pa$$w0rd@2");
    }

    #[test]
    fn decrypt_refuses_a_wrong_key_or_an_altered_buffer() {
        let ctx = FipsContext::new().unwrap();
        let cek = hex(&[SESSION_KEY]);
        let enc = encrypt(&ctx, &cek, [7u8; 16], &buffer_for(&[0x41, 0], &[0x5a]).unwrap()).unwrap();
        assert!(decrypt(&ctx, &[0u8; 16], &enc).unwrap_err().contains("AuthData"));
        let mut altered = enc.clone();
        altered.cipher[0] ^= 1;
        assert!(decrypt(&ctx, &cek, &altered).unwrap_err().contains("AuthData"));
        let mut salted = enc.clone();
        salted.salt[0] ^= 1;
        assert!(decrypt(&ctx, &cek, &salted).is_err());
        assert!(decrypt(&ctx, &[], &enc).is_err());
    }

    #[test]
    fn buffer_lengths() {
        assert!(password_from_buffer(&[0u8; 10]).is_err());
        let mut b = vec![0u8; BUFFER_LEN];
        b[0] = 3; // odd: not UTF-16
        assert!(password_from_buffer(&b).is_err());
        b[0] = 0;
        b[1] = 2; // 512: fits
        assert_eq!(password_from_buffer(&b).unwrap().len(), 512);
        b[1] = 3; // 768: does not
        assert!(password_from_buffer(&b).is_err());
    }
}
