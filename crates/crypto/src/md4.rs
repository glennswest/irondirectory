//! MD4 (RFC 1320), hand-rolled in pure Rust -- deliberately **not** part
//! of this crate's FIPS boundary (#19).
//!
//! MD4 is not a FIPS-approved algorithm and has no place in `FipsContext`/
//! `ossl` (the `ossl` crate itself doesn't even expose it -- only SHA-1/
//! SHA-2/SHA-3 and, behind a feature flag, MD5). It exists here for
//! exactly one reason: MS-NRPC's Netlogon Secure Channel handshake
//! (`NetrServerAuthenticate3`) derives its shared session key from a
//! computer account's **NTOWF** (`NT hash = MD4(UTF-16LE(password))`) --
//! true even in the modern `NETLOGON_NEG_SUPPORTS_AES` negotiation
//! variant, where AES only encrypts channel traffic *after* that key is
//! established. There is no FIPS-approved substitute; real Windows and
//! Samba both still compute it this way. This is a narrow, cited
//! exception to D4 ("AES-only Kerberos, no NTLM/RC4/DES/MD4/MD5") for
//! computer-account NETLOGON interop only -- user Kerberos keys
//! (PBKDF2, `crate::pbkdf2`) and all ordinary hashing (`crate::digest`)
//! remain untouched and fully FIPS-compliant.
//!
//! Pure Rust, no OpenSSL/`ossl` involvement at all -- this can't
//! accidentally load a non-FIPS algorithm through the same library
//! context real FIPS-audited operations use, since it doesn't touch
//! that context in the first place.

fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// MD4 digest of `message` (RFC 1320).
pub fn md4(message: &[u8]) -> [u8; 16] {
    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    let bit_len = (message.len() as u64).wrapping_mul(8);
    let mut padded = message.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    for block in padded.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        // Round 1: F, no constant, k = 0..15 in order.
        for i in 0..16 {
            let s = [3u32, 7, 11, 19][i % 4];
            let k = i;
            let t = a.wrapping_add(f(b, c, d)).wrapping_add(x[k]);
            (a, d, c, b) = (d, c, b, t.rotate_left(s));
        }
        // Round 2: G, constant 0x5A827999, k grouped by column.
        const ROUND2_ORDER: [usize; 16] = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
        for i in 0..16 {
            let s = [3u32, 5, 9, 13][i % 4];
            let k = ROUND2_ORDER[i];
            let t = a.wrapping_add(g(b, c, d)).wrapping_add(x[k]).wrapping_add(0x5A82_7999);
            (a, d, c, b) = (d, c, b, t.rotate_left(s));
        }
        // Round 3: H, constant 0x6ED9EBA1, k in bit-reversed-pair order.
        const ROUND3_ORDER: [usize; 16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
        for i in 0..16 {
            let s = [3u32, 9, 11, 15][i % 4];
            let k = ROUND3_ORDER[i];
            let t = a.wrapping_add(h(b, c, d)).wrapping_add(x[k]).wrapping_add(0x6ED9_EBA1);
            (a, d, c, b) = (d, c, b, t.rotate_left(s));
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// `NTOWF(password) = MD4(UTF-16LE(password))` -- the "NT hash" MS-NRPC's
/// Netlogon Secure Channel uses as a computer account's shared secret
/// (MS-NRPC 3.1.4.3.2/3.1.4.3.3; same convention as NTLM's NT hash).
pub fn ntowf(password: &str) -> [u8; 16] {
    let utf16le: Vec<u8> = password.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    md4(&utf16le)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1320 Appendix A.5's own test suite -- verified against the
    // published spec, not re-derived from this implementation.
    #[test]
    fn rfc1320_test_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
            (b"abc", "a448017aaf21d8525fc10ae87ef6db41"),
            (b"message digest", "d9130a8164549fe818874806e1c7014b"),
            (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
            (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536",
            ),
        ];
        for (input, expected) in cases {
            let digest = md4(input);
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(&hex, expected, "MD4({:?})", String::from_utf8_lossy(input));
        }
    }

    #[test]
    fn ntowf_is_md4_of_utf16le_password() {
        let expected = md4(&"password".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>());
        assert_eq!(ntowf("password"), expected);
    }
}
