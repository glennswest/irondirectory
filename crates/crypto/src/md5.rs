//! MD5 (RFC 1321), hand-rolled in pure Rust -- deliberately **not** part of
//! this crate's FIPS boundary (#65), the same kind of cited D4 exception as
//! [`crate::md4`].
//!
//! It exists for exactly one use: the `Bnd` field of the Kerberos GSS-API
//! checksum (RFC 4121 §4.1.1.2, inherited from RFC 1964 §1.1.1), which is
//! defined as the MD5 of the channel bindings and has no other hash. An
//! acceptor checking channel bindings -- what Active Directory calls "LDAP
//! channel binding" (ADV190023), binding a GSSAPI bind to the TLS
//! connection it arrived on via RFC 5929 `tls-server-end-point` -- must
//! compute it. MD5 keys nothing here and protects no secret: `Bnd` travels
//! inside the Authenticator, which is encrypted and integrity-protected
//! under the ticket's session key; MD5 only condenses public data (the
//! hash of our own certificate) into the fixed 16-byte slot. The owner
//! decided this on #65 (2026-11-20: "Do what AD does").
//!
//! Pure Rust, no OpenSSL/`ossl` involvement: it cannot load a non-FIPS
//! algorithm into the library context the FIPS-audited operations use.

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4,
    11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// RFC 1321 §3.4's table T: `floor(abs(sin(i + 1)) * 2^32)`.
const K: [u32; 64] = [
    0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee, 0xf57c_0faf, 0x4787_c62a, 0xa830_4613, 0xfd46_9501,
    0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be, 0x6b90_1122, 0xfd98_7193, 0xa679_438e, 0x49b4_0821,
    0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa, 0xd62f_105d, 0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8,
    0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed, 0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a,
    0xfffa_3942, 0x8771_f681, 0x6d9d_6122, 0xfde5_380c, 0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70,
    0x289b_7ec6, 0xeaa1_27fa, 0xd4ef_3085, 0x0488_1d05, 0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665,
    0xf429_2244, 0x432a_ff97, 0xab94_23a7, 0xfc93_a039, 0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
    0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1, 0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb, 0xeb86_d391,
];

/// MD5 digest of `message` (RFC 1321).
pub fn md5(message: &[u8]) -> [u8; 16] {
    let mut h: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    let bit_len = (message.len() as u64).wrapping_mul(8);
    let mut padded = message.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    for block in padded.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (word, chunk) in m.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let [mut a, mut b, mut c, mut d] = h;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let t = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            (a, d, c) = (d, c, b);
            b = b.wrapping_add(t.rotate_left(S[i]));
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
    }

    let mut out = [0u8; 16];
    for (dst, word) in out.chunks_exact_mut(4).zip(h) {
        dst.copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1321 Appendix A.5's test suite.
    #[test]
    fn rfc1321_test_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", "d41d8cd98f00b204e9800998ecf8427e"),
            (b"a", "0cc175b9c0f1b6a831c399e269772661"),
            (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
            (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (b"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
            (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (input, expected) in cases {
            let hex: String = md5(input).iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(&hex, expected, "MD5({:?})", String::from_utf8_lossy(input));
        }
    }

    // Messages around the 56/64-byte padding boundaries, checked against
    // values computed with Python's hashlib.md5.
    #[test]
    fn padding_boundaries() {
        for (n, expected) in [
            (55usize, "ef1772b6dff9a122358552954ad0df65"),
            (56, "3b0c8ac703f828b04c6c197006d17218"),
            (64, "014842d480b571495a4a0363793f7367"),
            (119, "8a7bd0732ed6a28ce75f6dabc90e1613"),
        ] {
            let hex: String = md5(&vec![b'a'; n]).iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, expected, "MD5('a' * {n})");
        }
    }
}
