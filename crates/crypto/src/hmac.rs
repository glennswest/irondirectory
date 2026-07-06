use crate::{Error, FipsContext};
use ossl::mac::{MacAlg, OsslMac};
use ossl::OsslSecret;

fn hmac(
    ctx: &FipsContext,
    alg: MacAlg,
    key: &[u8],
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut m = OsslMac::new(ctx.inner(), alg, OsslSecret::from_slice(key))?;
    m.update(data)?;
    Ok(m.finalize(out)?)
}

pub fn hmac_sha256(ctx: &FipsContext, key: &[u8], data: &[u8]) -> Result<[u8; 32], Error> {
    let mut out = [0u8; 32];
    hmac(ctx, MacAlg::HmacSha2_256, key, data, &mut out)?;
    Ok(out)
}

pub fn hmac_sha512(ctx: &FipsContext, key: &[u8], data: &[u8]) -> Result<[u8; 64], Error> {
    let mut out = [0u8; 64];
    hmac(ctx, MacAlg::HmacSha2_512, key, data, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 test case 2: Key = "Jefe", Data = "what do ya want for nothing?"
    #[test]
    fn hmac_sha256_rfc4231_case2() {
        let ctx = FipsContext::new().unwrap();
        let out = hmac_sha256(&ctx, b"Jefe", b"what do ya want for nothing?").unwrap();
        assert_eq!(
            hex::encode(out),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    // RFC 4231 test case 2, HMAC-SHA-512.
    #[test]
    fn hmac_sha512_rfc4231_case2() {
        let ctx = FipsContext::new().unwrap();
        let out = hmac_sha512(&ctx, b"Jefe", b"what do ya want for nothing?").unwrap();
        assert_eq!(
            hex::encode(out),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
    }
}
