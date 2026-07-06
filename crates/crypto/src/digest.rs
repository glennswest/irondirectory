use crate::{Error, FipsContext};
use ossl::digest::{DigestAlg, OsslDigest};

fn digest(ctx: &FipsContext, alg: DigestAlg, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut d = OsslDigest::new(ctx.inner(), alg, None)?;
    d.update(data)?;
    Ok(d.finalize(out)?)
}

pub fn sha256(ctx: &FipsContext, data: &[u8]) -> Result<[u8; 32], Error> {
    let mut out = [0u8; 32];
    digest(ctx, DigestAlg::Sha2_256, data, &mut out)?;
    Ok(out)
}

pub fn sha384(ctx: &FipsContext, data: &[u8]) -> Result<[u8; 48], Error> {
    let mut out = [0u8; 48];
    digest(ctx, DigestAlg::Sha2_384, data, &mut out)?;
    Ok(out)
}

pub fn sha512(ctx: &FipsContext, data: &[u8]) -> Result<[u8; 64], Error> {
    let mut out = [0u8; 64];
    digest(ctx, DigestAlg::Sha2_512, data, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST FIPS 180-4 short message test vectors.
    #[test]
    fn sha256_abc() {
        let ctx = FipsContext::new().unwrap();
        let out = sha256(&ctx, b"abc").unwrap();
        assert_eq!(
            hex::encode(out),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha384_abc() {
        let ctx = FipsContext::new().unwrap();
        let out = sha384(&ctx, b"abc").unwrap();
        assert_eq!(
            hex::encode(out),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn sha512_abc() {
        let ctx = FipsContext::new().unwrap();
        let out = sha512(&ctx, b"abc").unwrap();
        assert_eq!(
            hex::encode(out),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }
}
