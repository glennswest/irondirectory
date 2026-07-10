//! Asymmetric signing (D4): ES256 (ECDSA P-256 + SHA-256, RFC 7518 §3.4),
//! the FIPS 186-4/186-5-approved algorithm `iron-oidc` (#15) signs ID
//! tokens with. Everything here routes through the same OpenSSL FIPS
//! provider as the rest of this crate -- `ossl`'s `EvpPkey`/`OsslSignature`
//! wrap `EVP_PKEY_keygen`/`EVP_DigestSign`/`EVP_DigestVerify` under the
//! hood, exactly like `pbkdf2`/`kerberos` already do for their own
//! operations.
//!
//! **JOSE vs. DER signature encoding.** OpenSSL's ECDSA signing always
//! produces a DER-encoded `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s
//! INTEGER }`. JWS's ES256 (RFC 7518 §3.4) instead requires the fixed-size
//! concatenation `R || S` (32 bytes each for P-256, "P1363"/"JOSE" format).
//! `ossl` has no built-in option to emit the JOSE form directly (its only
//! `raw`-signature knobs are for ML-DSA/SLH-DSA, not ECDSA), so this
//! module hand-converts between them (`der_to_jose`/`jose_to_der`) --
//! deliberately, rather than depending on a general-purpose ASN.1 decoder
//! for a two-integer structure this simple (same reasoning as
//! `iron-ldap::framing`'s hand-rolled BER tag/length parsing).

use crate::{Error, FipsContext};
use ossl::pkey::{EvpPkey, EvpPkeyType, PkeyData};
use ossl::signature::{OsslSignature, SigAlg, SigOp};

/// Byte length of each of R and S for a P-256 ECDSA signature -- also the
/// byte length of the raw `x`/`y` public key coordinates.
const P256_COMPONENT_LEN: usize = 32;

/// An ephemeral ES256 signing keypair. Generated fresh by [`EcKeyPair::generate`]
/// -- there is no persistence across process restarts yet (a real
/// deployment would need to load/save this, e.g. via a configured PEM/PARAM
/// file, so previously-issued tokens and a previously-published JWKS stay
/// valid across a restart; out of scope for #15's first vertical slice,
/// documented rather than silently absent).
pub struct EcKeyPair {
    pkey: EvpPkey,
    /// Raw uncompressed point (`0x04 || X || Y`), cached at construction
    /// time so [`EcKeyPair::public_xy`] doesn't need to re-export on every
    /// call (e.g. once per `/jwks.json` request).
    pubkey_uncompressed: Vec<u8>,
}

impl EcKeyPair {
    /// Generates a fresh P-256 keypair.
    pub fn generate(ctx: &FipsContext) -> Result<Self, Error> {
        let pkey = EvpPkey::generate(ctx.inner(), EvpPkeyType::P256)?;
        let PkeyData::Ecc(mut ecc) = pkey.export()? else {
            return Err(Error::Ossl);
        };
        let pubkey_uncompressed = ecc.pubkey.take().ok_or(Error::Ossl)?;
        Ok(EcKeyPair { pkey, pubkey_uncompressed })
    }

    /// The public key's raw `(x, y)` coordinates, each exactly
    /// [`P256_COMPONENT_LEN`] bytes -- the values a JWK's `"x"`/`"y"`
    /// members (base64url, unpadded) are built from.
    pub fn public_xy(&self) -> Result<(&[u8], &[u8]), Error> {
        // Uncompressed SEC1 point encoding: 0x04 || X || Y.
        let want = 1 + 2 * P256_COMPONENT_LEN;
        if self.pubkey_uncompressed.len() != want || self.pubkey_uncompressed[0] != 0x04 {
            return Err(Error::Ossl);
        }
        let (x, y) = self.pubkey_uncompressed[1..].split_at(P256_COMPONENT_LEN);
        Ok((x, y))
    }

    /// Signs `message` (the JWS signing input: base64url header + `.` +
    /// base64url payload), returning the 64-byte JOSE-format `R || S`
    /// signature ES256 requires.
    pub fn sign_es256(&mut self, ctx: &FipsContext, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut signer = OsslSignature::new(ctx.inner(), SigOp::Sign, SigAlg::EcdsaSha2_256, &mut self.pkey, None)?;
        let len = signer.sign(message, None)?;
        let mut der = vec![0u8; len];
        let actual = signer.sign(message, Some(&mut der))?;
        der.truncate(actual);
        der_to_jose(&der, P256_COMPONENT_LEN)
    }

    /// Verifies a JOSE-format `R || S` ES256 signature over `message`.
    pub fn verify_es256(&mut self, ctx: &FipsContext, message: &[u8], jose_signature: &[u8]) -> Result<bool, Error> {
        if jose_signature.len() != 2 * P256_COMPONENT_LEN {
            return Ok(false);
        }
        let der = jose_to_der(jose_signature, P256_COMPONENT_LEN);
        let mut verifier = OsslSignature::new(ctx.inner(), SigOp::Verify, SigAlg::EcdsaSha2_256, &mut self.pkey, None)?;
        Ok(verifier.verify(message, Some(&der)).is_ok())
    }
}

/// Converts a DER `ECDSA-Sig-Value` to the fixed-size JOSE `R || S` form
/// (RFC 7518 §3.4), left-padding each component to `component_len` bytes
/// and stripping the sign-bit padding byte DER adds when an integer's
/// high bit is set. Assumes short-form (single-byte) DER lengths
/// throughout, valid for any curve up to P-384 -- P-521 would need a
/// long-form length parser this doesn't have.
fn der_to_jose(der: &[u8], component_len: usize) -> Result<Vec<u8>, Error> {
    let mut pos = 0;
    let next = |pos: &mut usize, n: usize| -> Result<&[u8], Error> {
        let slice = der.get(*pos..*pos + n).ok_or(Error::Ossl)?;
        *pos += n;
        Ok(slice)
    };
    if next(&mut pos, 1)? != [0x30] {
        return Err(Error::Ossl);
    }
    let _seq_len = next(&mut pos, 1)?[0];

    let read_integer = |pos: &mut usize| -> Result<Vec<u8>, Error> {
        if next(pos, 1)? != [0x02] {
            return Err(Error::Ossl);
        }
        let len = next(pos, 1)?[0] as usize;
        let bytes = next(pos, len)?;
        // Strip a single DER sign-bit padding byte, if present.
        let bytes = if bytes.len() > component_len && bytes[0] == 0x00 { &bytes[1..] } else { bytes };
        if bytes.len() > component_len {
            return Err(Error::Ossl);
        }
        let mut padded = vec![0u8; component_len];
        padded[component_len - bytes.len()..].copy_from_slice(bytes);
        Ok(padded)
    };
    let r = read_integer(&mut pos)?;
    let s = read_integer(&mut pos)?;

    let mut out = r;
    out.extend_from_slice(&s);
    Ok(out)
}

/// The inverse of [`der_to_jose`]: rebuilds a DER `ECDSA-Sig-Value` from
/// the fixed-size JOSE `R || S` form, for handing to `ossl`'s verifier
/// (which only accepts DER). `raw` must be exactly `2 * component_len`
/// bytes -- callers check this before calling.
fn jose_to_der(raw: &[u8], component_len: usize) -> Vec<u8> {
    fn encode_integer(component: &[u8]) -> Vec<u8> {
        // Strip leading zero bytes, but keep at least one.
        let mut trimmed = component;
        while trimmed.len() > 1 && trimmed[0] == 0 {
            trimmed = &trimmed[1..];
        }
        let mut value = Vec::with_capacity(trimmed.len() + 1);
        // DER INTEGER is signed; if the high bit is set, prepend 0x00 so
        // it isn't misread as negative.
        if trimmed[0] & 0x80 != 0 {
            value.push(0x00);
        }
        value.extend_from_slice(trimmed);
        let mut out = vec![0x02, value.len() as u8];
        out.extend_from_slice(&value);
        out
    }
    let (r, s) = raw.split_at(component_len);
    let r_der = encode_integer(r);
    let s_der = encode_integer(s);
    let mut out = vec![0x30, (r_der.len() + s_der.len()) as u8];
    out.extend_from_slice(&r_der);
    out.extend_from_slice(&s_der);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_roundtrip() {
        let ctx = FipsContext::new().unwrap();
        let mut kp = EcKeyPair::generate(&ctx).unwrap();
        let msg = b"header.payload";
        let sig = kp.sign_es256(&ctx, msg).unwrap();
        assert_eq!(sig.len(), 64, "JOSE ES256 signature must be exactly 64 bytes");
        assert!(kp.verify_es256(&ctx, msg, &sig).unwrap());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let ctx = FipsContext::new().unwrap();
        let mut kp = EcKeyPair::generate(&ctx).unwrap();
        let sig = kp.sign_es256(&ctx, b"original").unwrap();
        assert!(!kp.verify_es256(&ctx, b"tampered", &sig).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_length_signature() {
        let ctx = FipsContext::new().unwrap();
        let mut kp = EcKeyPair::generate(&ctx).unwrap();
        assert!(!kp.verify_es256(&ctx, b"msg", &[0u8; 10]).unwrap());
    }

    #[test]
    fn public_xy_is_32_bytes_each() {
        let ctx = FipsContext::new().unwrap();
        let kp = EcKeyPair::generate(&ctx).unwrap();
        let (x, y) = kp.public_xy().unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
    }

    #[test]
    fn der_jose_roundtrip_with_high_bit_components() {
        // Components whose top bit is set need a DER sign-bit pad byte;
        // exercise that path explicitly rather than relying on random
        // signatures happening to hit it.
        let mut raw = vec![0xffu8; 32];
        raw.extend(vec![0x01u8; 32]);
        let der = jose_to_der(&raw, 32);
        let back = der_to_jose(&der, 32).unwrap();
        assert_eq!(raw, back);
    }

    #[test]
    fn der_jose_roundtrip_with_leading_zero_components() {
        let mut raw = vec![0u8; 31];
        raw.push(0x42);
        raw.extend(vec![0u8; 31]);
        raw.push(0x07);
        let der = jose_to_der(&raw, 32);
        let back = der_to_jose(&der, 32).unwrap();
        assert_eq!(raw, back);
    }
}
