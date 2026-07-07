//! Kerberos principal storage on top of `iron-store`'s `Entry` (#5).
//!
//! A principal's Kerberos material lives as extra attributes on its
//! regular DIT entry (the same entry `iron-ldap` serves) -- there's no
//! separate "Kerberos database"; `iron-kdc` and `iron-ldap` share one
//! DIT over the same fastetcd partition (D2/D8).
//!
//! Deliberately NOT derived from the LDAP `userPassword` attribute:
//! `userPassword` holds a PBKDF2 hash (D4), and Kerberos string-to-key
//! needs the original passphrase, which is never stored anywhere after
//! it's hashed. Kerberos keys are instead derived and stored *once*, at
//! the moment a password is set, via [`set_password`] -- currently only
//! reachable through `iron-kdc-ctl` (an admin path), not automatically
//! from an LDAP password change. Wiring the two together (so an LDAP
//! `userPassword` modify also refreshes Kerberos keys) is a natural
//! follow-up, out of scope for this pass.
//!
//! Attributes used (all lowercase, matching `Entry`'s case folding):
//! - `krbprincipalname`: `<primary>[/<instance>]@<REALM>`.
//! - `krbsalt`: hex-encoded salt, always >= [`iron_crypto::kerberos::MIN_SALT_LEN`]
//!   bytes (see docs/FIPS.md) and always sent explicitly via
//!   PA-ETYPE-INFO2 -- clients never need to guess it.
//! - `krbkey`: one value per supported enctype, `<etype>:<kvno>:<hex-key>`.

use iron_crypto::kerberos::{self, Enctype};
use iron_crypto::FipsContext;
use iron_store::model::Entry;

pub const ATTR_PRINCIPAL_NAME: &str = "krbprincipalname";
pub const ATTR_SALT: &str = "krbsalt";
pub const ATTR_KEY: &str = "krbkey";

/// Enctypes a freshly-set password gets keys for, in preference order
/// (D4: prefer RFC 8009's aes256-cts-hmac-sha384-192; aes256-cts-hmac-
/// sha1-96 acceptable for older clients). The 128-bit variants are
/// deliberately not issued by default -- nothing in this deployment
/// needs them, and every principal can still request public/etype-list
/// negotiation to include them later if that changes.
pub const DEFAULT_ENCTYPES: [Enctype; 2] = [Enctype::Aes256CtsHmacSha384_192, Enctype::Aes256CtsHmacSha1_96];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("crypto error: {0}")]
    Crypto(#[from] iron_crypto::Error),
    #[error("no {0} attribute on entry")]
    MissingAttr(&'static str),
    #[error("malformed {0} attribute value: {1:?}")]
    Malformed(&'static str, String),
    #[error("no key found for etype {0}")]
    NoKeyForEtype(i32),
}

pub struct PrincipalKey {
    pub enctype: Enctype,
    pub kvno: u32,
    pub key: Vec<u8>,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Derives and stores fresh Kerberos keys (for [`DEFAULT_ENCTYPES`]) from
/// `password`, generating a new random salt (>= the FIPS minimum) and
/// resetting `kvno` to 1. Overwrites any existing `krbsalt`/`krbkey`
/// attributes -- there is no key history/rollover in this pass.
///
/// The salt is a hex string of random bytes, not the raw random bytes
/// themselves: it's sent to clients over the wire inside PA-ETYPE-INFO2's
/// `salt` field, which is a `GeneralString` -- `rasn-kerberos` validates
/// that against a specific permitted character set (C0 controls, space,
/// Basic Latin, DELETE, Latin-1 Supplement) that excludes some byte
/// values, so raw uniformly-random bytes fail to encode. Hex digits are
/// always safely within the permitted set; this doesn't weaken anything
/// since a PBKDF2 salt's job is domain separation, not secrecy.
pub fn set_password(ctx: &FipsContext, entry: &mut Entry, principal_name: &str, password: &[u8]) -> Result<(), Error> {
    let salt = to_hex(&kerberos::random_bytes(ctx, kerberos::MIN_SALT_LEN)?);
    let mut key_values = Vec::with_capacity(DEFAULT_ENCTYPES.len());
    for enctype in DEFAULT_ENCTYPES {
        let key = kerberos::string_to_key(ctx, enctype, password, salt.as_bytes(), None)?;
        key_values.push(format!("{}:1:{}", enctype.etype_number(), to_hex(&key)));
    }
    entry.set(ATTR_PRINCIPAL_NAME, [principal_name.to_string()]);
    entry.set(ATTR_SALT, [salt]);
    entry.set(ATTR_KEY, key_values);
    Ok(())
}

/// The principal name stored on `entry`.
pub fn principal_name(entry: &Entry) -> Result<&str, Error> {
    entry
        .get(ATTR_PRINCIPAL_NAME)
        .and_then(|v| v.first())
        .map(String::as_str)
        .ok_or(Error::MissingAttr(ATTR_PRINCIPAL_NAME))
}

/// Every Kerberos key stored on `entry`.
pub fn keys(entry: &Entry) -> Result<Vec<PrincipalKey>, Error> {
    let values = entry.get(ATTR_KEY).ok_or(Error::MissingAttr(ATTR_KEY))?;
    values
        .iter()
        .map(|v| {
            let mut parts = v.splitn(3, ':');
            let (Some(etype_str), Some(kvno_str), Some(hex_key)) = (parts.next(), parts.next(), parts.next()) else {
                return Err(Error::Malformed(ATTR_KEY, v.clone()));
            };
            let etype_num: i32 = etype_str.parse().map_err(|_| Error::Malformed(ATTR_KEY, v.clone()))?;
            let enctype = Enctype::try_from(etype_num).map_err(|_| Error::Malformed(ATTR_KEY, v.clone()))?;
            let kvno: u32 = kvno_str.parse().map_err(|_| Error::Malformed(ATTR_KEY, v.clone()))?;
            let key = from_hex(hex_key).ok_or_else(|| Error::Malformed(ATTR_KEY, v.clone()))?;
            Ok(PrincipalKey { enctype, kvno, key })
        })
        .collect()
}

/// The stored key for a specific enctype, if present.
pub fn key_for_enctype(entry: &Entry, enctype: Enctype) -> Result<PrincipalKey, Error> {
    keys(entry)?
        .into_iter()
        .find(|k| k.enctype == enctype)
        .ok_or(Error::NoKeyForEtype(enctype.etype_number()))
}

/// The stored salt, decoded.
pub fn salt(entry: &Entry) -> Result<Vec<u8>, Error> {
    let salt = entry.get(ATTR_SALT).and_then(|v| v.first()).ok_or(Error::MissingAttr(ATTR_SALT))?;
    Ok(salt.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_password_then_read_back() {
        let ctx = FipsContext::new().unwrap();
        let mut entry = Entry::new();
        set_password(&ctx, &mut entry, "alice@IRON.LO", b"correcthorsebatterystaple").unwrap();

        assert_eq!(principal_name(&entry).unwrap(), "alice@IRON.LO");
        let s = salt(&entry).unwrap();
        assert!(s.len() >= kerberos::MIN_SALT_LEN);

        let all = keys(&entry).unwrap();
        assert_eq!(all.len(), DEFAULT_ENCTYPES.len());
        for enctype in DEFAULT_ENCTYPES {
            let k = key_for_enctype(&entry, enctype).unwrap();
            assert_eq!(k.kvno, 1);
            assert_eq!(k.key.len(), enctype.key_len());
            // Re-deriving with the stored salt must reproduce the same key.
            let rederived = kerberos::string_to_key(&ctx, enctype, b"correcthorsebatterystaple", &s, None).unwrap();
            assert_eq!(k.key, rederived);
        }
    }

    #[test]
    fn missing_attrs_error_cleanly() {
        let entry = Entry::new();
        assert!(matches!(principal_name(&entry), Err(Error::MissingAttr(_))));
        assert!(matches!(salt(&entry), Err(Error::MissingAttr(_))));
        assert!(matches!(keys(&entry), Err(Error::MissingAttr(_))));
    }
}
