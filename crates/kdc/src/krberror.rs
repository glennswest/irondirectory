//! `KRB-ERROR` construction (RFC 4120 §5.9.1) and the error-code
//! constants this KDC actually returns. Not every RFC 4120 error code is
//! defined here -- only the ones this implementation's error paths use.

use rasn_kerberos::{KrbError, MethodData, PrincipalName};

use crate::time::now;

pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;
pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7;
pub const KDC_ERR_ETYPE_NOSUPP: i32 = 14;
pub const KDC_ERR_PREAUTH_FAILED: i32 = 24;
pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
pub const KRB_AP_ERR_TKT_EXPIRED: i32 = 32;
pub const KRB_AP_ERR_BAD_INTEGRITY: i32 = 31;
pub const KRB_AP_ERR_SKEW: i32 = 37;
pub const KRB_AP_ERR_BADMATCH: i32 = 36;
pub const KRB_AP_ERR_MODIFIED: i32 = 41;
pub const KRB_ERR_GENERIC: i32 = 60;

/// Builds a `KRB-ERROR` message. `sname`/`realm` identify the KDC/TGS
/// itself (the "issuing principal"), not the client.
pub fn build(error_code: i32, realm: &str, sname: PrincipalName, e_text: Option<String>, e_data: Option<Vec<u8>>) -> KrbError {
    let (stime, susec) = now();
    KrbError {
        pvno: 5.into(),
        msg_type: 30.into(), // KRB_ERROR
        ctime: None,
        cusec: None,
        stime,
        susec,
        error_code,
        crealm: None,
        cname: None,
        realm: crate::string_to_gstring(realm),
        sname,
        e_text: e_text.map(|s| crate::string_to_gstring(&s)),
        e_data: e_data.map(Into::into),
    }
}

/// Encodes `METHOD-DATA` (`SEQUENCE OF PA-DATA`) for use as a
/// `KDC_ERR_PREAUTH_REQUIRED` error's `e-data` field.
pub fn encode_method_data(method_data: &MethodData) -> Result<Vec<u8>, rasn::error::EncodeError> {
    rasn::der::encode(method_data)
}
