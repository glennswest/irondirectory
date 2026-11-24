//! The directory attributes that hold, or bind, an account's credentials
//! (#75): what LDAP must never write, and the subset it must never return
//! (#60).
//!
//! These are written only by the password operations -- RFC 3062 Password
//! Modify (iron-ldapd), kpasswd (iron-kdcd), `NetrServerPasswordSet2` and
//! SAMR `SetInformationUser2` (iron-rpcd) -- and by the operator tools and
//! iron-bootstrap, all of which write the store directly. Through LDAP
//! Add/Modify/ModDN they would let any writer plant an inter-realm key
//! (`krbtgt/<OUR REALM>@ANY.REALM` + `krbkey`, which `tgs_exchange` accepts
//! as a trust), replace `krbtgt`'s key (forge any TGT) or a user's (take the
//! account), or step around the password policy (#70). Active Directory
//! likewise keeps its secret attributes out of reach of LDAP writes.

use crate::{policy, principal};

/// iron-rpc's NETLOGON key: the account's NT one-way function of its
/// password (MS-NRPC's secure channel needs it).
pub const ATTR_NETLOGON_NTOWF: &str = "netlogonntowf";

/// Key material: never written over LDAP, and never to be returned by a
/// search (#60).
pub const KEY_ATTRS: &[&str] = &[principal::ATTR_KEY, principal::ATTR_SALT, policy::ATTR_HISTORY, ATTR_NETLOGON_NTOWF];

/// Every attribute LDAP Add/Modify/ModDN refuses (#75): the key material
/// plus what binds it to an account -- the principal name the KDC looks
/// keys up by, and `pwdLastSet`, which the password policy's ages run from.
pub const LDAP_WRITE_PROTECTED_ATTRS: &[&str] =
    &[principal::ATTR_KEY, principal::ATTR_SALT, policy::ATTR_HISTORY, ATTR_NETLOGON_NTOWF, principal::ATTR_PRINCIPAL_NAME, policy::ATTR_PWD_LAST_SET];

/// An attribute description's type, without options (`krbKey;binary` is
/// `krbkey`), lower-cased.
fn attr_type(description: &str) -> String {
    description.split(';').next().unwrap_or_default().trim().to_ascii_lowercase()
}

/// Whether LDAP may not write `description` (any case, any options).
pub fn is_ldap_write_protected(description: &str) -> bool {
    LDAP_WRITE_PROTECTED_ATTRS.contains(&attr_type(description).as_str())
}

/// Whether `description` names key material (#60's read deny-list).
pub fn is_key_material(description: &str) -> bool {
    KEY_ATTRS.contains(&attr_type(description).as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_names_match_in_any_case_and_with_options() {
        for a in ["krbKey", "KRBSALT", "krbPrincipalName", "krbprincipalname;x-foo", "netlogonNTOWF", "pwdLastSet", "krbPwdHistory"] {
            assert!(is_ldap_write_protected(a), "{a}");
        }
        for a in ["cn", "userPassword", "sAMAccountName", "krbkeyx", "userAccountControl", "objectSid"] {
            assert!(!is_ldap_write_protected(a), "{a}");
        }
    }

    #[test]
    fn key_material_is_a_subset_of_the_write_protected_list() {
        for a in KEY_ATTRS {
            assert!(LDAP_WRITE_PROTECTED_ATTRS.contains(a), "{a}");
            assert!(is_key_material(a));
        }
        assert!(!is_key_material("krbPrincipalName"));
        assert!(!is_key_material("pwdLastSet"));
    }
}
