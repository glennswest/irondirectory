//! Security-principal auto-provisioning (#17): stamps a freshly-added
//! `user`/`computer`/`group` entry with an `objectSid` (allocated from
//! its domain partition's RID pool) and a default `nTSecurityDescriptor`
//! -- mirroring real AD, where the DC assigns both automatically at
//! object creation, not something a client computes itself.
//!
//! `objectSid`/`nTSecurityDescriptor` are fundamentally binary
//! (MS-DTYP), but `iron_store::model::Entry`'s attribute values are
//! UTF-8 strings only (a documented, deliberate deferral -- "binary
//! attribute values are out of scope until a concrete need shows up").
//! Rather than adding a new `Entry` value variant (a much larger,
//! ripple-through-every-caller change), both attributes are stored here
//! as standard base64 text and decoded back to raw bytes only at the
//! LDAP wire-projection boundary (`session::project_attributes`) --
//! exactly the smaller, documented-encoding-convention fix the gap
//! calls for.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use iron_partition::{security_descriptor, Dn, Sid};
use iron_store::model::Entry;
use iron_store::store::Store;
use iron_store::StoreError;

/// `objectSid`, stored as base64 (see module docs).
pub const OBJECT_SID_ATTR: &str = "objectsid";
/// `nTSecurityDescriptor`, stored as base64 (see module docs).
pub const NT_SECURITY_DESCRIPTOR_ATTR: &str = "ntsecuritydescriptor";

/// objectClasses real AD treats as security principals -- these get an
/// `objectSid`/`nTSecurityDescriptor`; nothing else does.
const SECURITY_PRINCIPAL_CLASSES: &[&str] = &["user", "computer", "group"];

fn declares_security_principal_class(entry: &Entry) -> bool {
    entry.get("objectclass").is_some_and(|classes| {
        classes.iter().any(|c| SECURITY_PRINCIPAL_CLASSES.iter().any(|sc| sc.eq_ignore_ascii_case(c)))
    })
}

/// If `entry` declares a security-principal objectClass (`user`/
/// `computer`/`group`) and the partition `dn` belongs to has a
/// provisioned domain SID (`Partition::domain_sid`, set via
/// `iron-config-ctl`), allocates a fresh RID from that partition's pool
/// and stamps `entry` with the resulting `objectSid` plus a default
/// `nTSecurityDescriptor`.
///
/// A deliberate no-op, not an error, if either condition doesn't hold:
/// an entry with no recognized security-principal objectClass is left
/// alone (e.g. an `organizationalUnit`), and a partition with no domain
/// SID yet just doesn't stamp anything -- exactly like a real domain
/// before its SID is assigned, not a broken add.
pub async fn stamp_security_principal(store: &mut Store, dn: &Dn, entry: &mut Entry) -> Result<(), StoreError> {
    if !declares_security_principal_class(entry) {
        return Ok(());
    }
    let Some(domain_sid_str) = store.registry().resolve(dn).and_then(|p| p.domain_sid.clone()) else {
        return Ok(());
    };
    let Some(domain_sid) = Sid::parse(&domain_sid_str) else {
        tracing::warn!(%domain_sid_str, "partition's stored domain_sid does not parse, skipping SID/nTSD stamping");
        return Ok(());
    };

    let rid = store.allocate_rid(dn).await?;
    let object_sid = domain_sid.with_sub_authority(rid);
    entry.set(OBJECT_SID_ATTR, [STANDARD.encode(object_sid.encode())]);

    let descriptor = security_descriptor::default_descriptor(&domain_sid);
    entry.set(NT_SECURITY_DESCRIPTOR_ATTR, [STANDARD.encode(descriptor)]);

    Ok(())
}

/// Attributes whose stored value is base64-encoded binary data (see
/// module docs) -- `session::project_attributes` decodes these to raw
/// bytes rather than treating the stored string as the wire value
/// verbatim, the way every other attribute works.
pub fn is_binary_attr(name: &str) -> bool {
    name.eq_ignore_ascii_case(OBJECT_SID_ATTR) || name.eq_ignore_ascii_case(NT_SECURITY_DESCRIPTOR_ATTR)
}

/// Decodes a stored base64 value back to raw wire bytes. Falls back to
/// the stored string's own UTF-8 bytes on a decode failure (should
/// never happen for a value this module itself wrote) rather than
/// dropping the value or panicking.
pub fn decode_binary_attr(value: &str) -> Vec<u8> {
    STANDARD.decode(value).unwrap_or_else(|_| value.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declares_security_principal_class_matches_user_computer_group() {
        for class in ["user", "computer", "group", "USER", "Computer"] {
            let mut e = Entry::new();
            e.set("objectclass", [class]);
            assert!(declares_security_principal_class(&e), "{class} should be recognized");
        }
    }

    #[test]
    fn declares_security_principal_class_rejects_unrelated_classes() {
        let mut e = Entry::new();
        e.set("objectclass", ["organizationalUnit"]);
        assert!(!declares_security_principal_class(&e));
    }

    #[test]
    fn declares_security_principal_class_false_with_no_objectclass_at_all() {
        let e = Entry::new();
        assert!(!declares_security_principal_class(&e));
    }

    #[test]
    fn binary_attr_roundtrips_through_base64() {
        let raw = vec![1u8, 5, 21, 0, 0, 0, 0, 0, 5, 0, 0, 0];
        let encoded = STANDARD.encode(&raw);
        assert!(is_binary_attr("objectSid"));
        assert!(is_binary_attr("NTSECURITYDESCRIPTOR"));
        assert!(!is_binary_attr("cn"));
        assert_eq!(decode_binary_attr(&encoded), raw);
    }
}
