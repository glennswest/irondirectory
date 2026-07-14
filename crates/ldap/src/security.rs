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

use iron_partition::{security_descriptor, Dn, Sid};
use iron_store::binary_attrs::{encode_binary_attr, OBJECT_SID_ATTR, NT_SECURITY_DESCRIPTOR_ATTR};
use iron_store::model::Entry;
use iron_store::store::Store;
use iron_store::StoreError;

pub use iron_store::binary_attrs::{decode_binary_attr, is_binary_attr};

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
///
/// `topology` should be `Referrals::topology` -- the forest-wide
/// registry loaded from the persisted configuration partition (#9).
/// `Store::registry()` is deliberately NOT consulted first: it's a
/// bare, locally-constructed single-partition registry built at
/// startup purely for DN-to-cluster routing, and never carries a
/// provisioned `domain_sid` -- the same gap that made rootDSE's
/// `schemaNamingContext`/`configurationNamingContext` never appear
/// until that lookup was corrected (see `session::handle_search`).
/// Falls back to `store.registry()` only when no topology is
/// configured at all, matching `referral_for`'s fallback shape.
pub async fn stamp_security_principal(
    store: &mut Store,
    topology: Option<&iron_partition::PartitionRegistry>,
    dn: &Dn,
    entry: &mut Entry,
) -> Result<(), StoreError> {
    if !declares_security_principal_class(entry) {
        return Ok(());
    }
    let registry = topology.unwrap_or_else(|| store.registry());
    let Some(domain_sid_str) = registry.resolve(dn).and_then(|p| p.domain_sid.clone()) else {
        return Ok(());
    };
    let Some(domain_sid) = Sid::parse(&domain_sid_str) else {
        tracing::warn!(%domain_sid_str, "partition's stored domain_sid does not parse, skipping SID/nTSD stamping");
        return Ok(());
    };

    let rid = store.allocate_rid(dn).await?;
    let object_sid = domain_sid.with_sub_authority(rid);
    entry.set(OBJECT_SID_ATTR, [encode_binary_attr(&object_sid.encode())]);

    let descriptor = security_descriptor::default_descriptor(&domain_sid);
    entry.set(NT_SECURITY_DESCRIPTOR_ATTR, [encode_binary_attr(&descriptor)]);

    Ok(())
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
}
