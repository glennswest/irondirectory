//! Minimal built-in schema validation: AD-shaped structural classes plus
//! RFC 2307 posix classes (#4's last item). Deliberately a small,
//! hand-picked subset, not full schema-subentry publishing (`cn=subschema`,
//! attribute syntax/matching-rule enforcement) -- this only checks that an
//! entry has every MUST attribute of the objectClasses it declares, for
//! the classes modeled here.
//!
//! objectClasses this doesn't model are passed through unvalidated
//! (permissive default): this is a completeness check for the classes we
//! DO know about, not a closed-world schema gate that rejects anything
//! unrecognized -- real deployments routinely extend schema beyond any
//! fixed built-in list.

use iron_store::model::Entry;

struct ObjectClass {
    name: &'static str,
    must: &'static [&'static str],
}

const CLASSES: &[ObjectClass] = &[
    ObjectClass { name: "top", must: &[] },
    // RFC 4519 / core LDAP
    ObjectClass { name: "person", must: &["cn", "sn"] },
    ObjectClass { name: "organizationalPerson", must: &["cn", "sn"] },
    ObjectClass { name: "inetOrgPerson", must: &["cn", "sn"] },
    ObjectClass { name: "organizationalUnit", must: &["ou"] },
    ObjectClass { name: "groupOfNames", must: &["cn", "member"] },
    // AD-shaped (Microsoft's real `user`/`group` classes carry a much
    // larger MAY list and inherit through a deep chain; this models just
    // the structurally-required core, enough to catch an obviously
    // incomplete entry).
    ObjectClass { name: "user", must: &["cn"] },
    ObjectClass { name: "group", must: &["cn"] },
    // RFC 2307 posix auxiliary classes
    ObjectClass {
        name: "posixAccount",
        must: &["cn", "uid", "uidNumber", "gidNumber", "homeDirectory"],
    },
    ObjectClass { name: "posixGroup", must: &["cn", "gidNumber"] },
];

/// Checks `entry` against every objectClass it declares that we have a
/// definition for. Returns a description of the first missing MUST
/// attribute found, if any. An entry with no `objectClass` at all, or
/// only objectClasses we don't model, passes trivially -- this function
/// only enforces what it actually knows about.
pub fn validate(entry: &Entry) -> Result<(), String> {
    let Some(classes) = entry.get("objectclass") else {
        return Ok(());
    };
    for oc in classes {
        let Some(def) = CLASSES.iter().find(|c| c.name.eq_ignore_ascii_case(oc)) else {
            continue;
        };
        for must in def.must {
            let present = entry.get(must).is_some_and(|v| !v.is_empty());
            if !present {
                return Err(format!("objectClass {oc} requires attribute {must}"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_complete_person() {
        let mut e = Entry::new();
        e.set("objectclass", ["person", "top"]);
        e.set("cn", ["alice"]);
        e.set("sn", ["Smith"]);
        assert!(validate(&e).is_ok());
    }

    #[test]
    fn rejects_person_missing_sn() {
        let mut e = Entry::new();
        e.set("objectclass", ["person"]);
        e.set("cn", ["alice"]);
        let err = validate(&e).unwrap_err();
        assert!(err.contains("sn"));
    }

    #[test]
    fn rejects_posix_account_missing_uid_number() {
        let mut e = Entry::new();
        e.set("objectclass", ["posixAccount"]);
        e.set("cn", ["alice"]);
        e.set("uid", ["alice"]);
        e.set("gidnumber", ["100"]);
        e.set("homedirectory", ["/home/alice"]);
        let err = validate(&e).unwrap_err();
        assert!(err.contains("uidNumber"));
    }

    #[test]
    fn accepts_complete_posix_account() {
        let mut e = Entry::new();
        e.set("objectclass", ["posixAccount", "top"]);
        e.set("cn", ["alice"]);
        e.set("uid", ["alice"]);
        e.set("uidnumber", ["1001"]);
        e.set("gidnumber", ["100"]);
        e.set("homedirectory", ["/home/alice"]);
        assert!(validate(&e).is_ok());
    }

    #[test]
    fn unknown_objectclass_passes_trivially() {
        let mut e = Entry::new();
        e.set("objectclass", ["someCustomClassNotModeled"]);
        assert!(validate(&e).is_ok());
    }
}
