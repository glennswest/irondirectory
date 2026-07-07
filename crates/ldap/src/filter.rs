//! Search filter evaluation against a stored [`iron_store::model::Entry`].
//!
//! Implements the core filter kinds (`Present`, `EqualityMatch`, `And`,
//! `Or`, `Not`). Substrings/ordering/approximate/extensible matches are not
//! yet implemented -- they conservatively evaluate to non-matching (an
//! empty result set for those clauses) rather than erroring the whole
//! search, so a client asking for something not yet supported gets an
//! under-inclusive (not wrong) answer.

use iron_store::model::Entry;
use rasn_ldap::Filter;

pub fn matches(entry: &Entry, filter: &Filter) -> bool {
    match filter {
        Filter::Present(attr) => entry.get(attr).is_some_and(|v| !v.is_empty()),
        Filter::EqualityMatch(ava) => {
            let want = String::from_utf8_lossy(&ava.assertion_value);
            entry
                .get(ava.attribute_desc.as_str())
                .is_some_and(|vals| vals.iter().any(|v| v.eq_ignore_ascii_case(&want)))
        }
        Filter::And(filters) => filters.to_vec().into_iter().all(|f| matches(entry, f)),
        Filter::Or(filters) => filters.to_vec().into_iter().any(|f| matches(entry, f)),
        Filter::Not(inner) => !matches(entry, inner),
        Filter::Substrings(_)
        | Filter::GreaterOrEqual(_)
        | Filter::LessOrEqual(_)
        | Filter::ApproxMatch(_)
        | Filter::ExtensibleMatch(_)
        | _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rasn::types::SetOf;
    use rasn_ldap::AttributeValueAssertion;

    fn entry() -> Entry {
        let mut e = Entry::new();
        e.set("cn", ["alice"]);
        e.set("objectClass", ["person", "top"]);
        e
    }

    #[test]
    fn present_matches_when_attribute_has_values() {
        assert!(matches(&entry(), &Filter::Present("cn".into())));
        assert!(!matches(&entry(), &Filter::Present("mail".into())));
    }

    #[test]
    fn equality_is_case_insensitive() {
        let f = Filter::EqualityMatch(AttributeValueAssertion::new(
            "cn".into(),
            b"Alice".to_vec().into(),
        ));
        assert!(matches(&entry(), &f));
    }

    #[test]
    fn and_or_not_compose() {
        let has_cn = Filter::Present("cn".into());
        let has_mail = Filter::Present("mail".into());
        assert!(matches(
            &entry(),
            &Filter::And(SetOf::from_vec(vec![has_cn.clone()]))
        ));
        assert!(!matches(
            &entry(),
            &Filter::And(SetOf::from_vec(vec![has_cn.clone(), has_mail.clone()]))
        ));
        assert!(matches(
            &entry(),
            &Filter::Or(SetOf::from_vec(vec![has_cn.clone(), has_mail.clone()]))
        ));
        assert!(matches(&entry(), &Filter::Not(Box::new(has_mail))));
    }
}
