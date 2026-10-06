//! Search filter evaluation against a stored [`iron_store::model::Entry`]
//! (RFC 4511 §4.5.1.7), shared by iron-ldap and iron-gc.
//!
//! Every filter item evaluates to TRUE, FALSE or Undefined; an entry is
//! returned only when the whole filter is TRUE. `And` is FALSE if any
//! item is, else Undefined if any is, else TRUE; `Or` is the mirror; `Not`
//! swaps TRUE and FALSE and keeps Undefined -- so `(!(x:9.9:=y))` with an
//! unknown matching rule matches nothing, not everything.
//!
//! - equality, approx: case-ignore after folding insignificant spaces
//!   (RFC 4518's caseIgnoreMatch, approximated: Unicode lowercase, runs of
//!   whitespace to one space, trimmed). Approx is the same test: RFC 4511
//!   leaves the algorithm to the server.
//! - substrings: initial/any/final in order, on the same folded values.
//! - `>=`/`<=`: numeric when both the value and the assertion are
//!   integers (uidNumber, userAccountControl, ...), else case-ignore
//!   string order (which also orders GeneralizedTime values correctly).
//! - extensible: with no matching rule, the attribute's equality; the AD
//!   bitwise rules 1.2.840.113556.1.4.803 (AND) and .804 (OR) that SSSD's
//!   AD provider sends for `userAccountControl`; caseIgnoreMatch
//!   (2.5.13.2), caseExactMatch (2.5.13.5), integerMatch (2.5.13.14) and
//!   objectIdentifierMatch (2.5.13.0), by OID or name. Any other rule
//!   (e.g. AD's LDAP_MATCHING_RULE_IN_CHAIN) is Undefined. `dnAttributes`
//!   is not supported: only the entry's attributes are matched.
//!
//! An attribute the entry lacks makes an item FALSE (there is no schema to
//! say an attribute type is unknown, which would make it Undefined).

use iron_store::model::Entry;
use rasn_ldap::{Filter, MatchingRuleAssertion, SubstringChoice, SubstringFilter};

/// RFC 4511's three-valued filter result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tri {
    True,
    False,
    Undefined,
}

impl From<bool> for Tri {
    fn from(b: bool) -> Self {
        if b {
            Tri::True
        } else {
            Tri::False
        }
    }
}

/// Whether `filter` is TRUE for `entry`.
pub fn matches(entry: &Entry, filter: &Filter) -> bool {
    evaluate(entry, filter) == Tri::True
}

/// The filter's RFC 4511 value for `entry`.
pub fn evaluate(entry: &Entry, filter: &Filter) -> Tri {
    match filter {
        Filter::And(filters) => {
            let mut result = Tri::True;
            for f in filters.to_vec() {
                match evaluate(entry, f) {
                    Tri::False => return Tri::False,
                    Tri::Undefined => result = Tri::Undefined,
                    Tri::True => {}
                }
            }
            result
        }
        Filter::Or(filters) => {
            let mut result = Tri::False;
            for f in filters.to_vec() {
                match evaluate(entry, f) {
                    Tri::True => return Tri::True,
                    Tri::Undefined => result = Tri::Undefined,
                    Tri::False => {}
                }
            }
            result
        }
        Filter::Not(inner) => match evaluate(entry, inner) {
            Tri::True => Tri::False,
            Tri::False => Tri::True,
            Tri::Undefined => Tri::Undefined,
        },
        Filter::Present(attr) => entry.get(attr).is_some_and(|v| !v.is_empty()).into(),
        Filter::EqualityMatch(ava) | Filter::ApproxMatch(ava) => {
            let want = fold(&String::from_utf8_lossy(&ava.assertion_value));
            any_value(entry, ava.attribute_desc.as_str(), |v| fold(v) == want)
        }
        Filter::Substrings(sf) => substrings(entry, sf),
        Filter::GreaterOrEqual(ava) => {
            let want = String::from_utf8_lossy(&ava.assertion_value);
            any_value(entry, ava.attribute_desc.as_str(), |v| order(v, &want) != std::cmp::Ordering::Less)
        }
        Filter::LessOrEqual(ava) => {
            let want = String::from_utf8_lossy(&ava.assertion_value);
            any_value(entry, ava.attribute_desc.as_str(), |v| order(v, &want) != std::cmp::Ordering::Greater)
        }
        Filter::ExtensibleMatch(mra) => extensible(entry, mra),
        #[allow(unreachable_patterns)] // `Filter` is non_exhaustive
        _ => Tri::Undefined,
    }
}

/// TRUE if some value of `attr` satisfies `test`; FALSE otherwise
/// (including when the entry has no such attribute).
fn any_value(entry: &Entry, attr: &str, test: impl Fn(&str) -> bool) -> Tri {
    entry.get(attr).is_some_and(|vals| vals.iter().any(|v| test(v))).into()
}

/// caseIgnoreMatch's preparation, approximated: lowercase, runs of
/// whitespace to one space, trimmed.
fn fold(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

/// A substring component: lowercased, whitespace runs folded, not trimmed
/// (a component's own edge spaces are part of what it asserts).
fn fold_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !in_space {
                out.push(' ');
            }
            in_space = true;
        } else {
            out.extend(c.to_lowercase());
            in_space = false;
        }
    }
    out
}

fn substrings(entry: &Entry, sf: &SubstringFilter) -> Tri {
    let mut initial = None;
    let mut any = Vec::new();
    let mut final_ = None;
    let n = sf.substrings.len();
    for (i, choice) in sf.substrings.iter().enumerate() {
        match choice {
            // RFC 4511: at most one initial, first; at most one final, last.
            SubstringChoice::Initial(v) if i == 0 => initial = Some(fold_component(&String::from_utf8_lossy(v))),
            SubstringChoice::Any(v) => any.push(fold_component(&String::from_utf8_lossy(v))),
            SubstringChoice::Final(v) if i == n - 1 => final_ = Some(fold_component(&String::from_utf8_lossy(v))),
            _ => return Tri::Undefined,
        }
    }
    any_value(entry, sf.r#type.as_str(), |v| substring_match(&fold(v), initial.as_deref(), &any, final_.as_deref()))
}

fn substring_match(value: &str, initial: Option<&str>, any: &[String], final_: Option<&str>) -> bool {
    let mut rest = value;
    if let Some(i) = initial {
        let Some(r) = rest.strip_prefix(i) else { return false };
        rest = r;
    }
    for a in any {
        let Some(pos) = rest.find(a.as_str()) else { return false };
        rest = &rest[pos + a.len()..];
    }
    match final_ {
        Some(f) => rest.ends_with(f),
        None => true,
    }
}

/// Integer order when both sides are integers, else case-ignore string
/// order.
fn order(value: &str, assertion: &str) -> std::cmp::Ordering {
    match (value.trim().parse::<i128>(), assertion.trim().parse::<i128>()) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        _ => fold(value).cmp(&fold(assertion)),
    }
}

/// How an extensible match compares one value with the assertion; `None`
/// when the assertion isn't valid for the rule (Undefined).
type Rule = fn(&str, &str) -> Option<bool>;

fn rule(name: Option<&str>) -> Option<Rule> {
    let Some(name) = name else {
        return Some(|v, a| Some(fold(v) == fold(a)));
    };
    let r: Rule = match name.to_ascii_lowercase().as_str() {
        "1.2.840.113556.1.4.803" | "ldap_matching_rule_bit_and" => |v, a| {
            let (v, a) = (int(v)?, int(a)?);
            Some(v & a == a)
        },
        "1.2.840.113556.1.4.804" | "ldap_matching_rule_bit_or" => |v, a| {
            let (v, a) = (int(v)?, int(a)?);
            Some(v & a != 0)
        },
        "2.5.13.2" | "caseignorematch" => |v, a| Some(fold(v) == fold(a)),
        "2.5.13.5" | "caseexactmatch" => |v, a| Some(v == a),
        "2.5.13.14" | "integermatch" => |v, a| Some(int(v)? == int(a)?),
        "2.5.13.0" | "objectidentifiermatch" => |v, a| Some(v.trim().eq_ignore_ascii_case(a.trim())),
        _ => return None,
    };
    Some(r)
}

/// An integer as AD stores flag words: signed decimal (userAccountControl
/// and groupType can be negative), compared as 64-bit two's complement.
fn int(s: &str) -> Option<i64> {
    s.trim().parse::<i64>().ok()
}

fn extensible(entry: &Entry, mra: &MatchingRuleAssertion) -> Tri {
    let Some(rule) = rule(mra.matching_rule.as_ref().map(|r| r.as_str())) else {
        return Tri::Undefined;
    };
    let assertion = String::from_utf8_lossy(&mra.match_value);
    let attrs: Vec<&str> = match &mra.r#type {
        Some(t) => vec![t.as_str()],
        // No type: every attribute the rule applies to.
        None if mra.matching_rule.is_some() => entry.attr_names().collect(),
        None => return Tri::Undefined, // RFC 4511: one of the two is required
    };
    let mut result = Tri::False;
    for attr in attrs {
        for v in entry.get(attr).unwrap_or_default() {
            match rule(v, &assertion) {
                Some(true) => return Tri::True,
                // A value the rule can't read (say, a name under an
                // integer rule) only makes this Undefined when the
                // attribute was named; with no type, other attributes
                // simply aren't of that syntax.
                None if mra.r#type.is_some() => result = Tri::Undefined,
                _ => {}
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rasn::types::SetOf;
    use rasn_ldap::AttributeValueAssertion;

    fn entry() -> Entry {
        let mut e = Entry::new();
        e.set("cn", ["Alice  Smith"]);
        e.set("objectClass", ["person", "top"]);
        e.set("uidNumber", ["1500"]);
        e.set("userAccountControl", ["4098"]); // ACCOUNTDISABLE (2) | WORKSTATION_TRUST_ACCOUNT (4096)
        e.set("whenCreated", ["20261006120000.0Z"]);
        e
    }

    fn ava(attr: &str, v: &str) -> AttributeValueAssertion {
        AttributeValueAssertion::new(attr.into(), v.as_bytes().to_vec().into())
    }

    fn sub(attr: &str, parts: Vec<SubstringChoice>) -> Filter {
        Filter::Substrings(SubstringFilter::new(attr.into(), parts))
    }

    fn b(s: &str) -> rasn::types::OctetString {
        s.as_bytes().to_vec().into()
    }

    fn ext(rule: Option<&str>, attr: Option<&str>, v: &str) -> Filter {
        Filter::ExtensibleMatch(MatchingRuleAssertion::new(rule.map(Into::into), attr.map(Into::into), b(v), false))
    }

    #[test]
    fn present_matches_when_attribute_has_values() {
        assert!(matches(&entry(), &Filter::Present("cn".into())));
        assert!(!matches(&entry(), &Filter::Present("mail".into())));
    }

    #[test]
    fn equality_ignores_case_and_insignificant_spaces() {
        assert!(matches(&entry(), &Filter::EqualityMatch(ava("cn", "alice smith"))));
        assert!(matches(&entry(), &Filter::EqualityMatch(ava("CN", " ALICE   SMITH "))));
        assert!(!matches(&entry(), &Filter::EqualityMatch(ava("cn", "alice"))));
    }

    #[test]
    fn substrings_initial_any_final() {
        use SubstringChoice::*;
        assert!(matches(&entry(), &sub("cn", vec![Initial(b("al"))])));
        assert!(matches(&entry(), &sub("cn", vec![Final(b("SMITH"))])));
        assert!(matches(&entry(), &sub("cn", vec![Any(b("ce s"))])));
        assert!(matches(&entry(), &sub("cn", vec![Initial(b("a")), Any(b("i")), Any(b("m")), Final(b("h"))])));
        assert!(!matches(&entry(), &sub("cn", vec![Initial(b("smith"))])));
        assert!(!matches(&entry(), &sub("cn", vec![Initial(b("al")), Any(b("ice")), Final(b("ice"))])));
        // components may not overlap: nothing is left after the initial for the final
        assert!(!matches(&entry(), &sub("cn", vec![Initial(b("alice smith")), Final(b("h"))])));
        assert!(!matches(&entry(), &sub("mail", vec![Initial(b("a"))])));
    }

    #[test]
    fn substrings_out_of_order_initial_is_undefined() {
        use SubstringChoice::*;
        assert_eq!(evaluate(&entry(), &sub("cn", vec![Any(b("a")), Initial(b("a"))])), Tri::Undefined);
    }

    #[test]
    fn ordering_is_numeric_for_integers_and_string_otherwise() {
        assert!(matches(&entry(), &Filter::GreaterOrEqual(ava("uidNumber", "1000"))));
        assert!(!matches(&entry(), &Filter::GreaterOrEqual(ava("uidNumber", "2000"))));
        // numeric, not lexicographic: "1500" <= "900" as strings, not as numbers
        assert!(!matches(&entry(), &Filter::LessOrEqual(ava("uidNumber", "900"))));
        assert!(matches(&entry(), &Filter::LessOrEqual(ava("uidNumber", "1500"))));
        assert!(matches(&entry(), &Filter::GreaterOrEqual(ava("whenCreated", "20260101000000.0Z"))));
        assert!(!matches(&entry(), &Filter::LessOrEqual(ava("whenCreated", "20260101000000.0Z"))));
        assert!(matches(&entry(), &Filter::GreaterOrEqual(ava("cn", "aaa"))));
    }

    #[test]
    fn approx_is_folded_equality() {
        assert!(matches(&entry(), &Filter::ApproxMatch(ava("cn", "ALICE SMITH"))));
        assert!(!matches(&entry(), &Filter::ApproxMatch(ava("cn", "alise smith"))));
    }

    #[test]
    fn ad_bitwise_rules() {
        // SSSD's AD provider: disabled accounts
        assert!(matches(&entry(), &ext(Some("1.2.840.113556.1.4.803"), Some("userAccountControl"), "2")));
        assert!(matches(&entry(), &ext(Some("1.2.840.113556.1.4.803"), Some("userAccountControl"), "4098")));
        assert!(!matches(&entry(), &ext(Some("1.2.840.113556.1.4.803"), Some("userAccountControl"), "512")));
        assert!(matches(&entry(), &ext(Some("1.2.840.113556.1.4.804"), Some("userAccountControl"), "514")));
        assert!(!matches(&entry(), &ext(Some("1.2.840.113556.1.4.804"), Some("userAccountControl"), "512")));
        // negative flag words (groupType) are two's complement
        let mut g = Entry::new();
        g.set("groupType", ["-2147483646"]); // 0x80000002: security, global
        // AD's own "security group" filter: bit 0x80000000 of a negative word
        assert!(matches(&g, &ext(Some("1.2.840.113556.1.4.803"), Some("groupType"), "2147483648")));
        assert!(matches(&g, &ext(Some("1.2.840.113556.1.4.803"), Some("groupType"), "2")));
        assert!(matches(&g, &ext(Some("1.2.840.113556.1.4.803"), Some("groupType"), "-2147483648")));
    }

    #[test]
    fn extensible_named_rules_and_no_rule() {
        assert!(matches(&entry(), &ext(Some("caseIgnoreMatch"), Some("cn"), "ALICE SMITH")));
        assert!(!matches(&entry(), &ext(Some("2.5.13.5"), Some("cn"), "alice  smith")));
        assert!(matches(&entry(), &ext(Some("2.5.13.5"), Some("cn"), "Alice  Smith")));
        assert!(matches(&entry(), &ext(None, Some("cn"), "alice smith")));
        assert!(matches(&entry(), &ext(Some("integerMatch"), Some("uidNumber"), "1500")));
        // no type: any attribute the rule applies to
        assert!(matches(&entry(), &ext(Some("2.5.13.14"), None, "4098")));
    }

    #[test]
    fn unknown_rule_is_undefined_and_not_keeps_it_undefined() {
        let f = ext(Some("1.2.840.113556.1.4.1941"), Some("memberOf"), "cn=x");
        assert_eq!(evaluate(&entry(), &f), Tri::Undefined);
        assert!(!matches(&entry(), &Filter::Not(Box::new(f.clone()))));
        // an integer rule on a non-integer value of a named attribute
        assert_eq!(evaluate(&entry(), &ext(Some("2.5.13.14"), Some("cn"), "1")), Tri::Undefined);
    }

    #[test]
    fn three_valued_and_or_not() {
        let undef = ext(Some("9.9.9"), Some("cn"), "x");
        let t = Filter::Present("cn".into());
        let f = Filter::Present("mail".into());
        let and = |v: Vec<Filter>| Filter::And(SetOf::from_vec(v));
        let or = |v: Vec<Filter>| Filter::Or(SetOf::from_vec(v));
        assert_eq!(evaluate(&entry(), &and(vec![t.clone(), undef.clone()])), Tri::Undefined);
        assert_eq!(evaluate(&entry(), &and(vec![f.clone(), undef.clone()])), Tri::False);
        assert_eq!(evaluate(&entry(), &or(vec![t.clone(), undef.clone()])), Tri::True);
        assert_eq!(evaluate(&entry(), &or(vec![f.clone(), undef.clone()])), Tri::Undefined);
        assert!(matches(&entry(), &Filter::Not(Box::new(f))));
        assert!(matches(&entry(), &and(vec![t.clone()])));
        assert!(matches(&entry(), &or(vec![t])));
    }
}
