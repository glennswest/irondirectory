//! Synthesizes the rootDSE entry (RFC 4512 §5.1) from the PartitionRegistry:
//! `namingContexts` lists every partition's base DN.

use iron_partition::PartitionRegistry;
use rasn::types::SetOf;
use rasn_ldap::{PartialAttribute, SearchResultEntry};

fn attr(name: &str, values: impl IntoIterator<Item = String>) -> PartialAttribute {
    PartialAttribute::new(
        name.into(),
        SetOf::from_vec(values.into_iter().map(|v| v.into_bytes().into()).collect()),
    )
}

pub fn build(registry: &PartitionRegistry) -> SearchResultEntry {
    let mut attrs = vec![
        attr("objectClass", ["top".to_string()]),
        attr("supportedLDAPVersion", ["3".to_string()]),
        attr("vendorName", ["irondirectory".to_string()]),
    ];

    let naming_contexts: Vec<String> = registry.iter().map(|p| p.base_dn.to_string()).collect();
    if !naming_contexts.is_empty() {
        attrs.push(attr("namingContexts", naming_contexts));
    }

    SearchResultEntry::new(String::new().into(), attrs)
}
