pub mod authorize;
pub mod discovery;
pub mod token;
pub mod userinfo;

use iron_partition::Dn;
use iron_store::model::Entry;
use iron_store::store::Store;

/// LDAP attribute holding the PBKDF2-hashed password (D4) -- same
/// attribute/convention `iron-ldap::session` authenticates simple binds
/// against, lowercase to match `Entry`'s case-folded storage.
pub const USER_PASSWORD_ATTR: &str = "userpassword";

/// Resolves `username` to its directory entry via `login_attribute`
/// (typically `uid`), the same style of lookup `iron-ldap`'s GSSAPI bind
/// uses for its own principal-to-entry resolution. `None` for "no such
/// user" and "ambiguous" alike -- a caller can't tell them apart, same
/// anti-enumeration reasoning as `iron-ldap::session::authenticate_simple`.
pub async fn resolve_user(store: &mut Store, base_dn: &Dn, login_attribute: &str, username: &str) -> Option<(Dn, Entry)> {
    let dns = store.lookup_by_index(base_dn, login_attribute, username).await.ok()?;
    let [dn] = dns.as_slice() else { return None };
    let entry = store.get_entry(dn).await.ok()??;
    Some((dn.clone(), entry))
}
