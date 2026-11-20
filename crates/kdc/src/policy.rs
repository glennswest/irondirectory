//! Domain password policy (#70): length, complexity, history and ages,
//! in Active Directory's shape.
//!
//! The policy lives on the domain head entry (the partition's base DN),
//! as AD keeps it on the `domainDNS` object:
//!
//! - `minPwdLength`: minimum length in characters. The effective minimum
//!   is never below [`FIPS_MIN_LENGTH`] (8): PBKDF2 under the FIPS
//!   provider refuses a shorter passphrase (docs/FIPS.md).
//! - `pwdHistoryLength`: a change may not reuse any of the last N
//!   passwords, the current one included (N = 1 forbids only the current).
//! - `pwdProperties`: bit 0x1 `DOMAIN_PASSWORD_COMPLEX` turns on the
//!   complexity rules ([`complexity_violation`]).
//! - `minPwdAge` / `maxPwdAge`: AD's encoding, a negative count of 100 ns
//!   intervals (`-864000000000` is one day). `0` (or `i64::MIN`, AD's
//!   "never") means no limit. A positive value is read as its magnitude.
//!
//! An attribute that is absent is not enforced; a domain with none of them
//! has the 8-character floor and nothing else.
//!
//! Which rules apply depends on who sets the password, as in AD:
//!
//! | rule        | [`Mode::Change`] (own password) | [`Mode::Reset`] (admin) |
//! |-------------|-----------------|------------|
//! | length      | yes             | yes        |
//! | complexity  | yes             | yes        |
//! | history     | yes             | no         |
//! | minimum age | yes             | no         |
//!
//! Machine accounts (a `sAMAccountName` ending in `$`, objectClass
//! `computer`, or a trust-account `userAccountControl` bit) are exempt
//! from complexity, history and both ages; only the length applies.
//!
//! [`crate::principal::set_password`] keeps what the checks read:
//! `pwdLastSet` (a FILETIME, as in AD) and `krbpwdhistory`, one value per
//! past password, newest first: `<salt>:<hex aes256-cts-hmac-sha384-192
//! key>`, at most [`HISTORY_MAX`] (AD's ceiling). A history check derives
//! the candidate under each stored salt and compares keys; no password is
//! ever stored.

use iron_crypto::kerberos::{self, Enctype};
use iron_crypto::FipsContext;
use iron_partition::Dn;
use iron_store::model::Entry;

pub const ATTR_MIN_LENGTH: &str = "minpwdlength";
pub const ATTR_HISTORY_LENGTH: &str = "pwdhistorylength";
pub const ATTR_PROPERTIES: &str = "pwdproperties";
pub const ATTR_MIN_AGE: &str = "minpwdage";
pub const ATTR_MAX_AGE: &str = "maxpwdage";
/// On a principal: when its password was last set, a FILETIME (100 ns
/// intervals since 1601-01-01 UTC), as AD's `pwdLastSet`. `0` means "must
/// change at next logon".
pub const ATTR_PWD_LAST_SET: &str = "pwdlastset";
/// On a principal: past passwords' keys, newest first (module docs).
pub const ATTR_HISTORY: &str = "krbpwdhistory";

/// The floor under any configured `minPwdLength` (FIPS PBKDF2 minimum).
pub const FIPS_MIN_LENGTH: u32 = 8;
/// AD's maximum `pwdHistoryLength`, and how many past keys are kept.
pub const HISTORY_MAX: usize = 24;
/// `pwdProperties` bit: passwords must meet the complexity rules.
pub const DOMAIN_PASSWORD_COMPLEX: u32 = 0x1;
/// The enctype a history value's key is derived for.
pub const HISTORY_ENCTYPE: Enctype = Enctype::Aes256CtsHmacSha384_192;

/// `userAccountControl` bits (MS-ADTS 2.2.16).
const UF_DONT_EXPIRE_PASSWD: u32 = 0x0001_0000;
const UF_TRUST_ACCOUNT_MASK: u32 = 0x0000_0800 | 0x0000_1000 | 0x0000_2000; // interdomain, workstation, server

/// Seconds between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_OFFSET_SECS: u64 = 11_644_473_600;
const TICKS_PER_SEC: u64 = 10_000_000;

/// A domain's password policy (module docs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// As configured (`minPwdLength`); see [`Policy::effective_min_length`].
    pub min_length: u32,
    pub history_length: u32,
    pub properties: u32,
    /// In 100 ns ticks; 0 = none.
    pub min_age: u64,
    /// In 100 ns ticks; 0 = never expires.
    pub max_age: u64,
}

/// Who is setting the password (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The account's own password, by its holder.
    Change,
    /// Another account's, by an administrator (or a machine's own, over
    /// Netlogon's secure channel).
    Reset,
}

/// Why a password was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Violation {
    #[error("password must be at least {0} characters")]
    TooShort(u32),
    #[error("password does not meet the complexity requirements: {0}")]
    NotComplex(String),
    #[error("password was used within the last {0} passwords")]
    InHistory(u32),
    #[error("password was changed less than the minimum password age ago")]
    TooSoon,
    /// Not a policy outcome: the check itself failed (crypto).
    #[error("password policy check failed: {0}")]
    Internal(String),
}

impl Violation {
    /// A policy refusal (as opposed to [`Violation::Internal`]).
    pub fn is_policy(&self) -> bool {
        !matches!(self, Violation::Internal(_))
    }
}

fn first_value<'a>(entry: &'a Entry, attr: &str) -> Option<&'a str> {
    entry.get(attr).and_then(|v| v.first()).map(String::as_str)
}

fn int_attr(entry: &Entry, attr: &str) -> Option<i64> {
    first_value(entry, attr)?.trim().parse().ok()
}

/// AD interval: negative 100 ns ticks; 0 and `i64::MIN` mean "none".
fn interval(entry: &Entry, attr: &str) -> u64 {
    match int_attr(entry, attr) {
        None | Some(0) | Some(i64::MIN) => 0,
        Some(v) => v.unsigned_abs(),
    }
}

impl Policy {
    /// The policy carried by a domain head entry.
    pub fn from_domain(domain: &Entry) -> Policy {
        let clamp = |v: Option<i64>| v.map(|v| v.clamp(0, u32::MAX as i64) as u32).unwrap_or(0);
        Policy {
            min_length: clamp(int_attr(domain, ATTR_MIN_LENGTH)),
            history_length: clamp(int_attr(domain, ATTR_HISTORY_LENGTH)).min(HISTORY_MAX as u32),
            // pwdProperties is a flag word; AD may store it signed.
            properties: int_attr(domain, ATTR_PROPERTIES).map(|v| v as u32).unwrap_or(0),
            min_age: interval(domain, ATTR_MIN_AGE),
            max_age: interval(domain, ATTR_MAX_AGE),
        }
    }

    /// Reads the policy from the domain head `domain`. A missing head is
    /// the empty policy (nothing configured).
    pub async fn load(store: &mut iron_store::store::Store, domain: &Dn) -> Result<Policy, iron_store::StoreError> {
        Ok(store.get_entry(domain).await?.map(|e| Policy::from_domain(&e)).unwrap_or_default())
    }

    pub fn effective_min_length(&self) -> u32 {
        self.min_length.max(FIPS_MIN_LENGTH)
    }

    pub fn complex(&self) -> bool {
        self.properties & DOMAIN_PASSWORD_COMPLEX != 0
    }

    /// The 30-byte policy record AD returns as the result string of a
    /// kpasswd SOFTERROR (what MIT's `krb5_chpw_message` and impacket's
    /// `_decodePasswordPolicy` decode): big-endian `u16 0`, `u32
    /// MinPasswordLength`, `u32 PasswordHistoryLength`, `u32
    /// PasswordProperties`, `u64 MaxPasswordAge`, `u64 MinPasswordAge`
    /// (ages as positive 100 ns ticks).
    pub fn blob(&self) -> [u8; 30] {
        let mut b = [0u8; 30];
        b[2..6].copy_from_slice(&self.effective_min_length().to_be_bytes());
        b[6..10].copy_from_slice(&self.history_length.to_be_bytes());
        b[10..14].copy_from_slice(&self.properties.to_be_bytes());
        b[14..22].copy_from_slice(&self.max_age.to_be_bytes());
        b[22..30].copy_from_slice(&self.min_age.to_be_bytes());
        b
    }
}

/// Now, as a FILETIME.
pub fn filetime_now() -> u64 {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    (d.as_secs() + FILETIME_UNIX_OFFSET_SECS) * TICKS_PER_SEC + u64::from(d.subsec_nanos()) / 100
}

fn uac(entry: &Entry) -> u32 {
    int_attr(entry, "useraccountcontrol").map(|v| v as u32).unwrap_or(0)
}

/// A computer or trust account (module docs).
pub fn is_machine(entry: &Entry) -> bool {
    first_value(entry, "samaccountname").is_some_and(|n| n.ends_with('$'))
        || entry.get("objectclass").is_some_and(|ocs| ocs.iter().any(|oc| oc.eq_ignore_ascii_case("computer")))
        || uac(entry) & UF_TRUST_ACCOUNT_MASK != 0
}

/// `pwdLastSet`, if recorded.
pub fn pwd_last_set(entry: &Entry) -> Option<u64> {
    first_value(entry, ATTR_PWD_LAST_SET)?.trim().parse().ok()
}

/// Whether `entry`'s password has expired at `now` (a FILETIME): it was
/// marked "must change" (`pwdLastSet` 0), or is older than `maxPwdAge`.
/// Machines, `krbtgt` and `DONT_EXPIRE_PASSWD` accounts never expire, nor
/// does an entry with no `pwdLastSet` (set before #70 recorded it).
pub fn password_expired(policy: &Policy, entry: &Entry, now: u64) -> bool {
    if is_machine(entry) || uac(entry) & UF_DONT_EXPIRE_PASSWD != 0 {
        return false;
    }
    if crate::principal::principal_name(entry).is_ok_and(|p| p.starts_with("krbtgt/")) {
        return false;
    }
    match pwd_last_set(entry) {
        None => false,
        Some(0) => true,
        Some(set) => policy.max_age != 0 && now.saturating_sub(set) >= policy.max_age,
    }
}

/// Checks `password` for `entry` against `policy`. `now` is a FILETIME.
pub fn check(ctx: &FipsContext, policy: &Policy, entry: &Entry, password: &[u8], mode: Mode, now: u64) -> Result<(), Violation> {
    let text = String::from_utf8_lossy(password);
    let min = policy.effective_min_length();
    if password.len() < FIPS_MIN_LENGTH as usize || text.chars().count() < min as usize {
        return Err(Violation::TooShort(min));
    }
    if is_machine(entry) {
        return Ok(());
    }
    if policy.complex() {
        if let Some(why) = complexity_violation(&text, entry) {
            return Err(Violation::NotComplex(why));
        }
    }
    if mode == Mode::Change {
        if policy.min_age != 0 {
            if let Some(set) = pwd_last_set(entry).filter(|&s| s != 0) {
                if now.saturating_sub(set) < policy.min_age {
                    return Err(Violation::TooSoon);
                }
            }
        }
        if policy.history_length != 0 && in_history(ctx, entry, password, policy.history_length as usize)? {
            return Err(Violation::InHistory(policy.history_length));
        }
    }
    Ok(())
}

/// AD's "Password must meet complexity requirements": it may not contain
/// the `sAMAccountName` (when longer than two characters) nor any token of
/// three or more characters of the `displayName` (split on `,.-_#`, space
/// and tab), case-insensitively; and it draws on at least three of: upper
/// case, lower case, digits, non-alphanumerics, and letters that are
/// neither upper nor lower case. `None` if it complies, else why not.
pub fn complexity_violation(password: &str, entry: &Entry) -> Option<String> {
    let lower = password.to_lowercase();
    if let Some(sam) = first_value(entry, "samaccountname") {
        let sam = sam.to_lowercase();
        if sam.chars().count() > 2 && lower.contains(&sam) {
            return Some("it contains the account name".into());
        }
    }
    if let Some(display) = first_value(entry, "displayname") {
        let delims = [',', '.', '-', '_', '#', ' ', '\t'];
        for token in display.split(&delims[..]).filter(|t| t.chars().count() >= 3) {
            if lower.contains(&token.to_lowercase()) {
                return Some("it contains part of the display name".into());
            }
        }
    }
    let (mut upper, mut low, mut digit, mut other, mut letter) = (false, false, false, false, false);
    for c in password.chars() {
        if c.is_uppercase() {
            upper = true;
        } else if c.is_lowercase() {
            low = true;
        } else if c.is_ascii_digit() {
            digit = true;
        } else if c.is_alphabetic() {
            letter = true;
        } else if !c.is_control() && !c.is_numeric() {
            other = true;
        }
    }
    let kinds = [upper, low, digit, other, letter].iter().filter(|&&k| k).count();
    (kinds < 3).then(|| format!("it uses {kinds} of the 5 character kinds, 3 are needed"))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether `password` is one of the last `n` passwords. An entry set
/// before #70 kept history has only its current key to compare with.
fn in_history(ctx: &FipsContext, entry: &Entry, password: &[u8], n: usize) -> Result<bool, Violation> {
    let mut candidates: Vec<(Vec<u8>, Vec<u8>)> = history(entry).into_iter().take(n).collect();
    if candidates.is_empty() {
        if let (Ok(salt), Ok(key)) = (crate::principal::salt(entry), crate::principal::key_for_enctype(entry, HISTORY_ENCTYPE)) {
            candidates.push((salt, key.key));
        }
    }
    for (salt, key) in candidates {
        let derived = kerberos::string_to_key(ctx, HISTORY_ENCTYPE, password, &salt, None).map_err(|e| Violation::Internal(e.to_string()))?;
        if constant_time_eq(&derived, &key) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The stored history, newest first, as `(salt, key)`; malformed values
/// are skipped.
pub fn history(entry: &Entry) -> Vec<(Vec<u8>, Vec<u8>)> {
    entry
        .get(ATTR_HISTORY)
        .unwrap_or_default()
        .iter()
        .filter_map(|v| {
            let (salt, key) = v.split_once(':')?;
            Some((salt.as_bytes().to_vec(), hex_decode(key)?))
        })
        .collect()
}

/// Puts `(salt, key)` at the front of `entry`'s history, keeping at most
/// [`HISTORY_MAX`].
pub fn push_history(entry: &mut Entry, salt: &str, key: &[u8]) {
    let mut values = vec![format!("{salt}:{}", hex_encode(key))];
    values.extend(entry.get(ATTR_HISTORY).unwrap_or_default().iter().take(HISTORY_MAX - 1).cloned());
    entry.set(ATTR_HISTORY, values);
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 864_000_000_000;

    fn domain(pairs: &[(&str, &str)]) -> Entry {
        let mut e = Entry::new();
        for (k, v) in pairs {
            e.set(k, [*v]);
        }
        e
    }

    fn user(sam: &str) -> Entry {
        let mut e = Entry::new();
        e.set("objectclass", ["top", "person", "user"]);
        e.set("samaccountname", [sam]);
        e
    }

    #[test]
    fn absent_policy_is_the_fips_floor_only() {
        let p = Policy::from_domain(&Entry::new());
        assert_eq!(p, Policy::default());
        assert_eq!(p.effective_min_length(), 8);
        let ctx = FipsContext::new().unwrap();
        assert_eq!(check(&ctx, &p, &user("alice"), b"short1", Mode::Change, 0), Err(Violation::TooShort(8)));
        assert_eq!(check(&ctx, &p, &user("alice"), b"alllowercase", Mode::Change, 0), Ok(()));
    }

    #[test]
    fn reads_ad_encoded_policy() {
        let p = Policy::from_domain(&domain(&[
            ("minPwdLength", "12"),
            ("pwdHistoryLength", "99"),
            ("pwdProperties", "1"),
            ("minPwdAge", &(-DAY).to_string()),
            ("maxPwdAge", "-9223372036854775808"),
        ]));
        assert_eq!(p, Policy { min_length: 12, history_length: 24, properties: 1, min_age: DAY as u64, max_age: 0 });
        assert!(p.complex());
    }

    #[test]
    fn blob_matches_impacket_and_mit_layout() {
        // struct.pack("!HIIIQQ", 0, 14, 24, 1, 42 days, 1 day)
        let p = Policy { min_length: 14, history_length: 24, properties: 1, min_age: DAY as u64, max_age: 42 * DAY as u64 };
        let b = p.blob();
        assert_eq!(&b[..2], &[0, 0]);
        assert_eq!(u32::from_be_bytes(b[2..6].try_into().unwrap()), 14);
        assert_eq!(u32::from_be_bytes(b[6..10].try_into().unwrap()), 24);
        assert_eq!(u32::from_be_bytes(b[10..14].try_into().unwrap()), 1);
        assert_eq!(u64::from_be_bytes(b[14..22].try_into().unwrap()), 42 * DAY as u64);
        assert_eq!(u64::from_be_bytes(b[22..30].try_into().unwrap()), DAY as u64);
        // The FIPS floor is what is reported when less is configured.
        assert_eq!(u32::from_be_bytes(Policy::default().blob()[2..6].try_into().unwrap()), 8);
    }

    #[test]
    fn complexity_rules() {
        let mut alice = user("alice");
        alice.set("displayName", ["Alice Smith-Jones"]);
        assert!(complexity_violation("Passw0rd!x", &alice).is_none());
        assert!(complexity_violation("lowercaseonly", &alice).unwrap().contains("1 of the 5"));
        assert!(complexity_violation("lower123456", &alice).unwrap().contains("2 of the 5"));
        assert!(complexity_violation("Lower123456", &alice).is_none());
        assert!(complexity_violation("xxALICExx1!", &alice).unwrap().contains("account name"));
        assert!(complexity_violation("Jones2026!!", &alice).unwrap().contains("display name"));
        // A two-letter token of the display name is ignored.
        let mut bo = user("bo");
        bo.set("displayName", ["Bo Li"]);
        assert!(complexity_violation("Bo1Li2bo!!", &bo).is_none());
        // Letters with no case (CJK) are a kind of their own.
        assert!(complexity_violation("密码密码abc1", &alice).is_none());
    }

    #[test]
    fn machines_are_exempt_from_all_but_length() {
        let p = Policy { min_length: 0, history_length: 24, properties: 1, min_age: DAY as u64, max_age: DAY as u64 };
        let ctx = FipsContext::new().unwrap();
        let m = user("TESTMAC1$");
        assert!(is_machine(&m));
        assert_eq!(check(&ctx, &p, &m, b"lowercaseonly", Mode::Change, 0), Ok(()));
        assert_eq!(check(&ctx, &p, &m, b"short", Mode::Reset, 0), Err(Violation::TooShort(8)));
        let mut set = m.clone();
        set.set(ATTR_PWD_LAST_SET, ["1"]);
        assert!(!password_expired(&p, &set, u64::MAX));
    }

    #[test]
    fn history_refuses_reuse_on_change_but_not_on_reset() {
        let ctx = FipsContext::new().unwrap();
        let p = Policy { history_length: 2, ..Policy::default() };
        let mut e = user("alice");
        crate::principal::set_password(&ctx, &mut e, "alice@IRON.LO", b"FirstPass1!").unwrap();
        crate::principal::set_password(&ctx, &mut e, "alice@IRON.LO", b"SecondPass2!").unwrap();
        crate::principal::set_password(&ctx, &mut e, "alice@IRON.LO", b"ThirdPass3!").unwrap();
        assert_eq!(history(&e).len(), 3);
        assert_eq!(check(&ctx, &p, &e, b"ThirdPass3!", Mode::Change, 0), Err(Violation::InHistory(2)));
        assert_eq!(check(&ctx, &p, &e, b"SecondPass2!", Mode::Change, 0), Err(Violation::InHistory(2)));
        // The third-newest is outside a history of 2.
        assert_eq!(check(&ctx, &p, &e, b"FirstPass1!", Mode::Change, 0), Ok(()));
        assert_eq!(check(&ctx, &p, &e, b"ThirdPass3!", Mode::Reset, 0), Ok(()));
    }

    #[test]
    fn history_falls_back_to_the_current_key() {
        let ctx = FipsContext::new().unwrap();
        let mut e = user("alice");
        crate::principal::set_password(&ctx, &mut e, "alice@IRON.LO", b"CurrentPass1!").unwrap();
        e.set(ATTR_HISTORY, Vec::<String>::new());
        let p = Policy { history_length: 1, ..Policy::default() };
        assert_eq!(check(&ctx, &p, &e, b"CurrentPass1!", Mode::Change, 0), Err(Violation::InHistory(1)));
    }

    #[test]
    fn history_is_capped() {
        let mut e = Entry::new();
        for i in 0..30 {
            push_history(&mut e, &format!("salt{i}"), &[i as u8]);
        }
        let h = history(&e);
        assert_eq!(h.len(), HISTORY_MAX);
        assert_eq!(h[0], (b"salt29".to_vec(), vec![29]));
    }

    #[test]
    fn ages() {
        let ctx = FipsContext::new().unwrap();
        let p = Policy { min_age: DAY as u64, max_age: 10 * DAY as u64, ..Policy::default() };
        let set = 1_000 * DAY as u64;
        let mut e = user("alice");
        e.set(ATTR_PWD_LAST_SET, [set.to_string()]);
        assert_eq!(check(&ctx, &p, &e, b"Whatever123!", Mode::Change, set + 10), Err(Violation::TooSoon));
        assert_eq!(check(&ctx, &p, &e, b"Whatever123!", Mode::Reset, set + 10), Ok(()));
        assert_eq!(check(&ctx, &p, &e, b"Whatever123!", Mode::Change, set + DAY as u64), Ok(()));
        assert!(!password_expired(&p, &e, set + 9 * DAY as u64));
        assert!(password_expired(&p, &e, set + 10 * DAY as u64));
        e.set("userAccountControl", ["66048"]); // NORMAL_ACCOUNT | DONT_EXPIRE_PASSWD
        assert!(!password_expired(&p, &e, set + 10 * DAY as u64));
        let mut must_change = user("bob");
        must_change.set(ATTR_PWD_LAST_SET, ["0"]);
        assert!(password_expired(&Policy::default(), &must_change, set));
        assert!(!password_expired(&p, &user("legacy"), u64::MAX));
    }

    #[test]
    fn filetime_now_is_recent() {
        // 2025-12-30T00:00:00Z as a FILETIME.
        assert!(filetime_now() > 134_115_840_000_000_000);
    }
}
