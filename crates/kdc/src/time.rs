//! Kerberos timestamps: `KerberosTime` is DER `GeneralizedTime`
//! (RFC 4120 says it must carry no fractional seconds -- microsecond
//! precision travels separately, in a sibling `*usec` field), which
//! `rasn-kerberos` types as `chrono::DateTime<FixedOffset>`.

use chrono::{TimeZone, Utc};
use rasn::types::Integer;
use rasn_kerberos::KerberosTime;

/// The current time as `(KerberosTime, microseconds)`, whole-second
/// truncated in the `KerberosTime` half per RFC 4120 §5.2.3.
pub fn now() -> (KerberosTime, Integer) {
    let now = Utc::now();
    let usec = now.timestamp_subsec_micros();
    let whole_seconds = Utc.timestamp_opt(now.timestamp(), 0).single().expect("valid timestamp");
    (KerberosTime(whole_seconds.fixed_offset()), (usec as i64).into())
}

/// `now() + seconds`, for ticket `end_time`/`renew_till` etc.
pub fn plus_seconds(seconds: i64) -> KerberosTime {
    let t = Utc::now() + chrono::Duration::seconds(seconds);
    let whole_seconds = Utc.timestamp_opt(t.timestamp(), 0).single().expect("valid timestamp");
    KerberosTime(whole_seconds.fixed_offset())
}

/// Seconds between `a` and `b` (`b - a`), for clock-skew checks.
pub fn diff_seconds(a: &KerberosTime, b: &KerberosTime) -> i64 {
    (b.0 - a.0).num_seconds()
}
