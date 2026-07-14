//! LSARPC (MS-LSAD): just enough for the domain-join handshake to read
//! this domain's SID and DNS/NetBIOS name (#19). `LsarOpenPolicy2` and
//! `LsarClose` don't validate their request contents at all -- this is
//! a permissive, stateless, single-purpose server (no real handle
//! table): `OpenPolicy2` always succeeds with a fixed handle value,
//! `Close` always succeeds for any handle presented. Only
//! `LsarQueryInformationPolicy2` needs real data (the domain's SID/
//! name), read from the caller-supplied [`DomainInfo`].

use crate::ndr::{NdrReader, NdrWriter};
use iron_partition::Sid;

pub const OPNUM_CLOSE: u16 = 0;
pub const OPNUM_OPEN_POLICY2: u16 = 44;
pub const OPNUM_QUERY_INFORMATION_POLICY2: u16 = 46;

/// `PolicyDnsDomainInformation` (MS-LSAD `POLICY_INFORMATION_CLASS`, value 12).
pub const POLICY_DNS_DOMAIN_INFORMATION: u16 = 12;

/// A fixed, non-secret placeholder policy handle -- this server doesn't
/// track real handle state (see module docs), so every `OpenPolicy2`
/// returns this same value and every `Close` accepts any handle.
pub const POLICY_HANDLE: [u8; 20] = [0x4c, 0x53, 0x41, 0x00, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// What `LsarQueryInformationPolicy2` reports for `PolicyDnsDomainInformation`.
pub struct DomainInfo<'a> {
    pub netbios_name: &'a str,
    pub dns_domain_name: &'a str,
    pub dns_forest_name: &'a str,
    pub domain_sid: &'a Sid,
}

/// `LsarOpenPolicy2`: ignores its request entirely (see module docs) and
/// always returns [`POLICY_HANDLE`] with `STATUS_SUCCESS`.
pub fn open_policy2() -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.handle(&POLICY_HANDLE);
    w.u32(0); // NTSTATUS STATUS_SUCCESS
    w.buf
}

/// `LsarClose`: always succeeds, echoing a zeroed handle (real servers
/// zero the handle in the response to signal it's no longer valid).
pub fn close() -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.handle(&[0u8; 20]);
    w.u32(0); // STATUS_SUCCESS
    w.buf
}

/// `LsarQueryInformationPolicy2` for `PolicyDnsDomainInformation` (the
/// only info level this server implements -- anything else gets
/// `STATUS_INVALID_INFO_CLASS`, `None` here to signal that to the caller).
pub fn query_information_policy2(stub_data: &[u8], info: &DomainInfo) -> Option<Vec<u8>> {
    let mut r = NdrReader::new(stub_data);
    let _handle = r.handle().ok()?;
    let level = r.u16().ok()?;
    if level != POLICY_DNS_DOMAIN_INFORMATION {
        return None;
    }

    let mut w = NdrWriter::new();
    w.referent_id(); // Buffer: PLSAPR_POLICY_INFORMATION (non-null)
    w.u16(POLICY_DNS_DOMAIN_INFORMATION); // union discriminant/switch
    w.u16(0); // pad to 4-byte align before the struct body

    // LSAPR_POLICY_DNS_DOMAIN_INFO fixed part: three RPC_UNICODE_STRING
    // headers, then a 16-byte GUID (all zero -- not modeled), then a SID pointer.
    let name = w.unicode_string_header(Some(info.netbios_name));
    let dns_name = w.unicode_string_header(Some(info.dns_domain_name));
    let dns_forest = w.unicode_string_header(Some(info.dns_forest_name));
    w.bytes(&[0u8; 16]); // DomainGuid -- not modeled
    w.referent_id(); // Sid

    if let Some(s) = name {
        w.unicode_string_deferred(&s);
    }
    if let Some(s) = dns_name {
        w.unicode_string_deferred(&s);
    }
    if let Some(s) = dns_forest {
        w.unicode_string_deferred(&s);
    }
    w.sid_deferred(info.domain_sid);

    w.u32(0); // NTSTATUS STATUS_SUCCESS
    Some(w.buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_domain_info() -> (Sid, DomainInfo<'static>) {
        let sid = Sid::new(Sid::NT_AUTHORITY, [21, 1004336348, 1177238915, 682003330]);
        let info = DomainInfo {
            netbios_name: "IRONLO",
            dns_domain_name: "iron.lo",
            dns_forest_name: "iron.lo",
            domain_sid: Box::leak(Box::new(sid.clone())),
        };
        (sid, info)
    }

    #[test]
    fn open_policy2_returns_fixed_handle_and_success() {
        let resp = open_policy2();
        assert_eq!(&resp[0..20], &POLICY_HANDLE);
        assert_eq!(u32::from_le_bytes(resp[20..24].try_into().unwrap()), 0);
    }

    #[test]
    fn close_zeroes_the_handle() {
        let resp = close();
        assert_eq!(&resp[0..20], &[0u8; 20]);
    }

    #[test]
    fn query_dns_domain_information_round_trips() {
        let (sid, info) = sample_domain_info();
        let mut req = NdrWriter::new();
        req.handle(&POLICY_HANDLE);
        req.u16(POLICY_DNS_DOMAIN_INFORMATION);
        let resp = query_information_policy2(&req.buf, &info).unwrap();

        // Trailing NTSTATUS must be success.
        assert_eq!(u32::from_le_bytes(resp[resp.len() - 4..].try_into().unwrap()), 0);

        let mut r = NdrReader::new(&resp);
        let referent = r.u32().unwrap();
        assert_ne!(referent, 0);
        let discriminant = r.u16().unwrap();
        assert_eq!(discriminant, POLICY_DNS_DOMAIN_INFORMATION);
        let _pad = r.u16().unwrap();
        let (name_len, name_ref) = r.unicode_string_header().unwrap();
        assert_eq!(name_len, ("IRONLO".len() * 2) as u16);
        let (_, dns_ref) = r.unicode_string_header().unwrap();
        let (_, forest_ref) = r.unicode_string_header().unwrap();
        let _guid = r.bytes(16).unwrap();
        let sid_referent = r.u32().unwrap();
        assert_ne!(sid_referent, 0);

        assert_ne!(name_ref, 0);
        let name = r.unicode_string_deferred().unwrap();
        r.pad_to_4(); // writer pads each string to 4 -- reader must consume it explicitly now
        assert_eq!(name, "IRONLO");
        assert_ne!(dns_ref, 0);
        let dns_name = r.unicode_string_deferred().unwrap();
        r.pad_to_4();
        assert_eq!(dns_name, "iron.lo");
        assert_ne!(forest_ref, 0);
        let dns_forest = r.unicode_string_deferred().unwrap();
        r.pad_to_4();
        assert_eq!(dns_forest, "iron.lo");
        let decoded_sid = r.sid_deferred().unwrap();
        assert_eq!(decoded_sid, sid);
    }

    #[test]
    fn unknown_info_level_returns_none() {
        let (_sid, info) = sample_domain_info();
        let mut req = NdrWriter::new();
        req.handle(&POLICY_HANDLE);
        req.u16(999);
        assert!(query_information_policy2(&req.buf, &info).is_none());
    }
}
