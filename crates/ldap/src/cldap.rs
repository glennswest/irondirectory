//! The LDAP ping (#52, MS-ADTS 6.3.3): how a Windows client finds a domain
//! controller before it joins or logs on.
//!
//! The client sends a search with base `""`, scope base, a filter that is
//! an AND of equality terms naming the domain it wants -- `DnsDomain`,
//! `Host`, `DnsHostName`, `User`, `AAC`, `DomainSid`, `DomainGuid`, and
//! `NtVer` (a little-endian u32 of `NETLOGON_NT_VERSION_*` bits) -- and the
//! one attribute `Netlogon`. The DC answers with a `Netlogon` value holding
//! a `NETLOGON_SAM_LOGON_RESPONSE_EX` (MS-ADTS 6.3.1.9): the DC's flags,
//! the domain GUID, the forest/domain/host DNS names, the NetBIOS names and
//! the site names, all RFC 1035-compressed against the start of the value.
//!
//! The ping arrives over CLDAP (UDP 389: one `LDAPMessage` per datagram,
//! answered with the `SearchResultEntry` and `SearchResultDone` in one
//! datagram, as AD does) and sometimes over plain LDAP on TCP;
//! [`answer`] serves both.
//!
//! What is answered:
//! - a ping whose `DnsDomain`, `DomainGuid` or `DomainSid` names another
//!   domain gets a `SearchResultDone` with no entry (the DC is not one of
//!   that domain's);
//! - `NtVer` must ask for the `_EX` form (`NETLOGON_NT_VERSION_5EX` or
//!   `_5EX_WITH_IP`), as Windows (XP and later) and Samba both send.
//!   The NT4 and plain-V5 response formats (6.3.1.7, 6.3.1.8) are not
//!   built: such a ping gets a done with no entry, logged.
//! - `User` (with `AAC`): the opcode is `LOGON_SAM_LOGON_RESPONSE_EX` (23)
//!   when `sAMAccountName` names an account that is not disabled and, when
//!   `AAC` is given, whose account type is one `AAC` names (Samba's test:
//!   `AAC` is MS-SAMR 2.2.1.12 USER_* bits, mapped to `userAccountControl`'s
//!   UF_* bits); else `LOGON_SAM_USER_UNKNOWN_EX` (25). Without `User`, 23.
//!
//! The flags this DC claims are what it is: writable (D3: every replica is
//! a strongly-consistent writer, so each may also answer as the PDC), an
//! LDAP server, a directory service, a KDC (the DC host runs iron-kdcd
//! beside iron-ldapd, as the golden does), and not a GC (iron-gcd is its
//! own daemon on 3268), not a time server, not an RODC. DS_DS_8/9/10 match
//! the 2016 functional levels rootDSE publishes. There are no sites yet:
//! the DC and every client are in `Default-First-Site-Name`, so the DC is
//! always the closest.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use iron_partition::{Dn, Guid, PartitionId, PartitionRegistry, Sid};
use rasn::types::SetOf;
use rasn_ldap::{
    Filter, LdapMessage, LdapResult, PartialAttribute, ProtocolOp, ResultCode, SearchRequest, SearchRequestScope,
    SearchResultDone, SearchResultEntry,
};
use tokio::net::UdpSocket;

use crate::AppState;

/// NETLOGON_NT_VERSION_* (MS-ADTS 6.3.1.1).
pub const NT_VERSION_1: u32 = 0x1;
pub const NT_VERSION_5: u32 = 0x2;
pub const NT_VERSION_5EX: u32 = 0x4;
pub const NT_VERSION_5EX_WITH_IP: u32 = 0x8;
pub const NT_VERSION_WITH_CLOSEST_SITE: u32 = 0x10;

/// Operation codes (MS-ADTS 6.3.1.9).
pub const LOGON_SAM_LOGON_RESPONSE_EX: u16 = 23;
pub const LOGON_SAM_USER_UNKNOWN_EX: u16 = 25;

/// DS_FLAG bits (MS-ADTS 6.3.1.2).
pub const DS_PDC_FLAG: u32 = 0x0000_0001;
pub const DS_GC_FLAG: u32 = 0x0000_0004;
pub const DS_LDAP_FLAG: u32 = 0x0000_0008;
pub const DS_DS_FLAG: u32 = 0x0000_0010;
pub const DS_KDC_FLAG: u32 = 0x0000_0020;
pub const DS_TIMESERV_FLAG: u32 = 0x0000_0040;
pub const DS_CLOSEST_FLAG: u32 = 0x0000_0080;
pub const DS_WRITABLE_FLAG: u32 = 0x0000_0100;
pub const DS_FULL_SECRET_DOMAIN_6_FLAG: u32 = 0x0000_1000;
pub const DS_DS_8_FLAG: u32 = 0x0000_4000;
pub const DS_DS_9_FLAG: u32 = 0x0000_8000;
pub const DS_DS_10_FLAG: u32 = 0x0001_0000;
pub const DS_DNS_CONTROLLER_FLAG: u32 = 0x2000_0000;
pub const DS_DNS_DOMAIN_FLAG: u32 = 0x4000_0000;
pub const DS_DNS_FOREST_FLAG: u32 = 0x8000_0000;

/// The one site there is (no `cn=Sites` container yet).
pub const DEFAULT_SITE: &str = "Default-First-Site-Name";

/// What a ping answer says about this DC and its domain. Built once at
/// startup from the forest registry ([`DcInfo::from_topology`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcInfo {
    pub base_dn: Dn,
    pub forest_dns: String,
    pub domain_dns: String,
    pub host_dns: String,
    pub netbios_domain: String,
    pub netbios_computer: String,
    pub domain_guid: Guid,
    pub domain_sid: Option<Sid>,
    pub forest_root: bool,
    /// The address `_WITH_IP` answers carry. `None`: the address the
    /// client's datagram reached (UDP) or `host_dns` resolves to (TCP).
    pub address: Option<Ipv4Addr>,
}

impl DcInfo {
    /// This DC's answer, from its own partition's record in the forest
    /// registry: the realm (as the domain's DNS name), the domain GUID and
    /// SID, the NetBIOS name, and the root domain's realm as the forest's
    /// name. `host` is the DC's own DNS name; one with no dot is taken as
    /// a host in the domain. Errors name what the record lacks.
    pub fn from_topology(topology: &PartitionRegistry, own: &PartitionId, host: &str, address: Option<Ipv4Addr>) -> Result<DcInfo, String> {
        let p = topology.get(own).ok_or_else(|| format!("partition {own} is not in the forest registry"))?;
        let realm = p.realm.as_deref().ok_or_else(|| format!("partition {own} has no realm"))?;
        let guid_text = p.domain_guid.as_deref().ok_or_else(|| format!("partition {own} has no domain GUID (run iron-bootstrap to fill it in)"))?;
        let domain_guid = Guid::parse(guid_text).ok_or_else(|| format!("partition {own}'s domain GUID {guid_text:?} does not parse"))?;
        let domain_sid = match p.domain_sid.as_deref() {
            Some(s) => Some(Sid::parse(s).ok_or_else(|| format!("partition {own}'s domain SID {s:?} does not parse"))?),
            None => None,
        };
        let domain_dns = realm.to_ascii_lowercase();
        let forest_dns = topology
            .root_domain_partition(&p.forest)
            .and_then(|r| r.realm.as_deref())
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| domain_dns.clone());
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return Err("the DC's host name is empty".into());
        }
        let host_dns = if host.contains('.') { host } else { format!("{host}.{domain_dns}") };
        let netbios_computer = netbios(host_dns.split('.').next().unwrap_or_default());
        let netbios_domain = p.netbios_name.clone().unwrap_or_else(|| netbios(realm.split('.').next().unwrap_or_default()));
        Ok(DcInfo {
            base_dn: p.base_dn.clone(),
            forest_dns,
            domain_dns,
            host_dns,
            netbios_domain,
            netbios_computer,
            domain_guid,
            domain_sid,
            forest_root: p.superior.is_none(),
            address,
        })
    }

    /// The DS_FLAG bits this DC answers with (see the module docs).
    pub fn flags(&self) -> u32 {
        let mut f = DS_PDC_FLAG
            | DS_LDAP_FLAG
            | DS_DS_FLAG
            | DS_KDC_FLAG
            | DS_CLOSEST_FLAG
            | DS_WRITABLE_FLAG
            | DS_FULL_SECRET_DOMAIN_6_FLAG
            | DS_DS_8_FLAG
            | DS_DS_9_FLAG
            | DS_DS_10_FLAG
            | DS_DNS_CONTROLLER_FLAG
            | DS_DNS_DOMAIN_FLAG;
        if self.forest_root {
            f |= DS_DNS_FOREST_FLAG;
        }
        f
    }
}

/// A NetBIOS name: upper case, at most 15 characters.
fn netbios(label: &str) -> String {
    label.to_ascii_uppercase().chars().take(15).collect()
}

/// The terms of one LDAP ping's filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ping {
    pub dns_domain: Option<String>,
    pub host: Option<String>,
    pub user: Option<String>,
    pub aac: Option<u32>,
    pub domain_sid: Option<Vec<u8>>,
    pub domain_guid: Option<Vec<u8>>,
    pub nt_ver: u32,
}

fn le_u32(v: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(v.try_into().ok()?))
}

/// The ping in `req`, or `None` when `req` is not one: base `""`, scope
/// base, an equality term or an AND of them carrying a 4-byte `NtVer`, and
/// `Netlogon` among the requested attributes. Terms the ping does not use
/// (`DnsHostName`, unknown ones) are ignored.
pub fn parse_ping(req: &SearchRequest) -> Option<Ping> {
    if !req.base_object.is_empty() || req.scope != SearchRequestScope::BaseObject {
        return None;
    }
    if !req.attributes.iter().any(|a| a.eq_ignore_ascii_case("Netlogon")) {
        return None;
    }
    let terms = match &req.filter {
        Filter::And(set) => set.to_vec().into_iter().cloned().collect::<Vec<Filter>>(),
        f @ Filter::EqualityMatch(_) => vec![f.clone()],
        _ => return None,
    };
    let mut ping = Ping::default();
    let mut nt_ver = None;
    for term in &terms {
        let Filter::EqualityMatch(ava) = term else { return None };
        let v: &[u8] = &ava.assertion_value;
        let text = || String::from_utf8_lossy(v).into_owned();
        match ava.attribute_desc.to_ascii_lowercase().as_str() {
            "dnsdomain" => ping.dns_domain = Some(text()),
            "host" => ping.host = Some(text()),
            "user" => ping.user = Some(text()),
            "aac" => ping.aac = Some(le_u32(v)?),
            "domainsid" => ping.domain_sid = Some(v.to_vec()),
            "domainguid" => ping.domain_guid = Some(v.to_vec()),
            "ntver" => nt_ver = Some(le_u32(v)?),
            _ => {}
        }
    }
    ping.nt_ver = nt_ver?;
    Some(ping)
}

/// Whether the ping names this DC's domain (every one of `DnsDomain`,
/// `DomainGuid`, `DomainSid` that it carries; an empty value, or an
/// all-zero GUID, names none).
pub fn names_this_domain(info: &DcInfo, ping: &Ping) -> bool {
    if let Some(d) = &ping.dns_domain {
        let d = d.trim_end_matches('.');
        if !d.is_empty() && !d.eq_ignore_ascii_case(&info.domain_dns) {
            return false;
        }
    }
    if let Some(g) = &ping.domain_guid {
        // An all-zero GUID names no domain (a client that kept LSARPC's
        // old zero DomainGuid, before #52, sends one).
        if g.iter().any(|b| *b != 0) && g.as_slice() != info.domain_guid.to_wire() {
            return false;
        }
    }
    if let Some(s) = &ping.domain_sid {
        if !s.is_empty() && Some(s.clone()) != info.domain_sid.as_ref().map(Sid::encode) {
            return false;
        }
    }
    true
}

/// RFC 1035 §4.1.4 name compression over one buffer, as MS-ADTS 6.3.1.9's
/// strings are: every suffix written is remembered, and a later name ending
/// in one points back to it.
struct NameWriter {
    buf: Vec<u8>,
    seen: HashMap<String, u16>,
}

impl NameWriter {
    fn name(&mut self, s: &str) {
        let labels: Vec<&str> = s.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).collect();
        for i in 0..labels.len() {
            let suffix = labels[i..].join(".").to_ascii_lowercase();
            if let Some(&off) = self.seen.get(&suffix) {
                self.buf.extend_from_slice(&(0xC000 | off).to_be_bytes());
                return;
            }
            if self.buf.len() < 0x3FFF {
                self.seen.insert(suffix, self.buf.len() as u16);
            }
            let bytes = labels[i].as_bytes();
            let bytes = &bytes[..bytes.len().min(63)];
            self.buf.push(bytes.len() as u8);
            self.buf.extend_from_slice(bytes);
        }
        self.buf.push(0);
    }
}

/// The `NETLOGON_SAM_LOGON_RESPONSE_EX` (MS-ADTS 6.3.1.9) for `ping`, or
/// `None` when this DC does not answer it (another domain, or no `_EX`
/// form asked for). `user_known`: the `User` lookup's result, `None` when
/// the ping names no user. `dc_ip`: the address a `_WITH_IP` answer
/// carries.
pub fn netlogon_response(info: &DcInfo, ping: &Ping, user_known: Option<bool>, dc_ip: Ipv4Addr) -> Option<Vec<u8>> {
    if ping.nt_ver & (NT_VERSION_5EX | NT_VERSION_5EX_WITH_IP) == 0 || !names_this_domain(info, ping) {
        return None;
    }
    let opcode = if user_known == Some(false) { LOGON_SAM_USER_UNKNOWN_EX } else { LOGON_SAM_LOGON_RESPONSE_EX };
    let mut w = NameWriter { buf: Vec::with_capacity(256), seen: HashMap::new() };
    w.buf.extend_from_slice(&opcode.to_le_bytes());
    w.buf.extend_from_slice(&0u16.to_le_bytes()); // Sbz
    w.buf.extend_from_slice(&info.flags().to_le_bytes());
    w.buf.extend_from_slice(&info.domain_guid.to_wire());
    w.name(&info.forest_dns);
    w.name(&info.domain_dns);
    w.name(&info.host_dns);
    w.name(&info.netbios_domain);
    w.name(&info.netbios_computer);
    w.name(ping.user.as_deref().unwrap_or(""));
    w.name(DEFAULT_SITE); // DcSiteName
    w.name(DEFAULT_SITE); // ClientSiteName
    let mut nt_version = NT_VERSION_1 | NT_VERSION_5EX;
    if ping.nt_ver & NT_VERSION_5EX_WITH_IP != 0 {
        // DcSockAddr: a sockaddr_in (family 2 little-endian, port 0, the
        // address in network order, eight zero bytes).
        w.buf.push(16);
        w.buf.extend_from_slice(&2u16.to_le_bytes());
        w.buf.extend_from_slice(&0u16.to_be_bytes());
        w.buf.extend_from_slice(&dc_ip.octets());
        w.buf.extend_from_slice(&[0u8; 8]);
        nt_version |= NT_VERSION_5EX_WITH_IP;
    }
    if ping.nt_ver & NT_VERSION_WITH_CLOSEST_SITE != 0 {
        w.name(""); // NextClosestSiteName: one site, nothing closer
    }
    w.buf.extend_from_slice(&nt_version.to_le_bytes());
    w.buf.extend_from_slice(&0xFFFFu16.to_le_bytes()); // LmNtToken
    w.buf.extend_from_slice(&0xFFFFu16.to_le_bytes()); // Lm20Token
    Some(w.buf)
}

/// MS-SAMR 2.2.1.12 USER_* account bits (what `AAC` carries) to the
/// `userAccountControl` UF_* bits iron-rpc stores (MS-ADTS 2.2.16).
fn aac_to_uf(aac: u32) -> u32 {
    const MAP: [(u32, u32); 9] = [
        (0x0001, 0x0002), // ACCOUNT_DISABLED
        (0x0002, 0x0008), // HOME_DIRECTORY_REQUIRED
        (0x0004, 0x0020), // PASSWORD_NOT_REQUIRED
        (0x0008, 0x0100), // TEMP_DUPLICATE_ACCOUNT
        (0x0010, 0x0200), // NORMAL_ACCOUNT
        (0x0020, 0x0400), // MNS_LOGON_ACCOUNT
        (0x0040, 0x0800), // INTERDOMAIN_TRUST_ACCOUNT
        (0x0080, 0x1000), // WORKSTATION_TRUST_ACCOUNT
        (0x0100, 0x2000), // SERVER_TRUST_ACCOUNT
    ];
    MAP.iter().filter(|(a, _)| aac & a != 0).fold(0, |uf, (_, u)| uf | u)
}

const UF_ACCOUNTDISABLE: u32 = 0x0002;

/// Whether an account with this `userAccountControl` answers a ping for
/// it: not disabled, and of a type `aac` names (any, without `aac` or with
/// `aac` 0). An account with no `userAccountControl` (one added over LDAP
/// without it) is taken as enabled and of any type.
pub fn account_answers(uac: Option<u32>, aac: Option<u32>) -> bool {
    let Some(uac) = uac else { return true };
    if uac & UF_ACCOUNTDISABLE != 0 {
        return false;
    }
    match aac.map(aac_to_uf) {
        None | Some(0) => true,
        Some(want) => uac & want != 0,
    }
}

async fn user_known(app: &AppState, info: &DcInfo, user: &str, aac: Option<u32>) -> bool {
    let mut store = app.store.lock().await;
    let mut candidates = vec![user.to_string()];
    if user.to_ascii_uppercase() != user {
        candidates.push(user.to_ascii_uppercase());
    }
    for name in candidates {
        let dns = match store.lookup_by_index(&info.base_dn, "samaccountname", &name).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(user, "LDAP ping: sAMAccountName lookup failed: {e}");
                return false;
            }
        };
        for dn in dns {
            if let Ok(Some(entry)) = store.get_entry(&dn).await {
                let uac = entry.get("useraccountcontrol").and_then(|v| v.first()).and_then(|v| v.parse::<u32>().ok());
                if account_answers(uac, aac) {
                    return true;
                }
            }
        }
    }
    false
}

fn done(code: ResultCode, diagnostic: &str) -> ProtocolOp {
    ProtocolOp::SearchResDone(SearchResultDone(LdapResult::new(code, String::new().into(), diagnostic.into())))
}

/// The answer to `req` when it is an LDAP ping, else `None` (an ordinary
/// search for the caller to serve). `dc_ip`: see [`DcInfo::address`].
pub async fn answer(app: &AppState, req: &SearchRequest, dc_ip: Option<Ipv4Addr>) -> Option<Vec<ProtocolOp>> {
    let ping = parse_ping(req)?;
    let Some(info) = app.dc_info.as_ref() else {
        return Some(vec![done(ResultCode::UnwillingToPerform, "LDAP ping: this DC has no domain record (IRON_LDAP_CONFIG_* unset, or no domain GUID)")]);
    };
    if ping.nt_ver & (NT_VERSION_5EX | NT_VERSION_5EX_WITH_IP) == 0 {
        tracing::info!(nt_ver = format!("{:#x}", ping.nt_ver), "LDAP ping without NETLOGON_NT_VERSION_5EX: only the _EX response is built");
    }
    let known = match &ping.user {
        Some(u) if !u.is_empty() => Some(user_known(app, info, u, ping.aac).await),
        _ => None,
    };
    let ip = match (info.address, dc_ip) {
        (Some(a), _) | (None, Some(a)) => a,
        (None, None) if ping.nt_ver & NT_VERSION_5EX_WITH_IP != 0 => resolve_v4(&info.host_dns).await.unwrap_or(Ipv4Addr::UNSPECIFIED),
        (None, None) => Ipv4Addr::UNSPECIFIED,
    };
    let mut ops = Vec::with_capacity(2);
    if let Some(blob) = netlogon_response(info, &ping, known, ip) {
        let attr = PartialAttribute::new("Netlogon".into(), SetOf::from_vec(vec![blob.into()]));
        ops.push(ProtocolOp::SearchResEntry(SearchResultEntry::new(String::new().into(), vec![attr])));
    }
    ops.push(done(ResultCode::Success, ""));
    Some(ops)
}

async fn resolve_v4(host: &str) -> Option<Ipv4Addr> {
    tokio::net::lookup_host((host, 389)).await.ok()?.find_map(|a| match a.ip() {
        IpAddr::V4(v) => Some(v),
        IpAddr::V6(_) => None,
    })
}

/// The local IPv4 address a datagram to `peer` leaves from (a connected
/// UDP socket sends nothing; it only picks the route).
fn local_ip_towards(peer: SocketAddr) -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    s.connect(peer).ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v) if !v.is_unspecified() => Some(v),
        _ => None,
    }
}

/// The reply datagram for one request datagram: the encoded response
/// messages back to back, or `None` to send nothing (not an `LDAPMessage`,
/// or not a search). A search that is not a ping is refused: CLDAP here
/// serves only the ping.
pub async fn handle_datagram(app: &AppState, datagram: &[u8], dc_ip: Option<Ipv4Addr>) -> Option<Vec<u8>> {
    let msg: LdapMessage = rasn::ber::decode(datagram).ok()?;
    let ProtocolOp::SearchRequest(req) = &msg.protocol_op else { return None };
    let ops = match answer(app, req, dc_ip).await {
        Some(ops) => ops,
        None => vec![done(ResultCode::UnwillingToPerform, "CLDAP serves only the LDAP ping (MS-ADTS 6.3.3)")],
    };
    let mut out = Vec::new();
    for op in ops {
        out.extend(rasn::ber::encode(&LdapMessage::new(msg.message_id, op)).ok()?);
    }
    Some(out)
}

/// Serves CLDAP on `socket` until it errors: each datagram is answered on
/// its own task.
pub async fn serve(socket: UdpSocket, app: Arc<AppState>) -> std::io::Result<()> {
    let socket = Arc::new(socket);
    let bound = match socket.local_addr()?.ip() {
        IpAddr::V4(v) if !v.is_unspecified() => Some(v),
        _ => None,
    };
    let mut buf = vec![0u8; 65_536];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let datagram = buf[..n].to_vec();
        let (app, socket) = (app.clone(), socket.clone());
        tokio::spawn(async move {
            let dc_ip = bound.or_else(|| local_ip_towards(peer));
            if let Some(reply) = handle_datagram(&app, &datagram, dc_ip).await {
                if let Err(e) = socket.send_to(&reply, peer).await {
                    tracing::warn!(%peer, "CLDAP reply not sent: {e}");
                }
            } else {
                tracing::debug!(%peer, n, "CLDAP datagram ignored (not an LDAP search)");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iron_partition::{ClusterRef, ForestId, Partition};
    use rasn_ldap::AttributeValueAssertion;

    fn info() -> DcInfo {
        DcInfo {
            base_dn: Dn::parse("dc=corp,dc=example,dc=lo").unwrap(),
            forest_dns: "corp.example.lo".into(),
            domain_dns: "corp.example.lo".into(),
            host_dns: "dc1.corp.example.lo".into(),
            netbios_domain: "CORP".into(),
            netbios_computer: "DC1".into(),
            domain_guid: Guid::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            domain_sid: Some(Sid::parse("S-1-5-21-1-2-3").unwrap()),
            forest_root: true,
            address: None,
        }
    }

    fn eq(attr: &str, v: &[u8]) -> Filter {
        Filter::EqualityMatch(AttributeValueAssertion::new(attr.into(), v.to_vec().into()))
    }

    fn req(filter: Filter, attrs: &[&str]) -> SearchRequest {
        SearchRequest::new(
            String::new().into(),
            SearchRequestScope::BaseObject,
            rasn_ldap::SearchRequestDerefAliases::NeverDerefAliases,
            0,
            0,
            false,
            filter,
            attrs.iter().map(|a| (*a).into()).collect(),
        )
    }

    fn ping_req(terms: Vec<Filter>) -> SearchRequest {
        req(Filter::And(SetOf::from_vec(terms)), &["Netlogon"])
    }

    #[test]
    fn a_ping_is_parsed_and_other_searches_are_not() {
        let r = ping_req(vec![eq("DnsDomain", b"corp.example.lo"), eq("Host", b"WS1"), eq("NtVer", &6u32.to_le_bytes())]);
        let p = parse_ping(&r).unwrap();
        assert_eq!(p.dns_domain.as_deref(), Some("corp.example.lo"));
        assert_eq!(p.host.as_deref(), Some("WS1"));
        assert_eq!(p.nt_ver, 6);

        // No NtVer, a 3-byte NtVer, no Netlogon attribute: not a ping.
        assert!(parse_ping(&ping_req(vec![eq("DnsDomain", b"corp.example.lo")])).is_none());
        assert!(parse_ping(&ping_req(vec![eq("NtVer", &[6, 0, 0])])).is_none());
        assert!(parse_ping(&req(Filter::And(SetOf::from_vec(vec![eq("NtVer", &6u32.to_le_bytes())])), &["namingContexts"])).is_none());
        // A single NtVer term is a ping too.
        assert!(parse_ping(&req(eq("ntver", &4u32.to_le_bytes()), &["netlogon"])).is_some());
    }

    /// Decodes a compressed name at `off`, returning it and the offset after it.
    fn read_name(b: &[u8], mut off: usize) -> (String, usize) {
        let mut labels = Vec::new();
        let mut end = None;
        loop {
            let len = b[off] as usize;
            if len & 0xC0 == 0xC0 {
                end.get_or_insert(off + 2);
                off = ((len & 0x3F) << 8) | b[off + 1] as usize;
                continue;
            }
            if len == 0 {
                end.get_or_insert(off + 1);
                break;
            }
            labels.push(String::from_utf8(b[off + 1..off + 1 + len].to_vec()).unwrap());
            off += 1 + len;
        }
        (labels.join("."), end.unwrap())
    }

    #[test]
    fn the_ex_response_has_every_field_in_order_with_names_compressed() {
        let ping = Ping { user: Some("WS1$".into()), nt_ver: NT_VERSION_5EX | NT_VERSION_5EX_WITH_IP | NT_VERSION_WITH_CLOSEST_SITE, ..Ping::default() };
        let b = netlogon_response(&info(), &ping, Some(true), Ipv4Addr::new(192, 0, 2, 7)).unwrap();
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), LOGON_SAM_LOGON_RESPONSE_EX);
        assert_eq!(u16::from_le_bytes([b[2], b[3]]), 0);
        let flags = u32::from_le_bytes(b[4..8].try_into().unwrap());
        assert_eq!(flags & (DS_GC_FLAG | DS_TIMESERV_FLAG), 0);
        for f in [DS_PDC_FLAG, DS_LDAP_FLAG, DS_DS_FLAG, DS_KDC_FLAG, DS_WRITABLE_FLAG, DS_CLOSEST_FLAG, DS_DNS_FOREST_FLAG] {
            assert_ne!(flags & f, 0, "{f:#x}");
        }
        assert_eq!(&b[8..24], &info().domain_guid.to_wire());
        let mut off = 24;
        let mut names = Vec::new();
        for _ in 0..8 {
            let (n, next) = read_name(&b, off);
            names.push(n);
            off = next;
        }
        assert_eq!(
            names,
            ["corp.example.lo", "corp.example.lo", "dc1.corp.example.lo", "CORP", "DC1", "WS1$", DEFAULT_SITE, DEFAULT_SITE]
        );
        // The domain name repeats the forest's: a bare 2-byte pointer.
        assert_eq!(b[24 + 17], 0xC0);
        assert_eq!(b[off], 16);
        assert_eq!(&b[off + 1..off + 17], &[2, 0, 0, 0, 192, 0, 2, 7, 0, 0, 0, 0, 0, 0, 0, 0]);
        off += 17;
        let (next_closest, next) = read_name(&b, off);
        assert_eq!(next_closest, "");
        off = next;
        assert_eq!(u32::from_le_bytes(b[off..off + 4].try_into().unwrap()), NT_VERSION_1 | NT_VERSION_5EX | NT_VERSION_5EX_WITH_IP);
        assert_eq!(&b[off + 4..], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn without_with_ip_there_is_no_sockaddr_and_an_unknown_user_is_opcode_25() {
        let ping = Ping { user: Some("NOBODY$".into()), nt_ver: NT_VERSION_5EX, ..Ping::default() };
        let b = netlogon_response(&info(), &ping, Some(false), Ipv4Addr::UNSPECIFIED).unwrap();
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), LOGON_SAM_USER_UNKNOWN_EX);
        let mut off = 24;
        for _ in 0..8 {
            off = read_name(&b, off).1;
        }
        assert_eq!(u32::from_le_bytes(b[off..off + 4].try_into().unwrap()), NT_VERSION_1 | NT_VERSION_5EX);
        assert_eq!(b.len(), off + 8);
    }

    #[test]
    fn another_domain_or_no_ex_version_gets_no_answer() {
        let i = info();
        let ok = Ping { nt_ver: NT_VERSION_5EX, ..Ping::default() };
        assert!(netlogon_response(&i, &ok, None, Ipv4Addr::UNSPECIFIED).is_some());
        let zero_guid = Ping { domain_guid: Some(vec![0; 16]), ..ok.clone() };
        assert!(netlogon_response(&i, &zero_guid, None, Ipv4Addr::UNSPECIFIED).is_some());
        let trailing_dot = Ping { dns_domain: Some("CORP.example.lo.".into()), ..ok.clone() };
        assert!(netlogon_response(&i, &trailing_dot, None, Ipv4Addr::UNSPECIFIED).is_some());
        for p in [
            Ping { dns_domain: Some("other.lo".into()), ..ok.clone() },
            Ping { domain_guid: Some(vec![1; 16]), ..ok.clone() },
            Ping { domain_sid: Some(Sid::parse("S-1-5-21-9-9-9").unwrap().encode()), ..ok.clone() },
            Ping { nt_ver: NT_VERSION_1 | NT_VERSION_5, ..ok.clone() },
        ] {
            assert!(netlogon_response(&i, &p, None, Ipv4Addr::UNSPECIFIED).is_none(), "{p:?}");
        }
        let right_ids = Ping { domain_guid: Some(i.domain_guid.to_wire().to_vec()), domain_sid: Some(i.domain_sid.clone().unwrap().encode()), ..ok };
        assert!(netlogon_response(&i, &right_ids, None, Ipv4Addr::UNSPECIFIED).is_some());
    }

    #[test]
    fn aac_selects_account_types_and_disabled_accounts_never_answer() {
        let workstation = Some(0x1000);
        assert!(account_answers(workstation, None));
        assert!(account_answers(workstation, Some(0)));
        assert!(account_answers(workstation, Some(0x80)));
        assert!(!account_answers(workstation, Some(0x10)));
        assert!(account_answers(Some(0x200), Some(0x10 | 0x80)));
        assert!(!account_answers(Some(0x1000 | UF_ACCOUNTDISABLE), None));
        assert!(account_answers(None, Some(0x80)));
    }

    #[test]
    fn dc_info_comes_from_the_registry_record() {
        let cluster = ClusterRef::plaintext(["http://127.0.0.1:2379"]);
        let forest = ForestId::new("corp").unwrap();
        let root = Partition::domain("corp", forest.clone(), Dn::parse("dc=corp,dc=example,dc=lo").unwrap(), cluster.clone())
            .unwrap()
            .with_netbios_name("corp")
            .with_domain_sid("S-1-5-21-1-2-3")
            .with_domain_guid("00112233-4455-6677-8899-aabbccddeeff");
        let child = Partition::domain("eu", forest, Dn::parse("dc=eu,dc=corp,dc=example,dc=lo").unwrap(), cluster)
            .unwrap()
            .with_superior(root.id.clone());
        let mut reg = PartitionRegistry::new();
        reg.insert(root.clone()).unwrap();
        reg.insert(child.clone()).unwrap();

        let i = DcInfo::from_topology(&reg, &root.id, "DC1", None).unwrap();
        assert_eq!(i.host_dns, "dc1.corp.example.lo");
        assert_eq!(i.netbios_computer, "DC1");
        assert_eq!(i.netbios_domain, "CORP");
        assert!(i.forest_root && i.flags() & DS_DNS_FOREST_FLAG != 0);

        let err = DcInfo::from_topology(&reg, &child.id, "dc2.eu.corp.example.lo", None).unwrap_err();
        assert!(err.contains("no domain GUID"), "{err}");
        let mut reg2 = PartitionRegistry::new();
        reg2.insert(root.clone()).unwrap();
        reg2.insert(child.with_domain_guid("ffeeddcc-bbaa-9988-7766-554433221100")).unwrap();
        let i = DcInfo::from_topology(&reg2, &PartitionId::new("eu").unwrap(), "dc2.eu.corp.example.lo", None).unwrap();
        assert_eq!((i.forest_dns.as_str(), i.domain_dns.as_str(), i.netbios_domain.as_str()), ("corp.example.lo", "eu.corp.example.lo", "EU"));
        assert!(!i.forest_root && i.flags() & DS_DNS_FOREST_FLAG == 0);
    }
}
