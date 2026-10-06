//! kpasswd: Kerberos change/set password (RFC 3244, #20), port 464.
//!
//! What `dsconfigad` (macOS) uses to give the computer account it just
//! created over LDAP its password, and what MIT `kpasswd` uses to change
//! a user's own. A request is
//!
//! ```text
//! message length (2) | version (2) | AP-REQ length (2) | AP-REQ | KRB-PRIV
//! ```
//!
//! - version 1: change password. The KRB-PRIV's user-data is the new
//!   password, for the ticket's own client.
//! - version 0xff80: set password. The user-data is a `ChgPwdData`
//!   (new password, optional target name and realm).
//!
//! The AP-REQ's ticket is for `kadmin/changepw`, which (as in AD) has no
//! entry of its own: it is read with the krbtgt key (see
//! [`crate::is_changepw`]). The KRB-PRIV is sealed with the
//! Authenticator's subkey (the ticket session key if none, key usage 13).
//! Changing one's own password needs an INITIAL ticket (one from the AS,
//! i.e. a fresh password); setting another principal's needs a
//! domain-admin requester (RID 500, or a member of the RID 512 group).
//!
//! The reply is `length | version 1 | AP-REP length | AP-REP | KRB-PRIV`,
//! the KRB-PRIV carrying a 2-byte result code and a UTF-8 string. A
//! request that can't be authenticated gets `AP-REP length 0` and a
//! KRB-ERROR whose e-data is the result code and string.
//!
//! Not implemented, documented rather than silent: a replay cache for
//! KRB-PRIV timestamps (the AP-REQ's own clock-skew check bounds a
//! replay to the skew window), and password history or complexity
//! policy beyond the FIPS PBKDF2 minimum of 8 bytes.

use std::net::{IpAddr, SocketAddr};

use iron_crypto::kerberos::{self, Enctype};
use iron_partition::{Dn, Sid};
use iron_store::binary_attrs::{decode_binary_attr, OBJECT_SID_ATTR};
use iron_store::model::Entry;
// The prelude, not just the derive names: the derives expand to calls on
// rasn's Encoder/Decoder traits, which must be in scope.
use rasn::prelude::*;
use rasn_kerberos::{ApRep, ApReq, Authenticator, EncApRepPart, EncTicketPart, EncryptedData, HostAddress, KerberosTime, KrbPriv, PrincipalName, Realm};

use crate::{krberror, principal_name_to_string, realm_to_string, AppState, CLOCK_SKEW_SECS};

pub const VERSION_CHANGE: u16 = 1;
pub const VERSION_SET: u16 = 0xff80;

/// RFC 3244 §2 result codes.
pub mod result {
    pub const SUCCESS: u16 = 0;
    pub const MALFORMED: u16 = 1;
    pub const HARDERROR: u16 = 2;
    pub const AUTHERROR: u16 = 3;
    pub const SOFTERROR: u16 = 4;
    pub const ACCESSDENIED: u16 = 5;
    pub const BAD_VERSION: u16 = 6;
    pub const INITIAL_FLAG_NEEDED: u16 = 7;
}

/// Key usage for KRB-PRIV's encrypted part (RFC 4120 §7.5.1).
const USAGE_KRB_PRIV: u32 = 13;
const USAGE_AP_REP: u32 = 12;
const USAGE_AP_REQ_AUTH: u32 = 11;
const USAGE_TICKET: u32 = 2;

const ADMINISTRATOR_RID: u32 = 500;
const DOMAIN_ADMINS_RID: u32 = 512;

/// `EncKrbPrivPart` (RFC 4120 §5.7.1) with `s-address` optional:
/// `rasn-kerberos` makes it mandatory, but Heimdal (macOS) treats it as
/// optional and may omit it.
#[derive(AsnType, Clone, Debug, Decode, Encode)]
#[rasn(tag(explicit(application, 28)))]
pub struct EncKrbPrivPart {
    #[rasn(tag(explicit(0)))]
    pub user_data: OctetString,
    #[rasn(tag(explicit(1)))]
    pub timestamp: Option<KerberosTime>,
    #[rasn(tag(explicit(2)))]
    pub usec: Option<Integer>,
    #[rasn(tag(explicit(3)))]
    pub seq_number: Option<u32>,
    #[rasn(tag(explicit(4)))]
    pub s_address: Option<HostAddress>,
    #[rasn(tag(explicit(5)))]
    pub r_address: Option<HostAddress>,
}

/// RFC 3244 §2 `ChgPwdData`, the user-data of a version 0xff80 request.
#[derive(AsnType, Clone, Debug, Decode, Encode)]
pub struct ChgPwdData {
    #[rasn(tag(explicit(0)))]
    pub newpasswd: OctetString,
    #[rasn(tag(explicit(1)))]
    pub targname: Option<PrincipalName>,
    #[rasn(tag(explicit(2)))]
    pub targrealm: Option<Realm>,
}

/// A refused or failed request: the result code and the text sent back.
struct Refusal {
    code: u16,
    text: String,
}

fn refuse(code: u16, text: impl Into<String>) -> Refusal {
    Refusal { code, text: text.into() }
}

/// What a verified AP-REQ establishes.
struct Authenticated {
    client: String,
    client_realm: String,
    initial: bool,
    ticket_session_key: Vec<u8>,
    ticket_enctype: Enctype,
    /// The key the KRB-PRIVs are sealed with: the Authenticator's subkey,
    /// else the ticket session key.
    priv_key: Vec<u8>,
    priv_enctype: Enctype,
    authenticator: Authenticator,
}

/// Handles one kpasswd request. `local` is the address the request
/// arrived on, used as the reply KRB-PRIV's `s-address`.
pub async fn handle(app: &AppState, request: &[u8], local: IpAddr) -> Vec<u8> {
    match handle_inner(app, request, local).await {
        Ok(reply) => reply,
        Err(r) => {
            tracing::info!(code = r.code, "kpasswd request refused before authentication: {}", r.text);
            error_reply(app, r.code, &r.text)
        }
    }
}

async fn handle_inner(app: &AppState, request: &[u8], local: IpAddr) -> Result<Vec<u8>, Refusal> {
    if request.len() < 6 {
        return Err(refuse(result::MALFORMED, "request shorter than its header"));
    }
    let msg_len = u16::from_be_bytes([request[0], request[1]]) as usize;
    let version = u16::from_be_bytes([request[2], request[3]]);
    let ap_req_len = u16::from_be_bytes([request[4], request[5]]) as usize;
    if msg_len != request.len() || 6 + ap_req_len > request.len() {
        return Err(refuse(result::MALFORMED, "length fields don't match the request"));
    }
    if version != VERSION_CHANGE && version != VERSION_SET {
        return Err(refuse(result::BAD_VERSION, format!("unsupported protocol version 0x{version:04x}")));
    }
    let ap_req: ApReq = rasn::der::decode(&request[6..6 + ap_req_len]).map_err(|e| refuse(result::MALFORMED, format!("malformed AP-REQ: {e}")))?;
    let priv_msg: KrbPriv = rasn::der::decode(&request[6 + ap_req_len..]).map_err(|e| refuse(result::MALFORMED, format!("malformed KRB-PRIV: {e}")))?;

    let auth = verify_ap_req(app, &ap_req).await?;

    // From here the client is authenticated: every outcome is a sealed
    // reply carrying a result code.
    let seq = server_seq(app);
    let outcome = match open_priv(app, &auth, &priv_msg) {
        Ok(user_data) => change(app, &auth, version, &user_data).await,
        Err(r) => Err(r),
    };
    let (code, text) = match outcome {
        Ok(target) => {
            tracing::info!(requester = %format!("{}@{}", auth.client, auth.client_realm), %target, "kpasswd: password set");
            (result::SUCCESS, "Password changed".to_string())
        }
        Err(r) => {
            tracing::warn!(requester = %format!("{}@{}", auth.client, auth.client_realm), code = r.code, "kpasswd: refused: {}", r.text);
            (r.code, r.text)
        }
    };
    sealed_reply(app, &auth, seq, local, code, &text).map_err(|e| refuse(result::HARDERROR, e))
}

/// Decrypts and checks the `kadmin/changepw` ticket and its Authenticator.
async fn verify_ap_req(app: &AppState, ap_req: &ApReq) -> Result<Authenticated, Refusal> {
    if !crate::is_changepw(&ap_req.ticket.sname) || !realm_to_string(&ap_req.ticket.realm).eq_ignore_ascii_case(&app.realm) {
        return Err(refuse(
            result::AUTHERROR,
            format!("ticket is for {}@{}, not kadmin/changepw@{}", principal_name_to_string(&ap_req.ticket.sname), realm_to_string(&ap_req.ticket.realm), app.realm),
        ));
    }
    let ticket_enctype = Enctype::try_from(ap_req.ticket.enc_part.etype).map_err(|_| refuse(result::AUTHERROR, "unsupported ticket enctype"))?;
    let krbtgt = format!("krbtgt/{0}@{0}", app.realm);
    let krbtgt_entry = {
        let mut store = app.store.lock().await;
        let dn = match store.lookup_by_index(&app.base_dn, crate::principal::ATTR_PRINCIPAL_NAME, &krbtgt).await {
            Ok(dns) if dns.len() == 1 => dns.into_iter().next().unwrap(),
            _ => return Err(refuse(result::HARDERROR, "krbtgt principal not provisioned")),
        };
        store.get_entry(&dn).await.ok().flatten().ok_or_else(|| refuse(result::HARDERROR, "krbtgt entry missing"))?
    };
    let key = crate::principal::key_for_enctype(&krbtgt_entry, ticket_enctype).map_err(|_| refuse(result::AUTHERROR, "no krbtgt key for the ticket's enctype"))?;
    let ticket_bytes = kerberos::decrypt(&app.fips, ticket_enctype, &key.key, USAGE_TICKET, &ap_req.ticket.enc_part.cipher)
        .map_err(|_| refuse(result::AUTHERROR, "ticket does not decrypt"))?;
    let ticket: EncTicketPart = rasn::der::decode(&ticket_bytes).map_err(|e| refuse(result::AUTHERROR, format!("malformed ticket: {e}")))?;
    let (now, _) = crate::time::now();
    if crate::time::diff_seconds(&ticket.end_time, &now) > 0 {
        return Err(refuse(result::AUTHERROR, "ticket expired"));
    }

    let ticket_session_key = ticket.key.value.to_vec();
    let auth_bytes = kerberos::decrypt(&app.fips, ticket_enctype, &ticket_session_key, USAGE_AP_REQ_AUTH, &ap_req.authenticator.cipher)
        .map_err(|_| refuse(result::AUTHERROR, "authenticator does not decrypt"))?;
    let authenticator: Authenticator = rasn::der::decode(&auth_bytes).map_err(|e| refuse(result::AUTHERROR, format!("malformed authenticator: {e}")))?;
    if authenticator.cname != ticket.cname || authenticator.crealm != ticket.crealm {
        return Err(refuse(result::AUTHERROR, "authenticator does not match the ticket"));
    }
    if crate::time::diff_seconds(&authenticator.ctime, &now).abs() > CLOCK_SKEW_SECS {
        return Err(refuse(result::AUTHERROR, "clock skew too great"));
    }

    let (priv_key, priv_enctype) = match &authenticator.subkey {
        Some(sk) => (sk.value.to_vec(), Enctype::try_from(sk.r#type).map_err(|_| refuse(result::AUTHERROR, "unsupported subkey enctype"))?),
        None => (ticket_session_key.clone(), ticket_enctype),
    };
    Ok(Authenticated {
        client: principal_name_to_string(&ticket.cname),
        client_realm: realm_to_string(&ticket.crealm),
        initial: crate::has_flag(&ticket.flags, crate::flag::INITIAL),
        ticket_session_key,
        ticket_enctype,
        priv_key,
        priv_enctype,
        authenticator,
    })
}

/// The request KRB-PRIV's user-data.
fn open_priv(app: &AppState, auth: &Authenticated, msg: &KrbPriv) -> Result<Vec<u8>, Refusal> {
    let enctype = Enctype::try_from(msg.enc_part.etype).unwrap_or(auth.priv_enctype);
    let plain = kerberos::decrypt(&app.fips, enctype, &auth.priv_key, USAGE_KRB_PRIV, &msg.enc_part.cipher)
        .map_err(|_| refuse(result::AUTHERROR, "KRB-PRIV does not decrypt under the authenticator's key"))?;
    let part: EncKrbPrivPart = rasn::der::decode(&plain).map_err(|e| refuse(result::MALFORMED, format!("malformed KRB-PRIV body: {e}")))?;
    Ok(part.user_data.to_vec())
}

/// Applies the request; returns the target principal on success.
async fn change(app: &AppState, auth: &Authenticated, version: u16, user_data: &[u8]) -> Result<String, Refusal> {
    let (new_password, target_name, target_realm) = if version == VERSION_CHANGE {
        (user_data.to_vec(), None, None)
    } else {
        let d: ChgPwdData = rasn::der::decode(user_data).map_err(|e| refuse(result::MALFORMED, format!("malformed ChgPwdData: {e}")))?;
        (d.newpasswd.to_vec(), d.targname.map(|n| principal_name_to_string(&n)), d.targrealm.map(|r| realm_to_string(&r)))
    };
    let target_realm = target_realm.unwrap_or_else(|| auth.client_realm.clone());
    if !target_realm.eq_ignore_ascii_case(&app.realm) {
        return Err(refuse(result::HARDERROR, format!("target realm {target_realm} is not served here")));
    }
    let target_name = target_name.unwrap_or_else(|| auth.client.clone());
    let is_self = target_name.eq_ignore_ascii_case(&auth.client) && auth.client_realm.eq_ignore_ascii_case(&app.realm);
    let target = format!("{target_name}@{}", app.realm);

    let mut store = app.store.lock().await;
    if is_self {
        if !auth.initial {
            return Err(refuse(result::INITIAL_FLAG_NEEDED, "changing your own password needs a ticket from a fresh password (INITIAL)"));
        }
    } else if !is_domain_admin(app, &mut store, &format!("{}@{}", auth.client, auth.client_realm)).await {
        return Err(refuse(result::ACCESSDENIED, format!("{}@{} may not set the password of {target}", auth.client, auth.client_realm)));
    }

    let dn = find_target(app, &mut store, &target_name, &target).await?;
    let mut entry = store.get_entry(&dn).await.map_err(|e| refuse(result::HARDERROR, e.to_string()))?.ok_or_else(|| refuse(result::HARDERROR, format!("{dn} vanished")))?;
    // An entry created over LDAP has no principal name yet: it becomes
    // the name the client asked for (`<sAMAccountName>@REALM`).
    let principal = crate::principal::principal_name(&entry).map(str::to_string).unwrap_or_else(|_| target.clone());
    if new_password.len() < 8 {
        return Err(refuse(result::SOFTERROR, "password must be at least 8 characters"));
    }
    crate::principal::set_password(&app.fips, &mut entry, &principal, &new_password).map_err(|e| refuse(result::SOFTERROR, e.to_string()))?;
    store.put_entry(&dn, &entry, &app.index_spec).await.map_err(|e| refuse(result::HARDERROR, e.to_string()))?;
    Ok(principal)
}

/// The target's entry: by `krbprincipalname`, else by `sAMAccountName`
/// (a computer account `dsconfigad` created over LDAP has no Kerberos
/// name until this first password is set).
async fn find_target(app: &AppState, store: &mut iron_store::store::Store, name: &str, principal: &str) -> Result<Dn, Refusal> {
    for (attr, value) in [(crate::principal::ATTR_PRINCIPAL_NAME, principal), ("samaccountname", name)] {
        match store.lookup_by_index(&app.base_dn, attr, value).await {
            Ok(dns) if dns.len() == 1 => return Ok(dns.into_iter().next().unwrap()),
            Ok(dns) if dns.len() > 1 => return Err(refuse(result::HARDERROR, format!("{} entries are named {value}", dns.len()))),
            Ok(_) => {}
            Err(e) => return Err(refuse(result::HARDERROR, e.to_string())),
        }
    }
    Err(refuse(result::HARDERROR, format!("no such principal {principal}")))
}

/// RID 500, or a member of the group with RID 512 (Domain Admins).
async fn is_domain_admin(app: &AppState, store: &mut iron_store::store::Store, principal: &str) -> bool {
    let Ok(dns) = store.lookup_by_index(&app.base_dn, crate::principal::ATTR_PRINCIPAL_NAME, principal).await else { return false };
    let [dn] = dns.as_slice() else { return false };
    let Ok(Some(entry)) = store.get_entry(dn).await else { return false };
    if rid(&entry) == Some(ADMINISTRATOR_RID) {
        return true;
    }
    crate::pac::group_rids(store, &app.base_dn, dn).await.contains(&DOMAIN_ADMINS_RID)
}

fn rid(entry: &Entry) -> Option<u32> {
    let sid = Sid::decode(&decode_binary_attr(entry.get(OBJECT_SID_ATTR)?.first()?))?;
    sid.sub_authorities().last().copied()
}

/// A fresh sequence number for the reply (AP-REP and KRB-PRIV carry the
/// same one; clients check the KRB-PRIV's against the AP-REP's).
fn server_seq(app: &AppState) -> u32 {
    kerberos::random_bytes(&app.fips, 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) & 0x3fff_ffff).unwrap_or(1)
}

fn host_address(ip: IpAddr) -> HostAddress {
    match ip {
        IpAddr::V4(v4) => HostAddress { addr_type: 2, address: v4.octets().to_vec().into() },
        IpAddr::V6(v6) => HostAddress { addr_type: 24, address: v6.octets().to_vec().into() },
    }
}

fn result_data(code: u16, text: &str) -> Vec<u8> {
    let mut d = code.to_be_bytes().to_vec();
    d.extend_from_slice(text.as_bytes());
    d
}

fn frame(ap_rep: &[u8], body: &[u8]) -> Vec<u8> {
    let len = 6 + ap_rep.len() + body.len();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&VERSION_CHANGE.to_be_bytes());
    out.extend_from_slice(&(ap_rep.len() as u16).to_be_bytes());
    out.extend_from_slice(ap_rep);
    out.extend_from_slice(body);
    out
}

/// AP-REP (ticket session key, echoing the client's ctime/cusec) plus a
/// KRB-PRIV under the authenticator's key carrying the result.
fn sealed_reply(app: &AppState, auth: &Authenticated, seq: u32, local: IpAddr, code: u16, text: &str) -> Result<Vec<u8>, String> {
    let rep_part = EncApRepPart { ctime: auth.authenticator.ctime.clone(), cusec: auth.authenticator.cusec.clone(), subkey: None, seq_number: Some(seq) };
    let rep_bytes = rasn::der::encode(&rep_part).map_err(|e| e.to_string())?;
    let rep_cipher = kerberos::encrypt(&app.fips, auth.ticket_enctype, &auth.ticket_session_key, USAGE_AP_REP, &rep_bytes).map_err(|e| e.to_string())?;
    let ap_rep = ApRep { pvno: 5.into(), msg_type: 15.into(), enc_part: EncryptedData { etype: auth.ticket_enctype.etype_number(), kvno: None, cipher: rep_cipher.into() } };
    let ap_rep_bytes = rasn::der::encode(&ap_rep).map_err(|e| e.to_string())?;

    let (timestamp, usec) = crate::time::now();
    let priv_part = EncKrbPrivPart {
        user_data: result_data(code, text).into(),
        timestamp: Some(timestamp),
        usec: Some(usec),
        seq_number: Some(seq),
        s_address: Some(host_address(local)),
        r_address: None,
    };
    let priv_bytes = rasn::der::encode(&priv_part).map_err(|e| e.to_string())?;
    let priv_cipher = kerberos::encrypt(&app.fips, auth.priv_enctype, &auth.priv_key, USAGE_KRB_PRIV, &priv_bytes).map_err(|e| e.to_string())?;
    let priv_msg = KrbPriv { pvno: 5.into(), msg_type: 21.into(), enc_part: EncryptedData { etype: auth.priv_enctype.etype_number(), kvno: None, cipher: priv_cipher.into() } };
    let priv_msg_bytes = rasn::der::encode(&priv_msg).map_err(|e| e.to_string())?;
    Ok(frame(&ap_rep_bytes, &priv_msg_bytes))
}

/// A refusal before the client is authenticated: no AP-REP, a KRB-ERROR
/// whose e-data is the result code and text (RFC 3244 §2).
fn error_reply(app: &AppState, code: u16, text: &str) -> Vec<u8> {
    let err = krberror::build(krberror::KRB_ERR_GENERIC, &app.realm, crate::string_to_principal_name("kadmin/changepw"), Some(text.to_string()), Some(result_data(code, text)));
    frame(&[], &rasn::der::encode(&err).unwrap_or_default())
}

/// Serves kpasswd over UDP until the socket errors.
pub async fn serve_udp(socket: tokio::net::UdpSocket, app: std::sync::Arc<AppState>) -> std::io::Result<()> {
    let socket = std::sync::Arc::new(socket);
    let bound = socket.local_addr()?.ip();
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let request = buf[..n].to_vec();
        let (app, socket) = (app.clone(), socket.clone());
        tokio::spawn(async move {
            let local = if bound.is_unspecified() { route_source(peer).unwrap_or(bound) } else { bound };
            let reply = handle(&app, &request, local).await;
            if let Err(e) = socket.send_to(&reply, peer).await {
                tracing::debug!(%peer, "kpasswd: failed to send UDP reply: {e}");
            }
        });
    }
}

/// The local address a reply to `peer` leaves from (a socket bound to
/// the wildcard address doesn't know): connect a throwaway UDP socket
/// and ask it. Sends nothing.
fn route_source(peer: SocketAddr) -> Option<IpAddr> {
    let any: SocketAddr = if peer.is_ipv4() { "0.0.0.0:0".parse().ok()? } else { "[::]:0".parse().ok()? };
    let s = std::net::UdpSocket::bind(any).ok()?;
    s.connect(peer).ok()?;
    Some(s.local_addr().ok()?.ip())
}

/// Serves kpasswd over TCP (4-byte length-prefixed, like the KDC's own
/// TCP transport) until the listener errors.
pub async fn serve_tcp(listener: tokio::net::TcpListener, app: std::sync::Arc<AppState>) -> std::io::Result<()> {
    loop {
        let (mut stream, peer) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            let local = stream.local_addr().map(|a| a.ip()).unwrap_or(IpAddr::from([0, 0, 0, 0]));
            loop {
                match crate::wire::read_tcp_message(&mut stream).await {
                    Ok(Some(request)) => {
                        let reply = handle(&app, &request, local).await;
                        if crate::wire::write_tcp_message(&mut stream, &reply).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        tracing::debug!(%peer, "kpasswd: TCP connection ended: {e}");
                        break;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_lays_out_length_version_and_ap_rep_length() {
        let f = frame(&[0xaa, 0xbb], &[0xcc]);
        assert_eq!(f, vec![0x00, 0x09, 0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn result_data_is_big_endian_code_then_text() {
        assert_eq!(result_data(result::ACCESSDENIED, "no"), vec![0x00, 0x05, b'n', b'o']);
    }

    #[test]
    fn priv_part_without_s_address_decodes() {
        let part = EncKrbPrivPart { user_data: b"pw".to_vec().into(), timestamp: None, usec: None, seq_number: Some(7), s_address: None, r_address: None };
        let bytes = rasn::der::encode(&part).unwrap();
        assert_eq!(bytes[0], 0x7c); // [APPLICATION 28], constructed
        let back: EncKrbPrivPart = rasn::der::decode(&bytes).unwrap();
        assert_eq!(back.user_data.as_ref(), b"pw");
        assert_eq!(back.seq_number, Some(7));
    }

    #[test]
    fn chgpwddata_roundtrips_with_and_without_a_target() {
        let d = ChgPwdData { newpasswd: b"NewPass123!".to_vec().into(), targname: Some(crate::string_to_principal_name("TESTMAC1$")), targrealm: Some(crate::string_to_gstring("IRON.G8.LO")) };
        let back: ChgPwdData = rasn::der::decode(&rasn::der::encode(&d).unwrap()).unwrap();
        assert_eq!(principal_name_to_string(back.targname.as_ref().unwrap()), "TESTMAC1$");
        let bare = ChgPwdData { newpasswd: b"x".to_vec().into(), targname: None, targrealm: None };
        let back: ChgPwdData = rasn::der::decode(&rasn::der::encode(&bare).unwrap()).unwrap();
        assert!(back.targname.is_none());
    }
}
