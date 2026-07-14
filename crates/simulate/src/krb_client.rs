//! A minimal Kerberos 5 client (#23): AS-REQ/AS-REP with PA-ENC-TIMESTAMP
//! preauth, TGS-REQ/TGS-REP -- mirroring `iron-kdc`'s server-side
//! `as_exchange`/`tgs_exchange` flow in reverse. Nothing in this
//! workspace previously spoke Kerberos as a *client*; every prior issue
//! (#5, #7, #8, #11, #16) verified against real `kinit`/`klist`/MIT
//! krb5 instead. This one exists so the simulation harness doesn't need
//! to shell out to system Kerberos tools to get a TGT/service ticket.
//!
//! Reuses `iron_kdc`'s wire framing (`wire::read_tcp_message`/
//! `write_tcp_message`) and string/time helpers directly rather than
//! duplicating them.

use iron_crypto::kerberos::{self, Enctype};
use iron_crypto::FipsContext;
use rasn_kerberos::{
    ApOptions, ApReq, AsRep, Authenticator, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, EncTicketPart, EncryptedData,
    EtypeInfo2Entry, KdcOptions, KdcReq, KdcReqBody, KrbError, PaData, PaEncTsEnc, PrincipalName, Ticket, TgsRep,
};
use tokio::net::TcpStream;

const PA_ENC_TIMESTAMP: i32 = 2;
const PA_ETYPE_INFO2: i32 = 19;
const PA_TGS_REQ: i32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum KrbClientError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("wire framing error: {0}")]
    Wire(#[from] iron_kdc::wire::WireError),
    #[error("crypto error: {0}")]
    Crypto(#[from] iron_crypto::Error),
    #[error("KDC returned an error: code {0}")]
    KdcError(i32),
    #[error("unrecognized or malformed KDC response")]
    Malformed,
    #[error("no usable etype/salt offered by the KDC")]
    NoUsableEtype,
}

/// A ticket plus the session key needed to use it (TGT or service ticket).
pub struct Credential {
    pub ticket: Ticket,
    pub session_key: Vec<u8>,
    pub enctype: Enctype,
    pub cname: PrincipalName,
    pub crealm: rasn_kerberos::Realm,
    pub auth_time_unix_secs: i64,
}

fn kerberos_time_to_unix(t: &rasn_kerberos::KerberosTime) -> i64 {
    t.0.timestamp()
}

async fn send_and_recv(addr: &str, msg: &[u8]) -> Result<Vec<u8>, KrbClientError> {
    let mut stream = TcpStream::connect(addr).await?;
    iron_kdc::wire::write_tcp_message(&mut stream, msg).await?;
    iron_kdc::wire::read_tcp_message(&mut stream).await?.ok_or(KrbClientError::Malformed)
}

/// Tag byte (low 5 bits of an APPLICATION-tagged DER value) for each
/// response type this client needs to distinguish, mirroring
/// `iron_kdc::wire::decode_request`'s same approach for requests.
fn decode_as_or_error(bytes: &[u8]) -> Result<Result<AsRep, KrbError>, KrbClientError> {
    let tag = bytes.first().ok_or(KrbClientError::Malformed)? & 0x1F;
    match tag {
        11 => Ok(Ok(rasn::der::decode(bytes).map_err(|_| KrbClientError::Malformed)?)),
        30 => Ok(Err(rasn::der::decode(bytes).map_err(|_| KrbClientError::Malformed)?)),
        _ => Err(KrbClientError::Malformed),
    }
}

fn decode_tgs_or_error(bytes: &[u8]) -> Result<Result<TgsRep, KrbError>, KrbClientError> {
    let tag = bytes.first().ok_or(KrbClientError::Malformed)? & 0x1F;
    match tag {
        13 => Ok(Ok(rasn::der::decode(bytes).map_err(|_| KrbClientError::Malformed)?)),
        30 => Ok(Err(rasn::der::decode(bytes).map_err(|_| KrbClientError::Malformed)?)),
        _ => Err(KrbClientError::Malformed),
    }
}

/// Performs a full AS-REQ/AS-REP exchange (including the round-trip
/// through `KDC_ERR_PREAUTH_REQUIRED` a real client always needs, since
/// this KDC -- like any RFC 4120-conformant one -- never accepts an
/// unauthenticated first request), returning the client's TGT.
pub async fn as_exchange(fips: &FipsContext, addr: &str, realm: &str, principal: &str, password: &[u8]) -> Result<Credential, KrbClientError> {
    let realm_g = iron_kdc::string_to_gstring(realm);
    let cname = iron_kdc::string_to_principal_name(principal);
    let sname = iron_kdc::krbtgt_principal_name(realm);

    let nonce: u32 = 0x1234_5678; // fixed, documented -- this client doesn't need cryptographic nonce unpredictability, only freshness-echo verification
    let req_body = KdcReqBody {
        kdc_options: KdcOptions::reserved(),
        cname: Some(cname.clone()),
        realm: realm_g.clone(),
        sname: Some(sname.clone()),
        from: None,
        till: iron_kdc::time::plus_seconds(10 * 3600),
        rtime: None,
        nonce,
        etype: vec![Enctype::Aes256CtsHmacSha384_192.etype_number(), Enctype::Aes256CtsHmacSha1_96.etype_number()],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let as_req_1 = rasn_kerberos::AsReq(KdcReq { pvno: 5.into(), msg_type: 10.into(), padata: None, req_body: req_body.clone() });
    let resp1 = send_and_recv(addr, &rasn::der::encode(&as_req_1).map_err(|_| KrbClientError::Malformed)?).await?;
    let err1 = match decode_as_or_error(&resp1)? {
        Ok(_) => return Err(KrbClientError::Malformed), // a conformant KDC never issues a TGT without preauth
        Err(e) => e,
    };
    if err1.error_code != 25 {
        // KDC_ERR_PREAUTH_REQUIRED
        return Err(KrbClientError::KdcError(err1.error_code));
    }
    let e_data = err1.e_data.ok_or(KrbClientError::Malformed)?;
    let method_data: Vec<PaData> = rasn::der::decode(&e_data).map_err(|_| KrbClientError::Malformed)?;
    let etype_info2_pa = method_data.iter().find(|p| p.r#type == PA_ETYPE_INFO2).ok_or(KrbClientError::Malformed)?;
    let etype_info2: Vec<EtypeInfo2Entry> = rasn::der::decode(&etype_info2_pa.value).map_err(|_| KrbClientError::Malformed)?;

    let Some(chosen) = etype_info2.iter().find_map(|e| Enctype::try_from(e.etype).ok().map(|enc| (enc, e.salt.clone()))) else {
        return Err(KrbClientError::NoUsableEtype);
    };
    let (enctype, salt) = chosen;
    let salt_bytes = salt.map(|s| s.as_bytes().to_vec()).unwrap_or_default();
    let key = kerberos::string_to_key(fips, enctype, password, &salt_bytes, None)?;

    let (client_now, client_usec) = iron_kdc::time::now();
    let pa_enc_ts_enc = PaEncTsEnc { patimestamp: client_now, pausec: Some(client_usec) };
    let pa_enc_ts_bytes = rasn::der::encode(&pa_enc_ts_enc).map_err(|_| KrbClientError::Malformed)?;
    let cipher = kerberos::encrypt(fips, enctype, &key, 1, &pa_enc_ts_bytes)?;
    let pa_enc_ts = PaData {
        r#type: PA_ENC_TIMESTAMP,
        value: rasn::der::encode(&EncryptedData { etype: enctype.etype_number(), kvno: None, cipher: cipher.into() })
            .map_err(|_| KrbClientError::Malformed)?
            .into(),
    };

    let as_req_2 = rasn_kerberos::AsReq(KdcReq { pvno: 5.into(), msg_type: 10.into(), padata: Some(vec![pa_enc_ts]), req_body });
    let resp2 = send_and_recv(addr, &rasn::der::encode(&as_req_2).map_err(|_| KrbClientError::Malformed)?).await?;
    let as_rep = match decode_as_or_error(&resp2)? {
        Ok(rep) => rep,
        Err(e) => return Err(KrbClientError::KdcError(e.error_code)),
    };

    let Ok(reply_etype) = Enctype::try_from(as_rep.0.enc_part.etype) else { return Err(KrbClientError::Malformed) };
    let plain = kerberos::decrypt(fips, reply_etype, &key, 3, &as_rep.0.enc_part.cipher)?;
    let enc_part: EncAsRepPart = rasn::der::decode(&plain).map_err(|_| KrbClientError::Malformed)?;
    let EncKdcRepPart { key: session_key, nonce: reply_nonce, auth_time, .. } = enc_part.0;
    if reply_nonce != nonce {
        return Err(KrbClientError::Malformed);
    }
    let Ok(session_enctype) = Enctype::try_from(session_key.r#type) else { return Err(KrbClientError::Malformed) };

    Ok(Credential {
        ticket: as_rep.0.ticket,
        session_key: session_key.value.to_vec(),
        enctype: session_enctype,
        cname: as_rep.0.cname,
        crealm: as_rep.0.crealm,
        auth_time_unix_secs: kerberos_time_to_unix(&auth_time),
    })
}

/// Performs a TGS-REQ/TGS-REP exchange, exchanging `tgt` for a service
/// ticket to `service_principal`.
pub async fn tgs_exchange(fips: &FipsContext, addr: &str, realm: &str, tgt: &Credential, service_principal: &str) -> Result<Credential, KrbClientError> {
    let realm_g = iron_kdc::string_to_gstring(realm);
    let sname = iron_kdc::string_to_principal_name(service_principal);

    let (auth_now, auth_usec) = iron_kdc::time::now();
    let authenticator = Authenticator {
        authenticator_vno: 5.into(),
        crealm: tgt.crealm.clone(),
        cname: tgt.cname.clone(),
        cksum: None,
        ctime: auth_now,
        cusec: auth_usec,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let auth_bytes = rasn::der::encode(&authenticator).map_err(|_| KrbClientError::Malformed)?;
    let auth_cipher = kerberos::encrypt(fips, tgt.enctype, &tgt.session_key, 7, &auth_bytes)?;
    let ap_req = ApReq {
        pvno: 5.into(),
        msg_type: 14.into(),
        ap_options: ApOptions::reserved(),
        ticket: tgt.ticket.clone(),
        authenticator: EncryptedData { etype: tgt.enctype.etype_number(), kvno: None, cipher: auth_cipher.into() },
    };
    let pa_tgs_req = PaData { r#type: PA_TGS_REQ, value: rasn::der::encode(&ap_req).map_err(|_| KrbClientError::Malformed)?.into() };

    let nonce: u32 = 0x2468_1357;
    let req_body = KdcReqBody {
        kdc_options: KdcOptions::reserved(),
        cname: None,
        realm: realm_g,
        sname: Some(sname),
        from: None,
        till: iron_kdc::time::plus_seconds(10 * 3600),
        rtime: None,
        nonce,
        etype: vec![tgt.enctype.etype_number()],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let tgs_req = rasn_kerberos::TgsReq(KdcReq { pvno: 5.into(), msg_type: 12.into(), padata: Some(vec![pa_tgs_req]), req_body });
    let resp = send_and_recv(addr, &rasn::der::encode(&tgs_req).map_err(|_| KrbClientError::Malformed)?).await?;
    let tgs_rep = match decode_tgs_or_error(&resp)? {
        Ok(rep) => rep,
        Err(e) => return Err(KrbClientError::KdcError(e.error_code)),
    };

    let plain = kerberos::decrypt(fips, tgt.enctype, &tgt.session_key, 8, &tgs_rep.0.enc_part.cipher)?;
    let enc_part: EncTgsRepPart = rasn::der::decode(&plain).map_err(|_| KrbClientError::Malformed)?;
    let EncKdcRepPart { key: session_key, nonce: reply_nonce, auth_time, .. } = enc_part.0;
    if reply_nonce != nonce {
        return Err(KrbClientError::Malformed);
    }
    let Ok(session_enctype) = Enctype::try_from(session_key.r#type) else { return Err(KrbClientError::Malformed) };

    Ok(Credential {
        ticket: tgs_rep.0.ticket,
        session_key: session_key.value.to_vec(),
        enctype: session_enctype,
        cname: tgs_rep.0.cname,
        crealm: tgs_rep.0.crealm,
        auth_time_unix_secs: kerberos_time_to_unix(&auth_time),
    })
}

/// Decrypts a service ticket with its (independently known) server key
/// -- only possible in this simulation harness because it provisions
/// the "service" principal's key itself (a real client never has this
/// visibility; see module docs). Used to confirm the ticket carries the
/// expected `AD-WIN2K-PAC` authorization-data element.
pub fn decrypt_ticket(fips: &FipsContext, ticket: &Ticket, server_key: &[u8], server_enctype: Enctype) -> Result<EncTicketPart, KrbClientError> {
    let plain = kerberos::decrypt(fips, server_enctype, server_key, 2, &ticket.enc_part.cipher)?;
    rasn::der::decode(&plain).map_err(|_| KrbClientError::Malformed)
}

/// Whether `enc_ticket_part`'s `authorization_data` contains a well-
/// formed `AD-WIN2K-PAC` (AD-IF-RELEVANT wrapping AD-WIN2K-PAC, #18) and,
/// if so, the raw PAC bytes.
pub fn extract_pac(enc_ticket_part: &EncTicketPart) -> Option<Vec<u8>> {
    let ad = enc_ticket_part.authorization_data.as_ref()?;
    let if_relevant = ad.iter().find(|e| e.r#type == 1)?;
    let inner: Vec<rasn_kerberos::AuthorizationDataValue> = rasn::der::decode(&if_relevant.data).ok()?;
    let pac_entry = inner.iter().find(|e| e.r#type == 128)?;
    Some(pac_entry.data.to_vec())
}

/// Reads a PAC's buffer types (`PACTYPE`'s `cBuffers` + each entry's
/// `ulType`) without decoding `KERB_VALIDATION_INFO` itself -- #18
/// already independently verified that structure byte-for-byte; this
/// just confirms the *expected buffers are present* in a PAC produced
/// through a real join+login flow, not a standalone `pac::generate` call.
pub fn pac_buffer_types(pac_bytes: &[u8]) -> Option<Vec<u32>> {
    if pac_bytes.len() < 8 {
        return None;
    }
    let c_buffers = u32::from_le_bytes(pac_bytes[0..4].try_into().ok()?) as usize;
    let mut types = Vec::with_capacity(c_buffers);
    for i in 0..c_buffers {
        let off = 8 + i * 16;
        if pac_bytes.len() < off + 4 {
            return None;
        }
        types.push(u32::from_le_bytes(pac_bytes[off..off + 4].try_into().ok()?));
    }
    Some(types)
}
