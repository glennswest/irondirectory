//! TGS-REQ/TGS-REP (RFC 4120 §3.3, §5.4) -- exchanges a TGT for a service
//! ticket. The client authenticates itself via an `AP-REQ` (built from
//! the TGT) carried in the request's `PA-TGS-REQ` padata, rather than a
//! long-term key -- that's the whole point of the ticket-granting step.
//!
//! Simplifications, documented rather than silently absent: no replay
//! cache (a captured-and-replayed Authenticator within its clock-skew
//! window would be accepted twice), no renewal/forwarding/user-to-user,
//! no `enc_authorization_data`. These match a first vertical slice's
//! scope, not a production-hardened KDC.

use iron_crypto::kerberos::{self, Enctype};
use rasn_kerberos::{
    ApReq, Authenticator, EncKdcRepPart, EncTgsRepPart, EncTicketPart, EncryptedData, EncryptionKey, KdcReq, KdcRep,
    Ticket, TicketFlags, TgsRep, TransitedEncoding,
};

use crate::krberror::{self, KDC_ERR_S_PRINCIPAL_UNKNOWN, KRB_AP_ERR_BADMATCH, KRB_AP_ERR_BAD_INTEGRITY, KRB_AP_ERR_SKEW, KRB_AP_ERR_TKT_EXPIRED};
use crate::wire::KdcResponse;
use crate::{krbtgt_principal_name, principal_name_to_string, AppState, TICKET_LIFETIME_SECS, CLOCK_SKEW_SECS};

const PA_TGS_REQ: i32 = 1;

pub async fn handle(app: &AppState, req: &KdcReq) -> KdcResponse {
    let realm = &req.req_body.realm;
    let realm_str = crate::realm_to_string(realm);
    let kdc_sname = krbtgt_principal_name(&realm_str);

    let Some(padata) = &req.padata else {
        return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some("TGS-REQ missing padata".into()), None).into();
    };
    let Some(pa_tgs) = padata.iter().find(|p| p.r#type == PA_TGS_REQ) else {
        return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some("TGS-REQ missing PA-TGS-REQ".into()), None).into();
    };
    let ap_req: ApReq = match rasn::der::decode(&pa_tgs.value) {
        Ok(v) => v,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(format!("malformed AP-REQ: {e}")), None).into(),
    };

    // Decrypt the presented ticket under ITS OWN issuer's key -- looked
    // up from the ticket's own sname/realm, not assumed to always be our
    // own realm's plain krbtgt. This is what makes cross-realm referral
    // chaining (#6, D8) structurally correct: a same-realm TGT's issuer
    // is "krbtgt/OURS@OURS" either way, but a cross-realm referral
    // ticket's issuer is "krbtgt/THEIRS@OURS" -- the inter-realm key we
    // share with the other realm, stored as an ordinary principal here
    // under that name (via iron-kdc-ctl, same mechanism as any other
    // principal). Model-correct but not live-tested beyond one realm
    // (D10): there's no second realm/partition deployed yet to chain
    // against.
    let issuer_principal = format!(
        "{}@{}",
        principal_name_to_string(&ap_req.ticket.sname),
        crate::realm_to_string(&ap_req.ticket.realm)
    );
    let mut store = app.store.lock().await;
    let issuer_dn = match store.lookup_by_index(&app.base_dn, crate::principal::ATTR_PRINCIPAL_NAME, &issuer_principal).await {
        Ok(dns) if dns.len() == 1 => dns.into_iter().next().unwrap(),
        _ => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(format!("no key for ticket issuer {issuer_principal}")), None).into(),
    };
    let issuer_entry = match store.get_entry(&issuer_dn).await {
        Ok(Some(e)) => e,
        _ => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some("ticket issuer principal entry missing".into()), None).into(),
    };
    let issuer_keys = match crate::principal::keys(&issuer_entry) {
        Ok(k) => k,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };
    let Ok(tkt_enctype) = Enctype::try_from(ap_req.ticket.enc_part.etype) else {
        return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some("unsupported ticket etype".into()), None).into();
    };
    let Some(issuer_key) = issuer_keys.iter().find(|k| k.enctype == tkt_enctype) else {
        return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some("ticket issuer has no matching key for this ticket's etype".into()), None).into();
    };
    let enc_ticket_bytes = match kerberos::decrypt(&app.fips, tkt_enctype, &issuer_key.key, 2, &ap_req.ticket.enc_part.cipher) {
        Ok(b) => b,
        Err(_) => return krberror::build(KRB_AP_ERR_BAD_INTEGRITY, &realm_str, kdc_sname, Some("failed to decrypt ticket".into()), None).into(),
    };
    let tgt: EncTicketPart = match rasn::der::decode(&enc_ticket_bytes) {
        Ok(v) => v,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(format!("malformed EncTicketPart: {e}")), None).into(),
    };

    let (server_now, _) = crate::time::now();
    if crate::time::diff_seconds(&tgt.end_time, &server_now) > 0 {
        return krberror::build(KRB_AP_ERR_TKT_EXPIRED, &realm_str, kdc_sname, Some("ticket expired".into()), None).into();
    }

    // Verify the Authenticator (proves the client holds the TGT's
    // session key -- decryption succeeding at all is most of the proof).
    let session_key = tgt.key.value.clone();
    let auth_bytes = match kerberos::decrypt(&app.fips, tkt_enctype, &session_key, 7, &ap_req.authenticator.cipher) {
        Ok(b) => b,
        Err(_) => return krberror::build(KRB_AP_ERR_BAD_INTEGRITY, &realm_str, kdc_sname, Some("failed to decrypt authenticator".into()), None).into(),
    };
    let authenticator: Authenticator = match rasn::der::decode(&auth_bytes) {
        Ok(v) => v,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(format!("malformed Authenticator: {e}")), None).into(),
    };
    if authenticator.crealm != tgt.crealm || authenticator.cname != tgt.cname {
        return krberror::build(KRB_AP_ERR_BADMATCH, &realm_str, kdc_sname, Some("authenticator does not match ticket".into()), None).into();
    }
    if crate::time::diff_seconds(&authenticator.ctime, &server_now).abs() > CLOCK_SKEW_SECS {
        return krberror::build(KRB_AP_ERR_SKEW, &realm_str, kdc_sname, Some("clock skew too great".into()), None).into();
    }

    // Look up the requested service principal.
    let Some(sname) = &req.req_body.sname else {
        return krberror::build(KDC_ERR_S_PRINCIPAL_UNKNOWN, &realm_str, kdc_sname, Some("no server name in request".into()), None).into();
    };
    let service_principal = format!("{}@{}", principal_name_to_string(sname), crate::realm_to_string(realm));
    let service_dn = match store.lookup_by_index(&app.base_dn, crate::principal::ATTR_PRINCIPAL_NAME, &service_principal).await {
        Ok(dns) if dns.len() == 1 => dns.into_iter().next().unwrap(),
        _ => return krberror::build(KDC_ERR_S_PRINCIPAL_UNKNOWN, &realm_str, kdc_sname, Some(format!("no such principal {service_principal}")), None).into(),
    };
    let service_entry = match store.get_entry(&service_dn).await {
        Ok(Some(e)) => e,
        _ => return krberror::build(KDC_ERR_S_PRINCIPAL_UNKNOWN, &realm_str, kdc_sname, Some(format!("no such principal {service_principal}")), None).into(),
    };
    drop(store);
    let service_keys = match crate::principal::keys(&service_entry) {
        Ok(k) => k,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };
    // Prefer an etype the client also asked for, matching the AS
    // exchange's negotiation approach; fall back to the service's own
    // preferred key.
    let Some(service_key) = service_keys
        .iter()
        .find(|k| req.req_body.etype.contains(&k.enctype.etype_number()))
        .or_else(|| service_keys.first())
    else {
        return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some("service principal has no keys".into()), None).into();
    };

    let new_session_key_bytes = match kerberos::random_bytes(&app.fips, service_key.enctype.key_len()) {
        Ok(k) => k,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };
    let new_session_key = EncryptionKey { r#type: service_key.enctype.etype_number(), value: new_session_key_bytes.clone().into() };

    let (auth_time, _) = crate::time::now();
    let end_time = crate::time::plus_seconds(TICKET_LIFETIME_SECS.min(crate::time::diff_seconds(&auth_time, &tgt.end_time)));
    let flags = TicketFlags::reserved(); // no INITIAL flag on a service ticket

    let enc_ticket_part = EncTicketPart {
        flags: flags.clone(),
        key: new_session_key.clone(),
        crealm: tgt.crealm.clone(),
        cname: tgt.cname.clone(),
        transited: TransitedEncoding { r#type: 0, contents: rasn::types::OctetString::from(Vec::new()) },
        auth_time: tgt.auth_time.clone(),
        start_time: None,
        end_time: end_time.clone(),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let enc_ticket_bytes = match rasn::der::encode(&enc_ticket_part) {
        Ok(b) => b,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };
    let ticket_cipher = match kerberos::encrypt(&app.fips, service_key.enctype, &service_key.key, 2, &enc_ticket_bytes) {
        Ok(c) => c,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };
    let ticket = Ticket {
        tkt_vno: 5.into(),
        realm: realm.clone(),
        sname: sname.clone(),
        enc_part: EncryptedData { etype: service_key.enctype.etype_number(), kvno: Some(service_key.kvno), cipher: ticket_cipher.into() },
    };

    let enc_kdc_rep_part = EncKdcRepPart {
        key: new_session_key,
        last_req: Vec::new(),
        nonce: req.req_body.nonce,
        key_expiration: None,
        flags,
        auth_time: tgt.auth_time.clone(),
        start_time: None,
        end_time,
        renew_till: None,
        srealm: realm.clone(),
        sname: sname.clone(),
        caddr: None,
        encrypted_pa_data: None,
    };
    let enc_tgs_rep_bytes = match rasn::der::encode(&EncTgsRepPart(enc_kdc_rep_part)) {
        Ok(b) => b,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname.clone(), Some(e.to_string()), None).into(),
    };
    // Key usage 8: encrypted with the TGS session key (from the TGT),
    // not usage 9 (which is for when the client supplied a subkey in
    // the Authenticator -- not supported in this pass).
    let enc_part_cipher = match kerberos::encrypt(&app.fips, tkt_enctype, &session_key, 8, &enc_tgs_rep_bytes) {
        Ok(c) => c,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };

    let tgs_rep = TgsRep(KdcRep {
        pvno: 5.into(),
        msg_type: 13.into(),
        padata: None,
        crealm: tgt.crealm,
        cname: tgt.cname,
        ticket,
        enc_part: EncryptedData { etype: tkt_enctype.etype_number(), kvno: None, cipher: enc_part_cipher.into() },
    });
    KdcResponse::TgsRep(tgs_rep)
}

