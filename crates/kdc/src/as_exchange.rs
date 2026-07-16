//! AS-REQ/AS-REP (RFC 4120 §3.1, §5.4) with PA-ENC-TIMESTAMP pre-auth
//! (§5.2.7.2). Issues a TGT (a `Ticket` for `krbtgt/REALM`) once the
//! client proves knowledge of its long-term key.

use iron_crypto::kerberos::{self, Enctype};
use rasn::types::{GeneralString, OctetString};
use rasn_kerberos::{
    AsRep, EncAsRepPart, EncKdcRepPart, EncTicketPart, EncryptedData, EncryptionKey, EtypeInfo2Entry, KdcReq, KdcRep,
    PaData, PaEncTsEnc, Ticket, TicketFlags, TransitedEncoding,
};

use crate::krberror::{self, KDC_ERR_C_PRINCIPAL_UNKNOWN, KDC_ERR_ETYPE_NOSUPP, KDC_ERR_PREAUTH_FAILED, KDC_ERR_PREAUTH_REQUIRED, KRB_AP_ERR_SKEW};
use crate::wire::KdcResponse;
use crate::{krbtgt_principal_name, principal_name_to_string, AppState, TICKET_LIFETIME_SECS, CLOCK_SKEW_SECS};

const PA_ENC_TIMESTAMP: i32 = 2;
const PA_ETYPE_INFO2: i32 = 19;

pub async fn handle(app: &AppState, req: &KdcReq) -> KdcResponse {
    let realm = &req.req_body.realm;
    let realm_str = crate::realm_to_string(realm);
    let kdc_sname = krbtgt_principal_name(&realm_str);

    let Some(cname) = &req.req_body.cname else {
        return krberror::build(KDC_ERR_C_PRINCIPAL_UNKNOWN, &realm_str, kdc_sname, Some("no client name in request".into()), None).into();
    };
    let client_principal = format!("{}@{}", principal_name_to_string(cname), crate::realm_to_string(realm));

    let mut store = app.store.lock().await;
    let client_dn = match store.lookup_by_index(&app.base_dn, crate::principal::ATTR_PRINCIPAL_NAME, &client_principal).await {
        Ok(dns) if dns.len() == 1 => dns.into_iter().next().unwrap(),
        Ok(_) => return krberror::build(KDC_ERR_C_PRINCIPAL_UNKNOWN, &realm_str, kdc_sname, Some(format!("no such principal {client_principal}")), None).into(),
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };
    let client_entry = match store.get_entry(&client_dn).await {
        Ok(Some(e)) => e,
        Ok(None) => return krberror::build(KDC_ERR_C_PRINCIPAL_UNKNOWN, &realm_str, kdc_sname, Some(format!("no such principal {client_principal}")), None).into(),
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };
    let client_keys = match crate::principal::keys(&client_entry) {
        Ok(k) => k,
        Err(e) => return krberror::build(KDC_ERR_C_PRINCIPAL_UNKNOWN, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };
    let client_salt = match crate::principal::salt(&client_entry) {
        Ok(s) => s,
        Err(e) => return krberror::build(KDC_ERR_C_PRINCIPAL_UNKNOWN, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };

    // Pre-auth: find PA-ENC-TIMESTAMP among the request's padata.
    let pa_enc_ts = req
        .padata
        .as_ref()
        .and_then(|padata| padata.iter().find(|p| p.r#type == PA_ENC_TIMESTAMP));

    let Some(pa) = pa_enc_ts else {
        // PA-ETYPE-INFO2 is ONE PaData entry whose value is a single
        // DER-encoded SEQUENCE OF ETYPE-INFO2-ENTRY covering every
        // enctype we offer -- not one PaData per enctype (that was a
        // real bug here: MIT krb5 silently treats a request built that
        // way as having no usable preauth method and fails client-side
        // with "Generic preauthentication failure" before ever sending
        // a second request, which is exactly what was observed live).
        //
        // Also required (found via the same live debugging, by reading
        // the real kdc_preauth_encts.c's enc_ts_get -- confirmed with
        // gdb that MIT krb5's client never even calls its key-derivation
        // function without this): a bare PA-ENC-TIMESTAMP (type 2, empty
        // value) marker entry alongside PA-ETYPE-INFO2. Without it, the
        // client has salt/etype info but no signal that the mechanism
        // itself is actually offered, so it silently produces no retry
        // padata at all and reports the same generic failure.
        let etype_info2: Vec<EtypeInfo2Entry> = client_keys
            .iter()
            .filter_map(|k| GeneralString::from_bytes(&client_salt).ok().map(|salt| EtypeInfo2Entry { etype: k.enctype.etype_number(), salt: Some(salt), s2kparams: None }))
            .collect();
        let e_data = rasn::der::encode(&etype_info2).ok().and_then(|encoded| {
            let method_data = vec![
                PaData { r#type: PA_ENC_TIMESTAMP, value: Vec::new().into() },
                PaData { r#type: PA_ETYPE_INFO2, value: encoded.into() },
            ];
            krberror::encode_method_data(&method_data).ok()
        });
        return krberror::build(KDC_ERR_PREAUTH_REQUIRED, &realm_str, kdc_sname, Some("additional pre-authentication required".into()), e_data).into();
    };

    let enc_data: EncryptedData = match rasn::der::decode(&pa.value) {
        Ok(v) => v,
        Err(e) => return krberror::build(KDC_ERR_PREAUTH_FAILED, &realm_str, kdc_sname, Some(format!("malformed PA-ENC-TIMESTAMP: {e}")), None).into(),
    };
    let Ok(enctype) = Enctype::try_from(enc_data.etype) else {
        return krberror::build(KDC_ERR_ETYPE_NOSUPP, &realm_str, kdc_sname, Some("unsupported PA-ENC-TIMESTAMP etype".into()), None).into();
    };
    let Some(client_key) = client_keys.iter().find(|k| k.enctype == enctype) else {
        return krberror::build(KDC_ERR_PREAUTH_FAILED, &realm_str, kdc_sname, Some("no key for the etype used in PA-ENC-TIMESTAMP".into()), None).into();
    };

    let ts_plain = match kerberos::decrypt(&app.fips, enctype, &client_key.key, 1, &enc_data.cipher) {
        Ok(p) => p,
        Err(_) => return krberror::build(KDC_ERR_PREAUTH_FAILED, &realm_str, kdc_sname, Some("PA-ENC-TIMESTAMP decryption failed (wrong password)".into()), None).into(),
    };
    let pa_enc_ts_enc: PaEncTsEnc = match rasn::der::decode(&ts_plain) {
        Ok(v) => v,
        Err(e) => return krberror::build(KDC_ERR_PREAUTH_FAILED, &realm_str, kdc_sname, Some(format!("malformed PA-ENC-TS-ENC: {e}")), None).into(),
    };
    let (server_now, _) = crate::time::now();
    if crate::time::diff_seconds(&server_now, &pa_enc_ts_enc.patimestamp).abs() > CLOCK_SKEW_SECS {
        return krberror::build(KRB_AP_ERR_SKEW, &realm_str, kdc_sname, Some("clock skew too great".into()), None).into();
    }

    // Server (krbtgt) key: encrypts the issued Ticket.
    let krbtgt_dn = match store
        .lookup_by_index(&app.base_dn, crate::principal::ATTR_PRINCIPAL_NAME, &format!("{}@{}", principal_name_to_string(&kdc_sname), crate::realm_to_string(realm)))
        .await
    {
        Ok(dns) if dns.len() == 1 => dns.into_iter().next().unwrap(),
        _ => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some("krbtgt principal not provisioned for this realm".into()), None).into(),
    };
    let krbtgt_entry = match store.get_entry(&krbtgt_dn).await {
        Ok(Some(e)) => e,
        _ => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some("krbtgt principal entry missing".into()), None).into(),
    };
    // #18: gathered here (while `store` is still locked, for the "member"
    // reverse-index lookup) but embedded into the ticket below, once the
    // krbtgt key -- also this TGT's PAC-signing key, since krbtgt IS the
    // "server" for a TGT -- is known.
    let pac_context = crate::pac::gather_context(&mut store, &app.base_dn, app.topology.as_ref(), &realm_str, &client_dn, &client_entry).await;
    drop(store);

    let krbtgt_keys = match crate::principal::keys(&krbtgt_entry) {
        Ok(k) => k,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };
    // Use the same enctype as the client's verified key when the krbtgt
    // has one, so the whole exchange stays in one enctype family;
    // otherwise fall back to the krbtgt's own preferred key.
    let Some(krbtgt_key) = krbtgt_keys.iter().find(|k| k.enctype == enctype).or_else(|| krbtgt_keys.first()) else {
        return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some("krbtgt has no keys".into()), None).into();
    };

    let session_key_bytes = match kerberos::random_bytes(&app.fips, enctype.key_len()) {
        Ok(k) => k,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };
    let session_key = EncryptionKey { r#type: enctype.etype_number(), value: session_key_bytes.clone().into() };

    let (auth_time, _) = crate::time::now();
    let end_time = crate::time::plus_seconds(TICKET_LIFETIME_SECS);
    let flags = TicketFlags::initial();

    // #18: for a TGT, krbtgt is both the ticket's "server" (its own key
    // encrypts this ticket, right below) and the "KDC" vouching for the
    // PAC -- so both PAC signatures use the same krbtgt key.
    let authorization_data = pac_context.as_ref().and_then(|ctx| {
        let input = ctx.as_input(auth_time.0.timestamp());
        crate::pac::generate(&app.fips, &input, &krbtgt_key.key, krbtgt_key.enctype, &krbtgt_key.key, krbtgt_key.enctype)
            .ok()
            .and_then(crate::wrap_pac_authorization_data)
    });

    let enc_ticket_part = EncTicketPart {
        flags: flags.clone(),
        key: session_key.clone(),
        crealm: realm.clone(),
        cname: cname.clone(),
        transited: TransitedEncoding { r#type: 0, contents: OctetString::from(Vec::new()) },
        auth_time: auth_time.clone(),
        start_time: None,
        end_time: end_time.clone(),
        renew_till: None,
        caddr: None,
        authorization_data,
    };
    let enc_ticket_bytes = match rasn::der::encode(&enc_ticket_part) {
        Ok(b) => b,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };
    // A fresh FipsContext for these two encrypts (the ticket, and the
    // AS-REP enc-part below) rather than the long-lived `app.fips`:
    // found live against a real client (#20, macOS's Heimdal-based
    // `dsconfigad`) that a client can consistently fail to decrypt an
    // AS-REP encrypted on a `FipsContext` that's already handled many
    // prior, unrelated operations over the daemon's lifetime, while an
    // otherwise-identical encrypt on a freshly-created context always
    // succeeds. Root cause not isolated (extensive live bisection during
    // #23 never reproduced it in a minimal, controlled repro outside a
    // real long-running daemon) -- treated as an external ossl/OpenSSL-
    // FIPS-provider state issue, mitigated here rather than by chasing
    // it further given how conclusively "fresh context" resolves it.
    let ticket_fips = match iron_crypto::FipsContext::new() {
        Ok(f) => f,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };
    let ticket_cipher = match kerberos::encrypt(&ticket_fips, krbtgt_key.enctype, &krbtgt_key.key, 2, &enc_ticket_bytes) {
        Ok(c) => c,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, kdc_sname, Some(e.to_string()), None).into(),
    };
    let ticket = Ticket {
        tkt_vno: 5.into(),
        realm: realm.clone(),
        sname: kdc_sname.clone(),
        enc_part: EncryptedData { etype: krbtgt_key.enctype.etype_number(), kvno: Some(krbtgt_key.kvno), cipher: ticket_cipher.into() },
    };

    let enc_kdc_rep_part = EncKdcRepPart {
        key: session_key,
        last_req: Vec::new(),
        nonce: req.req_body.nonce,
        key_expiration: None,
        flags,
        auth_time,
        start_time: None,
        end_time,
        renew_till: None,
        srealm: realm.clone(),
        sname: kdc_sname,
        caddr: None,
        encrypted_pa_data: None,
    };
    let enc_as_rep_bytes = match rasn::der::encode(&EncAsRepPart(enc_kdc_rep_part)) {
        Ok(b) => b,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, krbtgt_principal_name(&realm_str), Some(e.to_string()), None).into(),
    };
    let enc_part_cipher = match kerberos::encrypt(&ticket_fips, enctype, &client_key.key, 3, &enc_as_rep_bytes) {
        Ok(c) => c,
        Err(e) => return krberror::build(krberror::KRB_ERR_GENERIC, &realm_str, krbtgt_principal_name(&realm_str), Some(e.to_string()), None).into(),
    };

    let as_rep = AsRep(KdcRep {
        pvno: 5.into(),
        msg_type: 11.into(),
        padata: None,
        crealm: realm.clone(),
        cname: cname.clone(),
        ticket,
        enc_part: EncryptedData { etype: enctype.etype_number(), kvno: Some(client_key.kvno), cipher: enc_part_cipher.into() },
    });
    KdcResponse::AsRep(as_rep)
}

impl From<rasn_kerberos::KrbError> for KdcResponse {
    fn from(e: rasn_kerberos::KrbError) -> Self {
        KdcResponse::Error(e)
    }
}
