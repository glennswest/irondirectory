//! NETLOGON / MS-NRPC: the secure-channel handshake
//! (`NetrServerReqChallenge`/`NetrServerAuthenticate3`) that establishes
//! a computer account's trust relationship with the domain (#19). AES-
//! negotiated path only (`NETLOGON_NEG_SUPPORTS_AES`, bit `0x0100_0000`
//! -- confirmed against Samba's own `librpc/idl/netlogon.idl`, since
//! impacket's client-only implementation doesn't enumerate the
//! negotiate-flag bits at all).
//!
//! By design, this handshake is the one thing in this crate that's
//! deliberately unauthenticated at the RPC-bind layer -- authentication
//! *is* what these two calls establish, wrapping them in RPC-level auth
//! would be circular. The shared secret is the computer account's
//! NTOWF (MS-NRPC 3.1.4.3.1's `ComputeSessionKeyAES`), which needs
//! `iron_crypto::md4`'s narrow D4 exception (see that module's docs) --
//! but the HMAC-SHA256 and AES-CFB8 steps downstream of that are
//! ordinary FIPS-approved algorithms, and go through `iron_crypto`'s
//! `FipsContext`-gated primitives (`hmac::hmac_sha256`,
//! `aead::aes128_cfb8_encrypt`) exactly like everything else in this
//! project -- MD4/NTOWF is the *only* cited exception, not an excuse to
//! route the rest of this handshake's crypto around the FIPS provider.
//!
//! #20 adds what a real join does next: the secure channel is kept per
//! computer name (in [`NetlogonState`], across connections), a client
//! binds to it as an RPC security provider ([`crate::schannel`]), and over
//! that sealed or signed binding `NetrServerPasswordSet2` sets the
//! computer account's password -- its NTOWF and its Kerberos keys. The
//! Zerologon (CVE-2020-1472) mitigations of MS-NRPC 3.1.4.1/3.5.4.4.5 are
//! in: a random server challenge, a client challenge whose first five
//! bytes are all equal is refused, `NetrServerPasswordSet2` is refused
//! outside a sealed/signed Schannel binding, and a password buffer whose
//! length or confounder came through unencrypted is refused.
//!
//! Session-key derivation and credential verification cross-checked
//! against impacket's `dcerpc.v5.nrpc.ComputeSessionKeyAES`/
//! `ComputeNetlogonCredentialAES` (client-side code, since impacket only
//! implements the client/establisher role -- the server-side algorithm
//! mirrored here is the same math, just verifying instead of asserting).

use std::collections::HashMap;

use iron_crypto::FipsContext;
use iron_partition::Dn;
use iron_store::store::Store;
use tokio::sync::Mutex;

use crate::ndr::{NdrReader, NdrWriter};
use crate::{ntstatus, CallError};

pub const OPNUM_SERVER_REQ_CHALLENGE: u16 = 4;
pub const OPNUM_SERVER_AUTHENTICATE3: u16 = 26;
pub const OPNUM_SERVER_PASSWORD_SET2: u16 = 30;

/// MS-NRPC negotiate flag, confirmed against Samba's `netlogon.idl`.
pub const NETLOGON_NEG_SUPPORTS_AES: u32 = 0x0100_0000;

/// Attribute holding a computer account's NTOWF (hex-encoded 16 bytes) --
/// a stand-in for real `SamrSetInformationUser2` password-setting
/// (out of scope this pass, see crate docs): provisioned directly (e.g.
/// via `iron-rpc-ctl set-computer-secret`) so this handshake has a real
/// shared secret to authenticate against.
pub const NTOWF_ATTR: &str = "netlogonntowf";

pub struct NetlogonState {
    pub store: Mutex<Store>,
    pub base_dn: Dn,
    pub fips: FipsContext,
    /// Kerberos realm of the domain: a computer account's principal is
    /// `<account>@<realm>` until it has one (as kpasswd names it).
    pub realm: String,
    /// Established secure channels, by upper-cased computer name. A new
    /// `NetrServerAuthenticate3` for the same computer replaces its channel,
    /// as on Windows.
    pub channels: std::sync::Mutex<HashMap<String, SecureChannel>>,
}

impl NetlogonState {
    pub fn new(store: Store, base_dn: Dn, fips: FipsContext, realm: String) -> Self {
        NetlogonState { store: Mutex::new(store), base_dn, fips, realm, channels: Default::default() }
    }

    /// The session key of `computer`'s channel, for an Schannel bind.
    pub fn session_key(&self, computer: &str) -> Option<[u8; 16]> {
        self.channels.lock().unwrap().get(&computer.to_uppercase()).map(|c| c.session_key)
    }
}

/// A secure channel (MS-NRPC 3.1.1): the session key and the server's
/// copy of the credential chain.
#[derive(Clone)]
pub struct SecureChannel {
    pub session_key: [u8; 16],
    stored_credential: [u8; 8],
    account_name: String,
}

/// Per-connection state: `NetrServerAuthenticate3` needs the challenges
/// exchanged by a prior `NetrServerReqChallenge` on the *same* connection.
#[derive(Default)]
pub struct Session {
    challenges: Option<([u8; 8], [u8; 8])>,
}

/// The Schannel binding a request arrived on (`None`: unauthenticated).
pub struct Binding {
    pub computer: String,
    pub auth_level: u8,
}

/// MS-NRPC 3.1.4.3.1 `ComputeSessionKeyAES`:
/// `HMAC-SHA256(NTOWF, clientChallenge || serverChallenge)[:16]`.
pub fn compute_session_key_aes(fips: &FipsContext, ntowf: &[u8; 16], client_challenge: &[u8; 8], server_challenge: &[u8; 8]) -> Result<[u8; 16], iron_crypto::Error> {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(client_challenge);
    data.extend_from_slice(server_challenge);
    let full = iron_crypto::hmac::hmac_sha256(fips, ntowf, &data)?;
    Ok(full[..16].try_into().unwrap())
}

/// MS-NRPC 3.1.4.4.1's credential-encryption primitive: AES-128-CFB8
/// with a zero IV over the 8-byte challenge/credential value. `pub`
/// (not just `pub(crate)`) since the simulation harness (#23) -- this
/// crate's first genuine RPC *client* -- needs the exact same math to
/// compute its own client credential and verify the server's.
pub fn compute_credential(fips: &FipsContext, session_key: &[u8; 16], challenge: &[u8; 8]) -> Result<[u8; 8], iron_crypto::Error> {
    let out = iron_crypto::aead::aes128_cfb8_encrypt(fips, session_key, challenge)?;
    Ok(out[..8].try_into().unwrap())
}

/// `Ok` is the response stub; a handler's `None` means its stub didn't
/// decode.
pub async fn dispatch(state: &NetlogonState, session: &mut Session, binding: Option<&Binding>, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, CallError> {
    let response = match opnum {
        OPNUM_SERVER_REQ_CHALLENGE => server_req_challenge(state, session, stub),
        OPNUM_SERVER_AUTHENTICATE3 => server_authenticate3(state, session, stub).await,
        OPNUM_SERVER_PASSWORD_SET2 => server_password_set2(state, binding, stub).await,
        _ => return Err(CallError::UnknownOpnum),
    };
    response.ok_or(CallError::Malformed)
}

fn server_req_challenge(state: &NetlogonState, session: &mut Session, stub: &[u8]) -> Option<Vec<u8>> {
    let mut r = NdrReader::new(stub);
    // NetrServerReqChallenge(PrimaryName: PLOGONSRV_HANDLE (a pointer,
    // LPWSTR), ComputerName: WSTR (embedded directly, NOT a pointer --
    // no RPC_UNICODE_STRING-style Length/MaximumLength/referent prefix),
    // ClientChallenge: NETLOGON_CREDENTIAL (8 raw bytes)).
    //
    // Verified byte-for-byte against a real request impacket actually
    // produces (not assumed): PrimaryName's referent is immediately
    // followed by *its own* deferred WSTR content right there (NOT
    // batched after every fixed field the way a struct's own internal
    // pointers defer -- a plain RPC parameter list defers per-parameter,
    // in place), padded to 4 bytes only because the next field
    // (ComputerName's u32-led header) needs that alignment. ComputerName's
    // own embedded content is NOT followed by padding, because the next
    // field (ClientChallenge, 8 raw bytes) needs none. An earlier version
    // of this function assumed pointer data was always batched at the
    // end (the rule that happens to hold for `iron-kdc::pac`'s
    // KERB_VALIDATION_INFO *struct*) and got this badly wrong.
    let primary_name_referent = r.u32().ok()?;
    if primary_name_referent != 0 {
        let _primary_name = r.unicode_string_deferred().ok()?;
        r.pad_to_4();
    }
    let _computer_name = r.embedded_wstr().ok()?;
    let client_challenge: [u8; 8] = r.bytes(8).ok()?.try_into().ok()?;

    // Random, from the FIPS DRBG (MS-NRPC 3.1.4.1; a predictable server
    // challenge is half of what Zerologon needed).
    let mut w = NdrWriter::new();
    match iron_crypto::kerberos::random_bytes(&state.fips, 8) {
        Ok(random) => {
            let server_challenge: [u8; 8] = random.try_into().ok()?;
            session.challenges = Some((client_challenge, server_challenge));
            w.bytes(&server_challenge);
            w.u32(ntstatus::SUCCESS);
        }
        Err(e) => {
            tracing::warn!("NetrServerReqChallenge: no random challenge: {e}");
            w.bytes(&[0u8; 8]);
            w.u32(ntstatus::INTERNAL_ERROR);
        }
    }
    Some(w.buf)
}

/// `None` only when the request doesn't decode; a failed authentication
/// answers `STATUS_ACCESS_DENIED` (as Windows does) and logs why.
async fn server_authenticate3(state: &NetlogonState, session: &mut Session, stub: &[u8]) -> Option<Vec<u8>> {
    // NetrServerAuthenticate3(PrimaryName: PLOGONSRV_HANDLE (pointer),
    // AccountName: WSTR (embedded), SecureChannelType:
    // NETLOGON_SECURE_CHANNEL_TYPE (NDRENUM -> 2-byte USHORT on the
    // wire), ComputerName: WSTR (embedded), ClientCredential:
    // NETLOGON_CREDENTIAL (8 bytes), NegotiateFlags: ULONG).
    //
    // Same per-parameter (not batched) deferral as `server_req_challenge`,
    // verified against a real request byte-for-byte: PrimaryName's
    // deferred content (if any) comes right after its referent, padded
    // to 4 because AccountName's header needs it. AccountName's own
    // embedded content is NOT padded afterward -- the next field
    // (SecureChannelType, 2 bytes) doesn't need 4-byte alignment, and in
    // practice the two together often land back on a 4-byte boundary
    // before ComputerName's header anyway. ComputerName's content is
    // likewise unpadded before ClientCredential (8 raw bytes, no
    // alignment requirement).
    let mut r = NdrReader::new(stub);
    let primary_name_referent = r.u32().ok()?;
    if primary_name_referent != 0 {
        let _primary_name = r.unicode_string_deferred().ok()?;
        r.pad_to_4();
    }
    let account_name = r.embedded_wstr().ok()?;
    let _secure_channel_type = r.u16().ok()?;
    r.pad_to_4(); // ComputerName's header (a u32-led conformant array) needs 4-byte alignment
    let computer_name = r.embedded_wstr().ok()?;
    let client_credential: [u8; 8] = r.bytes(8).ok()?.try_into().ok()?;
    let negotiate_flags = r.u32().ok()?;

    // WSTR fields are conventionally NUL-terminated on the wire (unlike
    // RPC_UNICODE_STRING, which carries an explicit Length instead) --
    // strip it before using this as a DIT lookup key.
    let account_name = account_name.trim_end_matches('\0');
    let computer_name = computer_name.trim_end_matches('\0');
    // A challenge pair is good for one attempt.
    let challenges = session.challenges.take();
    let mut w = NdrWriter::new();
    match authenticate(state, challenges, account_name, &client_credential, negotiate_flags).await {
        Ok((server_credential, session_key)) => {
            let channel = SecureChannel { session_key, stored_credential: client_credential, account_name: account_name.to_string() };
            state.channels.lock().unwrap().insert(computer_name.to_uppercase(), channel);
            w.bytes(&server_credential);
            w.u32(negotiate_flags); // echo back what we support (AES only)
            w.u32(0); // AccountRid -- not tracked distinctly from the account entry here
            w.u32(ntstatus::SUCCESS);
        }
        Err(reason) => {
            tracing::warn!(account = account_name, "NetrServerAuthenticate3 denied: {reason}");
            w.bytes(&[0u8; 8]);
            w.u32(0);
            w.u32(0);
            w.u32(ntstatus::ACCESS_DENIED);
        }
    }
    Some(w.buf)
}

/// Checks the client credential against the account's NTOWF; returns the
/// server credential and the session key, or why the account is refused.
async fn authenticate(state: &NetlogonState, challenges: Option<([u8; 8], [u8; 8])>, account_name: &str, client_credential: &[u8; 8], negotiate_flags: u32) -> Result<([u8; 8], [u8; 16]), String> {
    let (client_challenge, server_challenge) = challenges.ok_or("no NetrServerReqChallenge on this connection")?;
    if negotiate_flags & NETLOGON_NEG_SUPPORTS_AES == 0 {
        return Err(format!("client did not offer AES (flags 0x{negotiate_flags:08x}); only the AES path is implemented"));
    }
    if !is_random_challenge(&client_challenge) {
        return Err("client challenge's first five bytes are all equal (CVE-2020-1472)".into());
    }

    let (dn, entry) = find_account(state, account_name).await?;
    let ntowf_hex = entry.get(NTOWF_ATTR).and_then(|v| v.first()).ok_or_else(|| format!("{dn} has no {NTOWF_ATTR}"))?;
    let ntowf: [u8; 16] = hex_decode(ntowf_hex).and_then(|b| b.try_into().ok()).ok_or_else(|| format!("{dn}'s {NTOWF_ATTR} is not 16 hex bytes"))?;

    let crypto = |e: iron_crypto::Error| format!("crypto: {e}");
    let session_key = compute_session_key_aes(&state.fips, &ntowf, &client_challenge, &server_challenge).map_err(crypto)?;
    let expected_client_credential = compute_credential(&state.fips, &session_key, &client_challenge).map_err(crypto)?;
    if &expected_client_credential != client_credential {
        return Err("client credential does not match the account's secret".into());
    }
    Ok((compute_credential(&state.fips, &session_key, &server_challenge).map_err(crypto)?, session_key))
}

/// MS-NRPC 3.1.4.1: "If none of the first 5 bytes of the client challenge
/// is unique, the server MUST fail session-key negotiation" (the
/// CVE-2020-1472 fix; Samba's `netlogon_creds_is_random_challenge`).
pub fn is_random_challenge(challenge: &[u8; 8]) -> bool {
    challenge[1..5].iter().any(|&b| b != challenge[0])
}

async fn find_account(state: &NetlogonState, account_name: &str) -> Result<(Dn, iron_store::model::Entry), String> {
    let mut store = state.store.lock().await;
    let dns = store.lookup_by_index(&state.base_dn, "cn", account_name).await.map_err(|e| format!("index lookup failed: {e}"))?;
    let dn = match dns.as_slice() {
        [dn] => dn.clone(),
        [] => return Err("no such account".into()),
        many => return Err(format!("{} entries share the name", many.len())),
    };
    let entry = store.get_entry(&dn).await.map_err(|e| format!("read of {dn} failed: {e}"))?.ok_or_else(|| format!("{dn} is indexed but missing"))?;
    Ok((dn, entry))
}

/// Adds `n` to the credential's first four bytes (a little-endian u32,
/// wrapping), as MS-NRPC 3.1.4.5 steps the credential chain.
fn credential_plus(credential: &[u8; 8], n: u32) -> [u8; 8] {
    let mut out = *credential;
    let low = u32::from_le_bytes(credential[..4].try_into().unwrap()).wrapping_add(n);
    out[..4].copy_from_slice(&low.to_le_bytes());
    out
}

/// MS-NRPC 3.1.4.5, server side: checks the client's authenticator
/// against the channel's stored credential and steps the chain; returns
/// the return authenticator's credential.
pub fn step_authenticator(fips: &FipsContext, channel: &mut SecureChannel, credential: &[u8; 8], timestamp: u32) -> Result<[u8; 8], String> {
    let crypto = |e: iron_crypto::Error| format!("crypto: {e}");
    let temp = credential_plus(&channel.stored_credential, timestamp);
    if &compute_credential(fips, &channel.session_key, &temp).map_err(crypto)? != credential {
        return Err("authenticator does not match the secure channel".into());
    }
    channel.stored_credential = credential_plus(&temp, 1);
    compute_credential(fips, &channel.session_key, &channel.stored_credential).map_err(crypto)
}

/// MS-NRPC 2.2.1.3.7 `NL_TRUST_PASSWORD`, decrypted with AES-128-CFB8
/// under the session key (zero IV, 3.4.5.2.5). Returns the password's
/// UTF-16LE bytes, refusing the shapes Zerologon used: a length field or
/// confounder that came through unencrypted, or an empty password
/// (Samba's `netr_ServerPasswordSet2` checks).
pub fn decrypt_trust_password(fips: &FipsContext, session_key: &[u8; 16], encrypted: &[u8; 516]) -> Result<Vec<u8>, String> {
    let plain = iron_crypto::aead::aes128_cfb8(fips, session_key, &[0u8; 16], encrypted, false).map_err(|e| format!("crypto: {e}"))?;
    let len = u32::from_le_bytes(plain[512..516].try_into().unwrap()) as usize;
    if plain[512..516] == encrypted[512..516] {
        return Err("password length was not encrypted".into());
    }
    if len > 512 || len % 2 != 0 {
        return Err(format!("password length {len} is not a UTF-16 length within 512 bytes"));
    }
    if len < 2 {
        return Err("empty password".into());
    }
    let confounder = 512 - len;
    if confounder > 0 && plain[..confounder] == encrypted[..confounder] {
        return Err("password buffer's confounder was not encrypted".into());
    }
    Ok(plain[confounder..512].to_vec())
}

/// `NetrServerPasswordSet2` (opnum 30, MS-NRPC 3.5.4.4.5): the computer
/// sets its own account password over its secure channel.
async fn server_password_set2(state: &NetlogonState, binding: Option<&Binding>, stub: &[u8]) -> Option<Vec<u8>> {
    // PrimaryName (pointer), AccountName (WSTR), SecureChannelType (u16),
    // ComputerName (WSTR) -- as NetrServerAuthenticate3 -- then
    // Authenticator (NETLOGON_AUTHENTICATOR: Credential 8 bytes, Timestamp
    // u32; the struct is 4-aligned) and ClearNewPassword (516 bytes).
    let mut r = NdrReader::new(stub);
    let primary_name_referent = r.u32().ok()?;
    if primary_name_referent != 0 {
        let _primary_name = r.unicode_string_deferred().ok()?;
        r.pad_to_4();
    }
    let account_name = r.embedded_wstr().ok()?;
    let _secure_channel_type = r.u16().ok()?;
    r.pad_to_4();
    let computer_name = r.embedded_wstr().ok()?;
    r.pad_to_4();
    let credential: [u8; 8] = r.bytes(8).ok()?.try_into().ok()?;
    let timestamp = r.u32().ok()?;
    let encrypted: [u8; 516] = r.bytes(516).ok()?.try_into().ok()?;
    let account_name = account_name.trim_end_matches('\0');
    let computer_name = computer_name.trim_end_matches('\0');

    let mut w = NdrWriter::new();
    match password_set2(state, binding, account_name, computer_name, &credential, timestamp, &encrypted).await {
        Ok((return_credential, principal)) => {
            tracing::info!(account = account_name, computer = computer_name, %principal, "NetrServerPasswordSet2: password set");
            w.bytes(&return_credential);
            w.u32(0);
            w.u32(ntstatus::SUCCESS);
        }
        Err(reason) => {
            tracing::warn!(account = account_name, computer = computer_name, "NetrServerPasswordSet2 denied: {reason}");
            w.bytes(&[0u8; 8]);
            w.u32(0);
            w.u32(ntstatus::ACCESS_DENIED);
        }
    }
    Some(w.buf)
}

async fn password_set2(state: &NetlogonState, binding: Option<&Binding>, account_name: &str, computer_name: &str, credential: &[u8; 8], timestamp: u32, encrypted: &[u8; 516]) -> Result<([u8; 8], String), String> {
    let binding = binding.ok_or("not over a sealed or signed Netlogon secure channel binding")?;
    if !binding.computer.eq_ignore_ascii_case(computer_name) {
        return Err(format!("binding is {}'s secure channel, not {computer_name}'s", binding.computer));
    }
    // Step the chain under the lock, then work on a copy: a failed write
    // below still consumed the authenticator, as on Windows.
    let (return_credential, channel) = {
        let mut channels = state.channels.lock().unwrap();
        let channel = channels.get_mut(&computer_name.to_uppercase()).ok_or("no secure channel for this computer")?;
        if !channel.account_name.eq_ignore_ascii_case(account_name) {
            return Err(format!("secure channel is for account {}, not {account_name}", channel.account_name));
        }
        (step_authenticator(&state.fips, channel, credential, timestamp)?, channel.clone())
    };
    let utf16 = decrypt_trust_password(&state.fips, &channel.session_key, encrypted)?;

    let (dn, mut entry) = find_account(state, account_name).await?;
    // NTOWF over the raw UTF-16 bytes (Windows machine passwords are
    // random UTF-16 code units, not always valid Unicode); the Kerberos
    // keys over its UTF-8 form with unpaired surrogates replaced, as
    // Samba's CH_UTF16MUNGED does.
    let ntowf = iron_crypto::md4::md4(&utf16);
    let units: Vec<u16> = utf16.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let password = String::from_utf16_lossy(&units);
    let principal = iron_kdc::principal::principal_name(&entry).map(str::to_string).unwrap_or_else(|_| format!("{account_name}@{}", state.realm));
    iron_kdc::principal::set_password(&state.fips, &mut entry, &principal, password.as_bytes()).map_err(|e| format!("Kerberos keys: {e}"))?;
    entry.set(NTOWF_ATTR, [ntowf.iter().map(|b| format!("{b:02x}")).collect::<String>()]);
    if entry.get("samaccountname").is_none() {
        entry.set("samaccountname", [account_name.to_string()]);
    }
    let mut store = state.store.lock().await;
    store.put_entry(&dn, &entry, &iron_kdc::index_spec()).await.map_err(|e| format!("write of {dn} failed: {e}"))?;
    Ok((return_credential, principal))
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

    #[test]
    fn session_key_derivation_is_deterministic_and_challenge_dependent() {
        let fips = FipsContext::new().unwrap();
        let ntowf = [0x11u8; 16];
        let cc = [1u8; 8];
        let sc = [2u8; 8];
        let k1 = compute_session_key_aes(&fips, &ntowf, &cc, &sc).unwrap();
        let k2 = compute_session_key_aes(&fips, &ntowf, &cc, &sc).unwrap();
        assert_eq!(k1, k2);
        let k3 = compute_session_key_aes(&fips, &ntowf, &[3u8; 8], &sc).unwrap();
        assert_ne!(k1, k3);
    }

    #[test]
    fn zerologon_challenges_are_refused() {
        assert!(!is_random_challenge(&[0; 8]));
        assert!(!is_random_challenge(&[7, 7, 7, 7, 7, 1, 2, 3]));
        assert!(is_random_challenge(&[7, 7, 7, 7, 8, 7, 7, 7]));
        assert!(is_random_challenge(b"12345678"));
    }

    #[test]
    fn authenticator_chain_steps_as_the_client_does() {
        let fips = FipsContext::new().unwrap();
        let key = [5u8; 16];
        let client_credential = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut channel = SecureChannel { session_key: key, stored_credential: client_credential, account_name: "WS1$".into() };
        // Client (impacket ComputeNetlogonAuthenticatorAES): stored + ts.
        let ts = 1_700_000_000u32;
        let auth = compute_credential(&fips, &key, &credential_plus(&client_credential, ts)).unwrap();
        let ret = step_authenticator(&fips, &mut channel, &auth, ts).unwrap();
        // Client checks the return authenticator against stored + ts + 1.
        assert_eq!(ret, compute_credential(&fips, &key, &credential_plus(&client_credential, ts + 1)).unwrap());
        // The same authenticator again is a replay.
        assert!(step_authenticator(&fips, &mut channel, &auth, ts).is_err());
        // The next one chains from stored + ts + 1.
        let next = credential_plus(&credential_plus(&client_credential, ts + 1), ts + 5);
        let auth2 = compute_credential(&fips, &key, &next).unwrap();
        assert!(step_authenticator(&fips, &mut channel, &auth2, ts + 5).is_ok());
    }

    fn encrypt_trust_password(fips: &FipsContext, key: &[u8; 16], plain: &[u8; 516]) -> [u8; 516] {
        iron_crypto::aead::aes128_cfb8(fips, key, &[0u8; 16], plain, true).unwrap().try_into().unwrap()
    }

    #[test]
    fn trust_password_decrypts_and_zerologon_buffers_are_refused() {
        let fips = FipsContext::new().unwrap();
        let key = [9u8; 16];
        let password: Vec<u8> = "MachinePass123!".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut plain = [0x5au8; 516];
        plain[512 - password.len()..512].copy_from_slice(&password);
        plain[512..].copy_from_slice(&(password.len() as u32).to_le_bytes());
        let enc = encrypt_trust_password(&fips, &key, &plain);
        assert_eq!(decrypt_trust_password(&fips, &key, &enc).unwrap(), password);

        // Zerologon: all zeros on the wire.
        assert!(decrypt_trust_password(&fips, &key, &[0u8; 516]).is_err());
        // An empty password, properly encrypted.
        let mut empty = [0x5au8; 516];
        empty[512..].copy_from_slice(&0u32.to_le_bytes());
        assert!(decrypt_trust_password(&fips, &key, &encrypt_trust_password(&fips, &key, &empty)).is_err());
        // Wrong key: the length decrypts to garbage and is refused.
        assert!(decrypt_trust_password(&fips, &[8u8; 16], &enc).is_err());
    }

    #[test]
    fn credential_is_deterministic_and_key_dependent() {
        let fips = FipsContext::new().unwrap();
        let key1 = [1u8; 16];
        let key2 = [2u8; 16];
        let data = [9u8; 8];
        assert_eq!(compute_credential(&fips, &key1, &data).unwrap(), compute_credential(&fips, &key1, &data).unwrap());
        assert_ne!(compute_credential(&fips, &key1, &data).unwrap(), compute_credential(&fips, &key2, &data).unwrap());
    }
}
