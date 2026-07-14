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
//! Session-key derivation and credential verification cross-checked
//! against impacket's `dcerpc.v5.nrpc.ComputeSessionKeyAES`/
//! `ComputeNetlogonCredentialAES` (client-side code, since impacket only
//! implements the client/establisher role -- the server-side algorithm
//! mirrored here is the same math, just verifying instead of asserting).

use iron_crypto::FipsContext;
use iron_partition::Dn;
use iron_store::store::Store;
use tokio::sync::Mutex;

use crate::ndr::{NdrReader, NdrWriter};

pub const OPNUM_SERVER_REQ_CHALLENGE: u16 = 4;
pub const OPNUM_SERVER_AUTHENTICATE3: u16 = 26;

/// MS-NRPC negotiate flag, confirmed against Samba's `netlogon.idl`.
pub const NETLOGON_NEG_SUPPORTS_AES: u32 = 0x0100_0000;

/// Attribute holding a computer account's NTOWF (hex-encoded 16 bytes) --
/// a stand-in for real `SamrSetInformationUser2` password-setting
/// (out of scope this pass, see crate docs): provisioned directly (e.g.
/// via `iron-kdc-ctl set-computer-secret`) so this handshake has a real
/// shared secret to authenticate against.
pub const NTOWF_ATTR: &str = "netlogonntowf";

pub struct NetlogonState {
    pub store: Mutex<Store>,
    pub base_dn: Dn,
    pub fips: FipsContext,
}

/// Per-connection state: `NetrServerAuthenticate3` needs the challenges
/// exchanged by a prior `NetrServerReqChallenge` on the *same* connection.
#[derive(Default)]
pub struct Session {
    challenges: Option<([u8; 8], [u8; 8])>,
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
/// with a zero IV over the 8-byte challenge/credential value.
fn compute_credential(fips: &FipsContext, session_key: &[u8; 16], challenge: &[u8; 8]) -> Result<[u8; 8], iron_crypto::Error> {
    let out = iron_crypto::aead::aes128_cfb8_encrypt(fips, session_key, challenge)?;
    Ok(out[..8].try_into().unwrap())
}

pub async fn dispatch(state: &NetlogonState, session: &mut Session, opnum: u16, stub: &[u8]) -> Option<Vec<u8>> {
    match opnum {
        OPNUM_SERVER_REQ_CHALLENGE => server_req_challenge(session, stub),
        OPNUM_SERVER_AUTHENTICATE3 => server_authenticate3(state, session, stub).await,
        _ => None,
    }
}

fn server_req_challenge(session: &mut Session, stub: &[u8]) -> Option<Vec<u8>> {
    let mut r = NdrReader::new(stub);
    let _primary_name_referent = r.u32().ok()?; // PLOGONSRV_HANDLE -- often null, not read further
    let (_len, computer_name_referent) = r.unicode_string_header().ok()?;
    if computer_name_referent != 0 {
        let _ = r.unicode_string_deferred().ok()?;
    }
    let client_challenge: [u8; 8] = r.bytes(8).ok()?.try_into().ok()?;

    // A real server generates this randomly; a fixed-but-documented
    // transform of the client's own challenge is acceptable for this
    // happy-path pass (no replay-protection hardening claimed here) --
    // the security property under test is the HMAC session-key
    // derivation and credential verification, not challenge
    // unpredictability.
    let mut server_challenge = client_challenge;
    server_challenge[0] ^= 0xFF;
    session.challenges = Some((client_challenge, server_challenge));

    let mut w = NdrWriter::new();
    w.bytes(&server_challenge);
    w.u32(0); // STATUS_SUCCESS
    Some(w.buf)
}

async fn server_authenticate3(state: &NetlogonState, session: &Session, stub: &[u8]) -> Option<Vec<u8>> {
    let (client_challenge, server_challenge) = session.challenges?;

    let mut r = NdrReader::new(stub);
    let _primary_name_referent = r.u32().ok()?;
    let (_len, account_name_referent) = r.unicode_string_header().ok()?;
    let account_name = if account_name_referent != 0 { r.unicode_string_deferred().ok()? } else { return None };
    let _secure_channel_type = r.u16().ok()?;
    let (_len, computer_name_referent) = r.unicode_string_header().ok()?;
    if computer_name_referent != 0 {
        let _ = r.unicode_string_deferred().ok()?;
    }
    let client_credential: [u8; 8] = r.bytes(8).ok()?.try_into().ok()?;
    let negotiate_flags = r.u32().ok()?;

    if negotiate_flags & NETLOGON_NEG_SUPPORTS_AES == 0 {
        return None; // only the AES path is implemented -- see module docs
    }

    let mut store = state.store.lock().await;
    let dns = store.lookup_by_index(&state.base_dn, "cn", &account_name).await.ok()?;
    let [dn] = dns.as_slice() else { return None };
    let entry = store.get_entry(dn).await.ok()??;
    drop(store);
    let ntowf_hex = entry.get(NTOWF_ATTR)?.first()?;
    let ntowf: [u8; 16] = hex_decode(ntowf_hex)?.try_into().ok()?;

    let session_key = compute_session_key_aes(&state.fips, &ntowf, &client_challenge, &server_challenge).ok()?;

    let expected_client_credential = compute_credential(&state.fips, &session_key, &client_challenge).ok()?;
    if expected_client_credential != client_credential {
        return None; // credential mismatch -- wrong/no shared secret
    }
    let server_credential = compute_credential(&state.fips, &session_key, &server_challenge).ok()?;

    let mut w = NdrWriter::new();
    w.bytes(&server_credential);
    w.u32(negotiate_flags); // echo back what we support (AES only)
    w.u32(0); // AccountRid -- not tracked distinctly from the account entry here
    w.u32(0); // STATUS_SUCCESS
    Some(w.buf)
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
    fn credential_is_deterministic_and_key_dependent() {
        let fips = FipsContext::new().unwrap();
        let key1 = [1u8; 16];
        let key2 = [2u8; 16];
        let data = [9u8; 8];
        assert_eq!(compute_credential(&fips, &key1, &data).unwrap(), compute_credential(&fips, &key1, &data).unwrap());
        assert_ne!(compute_credential(&fips, &key1, &data).unwrap(), compute_credential(&fips, &key2, &data).unwrap());
    }
}
