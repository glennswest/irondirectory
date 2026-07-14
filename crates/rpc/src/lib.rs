//! iron-rpc: a minimal MS-RPCE (DCE/RPC) server for SAMR/LSARPC/NETLOGON
//! (#19 -- the Windows-join handshake, D6 Tier 2).
//!
//! Deliberately narrow, matching this project's established "hand-roll
//! one shape, verify against a real independent implementation" style
//! (`iron-partition::sid`/`security_descriptor`, #17; `iron-kdc::pac`,
//! #18): a small NDR reader/writer ([`ndr`]) and PDU framing ([`pdu`]),
//! not a general DCE-RPC engine, cross-checked throughout against
//! [impacket](https://github.com/fortra/impacket)'s independent
//! implementation of these same three interfaces.
//!
//! **Transport**: unauthenticated `ncacn_ip_tcp` only (a plain TCP
//! listener speaking DCE/RPC directly) -- not the `ncacn_np` (SMB named
//! pipe) transport a real Windows `Add-Computer` actually uses. Hosting
//! `\PIPE\samr`/`\PIPE\lsarpc`/`\PIPE\netlogon` over SMB is `rocketsmbd`'s
//! territory (the sister project's "SMB half" role); this crate exposes
//! its dispatch as an ordinary `&[u8] -> Vec<u8>` PDU-in/PDU-out function
//! so a future SMB-hosted transport can reuse it without depending on
//! this crate's own TCP listener. `ncacn_ip_tcp` is genuinely useful on
//! its own, though: it's exactly what Samba's `rpcclient`/`net rpc`
//! (real, independent DCE-RPC clients) can point straight at with `-p
//! <port>`, giving a real interop verification path without needing SMB
//! or a real Windows machine at all.
//!
//! **Authentication**: none. SAMR calls that create/modify accounts are
//! implemented, but real Windows/Samba gate them behind an authenticated
//! (NTLMSSP) RPC bind -- adding that is a distinct, large protocol
//! surface of its own and explicitly out of scope for this pass.
//! NETLOGON's `NetrServerReqChallenge`/`NetrServerAuthenticate3` are
//! implemented in full including the real secure-channel cryptography
//! (by design unauthenticated at the RPC-bind layer -- that's the whole
//! point, authentication happens *through* these calls) -- see
//! [`netlogon`] for the MD4/NTOWF exception this required (D4).

pub mod lsarpc;
pub mod ndr;
pub mod netlogon;
pub mod pdu;
pub mod samr;
pub mod uuid;
