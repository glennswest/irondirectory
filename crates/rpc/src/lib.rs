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
//! **Transports**: `ncacn_ip_tcp` ([`server::serve`], a TCP listener speaking
//! DCE/RPC directly: what Samba's `rpcclient`/`net rpc` reach with `-p
//! <port>`, and what `iron-simulate` uses), and `ncacn_np` ([`pipe`], #53):
//! SMB named pipes (`\PIPE\samr`, `\PIPE\lsarpc`, `\PIPE\netlogon` on
//! `IPC$`), which rocketsmbd serves and forwards to a Unix socket here, one
//! connection per pipe, after a preamble naming the SMB session's user (with
//! the Kerberos PAC's SIDs) and its session key. Windows reaches these
//! interfaces only over `ncacn_np`. Both run the same PDU loop
//! ([`server::handle_connection`]).
//!
//! **Authentication**: no RPC-level bind authentication except the Netlogon
//! secure channel ([`schannel`], `auth_type` 68, #20) -- what a joining
//! computer uses to set its own password with `NetrServerPasswordSet2`.
//! Over a pipe, the caller is the SMB session's user: SAMR lets a Domain
//! Admin create accounts and set their passwords
//! (`SamrSetInformationUser2`, AES: [`samr_aes`]). Over TCP there is no
//! caller and no session key: SAMR creates accounts unauthenticated (#76)
//! and sets no passwords. NETLOGON's `NetrServerReqChallenge`/
//! `NetrServerAuthenticate3` are unauthenticated at the bind by design
//! (authentication happens *through* them) -- see [`netlogon`] for the
//! MD4/NTOWF exception this required (D4).

pub mod lsarpc;
pub mod ndr;
pub mod netlogon;
pub mod pdu;
pub mod pipe;
pub mod samr;
pub mod samr_aes;
pub mod schannel;
pub mod server;
pub mod uuid;

/// Why a call produced no response stub. [`server`] turns it into a
/// `fault` PDU: an opnum the bound interface doesn't implement is
/// `nca_op_rng_error`, a stub that doesn't decode is `nca_s_fault_ndr`.
/// A call that decodes but fails (no such account, a wrong credential, a
/// store error) is not a `CallError`: it answers with an NTSTATUS in the
/// response stub, as Windows does, and is logged (#24 -- every failure
/// used to come back as an unlogged `nca_unk_if`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    UnknownOpnum,
    Malformed,
}

/// NTSTATUS values the handlers answer with.
pub mod ntstatus {
    pub const SUCCESS: u32 = 0;
    pub const ACCESS_DENIED: u32 = 0xC000_0022;
    pub const USER_EXISTS: u32 = 0xC000_0063;
    pub const INTERNAL_DB_ERROR: u32 = 0xC000_0158;
    pub const INTERNAL_ERROR: u32 = 0xC000_00E5;
}
