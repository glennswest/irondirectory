//! iron-simulate: a native Rust domain-join + login simulation harness
//! (#23), for scale testing and simpler day-to-day verification than
//! hand-rolling `rpcclient`/impacket sessions.
//!
//! Simulates the real-world call sequence a Windows Server or PC
//! performs joining a domain -- LSARPC (read domain info) -> SAMR
//! (create computer account) -> NETLOGON (secure channel) -> Kerberos
//! AS-REQ/TGS-REQ (get a TGT + a PAC-bearing service ticket) -- against
//! this project's own real `iron-ldapd`/`iron-kdcd`/`iron-rpcd`, plus a
//! "normal PC" ordinary interactive logon (AS-REQ/TGS-REQ only, no
//! join). Reuses `iron_rpc`'s NDR/PDU primitives for the RPC client
//! side; the Kerberos client (`krb_client`) is net-new, since nothing
//! in this workspace previously spoke Kerberos as a *client* (every
//! prior issue used real `kinit`/`klist`/impacket for that role).

pub mod join;
pub mod krb_client;
pub mod lsarpc_client;
pub mod netlogon_client;
pub mod rpc_client;
pub mod samr_client;
