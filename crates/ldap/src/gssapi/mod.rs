//! SASL/GSSAPI bind support (RFC 4752) over Kerberos V5 (RFC 4121), for
//! LDAP's SASL bind mechanism (RFC 4513 §5.2). Builds entirely on
//! `iron_crypto::kerberos`'s existing encrypt/decrypt/checksum
//! primitives and `iron-kdc`'s principal storage/message-type reuse --
//! the underlying Kerberos crypto here is the same operation
//! `iron-kdc`'s TGS-REQ handler already performs (decrypt a Ticket,
//! validate an Authenticator), just as an application server (GSS
//! acceptor) instead of a KDC.
//!
//! Key usage numbers from RFC 4120 §7.5.1 / RFC 4121 §2 differ from
//! `iron-kdc`'s: 11/12 for the AP-REQ/AP-REP here (vs. TGS-REQ's 2/7/8),
//! and 22/24 (KG-USAGE-ACCEPTOR-SEAL/KG-USAGE-INITIATOR-SEAL) for the
//! RFC 4752 security-layer negotiation's Wrap tokens.
//!
//! Scope for this pass: mutual authentication (when requested, which
//! real LDAP GSSAPI clients always do), "no security layer" negotiation
//! only (clients requesting integrity/confidentiality get told only
//! "no protection" is available -- use StartTLS/LDAPS for transport
//! security instead). Not implemented: channel binding verification,
//! delegation, and integrity/confidentiality security layers for LDAP
//! traffic after bind.

pub mod accept;
pub mod token;
pub mod wrap;
