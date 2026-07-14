//! SAMR (MS-SAMR): account enumeration/creation for the domain-join
//! handshake (#19). Password-setting (`SamrSetInformationUser2`) needs
//! an authenticated (NTLMSSP) RPC bind's session key and is out of
//! scope for this pass -- see crate docs.
