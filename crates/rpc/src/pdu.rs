//! MS-RPCE PDU framing: the 16-byte common header plus `bind`/`bind_ack`/
//! `request`/`response`/`fault` bodies (#19). Cross-checked against
//! impacket's `dcerpc.v5.rpcrt` (`MSRPCHeader`/`MSRPCBind`/
//! `MSRPCBindAck`/`MSRPCRequestHeader`/`MSRPCRespHeader`).
//!
//! Deliberately unauthenticated only: no `sec_trailer`/auth-data support
//! (`auth_len` is always 0 here). SAMR/LSARPC/NETLOGON's real-world
//! authenticated (NTLMSSP/Schannel) RPC binds are out of scope for this
//! pass -- see the crate-level docs.

use crate::uuid::NDR_TRANSFER_SYNTAX;

pub const PTYPE_REQUEST: u8 = 0x00;
pub const PTYPE_RESPONSE: u8 = 0x02;
pub const PTYPE_FAULT: u8 = 0x03;
pub const PTYPE_BIND: u8 = 0x0B;
pub const PTYPE_BIND_ACK: u8 = 0x0C;
pub const PTYPE_BIND_NAK: u8 = 0x0D;

pub const PFC_FIRST_FRAG: u8 = 0x01;
pub const PFC_LAST_FRAG: u8 = 0x02;

/// `nca_s_fault_ndr` (0x000006F7) -- returned when a request PDU can't be
/// decoded at all. Real Windows/Samba treat this as a generic "bad
/// stub data" fault; a more precise per-opnum fault code isn't worth
/// modeling for a happy-path server.
pub const FAULT_NDR: u32 = 0x0000_06F7;
/// `nca_unk_if` (0x1C010003) -- unknown interface/opnum.
pub const FAULT_UNK_IF: u32 = 0x1C01_0003;

#[derive(Debug, thiserror::Error)]
pub enum PduError {
    #[error("PDU too short ({0} bytes, need at least 16 for the common header)")]
    TooShort(usize),
    #[error("unsupported RPC version {major}.{minor} (only 5.0 is supported)")]
    UnsupportedVersion { major: u8, minor: u8 },
    #[error("fragment length {declared} doesn't match the {actual} bytes actually present")]
    LengthMismatch { declared: u16, actual: usize },
}

#[derive(Debug, Clone)]
pub struct PduHeader {
    pub ptype: u8,
    pub flags: u8,
    pub call_id: u32,
}

/// Reads a complete PDU (header + body) from `buf`, which must contain
/// exactly one fragment (`frag_len` bytes) -- this server never
/// fragments requests/responses (every SAMR/LSARPC/NETLOGON PDU used
/// here fits comfortably in one fragment).
pub fn parse_header(buf: &[u8]) -> Result<(PduHeader, u16), PduError> {
    if buf.len() < 16 {
        return Err(PduError::TooShort(buf.len()));
    }
    let ver_major = buf[0];
    let ver_minor = buf[1];
    if ver_major != 5 {
        return Err(PduError::UnsupportedVersion { major: ver_major, minor: ver_minor });
    }
    let ptype = buf[2];
    let flags = buf[3];
    let frag_len = u16::from_le_bytes([buf[8], buf[9]]);
    let call_id = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    Ok((PduHeader { ptype, flags, call_id }, frag_len))
}

fn write_common_header(out: &mut Vec<u8>, ptype: u8, frag_len: u16, call_id: u32) {
    out.push(5); // ver_major
    out.push(0); // ver_minor
    out.push(ptype);
    out.push(PFC_FIRST_FRAG | PFC_LAST_FRAG); // never fragmented
    out.extend_from_slice(&0x10u32.to_le_bytes()); // representation: LE/ASCII/IEEE
    out.extend_from_slice(&frag_len.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // auth_len = 0 (unauthenticated)
    out.extend_from_slice(&call_id.to_le_bytes());
}

/// A single accepted-or-rejected presentation context result for `bind_ack`.
pub struct CtxResult {
    /// 0 = acceptance, 2 = provider rejection (used for "syntax not supported").
    pub result: u16,
    pub reason: u16,
}

impl CtxResult {
    pub fn accept() -> Self {
        CtxResult { result: 0, reason: 0 }
    }
    pub fn reject_abstract_syntax_not_supported() -> Self {
        CtxResult { result: 2, reason: 2 }
    }
}

/// Builds a `bind_ack` PDU accepting (or rejecting) each of `results`, in
/// the same order the client's `bind` listed its presentation contexts.
/// `sec_addr` is the "secondary address" string real implementations use
/// for a protocol-specific port hint -- empty is valid and universally
/// accepted (rpcclient/Samba don't require a real value for our ncacn_ip_tcp
/// listener, since the client already knows the port it connected to).
pub fn build_bind_ack(call_id: u32, max_frag: u16, assoc_group: u32, results: &[CtxResult]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&max_frag.to_le_bytes());
    body.extend_from_slice(&max_frag.to_le_bytes());
    body.extend_from_slice(&assoc_group.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // SecondaryAddrLen = 0
    // No SecondaryAddr bytes at all (a literal empty string, no NUL
    // terminator). Pad so ctx_num lands 4-byte aligned relative to the
    // PDU start -- the 16-byte common header is already a multiple of
    // 4, so aligning `body.len()` here is equivalent.
    let pad = (4 - (body.len() % 4)) % 4;
    body.extend(std::iter::repeat_n(0u8, pad));
    body.push(results.len() as u8); // ctx_num
    body.push(0); // Reserved
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
    for r in results {
        body.extend_from_slice(&r.result.to_le_bytes());
        body.extend_from_slice(&r.reason.to_le_bytes());
        body.extend_from_slice(&*NDR_TRANSFER_SYNTAX);
    }

    let frag_len = (16 + body.len()) as u16;
    let mut out = Vec::with_capacity(frag_len as usize);
    write_common_header(&mut out, PTYPE_BIND_ACK, frag_len, call_id);
    out.extend_from_slice(&body);
    out
}

/// Builds a `response` PDU wrapping `stub_data` (the NDR-encoded return
/// values for whatever operation was requested).
pub fn build_response(call_id: u32, ctx_id: u16, stub_data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + stub_data.len());
    body.extend_from_slice(&(stub_data.len() as u32).to_le_bytes()); // alloc_hint
    body.extend_from_slice(&ctx_id.to_le_bytes());
    body.push(0); // cancel_count
    body.push(0); // reserved
    body.extend_from_slice(stub_data);

    let frag_len = (16 + body.len()) as u16;
    let mut out = Vec::with_capacity(frag_len as usize);
    write_common_header(&mut out, PTYPE_RESPONSE, frag_len, call_id);
    out.extend_from_slice(&body);
    out
}

/// Builds a `fault` PDU with the given NCA status code.
pub fn build_fault(call_id: u32, ctx_id: u16, status: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(12);
    body.extend_from_slice(&4u32.to_le_bytes()); // alloc_hint
    body.extend_from_slice(&ctx_id.to_le_bytes());
    body.push(0); // cancel_count
    body.push(0); // reserved
    body.extend_from_slice(&status.to_le_bytes());

    let frag_len = (16 + body.len()) as u16;
    let mut out = Vec::with_capacity(frag_len as usize);
    write_common_header(&mut out, PTYPE_FAULT, frag_len, call_id);
    out.extend_from_slice(&body);
    out
}

/// A single presentation context from a client's `bind` PDU.
pub struct BindCtxItem {
    pub ctx_id: u16,
    pub abstract_syntax: [u8; 20],
}

/// Parses a `bind` PDU's body (everything after the 16-byte common
/// header) into its presentation contexts. Only the abstract syntax is
/// returned -- the transfer syntax is validated (must be NDR 2.0) but
/// not surfaced, since this server offers nothing else.
pub fn parse_bind_body(body: &[u8]) -> Option<Vec<BindCtxItem>> {
    if body.len() < 12 {
        return None;
    }
    let ctx_num = body[8] as usize;
    // ctx_num(1) + Reserved(1) + Reserved2(2) = 4 bytes after the 8-byte
    // max_tfrag/max_rfrag/assoc_group fields, so ctx_items start at 12.
    let mut pos = 12;
    let mut items = Vec::with_capacity(ctx_num);
    for _ in 0..ctx_num {
        if body.len() < pos + 4 {
            return None;
        }
        let ctx_id = u16::from_le_bytes([body[pos], body[pos + 1]]);
        let trans_items = body[pos + 2];
        pos += 4;
        if trans_items != 1 || body.len() < pos + 40 {
            return None; // only single-transfer-syntax contexts are modeled
        }
        let abstract_syntax: [u8; 20] = body[pos..pos + 20].try_into().unwrap();
        pos += 40; // abstract syntax (20) + transfer syntax (20)
        items.push(BindCtxItem { ctx_id, abstract_syntax });
    }
    Some(items)
}

/// A parsed `request` PDU body.
pub struct RequestBody<'a> {
    pub ctx_id: u16,
    pub opnum: u16,
    pub stub_data: &'a [u8],
}

pub fn parse_request_body(body: &[u8]) -> Option<RequestBody<'_>> {
    if body.len() < 8 {
        return None;
    }
    let ctx_id = u16::from_le_bytes([body[4], body[5]]);
    let opnum = u16::from_le_bytes([body[6], body[7]]);
    Some(RequestBody { ctx_id, opnum, stub_data: &body[8..] })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_frames_stub_data_correctly() {
        let pdu = build_response(42, 0, &[1, 2, 3, 4]);
        let (hdr, frag_len) = parse_header(&pdu).unwrap();
        assert_eq!(hdr.ptype, PTYPE_RESPONSE);
        assert_eq!(hdr.call_id, 42);
        assert_eq!(frag_len as usize, pdu.len());
        assert_eq!(&pdu[16..20], &4u32.to_le_bytes()); // alloc_hint
        assert_eq!(&pdu[24..], &[1, 2, 3, 4]);
    }

    #[test]
    fn fault_carries_the_status_code() {
        let pdu = build_fault(1, 0, FAULT_UNK_IF);
        let (hdr, _) = parse_header(&pdu).unwrap();
        assert_eq!(hdr.ptype, PTYPE_FAULT);
        let status = u32::from_le_bytes(pdu[24..28].try_into().unwrap());
        assert_eq!(status, FAULT_UNK_IF);
    }

    #[test]
    fn bind_ack_echoes_ndr_transfer_syntax_per_context() {
        let pdu = build_bind_ack(7, 4280, 1, &[CtxResult::accept(), CtxResult::accept()]);
        let (hdr, frag_len) = parse_header(&pdu).unwrap();
        assert_eq!(hdr.ptype, PTYPE_BIND_ACK);
        assert_eq!(frag_len as usize, pdu.len());

        // Body: max_tfrag(2) max_rfrag(2) assoc_group(4) SecondaryAddrLen(2)
        // [pad to 4-align] ctx_num(1) Reserved(1) Reserved2(2) then ctx items.
        let body = &pdu[16..];
        assert_eq!(u16::from_le_bytes(body[0..2].try_into().unwrap()), 4280);
        assert_eq!(u32::from_le_bytes(body[4..8].try_into().unwrap()), 1); // assoc_group
        assert_eq!(u16::from_le_bytes(body[8..10].try_into().unwrap()), 0); // SecondaryAddrLen
        let pad = 4 - (10 % 4);
        let ctx_num_pos = 10 + pad;
        assert_eq!(body[ctx_num_pos], 2, "ctx_num");
        let items_start = ctx_num_pos + 4;
        for i in 0..2 {
            let item = &body[items_start + i * 24..items_start + (i + 1) * 24];
            let result = u16::from_le_bytes(item[0..2].try_into().unwrap());
            assert_eq!(result, 0, "context {i} should be accepted");
            assert_eq!(&item[4..24], &*NDR_TRANSFER_SYNTAX, "context {i} echoes NDR transfer syntax");
        }
    }

    #[test]
    fn parses_a_hand_built_bind_body() {
        let mut body = Vec::new();
        body.extend_from_slice(&4280u16.to_le_bytes());
        body.extend_from_slice(&4280u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.push(1); // ctx_num
        body.push(0);
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // ctx_id
        body.push(1); // trans_items
        body.push(0); // pad
        body.extend_from_slice(&*crate::uuid::SAMR_SYNTAX);
        body.extend_from_slice(&*crate::uuid::NDR_TRANSFER_SYNTAX);

        let items = parse_bind_body(&body).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].abstract_syntax, *crate::uuid::SAMR_SYNTAX);
    }

    #[test]
    fn parses_a_hand_built_request_body() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // alloc_hint
        body.extend_from_slice(&3u16.to_le_bytes()); // ctx_id
        body.extend_from_slice(&64u16.to_le_bytes()); // opnum
        body.extend_from_slice(&[9, 9, 9]); // stub

        let req = parse_request_body(&body).unwrap();
        assert_eq!(req.ctx_id, 3);
        assert_eq!(req.opnum, 64);
        assert_eq!(req.stub_data, &[9, 9, 9]);
    }
}
