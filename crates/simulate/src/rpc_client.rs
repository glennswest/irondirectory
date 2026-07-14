//! A minimal DCE/RPC client over `ncacn_ip_tcp`, built on `iron_rpc`'s
//! PDU/NDR primitives (#23) -- the counterpart to `iron_rpc::server`'s
//! server-side connection handling. One presentation-context bind per
//! connection, matching `iron-rpcd`'s own one-bind-per-connection model.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, thiserror::Error)]
pub enum RpcClientError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("server rejected the bind (interface not supported)")]
    BindRejected,
    #[error("malformed PDU from server")]
    Malformed,
    #[error("RPC fault: NCA status 0x{0:08x}")]
    Fault(u32),
    #[error("connection closed unexpectedly")]
    ConnectionClosed,
}

pub struct RpcClient {
    stream: TcpStream,
    call_id: u32,
    ctx_id: u16,
}

impl RpcClient {
    /// Connects to `addr` and binds `abstract_syntax` (one presentation
    /// context, ctx_id 0) against the NDR transfer syntax.
    pub async fn connect(addr: &str, abstract_syntax: [u8; 20]) -> Result<Self, RpcClientError> {
        let mut stream = TcpStream::connect(addr).await?;
        let ctx_id = 0u16;
        let bind_pdu = iron_rpc::pdu::build_bind(1, 4280, &[(ctx_id, abstract_syntax)]);
        stream.write_all(&bind_pdu).await?;

        let resp = read_pdu(&mut stream).await?;
        let (hdr, _) = iron_rpc::pdu::parse_header(&resp).map_err(|_| RpcClientError::Malformed)?;
        if hdr.ptype != iron_rpc::pdu::PTYPE_BIND_ACK {
            return Err(RpcClientError::BindRejected);
        }
        let accepted = iron_rpc::pdu::parse_bind_ack_all_accepted(&resp[16..]).ok_or(RpcClientError::Malformed)?;
        if !accepted {
            return Err(RpcClientError::BindRejected);
        }

        Ok(RpcClient { stream, call_id: 2, ctx_id })
    }

    /// Makes one RPC call: sends `stub` (the NDR-encoded request
    /// parameters) as `opnum`'s request, returns the response's stub
    /// data (the NDR-encoded return values) or the fault status code.
    pub async fn call(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, RpcClientError> {
        let call_id = self.call_id;
        self.call_id += 1;
        let req = iron_rpc::pdu::build_request(call_id, self.ctx_id, opnum, stub);
        self.stream.write_all(&req).await?;

        let resp = read_pdu(&mut self.stream).await?;
        let (hdr, _) = iron_rpc::pdu::parse_header(&resp).map_err(|_| RpcClientError::Malformed)?;
        match iron_rpc::pdu::parse_response_body(hdr.ptype, &resp[16..]) {
            Some(Ok(stub)) => Ok(stub.to_vec()),
            Some(Err(status)) => Err(RpcClientError::Fault(status)),
            None => Err(RpcClientError::Malformed),
        }
    }
}

async fn read_pdu(stream: &mut TcpStream) -> Result<Vec<u8>, RpcClientError> {
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).await.map_err(|_| RpcClientError::ConnectionClosed)?;
    let frag_len = u16::from_le_bytes([header[8], header[9]]) as usize;
    if frag_len < 16 {
        return Err(RpcClientError::Malformed);
    }
    let mut rest = vec![0u8; frag_len - 16];
    stream.read_exact(&mut rest).await?;
    let mut pdu = header.to_vec();
    pdu.extend_from_slice(&rest);
    Ok(pdu)
}
