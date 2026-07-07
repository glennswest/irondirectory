//! A stream that starts plaintext and can be upgraded to TLS in place
//! (StartTLS, RFC 4511 §4.14) without `handle_connection` needing a
//! different generic type mid-function -- Rust can't change a type
//! parameter at runtime, so the upgrade instead swaps an enum variant.
//!
//! Not used by `serve_ldaps` (implicit TLS from the first byte) -- only
//! by the plaintext listener, where a client may later ask to upgrade.

use std::pin::Pin;
use std::task::{Context, Poll};

use openssl::ssl::{Ssl, SslAcceptor};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub enum Conn<S> {
    Plain(S),
    Tls(tokio_openssl::SslStream<S>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    /// Performs the StartTLS server handshake, consuming the plaintext
    /// connection and returning the upgraded one. A no-op (returns `self`
    /// unchanged) if already TLS, rather than erroring -- the caller
    /// (session.rs) already rejects a second StartTLS request before
    /// this would ever be reached.
    pub async fn upgrade_to_tls(self, acceptor: &SslAcceptor) -> Result<Self, String> {
        let plain = match self {
            Conn::Plain(s) => s,
            tls @ Conn::Tls(_) => return Ok(tls),
        };
        let ssl = Ssl::new(acceptor.context()).map_err(|e| e.to_string())?;
        let mut stream = tokio_openssl::SslStream::new(ssl, plain).map_err(|e| e.to_string())?;
        Pin::new(&mut stream).accept().await.map_err(|e| e.to_string())?;
        Ok(Conn::Tls(stream))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Conn<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Conn::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Conn<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Conn::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_flush(cx),
            Conn::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Conn::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
