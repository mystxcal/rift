//! Authenticated TLS and HTTP upgrade for the RIFT WebSocket transport.

use std::{fmt, io, str::FromStr, time::Duration};

use asupersync::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{
        TcpStream, TcpStreamBuilder,
        websocket::{
            ClientHandshake, HandshakeError, HttpRequest, HttpResponse, ServerHandshake, WsUrl,
        },
    },
    time::{timeout, wall_now},
    tls::{TlsAcceptor, TlsConnector, TlsError, TlsStream},
    util::OsEntropy,
};
use thiserror::Error;

use crate::{RIFT_WEBSOCKET_PATH, RIFT_WEBSOCKET_PROTOCOL, WebSocketByteStream, WebSocketRole};

const HTTP_HEADER_LIMIT_BYTES: usize = 16 * 1024;
const HTTP_READ_CHUNK_BYTES: usize = 2 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_11_ALPN: &[u8] = b"http/1.1";

/// Validated public RIFT relay endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WssEndpoint {
    url: String,
    parsed: WsUrl,
}

impl WssEndpoint {
    /// Original canonical URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// TLS server name used for certificate validation.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.parsed.host
    }

    /// TCP port used by the endpoint.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.parsed.port
    }
}

impl fmt::Display for WssEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.url)
    }
}

impl FromStr for WssEndpoint {
    type Err = WssError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = WsUrl::parse(value)?;
        if !parsed.tls {
            return Err(WssError::InvalidEndpoint(
                "public relay endpoints must use wss://".to_owned(),
            ));
        }
        if parsed.path != RIFT_WEBSOCKET_PATH {
            return Err(WssError::InvalidEndpoint(format!(
                "relay path must be {RIFT_WEBSOCKET_PATH}"
            )));
        }
        Ok(Self {
            url: value.to_owned(),
            parsed,
        })
    }
}

/// TLS-upgraded, RFC 6455-framed RIFT relay byte stream.
pub type WssStream = WebSocketByteStream<TlsStream<TcpStream>>;

/// WSS connection or upgrade failure.
#[derive(Debug, Error)]
pub enum WssError {
    /// Endpoint violates RIFT's canonical public transport contract.
    #[error("invalid RIFT relay endpoint: {0}")]
    InvalidEndpoint(String),
    /// TCP or upgraded transport I/O failed.
    #[error("RIFT relay I/O failed: {0}")]
    Io(#[from] io::Error),
    /// TLS authentication or negotiation failed.
    #[error("RIFT relay TLS failed: {0}")]
    Tls(#[from] TlsError),
    /// HTTP/WebSocket upgrade was malformed or unauthenticated.
    #[error("RIFT relay WebSocket upgrade failed: {0}")]
    Handshake(#[from] HandshakeError),
    /// Opening handshake exceeded its fixed total deadline.
    #[error("RIFT relay WebSocket upgrade timed out")]
    Timeout,
}

/// Connect to a public RIFT relay using CA-authenticated TLS.
///
/// # Errors
///
/// Returns for DNS/TCP/TLS failures, a bounded HTTP upgrade failure, or a
/// relay that does not explicitly negotiate the RIFT subprotocol.
pub async fn connect_wss(endpoint: &WssEndpoint) -> Result<WssStream, WssError> {
    let connector = TlsConnector::builder()
        .with_webpki_roots()
        .alpn_protocols_required(vec![HTTP_11_ALPN.to_vec()])
        .handshake_timeout(HANDSHAKE_TIMEOUT)
        .build()?;
    connect_wss_with(endpoint, &connector).await
}

/// Connect with an explicit TLS policy, primarily for local trust roots.
///
/// # Errors
///
/// Has the same failure contract as [`connect_wss`].
pub async fn connect_wss_with(
    endpoint: &WssEndpoint,
    connector: &TlsConnector,
) -> Result<WssStream, WssError> {
    let address = if endpoint.host().contains(':') {
        format!("[{}]:{}", endpoint.host(), endpoint.port())
    } else {
        format!("{}:{}", endpoint.host(), endpoint.port())
    };
    let tcp = TcpStreamBuilder::new(address)
        .connect_timeout(HANDSHAKE_TIMEOUT)
        .nodelay(true)
        .connect()
        .await?;
    let mut tls = connector.connect(endpoint.host(), tcp).await?;
    let handshake =
        ClientHandshake::new(endpoint.as_str(), &OsEntropy)?.protocol(RIFT_WEBSOCKET_PROTOCOL);
    tls.write_all(&handshake.request_bytes()).await?;
    tls.flush().await?;
    let response_bytes = read_http_headers(&mut tls).await?;
    let header_bytes = header_end(&response_bytes).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "incomplete WebSocket response")
    })?;
    let response = HttpResponse::parse(&response_bytes[..header_bytes])?;
    let trailing = response_bytes[header_bytes..].to_vec();
    handshake.validate_response(&response)?;
    if response.header("sec-websocket-protocol") != Some(RIFT_WEBSOCKET_PROTOCOL) {
        return Err(WssError::InvalidEndpoint(
            "relay did not negotiate the required rift.v1 subprotocol".to_owned(),
        ));
    }
    Ok(WebSocketByteStream::with_trailing(
        tls,
        WebSocketRole::Client,
        &trailing,
    ))
}

/// Authenticate TLS and upgrade one accepted TCP connection to RIFT WSS.
///
/// # Errors
///
/// Returns for TLS, bounded HTTP parsing, canonical path, subprotocol, or
/// response-write failures. Invalid HTTP requests receive a bounded rejection.
pub async fn accept_wss(tcp: TcpStream, acceptor: &TlsAcceptor) -> Result<WssStream, WssError> {
    tcp.set_nodelay(true)?;
    let mut tls = acceptor.accept(tcp).await?;
    let request_bytes = read_http_headers(&mut tls).await?;
    let (request, trailing) = match HttpRequest::parse_with_trailing(&request_bytes) {
        Ok(parsed) => parsed,
        Err(error) => {
            tls.write_all(&ServerHandshake::reject(400, "Bad Request"))
                .await?;
            tls.flush().await?;
            return Err(error.into());
        }
    };
    if request.path != RIFT_WEBSOCKET_PATH {
        tls.write_all(&ServerHandshake::reject(404, "Not Found"))
            .await?;
        tls.flush().await?;
        return Err(WssError::InvalidEndpoint(
            "request used a non-RIFT relay path".to_owned(),
        ));
    }
    let handshake = ServerHandshake::new().protocol(RIFT_WEBSOCKET_PROTOCOL);
    let accepted = match handshake.accept(&request) {
        Ok(accepted) => accepted,
        Err(error) => {
            tls.write_all(&ServerHandshake::reject(400, "Bad WebSocket Request"))
                .await?;
            tls.flush().await?;
            return Err(error.into());
        }
    };
    if accepted.protocol.as_deref() != Some(RIFT_WEBSOCKET_PROTOCOL) {
        tls.write_all(&ServerHandshake::reject(426, "RIFT subprotocol required"))
            .await?;
        tls.flush().await?;
        return Err(WssError::InvalidEndpoint(
            "request omitted the required rift.v1 subprotocol".to_owned(),
        ));
    }
    tls.write_all(&accepted.response_bytes()).await?;
    tls.flush().await?;
    Ok(WebSocketByteStream::with_trailing(
        tls,
        WebSocketRole::Server,
        trailing,
    ))
}

async fn read_http_headers<IO>(stream: &mut IO) -> Result<Vec<u8>, WssError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let read = async {
        let mut collected = Vec::with_capacity(HTTP_READ_CHUNK_BYTES);
        let mut chunk = [0_u8; HTTP_READ_CHUNK_BYTES];
        loop {
            if header_end(&collected).is_some() {
                return Ok(collected);
            }
            if collected.len() == HTTP_HEADER_LIMIT_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WebSocket HTTP headers exceeded 16 KiB",
                ));
            }
            let allowed = (HTTP_HEADER_LIMIT_BYTES - collected.len()).min(chunk.len());
            let received = stream.read(&mut chunk[..allowed]).await?;
            if received == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection ended before WebSocket HTTP headers",
                ));
            }
            collected.extend_from_slice(&chunk[..received]);
        }
    };
    timeout(wall_now(), HANDSHAKE_TIMEOUT, read)
        .await
        .map_err(|_| WssError::Timeout)?
        .map_err(WssError::Io)
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_requires_authenticated_canonical_wss() {
        assert!("wss://relay.example/rift/v1".parse::<WssEndpoint>().is_ok());
        assert!("ws://relay.example/rift/v1".parse::<WssEndpoint>().is_err());
        assert!("wss://relay.example/other".parse::<WssEndpoint>().is_err());
        assert!(
            "wss://relay.example/rift/v1?token=no"
                .parse::<WssEndpoint>()
                .is_err()
        );
    }

    #[test]
    fn finds_only_complete_header_terminator() {
        assert_eq!(header_end(b"x\r\n\r\nmore"), Some(5));
        assert_eq!(header_end(b"x\r\n\r"), None);
    }
}
