//! Client-side admission to a blind live relay.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};

use asupersync::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    tls::TlsConnector,
};
use rift_protocol::{
    Capability, JOIN_ACK_BYTES, JoinPrelude, JoinStatus, ROUTE_BUNDLE_HEADER_BYTES,
    RendezvousError, RendezvousRole, RouteBundle, RouteBundleError, route_bundle_encoded_len,
};
use rift_transport::{WssEndpoint, WssError, WssStream, connect_wss, connect_wss_with};
use thiserror::Error;
use zeroize::Zeroizing;

/// One accepted relay locator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayEndpoint {
    /// Raw TCP oracle, deliberately restricted to the local machine.
    Loopback(SocketAddr),
    /// CA-authenticated public WebSocket transport.
    Wss(WssEndpoint),
}

impl From<SocketAddr> for RelayEndpoint {
    fn from(address: SocketAddr) -> Self {
        Self::Loopback(address)
    }
}

impl FromStr for RelayEndpoint {
    type Err = RelayClientError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = value.parse::<SocketAddr>() {
            if address.ip().is_loopback() {
                return Ok(Self::Loopback(address));
            }
            return Err(RelayClientError::InvalidEndpoint(
                "raw relay sockets are restricted to loopback".to_owned(),
            ));
        }
        value
            .parse::<WssEndpoint>()
            .map(Self::Wss)
            .map_err(RelayClientError::Wss)
    }
}

/// One relay endpoint together with its explicit client-side TLS policy.
///
/// The ordinary constructor uses RIFT's public-root policy. An explicit
/// connector is accepted only for WSS endpoints, which lets private relays use
/// a locally administered CA without weakening the loopback-only raw path.
#[derive(Clone)]
pub struct RelayDialer {
    endpoint: RelayEndpoint,
    tls: Option<TlsConnector>,
}

impl RelayDialer {
    /// Use the endpoint's normal trust policy.
    #[must_use]
    pub const fn new(endpoint: RelayEndpoint) -> Self {
        Self {
            endpoint,
            tls: None,
        }
    }

    /// Use one explicit CA-authenticated TLS policy for a WSS endpoint.
    ///
    /// # Errors
    ///
    /// Raw loopback TCP has no TLS layer and therefore rejects a connector.
    pub fn with_tls(endpoint: RelayEndpoint, tls: TlsConnector) -> Result<Self, RelayClientError> {
        if !matches!(endpoint, RelayEndpoint::Wss(_)) {
            return Err(RelayClientError::InvalidEndpoint(
                "an explicit TLS policy requires a WSS relay".to_owned(),
            ));
        }
        Ok(Self {
            endpoint,
            tls: Some(tls),
        })
    }

    /// Endpoint shared by stream admission and UDP rendezvous.
    #[must_use]
    pub const fn endpoint(&self) -> &RelayEndpoint {
        &self.endpoint
    }
}

impl From<RelayEndpoint> for RelayDialer {
    fn from(endpoint: RelayEndpoint) -> Self {
        Self::new(endpoint)
    }
}

enum RelayStreamInner {
    /// Local raw TCP oracle.
    Loopback(TcpStream),
    /// Public authenticated WSS path.
    Wss(Box<WssStream>),
}

/// Ordered path returned by relay admission together with optional network
/// acceleration routes issued for this exact live match.
pub struct RelayStream {
    inner: RelayStreamInner,
    routes: Option<RouteBundle>,
}

impl RelayStream {
    /// Provider-independent routes delivered by the relay for this match.
    #[must_use]
    pub const fn routes(&self) -> Option<&RouteBundle> {
        self.routes.as_ref()
    }

    pub(crate) fn take_routes(&mut self) -> Option<RouteBundle> {
        self.routes.take()
    }
}

impl AsyncRead for RelayStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            RelayStreamInner::Loopback(stream) => Pin::new(stream).poll_read(cx, buffer),
            RelayStreamInner::Wss(stream) => Pin::new(stream.as_mut()).poll_read(cx, buffer),
        }
    }
}

impl AsyncWrite for RelayStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            RelayStreamInner::Loopback(stream) => Pin::new(stream).poll_write(cx, buffer),
            RelayStreamInner::Wss(stream) => Pin::new(stream.as_mut()).poll_write(cx, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            RelayStreamInner::Loopback(stream) => Pin::new(stream).poll_flush(cx),
            RelayStreamInner::Wss(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            RelayStreamInner::Loopback(stream) => Pin::new(stream).poll_shutdown(cx),
            RelayStreamInner::Wss(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Relay connection or admission failure.
#[derive(Debug, Error)]
pub enum RelayClientError {
    /// Raw TCP path could not be established or failed during admission.
    #[error("relay connection failed: {0}")]
    Io(#[from] io::Error),
    /// Authenticated WSS transport failed.
    #[error(transparent)]
    Wss(#[from] WssError),
    /// Relay endpoint is not one of RIFT's safe transport forms.
    #[error("invalid relay endpoint: {0}")]
    InvalidEndpoint(String),
    /// Relay emitted a malformed response.
    #[error(transparent)]
    Protocol(#[from] RendezvousError),
    /// Relay route bootstrap was malformed or exceeded its fixed bounds.
    #[error(transparent)]
    RouteBundle(#[from] RouteBundleError),
    /// Relay declined this connection with an explicit bounded status.
    #[error("relay declined the connection: {0:?}")]
    Declined(JoinStatus),
}

/// Exclusively reserved sender-side relay stream awaiting its receiver.
pub struct SenderReservation {
    stream: RelayStream,
    endpoint: RelayEndpoint,
    dialer: RelayDialer,
}

impl SenderReservation {
    /// Relay endpoint shared by stream admission and UDP rendezvous.
    #[must_use]
    pub fn endpoint(&self) -> &RelayEndpoint {
        &self.endpoint
    }

    pub(crate) fn dialer(&self) -> RelayDialer {
        self.dialer.clone()
    }

    /// Wait until the relay has atomically consumed the complementary receiver.
    ///
    /// # Errors
    ///
    /// Returns for path I/O, a malformed relay response, expiry, or shutdown.
    pub async fn wait_matched(mut self) -> Result<RelayStream, RelayClientError> {
        expect_matched(&mut self.stream).await?;
        Ok(self.stream)
    }
}

/// Connect, disclose only lookup and role, and wait for a complementary peer.
///
/// # Errors
///
/// Returns for path I/O, malformed relay responses, or non-matched status.
pub async fn connect_relay(
    address: SocketAddr,
    capability: &Capability,
    role: RendezvousRole,
) -> Result<RelayStream, RelayClientError> {
    connect_relay_lookup(address, *capability.lookup_id(), role).await
}

/// Reserve a sender lookup on a local development relay.
///
/// # Errors
///
/// Returns unless the relay confirms exclusive ownership with `Reserved`.
pub async fn reserve_sender_relay(
    address: SocketAddr,
    lookup_id: [u8; 16],
) -> Result<SenderReservation, RelayClientError> {
    reserve_sender_endpoint(address.into(), lookup_id).await
}

/// Reserve a sender lookup on either safe relay transport.
///
/// # Errors
///
/// Returns unless the endpoint is valid and grants exclusive ownership.
pub async fn reserve_sender_endpoint(
    endpoint: RelayEndpoint,
    lookup_id: [u8; 16],
) -> Result<SenderReservation, RelayClientError> {
    reserve_sender_with(RelayDialer::new(endpoint), lookup_id).await
}

/// Reserve a sender lookup with an explicit relay dialing policy.
///
/// # Errors
///
/// Returns unless the dialer is valid and grants exclusive ownership.
pub async fn reserve_sender_with(
    dialer: RelayDialer,
    lookup_id: [u8; 16],
) -> Result<SenderReservation, RelayClientError> {
    let endpoint = dialer.endpoint.clone();
    let mut stream = join_relay(&dialer, lookup_id, RendezvousRole::Sender).await?;
    let status = read_status(&mut stream).await?;
    if status != JoinStatus::Reserved {
        return Err(RelayClientError::Declined(status));
    }
    Ok(SenderReservation {
        stream,
        endpoint,
        dialer,
    })
}

/// Connect by an already-derived lookup on a local development relay.
///
/// # Errors
///
/// Returns for path I/O, malformed relay responses, or declined admission.
pub async fn connect_relay_lookup(
    address: SocketAddr,
    lookup_id: [u8; 16],
    role: RendezvousRole,
) -> Result<RelayStream, RelayClientError> {
    connect_relay_lookup_endpoint(address.into(), lookup_id, role).await
}

/// Connect by an already-derived lookup on either safe relay transport.
///
/// # Errors
///
/// Returns for endpoint, path, protocol, or admission failure.
pub async fn connect_relay_lookup_endpoint(
    endpoint: RelayEndpoint,
    lookup_id: [u8; 16],
    role: RendezvousRole,
) -> Result<RelayStream, RelayClientError> {
    connect_relay_lookup_with(&RelayDialer::new(endpoint), lookup_id, role).await
}

/// Connect by an already-derived lookup with an explicit dialing policy.
///
/// # Errors
///
/// Returns for endpoint, path, protocol, or admission failure.
pub async fn connect_relay_lookup_with(
    dialer: &RelayDialer,
    lookup_id: [u8; 16],
    role: RendezvousRole,
) -> Result<RelayStream, RelayClientError> {
    let mut stream = join_relay(dialer, lookup_id, role).await?;
    let status = read_status(&mut stream).await?;
    match status {
        JoinStatus::Matched => Ok(stream),
        JoinStatus::MatchedWithRoutes => {
            read_route_bundle(&mut stream).await?;
            Ok(stream)
        }
        JoinStatus::Reserved => {
            expect_matched(&mut stream).await?;
            Ok(stream)
        }
        declined => Err(RelayClientError::Declined(declined)),
    }
}

async fn join_relay(
    dialer: &RelayDialer,
    lookup_id: [u8; 16],
    role: RendezvousRole,
) -> Result<RelayStream, RelayClientError> {
    let mut stream = match &dialer.endpoint {
        RelayEndpoint::Loopback(address) => {
            if !address.ip().is_loopback() {
                return Err(RelayClientError::InvalidEndpoint(
                    "raw relay sockets are restricted to loopback".to_owned(),
                ));
            }
            RelayStream {
                inner: RelayStreamInner::Loopback(TcpStream::connect(*address).await?),
                routes: None,
            }
        }
        RelayEndpoint::Wss(endpoint) => {
            let stream = if let Some(tls) = &dialer.tls {
                connect_wss_with(endpoint, tls).await?
            } else {
                connect_wss(endpoint).await?
            };
            RelayStream {
                inner: RelayStreamInner::Wss(Box::new(stream)),
                routes: None,
            }
        }
    };
    let prelude = JoinPrelude { lookup_id, role };
    stream.write_all(&prelude.encode()).await?;
    stream.flush().await?;
    Ok(stream)
}

async fn expect_matched(stream: &mut RelayStream) -> Result<(), RelayClientError> {
    let status = read_status(stream).await?;
    match status {
        JoinStatus::Matched => Ok(()),
        JoinStatus::MatchedWithRoutes => read_route_bundle(stream).await,
        declined => Err(RelayClientError::Declined(declined)),
    }
}

async fn read_route_bundle(stream: &mut RelayStream) -> Result<(), RelayClientError> {
    let mut header = [0_u8; ROUTE_BUNDLE_HEADER_BYTES];
    stream.read_exact(&mut header).await?;
    let encoded_len = route_bundle_encoded_len(&header)?;
    let mut encoded = Zeroizing::new(vec![0_u8; encoded_len]);
    encoded[..ROUTE_BUNDLE_HEADER_BYTES].copy_from_slice(&header);
    stream
        .read_exact(&mut encoded[ROUTE_BUNDLE_HEADER_BYTES..])
        .await?;
    stream.routes = Some(RouteBundle::decode(encoded)?);
    Ok(())
}

async fn read_status<S>(stream: &mut S) -> Result<JoinStatus, RelayClientError>
where
    S: AsyncRead + Unpin,
{
    let mut encoded = [0_u8; JOIN_ACK_BYTES];
    stream.read_exact(&mut encoded).await?;
    JoinStatus::decode(&encoded).map_err(RelayClientError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parser_rejects_public_raw_tcp_and_plain_websocket() {
        assert!("127.0.0.1:7337".parse::<RelayEndpoint>().is_ok());
        assert!("192.0.2.1:7337".parse::<RelayEndpoint>().is_err());
        assert!(
            "ws://relay.example/rift/v1"
                .parse::<RelayEndpoint>()
                .is_err()
        );
        assert!(
            "wss://relay.example/rift/v1"
                .parse::<RelayEndpoint>()
                .is_ok()
        );
    }

    #[test]
    fn explicit_tls_policy_cannot_be_attached_to_raw_loopback() {
        let connector = TlsConnector::builder().with_webpki_roots().build().unwrap();
        let endpoint = "127.0.0.1:7337".parse::<RelayEndpoint>().unwrap();
        assert!(matches!(
            RelayDialer::with_tls(endpoint, connector),
            Err(RelayClientError::InvalidEndpoint(_))
        ));
    }
}
