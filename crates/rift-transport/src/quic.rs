//! Runtime-neutral QUIC protocol state driven by explicit datagram and time events.
//!
//! This module deliberately uses `quinn-proto` rather than a runtime-bearing
//! QUIC facade. RIFT owns socket readiness, timers, task lifetime, and path
//! selection through asupersync; QUIC owns packet protection, congestion,
//! pacing, loss recovery, flow control, and stream ordering.

use std::{collections::VecDeque, net::IpAddr, net::SocketAddr, sync::Arc, time::Instant};

use bytes::{Bytes, BytesMut};
use quinn_proto::{
    ClientConfig, ConnectError, Connection, ConnectionError, ConnectionHandle, DatagramEvent, Dir,
    EcnCodepoint, Endpoint, EndpointConfig, Event, FinishError, ReadError, ReadableError,
    ServerConfig, StreamId, TransportConfig, VarInt, WriteError,
    crypto::rustls::{NoInitialCipherSuite, QuicClientConfig, QuicServerConfig},
    rustls::{
        self, RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use thiserror::Error;

const MAX_GSO_DATAGRAMS: usize = 64;
const RIFT_QUIC_SERVER_NAME: &str = "rift.invalid";
const RIFT_QUIC_ALPN: &[u8] = b"rift/1";
const QUIC_STREAM_WINDOW_BYTES: u32 = 64 * 1024 * 1024;
const QUIC_CONNECTION_WINDOW_BYTES: u32 = 128 * 1024 * 1024;

/// Bounded transport evidence exposed to RIFT's completion controller.
///
/// This is deliberately a small, stable projection rather than the QUIC
/// implementation's complete statistics structure.  Object scheduling may
/// consume transport evidence, but it must not become coupled to one QUIC
/// engine's internal types.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuicPathStats {
    /// Current smoothed round-trip estimate.
    pub rtt_us: u64,
    /// Current congestion window in bytes.
    pub congestion_window: u64,
    /// UDP payload bytes emitted by this endpoint.
    pub sent_bytes: u64,
    /// UDP payload bytes accepted by this endpoint.
    pub received_bytes: u64,
    /// Payload bytes declared lost by QUIC.
    pub lost_bytes: u64,
    /// Packets emitted on the current path.
    pub sent_packets: u64,
    /// Packets declared lost on the current path.
    pub lost_packets: u64,
    /// Congestion events observed on the current path.
    pub congestion_events: u64,
}

/// One ephemeral server certificate and private key for a live RIFT transfer.
///
/// The public certificate is sent only inside the authenticated pairing
/// channel. The peer pins that exact certificate; no ambient PKI or insecure
/// certificate bypass is involved.
#[derive(Clone)]
pub struct QuicServerIdentity {
    certificate: CertificateDer<'static>,
    config: ServerConfig,
}

impl std::fmt::Debug for QuicServerIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuicServerIdentity")
            .field("certificate_bytes", &self.certificate.len())
            .finish_non_exhaustive()
    }
}

impl QuicServerIdentity {
    /// Generate one transfer-scoped identity and high-throughput server config.
    ///
    /// # Errors
    ///
    /// Returns for operating-system entropy, certificate generation, TLS
    /// configuration, or an unavailable mandatory QUIC cipher suite.
    pub fn generate() -> Result<Self, QuicIdentityError> {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![RIFT_QUIC_SERVER_NAME.to_owned()])?;
        let certificate = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)?;
        tls.alpn_protocols = vec![RIFT_QUIC_ALPN.to_vec()];
        tls.max_early_data_size = u32::MAX;
        let crypto = QuicServerConfig::try_from(tls)?;
        let mut config = ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(transfer_transport_config());
        Ok(Self {
            certificate,
            config,
        })
    }

    /// Exact DER certificate bytes to exchange through authenticated control.
    #[must_use]
    pub fn certificate(&self) -> Bytes {
        Bytes::copy_from_slice(self.certificate.as_ref())
    }

    /// Clone the server config for one listening endpoint.
    #[must_use]
    pub fn server_config(&self) -> ServerConfig {
        self.config.clone()
    }
}

/// Build a client config that trusts exactly one authenticated peer certificate.
///
/// # Errors
///
/// Returns for malformed certificate bytes, TLS configuration, or an
/// unavailable mandatory QUIC cipher suite.
pub fn pinned_client_config(certificate: &[u8]) -> Result<ClientConfig, QuicIdentityError> {
    let certificate = CertificateDer::from(certificate.to_vec());
    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![RIFT_QUIC_ALPN.to_vec()];
    let crypto = QuicClientConfig::try_from(tls)?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(transfer_transport_config());
    Ok(config)
}

fn transfer_transport_config() -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_uni_streams(VarInt::from_u32(16))
        .stream_receive_window(VarInt::from_u32(QUIC_STREAM_WINDOW_BYTES))
        .receive_window(VarInt::from_u32(QUIC_CONNECTION_WINDOW_BYTES))
        .send_window(u64::from(QUIC_CONNECTION_WINDOW_BYTES));
    Arc::new(transport)
}

/// Ephemeral QUIC identity or TLS configuration failure.
#[derive(Debug, Error)]
pub enum QuicIdentityError {
    /// Ephemeral certificate generation failed.
    #[error("could not generate the ephemeral QUIC identity: {0}")]
    Certificate(#[from] rcgen::Error),
    /// Rustls rejected certificate or TLS configuration.
    #[error("invalid ephemeral QUIC TLS configuration: {0}")]
    Tls(#[from] rustls::Error),
    /// The mandatory QUIC initial cipher suite was unavailable.
    #[error("mandatory QUIC initial cipher suite is unavailable: {0}")]
    Cipher(#[from] NoInitialCipherSuite),
}

/// Pinned-identity setup or connection bootstrap failure.
#[derive(Debug, Error)]
pub enum QuicBootstrapError {
    /// Peer certificate or TLS configuration was invalid.
    #[error(transparent)]
    Identity(#[from] QuicIdentityError),
    /// The client endpoint could not begin its connection.
    #[error(transparent)]
    Engine(#[from] QuicEngineError),
}

/// QUIC endpoint role for one live RIFT session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicRole {
    /// Initiates the authenticated transport connection.
    Client,
    /// Accepts exactly one authenticated transport connection.
    Server,
}

/// One transport datagram emitted by the deterministic QUIC state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicDatagram {
    /// Logical remote address. A path adapter may map this through TURN.
    pub destination: SocketAddr,
    /// Explicit congestion notification selected by the QUIC controller.
    pub ecn: Option<EcnCodepoint>,
    /// Optional source address requested for a multi-homed socket.
    pub source_ip: Option<IpAddr>,
    /// One UDP payload, or consecutive equal-sized GSO payloads.
    pub payload: Bytes,
    /// GSO segment size when `payload` contains multiple datagrams.
    pub segment_size: Option<usize>,
}

impl QuicDatagram {
    /// Split a GSO aggregate into the logical UDP datagrams seen by a peer.
    #[must_use]
    pub fn into_segments(self) -> Vec<QuicDatagram> {
        let Some(segment_size) = self.segment_size else {
            return vec![self];
        };
        if segment_size == 0 || self.payload.len() <= segment_size {
            return vec![QuicDatagram {
                segment_size: None,
                ..self
            }];
        }

        let mut payload = self.payload;
        let mut segments = Vec::with_capacity(payload.len().div_ceil(segment_size));
        while !payload.is_empty() {
            let length = payload.len().min(segment_size);
            segments.push(QuicDatagram {
                destination: self.destination,
                ecn: self.ecn,
                source_ip: self.source_ip,
                payload: payload.split_to(length),
                segment_size: None,
            });
        }
        segments
    }
}

/// Runtime-independent QUIC state-machine failure.
#[derive(Debug, Error)]
pub enum QuicEngineError {
    /// Client connection parameters were invalid before any packet was sent.
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// Server could not accept a syntactically valid initial datagram.
    #[error("QUIC accept failed: {0}")]
    Accept(ConnectionError),
    /// An event referenced a connection other than the endpoint's live peer.
    #[error("QUIC event referenced an unknown connection")]
    UnknownConnection,
    /// Application I/O was attempted before a connection existed.
    #[error("QUIC connection is not established")]
    NoConnection,
}

/// One single-peer QUIC endpoint with no sockets, clock, or spawned tasks.
///
/// Incoming datagrams and timer expirations are explicit inputs. Outgoing
/// datagrams, application events, and the next deadline are explicit outputs.
/// This lets the same connection run over direct UDP, TURN, or a deterministic
/// lab path without changing its congestion or stream state.
pub struct QuicEngine {
    role: QuicRole,
    endpoint: Endpoint,
    connection: Option<(ConnectionHandle, Connection)>,
    pending_datagrams: VecDeque<QuicDatagram>,
    scratch: Vec<u8>,
}

impl QuicEngine {
    /// Begin a client connection authenticated by an exact peer certificate.
    ///
    /// # Errors
    ///
    /// Returns for invalid authenticated certificate material or connection
    /// bootstrap failure.
    pub fn connect_pinned(
        now: Instant,
        remote: SocketAddr,
        certificate: &[u8],
    ) -> Result<Self, QuicBootstrapError> {
        Ok(Self::connect(
            Arc::new(EndpointConfig::default()),
            pinned_client_config(certificate)?,
            now,
            remote,
            RIFT_QUIC_SERVER_NAME,
        )?)
    }

    /// Create a server endpoint from one transfer-scoped identity.
    #[must_use]
    pub fn listen_identity(identity: &QuicServerIdentity) -> Self {
        Self::listen(
            Arc::new(EndpointConfig::default()),
            identity.server_config(),
        )
    }

    /// Create a client endpoint and begin one connection to `remote`.
    ///
    /// # Errors
    ///
    /// Returns when the endpoint, address, server name, or crypto configuration
    /// cannot initiate a QUIC connection.
    pub fn connect(
        endpoint_config: Arc<EndpointConfig>,
        client_config: ClientConfig,
        now: Instant,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<Self, QuicEngineError> {
        let mut endpoint = Endpoint::new(endpoint_config, None, true, None);
        let connection = endpoint.connect(now, client_config, remote, server_name)?;
        Ok(Self {
            role: QuicRole::Client,
            endpoint,
            connection: Some(connection),
            pending_datagrams: VecDeque::new(),
            scratch: Vec::new(),
        })
    }

    /// Create a server endpoint that will accept exactly one connection.
    #[must_use]
    pub fn listen(endpoint_config: Arc<EndpointConfig>, server_config: ServerConfig) -> Self {
        Self {
            role: QuicRole::Server,
            endpoint: Endpoint::new(endpoint_config, Some(Arc::new(server_config)), true, None),
            connection: None,
            pending_datagrams: VecDeque::new(),
            scratch: Vec::new(),
        }
    }

    /// Endpoint role.
    #[must_use]
    pub const fn role(&self) -> QuicRole {
        self.role
    }

    /// Whether QUIC has completed its transport handshake.
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(|(_, connection)| !connection.is_handshaking())
    }

    /// Snapshot the current connection evidence used by upper-layer
    /// completion-time scheduling.
    #[must_use]
    pub fn path_stats(&self) -> QuicPathStats {
        let Some((_, connection)) = self.connection.as_ref() else {
            return QuicPathStats::default();
        };
        let stats = connection.stats();
        QuicPathStats {
            rtt_us: u64::try_from(stats.path.rtt.as_micros()).unwrap_or(u64::MAX),
            congestion_window: stats.path.cwnd,
            sent_bytes: stats.udp_tx.bytes,
            received_bytes: stats.udp_rx.bytes,
            lost_bytes: stats.path.lost_bytes,
            sent_packets: stats.path.sent_packets,
            lost_packets: stats.path.lost_packets,
            congestion_events: stats.path.congestion_events,
        }
    }

    /// Feed one logical UDP datagram into the endpoint.
    ///
    /// `remote` is the peer address in the logical datagram path. A TURN adapter
    /// should remove TURN framing and supply the relayed peer address here.
    ///
    /// # Errors
    ///
    /// Returns when a second peer arrives, an internal handle is inconsistent,
    /// or the server cannot accept a valid initial packet.
    pub fn handle_datagram(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local_ip: Option<IpAddr>,
        ecn: Option<EcnCodepoint>,
        payload: BytesMut,
    ) -> Result<(), QuicEngineError> {
        self.scratch.clear();
        let event = self
            .endpoint
            .handle(now, remote, local_ip, ecn, payload, &mut self.scratch);
        if let Some(event) = event {
            self.handle_datagram_event(now, event)?;
        }
        self.service_endpoint_events()?;
        Ok(())
    }

    /// Notify QUIC that its current deadline has elapsed.
    ///
    /// Calling this before the returned deadline is harmless but unnecessary.
    ///
    /// # Errors
    ///
    /// Returns only if the endpoint's single-connection invariant was broken.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), QuicEngineError> {
        let (_, connection) = self
            .connection
            .as_mut()
            .ok_or(QuicEngineError::NoConnection)?;
        connection.handle_timeout(now);
        self.service_endpoint_events()
    }

    /// Next protocol deadline, if a connection is live.
    #[must_use]
    pub fn next_timeout(&mut self) -> Option<Instant> {
        self.connection
            .as_mut()
            .and_then(|(_, connection)| connection.poll_timeout())
    }

    /// Poll one datagram that the selected path must transmit.
    ///
    /// # Errors
    ///
    /// Returns only if endpoint and connection handle state disagree.
    pub fn poll_datagram(&mut self, now: Instant) -> Result<Option<QuicDatagram>, QuicEngineError> {
        if let Some(datagram) = self.pending_datagrams.pop_front() {
            return Ok(Some(datagram));
        }
        self.service_endpoint_events()?;
        let Some((_, connection)) = self.connection.as_mut() else {
            return Ok(None);
        };
        self.scratch.clear();
        let Some(transmit) = connection.poll_transmit(now, MAX_GSO_DATAGRAMS, &mut self.scratch)
        else {
            return Ok(None);
        };
        Ok(Some(owned_datagram(&transmit, &self.scratch)))
    }

    /// Poll one application-facing connection or stream event.
    #[must_use]
    pub fn poll_event(&mut self) -> Option<Event> {
        self.connection
            .as_mut()
            .and_then(|(_, connection)| connection.poll())
    }

    /// Open one unidirectional stream when peer flow-control credit permits it.
    ///
    /// # Errors
    ///
    /// Returns when no connection exists.
    pub fn open_uni(&mut self) -> Result<Option<StreamId>, QuicEngineError> {
        let (_, connection) = self
            .connection
            .as_mut()
            .ok_or(QuicEngineError::NoConnection)?;
        Ok(connection.streams().open(Dir::Uni))
    }

    /// Accept one peer-created unidirectional stream.
    ///
    /// # Errors
    ///
    /// Returns when no connection exists.
    pub fn accept_uni(&mut self) -> Result<Option<StreamId>, QuicEngineError> {
        let (_, connection) = self
            .connection
            .as_mut()
            .ok_or(QuicEngineError::NoConnection)?;
        Ok(connection.streams().accept(Dir::Uni))
    }

    /// Queue bytes on a stream without waiting for packet or chunk acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns QUIC flow-control or stream-state errors.
    pub fn write(&mut self, stream: StreamId, bytes: &[u8]) -> Result<usize, QuicStreamWriteError> {
        self.connection
            .as_mut()
            .ok_or(QuicStreamWriteError::NoConnection)?
            .1
            .send_stream(stream)
            .write(bytes)
            .map_err(QuicStreamWriteError::Write)
    }

    /// Finish one send stream after all application bytes have been queued.
    ///
    /// # Errors
    ///
    /// Returns when the peer stopped or the stream was already closed.
    pub fn finish(&mut self, stream: StreamId) -> Result<(), QuicStreamFinishError> {
        self.connection
            .as_mut()
            .ok_or(QuicStreamFinishError::NoConnection)?
            .1
            .send_stream(stream)
            .finish()
            .map_err(QuicStreamFinishError::Finish)
    }

    /// Read one ordered stream chunk, returning `None` only at stream end.
    ///
    /// # Errors
    ///
    /// Returns `ReadableError` when the stream is not currently readable and
    /// `ReadError` for reset or invalid ordering state.
    pub fn read(
        &mut self,
        stream: StreamId,
        maximum: usize,
    ) -> Result<Option<Bytes>, QuicReadError> {
        let connection = &mut self
            .connection
            .as_mut()
            .ok_or(QuicReadError::NoConnection)?
            .1;
        let mut receive_stream = connection.recv_stream(stream);
        let mut chunks = receive_stream
            .read(true)
            .map_err(QuicReadError::NotReadable)?;
        let chunk = chunks.next(maximum).map_err(QuicReadError::Read)?;
        let _ = chunks.finalize();
        Ok(chunk.map(|chunk| chunk.bytes))
    }

    fn handle_datagram_event(
        &mut self,
        now: Instant,
        event: DatagramEvent,
    ) -> Result<(), QuicEngineError> {
        match event {
            DatagramEvent::ConnectionEvent(handle, event) => {
                let Some((owned, connection)) = self.connection.as_mut() else {
                    return Err(QuicEngineError::UnknownConnection);
                };
                if *owned != handle {
                    return Err(QuicEngineError::UnknownConnection);
                }
                connection.handle_event(event);
            }
            DatagramEvent::NewConnection(incoming) => {
                if self.connection.is_some() {
                    self.scratch.clear();
                    let transmit = self.endpoint.refuse(incoming, &mut self.scratch);
                    self.pending_datagrams
                        .push_back(owned_datagram(&transmit, &self.scratch));
                    return Ok(());
                }
                self.scratch.clear();
                match self.endpoint.accept(incoming, now, &mut self.scratch, None) {
                    Ok(connection) => self.connection = Some(connection),
                    Err(error) => {
                        if let Some(transmit) = error.response {
                            self.pending_datagrams
                                .push_back(owned_datagram(&transmit, &self.scratch));
                        }
                        return Err(QuicEngineError::Accept(error.cause));
                    }
                }
            }
            DatagramEvent::Response(transmit) => self
                .pending_datagrams
                .push_back(owned_datagram(&transmit, &self.scratch)),
        }
        Ok(())
    }

    fn service_endpoint_events(&mut self) -> Result<(), QuicEngineError> {
        loop {
            let endpoint_event = self
                .connection
                .as_mut()
                .and_then(|(_, connection)| connection.poll_endpoint_events());
            let Some(event) = endpoint_event else {
                return Ok(());
            };
            let handle = self
                .connection
                .as_ref()
                .map(|(handle, _)| *handle)
                .ok_or(QuicEngineError::NoConnection)?;
            if let Some(event) = self.endpoint.handle_event(handle, event) {
                let Some((owned, connection)) = self.connection.as_mut() else {
                    return Err(QuicEngineError::UnknownConnection);
                };
                if *owned != handle {
                    return Err(QuicEngineError::UnknownConnection);
                }
                connection.handle_event(event);
            }
        }
    }
}

/// Stream receive failure preserving QUIC's blocked-versus-terminal distinction.
#[derive(Debug, Error)]
pub enum QuicReadError {
    /// No connection exists yet.
    #[error("QUIC connection is not established")]
    NoConnection,
    /// The stream has no readable data or has already closed.
    #[error(transparent)]
    NotReadable(ReadableError),
    /// The stream was reset or its read ordering contract was violated.
    #[error(transparent)]
    Read(ReadError),
}

impl QuicReadError {
    /// Whether ordered reading can make progress only after more network input.
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        matches!(self, Self::Read(ReadError::Blocked))
    }
}

/// QUIC stream write failure.
#[derive(Debug, Error)]
pub enum QuicStreamWriteError {
    /// No connection exists yet.
    #[error("QUIC connection is not established")]
    NoConnection,
    /// QUIC flow control or stream state rejected the write.
    #[error(transparent)]
    Write(WriteError),
}

impl QuicStreamWriteError {
    /// Whether writing can make progress only after congestion or flow-control
    /// state advances.
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        matches!(self, Self::Write(WriteError::Blocked))
    }
}

/// QUIC stream finish failure.
#[derive(Debug, Error)]
pub enum QuicStreamFinishError {
    /// No connection exists yet.
    #[error("QUIC connection is not established")]
    NoConnection,
    /// The peer stopped the stream or it was already closed.
    #[error(transparent)]
    Finish(FinishError),
}

fn owned_datagram(transmit: &quinn_proto::Transmit, payload: &[u8]) -> QuicDatagram {
    QuicDatagram {
        destination: transmit.destination,
        ecn: transmit.ecn,
        source_ip: transmit.src_ip,
        payload: Bytes::copy_from_slice(&payload[..transmit.size]),
        segment_size: transmit.segment_size,
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use quinn_proto::{ClientConfig, EndpointConfig, ServerConfig};

    use super::*;

    const PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

    #[test]
    fn one_stream_queues_megabytes_without_record_ack_boundaries() {
        let (client_config, server_config) = configs();
        let server_address = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 44_443);
        let client_address = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 44_444);
        let mut now = Instant::now();
        let mut client = QuicEngine::connect(
            Arc::new(EndpointConfig::default()),
            client_config,
            now,
            server_address,
            "rift.invalid",
        )
        .unwrap();
        let mut server = QuicEngine::listen(Arc::new(EndpointConfig::default()), server_config);

        drive_until(
            &mut client,
            client_address,
            &mut server,
            server_address,
            &mut now,
            |client, server| client.is_established() && server.is_established(),
        );

        let stream = client.open_uni().unwrap().unwrap();
        let payload = vec![0xA5; PAYLOAD_BYTES];
        let accepted = client.write(stream, &payload).unwrap();
        assert_eq!(accepted, PAYLOAD_BYTES);
        client.finish(stream).unwrap();

        let mut receive_stream = None;
        let mut received = Vec::with_capacity(PAYLOAD_BYTES);
        drive_until(
            &mut client,
            client_address,
            &mut server,
            server_address,
            &mut now,
            |_, server| {
                if receive_stream.is_none() {
                    receive_stream = server.accept_uni().unwrap();
                }
                if let Some(stream) = receive_stream {
                    loop {
                        match server.read(stream, usize::MAX) {
                            Ok(Some(bytes)) => received.extend_from_slice(&bytes),
                            Ok(None) => return received.len() == PAYLOAD_BYTES,
                            Err(QuicReadError::Read(ReadError::Blocked)) => break,
                            Err(error) => panic!("receive failed: {error}"),
                        }
                    }
                }
                false
            },
        );
        assert_eq!(received, payload);
    }

    fn configs() -> (ClientConfig, ServerConfig) {
        let server = QuicServerIdentity::generate().unwrap();
        let client = pinned_client_config(&server.certificate()).unwrap();
        (client, server.server_config())
    }

    fn drive_until(
        client: &mut QuicEngine,
        client_address: SocketAddr,
        server: &mut QuicEngine,
        server_address: SocketAddr,
        now: &mut Instant,
        mut complete: impl FnMut(&mut QuicEngine, &mut QuicEngine) -> bool,
    ) {
        for _ in 0..100_000 {
            while let Some(datagram) = client.poll_datagram(*now).unwrap() {
                for datagram in datagram.into_segments() {
                    assert_eq!(datagram.destination, server_address);
                    server
                        .handle_datagram(
                            *now,
                            client_address,
                            Some(server_address.ip()),
                            datagram.ecn,
                            BytesMut::from(datagram.payload.as_ref()),
                        )
                        .unwrap();
                }
            }
            while let Some(datagram) = server.poll_datagram(*now).unwrap() {
                for datagram in datagram.into_segments() {
                    assert_eq!(datagram.destination, client_address);
                    client
                        .handle_datagram(
                            *now,
                            server_address,
                            Some(client_address.ip()),
                            datagram.ecn,
                            BytesMut::from(datagram.payload.as_ref()),
                        )
                        .unwrap();
                }
            }
            while client.poll_event().is_some() {}
            while server.poll_event().is_some() {}
            if complete(client, server) {
                return;
            }

            *now += Duration::from_millis(1);
            if client
                .next_timeout()
                .is_some_and(|deadline| deadline <= *now)
            {
                client.handle_timeout(*now).unwrap();
            }
            if server
                .next_timeout()
                .is_some_and(|deadline| deadline <= *now)
            {
                server.handle_timeout(*now).unwrap();
            }
        }
        panic!("QUIC pair did not reach the expected state");
    }
}
