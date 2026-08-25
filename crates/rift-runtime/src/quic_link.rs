//! Asupersync-native direct UDP driver for RIFT's runtime-neutral QUIC engine.

use std::{io, net::SocketAddr, time::Duration, time::Instant};

use asupersync::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpOutboundDatagram, UdpSocket},
    time::{timeout_at, wall_now},
    tls::{TlsConnector, TlsStream},
};
use bytes::{Bytes, BytesMut};
use rift_transport::{
    QuicBootstrapError, QuicDatagram, QuicEngine, QuicEngineError, QuicEvent, QuicPathStats,
    QuicReadError, QuicServerIdentity, QuicStreamEvent, QuicStreamFinishError, QuicStreamId,
    QuicStreamWriteError, TurnEngine, TurnEngineError, TurnEngineEvent, TurnStreamEngine, TurnTime,
};
use thiserror::Error;

use crate::migration::TransferTransport;

const RECEIVE_BATCH: usize = 64;
const MAX_QUIC_DATAGRAM_BYTES: usize = 65_535;
const MAX_OFF_PATH_DATAGRAMS: u16 = 1_024;
const RECEIVE_FIN_ACK_DRAIN: Duration = Duration::from_millis(50);
const MAX_TURN_STREAM_BUFFER_BYTES: usize = 256 * 1024;
const APPLICATION_FLUSH_BYTES: usize = 1024 * 1024;
const MAX_ACTIVE_LANES: usize = 64;

struct PathInbound {
    source: SocketAddr,
    payload: BytesMut,
}

struct LaneReceive {
    stream: QuicStreamId,
    expected: Option<usize>,
    bytes: Vec<u8>,
}

struct DirectUdpPath {
    socket: UdpSocket,
    peer: SocketAddr,
    receive_spares: Vec<Vec<u8>>,
    off_path_datagrams: u16,
}

struct TurnUdpPath {
    socket: UdpSocket,
    peer: SocketAddr,
    server: SocketAddr,
    engine: TurnEngine,
    started: Instant,
    receive_spares: Vec<Vec<u8>>,
    off_path_datagrams: u16,
}

enum TurnOuterStream {
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

struct TurnStreamPath {
    stream: TurnOuterStream,
    local: SocketAddr,
    peer: SocketAddr,
    engine: TurnStreamEngine,
    wire: TurnStreamWire,
    started: Instant,
    off_path_datagrams: u16,
}

/// One live TURN allocation before an authenticated peer candidate is bound.
///
/// The allocation owns the exact UDP socket used for the later QUIC session.
/// Its credentials remain inside the TURN engine and are omitted from debug
/// output.
pub struct TurnUdpAllocation {
    socket: UdpSocket,
    server: SocketAddr,
    engine: TurnEngine,
    started: Instant,
    relayed: SocketAddr,
    receive_spares: Vec<Vec<u8>>,
    off_path_datagrams: u16,
}

/// One UDP TURN allocation reached over TCP or certificate-validated TLS.
///
/// This carrier exists for networks that block UDP. The relayed payload is
/// still the exact end-to-end QUIC datagram stream; TLS protects only the
/// client-to-TURN hop and never replaces RIFT's pinned QUIC identity.
pub struct TurnStreamAllocation {
    stream: TurnOuterStream,
    local: SocketAddr,
    server: SocketAddr,
    engine: TurnStreamEngine,
    wire: TurnStreamWire,
    started: Instant,
    relayed: SocketAddr,
    off_path_datagrams: u16,
}

#[derive(Default)]
struct TurnStreamWire {
    buffered: BytesMut,
}

impl TurnStreamWire {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<Bytes>, DirectQuicLinkError> {
        if self.buffered.len().saturating_add(bytes.len()) > MAX_TURN_STREAM_BUFFER_BYTES {
            return Err(invalid_turn_stream());
        }
        self.buffered.extend_from_slice(bytes);
        let mut frames = Vec::new();
        loop {
            if self.buffered.len() < 4 {
                break;
            }
            let kind = self.buffered[0] & 0xc0;
            let payload_len = usize::from(u16::from_be_bytes([self.buffered[2], self.buffered[3]]));
            let (frame_len, wire_len) = match kind {
                0x00 => {
                    if self.buffered.len() < 20 || payload_len % 4 != 0 {
                        if self.buffered.len() < 20 {
                            break;
                        }
                        return Err(invalid_turn_stream());
                    }
                    let frame_len = 20_usize.saturating_add(payload_len);
                    (frame_len, frame_len)
                }
                0x40 => {
                    let frame_len = 4_usize.saturating_add(payload_len);
                    (frame_len, frame_len.saturating_add(3) & !3)
                }
                _ => return Err(invalid_turn_stream()),
            };
            if wire_len > MAX_TURN_STREAM_BUFFER_BYTES {
                return Err(invalid_turn_stream());
            }
            if self.buffered.len() < wire_len {
                break;
            }
            let mut frame = self.buffered.split_to(wire_len);
            frame.truncate(frame_len);
            frames.push(frame.freeze());
        }
        Ok(frames)
    }
}

impl std::fmt::Debug for TurnUdpAllocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TurnUdpAllocation")
            .field("server", &self.server)
            .field("relayed", &self.relayed)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for TurnStreamAllocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TurnStreamAllocation")
            .field("server", &self.server)
            .field("relayed", &self.relayed)
            .finish_non_exhaustive()
    }
}

enum DatagramPath {
    Direct(DirectUdpPath),
    Turn(Box<TurnUdpPath>),
    TurnStream(Box<TurnStreamPath>),
}

/// Direct UDP execution failure for one authenticated QUIC connection.
#[derive(Debug, Error)]
pub enum DirectQuicLinkError {
    /// Socket setup or datagram I/O failed.
    #[error("direct QUIC UDP I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Pinned identity or connection bootstrap failed.
    #[error(transparent)]
    Bootstrap(#[from] QuicBootstrapError),
    /// Runtime-neutral QUIC state transition failed.
    #[error(transparent)]
    Engine(#[from] QuicEngineError),
    /// QUIC rejected a stream write.
    #[error(transparent)]
    Write(#[from] QuicStreamWriteError),
    /// QUIC rejected stream completion.
    #[error(transparent)]
    Finish(#[from] QuicStreamFinishError),
    /// QUIC rejected ordered stream reading.
    #[error(transparent)]
    Read(#[from] QuicReadError),
    /// The peer closed the connection before the operation completed.
    #[error("peer closed the direct QUIC connection: {0}")]
    ConnectionLost(String),
    /// QUIC emitted a packet for a path other than the selected peer.
    #[error("QUIC attempted to leave the selected direct path")]
    WrongDestination,
    /// Too much unrelated UDP traffic arrived on the selected socket.
    #[error("direct QUIC path exceeded its unrelated-datagram budget")]
    OffPathFlood,
    /// The bounded operation did not finish in time.
    #[error("direct QUIC operation timed out")]
    Timeout,
    /// A framed application record exceeded its declared receiver ceiling.
    #[error("direct QUIC frame exceeds its bounded protocol limit")]
    FrameTooLarge,
    /// One connection attempted to mix the legacy object stream and
    /// independent-lane protocols.
    #[error("direct QUIC application modes cannot be mixed on one connection")]
    MixedApplicationModes,
    /// The peer closed its stream inside a framed application record.
    #[error("peer closed the direct QUIC stream inside a frame")]
    UnexpectedEof,
    /// Runtime-neutral TURN state transition failed.
    #[error(transparent)]
    Turn(#[from] TurnEngineError),
    /// TURN server rejected allocation, permission, or channel setup.
    #[error("TURN path setup was rejected by the relay")]
    TurnRejected,
    /// TURN emitted traffic for a server other than the configured relay.
    #[error("TURN attempted to leave the selected relay path")]
    WrongTurnServer,
    /// TLS setup or transport failed on the TURN/TLS carrier.
    #[error(transparent)]
    Tls(#[from] asupersync::tls::TlsError),
}

impl TurnUdpAllocation {
    async fn allocate(
        socket: UdpSocket,
        server: SocketAddr,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<Self, DirectQuicLinkError> {
        let local = socket.local_addr()?;
        let started = Instant::now();
        let engine = TurnEngine::allocate(local, server, username, password);
        let mut allocation = PendingTurnAllocation {
            socket,
            server,
            engine,
            started,
            receive_spares: Vec::with_capacity(RECEIVE_BATCH),
            off_path_datagrams: 0,
        };
        let deadline = deadline_after(timeout);
        let relayed = 'allocation: loop {
            for event in allocation.drive_once(deadline).await? {
                match event {
                    TurnEngineEvent::AllocationCreated(address) => break 'allocation address,
                    TurnEngineEvent::AllocationFailed => {
                        return Err(DirectQuicLinkError::TurnRejected);
                    }
                    _ => {}
                }
            }
        };

        Ok(Self {
            socket: allocation.socket,
            server,
            engine: allocation.engine,
            started,
            relayed,
            receive_spares: allocation.receive_spares,
            off_path_datagrams: allocation.off_path_datagrams,
        })
    }

    /// Public relay candidate to exchange inside authenticated control.
    #[must_use]
    pub const fn relayed_addr(&self) -> SocketAddr {
        self.relayed
    }

    async fn bind_peer(
        self,
        peer: SocketAddr,
        timeout: Duration,
    ) -> Result<TurnUdpPath, DirectQuicLinkError> {
        let mut allocation = PendingTurnAllocation {
            socket: self.socket,
            server: self.server,
            engine: self.engine,
            started: self.started,
            receive_spares: self.receive_spares,
            off_path_datagrams: self.off_path_datagrams,
        };
        let deadline = deadline_after(timeout);
        allocation
            .engine
            .create_permission(peer.ip(), turn_now(allocation.started))?;
        loop {
            let mut ready = false;
            for event in allocation.drive_once(deadline).await? {
                match event {
                    TurnEngineEvent::PermissionCreated(address) if address == peer.ip() => {
                        ready = true;
                    }
                    TurnEngineEvent::PermissionFailed(address) if address == peer.ip() => {
                        return Err(DirectQuicLinkError::TurnRejected);
                    }
                    _ => {}
                }
            }
            if ready {
                break;
            }
        }

        allocation
            .engine
            .bind_channel(peer, turn_now(allocation.started))?;
        loop {
            let mut ready = false;
            for event in allocation.drive_once(deadline).await? {
                match event {
                    TurnEngineEvent::ChannelCreated(address) if address == peer => ready = true,
                    TurnEngineEvent::ChannelFailed(address) if address == peer => {
                        return Err(DirectQuicLinkError::TurnRejected);
                    }
                    _ => {}
                }
            }
            if ready {
                break;
            }
        }

        Ok(TurnUdpPath {
            socket: allocation.socket,
            peer,
            server: allocation.server,
            engine: allocation.engine,
            started: allocation.started,
            receive_spares: allocation.receive_spares,
            off_path_datagrams: allocation.off_path_datagrams,
        })
    }
}

impl TurnOuterStream {
    async fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer).await,
            Self::Tls(stream) => stream.read(buffer).await,
        }
    }

    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.write_all(bytes).await,
            Self::Tls(stream) => stream.write_all(bytes).await,
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush().await,
            Self::Tls(stream) => stream.flush().await,
        }
    }
}

impl TurnStreamAllocation {
    async fn allocate(
        server_name: &str,
        server: SocketAddr,
        tls: bool,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<Self, DirectQuicLinkError> {
        let deadline = deadline_after(timeout);
        let tcp = timeout_at(runtime_deadline(deadline), TcpStream::connect(server))
            .await
            .map_err(|_| DirectQuicLinkError::Timeout)??;
        let local = tcp.local_addr()?;
        let stream = if tls {
            let connector = TlsConnector::builder()
                .with_webpki_roots()
                .with_strict_ca_validation()
                .handshake_timeout(remaining(deadline)?)
                .build()?;
            let stream = connector.connect(server_name, tcp).await?;
            TurnOuterStream::Tls(Box::new(stream))
        } else {
            TurnOuterStream::Tcp(tcp)
        };
        let started = Instant::now();
        let engine = TurnStreamEngine::allocate(local, server, username, password);
        let mut allocation = PendingTurnStreamAllocation {
            stream,
            local,
            engine,
            wire: TurnStreamWire::default(),
            started,
            off_path_datagrams: 0,
        };
        let relayed = 'allocation: loop {
            for event in allocation.drive_once(deadline).await? {
                match event {
                    TurnEngineEvent::AllocationCreated(address) => break 'allocation address,
                    TurnEngineEvent::AllocationFailed => {
                        return Err(DirectQuicLinkError::TurnRejected);
                    }
                    _ => {}
                }
            }
        };
        Ok(Self {
            stream: allocation.stream,
            local,
            server,
            engine: allocation.engine,
            wire: allocation.wire,
            started,
            relayed,
            off_path_datagrams: allocation.off_path_datagrams,
        })
    }

    /// Public UDP relay candidate to exchange inside authenticated control.
    #[must_use]
    pub const fn relayed_addr(&self) -> SocketAddr {
        self.relayed
    }

    async fn bind_peer(
        self,
        peer: SocketAddr,
        timeout: Duration,
    ) -> Result<TurnStreamPath, DirectQuicLinkError> {
        let mut allocation = PendingTurnStreamAllocation {
            stream: self.stream,
            local: self.local,
            engine: self.engine,
            wire: self.wire,
            started: self.started,
            off_path_datagrams: self.off_path_datagrams,
        };
        let deadline = deadline_after(timeout);
        allocation
            .engine
            .create_permission(peer.ip(), turn_now(allocation.started))?;
        loop {
            let mut ready = false;
            for event in allocation.drive_once(deadline).await? {
                match event {
                    TurnEngineEvent::PermissionCreated(address) if address == peer.ip() => {
                        ready = true;
                    }
                    TurnEngineEvent::PermissionFailed(address) if address == peer.ip() => {
                        return Err(DirectQuicLinkError::TurnRejected);
                    }
                    _ => {}
                }
            }
            if ready {
                break;
            }
        }
        allocation
            .engine
            .bind_channel(peer, turn_now(allocation.started))?;
        loop {
            let mut ready = false;
            for event in allocation.drive_once(deadline).await? {
                match event {
                    TurnEngineEvent::ChannelCreated(address) if address == peer => ready = true,
                    TurnEngineEvent::ChannelFailed(address) if address == peer => {
                        return Err(DirectQuicLinkError::TurnRejected);
                    }
                    _ => {}
                }
            }
            if ready {
                break;
            }
        }
        Ok(TurnStreamPath {
            stream: allocation.stream,
            local: allocation.local,
            peer,
            engine: allocation.engine,
            wire: allocation.wire,
            started: allocation.started,
            off_path_datagrams: allocation.off_path_datagrams,
        })
    }
}

struct PendingTurnStreamAllocation {
    stream: TurnOuterStream,
    local: SocketAddr,
    engine: TurnStreamEngine,
    wire: TurnStreamWire,
    started: Instant,
    off_path_datagrams: u16,
}

impl PendingTurnStreamAllocation {
    async fn drive_once(
        &mut self,
        deadline: Instant,
    ) -> Result<Vec<TurnEngineEvent>, DirectQuicLinkError> {
        if Instant::now() >= deadline {
            return Err(DirectQuicLinkError::Timeout);
        }
        self.flush_control().await?;
        let mut events = drain_turn_stream_events(&mut self.engine);
        if !events.is_empty() {
            return Ok(events);
        }
        let turn_deadline = self
            .engine
            .poll_deadline(turn_now(self.started))
            .and_then(|time| turn_instant(self.started, time))
            .unwrap_or(deadline);
        self.flush_control().await?;
        let mut buffer = vec![0_u8; MAX_QUIC_DATAGRAM_BYTES].into_boxed_slice();
        let received = timeout_at(
            runtime_deadline(turn_deadline.min(deadline)),
            self.stream.read(&mut buffer),
        )
        .await;
        if let Ok(length) = received {
            let length = length?;
            if length == 0 {
                return Err(DirectQuicLinkError::UnexpectedEof);
            }
            for frame in self.wire.push(&buffer[..length])? {
                let _ = self
                    .engine
                    .handle_server_bytes(frame, turn_now(self.started));
            }
        }
        self.flush_control().await?;
        events.extend(drain_turn_stream_events(&mut self.engine));
        Ok(events)
    }

    async fn flush_control(&mut self) -> Result<(), DirectQuicLinkError> {
        flush_turn_stream_control(&mut self.stream, &mut self.engine, turn_now(self.started)).await
    }
}

struct PendingTurnAllocation {
    socket: UdpSocket,
    server: SocketAddr,
    engine: TurnEngine,
    started: Instant,
    receive_spares: Vec<Vec<u8>>,
    off_path_datagrams: u16,
}

impl PendingTurnAllocation {
    async fn drive_once(
        &mut self,
        deadline: Instant,
    ) -> Result<Vec<TurnEngineEvent>, DirectQuicLinkError> {
        if Instant::now() >= deadline {
            return Err(DirectQuicLinkError::Timeout);
        }
        self.flush_control().await?;
        let mut events = drain_turn_events(&mut self.engine);
        if !events.is_empty() {
            return Ok(events);
        }
        let turn_deadline = self
            .engine
            .poll_deadline(turn_now(self.started))
            .and_then(|time| turn_instant(self.started, time))
            .unwrap_or(deadline);
        self.flush_control().await?;
        let received = timeout_at(
            runtime_deadline(turn_deadline.min(deadline)),
            self.socket.recv_batch_from_reusing(
                RECEIVE_BATCH,
                MAX_QUIC_DATAGRAM_BYTES,
                &mut self.receive_spares,
            ),
        )
        .await;
        if let Ok(batch) = received {
            let mut batch = batch?;
            let local = self.socket.local_addr()?;
            for packet in batch.packets.drain(..) {
                if packet.src_addr != self.server {
                    account_off_path(&mut self.off_path_datagrams)?;
                    continue;
                }
                if packet.possibly_truncated {
                    return Err(oversized_datagram());
                }
                let _ = self.engine.handle_server_datagram(
                    packet.src_addr,
                    local,
                    packet.payload.into(),
                    turn_now(self.started),
                );
            }
            batch.recycle_payloads_into(&mut self.receive_spares, RECEIVE_BATCH);
        }
        self.flush_control().await?;
        events.extend(drain_turn_events(&mut self.engine));
        Ok(events)
    }

    async fn flush_control(&mut self) -> Result<(), DirectQuicLinkError> {
        flush_turn_control(
            &mut self.socket,
            self.server,
            &mut self.engine,
            turn_now(self.started),
        )
        .await
    }
}

impl DatagramPath {
    fn direct(socket: UdpSocket, peer: SocketAddr) -> Self {
        Self::Direct(DirectUdpPath {
            socket,
            peer,
            receive_spares: Vec::with_capacity(RECEIVE_BATCH),
            off_path_datagrams: 0,
        })
    }

    fn local_addr(&self) -> Result<SocketAddr, DirectQuicLinkError> {
        Ok(match self {
            Self::Direct(path) => path.socket.local_addr()?,
            Self::Turn(path) => path.socket.local_addr()?,
            Self::TurnStream(path) => path.local,
        })
    }

    async fn send(&mut self, datagrams: Vec<QuicDatagram>) -> Result<(), DirectQuicLinkError> {
        match self {
            Self::Direct(path) => path.send(datagrams).await,
            Self::Turn(path) => path.send(datagrams).await,
            Self::TurnStream(path) => path.send(datagrams).await,
        }
    }

    async fn receive_until(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<Vec<PathInbound>>, DirectQuicLinkError> {
        match self {
            Self::Direct(path) => path.receive_until(deadline).await,
            Self::Turn(path) => path.receive_until(deadline).await,
            Self::TurnStream(path) => path.receive_until(deadline).await,
        }
    }
}

impl DirectUdpPath {
    async fn send(&mut self, datagrams: Vec<QuicDatagram>) -> Result<(), DirectQuicLinkError> {
        let peer = self.peer;
        let datagrams = logical_datagrams(datagrams, peer)?;
        let packets = datagrams
            .iter()
            .map(|datagram| UdpOutboundDatagram {
                dst_addr: peer,
                payload: &datagram.payload,
            })
            .collect::<Vec<_>>();
        send_batch(&mut self.socket, &packets).await
    }

    async fn receive_until(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<Vec<PathInbound>>, DirectQuicLinkError> {
        let timer = runtime_deadline(deadline);
        let received = timeout_at(
            timer,
            self.socket.recv_batch_from_reusing(
                RECEIVE_BATCH,
                MAX_QUIC_DATAGRAM_BYTES,
                &mut self.receive_spares,
            ),
        )
        .await;
        let Ok(batch) = received else {
            return Ok(None);
        };
        let mut batch = batch?;
        let mut inbound = Vec::with_capacity(batch.packets.len());
        for packet in batch.packets.drain(..) {
            if packet.src_addr != self.peer {
                account_off_path(&mut self.off_path_datagrams)?;
                continue;
            }
            if packet.possibly_truncated {
                return Err(oversized_datagram());
            }
            inbound.push(PathInbound {
                source: self.peer,
                payload: BytesMut::from(packet.payload.as_slice()),
            });
        }
        batch.recycle_payloads_into(&mut self.receive_spares, RECEIVE_BATCH);
        Ok(Some(inbound))
    }
}

impl TurnUdpPath {
    async fn send(&mut self, datagrams: Vec<QuicDatagram>) -> Result<(), DirectQuicLinkError> {
        let logical = logical_datagrams(datagrams, self.peer)?;
        let now = turn_now(self.started);
        let mut wrapped = Vec::with_capacity(logical.len());
        for datagram in logical {
            let datagram = self.engine.send_peer(self.peer, datagram.payload, now)?;
            if datagram.destination != self.server {
                return Err(DirectQuicLinkError::WrongTurnServer);
            }
            wrapped.push(datagram.payload);
        }
        send_payloads(&mut self.socket, self.server, &wrapped).await?;
        self.flush_control().await
    }

    async fn receive_until(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<Vec<PathInbound>>, DirectQuicLinkError> {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let turn_deadline = self
                .engine
                .poll_deadline(turn_now(self.started))
                .and_then(|time| turn_instant(self.started, time))
                .unwrap_or(deadline);
            self.flush_control().await?;
            let timer = runtime_deadline(turn_deadline.min(deadline));
            let received = timeout_at(
                timer,
                self.socket.recv_batch_from_reusing(
                    RECEIVE_BATCH,
                    MAX_QUIC_DATAGRAM_BYTES,
                    &mut self.receive_spares,
                ),
            )
            .await;
            let Ok(batch) = received else {
                continue;
            };
            let mut batch = batch?;
            let local = self.socket.local_addr()?;
            let mut inbound = Vec::new();
            for packet in batch.packets.drain(..) {
                if packet.src_addr != self.server {
                    account_off_path(&mut self.off_path_datagrams)?;
                    continue;
                }
                if packet.possibly_truncated {
                    return Err(oversized_datagram());
                }
                if let Some(peer) = self.engine.handle_server_datagram(
                    packet.src_addr,
                    local,
                    packet.payload.into(),
                    turn_now(self.started),
                ) {
                    if peer.peer != self.peer {
                        account_off_path(&mut self.off_path_datagrams)?;
                        continue;
                    }
                    inbound.push(PathInbound {
                        source: peer.peer,
                        payload: BytesMut::from(peer.payload.as_ref()),
                    });
                }
            }
            batch.recycle_payloads_into(&mut self.receive_spares, RECEIVE_BATCH);
            self.flush_control().await?;
            if !inbound.is_empty() {
                return Ok(Some(inbound));
            }
        }
    }

    async fn flush_control(&mut self) -> Result<(), DirectQuicLinkError> {
        flush_turn_control(
            &mut self.socket,
            self.server,
            &mut self.engine,
            turn_now(self.started),
        )
        .await
    }
}

impl TurnStreamPath {
    async fn send(&mut self, datagrams: Vec<QuicDatagram>) -> Result<(), DirectQuicLinkError> {
        let logical = logical_datagrams(datagrams, self.peer)?;
        let now = turn_now(self.started);
        let mut batch = Vec::with_capacity(logical.len().saturating_mul(1_280));
        for datagram in logical {
            let write = self.engine.send_peer(self.peer, datagram.payload, now)?;
            append_turn_stream_write(&mut batch, &write.payload)?;
        }
        if !batch.is_empty() {
            self.stream.write_all(&batch).await?;
            self.stream.flush().await?;
        }
        self.flush_control().await
    }

    async fn receive_until(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<Vec<PathInbound>>, DirectQuicLinkError> {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let turn_deadline = self
                .engine
                .poll_deadline(turn_now(self.started))
                .and_then(|time| turn_instant(self.started, time))
                .unwrap_or(deadline);
            self.flush_control().await?;
            let mut buffer = vec![0_u8; MAX_QUIC_DATAGRAM_BYTES].into_boxed_slice();
            let received = timeout_at(
                runtime_deadline(turn_deadline.min(deadline)),
                self.stream.read(&mut buffer),
            )
            .await;
            let Ok(length) = received else {
                continue;
            };
            let length = length?;
            if length == 0 {
                return Err(DirectQuicLinkError::UnexpectedEof);
            }
            let now = turn_now(self.started);
            let mut inbound = Vec::new();
            for frame in self.wire.push(&buffer[..length])? {
                if let Some(peer) = self.engine.handle_server_bytes(frame, now) {
                    self.collect_peer(&peer, &mut inbound)?;
                }
                while let Some(peer) = self.engine.poll_peer(now) {
                    self.collect_peer(&peer, &mut inbound)?;
                }
            }
            self.flush_control().await?;
            if !inbound.is_empty() {
                return Ok(Some(inbound));
            }
        }
    }

    fn collect_peer(
        &mut self,
        peer: &rift_transport::TurnPeerDatagram,
        inbound: &mut Vec<PathInbound>,
    ) -> Result<(), DirectQuicLinkError> {
        if peer.peer != self.peer {
            account_off_path(&mut self.off_path_datagrams)?;
            return Ok(());
        }
        inbound.push(PathInbound {
            source: peer.peer,
            payload: BytesMut::from(peer.payload.as_ref()),
        });
        Ok(())
    }

    async fn flush_control(&mut self) -> Result<(), DirectQuicLinkError> {
        flush_turn_stream_control(&mut self.stream, &mut self.engine, turn_now(self.started)).await
    }
}

/// One direct UDP path carrying a continuously-flowing authenticated QUIC session.
///
/// The protocol engine owns reliability, congestion control, pacing, packet
/// protection, and stream flow control. This adapter owns only concrete socket
/// I/O, batching, timers, and strict path filtering.
pub struct DirectQuicLink {
    path: DatagramPath,
    engine: QuicEngine,
    send_stream: Option<QuicStreamId>,
    receive_stream: Option<QuicStreamId>,
    finished_streams: Vec<QuicStreamId>,
    queued_application_bytes: usize,
    lane_sends: Vec<QuicStreamId>,
    lane_receives: Vec<LaneReceive>,
    crypto_cpu_us: u64,
    socket_io_us: u64,
}

/// Bounded cumulative measurements for one authenticated QUIC carrier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct QuicLinkMetrics {
    pub(crate) quic_cpu_us: u64,
    pub(crate) socket_io_us: u64,
    pub(crate) path: QuicPathStats,
}

impl DirectQuicLink {
    /// Concrete authenticated carrier owned by this QUIC connection.
    #[must_use]
    pub const fn transport(&self) -> TransferTransport {
        match &self.path {
            DatagramPath::Direct(_) => TransferTransport::DirectQuic,
            DatagramPath::Turn(_) => TransferTransport::TurnUdpQuic,
            DatagramPath::TurnStream(path) => match path.stream {
                TurnOuterStream::Tcp(_) => TransferTransport::TurnTcpQuic,
                TurnOuterStream::Tls(_) => TransferTransport::TurnTlsQuic,
            },
        }
    }

    /// Current bounded transport evidence for completion-time scheduling.
    #[must_use]
    pub fn path_stats(&self) -> QuicPathStats {
        self.engine.path_stats()
    }

    #[must_use]
    pub(crate) fn metrics(&self) -> QuicLinkMetrics {
        QuicLinkMetrics {
            quic_cpu_us: self.crypto_cpu_us,
            socket_io_us: self.socket_io_us,
            path: self.engine.path_stats(),
        }
    }

    /// Number of application lanes whose FIN has not yet been acknowledged.
    #[must_use]
    pub fn in_flight_lanes(&self) -> usize {
        self.lane_sends.len()
    }

    /// Allocate one UDP TURN relay candidate using short-lived credentials.
    ///
    /// The long-lived provider key never belongs here; the control plane uses
    /// it to mint the supplied ephemeral username and password.
    ///
    /// # Errors
    ///
    /// Returns for socket I/O, TURN rejection, or bounded setup timeout.
    pub async fn allocate_turn(
        socket: UdpSocket,
        server: SocketAddr,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<TurnUdpAllocation, DirectQuicLinkError> {
        TurnUdpAllocation::allocate(socket, server, username, password, timeout).await
    }

    /// Allocate one UDP TURN relay candidate over TCP or TLS.
    ///
    /// TLS uses public roots and exact DNS-name validation. Plain TCP is useful
    /// only as an explicit last-mile compatibility carrier; the inner QUIC
    /// session remains pinned and end-to-end encrypted in both cases.
    ///
    /// # Errors
    ///
    /// Returns for TCP/TLS I/O, certificate rejection, TURN rejection, or the
    /// bounded setup timeout.
    pub async fn allocate_turn_stream(
        server_name: &str,
        server: SocketAddr,
        tls: bool,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<TurnStreamAllocation, DirectQuicLinkError> {
        TurnStreamAllocation::allocate(server_name, server, tls, username, password, timeout).await
    }

    /// Start a client on an already-bound socket, pinning the exact transfer
    /// certificate received through authenticated control.
    ///
    /// # Errors
    ///
    /// Returns for malformed identity material or an invalid connection target.
    pub fn connect(
        socket: UdpSocket,
        peer: SocketAddr,
        certificate: &[u8],
    ) -> Result<Self, DirectQuicLinkError> {
        let engine = QuicEngine::connect_pinned(Instant::now(), peer, certificate)?;
        Ok(Self::new(DatagramPath::direct(socket, peer), engine))
    }

    /// Start a single-peer server on an already-bound socket.
    #[must_use]
    pub fn listen(socket: UdpSocket, peer: SocketAddr, identity: &QuicServerIdentity) -> Self {
        Self::new(
            DatagramPath::direct(socket, peer),
            QuicEngine::listen_identity(identity),
        )
    }

    /// Start a client over an activated TURN allocation while pinning the exact
    /// transfer certificate received through authenticated control.
    ///
    /// # Errors
    ///
    /// Returns for TURN permission/channel setup, malformed identity material,
    /// or an invalid connection target.
    pub async fn connect_turn(
        allocation: TurnUdpAllocation,
        peer: SocketAddr,
        certificate: &[u8],
        timeout: Duration,
    ) -> Result<Self, DirectQuicLinkError> {
        let path = allocation.bind_peer(peer, timeout).await?;
        let engine = QuicEngine::connect_pinned(Instant::now(), peer, certificate)?;
        Ok(Self::new(DatagramPath::Turn(Box::new(path)), engine))
    }

    /// Start a server over an activated TURN allocation.
    ///
    /// # Errors
    ///
    /// Returns for TURN permission/channel setup or bounded setup timeout.
    pub async fn listen_turn(
        allocation: TurnUdpAllocation,
        peer: SocketAddr,
        identity: &QuicServerIdentity,
        timeout: Duration,
    ) -> Result<Self, DirectQuicLinkError> {
        let path = allocation.bind_peer(peer, timeout).await?;
        Ok(Self::new(
            DatagramPath::Turn(Box::new(path)),
            QuicEngine::listen_identity(identity),
        ))
    }

    /// Start a client over TURN/TCP or TURN/TLS while pinning the peer's exact
    /// transfer certificate.
    ///
    /// # Errors
    ///
    /// Returns for TURN permission/channel setup, malformed identity material,
    /// or bounded setup timeout.
    pub async fn connect_turn_stream(
        allocation: TurnStreamAllocation,
        peer: SocketAddr,
        certificate: &[u8],
        timeout: Duration,
    ) -> Result<Self, DirectQuicLinkError> {
        let path = allocation.bind_peer(peer, timeout).await?;
        let engine = QuicEngine::connect_pinned(Instant::now(), peer, certificate)?;
        Ok(Self::new(DatagramPath::TurnStream(Box::new(path)), engine))
    }

    /// Start a server over TURN/TCP or TURN/TLS.
    ///
    /// # Errors
    ///
    /// Returns for TURN permission/channel setup or bounded setup timeout.
    pub async fn listen_turn_stream(
        allocation: TurnStreamAllocation,
        peer: SocketAddr,
        identity: &QuicServerIdentity,
        timeout: Duration,
    ) -> Result<Self, DirectQuicLinkError> {
        let path = allocation.bind_peer(peer, timeout).await?;
        Ok(Self::new(
            DatagramPath::TurnStream(Box::new(path)),
            QuicEngine::listen_identity(identity),
        ))
    }

    fn new(path: DatagramPath, engine: QuicEngine) -> Self {
        Self {
            path,
            engine,
            send_stream: None,
            receive_stream: None,
            finished_streams: Vec::new(),
            queued_application_bytes: 0,
            lane_sends: Vec::new(),
            lane_receives: Vec::new(),
            crypto_cpu_us: 0,
            socket_io_us: 0,
        }
    }

    /// Bound local socket address.
    ///
    /// # Errors
    ///
    /// Returns when the operating system cannot report the socket address.
    pub fn local_addr(&self) -> Result<SocketAddr, DirectQuicLinkError> {
        self.path.local_addr()
    }

    /// Complete the QUIC handshake within a bounded interval.
    ///
    /// # Errors
    ///
    /// Returns for path I/O, protocol failure, peer closure, or timeout.
    pub async fn establish(&mut self, timeout: Duration) -> Result<(), DirectQuicLinkError> {
        let deadline = deadline_after(timeout);
        while !self.engine.is_established() {
            self.drive_once(deadline).await?;
        }
        self.flush_outgoing().await?;
        Ok(())
    }

    /// Send a complete byte sequence on one continuously-flowing unidirectional
    /// stream and wait until the peer acknowledges stream completion.
    ///
    /// This is the first real-wire gate. Production file integration will feed
    /// the same stream incrementally from the file oracle rather than materialize
    /// the whole object in memory.
    ///
    /// # Errors
    ///
    /// Returns for path I/O, protocol failure, peer closure, or timeout.
    pub async fn send_bytes(
        &mut self,
        bytes: &[u8],
        timeout: Duration,
    ) -> Result<(), DirectQuicLinkError> {
        let deadline = deadline_after(timeout);
        if !self.engine.is_established() {
            self.establish(remaining(deadline)?).await?;
        }
        let stream = loop {
            if let Some(stream) = self.engine.open_uni()? {
                break stream;
            }
            self.drive_once(deadline).await?;
        };

        let mut offset = 0;
        while offset < bytes.len() {
            match self.engine.write(stream, &bytes[offset..]) {
                Ok(written) => {
                    offset += written;
                    self.flush_outgoing().await?;
                }
                Err(error) if error.is_blocked() => self.drive_once(deadline).await?,
                Err(error) => return Err(error.into()),
            }
        }
        self.engine.finish(stream)?;
        self.flush_outgoing().await?;

        loop {
            if self.take_stream_finished(stream)? {
                return Ok(());
            }
            self.drive_once(deadline).await?;
        }
    }

    /// Receive one complete unidirectional byte stream.
    ///
    /// # Errors
    ///
    /// Returns for path I/O, protocol failure, peer closure, or timeout.
    pub async fn receive_bytes(
        &mut self,
        timeout: Duration,
    ) -> Result<Vec<u8>, DirectQuicLinkError> {
        let deadline = deadline_after(timeout);
        if !self.engine.is_established() {
            self.establish(remaining(deadline)?).await?;
        }
        let stream = loop {
            if let Some(stream) = self.engine.accept_uni()? {
                break stream;
            }
            self.drive_once(deadline).await?;
        };
        let mut output = Vec::new();
        loop {
            match self.engine.read(stream, 1024 * 1024) {
                Ok(Some(chunk)) => output.extend_from_slice(&chunk),
                Ok(None) => {
                    self.drain_receive_finish_ack(deadline).await?;
                    return Ok(output);
                }
                Err(error) if error.is_blocked() => self.drive_once(deadline).await?,
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Queue one length-delimited application frame without waiting for a
    /// frame-level acknowledgement. QUIC may keep many such frames in flight.
    ///
    /// # Errors
    ///
    /// Returns for an oversized frame, path I/O, protocol failure, peer closure,
    /// or timeout while waiting for stream flow-control credit.
    pub async fn send_frame(
        &mut self,
        frame: &[u8],
        maximum: usize,
        timeout: Duration,
    ) -> Result<(), DirectQuicLinkError> {
        self.queue_frame(frame, maximum, timeout).await?;
        self.flush_frames().await
    }

    /// Queue one bounded application frame while coalescing packet emission.
    /// Flow-control pressure still drives ACKs immediately; this only avoids a
    /// syscall boundary for every integrity record.
    ///
    /// # Errors
    ///
    /// Returns for oversized frames, path I/O, protocol failure, peer closure,
    /// or the bounded flow-control timeout.
    pub async fn queue_frame(
        &mut self,
        frame: &[u8],
        maximum: usize,
        timeout: Duration,
    ) -> Result<(), DirectQuicLinkError> {
        if frame.len() > maximum || frame.len() > u32::MAX as usize {
            return Err(DirectQuicLinkError::FrameTooLarge);
        }
        let deadline = deadline_after(timeout);
        let stream = self.send_stream(deadline).await?;
        let length = u32::try_from(frame.len())
            .map_err(|_| DirectQuicLinkError::FrameTooLarge)?
            .to_be_bytes();
        self.write_all(stream, &length, deadline).await?;
        self.write_all(stream, frame, deadline).await?;
        self.queued_application_bytes = self
            .queued_application_bytes
            .saturating_add(length.len())
            .saturating_add(frame.len());
        if self.queued_application_bytes >= APPLICATION_FLUSH_BYTES {
            self.flush_outgoing().await?;
        }
        Ok(())
    }

    /// Emit all currently queueable QUIC packets without closing the stream.
    ///
    /// # Errors
    ///
    /// Returns for QUIC engine failure or concrete path I/O failure.
    pub async fn flush_frames(&mut self) -> Result<(), DirectQuicLinkError> {
        self.flush_outgoing().await
    }

    /// Receive one bounded length-delimited application frame.
    ///
    /// # Errors
    ///
    /// Returns for an oversized frame, premature stream end, path I/O,
    /// protocol failure, peer closure, or timeout.
    pub async fn receive_frame(
        &mut self,
        maximum: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, DirectQuicLinkError> {
        let deadline = deadline_after(timeout);
        let stream = self.receive_stream(deadline).await?;
        let length = self.read_exact(stream, 4, deadline).await?;
        let encoded: [u8; 4] = length
            .try_into()
            .map_err(|_| DirectQuicLinkError::UnexpectedEof)?;
        let length = u32::from_be_bytes(encoded);
        let length = usize::try_from(length).map_err(|_| DirectQuicLinkError::FrameTooLarge)?;
        if length > maximum {
            return Err(DirectQuicLinkError::FrameTooLarge);
        }
        self.read_exact(stream, length, deadline).await
    }

    /// Queue one independently deliverable bounded application lane.
    ///
    /// Each lane is a short unidirectional QUIC stream. A stalled earlier lane
    /// therefore cannot block verification of a later one. Stream count and
    /// resident bytes remain bounded; flow and congestion control stay owned
    /// by QUIC.
    ///
    /// # Errors
    ///
    /// Returns for an oversized lane, path failure, protocol failure, or a
    /// bounded wait for stream credit.
    pub async fn queue_lane(
        &mut self,
        bytes: &[u8],
        maximum: usize,
        timeout: Duration,
    ) -> Result<(), DirectQuicLinkError> {
        if bytes.len() > maximum || bytes.len() > u32::MAX as usize {
            return Err(DirectQuicLinkError::FrameTooLarge);
        }
        if self.send_stream.is_some() {
            return Err(DirectQuicLinkError::MixedApplicationModes);
        }
        let deadline = deadline_after(timeout);
        self.reap_finished_lanes()?;
        while self.lane_sends.len() >= MAX_ACTIVE_LANES {
            self.drive_once(deadline).await?;
            self.reap_finished_lanes()?;
        }
        if !self.engine.is_established() {
            self.establish(remaining(deadline)?).await?;
        }
        let stream = loop {
            if let Some(stream) = self.engine.open_uni()? {
                break stream;
            }
            self.drive_once(deadline).await?;
            self.reap_finished_lanes()?;
        };
        let length = u32::try_from(bytes.len())
            .map_err(|_| DirectQuicLinkError::FrameTooLarge)?
            .to_be_bytes();
        self.write_all(stream, &length, deadline).await?;
        self.write_all(stream, bytes, deadline).await?;
        self.engine.finish(stream)?;
        self.lane_sends.push(stream);
        self.queued_application_bytes = self
            .queued_application_bytes
            .saturating_add(length.len())
            .saturating_add(bytes.len());
        if self.queued_application_bytes >= APPLICATION_FLUSH_BYTES {
            self.flush_outgoing().await?;
        }
        Ok(())
    }

    /// Flush currently queueable packets from independent lanes.
    ///
    /// # Errors
    ///
    /// Returns for QUIC or concrete path failure.
    pub async fn flush_lanes(&mut self) -> Result<(), DirectQuicLinkError> {
        self.flush_outgoing().await
    }

    /// Give an outstanding lane a bounded chance to consume ACK/loss/timer
    /// evidence without waiting for every lane to finish.
    ///
    /// # Errors
    ///
    /// Returns only for a concrete path or QUIC failure. An ordinary empty
    /// poll is successful and leaves the lane in flight.
    pub async fn poll_lane_progress(
        &mut self,
        timeout: Duration,
    ) -> Result<(), DirectQuicLinkError> {
        self.reap_finished_lanes()?;
        if self.lane_sends.is_empty() {
            return Ok(());
        }
        let deadline = deadline_after(timeout);
        match self.drive_once(deadline).await {
            Ok(()) | Err(DirectQuicLinkError::Timeout) => {}
            Err(error) => return Err(error),
        }
        self.reap_finished_lanes()?;
        Ok(())
    }

    /// Receive whichever complete independent lane becomes available first.
    ///
    /// Accepted streams are polled fairly in bounded rounds. An incomplete
    /// stream remains resident while later streams continue making progress,
    /// removing object-wide application head-of-line blocking.
    ///
    /// # Errors
    ///
    /// Returns for oversized/trailing lane bytes, path failure, protocol
    /// failure, or timeout.
    pub async fn receive_lane(
        &mut self,
        maximum: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, DirectQuicLinkError> {
        if self.receive_stream.is_some() {
            return Err(DirectQuicLinkError::MixedApplicationModes);
        }
        let deadline = deadline_after(timeout);
        if !self.engine.is_established() {
            self.establish(remaining(deadline)?).await?;
        }
        loop {
            while self.lane_receives.len() < MAX_ACTIVE_LANES {
                let Some(stream) = self.engine.accept_uni()? else {
                    break;
                };
                self.lane_receives.push(LaneReceive {
                    stream,
                    expected: None,
                    bytes: Vec::new(),
                });
            }

            let mut index = 0;
            while index < self.lane_receives.len() {
                if self.poll_lane(index, maximum)? {
                    let lane = self.lane_receives.swap_remove(index);
                    // Stream FIN acknowledgement may be delayed by QUIC even
                    // after the application bytes are readable. Drain that
                    // bounded timer before the caller can drop its endpoint;
                    // otherwise a final receipt can be delivered locally yet
                    // leave its sender waiting until the full idle timeout.
                    self.drain_receive_finish_ack(deadline).await?;
                    return Ok(lane.bytes);
                }
                index += 1;
            }
            self.drive_once(deadline).await?;
        }
    }

    /// Wait until every locally emitted independent lane is acknowledged.
    ///
    /// # Errors
    ///
    /// Returns for path/protocol failure or timeout.
    pub async fn finish_lanes(&mut self, timeout: Duration) -> Result<(), DirectQuicLinkError> {
        let deadline = deadline_after(timeout);
        self.flush_outgoing().await?;
        loop {
            self.reap_finished_lanes()?;
            if self.lane_sends.is_empty() {
                return Ok(());
            }
            self.drive_once(deadline).await?;
        }
    }

    /// Finish the application send stream and wait for peer acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns for path I/O, protocol failure, peer closure, or timeout.
    pub async fn finish_send_stream(
        &mut self,
        timeout: Duration,
    ) -> Result<(), DirectQuicLinkError> {
        let deadline = deadline_after(timeout);
        let stream = self.send_stream(deadline).await?;
        self.engine.finish(stream)?;
        self.flush_outgoing().await?;
        loop {
            if self.take_stream_finished(stream)? {
                return Ok(());
            }
            self.drive_once(deadline).await?;
        }
    }

    /// Require the peer to finish the current receive stream with no trailing
    /// application bytes, and drive the acknowledgement before returning.
    ///
    /// # Errors
    ///
    /// Returns for trailing bytes, path I/O, protocol failure, peer closure, or
    /// timeout.
    pub async fn finish_receive_stream(
        &mut self,
        timeout: Duration,
    ) -> Result<(), DirectQuicLinkError> {
        let deadline = deadline_after(timeout);
        let stream = self.receive_stream(deadline).await?;
        loop {
            match self.engine.read(stream, 1) {
                Ok(None) => {
                    self.drain_receive_finish_ack(deadline).await?;
                    return Ok(());
                }
                Ok(Some(_)) => return Err(DirectQuicLinkError::FrameTooLarge),
                Err(error) if error.is_blocked() => self.drive_once(deadline).await?,
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn send_stream(
        &mut self,
        deadline: Instant,
    ) -> Result<QuicStreamId, DirectQuicLinkError> {
        if let Some(stream) = self.send_stream {
            return Ok(stream);
        }
        if !self.engine.is_established() {
            self.establish(remaining(deadline)?).await?;
        }
        loop {
            if let Some(stream) = self.engine.open_uni()? {
                self.send_stream = Some(stream);
                return Ok(stream);
            }
            self.drive_once(deadline).await?;
        }
    }

    async fn drain_receive_finish_ack(
        &mut self,
        deadline: Instant,
    ) -> Result<(), DirectQuicLinkError> {
        self.flush_outgoing().await?;
        let acknowledgement_deadline = (Instant::now() + RECEIVE_FIN_ACK_DRAIN).min(deadline);
        while Instant::now() < acknowledgement_deadline {
            match self.drive_once(acknowledgement_deadline).await {
                Ok(()) => {}
                Err(DirectQuicLinkError::Timeout) => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    async fn receive_stream(
        &mut self,
        deadline: Instant,
    ) -> Result<QuicStreamId, DirectQuicLinkError> {
        if let Some(stream) = self.receive_stream {
            return Ok(stream);
        }
        if !self.engine.is_established() {
            self.establish(remaining(deadline)?).await?;
        }
        loop {
            if let Some(stream) = self.engine.accept_uni()? {
                self.receive_stream = Some(stream);
                return Ok(stream);
            }
            self.drive_once(deadline).await?;
        }
    }

    async fn write_all(
        &mut self,
        stream: QuicStreamId,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), DirectQuicLinkError> {
        let mut offset = 0;
        while offset < bytes.len() {
            match self.engine.write(stream, &bytes[offset..]) {
                Ok(written) => offset += written,
                Err(error) if error.is_blocked() => self.drive_once(deadline).await?,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    async fn read_exact(
        &mut self,
        stream: QuicStreamId,
        length: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, DirectQuicLinkError> {
        let mut output = Vec::with_capacity(length);
        while output.len() < length {
            match self.engine.read(stream, length - output.len()) {
                Ok(Some(chunk)) => output.extend_from_slice(&chunk),
                Ok(None) => return Err(DirectQuicLinkError::UnexpectedEof),
                Err(error) if error.is_blocked() => self.drive_once(deadline).await?,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(output)
    }

    fn poll_lane(&mut self, index: usize, maximum: usize) -> Result<bool, DirectQuicLinkError> {
        loop {
            let stream = self.lane_receives[index].stream;
            let expected = self.lane_receives[index].expected;
            let wanted = match expected {
                None => 4_usize.saturating_sub(self.lane_receives[index].bytes.len()),
                Some(length) => length.saturating_sub(self.lane_receives[index].bytes.len()),
            };
            if wanted == 0 {
                if expected.is_none() {
                    let encoded: [u8; 4] = self.lane_receives[index]
                        .bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| DirectQuicLinkError::UnexpectedEof)?;
                    let length = usize::try_from(u32::from_be_bytes(encoded))
                        .map_err(|_| DirectQuicLinkError::FrameTooLarge)?;
                    if length > maximum {
                        return Err(DirectQuicLinkError::FrameTooLarge);
                    }
                    self.lane_receives[index].expected = Some(length);
                    self.lane_receives[index].bytes.clear();
                    if length != 0 {
                        self.lane_receives[index].bytes.reserve(length);
                    }
                    continue;
                }
                return match self.engine.read(stream, 1) {
                    Ok(None) => Ok(true),
                    Ok(Some(_)) => Err(DirectQuicLinkError::FrameTooLarge),
                    Err(error) if error.is_blocked() => Ok(false),
                    Err(error) => Err(error.into()),
                };
            }
            match self.engine.read(stream, wanted) {
                Ok(Some(chunk)) => self.lane_receives[index].bytes.extend_from_slice(&chunk),
                Ok(None) => return Err(DirectQuicLinkError::UnexpectedEof),
                Err(error) if error.is_blocked() => return Ok(false),
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn drive_once(&mut self, deadline: Instant) -> Result<(), DirectQuicLinkError> {
        self.flush_outgoing().await?;
        self.collect_events()?;
        if Instant::now() >= deadline {
            return Err(DirectQuicLinkError::Timeout);
        }

        let protocol_deadline = self.engine.next_timeout();
        let receive_deadline = protocol_deadline.map_or(deadline, |wake| wake.min(deadline));
        let io_started = Instant::now();
        let inbound = self.path.receive_until(receive_deadline).await?;
        self.socket_io_us = self
            .socket_io_us
            .saturating_add(elapsed_us(io_started.elapsed()));
        if let Some(inbound) = inbound {
            let local_ip = self.path.local_addr()?.ip();
            let local_ip = (!local_ip.is_unspecified()).then_some(local_ip);
            let quic_started = Instant::now();
            for packet in inbound {
                self.engine.handle_datagram(
                    Instant::now(),
                    packet.source,
                    local_ip,
                    None,
                    packet.payload,
                )?;
            }
            self.crypto_cpu_us = self
                .crypto_cpu_us
                .saturating_add(elapsed_us(quic_started.elapsed()));
        } else {
            let now = Instant::now();
            if now >= deadline {
                return Err(DirectQuicLinkError::Timeout);
            }
            if protocol_deadline.is_some_and(|wake| wake <= now) {
                self.engine.handle_timeout(now)?;
            }
        }

        self.flush_outgoing().await?;
        self.collect_events()
    }

    async fn flush_outgoing(&mut self) -> Result<(), DirectQuicLinkError> {
        let mut datagrams = Vec::new();
        let quic_started = Instant::now();
        while let Some(datagram) = self.engine.poll_datagram(Instant::now())? {
            datagrams.push(datagram);
        }
        self.crypto_cpu_us = self
            .crypto_cpu_us
            .saturating_add(elapsed_us(quic_started.elapsed()));
        let io_started = Instant::now();
        self.path.send(datagrams).await?;
        self.socket_io_us = self
            .socket_io_us
            .saturating_add(elapsed_us(io_started.elapsed()));
        self.queued_application_bytes = 0;
        Ok(())
    }

    fn collect_events(&mut self) -> Result<(), DirectQuicLinkError> {
        while let Some(event) = self.engine.poll_event() {
            match event {
                QuicEvent::ConnectionLost { reason } => {
                    return Err(DirectQuicLinkError::ConnectionLost(reason.to_string()));
                }
                QuicEvent::Stream(QuicStreamEvent::Finished { id })
                    if !self.finished_streams.contains(&id) =>
                {
                    self.finished_streams.push(id);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn reap_finished_lanes(&mut self) -> Result<(), DirectQuicLinkError> {
        self.collect_events()?;
        let mut index = 0;
        while index < self.lane_sends.len() {
            let stream = self.lane_sends[index];
            let Some(finished) = self
                .finished_streams
                .iter()
                .position(|candidate| *candidate == stream)
            else {
                index += 1;
                continue;
            };
            self.finished_streams.swap_remove(finished);
            self.lane_sends.swap_remove(index);
        }
        Ok(())
    }

    fn take_stream_finished(&mut self, target: QuicStreamId) -> Result<bool, DirectQuicLinkError> {
        self.collect_events()?;
        let Some(position) = self
            .finished_streams
            .iter()
            .position(|stream| *stream == target)
        else {
            return Ok(false);
        };
        self.finished_streams.swap_remove(position);
        Ok(true)
    }
}

fn elapsed_us(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn logical_datagrams(
    datagrams: Vec<QuicDatagram>,
    peer: SocketAddr,
) -> Result<Vec<QuicDatagram>, DirectQuicLinkError> {
    let mut logical = Vec::new();
    for datagram in datagrams {
        if datagram.destination != peer {
            return Err(DirectQuicLinkError::WrongDestination);
        }
        logical.extend(datagram.into_segments());
    }
    Ok(logical)
}

async fn send_payloads(
    socket: &mut UdpSocket,
    destination: SocketAddr,
    payloads: &[bytes::Bytes],
) -> Result<(), DirectQuicLinkError> {
    let packets = payloads
        .iter()
        .map(|payload| UdpOutboundDatagram {
            dst_addr: destination,
            payload,
        })
        .collect::<Vec<_>>();
    send_batch(socket, &packets).await
}

async fn flush_turn_control(
    socket: &mut UdpSocket,
    server: SocketAddr,
    engine: &mut TurnEngine,
    now: TurnTime,
) -> Result<(), DirectQuicLinkError> {
    let mut payloads = Vec::new();
    while let Some(datagram) = engine.poll_datagram(now) {
        if datagram.destination != server {
            return Err(DirectQuicLinkError::WrongTurnServer);
        }
        payloads.push(datagram.payload);
    }
    send_payloads(socket, server, &payloads).await
}

async fn flush_turn_stream_control(
    stream: &mut TurnOuterStream,
    engine: &mut TurnStreamEngine,
    now: TurnTime,
) -> Result<(), DirectQuicLinkError> {
    let mut wrote = false;
    while let Some(write) = engine.poll_write(now) {
        let mut framed = Vec::with_capacity(write.payload.len().saturating_add(3));
        append_turn_stream_write(&mut framed, &write.payload)?;
        stream.write_all(&framed).await?;
        wrote = true;
    }
    if wrote {
        stream.flush().await?;
    }
    Ok(())
}

fn append_turn_stream_write(
    output: &mut Vec<u8>,
    payload: &[u8],
) -> Result<(), DirectQuicLinkError> {
    if payload.len() < 4 {
        return Err(invalid_turn_stream());
    }
    let kind = payload[0] & 0xc0;
    let declared = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    let expected = match kind {
        0x00 if payload.len() >= 20 && declared % 4 == 0 => 20_usize.saturating_add(declared),
        0x40 => 4_usize.saturating_add(declared),
        _ => return Err(invalid_turn_stream()),
    };
    if expected != payload.len() {
        return Err(invalid_turn_stream());
    }
    output.extend_from_slice(payload);
    if kind == 0x40 {
        output.resize(output.len().saturating_add(3) & !3, 0);
    }
    Ok(())
}

fn drain_turn_events(engine: &mut TurnEngine) -> Vec<TurnEngineEvent> {
    let mut events = Vec::new();
    while let Some(event) = engine.poll_event() {
        events.push(event);
    }
    events
}

fn drain_turn_stream_events(engine: &mut TurnStreamEngine) -> Vec<TurnEngineEvent> {
    let mut events = Vec::new();
    while let Some(event) = engine.poll_event() {
        events.push(event);
    }
    events
}

async fn send_batch(
    socket: &mut UdpSocket,
    packets: &[UdpOutboundDatagram<'_>],
) -> Result<(), DirectQuicLinkError> {
    if packets.is_empty() {
        return Ok(());
    }
    let report = socket.send_batch_to(packets).await?;
    if report.packets_processed != packets.len() || report.error.is_some() {
        return Err(DirectQuicLinkError::Io(io::Error::other(
            "partial QUIC datagram batch send",
        )));
    }
    Ok(())
}

fn account_off_path(counter: &mut u16) -> Result<(), DirectQuicLinkError> {
    *counter = counter.saturating_add(1);
    if *counter >= MAX_OFF_PATH_DATAGRAMS {
        return Err(DirectQuicLinkError::OffPathFlood);
    }
    Ok(())
}

fn oversized_datagram() -> DirectQuicLinkError {
    DirectQuicLinkError::Io(io::Error::new(
        io::ErrorKind::InvalidData,
        "oversized QUIC datagram",
    ))
}

fn invalid_turn_stream() -> DirectQuicLinkError {
    DirectQuicLinkError::Io(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or oversized TURN stream framing",
    ))
}

fn runtime_deadline(deadline: Instant) -> asupersync::types::Time {
    let wait = deadline.saturating_duration_since(Instant::now());
    wall_now().saturating_add_nanos(duration_nanos(wait))
}

fn turn_now(started: Instant) -> TurnTime {
    TurnTime::from_elapsed(started.elapsed())
}

fn turn_instant(started: Instant, time: TurnTime) -> Option<Instant> {
    let nanos = u64::try_from(time.as_nanos()).ok()?;
    started.checked_add(Duration::from_nanos(nanos))
}

fn deadline_after(timeout: Duration) -> Instant {
    Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now)
}

fn remaining(deadline: Instant) -> Result<Duration, DirectQuicLinkError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(DirectQuicLinkError::Timeout)
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use asupersync::{
        cx::Cx,
        http::HttpClient,
        net::{UdpSocket, lookup_all},
        runtime::RuntimeBuilder,
    };
    use rift_protocol::RouteTransport;
    use rift_relay::CloudflareTurnConfig;

    use super::*;

    const PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

    #[test]
    fn turn_stream_wire_restores_rfc_channel_padding_across_read_splits() {
        let mut outbound = Vec::new();
        append_turn_stream_write(&mut outbound, &[0x40, 0x01, 0, 3, 7, 8, 9]).unwrap();
        assert_eq!(outbound, [0x40, 0x01, 0, 3, 7, 8, 9, 0]);

        let mut wire = TurnStreamWire::default();
        assert!(wire.push(&outbound[..2]).unwrap().is_empty());
        assert!(wire.push(&outbound[2..6]).unwrap().is_empty());
        let frames = wire.push(&outbound[6..]).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].as_ref(), &[0x40, 0x01, 0, 3, 7, 8, 9]);
    }

    #[test]
    fn turn_stream_wire_rejects_non_turn_prefixes_and_declared_mismatch() {
        let mut wire = TurnStreamWire::default();
        assert!(wire.push(&[0x80, 0, 0, 0]).is_err());
        assert!(append_turn_stream_write(&mut Vec::new(), &[0x40, 1, 0, 2, 9]).is_err());
    }

    #[test]
    fn native_udp_moves_one_saturated_stream_without_record_stop_signs() {
        let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        runtime.block_on(async move {
            let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_address = server_socket.local_addr().unwrap();
            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_address = client_socket.local_addr().unwrap();
            let identity = QuicServerIdentity::generate().unwrap();
            let certificate = identity.certificate();
            let mut server = DirectQuicLink::listen(server_socket, client_address, &identity);
            let mut client =
                DirectQuicLink::connect(client_socket, server_address, &certificate).unwrap();
            let cx = Cx::current().unwrap();
            let mut receive_task = cx
                .spawn(
                    move |_cx| async move { server.receive_bytes(Duration::from_secs(20)).await },
                )
                .unwrap();
            let expected = (0..PAYLOAD_BYTES)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect::<Vec<_>>();

            client
                .send_bytes(&expected, Duration::from_secs(20))
                .await
                .unwrap();
            let delivered = receive_task.join(&cx).await.unwrap().unwrap();
            assert_eq!(delivered, expected);
        });
    }

    #[test]
    fn independent_lanes_complete_without_object_stream_ordering() {
        let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        runtime.block_on(async move {
            let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_address = server_socket.local_addr().unwrap();
            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_address = client_socket.local_addr().unwrap();
            let identity = QuicServerIdentity::generate().unwrap();
            let certificate = identity.certificate();
            let mut server = DirectQuicLink::listen(server_socket, client_address, &identity);
            let mut client =
                DirectQuicLink::connect(client_socket, server_address, &certificate).unwrap();
            let cx = Cx::current().unwrap();
            let mut receive_task = cx
                .spawn(move |_cx| async move {
                    let mut received = Vec::new();
                    for _ in 0..3 {
                        received.push(
                            server
                                .receive_lane(2 * 1024 * 1024, Duration::from_secs(20))
                                .await?,
                        );
                    }
                    received.sort_by_key(Vec::len);
                    Ok::<_, DirectQuicLinkError>(received)
                })
                .unwrap();

            client
                .queue_lane(
                    &vec![1; 1024 * 1024],
                    2 * 1024 * 1024,
                    Duration::from_secs(20),
                )
                .await
                .unwrap();
            client
                .queue_lane(b"tail", 2 * 1024 * 1024, Duration::from_secs(20))
                .await
                .unwrap();
            client
                .queue_lane(
                    &vec![2; 128 * 1024],
                    2 * 1024 * 1024,
                    Duration::from_secs(20),
                )
                .await
                .unwrap();
            client.flush_lanes().await.unwrap();
            client.finish_lanes(Duration::from_secs(20)).await.unwrap();

            let received = receive_task.join(&cx).await.unwrap().unwrap();
            assert_eq!(received[0], b"tail");
            assert_eq!(received[1], vec![2; 128 * 1024]);
            assert_eq!(received[2], vec![1; 1024 * 1024]);
        });
    }

    #[test]
    fn live_turn_carries_the_identical_quic_stream_when_enabled() {
        let Ok(server) = std::env::var("RIFT_TURN_LAB") else {
            return;
        };
        let server: SocketAddr = server.parse().unwrap();
        let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        runtime.block_on(async move {
            let left_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let right_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let left = DirectQuicLink::allocate_turn(
                left_socket,
                server,
                "rift",
                "rift-test-secret",
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            let right = DirectQuicLink::allocate_turn(
                right_socket,
                server,
                "rift",
                "rift-test-secret",
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            let left_relay = left.relayed_addr();
            let right_relay = right.relayed_addr();
            let identity = QuicServerIdentity::generate().unwrap();
            let certificate = identity.certificate();
            let mut receiver =
                DirectQuicLink::listen_turn(right, left_relay, &identity, Duration::from_secs(5))
                    .await
                    .unwrap();
            let mut sender = DirectQuicLink::connect_turn(
                left,
                right_relay,
                &certificate,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            let cx = Cx::current().unwrap();
            let mut receive_task = cx
                .spawn(move |_cx| async move {
                    receiver.establish(Duration::from_secs(10)).await?;
                    receiver.receive_bytes(Duration::from_secs(20)).await
                })
                .unwrap();
            let expected = (0..4 * 1024 * 1024)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect::<Vec<_>>();

            sender.establish(Duration::from_secs(10)).await.unwrap();
            sender
                .send_bytes(&expected, Duration::from_secs(20))
                .await
                .unwrap();
            let delivered = receive_task.join(&cx).await.unwrap().unwrap();
            assert_eq!(delivered, expected);
        });
    }

    #[test]
    fn live_cloudflare_turn_carries_pinned_quic_when_enabled() {
        if std::env::var_os("RIFT_CLOUDFLARE_LIVE").is_none() {
            return;
        }
        let key_id = std::env::var("RIFT_CLOUDFLARE_TURN_KEY_ID").unwrap();
        let api_token = std::env::var("RIFT_CLOUDFLARE_TURN_API_TOKEN").unwrap();
        let config =
            CloudflareTurnConfig::new(key_id, api_token, 5 * 60, Duration::from_secs(10)).unwrap();
        let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            let credentials = config.generate(&HttpClient::new(), &cx).await.unwrap();
            let route = credentials
                .servers()
                .iter()
                .find(|server| server.transport == RouteTransport::TurnUdp && server.port == 3478)
                .unwrap();
            let server = lookup_all(format!("{}:{}", route.host, route.port))
                .await
                .unwrap()
                .into_iter()
                .find(SocketAddr::is_ipv4)
                .unwrap();
            let bind = if server.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let left_socket = UdpSocket::bind(bind).await.unwrap();
            let right_socket = UdpSocket::bind(bind).await.unwrap();
            let left = DirectQuicLink::allocate_turn(
                left_socket,
                server,
                credentials.username(),
                credentials.credential(),
                Duration::from_secs(10),
            )
            .await
            .unwrap();
            let right = DirectQuicLink::allocate_turn(
                right_socket,
                server,
                credentials.username(),
                credentials.credential(),
                Duration::from_secs(10),
            )
            .await
            .unwrap();
            let left_relay = left.relayed_addr();
            let right_relay = right.relayed_addr();
            let identity = QuicServerIdentity::generate().unwrap();
            let certificate = identity.certificate();
            let mut receiver =
                DirectQuicLink::listen_turn(right, left_relay, &identity, Duration::from_secs(10))
                    .await
                    .unwrap();
            let mut sender = DirectQuicLink::connect_turn(
                left,
                right_relay,
                &certificate,
                Duration::from_secs(10),
            )
            .await
            .unwrap();
            assert_eq!(receiver.transport(), TransferTransport::TurnUdpQuic);
            assert_eq!(sender.transport(), TransferTransport::TurnUdpQuic);
            let mut receive_task = cx
                .spawn(move |_cx| async move {
                    receiver.establish(Duration::from_secs(20)).await?;
                    receiver.receive_bytes(Duration::from_secs(30)).await
                })
                .unwrap();
            let expected = (0..1024 * 1024)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect::<Vec<_>>();

            sender.establish(Duration::from_secs(20)).await.unwrap();
            sender
                .send_bytes(&expected, Duration::from_secs(30))
                .await
                .unwrap();
            let delivered = receive_task.join(&cx).await.unwrap().unwrap();
            assert_eq!(delivered, expected);
        });
    }

    #[test]
    fn live_turn_tcp_carries_the_identical_quic_stream_when_enabled() {
        let Ok(server) = std::env::var("RIFT_TURN_STREAM_LAB") else {
            return;
        };
        let server: SocketAddr = server.parse().unwrap();
        let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        runtime.block_on(async move {
            let left = DirectQuicLink::allocate_turn_stream(
                "localhost",
                server,
                false,
                "rift",
                "rift-test-secret",
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            let right = DirectQuicLink::allocate_turn_stream(
                "localhost",
                server,
                false,
                "rift",
                "rift-test-secret",
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            let left_relay = left.relayed_addr();
            let right_relay = right.relayed_addr();
            let identity = QuicServerIdentity::generate().unwrap();
            let certificate = identity.certificate();
            let mut receiver = DirectQuicLink::listen_turn_stream(
                right,
                left_relay,
                &identity,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            let mut sender = DirectQuicLink::connect_turn_stream(
                left,
                right_relay,
                &certificate,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            let cx = Cx::current().unwrap();
            let mut receive_task = cx
                .spawn(move |_cx| async move {
                    receiver.establish(Duration::from_secs(10)).await?;
                    receiver.receive_bytes(Duration::from_secs(20)).await
                })
                .unwrap();
            let expected = (0..4 * 1024 * 1024)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect::<Vec<_>>();
            sender.establish(Duration::from_secs(10)).await.unwrap();
            sender
                .send_bytes(&expected, Duration::from_secs(20))
                .await
                .unwrap();
            let delivered = receive_task.join(&cx).await.unwrap().unwrap();
            assert_eq!(delivered, expected);
        });
    }

    #[test]
    fn live_turn_tcp_delivers_one_peer_datagram_when_enabled() {
        let Ok(server) = std::env::var("RIFT_TURN_STREAM_LAB") else {
            return;
        };
        let server: SocketAddr = server.parse().unwrap();
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        runtime.block_on(async move {
            let left = DirectQuicLink::allocate_turn_stream(
                "localhost",
                server,
                false,
                "rift",
                "rift-test-secret",
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            let right = DirectQuicLink::allocate_turn_stream(
                "localhost",
                server,
                false,
                "rift",
                "rift-test-secret",
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            let left_relay = left.relayed_addr();
            let right_relay = right.relayed_addr();
            let mut left = left
                .bind_peer(right_relay, Duration::from_secs(5))
                .await
                .unwrap();
            let mut right = right
                .bind_peer(left_relay, Duration::from_secs(5))
                .await
                .unwrap();
            left.send(vec![QuicDatagram {
                destination: right_relay,
                ecn: None,
                source_ip: None,
                payload: Bytes::from_static(b"path oracle"),
                segment_size: None,
            }])
            .await
            .unwrap();
            let received = right
                .receive_until(Instant::now() + Duration::from_secs(5))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].source, left_relay);
            assert_eq!(received[0].payload.as_ref(), b"path oracle");
        });
    }
}
