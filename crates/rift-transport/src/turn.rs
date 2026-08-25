//! Runtime-neutral TURN allocation and peer-datagram state.
//!
//! RIFT keeps TURN outside QUIC. This adapter owns only TURN authentication,
//! allocation refresh, permissions, channel binding, and server framing. The
//! inner payload remains an ordinary QUIC datagram, so direct and relayed paths
//! share one congestion, reliability, stream, and end-to-end security model.

use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use thiserror::Error;
use turn_client_proto::{
    api::{
        BindChannelError, CreatePermissionError, SendError, TurnClientApi, TurnEvent, TurnPollRet,
        TurnRecvRet,
    },
    stun::{Instant as ProtocolInstant, agent::Transmit, types::TransportType},
    tcp::TurnClientTcp,
    types::TurnCredentials,
    udp::TurnClientUdp,
};

/// Monotonic time for the sans-I/O TURN state machine.
///
/// The epoch is arbitrary; callers only need to preserve monotonicity within
/// one allocation. Nanoseconds avoid coupling TURN to a runtime clock.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct TurnTime(i64);

impl TurnTime {
    /// The start of one allocation's local monotonic timeline.
    pub const ZERO: Self = Self(0);

    /// Build a time from elapsed duration, saturating at the protocol limit.
    #[must_use]
    pub fn from_elapsed(elapsed: Duration) -> Self {
        Self(i64::try_from(elapsed.as_nanos()).unwrap_or(i64::MAX))
    }

    /// Elapsed nanoseconds on this allocation's local timeline.
    #[must_use]
    pub const fn as_nanos(self) -> i64 {
        self.0
    }

    fn protocol(self) -> ProtocolInstant {
        ProtocolInstant::from_nanos(self.0)
    }

    fn from_protocol(time: ProtocolInstant) -> Self {
        Self(time.as_nanos())
    }
}

/// One datagram to transmit to the configured TURN server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnDatagram {
    /// Local socket address associated with the TURN allocation.
    pub source: SocketAddr,
    /// TURN server address.
    pub destination: SocketAddr,
    /// Exact UDP payload to send.
    pub payload: Bytes,
}

/// One peer payload recovered from TURN framing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnPeerDatagram {
    /// Peer relay or host address named by TURN.
    pub peer: SocketAddr,
    /// Inner application datagram; for RIFT this is one QUIC packet.
    pub payload: Bytes,
}

/// Bytes to write on one connected TURN/TCP or TURN/TLS control stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnStreamWrite {
    /// Exact TURN framing bytes. The outer stream provides ordering.
    pub payload: Bytes,
}

/// Stable allocation event exposed to candidate racing and diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnEngineEvent {
    /// The server created a UDP relay allocation.
    AllocationCreated(SocketAddr),
    /// The server rejected the requested IPv4 allocation.
    AllocationFailed,
    /// A permission now admits traffic to a peer IP.
    PermissionCreated(std::net::IpAddr),
    /// The server rejected a peer permission.
    PermissionFailed(std::net::IpAddr),
    /// A channel binding now carries a peer efficiently.
    ChannelCreated(SocketAddr),
    /// The server rejected a channel binding.
    ChannelFailed(SocketAddr),
}

/// TURN state-machine or policy failure.
#[derive(Debug, Error)]
pub enum TurnEngineError {
    /// The TURN client did not yet have an allocation for this operation.
    #[error("TURN allocation is not ready")]
    NoAllocation,
    /// A peer permission could not be requested.
    #[error("TURN permission request failed: {0}")]
    Permission(#[source] CreatePermissionError),
    /// A channel binding could not be requested.
    #[error("TURN channel binding failed: {0}")]
    Channel(#[source] BindChannelError),
    /// A peer datagram could not be framed for TURN.
    #[error("TURN peer send failed: {0}")]
    Send(#[source] SendError),
}

/// One UDP TURN allocation with explicit network and clock inputs.
pub struct TurnEngine {
    client: TurnClientUdp,
    relayed_address: Option<SocketAddr>,
}

/// One UDP relay allocation carried over an ordered TURN/TCP connection.
///
/// This is deliberately separate from [`TurnEngine`]: the allocation still
/// relays UDP datagrams for QUIC, while its client-to-TURN hop is an ordered
/// byte stream (normally TLS on port 443). The QUIC engine therefore remains
/// unchanged across direct UDP, TURN/UDP, and TURN/TLS carriers.
pub struct TurnStreamEngine {
    client: TurnClientTcp,
    relayed_address: Option<SocketAddr>,
}

impl std::fmt::Debug for TurnEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TurnEngine")
            .field("local_addr", &self.local_addr())
            .field("server_addr", &self.server_addr())
            .field("relayed_address", &self.relayed_address)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for TurnStreamEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TurnStreamEngine")
            .field("local_addr", &self.local_addr())
            .field("server_addr", &self.server_addr())
            .field("relayed_address", &self.relayed_address)
            .finish_non_exhaustive()
    }
}

impl TurnEngine {
    /// Begin one authenticated UDP allocation.
    ///
    /// Credentials are owned by the protocol engine and never exposed through
    /// events or debug output. Production callers should supply short-lived
    /// credentials from the control plane.
    #[must_use]
    pub fn allocate(local: SocketAddr, server: SocketAddr, username: &str, password: &str) -> Self {
        let credentials = TurnCredentials::new(username, password);
        let config = turn_client_proto::api::TurnConfig::new(credentials);
        Self {
            client: TurnClientUdp::allocate(local, server, config),
            relayed_address: None,
        }
    }

    /// Local socket address bound to this state machine.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.client.local_addr()
    }

    /// TURN server address.
    #[must_use]
    pub fn server_addr(&self) -> SocketAddr {
        self.client.remote_addr()
    }

    /// Current relayed address once allocation succeeds.
    #[must_use]
    pub const fn relayed_addr(&self) -> Option<SocketAddr> {
        self.relayed_address
    }

    /// Feed a datagram received on the allocation's network socket.
    ///
    /// Off-path datagrams are ignored. Authenticated TURN control responses are
    /// consumed internally; peer data is returned with its logical source.
    #[must_use]
    pub fn handle_server_datagram(
        &mut self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: Bytes,
        now: TurnTime,
    ) -> Option<TurnPeerDatagram> {
        let transmit = Transmit::new(payload, TransportType::Udp, source, destination);
        match self.client.recv(transmit, now.protocol()) {
            TurnRecvRet::PeerData(data) => Some(TurnPeerDatagram {
                peer: data.peer,
                payload: Bytes::copy_from_slice(data.data()),
            }),
            TurnRecvRet::Handled | TurnRecvRet::Ignored(_) | TurnRecvRet::PeerIcmp { .. } => None,
        }
    }

    /// Ask the server to admit one peer IP for this allocation.
    ///
    /// # Errors
    ///
    /// Returns when no allocation exists or the request conflicts with live
    /// TURN state.
    pub fn create_permission(
        &mut self,
        peer: std::net::IpAddr,
        now: TurnTime,
    ) -> Result<(), TurnEngineError> {
        self.client
            .create_permission(TransportType::Udp, peer, now.protocol())
            .map_err(|error| match error {
                CreatePermissionError::NoAllocation => TurnEngineError::NoAllocation,
                other => TurnEngineError::Permission(other),
            })
    }

    /// Bind a compact TURN channel to one peer after permission succeeds.
    ///
    /// # Errors
    ///
    /// Returns when no allocation exists or live TURN state rejects the bind.
    pub fn bind_channel(&mut self, peer: SocketAddr, now: TurnTime) -> Result<(), TurnEngineError> {
        self.client
            .bind_channel(TransportType::Udp, peer, now.protocol())
            .map_err(|error| match error {
                BindChannelError::NoAllocation => TurnEngineError::NoAllocation,
                other => TurnEngineError::Channel(other),
            })
    }

    /// Wrap one QUIC datagram for delivery through TURN.
    ///
    /// # Errors
    ///
    /// Returns until allocation and peer permission are ready.
    pub fn send_peer(
        &mut self,
        peer: SocketAddr,
        payload: Bytes,
        now: TurnTime,
    ) -> Result<TurnDatagram, TurnEngineError> {
        let transmit = self
            .client
            .send_to(TransportType::Udp, peer, payload, now.protocol())
            .map_err(|error| match error {
                SendError::NoAllocation | SendError::NoPermission => TurnEngineError::NoAllocation,
                other => TurnEngineError::Send(other),
            })?
            .ok_or(TurnEngineError::NoAllocation)?
            .build();
        Ok(TurnDatagram {
            source: transmit.from,
            destination: transmit.to,
            payload: Bytes::from(transmit.data),
        })
    }

    /// Poll one TURN control datagram that must be sent to the server.
    #[must_use]
    pub fn poll_datagram(&mut self, now: TurnTime) -> Option<TurnDatagram> {
        self.client
            .poll_transmit(now.protocol())
            .map(|transmit| TurnDatagram {
                source: transmit.from,
                destination: transmit.to,
                payload: Bytes::copy_from_slice(transmit.data.as_ref()),
            })
    }

    /// Poll one stable allocation event.
    #[must_use]
    pub fn poll_event(&mut self) -> Option<TurnEngineEvent> {
        let event = self.client.poll_event()?;
        let event = match event {
            TurnEvent::AllocationCreated(TransportType::Udp, address) => {
                self.relayed_address = Some(address);
                TurnEngineEvent::AllocationCreated(address)
            }
            TurnEvent::AllocationCreated(_, address) => TurnEngineEvent::AllocationCreated(address),
            TurnEvent::AllocationCreateFailed(_) => TurnEngineEvent::AllocationFailed,
            TurnEvent::PermissionCreated(_, address) => TurnEngineEvent::PermissionCreated(address),
            TurnEvent::PermissionCreateFailed(_, address) => {
                TurnEngineEvent::PermissionFailed(address)
            }
            TurnEvent::ChannelCreated(_, address) => TurnEngineEvent::ChannelCreated(address),
            TurnEvent::ChannelCreateFailed(_, address) => TurnEngineEvent::ChannelFailed(address),
            TurnEvent::TcpConnected(_) | TurnEvent::TcpConnectFailed(_) => return None,
        };
        Some(event)
    }

    /// Advance TURN timers and return the next wakeup or terminal closure.
    #[must_use]
    pub fn poll_deadline(&mut self, now: TurnTime) -> Option<TurnTime> {
        match self.client.poll(now.protocol()) {
            TurnPollRet::WaitUntil(deadline) => Some(TurnTime::from_protocol(deadline)),
            TurnPollRet::Closed
            | TurnPollRet::AllocateTcpSocket { .. }
            | TurnPollRet::TcpClose { .. } => None,
        }
    }
}

impl TurnStreamEngine {
    /// Begin one authenticated UDP allocation over a connected TURN stream.
    ///
    /// `local` and `server` describe the underlying TCP five-tuple. TLS, when
    /// used, stays outside this runtime-neutral state machine.
    #[must_use]
    pub fn allocate(local: SocketAddr, server: SocketAddr, username: &str, password: &str) -> Self {
        let credentials = TurnCredentials::new(username, password);
        let mut config = turn_client_proto::api::TurnConfig::new(credentials);
        config.set_allocation_transport(TransportType::Udp);
        Self {
            client: TurnClientTcp::allocate(local, server, config),
            relayed_address: None,
        }
    }

    /// Local address of the connected outer stream.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.client.local_addr()
    }

    /// Remote TURN server address of the connected outer stream.
    #[must_use]
    pub fn server_addr(&self) -> SocketAddr {
        self.client.remote_addr()
    }

    /// Current relayed UDP address once allocation succeeds.
    #[must_use]
    pub const fn relayed_addr(&self) -> Option<SocketAddr> {
        self.relayed_address
    }

    /// Feed bytes read from the connected TURN stream.
    ///
    /// The underlying protocol parser retains partial STUN messages and
    /// `ChannelData` frames across calls, so arbitrary TCP/TLS read boundaries
    /// are safe.
    #[must_use]
    pub fn handle_server_bytes(
        &mut self,
        payload: Bytes,
        now: TurnTime,
    ) -> Option<TurnPeerDatagram> {
        let transmit = Transmit::new(
            payload,
            TransportType::Tcp,
            self.server_addr(),
            self.local_addr(),
        );
        match self.client.recv(transmit, now.protocol()) {
            TurnRecvRet::PeerData(data) => Some(TurnPeerDatagram {
                peer: data.peer,
                payload: Bytes::copy_from_slice(data.data()),
            }),
            TurnRecvRet::Handled | TurnRecvRet::Ignored(_) | TurnRecvRet::PeerIcmp { .. } => None,
        }
    }

    /// Poll peer data buffered behind a prior multi-frame stream read.
    #[must_use]
    pub fn poll_peer(&mut self, now: TurnTime) -> Option<TurnPeerDatagram> {
        let data = self.client.poll_recv(now.protocol())?;
        Some(TurnPeerDatagram {
            peer: data.peer,
            payload: Bytes::copy_from_slice(data.data()),
        })
    }

    /// Ask the UDP allocation to admit one peer IP.
    ///
    /// # Errors
    ///
    /// Returns until allocation exists or if the live TURN state rejects the
    /// permission request.
    pub fn create_permission(
        &mut self,
        peer: std::net::IpAddr,
        now: TurnTime,
    ) -> Result<(), TurnEngineError> {
        self.client
            .create_permission(TransportType::Udp, peer, now.protocol())
            .map_err(|error| match error {
                CreatePermissionError::NoAllocation => TurnEngineError::NoAllocation,
                other => TurnEngineError::Permission(other),
            })
    }

    /// Bind compact `ChannelData` framing to one peer.
    ///
    /// # Errors
    ///
    /// Returns until allocation exists or if the live TURN state rejects the
    /// channel binding.
    pub fn bind_channel(&mut self, peer: SocketAddr, now: TurnTime) -> Result<(), TurnEngineError> {
        self.client
            .bind_channel(TransportType::Udp, peer, now.protocol())
            .map_err(|error| match error {
                BindChannelError::NoAllocation => TurnEngineError::NoAllocation,
                other => TurnEngineError::Channel(other),
            })
    }

    /// Wrap one QUIC datagram for the relayed peer.
    ///
    /// # Errors
    ///
    /// Returns until allocation and peer permission are ready, or when TURN
    /// rejects the payload.
    pub fn send_peer(
        &mut self,
        peer: SocketAddr,
        payload: Bytes,
        now: TurnTime,
    ) -> Result<TurnStreamWrite, TurnEngineError> {
        let transmit = self
            .client
            .send_to(TransportType::Udp, peer, payload, now.protocol())
            .map_err(|error| match error {
                SendError::NoAllocation | SendError::NoPermission => TurnEngineError::NoAllocation,
                other => TurnEngineError::Send(other),
            })?
            .ok_or(TurnEngineError::NoAllocation)?
            .build();
        Ok(TurnStreamWrite {
            payload: Bytes::copy_from_slice(transmit.data.as_ref()),
        })
    }

    /// Poll control bytes that must be written to the connected TURN stream.
    #[must_use]
    pub fn poll_write(&mut self, now: TurnTime) -> Option<TurnStreamWrite> {
        self.client
            .poll_transmit(now.protocol())
            .map(|transmit| TurnStreamWrite {
                payload: Bytes::copy_from_slice(transmit.data.as_ref()),
            })
    }

    /// Poll one stable allocation event.
    #[must_use]
    pub fn poll_event(&mut self) -> Option<TurnEngineEvent> {
        let event = self.client.poll_event()?;
        let event = match event {
            TurnEvent::AllocationCreated(TransportType::Udp, address) => {
                self.relayed_address = Some(address);
                TurnEngineEvent::AllocationCreated(address)
            }
            TurnEvent::AllocationCreated(_, address) => TurnEngineEvent::AllocationCreated(address),
            TurnEvent::AllocationCreateFailed(_) => TurnEngineEvent::AllocationFailed,
            TurnEvent::PermissionCreated(_, address) => TurnEngineEvent::PermissionCreated(address),
            TurnEvent::PermissionCreateFailed(_, address) => {
                TurnEngineEvent::PermissionFailed(address)
            }
            TurnEvent::ChannelCreated(_, address) => TurnEngineEvent::ChannelCreated(address),
            TurnEvent::ChannelCreateFailed(_, address) => TurnEngineEvent::ChannelFailed(address),
            TurnEvent::TcpConnected(_) | TurnEvent::TcpConnectFailed(_) => return None,
        };
        Some(event)
    }

    /// Advance TURN timers and return the next wakeup or terminal closure.
    #[must_use]
    pub fn poll_deadline(&mut self, now: TurnTime) -> Option<TurnTime> {
        match self.client.poll(now.protocol()) {
            TurnPollRet::WaitUntil(deadline) => Some(TurnTime::from_protocol(deadline)),
            TurnPollRet::Closed
            | TurnPollRet::AllocateTcpSocket { .. }
            | TurnPollRet::TcpClose { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_bootstrap_is_explicit_and_does_not_expose_credentials() {
        let local = "192.0.2.10:50000".parse().unwrap();
        let server = "198.51.100.20:3478".parse().unwrap();
        let mut turn = TurnEngine::allocate(local, server, "short-lived-user", "secret-password");

        let first = turn.poll_datagram(TurnTime::ZERO).unwrap();
        assert_eq!(first.source, local);
        assert_eq!(first.destination, server);
        assert!(!first.payload.is_empty());
        assert_eq!(turn.relayed_addr(), None);

        let debug = format!("{turn:?}");
        assert!(!debug.contains("secret-password"));
        assert!(!debug.contains("short-lived-user"));
    }

    #[test]
    fn off_path_datagrams_never_become_peer_payload() {
        let local = "192.0.2.10:50000".parse().unwrap();
        let server = "198.51.100.20:3478".parse().unwrap();
        let mut turn = TurnEngine::allocate(local, server, "user", "password");

        assert_eq!(
            turn.handle_server_datagram(
                "203.0.113.9:3478".parse().unwrap(),
                local,
                Bytes::from_static(b"not the TURN server"),
                TurnTime::ZERO,
            ),
            None
        );
    }

    #[test]
    fn turn_time_saturates_without_wrapping() {
        assert_eq!(TurnTime::from_elapsed(Duration::MAX).as_nanos(), i64::MAX);
    }
}
