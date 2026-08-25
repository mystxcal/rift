//! Authenticated direct UDP path acquisition over the relay's rendezvous port.

use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use asupersync::{
    net::{UdpSocket, lookup_all},
    time::{sleep, timeout_at, wall_now},
};
use rift_protocol::{
    DIRECT_AEAD_TAG_BYTES, DIRECT_CIPHERTEXT_HEADER_BYTES, DIRECT_MTU_CANDIDATES,
    DIRECT_PROBE_BYTES, DirectCiphertext, DirectHandshake, DirectMatch, DirectPacket, DirectProbe,
    DirectProtocolError, DirectRegistration, MAX_DIRECT_DATAGRAM_BYTES, Role, mtu_probe_data_bytes,
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{CryptoError, DatagramCipher, HandshakeRole, NoiseHandshake, RelayEndpoint};

const REGISTRATION_DOMAIN: &str = "rift.direct.registration.v1";
const PROBE_DOMAIN: &str = "rift.direct.probe.v1";
const PATH_DOMAIN: &str = "rift.direct.path.v1";
const NOISE_DOMAIN: &str = "rift.direct.noise.v1";
const PROLOGUE_MAGIC: &[u8] = b"RIFT-DIRECT-NOISE-1";

/// Bounded acquisition and authentication policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectAcquirePolicy {
    /// Initial registration and probe retransmission timeout.
    pub initial_rto: Duration,
    /// Total transmissions for each acquisition stage.
    pub max_attempts: u8,
    /// Unrelated or malformed datagrams tolerated per attempt.
    pub max_unrelated_datagrams: u16,
}

impl Default for DirectAcquirePolicy {
    fn default() -> Self {
        Self {
            initial_rto: Duration::from_millis(250),
            max_attempts: 6,
            max_unrelated_datagrams: 32,
        }
    }
}

impl DirectAcquirePolicy {
    fn validate(self) -> Result<Self, DirectPathError> {
        if self.initial_rto.is_zero()
            || self.initial_rto > Duration::from_secs(2)
            || self.max_attempts == 0
            || self.max_attempts > 10
            || self.max_unrelated_datagrams == 0
            || self.max_unrelated_datagrams > 1_024
        {
            return Err(DirectPathError::InvalidPolicy);
        }
        Ok(self)
    }
}

/// A bidirectionally validated, session-authenticated direct path.
pub struct DirectPath {
    pub(crate) socket: UdpSocket,
    pub(crate) peer: SocketAddr,
    pub(crate) path_id: u32,
    pub(crate) cipher: DatagramCipher,
    pub(crate) local_challenge: [u8; 16],
    pub(crate) peer_challenge: [u8; 16],
    validation_rtt_us: u64,
    goodput_floor_bps: u64,
    max_datagram_bytes: usize,
}

/// A transfer-authenticated socket ready for the pinned QUIC handshake.
pub(crate) struct DirectQuicCandidate {
    socket: UdpSocket,
    peer: SocketAddr,
}

/// Bounded acquisition phase that failed to make progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectAcquisitionStage {
    /// Opaque endpoint matching through the blind rendezvous.
    Rendezvous,
    /// Bidirectional keyed probe validation of the advertised candidate.
    PathValidation,
    /// Authenticated Noise session establishment and confirmation.
    NoiseHandshake,
    /// Encrypted path-capacity trial preceding payload migration.
    PathTrial,
}

impl fmt::Display for DirectAcquisitionStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rendezvous => "rendezvous",
            Self::PathValidation => "validation",
            Self::NoiseHandshake => "Noise handshake",
            Self::PathTrial => "path trial",
        })
    }
}

impl DirectPath {
    /// Candidate-pair identity bound into the authenticated transcript.
    #[must_use]
    pub const fn path_id(&self) -> u32 {
        self.path_id
    }

    /// Authenticated peer source address observed through rendezvous and probes.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// End-to-end probe round-trip in microseconds.
    #[must_use]
    pub const fn validation_rtt_us(&self) -> u64 {
        self.validation_rtt_us
    }

    /// Authenticated trial's conservative useful-delivery floor.
    #[must_use]
    pub const fn goodput_floor_bps(&self) -> u64 {
        self.goodput_floor_bps
    }

    /// Largest authenticated UDP payload admitted by this path.
    #[must_use]
    pub const fn max_datagram_bytes(&self) -> usize {
        self.max_datagram_bytes
    }
}

impl DirectQuicCandidate {
    pub(crate) fn into_quic_parts(self) -> (UdpSocket, SocketAddr) {
        (self.socket, self.peer)
    }
}

/// Direct-path acquisition failure. The relay path may remain usable.
#[derive(Debug, Error)]
pub enum DirectPathError {
    /// Policy would permit inert or excessive acquisition work.
    #[error("invalid direct-path acquisition policy")]
    InvalidPolicy,
    /// Operating-system CSPRNG was unavailable.
    #[error("secure operating-system entropy unavailable")]
    EntropyUnavailable,
    /// Relay endpoint could not resolve to a UDP rendezvous address.
    #[error("direct rendezvous endpoint resolution failed: {0}")]
    Resolution(#[source] io::Error),
    /// UDP socket operation failed at a named acquisition boundary.
    #[error("direct-path I/O failed while attempting to {operation}: {source}")]
    Io {
        /// Stable operation name suitable for diagnostics.
        operation: &'static str,
        /// Operating-system or reactor error.
        #[source]
        source: io::Error,
    },
    /// Direct-path datagram was malformed.
    #[error(transparent)]
    Protocol(#[from] DirectProtocolError),
    /// Direct Noise authentication failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Bounded acquisition did not validate a direct path.
    #[error("direct-path {0} timed out")]
    Timeout(DirectAcquisitionStage),
    /// Datagram noise exhausted the bounded processing budget.
    #[error("too many unrelated datagrams during direct-path acquisition")]
    UnrelatedDatagramLimit,
}

/// Acquire and authenticate a direct UDP path without involving payload state.
///
/// Both peers use the same live socket for rendezvous, simultaneous-open probes,
/// Noise, and subsequent data. Relay-provided addresses are treated only as
/// candidates; migration is permitted only after bidirectional keyed probes and
/// a fresh direct-path Noise transcript complete.
///
/// # Errors
///
/// Returns for invalid policy, resolution, entropy, socket, bounded timeout,
/// malformed peer datagrams, or authentication failure.
pub async fn acquire_direct_path(
    endpoint: &RelayEndpoint,
    lookup_id: [u8; 16],
    transfer_secret: &[u8; 32],
    role: Role,
    policy: DirectAcquirePolicy,
) -> Result<DirectPath, DirectPathError> {
    acquire_direct_path_bound(endpoint, lookup_id, transfer_secret, role, 0, policy).await
}

/// Acquire a direct path from one explicit local UDP port.
///
/// Port zero preserves the operating system's ephemeral-port selection. A
/// fixed port is useful for administered firewall/NAT mappings and reproducible
/// network assays; the same socket still owns rendezvous, probes, Noise, trial,
/// and data.
///
/// # Errors
///
/// Has the same bounded failure contract as [`acquire_direct_path`], plus a
/// bind failure when the requested local port is unavailable.
pub async fn acquire_direct_path_bound(
    endpoint: &RelayEndpoint,
    lookup_id: [u8; 16],
    transfer_secret: &[u8; 32],
    role: Role,
    bind_port: u16,
    policy: DirectAcquirePolicy,
) -> Result<DirectPath, DirectPathError> {
    let validated = acquire_validated_path(
        endpoint,
        lookup_id,
        transfer_secret,
        role,
        bind_port,
        policy,
    )
    .await?;
    let ValidatedPath {
        mut socket,
        peer,
        path_id,
        local_nonce,
        peer_nonce,
        local_challenge,
        peer_challenge,
        validation_rtt_us,
    } = validated;
    let policy = policy.validate()?;
    let transcript = direct_prologue(
        lookup_id,
        path_id,
        role,
        local_nonce,
        peer_nonce,
        local_challenge,
        peer_challenge,
    );
    let noise_secret = Zeroizing::new(derive_key(NOISE_DOMAIN, transfer_secret, &transcript));
    let cipher = establish_direct_noise(
        &mut socket,
        peer,
        path_id,
        role,
        &noise_secret,
        &transcript,
        local_challenge,
        peer_challenge,
        policy,
    )
    .await?;
    let max_datagram_bytes = discover_path_mtu(
        &mut socket,
        peer,
        path_id,
        role,
        &cipher,
        local_challenge,
        peer_challenge,
        policy,
    )
    .await?;
    let goodput_floor_bps = measure_direct_goodput(
        &mut socket,
        peer,
        path_id,
        role,
        &cipher,
        local_challenge,
        peer_challenge,
        policy,
        max_datagram_bytes,
    )
    .await?;
    Ok(DirectPath {
        socket,
        peer,
        path_id,
        cipher,
        local_challenge,
        peer_challenge,
        validation_rtt_us,
        goodput_floor_bps,
        max_datagram_bytes,
    })
}

/// Acquire only the authenticated socket identity needed by pinned QUIC.
///
/// This deliberately omits the legacy direct-record Noise, PLPMTUD, and trial
/// phases. QUIC owns packet protection, path MTU, congestion, and delivery
/// measurement for the production transfer, so repeating those phases would
/// add latency without strengthening the selected data plane.
pub(crate) async fn acquire_direct_quic_candidate_bound(
    endpoint: &RelayEndpoint,
    lookup_id: [u8; 16],
    transfer_secret: &[u8; 32],
    role: Role,
    bind_port: u16,
    policy: DirectAcquirePolicy,
) -> Result<DirectQuicCandidate, DirectPathError> {
    let validated = acquire_validated_path(
        endpoint,
        lookup_id,
        transfer_secret,
        role,
        bind_port,
        policy,
    )
    .await?;
    Ok(DirectQuicCandidate {
        socket: validated.socket,
        peer: validated.peer,
    })
}

struct ValidatedPath {
    socket: UdpSocket,
    peer: SocketAddr,
    path_id: u32,
    local_nonce: [u8; 16],
    peer_nonce: [u8; 16],
    local_challenge: [u8; 16],
    peer_challenge: [u8; 16],
    validation_rtt_us: u64,
}

async fn acquire_validated_path(
    endpoint: &RelayEndpoint,
    lookup_id: [u8; 16],
    transfer_secret: &[u8; 32],
    role: Role,
    bind_port: u16,
    policy: DirectAcquirePolicy,
) -> Result<ValidatedPath, DirectPathError> {
    let policy = policy.validate()?;
    let relay = resolve_udp_endpoint(endpoint).await?;
    let mut socket = bind_live_udp(relay, bind_port).await?;
    let local_nonce = random_16()?;
    let registration_key = derive_key(REGISTRATION_DOMAIN, transfer_secret, &lookup_id);
    let prefix = DirectRegistration::authenticated_prefix(lookup_id, role, local_nonce);
    let registration = DirectRegistration {
        lookup_id,
        role,
        nonce: local_nonce,
        authenticator: authenticate(&registration_key, &prefix),
    };
    let matched = register(&mut socket, relay, registration, policy).await?;
    let peer_prefix =
        DirectRegistration::authenticated_prefix(lookup_id, opposite(role), matched.peer_nonce);
    let expected_peer_authenticator = authenticate(&registration_key, &peer_prefix);
    if !bool::from(expected_peer_authenticator.ct_eq(&matched.peer_authenticator)) {
        return Err(DirectPathError::Timeout(DirectAcquisitionStage::Rendezvous));
    }
    let path_id = derive_path_id(lookup_id, role, local_nonce, matched.peer_nonce);
    let local_challenge = random_16()?;
    let probe_key = derive_key(
        PROBE_DOMAIN,
        transfer_secret,
        &path_context(lookup_id, path_id, role, local_nonce, matched.peer_nonce),
    );
    let (peer_challenge, validation_rtt_us) = validate_path(
        &mut socket,
        matched.peer_addr,
        lookup_id,
        role,
        path_id,
        local_challenge,
        &probe_key,
        policy,
    )
    .await?;
    Ok(ValidatedPath {
        socket,
        peer: matched.peer_addr,
        path_id,
        local_nonce,
        peer_nonce: matched.peer_nonce,
        local_challenge,
        peer_challenge,
        validation_rtt_us,
    })
}

async fn bind_live_udp(relay: SocketAddr, port: u16) -> Result<UdpSocket, DirectPathError> {
    let bind = match relay.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
    };
    UdpSocket::bind(bind)
        .await
        .map_err(|source| direct_io("bind the live UDP socket", source))
}

async fn resolve_udp_endpoint(endpoint: &RelayEndpoint) -> Result<SocketAddr, DirectPathError> {
    match endpoint {
        RelayEndpoint::Loopback(address) => Ok(*address),
        RelayEndpoint::Wss(endpoint) => {
            let address = if endpoint.host().contains(':') {
                format!("[{}]:{}", endpoint.host(), endpoint.port())
            } else {
                format!("{}:{}", endpoint.host(), endpoint.port())
            };
            lookup_all(address)
                .await
                .map_err(DirectPathError::Resolution)?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    DirectPathError::Resolution(io::Error::new(
                        io::ErrorKind::NotFound,
                        "relay name resolved no UDP address",
                    ))
                })
        }
    }
}

async fn register(
    socket: &mut UdpSocket,
    relay: SocketAddr,
    registration: DirectRegistration,
    policy: DirectAcquirePolicy,
) -> Result<DirectMatch, DirectPathError> {
    let encoded = registration.encode();
    let mut rto = policy.initial_rto;
    let mut buffer = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
    for _ in 0..policy.max_attempts {
        send_datagram_attempt(socket, &encoded, relay)
            .await
            .map_err(|source| direct_io("send a rendezvous registration", source))?;
        let deadline = wall_now().saturating_add_nanos(duration_nanos(rto));
        let mut unrelated = 0_u16;
        loop {
            let Ok(received) = timeout_at(deadline, socket.recv_from(&mut buffer)).await else {
                break;
            };
            let (length, source) =
                received.map_err(|source| direct_io("receive a rendezvous match", source))?;
            if source == relay
                && let Ok(matched) = DirectMatch::decode(&buffer[..length])
                && matched.lookup_id == registration.lookup_id
            {
                return Ok(matched);
            }
            unrelated = unrelated.saturating_add(1);
            if unrelated >= policy.max_unrelated_datagrams {
                return Err(DirectPathError::UnrelatedDatagramLimit);
            }
        }
        rto = rto.saturating_mul(2).min(Duration::from_secs(2));
    }
    Err(DirectPathError::Timeout(DirectAcquisitionStage::Rendezvous))
}

#[allow(clippy::too_many_arguments)]
async fn validate_path(
    socket: &mut UdpSocket,
    peer: SocketAddr,
    lookup_id: [u8; 16],
    role: Role,
    path_id: u32,
    local_challenge: [u8; 16],
    key: &[u8; 32],
    policy: DirectAcquirePolicy,
) -> Result<([u8; 16], u64), DirectPathError> {
    let mut peer_challenge = None;
    let mut peer_answered = false;
    let mut rto = policy.initial_rto;
    let mut buffer = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
    for _ in 0..policy.max_attempts {
        let attempt_started = wall_now();
        let response = peer_challenge.unwrap_or([0; 16]);
        let probe = signed_probe(lookup_id, role, path_id, local_challenge, response, key);
        send_datagram_attempt(socket, &probe.encode(), peer)
            .await
            .map_err(|source| direct_io("send a path-validation probe", source))?;
        let deadline = wall_now().saturating_add_nanos(duration_nanos(rto));
        let mut unrelated = 0_u16;
        loop {
            let Ok(received) = timeout_at(deadline, socket.recv_from(&mut buffer)).await else {
                break;
            };
            let (length, source) =
                received.map_err(|source| direct_io("receive a path-validation probe", source))?;
            let Some(probe) = authenticate_probe(
                &buffer[..length],
                source,
                peer,
                lookup_id,
                opposite(role),
                path_id,
                key,
            ) else {
                unrelated = unrelated.saturating_add(1);
                if unrelated >= policy.max_unrelated_datagrams {
                    return Err(DirectPathError::UnrelatedDatagramLimit);
                }
                continue;
            };
            peer_challenge = Some(probe.challenge);
            peer_answered |= probe.response == local_challenge;
            let answer = signed_probe(
                lookup_id,
                role,
                path_id,
                local_challenge,
                probe.challenge,
                key,
            );
            send_datagram_attempt(socket, &answer.encode(), peer)
                .await
                .map_err(|source| direct_io("answer a path-validation probe", source))?;
            if peer_answered {
                // Repeat the proof, not just the initial challenge, so the peer
                // is very likely to leave validation before Noise begins.
                send_datagram_attempt(socket, &answer.encode(), peer)
                    .await
                    .map_err(|source| direct_io("repeat a path-validation proof", source))?;
                let sample_us = wall_now()
                    .duration_since(attempt_started)
                    .div_ceil(1_000)
                    .max(1);
                return Ok((probe.challenge, sample_us));
            }
        }
        rto = rto.saturating_mul(2).min(Duration::from_secs(2));
    }
    Err(DirectPathError::Timeout(
        DirectAcquisitionStage::PathValidation,
    ))
}

fn signed_probe(
    lookup_id: [u8; 16],
    role: Role,
    path_id: u32,
    challenge: [u8; 16],
    response: [u8; 16],
    key: &[u8; 32],
) -> DirectProbe {
    let prefix = DirectProbe::authenticated_prefix(lookup_id, role, path_id, challenge, response);
    DirectProbe {
        lookup_id,
        role,
        path_id,
        challenge,
        response,
        authenticator: authenticate(key, &prefix),
    }
}

#[allow(clippy::too_many_arguments)]
fn authenticate_probe(
    input: &[u8],
    source: SocketAddr,
    expected_source: SocketAddr,
    lookup_id: [u8; 16],
    role: Role,
    path_id: u32,
    key: &[u8; 32],
) -> Option<DirectProbe> {
    if input.len() != DIRECT_PROBE_BYTES || source != expected_source {
        return None;
    }
    let probe = DirectProbe::decode(input).ok()?;
    if probe.lookup_id != lookup_id || probe.role != role || probe.path_id != path_id {
        return None;
    }
    let prefix = DirectProbe::authenticated_prefix(
        probe.lookup_id,
        probe.role,
        probe.path_id,
        probe.challenge,
        probe.response,
    );
    let expected = authenticate(key, &prefix);
    if bool::from(expected.ct_eq(&probe.authenticator)) {
        Some(probe)
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
async fn establish_direct_noise(
    socket: &mut UdpSocket,
    peer: SocketAddr,
    path_id: u32,
    role: Role,
    secret: &[u8; 32],
    prologue: &[u8],
    local_challenge: [u8; 16],
    peer_challenge: [u8; 16],
    policy: DirectAcquirePolicy,
) -> Result<DatagramCipher, DirectPathError> {
    match role {
        Role::Sender => {
            establish_noise_initiator(
                socket,
                peer,
                path_id,
                secret,
                prologue,
                local_challenge,
                peer_challenge,
                policy,
            )
            .await
        }
        Role::Receiver => {
            establish_noise_responder(
                socket,
                peer,
                path_id,
                secret,
                prologue,
                local_challenge,
                peer_challenge,
                policy,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn establish_noise_initiator(
    socket: &mut UdpSocket,
    peer: SocketAddr,
    path_id: u32,
    secret: &[u8; 32],
    prologue: &[u8],
    local_challenge: [u8; 16],
    peer_challenge: [u8; 16],
    policy: DirectAcquirePolicy,
) -> Result<DatagramCipher, DirectPathError> {
    let mut handshake = NoiseHandshake::new(HandshakeRole::Initiator, secret, prologue)?;
    let mut flight = [0_u8; 1_024];
    let flight_len = handshake.write_message(&[], &mut flight)?;
    let encoded = DirectHandshake {
        role: Role::Sender,
        path_id,
        payload: flight[..flight_len].to_vec(),
    }
    .encode()?;
    let mut rto = policy.initial_rto;
    let mut buffer = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
    for _ in 0..policy.max_attempts {
        send_datagram_attempt(socket, &encoded, peer)
            .await
            .map_err(|source| direct_io("send the Noise initiator flight", source))?;
        let deadline = wall_now().saturating_add_nanos(duration_nanos(rto));
        let mut unrelated = 0_u16;
        loop {
            let Ok(received) = timeout_at(deadline, socket.recv_from(&mut buffer)).await else {
                break;
            };
            let (length, source) = received
                .map_err(|source| direct_io("receive the Noise responder flight", source))?;
            if source != peer {
                unrelated = unrelated.saturating_add(1);
            } else if let Ok(response) = DirectHandshake::decode(&buffer[..length]) {
                if response.role == Role::Receiver && response.path_id == path_id {
                    let mut payload = [0_u8; 256];
                    handshake.read_message(&response.payload, &mut payload)?;
                    let cipher = handshake.into_datagram_transport()?;
                    return confirm_initiator(
                        socket,
                        peer,
                        path_id,
                        cipher,
                        local_challenge,
                        peer_challenge,
                        policy,
                    )
                    .await;
                }
                unrelated = unrelated.saturating_add(1);
            } else {
                unrelated = unrelated.saturating_add(1);
            }
            if unrelated >= policy.max_unrelated_datagrams {
                return Err(DirectPathError::UnrelatedDatagramLimit);
            }
        }
        rto = rto.saturating_mul(2).min(Duration::from_secs(2));
    }
    Err(DirectPathError::Timeout(
        DirectAcquisitionStage::NoiseHandshake,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn establish_noise_responder(
    socket: &mut UdpSocket,
    peer: SocketAddr,
    path_id: u32,
    secret: &[u8; 32],
    prologue: &[u8],
    local_challenge: [u8; 16],
    peer_challenge: [u8; 16],
    policy: DirectAcquirePolicy,
) -> Result<DatagramCipher, DirectPathError> {
    let mut handshake = NoiseHandshake::new(HandshakeRole::Responder, secret, prologue)?;
    let mut buffer = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
    let mut rto = policy.initial_rto;
    let mut response: Option<Vec<u8>> = None;
    for _ in 0..policy.max_attempts {
        if let Some(encoded) = &response {
            send_datagram_attempt(socket, encoded, peer)
                .await
                .map_err(|source| direct_io("repeat the Noise responder flight", source))?;
        }
        let deadline = wall_now().saturating_add_nanos(duration_nanos(rto));
        let mut unrelated = 0_u16;
        loop {
            let Ok(received) = timeout_at(deadline, socket.recv_from(&mut buffer)).await else {
                break;
            };
            let (length, source) =
                received.map_err(|source| direct_io("receive a Noise handshake flight", source))?;
            if source != peer {
                unrelated = unrelated.saturating_add(1);
            } else if response.is_none() {
                if let Ok(first) = DirectHandshake::decode(&buffer[..length])
                    && first.role == Role::Sender
                    && first.path_id == path_id
                {
                    let mut payload = [0_u8; 256];
                    handshake.read_message(&first.payload, &mut payload)?;
                    let mut flight = [0_u8; 1_024];
                    let flight_len = handshake.write_message(&[], &mut flight)?;
                    let encoded = DirectHandshake {
                        role: Role::Receiver,
                        path_id,
                        payload: flight[..flight_len].to_vec(),
                    }
                    .encode()?;
                    send_datagram_attempt(socket, &encoded, peer)
                        .await
                        .map_err(|source| direct_io("send the Noise responder flight", source))?;
                    response = Some(encoded);
                    continue;
                }
                unrelated = unrelated.saturating_add(1);
            } else if let Ok(ciphertext) = DirectCiphertext::decode(&buffer[..length]) {
                if ciphertext.path_id == path_id {
                    let cipher = handshake.into_datagram_transport()?;
                    let mut plaintext = [0_u8; 64];
                    let length =
                        cipher.open(ciphertext.nonce, &ciphertext.payload, &mut plaintext)?;
                    if DirectPacket::decode(&plaintext[..length])
                        == Ok(DirectPacket::Confirm {
                            challenge: local_challenge,
                        })
                    {
                        send_confirm(socket, peer, path_id, &cipher, peer_challenge).await?;
                        send_confirm(socket, peer, path_id, &cipher, peer_challenge).await?;
                        return Ok(cipher);
                    }
                    return Err(DirectPathError::Timeout(
                        DirectAcquisitionStage::NoiseHandshake,
                    ));
                }
                unrelated = unrelated.saturating_add(1);
            } else if let Some(encoded) = &response {
                // A duplicate first flight means our second flight was lost.
                if DirectHandshake::decode(&buffer[..length]).is_ok() {
                    send_datagram_attempt(socket, encoded, peer)
                        .await
                        .map_err(|source| {
                            direct_io("recover the Noise responder flight", source)
                        })?;
                } else {
                    unrelated = unrelated.saturating_add(1);
                }
            }
            if unrelated >= policy.max_unrelated_datagrams {
                return Err(DirectPathError::UnrelatedDatagramLimit);
            }
        }
        rto = rto.saturating_mul(2).min(Duration::from_secs(2));
    }
    Err(DirectPathError::Timeout(
        DirectAcquisitionStage::NoiseHandshake,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn confirm_initiator(
    socket: &mut UdpSocket,
    peer: SocketAddr,
    path_id: u32,
    cipher: DatagramCipher,
    local_challenge: [u8; 16],
    peer_challenge: [u8; 16],
    policy: DirectAcquirePolicy,
) -> Result<DatagramCipher, DirectPathError> {
    let mut rto = policy.initial_rto;
    let mut buffer = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
    for _ in 0..policy.max_attempts {
        send_confirm(socket, peer, path_id, &cipher, peer_challenge).await?;
        let deadline = wall_now().saturating_add_nanos(duration_nanos(rto));
        let mut unrelated = 0_u16;
        loop {
            let Ok(received) = timeout_at(deadline, socket.recv_from(&mut buffer)).await else {
                break;
            };
            let (length, source) =
                received.map_err(|source| direct_io("receive Noise confirmation", source))?;
            if source == peer
                && let Ok(ciphertext) = DirectCiphertext::decode(&buffer[..length])
                && ciphertext.path_id == path_id
            {
                let mut plaintext = [0_u8; 64];
                let length = cipher.open(ciphertext.nonce, &ciphertext.payload, &mut plaintext)?;
                if DirectPacket::decode(&plaintext[..length])
                    == Ok(DirectPacket::Confirm {
                        challenge: local_challenge,
                    })
                {
                    return Ok(cipher);
                }
            }
            unrelated = unrelated.saturating_add(1);
            if unrelated >= policy.max_unrelated_datagrams {
                return Err(DirectPathError::UnrelatedDatagramLimit);
            }
        }
        rto = rto.saturating_mul(2).min(Duration::from_secs(2));
    }
    Err(DirectPathError::Timeout(
        DirectAcquisitionStage::NoiseHandshake,
    ))
}

async fn send_confirm(
    socket: &mut UdpSocket,
    peer: SocketAddr,
    path_id: u32,
    cipher: &DatagramCipher,
    challenge: [u8; 16],
) -> Result<(), DirectPathError> {
    let plaintext = DirectPacket::Confirm { challenge }.encode()?;
    let mut encrypted = [0_u8; 64];
    let (nonce, length) = cipher.seal(&plaintext, &mut encrypted)?;
    let envelope = DirectCiphertext {
        path_id,
        nonce,
        payload: encrypted[..length].to_vec(),
    }
    .encode()?;
    send_datagram_attempt(socket, &envelope, peer)
        .await
        .map_err(|source| direct_io("send Noise confirmation", source))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn discover_path_mtu(
    socket: &mut UdpSocket,
    peer: SocketAddr,
    path_id: u32,
    role: Role,
    cipher: &DatagramCipher,
    local_challenge: [u8; 16],
    peer_challenge: [u8; 16],
    policy: DirectAcquirePolicy,
) -> Result<usize, DirectPathError> {
    match role {
        Role::Sender => {
            discover_path_mtu_sender(
                socket,
                peer,
                path_id,
                cipher,
                local_challenge,
                peer_challenge,
                policy,
            )
            .await
        }
        Role::Receiver => {
            discover_path_mtu_receiver(
                socket,
                peer,
                path_id,
                cipher,
                local_challenge,
                peer_challenge,
                policy,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn discover_path_mtu_sender(
    socket: &mut UdpSocket,
    peer: SocketAddr,
    path_id: u32,
    cipher: &DatagramCipher,
    local_challenge: [u8; 16],
    peer_challenge: [u8; 16],
    policy: DirectAcquirePolicy,
) -> Result<usize, DirectPathError> {
    let token = u64::from_be_bytes(random_16()?[..8].try_into().expect("eight-byte prefix"));
    let probe_rto = policy
        .initial_rto
        .clamp(Duration::from_millis(50), Duration::from_millis(250));
    let mut buffer = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
    for datagram_bytes in DIRECT_MTU_CANDIDATES {
        let probe = DirectPacket::MtuProbe {
            token,
            datagram_bytes,
            data: vec![
                0xA5;
                mtu_probe_data_bytes(usize::from(datagram_bytes))
                    .ok_or(DirectPathError::InvalidPolicy)?
            ],
        };
        for _ in 0..policy.max_attempts.min(3) {
            send_encrypted_packet(socket, peer, path_id, cipher, &probe).await?;
            let deadline = wall_now().saturating_add_nanos(duration_nanos(probe_rto));
            let mut unrelated = 0_u16;
            loop {
                let Ok(received) = timeout_at(deadline, socket.recv_from(&mut buffer)).await else {
                    break;
                };
                let (length, source) = received.map_err(|source| {
                    direct_io("receive a packetization-layer probe receipt", source)
                })?;
                if source == peer {
                    match open_direct_packet(cipher, path_id, &buffer[..length]) {
                        Some(DirectPacket::MtuAck {
                            token: ack_token,
                            datagram_bytes: ack_bytes,
                        }) if ack_token == token && ack_bytes == datagram_bytes => {
                            let result = DirectPacket::MtuResult {
                                token,
                                datagram_bytes,
                            };
                            for _ in 0..3 {
                                send_encrypted_packet(socket, peer, path_id, cipher, &result)
                                    .await?;
                            }
                            return Ok(usize::from(datagram_bytes));
                        }
                        Some(DirectPacket::Confirm { challenge })
                            if challenge == local_challenge =>
                        {
                            send_confirm(socket, peer, path_id, cipher, peer_challenge).await?;
                            continue;
                        }
                        _ => {}
                    }
                }
                unrelated = unrelated.saturating_add(1);
                if unrelated >= policy.max_unrelated_datagrams {
                    return Err(DirectPathError::UnrelatedDatagramLimit);
                }
            }
        }
    }
    Err(DirectPathError::Timeout(DirectAcquisitionStage::PathTrial))
}

#[allow(clippy::too_many_arguments)]
async fn discover_path_mtu_receiver(
    socket: &mut UdpSocket,
    peer: SocketAddr,
    path_id: u32,
    cipher: &DatagramCipher,
    local_challenge: [u8; 16],
    peer_challenge: [u8; 16],
    policy: DirectAcquirePolicy,
) -> Result<usize, DirectPathError> {
    let probe_rto = policy
        .initial_rto
        .clamp(Duration::from_millis(50), Duration::from_millis(250));
    let total_waits = usize::from(policy.max_attempts)
        .saturating_mul(DIRECT_MTU_CANDIDATES.len())
        .max(1);
    let mut buffer = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
    let mut series_token = None;
    let mut observed = Vec::with_capacity(DIRECT_MTU_CANDIDATES.len());
    for _ in 0..total_waits {
        let deadline = wall_now().saturating_add_nanos(duration_nanos(probe_rto));
        let mut unrelated = 0_u16;
        loop {
            let Ok(received) = timeout_at(deadline, socket.recv_from(&mut buffer)).await else {
                break;
            };
            let (length, source) = received
                .map_err(|source| direct_io("receive a packetization-layer probe", source))?;
            if source == peer {
                match open_direct_packet(cipher, path_id, &buffer[..length]) {
                    Some(DirectPacket::MtuProbe {
                        token,
                        datagram_bytes,
                        ..
                    }) if usize::from(datagram_bytes) == length
                        && DIRECT_MTU_CANDIDATES.contains(&datagram_bytes)
                        && series_token.is_none_or(|value| value == token) =>
                    {
                        series_token = Some(token);
                        if !observed.contains(&datagram_bytes) {
                            observed.push(datagram_bytes);
                        }
                        send_encrypted_packet(
                            socket,
                            peer,
                            path_id,
                            cipher,
                            &DirectPacket::MtuAck {
                                token,
                                datagram_bytes,
                            },
                        )
                        .await?;
                        continue;
                    }
                    Some(DirectPacket::MtuResult {
                        token,
                        datagram_bytes,
                    }) if series_token == Some(token) && observed.contains(&datagram_bytes) => {
                        return Ok(usize::from(datagram_bytes));
                    }
                    Some(DirectPacket::Trial { .. })
                        if series_token.is_some()
                            && u16::try_from(length)
                                .is_ok_and(|bytes| observed.contains(&bytes)) =>
                    {
                        // A trial is an authenticated implicit result if every
                        // tiny result datagram was lost. Discarding its first
                        // copy is safe because the trial retransmits by design.
                        return Ok(length);
                    }
                    Some(DirectPacket::Confirm { challenge }) if challenge == local_challenge => {
                        send_confirm(socket, peer, path_id, cipher, peer_challenge).await?;
                        continue;
                    }
                    _ => {}
                }
            }
            unrelated = unrelated.saturating_add(1);
            if unrelated >= policy.max_unrelated_datagrams {
                return Err(DirectPathError::UnrelatedDatagramLimit);
            }
        }
    }
    Err(DirectPathError::Timeout(DirectAcquisitionStage::PathTrial))
}

#[allow(clippy::too_many_arguments)]
async fn measure_direct_goodput(
    socket: &mut UdpSocket,
    peer: SocketAddr,
    path_id: u32,
    role: Role,
    cipher: &DatagramCipher,
    local_challenge: [u8; 16],
    peer_challenge: [u8; 16],
    policy: DirectAcquirePolicy,
    max_datagram_bytes: usize,
) -> Result<u64, DirectPathError> {
    match role {
        Role::Sender => {
            trial_sender(socket, peer, path_id, cipher, policy, max_datagram_bytes).await
        }
        Role::Receiver => {
            trial_receiver(
                socket,
                peer,
                path_id,
                cipher,
                local_challenge,
                peer_challenge,
                policy,
            )
            .await
        }
    }
}

struct TrialSender<'a> {
    peer: SocketAddr,
    path_id: u32,
    cipher: &'a DatagramCipher,
    token: u64,
    count: u8,
    acquire: DirectAcquirePolicy,
    delivery: crate::DirectRecordPolicy,
}

impl TrialSender<'_> {
    async fn send_flight(
        &self,
        socket: &mut UdpSocket,
        flight: &[u8],
        data: &[u8],
    ) -> Result<(), DirectPathError> {
        for (position, index) in flight.iter().copied().enumerate() {
            send_encrypted_packet(
                socket,
                self.peer,
                self.path_id,
                self.cipher,
                &DirectPacket::Trial {
                    token: self.token,
                    index,
                    count: self.count,
                    data: data.to_vec(),
                },
            )
            .await?;
            if position + 1 < flight.len() && !self.delivery.pacing_interval.is_zero() {
                sleep(wall_now(), self.delivery.pacing_interval).await;
            }
        }
        Ok(())
    }

    async fn collect_acks(
        &self,
        socket: &mut UdpSocket,
        flight: &[u8],
        acknowledged: u64,
        rto: Duration,
    ) -> Result<u64, DirectPathError> {
        let deadline = wall_now().saturating_add_nanos(duration_nanos(rto));
        let mut acknowledged = acknowledged;
        let mut unrelated = 0_u16;
        let mut buffer = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
        loop {
            let Ok(received) = timeout_at(deadline, socket.recv_from(&mut buffer)).await else {
                return Ok(acknowledged);
            };
            let (length, source) = received
                .map_err(|source| direct_io("receive a path-trial acknowledgement", source))?;
            if source == self.peer
                && let Some(DirectPacket::TrialAck {
                    token,
                    count,
                    bitmap,
                }) = open_direct_packet(self.cipher, self.path_id, &buffer[..length])
                && token == self.token
                && count == self.count
            {
                acknowledged |= bitmap;
                if flight
                    .iter()
                    .all(|index| acknowledged & (1_u64 << index) != 0)
                {
                    return Ok(acknowledged);
                }
                continue;
            }
            unrelated = unrelated.saturating_add(1);
            if unrelated >= self.acquire.max_unrelated_datagrams {
                return Err(DirectPathError::UnrelatedDatagramLimit);
            }
        }
    }
}

async fn trial_sender(
    socket: &mut UdpSocket,
    peer: SocketAddr,
    path_id: u32,
    cipher: &DatagramCipher,
    policy: DirectAcquirePolicy,
    max_datagram_bytes: usize,
) -> Result<u64, DirectPathError> {
    const COUNT: u8 = 32;
    let delivery = crate::DirectRecordPolicy::default();
    let token = u64::from_be_bytes(random_16()?[..8].try_into().expect("eight-byte prefix"));
    let trial = TrialSender {
        peer,
        path_id,
        cipher,
        token,
        count: COUNT,
        acquire: policy,
        delivery,
    };
    let data_len = max_datagram_bytes
        .checked_sub(DIRECT_CIPHERTEXT_HEADER_BYTES + DIRECT_AEAD_TAG_BYTES + 12)
        .ok_or(DirectPathError::InvalidPolicy)?;
    let mut data = vec![0_u8; data_len];
    getrandom::fill(&mut data).map_err(|_| DirectPathError::EntropyUnavailable)?;
    let started = wall_now();
    let mut acknowledged = 0_u64;
    let complete = (1_u64 << COUNT) - 1;
    let base_rto = policy
        .initial_rto
        .max(delivery.min_rto)
        .min(delivery.max_rto);
    let mut rto = base_rto;
    let mut congestion_window = delivery.initial_window.min(COUNT);
    let mut no_progress_timeouts = 0_u8;
    while acknowledged != complete {
        let flight = (0..COUNT)
            .filter(|index| acknowledged & (1_u64 << index) == 0)
            .take(usize::from(congestion_window))
            .collect::<Vec<_>>();
        trial.send_flight(socket, &flight, &data).await?;
        let before = acknowledged;
        acknowledged = trial
            .collect_acks(socket, &flight, acknowledged, rto)
            .await?;

        let flight_complete = flight
            .iter()
            .all(|index| acknowledged & (1_u64 << index) != 0);
        if flight_complete {
            let gained = (acknowledged ^ before).count_ones().max(1);
            congestion_window = congestion_window
                .saturating_add(u8::try_from(gained).unwrap_or(u8::MAX))
                .min(delivery.max_window)
                .min(COUNT);
            no_progress_timeouts = 0;
            rto = base_rto;
        } else {
            congestion_window = (congestion_window / 2).max(2);
            rto = rto.saturating_mul(2).min(delivery.max_rto);
            no_progress_timeouts = if acknowledged == before {
                no_progress_timeouts.saturating_add(1)
            } else {
                0
            };
            if no_progress_timeouts >= policy.max_attempts.min(delivery.max_timeouts) {
                return Err(DirectPathError::Timeout(DirectAcquisitionStage::PathTrial));
            }
        }
    }

    let elapsed_ns = wall_now().duration_since(started).max(1);
    let useful_bits = u64::from(COUNT)
        .saturating_mul(u64::try_from(data_len).unwrap_or(u64::MAX))
        .saturating_mul(8);
    let measured = u128::from(useful_bits).saturating_mul(1_000_000_000) / u128::from(elapsed_ns);
    let floor = u64::try_from(measured / 2).unwrap_or(u64::MAX).max(1);
    let result = DirectPacket::TrialResult {
        goodput_floor_bps: floor,
    };
    for _ in 0..3 {
        send_encrypted_packet(socket, peer, path_id, cipher, &result).await?;
    }
    Ok(floor)
}

#[allow(clippy::too_many_arguments)]
async fn trial_receiver(
    socket: &mut UdpSocket,
    peer: SocketAddr,
    path_id: u32,
    cipher: &DatagramCipher,
    local_challenge: [u8; 16],
    peer_challenge: [u8; 16],
    policy: DirectAcquirePolicy,
) -> Result<u64, DirectPathError> {
    let mut token = None;
    let mut count = None;
    let mut bitmap = 0_u64;
    let mut rto = policy.initial_rto;
    let mut buffer = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
    for _ in 0..policy.max_attempts {
        let deadline = wall_now().saturating_add_nanos(duration_nanos(rto));
        let mut unrelated = 0_u16;
        loop {
            let Ok(received) = timeout_at(deadline, socket.recv_from(&mut buffer)).await else {
                break;
            };
            let (length, source) =
                received.map_err(|source| direct_io("receive a path-trial datagram", source))?;
            if source == peer {
                match open_direct_packet(cipher, path_id, &buffer[..length]) {
                    Some(DirectPacket::Trial {
                        token: packet_token,
                        index,
                        count: packet_count,
                        ..
                    }) if token.is_none_or(|value| value == packet_token)
                        && count.is_none_or(|value| value == packet_count) =>
                    {
                        token = Some(packet_token);
                        count = Some(packet_count);
                        bitmap |= 1_u64 << index;
                        send_encrypted_packet(
                            socket,
                            peer,
                            path_id,
                            cipher,
                            &DirectPacket::TrialAck {
                                token: packet_token,
                                count: packet_count,
                                bitmap,
                            },
                        )
                        .await?;
                        continue;
                    }
                    Some(DirectPacket::TrialResult { goodput_floor_bps })
                        if count.is_some_and(|value| bitmap == (1_u64 << value) - 1) =>
                    {
                        return Ok(goodput_floor_bps);
                    }
                    Some(DirectPacket::Confirm { challenge }) if challenge == local_challenge => {
                        send_encrypted_packet(
                            socket,
                            peer,
                            path_id,
                            cipher,
                            &DirectPacket::Confirm {
                                challenge: peer_challenge,
                            },
                        )
                        .await?;
                        continue;
                    }
                    _ => {}
                }
            }
            unrelated = unrelated.saturating_add(1);
            if unrelated >= policy.max_unrelated_datagrams {
                return Err(DirectPathError::UnrelatedDatagramLimit);
            }
        }
        rto = rto.saturating_mul(2).min(Duration::from_secs(2));
    }
    Err(DirectPathError::Timeout(DirectAcquisitionStage::PathTrial))
}

async fn send_encrypted_packet(
    socket: &mut UdpSocket,
    peer: SocketAddr,
    path_id: u32,
    cipher: &DatagramCipher,
    packet: &DirectPacket,
) -> Result<(), DirectPathError> {
    let plaintext = packet.encode()?;
    let mut encrypted = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
    let (nonce, length) = cipher.seal(&plaintext, &mut encrypted)?;
    let datagram = DirectCiphertext {
        path_id,
        nonce,
        payload: encrypted[..length].to_vec(),
    }
    .encode()?;
    send_datagram_attempt(socket, &datagram, peer)
        .await
        .map_err(|source| direct_io("send an encrypted path-trial datagram", source))?;
    Ok(())
}

fn open_direct_packet(
    cipher: &DatagramCipher,
    path_id: u32,
    datagram: &[u8],
) -> Option<DirectPacket> {
    let envelope = DirectCiphertext::decode(datagram).ok()?;
    if envelope.path_id != path_id {
        return None;
    }
    let mut plaintext = [0_u8; rift_protocol::MAX_DIRECT_PACKET_BYTES];
    let length = cipher
        .open(envelope.nonce, &envelope.payload, &mut plaintext)
        .ok()?;
    DirectPacket::decode(&plaintext[..length]).ok()
}

fn derive_path_id(
    lookup_id: [u8; 16],
    role: Role,
    local_nonce: [u8; 16],
    peer_nonce: [u8; 16],
) -> u32 {
    let context = path_context(lookup_id, 0, role, local_nonce, peer_nonce);
    let digest = blake3::derive_key(PATH_DOMAIN, &context);
    u32::from_be_bytes(digest[..4].try_into().expect("four-byte digest prefix"))
}

fn path_context(
    lookup_id: [u8; 16],
    path_id: u32,
    role: Role,
    local_nonce: [u8; 16],
    peer_nonce: [u8; 16],
) -> Vec<u8> {
    let (sender_nonce, receiver_nonce) = match role {
        Role::Sender => (local_nonce, peer_nonce),
        Role::Receiver => (peer_nonce, local_nonce),
    };
    let mut output = Vec::with_capacity(52);
    output.extend_from_slice(&lookup_id);
    output.extend_from_slice(&path_id.to_be_bytes());
    output.extend_from_slice(&sender_nonce);
    output.extend_from_slice(&receiver_nonce);
    output
}

#[allow(clippy::too_many_arguments)]
fn direct_prologue(
    lookup_id: [u8; 16],
    path_id: u32,
    role: Role,
    local_nonce: [u8; 16],
    peer_nonce: [u8; 16],
    local_challenge: [u8; 16],
    peer_challenge: [u8; 16],
) -> Vec<u8> {
    let (sender_nonce, receiver_nonce, sender_challenge, receiver_challenge) = match role {
        Role::Sender => (local_nonce, peer_nonce, local_challenge, peer_challenge),
        Role::Receiver => (peer_nonce, local_nonce, peer_challenge, local_challenge),
    };
    let mut output = Vec::with_capacity(PROLOGUE_MAGIC.len() + 84);
    output.extend_from_slice(PROLOGUE_MAGIC);
    output.extend_from_slice(&lookup_id);
    output.extend_from_slice(&path_id.to_be_bytes());
    output.extend_from_slice(&sender_nonce);
    output.extend_from_slice(&receiver_nonce);
    output.extend_from_slice(&sender_challenge);
    output.extend_from_slice(&receiver_challenge);
    output
}

fn derive_key(domain: &str, secret: &[u8; 32], context: &[u8]) -> [u8; 32] {
    let mut material = Zeroizing::new(Vec::with_capacity(secret.len() + context.len()));
    material.extend_from_slice(secret);
    material.extend_from_slice(context);
    blake3::derive_key(domain, &material)
}

fn authenticate(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    blake3::keyed_hash(key, message).as_bytes()[..16]
        .try_into()
        .expect("fixed authenticator prefix")
}

fn random_16() -> Result<[u8; 16], DirectPathError> {
    let mut output = [0_u8; 16];
    getrandom::fill(&mut output).map_err(|_| DirectPathError::EntropyUnavailable)?;
    if output == [0; 16] {
        return Err(DirectPathError::EntropyUnavailable);
    }
    Ok(output)
}

async fn send_datagram_attempt(
    socket: &mut UdpSocket,
    bytes: &[u8],
    target: SocketAddr,
) -> io::Result<()> {
    let sent = match socket.send_to(bytes, target).await {
        Ok(sent) => sent,
        Err(error) if is_unattributable_udp_path_signal(&error) => {
            // An unconnected UDP socket can surface a delayed ICMP error from
            // an earlier destination on the next send. Acquisition crosses
            // relay and peer destinations on one socket, so the error cannot
            // safely be attributed to this packet. Treat exactly this attempt
            // as loss; every owning stage remains strictly retry-bounded.
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if sent == bytes.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial direct-path datagram send",
        ))
    }
}

fn is_unattributable_udp_path_signal(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::PermissionDenied
    ) || is_message_too_long(error)
}

#[cfg(target_os = "linux")]
fn is_message_too_long(error: &io::Error) -> bool {
    error.raw_os_error() == Some(90)
}

#[cfg(not(target_os = "linux"))]
fn is_message_too_long(_error: &io::Error) -> bool {
    false
}

fn direct_io(operation: &'static str, source: io::Error) -> DirectPathError {
    DirectPathError::Io { operation, source }
}

const fn opposite(role: Role) -> Role {
    match role {
        Role::Sender => Role::Receiver,
        Role::Receiver => Role::Sender,
    }
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use asupersync::{cx::Cx, net::UdpSocket, runtime::RuntimeBuilder};
    use rift_protocol::SequencedRecord;
    use rift_relay::{RelayPolicy, serve_direct_rendezvous};

    use super::*;
    use crate::{DirectRecordPolicy, DirectRecordReceiver, DirectRecordSender};

    #[test]
    fn both_roles_derive_identical_path_context_and_prologue() {
        let sender = direct_prologue([1; 16], 7, Role::Sender, [2; 16], [3; 16], [4; 16], [5; 16]);
        let receiver = direct_prologue(
            [1; 16],
            7,
            Role::Receiver,
            [3; 16],
            [2; 16],
            [5; 16],
            [4; 16],
        );
        assert_eq!(sender, receiver);
        assert_eq!(
            derive_path_id([1; 16], Role::Sender, [2; 16], [3; 16]),
            derive_path_id([1; 16], Role::Receiver, [3; 16], [2; 16])
        );
    }

    #[test]
    fn wrong_probe_key_fails_before_path_validation() {
        let probe = signed_probe([1; 16], Role::Sender, 9, [2; 16], [3; 16], &[4; 32]);
        assert!(
            authenticate_probe(
                &probe.encode(),
                "127.0.0.1:1".parse().unwrap(),
                "127.0.0.1:1".parse().unwrap(),
                [1; 16],
                Role::Sender,
                9,
                &[5; 32],
            )
            .is_none()
        );
    }

    #[test]
    fn loopback_peers_acquire_one_authenticated_direct_path() {
        let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        runtime.block_on(async move {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = udp.local_addr().unwrap();
            let mut relay_task = Cx::current()
                .unwrap()
                .spawn(move |_cx| async move {
                    serve_direct_rendezvous(
                        udp,
                        RelayPolicy {
                            match_timeout_ms: 2_000,
                            ..RelayPolicy::default()
                        },
                    )
                    .await
                })
                .unwrap();
            let policy = DirectAcquirePolicy {
                initial_rto: Duration::from_millis(50),
                max_attempts: 8,
                max_unrelated_datagrams: 16,
            };
            let cx = Cx::current().unwrap();
            let mut sender_task = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [7; 16],
                        &[8; 32],
                        Role::Sender,
                        policy,
                    )
                    .await
                })
                .unwrap();
            let mut receiver_task = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [7; 16],
                        &[8; 32],
                        Role::Receiver,
                        policy,
                    )
                    .await
                })
                .unwrap();
            let sender = sender_task.join(&cx).await.unwrap().unwrap();
            let receiver = receiver_task.join(&cx).await.unwrap().unwrap();
            assert_eq!(sender.path_id(), receiver.path_id());
            assert_eq!(sender.max_datagram_bytes(), MAX_DIRECT_DATAGRAM_BYTES);
            assert_eq!(receiver.max_datagram_bytes(), MAX_DIRECT_DATAGRAM_BYTES);
            assert_eq!(
                sender.peer_addr().port(),
                receiver.socket.local_addr().unwrap().port()
            );
            assert_eq!(
                receiver.peer_addr().port(),
                sender.socket.local_addr().unwrap().port()
            );
            relay_task.abort();
            let _ = relay_task.join(&cx).await;
        });
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn authenticated_plpmtud_selects_the_largest_delivered_candidate() {
        let runtime = RuntimeBuilder::new().worker_threads(6).build().unwrap();
        runtime.block_on(async move {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = udp.local_addr().unwrap();
            let cx = Cx::current().unwrap();
            let mut relay_task = cx
                .spawn(move |_cx| async move {
                    serve_direct_rendezvous(udp, RelayPolicy::default()).await
                })
                .unwrap();
            let policy = DirectAcquirePolicy {
                initial_rto: Duration::from_millis(50),
                max_attempts: 8,
                max_unrelated_datagrams: 64,
            };
            let mut sender_task = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0xB7; 16],
                        &[0xC8; 32],
                        Role::Sender,
                        policy,
                    )
                    .await
                })
                .unwrap();
            let mut receiver_task = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0xB7; 16],
                        &[0xC8; 32],
                        Role::Receiver,
                        policy,
                    )
                    .await
                })
                .unwrap();
            let mut sender = sender_task.join(&cx).await.unwrap().unwrap();
            let mut receiver = receiver_task.join(&cx).await.unwrap().unwrap();
            let sender_actual = SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                sender.socket.local_addr().unwrap().port(),
            );
            let receiver_actual = SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                receiver.socket.local_addr().unwrap().port(),
            );
            let mut proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let proxy_addr = proxy.local_addr().unwrap();
            sender.peer = proxy_addr;
            receiver.peer = proxy_addr;
            let mut proxy_task = cx
                .spawn(move |proxy_cx| async move {
                    let mut buffer = [0_u8; MAX_DIRECT_DATAGRAM_BYTES];
                    loop {
                        if proxy_cx.checkpoint().is_err() {
                            break;
                        }
                        let Ok((length, source)) = proxy.recv_from(&mut buffer).await else {
                            break;
                        };
                        if source == sender_actual {
                            if length <= 1_280 {
                                proxy
                                    .send_to(&buffer[..length], receiver_actual)
                                    .await
                                    .unwrap();
                            }
                        } else if source == receiver_actual {
                            proxy
                                .send_to(&buffer[..length], sender_actual)
                                .await
                                .unwrap();
                        }
                    }
                })
                .unwrap();
            let mut sender_probe = cx
                .spawn(move |_cx| async move {
                    let selected = discover_path_mtu(
                        &mut sender.socket,
                        sender.peer,
                        sender.path_id,
                        Role::Sender,
                        &sender.cipher,
                        sender.local_challenge,
                        sender.peer_challenge,
                        policy,
                    )
                    .await?;
                    sender.max_datagram_bytes = selected;
                    Ok::<DirectPath, DirectPathError>(sender)
                })
                .unwrap();
            let mut receiver_probe = cx
                .spawn(move |_cx| async move {
                    let selected = discover_path_mtu(
                        &mut receiver.socket,
                        receiver.peer,
                        receiver.path_id,
                        Role::Receiver,
                        &receiver.cipher,
                        receiver.local_challenge,
                        receiver.peer_challenge,
                        policy,
                    )
                    .await?;
                    receiver.max_datagram_bytes = selected;
                    Ok::<DirectPath, DirectPathError>(receiver)
                })
                .unwrap();
            let sender = sender_probe.join(&cx).await.unwrap().unwrap();
            let receiver = receiver_probe.join(&cx).await.unwrap().unwrap();
            assert_eq!(sender.max_datagram_bytes(), 1_280);
            assert_eq!(receiver.max_datagram_bytes(), 1_280);

            let record_policy = DirectRecordPolicy {
                idle_timeout: Duration::from_secs(3),
                ..DirectRecordPolicy::default()
            };
            let mut record_receiver =
                DirectRecordReceiver::new(receiver, 0, record_policy).unwrap();
            let mut record_receive_task = cx
                .spawn(move |_cx| async move { record_receiver.receive_record().await })
                .unwrap();
            let expected = SequencedRecord {
                sequence: 0,
                payload: vec![0x8D; 57_000],
            };
            let mut record_sender = DirectRecordSender::new(sender, record_policy).unwrap();
            let stats = record_sender.send_record(&expected).await.unwrap();
            assert_eq!(
                record_receive_task.join(&cx).await.unwrap().unwrap(),
                expected
            );
            assert!(stats.datagrams_sent > 1);
            proxy_task.abort();
            let _ = proxy_task.join(&cx).await;
            relay_task.abort();
            let _ = relay_task.join(&cx).await;
        });
    }

    #[test]
    fn matched_lookup_with_wrong_secret_never_authenticates_the_path() {
        let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        runtime.block_on(async move {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = udp.local_addr().unwrap();
            let cx = Cx::current().unwrap();
            let mut relay_task = cx
                .spawn(move |_cx| async move {
                    serve_direct_rendezvous(udp, RelayPolicy::default()).await
                })
                .unwrap();
            let policy = DirectAcquirePolicy {
                initial_rto: Duration::from_millis(30),
                max_attempts: 3,
                max_unrelated_datagrams: 64,
            };
            let mut sender = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0x91; 16],
                        &[0xA1; 32],
                        Role::Sender,
                        policy,
                    )
                    .await
                })
                .unwrap();
            let mut receiver = cx
                .spawn(move |_cx| async move {
                    acquire_direct_path(
                        &RelayEndpoint::Loopback(relay),
                        [0x91; 16],
                        &[0xA2; 32],
                        Role::Receiver,
                        policy,
                    )
                    .await
                })
                .unwrap();
            assert!(sender.join(&cx).await.unwrap().is_err());
            assert!(receiver.join(&cx).await.unwrap().is_err());
            relay_task.abort();
            let _ = relay_task.join(&cx).await;
        });
    }
}
