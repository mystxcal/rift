//! Authenticated selection of a direct or TURN-carried QUIC data plane.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use asupersync::{
    cx::Cx,
    net::{UdpSocket, lookup_all},
    runtime::TaskHandle,
    time::{sleep, timeout_at, wall_now},
};
use rift_protocol::{Role, RouteBundle, RouteTransport};
use rift_transport::QuicServerIdentity;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    DirectPathError, DirectQuicLink, DirectQuicLinkError, MigrationPolicy, RelayStream,
    SecureStream, SecureStreamError, StunPolicy, TurnStreamAllocation, TurnUdpAllocation,
    direct::DirectQuicCandidate,
    discover_server_reflexive,
    path_pool::{CarrierKind, QuicPathPool},
};

const OFFER_MAGIC: [u8; 4] = *b"RFQO";
const DECISION_MAGIC: [u8; 4] = *b"RFQD";
const BENCH_STATUS_MAGIC: [u8; 4] = *b"RFQB";
const SELECTION_MAGIC: [u8; 4] = *b"RFQS";
const VERSION: u8 = 4;
const OFFER_HEADER_BYTES: usize = 100;
const MAX_CERTIFICATE_BYTES: usize = 4 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const PROBE_MAGIC: [u8; 4] = *b"RFQP";
const PROBE_BYTES: usize = 40;
const SRFLX_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const SRFLX_PROBE_RTO: Duration = Duration::from_millis(75);
const PROBE_CONFIRMATION_WINDOW: Duration = Duration::from_millis(150);
const PROBE_CONFIRMATION_RTO: Duration = Duration::from_millis(25);
const MAX_PROBE_NOISE: u16 = 128;
const TURN_STREAM_HEAD_START: Duration = Duration::from_millis(150);
const ALTERNATE_ROUTE_HEAD_START: Duration = Duration::from_millis(75);
const BENCHMARK_RECORD_BYTES: usize = 48 * 1024;
const BENCHMARK_RECORDS: usize = 6;
const BENCHMARK_TIMEOUT: Duration = Duration::from_secs(4);
const RELAY_SELECTION: u8 = u8::MAX;

/// Selected authenticated data plane. Relay is always the correctness fallback.
pub(crate) enum QuicPathSelection {
    Relay(Box<SecureStream<RelayStream>>),
    Quic(Box<QuicPathPool>),
}

/// Failure before both peers can agree on a data plane.
#[derive(Debug, Error)]
pub enum QuicPathSelectionError {
    /// The authenticated relay control stream failed.
    #[error(transparent)]
    Secure(#[from] SecureStreamError),
    /// A peer sent a malformed, contradictory, or non-canonical offer.
    #[error("invalid authenticated QUIC path offer")]
    InvalidOffer,
    /// The sender could not generate its transfer-scoped pinned identity.
    #[error("could not generate the transfer-scoped QUIC identity: {0}")]
    Identity(#[from] rift_transport::QuicIdentityError),
    /// Local path-selection time policy was inert or excessive.
    #[error("invalid QUIC path-selection policy")]
    InvalidPolicy,
    /// Transfer-scoped path-probe entropy was unavailable.
    #[error("could not generate authenticated path-probe entropy")]
    EntropyUnavailable,
}

struct LocalCandidates {
    direct: Option<DirectQuicCandidate>,
    host: Option<HostSocket>,
    srflx: Option<StunSocket>,
    turn: Option<TurnUdpAllocation>,
    turn_stream: Option<TurnStreamAllocation>,
}

struct HostSocket {
    socket: UdpSocket,
    address: SocketAddr,
    peer: Option<SocketAddr>,
}

struct StunSocket {
    socket: UdpSocket,
    mapped: SocketAddr,
    peer: Option<SocketAddr>,
    kind: CarrierKind,
}

struct PathOffer {
    direct_ready: bool,
    turn_udp_relay: Option<SocketAddr>,
    turn_stream_relay: Option<SocketAddr>,
    host: Option<SocketAddr>,
    srflx: Option<SocketAddr>,
    probe_nonce: [u8; 16],
    certificate: Vec<u8>,
}

// Put the host/server-reflexive socket first so a proved LAN path becomes the
// control and initial payload carrier instead of a public rendezvous path.
const HOST_SLOT: usize = 0;
const SRFLX_SLOT: usize = 1;
const DIRECT_SLOT: usize = 2;
const TURN_UDP_SLOT: usize = 3;
const TURN_STREAM_SLOT: usize = 4;
const PATH_SLOTS: usize = 5;

/// Select the sender's fastest mutually ready QUIC carrier, falling back to
/// the already-authenticated relay without making acceleration an availability
/// dependency.
pub(crate) async fn select_sender_quic(
    mut secure: SecureStream<RelayStream>,
    direct: Option<TaskHandle<Result<DirectQuicCandidate, DirectPathError>>>,
    routes: Option<RouteBundle>,
    policy: MigrationPolicy,
    transfer_secret: &[u8; 32],
    allow_acceleration: bool,
) -> Result<QuicPathSelection, QuicPathSelectionError> {
    if !policy.validate() {
        return Err(QuicPathSelectionError::InvalidPolicy);
    }
    let candidates = gather_candidates(direct, routes, policy).await;
    let probe_nonce = candidate_nonce(&candidates)?;
    let local = PathOffer {
        direct_ready: candidates.direct.is_some(),
        turn_udp_relay: candidates
            .turn
            .as_ref()
            .map(TurnUdpAllocation::relayed_addr),
        turn_stream_relay: candidates
            .turn_stream
            .as_ref()
            .map(TurnStreamAllocation::relayed_addr),
        host: candidates.host.as_ref().map(|candidate| candidate.address),
        srflx: candidates.srflx.as_ref().map(|candidate| candidate.mapped),
        probe_nonce,
        certificate: Vec::new(),
    };
    let peer = exchange_offer(&mut secure, &local).await?;
    if peer.certificate.is_empty() || peer.certificate.len() > MAX_CERTIFICATE_BYTES {
        return Err(QuicPathSelectionError::InvalidOffer);
    }
    let candidates = validate_udp_candidates(
        candidates,
        &peer,
        transfer_secret,
        Role::Sender,
        probe_nonce,
    )
    .await;
    let attempts = Box::pin(build_sender_links(candidates, &peer, policy)).await;
    Box::pin(settle_attempts(
        secure,
        attempts,
        Role::Sender,
        allow_acceleration,
    ))
    .await
}

/// Select the receiver's fastest mutually ready QUIC carrier.
pub(crate) async fn select_receiver_quic(
    mut secure: SecureStream<RelayStream>,
    direct: Option<TaskHandle<Result<DirectQuicCandidate, DirectPathError>>>,
    routes: Option<RouteBundle>,
    policy: MigrationPolicy,
    transfer_secret: &[u8; 32],
    allow_acceleration: bool,
) -> Result<QuicPathSelection, QuicPathSelectionError> {
    if !policy.validate() {
        return Err(QuicPathSelectionError::InvalidPolicy);
    }
    let identity = QuicServerIdentity::generate()?;
    let candidates = gather_candidates(direct, routes, policy).await;
    let probe_nonce = candidate_nonce(&candidates)?;
    let local = PathOffer {
        direct_ready: candidates.direct.is_some(),
        turn_udp_relay: candidates
            .turn
            .as_ref()
            .map(TurnUdpAllocation::relayed_addr),
        turn_stream_relay: candidates
            .turn_stream
            .as_ref()
            .map(TurnStreamAllocation::relayed_addr),
        host: candidates.host.as_ref().map(|candidate| candidate.address),
        srflx: candidates.srflx.as_ref().map(|candidate| candidate.mapped),
        probe_nonce,
        certificate: identity.certificate().to_vec(),
    };
    let peer = exchange_offer(&mut secure, &local).await?;
    if peer.certificate.is_empty() {
        let candidates = validate_udp_candidates(
            candidates,
            &peer,
            transfer_secret,
            Role::Receiver,
            probe_nonce,
        )
        .await;
        let attempts = Box::pin(build_receiver_links(candidates, &peer, &identity, policy)).await;
        return Box::pin(settle_attempts(
            secure,
            attempts,
            Role::Receiver,
            allow_acceleration,
        ))
        .await;
    }
    Err(QuicPathSelectionError::InvalidOffer)
}

async fn gather_candidates(
    mut direct_task: Option<TaskHandle<Result<DirectQuicCandidate, DirectPathError>>>,
    routes: Option<RouteBundle>,
    policy: MigrationPolicy,
) -> LocalCandidates {
    let mut host_task = spawn_host_socket(routes.as_ref());
    let mut stun_task = spawn_stun_socket(routes.as_ref());
    let mut turn_task = spawn_turn_allocation(routes.as_ref(), policy.turn_setup_timeout);
    let mut turn_stream_task =
        spawn_turn_stream_allocation(routes.as_ref(), policy.turn_setup_timeout);
    let mut direct = None;
    let mut host = None;
    let mut srflx = None;
    let mut turn = None;
    let mut turn_stream = None;
    let started = Instant::now();
    let deadline = started + policy.gather_budget;
    let mut first_ready = None;
    // Arrival order never chooses the route. Gathering stops only after UDP
    // discovery settles (plus a short grace for other ready candidates), all
    // work finishes, or the outer network-operation bound expires. The live
    // candidates are authenticated and benchmarked below before selection.
    loop {
        poll_direct(&mut direct_task, &mut direct);
        poll_host(&mut host_task, &mut host);
        poll_stun(&mut stun_task, &mut srflx);
        poll_turn(&mut turn_task, &mut turn);
        poll_turn_stream(&mut turn_stream_task, &mut turn_stream);
        if (host.is_some()
            || srflx.is_some()
            || direct.is_some()
            || turn.is_some()
            || turn_stream.is_some())
            && first_ready.is_none()
        {
            first_ready = Some(Instant::now());
        }
        let now = Instant::now();
        let all_finished = direct_task.is_none()
            && host_task.is_none()
            && stun_task.is_none()
            && turn_task.is_none()
            && turn_stream_task.is_none();
        let ready_grace_elapsed =
            first_ready.is_some_and(|ready| now.duration_since(ready) >= policy.ready_grace);
        if (GatherState {
            all_finished,
            deadline_reached: now >= deadline,
            discovery: if host_task.is_some() || stun_task.is_some() {
                DiscoveryState::Pending
            } else {
                DiscoveryState::Settled
            },
            ready_grace_elapsed,
        })
        .is_complete()
        {
            break;
        }
        sleep(wall_now(), POLL_INTERVAL).await;
    }
    stop_task(&mut direct_task).await;
    stop_task(&mut host_task).await;
    stop_task(&mut stun_task).await;
    stop_task(&mut turn_task).await;
    stop_task(&mut turn_stream_task).await;
    LocalCandidates {
        direct,
        host,
        srflx,
        turn,
        turn_stream,
    }
}

struct GatherState {
    all_finished: bool,
    deadline_reached: bool,
    discovery: DiscoveryState,
    ready_grace_elapsed: bool,
}

enum DiscoveryState {
    Pending,
    Settled,
}

impl GatherState {
    const fn is_complete(&self) -> bool {
        self.all_finished
            || self.deadline_reached
            || (matches!(self.discovery, DiscoveryState::Settled) && self.ready_grace_elapsed)
    }
}

fn poll_direct(
    task: &mut Option<TaskHandle<Result<DirectQuicCandidate, DirectPathError>>>,
    result: &mut Option<DirectQuicCandidate>,
) {
    let Some(pending) = task else { return };
    match pending.try_join() {
        Ok(Some(Ok(path))) => {
            *result = Some(path);
            *task = None;
        }
        Ok(Some(Err(_))) | Err(_) => *task = None,
        Ok(None) => {}
    }
}

fn poll_host(
    task: &mut Option<TaskHandle<Result<HostSocket, DirectQuicLinkError>>>,
    result: &mut Option<HostSocket>,
) {
    let Some(pending) = task else { return };
    match pending.try_join() {
        Ok(Some(Ok(candidate))) => {
            *result = Some(candidate);
            *task = None;
        }
        Ok(Some(Err(_))) | Err(_) => *task = None,
        Ok(None) => {}
    }
}

fn poll_turn(
    task: &mut Option<TaskHandle<Result<TurnUdpAllocation, DirectQuicLinkError>>>,
    result: &mut Option<TurnUdpAllocation>,
) {
    let Some(pending) = task else { return };
    match pending.try_join() {
        Ok(Some(Ok(allocation))) => {
            *result = Some(allocation);
            *task = None;
        }
        Ok(Some(Err(_))) | Err(_) => *task = None,
        Ok(None) => {}
    }
}

fn poll_turn_stream(
    task: &mut Option<TaskHandle<Result<TurnStreamAllocation, DirectQuicLinkError>>>,
    result: &mut Option<TurnStreamAllocation>,
) {
    let Some(pending) = task else { return };
    match pending.try_join() {
        Ok(Some(Ok(allocation))) => {
            *result = Some(allocation);
            *task = None;
        }
        Ok(Some(Err(_))) | Err(_) => *task = None,
        Ok(None) => {}
    }
}

fn poll_stun(
    task: &mut Option<TaskHandle<Result<StunSocket, DirectQuicLinkError>>>,
    result: &mut Option<StunSocket>,
) {
    let Some(pending) = task else { return };
    match pending.try_join() {
        Ok(Some(Ok(candidate))) => {
            *result = Some(candidate);
            *task = None;
        }
        Ok(Some(Err(_))) | Err(_) => *task = None,
        Ok(None) => {}
    }
}

async fn stop_task<T>(task: &mut Option<TaskHandle<T>>) {
    let Some(mut pending) = task.take() else {
        return;
    };
    pending.abort();
    if let Some(cx) = Cx::current() {
        let _ = pending.join(&cx).await;
    }
}

fn spawn_turn_allocation(
    routes: Option<&RouteBundle>,
    setup_timeout: Duration,
) -> Option<TaskHandle<Result<TurnUdpAllocation, DirectQuicLinkError>>> {
    let routes = routes?;
    let authorization = routes.turn()?;
    let servers = routes
        .servers()
        .iter()
        .filter(|server| server.transport == RouteTransport::TurnUdp)
        .cloned()
        .collect::<Vec<_>>();
    if servers.is_empty() {
        return None;
    }
    let username = Zeroizing::new(authorization.username().to_owned());
    let credential = Zeroizing::new(authorization.credential().to_owned());
    Cx::current()?
        .spawn(move |_turn_cx| async move {
            let mut attempts = Vec::new();
            for (route_index, route) in servers.into_iter().enumerate() {
                for server in resolve_race_addresses(&route.host, route.port).await? {
                    let username = Zeroizing::new(username.as_str().to_owned());
                    let credential = Zeroizing::new(credential.as_str().to_owned());
                    let head_start = alternate_route_head_start(route_index);
                    let task = Cx::current()
                        .ok_or_else(no_route_runtime)?
                        .spawn(move |_cx| async move {
                            if !head_start.is_zero() {
                                sleep(wall_now(), head_start).await;
                            }
                            let socket = UdpSocket::bind(unspecified_for(server)).await?;
                            DirectQuicLink::allocate_turn(
                                socket,
                                server,
                                username.as_str(),
                                credential.as_str(),
                                setup_timeout,
                            )
                            .await
                        })
                        .map_err(|error| {
                            DirectQuicLinkError::Io(io::Error::other(error.to_string()))
                        })?;
                    attempts.push(task);
                }
            }
            first_route_success(attempts).await
        })
        .ok()
}

fn spawn_turn_stream_allocation(
    routes: Option<&RouteBundle>,
    setup_timeout: Duration,
) -> Option<TaskHandle<Result<TurnStreamAllocation, DirectQuicLinkError>>> {
    let routes = routes?;
    let authorization = routes.turn()?;
    let servers = routes
        .servers()
        .iter()
        .filter(|server| {
            matches!(
                server.transport,
                RouteTransport::TurnTls | RouteTransport::TurnTcp
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    if servers.is_empty() {
        return None;
    }
    let username = Zeroizing::new(authorization.username().to_owned());
    let credential = Zeroizing::new(authorization.credential().to_owned());
    Cx::current()?
        .spawn(move |_turn_cx| async move {
            sleep(wall_now(), TURN_STREAM_HEAD_START).await;
            let mut attempts = Vec::new();
            for (route_index, route) in servers.into_iter().enumerate() {
                for server in resolve_race_addresses(&route.host, route.port).await? {
                    let server_name = route.host.clone();
                    let tls = route.transport == RouteTransport::TurnTls;
                    let username = Zeroizing::new(username.as_str().to_owned());
                    let credential = Zeroizing::new(credential.as_str().to_owned());
                    let head_start = alternate_route_head_start(route_index);
                    let task = Cx::current()
                        .ok_or_else(no_route_runtime)?
                        .spawn(move |_cx| async move {
                            if !head_start.is_zero() {
                                sleep(wall_now(), head_start).await;
                            }
                            DirectQuicLink::allocate_turn_stream(
                                &server_name,
                                server,
                                tls,
                                username.as_str(),
                                credential.as_str(),
                                setup_timeout,
                            )
                            .await
                        })
                        .map_err(|error| {
                            DirectQuicLinkError::Io(io::Error::other(error.to_string()))
                        })?;
                    attempts.push(task);
                }
            }
            first_route_success(attempts).await
        })
        .ok()
}

fn spawn_stun_socket(
    routes: Option<&RouteBundle>,
) -> Option<TaskHandle<Result<StunSocket, DirectQuicLinkError>>> {
    let servers = routes?
        .servers()
        .iter()
        .filter(|server| server.transport == RouteTransport::StunUdp)
        .cloned()
        .collect::<Vec<_>>();
    if servers.is_empty() {
        return None;
    }
    Cx::current()?
        .spawn(move |_stun_cx| async move {
            let mut attempts = Vec::new();
            for (route_index, route) in servers.into_iter().enumerate() {
                for server in resolve_race_addresses(&route.host, route.port).await? {
                    let head_start = alternate_route_head_start(route_index);
                    let task = Cx::current()
                        .ok_or_else(no_route_runtime)?
                        .spawn(move |_cx| async move {
                            if !head_start.is_zero() {
                                sleep(wall_now(), head_start).await;
                            }
                            let mut socket = UdpSocket::bind(unspecified_for(server)).await?;
                            let mapped = discover_server_reflexive(
                                &mut socket,
                                server,
                                StunPolicy {
                                    initial_rto: Duration::from_millis(100),
                                    max_attempts: 3,
                                    max_unrelated_datagrams: 32,
                                },
                            )
                            .await
                            .map_err(|error| {
                                DirectQuicLinkError::Io(io::Error::other(format!(
                                    "STUN discovery failed: {error}"
                                )))
                            })?
                            .mapped;
                            Ok(StunSocket {
                                socket,
                                mapped,
                                peer: None,
                                kind: CarrierKind::ServerReflexive,
                            })
                        })
                        .map_err(|error| {
                            DirectQuicLinkError::Io(io::Error::other(error.to_string()))
                        })?;
                    attempts.push(task);
                }
            }
            first_route_success(attempts).await
        })
        .ok()
}

fn spawn_host_socket(
    routes: Option<&RouteBundle>,
) -> Option<TaskHandle<Result<HostSocket, DirectQuicLinkError>>> {
    let servers = routes?.servers().to_vec();
    if servers.is_empty() {
        return None;
    }
    Cx::current()?
        .spawn(move |_host_cx| async move {
            let mut attempts = Vec::new();
            for (route_index, route) in servers.into_iter().enumerate() {
                for server in resolve_race_addresses(&route.host, route.port).await? {
                    let head_start = alternate_route_head_start(route_index);
                    let task = Cx::current()
                        .ok_or_else(no_route_runtime)?
                        .spawn(move |_cx| async move {
                            if !head_start.is_zero() {
                                sleep(wall_now(), head_start).await;
                            }
                            let socket = UdpSocket::bind(unspecified_for(server)).await?;
                            let port = socket.local_addr()?.port();
                            let address =
                                local_route_candidate(server, port)?.ok_or_else(|| {
                                    DirectQuicLinkError::Io(io::Error::other(
                                        "route has no usable local host address",
                                    ))
                                })?;
                            Ok(HostSocket {
                                socket,
                                address,
                                peer: None,
                            })
                        })
                        .map_err(|error| {
                            DirectQuicLinkError::Io(io::Error::other(error.to_string()))
                        })?;
                    attempts.push(task);
                }
            }
            first_route_success(attempts).await
        })
        .ok()
}

fn alternate_route_head_start(index: usize) -> Duration {
    ALTERNATE_ROUTE_HEAD_START.saturating_mul(u32::try_from(index).unwrap_or(u32::MAX))
}

async fn resolve_race_addresses(
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, DirectQuicLinkError> {
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let addresses = lookup_all(authority).await?;
    let mut selected = Vec::with_capacity(2);
    let mut last_error = None;
    for prefer_ipv6 in [true, false] {
        for address in addresses
            .iter()
            .copied()
            .filter(|address| address.is_ipv6() == prefer_ipv6)
        {
            match route_probe(address) {
                Ok(()) => {
                    selected.push(address);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
    }
    if selected.is_empty() {
        return Err(DirectQuicLinkError::Io(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "route endpoint resolved no reachable addresses",
            )
        })));
    }
    Ok(selected)
}

async fn first_route_success<T>(
    mut attempts: Vec<TaskHandle<Result<T, DirectQuicLinkError>>>,
) -> Result<T, DirectQuicLinkError> {
    let mut last_error = None;
    loop {
        let mut index = 0;
        while index < attempts.len() {
            match attempts[index].try_join() {
                Ok(Some(Ok(value))) => {
                    stop_tasks(&mut attempts).await;
                    return Ok(value);
                }
                Ok(Some(Err(error))) => {
                    last_error = Some(error);
                    attempts.swap_remove(index);
                }
                Err(error) => {
                    last_error = Some(DirectQuicLinkError::Io(io::Error::other(error.to_string())));
                    attempts.swap_remove(index);
                }
                Ok(None) => index += 1,
            }
        }
        if attempts.is_empty() {
            return Err(last_error.unwrap_or_else(no_route_runtime));
        }
        sleep(wall_now(), POLL_INTERVAL).await;
    }
}

async fn stop_tasks<T>(tasks: &mut Vec<TaskHandle<T>>) {
    while let Some(mut task) = tasks.pop() {
        task.abort();
        if let Some(cx) = Cx::current() {
            let _ = task.join(&cx).await;
        }
    }
}

fn unspecified_for(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn no_route_runtime() -> DirectQuicLinkError {
    DirectQuicLinkError::Io(io::Error::other("route race runtime unavailable"))
}

fn route_probe(address: SocketAddr) -> io::Result<()> {
    local_route_candidate(address, 1).map(|_| ())
}

fn local_route_candidate(address: SocketAddr, port: u16) -> io::Result<Option<SocketAddr>> {
    let bind = match address.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = std::net::UdpSocket::bind(bind)?;
    socket.connect(address)?;
    let ip = socket.local_addr()?.ip();
    Ok(usable_host_ip(ip).then_some(SocketAddr::new(ip, port)))
}

const fn usable_host_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast(),
    }
}

async fn exchange_offer(
    secure: &mut SecureStream<RelayStream>,
    local: &PathOffer,
) -> Result<PathOffer, QuicPathSelectionError> {
    secure.send(&encode_offer(local)?).await?;
    secure.flush().await?;
    decode_offer(&secure.receive().await?)
}

async fn validate_udp_candidates(
    mut candidates: LocalCandidates,
    peer: &PathOffer,
    transfer_secret: &[u8; 32],
    role: Role,
    local_nonce: [u8; 16],
) -> LocalCandidates {
    if let (Some(mut local), Some(peer_address)) = (candidates.host.take(), peer.host)
        && local.address.is_ipv4() == peer_address.is_ipv4()
        && let Ok(validated) = probe_udp_candidates(
            &mut local.socket,
            &[peer_address],
            transfer_secret,
            role,
            local_nonce,
            peer.probe_nonce,
        )
        .await
    {
        local.peer = Some(validated);
        candidates.host = Some(local);
    }
    if let (Some(mut local), Some(peer_address)) = (candidates.srflx.take(), peer.srflx)
        && local.mapped.is_ipv4() == peer_address.is_ipv4()
        && let Ok(validated) = probe_udp_candidates(
            &mut local.socket,
            &[peer_address],
            transfer_secret,
            role,
            local_nonce,
            peer.probe_nonce,
        )
        .await
    {
        local.peer = Some(validated);
        candidates.srflx = Some(local);
    }
    candidates
}

async fn probe_udp_candidates(
    socket: &mut UdpSocket,
    peer_candidates: &[SocketAddr],
    transfer_secret: &[u8; 32],
    role: Role,
    local_nonce: [u8; 16],
    peer_nonce: [u8; 16],
) -> Result<SocketAddr, DirectQuicLinkError> {
    let key = blake3::derive_key("rift.quic.srflx.probe.v1", transfer_secret);
    let outbound = encode_probe(role, local_nonce, &key);
    let deadline = Instant::now() + SRFLX_PROBE_TIMEOUT;
    let mut next_send = Instant::now();
    let mut validated: Option<SocketAddr> = None;
    let mut confirmation_deadline: Option<Instant> = None;
    let mut buffer = [0_u8; 256];
    let mut unrelated = 0_u16;
    loop {
        let now = Instant::now();
        if confirmation_deadline.is_some_and(|confirmation| now >= confirmation) {
            return validated.ok_or(DirectQuicLinkError::Timeout);
        }
        if now >= deadline {
            return validated.ok_or(DirectQuicLinkError::Timeout);
        }
        if now >= next_send {
            if let Some(peer) = validated {
                socket.send_to(&outbound, peer).await?;
            } else {
                for peer_candidate in peer_candidates {
                    socket.send_to(&outbound, *peer_candidate).await?;
                }
            }
            next_send = now
                + if validated.is_some() {
                    PROBE_CONFIRMATION_RTO
                } else {
                    SRFLX_PROBE_RTO
                };
        }
        let receive_until = confirmation_deadline
            .map_or(deadline, |confirmation| confirmation.min(deadline))
            .min(next_send);
        let wait = receive_until.saturating_duration_since(Instant::now());
        let receive_deadline =
            wall_now().saturating_add_nanos(u64::try_from(wait.as_nanos()).unwrap_or(u64::MAX));
        let Ok(received) = timeout_at(receive_deadline, socket.recv_from(&mut buffer)).await else {
            continue;
        };
        let (length, source) = received?;
        if decode_probe(&buffer[..length], opposite(role), peer_nonce, &key) {
            if validated.is_none() {
                validated = Some(source);
                confirmation_deadline =
                    Some((Instant::now() + PROBE_CONFIRMATION_WINDOW).min(deadline));
            }
            if validated == Some(source) {
                // A received probe is only half of mutual reachability. Reply
                // immediately and linger briefly so a peer whose first packet
                // arrived before this socket was ready cannot remain trapped in
                // validation while this side has already promoted to QUIC.
                socket.send_to(&outbound, source).await?;
                next_send = Instant::now() + PROBE_CONFIRMATION_RTO;
                continue;
            }
        }
        unrelated = unrelated.saturating_add(1);
        if unrelated >= MAX_PROBE_NOISE {
            return Err(DirectQuicLinkError::OffPathFlood);
        }
    }
}

fn encode_probe(role: Role, nonce: [u8; 16], key: &[u8; 32]) -> [u8; PROBE_BYTES] {
    let mut output = [0_u8; PROBE_BYTES];
    output[..4].copy_from_slice(&PROBE_MAGIC);
    output[4] = VERSION;
    output[5] = encode_role(role);
    output[8..24].copy_from_slice(&nonce);
    let authenticator = blake3::keyed_hash(key, &output[..24]);
    output[24..].copy_from_slice(&authenticator.as_bytes()[..16]);
    output
}

fn decode_probe(input: &[u8], role: Role, nonce: [u8; 16], key: &[u8; 32]) -> bool {
    if input.len() != PROBE_BYTES
        || input[..4] != PROBE_MAGIC
        || input[4] != VERSION
        || input[5] != encode_role(role)
        || input[6..8] != [0, 0]
        || input[8..24] != nonce
    {
        return false;
    }
    let expected = blake3::keyed_hash(key, &input[..24]);
    bool::from(subtle::ConstantTimeEq::ct_eq(
        &input[24..],
        &expected.as_bytes()[..16],
    ))
}

const fn encode_role(role: Role) -> u8 {
    match role {
        Role::Sender => 1,
        Role::Receiver => 2,
    }
}

const fn opposite(role: Role) -> Role {
    match role {
        Role::Sender => Role::Receiver,
        Role::Receiver => Role::Sender,
    }
}

fn candidate_nonce(candidates: &LocalCandidates) -> Result<[u8; 16], QuicPathSelectionError> {
    if candidates.host.is_none() && candidates.srflx.is_none() {
        return Ok([0; 16]);
    }
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| QuicPathSelectionError::EntropyUnavailable)?;
    Ok(nonce)
}

type LinkSlots = [Option<(CarrierKind, DirectQuicLink)>; PATH_SLOTS];
type LinkEstablishTask = TaskHandle<Option<(CarrierKind, DirectQuicLink)>>;
type LinkEstablishTasks = [Option<LinkEstablishTask>; PATH_SLOTS];

#[allow(clippy::collapsible_if)]
async fn build_sender_links(
    mut candidates: LocalCandidates,
    peer: &PathOffer,
    policy: MigrationPolicy,
) -> LinkSlots {
    let mut links: LinkSlots = std::array::from_fn(|_| None);
    if candidates.direct.is_some() && peer.direct_ready {
        let (socket, peer_address) = candidates.direct.take().unwrap().into_quic_parts();
        if let Ok(link) = DirectQuicLink::connect(socket, peer_address, &peer.certificate) {
            links[DIRECT_SLOT] = Some((CarrierKind::Direct, link));
        }
    }
    if let Some(candidate) = candidates.host.take()
        && let Some(peer_address) = candidate.peer
        && let Ok(link) = DirectQuicLink::connect(candidate.socket, peer_address, &peer.certificate)
    {
        links[HOST_SLOT] = Some((CarrierKind::Lan, link));
    }
    if let Some(candidate) = candidates.srflx.take() {
        if let Some(peer_address) = candidate.peer {
            if let Ok(link) =
                DirectQuicLink::connect(candidate.socket, peer_address, &peer.certificate)
            {
                links[SRFLX_SLOT] = Some((candidate.kind, link));
            }
        }
    }
    links = Box::pin(establish_slots(links, policy)).await;
    if let (Some(allocation), Some(peer_address)) = (candidates.turn.take(), peer.turn_udp_relay) {
        if let Ok(link) = DirectQuicLink::connect_turn(
            allocation,
            peer_address,
            &peer.certificate,
            policy.turn_setup_timeout,
        )
        .await
        {
            links[TURN_UDP_SLOT] = establish_slot(CarrierKind::TurnUdp, link, policy).await;
        }
    }
    if let (Some(allocation), Some(peer_address)) =
        (candidates.turn_stream.take(), peer.turn_stream_relay)
    {
        if let Ok(link) = DirectQuicLink::connect_turn_stream(
            allocation,
            peer_address,
            &peer.certificate,
            policy.turn_setup_timeout,
        )
        .await
        {
            links[TURN_STREAM_SLOT] = establish_slot(CarrierKind::TurnStream, link, policy).await;
        }
    }
    links
}

#[allow(clippy::collapsible_if)]
async fn build_receiver_links(
    mut candidates: LocalCandidates,
    peer: &PathOffer,
    identity: &QuicServerIdentity,
    policy: MigrationPolicy,
) -> LinkSlots {
    let mut links: LinkSlots = std::array::from_fn(|_| None);
    if candidates.direct.is_some() && peer.direct_ready {
        let (socket, peer_address) = candidates.direct.take().unwrap().into_quic_parts();
        let link = DirectQuicLink::listen(socket, peer_address, identity);
        links[DIRECT_SLOT] = Some((CarrierKind::Direct, link));
    }
    if let Some(candidate) = candidates.host.take()
        && let Some(peer_address) = candidate.peer
    {
        let link = DirectQuicLink::listen(candidate.socket, peer_address, identity);
        links[HOST_SLOT] = Some((CarrierKind::Lan, link));
    }
    if let Some(candidate) = candidates.srflx.take() {
        if let Some(peer_address) = candidate.peer {
            let link = DirectQuicLink::listen(candidate.socket, peer_address, identity);
            links[SRFLX_SLOT] = Some((candidate.kind, link));
        }
    }
    links = Box::pin(establish_slots(links, policy)).await;
    if let (Some(allocation), Some(peer_address)) = (candidates.turn.take(), peer.turn_udp_relay) {
        if let Ok(link) = DirectQuicLink::listen_turn(
            allocation,
            peer_address,
            identity,
            policy.turn_setup_timeout,
        )
        .await
        {
            links[TURN_UDP_SLOT] = establish_slot(CarrierKind::TurnUdp, link, policy).await;
        }
    }
    if let (Some(allocation), Some(peer_address)) =
        (candidates.turn_stream.take(), peer.turn_stream_relay)
    {
        if let Ok(link) = DirectQuicLink::listen_turn_stream(
            allocation,
            peer_address,
            identity,
            policy.turn_setup_timeout,
        )
        .await
        {
            links[TURN_STREAM_SLOT] = establish_slot(CarrierKind::TurnStream, link, policy).await;
        }
    }
    links
}

async fn establish_slot(
    kind: CarrierKind,
    mut link: DirectQuicLink,
    policy: MigrationPolicy,
) -> Option<(CarrierKind, DirectQuicLink)> {
    link.establish(policy.quic_handshake_timeout)
        .await
        .ok()
        .map(|()| (kind, link))
}

async fn establish_slots(mut links: LinkSlots, policy: MigrationPolicy) -> LinkSlots {
    let Some(cx) = Cx::current() else {
        for slot in &mut links {
            if let Some((kind, link)) = slot.take() {
                *slot = establish_slot(kind, link, policy).await;
            }
        }
        return links;
    };
    let mut tasks: LinkEstablishTasks = std::array::from_fn(|_| None);
    for (slot, link) in links.iter_mut().enumerate() {
        let Some((kind, link)) = link.take() else {
            continue;
        };
        tasks[slot] = cx
            .spawn(move |_cx| async move { establish_slot(kind, link, policy).await })
            .ok();
    }

    loop {
        let mut pending = false;
        for (slot, task) in tasks.iter_mut().enumerate() {
            let Some(handle) = task else { continue };
            match handle.try_join() {
                Ok(Some(result)) => {
                    links[slot] = result;
                    *task = None;
                }
                Ok(None) => pending = true,
                Err(_) => *task = None,
            }
        }
        if !pending {
            return links;
        }
        sleep(wall_now(), POLL_INTERVAL).await;
    }
}

async fn settle_attempts(
    mut secure: SecureStream<RelayStream>,
    mut attempts: LinkSlots,
    role: Role,
    allow_acceleration: bool,
) -> Result<QuicPathSelection, QuicPathSelectionError> {
    let ready = if allow_acceleration {
        attempts
            .iter()
            .enumerate()
            .fold(0_u8, |mask, (slot, link)| {
                mask | (u8::from(link.is_some()) << slot)
            })
    } else {
        0
    };
    let mut decision = [0_u8; 6];
    decision[..4].copy_from_slice(&DECISION_MAGIC);
    decision[4] = VERSION;
    decision[5] = ready;
    secure.send(&decision).await?;
    secure.flush().await?;
    let peer = secure.receive().await?;
    if peer.len() != decision.len()
        || peer[..5] != decision[..5]
        || peer[5] & !((1_u8 << PATH_SLOTS) - 1) != 0
    {
        return Err(QuicPathSelectionError::InvalidOffer);
    }
    let mutual = ready & peer[5];
    if mutual == 0 {
        return Ok(QuicPathSelection::Relay(Box::new(secure)));
    }

    // Reachability is not performance. Measure useful encrypted delivery on
    // the already-live relay and every mutually authenticated QUIC carrier
    // before allowing any challenger to displace WSS.
    let relay_bps = benchmark_relay(&mut secure, role).await?;
    let mut rates = [0_u64; PATH_SLOTS];
    for (slot, attempt) in attempts.iter_mut().enumerate() {
        if mutual & (1 << slot) == 0 {
            continue;
        }
        let local = match attempt.as_mut() {
            Some((_kind, link)) => benchmark_quic(link, role).await,
            None => None,
        };
        let peer_ok = exchange_benchmark_status(&mut secure, slot, local.is_some()).await?;
        if peer_ok {
            rates[slot] = local.unwrap_or_default();
        }
    }

    let selection = match role {
        Role::Sender => {
            let best = rates
                .iter()
                .enumerate()
                .max_by_key(|(_, rate)| **rate)
                .filter(|(_, rate)| **rate > relay_bps.saturating_add(relay_bps / 8))
                .map_or(RELAY_SELECTION, |(slot, _)| {
                    u8::try_from(slot).unwrap_or(RELAY_SELECTION)
                });
            send_selection(&mut secure, best).await?;
            best
        }
        Role::Receiver => receive_selection(&mut secure, mutual).await?,
    };
    if selection == RELAY_SELECTION {
        return Ok(QuicPathSelection::Relay(Box::new(secure)));
    }

    let selected = usize::from(selection);
    if selected >= PATH_SLOTS || mutual & (1 << selected) == 0 || rates[selected] == 0 {
        return Err(QuicPathSelectionError::InvalidOffer);
    }
    let links = attempts[selected].take().into_iter().collect();
    let _ = secure.shutdown().await;
    Ok(QuicPathSelection::Quic(Box::new(QuicPathPool::new(links))))
}

async fn benchmark_relay(
    secure: &mut SecureStream<RelayStream>,
    role: Role,
) -> Result<u64, QuicPathSelectionError> {
    let mut record = vec![0_u8; BENCHMARK_RECORD_BYTES];
    record[..8].copy_from_slice(b"RIFTbnch");
    match role {
        Role::Sender => {
            let started = Instant::now();
            for sequence in 0..BENCHMARK_RECORDS {
                record[8..16].copy_from_slice(&(sequence as u64).to_be_bytes());
                secure.send(&record).await?;
            }
            secure.flush().await?;
            if secure.receive().await? != b"RIFTbnch-ok" {
                return Err(QuicPathSelectionError::InvalidOffer);
            }
            Ok(measured_bps(
                BENCHMARK_RECORD_BYTES.saturating_mul(BENCHMARK_RECORDS),
                started.elapsed(),
            ))
        }
        Role::Receiver => {
            for sequence in 0..BENCHMARK_RECORDS {
                let received = secure.receive().await?;
                if received.len() != BENCHMARK_RECORD_BYTES
                    || received[..8] != *b"RIFTbnch"
                    || received[8..16] != (sequence as u64).to_be_bytes()
                {
                    return Err(QuicPathSelectionError::InvalidOffer);
                }
            }
            secure.send(b"RIFTbnch-ok").await?;
            secure.flush().await?;
            Ok(0)
        }
    }
}

async fn benchmark_quic(link: &mut DirectQuicLink, role: Role) -> Option<u64> {
    let mut payload = vec![0_u8; BENCHMARK_RECORD_BYTES * BENCHMARK_RECORDS];
    payload[..8].copy_from_slice(b"RIFTquic");
    match role {
        Role::Sender => {
            let started = Instant::now();
            link.send_bytes(&payload, BENCHMARK_TIMEOUT).await.ok()?;
            Some(measured_bps(payload.len(), started.elapsed()))
        }
        Role::Receiver => {
            let received = link.receive_bytes(BENCHMARK_TIMEOUT).await.ok()?;
            (received.len() == payload.len() && received[..8] == *b"RIFTquic").then_some(1)
        }
    }
}

async fn exchange_benchmark_status(
    secure: &mut SecureStream<RelayStream>,
    slot: usize,
    success: bool,
) -> Result<bool, QuicPathSelectionError> {
    let mut status = [0_u8; 8];
    status[..4].copy_from_slice(&BENCH_STATUS_MAGIC);
    status[4] = VERSION;
    status[5] = u8::try_from(slot).map_err(|_| QuicPathSelectionError::InvalidOffer)?;
    status[6] = u8::from(success);
    secure.send(&status).await?;
    secure.flush().await?;
    let peer = secure.receive().await?;
    if peer.len() != status.len() || peer[..6] != status[..6] || peer[6] > 1 || peer[7] != 0 {
        return Err(QuicPathSelectionError::InvalidOffer);
    }
    Ok(success && peer[6] == 1)
}

async fn send_selection(
    secure: &mut SecureStream<RelayStream>,
    selection: u8,
) -> Result<(), QuicPathSelectionError> {
    let mut decision = [0_u8; 6];
    decision[..4].copy_from_slice(&SELECTION_MAGIC);
    decision[4] = VERSION;
    decision[5] = selection;
    secure.send(&decision).await?;
    secure.flush().await?;
    Ok(())
}

async fn receive_selection(
    secure: &mut SecureStream<RelayStream>,
    mutual: u8,
) -> Result<u8, QuicPathSelectionError> {
    let decision = secure.receive().await?;
    if decision.len() != 6 || decision[..4] != SELECTION_MAGIC || decision[4] != VERSION {
        return Err(QuicPathSelectionError::InvalidOffer);
    }
    let selection = decision[5];
    if selection != RELAY_SELECTION
        && (usize::from(selection) >= PATH_SLOTS || mutual & (1 << selection) == 0)
    {
        return Err(QuicPathSelectionError::InvalidOffer);
    }
    Ok(selection)
}

fn measured_bps(bytes: usize, elapsed: Duration) -> u64 {
    let micros = elapsed.as_micros().max(1);
    let bits = (bytes as u128).saturating_mul(8_000_000);
    u64::try_from(bits / micros).unwrap_or(u64::MAX)
}

fn encode_offer(offer: &PathOffer) -> Result<Vec<u8>, QuicPathSelectionError> {
    if offer.certificate.len() > MAX_CERTIFICATE_BYTES
        || offer.host.is_none() && offer.srflx.is_none() && offer.probe_nonce != [0; 16]
    {
        return Err(QuicPathSelectionError::InvalidOffer);
    }
    let mut encoded = vec![0_u8; OFFER_HEADER_BYTES + offer.certificate.len()];
    encoded[..4].copy_from_slice(&OFFER_MAGIC);
    encoded[4] = VERSION;
    encoded[5] = u8::from(offer.direct_ready);
    encoded[6..8].copy_from_slice(
        &u16::try_from(offer.certificate.len())
            .map_err(|_| QuicPathSelectionError::InvalidOffer)?
            .to_be_bytes(),
    );
    encode_socket(offer.turn_udp_relay, &mut encoded[8..27]);
    encode_socket(offer.turn_stream_relay, &mut encoded[27..46]);
    encode_socket(offer.host, &mut encoded[46..65]);
    encode_socket(offer.srflx, &mut encoded[65..84]);
    encoded[84..100].copy_from_slice(&offer.probe_nonce);
    encoded[OFFER_HEADER_BYTES..].copy_from_slice(&offer.certificate);
    Ok(encoded)
}

fn decode_offer(encoded: &[u8]) -> Result<PathOffer, QuicPathSelectionError> {
    if encoded.len() < OFFER_HEADER_BYTES
        || encoded[..4] != OFFER_MAGIC
        || encoded[4] != VERSION
        || encoded[5] > 1
    {
        return Err(QuicPathSelectionError::InvalidOffer);
    }
    let certificate_len = usize::from(u16::from_be_bytes([encoded[6], encoded[7]]));
    if certificate_len > MAX_CERTIFICATE_BYTES
        || encoded.len() != OFFER_HEADER_BYTES + certificate_len
    {
        return Err(QuicPathSelectionError::InvalidOffer);
    }
    let host = decode_socket(&encoded[46..65])?;
    if host.is_some_and(|candidate| !usable_host_ip(candidate.ip())) {
        return Err(QuicPathSelectionError::InvalidOffer);
    }
    let srflx = decode_socket(&encoded[65..84])?;
    let probe_nonce = encoded[84..100]
        .try_into()
        .map_err(|_| QuicPathSelectionError::InvalidOffer)?;
    if host.is_none() && srflx.is_none() && probe_nonce != [0; 16] {
        return Err(QuicPathSelectionError::InvalidOffer);
    }
    Ok(PathOffer {
        direct_ready: encoded[5] == 1,
        turn_udp_relay: decode_socket(&encoded[8..27])?,
        turn_stream_relay: decode_socket(&encoded[27..46])?,
        host,
        srflx,
        probe_nonce,
        certificate: encoded[OFFER_HEADER_BYTES..].to_vec(),
    })
}

fn encode_socket(address: Option<SocketAddr>, output: &mut [u8]) {
    match address {
        None => {}
        Some(SocketAddr::V4(address)) => {
            output[0] = 4;
            output[1..5].copy_from_slice(&address.ip().octets());
            output[17..19].copy_from_slice(&address.port().to_be_bytes());
        }
        Some(SocketAddr::V6(address)) => {
            output[0] = 6;
            output[1..17].copy_from_slice(&address.ip().octets());
            output[17..19].copy_from_slice(&address.port().to_be_bytes());
        }
    }
}

fn decode_socket(input: &[u8]) -> Result<Option<SocketAddr>, QuicPathSelectionError> {
    if input.len() != 19 {
        return Err(QuicPathSelectionError::InvalidOffer);
    }
    let port = u16::from_be_bytes([input[17], input[18]]);
    match input[0] {
        0 if input[1..].iter().all(|byte| *byte == 0) => Ok(None),
        4 if input[5..17].iter().all(|byte| *byte == 0) && port != 0 => Ok(Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(input[1], input[2], input[3], input[4])),
            port,
        ))),
        6 if port != 0 => {
            let octets: [u8; 16] = input[1..17]
                .try_into()
                .map_err(|_| QuicPathSelectionError::InvalidOffer)?;
            Ok(Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            )))
        }
        _ => Err(QuicPathSelectionError::InvalidOffer),
    }
}

#[cfg(test)]
mod tests {
    use asupersync::{net::UdpSocket, runtime::RuntimeBuilder};
    use rift_protocol::RouteServer;

    use super::*;

    #[test]
    fn offers_round_trip_ipv4_ipv6_and_certificate_exactly() {
        for address in [
            Some("192.0.2.4:3478".parse().unwrap()),
            Some("[2001:db8::4]:5349".parse().unwrap()),
            None,
        ] {
            let offer = PathOffer {
                direct_ready: true,
                turn_udp_relay: address,
                turn_stream_relay: Some("203.0.113.9:5349".parse().unwrap()),
                host: Some("10.23.4.8:4111".parse().unwrap()),
                srflx: Some("198.51.100.8:4111".parse().unwrap()),
                probe_nonce: [9; 16],
                certificate: vec![1, 2, 3, 4],
            };
            let decoded = decode_offer(&encode_offer(&offer).unwrap()).unwrap();
            assert_eq!(decoded.direct_ready, offer.direct_ready);
            assert_eq!(decoded.turn_udp_relay, offer.turn_udp_relay);
            assert_eq!(decoded.turn_stream_relay, offer.turn_stream_relay);
            assert_eq!(decoded.host, offer.host);
            assert_eq!(decoded.srflx, offer.srflx);
            assert_eq!(decoded.probe_nonce, offer.probe_nonce);
            assert_eq!(decoded.certificate, offer.certificate);
        }
    }

    #[test]
    fn host_candidate_does_not_require_stun_mapping() {
        let offer = PathOffer {
            direct_ready: false,
            turn_udp_relay: None,
            turn_stream_relay: None,
            host: Some("10.23.4.8:4111".parse().unwrap()),
            srflx: None,
            probe_nonce: [9; 16],
            certificate: Vec::new(),
        };
        let decoded = decode_offer(&encode_offer(&offer).unwrap()).unwrap();
        assert_eq!(decoded.host, offer.host);
        assert_eq!(decoded.srflx, None);
        assert_eq!(decoded.probe_nonce, offer.probe_nonce);
    }

    #[test]
    fn faster_fallback_never_preempts_pending_udp_discovery() {
        assert!(
            !GatherState {
                all_finished: false,
                deadline_reached: false,
                discovery: DiscoveryState::Pending,
                ready_grace_elapsed: true,
            }
            .is_complete()
        );
        assert!(
            GatherState {
                all_finished: false,
                deadline_reached: false,
                discovery: DiscoveryState::Settled,
                ready_grace_elapsed: true,
            }
            .is_complete()
        );
        assert!(
            GatherState {
                all_finished: false,
                deadline_reached: true,
                discovery: DiscoveryState::Pending,
                ready_grace_elapsed: false,
            }
            .is_complete()
        );
    }

    #[test]
    fn host_socket_exists_without_a_working_stun_server() {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        runtime.block_on(async {
            let routes = RouteBundle::new(
                vec![RouteServer {
                    transport: RouteTransport::StunUdp,
                    host: "192.0.2.1".into(),
                    port: 9,
                }],
                None,
            )
            .unwrap();
            let cx = Cx::current().unwrap();
            let mut task = spawn_host_socket(Some(&routes)).unwrap();
            let candidate = task.join(&cx).await.unwrap().unwrap();
            assert!(usable_host_ip(candidate.address.ip()));
            assert_eq!(
                candidate.address.port(),
                candidate.socket.local_addr().unwrap().port()
            );
        });
    }

    #[test]
    fn noncanonical_absent_address_is_rejected() {
        let mut encoded = encode_offer(&PathOffer {
            direct_ready: false,
            turn_udp_relay: None,
            turn_stream_relay: None,
            host: None,
            srflx: None,
            probe_nonce: [0; 16],
            certificate: Vec::new(),
        })
        .unwrap();
        encoded[9] = 1;
        assert!(matches!(
            decode_offer(&encoded),
            Err(QuicPathSelectionError::InvalidOffer)
        ));

        let mut encoded = encode_offer(&PathOffer {
            direct_ready: false,
            turn_udp_relay: None,
            turn_stream_relay: None,
            host: None,
            srflx: None,
            probe_nonce: [0; 16],
            certificate: Vec::new(),
        })
        .unwrap();
        encoded[84] = 1;
        assert!(matches!(
            decode_offer(&encoded),
            Err(QuicPathSelectionError::InvalidOffer)
        ));
    }

    #[test]
    fn path_probe_authenticator_is_transfer_and_role_bound() {
        let probe = encode_probe(Role::Sender, [3; 16], &[7; 32]);
        assert!(decode_probe(&probe, Role::Sender, [3; 16], &[7; 32]));
        assert!(!decode_probe(&probe, Role::Receiver, [3; 16], &[7; 32]));
        assert!(!decode_probe(&probe, Role::Sender, [4; 16], &[7; 32]));
        assert!(!decode_probe(&probe, Role::Sender, [3; 16], &[8; 32]));
    }

    #[test]
    fn validated_probe_is_confirmed_before_socket_promotion() {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        let handle = runtime.handle();
        runtime.block_on(async move {
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sender_address = sender.local_addr().unwrap();
            let mut peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer_address = peer.local_addr().unwrap();
            let sender_task = handle.spawn(async move {
                probe_udp_candidates(
                    &mut sender,
                    &[peer_address],
                    &[7; 32],
                    Role::Sender,
                    [1; 16],
                    [2; 16],
                )
                .await
                .unwrap()
            });

            let mut buffer = [0_u8; 256];
            let (_, source) = peer.recv_from(&mut buffer).await.unwrap();
            assert_eq!(source, sender_address);
            let key = blake3::derive_key("rift.quic.srflx.probe.v1", &[7; 32]);
            let response = encode_probe(Role::Receiver, [2; 16], &key);
            peer.send_to(&response, sender_address).await.unwrap();

            let deadline = wall_now().saturating_add_nanos(1_000_000_000);
            let (length, source) = timeout_at(deadline, peer.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(source, sender_address);
            assert!(decode_probe(&buffer[..length], Role::Sender, [1; 16], &key));
            assert_eq!(sender_task.await, peer_address);
        });
    }

    #[test]
    fn authenticated_srflx_probe_opens_both_directions() {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        let handle = runtime.handle();
        runtime.block_on(async move {
            let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sender_address = sender.local_addr().unwrap();
            let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_address = receiver.local_addr().unwrap();
            let sender_probe = handle.spawn(async move {
                probe_udp_candidates(
                    &mut sender,
                    &[receiver_address],
                    &[7; 32],
                    Role::Sender,
                    [1; 16],
                    [2; 16],
                )
                .await
                .unwrap()
            });
            let receiver_peer = probe_udp_candidates(
                &mut receiver,
                &[sender_address],
                &[7; 32],
                Role::Receiver,
                [2; 16],
                [1; 16],
            )
            .await
            .unwrap();
            assert_eq!(sender_probe.await, receiver_address);
            assert_eq!(receiver_peer, sender_address);
        });
    }

    #[test]
    fn authenticated_host_probe_promotes_the_same_sockets_to_quic() {
        let runtime = RuntimeBuilder::new().worker_threads(2).build().unwrap();
        let handle = runtime.handle();
        runtime.block_on(async move {
            let mut sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sender_address = sender_socket.local_addr().unwrap();
            let mut receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_address = receiver_socket.local_addr().unwrap();
            let identity = QuicServerIdentity::generate().unwrap();
            let certificate = identity.certificate().to_vec();

            let sender = handle.spawn(async move {
                let peer = probe_udp_candidates(
                    &mut sender_socket,
                    &[receiver_address],
                    &[7; 32],
                    Role::Sender,
                    [1; 16],
                    [2; 16],
                )
                .await
                .unwrap();
                let mut link = DirectQuicLink::connect(sender_socket, peer, &certificate).unwrap();
                link.send_bytes(b"promoted", Duration::from_secs(5))
                    .await
                    .unwrap();
            });

            let peer = probe_udp_candidates(
                &mut receiver_socket,
                &[sender_address],
                &[7; 32],
                Role::Receiver,
                [2; 16],
                [1; 16],
            )
            .await
            .unwrap();
            let mut link = DirectQuicLink::listen(receiver_socket, peer, &identity);
            let received = link.receive_bytes(Duration::from_secs(5)).await.unwrap();
            sender.await;
            assert_eq!(received, b"promoted");
        });
    }

    #[test]
    fn viable_lan_handshake_is_not_serialized_behind_a_stalled_path() {
        let runtime = RuntimeBuilder::new().worker_threads(3).build().unwrap();
        let handle = runtime.handle();
        runtime.block_on(async move {
            let receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let receiver_address = receiver_socket.local_addr().unwrap();
            let lan_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let lan_address = lan_socket.local_addr().unwrap();
            let stalled_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let blackhole_address = blackhole.local_addr().unwrap();
            let identity = QuicServerIdentity::generate().unwrap();
            let certificate = identity.certificate().to_vec();
            let server = handle.spawn(async move {
                let mut link = DirectQuicLink::listen(receiver_socket, lan_address, &identity);
                link.establish(Duration::from_secs(2)).await.unwrap();
                link
            });

            let stalled =
                DirectQuicLink::connect(stalled_socket, blackhole_address, &certificate).unwrap();
            let lan = DirectQuicLink::connect(lan_socket, receiver_address, &certificate).unwrap();
            let mut links: LinkSlots = std::array::from_fn(|_| None);
            links[DIRECT_SLOT] = Some((CarrierKind::Direct, stalled));
            links[HOST_SLOT] = Some((CarrierKind::Lan, lan));
            let policy = MigrationPolicy {
                quic_handshake_timeout: Duration::from_millis(400),
                ..MigrationPolicy::default()
            };

            let links = Box::pin(establish_slots(links, policy)).await;
            assert!(links[HOST_SLOT].is_some());
            assert!(links[DIRECT_SLOT].is_none());
            let _server = server.await;
        });
    }
}
