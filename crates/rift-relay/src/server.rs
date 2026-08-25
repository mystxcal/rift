//! Structured, bounded live relay service.

use std::{io, sync::Arc, time::Duration};

use asupersync::{
    channel::mpsc,
    cx::Cx,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::TaskHandle,
    time::{timeout, wall_now},
    tls::TlsAcceptor,
};
use rift_protocol::{JOIN_PRELUDE_BYTES, JoinPrelude, JoinStatus, RendezvousRole};
use rift_transport::{WssStream, accept_wss};
use thiserror::Error;

use crate::{
    ForwardError, ForwardStats, JoinError, JoinOutcome, MatchTable, PeerRole, RelayPolicy,
    RelayPolicyError, RelayRouteIssuer, forward::forward_bidirectional_websocket,
    forward_bidirectional,
};

/// Terminal one-shot relay failure.
#[derive(Debug, Error)]
pub enum RelayServerError {
    /// Resource policy is invalid.
    #[error(transparent)]
    Policy(#[from] RelayPolicyError),
    /// Listener, admission, or structured-worker I/O failed.
    #[error("relay service I/O failed: {0}")]
    Io(#[from] io::Error),
    /// A matched session terminated unsuccessfully.
    #[error(transparent)]
    Forward(#[from] ForwardError),
}

enum PreparedConnection<S> {
    Valid { stream: S, prelude: JoinPrelude },
    AcceptFailed(io::Error),
}

type PreparedInbox<S> = (mpsc::Receiver<PreparedConnection<S>>, Vec<TaskHandle<()>>);

/// Accept connections until one complementary pair has been forwarded.
///
/// A bounded worker set isolates slow prelude writers from the matcher and
/// listener. Prelude workers and the matched forwarding session are children
/// of the calling runtime context; all are stopped or joined before this
/// function returns.
///
/// # Errors
///
/// Returns when listener I/O fails, policy is invalid, worker ownership cannot
/// be established, or the matched path fails. Peer admission failures remain
/// contained while the service looks for a valid pair.
pub async fn serve_one(
    listener: TcpListener,
    policy: RelayPolicy,
) -> Result<ForwardStats, RelayServerError> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(RelayServerError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "raw relay ingress is restricted to loopback",
        )));
    }
    let mut outcomes = serve_exact(listener, policy, 1).await?;
    outcomes
        .pop()
        .ok_or_else(|| io::Error::other("relay produced no terminal session"))?
}

/// Accept WSS connections until one complementary pair has been forwarded.
///
/// TLS, a canonical HTTP path, and the `rift.v1` WebSocket subprotocol are
/// validated before a connection can enter the lookup matcher.
///
/// # Errors
///
/// Returns when listener I/O fails, policy is invalid, worker ownership cannot
/// be established, or the matched path fails. Invalid remote handshakes remain
/// isolated inside the bounded admission workers.
pub async fn serve_one_wss(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    policy: RelayPolicy,
) -> Result<ForwardStats, RelayServerError> {
    let mut outcomes = serve_exact_wss(listener, acceptor, policy, 1).await?;
    outcomes
        .pop()
        .ok_or_else(|| io::Error::other("relay produced no terminal WSS session"))?
}

/// Accept one WSS pair and issue provider-independent acceleration routes.
///
/// Credential issuance is bounded and fail-soft: provider unavailability
/// preserves the authenticated WSS correctness path rather than rejecting a
/// live pair.
///
/// # Errors
///
/// Has the same bounded service contract as [`serve_one_wss`].
pub async fn serve_one_wss_with_routes(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    policy: RelayPolicy,
    route_issuer: RelayRouteIssuer,
) -> Result<ForwardStats, RelayServerError> {
    let mut outcomes =
        serve_exact_wss_with_routes(listener, acceptor, policy, 1, route_issuer).await?;
    outcomes
        .pop()
        .ok_or_else(|| io::Error::other("relay produced no terminal WSS session"))?
}

/// Serve bounded raw loopback sessions until the owning runtime cancels the service.
///
/// # Errors
///
/// Returns only for listener/worker failure or invalid policy. Individual
/// matched-session failures are contained and released.
pub async fn serve(listener: TcpListener, policy: RelayPolicy) -> Result<(), RelayServerError> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(RelayServerError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "raw relay ingress is restricted to loopback",
        )));
    }
    let _ = serve_exact_inner(listener, policy, None).await?;
    Ok(())
}

/// Serve bounded authenticated WSS sessions until the owning runtime cancels.
///
/// The service is persistent, but every lookup, admission worker, forwarding
/// session, buffer, and idle lifetime remains independently bounded.
///
/// # Errors
///
/// Returns only for listener/worker failure or invalid policy. Individual
/// matched-session failures are contained and released.
pub async fn serve_wss(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    policy: RelayPolicy,
) -> Result<(), RelayServerError> {
    let _ = serve_exact_wss_inner(listener, acceptor, policy, None, None).await?;
    Ok(())
}

/// Serve WSS sessions with short-lived acceleration routes for each match.
///
/// # Errors
///
/// Has the same bounded service contract as [`serve_wss`].
pub async fn serve_wss_with_routes(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    policy: RelayPolicy,
    route_issuer: RelayRouteIssuer,
) -> Result<(), RelayServerError> {
    let _ = serve_exact_wss_inner(listener, acceptor, policy, None, Some(route_issuer)).await?;
    Ok(())
}

async fn serve_exact(
    listener: TcpListener,
    policy: RelayPolicy,
    target_sessions: u32,
) -> Result<Vec<Result<ForwardStats, RelayServerError>>, RelayServerError> {
    serve_exact_inner(listener, policy, Some(target_sessions)).await
}

async fn serve_exact_inner(
    listener: TcpListener,
    policy: RelayPolicy,
    target_sessions: Option<u32>,
) -> Result<Vec<Result<ForwardStats, RelayServerError>>, RelayServerError> {
    let policy = policy.validate()?;
    if target_sessions == Some(0) {
        return Err(RelayPolicyError::UnboundedOrPersistent.into());
    }
    let cx = Cx::current().ok_or_else(|| io::Error::other("relay requires a runtime context"))?;
    let (prepared_rx, workers) = start_prelude_workers(&cx, listener, policy)?;
    serve_prepared(
        &cx,
        prepared_rx,
        workers,
        policy,
        target_sessions,
        false,
        None,
    )
    .await
}

async fn serve_exact_wss(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    policy: RelayPolicy,
    target_sessions: u32,
) -> Result<Vec<Result<ForwardStats, RelayServerError>>, RelayServerError> {
    serve_exact_wss_inner(listener, acceptor, policy, Some(target_sessions), None).await
}

async fn serve_exact_wss_with_routes(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    policy: RelayPolicy,
    target_sessions: u32,
    route_issuer: RelayRouteIssuer,
) -> Result<Vec<Result<ForwardStats, RelayServerError>>, RelayServerError> {
    serve_exact_wss_inner(
        listener,
        acceptor,
        policy,
        Some(target_sessions),
        Some(route_issuer),
    )
    .await
}

async fn serve_exact_wss_inner(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    policy: RelayPolicy,
    target_sessions: Option<u32>,
    route_issuer: Option<RelayRouteIssuer>,
) -> Result<Vec<Result<ForwardStats, RelayServerError>>, RelayServerError> {
    let policy = policy.validate()?;
    if target_sessions == Some(0) {
        return Err(RelayPolicyError::UnboundedOrPersistent.into());
    }
    let cx = Cx::current().ok_or_else(|| io::Error::other("relay requires a runtime context"))?;
    let (prepared_rx, workers) = start_wss_prelude_workers(&cx, listener, acceptor, policy)?;
    serve_prepared(
        &cx,
        prepared_rx,
        workers,
        policy,
        target_sessions,
        true,
        route_issuer,
    )
    .await
}

async fn serve_prepared<S>(
    cx: &Cx,
    mut prepared_rx: mpsc::Receiver<PreparedConnection<S>>,
    mut workers: Vec<TaskHandle<()>>,
    policy: RelayPolicy,
    target_sessions: Option<u32>,
    websocket_close_is_terminal: bool,
    route_issuer: Option<RelayRouteIssuer>,
) -> Result<Vec<Result<ForwardStats, RelayServerError>>, RelayServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let pending_capacity = usize::try_from(policy.max_pending_lookups)
        .map_err(|_| RelayPolicyError::UnboundedOrPersistent)?;
    let active_capacity = usize::try_from(policy.max_sessions)
        .map_err(|_| RelayPolicyError::UnboundedOrPersistent)?;
    let mut match_table = MatchTable::new(pending_capacity, policy.match_timeout_ms)
        .map_err(|_| RelayPolicyError::UnboundedOrPersistent)?;
    let sweep = Duration::from_millis(policy.match_timeout_ms.min(100));

    let mut active: Vec<TaskHandle<Result<ForwardStats, RelayServerError>>> = Vec::new();
    let mut terminal = Vec::new();
    let mut admitted_sessions = 0_u32;
    while target_sessions.is_none_or(|target| admitted_sessions < target) {
        reap_finished(&mut active, &mut terminal);
        if target_sessions.is_none() {
            terminal.clear();
        }
        let prepared = timeout(wall_now(), sweep, prepared_rx.recv(cx)).await;
        let Ok(prepared) = prepared else {
            match_table.expire(now_ms());
            continue;
        };
        let prepared = prepared.map_err(|_| io::Error::other("relay accept workers stopped"))?;
        let PreparedConnection::Valid {
            mut stream,
            prelude,
        } = prepared
        else {
            let PreparedConnection::AcceptFailed(error) = prepared else {
                unreachable!();
            };
            stop_workers(cx, &mut workers).await;
            return Err(RelayServerError::Io(error));
        };

        let role = match prelude.role {
            RendezvousRole::Sender => PeerRole::Sender,
            RendezvousRole::Receiver => PeerRole::Receiver,
        };
        let completes_pair = match match_table.would_match(now_ms(), prelude.lookup_id, role) {
            Ok(completes_pair) => completes_pair,
            Err(error) => {
                let status = join_error_status(error);
                let _ = send_status(&mut stream, status).await;
                continue;
            }
        };
        if completes_pair && active.len() >= active_capacity {
            let _ = send_status(&mut stream, JoinStatus::CapacityExhausted).await;
            continue;
        }
        if !completes_pair && role == PeerRole::Receiver {
            let _ = send_status(&mut stream, JoinStatus::SenderAbsent).await;
            continue;
        }
        match match_table.join(now_ms(), prelude.lookup_id, role, stream) {
            Ok(JoinOutcome::Waiting) => {
                let Some(waiting) = match_table.waiting_endpoint_mut(prelude.lookup_id, role)
                else {
                    stop_workers(cx, &mut workers).await;
                    return Err(RelayServerError::Io(io::Error::other(
                        "relay reservation invariant failed",
                    )));
                };
                if send_status(waiting, JoinStatus::Reserved).await.is_err() {
                    let _ = match_table.leave(prelude.lookup_id, role);
                }
            }
            Ok(JoinOutcome::Matched { sender, receiver }) => {
                admitted_sessions = admitted_sessions.saturating_add(1);
                let idle = Duration::from_millis(policy.idle_timeout_ms);
                let session = spawn_session(
                    cx,
                    sender,
                    receiver,
                    idle,
                    websocket_close_is_terminal,
                    route_issuer.clone(),
                )?;
                active.push(session);
            }
            Err(JoinError::RoleOccupied | JoinError::CapacityExhausted) => {
                stop_workers(cx, &mut workers).await;
                return Err(RelayServerError::Io(io::Error::other(
                    "relay admission changed without an intervening owner",
                )));
            }
            Err(
                JoinError::InvalidCapacity | JoinError::InvalidTtl | JoinError::InvariantViolation,
            ) => {
                stop_workers(cx, &mut workers).await;
                return Err(RelayServerError::Io(io::Error::other(
                    "relay ownership invariant failed",
                )));
            }
        }
    }

    stop_workers(cx, &mut workers).await;
    drop(match_table);
    drain_sessions(cx, &mut active, &mut terminal).await;
    Ok(terminal)
}

fn spawn_session<S>(
    cx: &Cx,
    sender: S,
    receiver: S,
    idle: Duration,
    websocket_close_is_terminal: bool,
    route_issuer: Option<RelayRouteIssuer>,
) -> Result<TaskHandle<Result<ForwardStats, RelayServerError>>, RelayServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    cx.spawn(move |session_cx| async move {
        run_session(
            &session_cx,
            sender,
            receiver,
            idle,
            websocket_close_is_terminal,
            route_issuer,
        )
        .await
    })
    .map_err(|error| RelayServerError::Io(io::Error::other(error.to_string())))
}

fn start_prelude_workers(
    cx: &Cx,
    listener: TcpListener,
    policy: RelayPolicy,
) -> Result<PreparedInbox<TcpStream>, RelayServerError> {
    let listener = Arc::new(listener);
    let queue_capacity = usize::from(policy.prelude_workers).saturating_mul(2);
    let (prepared_tx, prepared_rx) = mpsc::channel(queue_capacity);
    let mut workers = Vec::with_capacity(usize::from(policy.prelude_workers));

    for _ in 0..policy.prelude_workers {
        let listener = Arc::clone(&listener);
        let prepared_tx = prepared_tx.clone();
        let timeout_ms = policy.prelude_timeout_ms;
        let worker = cx
            .spawn(move |worker_cx| async move {
                accept_prepared(&worker_cx, listener, prepared_tx, timeout_ms).await;
            })
            .map_err(|error| io::Error::other(error.to_string()))?;
        workers.push(worker);
    }
    drop(prepared_tx);
    Ok((prepared_rx, workers))
}

fn start_wss_prelude_workers(
    cx: &Cx,
    listener: TcpListener,
    acceptor: TlsAcceptor,
    policy: RelayPolicy,
) -> Result<PreparedInbox<WssStream>, RelayServerError> {
    let listener = Arc::new(listener);
    let acceptor = Arc::new(acceptor);
    let queue_capacity = usize::from(policy.prelude_workers).saturating_mul(2);
    let (prepared_tx, prepared_rx) = mpsc::channel(queue_capacity);
    let mut workers = Vec::with_capacity(usize::from(policy.prelude_workers));

    for _ in 0..policy.prelude_workers {
        let listener = Arc::clone(&listener);
        let acceptor = Arc::clone(&acceptor);
        let prepared_tx = prepared_tx.clone();
        let timeout_ms = policy.prelude_timeout_ms;
        let worker = cx
            .spawn(move |worker_cx| async move {
                accept_prepared_wss(&worker_cx, listener, acceptor, prepared_tx, timeout_ms).await;
            })
            .map_err(|error| io::Error::other(error.to_string()))?;
        workers.push(worker);
    }
    drop(prepared_tx);
    Ok((prepared_rx, workers))
}

async fn run_session<S>(
    cx: &Cx,
    mut sender: S,
    mut receiver: S,
    idle: Duration,
    websocket_close_is_terminal: bool,
    route_issuer: Option<RelayRouteIssuer>,
) -> Result<ForwardStats, RelayServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let route_bundle = if let Some(issuer) = route_issuer {
        issuer.issue(cx).await.ok()
    } else {
        None
    };
    let matched_status = if route_bundle.is_some() {
        JoinStatus::MatchedWithRoutes
    } else {
        JoinStatus::Matched
    };
    if send_status(&mut sender, matched_status).await.is_err() {
        let _ = send_status(&mut receiver, JoinStatus::Unavailable).await;
        return Err(RelayServerError::Io(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "sender left before relay match",
        )));
    }
    send_status(&mut receiver, matched_status).await?;
    if let Some(bundle) = route_bundle {
        sender.write_all(&bundle).await?;
        receiver.write_all(&bundle).await?;
        sender.flush().await?;
        receiver.flush().await?;
    }
    if websocket_close_is_terminal {
        forward_bidirectional_websocket(&mut sender, &mut receiver, idle)
            .await
            .map_err(RelayServerError::from)
    } else {
        forward_bidirectional(&mut sender, &mut receiver, idle)
            .await
            .map_err(RelayServerError::from)
    }
}

fn reap_finished(
    active: &mut Vec<TaskHandle<Result<ForwardStats, RelayServerError>>>,
    terminal: &mut Vec<Result<ForwardStats, RelayServerError>>,
) {
    let mut index = 0;
    while index < active.len() {
        match active[index].try_join() {
            Ok(Some(outcome)) => {
                terminal.push(outcome);
                active.remove(index);
            }
            Ok(None) => index += 1,
            Err(error) => {
                terminal.push(Err(RelayServerError::Io(io::Error::other(
                    error.to_string(),
                ))));
                active.remove(index);
            }
        }
    }
}

async fn drain_sessions(
    cx: &Cx,
    active: &mut Vec<TaskHandle<Result<ForwardStats, RelayServerError>>>,
    terminal: &mut Vec<Result<ForwardStats, RelayServerError>>,
) {
    for mut session in active.drain(..) {
        match session.join(cx).await {
            Ok(outcome) => terminal.push(outcome),
            Err(error) => terminal.push(Err(RelayServerError::Io(io::Error::other(
                error.to_string(),
            )))),
        }
    }
}

async fn accept_prepared(
    cx: &Cx,
    listener: Arc<TcpListener>,
    sender: mpsc::Sender<PreparedConnection<TcpStream>>,
    prelude_timeout_ms: u64,
) {
    loop {
        if cx.checkpoint().is_err() {
            return;
        }
        let (mut stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return,
            Err(error) => {
                let _ = sender
                    .send(cx, PreparedConnection::AcceptFailed(error))
                    .await;
                return;
            }
        };
        let Some(prelude) = read_prelude(&mut stream, prelude_timeout_ms).await else {
            let _ = send_status(&mut stream, JoinStatus::InvalidPrelude).await;
            continue;
        };
        if sender
            .send(cx, PreparedConnection::Valid { stream, prelude })
            .await
            .is_err()
        {
            return;
        }
    }
}

async fn accept_prepared_wss(
    cx: &Cx,
    listener: Arc<TcpListener>,
    acceptor: Arc<TlsAcceptor>,
    sender: mpsc::Sender<PreparedConnection<WssStream>>,
    prelude_timeout_ms: u64,
) {
    loop {
        if cx.checkpoint().is_err() {
            return;
        }
        let (tcp, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return,
            Err(error) => {
                let _ = sender
                    .send(cx, PreparedConnection::AcceptFailed(error))
                    .await;
                return;
            }
        };
        let Ok(mut stream) = accept_wss(tcp, &acceptor).await else {
            continue;
        };
        let Some(prelude) = read_prelude(&mut stream, prelude_timeout_ms).await else {
            let _ = send_status(&mut stream, JoinStatus::InvalidPrelude).await;
            continue;
        };
        if sender
            .send(cx, PreparedConnection::Valid { stream, prelude })
            .await
            .is_err()
        {
            return;
        }
    }
}

async fn stop_workers(cx: &Cx, workers: &mut Vec<TaskHandle<()>>) {
    for worker in workers.iter() {
        worker.abort();
    }
    for worker in workers.iter_mut() {
        let _ = worker.join(cx).await;
    }
    workers.clear();
}

async fn read_prelude<S>(stream: &mut S, timeout_ms: u64) -> Option<JoinPrelude>
where
    S: AsyncRead + Unpin,
{
    let mut encoded = [0_u8; JOIN_PRELUDE_BYTES];
    match timeout(
        wall_now(),
        Duration::from_millis(timeout_ms),
        stream.read_exact(&mut encoded),
    )
    .await
    {
        Ok(Ok(())) => JoinPrelude::decode(&encoded).ok(),
        Ok(Err(_)) | Err(_) => None,
    }
}

async fn send_status<S>(stream: &mut S, status: JoinStatus) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&status.encode()).await?;
    stream.flush().await
}

fn join_error_status(error: JoinError) -> JoinStatus {
    match error {
        JoinError::RoleOccupied => JoinStatus::RoleOccupied,
        JoinError::CapacityExhausted => JoinStatus::CapacityExhausted,
        JoinError::InvalidCapacity | JoinError::InvalidTtl | JoinError::InvariantViolation => {
            JoinStatus::Unavailable
        }
    }
}

fn now_ms() -> u64 {
    wall_now().as_nanos() / 1_000_000
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use asupersync::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        runtime::RuntimeBuilder,
        tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsConnector},
    };
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rift_protocol::{JOIN_ACK_BYTES, JoinPrelude, JoinStatus, RendezvousRole};
    use rift_transport::{WssEndpoint, connect_wss_with};

    use super::*;

    async fn admitted(
        address: std::net::SocketAddr,
        lookup_id: [u8; 16],
        role: RendezvousRole,
    ) -> TcpStream {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(&JoinPrelude { lookup_id, role }.encode())
            .await
            .unwrap();
        let mut encoded = [0_u8; JOIN_ACK_BYTES];
        stream.read_exact(&mut encoded).await.unwrap();
        if JoinStatus::decode(&encoded) == Ok(JoinStatus::Reserved) {
            stream.read_exact(&mut encoded).await.unwrap();
        }
        assert_eq!(JoinStatus::decode(&encoded), Ok(JoinStatus::Matched));
        stream
    }

    async fn reserved_sender(address: std::net::SocketAddr, lookup_id: [u8; 16]) -> TcpStream {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(
                &JoinPrelude {
                    lookup_id,
                    role: RendezvousRole::Sender,
                }
                .encode(),
            )
            .await
            .unwrap();
        let mut encoded = [0_u8; JOIN_ACK_BYTES];
        stream.read_exact(&mut encoded).await.unwrap();
        assert_eq!(JoinStatus::decode(&encoded), Ok(JoinStatus::Reserved));
        stream
    }

    async fn matched_sender(mut stream: TcpStream) -> TcpStream {
        let mut encoded = [0_u8; JOIN_ACK_BYTES];
        stream.read_exact(&mut encoded).await.unwrap();
        assert_eq!(JoinStatus::decode(&encoded), Ok(JoinStatus::Matched));
        stream
    }

    fn test_tls() -> (TlsAcceptor, TlsConnector) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate = Certificate::from_der(cert.der().to_vec());
        let acceptor = TlsAcceptor::builder(
            CertificateChain::from_cert(certificate.clone()),
            PrivateKey::from_pkcs8_der(signing_key.serialize_der()),
        )
        .alpn_protocols_required(vec![b"http/1.1".to_vec()])
        .handshake_timeout(Duration::from_secs(2))
        .build()
        .unwrap();
        let connector = TlsConnector::builder()
            .add_root_certificate(&certificate)
            .alpn_protocols_required(vec![b"http/1.1".to_vec()])
            .handshake_timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        (acceptor, connector)
    }

    #[test]
    fn authenticated_wss_forwards_the_same_blind_byte_path() {
        let runtime = RuntimeBuilder::new().worker_threads(3).build().unwrap();
        let handle = runtime.handle();
        let stats = runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let endpoint: WssEndpoint = format!("wss://localhost:{}/rift/v1", address.port())
                .parse()
                .unwrap();
            let (acceptor, connector) = test_tls();
            let relay = handle.clone().spawn(async move {
                serve_one_wss(listener, acceptor, RelayPolicy::default())
                    .await
                    .unwrap()
            });

            let lookup_id = [17; 16];
            let mut sender = connect_wss_with(&endpoint, &connector).await.unwrap();
            sender
                .write_all(
                    &JoinPrelude {
                        lookup_id,
                        role: RendezvousRole::Sender,
                    }
                    .encode(),
                )
                .await
                .unwrap();
            let mut status = [0_u8; JOIN_ACK_BYTES];
            sender.read_exact(&mut status).await.unwrap();
            assert_eq!(JoinStatus::decode(&status), Ok(JoinStatus::Reserved));

            let mut receiver = connect_wss_with(&endpoint, &connector).await.unwrap();
            receiver
                .write_all(
                    &JoinPrelude {
                        lookup_id,
                        role: RendezvousRole::Receiver,
                    }
                    .encode(),
                )
                .await
                .unwrap();
            sender.read_exact(&mut status).await.unwrap();
            assert_eq!(JoinStatus::decode(&status), Ok(JoinStatus::Matched));
            receiver.read_exact(&mut status).await.unwrap();
            assert_eq!(JoinStatus::decode(&status), Ok(JoinStatus::Matched));

            sender.write_all(b"opaque ciphertext").await.unwrap();
            let mut opaque = [0_u8; 17];
            receiver.read_exact(&mut opaque).await.unwrap();
            assert_eq!(&opaque, b"opaque ciphertext");
            receiver.write_all(b"receipt").await.unwrap();
            let mut receipt = [0_u8; 7];
            sender.read_exact(&mut receipt).await.unwrap();
            assert_eq!(&receipt, b"receipt");
            sender.shutdown().await.unwrap();
            receiver.shutdown().await.unwrap();
            relay.await
        });
        assert_eq!(stats.sender_to_receiver, 17);
        assert_eq!(stats.receiver_to_sender, 7);
    }

    #[test]
    fn raw_relay_api_refuses_public_ingress() {
        let runtime = RuntimeBuilder::new().worker_threads(1).build().unwrap();
        let error = runtime.block_on(async {
            let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
            serve_one(listener, RelayPolicy::default())
                .await
                .unwrap_err()
        });
        assert!(matches!(
            error,
            RelayServerError::Io(ref io_error)
                if io_error.kind() == io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn persistent_relay_serves_sequential_pairs_under_one_owner() {
        let runtime = RuntimeBuilder::new().worker_threads(3).build().unwrap();
        runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let cx = Cx::current().unwrap();
            let mut relay = cx
                .spawn(
                    move |_relay_cx| async move { serve(listener, RelayPolicy::default()).await },
                )
                .unwrap();

            for identity in [31_u8, 32_u8] {
                let sender = reserved_sender(address, [identity; 16]).await;
                let mut receiver =
                    admitted(address, [identity; 16], RendezvousRole::Receiver).await;
                let mut sender = matched_sender(sender).await;
                sender.write_all(&[identity]).await.unwrap();
                let mut byte = [0_u8; 1];
                receiver.read_exact(&mut byte).await.unwrap();
                assert_eq!(byte, [identity]);
                AsyncWriteExt::shutdown(&mut sender).await.unwrap();
                AsyncWriteExt::shutdown(&mut receiver).await.unwrap();
            }

            relay.abort();
            let _ = relay.join(&cx).await;
        });
    }

    #[test]
    fn slow_prelude_cannot_head_of_line_block_a_valid_pair() {
        let runtime = RuntimeBuilder::new().worker_threads(3).build().unwrap();
        let handle = runtime.handle();
        let started = Instant::now();
        let stats = runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let policy = RelayPolicy {
                prelude_timeout_ms: 1_000,
                prelude_workers: 2,
                ..RelayPolicy::default()
            };
            let relay = handle
                .clone()
                .spawn(async move { serve_one(listener, policy).await.unwrap() });

            let _slow = TcpStream::connect(address).await.unwrap();
            let sender = reserved_sender(address, [8; 16]).await;
            let mut receiver = admitted(address, [8; 16], RendezvousRole::Receiver).await;
            let mut sender = matched_sender(sender).await;
            sender.write_all(b"ciphertext").await.unwrap();
            let mut inbound = [0_u8; 10];
            receiver.read_exact(&mut inbound).await.unwrap();
            assert_eq!(&inbound, b"ciphertext");
            receiver.write_all(b"ok").await.unwrap();
            let mut response = [0_u8; 2];
            sender.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"ok");
            AsyncWriteExt::shutdown(&mut sender).await.unwrap();
            AsyncWriteExt::shutdown(&mut receiver).await.unwrap();
            relay.await
        });

        assert!(started.elapsed() < Duration::from_millis(900));
        assert_eq!(stats.sender_to_receiver, 10);
        assert_eq!(stats.receiver_to_sender, 2);
    }

    #[test]
    fn inactive_matched_pair_is_closed_by_idle_policy() {
        let runtime = RuntimeBuilder::new().worker_threads(3).build().unwrap();
        let handle = runtime.handle();
        let error = runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let policy = RelayPolicy {
                idle_timeout_ms: 40,
                ..RelayPolicy::default()
            };
            let relay = handle
                .clone()
                .spawn(async move { serve_one(listener, policy).await.unwrap_err() });
            let sender = reserved_sender(address, [5; 16]).await;
            let _receiver = admitted(address, [5; 16], RendezvousRole::Receiver).await;
            let _sender = matched_sender(sender).await;
            relay.await
        });
        assert!(matches!(
            error,
            RelayServerError::Forward(ForwardError::IdleTimeout)
        ));
    }

    #[test]
    fn receiver_cannot_squat_an_unreserved_nameplate() {
        let runtime = RuntimeBuilder::new().worker_threads(3).build().unwrap();
        let handle = runtime.handle();
        runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let relay = handle.clone().spawn(async move {
                let _ = serve_one(listener, RelayPolicy::default()).await;
            });

            let mut squatter = TcpStream::connect(address).await.unwrap();
            squatter
                .write_all(
                    &JoinPrelude {
                        lookup_id: [9; 16],
                        role: RendezvousRole::Receiver,
                    }
                    .encode(),
                )
                .await
                .unwrap();
            let mut status = [0_u8; JOIN_ACK_BYTES];
            squatter.read_exact(&mut status).await.unwrap();
            assert_eq!(JoinStatus::decode(&status), Ok(JoinStatus::SenderAbsent));

            let sender = reserved_sender(address, [9; 16]).await;
            let mut receiver = admitted(address, [9; 16], RendezvousRole::Receiver).await;
            let mut sender = matched_sender(sender).await;
            AsyncWriteExt::shutdown(&mut sender).await.unwrap();
            AsyncWriteExt::shutdown(&mut receiver).await.unwrap();
            let () = relay.await;
        });
    }

    #[test]
    fn distinct_lookups_forward_concurrently_under_one_owner() {
        let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        let handle = runtime.handle();
        let outcomes = runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let policy = RelayPolicy {
                max_sessions: 2,
                ..RelayPolicy::default()
            };
            let relay = handle
                .clone()
                .spawn(async move { serve_exact(listener, policy, 2).await.unwrap() });

            let first_sender = reserved_sender(address, [1; 16]).await;
            let mut first_receiver = admitted(address, [1; 16], RendezvousRole::Receiver).await;
            let mut first_sender = matched_sender(first_sender).await;

            let second_sender = reserved_sender(address, [2; 16]).await;
            let mut second_receiver = admitted(address, [2; 16], RendezvousRole::Receiver).await;
            let mut second_sender = matched_sender(second_sender).await;

            first_sender.write_all(b"first").await.unwrap();
            second_sender.write_all(b"second").await.unwrap();
            let mut first = [0_u8; 5];
            let mut second = [0_u8; 6];
            first_receiver.read_exact(&mut first).await.unwrap();
            second_receiver.read_exact(&mut second).await.unwrap();
            assert_eq!(&first, b"first");
            assert_eq!(&second, b"second");

            AsyncWriteExt::shutdown(&mut first_sender).await.unwrap();
            AsyncWriteExt::shutdown(&mut first_receiver).await.unwrap();
            AsyncWriteExt::shutdown(&mut second_sender).await.unwrap();
            AsyncWriteExt::shutdown(&mut second_receiver).await.unwrap();
            relay.await
        });

        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(Result::is_ok));
    }

    #[test]
    fn active_session_capacity_rejects_without_consuming_waiting_peer() {
        let runtime = RuntimeBuilder::new().worker_threads(4).build().unwrap();
        let handle = runtime.handle();
        let outcomes = runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let policy = RelayPolicy {
                max_sessions: 1,
                ..RelayPolicy::default()
            };
            let relay = handle
                .clone()
                .spawn(async move { serve_exact(listener, policy, 2).await.unwrap() });

            let first_sender = reserved_sender(address, [3; 16]).await;
            let mut first_receiver = admitted(address, [3; 16], RendezvousRole::Receiver).await;
            let mut first_sender = matched_sender(first_sender).await;

            let mut waiting_sender = TcpStream::connect(address).await.unwrap();
            waiting_sender
                .write_all(
                    &JoinPrelude {
                        lookup_id: [4; 16],
                        role: RendezvousRole::Sender,
                    }
                    .encode(),
                )
                .await
                .unwrap();
            let mut reserved = [0_u8; JOIN_ACK_BYTES];
            waiting_sender.read_exact(&mut reserved).await.unwrap();
            assert_eq!(JoinStatus::decode(&reserved), Ok(JoinStatus::Reserved));
            let mut rejected_receiver = TcpStream::connect(address).await.unwrap();
            rejected_receiver
                .write_all(
                    &JoinPrelude {
                        lookup_id: [4; 16],
                        role: RendezvousRole::Receiver,
                    }
                    .encode(),
                )
                .await
                .unwrap();
            let mut rejected = [0_u8; JOIN_ACK_BYTES];
            rejected_receiver.read_exact(&mut rejected).await.unwrap();
            assert_eq!(
                JoinStatus::decode(&rejected),
                Ok(JoinStatus::CapacityExhausted)
            );

            AsyncWriteExt::shutdown(&mut first_sender).await.unwrap();
            AsyncWriteExt::shutdown(&mut first_receiver).await.unwrap();
            asupersync::time::sleep(wall_now(), Duration::from_millis(250)).await;

            let mut retry_receiver = TcpStream::connect(address).await.unwrap();
            retry_receiver
                .write_all(
                    &JoinPrelude {
                        lookup_id: [4; 16],
                        role: RendezvousRole::Receiver,
                    }
                    .encode(),
                )
                .await
                .unwrap();
            let mut sender_ack = [0_u8; JOIN_ACK_BYTES];
            let mut receiver_ack = [0_u8; JOIN_ACK_BYTES];
            waiting_sender.read_exact(&mut sender_ack).await.unwrap();
            retry_receiver.read_exact(&mut receiver_ack).await.unwrap();
            assert_eq!(JoinStatus::decode(&sender_ack), Ok(JoinStatus::Matched));
            assert_eq!(JoinStatus::decode(&receiver_ack), Ok(JoinStatus::Matched));
            AsyncWriteExt::shutdown(&mut waiting_sender).await.unwrap();
            AsyncWriteExt::shutdown(&mut retry_receiver).await.unwrap();
            relay.await
        });

        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(Result::is_ok));
    }
}
