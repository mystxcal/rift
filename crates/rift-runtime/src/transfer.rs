//! Executable single-file transfer path over the blind stream relay.

use std::{
    net::SocketAddr,
    path::Path,
    time::{Duration, Instant},
};

use asupersync::{
    cx::Cx,
    runtime::TaskHandle,
    time::{sleep, wall_now},
};

use rift_protocol::{
    Capability, HandshakePrologue, HardLimits, JoinStatus, PairingCode, PairingCodeError,
    RendezvousRole, Role, SelectedAlgorithms,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    DirectAcquirePolicy, DirectPathError, FileOracleError, HandshakeRole, MigrationPolicy,
    PairingError, ReceiveSummary, ReceiveTarget, RelayClientError, RelayDialer, RelayEndpoint,
    SecureStream, SecureStreamError, SendSummary, SenderReservation, TransferObserver,
    connect_relay, connect_relay_lookup_with,
    direct::{DirectQuicCandidate, acquire_direct_quic_candidate_bound},
    establish_pairing_secret,
    file_oracle::{NoopObserver, ResumeToken},
    piece_oracle::{receive_object_piecewise, send_object_piecewise},
    piece_path::RelayPiecePath,
    quic_path::{
        QuicPathSelection, QuicPathSelectionError, select_receiver_quic, select_sender_quic,
    },
    receive_file, reserve_sender_endpoint, reserve_sender_relay, reserve_sender_with, send_file,
};

/// Complete local-relay transfer failure.
#[derive(Debug, Error)]
pub enum TransferError {
    /// Blind relay connection or admission failed.
    #[error(transparent)]
    Relay(#[from] RelayClientError),
    /// Capability-authenticated Noise establishment failed.
    #[error(transparent)]
    Secure(#[from] SecureStreamError),
    /// Authenticated object transfer or commit failed.
    #[error(transparent)]
    File(#[from] FileOracleError),
    /// Compact human-code authentication failed.
    #[error(transparent)]
    Pairing(#[from] PairingError),
    /// Compact code generation failed.
    #[error(transparent)]
    PairingCode(#[from] PairingCodeError),
    /// Authenticated QUIC path negotiation failed before payload selection.
    #[error(transparent)]
    QuicPath(#[from] QuicPathSelectionError),
    /// Repeated random nameplates were already owned by live senders.
    #[error("could not reserve a free pairing nameplate")]
    NameplateCollision,
}

/// End-to-end policy for one live transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferPolicy {
    /// Bounded direct-path acquisition policy.
    pub direct_acquisition: DirectAcquirePolicy,
    /// Relay-to-direct completion-time and fallback policy.
    pub migration: MigrationPolicy,
    /// Local UDP port for rendezvous through data; zero requests an ephemeral port.
    pub direct_bind_port: u16,
    /// Additional live reconnection attempts after an interrupted path.
    pub resume_attempts: u8,
    /// Maximum wall-clock interval in which one live transfer may reconnect.
    pub resume_window: Duration,
}

impl Default for TransferPolicy {
    fn default() -> Self {
        Self {
            direct_acquisition: DirectAcquirePolicy::default(),
            migration: MigrationPolicy::default(),
            direct_bind_port: 0,
            resume_attempts: 8,
            resume_window: Duration::from_mins(2),
        }
    }
}

/// Generate and reserve a fresh compact code before returning it to the UI.
///
/// Live sender collisions are retried with fresh CSPRNG output. No rejected
/// code is ever exposed to the caller.
///
/// # Errors
///
/// Returns for entropy failure, relay failure other than a sender collision,
/// or exhaustion of the bounded collision retry budget.
pub async fn reserve_fresh_pairing_sender(
    address: SocketAddr,
) -> Result<(PairingCode, SenderReservation), TransferError> {
    reserve_fresh_pairing_sender_endpoint(address.into()).await
}

/// Generate and reserve a fresh compact code on either safe relay transport.
///
/// # Errors
///
/// Returns for entropy, endpoint, relay, or bounded collision exhaustion.
pub async fn reserve_fresh_pairing_sender_endpoint(
    endpoint: RelayEndpoint,
) -> Result<(PairingCode, SenderReservation), TransferError> {
    reserve_fresh_pairing_sender_with(RelayDialer::new(endpoint)).await
}

/// Generate and reserve a fresh code with an explicit relay dialing policy.
///
/// # Errors
///
/// Returns for entropy, endpoint, relay, or bounded collision exhaustion.
pub async fn reserve_fresh_pairing_sender_with(
    dialer: RelayDialer,
) -> Result<(PairingCode, SenderReservation), TransferError> {
    const ATTEMPTS: usize = 16;
    for _ in 0..ATTEMPTS {
        let code = PairingCode::generate()?;
        match reserve_sender_with(dialer.clone(), code.lookup_id()).await {
            Ok(reservation) => return Ok((code, reservation)),
            Err(RelayClientError::Declined(JoinStatus::RoleOccupied)) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(TransferError::NameplateCollision)
}

/// Reserve a sender nameplate before exposing its compact code.
///
/// # Errors
///
/// Returns unless the relay grants exclusive ownership of the sender slot.
pub async fn reserve_pairing_sender(
    address: SocketAddr,
    code: &PairingCode,
) -> Result<SenderReservation, TransferError> {
    reserve_sender_relay(address, code.lookup_id())
        .await
        .map_err(TransferError::from)
}

/// Reserve a sender nameplate through either safe relay transport.
///
/// # Errors
///
/// Returns unless the relay grants exclusive ownership of the sender slot.
pub async fn reserve_pairing_sender_endpoint(
    endpoint: RelayEndpoint,
    code: &PairingCode,
) -> Result<SenderReservation, TransferError> {
    reserve_sender_endpoint(endpoint, code.lookup_id())
        .await
        .map_err(TransferError::from)
}

/// Authenticate and send over an already-reserved compact-code rendezvous.
///
/// # Errors
///
/// Returns for match failure, SPAKE2 confirmation failure, Noise failure,
/// source mutation, object transfer, or a mismatched commit receipt.
pub async fn send_reserved_via_pairing(
    reservation: SenderReservation,
    code: &PairingCode,
    source: impl AsRef<Path>,
) -> Result<SendSummary, TransferError> {
    send_reserved_via_pairing_with_policy(reservation, code, source, TransferPolicy::default())
        .await
}

/// Authenticate and send with one explicit end-to-end path policy.
///
/// # Errors
///
/// Has the same failure contract as [`send_reserved_via_pairing`].
pub async fn send_reserved_via_pairing_with_policy(
    reservation: SenderReservation,
    code: &PairingCode,
    source: impl AsRef<Path>,
    policy: TransferPolicy,
) -> Result<SendSummary, TransferError> {
    send_reserved_via_pairing_observed_with_policy(reservation, code, source, policy, &NoopObserver)
        .await
}

/// Send with a read-only UI observation hook.
///
/// # Errors
///
/// Has the same transfer contract as [`send_reserved_via_pairing_with_policy`].
pub async fn send_reserved_via_pairing_observed_with_policy(
    reservation: SenderReservation,
    code: &PairingCode,
    source: impl AsRef<Path>,
    policy: TransferPolicy,
    observer: &dyn TransferObserver,
) -> Result<SendSummary, TransferError> {
    let dialer = reservation.dialer();
    let token = ResumeToken::generate()?;
    let deadline = Instant::now()
        .checked_add(policy.resume_window)
        .unwrap_or_else(Instant::now);
    let mut reservation = Some(reservation);
    let mut attempt = 0_u8;
    let mut allow_acceleration = true;
    loop {
        let current = match reservation.take() {
            Some(reservation) => reservation,
            None => match reserve_sender_with(dialer.clone(), code.lookup_id()).await {
                Ok(reservation) => reservation,
                Err(error) => {
                    let error = TransferError::Relay(error);
                    if !may_retry(&error, attempt, deadline, policy) {
                        return Err(error);
                    }
                    wait_before_retry(attempt).await;
                    attempt = attempt.saturating_add(1);
                    continue;
                }
            },
        };
        match send_pairing_attempt(
            current,
            code,
            source.as_ref(),
            policy,
            observer,
            &token,
            allow_acceleration,
        )
        .await
        {
            Ok(summary) => return Ok(summary),
            Err(error) if may_retry(&error, attempt, deadline, policy) => {
                if demotes_acceleration(&error) && allow_acceleration {
                    allow_acceleration = false;
                    observer.observe(crate::TransferProgress::Recovering);
                }
                wait_before_retry(attempt).await;
                attempt = attempt.saturating_add(1);
            }
            Err(error) => return Err(error),
        }
    }
}

async fn send_pairing_attempt(
    reservation: SenderReservation,
    code: &PairingCode,
    source: &Path,
    policy: TransferPolicy,
    observer: &dyn TransferObserver,
    token: &ResumeToken,
    allow_acceleration: bool,
) -> Result<SendSummary, TransferError> {
    let endpoint = reservation.endpoint().clone();
    let mut relay = reservation.wait_matched().await?;
    let routes = relay.take_routes();
    let secret = establish_pairing_secret(&mut relay, code, Role::Sender).await?;
    let mut direct =
        spawn_direct_acquisition(endpoint, code.lookup_id(), &secret, Role::Sender, policy);
    let prologue = prologue_for_lookup(code.lookup_id()).encode();
    let secure =
        match SecureStream::establish(relay, HandshakeRole::Initiator, &secret, &prologue).await {
            Ok(secure) => secure,
            Err(error) => {
                stop_direct_acquisition(&mut direct).await;
                return Err(error.into());
            }
        };
    observer.observe(crate::TransferProgress::PeerReady);
    match Box::pin(select_sender_quic(
        secure,
        direct,
        routes,
        policy.migration,
        &secret,
        allow_acceleration,
    ))
    .await?
    {
        QuicPathSelection::Quic(mut link) => {
            observer.observe(crate::TransferProgress::RouteSelected {
                primary: link.primary_transport(),
                candidates: link.path_count(),
            });
            send_object_piecewise(
                &mut *link,
                source,
                HardLimits::CONSERVATIVE,
                observer,
                token,
            )
            .await
            .map_err(TransferError::from)
        }
        QuicPathSelection::Relay(secure) => {
            observer.observe(crate::TransferProgress::RouteSelected {
                primary: crate::TransferTransport::Relay,
                candidates: 1,
            });
            let mut path = RelayPiecePath::new(*secure);
            send_object_piecewise(&mut path, source, HardLimits::CONSERVATIVE, observer, token)
                .await
                .map_err(TransferError::from)
        }
    }
}

/// Receive and atomically commit through a compact human pairing code.
///
/// # Errors
///
/// Returns for relay admission, SPAKE2 confirmation, Noise authentication,
/// protocol violation, staging, verification, or commit failure.
pub async fn receive_via_pairing(
    address: SocketAddr,
    code: &PairingCode,
    destination: impl AsRef<Path>,
) -> Result<ReceiveSummary, TransferError> {
    receive_via_pairing_endpoint(address.into(), code, destination).await
}

/// Receive and atomically commit through either safe relay transport.
///
/// # Errors
///
/// Returns for admission, pairing, Noise, transfer, or commit failure.
pub async fn receive_via_pairing_endpoint(
    endpoint: RelayEndpoint,
    code: &PairingCode,
    destination: impl AsRef<Path>,
) -> Result<ReceiveSummary, TransferError> {
    receive_via_pairing_with(RelayDialer::new(endpoint), code, destination).await
}

/// Receive and atomically commit with an explicit relay dialing policy.
///
/// # Errors
///
/// Returns for admission, pairing, Noise, transfer, or commit failure.
pub async fn receive_via_pairing_with(
    dialer: RelayDialer,
    code: &PairingCode,
    destination: impl AsRef<Path>,
) -> Result<ReceiveSummary, TransferError> {
    receive_via_pairing_with_policy(dialer, code, destination, TransferPolicy::default()).await
}

/// Receive and atomically commit with one explicit end-to-end path policy.
///
/// # Errors
///
/// Has the same failure contract as [`receive_via_pairing_with`].
pub async fn receive_via_pairing_with_policy(
    dialer: RelayDialer,
    code: &PairingCode,
    destination: impl AsRef<Path>,
    policy: TransferPolicy,
) -> Result<ReceiveSummary, TransferError> {
    Box::pin(receive_via_pairing_target_with_policy(
        dialer,
        code,
        ReceiveTarget::Exact(destination.as_ref().to_owned()),
        policy,
    ))
    .await
}

/// Receive with an explicit exact-path or preserve-name placement policy.
///
/// # Errors
///
/// Has the same authenticated transfer and commit contract as
/// [`receive_via_pairing_with_policy`].
pub async fn receive_via_pairing_target_with_policy(
    dialer: RelayDialer,
    code: &PairingCode,
    destination: ReceiveTarget,
    policy: TransferPolicy,
) -> Result<ReceiveSummary, TransferError> {
    Box::pin(receive_via_pairing_target_observed_with_policy(
        dialer,
        code,
        destination,
        policy,
        &NoopObserver,
    ))
    .await
}

/// Receive with a read-only UI observation hook.
///
/// # Errors
///
/// Has the same transfer contract as [`receive_via_pairing_target_with_policy`].
pub async fn receive_via_pairing_target_observed_with_policy(
    dialer: RelayDialer,
    code: &PairingCode,
    destination: ReceiveTarget,
    policy: TransferPolicy,
    observer: &dyn TransferObserver,
) -> Result<ReceiveSummary, TransferError> {
    let deadline = Instant::now()
        .checked_add(policy.resume_window)
        .unwrap_or_else(Instant::now);
    let mut attempt = 0_u8;
    let mut allow_acceleration = true;
    loop {
        match Box::pin(receive_pairing_attempt(
            &dialer,
            code,
            &destination,
            policy,
            observer,
            allow_acceleration,
        ))
        .await
        {
            Ok(summary) => return Ok(summary),
            Err(error) if may_retry(&error, attempt, deadline, policy) => {
                if demotes_acceleration(&error) && allow_acceleration {
                    allow_acceleration = false;
                    observer.observe(crate::TransferProgress::Recovering);
                }
                wait_before_retry(attempt).await;
                attempt = attempt.saturating_add(1);
            }
            Err(error) => return Err(error),
        }
    }
}

async fn receive_pairing_attempt(
    dialer: &RelayDialer,
    code: &PairingCode,
    destination: &ReceiveTarget,
    policy: TransferPolicy,
    observer: &dyn TransferObserver,
    allow_acceleration: bool,
) -> Result<ReceiveSummary, TransferError> {
    let endpoint = dialer.endpoint().clone();
    let mut relay =
        connect_relay_lookup_with(dialer, code.lookup_id(), RendezvousRole::Receiver).await?;
    let routes = relay.take_routes();
    let secret = establish_pairing_secret(&mut relay, code, Role::Receiver).await?;
    let mut direct =
        spawn_direct_acquisition(endpoint, code.lookup_id(), &secret, Role::Receiver, policy);
    let prologue = prologue_for_lookup(code.lookup_id()).encode();
    let secure =
        match SecureStream::establish(relay, HandshakeRole::Responder, &secret, &prologue).await {
            Ok(secure) => secure,
            Err(error) => {
                stop_direct_acquisition(&mut direct).await;
                return Err(error.into());
            }
        };
    observer.observe(crate::TransferProgress::PeerReady);
    match Box::pin(select_receiver_quic(
        secure,
        direct,
        routes,
        policy.migration,
        &secret,
        allow_acceleration,
    ))
    .await?
    {
        QuicPathSelection::Quic(mut link) => {
            observer.observe(crate::TransferProgress::RouteSelected {
                primary: link.primary_transport(),
                candidates: link.path_count(),
            });
            receive_object_piecewise(
                &mut *link,
                destination.clone(),
                HardLimits::CONSERVATIVE,
                observer,
            )
            .await
            .map_err(TransferError::from)
        }
        QuicPathSelection::Relay(secure) => {
            observer.observe(crate::TransferProgress::RouteSelected {
                primary: crate::TransferTransport::Relay,
                candidates: 1,
            });
            let mut path = RelayPiecePath::new(*secure);
            receive_object_piecewise(
                &mut path,
                destination.clone(),
                HardLimits::CONSERVATIVE,
                observer,
            )
            .await
            .map_err(TransferError::from)
        }
    }
}

fn may_retry(
    error: &TransferError,
    attempt: u8,
    deadline: Instant,
    policy: TransferPolicy,
) -> bool {
    attempt < policy.resume_attempts
        && Instant::now() < deadline
        && match error {
            TransferError::Relay(_) | TransferError::QuicPath(_) => true,
            TransferError::File(error) => error.is_retryable_path_failure(),
            TransferError::Secure(_)
            | TransferError::Pairing(_)
            | TransferError::PairingCode(_)
            | TransferError::NameplateCollision => false,
        }
}

fn demotes_acceleration(error: &TransferError) -> bool {
    match error {
        TransferError::QuicPath(_) => true,
        TransferError::File(error) => error.is_accelerated_path_failure(),
        _ => false,
    }
}

async fn wait_before_retry(attempt: u8) {
    let exponent = u32::from(attempt.min(3));
    let millis = 125_u64.saturating_mul(1_u64 << exponent).min(1_000);
    sleep(wall_now(), Duration::from_millis(millis)).await;
}

pub(crate) fn spawn_direct_acquisition(
    endpoint: RelayEndpoint,
    lookup_id: [u8; 16],
    secret: &[u8; 32],
    role: Role,
    policy: TransferPolicy,
) -> Option<TaskHandle<Result<DirectQuicCandidate, DirectPathError>>> {
    let cx = Cx::current()?;
    let secret = Zeroizing::new(*secret);
    cx.spawn(move |_direct_cx| async move {
        acquire_direct_quic_candidate_bound(
            &endpoint,
            lookup_id,
            &secret,
            role,
            policy.direct_bind_port,
            policy.direct_acquisition,
        )
        .await
    })
    .ok()
}

async fn stop_direct_acquisition(
    acquisition: &mut Option<TaskHandle<Result<DirectQuicCandidate, DirectPathError>>>,
) {
    let Some(mut task) = acquisition.take() else {
        return;
    };
    task.abort();
    if let Some(cx) = Cx::current() {
        let _ = task.join(&cx).await;
    }
}

/// Send one file through the correctness path.
///
/// # Errors
///
/// Returns for relay admission, Noise authentication, source mutation, object
/// transfer, or a mismatched commit receipt.
pub async fn send_via_relay(
    address: SocketAddr,
    capability: &Capability,
    source: impl AsRef<Path>,
) -> Result<SendSummary, TransferError> {
    let reservation = reserve_sender_relay(address, *capability.lookup_id()).await?;
    send_reserved_via_relay(reservation, capability, source).await
}

async fn send_reserved_via_relay(
    reservation: SenderReservation,
    capability: &Capability,
    source: impl AsRef<Path>,
) -> Result<SendSummary, TransferError> {
    let relay = reservation.wait_matched().await?;
    let prologue = fallback_prologue(capability).encode();
    let mut secure = SecureStream::establish(
        relay,
        HandshakeRole::Initiator,
        capability.secret(),
        &prologue,
    )
    .await?;
    send_file(&mut secure, source, HardLimits::CONSERVATIVE)
        .await
        .map_err(TransferError::from)
}

/// Receive, verify, and atomically commit one file through the correctness
/// path.
///
/// # Errors
///
/// Returns for relay admission, Noise authentication, protocol violation,
/// staging, verification, or commit failure.
pub async fn receive_via_relay(
    address: SocketAddr,
    capability: &Capability,
    destination: impl AsRef<Path>,
) -> Result<ReceiveSummary, TransferError> {
    let relay = connect_relay(address, capability, RendezvousRole::Receiver).await?;
    let prologue = fallback_prologue(capability).encode();
    let mut secure = SecureStream::establish(
        relay,
        HandshakeRole::Responder,
        capability.secret(),
        &prologue,
    )
    .await?;
    receive_file(&mut secure, destination, HardLimits::CONSERVATIVE)
        .await
        .map_err(TransferError::from)
}

fn fallback_prologue(capability: &Capability) -> HandshakePrologue {
    prologue_for_lookup(*capability.lookup_id())
}

pub(crate) fn prologue_for_lookup(lookup_id: [u8; 16]) -> HandshakePrologue {
    HandshakePrologue {
        lookup_id,
        initiator_role: Role::Sender,
        limits: HardLimits::CONSERVATIVE,
        algorithms: SelectedAlgorithms {
            aead: 0,
            coding: 0,
            compression: 0,
            representation: 0,
        },
        initial_path_id: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use asupersync::{
        cx::Cx,
        io::{AsyncRead, AsyncWrite, ReadBuf},
        net::{TcpListener, UdpSocket},
    };
    use rift_protocol::STREAM_BLOCK_BYTES;
    use rift_relay::{RelayPolicy, serve_direct_rendezvous, serve_one};

    use super::*;
    use crate::stream_crypto::STREAM_TAG_BYTES;
    use crate::{NoiseHandshake, ReceiptDelivery, RuntimePolicy, build_runtime};

    #[test]
    fn local_relay_path_is_byte_exact_and_commit_truthful() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        let contents: Vec<u8> = (0_u32..200_000).flat_map(u32::to_le_bytes).collect();
        std::fs::write(&source, &contents).unwrap();

        let runtime = build_runtime(RuntimePolicy { worker_threads: 3 }).unwrap();
        let handle = runtime.handle();
        let (sent, received, relayed) = runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let capability =
                Capability::from_parts(format!("rift+tcp://{address}"), [3; 16], [9; 32]).unwrap();

            let relay = handle
                .clone()
                .spawn(async move { serve_one(listener, RelayPolicy::default()).await.unwrap() });
            let reservation = reserve_sender_relay(address, *capability.lookup_id())
                .await
                .unwrap();
            let sender_capability = capability.clone();
            let sender = handle.clone().spawn(async move {
                send_reserved_via_relay(reservation, &sender_capability, source)
                    .await
                    .unwrap()
            });
            let received = receive_via_relay(address, &capability, destination)
                .await
                .unwrap();
            (sender.await, received, relay.await)
        });

        assert_eq!(sent.digest, received.digest);
        assert_eq!(sent.length, received.length);
        assert_eq!(sent.transport, crate::TransferTransport::Relay);
        assert_eq!(received.transport, crate::TransferTransport::Relay);
        assert_eq!(received.receipt, ReceiptDelivery::Sent);
        assert!(relayed.sender_to_receiver > sent.length);
        assert!(relayed.receiver_to_sender > 0);
        assert_eq!(
            std::fs::read(directory.path().join("destination.bin")).unwrap(),
            contents
        );
    }

    #[test]
    fn mismatched_transfer_secret_fails_before_destination_visibility() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        std::fs::write(&source, b"must never become visible").unwrap();

        let runtime = build_runtime(RuntimePolicy { worker_threads: 3 }).unwrap();
        let handle = runtime.handle();
        let (sender_failed, receiver_failed) = runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let sender_capability =
                Capability::from_parts(format!("rift+tcp://{address}"), [4; 16], [1; 32]).unwrap();
            let receiver_capability =
                Capability::from_parts(format!("rift+tcp://{address}"), [4; 16], [2; 32]).unwrap();

            let relay = handle.clone().spawn(async move {
                let _ = serve_one(listener, RelayPolicy::default()).await;
            });
            let reservation = reserve_sender_relay(address, *sender_capability.lookup_id())
                .await
                .unwrap();
            let sender = handle.clone().spawn(async move {
                send_reserved_via_relay(reservation, &sender_capability, source)
                    .await
                    .is_err()
            });
            let receiver_failed = receive_via_relay(address, &receiver_capability, destination)
                .await
                .is_err();
            let sender_failed = sender.await;
            let () = relay.await;
            (sender_failed, receiver_failed)
        });

        assert!(sender_failed);
        assert!(receiver_failed);
        assert!(!directory.path().join("destination.bin").exists());
    }

    #[test]
    fn compact_code_reserves_then_transfers_and_commits_exactly() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("pairing-source.bin");
        let destination = directory.path().join("pairing-destination.bin");
        let contents: Vec<u8> = (0_u32..120_000).flat_map(u32::to_le_bytes).collect();
        std::fs::write(&source, &contents).unwrap();

        let runtime = build_runtime(RuntimePolicy { worker_threads: 3 }).unwrap();
        let handle = runtime.handle();
        let (sent, received) = runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let relay = handle.clone().spawn(async move {
                let _ = serve_one(listener, RelayPolicy::default()).await;
            });
            let sender_code = "4827-lumeko".parse::<PairingCode>().unwrap();
            let reservation = reserve_pairing_sender(address, &sender_code).await.unwrap();
            let receive_task = handle.clone().spawn(async move {
                let code = "4827-lumeko".parse::<PairingCode>().unwrap();
                Box::pin(receive_via_pairing(address, &code, destination))
                    .await
                    .unwrap()
            });
            let sent = Box::pin(send_reserved_via_pairing(reservation, &sender_code, source))
                .await
                .unwrap();
            let received = receive_task.await;
            let () = relay.await;
            (sent, received)
        });

        assert_eq!(sent.digest, received.digest);
        assert_eq!(sent.length, received.length);
        assert_eq!(received.receipt, ReceiptDelivery::Sent);
        assert_eq!(
            std::fs::read(directory.path().join("pairing-destination.bin")).unwrap(),
            contents
        );
    }

    #[test]
    fn compact_code_promotes_the_verified_direct_socket_to_saturated_quic() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("quic-source.bin");
        let destination = directory.path().join("quic-destination.bin");
        let contents = vec![0xA7; 8 * 1024 * 1024];
        std::fs::write(&source, &contents).unwrap();

        let runtime = build_runtime(RuntimePolicy { worker_threads: 4 }).unwrap();
        let handle = runtime.handle();
        let (sent, received, relayed) = runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let udp = UdpSocket::bind(address).await.unwrap();
            let policy = RelayPolicy::default();
            let relay = handle
                .clone()
                .spawn(async move { serve_one(listener, policy).await.unwrap() });
            let cx = Cx::current().unwrap();
            let mut rendezvous = cx
                .spawn(
                    move |_rendezvous_cx| async move { serve_direct_rendezvous(udp, policy).await },
                )
                .unwrap();
            let sender_code = "4827-lumeko".parse::<PairingCode>().unwrap();
            let reservation = reserve_pairing_sender(address, &sender_code).await.unwrap();
            let receive_task = handle.clone().spawn(async move {
                let code = "4827-lumeko".parse::<PairingCode>().unwrap();
                Box::pin(receive_via_pairing(address, &code, destination))
                    .await
                    .unwrap()
            });
            let sent = Box::pin(send_reserved_via_pairing(reservation, &sender_code, source))
                .await
                .unwrap();
            let received = receive_task.await;
            let relayed = relay.await;
            rendezvous.abort();
            let _ = rendezvous.join(&cx).await;
            (sent, received, relayed)
        });

        assert_eq!(sent.digest, received.digest);
        assert_eq!(sent.transport, crate::TransferTransport::DirectQuic);
        assert_eq!(received.transport, crate::TransferTransport::DirectQuic);
        assert_eq!(received.receipt, ReceiptDelivery::Sent);
        assert!(
            relayed.sender_to_receiver + relayed.receiver_to_sender < sent.length / 10,
            "payload unexpectedly remained on the relay: {relayed:?}"
        );
        assert_eq!(
            std::fs::read(directory.path().join("quic-destination.bin")).unwrap(),
            contents
        );
    }

    #[test]
    fn wrong_pairing_word_fails_before_destination_visibility() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("wrong-word-source.bin");
        let destination = directory.path().join("wrong-word-destination.bin");
        std::fs::write(&source, b"must remain invisible").unwrap();

        let runtime = build_runtime(RuntimePolicy { worker_threads: 3 }).unwrap();
        let handle = runtime.handle();
        let (sender_failed, receiver_failed) = runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let relay = handle.clone().spawn(async move {
                let _ = serve_one(listener, RelayPolicy::default()).await;
            });
            let sender_code = "4827-lumeko".parse::<PairingCode>().unwrap();
            let reservation = reserve_pairing_sender(address, &sender_code).await.unwrap();
            let receiver = handle.clone().spawn(async move {
                let code = "4827-lameko".parse::<PairingCode>().unwrap();
                Box::pin(receive_via_pairing(address, &code, destination))
                    .await
                    .is_err()
            });
            let sender_failed =
                Box::pin(send_reserved_via_pairing(reservation, &sender_code, source))
                    .await
                    .is_err();
            let receiver_failed = receiver.await;
            let () = relay.await;
            (sender_failed, receiver_failed)
        });

        assert!(sender_failed);
        assert!(receiver_failed);
        assert!(!directory.path().join("wrong-word-destination.bin").exists());
    }

    #[test]
    fn path_failure_before_commit_never_leaks_partial_destination() {
        let source_bytes = 2 * usize::try_from(STREAM_BLOCK_BYTES).unwrap() + 17;
        for cutoff in precommit_cutoffs(source_bytes) {
            assert_cutoff_is_atomic(cutoff, source_bytes);
        }
    }

    fn precommit_cutoffs(source_bytes: usize) -> Vec<usize> {
        let capability =
            Capability::from_parts("rift+tcp://127.0.0.1:1", [6; 16], [7; 32]).unwrap();
        let prologue = fallback_prologue(&capability).encode();
        let mut handshake =
            NoiseHandshake::new(HandshakeRole::Initiator, capability.secret(), &prologue).unwrap();
        let mut message = [0_u8; 256];
        let mut offset = 2 + handshake.write_message(&[], &mut message).unwrap();
        let mut cutoffs = vec![0, 1, offset.saturating_sub(1), offset];
        let mut add_precommit_record = |plaintext_bytes: usize| {
            offset += 4 + plaintext_bytes + STREAM_TAG_BYTES;
            cutoffs.push(offset.saturating_sub(1));
            cutoffs.push(offset);
        };

        add_precommit_record(29); // FileStart
        let block_bytes = usize::try_from(STREAM_BLOCK_BYTES).unwrap();
        let mut remaining = source_bytes;
        while remaining > 0 {
            let bytes = remaining.min(block_bytes);
            add_precommit_record(21 + bytes); // BlockData
            add_precommit_record(41); // BlockSeal
            remaining -= bytes;
        }
        offset += 4 + 33 + STREAM_TAG_BYTES; // ObjectSeal commits when complete.
        cutoffs.push(offset - 1);
        cutoffs.sort_unstable();
        cutoffs.dedup();
        cutoffs
    }

    fn assert_cutoff_is_atomic(cutoff: usize, source_bytes: usize) {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("destination.bin");
        let contents = vec![0x5A; source_bytes];
        std::fs::write(&source, contents).unwrap();

        let runtime = build_runtime(RuntimePolicy { worker_threads: 3 }).unwrap();
        let handle = runtime.handle();
        let (sender_failed, receiver_failed) = runtime.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let capability =
                Capability::from_parts(format!("rift+tcp://{address}"), [6; 16], [7; 32]).unwrap();
            let relay = handle.clone().spawn(async move {
                let _ = serve_one(listener, RelayPolicy::default()).await;
            });
            let reservation = reserve_sender_relay(address, *capability.lookup_id())
                .await
                .unwrap();
            let sender_capability = capability.clone();
            let sender = handle.clone().spawn(async move {
                send_reserved_via_relay(reservation, &sender_capability, source)
                    .await
                    .is_err()
            });
            let tcp = connect_relay(address, &capability, RendezvousRole::Receiver)
                .await
                .unwrap();
            let cutoff_path = ReadCutoff::new(tcp, cutoff);
            let prologue = fallback_prologue(&capability).encode();
            let result = async {
                let mut secure = SecureStream::establish(
                    cutoff_path,
                    HandshakeRole::Responder,
                    capability.secret(),
                    &prologue,
                )
                .await?;
                receive_file(&mut secure, destination, HardLimits::CONSERVATIVE)
                    .await
                    .map_err(TransferError::from)
            }
            .await;
            let receiver_failed = result.is_err();
            let sender_failed = sender.await;
            let () = relay.await;
            (sender_failed, receiver_failed)
        });

        assert!(
            sender_failed,
            "sender unexpectedly succeeded at cutoff {cutoff}"
        );
        assert!(
            receiver_failed,
            "receiver unexpectedly succeeded at cutoff {cutoff}"
        );
        assert!(
            !directory.path().join("destination.bin").exists(),
            "partial destination became visible at cutoff {cutoff}"
        );
    }

    struct ReadCutoff<S> {
        inner: S,
        remaining: usize,
    }

    impl<S> ReadCutoff<S> {
        fn new(inner: S, remaining: usize) -> Self {
            Self { inner, remaining }
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for ReadCutoff<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.remaining == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "injected read cutoff",
                )));
            }
            let capacity = output.remaining().min(this.remaining);
            let mut storage = vec![0_u8; capacity];
            let mut limited = ReadBuf::new(&mut storage);
            match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
                Poll::Ready(Ok(())) => {
                    let bytes = limited.filled();
                    output.put_slice(bytes);
                    this.remaining -= bytes.len();
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for ReadCutoff<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }
}
