#![forbid(unsafe_code)]

//! RIFT's effects boundary on the asupersync structured runtime.

use asupersync::{
    error::Error as AsupersyncError,
    runtime::{Runtime, RuntimeBuilder},
};
use thiserror::Error;

pub mod candidate;
pub mod direct;
pub mod direct_record;
pub mod file_oracle;
pub mod migration;
pub mod pairing;
mod path_pool;
mod piece_oracle;
mod piece_path;
pub mod quic_link;
mod quic_path;
pub mod relay_client;
pub mod secure_stream;
pub mod staging;
pub mod stream_crypto;
pub mod transfer;

pub use candidate::{
    CandidateError, ServerReflexiveCandidate, StunPolicy, discover_server_reflexive,
};
pub use direct::{
    DirectAcquirePolicy, DirectAcquisitionStage, DirectPath, DirectPathError, acquire_direct_path,
    acquire_direct_path_bound,
};
pub use direct_record::{
    DirectRecordError, DirectRecordPolicy, DirectRecordReceiver, DirectRecordSender,
    DirectSendStats,
};
pub use file_oracle::{
    FileOracleError, ReceiptDelivery, ReceiveSummary, ReceiveTarget, SendSummary, TransferObserver,
    TransferProfile, TransferProgress, receive_file, receive_object, receive_object_quic,
    send_file, send_object, send_object_quic,
};
pub use migration::{
    DirectAcquisitionStatus, DirectFailureStatus, MigrationPolicy, MigrationReport,
    TransferTransport,
};
pub use pairing::{PairingError, establish_pairing_secret};
pub use quic_link::{DirectQuicLink, DirectQuicLinkError, TurnStreamAllocation, TurnUdpAllocation};
pub use quic_path::QuicPathSelectionError;
pub use relay_client::{
    RelayClientError, RelayDialer, RelayEndpoint, RelayStream, SenderReservation, connect_relay,
    connect_relay_lookup, connect_relay_lookup_endpoint, connect_relay_lookup_with,
    reserve_sender_endpoint, reserve_sender_relay, reserve_sender_with,
};
pub use secure_stream::{SecureStream, SecureStreamError};
pub use staging::{
    CleanupStatus, CommitError, CommitReceipt, StageError, StagingFile, StagingTree,
    StagingTreeFile, VerifiedStaging, VerifiedStagingTree,
};
pub use stream_crypto::{CryptoError, DatagramCipher, HandshakeRole, NoiseHandshake, StreamCipher};
pub use transfer::{
    TransferError, TransferPolicy, receive_via_pairing, receive_via_pairing_endpoint,
    receive_via_pairing_target_observed_with_policy, receive_via_pairing_target_with_policy,
    receive_via_pairing_with, receive_via_pairing_with_policy, receive_via_relay,
    reserve_fresh_pairing_sender, reserve_fresh_pairing_sender_endpoint,
    reserve_fresh_pairing_sender_with, reserve_pairing_sender, reserve_pairing_sender_endpoint,
    send_reserved_via_pairing, send_reserved_via_pairing_observed_with_policy,
    send_reserved_via_pairing_with_policy, send_via_relay,
};

/// Runtime construction policy owned by RIFT rather than ambient globals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimePolicy {
    /// Scheduler worker count. One is useful for deterministic smoke tests.
    pub worker_threads: usize,
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self { worker_threads: 2 }
    }
}

/// Runtime bootstrap failure.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// At least one scheduler worker is required.
    #[error("RIFT runtime requires at least one worker")]
    NoWorkers,
    /// asupersync could not initialize a required host service.
    #[error("asupersync runtime initialization failed: {0}")]
    Build(#[source] Box<AsupersyncError>),
}

impl From<AsupersyncError> for RuntimeError {
    fn from(error: AsupersyncError) -> Self {
        Self::Build(Box::new(error))
    }
}

/// Construct the sole process runtime. Transfer code receives its effects from
/// regions rooted in this runtime; it must not create hidden runtimes.
///
/// # Errors
///
/// Returns [`RuntimeError::NoWorkers`] for a zero-worker policy or
/// [`RuntimeError::Build`] when asupersync host-service initialization fails.
pub fn build_runtime(policy: RuntimePolicy) -> Result<Runtime, RuntimeError> {
    if policy.worker_threads == 0 {
        return Err(RuntimeError::NoWorkers);
    }
    RuntimeBuilder::multi_thread()
        .worker_threads(policy.worker_threads)
        .build()
        .map_err(RuntimeError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_workers_before_touching_host_services() {
        assert!(matches!(
            build_runtime(RuntimePolicy { worker_threads: 0 }),
            Err(RuntimeError::NoWorkers)
        ));
    }

    #[test]
    fn current_host_can_build_the_runtime_boundary() {
        let runtime = build_runtime(RuntimePolicy { worker_threads: 1 }).unwrap();
        assert_eq!(runtime.block_on(async { 21 * 2 }), 42);
    }
}
