//! Bounded policy and non-secret evidence for authenticated path selection.

use std::time::Duration;

/// Authenticated carrier that moved the committed object payload.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransferTransport {
    /// The always-available encrypted WebSocket relay carried the payload.
    #[default]
    Relay,
    /// A private-address peer path on the same local network carried QUIC.
    LanQuic,
    /// A mutually authenticated direct UDP path carried pinned QUIC.
    DirectQuic,
    /// Cloud or self-hosted TURN over UDP carried pinned QUIC.
    TurnUdpQuic,
    /// TURN over TCP carried pinned QUIC.
    TurnTcpQuic,
    /// TURN over TLS carried pinned QUIC.
    TurnTlsQuic,
    /// Multiple independently congestion-controlled pinned QUIC paths carried
    /// authenticated pieces under the completion-time controller.
    PathPoolQuic,
}

/// Bounded terminal state of direct-path acquisition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DirectAcquisitionStatus {
    /// No acquisition task could be started in the current runtime context.
    #[default]
    NotStarted,
    /// Selection completed before the acquisition task did.
    Incomplete,
    /// A session-authenticated path completed validation.
    Validated,
    /// Candidate resolution or socket I/O failed.
    IoFailed,
    /// Candidate authentication or protocol validation failed.
    AuthenticationFailed,
    /// The bounded acquisition deadline expired without a validated path.
    TimedOut,
    /// The task ended unexpectedly or exhausted its noise budget.
    Failed,
}

/// Last accelerated-path failure that required relay fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectFailureStatus {
    /// Congestion or handshake retry budget expired without progress.
    Timeout,
    /// Socket operation failed.
    Io,
    /// Authenticated framing or state was inconsistent.
    Protocol,
    /// Cryptographic state rejected the path.
    Authentication,
    /// Unrelated traffic exhausted the receive budget.
    UnrelatedDatagramLimit,
    /// Local selection policy was invalid.
    InvalidPolicy,
}

/// Stable, non-secret evidence about one path decision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MigrationReport {
    /// Terminal state of direct candidate acquisition.
    pub direct_acquisition: DirectAcquisitionStatus,
    /// Object records carried by the relay.
    pub relay_records: u64,
    /// Object records carried by a direct path.
    pub direct_records: u64,
    /// Accelerated-path failures recovered through the relay.
    pub fallback_events: u64,
    /// Observed relay useful throughput.
    pub relay_goodput_bps: Option<u64>,
    /// Conservative direct useful-throughput floor.
    pub direct_goodput_floor_bps: Option<u64>,
    /// Direct validation round-trip time.
    pub direct_validation_rtt_us: Option<u64>,
    /// Largest validated direct datagram.
    pub direct_max_datagram_bytes: Option<u16>,
    /// Smoothed direct round-trip time.
    pub direct_smoothed_rtt_us: Option<u64>,
    /// Current direct retransmission timeout.
    pub direct_rto_us: Option<u64>,
    /// First object record carried directly.
    pub first_direct_sequence: Option<u64>,
    /// Direct encrypted datagrams emitted.
    pub direct_datagrams: u64,
    /// Direct fragments transmitted more than once.
    pub direct_retransmitted_fragments: u64,
    /// Fragments retransmitted from selective loss evidence.
    pub direct_fast_retransmits: u64,
    /// Bounded tail probes emitted.
    pub direct_tail_probes: u64,
    /// Forward-error-correction symbols emitted.
    pub direct_repair_symbols: u64,
    /// Direct batches submitted.
    pub direct_send_batches: u64,
    /// Batches completed by native multi-message send.
    pub direct_native_send_batches: u64,
    /// Batches completed with generic segmentation offload.
    pub direct_gso_batches: u64,
    /// GSO modes disabled after loss evidence.
    pub direct_gso_demotions: u64,
    /// Timeout-driven congestion responses.
    pub direct_timeouts: u64,
    /// Last accelerated-path failure class.
    pub last_direct_failure: Option<DirectFailureStatus>,
}

/// Time envelope for direct/TURN gathering and pinned QUIC consensus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationPolicy {
    /// Maximum wall time spent gathering direct and TURN candidates.
    pub gather_budget: Duration,
    /// Grace after the first usable carrier appears for a preferable peer.
    pub ready_grace: Duration,
    /// TURN allocation, permission, and channel setup deadline.
    pub turn_setup_timeout: Duration,
    /// Pinned QUIC handshake deadline on the selected carrier.
    pub quic_handshake_timeout: Duration,
}

impl Default for MigrationPolicy {
    fn default() -> Self {
        Self {
            gather_budget: Duration::from_millis(1_500),
            ready_grace: Duration::from_millis(250),
            turn_setup_timeout: Duration::from_secs(3),
            quic_handshake_timeout: Duration::from_secs(3),
        }
    }
}

impl MigrationPolicy {
    pub(crate) fn validate(self) -> bool {
        !self.gather_budget.is_zero()
            && self.gather_budget <= Duration::from_secs(10)
            && self.ready_grace <= self.gather_budget
            && !self.turn_setup_timeout.is_zero()
            && self.turn_setup_timeout <= Duration::from_secs(15)
            && !self.quic_handshake_timeout.is_zero()
            && self.quic_handshake_timeout <= Duration::from_secs(15)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_selection_envelope_is_bounded() {
        assert!(MigrationPolicy::default().validate());
    }

    #[test]
    fn zero_or_excessive_deadlines_fail_closed() {
        let mut policy = MigrationPolicy {
            gather_budget: Duration::ZERO,
            ..MigrationPolicy::default()
        };
        assert!(!policy.validate());
        policy = MigrationPolicy::default();
        policy.quic_handshake_timeout = Duration::from_secs(16);
        assert!(!policy.validate());
    }
}
