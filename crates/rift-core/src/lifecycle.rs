//! Pure lifecycle machines for transfers and replaceable paths.

use thiserror::Error;

/// Monotonic transfer lifecycle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransferPhase {
    /// Local transfer owner exists but has admitted no child effects.
    #[default]
    Created,
    /// Rendezvous and path candidates are being acquired.
    Matching,
    /// A candidate peer is proving capability possession.
    Authenticating,
    /// Authenticated peers are intersecting limits and algorithms.
    Negotiating,
    /// Object declarations and information are in flight.
    Transferring,
    /// All graph nodes are present and final integrity is being checked.
    Verifying,
    /// Verified staging state is crossing the atomic visibility boundary.
    Committing,
    /// Destination is visible; sender completion awaits authenticated receipt.
    AwaitingReceipt,
    /// Receiver commit receipt has been authenticated.
    Complete,
    /// New work is closed and owned effects are draining.
    Cancelling,
    /// Cancellation cleanup is complete.
    Cancelled,
    /// Failure cleanup is in progress.
    Failing,
    /// Failure cleanup is complete.
    Failed,
}

/// Event admitted by the transfer owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferEvent {
    /// Start candidate acquisition.
    Begin,
    /// A peer candidate has been selected.
    PeerMatched,
    /// Capability-authenticated handshake completed.
    Authenticated,
    /// Hard limits and algorithms were successfully intersected.
    Negotiated,
    /// All required graph nodes became reconstructable.
    ObjectSatisfied,
    /// Block and final object seals verified.
    ObjectVerified,
    /// Atomic destination commit completed.
    DestinationCommitted,
    /// Authenticated receiver receipt arrived.
    ReceiptAuthenticated,
    /// User, peer, deadline, or parent requested cancellation.
    Cancel,
    /// All cancellation obligations drained.
    CancellationDrained,
    /// A non-cancellation terminal error occurred.
    Fail,
    /// All failure obligations drained.
    FailureDrained,
}

/// Transfer state machine with one narrow mutation point.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransferLifecycle {
    phase: TransferPhase,
}

/// Illegal lifecycle event.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("event {event:?} is invalid while transfer is {phase:?}")]
pub struct LifecycleError {
    /// Current state.
    pub phase: TransferPhase,
    /// Rejected event.
    pub event: TransferEvent,
}

impl TransferLifecycle {
    /// Create a transfer before child work is admitted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current phase.
    #[must_use]
    pub fn phase(self) -> TransferPhase {
        self.phase
    }

    /// Whether no future event can resume useful transfer work.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self.phase,
            TransferPhase::Complete | TransferPhase::Cancelled | TransferPhase::Failed
        )
    }

    /// Apply one owner event or leave state unchanged on failure.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] when the event would skip or rewind a phase.
    pub fn apply(&mut self, event: TransferEvent) -> Result<TransferPhase, LifecycleError> {
        use TransferEvent as E;
        use TransferPhase as P;

        let next = match (self.phase, event) {
            (P::Created, E::Begin) => P::Matching,
            (P::Matching, E::PeerMatched) => P::Authenticating,
            (P::Authenticating, E::Authenticated) => P::Negotiating,
            (P::Negotiating, E::Negotiated) => P::Transferring,
            (P::Transferring, E::ObjectSatisfied) => P::Verifying,
            (P::Verifying, E::ObjectVerified) => P::Committing,
            (P::Committing, E::DestinationCommitted) => P::AwaitingReceipt,
            (P::AwaitingReceipt, E::ReceiptAuthenticated) => P::Complete,
            (
                P::Created
                | P::Matching
                | P::Authenticating
                | P::Negotiating
                | P::Transferring
                | P::Verifying
                | P::Committing,
                E::Cancel,
            ) => P::Cancelling,
            (P::Cancelling, E::CancellationDrained) => P::Cancelled,
            (
                P::Created
                | P::Matching
                | P::Authenticating
                | P::Negotiating
                | P::Transferring
                | P::Verifying
                | P::Committing
                | P::AwaitingReceipt
                | P::Cancelling,
                E::Fail,
            ) => P::Failing,
            (P::Failing, E::FailureDrained) => P::Failed,
            _ => {
                return Err(LifecycleError {
                    phase: self.phase,
                    event,
                });
            }
        };
        self.phase = next;
        Ok(next)
    }
}

/// Lifecycle of one independently replaceable network path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PathPhase {
    /// Unvalidated address or relay route.
    #[default]
    Candidate,
    /// Authenticated challenge is in flight.
    Probing,
    /// Address ownership and session binding have been proven.
    Validated,
    /// Path may carry object or control information.
    Active,
    /// New packets are blocked while in-flight obligations drain.
    Draining,
    /// All resources for this path are released.
    Closed,
}

/// Pure path event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathEvent {
    /// Begin authenticated validation.
    Probe,
    /// Correct response arrived.
    Validated,
    /// Controller admitted this path for traffic.
    Activate,
    /// Stop admitting new traffic.
    Drain,
    /// All path obligations drained.
    Close,
}

/// Single-path lifecycle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PathLifecycle {
    phase: PathPhase,
}

/// Illegal path lifecycle event.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("event {event:?} is invalid while path is {phase:?}")]
pub struct PathLifecycleError {
    /// Current state.
    pub phase: PathPhase,
    /// Rejected event.
    pub event: PathEvent,
}

impl PathLifecycle {
    /// Current phase.
    #[must_use]
    pub fn phase(self) -> PathPhase {
        self.phase
    }

    /// Apply one path-owner event.
    ///
    /// # Errors
    ///
    /// Returns [`PathLifecycleError`] when the event would skip or rewind a phase.
    pub fn apply(&mut self, event: PathEvent) -> Result<PathPhase, PathLifecycleError> {
        let next = match (self.phase, event) {
            (PathPhase::Candidate, PathEvent::Probe) => PathPhase::Probing,
            (PathPhase::Probing, PathEvent::Validated) => PathPhase::Validated,
            (PathPhase::Validated, PathEvent::Activate) => PathPhase::Active,
            (
                PathPhase::Candidate
                | PathPhase::Probing
                | PathPhase::Validated
                | PathPhase::Active,
                PathEvent::Drain,
            ) => PathPhase::Draining,
            (PathPhase::Draining, PathEvent::Close) => PathPhase::Closed,
            _ => {
                return Err(PathLifecycleError {
                    phase: self.phase,
                    event,
                });
            }
        };
        self.phase = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_cannot_skip_verification_or_receipt() {
        let mut lifecycle = TransferLifecycle::new();
        for event in [
            TransferEvent::Begin,
            TransferEvent::PeerMatched,
            TransferEvent::Authenticated,
            TransferEvent::Negotiated,
            TransferEvent::ObjectSatisfied,
            TransferEvent::ObjectVerified,
        ] {
            lifecycle.apply(event).unwrap();
        }
        assert_eq!(lifecycle.phase(), TransferPhase::Committing);
        assert!(
            lifecycle
                .apply(TransferEvent::ReceiptAuthenticated)
                .is_err()
        );
        lifecycle
            .apply(TransferEvent::DestinationCommitted)
            .unwrap();
        assert!(lifecycle.apply(TransferEvent::ReceiptAuthenticated).is_ok());
        assert!(lifecycle.is_terminal());
    }

    #[test]
    fn cancellation_is_a_drain_not_a_terminal_jump() {
        let mut lifecycle = TransferLifecycle::new();
        lifecycle.apply(TransferEvent::Begin).unwrap();
        lifecycle.apply(TransferEvent::Cancel).unwrap();
        assert_eq!(lifecycle.phase(), TransferPhase::Cancelling);
        assert!(!lifecycle.is_terminal());
        lifecycle.apply(TransferEvent::CancellationDrained).unwrap();
        assert_eq!(lifecycle.phase(), TransferPhase::Cancelled);
    }

    #[test]
    fn active_path_must_drain_before_close() {
        let mut path = PathLifecycle::default();
        path.apply(PathEvent::Probe).unwrap();
        path.apply(PathEvent::Validated).unwrap();
        path.apply(PathEvent::Activate).unwrap();
        assert!(path.apply(PathEvent::Close).is_err());
        path.apply(PathEvent::Drain).unwrap();
        path.apply(PathEvent::Close).unwrap();
        assert_eq!(path.phase(), PathPhase::Closed);
    }
}
