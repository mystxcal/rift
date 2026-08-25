#![forbid(unsafe_code)]

//! Policy types for the blind, live-only RIFT relay.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod cloudflare_turn;
pub mod datagram;
pub mod forward;
pub mod matching;
pub mod server;

pub use cloudflare_turn::{
    CloudflareTurnConfig, CloudflareTurnError, CloudflareTurnServer, RelayRouteIssuer,
    ShortLivedTurnCredentials,
};
pub use datagram::{DirectRendezvousError, serve_direct_rendezvous};
pub use forward::{ForwardError, ForwardStats, forward_bidirectional};
pub use matching::{JoinError, JoinOutcome, MatchTable, PeerRole};
pub use server::{
    RelayServerError, serve, serve_one, serve_one_wss, serve_one_wss_with_routes, serve_wss,
    serve_wss_with_routes,
};

/// Hard resource envelope for a relay process.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayPolicy {
    /// Maximum simultaneously matched transfers.
    pub max_sessions: u32,
    /// Maximum unmatched lookup identifiers retained in memory.
    pub max_pending_lookups: u32,
    /// Maximum ciphertext retained per session for hop-local repair.
    pub max_ciphertext_window_bytes: u64,
    /// Maximum time a peer may occupy an unmatched lookup.
    pub match_timeout_ms: u64,
    /// Maximum time allowed to provide the fixed-width join prelude.
    pub prelude_timeout_ms: u64,
    /// Concurrent slow-prelude isolation slots. Remaining sockets stay in the
    /// kernel accept backlog rather than blocking the matcher.
    pub prelude_workers: u16,
    /// Idle sessions are removed after this duration in milliseconds.
    pub idle_timeout_ms: u64,
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            max_sessions: 1_024,
            max_pending_lookups: 10_000,
            max_ciphertext_window_bytes: 8 * 1024 * 1024,
            match_timeout_ms: 60_000,
            prelude_timeout_ms: 5_000,
            prelude_workers: 4,
            idle_timeout_ms: 30_000,
        }
    }
}

impl RelayPolicy {
    /// Validate that the relay cannot become an accidental deferred store.
    ///
    /// # Errors
    ///
    /// Returns [`RelayPolicyError::UnboundedOrPersistent`] when a zero or
    /// store-like resource envelope is requested.
    pub fn validate(self) -> Result<Self, RelayPolicyError> {
        if self.max_sessions == 0
            || self.max_pending_lookups == 0
            || self.max_ciphertext_window_bytes == 0
            || self.max_ciphertext_window_bytes > 64 * 1024 * 1024
            || self.match_timeout_ms == 0
            || self.match_timeout_ms > 300_000
            || self.prelude_timeout_ms == 0
            || self.prelude_timeout_ms > 30_000
            || self.prelude_workers == 0
            || self.prelude_workers > 64
            || self.idle_timeout_ms == 0
            || self.idle_timeout_ms > 300_000
        {
            return Err(RelayPolicyError::UnboundedOrPersistent);
        }
        Ok(self)
    }
}

/// Relay policy violates the live-only product boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RelayPolicyError {
    /// Policy permits unbounded memory or store-like persistence.
    #[error("relay policy must remain bounded and live-only")]
    UnboundedOrPersistent,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_live_only_and_bounded() {
        assert!(RelayPolicy::default().validate().is_ok());
    }

    #[test]
    fn five_minute_boundary_is_strict() {
        let policy = RelayPolicy {
            idle_timeout_ms: 300_001,
            ..RelayPolicy::default()
        };
        assert_eq!(
            policy.validate(),
            Err(RelayPolicyError::UnboundedOrPersistent)
        );
    }
}
