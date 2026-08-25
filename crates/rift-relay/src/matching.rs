//! Deterministic one-shot sender/receiver rendezvous ownership.

use std::collections::BTreeMap;

use thiserror::Error;

/// Endpoint role visible to the blind rendezvous.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRole {
    /// Object source.
    Sender,
    /// Object sink.
    Receiver,
}

/// Result of admitting one live endpoint.
#[derive(Debug)]
pub enum JoinOutcome<T> {
    /// Endpoint is owned by the table until its peer arrives or it expires.
    Waiting,
    /// Both roles were consumed exactly once and removed from the table.
    Matched {
        /// Sender endpoint.
        sender: T,
        /// Receiver endpoint.
        receiver: T,
    },
}

/// Admission failure that leaves existing ownership unchanged.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum JoinError {
    /// An endpoint already owns this lookup-role slot.
    #[error("rendezvous role is already occupied")]
    RoleOccupied,
    /// Bounded table has no room for a new lookup identifier.
    #[error("rendezvous capacity exhausted")]
    CapacityExhausted,
    /// Capacity must admit at least one lookup.
    #[error("rendezvous capacity must be nonzero")]
    InvalidCapacity,
    /// TTL must be nonzero.
    #[error("rendezvous time-to-live must be nonzero")]
    InvalidTtl,
    /// Defensive failure for an impossible internal ownership transition.
    #[error("rendezvous ownership invariant failed")]
    InvariantViolation,
}

#[derive(Debug)]
struct Pending<T> {
    sender: Option<T>,
    receiver: Option<T>,
    expires_at_ms: u64,
}

/// Bounded one-shot match table. Time is an explicit input for deterministic
/// tests and runtime-owned clocks.
#[derive(Debug)]
pub struct MatchTable<T> {
    pending: BTreeMap<[u8; 16], Pending<T>>,
    max_lookups: usize,
    ttl_ms: u64,
}

impl<T> MatchTable<T> {
    /// Construct a bounded live rendezvous table.
    ///
    /// # Errors
    ///
    /// Returns [`JoinError::InvalidTtl`] when `ttl_ms` is zero.
    pub fn new(max_lookups: usize, ttl_ms: u64) -> Result<Self, JoinError> {
        if max_lookups == 0 {
            return Err(JoinError::InvalidCapacity);
        }
        if ttl_ms == 0 {
            return Err(JoinError::InvalidTtl);
        }
        Ok(Self {
            pending: BTreeMap::new(),
            max_lookups,
            ttl_ms,
        })
    }

    /// Admit one endpoint or atomically consume a complete pair.
    ///
    /// `now_ms` comes from the runtime's monotonic clock. Expired entries are
    /// removed before capacity and role ownership are evaluated.
    ///
    /// # Errors
    ///
    /// Returns [`JoinError`] when the same role is already occupied or a new
    /// identifier would exceed the fixed capacity.
    pub fn join(
        &mut self,
        now_ms: u64,
        lookup: [u8; 16],
        role: PeerRole,
        endpoint: T,
    ) -> Result<JoinOutcome<T>, JoinError> {
        self.preflight(now_ms, lookup, role)?;
        let pending = self.pending.entry(lookup).or_insert_with(|| Pending {
            sender: None,
            receiver: None,
            expires_at_ms: now_ms.saturating_add(self.ttl_ms),
        });
        let slot = match role {
            PeerRole::Sender => &mut pending.sender,
            PeerRole::Receiver => &mut pending.receiver,
        };
        debug_assert!(slot.is_none());
        *slot = Some(endpoint);

        if pending.sender.is_some() && pending.receiver.is_some() {
            let mut matched = self
                .pending
                .remove(&lookup)
                .ok_or(JoinError::InvariantViolation)?;
            return Ok(JoinOutcome::Matched {
                sender: matched.sender.take().ok_or(JoinError::InvariantViolation)?,
                receiver: matched
                    .receiver
                    .take()
                    .ok_or(JoinError::InvariantViolation)?,
            });
        }
        Ok(JoinOutcome::Waiting)
    }

    /// Check admission without consuming the endpoint.
    ///
    /// The runtime uses this immediately before [`Self::join`] so a rejected
    /// socket remains available for an explicit status response. With one
    /// owner of the table there is no gap in which admission state can change.
    ///
    /// # Errors
    ///
    /// Returns the same resource or ownership failures as [`Self::join`].
    pub fn preflight(
        &mut self,
        now_ms: u64,
        lookup: [u8; 16],
        role: PeerRole,
    ) -> Result<(), JoinError> {
        self.expire(now_ms);
        if !self.pending.contains_key(&lookup) && self.pending.len() >= self.max_lookups {
            return Err(JoinError::CapacityExhausted);
        }
        if let Some(pending) = self.pending.get(&lookup) {
            let occupied = match role {
                PeerRole::Sender => pending.sender.is_some(),
                PeerRole::Receiver => pending.receiver.is_some(),
            };
            if occupied {
                return Err(JoinError::RoleOccupied);
            }
        }
        Ok(())
    }

    /// Report whether admitting this role would consume a complete pair.
    ///
    /// The same admission checks as [`Self::join`] run first, so callers can
    /// reserve an active-session slot without consuming either endpoint.
    ///
    /// # Errors
    ///
    /// Returns the same resource or ownership failures as [`Self::join`].
    pub fn would_match(
        &mut self,
        now_ms: u64,
        lookup: [u8; 16],
        role: PeerRole,
    ) -> Result<bool, JoinError> {
        self.preflight(now_ms, lookup, role)?;
        let Some(pending) = self.pending.get(&lookup) else {
            return Ok(false);
        };
        Ok(match role {
            PeerRole::Sender => pending.receiver.is_some(),
            PeerRole::Receiver => pending.sender.is_some(),
        })
    }

    /// Remove entries whose absolute monotonic deadline has elapsed.
    /// Returns the number of lookup identifiers released.
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let before = self.pending.len();
        self.pending
            .retain(|_, pending| pending.expires_at_ms > now_ms);
        before - self.pending.len()
    }

    /// Number of unmatched lookup identifiers currently owned.
    #[must_use]
    pub fn pending_lookups(&self) -> usize {
        self.pending.len()
    }

    /// Borrow a confirmed waiting endpoint for its post-admission response.
    pub(crate) fn waiting_endpoint_mut(
        &mut self,
        lookup: [u8; 16],
        role: PeerRole,
    ) -> Option<&mut T> {
        let pending = self.pending.get_mut(&lookup)?;
        match role {
            PeerRole::Sender => pending.sender.as_mut(),
            PeerRole::Receiver => pending.receiver.as_mut(),
        }
    }

    /// Release one waiting role when its reservation cannot be delivered.
    pub(crate) fn leave(&mut self, lookup: [u8; 16], role: PeerRole) -> Option<T> {
        let pending = self.pending.get_mut(&lookup)?;
        let endpoint = match role {
            PeerRole::Sender => pending.sender.take(),
            PeerRole::Receiver => pending.receiver.take(),
        };
        if pending.sender.is_none() && pending.receiver.is_none() {
            self.pending.remove(&lookup);
        }
        endpoint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_pair_is_consumed_once() {
        let mut table = MatchTable::new(2, 100).unwrap();
        assert!(matches!(
            table.join(0, [1; 16], PeerRole::Receiver, "receiver"),
            Ok(JoinOutcome::Waiting)
        ));
        let matched = table.join(1, [1; 16], PeerRole::Sender, "sender").unwrap();
        match matched {
            JoinOutcome::Matched { sender, receiver } => {
                assert_eq!(sender, "sender");
                assert_eq!(receiver, "receiver");
            }
            JoinOutcome::Waiting => panic!("pair should be complete"),
        }
        assert_eq!(table.pending_lookups(), 0);
    }

    #[test]
    fn duplicate_role_cannot_replace_live_owner() {
        let mut table = MatchTable::new(2, 100).unwrap();
        table.join(0, [1; 16], PeerRole::Sender, "first").unwrap();
        assert_eq!(
            table
                .join(1, [1; 16], PeerRole::Sender, "attacker")
                .unwrap_err(),
            JoinError::RoleOccupied
        );
    }

    #[test]
    fn preflight_rejects_without_consuming_the_candidate() {
        let mut table = MatchTable::new(2, 100).unwrap();
        table
            .join(0, [1; 16], PeerRole::Sender, "incumbent")
            .unwrap();
        assert_eq!(
            table.preflight(1, [1; 16], PeerRole::Sender),
            Err(JoinError::RoleOccupied)
        );
        let matched = table
            .join(2, [1; 16], PeerRole::Receiver, "receiver")
            .unwrap();
        assert!(matches!(matched, JoinOutcome::Matched { .. }));
    }

    #[test]
    fn complete_pair_can_be_reserved_without_consuming_it() {
        let mut table = MatchTable::new(2, 100).unwrap();
        table.join(0, [1; 16], PeerRole::Sender, "sender").unwrap();
        assert_eq!(table.would_match(1, [1; 16], PeerRole::Receiver), Ok(true));
        assert_eq!(table.pending_lookups(), 1);
        let matched = table
            .join(2, [1; 16], PeerRole::Receiver, "receiver")
            .unwrap();
        assert!(matches!(matched, JoinOutcome::Matched { .. }));
    }

    #[test]
    fn expiry_releases_endpoint_and_capacity() {
        let mut table = MatchTable::new(1, 100).unwrap();
        table.join(0, [1; 16], PeerRole::Sender, "stale").unwrap();
        assert_eq!(
            table
                .join(99, [2; 16], PeerRole::Sender, "blocked")
                .unwrap_err(),
            JoinError::CapacityExhausted
        );
        assert!(matches!(
            table.join(100, [2; 16], PeerRole::Sender, "fresh"),
            Ok(JoinOutcome::Waiting)
        ));
    }

    #[test]
    fn failed_reservation_delivery_releases_exact_role() {
        let mut table = MatchTable::new(1, 100).unwrap();
        table.join(0, [1; 16], PeerRole::Sender, "sender").unwrap();
        assert_eq!(
            table.waiting_endpoint_mut([1; 16], PeerRole::Sender),
            Some(&mut "sender")
        );
        assert_eq!(table.leave([1; 16], PeerRole::Sender), Some("sender"));
        assert_eq!(table.pending_lookups(), 0);
        assert!(matches!(
            table.join(1, [2; 16], PeerRole::Receiver, "receiver"),
            Ok(JoinOutcome::Waiting)
        ));
    }
}
