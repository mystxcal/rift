//! Deterministic receding-horizon decisions for object completion.
//!
//! This module does not choose a preferred transport.  It predicts when one
//! independently verifiable piece can become durable on each proved path and
//! acts only on the current completion-time critical path.

use thiserror::Error;

use crate::{BlockId, BlockPhase, PathId};

/// A piece that is ready, missing, or already owned by one path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PieceWork {
    /// Stable block identifier.
    pub block: BlockId,
    /// Logical payload bytes.
    pub bytes: u32,
    /// Earliest time source bytes and their commitment can be supplied.
    pub source_ready_us: u64,
    /// Canonical object-ledger phase.
    pub phase: BlockPhase,
    /// Existing unverified delivery, when the piece is in flight.
    pub flight: Option<Flight>,
}

/// Existing path-owned work for a piece.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Flight {
    /// Path carrying the attempt.
    pub path: PathId,
    /// Conservative predicted durable-arrival time.
    pub durable_at_us: u64,
}

/// Current measured capacity of one independently congestion-controlled path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionPath {
    /// Stable path identity.
    pub id: PathId,
    /// Paths with the same nonzero group are assumed to share a bottleneck.
    pub bottleneck_group: u32,
    /// Whether peer ownership and the authenticated carrier are proved.
    pub validated: bool,
    /// Earliest time the path may accept application work.
    pub ready_at_us: u64,
    /// End of work already admitted to the path queue.
    pub queue_free_at_us: u64,
    /// Conservative measured delivery rate, before uncertainty discount.
    pub delivery_rate_bps: u64,
    /// Relative uncertainty in basis points, strictly below 10,000.
    pub uncertainty_bps: u16,
    /// Fixed path latency and repair-risk allowance.
    pub latency_and_repair_us: u64,
    /// Current receiver verification/write backlog attributable to new work.
    pub receiver_backlog_us: u64,
    /// Hard bound on concurrently owned pieces.
    pub max_in_flight: u16,
    /// Pieces currently owned by this path.
    pub in_flight: u16,
}

/// One bounded controller decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionAction {
    /// Assign one missing piece to the predicted earliest path.
    Assign {
        /// Piece to assign.
        block: BlockId,
        /// Path that should own the attempt.
        path: PathId,
        /// Conservative predicted durable-arrival time.
        durable_at_us: u64,
    },
    /// Duplicate a genuine tail on an independently bottlenecked path.
    Duplicate {
        /// Tail piece to duplicate.
        block: BlockId,
        /// Independent path for the bounded duplicate.
        path: PathId,
        /// Earlier conservative durable-arrival time.
        durable_at_us: u64,
    },
    /// Deliberately wait for a path whose later start still finishes earlier.
    WaitUntil {
        /// First time at which evidence can change the decision.
        time_us: u64,
    },
    /// No network action can improve completion from the supplied state.
    Idle,
}

/// Invalid measured state supplied to the completion controller.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CompletionError {
    /// A piece had no bytes or contradicted its phase and flight ownership.
    #[error("invalid piece state for block {0:?}")]
    InvalidPiece(BlockId),
    /// One path exposed impossible capacity or queue state.
    #[error("invalid completion-path measurement for path {0:?}")]
    InvalidPath(PathId),
}

/// Choose the next action on the predicted completion-time critical path.
///
/// The controller uses only conservative integer estimates.  A future path is
/// allowed to beat an immediately available path, making an explicit wait a
/// first-class decision.  A duplicate is admitted only when it changes the
/// earliest predicted arrival and its bottleneck group differs from the
/// incumbent path.
///
/// # Errors
///
/// Returns [`CompletionError`] before policy when piece or path measurements
/// are internally inconsistent.
pub fn plan_completion(
    now_us: u64,
    pieces: &[PieceWork],
    paths: &[CompletionPath],
) -> Result<CompletionAction, CompletionError> {
    validate(pieces, paths)?;

    let mut critical_missing: Option<(PieceWork, CompletionPath, u64)> = None;
    let mut best_duplicate: Option<(PieceWork, CompletionPath, u64)> = None;
    let mut next_evidence = None;

    for piece in pieces {
        if matches!(piece.phase, BlockPhase::Verified | BlockPhase::Durable) {
            continue;
        }
        match piece.flight {
            None => {
                let Some((path, arrival)) = earliest_path(now_us, *piece, paths, PathFilter::Any)
                else {
                    continue;
                };
                if path.ready_at_us > now_us {
                    next_evidence = Some(
                        next_evidence
                            .map_or(path.ready_at_us, |time: u64| time.min(path.ready_at_us)),
                    );
                }
                let replace = critical_missing.is_none_or(|(current, _, current_arrival)| {
                    arrival > current_arrival
                        || (arrival == current_arrival && piece.block < current.block)
                });
                if replace {
                    critical_missing = Some((*piece, path, arrival));
                }
            }
            Some(flight) => {
                let incumbent_group = paths
                    .iter()
                    .find(|path| path.id == flight.path)
                    .map(|path| path.bottleneck_group);
                let Some((path, arrival)) = earliest_path(
                    now_us,
                    *piece,
                    paths,
                    incumbent_group.map_or(PathFilter::Any, PathFilter::Independent),
                ) else {
                    continue;
                };
                if arrival >= flight.durable_at_us {
                    continue;
                }
                let saved = flight.durable_at_us - arrival;
                let replace = best_duplicate.is_none_or(|(current, _, current_arrival)| {
                    let current_saved = current.flight.map_or(0, |owned| {
                        owned.durable_at_us.saturating_sub(current_arrival)
                    });
                    saved > current_saved || (saved == current_saved && piece.block < current.block)
                });
                if replace {
                    best_duplicate = Some((*piece, path, arrival));
                }
            }
        }
    }

    if let Some((piece, path, arrival)) = best_duplicate {
        if path.ready_at_us > now_us {
            return Ok(CompletionAction::WaitUntil {
                time_us: path.ready_at_us,
            });
        }
        return Ok(CompletionAction::Duplicate {
            block: piece.block,
            path: path.id,
            durable_at_us: arrival,
        });
    }

    if let Some((piece, best, arrival)) = critical_missing {
        if best.ready_at_us > now_us {
            let immediate = earliest_path(now_us, piece, paths, PathFilter::Immediate);
            if immediate.is_none_or(|(_, immediate_arrival)| arrival < immediate_arrival) {
                return Ok(CompletionAction::WaitUntil {
                    time_us: best.ready_at_us,
                });
            }
        }
        return Ok(CompletionAction::Assign {
            block: piece.block,
            path: best.id,
            durable_at_us: arrival,
        });
    }

    Ok(next_evidence.map_or(CompletionAction::Idle, |time_us| {
        CompletionAction::WaitUntil { time_us }
    }))
}

fn earliest_path(
    now_us: u64,
    piece: PieceWork,
    paths: &[CompletionPath],
    filter: PathFilter,
) -> Option<(CompletionPath, u64)> {
    paths
        .iter()
        .filter(|path| {
            path.validated
                && path.in_flight < path.max_in_flight
                && match filter {
                    PathFilter::Any => true,
                    PathFilter::Immediate => path.ready_at_us <= now_us,
                    PathFilter::Independent(group) => {
                        group == 0 || path.bottleneck_group == 0 || path.bottleneck_group != group
                    }
                }
        })
        .map(|path| (*path, durable_arrival(now_us, piece, *path)))
        .min_by_key(|(path, arrival)| (*arrival, path.id))
}

#[derive(Clone, Copy)]
enum PathFilter {
    Any,
    Immediate,
    Independent(u32),
}

fn durable_arrival(now_us: u64, piece: PieceWork, path: CompletionPath) -> u64 {
    let certainty_bps = 10_000_u64.saturating_sub(u64::from(path.uncertainty_bps));
    let effective_bps =
        u128::from(path.delivery_rate_bps).saturating_mul(u128::from(certainty_bps)) / 10_000;
    let bits = u128::from(piece.bytes).saturating_mul(8);
    let serialization_us = ceil_div(bits.saturating_mul(1_000_000), effective_bps.max(1));
    let serialization_us = u64::try_from(serialization_us).unwrap_or(u64::MAX);
    now_us
        .max(piece.source_ready_us)
        .max(path.ready_at_us)
        .max(path.queue_free_at_us)
        .saturating_add(serialization_us)
        .saturating_add(path.latency_and_repair_us)
        .saturating_add(path.receiver_backlog_us)
}

fn validate(pieces: &[PieceWork], paths: &[CompletionPath]) -> Result<(), CompletionError> {
    for piece in pieces {
        let ownership_matches =
            matches!(piece.phase, BlockPhase::InFlight) == piece.flight.is_some();
        if piece.bytes == 0 || !ownership_matches {
            return Err(CompletionError::InvalidPiece(piece.block));
        }
    }
    for path in paths {
        if path.delivery_rate_bps == 0
            || path.uncertainty_bps >= 10_000
            || path.max_in_flight == 0
            || path.in_flight > path.max_in_flight
        {
            return Err(CompletionError::InvalidPath(path.id));
        }
    }
    Ok(())
}

fn ceil_div(numerator: u128, denominator: u128) -> u128 {
    numerator / denominator + u128::from(!numerator.is_multiple_of(denominator))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piece(block: u64) -> PieceWork {
        PieceWork {
            block: BlockId(block),
            bytes: 1_000_000,
            source_ready_us: 0,
            phase: BlockPhase::Missing,
            flight: None,
        }
    }

    fn path(id: u32, ready_at_us: u64, rate: u64, group: u32) -> CompletionPath {
        CompletionPath {
            id: PathId(id),
            bottleneck_group: group,
            validated: true,
            ready_at_us,
            queue_free_at_us: 0,
            delivery_rate_bps: rate,
            uncertainty_bps: 0,
            latency_and_repair_us: 10_000,
            receiver_backlog_us: 0,
            max_in_flight: 8,
            in_flight: 0,
        }
    }

    #[test]
    fn waits_when_late_fast_path_finishes_before_ready_slow_path() {
        let slow = path(1, 0, 1_000_000, 1);
        let fast = path(2, 100_000, 100_000_000, 2);
        assert_eq!(
            plan_completion(0, &[piece(0)], &[slow, fast]).unwrap(),
            CompletionAction::WaitUntil { time_us: 100_000 }
        );
    }

    #[test]
    fn starts_immediately_when_waiting_cannot_reduce_completion_time() {
        let ready = path(1, 0, 100_000_000, 1);
        let late = path(2, 100_000, 1_000_000, 2);
        assert!(matches!(
            plan_completion(0, &[piece(0)], &[ready, late]).unwrap(),
            CompletionAction::Assign {
                path: PathId(1),
                ..
            }
        ));
    }

    #[test]
    fn duplicate_requires_independent_bottleneck_and_earlier_arrival() {
        let mut tail = piece(7);
        tail.phase = BlockPhase::InFlight;
        tail.flight = Some(Flight {
            path: PathId(1),
            durable_at_us: 5_000_000,
        });
        let incumbent = path(1, 0, 1_000_000, 4);
        let shared = path(2, 0, 100_000_000, 4);
        assert_eq!(
            plan_completion(0, &[tail], &[incumbent, shared]).unwrap(),
            CompletionAction::Idle
        );
        let independent = path(3, 0, 100_000_000, 9);
        assert!(matches!(
            plan_completion(0, &[tail], &[incumbent, shared, independent]).unwrap(),
            CompletionAction::Duplicate {
                path: PathId(3),
                ..
            }
        ));
    }

    #[test]
    fn saturated_path_disables_itself_without_special_policy() {
        let mut saturated = path(1, 0, 100_000_000, 1);
        saturated.in_flight = saturated.max_in_flight;
        assert_eq!(
            plan_completion(0, &[piece(0)], &[saturated]).unwrap(),
            CompletionAction::Idle
        );
    }
}
