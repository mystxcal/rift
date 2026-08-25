#![forbid(unsafe_code)]

//! Deterministic transport experiments and admission gates.

pub mod reachability;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A packet emitted into one deterministic slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Symbol {
    /// Original source symbol.
    Source(u16),
    /// Repair symbol assumed innovative until source rank is reached.
    Repair(u32),
}

/// One trace slot. `delivered = false` models loss after sender work.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Slot {
    /// Sender action in this slot.
    pub symbol: Symbol,
    /// Whether the receiver authenticated this packet.
    pub delivered: bool,
}

/// Result of deterministic rank evolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    /// First one-based slot at which reconstruction became possible.
    pub completion_slot: Option<usize>,
    /// Final decoder rank, capped at source rank.
    pub final_rank: u16,
    /// Transmissions after the receiver had enough information.
    pub post_completion_waste: usize,
}

/// Invalid experiment declaration.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LabError {
    /// Source rank must be positive.
    #[error("source rank must be positive")]
    ZeroSourceRank,
}

/// Execute an exact rank trace. This small reference model is intentionally
/// independent of production transport code and is suitable as an oracle.
///
/// # Errors
///
/// Returns [`LabError::ZeroSourceRank`] when no source symbols are declared.
pub fn simulate(source_rank: u16, slots: &[Slot]) -> Result<Outcome, LabError> {
    if source_rank == 0 {
        return Err(LabError::ZeroSourceRank);
    }
    let mut sources = BTreeSet::new();
    let mut repairs = BTreeSet::new();
    let mut completion_slot = None;
    let mut post_completion_waste = 0;

    for (index, slot) in slots.iter().enumerate() {
        if completion_slot.is_some() {
            post_completion_waste += 1;
            continue;
        }
        if slot.delivered {
            match slot.symbol {
                Symbol::Source(id) if id < source_rank => {
                    sources.insert(id);
                }
                Symbol::Repair(id) => {
                    repairs.insert(id);
                }
                Symbol::Source(_) => {}
            }
        }
        let rank = (sources.len() + repairs.len()).min(usize::from(source_rank));
        if rank == usize::from(source_rank) {
            completion_slot = Some(index + 1);
        }
    }

    let final_rank = u16::try_from((sources.len() + repairs.len()).min(usize::from(source_rank)))
        .unwrap_or(source_rank);
    Ok(Outcome {
        completion_slot,
        final_rank,
        post_completion_waste,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_source_does_not_inflate_rank() {
        let outcome = simulate(
            2,
            &[
                Slot {
                    symbol: Symbol::Source(0),
                    delivered: true,
                },
                Slot {
                    symbol: Symbol::Source(0),
                    delivered: true,
                },
            ],
        )
        .unwrap();
        assert_eq!(outcome.final_rank, 1);
        assert_eq!(outcome.completion_slot, None);
    }

    #[test]
    fn innovative_repair_closes_a_loss_hole() {
        let outcome = simulate(
            3,
            &[
                Slot {
                    symbol: Symbol::Source(0),
                    delivered: true,
                },
                Slot {
                    symbol: Symbol::Source(1),
                    delivered: false,
                },
                Slot {
                    symbol: Symbol::Source(2),
                    delivered: true,
                },
                Slot {
                    symbol: Symbol::Repair(7),
                    delivered: true,
                },
            ],
        )
        .unwrap();
        assert_eq!(outcome.completion_slot, Some(4));
        assert_eq!(outcome.final_rank, 3);
    }

    #[test]
    fn oracle_accounts_for_post_completion_waste() {
        let outcome = simulate(
            1,
            &[
                Slot {
                    symbol: Symbol::Source(0),
                    delivered: true,
                },
                Slot {
                    symbol: Symbol::Repair(1),
                    delivered: true,
                },
            ],
        )
        .unwrap();
        assert_eq!(outcome.post_completion_waste, 1);
    }
}
