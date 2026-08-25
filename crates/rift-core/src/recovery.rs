//! Pure, safety-projected information recovery for one authenticated flight.

use thiserror::Error;

/// Evidence that triggered a tactical recovery decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryEvent {
    /// A fresh authenticated selective acknowledgement was observed.
    AckObserved,
    /// A partially acknowledged flight stopped progressing before its RTO.
    TailStalled,
}

/// Why an early information action is admissible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryCause {
    /// Enough later fragments distinguish a hole from ordinary reordering.
    SelectiveAckGap,
    /// A partial flight stopped progressing for the bounded probe interval.
    TailProbe,
}

/// Fixed parent/candidate strategy used by production and causal ablations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryStrategy {
    /// Wait for the congestion RTO; immutable pre-M3 parent.
    RtoOnly,
    /// Recover every admissible hole by exact systematic retransmission.
    ExactOnly,
    /// Use exact known gaps and fresh repair for ambiguous multi-source tails.
    AdaptiveRepair,
}

/// One auditable, safety-projected information action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    /// Retransmit the named missing systematic fragments.
    Retransmit {
        /// Exact active-flight source identities.
        bitmap: u64,
        /// Evidence that admitted the action.
        cause: RecoveryCause,
    },
    /// Send a fresh MDS equation over the active flight generation.
    SendRepair {
        /// Systematic sources participating in the repair equation.
        source_bitmap: u64,
        /// Evidence that admitted the action.
        cause: RecoveryCause,
    },
}

/// Fixed safety envelope for tactical information recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryPolicy {
    /// Parent/candidate action family.
    pub strategy: RecoveryStrategy,
    /// Later acknowledged fragments required before a lower hole is inferred lost.
    pub reordering_threshold: u8,
    /// Maximum early information actions admitted by one congestion flight.
    pub max_early_actions_per_flight: u8,
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self {
            strategy: RecoveryStrategy::AdaptiveRepair,
            reordering_threshold: 3,
            max_early_actions_per_flight: 4,
        }
    }
}

/// Invalid or contradictory recovery evidence.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RecoveryError {
    /// Fragment count, action budget, or policy lies outside the scoreboard.
    #[error("invalid information-recovery geometry")]
    InvalidGeometry,
    /// An acknowledgement or flight contains bits outside the record.
    #[error("information-recovery bitmap exceeds the fragment count")]
    BitmapOutOfRange,
    /// Acknowledged or attempted fragments were not in the active flight.
    #[error("information-recovery evidence is outside the active flight")]
    EvidenceOutsideFlight,
}

/// Select the next admissible information action from authenticated evidence.
///
/// The safety projection is structural:
///
/// - RTO-only never acts early;
/// - a selective-ACK gap is always recovered exactly;
/// - a no-feedback tail probes one systematic symbol at a time;
/// - repair is admitted only for an ambiguous tail with multiple candidates;
/// - every action is inside the active flight and the fixed per-flight budget.
///
/// # Errors
///
/// Rejects impossible counts, policies, budgets, or bitmaps before choosing.
pub fn choose_recovery_action(
    count: u8,
    flight_bitmap: u64,
    acknowledged_bitmap: u64,
    exact_attempted_bitmap: u64,
    early_actions_spent: u8,
    event: RecoveryEvent,
    policy: RecoveryPolicy,
) -> Result<Option<RecoveryAction>, RecoveryError> {
    let acknowledged = validate(
        count,
        flight_bitmap,
        acknowledged_bitmap,
        exact_attempted_bitmap,
        early_actions_spent,
        policy,
    )?;
    if policy.strategy == RecoveryStrategy::RtoOnly
        || early_actions_spent >= policy.max_early_actions_per_flight
    {
        return Ok(None);
    }

    let missing = flight_bitmap & !acknowledged_bitmap & !exact_attempted_bitmap;
    match event {
        RecoveryEvent::AckObserved => {
            let budget = u32::from(policy.max_early_actions_per_flight - early_actions_spent);
            let mut chosen = 0_u64;
            for index in 0..count {
                let bit = 1_u64 << index;
                if missing & bit == 0 {
                    continue;
                }
                let later = acknowledged & !mask_through(index);
                if later.count_ones() >= u32::from(policy.reordering_threshold) {
                    chosen |= bit;
                    if chosen.count_ones() >= budget {
                        break;
                    }
                }
            }
            Ok((chosen != 0).then_some(RecoveryAction::Retransmit {
                bitmap: chosen,
                cause: RecoveryCause::SelectiveAckGap,
            }))
        }
        RecoveryEvent::TailStalled => {
            if acknowledged_bitmap & flight_bitmap == 0 {
                let Some(index) = highest_set_bit(missing) else {
                    return Ok(None);
                };
                return Ok(Some(RecoveryAction::Retransmit {
                    bitmap: 1_u64 << index,
                    cause: RecoveryCause::TailProbe,
                }));
            }
            if policy.strategy == RecoveryStrategy::AdaptiveRepair && missing.count_ones() > 1 {
                return Ok(Some(RecoveryAction::SendRepair {
                    source_bitmap: flight_bitmap,
                    cause: RecoveryCause::TailProbe,
                }));
            }
            let Some(index) = highest_set_bit(missing) else {
                return Ok(None);
            };
            Ok(Some(RecoveryAction::Retransmit {
                bitmap: 1_u64 << index,
                cause: RecoveryCause::TailProbe,
            }))
        }
    }
}

fn validate(
    count: u8,
    flight_bitmap: u64,
    acknowledged_bitmap: u64,
    exact_attempted_bitmap: u64,
    early_actions_spent: u8,
    policy: RecoveryPolicy,
) -> Result<u64, RecoveryError> {
    if count == 0
        || count > 64
        || policy.reordering_threshold == 0
        || policy.reordering_threshold >= 64
        || policy.max_early_actions_per_flight == 0
        || policy.max_early_actions_per_flight > 64
        || early_actions_spent > policy.max_early_actions_per_flight
    {
        return Err(RecoveryError::InvalidGeometry);
    }
    let valid = bitmap_for(count);
    if (flight_bitmap | acknowledged_bitmap | exact_attempted_bitmap) & !valid != 0 {
        return Err(RecoveryError::BitmapOutOfRange);
    }
    if acknowledged_bitmap & !flight_bitmap != 0 || exact_attempted_bitmap & !flight_bitmap != 0 {
        return Err(RecoveryError::EvidenceOutsideFlight);
    }
    Ok(acknowledged_bitmap & flight_bitmap)
}

const fn bitmap_for(count: u8) -> u64 {
    if count == 64 {
        u64::MAX
    } else {
        (1_u64 << count) - 1
    }
}

const fn mask_through(index: u8) -> u64 {
    if index == 63 {
        u64::MAX
    } else {
        (1_u64 << (index + 1)) - 1
    }
}

fn highest_set_bit(bitmap: u64) -> Option<u8> {
    (bitmap != 0).then(|| u8::try_from(bitmap.ilog2()).expect("bit index fits u8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(strategy: RecoveryStrategy) -> RecoveryPolicy {
        RecoveryPolicy {
            strategy,
            ..RecoveryPolicy::default()
        }
    }

    #[test]
    fn rto_parent_never_acts_early() {
        assert_eq!(
            choose_recovery_action(
                8,
                0xff,
                0xfb,
                0,
                0,
                RecoveryEvent::AckObserved,
                policy(RecoveryStrategy::RtoOnly),
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn known_gap_is_exact_even_when_repair_is_available() {
        assert_eq!(
            choose_recovery_action(
                8,
                0xff,
                0xfb,
                0,
                0,
                RecoveryEvent::AckObserved,
                policy(RecoveryStrategy::AdaptiveRepair),
            )
            .unwrap(),
            Some(RecoveryAction::Retransmit {
                bitmap: 0x04,
                cause: RecoveryCause::SelectiveAckGap,
            })
        );
    }

    #[test]
    fn bounded_reordering_does_not_trigger_action() {
        assert_eq!(
            choose_recovery_action(
                8,
                0xff,
                0x1b,
                0,
                0,
                RecoveryEvent::AckObserved,
                policy(RecoveryStrategy::AdaptiveRepair),
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn ambiguous_tail_uses_repair_but_exact_parent_retransmits() {
        let adaptive = choose_recovery_action(
            8,
            0xff,
            0x03,
            0,
            0,
            RecoveryEvent::TailStalled,
            policy(RecoveryStrategy::AdaptiveRepair),
        )
        .unwrap();
        assert_eq!(
            adaptive,
            Some(RecoveryAction::SendRepair {
                source_bitmap: 0xff,
                cause: RecoveryCause::TailProbe,
            })
        );
        assert_eq!(
            choose_recovery_action(
                8,
                0xff,
                0x03,
                0,
                0,
                RecoveryEvent::TailStalled,
                policy(RecoveryStrategy::ExactOnly),
            )
            .unwrap(),
            Some(RecoveryAction::Retransmit {
                bitmap: 0x80,
                cause: RecoveryCause::TailProbe,
            })
        );
    }

    #[test]
    fn one_tail_candidate_is_exact_without_coding_overhead() {
        assert_eq!(
            choose_recovery_action(
                8,
                0xff,
                0x7f,
                0,
                0,
                RecoveryEvent::TailStalled,
                policy(RecoveryStrategy::AdaptiveRepair),
            )
            .unwrap(),
            Some(RecoveryAction::Retransmit {
                bitmap: 0x80,
                cause: RecoveryCause::TailProbe,
            })
        );
    }

    #[test]
    fn no_feedback_probes_one_tail_and_exhausted_budget_is_inert() {
        let adaptive = policy(RecoveryStrategy::AdaptiveRepair);
        assert_eq!(
            choose_recovery_action(8, 0xff, 0, 0, 0, RecoveryEvent::TailStalled, adaptive,)
                .unwrap(),
            Some(RecoveryAction::Retransmit {
                bitmap: 0x80,
                cause: RecoveryCause::TailProbe,
            })
        );
        assert_eq!(
            choose_recovery_action(
                8,
                0xff,
                0x03,
                0,
                adaptive.max_early_actions_per_flight,
                RecoveryEvent::TailStalled,
                adaptive,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn contradictory_bitmaps_fail_before_policy() {
        assert_eq!(
            choose_recovery_action(
                4,
                0x0f,
                0x10,
                0,
                0,
                RecoveryEvent::AckObserved,
                RecoveryPolicy::default(),
            ),
            Err(RecoveryError::BitmapOutOfRange)
        );
    }
}
