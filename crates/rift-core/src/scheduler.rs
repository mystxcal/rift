//! Risk-sensitive action selection for the tactical controller.

use thiserror::Error;

/// A controller action that can add information or improve the path model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Send the next original source symbol.
    SendSystematic {
        /// Source block identifier.
        block: u64,
        /// Chosen path identifier.
        path: u32,
    },
    /// Repeat a missing source symbol exactly.
    Retransmit {
        /// Source block identifier.
        block: u64,
        /// Original symbol identifier.
        symbol: u32,
        /// Chosen path identifier.
        path: u32,
    },
    /// Send a fresh innovative repair symbol.
    SendRepair {
        /// Source block identifier.
        block: u64,
        /// Chosen path identifier.
        path: u32,
    },
    /// Validate or measure a candidate path.
    ProbePath {
        /// Candidate path identifier.
        path: u32,
    },
    /// Satisfy a block from receiver-local bytes.
    ReuseLocal {
        /// Source block identifier.
        block: u64,
    },
    /// Produce and offer a compressed block representation.
    Compress {
        /// Source block identifier.
        block: u64,
        /// Negotiated compression algorithm identifier.
        algorithm: u16,
    },
}

/// Resource consumption predicted for an action, in fixed implementation units.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceCost {
    /// Bytes put on the network.
    pub network_bytes: u64,
    /// Estimated CPU work units.
    pub cpu_units: u64,
    /// Estimated disk work units.
    pub disk_units: u64,
    /// Peak additional resident bytes.
    pub memory_bytes: u64,
}

/// Online shadow prices convert unlike resource costs to one scarcity cost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShadowPrices {
    /// Price per network byte.
    pub network: u64,
    /// Price per CPU work unit.
    pub cpu: u64,
    /// Price per disk work unit.
    pub disk: u64,
    /// Price per resident byte.
    pub memory: u64,
}

impl Default for ShadowPrices {
    fn default() -> Self {
        Self {
            network: 1,
            cpu: 1,
            disk: 1,
            memory: 1,
        }
    }
}

impl ResourceCost {
    fn priced(self, prices: ShadowPrices) -> u128 {
        u128::from(self.network_bytes) * u128::from(prices.network)
            + u128::from(self.cpu_units) * u128::from(prices.cpu)
            + u128::from(self.disk_units) * u128::from(prices.disk)
            + u128::from(self.memory_bytes) * u128::from(prices.memory)
    }
}

/// Predicted completion distribution after one admissible action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    /// The action being evaluated.
    pub action: Action,
    /// Completion-time samples in microseconds after the action.
    pub completion_samples_us: Vec<u64>,
    /// Resource cost of the action.
    pub cost: ResourceCost,
}

/// Selected action plus auditable fixed-point score components.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    /// Winning action.
    pub action: Action,
    /// Baseline tail-risk estimate in microseconds.
    pub baseline_cvar_us: u64,
    /// Predicted tail-risk estimate after the action.
    pub action_cvar_us: u64,
    /// Predicted reduction in tail risk.
    pub improvement_us: u64,
    /// Shadow-priced resource cost.
    pub priced_cost: u128,
}

/// Invalid scheduler input.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SchedulerError {
    /// Tail quantile must be in `(0, 10_000)` basis points.
    #[error("tail quantile must be between 1 and 9999 basis points")]
    InvalidQuantile,
    /// The baseline distribution is empty.
    #[error("baseline completion distribution is empty")]
    EmptyBaseline,
    /// A candidate used a different or empty sample population.
    #[error("candidate sample count must equal the baseline sample count")]
    SampleCountMismatch,
}

/// Choose the action with greatest positive `CVaR` reduction per priced cost.
///
/// `tail_quantile_bps = 9000` means average the worst 10% of samples. Inputs
/// are integer-only so decisions are deterministic across architectures.
///
/// # Errors
///
/// Returns [`SchedulerError`] for an invalid tail quantile, an empty baseline,
/// or candidate distributions with a different population size.
pub fn select_action(
    baseline_samples_us: &[u64],
    candidates: &[Candidate],
    tail_quantile_bps: u16,
    prices: ShadowPrices,
) -> Result<Option<Decision>, SchedulerError> {
    if tail_quantile_bps == 0 || tail_quantile_bps >= 10_000 {
        return Err(SchedulerError::InvalidQuantile);
    }
    if baseline_samples_us.is_empty() {
        return Err(SchedulerError::EmptyBaseline);
    }

    let baseline = cvar(baseline_samples_us, tail_quantile_bps);
    let mut best: Option<Decision> = None;
    for candidate in candidates {
        if candidate.completion_samples_us.len() != baseline_samples_us.len() {
            return Err(SchedulerError::SampleCountMismatch);
        }
        let after = cvar(&candidate.completion_samples_us, tail_quantile_bps);
        let improvement = baseline.saturating_sub(after);
        let cost = candidate.cost.priced(prices);
        if improvement == 0 || cost == 0 {
            continue;
        }
        let decision = Decision {
            action: candidate.action,
            baseline_cvar_us: baseline,
            action_cvar_us: after,
            improvement_us: improvement,
            priced_cost: cost,
        };
        let replaces = best.is_none_or(|current| {
            u128::from(improvement) * current.priced_cost
                > u128::from(current.improvement_us) * cost
        });
        if replaces {
            best = Some(decision);
        }
    }
    Ok(best)
}

fn cvar(samples: &[u64], quantile_bps: u16) -> u64 {
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let count = ordered.len();
    let first_tail = (count * usize::from(quantile_bps)) / 10_000;
    let tail = &ordered[first_tail.min(count - 1)..];
    let total = tail
        .iter()
        .fold(0_u128, |sum, value| sum + u128::from(*value));
    u64::try_from(total / tail.len() as u128).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(action: Action, samples: &[u64], network_bytes: u64) -> Candidate {
        Candidate {
            action,
            completion_samples_us: samples.to_vec(),
            cost: ResourceCost {
                network_bytes,
                ..ResourceCost::default()
            },
        }
    }

    #[test]
    fn chooses_tail_risk_reduction_per_cost_without_floats() {
        let baseline = [100, 100, 100, 100, 1_000];
        let cheap = candidate(Action::ProbePath { path: 1 }, &[90, 90, 90, 90, 900], 10);
        let rescue = candidate(
            Action::SendRepair { block: 8, path: 2 },
            &[100, 100, 100, 100, 400],
            20,
        );
        let decision = select_action(&baseline, &[cheap, rescue], 8_000, ShadowPrices::default())
            .unwrap()
            .unwrap();
        assert_eq!(decision.action, Action::SendRepair { block: 8, path: 2 });
    }

    #[test]
    fn rejects_non_improving_and_zero_cost_candidates() {
        let baseline = [100, 200];
        let worse = candidate(Action::ProbePath { path: 1 }, &[200, 300], 1);
        let free = candidate(Action::ReuseLocal { block: 1 }, &[10, 20], 0);
        assert_eq!(
            select_action(&baseline, &[worse, free], 5_000, ShadowPrices::default()).unwrap(),
            None
        );
    }
}
