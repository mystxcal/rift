//! Deterministic path-portfolio evaluation and migration decisions.

use thiserror::Error;

/// Stable identity of one independently validated route.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PathId(pub u32);

/// Reachability mechanism behind a path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathKind {
    /// Peer-to-peer datagram path.
    DirectDatagram,
    /// Blind relay datagram path.
    RelayDatagram,
    /// Blind reliable stream path.
    RelayStream,
}

/// Whether peer ownership and session binding have been proven.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathReadiness {
    /// Acquisition or authenticated probing is still in flight.
    Probing,
    /// Path is allowed to carry session traffic.
    Validated,
}

/// Conservative online estimate used for payload placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathEstimate {
    /// Stable path identity.
    pub id: PathId,
    /// Reachability mechanism, retained for explanation rather than priority.
    pub kind: PathKind,
    /// Only validated paths are eligible for payload placement.
    pub readiness: PathReadiness,
    /// Pessimistic time until this path can carry payload.
    pub setup_remaining_us: u64,
    /// Tail round-trip/control latency after setup.
    pub tail_rtt_us: u64,
    /// Conservative useful delivery rate after loss and protocol overhead.
    pub goodput_floor_bps: u64,
    /// Residual probability of path failure in basis points.
    pub failure_bps: u16,
}

/// Auditable predicted tail completion on one path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathPrediction {
    /// Candidate path.
    pub id: PathId,
    /// Estimated microseconds until the remaining bytes are useful at receiver.
    pub completion_bound_us: u64,
}

/// A migration that strictly clears the configured switching margin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationDecision {
    /// Incumbent path kept alive until migration is confirmed.
    pub from: PathId,
    /// Better validated path.
    pub to: PathId,
    /// Incumbent predicted completion bound.
    pub incumbent_bound_us: u64,
    /// Challenger bound including migration cost.
    pub challenger_bound_us: u64,
    /// Strict predicted gain after switching cost.
    pub gain_us: u64,
}

/// Invalid or incomparable path estimate.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PathModelError {
    /// Useful delivery rate must be positive.
    #[error("path goodput floor must be positive")]
    ZeroGoodput,
    /// Failure probability must leave some chance of successful delivery.
    #[error("path failure probability must be below 10000 basis points")]
    CertainFailure,
    /// Path portfolio has no validated candidate.
    #[error("path portfolio is empty")]
    EmptyPortfolio,
    /// Current path is absent from the supplied portfolio.
    #[error("incumbent path is absent from the portfolio")]
    MissingIncumbent,
}

impl PathEstimate {
    /// Predict a conservative completion bound for remaining logical bytes.
    ///
    /// The failure adjustment is deliberately simple and explicit: useful
    /// transmission time is divided by survival probability. Better online
    /// distributions may replace this estimator without changing portfolio or
    /// migration semantics.
    ///
    /// # Errors
    ///
    /// Rejects zero goodput and certain failure.
    pub fn predict(self, bytes_remaining: u64) -> Result<PathPrediction, PathModelError> {
        if self.goodput_floor_bps == 0 {
            return Err(PathModelError::ZeroGoodput);
        }
        if self.failure_bps >= 10_000 {
            return Err(PathModelError::CertainFailure);
        }

        let bits = u128::from(bytes_remaining).saturating_mul(8);
        let transmission_us = ceil_div(
            bits.saturating_mul(1_000_000),
            u128::from(self.goodput_floor_bps),
        );
        let survival_bps = 10_000_u128 - u128::from(self.failure_bps);
        let risk_adjusted_us = ceil_div(transmission_us.saturating_mul(10_000), survival_bps);
        let total = u128::from(self.setup_remaining_us)
            .saturating_add(u128::from(self.tail_rtt_us))
            .saturating_add(risk_adjusted_us);
        Ok(PathPrediction {
            id: self.id,
            completion_bound_us: u64::try_from(total).unwrap_or(u64::MAX),
        })
    }
}

/// Choose the lowest predicted tail completion, with stable-ID tie breaking.
///
/// No path kind receives an intrinsic preference. A ready relay can start a
/// small transfer while direct discovery continues; a high-goodput direct path
/// naturally wins for larger remaining objects once its setup cost amortizes.
///
/// # Errors
///
/// Rejects empty portfolios or any malformed estimate.
pub fn choose_path(
    portfolio: &[PathEstimate],
    bytes_remaining: u64,
) -> Result<PathPrediction, PathModelError> {
    let mut best: Option<PathPrediction> = None;
    for estimate in portfolio
        .iter()
        .filter(|estimate| estimate.readiness == PathReadiness::Validated)
    {
        let prediction = estimate.predict(bytes_remaining)?;
        if best.is_none_or(|incumbent| {
            (prediction.completion_bound_us, prediction.id)
                < (incumbent.completion_bound_us, incumbent.id)
        }) {
            best = Some(prediction);
        }
    }
    best.ok_or(PathModelError::EmptyPortfolio)
}

/// Decide whether a validated challenger justifies live path migration.
///
/// The current path remains the fallback until higher layers confirm the new
/// path is active; this function only makes the information-theoretic choice.
///
/// # Errors
///
/// Rejects malformed estimates or an absent incumbent.
pub fn choose_migration(
    current: PathId,
    portfolio: &[PathEstimate],
    bytes_remaining: u64,
    switch_cost_us: u64,
    minimum_gain_us: u64,
) -> Result<Option<MigrationDecision>, PathModelError> {
    let incumbent = portfolio
        .iter()
        .find(|estimate| estimate.id == current)
        .copied()
        .ok_or(PathModelError::MissingIncumbent)?
        .predict(bytes_remaining)?;
    let challenger = choose_path(portfolio, bytes_remaining)?;
    if challenger.id == current {
        return Ok(None);
    }
    let challenger_with_switch = challenger
        .completion_bound_us
        .saturating_add(switch_cost_us);
    let gain = incumbent
        .completion_bound_us
        .saturating_sub(challenger_with_switch);
    if gain <= minimum_gain_us {
        return Ok(None);
    }
    Ok(Some(MigrationDecision {
        from: current,
        to: challenger.id,
        incumbent_bound_us: incumbent.completion_bound_us,
        challenger_bound_us: challenger_with_switch,
        gain_us: gain,
    }))
}

fn ceil_div(numerator: u128, denominator: u128) -> u128 {
    numerator / denominator + u128::from(!numerator.is_multiple_of(denominator))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay() -> PathEstimate {
        PathEstimate {
            id: PathId(1),
            kind: PathKind::RelayStream,
            readiness: PathReadiness::Validated,
            setup_remaining_us: 0,
            tail_rtt_us: 20_000,
            goodput_floor_bps: 20_000_000,
            failure_bps: 10,
        }
    }

    fn direct() -> PathEstimate {
        PathEstimate {
            id: PathId(2),
            kind: PathKind::DirectDatagram,
            readiness: PathReadiness::Probing,
            setup_remaining_us: 80_000,
            tail_rtt_us: 10_000,
            goodput_floor_bps: 200_000_000,
            failure_bps: 100,
        }
    }

    #[test]
    fn ready_relay_wins_tiny_payload_while_direct_keeps_probing() {
        assert_eq!(
            choose_path(&[relay(), direct()], 1_024).unwrap().id,
            PathId(1)
        );
    }

    #[test]
    fn probing_direct_path_never_delays_first_payload() {
        assert_eq!(
            choose_path(&[relay(), direct()], 64 * 1024 * 1024)
                .unwrap()
                .id,
            PathId(1)
        );
    }

    #[test]
    fn migration_requires_switch_cost_and_strict_margin() {
        let mut direct = direct();
        direct.readiness = PathReadiness::Validated;
        direct.setup_remaining_us = 0;
        let portfolio = [relay(), direct];
        assert!(
            choose_migration(PathId(1), &portfolio, 1024, 100_000, 10_000)
                .unwrap()
                .is_none()
        );
        let decision = choose_migration(PathId(1), &portfolio, 64 * 1024 * 1024, 10_000, 10_000)
            .unwrap()
            .unwrap();
        assert_eq!(decision.to, PathId(2));
        assert!(decision.gain_us > 10_000);
    }

    #[test]
    fn path_kind_never_overrides_equal_measurements() {
        let first = PathEstimate {
            id: PathId(4),
            kind: PathKind::RelayStream,
            ..relay()
        };
        let second = PathEstimate {
            id: PathId(3),
            kind: PathKind::DirectDatagram,
            ..relay()
        };
        assert_eq!(choose_path(&[first, second], 10_000).unwrap().id, PathId(3));
    }

    #[test]
    fn invalid_measurements_fail_before_policy() {
        let mut estimate = relay();
        estimate.goodput_floor_bps = 0;
        assert_eq!(
            choose_path(&[estimate], 1),
            Err(PathModelError::ZeroGoodput)
        );
        estimate.goodput_floor_bps = 1;
        estimate.failure_bps = 10_000;
        assert_eq!(
            choose_path(&[estimate], 1),
            Err(PathModelError::CertainFailure)
        );
    }

    #[test]
    fn validated_direct_path_naturally_wins_after_setup_amortizes() {
        let mut direct = direct();
        direct.readiness = PathReadiness::Validated;
        direct.setup_remaining_us = 0;
        assert_eq!(
            choose_path(&[relay(), direct], 64 * 1024 * 1024)
                .unwrap()
                .id,
            PathId(2)
        );
    }
}
