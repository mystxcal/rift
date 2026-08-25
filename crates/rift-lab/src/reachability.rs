//! Deterministic oracle for relay-first path acquisition and live migration.

use rift_core::{
    MigrationDecision, PathEstimate, PathId, PathModelError, PathReadiness, choose_migration,
    choose_path,
};
use thiserror::Error;

/// One path plus the trace time at which authenticated validation succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScheduledPath {
    /// Controller estimate. Its initial readiness is ignored by the oracle.
    pub estimate: PathEstimate,
    /// Microseconds after invocation at which validation completes.
    pub validates_at_us: u64,
}

/// One committed primary-path change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationEvent {
    /// Trace time of the decision after switching cost.
    pub at_us: u64,
    /// Auditable core decision.
    pub decision: MigrationDecision,
}

/// Path-race result under constant per-path conservative goodput.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathRaceOutcome {
    /// First validated path used for payload.
    pub initial_path: PathId,
    /// Confirmed primary-path changes.
    pub migrations: Vec<MigrationEvent>,
    /// Predicted receiver completion from invocation.
    pub completion_us: u64,
}

/// Invalid deterministic reachability experiment.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReachabilityError {
    /// No path was declared.
    #[error("reachability trace has no paths")]
    NoPaths,
    /// Core path model rejected an estimate.
    #[error(transparent)]
    Path(#[from] PathModelError),
}

/// Simulate immediate use of the first validated path while discovery
/// continues, then apply the production migration criterion at validation
/// events.
///
/// This is an intentionally conservative potency oracle, not a packet model.
/// It prevents two common benchmark cheats: delaying all payload for a hoped-for
/// direct path, and claiming migration wins without charging switch cost.
///
/// # Errors
///
/// Rejects empty traces and invalid path estimates.
pub fn simulate_path_race(
    bytes: u64,
    paths: &[ScheduledPath],
    switch_cost_us: u64,
    minimum_gain_us: u64,
) -> Result<PathRaceOutcome, ReachabilityError> {
    if paths.is_empty() {
        return Err(ReachabilityError::NoPaths);
    }
    let mut events = paths.to_vec();
    events.sort_unstable_by_key(|path| (path.validates_at_us, path.estimate.id));
    let mut portfolio: Vec<PathEstimate> = paths
        .iter()
        .map(|path| PathEstimate {
            readiness: PathReadiness::Probing,
            ..path.estimate
        })
        .collect();
    let mut now_us = events[0].validates_at_us;
    validate_due(&mut portfolio, &events, now_us);
    let initial = choose_path(&portfolio, bytes)?;
    let initial_path = initial.id;
    let mut current = initial_path;
    let mut remaining = bytes;
    let mut migrations = Vec::new();
    let mut event_index = events.partition_point(|path| path.validates_at_us <= now_us);

    while event_index < events.len() && remaining > 0 {
        let next_time = events[event_index].validates_at_us;
        let elapsed = next_time.saturating_sub(now_us);
        let incumbent = portfolio
            .iter()
            .find(|path| path.id == current)
            .ok_or(PathModelError::MissingIncumbent)?;
        let completion = PathEstimate {
            setup_remaining_us: 0,
            ..*incumbent
        }
        .predict(remaining)?;
        if completion.completion_bound_us <= elapsed {
            now_us = now_us.saturating_add(completion.completion_bound_us);
            remaining = 0;
            break;
        }
        let delivered = delivered_bytes(*incumbent, elapsed)?;
        remaining = remaining.saturating_sub(delivered);
        now_us = next_time;
        validate_due(&mut portfolio, &events, now_us);
        event_index = events.partition_point(|path| path.validates_at_us <= now_us);
        if remaining == 0 {
            break;
        }

        if let Some(decision) = choose_migration(
            current,
            &portfolio,
            remaining,
            switch_cost_us,
            minimum_gain_us,
        )? {
            now_us = now_us.saturating_add(switch_cost_us);
            current = decision.to;
            migrations.push(MigrationEvent {
                at_us: now_us,
                decision,
            });
        }
    }

    if remaining > 0 {
        let incumbent = portfolio
            .iter()
            .find(|path| path.id == current)
            .ok_or(PathModelError::MissingIncumbent)?;
        let prediction = PathEstimate {
            setup_remaining_us: 0,
            ..*incumbent
        }
        .predict(remaining)?;
        now_us = now_us.saturating_add(prediction.completion_bound_us);
    }

    Ok(PathRaceOutcome {
        initial_path,
        migrations,
        completion_us: now_us,
    })
}

fn validate_due(portfolio: &mut [PathEstimate], events: &[ScheduledPath], now_us: u64) {
    for event in events
        .iter()
        .filter(|event| event.validates_at_us <= now_us)
    {
        if let Some(path) = portfolio
            .iter_mut()
            .find(|path| path.id == event.estimate.id)
        {
            path.readiness = PathReadiness::Validated;
            path.setup_remaining_us = 0;
        }
    }
}

fn delivered_bytes(path: PathEstimate, elapsed_us: u64) -> Result<u64, PathModelError> {
    if path.goodput_floor_bps == 0 {
        return Err(PathModelError::ZeroGoodput);
    }
    if path.failure_bps >= 10_000 {
        return Err(PathModelError::CertainFailure);
    }
    let useful_bps = u128::from(path.goodput_floor_bps)
        .saturating_mul(10_000 - u128::from(path.failure_bps))
        / 10_000;
    let bytes = useful_bps.saturating_mul(u128::from(elapsed_us)) / 8_000_000;
    Ok(u64::try_from(bytes).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use rift_core::{PathKind, PathReadiness};

    use super::*;

    fn path(
        id: u32,
        kind: PathKind,
        validates_at_us: u64,
        goodput_floor_bps: u64,
    ) -> ScheduledPath {
        ScheduledPath {
            estimate: PathEstimate {
                id: PathId(id),
                kind,
                readiness: PathReadiness::Probing,
                setup_remaining_us: validates_at_us,
                tail_rtt_us: 10_000,
                goodput_floor_bps,
                failure_bps: 0,
            },
            validates_at_us,
        }
    }

    #[test]
    fn first_relay_carries_small_object_without_waiting_for_direct() {
        let outcome = simulate_path_race(
            32 * 1024,
            &[
                path(1, PathKind::RelayStream, 10_000, 20_000_000),
                path(2, PathKind::DirectDatagram, 100_000, 200_000_000),
            ],
            5_000,
            5_000,
        )
        .unwrap();
        assert_eq!(outcome.initial_path, PathId(1));
        assert!(outcome.migrations.is_empty());
        assert!(outcome.completion_us < 100_000);
    }

    #[test]
    fn large_object_starts_on_relay_then_migrates_to_validated_direct() {
        let paths = [
            path(1, PathKind::RelayStream, 10_000, 20_000_000),
            path(2, PathKind::DirectDatagram, 100_000, 200_000_000),
        ];
        let outcome = simulate_path_race(64 * 1024 * 1024, &paths, 5_000, 5_000).unwrap();
        let relay_only = simulate_path_race(64 * 1024 * 1024, &paths[..1], 5_000, 5_000).unwrap();
        assert_eq!(outcome.initial_path, PathId(1));
        assert_eq!(outcome.migrations.len(), 1);
        assert_eq!(outcome.migrations[0].decision.to, PathId(2));
        assert!(outcome.completion_us < relay_only.completion_us);
    }
}
