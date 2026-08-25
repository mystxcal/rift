//! Integer-only RTT identification and bounded retransmission timing.

use thiserror::Error;

/// Invalid timing sample or envelope.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RttError {
    /// A duration was zero or the configured bounds were contradictory.
    #[error("invalid RTT timing geometry")]
    InvalidGeometry,
}

/// RFC 6298-style smoothed RTT state, expressed in microseconds.
///
/// The estimator is pure. Runtime code is responsible for Karn's rule: only
/// pass samples from flights that completed without retransmission or repair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RttEstimator {
    smoothed_us: u64,
    variation_us: u64,
}

impl RttEstimator {
    /// Seed one path from an authenticated validation round trip.
    ///
    /// # Errors
    ///
    /// Rejects a zero sample.
    pub fn new(sample_us: u64) -> Result<Self, RttError> {
        if sample_us == 0 {
            return Err(RttError::InvalidGeometry);
        }
        Ok(Self {
            smoothed_us: sample_us,
            variation_us: sample_us.div_ceil(2),
        })
    }

    /// Incorporate one unambiguous RTT sample.
    ///
    /// # Errors
    ///
    /// Rejects a zero sample.
    pub fn observe(&mut self, sample_us: u64) -> Result<(), RttError> {
        if sample_us == 0 {
            return Err(RttError::InvalidGeometry);
        }
        let error = self.smoothed_us.abs_diff(sample_us);
        self.variation_us = weighted(self.variation_us, 3, error, 1, 4);
        self.smoothed_us = weighted(self.smoothed_us, 7, sample_us, 1, 8);
        Ok(())
    }

    /// Current smoothed round-trip estimate.
    #[must_use]
    pub const fn smoothed_us(self) -> u64 {
        self.smoothed_us
    }

    /// Current mean-deviation estimate.
    #[must_use]
    pub const fn variation_us(self) -> u64 {
        self.variation_us
    }

    /// Retransmission timeout projected into a fixed safety envelope.
    ///
    /// # Errors
    ///
    /// Rejects zero or inverted timing bounds.
    pub fn rto_us(
        self,
        granularity_us: u64,
        minimum_us: u64,
        maximum_us: u64,
    ) -> Result<u64, RttError> {
        if granularity_us == 0 || minimum_us == 0 || minimum_us > maximum_us || maximum_us == 0 {
            return Err(RttError::InvalidGeometry);
        }
        let uncertainty = self.variation_us.saturating_mul(4).max(granularity_us);
        Ok(self
            .smoothed_us
            .saturating_add(uncertainty)
            .clamp(minimum_us, maximum_us))
    }

    /// Evidence-driven tail-probe delay below the current RTO when possible.
    ///
    /// The probe waits one smoothed RTT plus two deviations, then respects the
    /// configured floor and never exceeds the RTO.
    ///
    /// # Errors
    ///
    /// Rejects zero or inverted timing bounds.
    pub fn tail_probe_us(self, minimum_us: u64, rto_us: u64) -> Result<u64, RttError> {
        if minimum_us == 0 || rto_us == 0 || minimum_us > rto_us {
            return Err(RttError::InvalidGeometry);
        }
        Ok(self
            .smoothed_us
            .saturating_add(self.variation_us.saturating_mul(2))
            .max(minimum_us)
            .min(rto_us))
    }
}

fn weighted(left: u64, left_weight: u64, right: u64, right_weight: u64, divisor: u64) -> u64 {
    let numerator = u128::from(left)
        .saturating_mul(u128::from(left_weight))
        .saturating_add(u128::from(right).saturating_mul(u128::from(right_weight)));
    u64::try_from(numerator / u128::from(divisor)).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_matches_rfc_shape() {
        let estimator = RttEstimator::new(100_000).unwrap();
        assert_eq!(estimator.smoothed_us(), 100_000);
        assert_eq!(estimator.variation_us(), 50_000);
        assert_eq!(estimator.rto_us(1_000, 20_000, 2_000_000), Ok(300_000));
        assert_eq!(estimator.tail_probe_us(20_000, 300_000), Ok(200_000));
    }

    #[test]
    fn stable_samples_tighten_without_crossing_the_floor() {
        let mut estimator = RttEstimator::new(20_000).unwrap();
        for _ in 0..8 {
            estimator.observe(20_000).unwrap();
        }
        assert_eq!(estimator.smoothed_us(), 20_000);
        assert!(estimator.variation_us() < 1_100);
        assert_eq!(estimator.rto_us(1_000, 25_000, 2_000_000), Ok(25_000));
    }

    #[test]
    fn one_spike_moves_but_does_not_replace_history() {
        let mut estimator = RttEstimator::new(40_000).unwrap();
        estimator.observe(200_000).unwrap();
        assert_eq!(estimator.smoothed_us(), 60_000);
        assert_eq!(estimator.variation_us(), 55_000);
        assert_eq!(estimator.rto_us(1_000, 20_000, 500_000), Ok(280_000));
    }

    #[test]
    fn invalid_bounds_fail_closed() {
        assert_eq!(RttEstimator::new(0), Err(RttError::InvalidGeometry));
        let estimator = RttEstimator::new(1).unwrap();
        assert_eq!(estimator.rto_us(0, 1, 2), Err(RttError::InvalidGeometry));
        assert_eq!(
            estimator.tail_probe_us(3, 2),
            Err(RttError::InvalidGeometry)
        );
    }
}
