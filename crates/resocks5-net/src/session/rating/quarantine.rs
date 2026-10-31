//! Temporary quarantine of dead upstreams ([`QuarantinePolicy`]).
//!
//! The sand model only lowers an upstream's weight; it never removes it, so
//! a dead upstream keeps being tried (and keeps costing a connect timeout)
//! whenever the live ones are skipped. The quarantine is the hard layer on
//! top: after `threshold` consecutive *hard* failures (unreachable,
//! handshake timeout, broken proxy protocol) the upstream leaves the
//! selection order for a backoff period that doubles on every re-trip.
//! When the period ends the upstream is on *probation*: it is handed out,
//! one holder at a time (a lease), for an out-of-band probe by the caller.
//! A success clears the quarantine; a failure re-trips it with the doubled
//! period. While at least one upstream is healthy, quarantined and probing
//! upstreams never appear in the selection order; when none is healthy the
//! quarantine is ignored, so selection never runs dry.

use std::time::{Duration, Instant};

use super::policy::RatingError;

/// Knobs of the quarantine. [`QuarantinePolicy::default`] is the recommended
/// enabled setup; [`QuarantinePolicy::disabled`] keeps the plain sand model.
///
/// Built with `with_*` methods: the struct is `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct QuarantinePolicy {
    /// Consecutive hard failures that quarantine an upstream. `0` disables
    /// the quarantine.
    pub threshold: u32,
    /// Length of the first quarantine; doubles on every re-trip.
    pub initial: Duration,
    /// Upper bound of the (doubling) quarantine length.
    pub max: Duration,
    /// How long a probe owns the probation slot before another probe may be
    /// issued (a probe that never reports back is retried after it). Should
    /// exceed the probe's own timeout.
    pub probe_lease: Duration,
}

impl Default for QuarantinePolicy {
    fn default() -> Self {
        Self {
            threshold: 3,
            initial: Duration::from_secs(30),
            max: Duration::from_secs(600),
            probe_lease: Duration::from_secs(25),
        }
    }
}

impl QuarantinePolicy {
    /// No quarantine: selection is driven by the sand weights alone.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            threshold: 0,
            ..Self::default()
        }
    }

    /// `true` when the quarantine is active (`threshold > 0`).
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.threshold > 0
    }

    /// Set the consecutive-failure threshold (`0` disables).
    #[must_use]
    pub fn with_threshold(mut self, threshold: u32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Set the first quarantine length.
    #[must_use]
    pub fn with_initial(mut self, initial: Duration) -> Self {
        self.initial = initial;
        self
    }

    /// Set the maximum quarantine length.
    #[must_use]
    pub fn with_max(mut self, max: Duration) -> Self {
        self.max = max;
        self
    }

    /// Set the probe lease length.
    #[must_use]
    pub fn with_probe_lease(mut self, probe_lease: Duration) -> Self {
        self.probe_lease = probe_lease;
        self
    }

    /// Check the knobs. A disabled policy is always valid.
    ///
    /// # Errors
    /// [`RatingError::InvalidPolicy`] when an enabled policy has a zero
    /// `initial` or `probe_lease`, or `max < initial`.
    pub fn validate(&self) -> Result<(), RatingError> {
        if !self.enabled() {
            return Ok(());
        }
        if self.initial.is_zero() {
            return Err(RatingError::InvalidPolicy(
                "quarantine policy: initial must be > 0".to_string(),
            ));
        }
        if self.max < self.initial {
            return Err(RatingError::InvalidPolicy(format!(
                "quarantine policy: max ({:?}) must be >= initial ({:?})",
                self.max, self.initial
            )));
        }
        if self.probe_lease.is_zero() {
            return Err(RatingError::InvalidPolicy(
                "quarantine policy: probe_lease must be > 0".to_string(),
            ));
        }
        Ok(())
    }

    /// Length of the `trips`-th quarantine (`trips >= 1`): `initial`
    /// doubled `trips - 1` times, capped at `max`.
    fn duration_for(&self, trips: u32) -> Duration {
        let shift = trips.saturating_sub(1).min(20);
        self.initial.saturating_mul(1u32 << shift).min(self.max)
    }
}

/// Where an upstream stands relative to the quarantine at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum State {
    /// Never tripped, or cleared by a success.
    Healthy,
    /// Inside the backoff period: not selectable.
    Quarantined,
    /// Backoff over, not yet confirmed alive: handed out only as a probe.
    Probation,
}

/// Per-upstream quarantine bookkeeping.
#[derive(Debug, Default)]
pub(super) struct Cell {
    consecutive: u32,
    trips: u32,
    until: Option<Instant>,
    lease_until: Option<Instant>,
}

impl Cell {
    pub(super) fn state(&self, now: Instant) -> State {
        match self.until {
            None => State::Healthy,
            Some(until) if now < until => State::Quarantined,
            Some(_) => State::Probation,
        }
    }

    /// `true` once tripped and not yet cleared by a success.
    pub(super) fn is_tripped(&self) -> bool {
        self.until.is_some()
    }

    /// Count a hard failure. Returns the new quarantine length when this
    /// failure (re-)tripped the quarantine. A failure that lands inside an
    /// active quarantine belongs to a request that started before the trip
    /// and is ignored.
    pub(super) fn hard_failure(
        &mut self,
        now: Instant,
        policy: &QuarantinePolicy,
    ) -> Option<Duration> {
        if self.state(now) == State::Quarantined {
            return None;
        }
        self.lease_until = None;
        self.consecutive = self.consecutive.saturating_add(1);
        if self.consecutive < policy.threshold {
            return None;
        }
        self.trips = self.trips.saturating_add(1);
        let length = policy.duration_for(self.trips);
        self.until = Some(now.checked_add(length).unwrap_or(now));
        Some(length)
    }

    /// Quarantine right away, as if the threshold had just been reached
    /// (an explicit health check said the upstream is down). Returns the
    /// quarantine length.
    pub(super) fn trip_now(&mut self, now: Instant, policy: &QuarantinePolicy) -> Duration {
        self.lease_until = None;
        self.consecutive = self.consecutive.max(policy.threshold);
        self.trips = self.trips.saturating_add(1);
        let length = policy.duration_for(self.trips);
        self.until = Some(now.checked_add(length).unwrap_or(now));
        length
    }

    /// A success proves the upstream alive: forget everything.
    pub(super) fn success(&mut self) {
        *self = Cell::default();
    }

    /// Claim the probation slot. `true` only for an upstream on probation
    /// whose previous lease (if any) has run out.
    pub(super) fn try_lease(&mut self, now: Instant, policy: &QuarantinePolicy) -> bool {
        if self.state(now) != State::Probation {
            return false;
        }
        if self.lease_until.is_some_and(|lease| now < lease) {
            return false;
        }
        self.lease_until = Some(now.checked_add(policy.probe_lease).unwrap_or(now));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> QuarantinePolicy {
        QuarantinePolicy::default()
            .with_threshold(3)
            .with_initial(Duration::from_secs(30))
            .with_max(Duration::from_secs(100))
            .with_probe_lease(Duration::from_secs(10))
    }

    #[test]
    fn duration_doubles_and_is_capped() {
        let p = policy();
        assert_eq!(p.duration_for(1), Duration::from_secs(30));
        assert_eq!(p.duration_for(2), Duration::from_secs(60));
        assert_eq!(p.duration_for(3), Duration::from_secs(100));
        assert_eq!(p.duration_for(u32::MAX), Duration::from_secs(100));
    }

    #[test]
    fn trips_only_at_threshold() {
        let p = policy();
        let t0 = Instant::now();
        let mut c = Cell::default();
        assert_eq!(c.hard_failure(t0, &p), None);
        assert_eq!(c.hard_failure(t0, &p), None);
        assert_eq!(c.state(t0), State::Healthy);
        assert_eq!(c.hard_failure(t0, &p), Some(Duration::from_secs(30)));
        assert_eq!(c.state(t0), State::Quarantined);
    }

    #[test]
    fn success_resets_the_streak() {
        let p = policy();
        let t0 = Instant::now();
        let mut c = Cell::default();
        c.hard_failure(t0, &p);
        c.hard_failure(t0, &p);
        c.success();
        assert_eq!(c.hard_failure(t0, &p), None);
        assert_eq!(c.hard_failure(t0, &p), None);
        assert_eq!(c.state(t0), State::Healthy);
    }

    #[test]
    fn late_failure_inside_quarantine_is_ignored() {
        let p = policy();
        let t0 = Instant::now();
        let mut c = Cell::default();
        for _ in 0..3 {
            c.hard_failure(t0, &p);
        }
        assert_eq!(c.hard_failure(t0 + Duration::from_secs(5), &p), None);
        // Still the first backoff: probation starts at 30 s, not later.
        assert_eq!(c.state(t0 + Duration::from_secs(30)), State::Probation);
    }

    #[test]
    fn failed_probe_retrips_with_doubled_length() {
        let p = policy();
        let t0 = Instant::now();
        let mut c = Cell::default();
        for _ in 0..3 {
            c.hard_failure(t0, &p);
        }
        let t1 = t0 + Duration::from_secs(31);
        assert_eq!(c.state(t1), State::Probation);
        assert!(c.try_lease(t1, &p));
        assert_eq!(c.hard_failure(t1, &p), Some(Duration::from_secs(60)));
        assert_eq!(c.state(t1 + Duration::from_secs(59)), State::Quarantined);
        assert_eq!(c.state(t1 + Duration::from_secs(60)), State::Probation);
    }

    #[test]
    fn successful_probe_clears_the_quarantine() {
        let p = policy();
        let t0 = Instant::now();
        let mut c = Cell::default();
        for _ in 0..3 {
            c.hard_failure(t0, &p);
        }
        let t1 = t0 + Duration::from_secs(31);
        assert!(c.try_lease(t1, &p));
        c.success();
        assert_eq!(c.state(t1), State::Healthy);
        assert!(!c.is_tripped());
    }

    #[test]
    fn probe_lease_is_exclusive_until_it_expires() {
        let p = policy();
        let t0 = Instant::now();
        let mut c = Cell::default();
        for _ in 0..3 {
            c.hard_failure(t0, &p);
        }
        let t1 = t0 + Duration::from_secs(31);
        assert!(c.try_lease(t1, &p));
        assert!(!c.try_lease(t1 + Duration::from_secs(9), &p));
        assert!(c.try_lease(t1 + Duration::from_secs(10), &p));
    }

    #[test]
    fn no_lease_outside_probation() {
        let p = policy();
        let t0 = Instant::now();
        let mut c = Cell::default();
        assert!(!c.try_lease(t0, &p));
        for _ in 0..3 {
            c.hard_failure(t0, &p);
        }
        assert!(!c.try_lease(t0 + Duration::from_secs(1), &p));
    }

    #[test]
    fn validate_rules() {
        assert!(QuarantinePolicy::disabled().validate().is_ok());
        assert!(QuarantinePolicy::default().validate().is_ok());
        assert!(QuarantinePolicy::default()
            .with_initial(Duration::ZERO)
            .validate()
            .is_err());
        assert!(QuarantinePolicy::default()
            .with_max(Duration::from_secs(1))
            .validate()
            .is_err());
        assert!(QuarantinePolicy::default()
            .with_probe_lease(Duration::ZERO)
            .validate()
            .is_err());
        // A disabled policy ignores the other knobs.
        assert!(QuarantinePolicy::disabled()
            .with_initial(Duration::ZERO)
            .validate()
            .is_ok());
    }
}
