//! Persistable view of the quarantine bookkeeping, so a restart can resume
//! with the same dead/alive picture instead of relearning it from client
//! requests.

use std::time::{Duration, Instant};

use super::quarantine::State;
use super::Ratings;

/// Where an upstream stands in the quarantine cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpstreamState {
    /// Never tripped, or cleared by a success.
    Alive,
    /// Inside the backoff period: not selectable.
    Quarantined,
    /// Backoff over, not yet confirmed alive: handed out only as a probe.
    Probation,
}

/// One upstream's quarantine record. Holds only durations, never wall-clock
/// times: the caller owns time between a save and the next load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Health {
    /// Quarantine state.
    pub state: UpstreamState,
    /// Backoff time left; zero unless `state` is `Quarantined`.
    pub remaining: Duration,
    /// How many times the upstream was quarantined (drives the backoff length).
    pub trips: u32,
    /// Consecutive hard failures seen.
    pub consecutive: u32,
}

impl Health {
    /// Build a record.
    #[must_use]
    pub fn new(state: UpstreamState, remaining: Duration, trips: u32, consecutive: u32) -> Self {
        Self {
            state,
            remaining,
            trips,
            consecutive,
        }
    }
}

impl Ratings {
    /// Quarantine records of every upstream, in slot order. All `Alive`
    /// without a quarantine policy.
    pub fn health(&self) -> Vec<Health> {
        self.health_at(Instant::now())
    }

    fn health_at(&self, now: Instant) -> Vec<Health> {
        let inner = self.inner.lock().unwrap();
        inner
            .quarantine
            .iter()
            .map(|cell| {
                let (state, remaining, trips, consecutive) = cell.snapshot(now);
                let state = match state {
                    State::Healthy => UpstreamState::Alive,
                    State::Quarantined => UpstreamState::Quarantined,
                    State::Probation => UpstreamState::Probation,
                };
                Health::new(state, remaining, trips, consecutive)
            })
            .collect()
    }

    /// Re-create a saved quarantine for upstream `i`; meant for start-up,
    /// it overwrites the slot. `Alive` records change nothing. Returns
    /// `true` when a quarantine was applied.
    pub fn restore_health(&self, i: usize, health: &Health) -> bool {
        self.restore_health_at(i, health, Instant::now())
    }

    fn restore_health_at(&self, i: usize, health: &Health, now: Instant) -> bool {
        if !self.quarantine.enabled() || health.state == UpstreamState::Alive {
            return false;
        }
        let mut inner = self.inner.lock().unwrap();
        let Some(cell) = inner.quarantine.get_mut(i) else {
            return false;
        };
        cell.restore(
            health.state == UpstreamState::Quarantined,
            health.remaining,
            health.trips,
            health.consecutive,
            now,
            &self.quarantine,
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rating::{QuarantinePolicy, RatingPolicy};

    fn ratings() -> Ratings {
        Ratings::try_with_quarantine(
            3,
            RatingPolicy::default(),
            QuarantinePolicy::default()
                .with_threshold(2)
                .with_initial(Duration::from_secs(30))
                .with_max(Duration::from_secs(100)),
        )
        .unwrap()
    }

    #[test]
    fn a_fresh_set_is_alive() {
        assert!(ratings()
            .health()
            .iter()
            .all(|h| h.state == UpstreamState::Alive && h.trips == 0));
    }

    #[test]
    fn a_tripped_upstream_is_exported_with_time_left_and_trips() {
        let r = ratings();
        let t0 = Instant::now();
        r.on_hard_failure_at(1, t0);
        r.on_hard_failure_at(1, t0);
        let h = r.health_at(t0 + Duration::from_secs(10));
        assert_eq!(h[0].state, UpstreamState::Alive);
        assert_eq!(h[1].state, UpstreamState::Quarantined);
        assert_eq!(h[1].remaining, Duration::from_secs(20));
        assert_eq!(h[1].trips, 1);
        let later = r.health_at(t0 + Duration::from_secs(31));
        assert_eq!(later[1].state, UpstreamState::Probation);
        assert_eq!(later[1].remaining, Duration::ZERO);
    }

    #[test]
    fn restore_recreates_quarantine_and_probation() {
        let r = ratings();
        let now = Instant::now();
        let quarantined = Health::new(UpstreamState::Quarantined, Duration::from_secs(60), 2, 2);
        let probation = Health::new(UpstreamState::Probation, Duration::ZERO, 3, 2);
        assert!(r.restore_health_at(0, &quarantined, now));
        assert!(r.restore_health_at(1, &probation, now));
        assert!(!r.restore_health_at(
            2,
            &Health::new(UpstreamState::Alive, Duration::ZERO, 0, 0),
            now
        ));
        let h = r.health_at(now + Duration::from_secs(1));
        assert_eq!(h[0].state, UpstreamState::Quarantined);
        assert_eq!(h[0].remaining, Duration::from_secs(59));
        assert_eq!(h[0].trips, 2);
        assert_eq!(h[1].state, UpstreamState::Probation);
        assert_eq!(h[2].state, UpstreamState::Alive);
        // Probation is handed out as a probe, quarantine is not.
        assert_eq!(r.take_probes_at(now + Duration::from_secs(1)), vec![1]);
    }

    #[test]
    fn restore_caps_the_remaining_time_and_rejects_unknown_slots() {
        let r = ratings();
        let now = Instant::now();
        let huge = Health::new(
            UpstreamState::Quarantined,
            Duration::from_secs(86_400),
            1,
            1,
        );
        assert!(r.restore_health_at(0, &huge, now));
        assert_eq!(r.health_at(now)[0].remaining, Duration::from_secs(100));
        assert!(!r.restore_health_at(9, &huge, now));
    }

    #[test]
    fn a_success_after_restore_clears_everything() {
        let r = ratings();
        let health = Health::new(UpstreamState::Probation, Duration::ZERO, 4, 2);
        assert!(r.restore_health(0, &health));
        r.on_success(0);
        let h = r.health();
        assert_eq!(h[0].state, UpstreamState::Alive);
        assert_eq!(h[0].trips, 0);
    }

    #[test]
    fn without_a_quarantine_policy_nothing_is_restored() {
        let r = Ratings::new(1, RatingPolicy::default());
        let health = Health::new(UpstreamState::Probation, Duration::ZERO, 1, 1);
        assert!(!r.restore_health(0, &health));
    }
}
