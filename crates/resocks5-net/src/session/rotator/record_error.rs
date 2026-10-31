use super::ProxyRotator;
use crate::error::ConnectError;
use crate::types::ProxyConfig;
use std::time::Duration;

impl ProxyRotator {
    /// Record a typed connection error against the upstream rating.
    ///
    /// Errors excluded by [`ConnectError::counts_against_upstream`] do
    /// not affect ratings. Upstream-down errors count toward quarantine;
    /// other errors lower the rating without quarantining.
    ///
    /// Returns the quarantine duration if this error trips it.
    pub fn record_error(&self, proxy: &ProxyConfig, err: &ConnectError) -> Option<Duration> {
        if !err.counts_against_upstream() {
            return None;
        }
        if err.is_upstream_down() {
            return self.record_hard_failure(proxy);
        }
        self.record_failure(proxy);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ProtocolViolation, Stage, TimeoutKind};
    use crate::rating::{QuarantinePolicy, RatingPolicy};
    use std::time::Duration;

    fn proxy(host: &str) -> ProxyConfig {
        ProxyConfig::socks5(host, 1080)
    }

    fn rotator() -> ProxyRotator {
        ProxyRotator::try_with_quarantine(
            vec![proxy("a"), proxy("b")],
            RatingPolicy::default(),
            QuarantinePolicy::default().with_threshold(2),
            16,
            Duration::from_secs(60),
        )
        .unwrap()
    }

    fn down_error() -> ConnectError {
        ConnectError::Timeout {
            stage: Stage::Connect,
            kind: TimeoutKind::TcpConnect,
            endpoint: "a:1080".into(),
            after: Duration::from_secs(1),
        }
    }

    #[test]
    fn hard_error_quarantines_at_threshold() {
        let r = rotator();
        let p = proxy("a");
        assert_eq!(r.record_error(&p, &down_error()), None);
        assert_eq!(
            r.record_error(&p, &down_error()),
            Some(Duration::from_secs(30))
        );
        assert!(r.is_quarantined(&p));
    }

    #[cfg(feature = "pool")]
    #[test]
    fn capacity_is_a_no_op() {
        let r = rotator();
        let p = proxy("a");
        let error = ConnectError::AtCapacity(crate::pool::AtCapacity {
            host: "a".into(),
            port: 1080,
        });
        let before = r.ratings.weights();
        for _ in 0..8 {
            assert_eq!(r.record_error(&p, &error), None);
        }
        assert_eq!(r.ratings.weights(), before);
        assert_eq!(r.record_error(&p, &down_error()), None);
        assert_eq!(
            r.record_error(&p, &down_error()),
            Some(Duration::from_secs(30))
        );
        assert!(r.is_quarantined(&p));
    }

    #[test]
    fn target_side_error_lowers_weight_without_quarantine() {
        let r = rotator();
        let p = proxy("a");
        let weights_before = r.ratings.weights();
        let target_error = ConnectError::Protocol(ProtocolViolation::HttpClosedEarly);
        for _ in 0..8 {
            assert_eq!(r.record_error(&p, &target_error), None);
        }
        let weights_after = r.ratings.weights();
        assert!(weights_after[0] < weights_before[0]);
        assert_eq!(weights_after[1], weights_before[1]);
        assert!(!r.is_quarantined(&p));
        assert_eq!(r.record_error(&p, &down_error()), None);
        assert_eq!(
            r.record_error(&p, &down_error()),
            Some(Duration::from_secs(30))
        );
    }
}
