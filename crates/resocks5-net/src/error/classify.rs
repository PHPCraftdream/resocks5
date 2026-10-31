use super::{ConnectError, ProtocolViolation, Stage, TimeoutKind};

impl ConnectError {
    /// Whether this error indicates the upstream itself is down.
    ///
    /// A stalled or refused SOCKS5/HTTP CONNECT may instead be the
    /// destination's fault, so those errors are deliberately excluded.
    pub fn is_upstream_down(&self) -> bool {
        match self {
            ConnectError::Timeout { kind, .. } => matches!(
                kind,
                TimeoutKind::TcpConnect | TimeoutKind::HttpsTlsHandshake
            ),
            ConnectError::Io { stage, .. } => matches!(stage, Stage::Connect),
            ConnectError::AuthFailed { .. } | ConnectError::MethodUnsupported { .. } => true,
            ConnectError::Protocol(
                ProtocolViolation::Socks5BadVersion { .. }
                | ProtocolViolation::Socks5BadAuthVersion { .. },
            ) => true,
            #[cfg(feature = "tls")]
            ConnectError::Tls { .. } => true,
            _ => false,
        }
    }

    /// Whether this error should count against the upstream's rating.
    ///
    /// Capacity limits describe local load rather than upstream health.
    pub fn counts_against_upstream(&self) -> bool {
        #[cfg(feature = "pool")]
        if matches!(self, ConnectError::AtCapacity(_)) {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::time::Duration;

    fn timeout(kind: TimeoutKind, stage: Stage) -> ConnectError {
        ConnectError::Timeout {
            stage,
            kind,
            endpoint: "proxy:1080".into(),
            after: Duration::from_secs(1),
        }
    }

    fn io_error(stage: Stage) -> ConnectError {
        ConnectError::Io {
            stage,
            endpoint: None,
            source: io::Error::from(io::ErrorKind::ConnectionRefused),
        }
    }

    #[test]
    fn hard_failure_classification_is_exhaustive() {
        for kind in [TimeoutKind::TcpConnect, TimeoutKind::HttpsTlsHandshake] {
            assert!(timeout(kind, Stage::Handshake).is_upstream_down());
        }
        for kind in [
            TimeoutKind::Socks5Handshake,
            TimeoutKind::HttpHandshake,
            TimeoutKind::HttpsConnectHandshake,
            TimeoutKind::Total,
        ] {
            assert!(!timeout(kind, Stage::Connect).is_upstream_down());
        }
        assert!(io_error(Stage::Connect).is_upstream_down());
        assert!(!io_error(Stage::Handshake).is_upstream_down());
        assert!(!io_error(Stage::Total).is_upstream_down());
        assert!(ConnectError::AuthFailed { status: 1 }.is_upstream_down());
        assert!(ConnectError::MethodUnsupported {
            got: 0xff,
            with_auth: false
        }
        .is_upstream_down());
        assert!(
            ConnectError::Protocol(ProtocolViolation::Socks5BadVersion { got: 4 })
                .is_upstream_down()
        );
        assert!(
            ConnectError::Protocol(ProtocolViolation::Socks5BadAuthVersion { got: 2 })
                .is_upstream_down()
        );
        for violation in [
            ProtocolViolation::Socks5UnknownAddressType { got: 9 },
            ProtocolViolation::Socks5DomainTooLong { len: 256 },
            ProtocolViolation::Socks5CredentialsTooLong {
                username_len: 256,
                password_len: 0,
            },
            ProtocolViolation::HttpInvalidConnectTarget,
            ProtocolViolation::HttpResponseTooLarge,
            ProtocolViolation::HttpClosedEarly,
        ] {
            assert!(!ConnectError::Protocol(violation).is_upstream_down());
        }
        assert!(!ConnectError::ProxyRejected {
            protocol: crate::types::ProxyProtocol::Socks5,
            code: None,
            response: String::new()
        }
        .is_upstream_down());
        assert!(!ConnectError::InvalidTarget(String::new()).is_upstream_down());
        assert!(!ConnectError::TlsFeatureMissing {
            host: String::new()
        }
        .is_upstream_down());
        #[cfg(feature = "tls")]
        assert!(ConnectError::Tls {
            message: String::new(),
            source: None
        }
        .is_upstream_down());
        #[cfg(feature = "pool")]
        assert!(!ConnectError::AtCapacity(crate::pool::AtCapacity {
            host: String::new(),
            port: 0
        })
        .is_upstream_down());
    }

    #[test]
    fn classification_and_rating_count_are_exhaustive() {
        #[allow(unused_mut)]
        let mut errors = vec![
            (timeout(TimeoutKind::TcpConnect, Stage::Connect), true, true),
            (
                timeout(TimeoutKind::HttpsTlsHandshake, Stage::Handshake),
                true,
                true,
            ),
            (
                timeout(TimeoutKind::Socks5Handshake, Stage::Handshake),
                false,
                true,
            ),
            (
                timeout(TimeoutKind::HttpHandshake, Stage::Handshake),
                false,
                true,
            ),
            (
                timeout(TimeoutKind::HttpsConnectHandshake, Stage::Handshake),
                false,
                true,
            ),
            (timeout(TimeoutKind::Total, Stage::Total), false, true),
            (io_error(Stage::Connect), true, true),
            (io_error(Stage::Handshake), false, true),
            (io_error(Stage::Total), false, true),
            (ConnectError::AuthFailed { status: 1 }, true, true),
            (
                ConnectError::MethodUnsupported {
                    got: 0xff,
                    with_auth: false,
                },
                true,
                true,
            ),
            (
                ConnectError::Protocol(ProtocolViolation::Socks5BadVersion { got: 4 }),
                true,
                true,
            ),
            (
                ConnectError::Protocol(ProtocolViolation::Socks5BadAuthVersion { got: 2 }),
                true,
                true,
            ),
            (
                ConnectError::Protocol(ProtocolViolation::Socks5UnknownAddressType { got: 9 }),
                false,
                true,
            ),
            (
                ConnectError::Protocol(ProtocolViolation::Socks5DomainTooLong { len: 256 }),
                false,
                true,
            ),
            (
                ConnectError::Protocol(ProtocolViolation::Socks5CredentialsTooLong {
                    username_len: 256,
                    password_len: 0,
                }),
                false,
                true,
            ),
            (
                ConnectError::Protocol(ProtocolViolation::HttpInvalidConnectTarget),
                false,
                true,
            ),
            (
                ConnectError::Protocol(ProtocolViolation::HttpResponseTooLarge),
                false,
                true,
            ),
            (
                ConnectError::Protocol(ProtocolViolation::HttpClosedEarly),
                false,
                true,
            ),
            (
                ConnectError::ProxyRejected {
                    protocol: crate::types::ProxyProtocol::Socks5,
                    code: None,
                    response: String::new(),
                },
                false,
                true,
            ),
            (ConnectError::InvalidTarget(String::new()), false, true),
            (
                ConnectError::TlsFeatureMissing {
                    host: String::new(),
                },
                false,
                true,
            ),
        ];
        #[cfg(feature = "tls")]
        errors.push((
            ConnectError::Tls {
                message: String::new(),
                source: None,
            },
            true,
            true,
        ));
        #[cfg(feature = "pool")]
        errors.push((
            ConnectError::AtCapacity(crate::pool::AtCapacity {
                host: String::new(),
                port: 0,
            }),
            false,
            false,
        ));
        for (error, down, counted) in errors {
            assert_eq!(error.is_upstream_down(), down, "{error:?}");
            assert_eq!(error.counts_against_upstream(), counted, "{error:?}");
        }
    }
}
