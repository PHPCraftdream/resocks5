use super::{ConnectError, ProtocolViolation, Stage, TimeoutKind};
use crate::server::Reply;
use crate::types::ProxyProtocol;

impl ConnectError {
    /// Whether this error indicates the upstream itself is down.
    ///
    /// A stalled or refused SOCKS5/HTTP CONNECT may instead be the
    /// destination's fault, so those errors are deliberately excluded.
    /// The SOCKS5 greeting phase is the exception: until the upstream has
    /// answered the method selection, the CONNECT request has not been
    /// relayed, so a [`TimeoutKind::Socks5Greeting`] stall implicates the
    /// upstream alone.
    pub fn is_upstream_down(&self) -> bool {
        match self {
            ConnectError::Timeout { kind, .. } => matches!(
                kind,
                TimeoutKind::TcpConnect
                    | TimeoutKind::HttpsTlsHandshake
                    | TimeoutKind::Socks5Greeting
            ),
            ConnectError::Io { stage, .. } => matches!(stage, Stage::Connect),
            ConnectError::MethodUnsupported { .. }
            | ConnectError::SecureAuth(_)
            | ConnectError::Gssapi(_) => true,
            ConnectError::Protocol(ProtocolViolation::Socks5BadVersion { .. }) => true,
            #[cfg(feature = "tls")]
            ConnectError::Tls { .. } => true,
            _ => false,
        }
    }

    /// The reply a gateway should send its own client when this error ends
    /// the egress attempt: the single source of truth for the mapping, so
    /// every gateway built on this crate answers alike.
    ///
    /// | Error | Reply |
    /// |---|---|
    /// | any [`Timeout`](ConnectError::Timeout) | [`Reply::TimedOut`] |
    /// | SOCKS5 `ProxyRejected` REP 2 / 3 / 4 / 5 / 6 | `Forbidden` / `NetworkUnreachable` / `UpstreamUnavailable` / `ConnectionRefused` / `TimedOut` |
    /// | HTTP(S) `ProxyRejected` 403 / 504 / 502, 503 | `Forbidden` / `TimedOut` / `UpstreamUnavailable` |
    /// | other `ProxyRejected` (REP 1, 7, 8, other statuses, malformed) | `GeneralFailure` |
    /// | HTTP 407, SOCKS5 [`MethodUnsupported`](ConnectError::MethodUnsupported) (our credentials to the upstream) | `GeneralFailure` |
    /// | [`Io`](ConnectError::Io) timed out | `TimedOut` |
    /// | other [`Io`](ConnectError::Io) at [`Stage::Connect`] (the upstream itself is unreachable) | `UpstreamUnavailable` |
    /// | other [`Io`](ConnectError::Io) | `GeneralFailure` |
    /// | TLS failure | `UpstreamUnavailable` |
    /// | [`Protocol`](ConnectError::Protocol), [`InvalidTarget`](ConnectError::InvalidTarget), [`CleartextCredentialsRefused`](ConnectError::CleartextCredentialsRefused), missing TLS feature | `GeneralFailure` |
    /// | per-upstream cap hit (`AtCapacity`) | `Overloaded` |
    ///
    /// Only the destination's own verdict (a `ProxyRejected` code) selects a
    /// specific reply; failures of the upstream hop itself say "upstream
    /// unavailable" or "general failure", never "connection refused".
    pub fn suggested_reply(&self) -> Reply {
        match self {
            ConnectError::Timeout { .. } => Reply::TimedOut,
            ConnectError::Io { stage, source, .. } => {
                if source.kind() == std::io::ErrorKind::TimedOut {
                    Reply::TimedOut
                } else if matches!(stage, Stage::Connect) {
                    Reply::UpstreamUnavailable
                } else {
                    Reply::GeneralFailure
                }
            }
            ConnectError::ProxyRejected { protocol, code, .. } => match (protocol, code) {
                (ProxyProtocol::Socks5, Some(2)) => Reply::Forbidden,
                (ProxyProtocol::Socks5, Some(3)) => Reply::NetworkUnreachable,
                (ProxyProtocol::Socks5, Some(4)) => Reply::UpstreamUnavailable,
                (ProxyProtocol::Socks5, Some(5)) => Reply::ConnectionRefused,
                (ProxyProtocol::Socks5, Some(6)) => Reply::TimedOut,
                (ProxyProtocol::Http | ProxyProtocol::Https, Some(403)) => Reply::Forbidden,
                (ProxyProtocol::Http | ProxyProtocol::Https, Some(504)) => Reply::TimedOut,
                (ProxyProtocol::Http | ProxyProtocol::Https, Some(502 | 503)) => {
                    Reply::UpstreamUnavailable
                }
                _ => Reply::GeneralFailure,
            },
            ConnectError::MethodUnsupported { .. }
            | ConnectError::Protocol(_)
            | ConnectError::InvalidTarget(_)
            | ConnectError::CleartextCredentialsRefused
            | ConnectError::SecureAuth(_)
            | ConnectError::Gssapi(_)
            | ConnectError::TlsFeatureMissing { .. } => Reply::GeneralFailure,
            #[cfg(feature = "tls")]
            ConnectError::Tls { .. } => Reply::UpstreamUnavailable,
            #[cfg(feature = "pool")]
            ConnectError::AtCapacity(_) => Reply::Overloaded,
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
        // Our own configuration, not the upstream's behaviour.
        if matches!(self, ConnectError::CleartextCredentialsRefused) {
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
        // Mutation caught: removing `Socks5Greeting` from
        // `is_upstream_down` (or reverting the greeting-phase split) makes
        // this loop fail.
        for kind in [
            TimeoutKind::TcpConnect,
            TimeoutKind::HttpsTlsHandshake,
            TimeoutKind::Socks5Greeting,
        ] {
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
        assert!(ConnectError::MethodUnsupported {
            got: 0xff,
            with_auth: false
        }
        .is_upstream_down());
        assert!(
            ConnectError::Protocol(ProtocolViolation::Socks5BadVersion { got: 4 })
                .is_upstream_down()
        );
        for violation in [
            ProtocolViolation::Socks5UnknownAddressType { got: 9 },
            ProtocolViolation::Socks5DomainTooLong { len: 256 },
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
                timeout(TimeoutKind::Socks5Greeting, Stage::Handshake),
                true,
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

    fn rejected(protocol: ProxyProtocol, code: Option<u16>) -> ConnectError {
        ConnectError::ProxyRejected {
            protocol,
            code,
            response: String::new(),
        }
    }

    /// The single mapping from a connect failure to the reply a gateway gives
    /// its client. Mutations: moving a code to another reply, dropping the
    /// 504/REP 6 timeout rows, or sending the upstream-hop failures
    /// ("connection refused" at `Connect`) as the destination's refusal fails
    /// the matching row.
    #[test]
    fn suggested_reply_table() {
        use std::io::ErrorKind;
        let io = |stage, kind| ConnectError::Io {
            stage,
            endpoint: None,
            source: io::Error::from(kind),
        };
        let cases: Vec<(&str, ConnectError, Reply)> = vec![
            (
                "timeout connect",
                timeout(TimeoutKind::TcpConnect, Stage::Connect),
                Reply::TimedOut,
            ),
            (
                "timeout greeting",
                timeout(TimeoutKind::Socks5Greeting, Stage::Handshake),
                Reply::TimedOut,
            ),
            (
                "timeout connect reply",
                timeout(TimeoutKind::Socks5Handshake, Stage::Handshake),
                Reply::TimedOut,
            ),
            (
                "timeout total",
                timeout(TimeoutKind::HttpHandshake, Stage::Total),
                Reply::TimedOut,
            ),
            (
                "socks REP 1",
                rejected(ProxyProtocol::Socks5, Some(1)),
                Reply::GeneralFailure,
            ),
            (
                "socks REP 2",
                rejected(ProxyProtocol::Socks5, Some(2)),
                Reply::Forbidden,
            ),
            (
                "socks REP 3",
                rejected(ProxyProtocol::Socks5, Some(3)),
                Reply::NetworkUnreachable,
            ),
            (
                "socks REP 4",
                rejected(ProxyProtocol::Socks5, Some(4)),
                Reply::UpstreamUnavailable,
            ),
            (
                "socks REP 5",
                rejected(ProxyProtocol::Socks5, Some(5)),
                Reply::ConnectionRefused,
            ),
            (
                "socks REP 6",
                rejected(ProxyProtocol::Socks5, Some(6)),
                Reply::TimedOut,
            ),
            (
                "socks REP 7",
                rejected(ProxyProtocol::Socks5, Some(7)),
                Reply::GeneralFailure,
            ),
            (
                "socks REP 8",
                rejected(ProxyProtocol::Socks5, Some(8)),
                Reply::GeneralFailure,
            ),
            (
                "socks no code",
                rejected(ProxyProtocol::Socks5, None),
                Reply::GeneralFailure,
            ),
            (
                "http 403",
                rejected(ProxyProtocol::Http, Some(403)),
                Reply::Forbidden,
            ),
            (
                "http 407",
                rejected(ProxyProtocol::Http, Some(407)),
                Reply::GeneralFailure,
            ),
            (
                "http 502",
                rejected(ProxyProtocol::Http, Some(502)),
                Reply::UpstreamUnavailable,
            ),
            (
                "http 503",
                rejected(ProxyProtocol::Http, Some(503)),
                Reply::UpstreamUnavailable,
            ),
            (
                "http 504",
                rejected(ProxyProtocol::Http, Some(504)),
                Reply::TimedOut,
            ),
            (
                "https 403",
                rejected(ProxyProtocol::Https, Some(403)),
                Reply::Forbidden,
            ),
            (
                "https 504",
                rejected(ProxyProtocol::Https, Some(504)),
                Reply::TimedOut,
            ),
            (
                "http 404",
                rejected(ProxyProtocol::Http, Some(404)),
                Reply::GeneralFailure,
            ),
            (
                "http malformed",
                rejected(ProxyProtocol::Http, None),
                Reply::GeneralFailure,
            ),
            // A SOCKS5 code number means nothing on an HTTP upstream and back.
            (
                "http code 5",
                rejected(ProxyProtocol::Http, Some(5)),
                Reply::GeneralFailure,
            ),
            (
                "socks code 403",
                rejected(ProxyProtocol::Socks5, Some(403)),
                Reply::GeneralFailure,
            ),
            (
                "method unsupported",
                ConnectError::MethodUnsupported {
                    got: 0xff,
                    with_auth: true,
                },
                Reply::GeneralFailure,
            ),
            (
                "io refused at connect",
                io(Stage::Connect, ErrorKind::ConnectionRefused),
                Reply::UpstreamUnavailable,
            ),
            (
                "io reset at connect",
                io(Stage::Connect, ErrorKind::ConnectionReset),
                Reply::UpstreamUnavailable,
            ),
            (
                "io timed out",
                io(Stage::Handshake, ErrorKind::TimedOut),
                Reply::TimedOut,
            ),
            (
                "io timed out at connect",
                io(Stage::Connect, ErrorKind::TimedOut),
                Reply::TimedOut,
            ),
            (
                "io reset in handshake",
                io(Stage::Handshake, ErrorKind::ConnectionReset),
                Reply::GeneralFailure,
            ),
            (
                "protocol",
                ConnectError::Protocol(ProtocolViolation::HttpClosedEarly),
                Reply::GeneralFailure,
            ),
            (
                "invalid target",
                ConnectError::InvalidTarget("x".into()),
                Reply::GeneralFailure,
            ),
            (
                "tls feature missing",
                ConnectError::TlsFeatureMissing { host: "h".into() },
                Reply::GeneralFailure,
            ),
        ];
        for (name, error, expected) in cases {
            assert_eq!(error.suggested_reply(), expected, "{name}");
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn suggested_reply_for_a_tls_failure_is_upstream_unavailable() {
        let error = ConnectError::Tls {
            message: "m".into(),
            source: None,
        };
        assert_eq!(error.suggested_reply(), Reply::UpstreamUnavailable);
    }
}
