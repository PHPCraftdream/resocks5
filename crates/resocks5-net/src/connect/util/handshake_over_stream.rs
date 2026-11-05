//! SOCKS5 handshake driven over an arbitrary async stream.

use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::connect::host_port::HostPort;
use crate::error::{ConnectError, ProtocolViolation, Stage, TimeoutKind};
use crate::types::ProxyProtocol;

/// Performs SOCKS5 handshake over an existing stream.
///
/// Parses `target_addr` (`host:port`, IPv6 bracketed) and runs
/// [`socks5_handshake`]; the stream contract there applies unchanged.
///
/// # Errors
///
/// Returns [`ConnectError`] for I/O failures and every SOCKS5 protocol
/// violation (method negotiation, auth, version, ATYP). An unparseable
/// `target_addr` yields [`ConnectError::InvalidTarget`] before any byte
/// is written.
pub async fn handshake_over_stream<S>(
    stream: S,
    target_addr: &str,
    auth: Option<(&str, &str)>,
) -> Result<S, ConnectError>
where
    S: AsyncRead + AsyncWriteExt + Unpin,
{
    let parsed = super::HostPort::parse(target_addr)
        .ok_or_else(|| ConnectError::InvalidTarget(target_addr.to_string()))?;
    socks5_handshake(stream, parsed.host, parsed.port, auth).await
}

/// SOCKS5 (RFC 1928) CONNECT handshake with optional RFC 1929
/// username/password auth over an existing stream. `host` is unbracketed:
/// an IPv4/IPv6 literal sends ATYP 1/4, anything else a domain (ATYP 3).
///
/// Takes the stream by value or as `&mut S`; every step is flushed. There
/// is no deadline here: wrap the call in a timeout if one is needed.
///
/// On error or cancellation the stream is in an unspecified protocol
/// state and must be dropped. On success it is positioned right after the
/// CONNECT reply, ready for payload.
///
/// # Errors
///
/// Returns [`ConnectError`] for I/O failures and every SOCKS5 protocol
/// violation (method negotiation, auth, version, ATYP, domain length).
///
/// cancel-safe: NO — a cancelled handshake must close the stream.
pub async fn socks5_handshake<S>(
    stream: S,
    host: &str,
    port: u16,
    auth: Option<(&str, &str)>,
) -> Result<S, ConnectError>
where
    S: AsyncRead + AsyncWriteExt + Unpin,
{
    if host.is_empty() || port == 0 {
        return Err(ConnectError::InvalidTarget(HostPort::format(host, port)));
    }
    let stream = socks5_greeting(stream, auth).await?;
    socks5_connect_request(stream, host, port).await
}

/// Send the SOCKS5 greeting (method-selection request, RFC 1928 §3) and,
/// when `auth` is set, complete the RFC 1929 username/password
/// sub-negotiation.
///
/// On success the stream sits right after the method-selection (or
/// auth-status) reply, ready for [`socks5_connect_request`]. A stall in
/// this phase means the upstream never answered its own protocol: the
/// CONNECT request has not been sent, so the destination cannot be the
/// cause. Producers bound this phase with
/// [`TimeoutKind::Socks5Greeting`](crate::error::TimeoutKind).
pub(crate) async fn socks5_greeting<S>(
    mut stream: S,
    auth: Option<(&str, &str)>,
) -> Result<S, ConnectError>
where
    S: AsyncRead + AsyncWriteExt + Unpin,
{
    if auth.is_some() && !crate::CLEARTEXT_CLIENT {
        // RFC 1929 sends the password as is: refused before any byte.
        return Err(ConnectError::CleartextCredentialsRefused);
    }
    if let Some((username, password)) = auth {
        stream.write_all(&[0x05, 0x01, 0x02]).await?;
        stream.flush().await?;
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        if response[0] != 0x05 {
            return Err(ConnectError::Protocol(
                ProtocolViolation::Socks5BadVersion { got: response[0] },
            ));
        }
        if response[1] != 0x02 {
            return Err(ConnectError::MethodUnsupported {
                got: response[1],
                with_auth: true,
            });
        }

        let uname = username.as_bytes();
        let passwd = password.as_bytes();
        if uname.len() > 255 || passwd.len() > 255 {
            return Err(ConnectError::Protocol(
                ProtocolViolation::Socks5CredentialsTooLong {
                    username_len: uname.len(),
                    password_len: passwd.len(),
                },
            ));
        }

        let mut auth_req = Vec::with_capacity(3 + uname.len() + passwd.len());
        auth_req.push(0x01);
        auth_req.push(uname.len() as u8);
        auth_req.extend_from_slice(uname);
        auth_req.push(passwd.len() as u8);
        auth_req.extend_from_slice(passwd);
        stream.write_all(&auth_req).await?;
        stream.flush().await?;

        let mut auth_resp = [0u8; 2];
        stream.read_exact(&mut auth_resp).await?;
        if auth_resp[0] != 0x01 {
            return Err(ConnectError::Protocol(
                ProtocolViolation::Socks5BadAuthVersion { got: auth_resp[0] },
            ));
        }
        if auth_resp[1] != 0x00 {
            return Err(ConnectError::AuthFailed {
                status: auth_resp[1],
            });
        }
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        stream.flush().await?;
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        if response[0] != 0x05 {
            return Err(ConnectError::Protocol(
                ProtocolViolation::Socks5BadVersion { got: response[0] },
            ));
        }
        if response[1] != 0x00 {
            return Err(ConnectError::MethodUnsupported {
                got: response[1],
                with_auth: false,
            });
        }
    }
    Ok(stream)
}

/// Send the SOCKS5 CONNECT request for `host:port` (RFC 1928 §5) and read
/// the reply through the end of the bound address.
///
/// On success the stream sits right after the CONNECT reply, ready for
/// payload. A stall waiting for the reply may still be the destination's
/// fault — the upstream has already relayed the CONNECT — so producers
/// classify it as plain
/// [`TimeoutKind::Socks5Handshake`](crate::error::TimeoutKind).
pub(crate) async fn socks5_connect_request<S>(
    mut stream: S,
    host: &str,
    port: u16,
) -> Result<S, ConnectError>
where
    S: AsyncRead + AsyncWriteExt + Unpin,
{
    if host.is_empty() || port == 0 {
        return Err(ConnectError::InvalidTarget(HostPort::format(host, port)));
    }
    let (atyp, addr_bytes) = if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
        (0x01, ipv4.octets().to_vec())
    } else if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        (0x04, ipv6.octets().to_vec())
    } else {
        let domain = host.as_bytes();
        if domain.len() > 255 {
            return Err(ConnectError::Protocol(
                ProtocolViolation::Socks5DomainTooLong { len: domain.len() },
            ));
        }
        let mut v = vec![domain.len() as u8];
        v.extend_from_slice(domain);
        (0x03, v)
    };
    let mut req = Vec::new();
    req.extend_from_slice(&[0x05, 0x01, 0x00, atyp]);
    req.extend_from_slice(&addr_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;
    stream.flush().await?;
    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await?;
    if resp_header[0] != 0x05 {
        return Err(ConnectError::Protocol(
            ProtocolViolation::Socks5BadVersion {
                got: resp_header[0],
            },
        ));
    }
    if resp_header[1] != 0x00 {
        return Err(ConnectError::ProxyRejected {
            protocol: ProxyProtocol::Socks5,
            code: Some(u16::from(resp_header[1])),
            response: String::new(),
        });
    }
    if resp_header[2] != 0x00 {
        return Err(ConnectError::Protocol(
            ProtocolViolation::Socks5BadReserved {
                got: resp_header[2],
            },
        ));
    }
    match resp_header[3] {
        0x01 => {
            stream.read_exact(&mut [0u8; 6]).await?;
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            if len_buf[0] == 0 {
                return Err(ConnectError::Protocol(
                    ProtocolViolation::Socks5EmptyBoundDomain,
                ));
            }
            let mut skip = vec![0u8; len_buf[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            stream.read_exact(&mut [0u8; 18]).await?;
        }
        _ => {
            return Err(ConnectError::Protocol(
                ProtocolViolation::Socks5UnknownAddressType {
                    got: resp_header[3],
                },
            ))
        }
    }
    Ok(stream)
}

/// [`socks5_handshake`] bounded by an ABSOLUTE `deadline`, with a typed
/// timeout instead of an outer `timeout_at` that loses the phase.
///
/// One deadline covers both phases and tells them apart: silence while the
/// upstream should answer the greeting (method selection, or the RFC 1929
/// sub-negotiation) is [`TimeoutKind::Socks5Greeting`] — the CONNECT request
/// was never sent, so only the upstream can be at fault
/// ([`ConnectError::is_upstream_down`] is `true`); silence after the CONNECT
/// request is [`TimeoutKind::Socks5Handshake`] — the destination may be the
/// one stalling. Both are [`ConnectError::Timeout`] with
/// [`Stage::Handshake`], `endpoint` as given (`host:port` of the upstream, for
/// the message) and `after` = the time left to the deadline at the call.
///
/// An empty `host` or port 0 is [`ConnectError::InvalidTarget`] before any
/// byte is written. The stream contract of [`socks5_handshake`] applies
/// unchanged: after an error or timeout drop the stream.
///
/// cancel-safe: NO — a cancelled handshake must close the stream.
///
/// # Errors
///
/// As [`socks5_handshake`], plus [`ConnectError::Timeout`] as above.
pub async fn socks5_handshake_until<S>(
    stream: S,
    host: &str,
    port: u16,
    auth: Option<(&str, &str)>,
    deadline: tokio::time::Instant,
    endpoint: &str,
) -> Result<S, ConnectError>
where
    S: AsyncRead + AsyncWriteExt + Unpin,
{
    let after = deadline.saturating_duration_since(tokio::time::Instant::now());
    socks5_handshake_bounded(stream, host, port, auth, deadline, endpoint, after).await
}

/// The deadline-bounded SOCKS5 handshake with an explicit `after` (the budget
/// the error reports); shared by the public wrapper and the dial paths, whose
/// budget is a configured duration rather than "time left".
pub(crate) async fn socks5_handshake_bounded<S>(
    stream: S,
    host: &str,
    port: u16,
    auth: Option<(&str, &str)>,
    deadline: tokio::time::Instant,
    endpoint: &str,
    after: std::time::Duration,
) -> Result<S, ConnectError>
where
    S: AsyncRead + AsyncWriteExt + Unpin,
{
    if host.is_empty() || port == 0 {
        return Err(ConnectError::InvalidTarget(HostPort::format(host, port)));
    }
    let timed_out = |kind| ConnectError::Timeout {
        stage: Stage::Handshake,
        kind,
        endpoint: endpoint.to_owned(),
        after,
    };
    let stream = match tokio::time::timeout_at(deadline, socks5_greeting(stream, auth)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Err(error),
        Err(_) => return Err(timed_out(TimeoutKind::Socks5Greeting)),
    };
    match tokio::time::timeout_at(deadline, socks5_connect_request(stream, host, port)).await {
        Ok(result) => result,
        Err(_) => Err(timed_out(TimeoutKind::Socks5Handshake)),
    }
}

/// `Instant::now() + budget` for a caller-supplied budget: a sum outside the
/// clock's range (e.g. `Duration::MAX`) means "no practical deadline" instead
/// of an overflow panic on the dial path.
pub(crate) fn deadline_after(budget: std::time::Duration) -> tokio::time::Instant {
    const FAR: std::time::Duration = std::time::Duration::from_secs(100 * 365 * 24 * 3600);
    let now = tokio::time::Instant::now();
    now.checked_add(budget)
        .or_else(|| now.checked_add(FAR))
        .unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::time::Duration;

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use super::{deadline_after, handshake_over_stream};

    /// Mutation: the plain `Instant::now() + budget` panics on `Duration::MAX`;
    /// a clamp to `now` would fail the far-future floor.
    #[test]
    fn deadline_after_survives_unrepresentable_budgets() {
        let now = tokio::time::Instant::now();
        let far = deadline_after(Duration::MAX);
        assert!(far.saturating_duration_since(now) >= Duration::from_secs(365 * 24 * 3600));
        let soon = deadline_after(Duration::from_secs(5));
        let ahead = soon.saturating_duration_since(tokio::time::Instant::now());
        assert!(ahead >= Duration::from_secs(4) && ahead <= Duration::from_secs(5));
    }

    /// Minimal SOCKS5 server stub over a duplex half: completes the greeting
    /// (plus username/password sub-negotiation when `auth` is set, asserting
    /// the credentials), captures the CONNECT request (head + address + port),
    /// then replies with success and the payload `ok`.
    async fn stub_server(mut upstream: tokio::io::DuplexStream, auth: bool) -> ([u8; 4], Vec<u8>) {
        let mut greeting = [0u8; 3];
        upstream.read_exact(&mut greeting).await.unwrap();
        if auth {
            assert_eq!(greeting, [0x05, 0x01, 0x02]);
            upstream.write_all(&[0x05, 0x02]).await.unwrap();
            let mut ver = [0u8; 1];
            upstream.read_exact(&mut ver).await.unwrap();
            assert_eq!(ver[0], 0x01);
            let mut ulen = [0u8; 1];
            upstream.read_exact(&mut ulen).await.unwrap();
            let mut uname = vec![0u8; ulen[0] as usize];
            upstream.read_exact(&mut uname).await.unwrap();
            let mut plen = [0u8; 1];
            upstream.read_exact(&mut plen).await.unwrap();
            let mut passwd = vec![0u8; plen[0] as usize];
            upstream.read_exact(&mut passwd).await.unwrap();
            assert_eq!(uname, b"user");
            assert_eq!(passwd, b"pass");
            upstream.write_all(&[0x01, 0x00]).await.unwrap();
        } else {
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            upstream.write_all(&[0x05, 0x00]).await.unwrap();
        }

        let mut head = [0u8; 4];
        upstream.read_exact(&mut head).await.unwrap();
        let mut addr = match head[3] {
            0x01 => {
                let mut b = [0u8; 6];
                upstream.read_exact(&mut b).await.unwrap();
                b.to_vec()
            }
            0x03 => {
                let mut len = [0u8; 1];
                upstream.read_exact(&mut len).await.unwrap();
                let mut b = vec![0u8; len[0] as usize + 2];
                upstream.read_exact(&mut b).await.unwrap();
                b
            }
            0x04 => {
                let mut b = [0u8; 18];
                upstream.read_exact(&mut b).await.unwrap();
                b.to_vec()
            }
            other => panic!("unexpected ATYP {other:02x}"),
        };
        addr.insert(0, head[3]);
        upstream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        upstream.write_all(b"ok").await.unwrap();
        (head, addr)
    }

    /// Drive the client side and return the captured request head and
    /// ATYP-prefixed address bytes, asserting the returned stream still
    /// carries the stub's `ok` payload.
    async fn exchange(target: &str) -> anyhow::Result<([u8; 4], Vec<u8>)> {
        let (mut client, upstream) = duplex(4096);
        let server = tokio::spawn(stub_server(upstream, false));
        let stream = handshake_over_stream(&mut client, target, None).await?;
        let mut payload = Vec::new();
        tokio::pin!(stream);
        stream.read_to_end(&mut payload).await?;
        assert_eq!(payload, b"ok");
        Ok(server.await.unwrap())
    }

    #[tokio::test]
    async fn bracketed_ipv6_uses_atyp4() {
        let (head, addr) = tokio::time::timeout(Duration::from_secs(5), exchange("[::1]:443"))
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(head, [0x05, 0x01, 0x00, 0x04]);
        assert_eq!(addr[0], 0x04);
        assert_eq!(&addr[1..17], &Ipv6Addr::LOCALHOST.octets());
        assert_eq!(&addr[17..], &[0x01, 0xBB]);
    }

    #[tokio::test]
    async fn bare_ipv6_uses_atyp4() {
        let (head, addr) = tokio::time::timeout(Duration::from_secs(5), exchange("::1:443"))
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(head, [0x05, 0x01, 0x00, 0x04]);
        assert_eq!(&addr[1..17], &Ipv6Addr::LOCALHOST.octets());
        assert_eq!(&addr[17..], &[0x01, 0xBB]);
    }

    #[tokio::test]
    async fn ipv4_uses_atyp1() {
        let (head, addr) = tokio::time::timeout(Duration::from_secs(5), exchange("1.2.3.4:443"))
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(head, [0x05, 0x01, 0x00, 0x01]);
        assert_eq!(addr, vec![0x01, 1, 2, 3, 4, 0x01, 0xBB]);
    }

    #[tokio::test]
    async fn domain_uses_atyp3() {
        let (head, addr) =
            tokio::time::timeout(Duration::from_secs(5), exchange("example.com:443"))
                .await
                .expect("timed out")
                .unwrap();
        assert_eq!(head, [0x05, 0x01, 0x00, 0x03]);
        assert_eq!(addr[0], 0x03);
        assert_eq!(&addr[1..12], b"example.com");
        assert_eq!(&addr[12..], &[0x01, 0xBB]);
    }

    #[tokio::test]
    async fn missing_port_is_rejected() {
        let result = tokio::time::timeout(Duration::from_secs(5), exchange("no-port-target"))
            .await
            .expect("timed out");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn full_ipv6_bracketed() {
        let (head, addr) =
            tokio::time::timeout(Duration::from_secs(5), exchange("[2001:db8::1]:443"))
                .await
                .expect("timed out")
                .unwrap();
        assert_eq!(head, [0x05, 0x01, 0x00, 0x04]);
        let expected: [u8; 16] = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        assert_eq!(&addr[1..17], &expected);
        assert_eq!(&addr[17..], &[0x01, 0xBB]);
    }

    /// Same as [`exchange`], but the client half is wrapped in a real
    /// buffering layer: `BufStream::write_all` only reaches its own internal
    /// buffer until an explicit `flush`, so this times out unless every
    /// handshake message is flushed to the peer before the matching read.
    async fn exchange_buffered(
        target: &str,
        auth: Option<(&str, &str)>,
    ) -> anyhow::Result<([u8; 4], Vec<u8>)> {
        let (client, upstream) = duplex(4096);
        let mut buffered = tokio::io::BufStream::new(client);
        let server = tokio::spawn(stub_server(upstream, auth.is_some()));
        let stream = handshake_over_stream(&mut buffered, target, auth).await?;
        tokio::pin!(stream);
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await?;
        assert_eq!(payload, b"ok");
        Ok(server.await.unwrap())
    }

    #[tokio::test]
    async fn no_auth_completes_through_buffered_client() {
        let (head, addr) = tokio::time::timeout(
            Duration::from_secs(5),
            exchange_buffered("1.2.3.4:443", None),
        )
        .await
        .expect("handshake stalled: greeting/CONNECT never flushed to the peer")
        .unwrap();
        assert_eq!(head, [0x05, 0x01, 0x00, 0x01]);
        assert_eq!(addr, vec![0x01, 1, 2, 3, 4, 0x01, 0xBB]);
    }

    #[tokio::test]
    async fn auth_completes_through_buffered_client() {
        let (head, addr) = tokio::time::timeout(
            Duration::from_secs(5),
            exchange_buffered("1.2.3.4:443", Some(("user", "pass"))),
        )
        .await
        .expect("handshake stalled: greeting/auth/CONNECT never flushed to the peer")
        .unwrap();
        assert_eq!(head, [0x05, 0x01, 0x00, 0x01]);
        assert_eq!(addr, vec![0x01, 1, 2, 3, 4, 0x01, 0xBB]);
    }

    #[tokio::test]
    async fn strict_reply_errors_are_typed_and_classified() {
        use crate::error::{ConnectError, ProtocolViolation};
        tokio::time::timeout(Duration::from_secs(5), async {
            for (reply, expected) in [([0x05, 0x00, 0x01, 0x01], 1), ([0x05, 0x05, 0x01, 0x01], 2)]
            {
                let (client, mut server) = duplex(128);
                let peer = tokio::spawn(async move {
                    let mut greeting = [0; 3];
                    server.read_exact(&mut greeting).await.unwrap();
                    server.write_all(&[0x05, 0x00]).await.unwrap();
                    let mut request = [0; 4];
                    server.read_exact(&mut request).await.unwrap();
                    let mut address = [0; 6];
                    server.read_exact(&mut address).await.unwrap();
                    server.write_all(&reply).await.unwrap();
                });
                let error = super::socks5_handshake(client, "1.2.3.4", 80, None)
                    .await
                    .unwrap_err();
                match expected {
                    1 => assert!(matches!(
                        error,
                        ConnectError::Protocol(ProtocolViolation::Socks5BadReserved { got: 1 })
                    )),
                    _ => assert!(matches!(
                        error,
                        ConnectError::ProxyRejected { code: Some(5), .. }
                    )),
                }
                assert!(!error.is_upstream_down());
                assert!(error.counts_against_upstream());
                peer.await.unwrap();
            }
        })
        .await
        .expect("strict reply exchange timed out");
    }

    #[tokio::test]
    async fn empty_bound_domain_rejected_without_waiting_for_address() {
        use crate::error::{ConnectError, ProtocolViolation};
        let (client, mut server) = duplex(128);
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let peer = tokio::spawn(async move {
            let mut greeting = [0; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[0x05, 0x00]).await.unwrap();
            let mut request = [0; 4];
            server.read_exact(&mut request).await.unwrap();
            let mut address = [0; 6];
            server.read_exact(&mut address).await.unwrap();
            server.write_all(&[0x05, 0, 0, 3, 0]).await.unwrap();
            let _ = release_rx.await;
            let mut bytes = Vec::new();
            server.read_to_end(&mut bytes).await.unwrap();
            bytes
        });
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            super::socks5_handshake(client, "1.2.3.4", 80, None),
        )
        .await
        .expect("handshake waited for missing address")
        .unwrap_err();
        assert!(matches!(
            error,
            ConnectError::Protocol(ProtocolViolation::Socks5EmptyBoundDomain)
        ));
        assert!(!error.is_upstream_down());
        assert!(error.counts_against_upstream());
        let _ = release_tx.send(());
        assert!(tokio::time::timeout(Duration::from_secs(5), peer)
            .await
            .expect("peer timeout")
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn invalid_targets_write_no_bytes() {
        use crate::error::ConnectError;
        for (host, port) in [("", 80), ("valid.invalid", 0)] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let (client, mut server) = duplex(128);
                let peer = tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    server.read_to_end(&mut bytes).await.unwrap();
                    bytes
                });
                let error = super::socks5_handshake(client, host, port, None)
                    .await
                    .unwrap_err();
                assert!(matches!(error, ConnectError::InvalidTarget(_)));
                assert!(peer.await.unwrap().is_empty());
            })
            .await
            .expect("invalid target EOF check timed out");
        }
    }

    #[tokio::test]
    async fn success_reply_shapes_preserve_payload() {
        tokio::time::timeout(Duration::from_secs(5), async {
            for (atyp, bound) in [
                (1, vec![0; 6]),
                (3, vec![3, b'f', b'o', b'o', 0, 80]),
                (4, vec![0; 18]),
            ] {
                let (client, mut server) = duplex(128);
                let peer = tokio::spawn(async move {
                    let mut greeting = [0; 3];
                    server.read_exact(&mut greeting).await.unwrap();
                    server.write_all(&[0x05, 0x00]).await.unwrap();
                    let mut request = [0; 4];
                    server.read_exact(&mut request).await.unwrap();
                    let mut address = [0; 6];
                    server.read_exact(&mut address).await.unwrap();
                    server.write_all(&[0x05, 0, 0, atyp]).await.unwrap();
                    server.write_all(&bound).await.unwrap();
                    server.write_all(b"payload").await.unwrap();
                });
                let mut stream = super::socks5_handshake(client, "1.2.3.4", 80, None)
                    .await
                    .unwrap();
                let mut payload = [0; 7];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"payload");
                peer.await.unwrap();
            }
        })
        .await
        .expect("successful reply exchange timed out");
    }
}

#[cfg(test)]
mod core_tests {
    use tokio::io::duplex;

    use super::{handshake_over_stream, socks5_handshake};

    async fn wire(use_core: bool, auth: Option<(&str, &str)>) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let has_auth = auth.is_some();
        let (mut client, mut server) = duplex(4096);
        let peer = tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut buf = [0u8; 3];
            server.read_exact(&mut buf).await.unwrap();
            seen.extend_from_slice(&buf);
            if has_auth {
                server.write_all(&[0x05, 0x02]).await.unwrap();
                let mut a = [0u8; 3 + 4 + 4];
                server.read_exact(&mut a).await.unwrap();
                seen.extend_from_slice(&a);
                server.write_all(&[0x01, 0x00]).await.unwrap();
            } else {
                server.write_all(&[0x05, 0x00]).await.unwrap();
            }
            // 4 head + 1 len + 11 domain + 2 port
            let mut req = [0u8; 18];
            server.read_exact(&mut req).await.unwrap();
            seen.extend_from_slice(&req);
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            seen
        });
        if use_core {
            socks5_handshake(&mut client, "example.com", 443, auth)
                .await
                .unwrap();
        } else {
            handshake_over_stream(&mut client, "example.com:443", auth)
                .await
                .unwrap();
        }
        peer.await.unwrap()
    }

    #[tokio::test]
    async fn core_and_wrapper_emit_identical_bytes() {
        assert_eq!(wire(true, None).await, wire(false, None).await);
        let auth = Some(("user", "pass"));
        assert_eq!(wire(true, auth).await, wire(false, auth).await);
    }
}

#[cfg(test)]
mod deadline_tests {
    use std::time::Duration;

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::time::Instant;

    use super::socks5_handshake_until;
    use crate::error::{ConnectError, Stage, TimeoutKind};

    fn soon() -> Instant {
        Instant::now() + Duration::from_millis(200)
    }

    /// Silence on the greeting: the typed kind says "the upstream never spoke"
    /// and the error counts the upstream as down. Mutation: reporting every
    /// stall as `Socks5Handshake` (the lost distinction) fails the match.
    #[tokio::test]
    async fn silent_greeting_is_a_greeting_timeout() {
        let (client, _server) = duplex(64);
        let error = socks5_handshake_until(client, "example.test", 443, None, soon(), "up:1080")
            .await
            .unwrap_err();
        match &error {
            ConnectError::Timeout {
                stage: Stage::Handshake,
                kind: TimeoutKind::Socks5Greeting,
                endpoint,
                after,
            } => {
                assert_eq!(endpoint, "up:1080");
                assert!(*after <= Duration::from_millis(200));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(error.is_upstream_down());
    }

    /// The method reply arrives but the CONNECT reply never does: the stall
    /// may be the destination's, so it is the plain handshake kind and not
    /// "upstream down". Mutation: classifying it as a greeting timeout (or
    /// the other way round) fails here or above.
    #[tokio::test]
    async fn silent_connect_reply_is_a_handshake_timeout() {
        let (client, mut server) = duplex(64);
        let stub = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[5, 0]).await.unwrap();
            let mut request = [0u8; 4];
            server.read_exact(&mut request).await.unwrap();
            std::future::pending::<()>().await; // never answers the CONNECT
        });
        let error = socks5_handshake_until(client, "10.0.0.1", 80, None, soon(), "up:1080")
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                ConnectError::Timeout {
                    stage: Stage::Handshake,
                    kind: TimeoutKind::Socks5Handshake,
                    ..
                }
            ),
            "{error:?}"
        );
        assert!(!error.is_upstream_down());
        stub.abort();
    }

    /// A deadline that already passed fails at once as a greeting timeout.
    #[tokio::test]
    async fn an_expired_deadline_fails_immediately() {
        let (client, _server) = duplex(64);
        let error = socks5_handshake_until(client, "h", 80, None, Instant::now(), "up:1")
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ConnectError::Timeout {
                kind: TimeoutKind::Socks5Greeting,
                ..
            }
        ));
    }

    /// A full handshake inside the deadline succeeds and leaves the stream
    /// ready for payload.
    #[tokio::test]
    async fn a_handshake_inside_the_deadline_succeeds() {
        let (client, mut server) = duplex(64);
        let stub = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[5, 0]).await.unwrap();
            let mut request = [0u8; 10];
            server.read_exact(&mut request).await.unwrap();
            server
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            server.write_all(b"payload").await.unwrap();
        });
        let mut stream = socks5_handshake_until(
            client,
            "10.0.0.1",
            80,
            None,
            Instant::now() + Duration::from_secs(10),
            "up:1080",
        )
        .await
        .unwrap();
        let mut payload = [0u8; 7];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"payload");
        stub.await.unwrap();
    }

    /// An empty host or port 0 is refused before a single byte is written.
    #[tokio::test]
    async fn an_invalid_target_is_refused_before_any_byte() {
        for (host, port) in [("", 80u16), ("h", 0u16)] {
            let (client, mut server) = duplex(64);
            let error = socks5_handshake_until(client, host, port, None, soon(), "up:1")
                .await
                .unwrap_err();
            assert!(
                matches!(error, ConnectError::InvalidTarget(_)),
                "{host:?}:{port}"
            );
            // The client half is gone: the server sees EOF with nothing sent.
            let mut sent = Vec::new();
            server.read_to_end(&mut sent).await.unwrap();
            assert!(sent.is_empty(), "no byte may precede the target check");
        }
    }
}
