//! Opt-in strict HTTP CONNECT ingress tests (RFC 9112).

use super::*;
use crate::server::strict_http::{validate, StrictViolation};

/// Assemble one HTTP request from parts; lengths are never hand-written.
fn http_req(request_line: &str, headers: &[&str], pipeline: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(request_line.as_bytes());
    frame.extend_from_slice(b"\r\n");
    for header in headers {
        frame.extend_from_slice(header.as_bytes());
        frame.extend_from_slice(b"\r\n");
    }
    frame.extend_from_slice(b"\r\n");
    frame.extend_from_slice(pipeline);
    frame
}

/// Independent wire oracle (NOT derived from production).
const EXPECT_HTTP_505: &[u8] =
    b"HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/// Case A: the pure validator rejects and accepts exactly per rule class.
#[test]
fn strict_validate_table_rejects_and_accepts_per_rule() {
    #[rustfmt::skip]
    let rejected: [(&str, &[&str], &str); 63] = [
        // Bracketed but not an IPv6 address (only hex digits and colons).
        (
            "CONNECT [:::]:443 HTTP/1.1",
            &["Host: h"],
            "strict HTTP: bracketed authority is not an IPv6 address",
        ),
        // A control character inside a field name is an invalid token.
        ("CONNECT h:443 HTTP/1.1", &["X\u{1}Y: v"], "strict HTTP: invalid header field name"),
        // Duplicate Host is rejected for HTTP/1.0 as well.
        ("CONNECT h:443 HTTP/1.0", &["Host: a", "Host: b"], "strict HTTP: duplicate Host header"),
        ("CONNECT h:1 HTTP/garbage", &[], "strict HTTP: malformed HTTP-version"),
        ("CONNECT h:1 HTTP/1.1 extra", &[], "strict HTTP: malformed request line"),
        ("CONNECT h:1 http/1.1", &[], "strict HTTP: malformed HTTP-version"),
        ("CONNECT h:1 HTTP/11", &[], "strict HTTP: malformed HTTP-version"),
        ("CONNECT h:1 HTTP/1.", &[], "strict HTTP: malformed HTTP-version"),
        ("CONNECT h:1 HTTP/1.10", &[], "strict HTTP: malformed HTTP-version"),
        ("CONNECT  h:1 HTTP/1.1", &[], "strict HTTP: malformed request line"), // two spaces
        ("CONNECT h:1 HTTP/1.1 ", &[], "strict HTTP: malformed request line"), // trailing space
        ("CONNECT h:1 HTTP/2.0", &[], "505"),
        ("CONNECT h:1 HTTP/0.9", &[], "505"),
        ("CONNECT h:1 HTTP/1.2", &[], "505"),
        ("CONNECT ::1:443 HTTP/1.1", &[], "strict HTTP: bare IPv6 authority"),
        ("CONNECT 2001:db8::1:443 HTTP/1.1", &[], "strict HTTP: bare IPv6 authority"),
        ("CONNECT h:+80 HTTP/1.1", &[], "strict HTTP: invalid authority port"),
        ("CONNECT h:0 HTTP/1.1", &[], "strict HTTP: invalid authority port"),
        ("CONNECT h:65536 HTTP/1.1", &[], "strict HTTP: invalid authority port"),
        ("CONNECT h: HTTP/1.1", &[], "strict HTTP: invalid authority port"),
        ("CONNECT h HTTP/1.1", &[], "strict HTTP: authority is missing a port"),
        ("CONNECT :443 HTTP/1.1", &[], "strict HTTP: authority host is empty"),
        ("CONNECT h:80a HTTP/1.1", &[], "strict HTTP: invalid authority port"),
        ("CONNECT [::1] HTTP/1.1", &[], "strict HTTP: authority is missing a port"),
        ("CONNECT [h]:80 HTTP/1.1", &[], "strict HTTP: bracketed authority is not an IPv6 address"),
        ("CONNECT h:443 HTTP/1.1", &["X-Other: v"], "strict HTTP: missing Host header"),
        ("CONNECT h:443 HTTP/1.1", &["Host:"], "strict HTTP: empty Host header"),
        ("CONNECT h:443 HTTP/1.1", &["Host:   "], "strict HTTP: empty Host header"),
        (
            "CONNECT h:443 HTTP/1.1",
            &["Host: h:1", "host: h:1"],
            "strict HTTP: duplicate Host header",
        ),
        (
            "CONNECT h:443 HTTP/1.1",
            &["Host: h:1", "HOST: h:1"],
            "strict HTTP: duplicate Host header",
        ),
        ("CONNECT h:443 HTTP/1.1", &["Host : h:1"], "strict HTTP: whitespace before header colon"),
        (
            "CONNECT h:443 HTTP/1.1",
            &["X-No-Colon-Value"],
            "strict HTTP: header line is missing a colon",
        ),
        ("CONNECT h:443 HTTP/1.1", &[" X-Opaque: v"], "strict HTTP: obsolete line folding"),
        ("CONNECT h:443 HTTP/1.1", &[": v"], "strict HTTP: empty header field name"),
        ("CONNECT h:443 HTTP/1.1", &["X Bad(Name): v"], "strict HTTP: invalid header field name"),
        (
            "CONNECT h:443 HTTP/1.1",
            &[
                "Host: h:443",
                "Proxy-Authorization: Basic dXNlcjpwYXNz",
                "Proxy-Authorization: Basic dXNlcjpwYXNz",
            ],
            "strict HTTP: duplicate Proxy-Authorization header",
        ),
        // Authority host grammar: CONNECT authorities carry no path/userinfo.
        (
            "CONNECT example.com/path:443 HTTP/1.1",
            &["Host: h"],
            "strict HTTP: invalid authority host",
        ),
        (
            "CONNECT user@example.com:443 HTTP/1.1",
            &["Host: h"],
            "strict HTTP: invalid authority host",
        ),
        ("CONNECT example.com?x:443 HTTP/1.1", &["Host: h"], "strict HTTP: invalid authority host"),
        ("CONNECT example.com#f:443 HTTP/1.1", &["Host: h"], "strict HTTP: invalid authority host"),
        // A backslash is neither unreserved nor a sub-delim.
        ("CONNECT bad\\host:443 HTTP/1.1", &["Host: h"], "strict HTTP: invalid authority host"),
        // Percent-escapes need exactly two hex digits.
        (
            "CONNECT bad%zz.example:443 HTTP/1.1",
            &["Host: h"],
            "strict HTTP: invalid authority host",
        ),
        ("CONNECT %2:443 HTTP/1.1", &["Host: h"], "strict HTTP: invalid authority host"),
        ("CONNECT bad%:443 HTTP/1.1", &["Host: h"], "strict HTTP: invalid authority host"),
        // A space splits the request line before any host grammar runs.
        ("CONNECT exa mple.com:443 HTTP/1.1", &[], "strict HTTP: malformed request line"),
        // CTL bytes in field values: NUL, 0x1F, and 0x7F, in any header.
        (
            "CONNECT h:443 HTTP/1.1",
            &["Host: h:443", "X: a\u{0}b"],
            "strict HTTP: invalid header field value",
        ),
        (
            "CONNECT h:443 HTTP/1.1",
            &["Host: h:443", "X: v\u{1f}"],
            "strict HTTP: invalid header field value",
        ),
        (
            "CONNECT h:443 HTTP/1.1",
            &["Host: h:443", "X: v\u{7f}"],
            "strict HTTP: invalid header field value",
        ),
        ("CONNECT h:443 HTTP/1.1", &["Host: a\u{0}b"], "strict HTTP: invalid header field value"),
        (
            "CONNECT h:443 HTTP/1.1",
            &["Host: h:443", "Proxy-Authorization: Basic a\u{0}b"],
            "strict HTTP: invalid header field value",
        ),
        // Strict Host grammar (RFC 9110 section 7.2): uri-host [ ":" port ], port = *DIGIT.
        ("CONNECT h:1 HTTP/1.1", &["Host: bad/path"], "strict HTTP: invalid Host header"),
        ("CONNECT h:1 HTTP/1.1", &["Host: user@example.com"], "strict HTTP: invalid Host header"),
        ("CONNECT h:1 HTTP/1.1", &["Host: bad%zz.example"], "strict HTTP: invalid Host header"),
        ("CONNECT h:1 HTTP/1.1", &["Host: h:abc"], "strict HTTP: invalid Host header"),
        ("CONNECT h:1 HTTP/1.1", &["Host: h:1a"], "strict HTTP: invalid Host header"),
        ("CONNECT h:1 HTTP/1.1", &["Host: [::1"], "strict HTTP: invalid Host header"),
        ("CONNECT h:1 HTTP/1.1", &["Host: a b"], "strict HTTP: invalid Host header"),
        ("CONNECT h:1 HTTP/1.1", &["Host: ::1"], "strict HTTP: invalid Host header"),
        // IPvFuture needs 1*HEXDIG, then '.', then a non-empty tail.
        ("CONNECT h:1 HTTP/1.1", &["Host: [v.x]"], "strict HTTP: invalid Host header"),
        ("CONNECT h:1 HTTP/1.1", &["Host: [v1.]"], "strict HTTP: invalid Host header"),
        ("CONNECT h:1 HTTP/1.1", &["Host: [V.x]"], "strict HTTP: invalid Host header"),
        ("CONNECT h:1 HTTP/1.1", &["Host: [V1.]"], "strict HTTP: invalid Host header"),
        ("CONNECT h:1 HTTP/1.1", &["Host: [w1.x]"], "strict HTTP: invalid Host header"),
    ];
    for (request_line, headers, want) in rejected {
        let hdrs: Vec<&[u8]> = headers.iter().map(|h| h.as_bytes()).collect();
        match validate(request_line, &hdrs) {
            Err(StrictViolation::Bad(reason)) => assert_eq!(reason, want, "{request_line:?}"),
            Err(StrictViolation::Unsupported) => assert_eq!(want, "505", "{request_line:?}"),
            Ok(()) => panic!("expected rejection for {request_line:?}"),
        }
    }

    #[rustfmt::skip]
    let accepted: [(&str, &[&str]); 34] = [
        // IPv4-embedded IPv6 is a valid bracketed literal.
        (
            "CONNECT [::ffff:192.0.2.1]:443 HTTP/1.1",
            &["Host: [::ffff:192.0.2.1]:443"],
        ),
        ("CONNECT h:443 HTTP/1.1", &["Host: h:443"]),
        ("CONNECT h:443 HTTP/1.0", &[]),
        ("CONNECT [::1]:443 HTTP/1.1", &["Host: [::1]:443"]),
        ("CONNECT [2001:db8::1]:8080 HTTP/1.1", &["Host: example"]),
        ("CONNECT h:1 HTTP/1.1", &["Host: h:1"]),
        ("CONNECT h:65535 HTTP/1.1", &["Host: h"]),
        ("CONNECT h:443 HTTP/1.1", &["host: h:443"]), // lowercase name
        ("CONNECT h:443 HTTP/1.1", &["Host: other.example"]), // Host != target allowed
        (
            "CONNECT h:443 HTTP/1.1",
            &[
                "Host: h:443",
                "User-Agent: test",
                "Proxy-Connection: keep-alive",
            ],
        ),
        (
            "CONNECT h:443 HTTP/1.1",
            &["Proxy-Authorization: Basic dXNlcjpwYXNz", "Host: h:443"],
        ),
        // Authority host grammar accepts reg-names, IPv4, bracketed IPv6,
        // and well-formed percent-escapes.
        (
            "CONNECT example.com:443 HTTP/1.1",
            &["Host: example.com:443"],
        ),
        (
            "CONNECT a-b_c.example:443 HTTP/1.1",
            &["Host: a-b_c.example"],
        ),
        ("CONNECT 192.0.2.1:443 HTTP/1.1", &["Host: 192.0.2.1"]),
        (
            "CONNECT [2001:db8::1]:443 HTTP/1.1",
            &["Host: [2001:db8::1]:443"],
        ),
        (
            "CONNECT ex%41mple.com:443 HTTP/1.1",
            &["Host: ex%41mple.com"],
        ),
        // HTAB and obs-text bytes stay legal in field values.
        ("CONNECT h:443 HTTP/1.1", &["Host: h:443", "X-T: a\u{9}b"]),
        (
            "CONNECT h:443 HTTP/1.1",
            &["Host: h:443", "X-T: v\u{80}\u{ff}"],
        ),
        // Strict Host grammar (RFC 9110 section 7.2): reg-names, empty port,
        // any-digit port without range check, IPvFuture, bracketed IPv6, OWS.
        ("CONNECT h:1 HTTP/1.1", &["Host: example.com"]),
        ("CONNECT h:1 HTTP/1.1", &["Host: example.com:443"]),
        ("CONNECT h:1 HTTP/1.1", &["Host: example.com:"]), // empty port
        ("CONNECT h:1 HTTP/1.1", &["Host: h:000443"]), // leading zeros, 6 digits
        ("CONNECT h:1 HTTP/1.1", &["Host: h:0"]), // not range-checked
        ("CONNECT h:1 HTTP/1.1", &["Host: h:99999"]), // not range-checked
        ("CONNECT h:1 HTTP/1.1", &["Host: 192.0.2.1:80"]),
        ("CONNECT h:1 HTTP/1.1", &["Host: [::1]:443"]),
        ("CONNECT h:1 HTTP/1.1", &["Host: [::1]:0"]),
        ("CONNECT h:1 HTTP/1.1", &["Host: [2001:db8::1]"]),
        ("CONNECT h:1 HTTP/1.1", &["Host: [v1.example]"]), // IPvFuture
        ("CONNECT h:1 HTTP/1.1", &["Host: [V1.example]"]), // IPvFuture, uppercase V (ABNF "v")
        ("CONNECT h:1 HTTP/1.1", &["Host: [VaF.x:80]:443"]), // hex digits of either case
        ("CONNECT h:1 HTTP/1.1", &["Host: [v1.a:b]"]), // IPvFuture tail with ':'
        ("CONNECT h:1 HTTP/1.1", &["Host: ex%41mple.com"]),
        ("CONNECT h:1 HTTP/1.1", &["Host: example.com  "]), // trailing OWS trimmed
    ];
    for (request_line, headers) in accepted {
        let hdrs: Vec<&[u8]> = headers.iter().map(|h| h.as_bytes()).collect();
        assert!(validate(request_line, &hdrs).is_ok(), "{request_line:?}");
    }
}

/// Drive one strict-mode request through `accept`; returns the result and the
/// client-side bytes read to EOF after the server side is dropped.
async fn strict_reject(
    frame: &[u8],
    opts: ServerOptions,
) -> (Result<IncomingRequest, ServerError>, Vec<u8>) {
    let (mut peer, mut server) = duplex(4096);
    peer.write_all(frame).await.unwrap();
    let result = accept(&mut server, &opts).await;
    drop(server);
    let mut response = Vec::new();
    peer.read_to_end(&mut response).await.unwrap();
    // Every strict rejection, including 505, is a `ServerError::Protocol`.
    if let Err(error) = &result {
        assert!(matches!(error, ServerError::Protocol(_)), "{error:?}");
    }
    (result, response)
}

/// Case B: each violation class is answered with the exact wire head and reason.
#[tokio::test]
async fn strict_end_to_end_rejects_per_rule_class() {
    timeout(Duration::from_secs(10), async {
        let opts = || anon_options(false).strict_http(true);
        let token = "dXNlcjpwYXNz"; // base64("user:pass")

        // (1) Malformed request line (two spaces).
        let frame = http_req("CONNECT  h:1 HTTP/1.1", &[], b"");
        let (result, response) = strict_reject(&frame, opts()).await;
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "strict HTTP: malformed request line");
        assert_eq!(response, EXPECT_HTTP_400);

        // (2) Malformed HTTP-version.
        let frame = http_req("CONNECT h:1 HTTP/garbage", &["Host: h"], b"");
        let (result, response) = strict_reject(&frame, opts()).await;
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "strict HTTP: malformed HTTP-version");
        assert_eq!(response, EXPECT_HTTP_400);

        // (3) Unsupported HTTP-version answers 505 (no reason text).
        let frame = http_req("CONNECT h:1 HTTP/2.0", &["Host: h"], b"");
        let (result, response) = strict_reject(&frame, opts()).await;
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "strict HTTP: unsupported HTTP-version");
        assert_eq!(response, EXPECT_HTTP_505);

        // (4) Bare IPv6 authority.
        let frame = http_req("CONNECT ::1:443 HTTP/1.1", &["Host: h"], b"");
        let (result, response) = strict_reject(&frame, opts()).await;
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "strict HTTP: bare IPv6 authority");
        assert_eq!(response, EXPECT_HTTP_400);

        // (5) Invalid authority port.
        let frame = http_req("CONNECT h:0 HTTP/1.1", &["Host: h"], b"");
        let (result, response) = strict_reject(&frame, opts()).await;
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "strict HTTP: invalid authority port");
        assert_eq!(response, EXPECT_HTTP_400);

        // (6) Missing Host despite a VALID Proxy-Authorization: never authenticated.
        let auth = format!("Proxy-Authorization: Basic {token}");
        let frame = http_req("CONNECT h:443 HTTP/1.1", &[auth.as_str()], b"");
        let (result, response) = strict_reject(&frame, opts()).await;
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "strict HTTP: missing Host header");
        assert_eq!(response, EXPECT_HTTP_400);

        // (7) Duplicate Host.
        let frame = http_req("CONNECT h:443 HTTP/1.1", &["Host: h:1", "Host: h:1"], b"");
        let (result, response) = strict_reject(&frame, opts()).await;
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "strict HTTP: duplicate Host header");
        assert_eq!(response, EXPECT_HTTP_400);

        // (8) Obsolete line folding.
        let frame = http_req(
            "CONNECT h:443 HTTP/1.1",
            &["Host: h:443", " X-Opaque: v"],
            b"",
        );
        let (result, response) = strict_reject(&frame, opts()).await;
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "strict HTTP: obsolete line folding");
        assert_eq!(response, EXPECT_HTTP_400);

        // (9) Duplicate Proxy-Authorization (valid token twice): never authenticated.
        let auth = format!("Proxy-Authorization: Basic {token}");
        let frame = http_req(
            "CONNECT h:443 HTTP/1.1",
            &["Host: h:443", auth.as_str(), auth.as_str()],
            b"",
        );
        let (result, response) = strict_reject(&frame, opts()).await;
        let err = result.unwrap_err();
        assert_eq!(
            err.to_string(),
            "strict HTTP: duplicate Proxy-Authorization header"
        );
        assert_eq!(response, EXPECT_HTTP_400);
    })
    .await
    .expect("bounded strict_end_to_end_rejects_per_rule_class");
}

/// Case B: authority-grammar and field-value violations answer 400 before any
/// authentication, and the grammar's accept set is served end to end.
#[tokio::test]
async fn strict_end_to_end_authority_grammar_and_field_values() {
    timeout(Duration::from_secs(10), async {
        let opts = || anon_options(false).strict_http(true);
        let token = "dXNlcjpwYXNz"; // base64("user:pass")
        let auth = format!("Proxy-Authorization: Basic {token}");

        // (1) Path inside the authority: 400, never authenticated.
        let frame = http_req(
            "CONNECT example.com/path:443 HTTP/1.1",
            &[auth.as_str()],
            b"",
        );
        let (result, response) = strict_reject(&frame, opts()).await;
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "strict HTTP: invalid authority host");
        assert_eq!(response, EXPECT_HTTP_400);

        // (2) userinfo-style '@' inside the authority.
        let frame = http_req(
            "CONNECT user@example.com:443 HTTP/1.1",
            &[auth.as_str()],
            b"",
        );
        let (result, response) = strict_reject(&frame, opts()).await;
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "strict HTTP: invalid authority host");
        assert_eq!(response, EXPECT_HTTP_400);

        // (3) NUL in a field value despite a VALID auth header.
        let frame = http_req(
            "CONNECT h:443 HTTP/1.1",
            &["Host: h:443", auth.as_str(), "X-Evil: a\u{0}b"],
            b"",
        );
        let (result, response) = strict_reject(&frame, opts()).await;
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "strict HTTP: invalid header field value");
        assert_eq!(response, EXPECT_HTTP_400);

        // (4) 0x1F inside the Host value despite a VALID auth header.
        let frame = http_req(
            "CONNECT h:443 HTTP/1.1",
            &["Host: a\u{1f}b", auth.as_str()],
            b"",
        );
        let (result, response) = strict_reject(&frame, opts()).await;
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "strict HTTP: invalid header field value");
        assert_eq!(response, EXPECT_HTTP_400);

        // (5) 0x7F inside the Proxy-Authorization value itself.
        let evil_auth = format!("Proxy-Authorization: Basic {token}\u{7f}");
        let frame = http_req(
            "CONNECT h:443 HTTP/1.1",
            &["Host: h:443", evil_auth.as_str()],
            b"",
        );
        let (result, response) = strict_reject(&frame, opts()).await;
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "strict HTTP: invalid header field value");
        assert_eq!(response, EXPECT_HTTP_400);

        // (6) Accept: IPv4 and reg-name authorities are served, target intact.
        for target in ["192.0.2.1:443", "a-b_c.example:443"] {
            let frame = http_req(
                &format!("CONNECT {target} HTTP/1.1"),
                &[&format!("Host: {target}")],
                b"",
            );
            let (mut peer, mut server) = duplex(4096);
            peer.write_all(&frame).await.unwrap();
            let result = accept(&mut server, &anon_options(true).strict_http(true)).await;
            drop(server);
            peer.read_to_end(&mut Vec::new()).await.unwrap();
            let req = result.expect("strict authority accepted");
            assert_eq!(req.target(), target);
        }

        // (7) Accept: HTAB inside a field value stays legal end to end.
        let frame = http_req(
            "CONNECT h:443 HTTP/1.1",
            &["Host: h:443", "X-T: a\u{9}b"],
            b"",
        );
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(&frame).await.unwrap();
        let result = accept(&mut server, &anon_options(true).strict_http(true)).await;
        drop(server);
        peer.read_to_end(&mut Vec::new()).await.unwrap();
        assert_eq!(result.expect("HTAB value accepted").target(), "h:443");
    })
    .await
    .expect("bounded strict_end_to_end_authority_grammar_and_field_values");
}

/// Case C: browser-like and curl-like strict requests connect anonymously.
#[tokio::test]
async fn strict_on_accepts_browser_and_curl_requests() {
    timeout(Duration::from_secs(10), async {
        // Browser-like frame.
        let frame = http_req(
            "CONNECT h:443 HTTP/1.1",
            &[
                "Host: h:443",
                "User-Agent: test",
                "Proxy-Connection: keep-alive",
            ],
            b"",
        );
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(&frame).await.unwrap();
        let result = accept(&mut server, &anon_options(true).strict_http(true)).await;
        drop(server);
        peer.read_to_end(&mut Vec::new()).await.unwrap();
        let req = result.expect("browser-like strict request accepted");
        assert_eq!(req.username(), None);
        assert_eq!(req.target(), "h:443");

        // Curl-like frame (HTTP/1.0: Host is optional).
        let frame = http_req("CONNECT h:443 HTTP/1.0", &[], b"");
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(&frame).await.unwrap();
        let result = accept(&mut server, &anon_options(true).strict_http(true)).await;
        drop(server);
        peer.read_to_end(&mut Vec::new()).await.unwrap();
        let req = result.expect("curl-like strict request accepted");
        assert_eq!(req.username(), None);
        assert_eq!(req.target(), "h:443");
    })
    .await
    .expect("bounded strict_on_accepts_browser_and_curl_requests");
}

/// Case C: strict anonymous acceptance keeps the pipelined payload intact.
#[tokio::test]
async fn strict_on_anonymous_and_pipelined_payload() {
    timeout(Duration::from_secs(10), async {
        let frame = http_req(
            "CONNECT h:443 HTTP/1.1",
            &[
                "Host: h:443",
                "User-Agent: test",
                "Proxy-Connection: keep-alive",
            ],
            b"PIPE-STRICT-1",
        );
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(&frame).await.unwrap();
        let result = accept(&mut server, &anon_options(true).strict_http(true)).await;
        drop(server);
        peer.read_to_end(&mut Vec::new()).await.unwrap();
        let mut req = result.expect("anonymous strict request accepted");
        assert_eq!(req.username(), None);
        assert_eq!(req.pipeline(), b"PIPE-STRICT-1");
        assert_eq!(req.take_pipeline(), b"PIPE-STRICT-1");
    })
    .await
    .expect("bounded strict_on_anonymous_and_pipelined_payload");
}

/// Case C: a bracketed IPv6 authority is accepted with the brackets preserved.
#[tokio::test]
async fn strict_on_keeps_bracketed_ipv6_target() {
    timeout(Duration::from_secs(10), async {
        let frame = http_req("CONNECT [::1]:443 HTTP/1.1", &["Host: [::1]:443"], b"");
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(&frame).await.unwrap();
        // Anonymous access is allowed, so a request with no credentials passes.
        let result = accept(&mut server, &anon_options(true).strict_http(true)).await;
        drop(server);
        peer.read_to_end(&mut Vec::new()).await.unwrap();
        let req = result.expect("bracketed IPv6 strict request accepted");
        assert_eq!(req.target(), "[::1]:443");
    })
    .await
    .expect("bounded strict_on_keeps_bracketed_ipv6_target");
}

/// Case C: without anonymous access, a strict request without credentials gets 407.
#[tokio::test]
async fn strict_on_still_answers_407_when_anonymous_is_not_allowed() {
    timeout(Duration::from_secs(10), async {
        let frame = http_req(
            "CONNECT h:443 HTTP/1.1",
            &[
                "Host: h:443",
                "User-Agent: test",
                "Proxy-Connection: keep-alive",
            ],
            b"",
        );
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(&frame).await.unwrap();
        let result = accept(&mut server, &anon_options(false).strict_http(true)).await;
        drop(server);
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        assert!(matches!(result, Err(ServerError::Authentication(_))));
        // No scheme is enabled on this server: the bare closing 407.
        assert_eq!(response, EXPECT_HTTP_407_BARE_CLOSE);
    })
    .await
    .expect("bounded strict_on_still_answers_407_when_anonymous_is_not_allowed");
}

/// Case D: with strict off (the default) the lenient behaviours stay pinned.
#[tokio::test]
async fn strict_off_default_keeps_lenient_behaviour() {
    timeout(Duration::from_secs(10), async {
        // White-box: the flag defaults off and strict_http(false) matches the default.
        assert!(!anon_options(false).strict_http);
        assert!(!ServerOptions::new(Instant::now()).strict_http);
        let off = anon_options(false).strict_http(false);
        assert!(!off.strict_http);
        assert_eq!(off.anonymous, anon_options(false).anonymous);
        assert_eq!(off.cleartext, anon_options(false).cleartext);

        // Lenient pins, all with the flag off.
        let lenient = [
            // HostPort::parse accepts a bare IPv6 (::1 parses as Ipv6Addr) — pinned current behaviour.
            (http_req("CONNECT ::1:443 HTTP/1.1", &[], b""), "::1:443"),
            // u16::from_str accepts a leading '+' — pinned current behaviour.
            (http_req("CONNECT h:+80 HTTP/1.1", &[], b""), "h:+80"),
            // port 0 parses as u16 with no range check — pinned current behaviour.
            (http_req("CONNECT h:0 HTTP/1.1", &[], b""), "h:0"),
            // version check is only the HTTP/ prefix — pinned current behaviour.
            (http_req("CONNECT h:1 HTTP/garbage", &[], b""), "h:1"),
            // HostPort::parse accepts a path in the authority — pinned current behaviour.
            (
                http_req("CONNECT example.com/path:443 HTTP/1.1", &[], b""),
                "example.com/path:443",
            ),
            // Header field values are never byte-checked without strict — pinned current behaviour.
            (
                http_req("CONNECT h:443 HTTP/1.1", &["X: a\u{0}b"], b""),
                "h:443",
            ),
            // no Host header is required — pinned current behaviour.
            (http_req("CONNECT h:1 HTTP/1.1", &[], b""), "h:1"),
            // a header line without a colon is skipped — pinned current behaviour.
            (
                http_req("CONNECT h:1 HTTP/1.1", &["X-Opaque v"], b""),
                "h:1",
            ),
            // whitespace before the colon is tolerated — pinned current behaviour.
            (
                http_req("CONNECT h:1 HTTP/1.1", &["Host : h:1"], b""),
                "h:1",
            ),
            // duplicate Host headers are ignored — pinned current behaviour.
            (
                http_req("CONNECT h:1 HTTP/1.1", &["Host: a:1", "Host: b:2"], b""),
                "h:1",
            ),
        ];
        for (frame, want_target) in lenient {
            let (mut peer, mut server) = duplex(4096);
            peer.write_all(&frame).await.unwrap();
            let result = accept(&mut server, &anon_options(true)).await;
            drop(server);
            peer.read_to_end(&mut Vec::new()).await.unwrap();
            let req = result.expect("lenient request accepted");
            assert_eq!(req.target(), want_target, "{frame:?}");
        }

        // Duplicate Proxy-Authorization headers: any Proxy-Authorization is a
        // 407 (never authenticated) in lenient mode too.
        let first = "Proxy-Authorization: Basic dXNlcjE6cGFzczE=";
        let second = "Proxy-Authorization: Basic dXNlcjI6cGFzczI=";
        let frame = http_req("CONNECT h:1 HTTP/1.1", &[first, second], b"");
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(&frame).await.unwrap();
        let result = accept(&mut server, &anon_options(true)).await;
        drop(server);
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        assert!(matches!(result, Err(ServerError::Authentication(_))));
        assert_eq!(response, EXPECT_HTTP_407_BARE_CLOSE);
    })
    .await
    .expect("bounded strict_off_default_keeps_lenient_behaviour");
}

/// Case E: the builder chains, copies, and keeps deadline semantics first.
#[tokio::test]
async fn strict_http_options_chain_deadline_and_copy() {
    timeout(Duration::from_secs(10), async {
        // White-box: default off.
        assert!(!anon_options(false).strict_http);

        let opts = anon_options(false).strict_http(true);
        assert!(opts.strict_http);
        assert!(!opts.anonymous);
        assert!(opts.cleartext);

        // Copy semantics: reading through both after the copy compiles only for Copy.
        let copy = opts;
        assert!(copy.strict_http);
        assert!(opts.strict_http);

        // An expired deadline refuses BEFORE any strict check.
        let expired = ServerOptions::new(Instant::now())
            .allow_anonymous(true)
            .allow_cleartext(true)
            .strict_http(true);
        let frame = http_req("CONNECT h:443 HTTP/1.1", &["Host: h:443"], b"");
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(&frame).await.unwrap();
        let result = accept(&mut server, &expired).await;
        drop(server);
        peer.read_to_end(&mut Vec::new()).await.unwrap();
        assert!(matches!(result, Err(ServerError::Deadline)));
    })
    .await
    .expect("bounded strict_http_options_chain_deadline_and_copy");
}

/// Case F: strict HTTP never disturbs the SOCKS5 paths.
#[tokio::test]
async fn strict_http_leaves_socks5_untouched() {
    timeout(Duration::from_secs(10), async {
        // Anonymous is enabled: the no-auth client offers method 0 only, the
        // password client method 2 only, which is never selected.
        let opts = anon_options(true).strict_http(true);

        // (a) No-auth SOCKS5.
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(&socks_request(b"h")).await.unwrap();
        let result = accept(&mut server, &opts).await;
        drop(server);
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        let req = result.expect("no-auth socks accepted under strict_http");
        assert_eq!(req.target(), "h:443");
        assert_eq!(response, [5, 0]);

        // (b) Password SOCKS5 is refused: method 2 does not exist here.
        let mut frame = [5u8, 1, 2].to_vec();
        frame.extend_from_slice(&[1, 10]);
        frame.extend_from_slice(b"socks-user");
        frame.extend_from_slice(&[10]);
        frame.extend_from_slice(b"socks-pass");
        frame.extend_from_slice(&socks_request(b"h")[3..]);
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(&frame).await.unwrap();
        let result = accept(&mut server, &opts).await;
        drop(server);
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        assert!(matches!(result, Err(ServerError::Authentication(_))));
        assert_eq!(response, [5, 255]);
    })
    .await
    .expect("bounded strict_http_leaves_socks5_untouched");
}
