//! E2E dial tests for the outbound (upstream) auth resolution path:
//! `parse_proxy_list_checked` → `apply_upstream_auth` →
//! `resocks5_net::connect::dial` against a scripted cleartext-only
//! upstream. `MockAuth::Cleartext` is the contract that the mock speaks
//! SOCKS5 0x02 / HTTP Basic only — it never accepts our secure method,
//! so a secure-only entry must be refused before any password is sent.

use std::time::Duration;

use resocks5_net::connect::{dial_plain, ConnectError, DialOptions};
use resocks5_net::testing::{MockAuth, MockUpstream};
use resocks5_net::types::ProxyProtocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::startup::parse_proxy_list_checked;

/// Overall bound for one dial; each dial additionally carries its own
/// handshake budget. Deterministic: loopback only, no sleeps.
const DIAL_CAP: Duration = Duration::from_secs(30);

fn dial_opts() -> DialOptions {
    DialOptions::new().with_handshake_timeout(Duration::from_secs(10))
}

/// An entry marked `;secure_only` must refuse a cleartext-only upstream:
/// no Basic can be sent, so the dial fails before any password crosses
/// the wire. Mutation: dropping the `;secure_only` flag from the
/// resolution makes the dial succeed (Basic sent).
#[tokio::test]
async fn an_entry_marked_secure_only_refuses_a_cleartext_only_upstream() {
    let mock = MockUpstream::http()
        .auth(MockAuth::Cleartext {
            user: "u".into(),
            password: "p".into(),
        })
        .spawn()
        .await
        .expect("mock spawn");
    let list = vec![format!("u:p@127.0.0.1:{};secure_only", mock.addr().port())];
    let (parsed, failed) = parse_proxy_list_checked(&list, ProxyProtocol::Http, false);
    assert!(failed.is_empty(), "entry must parse: {failed:?}");
    let error = tokio::time::timeout(
        DIAL_CAP,
        dial_plain(&parsed[0], "example.test", 80, &dial_opts()),
    )
    .await
    .expect("test guard")
    .err()
    .expect("secure-only entry must refuse a cleartext-only upstream");
    assert!(
        matches!(error, ConnectError::CleartextCredentialsRefused),
        "{error:?}"
    );
    assert!(
        mock.targets().is_empty(),
        "no CONNECT may pass authentication: {:?}",
        mock.targets()
    );
}

/// Without the flag (and without the global switch) a plain entry keeps
/// its clear-text fallback: the old configs still dial and tunnel.
/// Mutation: a resolution that refuses clear text by default breaks old
/// configs.
#[tokio::test]
async fn a_plain_entry_still_dials_a_cleartext_upstream_by_default() {
    let mock = MockUpstream::http()
        .auth(MockAuth::Cleartext {
            user: "u".into(),
            password: "p".into(),
        })
        .spawn()
        .await
        .expect("mock spawn");
    let list = vec![format!("u:p@127.0.0.1:{}", mock.addr().port())];
    let (parsed, failed) = parse_proxy_list_checked(&list, ProxyProtocol::Http, false);
    assert!(failed.is_empty(), "entry must parse: {failed:?}");
    let mut tunnel = tokio::time::timeout(
        DIAL_CAP,
        dial_plain(&parsed[0], "example.test", 80, &dial_opts()),
    )
    .await
    .expect("test guard")
    .expect("plain entry must dial a cleartext upstream by default");
    tunnel.write_all(b"p").await.expect("tunnel write");
    let mut back = [0u8; 1];
    tunnel.read_exact(&mut back).await.expect("tunnel echo");
    assert_eq!(&back, b"p");
    assert_eq!(mock.targets(), vec!["example.test:80".to_string()]);
}

/// The global `upstream_auth.secure_only` switch forces our-method-only
/// even for an entry without the flag. Mutation: ignoring the global
/// switch re-admits Basic.
#[tokio::test]
async fn the_global_secure_only_switch_forces_the_secure_mode() {
    let mock = MockUpstream::http()
        .auth(MockAuth::Cleartext {
            user: "u".into(),
            password: "p".into(),
        })
        .spawn()
        .await
        .expect("mock spawn");
    let list = vec![format!("u:p@127.0.0.1:{}", mock.addr().port())];
    let (parsed, failed) = parse_proxy_list_checked(&list, ProxyProtocol::Http, true);
    assert!(failed.is_empty(), "entry must parse: {failed:?}");
    let error = tokio::time::timeout(
        DIAL_CAP,
        dial_plain(&parsed[0], "example.test", 80, &dial_opts()),
    )
    .await
    .expect("test guard")
    .err()
    .expect("global secure_only must refuse a cleartext-only upstream");
    assert!(
        matches!(error, ConnectError::CleartextCredentialsRefused),
        "{error:?}"
    );
    assert!(
        mock.targets().is_empty(),
        "no CONNECT may pass authentication: {:?}",
        mock.targets()
    );
}
