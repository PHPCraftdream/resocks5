//! The `;gssapi=` option of an upstream list entry.

use resocks5_net::types::ProxyProtocol;

use super::startup::{parse_proxy_list_checked, split_gssapi_option};

/// The option is split off the end only; credentials with a semicolon, and an
/// empty option, stay part of the entry. Mutation: splitting at the first
/// `;` mangles a password.
#[test]
fn the_option_is_split_off_the_end_of_the_entry() {
    assert_eq!(
        split_gssapi_option("10.0.0.1:1080;gssapi=socks@up.example.com"),
        ("10.0.0.1:1080", Some("socks@up.example.com"))
    );
    assert_eq!(
        split_gssapi_option("u:p;a;b@10.0.0.1:1080;gssapi=socks@h"),
        ("u:p;a;b@10.0.0.1:1080", Some("socks@h"))
    );
    assert_eq!(
        split_gssapi_option("u:p;gssapi=x@10.0.0.1:1080"),
        ("u:p;gssapi=x@10.0.0.1:1080", None)
    );
    assert_eq!(
        split_gssapi_option("10.0.0.1:1080;gssapi="),
        ("10.0.0.1:1080;gssapi=", None)
    );
}

/// Without the Kerberos backend a GSSAPI entry is dropped, not silently
/// downgraded to an unauthenticated upstream; an HTTP upstream cannot use
/// GSSAPI at all. Plain entries are unaffected. Mutation: keeping the entry
/// would dial an upstream that was meant to be authenticated.
#[cfg(not(feature = "gssapi-system"))]
#[test]
fn a_gssapi_entry_without_a_backend_is_dropped() {
    let list = vec![
        "10.0.0.1:1080;gssapi=socks@up.example.com".to_string(),
        "10.0.0.2:1080".to_string(),
    ];
    let (parsed, failed) = parse_proxy_list_checked(&list, ProxyProtocol::Socks5);
    assert_eq!(failed, vec![1]);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].host, "10.0.0.2");

    let http = vec!["10.0.0.3:8080;gssapi=socks@h".to_string()];
    let (parsed, failed) = parse_proxy_list_checked(&http, ProxyProtocol::Http);
    assert!(parsed.is_empty());
    assert_eq!(failed, vec![1]);
}
