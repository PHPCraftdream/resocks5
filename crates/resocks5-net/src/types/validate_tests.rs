use std::error::Error as _;
use std::sync::Arc;

use super::{
    ChainConfigError, CredentialField, ProxyConfig, ProxyConfigError, ProxyProtocol,
    MAX_CHAIN_NODES,
};

fn cfg(protocol: ProxyProtocol, host: &str, port: u16) -> ProxyConfig {
    ProxyConfig::new(protocol, host, port)
}

fn with_pair(protocol: ProxyProtocol, user: &str, password: &str) -> ProxyConfig {
    ProxyConfig::new(protocol, "proxy.example", 1080).with_auth(user, password)
}

/// Build a chain from OUTERMOST first to exit last, as `ProxyConfig::chain`
/// expects: the fixture order is the reported error index order.
fn chained(nodes: Vec<ProxyConfig>) -> ProxyConfig {
    ProxyConfig::chain(nodes.into_iter().map(Arc::new)).expect("non-empty chain")
}

/// Host of every node, outermost first: the fixture-order cross-check.
fn hosts(chain: &ProxyConfig) -> Vec<&str> {
    chain
        .nodes()
        .iter()
        .map(|node| node.host.as_str())
        .collect()
}

// host
#[test]
fn host_rules_empty_invalid_and_valid() {
    assert_eq!(
        ProxyConfig::socks5("", 1080).validate_node(),
        Err(ProxyConfigError::EmptyHost)
    );
    for host in ["a b", "a/b", "a@b", "a\0b", "a\tb"] {
        assert_eq!(
            ProxyConfig::socks5(host, 1080).validate_node(),
            Err(ProxyConfigError::InvalidHost),
            "host {host:?}"
        );
    }
    for host in ["2001:db8::1", "proxy.example.com", "127.0.0.1"] {
        assert_eq!(
            ProxyConfig::socks5(host, 1080).validate_node(),
            Ok(()),
            "host {host:?}"
        );
    }
}

// port
#[test]
fn zero_port_rejected_nonzero_ok() {
    assert_eq!(
        cfg(ProxyProtocol::Socks5, "proxy.example", 0).validate_node(),
        Err(ProxyConfigError::ZeroPort)
    );
    assert_eq!(
        cfg(ProxyProtocol::Socks5, "proxy.example", 1).validate_node(),
        Ok(())
    );
}

// gate flag
#[test]
fn gate_flag_must_match_gate_level_both_ways() {
    let mut c = cfg(ProxyProtocol::Socks5, "proxy.example", 1080);
    c.is_gate = true;
    assert_eq!(
        c.validate_node(),
        Err(ProxyConfigError::InconsistentGateFlag)
    );
    c.gate_level = 1;
    c.is_gate = false;
    assert_eq!(
        c.validate_node(),
        Err(ProxyConfigError::InconsistentGateFlag)
    );
    c.is_gate = true;
    assert_eq!(c.validate_node(), Ok(()));
    c.is_gate = false;
    c.gate_level = 0;
    assert_eq!(c.validate_node(), Ok(()));
}

// credentials presence
#[test]
fn incomplete_credentials_rejected_for_every_protocol() {
    for protocol in [
        ProxyProtocol::Socks5,
        ProxyProtocol::Http,
        ProxyProtocol::Https,
    ] {
        let mut c = cfg(protocol, "proxy.example", 1080);
        c.user = Some("u".into());
        assert_eq!(
            c.validate_node(),
            Err(ProxyConfigError::IncompleteCredentials),
            "{protocol:?} user only"
        );
        let mut c = cfg(protocol, "proxy.example", 1080);
        c.password = Some("p".into());
        assert_eq!(
            c.validate_node(),
            Err(ProxyConfigError::IncompleteCredentials),
            "{protocol:?} password only"
        );
    }
}

#[test]
fn no_credentials_ok_for_every_protocol() {
    for protocol in [
        ProxyProtocol::Socks5,
        ProxyProtocol::Http,
        ProxyProtocol::Https,
    ] {
        let c = cfg(protocol, "proxy.example", 1080);
        assert_eq!(c.validate_node(), Ok(()), "{protocol:?}");
    }
}

// socks5 credential bounds
#[test]
fn socks5_username_length_bounds() {
    assert_eq!(
        with_pair(ProxyProtocol::Socks5, "", "p").validate_node(),
        Err(ProxyConfigError::EmptyCredential {
            field: CredentialField::Username
        })
    );
    assert_eq!(
        with_pair(ProxyProtocol::Socks5, "a", "p").validate_node(),
        Ok(())
    );
    assert_eq!(
        with_pair(ProxyProtocol::Socks5, &"a".repeat(255), "p").validate_node(),
        Ok(())
    );
    assert_eq!(
        with_pair(ProxyProtocol::Socks5, &"a".repeat(256), "p").validate_node(),
        Err(ProxyConfigError::CredentialTooLong {
            field: CredentialField::Username,
            len: 256
        })
    );
}

#[test]
fn socks5_password_length_bounds() {
    assert_eq!(
        with_pair(ProxyProtocol::Socks5, "u", "").validate_node(),
        Err(ProxyConfigError::EmptyCredential {
            field: CredentialField::Password
        })
    );
    assert_eq!(
        with_pair(ProxyProtocol::Socks5, "u", "p").validate_node(),
        Ok(())
    );
    assert_eq!(
        with_pair(ProxyProtocol::Socks5, "u", &"p".repeat(255)).validate_node(),
        Ok(())
    );
    assert_eq!(
        with_pair(ProxyProtocol::Socks5, "u", &"p".repeat(256)).validate_node(),
        Err(ProxyConfigError::CredentialTooLong {
            field: CredentialField::Password,
            len: 256
        })
    );
}

#[test]
fn socks5_bounds_count_bytes_not_chars() {
    // 127 chars of 2-byte 'é' plus one ASCII byte = 255 bytes.
    assert_eq!(
        with_pair(ProxyProtocol::Socks5, &format!("{}a", "é".repeat(127)), "p").validate_node(),
        Ok(())
    );
    assert_eq!(
        with_pair(ProxyProtocol::Socks5, &"é".repeat(128), "p").validate_node(),
        Err(ProxyConfigError::CredentialTooLong {
            field: CredentialField::Username,
            len: 256
        })
    );
    assert_eq!(
        with_pair(ProxyProtocol::Socks5, "u", &format!("{}a", "é".repeat(127))).validate_node(),
        Ok(())
    );
    assert_eq!(
        with_pair(ProxyProtocol::Socks5, "u", &"é".repeat(128)).validate_node(),
        Err(ProxyConfigError::CredentialTooLong {
            field: CredentialField::Password,
            len: 256
        })
    );
}

// http/https credential rules
#[test]
fn http_username_colon_rejected_password_colon_ok() {
    for protocol in [ProxyProtocol::Http, ProxyProtocol::Https] {
        assert_eq!(
            with_pair(protocol, "a:b", "p").validate_node(),
            Err(ProxyConfigError::UsernameContainsColon),
            "{protocol:?}"
        );
        assert_eq!(with_pair(protocol, "u", "a:b").validate_node(), Ok(()));
        assert_eq!(
            with_pair(protocol, ":", "p").validate_node(),
            Err(ProxyConfigError::UsernameContainsColon)
        );
    }
}

#[test]
fn http_control_characters_rejected_for_both_fields() {
    for protocol in [ProxyProtocol::Http, ProxyProtocol::Https] {
        for c in ['\0', '\t', '\n', '\r', '\x1f', '\x7f'] {
            assert_eq!(
                with_pair(protocol, &c.to_string(), "p").validate_node(),
                Err(ProxyConfigError::ControlCharacter {
                    field: CredentialField::Username
                }),
                "{protocol:?} username {c:?}"
            );
            assert_eq!(
                with_pair(protocol, "u", &c.to_string()).validate_node(),
                Err(ProxyConfigError::ControlCharacter {
                    field: CredentialField::Password
                }),
                "{protocol:?} password {c:?}"
            );
        }
    }
}

#[test]
fn http_empty_and_non_ascii_and_long_ok() {
    for protocol in [ProxyProtocol::Http, ProxyProtocol::Https] {
        assert_eq!(with_pair(protocol, "", "").validate_node(), Ok(()));
        assert_eq!(with_pair(protocol, "u", "").validate_node(), Ok(()));
        assert_eq!(with_pair(protocol, "", "p").validate_node(), Ok(()));
        assert_eq!(
            with_pair(protocol, "üser", "pässwort").validate_node(),
            Ok(())
        );
        assert_eq!(
            with_pair(protocol, &"u".repeat(300), "p").validate_node(),
            Ok(())
        );
    }
}

// check order
#[test]
fn checks_run_in_documented_order() {
    let mut c = ProxyConfig::new(ProxyProtocol::Socks5, "", 0);
    c.password = Some("p".into());
    c.is_gate = true;
    assert_eq!(c.validate_node(), Err(ProxyConfigError::EmptyHost));
    c.host = "proxy.example".into();
    assert_eq!(c.validate_node(), Err(ProxyConfigError::ZeroPort));
    c.port = 1;
    assert_eq!(
        c.validate_node(),
        Err(ProxyConfigError::InconsistentGateFlag)
    );
    c.gate_level = 1;
    assert_eq!(
        c.validate_node(),
        Err(ProxyConfigError::IncompleteCredentials)
    );
    c.user = Some("u".into());
    assert_eq!(c.validate_node(), Ok(()));
}

// chain validation
//
// Fixtures use `ProxyConfig::chain`, whose input order is the node order
// (outermost first, exit last) and therefore the reported error index
// order. Every test cross-checks the index against the node found there.

#[test]
fn chain_reports_index_zero_of_three_for_bad_outermost() {
    let chain = chained(vec![
        ProxyConfig::socks5("outer-bad", 0), // ZeroPort at index 0
        ProxyConfig::socks5("mid", 2),
        ProxyConfig::socks5("exit", 3),
    ]);
    assert_eq!(hosts(&chain), ["outer-bad", "mid", "exit"]);
    assert_eq!(chain.nodes()[0].host, "outer-bad");
    let err = chain.validate().unwrap_err();
    assert_eq!(err.node(), 0);
    assert_eq!(err.kind(), ProxyConfigError::ZeroPort);
}

#[test]
fn chain_validates_middle_and_reports_index() {
    let chain = chained(vec![
        ProxyConfig::socks5("outer", 1),
        ProxyConfig::socks5("mid-bad", 0), // ZeroPort at index 1
        ProxyConfig::socks5("exit", 3),
    ]);
    assert_eq!(hosts(&chain), ["outer", "mid-bad", "exit"]);
    assert_eq!(chain.nodes()[1].host, "mid-bad");
    let err = chain.validate().unwrap_err();
    assert_eq!(err.node(), 1);
    assert_eq!(err.kind(), ProxyConfigError::ZeroPort);
    assert_eq!(err.to_string(), "node 1: proxy port is 0");
}

#[test]
fn chain_reports_last_index_of_three_for_bad_exit() {
    let chain = chained(vec![
        ProxyConfig::socks5("outer", 1),
        ProxyConfig::socks5("mid", 2),
        ProxyConfig::socks5("exit-bad", 0), // ZeroPort at index 2 (exit)
    ]);
    assert_eq!(hosts(&chain), ["outer", "mid", "exit-bad"]);
    assert_eq!(chain.nodes()[2].host, "exit-bad");
    let err = chain.validate().unwrap_err();
    assert_eq!(err.node(), 2);
    assert_eq!(err.kind(), ProxyConfigError::ZeroPort);
}

#[test]
fn chain_reports_last_index_of_three_for_incomplete_exit() {
    let mut exit = ProxyConfig::socks5("exit-bad", 3);
    exit.user = Some("u".into()); // IncompleteCredentials at index 2
    let chain = chained(vec![
        ProxyConfig::socks5("outer", 1),
        ProxyConfig::socks5("mid", 2),
        exit,
    ]);
    assert_eq!(hosts(&chain), ["outer", "mid", "exit-bad"]);
    assert_eq!(chain.nodes()[2].host, "exit-bad");
    let err = chain.validate().unwrap_err();
    assert_eq!(err.node(), 2);
    assert_eq!(err.kind(), ProxyConfigError::IncompleteCredentials);
}

#[test]
fn chain_first_error_wins_with_the_first_nodes_kind() {
    let mut exit = ProxyConfig::socks5("exit-bad", 3);
    exit.user = Some("u".into()); // IncompleteCredentials at index 2
    let chain = chained(vec![
        ProxyConfig::socks5("outer-bad", 0), // ZeroPort at index 0
        ProxyConfig::socks5("mid", 2),
        exit,
    ]);
    assert_eq!(hosts(&chain), ["outer-bad", "mid", "exit-bad"]);
    assert_eq!(chain.nodes()[0].host, "outer-bad");
    assert_eq!(chain.nodes()[2].host, "exit-bad");
    let err = chain.validate().unwrap_err();
    assert_eq!(err.node(), 0);
    assert_eq!(err.kind(), ProxyConfigError::ZeroPort);
}

#[test]
fn chain_of_one_reports_index_zero() {
    let chain = chained(vec![ProxyConfig::socks5("solo-bad", 0)]);
    assert_eq!(hosts(&chain), ["solo-bad"]);
    assert_eq!(chain.nodes()[0].host, "solo-bad");
    let err = chain.validate().unwrap_err();
    assert_eq!(err.node(), 0);
    assert_eq!(err.kind(), ProxyConfigError::ZeroPort);
}

#[test]
fn valid_chains_of_one_two_and_three_pass() {
    let one = chained(vec![ProxyConfig::socks5("solo", 1)]);
    assert_eq!(hosts(&one), ["solo"]);
    assert_eq!(one.validate(), Ok(()));
    let two = chained(vec![
        ProxyConfig::socks5("outer", 1),
        ProxyConfig::socks5("exit", 2),
    ]);
    assert_eq!(hosts(&two), ["outer", "exit"]);
    assert_eq!(two.validate(), Ok(()));
    let three = chained(vec![
        ProxyConfig::socks5("outer", 1),
        ProxyConfig::socks5("mid", 2),
        ProxyConfig::socks5("exit", 3),
    ]);
    assert_eq!(hosts(&three), ["outer", "mid", "exit"]);
    assert_eq!(three.validate(), Ok(()));
}

#[test]
fn chain_error_accessors_source_and_display() {
    let chain = chained(vec![
        ProxyConfig::socks5("outer", 1),
        ProxyConfig::socks5("mid-bad", 0), // ZeroPort at index 1
        ProxyConfig::socks5("exit", 3),
    ]);
    assert_eq!(hosts(&chain), ["outer", "mid-bad", "exit"]);
    assert_eq!(chain.nodes()[1].host, "mid-bad");
    let err: &ChainConfigError = &chain.validate().unwrap_err();
    assert_eq!(err.node(), 1);
    assert_eq!(err.kind(), ProxyConfigError::ZeroPort);
    assert_eq!(
        err.source()
            .expect("source")
            .downcast_ref::<ProxyConfigError>(),
        Some(&err.kind())
    );
    let rendered = err.to_string();
    assert!(rendered.starts_with("node 1: "), "{rendered}");
    assert!(rendered.contains(&err.kind().to_string()), "{rendered}");
    assert!(format!("{err:?}").contains("node"));
}

// try_with_auth
#[test]
fn try_with_auth_sets_both_fields_on_success() {
    let c = ProxyConfig::http("proxy.example", 1080)
        .try_with_auth("u", "p")
        .unwrap();
    assert_eq!(c.user.as_deref(), Some("u"));
    assert_eq!(c.password.as_deref(), Some("p"));
    let c = ProxyConfig::socks5("proxy.example", 1080)
        .try_with_auth("u", "p")
        .unwrap();
    assert_eq!(c.user.as_deref(), Some("u"));
    assert_eq!(c.password.as_deref(), Some("p"));
}

#[test]
fn try_with_auth_rejects_bad_pairs_and_fresh_config_then_works() {
    let pair =
        |c: ProxyConfig, u: &str, p: &str| c.try_with_auth(u, p).map(|c| (c.user, c.password));
    assert_eq!(
        pair(ProxyConfig::socks5("proxy.example", 1080), "u", ""),
        Err(ProxyConfigError::EmptyCredential {
            field: CredentialField::Password
        })
    );
    assert_eq!(
        pair(ProxyConfig::socks5("proxy.example", 1080), "", "p"),
        Err(ProxyConfigError::EmptyCredential {
            field: CredentialField::Username
        })
    );
    assert_eq!(
        pair(ProxyConfig::http("proxy.example", 1080), "a:b", "p"),
        Err(ProxyConfigError::UsernameContainsColon)
    );
    assert_eq!(
        pair(ProxyConfig::http("proxy.example", 1080), "u", "p\n"),
        Err(ProxyConfigError::ControlCharacter {
            field: CredentialField::Password
        })
    );
    let c = ProxyConfig::socks5("proxy.example", 1080)
        .try_with_auth("u", "p")
        .unwrap();
    assert_eq!(c.user.as_deref(), Some("u"));
    assert_eq!(c.password.as_deref(), Some("p"));
}

#[test]
fn try_with_auth_is_protocol_dependent() {
    let pair =
        |c: ProxyConfig, u: &str, p: &str| c.try_with_auth(u, p).map(|c| (c.user, c.password));
    assert_eq!(
        pair(ProxyConfig::http("proxy.example", 1080), "u", ""),
        Ok((Some("u".into()), Some("".into())))
    );
    assert_eq!(
        pair(ProxyConfig::socks5("proxy.example", 1080), "u", ""),
        Err(ProxyConfigError::EmptyCredential {
            field: CredentialField::Password
        })
    );
    let c = ProxyConfig::socks5("proxy.example", 1080)
        .try_with_auth("a:b", "p")
        .unwrap();
    assert_eq!(c.user.as_deref(), Some("a:b"));
    assert_eq!(
        pair(ProxyConfig::http("proxy.example", 1080), "a:b", "p"),
        Err(ProxyConfigError::UsernameContainsColon)
    );
}

// error rendering
#[test]
fn error_rendering_never_leaks_credentials_or_host() {
    const SECRETS: [&str; 3] = ["cred-user-7", "cred-secret-9", "cred-host-8"];
    let host = "cred-host-8";
    let mut c = ProxyConfig::new(ProxyProtocol::Socks5, host, 1080)
        .with_auth("cred-user-7", "cred-secret-9");
    c.is_gate = true;
    let errors = [
        ProxyConfig::socks5("", 1080).validate_node().unwrap_err(),
        ProxyConfig::socks5("cred-host-8/", 1080)
            .validate_node()
            .unwrap_err(),
        ProxyConfig::socks5(host, 0).validate_node().unwrap_err(),
        {
            let mut half = ProxyConfig::socks5(host, 1080);
            half.user = Some("cred-user-7".into());
            half.validate_node().unwrap_err()
        },
        ProxyConfig::socks5(host, 1080)
            .try_with_auth("cred-user-7", "")
            .unwrap_err(),
        ProxyConfig::socks5(host, 1080)
            .try_with_auth("cred-user-7", "x".repeat(256))
            .unwrap_err(),
        ProxyConfig::http(host, 1080)
            .try_with_auth("cred-user-7:x", "cred-secret-9")
            .unwrap_err(),
        ProxyConfig::http(host, 1080)
            .try_with_auth("cred-user-7", "cred-secret-9\n")
            .unwrap_err(),
        c.validate_node().unwrap_err(),
    ];
    for e in errors {
        for rendered in [format!("{e}"), format!("{e:?}")] {
            for secret in SECRETS {
                assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
            }
        }
    }
}

// error sources
#[test]
fn proxy_config_error_source_is_none_and_leak_free_for_every_variant() {
    const SECRETS: [&str; 3] = ["cred-user-7", "cred-secret-9", "cred-host-8"];
    let host = "cred-host-8";
    let mut gated = ProxyConfig::socks5(host, 1080).with_auth("cred-user-7", "cred-secret-9");
    gated.is_gate = true;
    let mut half = ProxyConfig::socks5(host, 1080);
    half.user = Some("cred-user-7".into());
    // One error per ProxyConfigError variant, in enum order, each produced
    // from a config carrying the secrets above.
    let errors = [
        ProxyConfig::socks5("", 1080)
            .with_auth("cred-user-7", "cred-secret-9")
            .validate_node()
            .unwrap_err(),
        ProxyConfig::socks5("cred-host-8/", 1080)
            .with_auth("cred-user-7", "cred-secret-9")
            .validate_node()
            .unwrap_err(),
        ProxyConfig::socks5(host, 0)
            .with_auth("cred-user-7", "cred-secret-9")
            .validate_node()
            .unwrap_err(),
        half.validate_node().unwrap_err(),
        ProxyConfig::socks5(host, 1080)
            .try_with_auth("cred-user-7", "")
            .unwrap_err(),
        ProxyConfig::socks5(host, 1080)
            .try_with_auth("cred-user-7", "cred-secret-9".repeat(20))
            .unwrap_err(),
        ProxyConfig::http(host, 1080)
            .try_with_auth("cred-user-7:x", "cred-secret-9")
            .unwrap_err(),
        ProxyConfig::http(host, 1080)
            .try_with_auth("cred-user-7", "cred-secret-9\n")
            .unwrap_err(),
        gated.validate_node().unwrap_err(),
    ];
    for e in &errors {
        assert!(e.source().is_none(), "unexpected source for {e:?}");
        for rendered in [format!("{e}"), format!("{e:?}")] {
            for secret in SECRETS {
                assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
            }
        }
    }
}

#[test]
fn chain_error_source_chain_is_present_and_leak_free() {
    // Both fixture hosts are forbidden in the rendered errors.
    const SECRETS: [&str; 4] = ["cred-user-7", "cred-secret-9", "cred-host-8", "outer"];
    // Exit node (index 1) carries both secrets but fails validation
    // (520-byte password); the kind names only the byte count.
    let exit = ProxyConfig::socks5("cred-host-8", 1080)
        .with_auth("cred-user-7", "cred-secret-9".repeat(40));
    let chain = chained(vec![ProxyConfig::socks5("outer", 1), exit]);
    assert_eq!(hosts(&chain), ["outer", "cred-host-8"]);
    assert_eq!(chain.nodes()[1].host, "cred-host-8");
    let err = chain.validate().unwrap_err();
    assert_eq!(err.node(), 1);
    assert_eq!(
        err.kind(),
        ProxyConfigError::CredentialTooLong {
            field: CredentialField::Password,
            len: 520
        }
    );
    for rendered in [format!("{err}"), format!("{err:?}")] {
        for secret in SECRETS {
            assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        }
    }
    let mut current = err.source();
    assert!(
        current.is_some(),
        "chain error must expose its kind as source"
    );
    let mut visited = 0;
    while let Some(source) = current {
        visited += 1;
        for rendered in [format!("{source}"), format!("{source:?}")] {
            for secret in SECRETS {
                assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
            }
        }
        current = source.source();
    }
    assert_eq!(visited, 1);
}

// builders do not validate
#[test]
fn with_auth_and_constructors_do_not_validate() {
    let c = ProxyConfig::socks5("h", 1).with_auth("u", "");
    assert_eq!(c.user.as_deref(), Some("u"));
    assert_eq!(c.password.as_deref(), Some(""));
    assert_eq!(
        c.validate_node(),
        Err(ProxyConfigError::EmptyCredential {
            field: CredentialField::Password
        })
    );
    let c = ProxyConfig::new(ProxyProtocol::Socks5, "", 0);
    assert_eq!(c.host, "");
    assert_eq!(c.port, 0);
    let c = ProxyConfig::from_addr(ProxyProtocol::Socks5, "u:p@[2001:db8::1]:1080").unwrap();
    assert_eq!(c.validate_node(), Ok(()));
}

#[test]
fn from_addr_still_accepts_lines_that_validation_rejects() {
    let c = ProxyConfig::from_addr(ProxyProtocol::Socks5, "user:@host:1080").unwrap();
    assert_eq!(c.user.as_deref(), Some("user"));
    assert_eq!(c.password.as_deref(), Some(""));
    assert_eq!(
        c.validate_node(),
        Err(ProxyConfigError::EmptyCredential {
            field: CredentialField::Password
        })
    );

    let line = format!("u:{}@host:1080", "p".repeat(256));
    let c = ProxyConfig::from_addr(ProxyProtocol::Socks5, &line).unwrap();
    assert_eq!(c.password.as_deref().map(str::len), Some(256));
    assert_eq!(
        c.validate_node(),
        Err(ProxyConfigError::CredentialTooLong {
            field: CredentialField::Password,
            len: 256
        })
    );
}

#[test]
fn with_auth_still_accepts_pairs_that_validation_rejects() {
    let c = ProxyConfig::http("proxy.example", 1080).with_auth("a:b", "p");
    assert_eq!(c.user.as_deref(), Some("a:b"));
    assert_eq!(
        c.validate_node(),
        Err(ProxyConfigError::UsernameContainsColon)
    );

    let c = ProxyConfig::https("proxy.example", 1080).with_auth("u", "p\n");
    assert_eq!(
        c.validate_node(),
        Err(ProxyConfigError::ControlCharacter {
            field: CredentialField::Password
        })
    );
}

#[test]
fn constructors_still_accept_zero_port_and_empty_host() {
    for c in [
        ProxyConfig::http("proxy.example", 0),
        ProxyConfig::https("proxy.example", 0),
        ProxyConfig::socks5("proxy.example", 0),
    ] {
        assert_eq!(c.port, 0);
        assert_eq!(c.validate_node(), Err(ProxyConfigError::ZeroPort));
    }
    for c in [
        ProxyConfig::http("", 1080),
        ProxyConfig::https("", 1080),
        ProxyConfig::socks5("", 1080),
    ] {
        assert_eq!(c.host, "");
        assert_eq!(c.validate_node(), Err(ProxyConfigError::EmptyHost));
    }
}

// chain depth limit
fn deep_chain(nodes: usize) -> ProxyConfig {
    let mut cfg = ProxyConfig::socks5("depth-host", 1);
    for _ in 1..nodes {
        cfg = ProxyConfig::socks5("depth-host", 1).with_gate(cfg);
    }
    cfg
}

/// Mutation caught: removing the depth check from `ProxyConfig::validate`
/// lets the 65-node chain validate cleanly and this fails.
#[test]
fn validate_rejects_chains_longer_than_max_nodes() {
    let chain = deep_chain(MAX_CHAIN_NODES + 1);
    assert_eq!(chain.chain_len(), MAX_CHAIN_NODES + 1);
    let err = chain.validate().unwrap_err();
    assert_eq!(err.node(), 0);
    assert_eq!(
        err.kind(),
        ProxyConfigError::ChainTooLong {
            max: MAX_CHAIN_NODES
        }
    );
    let rendered = err.to_string();
    assert!(rendered.contains("64"), "{rendered}");
    assert!(!rendered.contains("depth-host"), "{rendered}");
    assert!(!format!("{err:?}").contains("depth-host"));
}

/// Boundary pin: exactly [`MAX_CHAIN_NODES`] nodes stay valid. Mutation
/// caught: an off-by-one (`>=` instead of `>`) in the depth check makes
/// this fail.
#[test]
fn validate_accepts_chain_of_exactly_max_nodes() {
    let chain = deep_chain(MAX_CHAIN_NODES);
    assert_eq!(chain.chain_len(), MAX_CHAIN_NODES);
    assert_eq!(chain.validate(), Ok(()));
}

/// Mutation caught: moving the depth check behind the per-node loop lets
/// the invalid inner node (empty host, zero port at the exit) error win
/// and this fails.
#[test]
fn chain_depth_error_wins_over_node_errors() {
    let mut cfg = ProxyConfig::socks5("", 0);
    for _ in 0..MAX_CHAIN_NODES {
        cfg = ProxyConfig::socks5("depth-host", 1).with_gate(cfg);
    }
    assert_eq!(cfg.chain_len(), MAX_CHAIN_NODES + 1);
    let err = cfg.validate().unwrap_err();
    assert_eq!(
        err.kind(),
        ProxyConfigError::ChainTooLong {
            max: MAX_CHAIN_NODES
        }
    );
}
