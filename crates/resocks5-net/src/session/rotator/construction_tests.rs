use super::*;

fn make_proxy(host: &str, port: u16) -> ProxyConfig {
    ProxyConfig {
        protocol: crate::types::ProxyProtocol::Socks5,
        host: host.to_string(),
        port,
        user: None,
        password: None,
        is_gate: false,
        gate: None,
    }
}

#[test]
fn try_new_rejects_empty_list() {
    assert!(matches!(
        ProxyRotator::try_new(vec![]),
        Err(RotatorError::Empty)
    ));
}

#[test]
#[should_panic(expected = "ProxyRotator::new: invalid arguments")]
fn new_panics_on_empty_list() {
    let _ = ProxyRotator::new(vec![]);
}

#[test]
fn try_with_policy_rejects_invalid_policy() {
    let proxies = vec![make_proxy("h", 1000)];
    let policy = RatingPolicy {
        sand_max: 0.0,
        ..Default::default()
    };
    assert!(matches!(
        ProxyRotator::try_with_policy(proxies, policy),
        Err(RotatorError::InvalidPolicy(msg)) if msg.contains("sand_max")
    ));
}

#[test]
#[should_panic(expected = "ProxyRotator::with_policy: invalid arguments")]
fn with_policy_panics_on_invalid_policy() {
    let proxies = vec![make_proxy("h", 1000)];
    let policy = RatingPolicy {
        sand_max: 0.0,
        ..Default::default()
    };
    let _ = ProxyRotator::with_policy(proxies, policy);
}

#[test]
fn try_with_cache_limits_rejects_nan_policy() {
    let proxies = vec![make_proxy("h", 1000)];
    let policy = RatingPolicy {
        half_life_sec: f64::NAN,
        ..Default::default()
    };
    assert!(matches!(
        ProxyRotator::try_with_cache_limits(proxies, policy, 8, Duration::from_secs(60)),
        Err(RotatorError::InvalidPolicy(_))
    ));
}

#[test]
fn valid_policy_still_constructs_and_get_next_is_infallible() {
    let proxies = vec![make_proxy("h", 1000), make_proxy("h", 1001)];
    let r = ProxyRotator::new(proxies);
    assert_eq!(r.len(), 2);
    // Non-empty invariant: round-robin over both slots, twice around.
    let first = r.get_next();
    assert!(r.get_next().port != first.port || r.len() == 1);
    let _ = r.get_next();
    let _ = r.get_next();
}
