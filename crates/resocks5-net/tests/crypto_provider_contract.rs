//! Downstream-style release gate for the crypto-provider contract of
//! `connect::make_tls_connector`: pins the real behaviour of the rustls
//! in the build graph — including the panic path and its byte-exact
//! message — instead of assuming it from rustls' source.
//!
//! This deliberately lives in its own integration-test binary. rustls'
//! provider resolution is PROCESS-GLOBAL one-way state
//! (`get_default_or_install_from_crate_features` auto-installs the
//! auto-selected provider on first success), and `cargo test` runs all
//! lib tests in one process: the same steps inside the lib's test module
//! would mutate that global under the other ~190 tests and make every
//! provider-state assertion order-dependent. Here the whole lifecycle
//! runs inside ONE `#[test]` in a process of its own, so the order is
//! fully controlled and the lib test binary's process is never touched.

#![cfg(feature = "tls")]

use std::panic::catch_unwind;
use std::sync::Arc;

use resocks5_net::connect::{make_tls_connector, make_tls_connector_with_provider};

/// Set this env var when running this binary against a graph in which
/// rustls cannot auto-resolve a provider (e.g.
/// `--features rustls/custom-provider`): the documented contract says
/// `make_tls_connector` must then panic with the exact message below,
/// and this test fails loudly if it instead succeeds.
const EXPECT_PANIC_ENV: &str = "RESOCKS5NET_PROVIDER_CONTRACT_EXPECT_PANIC";

/// Byte-exact panic payload of rustls 0.23.40 (leading newline and
/// trailing whitespace included, exactly as written in
/// `get_default_or_install_from_crate_features`). If a rustls upgrade
/// ever changes this text, this assertion fails — by design: the
/// `# Panics` section on `make_tls_connector` documents this message
/// verbatim and must be refreshed with it.
const RUSTLS_NO_PROVIDER_PANIC: &str = "\nCould not automatically determine the process-level CryptoProvider from Rustls crate features.\nCall CryptoProvider::install_default() before this point to select a provider manually, or make sure exactly one of the 'aws-lc-rs' and 'ring' features is enabled.\nSee the documentation of the CryptoProvider type for more information.\n            ";

#[test]
fn process_crypto_provider_contract() {
    // Fresh process (this binary runs alone): nothing installed yet.
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_none(),
        "process-global CryptoProvider already installed before the first \
         rustls call — the contract below assumes a fresh process"
    );

    // This workspace's graph: `ring` is the sole built-in and
    // `custom-provider` is off, so an uninstalled process takes case 2 of
    // the documented contract — rustls auto-selects ring, auto-installs
    // it, and the convenience connector builds: today's behaviour,
    // unchanged. In a graph rustls cannot resolve (both built-ins, or
    // `custom-provider` — run with the env var above set), the same call
    // must instead panic with the exact message documented on
    // `make_tls_connector`.
    let outcome = catch_unwind(make_tls_connector);
    match outcome {
        Ok(connector) => {
            assert!(
                std::env::var_os(EXPECT_PANIC_ENV).is_none(),
                "a no-provider panic was expected in this graph, but \
                 make_tls_connector succeeded — rustls' resolution \
                 behaviour changed; refresh the documented contract"
            );
            assert!(
                rustls::crypto::CryptoProvider::get_default().is_some(),
                "a successful build must have installed the auto-selected \
                 provider into the process global"
            );
            drop(connector);
        }
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .expect("panic payload must be a string message");
            assert_eq!(message, RUSTLS_NO_PROVIDER_PANIC);
        }
    }

    // The escape hatch must hold in EVERY state — including a broken one
    // where nothing got installed: an explicitly supplied provider
    // bypasses process-global resolution entirely.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let _ = make_tls_connector_with_provider(provider);

    // The documented remedy in a still-broken state: install once and the
    // convenience path starts working. In an already-resolved process (the
    // auto-install above) a second install must be refused.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("first install in a fresh process must succeed");
    } else {
        assert!(
            rustls::crypto::ring::default_provider()
                .install_default()
                .is_err(),
            "install_default must be a one-time, process-wide operation"
        );
    }

    // With a default in place (installed or auto-installed), the
    // documented happy path works.
    let _ = make_tls_connector();
}
