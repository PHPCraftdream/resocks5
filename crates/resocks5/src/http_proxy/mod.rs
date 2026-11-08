//! HTTP CONNECT proxy handler — sibling protocol of
//! `handle_socks5_client`, reachable on the same listening port via the
//! protocol-detection dispatcher in `handle_client`.
//!
//! Only the `CONNECT` method is implemented. It covers HTTPS tunneling
//! (the overwhelming majority of HTTP-proxy traffic today). Plain HTTP
//! forward-proxy mode (`GET http://...`) is not supported — clients
//! requesting it get `501 Not Implemented` and any other malformed
//! request gets `400 Bad Request`.
//!
//! HTTP CONNECT authenticates like SOCKS5: clear-text Basic is offered
//! unless `auth.secure_only`; otherwise (and always first in the 407
//! challenge) `Resocks5-Secure`. The server selects the strongest method
//! the client supports. The identity flows into the handler: a direct
//! account bypasses the pool exactly like over SOCKS5, per-user IP
//! filters apply, and the direct cap is enforced. Anonymous access is
//! served only when `auth.allow_anonymous` — anonymous stays pool-only.
//! RFC 9110 §15.5.8 requires the 407 challenge; 403 denotes an access
//! denial. Upstream connect failures yield `502 Bad Gateway`; banned
//! targets yield `403 Forbidden`.

pub mod handle_http_client;

pub use handle_http_client::handle_http_client;
