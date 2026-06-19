//! HTTP CONNECT proxy handler — sibling protocol of
//! `proxy_tools::handle_socks5_client`, reachable on the same listening
//! port via the protocol-detection dispatcher in
//! `proxy_tools::handle_client`.
//!
//! Only the `CONNECT` method is implemented. It covers HTTPS tunneling
//! (the overwhelming majority of HTTP-proxy traffic today). Plain HTTP
//! forward-proxy mode (`GET http://...`) is not supported — clients
//! requesting it get `501 Not Implemented` and any other malformed
//! request gets `400 Bad Request`. We don't aim to be a general-purpose
//! HTTP proxy; we aim to expose the same upstream-rotator pipeline
//! through whichever proxy protocol the client speaks.
//!
//! Authentication uses RFC 7617 `Proxy-Authorization: Basic` with the
//! shared `AuthState` — the same users and the same `allow_anonymous`
//! policy as on the SOCKS5 side. Failed/missing credentials yield
//! `407 Proxy Authentication Required` with `Proxy-Authenticate: Basic
//! realm="resocks5"`. Upstream connect failures yield `502 Bad Gateway`;
//! banned targets yield `403 Forbidden`.

pub mod handle_http_client;

pub use handle_http_client::handle_http_client;
