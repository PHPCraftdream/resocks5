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
//! HTTP has no password authentication: Basic would put the password on
//! the wire. With `allow_anonymous` a request without `Proxy-Authorization`
//! is served anonymously; any request carrying credentials, and any request
//! when anonymous access is off, gets `407 Proxy Authentication Required`.
//! The challenge is `Resocks5-Secure`, not Basic.
//! This is not HTTP secure auth. RFC 9110 §15.5.8 requires the 407 challenge;
//! 403 denotes an access denial. A client may send Basic preemptively, which
//! the server cannot prevent. Browser prompt behavior has not been tested.
//! Users authenticate over SOCKS5 (secure auth, method 0x80). Upstream
//! connect failures yield `502 Bad Gateway`; banned targets yield
//! `403 Forbidden`.

pub mod handle_http_client;

pub use handle_http_client::handle_http_client;
