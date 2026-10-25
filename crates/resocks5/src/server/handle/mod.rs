// handle: client-facing protocol dispatch — single-byte protocol
// detection plus the SOCKS5 implementation.
pub(crate) mod handle_client;
pub(crate) mod handle_socks5_client;
// Регрессионные тесты AND-каскада allowed_clients (общий handle_client).
#[cfg(test)]
mod allowed_clients_tests;
