use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthConfig {
    /// When `true`, the server advertises SOCKS5 method `0x00`
    /// (no-authentication) alongside any user/password method, so a
    /// client without credentials can connect anonymously. The HTTP
    /// CONNECT path mirrors the same policy — no Proxy-Authorization
    /// required. When `false`, only authenticated clients are accepted.
    ///
    /// Behaviour matrix:
    ///
    /// | users.ktav | allow_anonymous | client experience           |
    /// |------------|-----------------|-----------------------------|
    /// | empty      | true (default)  | anonymous (legacy behaviour)|
    /// | empty      | false           | every client rejected       |
    /// | non-empty  | true            | client may auth or skip     |
    /// | non-empty  | false           | client MUST auth            |
    ///
    /// Default `true` keeps the historic "no users → no auth" mode
    /// working without an explicit setting.
    #[serde(default = "default_allow_anonymous")]
    pub allow_anonymous: bool,
}

fn default_allow_anonymous() -> bool {
    true
}
