use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthConfig {
    /// When `true`, the server advertises SOCKS5 method `0x00`
    /// (no-authentication) alongside secure auth (method `0x80`), so a
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
    /// Accept GSSAPI (Kerberos) clients, SOCKS5 method 0x01: the host-based
    /// service name the server answers to (`socks@proxy.example.com`, the
    /// principal `socks/proxy.example.com@REALM` in the keytab), or `*` for any
    /// principal in the keytab. Absent = GSSAPI off. Needs a build with the
    /// `gssapi-system` feature; a server without it refuses to start when this
    /// is set. When a client offers several methods the server picks the
    /// strongest it has: GSSAPI, then secure auth, then anonymous.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gssapi_service: Option<String>,
    /// The weakest per-message protection the server agrees to for GSSAPI
    /// clients: `integrity` (default) or `confidentiality`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gssapi_min_protection: Option<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            allow_anonymous: default_allow_anonymous(),
            gssapi_service: None,
            gssapi_min_protection: None,
        }
    }
}

fn default_allow_anonymous() -> bool {
    true
}
