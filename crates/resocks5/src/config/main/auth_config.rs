use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthConfig {
    /// When `true`, the server advertises SOCKS5 method `0x00`
    /// (no-authentication) alongside secure auth (method `0x80`), so a
    /// client without credentials can connect anonymously. The HTTP
    /// CONNECT path mirrors the same policy — no Proxy-Authorization
    /// required. When `false`, only authenticated clients are accepted.
    ///
    /// Behaviour matrix (default `true`):
    ///
    /// | users.ktav | allow_anonymous | client experience               |
    /// |------------|-----------------|---------------------------------|
    /// | empty      | true (default)  | anonymous                       |
    /// | empty      | false           | every client rejected           |
    /// | non-empty  | true (default)  | client may auth or skip         |
    /// | non-empty  | false           | client MUST auth                |
    ///
    /// The default is `true`: fresh and pre-0.5 configs admit anonymous
    /// clients, exactly as the historic default did. Existing configs with
    /// an explicit value keep it. When `secure_only` is `true`,
    /// `allow_anonymous` is IGNORED (no anonymous access is served).
    #[serde(default = "default_allow_anonymous")]
    pub allow_anonymous: bool,
    /// When `true`, the port serves ONLY our secure method — SOCKS5
    /// method `0x80` / HTTP `Resocks5-Secure`. No clear-text login
    /// (SOCKS5 0x02 / HTTP Basic) and no anonymous access:
    /// `allow_anonymous` is ignored, and a startup warning names the
    /// conflict when the two flags are combined. Default `false` keeps
    /// the old behaviour (clear text always accepted, anonymous per
    /// `allow_anonymous`).
    #[serde(default)]
    pub secure_only: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            allow_anonymous: default_allow_anonymous(),
            secure_only: false,
        }
    }
}

fn default_allow_anonymous() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use crate::config::{MainConfig, UpstreamAuthConfig};

    /// A 0.4.x config (GSSAPI fields, anonymous allowed) still parses: the
    /// explicit `allow_anonymous` is honoured, `secure_only` gets its
    /// default, and unknown fields (gssapi_*) are ignored.
    /// Mutation: dropping or renaming `allow_anonymous` breaks this parse.
    #[test]
    fn old_0_4_x_auth_section_still_parses() {
        let src = "\
port: 1
auth: { allow_anonymous: true, gssapi_service: \"socks@p.example.com\", gssapi_protection: \"none\" }
";
        let cfg: MainConfig = ktav::from_str(src).unwrap();
        assert!(cfg.auth.allow_anonymous);
        assert!(!cfg.auth.secure_only);
        assert_eq!(cfg.upstream_auth, UpstreamAuthConfig::default());
    }

    /// An explicit `allow_anonymous: false` overrides the (historic
    /// `true`) default. Mutation: hard-coding `true` in
    /// `default_allow_anonymous` (or removing the serde default fn) fails
    /// here.
    #[test]
    fn an_explicit_allow_anonymous_false_is_honoured() {
        let cfg: MainConfig =
            ktav::from_str("port: 1\nauth: { allow_anonymous: false }\n").unwrap();
        assert!(!cfg.auth.allow_anonymous);
    }

    /// An empty `auth:` section takes the historic defaults: anonymous
    /// allowed, clear text accepted (`secure_only == false`).
    /// Mutation: flipping either default fails a field here.
    #[test]
    fn an_empty_auth_section_takes_the_defaults() {
        let src = "port: 1\nauth: {}\n";
        let cfg: MainConfig = ktav::from_str(src).unwrap();
        assert!(cfg.auth.allow_anonymous);
        assert!(!cfg.auth.secure_only);
    }

    /// An explicit `secure_only: true` is honoured. Mutation: removing the
    /// `#[serde(default)]` field or ignoring the key fails here.
    #[test]
    fn an_explicit_secure_only_true_is_honoured() {
        let cfg: MainConfig = ktav::from_str("port: 1\nauth: { secure_only: true }\n").unwrap();
        assert!(cfg.auth.secure_only);
    }
}
