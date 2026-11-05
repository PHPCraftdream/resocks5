//! Configuration validation for [`ProxyConfig`] entries and chains.

use std::fmt;

use super::proxy_config::ProxyConfig;
use super::ProxyProtocol;

/// Which credential field a validation error refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CredentialField {
    /// The username field.
    Username,
    /// The password field.
    Password,
}

fn field_label(field: CredentialField) -> &'static str {
    match field {
        CredentialField::Username => "username",
        CredentialField::Password => "password",
    }
}

/// Why a single [`ProxyConfig`] entry failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyConfigError {
    /// The host string is empty.
    EmptyHost,
    /// The host contains a control character, whitespace, `/` or `@`.
    InvalidHost,
    /// The port is 0.
    ZeroPort,
    /// Exactly one of username and password is set.
    IncompleteCredentials,
    /// A SOCKS5 credential field is 0 bytes long.
    EmptyCredential {
        /// Which field is empty.
        field: CredentialField,
    },
    /// A SOCKS5 credential field exceeds the 255-byte RFC 1929 limit.
    CredentialTooLong {
        /// Which field is too long.
        field: CredentialField,
        /// The field's length in bytes.
        len: usize,
    },
    /// The username contains `':'`, which HTTP Basic cannot encode.
    UsernameContainsColon,
    /// A credential field contains an ASCII control character.
    ControlCharacter {
        /// Which field contains the control character.
        field: CredentialField,
    },
    /// `is_gate` does not match `gate_level > 0`.
    InconsistentGateFlag,
}

impl fmt::Display for ProxyConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyConfigError::EmptyHost => write!(f, "proxy host is empty"),
            ProxyConfigError::InvalidHost => {
                write!(
                    f,
                    "proxy host contains a forbidden character (control, whitespace, '/' or '@')"
                )
            }
            ProxyConfigError::ZeroPort => write!(f, "proxy port is 0"),
            ProxyConfigError::IncompleteCredentials => {
                write!(
                    f,
                    "credentials incomplete: exactly one of username and password is set"
                )
            }
            ProxyConfigError::EmptyCredential { field } => {
                write!(
                    f,
                    "proxy {} is empty; SOCKS5 requires at least 1 byte",
                    field_label(*field)
                )
            }
            ProxyConfigError::CredentialTooLong { field, len } => {
                write!(
                    f,
                    "proxy {} is {} bytes long; SOCKS5 allows at most 255",
                    field_label(*field),
                    len
                )
            }
            ProxyConfigError::UsernameContainsColon => {
                write!(
                    f,
                    "proxy username contains ':'; HTTP Basic cannot encode it"
                )
            }
            ProxyConfigError::ControlCharacter { field } => {
                write!(
                    f,
                    "proxy {} contains an ASCII control character",
                    field_label(*field)
                )
            }
            ProxyConfigError::InconsistentGateFlag => {
                write!(f, "is_gate does not match gate_level")
            }
        }
    }
}

impl std::error::Error for ProxyConfigError {}

/// A [`ProxyConfig`] chain failed validation at one of its nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainConfigError {
    node: usize,
    kind: ProxyConfigError,
}

impl ChainConfigError {
    /// Index of the first failing node, outermost first.
    pub fn node(&self) -> usize {
        self.node
    }

    /// The per-node validation error.
    pub fn kind(&self) -> ProxyConfigError {
        self.kind
    }
}

impl fmt::Display for ChainConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "node {}: {}", self.node, self.kind)
    }
}

impl std::error::Error for ChainConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.kind)
    }
}

/// Validate a username/password pair for `protocol`.
///
/// SOCKS5 (RFC 1929) checks username first, then password; each must be
/// 1..=255 bytes. HTTP/HTTPS (RFC 7617) checks for `':'` in the username,
/// then control characters in the username, then in the password.
fn validate_pair(
    protocol: ProxyProtocol,
    user: &str,
    password: &str,
) -> Result<(), ProxyConfigError> {
    match protocol {
        ProxyProtocol::Socks5 => {
            for (field, value) in [
                (CredentialField::Username, user),
                (CredentialField::Password, password),
            ] {
                let len = value.len();
                if len == 0 {
                    return Err(ProxyConfigError::EmptyCredential { field });
                }
                if len > 255 {
                    return Err(ProxyConfigError::CredentialTooLong { field, len });
                }
            }
            Ok(())
        }
        ProxyProtocol::Http | ProxyProtocol::Https => {
            if user.contains(':') {
                return Err(ProxyConfigError::UsernameContainsColon);
            }
            for (field, value) in [
                (CredentialField::Username, user),
                (CredentialField::Password, password),
            ] {
                if value.chars().any(|c| c.is_ascii_control()) {
                    return Err(ProxyConfigError::ControlCharacter { field });
                }
            }
            Ok(())
        }
    }
}

fn is_host_char_forbidden(c: char) -> bool {
    c.is_ascii_control() || c.is_whitespace() || c == '/' || c == '@'
}

impl ProxyConfig {
    /// Validate this entry only (not its gate links).
    ///
    /// Checks run in a fixed order and the first failing check wins:
    /// host, port, gate flag, then credentials.
    pub fn validate_node(&self) -> Result<(), ProxyConfigError> {
        if self.host.is_empty() {
            return Err(ProxyConfigError::EmptyHost);
        }
        if self.host.chars().any(is_host_char_forbidden) {
            return Err(ProxyConfigError::InvalidHost);
        }
        if self.port == 0 {
            return Err(ProxyConfigError::ZeroPort);
        }
        if self.is_gate != (self.gate_level > 0) {
            return Err(ProxyConfigError::InconsistentGateFlag);
        }
        match (self.user.as_deref(), self.password.as_deref()) {
            (None, None) => Ok(()),
            (Some(_), None) | (None, Some(_)) => Err(ProxyConfigError::IncompleteCredentials),
            (Some(user), Some(password)) => validate_pair(self.protocol, user, password),
        }
    }

    /// Validate every node of the chain, outermost first; the error
    /// carries the index of the first bad node.
    pub fn validate(&self) -> Result<(), ChainConfigError> {
        for (index, node) in self.nodes().iter().enumerate() {
            if let Err(kind) = node.validate_node() {
                return Err(ChainConfigError { node: index, kind });
            }
        }
        Ok(())
    }

    /// Fallible [`ProxyConfig::with_auth`]: validates the pair for this
    /// entry's protocol and only then sets it. Does not check host, port
    /// or gate fields.
    pub fn try_with_auth(
        self,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, ProxyConfigError> {
        let user = user.into();
        let password = password.into();
        validate_pair(self.protocol, &user, &password)?;
        Ok(self.with_auth(user, password))
    }
}
