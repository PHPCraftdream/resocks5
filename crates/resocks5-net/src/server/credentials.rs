//! Owned inbound credentials; retention copies stay redacted and are optionally wiped.

use std::fmt;

/// Owned UTF-8 credentials supplied at most once per handshake.
/// Debug deliberately reveals neither username nor password.
pub struct Credentials {
    username: String,
    password: String,
    username_raw: Option<Vec<u8>>, // present only when UNAME was not valid UTF-8
    password_raw: Option<Vec<u8>>,
}

impl Credentials {
    /// Build from an accepted username/password pair.
    pub(crate) fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
            username_raw: None,
            password_raw: None,
        }
    }

    /// Build credentials carrying the raw submitted bytes of any field that was
    /// not valid UTF-8 (the `String` fields hold the lossy decoding in that case).
    pub(crate) fn with_raw(
        username: String,
        password: String,
        username_raw: Option<Vec<u8>>,
        password_raw: Option<Vec<u8>>,
    ) -> Self {
        Self {
            username,
            password,
            username_raw,
            password_raw,
        }
    }

    /// Submitted username; for valid UTF-8 exactly the submitted text, for a
    /// non-UTF-8 field the lossy decoding (do not use it for identity or
    /// verification when `is_utf8()` is `false`).
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Submitted password; for valid UTF-8 exactly the submitted text, for a
    /// non-UTF-8 field the lossy decoding (do not use it for verification when
    /// `is_utf8()` is `false`).
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Internal duplicate for retention; `Credentials` stays publicly non-`Clone`.
    pub(crate) fn duplicate(&self) -> Credentials {
        Self {
            username: self.username.clone(),
            password: self.password.clone(),
            username_raw: self.username_raw.clone(),
            password_raw: self.password_raw.clone(),
        }
    }

    /// Exact submitted UNAME bytes (the lossy `username()` text must not be
    /// used for identity or verification when `is_utf8()` is `false`).
    pub fn username_bytes(&self) -> &[u8] {
        self.username_raw
            .as_deref()
            .unwrap_or(self.username.as_bytes())
    }

    /// Exact submitted PASSWD bytes.
    pub fn password_bytes(&self) -> &[u8] {
        self.password_raw
            .as_deref()
            .unwrap_or(self.password.as_bytes())
    }

    /// `true` iff both fields were valid UTF-8 (then `username()`/`password()`
    /// are byte-identical to the submission).
    pub fn is_utf8(&self) -> bool {
        self.username_raw.is_none() && self.password_raw.is_none()
    }

    /// Move both parts out. Uses `mem::take` so this compiles unchanged when a
    /// `Drop` impl exists (the feature-gated zeroizer).
    pub fn into_parts(mut self) -> (String, String) {
        let username = std::mem::take(&mut self.username);
        let password = std::mem::take(&mut self.password);
        (username, password)
    }

    /// Overwrite the secret material in place.
    #[cfg(feature = "zeroize")]
    pub(crate) fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.username.zeroize();
        self.password.zeroize();
        self.username_raw.zeroize();
        self.password_raw.zeroize();
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials { username: [REDACTED], password: [REDACTED] }")
    }
}

#[cfg(feature = "zeroize")]
impl Drop for Credentials {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(all(test, feature = "zeroize"))]
impl Credentials {
    /// Test-only view of the raw byte vectors (both `None` or empty after `wipe`).
    pub(crate) fn raw_parts(&self) -> (Option<&[u8]>, Option<&[u8]>) {
        (self.username_raw.as_deref(), self.password_raw.as_deref())
    }
}
