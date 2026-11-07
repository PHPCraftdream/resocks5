//! Owned inbound credentials; retention copies stay redacted and are optionally wiped.

use std::fmt;

/// Owned UTF-8 credentials supplied at most once per handshake.
/// Debug deliberately reveals neither username nor password.
pub struct Credentials {
    username: String,
    password: String,
    username_raw: Option<Vec<u8>>, // present only when UNAME was not valid UTF-8
    password_raw: Option<Vec<u8>>,
    basic_payload: Option<String>, // HTTP Basic only: the whole decoded token
}

impl Credentials {
    /// Build from an accepted username/password pair.
    pub(crate) fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
            username_raw: None,
            password_raw: None,
            basic_payload: None,
        }
    }

    /// Build from an HTTP Basic token: the pair split at the first `:` plus the
    /// whole decoded token (`payload`), kept verbatim.
    pub(crate) fn with_basic_payload(username: String, password: String, payload: String) -> Self {
        let mut credentials = Self::new(username, password);
        credentials.basic_payload = Some(payload);
        credentials
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
            basic_payload: None,
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
            basic_payload: self.basic_payload.clone(),
        }
    }

    /// The whole decoded HTTP Basic token, exactly as the client sent it
    /// (`user:pass`, split nowhere): `Some` for an HTTP Basic request, `None`
    /// for SOCKS5. Unlike `username()` / `password()` it never loses
    /// information: `"u:"` (empty password) and `"u:p:q"` (colon inside the
    /// password) stay unambiguous, and a gateway that forwards the token
    /// upstream needs no re-joining. The text is valid UTF-8 (a token that is
    /// not is refused with 407 before this point).
    pub fn basic_payload(&self) -> Option<&str> {
        self.basic_payload.as_deref()
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
        self.basic_payload.zeroize();
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
        #[cfg(test)]
        drop_observer::notify(self);
    }
}

#[cfg(all(test, feature = "zeroize"))]
pub(super) mod drop_observer {
    use super::Credentials;
    use std::cell::Cell;

    thread_local! {
        static OBSERVER: Cell<Option<fn(&Credentials)>> = const { Cell::new(None) };
    }

    pub(crate) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            OBSERVER.with(|slot| slot.set(None));
        }
    }

    pub(crate) fn install(observer: fn(&Credentials)) -> Guard {
        OBSERVER.with(|slot| {
            assert!(slot.get().is_none(), "nested credentials drop observer");
            slot.set(Some(observer));
        });
        Guard
    }

    pub(super) fn notify(credentials: &Credentials) {
        let observer = OBSERVER.try_with(Cell::get).ok().flatten();
        if let Some(observer) = observer {
            observer(credentials);
        }
    }
}

#[cfg(all(test, feature = "zeroize"))]
impl Credentials {
    /// Test-only view of the raw byte vectors (both `None` or empty after `wipe`).
    pub(crate) fn raw_parts(&self) -> (Option<&[u8]>, Option<&[u8]>) {
        (self.username_raw.as_deref(), self.password_raw.as_deref())
    }
}
