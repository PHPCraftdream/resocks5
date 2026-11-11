//! The stored form of a user's secret in `resocks5.users.ktav`.
//!
//! The value is an Argon2id v19 PHC string,
//! `$argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<key>`: `<key>` is the
//! 32-byte `K = Argon2id(password, salt, m, t, p)` the secure-auth exchange
//! proves knowledge of. The password itself is never stored. Hashes written
//! by earlier versions have exactly this shape, so existing accounts keep
//! working unchanged.

use argon2::password_hash::phc::{Error as PhcError, PasswordHash};
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine as _;
use resocks5_net::secure_auth::{KdfParams, UserSecret, KEY_LEN};

/// Why a stored value is not a usable secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretError {
    /// Not a PHC string at all.
    Format,
    /// Another algorithm or version than Argon2id v19.
    Algorithm,
    /// Missing, unknown or out-of-range `m`/`t`/`p` parameters.
    Params,
    /// A salt outside 8..=64 bytes.
    Salt,
    /// A key that is not 32 bytes long.
    Key,
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Format => "not an Argon2id PHC string",
            Self::Algorithm => "not Argon2id v19",
            Self::Params => "unsupported Argon2 parameters",
            Self::Salt => "salt outside 8..=64 bytes",
            Self::Key => "key is not 32 bytes",
        })
    }
}

/// Parse a stored value into a secret.
///
/// # Errors
///
/// [`SecretError`] naming what is wrong; the value itself is never echoed.
pub fn parse_secret(stored: &str) -> Result<UserSecret, SecretError> {
    let phc = PasswordHash::new(stored).map_err(|error| match error {
        // The PHC parser enforces the 8..=48 byte salt range itself.
        PhcError::SaltTooShort | PhcError::SaltTooLong => SecretError::Salt,
        _ => SecretError::Format,
    })?;
    if phc.algorithm != argon2::ARGON2ID_IDENT || phc.version.is_some_and(|v| v != 0x13) {
        return Err(SecretError::Algorithm);
    }
    let mut params = [None; 3];
    for (name, value) in phc.params.iter() {
        let slot = match name.as_str() {
            "m" => 0,
            "t" => 1,
            "p" => 2,
            // `keyid`/`data` would change the derivation: refuse them.
            _ => return Err(SecretError::Params),
        };
        params[slot] = Some(value.decimal().map_err(|_| SecretError::Params)?);
    }
    let [Some(memory_kib), Some(iterations), Some(parallelism)] = params else {
        return Err(SecretError::Params);
    };
    let params = KdfParams {
        memory_kib,
        iterations,
        parallelism,
    };
    let salt = phc.salt.ok_or(SecretError::Salt)?.to_vec();
    let key: [u8; KEY_LEN] = phc
        .hash
        .ok_or(SecretError::Key)?
        .as_bytes()
        .try_into()
        .map_err(|_| SecretError::Key)?;
    UserSecret::from_parts(salt, params, key).map_err(|error| match error {
        resocks5_net::SecureAuthError::BadLength => SecretError::Salt,
        _ => SecretError::Params,
    })
}

/// The stored form of `secret` (inverse of [`parse_secret`]).
pub fn encode_secret(secret: &UserSecret) -> String {
    let KdfParams {
        memory_kib,
        iterations,
        parallelism,
    } = secret.params;
    format!(
        "$argon2id$v=19$m={memory_kib},t={iterations},p={parallelism}${}${}",
        B64.encode(&secret.salt),
        B64.encode(secret.key())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::PasswordHasher;
    use argon2::{Algorithm, Argon2, Params, Version};
    use resocks5_net::secure_auth::derive_key;

    const WEAK: KdfParams = KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    /// Encoding and parsing are inverse. Mutation: swapping salt and key, or
    /// dropping a parameter, fails the comparison.
    #[test]
    fn a_secret_round_trips() {
        let secret = UserSecret::from_password("round-trip-pw", WEAK).unwrap();
        let stored = encode_secret(&secret);
        assert!(
            stored.starts_with("$argon2id$v=19$m=64,t=1,p=1$"),
            "{stored}"
        );
        let back = parse_secret(&stored).unwrap();
        assert_eq!(back.salt, secret.salt);
        assert_eq!(back.params, secret.params);
        assert_eq!(back.key(), secret.key());
    }

    /// A hash written by the old password-verify code (argon2's PHC hasher)
    /// parses into exactly the key the secure-auth client derives from the
    /// same password: old accounts keep working. Mutation: decoding the salt
    /// as its base64 text instead of its bytes derives another key.
    #[test]
    fn an_old_password_hash_is_the_secure_auth_key() {
        let argon = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(64, 1, 1, None).unwrap(),
        );
        let old = argon
            .hash_password_with_salt(b"legacy-password", b"0123456789abcdef")
            .unwrap()
            .to_string();
        let secret = parse_secret(&old).unwrap();
        assert_eq!(secret.salt, b"0123456789abcdef");
        let derived = derive_key(b"legacy-password", &secret.salt, &secret.params).unwrap();
        assert_eq!(secret.key(), &*derived);
    }

    /// Anything else is refused with a reason, never echoed. Mutation:
    /// accepting argon2i, a `keyid`, or a short key fails one row.
    #[test]
    fn unusable_values_are_refused() {
        let salt = B64.encode(b"0123456789abcdef");
        let key = B64.encode([7u8; 32]);
        let short = B64.encode([7u8; 16]);
        for (stored, error) in [
            ("init".to_owned(), SecretError::Format),
            ("plain-text".to_owned(), SecretError::Format),
            (
                format!("$argon2i$v=19$m=64,t=1,p=1${salt}${key}"),
                SecretError::Algorithm,
            ),
            (
                format!("$argon2id$v=16$m=64,t=1,p=1${salt}${key}"),
                SecretError::Algorithm,
            ),
            (
                format!("$argon2id$v=19$m=64,t=1${salt}${key}"),
                SecretError::Params,
            ),
            (
                format!("$argon2id$v=19$m=64,t=1,p=1,keyid=AAAA${salt}${key}"),
                SecretError::Params,
            ),
            (
                format!("$argon2id$v=19$m=4,t=1,p=1${salt}${key}"),
                SecretError::Params,
            ),
            (
                format!("$argon2id$v=19$m=64,t=1,p=1$AAAAAA${key}"),
                SecretError::Salt,
            ),
            (
                format!("$argon2id$v=19$m=64,t=1,p=1${salt}${short}"),
                SecretError::Key,
            ),
            (
                format!("$argon2id$v=19$m=64,t=1,p=1${salt}"),
                SecretError::Key,
            ),
        ] {
            assert_eq!(parse_secret(&stored).unwrap_err(), error, "{stored}");
        }
    }
}
