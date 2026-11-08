use std::path::Path;

use resocks5_net::secure_auth::KdfParams;
use serde::{Deserialize, Serialize};

use crate::auth::params::default_params;

/// Argon2id cost of NEW user secrets (`resocks5 users add` / `set-password`,
/// the first-login claim of an `init` account) and the cheapest cost an
/// `init` enrollment may use. Existing secrets keep the parameters stored with
/// them, so changing this never invalidates a users file. The section and each
/// field are optional; the defaults are the OWASP minimum (19 MiB, 2 passes,
/// 1 lane). A lower cost makes a stolen users file cheaper to attack offline;
/// a higher one costs more memory and time per login. Limits: `parallelism`
/// 1..=16, `iterations` 1..=16, `memory_kib` from `8 * parallelism` to 262144.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Config {
    /// Memory cost in KiB per derivation.
    #[serde(default = "default_memory_kib")]
    pub memory_kib: u32,
    /// Number of passes over the memory.
    #[serde(default = "default_iterations")]
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    #[serde(default = "default_parallelism")]
    pub parallelism: u32,
}

fn default_memory_kib() -> u32 {
    default_params().memory_kib
}

fn default_iterations() -> u32 {
    default_params().iterations
}

fn default_parallelism() -> u32 {
    default_params().parallelism
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self::from(default_params())
    }
}

impl From<KdfParams> for Argon2Config {
    fn from(params: KdfParams) -> Self {
        Self {
            memory_kib: params.memory_kib,
            iterations: params.iterations,
            parallelism: params.parallelism,
        }
    }
}

impl Argon2Config {
    /// The validated cost. Out-of-range values are an error naming the
    /// section (never silently clamped), so a typo cannot weaken or bomb the
    /// server.
    pub fn to_params(self) -> Result<KdfParams, String> {
        let params = KdfParams {
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        };
        if params.is_in_range() {
            Ok(params)
        } else {
            Err(format!(
                "auth.argon2 (memory_kib={}, iterations={}, parallelism={}) is out of range: \
                 parallelism 1..=16, iterations 1..=16, memory_kib from 8 * parallelism \
                 to 262144",
                self.memory_kib, self.iterations, self.parallelism
            ))
        }
    }
}

/// The cost the `users` subcommands create secrets with: `auth.argon2` of the
/// main config when that file exists and parses, otherwise the default. A
/// broken main config must not block user management (the subcommands never
/// require it), so a problem is reported on stderr and the default is used.
pub fn cost_for_cli(main_path: &Path) -> KdfParams {
    #[derive(Deserialize)]
    struct OnlyAuth {
        #[serde(default)]
        auth: OnlyArgon2,
    }
    #[derive(Deserialize, Default)]
    struct OnlyArgon2 {
        #[serde(default)]
        argon2: Argon2Config,
    }
    if !main_path.exists() {
        return default_params();
    }
    let parsed: Result<OnlyAuth, _> = ktav::from_file(main_path);
    let loaded = parsed
        .map_err(|e| e.to_string())
        .and_then(|cfg| cfg.auth.argon2.to_params());
    match loaded {
        Ok(params) => params,
        Err(error) => {
            eprintln!(
                "warning: {}: {error}; using the default Argon2id cost",
                main_path.display()
            );
            default_params()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A section with only some fields takes the defaults for the rest, and
    /// an empty/absent section is the default. Mutation: removing a field's
    /// `#[serde(default)]` makes the partial parse fail.
    #[test]
    fn missing_fields_take_the_defaults() {
        let cfg: crate::config::MainConfig =
            ktav::from_str("port: 1\nauth: { argon2: { memory_kib: 9000 } }\n").unwrap();
        assert_eq!(cfg.auth.argon2.memory_kib, 9000);
        assert_eq!(cfg.auth.argon2.iterations, default_params().iterations);
        assert_eq!(cfg.auth.argon2.parallelism, default_params().parallelism);
        let none: crate::config::MainConfig = ktav::from_str("port: 1\nauth: {}\n").unwrap();
        assert_eq!(none.auth.argon2, Argon2Config::default());
    }

    /// Explicit values are honoured and converted exactly. Mutation: a swapped
    /// field in `to_params` fails here.
    #[test]
    fn explicit_values_become_the_kdf_parameters() {
        let cfg = Argon2Config {
            memory_kib: 8192,
            iterations: 3,
            parallelism: 2,
        };
        assert_eq!(
            cfg.to_params().unwrap(),
            KdfParams {
                memory_kib: 8192,
                iterations: 3,
                parallelism: 2
            }
        );
    }

    /// Out-of-range values are refused with a message that names the section,
    /// not clamped. Mutation: skipping the range check lets a zero or a
    /// 4 GiB value through.
    #[test]
    fn out_of_range_values_are_refused() {
        for bad in [
            Argon2Config {
                memory_kib: 0,
                iterations: 2,
                parallelism: 1,
            },
            Argon2Config {
                memory_kib: 19456,
                iterations: 0,
                parallelism: 1,
            },
            Argon2Config {
                memory_kib: 19456,
                iterations: 2,
                parallelism: 0,
            },
            Argon2Config {
                memory_kib: 4_000_000,
                iterations: 2,
                parallelism: 1,
            },
            Argon2Config {
                memory_kib: 8,
                iterations: 2,
                parallelism: 2,
            },
        ] {
            let error = bad.to_params().unwrap_err();
            assert!(error.contains("auth.argon2"), "{error}");
        }
    }

    /// The production default is the SDK default (the OWASP minimum) — the
    /// serde default of a release build. Mutation: diverging `PRODUCTION`
    /// from the SDK constant fails here.
    #[test]
    fn the_production_default_is_the_owasp_minimum() {
        assert_eq!(
            Argon2Config::from(crate::auth::params::PRODUCTION),
            Argon2Config {
                memory_kib: 19456,
                iterations: 2,
                parallelism: 1
            }
        );
    }

    /// The CLI reads `auth.argon2` from an existing main config, falls back
    /// to the default when the file is absent, and (with a warning) when it
    /// is broken or out of range. Mutation: ignoring the file always yields
    /// the default and fails the first assert.
    #[test]
    fn the_cli_cost_follows_the_main_config() {
        let dir = std::env::temp_dir().join(format!("resocks5-argon2-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("main.ktav");
        std::fs::write(
            &path,
            "port: 1\nauth: { argon2: { memory_kib: 12345, iterations: 4, parallelism: 1 } }\n",
        )
        .unwrap();
        assert_eq!(
            cost_for_cli(&path),
            KdfParams {
                memory_kib: 12345,
                iterations: 4,
                parallelism: 1
            }
        );
        std::fs::write(&path, "port: 1\nauth: { argon2: { memory_kib: 1 } }\n").unwrap();
        assert_eq!(cost_for_cli(&path), default_params());
        std::fs::write(&path, "not ktav {{{").unwrap();
        assert_eq!(cost_for_cli(&path), default_params());
        assert_eq!(cost_for_cli(&dir.join("absent.ktav")), default_params());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
