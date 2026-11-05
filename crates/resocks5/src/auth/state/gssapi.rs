//! GSSAPI (Kerberos) clients: the accounts they map to and the acceptor.
//!
//! A GSSAPI user is an account named exactly like its authenticated principal
//! (`alice@EXAMPLE.COM`), with the `hash` value `gssapi`: it has no password
//! and no secure-auth secret, and logs in through Kerberos only. The account's
//! `enabled`, `direct` and `allowed_clients` apply as for any other.

use anyhow::{bail, Result};

#[cfg(feature = "gssapi")]
use super::AuthState;
use crate::config::AuthConfig;

/// The `hash` of an account that has no password and logs in through GSSAPI
/// only.
pub(crate) const GSSAPI_HASH: &str = "gssapi";

#[cfg(feature = "gssapi")]
pub(super) fn configured_acceptor(
    cfg: &AuthConfig,
) -> Result<Option<resocks5_net::gssapi::GssAcceptor>> {
    use resocks5_net::gssapi::Protection;

    let Some(service) = cfg.gssapi_service.as_deref() else {
        if cfg.gssapi_min_protection.is_some() {
            bail!("auth.gssapi_min_protection is set without auth.gssapi_service");
        }
        return Ok(None);
    };
    let min = match cfg.gssapi_min_protection.as_deref() {
        None | Some("integrity") => Protection::Integrity,
        Some("confidentiality") => Protection::Confidential,
        Some(other) => bail!(
            "auth.gssapi_min_protection: unknown value {other:?} (integrity or confidentiality)"
        ),
    };
    #[cfg(feature = "gssapi-system")]
    {
        use resocks5_net::gssapi::system::SystemBackend;
        let backend = if service == "*" {
            SystemBackend::new()
        } else {
            SystemBackend::new().with_acceptor(service)
        };
        Ok(Some(
            resocks5_net::gssapi::GssAcceptor::new(backend.shared()).with_min_protection(min),
        ))
    }
    #[cfg(not(feature = "gssapi-system"))]
    {
        let _ = (service, min);
        bail!(
            "auth.gssapi_service is set but this build has no Kerberos backend \
             (build with the `gssapi-system` feature)"
        )
    }
}

#[cfg(not(feature = "gssapi"))]
pub(super) fn refuse_without_support(cfg: &AuthConfig) -> Result<()> {
    if cfg.gssapi_service.is_some() || cfg.gssapi_min_protection.is_some() {
        bail!(
            "auth.gssapi_service is set but this build has no GSSAPI support \
             (build with the `gssapi-system` feature)"
        );
    }
    Ok(())
}

#[cfg(feature = "gssapi")]
impl AuthState {
    /// Use `acceptor` for GSSAPI clients instead of the configured one (tests
    /// bring a mock mechanism).
    #[cfg(test)]
    #[must_use]
    pub fn with_gssapi(mut self, acceptor: resocks5_net::gssapi::GssAcceptor) -> Self {
        self.gssapi = Some(acceptor);
        self
    }

    /// The GSSAPI acceptor, when GSSAPI is enabled.
    pub fn gssapi_acceptor(&self) -> Option<&resocks5_net::gssapi::GssAcceptor> {
        self.gssapi.as_ref()
    }

    /// The account an authenticated principal logs in as: the enabled account
    /// named exactly like it whose `allowed_clients` admit `ip`. `None` for an
    /// unknown, disabled or filtered principal.
    pub(crate) fn gssapi_account(
        &self,
        principal: &str,
        ip: Option<std::net::IpAddr>,
    ) -> Option<String> {
        self.client_ip_allowed(principal, ip)
            .then(|| principal.to_owned())
    }
}
