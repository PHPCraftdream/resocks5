//! The system GSS-API as a [`GssBackend`] (feature `gssapi-system`): Kerberos 5
//! through the platform's MIT Kerberos, Heimdal or Apple GSS library.
//!
//! * Client: acquires the default credentials (the credential cache — run
//!   `kinit`, or point `KRB5CCNAME` at one) and authenticates to the service
//!   `service@host` (a GSS host-based name, i.e. the principal
//!   `service/host@REALM`). Requested flags: mutual authentication, replay and
//!   sequence protection, integrity and confidentiality. Credential delegation
//!   is deliberately not requested: a proxy has no business holding a TGT.
//! * Server: acquires acceptor credentials from the keytab (`KRB5_KTNAME`, or
//!   the system default), for one service name or any principal it holds.
//!
//! The Kerberos library may contact the KDC while a client context is being
//! initialised (to obtain a service ticket once per ticket lifetime) and does
//! blocking I/O there; call from a multi-threaded runtime.

use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext, ServerCtx};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{OidSet, GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE};

use super::{GssBackend, GssContext, GssStep};
use crate::error::GssapiError;

fn backend(error: impl std::fmt::Display) -> GssapiError {
    GssapiError::Backend(error.to_string())
}

/// Kerberos 5 through the system GSS-API.
#[derive(Debug, Clone, Default)]
pub struct SystemBackend {
    acceptor: Option<String>,
}

impl SystemBackend {
    /// A backend for clients, or for a server accepting any principal in its
    /// keytab.
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept only as the host-based service `service` (`service@host`).
    #[must_use]
    pub fn with_acceptor(mut self, service: impl Into<String>) -> Self {
        self.acceptor = Some(service.into());
        self
    }

    /// This backend behind an `Arc`, as the credential types take it.
    pub fn shared(self) -> std::sync::Arc<dyn GssBackend> {
        std::sync::Arc::new(self)
    }
}

enum Ctx {
    Client(ClientCtx),
    Server(ServerCtx),
}

struct SystemContext(Ctx);

impl GssContext for SystemContext {
    fn step(&mut self, input: Option<&[u8]>) -> Result<GssStep, GssapiError> {
        let token = match &mut self.0 {
            Ctx::Client(ctx) => ctx.step(input, None),
            Ctx::Server(ctx) => {
                ctx.step(input.ok_or_else(|| backend("missing client token"))?, None)
            }
        }
        .map_err(backend)?;
        let done = match &self.0 {
            Ctx::Client(ctx) => ctx.is_complete(),
            Ctx::Server(ctx) => ctx.is_complete(),
        };
        Ok(GssStep {
            token: token.map(|buf| buf.to_vec()),
            done,
        })
    }

    fn peer_name(&self) -> Option<String> {
        match &self.0 {
            Ctx::Client(ctx) => ctx.target_name().ok().map(|name| name.to_string()),
            Ctx::Server(ctx) => ctx.source_name().ok().map(|name| name.to_string()),
        }
    }

    fn wrap(&mut self, data: &[u8], confidential: bool) -> Result<Vec<u8>, GssapiError> {
        let token = match &mut self.0 {
            Ctx::Client(ctx) => ctx.wrap(confidential, data),
            Ctx::Server(ctx) => ctx.wrap(confidential, data),
        }
        .map_err(backend)?;
        Ok(token.to_vec())
    }

    fn unwrap(&mut self, token: &[u8]) -> Result<Vec<u8>, GssapiError> {
        let data = match &mut self.0 {
            Ctx::Client(ctx) => ctx.unwrap(token),
            Ctx::Server(ctx) => ctx.unwrap(token),
        }
        .map_err(|_| GssapiError::Integrity)?;
        Ok(data.to_vec())
    }
}

fn kerberos_mechs() -> Result<OidSet, GssapiError> {
    OidSet::singleton(GSS_MECH_KRB5).map_err(backend)
}

impl GssBackend for SystemBackend {
    fn initiate(&self, target: &str) -> Result<Box<dyn GssContext>, GssapiError> {
        let name = Name::new(target.as_bytes(), Some(GSS_NT_HOSTBASED_SERVICE)).map_err(backend)?;
        let cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&kerberos_mechs()?))
            .map_err(|error| backend(format!("no usable credentials (kinit?): {error}")))?;
        let flags = CtxFlags::GSS_C_MUTUAL_FLAG
            | CtxFlags::GSS_C_REPLAY_FLAG
            | CtxFlags::GSS_C_SEQUENCE_FLAG
            | CtxFlags::GSS_C_INTEG_FLAG
            | CtxFlags::GSS_C_CONF_FLAG;
        Ok(Box::new(SystemContext(Ctx::Client(ClientCtx::new(
            Some(cred),
            name,
            flags,
            Some(GSS_MECH_KRB5),
        )))))
    }

    fn accept(&self) -> Result<Box<dyn GssContext>, GssapiError> {
        let name = match &self.acceptor {
            Some(service) => Some(
                Name::new(service.as_bytes(), Some(GSS_NT_HOSTBASED_SERVICE))
                    .and_then(|name| name.canonicalize(Some(GSS_MECH_KRB5)))
                    .map_err(backend)?,
            ),
            None => None,
        };
        let cred = Cred::acquire(
            name.as_ref(),
            None,
            CredUsage::Accept,
            Some(&kerberos_mechs()?),
        )
        .map_err(|error| backend(format!("no acceptor credentials (keytab?): {error}")))?;
        Ok(Box::new(SystemContext(Ctx::Server(ServerCtx::new(Some(
            cred,
        ))))))
    }
}

/// Real Kerberos: needs a KDC, a keytab and a ticket. Run by the
/// `gssapi-system` CI job (`.github/checks/kdc-test.sh`), which sets
/// `KRB5_CONFIG`, `KRB5CCNAME` (a TGT for `GSS_TEST_PRINCIPAL`) and
/// `KRB5_KTNAME` (the key of `socks/kdc.test.local`) and `GSS_TEST_SERVICE`.
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{timeout, Instant};

    use super::SystemBackend;
    use crate::connect::{dial_tcp, DialOptions};
    use crate::gssapi::{client_gssapi, server_gssapi, GssAcceptor, GssCredentials, Protection};
    use crate::server::{accept_with, AuthMethod, AuthMethods, NoSecrets, Reply, ServerOptions};
    use crate::types::ProxyConfig;
    use crate::GssapiError;

    fn service() -> String {
        std::env::var("GSS_TEST_SERVICE").expect("GSS_TEST_SERVICE (set by kdc-test.sh)")
    }

    fn principal() -> String {
        std::env::var("GSS_TEST_PRINCIPAL").expect("GSS_TEST_PRINCIPAL (set by kdc-test.sh)")
    }

    /// A real Kerberos exchange with protected messages enabled (level 2): the
    /// server learns the client's principal and a protected message
    /// round-trips.
    /// Mutation: a backend that does not verify the ticket, or reports the
    /// service as the peer, fails the principal.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a KDC: run by the gssapi-system CI job"]
    async fn a_real_kerberos_exchange() {
        let credentials = GssCredentials::new(SystemBackend::new().shared(), service())
            .with_requested_protection(Protection::Confidential)
            .with_min_protection(Protection::Confidential);
        let acceptor = GssAcceptor::new(SystemBackend::new().with_acceptor(service()).shared())
            .with_protection(Protection::Confidential);
        let (client, server) = duplex(16 * 1024);
        let (client, server) = tokio::join!(
            async move {
                let mut client = client;
                client_gssapi(&mut client, &credentials).await
            },
            async move {
                let mut server = server;
                server_gssapi(&mut server, &acceptor).await
            },
        );
        let mut client = client.unwrap();
        let (mut server, peer) = server.unwrap();
        assert_eq!(peer, principal());
        assert_eq!(client.protection(), Protection::Confidential);
        let sealed = client
            .seal(b"\x05\x01\x00\x01\x01\x02\x03\x04\x01\xbb")
            .unwrap();
        let mut reader = &sealed[..];
        assert_eq!(
            server.read_message(&mut reader).await.unwrap(),
            b"\x05\x01\x00\x01\x01\x02\x03\x04\x01\xbb"
        );
    }

    /// A service the KDC does not know is a typed backend failure, not a
    /// hang and not an anonymous fallback.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a KDC: run by the gssapi-system CI job"]
    async fn an_unknown_service_fails() {
        let credentials =
            GssCredentials::new(SystemBackend::new().shared(), "nosuch@kdc.test.local");
        let (mut client, _server) = duplex(4096);
        let error = client_gssapi(&mut client, &credentials).await.unwrap_err();
        assert!(matches!(error, GssapiError::Backend(_)), "{error:?}");
    }

    /// The whole path on a socket: `dial_tcp` with Kerberos against
    /// `accept_with`, SOCKS request and reply protected, tunnel echoing.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a KDC: run by the gssapi-system CI job"]
    async fn a_real_kerberos_dial_through_accept_with() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let acceptor = GssAcceptor::new(SystemBackend::new().with_acceptor(service()).shared());
            let options = ServerOptions::new(Instant::now() + Duration::from_secs(20), false, true);
            let methods = AuthMethods::<NoSecrets>::gssapi(&acceptor);
            let request = accept_with(&mut socket, &options, &methods).await.unwrap();
            request
                .reply(&mut socket, Reply::Established)
                .await
                .unwrap();
            let mut ping = [0u8; 4];
            socket.read_exact(&mut ping).await.unwrap();
            socket.write_all(&ping).await.unwrap();
            (request.auth_method(), request.username().map(str::to_owned))
        });
        let proxy = ProxyConfig::socks5("127.0.0.1", port).with_gssapi(GssCredentials::new(
            SystemBackend::new().shared(),
            service(),
        ));
        let mut tunnel = timeout(
            Duration::from_secs(30),
            dial_tcp(&proxy, "example.test", 443, &DialOptions::new()),
        )
        .await
        .unwrap()
        .unwrap();
        tunnel.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        tunnel.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
        let (method, user) = server.await.unwrap();
        assert_eq!(method, AuthMethod::Gssapi);
        assert_eq!(user, Some(principal()));
    }
}
