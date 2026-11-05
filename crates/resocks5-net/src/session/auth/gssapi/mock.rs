//! A mock GSSAPI mechanism for tests: NOT a security mechanism.
//!
//! [`MockBackend`] plays a tiny Kerberos-like mechanism with a shared "KDC key":
//! the client token proves it holds a ticket for a principal and service, the
//! server answers with a mutual-authentication token, and messages carry a
//! sequence number, a direction and an HMAC (plus a keystream when
//! confidentiality is requested). It exists so the RFC 1961 protocol layer is
//! tested end to end without a KDC; the real mechanism is the system backend.

use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{GssBackend, GssContext, GssStep};
use crate::error::GssapiError;

type HmacSha256 = Hmac<Sha256>;

const NONCE_LEN: usize = 16;
const MAC_LEN: usize = 32;

fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; MAC_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(&(part.len() as u32).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn verify(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    let mut check = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        check.update(&(part.len() as u32).to_be_bytes());
        check.update(part);
    }
    check.verify_slice(tag).is_ok()
}

fn backend_error(reason: &str) -> GssapiError {
    GssapiError::Backend(reason.to_owned())
}

/// The mock mechanism. `kdc_key` is the secret the "KDC" shares with both
/// sides; `principal` is the identity a client authenticates as, `service`
/// the name an acceptor answers to.
#[derive(Clone)]
pub struct MockBackend {
    kdc_key: [u8; 32],
    principal: Option<String>,
    service: Option<String>,
}

impl MockBackend {
    /// A backend trusting `kdc_key`.
    pub fn new(kdc_key: [u8; 32]) -> Self {
        Self {
            kdc_key,
            principal: None,
            service: None,
        }
    }

    /// The identity clients of this backend authenticate as.
    #[must_use]
    pub fn with_principal(mut self, principal: impl Into<String>) -> Self {
        self.principal = Some(principal.into());
        self
    }

    /// The service name an acceptor of this backend answers to.
    #[must_use]
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// This backend behind an `Arc`, as the credential types take it.
    pub fn shared(self) -> Arc<dyn GssBackend> {
        Arc::new(self)
    }
}

impl GssBackend for MockBackend {
    fn initiate(&self, target: &str) -> Result<Box<dyn GssContext>, GssapiError> {
        let principal = self
            .principal
            .clone()
            .ok_or_else(|| backend_error("no credentials (no ticket)"))?;
        Ok(Box::new(MockContext::new(
            self.kdc_key,
            Role::Client {
                principal,
                service: target.to_owned(),
            },
        )))
    }

    fn accept(&self) -> Result<Box<dyn GssContext>, GssapiError> {
        let service = self
            .service
            .clone()
            .ok_or_else(|| backend_error("no acceptor credentials (no keytab)"))?;
        Ok(Box::new(MockContext::new(
            self.kdc_key,
            Role::Server { service },
        )))
    }
}

enum Role {
    Client { principal: String, service: String },
    Server { service: String },
}

struct MockContext {
    kdc_key: [u8; 32],
    role: Role,
    nonce: [u8; NONCE_LEN],
    session_key: Option<[u8; 32]>,
    peer: Option<String>,
    send_seq: u64,
    recv_seq: u64,
    sent_first: bool,
}

impl MockContext {
    fn new(kdc_key: [u8; 32], role: Role) -> Self {
        Self {
            kdc_key,
            role,
            nonce: [0; NONCE_LEN],
            session_key: None,
            peer: None,
            send_seq: 0,
            recv_seq: 0,
            sent_first: false,
        }
    }

    fn is_client(&self) -> bool {
        matches!(self.role, Role::Client { .. })
    }

    /// Direction byte of what THIS side sends: reflection of a message back
    /// to its sender fails the MAC.
    fn send_dir(&self) -> u8 {
        u8::from(!self.is_client())
    }

    fn keystream(key: &[u8; 32], dir: u8, seq: u64, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + MAC_LEN);
        let mut counter = 0u32;
        while out.len() < len {
            out.extend_from_slice(&mac(
                key,
                &[b"ks", &[dir], &seq.to_be_bytes(), &counter.to_be_bytes()],
            ));
            counter += 1;
        }
        out.truncate(len);
        out
    }
}

impl GssContext for MockContext {
    fn step(&mut self, input: Option<&[u8]>) -> Result<GssStep, GssapiError> {
        match &self.role {
            Role::Client { principal, service } => {
                if !self.sent_first {
                    self.sent_first = true;
                    getrandom::getrandom(&mut self.nonce).map_err(|_| backend_error("rng"))?;
                    let tag = mac(
                        &self.kdc_key,
                        &[
                            b"req",
                            principal.as_bytes(),
                            service.as_bytes(),
                            &self.nonce,
                        ],
                    );
                    let mut token = vec![u8::try_from(principal.len()).unwrap_or(u8::MAX)];
                    token.extend_from_slice(principal.as_bytes());
                    token.push(u8::try_from(service.len()).unwrap_or(u8::MAX));
                    token.extend_from_slice(service.as_bytes());
                    token.extend_from_slice(&self.nonce);
                    token.extend_from_slice(&tag);
                    return Ok(GssStep {
                        token: Some(token),
                        done: false,
                    });
                }
                let reply = input.ok_or_else(|| backend_error("missing server token"))?;
                if !verify(&self.kdc_key, &[b"rep", &self.nonce], reply) {
                    return Err(backend_error("the server failed mutual authentication"));
                }
                self.session_key = Some(mac(&self.kdc_key, &[b"sess", &self.nonce]));
                self.peer = Some(service.clone());
                Ok(GssStep {
                    token: None,
                    done: true,
                })
            }
            Role::Server { service } => {
                let token = input.ok_or_else(|| backend_error("missing client token"))?;
                let (&plen, rest) = token.split_first().ok_or_else(|| backend_error("short"))?;
                if rest.len() < usize::from(plen) + 1 {
                    return Err(backend_error("short token"));
                }
                let (principal, rest) = rest.split_at(usize::from(plen));
                let (&slen, rest) = rest.split_first().ok_or_else(|| backend_error("short"))?;
                if rest.len() != usize::from(slen) + NONCE_LEN + MAC_LEN {
                    return Err(backend_error("bad token length"));
                }
                let (target, rest) = rest.split_at(usize::from(slen));
                let (nonce, tag) = rest.split_at(NONCE_LEN);
                if !verify(&self.kdc_key, &[b"req", principal, target, nonce], tag) {
                    return Err(backend_error("ticket does not verify"));
                }
                if target != service.as_bytes() {
                    return Err(backend_error("ticket is for another service"));
                }
                self.nonce.copy_from_slice(nonce);
                self.session_key = Some(mac(&self.kdc_key, &[b"sess", &self.nonce]));
                self.peer = Some(String::from_utf8_lossy(principal).into_owned());
                Ok(GssStep {
                    token: Some(mac(&self.kdc_key, &[b"rep", &self.nonce]).to_vec()),
                    done: true,
                })
            }
        }
    }

    fn peer_name(&self) -> Option<String> {
        self.peer.clone()
    }

    fn wrap(&mut self, data: &[u8], confidential: bool) -> Result<Vec<u8>, GssapiError> {
        let key = self.session_key.ok_or(GssapiError::NotEstablished)?;
        let dir = self.send_dir();
        let seq = self.send_seq;
        self.send_seq += 1;
        let body = if confidential {
            let stream = Self::keystream(&key, dir, seq, data.len());
            data.iter().zip(stream).map(|(d, k)| d ^ k).collect()
        } else {
            data.to_vec()
        };
        let flag = u8::from(confidential);
        let tag = mac(&key, &[b"msg", &[dir], &seq.to_be_bytes(), &[flag], &body]);
        let mut out = Vec::with_capacity(9 + body.len() + MAC_LEN);
        out.extend_from_slice(&seq.to_be_bytes());
        out.push(flag);
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn unwrap(&mut self, token: &[u8]) -> Result<Vec<u8>, GssapiError> {
        let key = self.session_key.ok_or(GssapiError::NotEstablished)?;
        if token.len() < 9 + MAC_LEN {
            return Err(GssapiError::Integrity);
        }
        let (seq_bytes, rest) = token.split_at(8);
        let seq = u64::from_be_bytes(seq_bytes.try_into().expect("8 bytes"));
        let (flag, rest) = (rest[0], &rest[1..]);
        let (body, tag) = rest.split_at(rest.len() - MAC_LEN);
        // What the peer sent travels in the opposite direction to ours.
        let dir = 1 - self.send_dir();
        if !verify(
            &key,
            &[b"msg", &[dir], &seq.to_be_bytes(), &[flag], body],
            tag,
        ) || seq != self.recv_seq
        {
            return Err(GssapiError::Integrity);
        }
        self.recv_seq += 1;
        Ok(if flag == 1 {
            let stream = Self::keystream(&key, dir, seq, body.len());
            body.iter().zip(stream).map(|(d, k)| d ^ k).collect()
        } else {
            body.to_vec()
        })
    }
}
