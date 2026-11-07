use std::net::IpAddr;
use std::sync::Arc;

use resocks5_net::secure_auth::{KdfParams, SecretStore, StoredUser, UserSecret};

use super::AuthState;

/// The secret store one connection authenticates against: the shared
/// [`AuthState`] seen through the peer's address. A user whose
/// `allowed_clients` rule rejects the peer is unknown here (decoy), and
/// cannot be enrolled from it.
pub struct PeerStore {
    auth: Arc<AuthState>,
    peer_ip: Option<IpAddr>,
}

impl PeerStore {
    pub(super) fn new(auth: Arc<AuthState>, peer_ip: Option<IpAddr>) -> Self {
        Self { auth, peer_ip }
    }
}

impl SecretStore for PeerStore {
    async fn lookup(&self, user: &str) -> Option<StoredUser> {
        if !self.auth.client_ip_allowed(user, self.peer_ip) {
            return None;
        }
        self.auth.lookup_secret(user)
    }

    async fn claim(&self, user: &str, secret: UserSecret) -> bool {
        self.auth.client_ip_allowed(user, self.peer_ip)
            && self.auth.claim_secret(user, secret).await
    }

    fn enrollment_floor(&self) -> KdfParams {
        self.auth.enrollment_floor
    }
}
