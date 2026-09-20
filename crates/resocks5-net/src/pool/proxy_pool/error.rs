/// Sentinel error returned when the per-upstream semaphore is full.
/// `establish_connection` uses `downcast_ref::<AtCapacity>()` to
/// distinguish "our load" from "upstream is broken" — the former
/// must NOT feed the sand-model failure signal.
#[derive(Clone)]
pub struct AtCapacity {
    /// The host of the upstream whose cap was hit.
    pub host: String,
    /// The port of the upstream whose cap was hit.
    pub port: u16,
}

impl std::fmt::Display for AtCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "upstream cap reached for {}:{}", self.host, self.port)
    }
}

impl std::fmt::Debug for AtCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AtCapacity({}:{})", self.host, self.port)
    }
}

impl std::error::Error for AtCapacity {}
