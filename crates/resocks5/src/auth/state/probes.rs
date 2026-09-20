#[cfg(test)]
use super::AuthState;

/// R7-04 test-only probe plumbing. The whole impl compiles to nothing
/// outside test builds. Never blocks and never fails: emits drop when no
/// probe is installed, and a send to a receiver whose test half is gone
/// is dropped as well.
#[cfg(test)]
impl AuthState {
    pub(super) fn install_claim_probe(&mut self, tx: std::sync::mpsc::Sender<&'static str>) {
        *self.claim_probe.lock().expect("claim probe mutex poisoned") = Some(tx);
    }

    pub(super) fn claim_probe_emit(&self, event: &'static str) {
        let probe = self.claim_probe.lock().expect("claim probe mutex poisoned");
        if let Some(tx) = probe.as_ref() {
            let _ = tx.send(event);
        }
    }
}
