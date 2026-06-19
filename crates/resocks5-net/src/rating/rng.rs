/// Minimal splitmix64 PRNG — no external `rand` dependency required.
pub struct SmallRng {
    state: u64,
}

impl SmallRng {
    /// Create from a fixed seed (deterministic).
    pub fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Create from OS entropy.
    pub fn from_os() -> Self {
        // Use std::time + std::thread::current().id() as entropy sources.
        // This is not cryptographic quality, but sufficient for weighted
        // random selection in a proxy rotator.
        let time_nanos = {
            let dur = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            dur.as_nanos() as u64
        };
        let thread_id = {
            // Thread ids are opaque; hash via Debug formatting.
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::thread::current().id().hash(&mut hasher);
            hasher.finish()
        };
        Self {
            state: time_nanos ^ thread_id,
        }
    }

    /// Produce the next pseudo-random `u64` (splitmix64).
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// Uniform `f64` in `[0, 1)` with 53-bit resolution.
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_determinism() {
        let mut a = SmallRng::from_seed(123);
        let mut b = SmallRng::from_seed(123);
        for i in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64(), "diverged at step {i}");
        }
    }

    #[test]
    fn next_f64_in_unit_interval() {
        let mut rng = SmallRng::from_seed(42);
        for _ in 0..10_000 {
            let v = rng.next_f64();
            assert!((0.0..1.0).contains(&v), "out of range: {v}");
        }
    }

    #[test]
    fn mean_close_to_half() {
        let mut rng = SmallRng::from_seed(42);
        let n = 100_000;
        let sum: f64 = (0..n).map(|_| rng.next_f64()).sum();
        let mean = sum / n as f64;
        assert!((mean - 0.5).abs() < 0.01, "mean = {mean}, expected ~0.5");
    }
}
