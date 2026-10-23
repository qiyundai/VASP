use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub interval: u64,
    pub next_at: u64,
    pub last_success: Option<u64>,
    pub failures: u32,
    pub last_error: Option<String>,
}
impl Schedule {
    pub fn new(interval: u64) -> Self {
        Self {
            interval,
            next_at: 0,
            last_success: None,
            failures: 0,
            last_error: None,
        }
    }
    pub fn due(&self, now: u64) -> bool {
        now >= self.next_at
    }
    pub fn success(&mut self, now: u64) {
        self.last_success = Some(now);
        self.failures = 0;
        self.last_error = None;
        self.next_at = now.saturating_add(self.interval);
    }
    pub fn failure(&mut self, now: u64, error: String) {
        self.failures = self.failures.saturating_add(1);
        self.last_error = Some(error.chars().take(512).collect());
        self.next_at = now.saturating_add(
            60_u64
                .saturating_mul(1_u64 << self.failures.min(9))
                .min(21600),
        );
    }
    pub fn stale(&self, now: u64) -> bool {
        self.last_success
            .is_none_or(|t| t > now || now - t > self.interval.saturating_mul(3).max(3600))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backoff_is_bounded() {
        let mut s = Schedule::new(1800);
        for _ in 0..100 {
            s.failure(10, "offline".into());
        }
        assert!(s.next_at <= 21610);
        assert!(s.stale(10));
        s.success(100);
        assert!(!s.stale(101));
        assert!(s.stale(99));
    }
}
