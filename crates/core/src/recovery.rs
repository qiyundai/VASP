//! Local recovery deadlines, independent of the model and wall-clock adjustments.
//! These values are intentionally not serializable: leases are never restored on boot.
use thiserror::Error;

#[derive(Clone, Copy, Debug)]
pub struct Sample {
    /// Windows interrupt time, including time spent asleep, in milliseconds.
    pub awake_and_sleep_ms: u64,
    pub wall_seconds: u64,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StopReason {
    #[error("lease expired")]
    Expired,
    #[error("heartbeat deadline missed")]
    HeartbeatLost,
    #[error("clock moved backwards")]
    ClockRegression,
    #[error("heartbeat sequence invalid")]
    InvalidHeartbeat,
}

/// A sticky deadline. A late heartbeat can never resurrect an expired lease.
pub struct RecoveryGuard {
    last: Sample,
    deadline_ms: u64,
    wall_deadline: u64,
    heartbeat_ms: u64,
    heartbeat_budget_ms: u64,
    sequence: u64,
    stopped: Option<StopReason>,
}

impl RecoveryGuard {
    pub fn new(
        now: Sample,
        lease_seconds: u64,
        heartbeat_budget_ms: u64,
    ) -> Result<Self, &'static str> {
        if !(1..=600).contains(&lease_seconds) || !(100..=10_000).contains(&heartbeat_budget_ms) {
            return Err("Invalid recovery deadline");
        }
        Ok(Self {
            last: now,
            deadline_ms: now
                .awake_and_sleep_ms
                .checked_add(lease_seconds * 1000)
                .ok_or("Clock overflow")?,
            wall_deadline: now
                .wall_seconds
                .checked_add(lease_seconds)
                .ok_or("Clock overflow")?,
            heartbeat_ms: now.awake_and_sleep_ms,
            heartbeat_budget_ms,
            sequence: 0,
            stopped: None,
        })
    }

    pub fn check(&mut self, now: Sample) -> Result<(), StopReason> {
        if let Some(reason) = self.stopped {
            return Err(reason);
        }
        let reason = if now.awake_and_sleep_ms < self.last.awake_and_sleep_ms
            || now.wall_seconds < self.last.wall_seconds
        {
            Some(StopReason::ClockRegression)
        } else if now.awake_and_sleep_ms >= self.deadline_ms
            || now.wall_seconds >= self.wall_deadline
        {
            Some(StopReason::Expired)
        } else if now.awake_and_sleep_ms.saturating_sub(self.heartbeat_ms)
            >= self.heartbeat_budget_ms
        {
            Some(StopReason::HeartbeatLost)
        } else {
            None
        };
        self.last = now;
        self.stopped = reason;
        reason.map_or(Ok(()), Err)
    }

    /// Called only for a heartbeat from the already-bound local worker, never model input.
    pub fn heartbeat(&mut self, sequence: u64, now: Sample) -> Result<(), StopReason> {
        self.check(now)?;
        if self.sequence.checked_add(1) != Some(sequence) {
            self.stopped = Some(StopReason::InvalidHeartbeat);
            return Err(StopReason::InvalidHeartbeat);
        }
        self.sequence = sequence;
        self.heartbeat_ms = now.awake_and_sleep_ms;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(ms: u64, wall: u64) -> Sample {
        Sample {
            awake_and_sleep_ms: ms,
            wall_seconds: wall,
        }
    }
    #[test]
    fn deadline_cannot_be_extended_by_heartbeats() {
        let mut guard = RecoveryGuard::new(sample(10_000, 100), 2, 1000).unwrap();
        guard.heartbeat(1, sample(10_500, 100)).unwrap();
        guard.heartbeat(2, sample(11_000, 101)).unwrap();
        guard.heartbeat(3, sample(11_500, 101)).unwrap();
        assert_eq!(
            guard.heartbeat(4, sample(12_000, 102)),
            Err(StopReason::Expired)
        );
        assert_eq!(guard.check(sample(11_500, 101)), Err(StopReason::Expired));
    }
    #[test]
    fn hung_worker_and_late_heartbeat_stop_at_boundary() {
        let mut guard = RecoveryGuard::new(sample(0, 100), 600, 2000).unwrap();
        guard.check(sample(1999, 101)).unwrap();
        assert_eq!(
            guard.heartbeat(1, sample(2000, 102)),
            Err(StopReason::HeartbeatLost)
        );
    }
    #[test]
    fn simulated_sleep_cannot_extend_lease_even_with_unchanged_wall_clock() {
        let mut guard = RecoveryGuard::new(sample(1000, 100), 10, 2000).unwrap();
        assert_eq!(guard.check(sample(61_000, 100)), Err(StopReason::Expired));
        let mut short_sleep = RecoveryGuard::new(sample(1000, 100), 600, 2000).unwrap();
        assert_eq!(
            short_sleep.heartbeat(1, sample(4000, 103)),
            Err(StopReason::HeartbeatLost)
        );
    }
    #[test]
    fn wall_changes_and_simulated_boot_clock_reset_invalidate_session() {
        for (next, reason) in [
            (sample(1001, 99), StopReason::ClockRegression),
            (sample(999, 101), StopReason::ClockRegression),
            (sample(1001, 701), StopReason::Expired),
        ] {
            let mut guard = RecoveryGuard::new(sample(1000, 100), 600, 2000).unwrap();
            assert_eq!(guard.check(next), Err(reason));
        }
    }
    #[test]
    fn replay_skips_and_invalid_limits_fail_closed() {
        for seq in [0, 2, u64::MAX] {
            let mut guard = RecoveryGuard::new(sample(0, 0), 600, 2000).unwrap();
            assert_eq!(
                guard.heartbeat(seq, sample(1, 0)),
                Err(StopReason::InvalidHeartbeat)
            );
        }
        for seconds in [0, 601, u64::MAX] {
            assert!(RecoveryGuard::new(sample(0, 0), seconds, 2000).is_err());
        }
        assert!(RecoveryGuard::new(sample(u64::MAX, 0), 1, 2000).is_err());
        assert!(RecoveryGuard::new(sample(0, u64::MAX), 1, 2000).is_err());
    }
}
