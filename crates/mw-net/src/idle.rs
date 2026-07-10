//! Idle backend-connection reaping.
//!
//! The daemon periodically sweeps each env's deadpool pool and closes backend
//! connections that have seen no activity within their idle timeout, releasing
//! the server-side connection. `Pool::retain` only ever inspects connections
//! sitting idle in the pool; one checked out for an in-flight query is not a
//! candidate, so active proxying is never interrupted. `last_used` measures time
//! since the connection was last checked out, so each checkout resets it: a
//! backend that keeps getting used stays pooled, and only one untouched for the
//! whole idle window is reaped.

use std::time::Duration;

/// Whether a pooled connection whose last use was `last_used` ago should be
/// kept. A zero `idle_timeout` disables reaping (keep everything). This is the
/// exact predicate handed to `Pool::retain`.
pub fn should_retain(last_used: Duration, idle_timeout: Duration) -> bool {
    idle_timeout.is_zero() || last_used < idle_timeout
}

/// Sweep cadence for the reaper given the smallest non-zero idle timeout across
/// envs. Sweeping about twice per window closes a stale connection within
/// ~1.5x its timeout; clamped so we neither busy-loop nor lag on large windows.
pub fn reaper_interval(min_idle_timeout: Duration) -> Duration {
    (min_idle_timeout / 2).clamp(Duration::from_secs(1), Duration::from_secs(60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recently_used_connection_is_retained() {
        // A connection used within the window survives: activity resets the
        // timer, so a busy backend is never disconnected.
        assert!(should_retain(
            Duration::from_secs(5),
            Duration::from_secs(300)
        ));
    }

    #[test]
    fn connection_idle_past_timeout_is_reaped() {
        assert!(!should_retain(
            Duration::from_secs(301),
            Duration::from_secs(300)
        ));
        // At exactly the timeout the connection is already reaped.
        assert!(!should_retain(
            Duration::from_secs(300),
            Duration::from_secs(300)
        ));
    }

    #[test]
    fn zero_timeout_never_reaps() {
        assert!(should_retain(Duration::from_secs(10_000), Duration::ZERO));
    }

    #[test]
    fn interval_is_clamped_to_sane_bounds() {
        assert_eq!(
            reaper_interval(Duration::from_secs(300)),
            Duration::from_secs(60)
        );
        assert_eq!(
            reaper_interval(Duration::from_secs(2)),
            Duration::from_secs(1)
        );
        assert_eq!(
            reaper_interval(Duration::from_secs(20)),
            Duration::from_secs(10)
        );
    }
}
