//! Idle timeouts, for both halves of a backend connection's life.
//!
//! A client session pins its backend connection (see `session_conn`) and is
//! closed by [`within_idle`] when it sends nothing for the idle timeout; that
//! closes the connection too. Pinned connections never return to the pool.
//!
//! The pool itself still holds connections that no client used: the ones the
//! env probe (`env test`, the wizard's check) opens and drops. The daemon
//! sweeps each env's pool and closes those once idle past the timeout.
//! `Pool::retain` only inspects connections sitting in the pool, so active
//! proxying is never interrupted.

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

/// Await `fut`, or give up after `idle` (zero waits forever). Wraps the read
/// of a client's next command: an idle session would otherwise hold its pinned
/// backend connection, one of max_pool, indefinitely.
pub async fn within_idle<T>(
    idle: Duration,
    fut: impl std::future::Future<Output = T>,
) -> Option<T> {
    if idle.is_zero() {
        Some(fut.await)
    } else {
        tokio::time::timeout(idle, fut).await.ok()
    }
}

/// How long to wait for a client's next command. Inside a transaction the
/// window runs from the last statement the backend ran, not the last message:
/// pings must not keep a transaction's locks held forever.
pub fn next_wait(idle: Duration, in_txn: bool, last_statement: std::time::Instant) -> Duration {
    if idle.is_zero() || !in_txn {
        return idle;
    }
    // Never zero: within_idle reads zero as "wait forever".
    idle.saturating_sub(last_statement.elapsed())
        .max(Duration::from_millis(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_in_transaction_window_runs_from_the_last_statement() {
        let idle = Duration::from_secs(10);
        let long_ago = std::time::Instant::now() - Duration::from_secs(60);
        assert_eq!(
            next_wait(idle, false, long_ago),
            idle,
            "outside a txn: full window"
        );
        assert_eq!(
            next_wait(idle, true, long_ago),
            Duration::from_millis(1),
            "pings since the last statement don't extend it"
        );
        assert!(next_wait(idle, true, std::time::Instant::now()) > Duration::from_secs(9));
        assert_eq!(next_wait(Duration::ZERO, true, long_ago), Duration::ZERO);
    }

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
