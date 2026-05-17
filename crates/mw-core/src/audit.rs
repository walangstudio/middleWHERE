//! Structured audit log for every query the proxy sees.
//!
//! Events are JSON-lines, one record per line, written to
//! `<state_dir>/audit/YYYY-MM-DD.jsonl` and rotated daily by
//! `tracing_appender::rolling`. Full statement text is NOT logged by default
//! — only a SHA-256 hash and the first 64 chars, which keeps PII out of the
//! log while still letting an operator correlate identical statements.

use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tracing_appender::non_blocking::WorkerGuard;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    Error,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEvent {
    pub ts: String,
    pub env: String,
    pub client_user: String,
    pub stmt_hash: String,
    pub stmt_first_64: String,
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<u64>,
    pub duration_ms: u64,
}

impl AuditEvent {
    pub fn new(
        env: impl Into<String>,
        client_user: impl Into<String>,
        sql: &str,
        decision: Decision,
        deny_reason: Option<String>,
        rows: Option<u64>,
        duration: Duration,
    ) -> Self {
        Self {
            ts: now_iso8601(),
            env: env.into(),
            client_user: client_user.into(),
            stmt_hash: hash_stmt(sql),
            stmt_first_64: first_64(sql),
            decision,
            deny_reason,
            rows,
            duration_ms: duration.as_millis().min(u64::MAX as u128) as u64,
        }
    }

    pub fn emit(&self) {
        // Use a dedicated tracing target so the subscriber routes only audit
        // events to the JSONL appender and not the rest of the logs.
        match serde_json::to_string(self) {
            Ok(line) => tracing::info!(target: "middlewhere::audit", "{line}"),
            Err(e) => tracing::warn!(target: "middlewhere::audit", err = %e,
                                     "failed to serialize audit event"),
        }
    }
}

fn hash_stmt(sql: &str) -> String {
    let mut h = Sha256::new();
    h.update(sql.as_bytes());
    let d = h.finalize();
    let mut s = String::with_capacity(7 + 64);
    s.push_str("sha256:");
    for b in d { s.push_str(&format!("{:02x}", b)); }
    s
}

fn first_64(sql: &str) -> String {
    let mut s = String::with_capacity(64);
    for (i, c) in sql.chars().enumerate() {
        if i >= 64 { break; }
        s.push(c);
    }
    s
}

fn now_iso8601() -> String {
    use time::format_description::well_known::Iso8601;
    time::OffsetDateTime::now_utc()
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

/// Initialize a tracing subscriber that:
///   - sends `target = "middlewhere::audit"` events (line per JSON record) to
///     a daily-rotated file under `<state_dir>/audit/`;
///   - sends everything else to stderr.
///
/// Returns a guard that must outlive the daemon — dropping it stops the
/// background writer thread and may lose buffered audit lines.
pub fn install_subscriber(state_dir: &Path) -> std::io::Result<WorkerGuard> {
    use tracing_subscriber::{filter::Targets, fmt, layer::SubscriberExt, util::SubscriberInitExt, Layer};

    let audit_dir = state_dir.join("audit");
    std::fs::create_dir_all(&audit_dir)?;
    let appender = tracing_appender::rolling::daily(&audit_dir, "audit.jsonl");
    let (audit_writer, guard) = tracing_appender::non_blocking(appender);

    let audit_layer = fmt::layer()
        .with_writer(audit_writer)
        .with_target(false)
        .with_level(false)
        .without_time()
        .with_ansi(false)
        .with_filter(Targets::new().with_target("middlewhere::audit", tracing::Level::INFO));

    let console_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(true)
        .with_filter(Targets::new()
            .with_default(tracing::Level::INFO)
            .with_target("middlewhere::audit", tracing::level_filters::LevelFilter::OFF));

    // `try_init` instead of `init`: a global subscriber may already exist
    // (another daemon instance in-process, an embedding host, or a test
    // harness). That must not panic the daemon. If init fails, audit events
    // route to whatever subscriber is already installed; the file appender
    // guard is still returned so the writer thread stays alive.
    if let Err(e) = tracing_subscriber::registry()
        .with(audit_layer)
        .with(console_layer)
        .try_init()
    {
        tracing::debug!(err = %e, "tracing subscriber already set; reusing it");
    }

    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stmt_hash_is_stable() {
        let a = hash_stmt("SELECT 1");
        let b = hash_stmt("SELECT 1");
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:") && a.len() == 7 + 64);
    }

    #[test]
    fn first_64_truncates_at_chars_not_bytes() {
        let s: String = "x".repeat(100);
        assert_eq!(first_64(&s).len(), 64);
        let mixed = "héllo";
        assert!(first_64(mixed).contains("héllo"));
    }

    #[test]
    fn event_serializes_with_expected_shape() {
        let ev = AuditEvent::new(
            "stage_w9", "alice", "SELECT 1",
            Decision::Allow, None, Some(1), Duration::from_millis(5),
        );
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains(r#""decision":"allow""#), "{s}");
        assert!(s.contains(r#""stmt_first_64":"SELECT 1""#));
        assert!(s.contains(r#""rows":1"#));
        // ts is ISO-8601 with a `T` separator
        assert!(s.contains("\"ts\":\""));
        assert!(s.contains("T"));
    }
}
