//! Tail the most-recent audit JSONL file. `tracing_appender::rolling::daily`
//! names files like `audit.jsonl.YYYY-MM-DD`; lexicographic ordering gives
//! us the most recent day for free.

use std::path::Path;

use anyhow::{Context, Result};

pub fn tail(state_dir: &Path, n: usize) -> Result<Vec<String>> {
    let dir = state_dir.join("audit");
    if !dir.exists() { return Ok(Vec::new()); }

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .with_context(|| format!("read_dir {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("audit.jsonl"))
        .collect();
    entries.sort_by_key(|e| e.file_name());
    let Some(latest) = entries.last() else { return Ok(Vec::new()); };

    let body = std::fs::read_to_string(latest.path())
        .with_context(|| format!("read {}", latest.path().display()))?;
    let lines: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    Ok(lines[start..].iter().map(|s| (*s).to_string()).collect())
}
