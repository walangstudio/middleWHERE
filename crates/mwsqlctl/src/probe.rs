//! Connection validation by shelling out to `mwsqld test`.
//!
//! The admin CLI carries no networking stack (no russh, no DB driver) and we
//! keep it that way: the daemon binary already has everything, so validating a
//! connection means running `mwsqld test --json` and reading its exit code +
//! one JSON line per env. `mwsqld test` reads the sealed config straight from
//! disk, so this works whether or not the service is running and validates a
//! just-written env before any restart.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use mw_core::state::KeystoreChoice;

use crate::ops;

/// Collapsed result of a probe run: the daemon's exit code is authoritative for
/// `ok`; `reason` is the first failing env's message, for the human only.
/// `unsupported` carries a note when the run passed solely because every
/// non-connecting env was an engine with no probe path (mssql) — a soft skip,
/// not a real connection.
pub struct ProbeOutcome {
    pub ok: bool,
    pub reason: String,
    pub unsupported: Option<String>,
    /// The daemon reported zero configured envs (`--all` on an env-less config):
    /// an empty set is not "all connected", so the caller must not read it as a
    /// pass. Distinguished by the daemon's `{"envs":0}` marker line.
    pub empty: bool,
}

/// Build the argv for `mwsqld test`. Pure so it can be unit-tested without
/// spawning. `--state-dir` pins the config location; the keystore flag makes the
/// daemon resolve the exact same master-key source the ctl did:
/// `file_keystore = true` → file-backed key at `state_dir` (`--file-keystore`),
/// `false` → the per-user OS keychain (`--user`). One of those two fully
/// determines `resolve_cli_target`'s choice regardless of the daemon's own
/// defaults.
pub fn build_probe_argv(env: Option<&str>, state_dir: &Path, file_keystore: bool) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec!["test".into(), "--json".into()];
    match env {
        Some(name) => {
            argv.push("--env".into());
            argv.push(name.into());
        }
        None => argv.push("--all".into()),
    }
    argv.push("--state-dir".into());
    argv.push(state_dir.as_os_str().to_owned());
    if file_keystore {
        argv.push("--file-keystore".into());
    } else {
        argv.push("--user".into());
    }
    argv
}

/// Run `mwsqld test` (built via [`build_probe_argv`]) and collapse its output to
/// one [`ProbeOutcome`]. Exit code 0 means every probed env connected.
pub fn run(daemon: &Path, argv: &[OsString]) -> Result<ProbeOutcome> {
    let out = Command::new(daemon)
        .args(argv)
        .output()
        .with_context(|| format!("run {} test", daemon.display()))?;
    let ok = out.status.success();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let reason = first_failure_reason(&stdout)
        .or_else(|| {
            let err = String::from_utf8_lossy(&out.stderr);
            let err = err.trim().to_string();
            (!err.is_empty()).then_some(err)
        })
        .unwrap_or_default();
    let unsupported = unsupported_only_reason(&stdout);
    Ok(ProbeOutcome {
        ok,
        reason,
        unsupported,
        empty: has_empty_marker(&stdout),
    })
}

/// The daemon's zero-envs marker (`{"envs":0}`), emitted by `mwsqld test --all`
/// when no envs are configured so this side can tell it apart from a clean pass.
fn has_empty_marker(stdout: &str) -> bool {
    stdout.lines().any(|l| l.trim() == "{\"envs\":0}")
}

/// Outcome of a validation attempt. `Skipped` is a soft pass: the probe could
/// not run (no daemon binary beside the ctl, or it failed to launch), so the
/// caller keeps the env rather than blocking on something orthogonal.
pub enum Validation {
    Ok,
    Failed(String),
    Skipped(String),
}

/// Validate one env (or all if `env` is `None`): locate the `mwsqld` sibling
/// binary and run `mwsqld test` against the same state dir + keystore the ctl
/// resolved. Service mode reads root-owned config, so the caller must already be
/// elevated (the wizard self-elevates; standalone `env test` is wrapped by
/// `run_elevated_or`).
pub fn validate(state_dir: &Path, ks: &KeystoreChoice, env: Option<&str>) -> Validation {
    let daemon = match ops::default_daemon_path() {
        Ok(d) if d.exists() => d,
        Ok(d) => {
            return Validation::Skipped(format!(
                "daemon binary not found at {} — install it beside mwsqlctl to validate",
                d.display()
            ))
        }
        Err(e) => return Validation::Skipped(format!("{e}")),
    };
    let file_keystore = matches!(ks, KeystoreChoice::File { .. });
    let argv = build_probe_argv(env, state_dir, file_keystore);
    match run(&daemon, &argv) {
        Ok(o) if o.empty => Validation::Skipped("no environments configured".to_string()),
        Ok(o) if o.ok => match o.unsupported {
            Some(note) => Validation::Skipped(note),
            None => Validation::Ok,
        },
        Ok(o) => Validation::Failed(if o.reason.is_empty() {
            "connection failed".to_string()
        } else {
            o.reason
        }),
        Err(e) => Validation::Skipped(format!("probe could not run: {e}")),
    }
}

/// The reason from the first genuine-failure JSON line. The daemon emits a fixed
/// field order — `{"ok":B,"supported":B,"env":"E","reason":"R"}` — so `reason`
/// (last field) runs to the closing `"}` regardless of its content. Lines with
/// `"supported":false` are unsupported engines, not failures, so they are
/// skipped.
fn first_failure_reason(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        if !line.contains("\"ok\":false") {
            continue;
        }
        if line.contains("\"supported\":false") {
            continue;
        }
        let r = extract_reason(line).unwrap_or_default();
        if !r.is_empty() {
            return Some(r);
        }
        // Failure with an empty reason: surface the env name instead.
        return Some(
            extract_field(line, "env")
                .map(|e| format!("env {e} failed"))
                .unwrap_or_else(|| "connection failed".to_string()),
        );
    }
    None
}

/// A skip note when the run passed *only* because every non-connecting env was
/// an unsupported engine — i.e. at least one `"supported":false` line and no
/// `"ok":true` line. Returns `None` the moment any env actually connected, so a
/// mix of working + unsupported envs still reads as a plain success.
fn unsupported_only_reason(stdout: &str) -> Option<String> {
    let mut note: Option<String> = None;
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        if line.contains("\"ok\":true") {
            return None;
        }
        if line.contains("\"supported\":false") && note.is_none() {
            note = Some(extract_reason(line).unwrap_or_default());
        }
    }
    note.map(|r| {
        if r.is_empty() {
            "engine not supported yet".to_string()
        } else {
            r
        }
    })
}

fn extract_reason(line: &str) -> Option<String> {
    const KEY: &str = "\"reason\":\"";
    let start = line.find(KEY)? + KEY.len();
    let rest = &line[start..];
    let end = rest.rfind("\"}")?;
    Some(unescape(&rest[..end]))
}

/// Extract a simple `"key":"value"` string field (value assumed escape-free —
/// used only for the env name, which is `[a-z0-9_-]`).
fn extract_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn unescape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            o.push(c);
            continue;
        }
        match chars.next() {
            Some('"') => o.push('"'),
            Some('\\') => o.push('\\'),
            Some('n') => o.push('\n'),
            Some('r') => o.push('\r'),
            Some('t') => o.push('\t'),
            Some('u') => {
                // Skip a \uXXXX escape; we don't reconstruct the codepoint for a
                // human-only message.
                for _ in 0..4 {
                    chars.next();
                }
                o.push('\u{fffd}');
            }
            Some(other) => o.push(other),
            None => {}
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn strs(argv: &[OsString]) -> Vec<String> {
        argv.iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn argv_one_env_file_keystore() {
        let argv = strs(&build_probe_argv(
            Some("dev"),
            &PathBuf::from("/var/lib/middlewhere"),
            true,
        ));
        assert_eq!(argv[0], "test");
        assert!(argv.contains(&"--json".to_string()));
        assert!(argv.windows(2).any(|w| w[0] == "--env" && w[1] == "dev"));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--state-dir" && w[1] == "/var/lib/middlewhere"));
        assert!(argv.contains(&"--file-keystore".to_string()));
        assert!(!argv.contains(&"--user".to_string()));
        assert!(!argv.contains(&"--all".to_string()));
    }

    #[test]
    fn argv_all_os_keystore() {
        let argv = strs(&build_probe_argv(
            None,
            &PathBuf::from("/home/me/.mw"),
            false,
        ));
        assert!(argv.contains(&"--all".to_string()));
        assert!(!argv.iter().any(|a| a == "--env"));
        assert!(argv.contains(&"--user".to_string()));
        assert!(!argv.contains(&"--file-keystore".to_string()));
    }

    #[test]
    fn zero_envs_marker_detected_but_not_a_connection_line() {
        // The daemon's `{"envs":0}` marker means no envs were probed — must read
        // as empty (→ Skipped), never as a failure or a pass.
        assert!(has_empty_marker("{\"envs\":0}\n"));
        assert!(!has_empty_marker(
            "{\"ok\":true,\"supported\":true,\"env\":\"a\",\"reason\":\"\"}\n"
        ));
        assert!(!has_empty_marker(""));
        // Not a genuine failure line, so it never surfaces as one.
        assert_eq!(first_failure_reason("{\"envs\":0}\n"), None);
    }

    #[test]
    fn parses_first_failure_reason() {
        let out = concat!(
            "{\"ok\":true,\"env\":\"a\",\"reason\":\"\"}\n",
            "{\"ok\":false,\"env\":\"b\",\"reason\":\"authentication failed for user 'app'\"}\n",
            "{\"ok\":false,\"env\":\"c\",\"reason\":\"connection refused\"}\n",
        );
        assert_eq!(
            first_failure_reason(out).as_deref(),
            Some("authentication failed for user 'app'")
        );
    }

    #[test]
    fn all_ok_has_no_failure_reason() {
        let out = "{\"ok\":true,\"env\":\"a\",\"reason\":\"\"}\n";
        assert_eq!(first_failure_reason(out), None);
    }

    #[test]
    fn failure_with_empty_reason_falls_back_to_env() {
        let out = "{\"ok\":false,\"env\":\"b\",\"reason\":\"\"}\n";
        assert_eq!(first_failure_reason(out).as_deref(), Some("env b failed"));
    }

    #[test]
    fn unescapes_quotes_and_newlines_in_reason() {
        let out = "{\"ok\":false,\"env\":\"b\",\"reason\":\"bad \\\"x\\\"\\nline2\"}\n";
        assert_eq!(
            first_failure_reason(out).as_deref(),
            Some("bad \"x\"\nline2")
        );
    }

    #[test]
    fn ignores_non_json_noise_lines() {
        let out = "warning: something\n{\"ok\":false,\"env\":\"b\",\"reason\":\"nope\"}\n";
        assert_eq!(first_failure_reason(out).as_deref(), Some("nope"));
    }

    #[test]
    fn unsupported_line_is_not_a_failure() {
        let out =
            "{\"ok\":false,\"supported\":false,\"env\":\"m\",\"reason\":\"engine mssql not supported yet\"}\n";
        assert_eq!(first_failure_reason(out), None);
    }

    #[test]
    fn real_failure_wins_over_unsupported_line() {
        let out = concat!(
            "{\"ok\":false,\"supported\":false,\"env\":\"m\",\"reason\":\"engine mssql not supported yet\"}\n",
            "{\"ok\":false,\"supported\":true,\"env\":\"b\",\"reason\":\"connection refused\"}\n",
        );
        assert_eq!(
            first_failure_reason(out).as_deref(),
            Some("connection refused")
        );
    }

    #[test]
    fn unsupported_only_yields_skip_note() {
        let out =
            "{\"ok\":false,\"supported\":false,\"env\":\"m\",\"reason\":\"engine mssql not supported yet\"}\n";
        assert_eq!(
            unsupported_only_reason(out).as_deref(),
            Some("engine mssql not supported yet")
        );
    }

    #[test]
    fn connected_plus_unsupported_is_not_a_skip() {
        let out = concat!(
            "{\"ok\":true,\"supported\":true,\"env\":\"a\",\"reason\":\"\"}\n",
            "{\"ok\":false,\"supported\":false,\"env\":\"m\",\"reason\":\"engine mssql not supported yet\"}\n",
        );
        assert_eq!(unsupported_only_reason(out), None);
    }

    #[test]
    fn all_connected_has_no_skip_note() {
        let out = "{\"ok\":true,\"supported\":true,\"env\":\"a\",\"reason\":\"\"}\n";
        assert_eq!(unsupported_only_reason(out), None);
    }
}
