//! Privilege elevation + OS service management, shared by `init` (which
//! installs the service) and `wizard` (which writes secrets into the
//! root-owned config and restarts the service to apply them).
//!
//! Elevation is *elevate-first*: in service mode a command re-execs itself
//! under `sudo` BEFORE prompting for anything, so every secret is entered in
//! the one root process that writes the root-owned state dir. No secret ever
//! crosses the sudo boundary. `current_exe()` is absolute, so the re-exec
//! works regardless of where the operator extracted the binary.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::installer::InstallParams;
use crate::ops;
use crate::prompt;

/// Set on the child when we re-exec under sudo, so the elevated process knows
/// not to try elevating again (sudo resets the env otherwise; `is_root()` is
/// the authoritative guard, this is just belt-and-braces).
pub(crate) const ELEVATED_MARKER: &str = "MW_ELEVATED";

// ---- root detection ----------------------------------------------------

#[cfg(target_os = "linux")]
pub(crate) fn is_root() -> bool {
    // SAFETY: geteuid is always-safe and never fails.
    unsafe { libc::geteuid() == 0 }
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn is_root() -> bool {
    false
}

pub(crate) fn already_elevated() -> bool {
    std::env::var_os(ELEVATED_MARKER).is_some()
}

// ---- service-name validation ------------------------------------------

/// A systemd service / unix account name we can safely bake into `useradd`,
/// `chown a:a`, `User=`, `/etc/systemd/system/<name>.service`, and
/// `systemctl restart <name>`. Restrict to a conservative `[a-z_][a-z0-9_-]*`
/// token (the default `mwsqld` passes).
pub(crate) fn validate_service_name(name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    let ok = name.len() <= 32
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if !ok {
        bail!(
            "invalid --service-name {name:?}: use a short lowercase name \
             matching [a-z_][a-z0-9_-]* (e.g. 'mwsqld')"
        );
    }
    Ok(())
}

// ---- elevation ---------------------------------------------------------

/// Build the argv passed to `sudo`: `-- <abs exe> <subcommand> <forwarded
/// flags>`. Pure so it can be unit-tested without spawning. `--` stops sudo
/// option parsing; the absolute exe path bypasses sudo's secure_path lookup.
// Only the unix re-exec path (and tests) call this; on Windows it's exercised
// solely by the test module.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn build_sudo_argv(me: &Path, subcommand: &str, forward: &[OsString]) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec!["--".into(), me.as_os_str().to_owned(), subcommand.into()];
    argv.extend(forward.iter().cloned());
    argv
}

/// Elevate-first for `subcommand`: confirm with the operator, then re-exec
/// `self` under sudo (which replaces this process). Returns `Ok(())` meaning
/// "handled — stop here" when it printed the manual command instead (no
/// terminal to confirm on, or the operator declined). The caller should
/// `return` this directly. On a successful re-exec it never returns.
pub(crate) fn elevate_or_print(subcommand: &str, forward: &[OsString], reason: &str) -> Result<()> {
    let me = std::env::current_exe().context("resolve current exe")?;
    if !me.exists() {
        bail!(
            "cannot locate own executable ({}) to re-run under sudo; \
             run: sudo <abs-path-to-mwsqlctl> {subcommand}",
            me.display()
        );
    }

    // Can't prompt for the sudo confirmation without a terminal — print the
    // exact command and stop, rather than failing half-way.
    if !std::io::stdin().is_terminal() {
        print_manual(&me, subcommand, forward);
        return Ok(());
    }

    println!("{reason}");
    if !prompt::confirm("Re-run under sudo now?", true).unwrap_or(false) {
        print_manual(&me, subcommand, forward);
        return Ok(());
    }
    re_exec_under_sudo(&me, subcommand, forward)
}

fn print_manual(me: &Path, subcommand: &str, forward: &[OsString]) {
    println!("\nNo changes made. Run it yourself when ready:");
    print!("  sudo {} {subcommand}", me.display());
    for a in forward {
        print!(" {}", a.to_string_lossy());
    }
    println!();
}

#[cfg(unix)]
fn re_exec_under_sudo(me: &Path, subcommand: &str, forward: &[OsString]) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let argv = build_sudo_argv(me, subcommand, forward);
    // exec replaces this process; the only way it returns is failure.
    let err = Command::new("sudo")
        .args(&argv)
        .env(ELEVATED_MARKER, "1")
        .exec();
    Err(anyhow::Error::new(err).context("exec sudo (is sudo installed and on PATH?)"))
}
#[cfg(not(unix))]
fn re_exec_under_sudo(_me: &Path, _subcommand: &str, _forward: &[OsString]) -> Result<()> {
    bail!("self-elevation is only supported on unix");
}

// ---- system account + ownership (linux) --------------------------------

#[cfg(target_os = "linux")]
pub(crate) fn ensure_service_user(name: &str) -> Result<()> {
    let exists = Command::new("getent")
        .arg("passwd")
        .arg(name)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if exists {
        return Ok(());
    }
    let status = Command::new("useradd")
        .args([
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            name,
        ])
        .status()
        .context("run useradd")?;
    if !status.success() {
        bail!("useradd {name} failed (exit {:?})", status.code());
    }
    println!("Created system user {name}");
    Ok(())
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn ensure_service_user(_name: &str) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn chown_state_dir(dir: &Path, name: &str) -> Result<()> {
    let status = Command::new("chown")
        .arg("-R")
        .arg(format!("{name}:{name}"))
        .arg(dir)
        .status()
        .context("run chown")?;
    if !status.success() {
        bail!("chown {} to {name} failed", dir.display());
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn chown_state_dir(_dir: &Path, _name: &str) -> Result<()> {
    Ok(())
}

// ---- service install + lifecycle ---------------------------------------

/// Write the hardened (fixed-user) unit and `enable --now` on Linux when root;
/// otherwise print the artifact + operator steps so the operator can apply it
/// (macOS launchd / Windows service / a non-root run). `exec_path` defaults to
/// the `mwsqld` sibling of this executable.
pub(crate) fn install_and_enable_service(
    service_name: &str,
    exec_path: Option<&Path>,
    state_dir: &Path,
) -> Result<()> {
    let exec = match exec_path {
        Some(p) => p.to_path_buf(),
        None => ops::default_daemon_path()?,
    };
    let params = InstallParams::new(
        service_name,
        exec.to_string_lossy().to_string(),
        state_dir.to_string_lossy().to_string(),
    );
    let art = ops::build_service_artifact(&params, true)?;

    if cfg!(target_os = "linux") && is_root() {
        let unit_path = PathBuf::from(format!("/etc/systemd/system/{service_name}.service"));
        ops::write_service_artifact(&unit_path, &art.artifact, true)?;
        run_cmd("systemctl", &["daemon-reload"])?;
        run_cmd("systemctl", &["enable", "--now", service_name])?;
        println!("\nService {service_name} installed and started.");
        println!("Follow logs:  journalctl -u {service_name} -f");
        println!("\nFor raw `sudo mwsqlctl` commands against this deployment, export once:");
        println!(
            "  export MW_STATE_DIR={} MW_FILE_KEYSTORE=1",
            state_dir.display()
        );
    } else {
        println!("\n# ---- {service_name} service unit ----");
        print!("{}", art.artifact);
        println!("\n# ---- operator steps (run elevated) ----\n{}", art.steps);
    }
    Ok(())
}

/// Restart the running service so it re-reads the sealed config (the daemon
/// binds its per-env listeners once at startup — there is no hot reload). Only
/// acts on Linux+root; elsewhere the caller prints a manual hint.
pub(crate) fn restart_service(name: &str) -> Result<()> {
    if cfg!(target_os = "linux") && is_root() {
        run_cmd("systemctl", &["restart", name])?;
        println!("Restarted {name} to apply the new configuration.");
    }
    Ok(())
}

pub(crate) fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("run {program}"))?;
    if !status.success() {
        bail!(
            "{program} {} failed (exit {:?})",
            args.join(" "),
            status.code()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_name_validation_rejects_unsafe_names() {
        for ok in ["mwsqld", "mw-sql_2", "_svc", "a"] {
            assert!(validate_service_name(ok).is_ok(), "{ok:?} should be valid");
        }
        for bad in [
            "My Gateway",
            "2bad",
            "has:colon",
            "path/slash",
            "Up.per",
            "",
            &"x".repeat(33),
        ] {
            assert!(
                validate_service_name(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn sudo_argv_frames_subcommand_then_forward() {
        // `me` is forwarded verbatim (it's `current_exe()` at runtime, already
        // absolute); build_sudo_argv only frames it as `-- <me> <sub> …`.
        let me = std::env::current_exe().unwrap();
        let fwd: Vec<OsString> = vec!["--service-name".into(), "mwsqld".into()];

        let argv = build_sudo_argv(&me, "init", &fwd);
        assert_eq!(argv[0], OsString::from("--"));
        assert_eq!(argv[1], me.as_os_str());
        assert_eq!(argv[2], OsString::from("init"));
        assert_eq!(argv[3], OsString::from("--service-name"));
        assert!(
            me.is_absolute(),
            "current_exe should be absolute, got {me:?}"
        );

        // The subcommand is a parameter, not hardcoded.
        let wiz = build_sudo_argv(&me, "wizard", &fwd);
        assert_eq!(wiz[2], OsString::from("wizard"));
    }
}
