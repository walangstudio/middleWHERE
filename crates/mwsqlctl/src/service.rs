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

/// Windows elevation check. Shells out to PowerShell rather than pulling in a
/// Win32 FFI dependency for one query; cached because it can't change within a
/// process. The non-Windows stub mirrors `is_root`'s non-Linux stub.
#[cfg(windows)]
pub(crate) fn is_admin() -> bool {
    use std::sync::OnceLock;
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "[bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)",
            ])
            .output();
        matches!(out, Ok(o) if o.status.success()
            && String::from_utf8_lossy(&o.stdout).trim().eq_ignore_ascii_case("true"))
    })
}
#[cfg(not(windows))]
pub(crate) fn is_admin() -> bool {
    false
}

/// Whether a service-mode command must elevate before it can install/configure.
/// Linux uses the `sudo` re-exec env marker; Windows uses the `--uac` flag set
/// on the relaunched child (UAC does not forward env vars).
pub(crate) fn needs_service_elevation(uac_relaunched: bool) -> bool {
    if cfg!(target_os = "linux") {
        !is_root() && !already_elevated()
    } else if cfg!(windows) {
        !is_admin() && !uac_relaunched
    } else {
        false
    }
}

/// Elevate `subcommand` and stop the current (unprivileged) process: `sudo`
/// re-exec on Linux, a UAC `Start-Process -Verb RunAs` relaunch on Windows.
/// Returns `Ok(())` meaning "handled — stop here"; the caller should `return`
/// it. (On a successful Linux re-exec it never returns.)
pub(crate) fn elevate_for_service(
    subcommand: &str,
    forward: &[OsString],
    reason: &str,
) -> Result<()> {
    if cfg!(windows) {
        relaunch_elevated_windows(subcommand, forward)
    } else {
        elevate_or_print(subcommand, forward, reason)
    }
}

/// Relaunch self elevated via UAC. The elevated child runs in its own new
/// console; we pass `--uac` so it knows not to re-elevate and to pause before
/// closing (so the one-time token stays readable).
#[cfg(windows)]
fn relaunch_elevated_windows(subcommand: &str, forward: &[OsString]) -> Result<()> {
    let me = std::env::current_exe().context("resolve current exe")?;
    // PowerShell single-quoted array: '<sub>','<arg>',…,'--uac'.
    let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let mut parts: Vec<String> = vec![quote(subcommand)];
    parts.extend(forward.iter().map(|a| quote(&a.to_string_lossy())));
    parts.push(quote("--uac"));
    let script = format!(
        "Start-Process -FilePath {} -Verb RunAs -ArgumentList {}",
        quote(&me.to_string_lossy()),
        parts.join(",")
    );
    println!("Requesting administrator privileges (a UAC prompt will appear)…");
    println!("Setup continues in a new elevated window.");
    let status = run_powershell(&script).context("launch elevated process via PowerShell")?;
    if !status.success() {
        bail!(
            "elevation was cancelled or failed. Re-run from an elevated PowerShell, \
             or run the printed service script as Administrator."
        );
    }
    Ok(())
}
#[cfg(not(windows))]
fn relaunch_elevated_windows(_subcommand: &str, _forward: &[OsString]) -> Result<()> {
    Ok(())
}

/// Run a PowerShell script via `-EncodedCommand` (base64 UTF-16LE). Avoids
/// command-line quoting/injection entirely, and — unlike a temp `.ps1` — never
/// writes a predictable-named script an attacker could pre-stage in the shared
/// temp dir before it runs elevated.
#[cfg(windows)]
fn run_powershell(script: &str) -> std::io::Result<std::process::ExitStatus> {
    use base64::Engine as _;
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
        .status()
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
    } else if cfg!(windows) && is_admin() {
        // Elevated already (UAC relaunch or an admin shell): run the generated
        // PowerShell registration for real instead of printing it.
        register_windows_service(&art.artifact, service_name)?;
        println!("\nService {service_name} installed and started.");
        println!("Inspect:  sc.exe query {service_name}");
    } else {
        println!("\n# ---- {service_name} service unit ----");
        print!("{}", art.artifact);
        println!("\n# ---- operator steps (run elevated) ----\n{}", art.steps);
    }
    Ok(())
}

/// Run the generated install script (single source of truth — the same text we
/// otherwise print) and start the service. Idempotent-ish: a re-run where the
/// service already exists surfaces the script's error.
#[cfg(windows)]
fn register_windows_service(script: &str, service_name: &str) -> Result<()> {
    // Idempotent: if the service already exists, don't re-run `sc create` (which
    // would fail) — just make sure it's started.
    let exists = Command::new("sc.exe")
        .args(["query", service_name])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if exists {
        println!("Service {service_name} already registered — ensuring it is started.");
        let _ = Command::new("sc.exe")
            .args(["start", service_name])
            .status();
        return Ok(());
    }
    // Run the generated install script in-memory (no temp file on disk).
    let status = run_powershell(script).context("run service install script")?;
    if !status.success() {
        bail!(
            "service install failed (is the {service_name} service already registered? \
             `sc.exe delete {service_name}` to recreate)"
        );
    }
    run_cmd("sc.exe", &["start", service_name])?;
    Ok(())
}
#[cfg(not(windows))]
fn register_windows_service(_script: &str, _service_name: &str) -> Result<()> {
    Ok(())
}

/// Restart the running service so it re-reads the sealed config (the daemon
/// binds its per-env listeners once at startup — there is no hot reload). Only
/// acts on Linux+root; elsewhere the caller prints a manual hint.
pub(crate) fn restart_service(name: &str) -> Result<()> {
    if cfg!(target_os = "linux") && is_root() {
        run_cmd("systemctl", &["restart", name])?;
        println!("Restarted {name} to apply the new configuration.");
    } else if cfg!(windows) && is_admin() {
        // sc.exe has no atomic restart; stop (ignore "not running") then start.
        let _ = Command::new("sc.exe").args(["stop", name]).status();
        run_cmd("sc.exe", &["start", name])?;
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
