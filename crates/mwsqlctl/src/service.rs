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

#[cfg(unix)]
pub(crate) fn is_root() -> bool {
    // SAFETY: geteuid is always-safe and never fails. Used on every unix
    // (Linux + macOS/BSD) — an in-process euid check, never a PATH-resolved
    // `id` subprocess that could false-negative an elevation decision.
    unsafe { libc::geteuid() == 0 }
}
#[cfg(not(unix))]
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
        let out = Command::new(windows_powershell_path())
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
/// Unix (Linux + macOS/BSD) uses the `sudo` re-exec env marker; Windows uses the
/// `--uac` flag set on the relaunched child (UAC does not forward env vars).
/// macOS is included so `init`/`wizard`/`uninstall` self-elevate to create the
/// root-owned state dir instead of dying with a raw "Permission denied".
pub(crate) fn needs_service_elevation(uac_relaunched: bool) -> bool {
    if cfg!(unix) {
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

/// Sentinel exit code the outer relaunch script returns when the UAC prompt is
/// declined or the elevated process can't start (Windows `ERROR_CANCELLED`), so
/// the parent can tell "cancelled" apart from a child that genuinely exited
/// non-zero and must have its code mirrored.
#[cfg(any(windows, test))]
const ELEVATION_CANCELLED: i32 = 1223;

/// Escape a string for a PowerShell single-quoted literal: only `'` is special
/// and doubles. Pure so [`build_inner_script`] is unit-testable without spawning
/// PowerShell.
#[cfg(any(windows, test))]
fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Absolute path to the system Windows PowerShell. Launching it by bare name
/// resolves through the CWD / PATH first, so a `powershell.exe` planted in
/// either — then run elevated via `-Verb RunAs` — would be an EoP. `%SystemRoot%`
/// is admin-owned, so paths under it are trustworthy.
#[cfg(any(windows, test))]
fn windows_powershell_path() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe")
}

/// Whether a UAC relaunch can proceed. Only stdin must be a terminal: the
/// elevated child is a separate process, so a piped parent stdin can't feed it
/// (e.g. `--password-stdin`) and we bail honestly. A redirected *stdout* is fine
/// — the parent mirrors the child's captured output to its own stdout, so
/// `mwsqlctl init > log` and `token=$(mwsqlctl grant …)` still work.
#[cfg(any(windows, test))]
fn can_relaunch_elevated(stdin_tty: bool) -> bool {
    stdin_tty
}

/// Decode a child temp file. Windows PowerShell 5.1 `1>`/`2>` write UTF-16LE
/// with a BOM; PowerShell 7 writes UTF-8. Sniff the BOM (`FF FE` = UTF-16LE) and
/// decode accordingly, otherwise treat the bytes as UTF-8 (stripping a UTF-8 BOM
/// if present). This is display text, so invalid sequences are replaced rather
/// than erroring — the previous `read_to_string` returned `Err` on the BOM and
/// silently dropped a one-time token. PowerShell's redirect also rewrites the
/// child's `\n` as `\r\n`, so we undo that: otherwise `token=$(mwsqlctl grant …)`
/// would capture a trailing CR that a POSIX `$()` doesn't strip.
#[cfg(any(windows, test))]
fn decode_child_output(bytes: &[u8]) -> String {
    let text = if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8_lossy(rest).into_owned()
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    text.replace("\r\n", "\n")
}

/// base64(UTF-16LE) encode a PowerShell script for `-EncodedCommand`: the bytes
/// are opaque to `CommandLineToArgvW`, so no argv re-split can corrupt the exe
/// path or its arguments. Pure + unit-tested.
#[cfg(any(windows, test))]
fn encode_powershell_command(script: &str) -> String {
    use base64::Engine as _;
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(utf16)
}

/// The script the *elevated* child runs. It creates both redirect targets with
/// `CreateNew` (fails if the name already exists — including a symlink/junction
/// a same-user attacker pre-planted — and never traverses a reparse point),
/// then runs the exe with output redirected to those now-real files. A child
/// that never launched (moved/quarantined exe, or a null `$LASTEXITCODE`)
/// reports a non-zero code instead of a false success.
#[cfg(any(windows, test))]
fn build_inner_script(exe: &str, args: &[String], out: &Path, err: &Path) -> String {
    let out_q = ps_single_quote(&out.to_string_lossy());
    let err_q = ps_single_quote(&err.to_string_lossy());
    let mut invoke = format!("& {}", ps_single_quote(exe));
    for a in args {
        invoke.push(' ');
        invoke.push_str(&ps_single_quote(a));
    }
    // No `$ErrorActionPreference = 'Stop'`: under Stop, Windows PowerShell turns
    // the exe's own stderr writes into a thrown NativeCommandError, so a
    // *successful* command that prints to stderr (every token banner does) would
    // be misreported as a failure. The `.NET` CreateNew calls throw regardless
    // (method exceptions are always terminating), and a missing/again-launchable
    // exe still throws CommandNotFoundException — both caught below.
    //
    // ponytail: a same-user attacker can still win a delete-and-relink race
    // between CreateNew and the redirect (residual TOCTOU); the ceiling if that
    // ever matters is a named pipe instead of a temp file.
    //
    // `2>` wraps the exe's native stderr as PowerShell error records (the
    // "<exe> : … NativeCommandError" noise), so the forwarded stderr banner is
    // cosmetically messy; stdout (the token) is clean. Upgrade path if that
    // matters: capture via System.Diagnostics.Process with StandardOutputEncoding
    // = UTF8 for raw, unwrapped output.
    format!(
        "$code = 1; \
         try {{ \
           [System.IO.File]::Open({out_q}, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read).Close(); \
           [System.IO.File]::Open({err_q}, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read).Close() \
         }} catch {{ exit 1 }}; \
         try {{ {invoke} 1> {out_q} 2> {err_q}; $code = $LASTEXITCODE }} \
         catch {{ [System.IO.File]::AppendAllText({err_q}, ($_ | Out-String)); $code = 1 }}; \
         if ($null -eq $code) {{ $code = 1 }}; exit $code"
    )
}

/// The outer script the unprivileged parent runs (itself via `-EncodedCommand`).
/// It launches the elevated child carrying `inner_b64` as a single opaque
/// `-EncodedCommand` argument, waits, and mirrors the child's exit code — a
/// declined UAC prompt (Start-Process throws) becomes [`ELEVATION_CANCELLED`].
#[cfg(any(windows, test))]
fn build_outer_script(inner_b64: &str) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'; \
         try {{ \
           $p = Start-Process {ps} -Verb RunAs -Wait -PassThru \
             -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand',{b64}; \
           $code = $p.ExitCode; if ($null -eq $code) {{ $code = 1 }}; exit $code \
         }} catch {{ exit {cancelled} }}",
        ps = ps_single_quote(&windows_powershell_path()),
        b64 = ps_single_quote(inner_b64),
        cancelled = ELEVATION_CANCELLED,
    )
}

/// Relaunch `me <args>` elevated and block until it finishes, then mirror the
/// child's stdout/stderr and exit code into this process. Gated on an interactive
/// stdin (see [`can_relaunch_elevated`]) so a piped-stdin invocation fails with a
/// clear message instead of a child that can't read its input; a redirected
/// stdout is fine — its captured output is mirrored back. Does not return on the
/// success path — it exits the process with the child's code.
#[cfg(windows)]
fn relaunch_elevated_and_wait(args: &[String]) -> Result<()> {
    use rand::RngCore;
    use std::io::Write;

    if !can_relaunch_elevated(std::io::stdin().is_terminal()) {
        bail!(
            "administrator privileges are required, and stdin is piped/redirected so \
             input can't reach the elevated child. Re-run this command from an \
             elevated terminal (Run as administrator), or pass --user for a per-user \
             setup that needs no elevation."
        );
    }

    let me = std::env::current_exe().context("resolve current exe")?;
    // Crypto-random name so a same-user process can't predict (and pre-plant) the
    // path; the elevated child then creates it with CreateNew (see build_inner_script).
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let base = std::env::temp_dir().join(format!("mwsqlctl-elev-{nonce}"));
    let out_tmp = base.with_extension("out");
    let err_tmp = base.with_extension("err");

    let inner = build_inner_script(&me.to_string_lossy(), args, &out_tmp, &err_tmp);
    let script = build_outer_script(&encode_powershell_command(&inner));
    println!("Requesting administrator privileges (a UAC prompt will appear)…");
    let status = run_powershell(&script).context("relaunch elevated via PowerShell")?;
    let code = status.code().unwrap_or(1);

    // shortcut: the elevated child's stdout/stderr transit a user-temp file;
    // upgrade to a named pipe if that round-trip is ever unacceptable. Read as
    // bytes and decode (WinPS 5.1 writes UTF-16LE+BOM) then delete on every path,
    // so a cancelled run leaves nothing behind and a token is never lost.
    let out = std::fs::read(&out_tmp)
        .map(|b| decode_child_output(&b))
        .unwrap_or_default();
    let err = std::fs::read(&err_tmp)
        .map(|b| decode_child_output(&b))
        .unwrap_or_default();
    let _ = std::fs::remove_file(&out_tmp);
    let _ = std::fs::remove_file(&err_tmp);

    if code == ELEVATION_CANCELLED {
        bail!("elevation was cancelled or could not start; run this from an elevated PowerShell instead.");
    }

    if !out.is_empty() {
        print!("{out}");
        std::io::stdout().flush().ok();
    }
    if !err.is_empty() {
        eprint!("{err}");
        std::io::stderr().flush().ok();
    }
    std::process::exit(code);
}

/// Relaunch self elevated via UAC for a service-install subcommand: `<sub>
/// <forward…> --uac`. Blocks on the child and mirrors its output + exit code.
#[cfg(windows)]
fn relaunch_elevated_windows(subcommand: &str, forward: &[OsString]) -> Result<()> {
    let mut args: Vec<String> = vec![subcommand.to_string()];
    args.extend(forward.iter().map(|a| a.to_string_lossy().into_owned()));
    args.push("--uac".to_string());
    relaunch_elevated_and_wait(&args)
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
    let encoded = encode_powershell_command(script);
    Command::new(windows_powershell_path())
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
    // exact command, then fail (non-zero). Returning Ok here would report success
    // having seeded/installed NOTHING, so a CI/Ansible/Docker run sees `init`
    // "succeed" and only trips on the next command against an unconfigured state
    // dir. An operation that did nothing must not report success.
    if !std::io::stdin().is_terminal() {
        print_manual(&me, subcommand, forward);
        bail!(
            "cannot elevate for `{subcommand}`: root is required but stdin is not a \
             terminal to confirm the sudo re-exec. Nothing was changed — run the \
             printed command under sudo."
        );
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
        // sc.exe has no atomic restart; stop (ignore "not running"), wait for the
        // service to actually exit, then start — `sc stop` only signals a stop, so
        // starting immediately races the pending stop ("service is stopping").
        let _ = Command::new("sc.exe").args(["stop", name]).status();
        wait_for_service_stopped(name);
        run_cmd("sc.exe", &["start", name])?;
        println!("Restarted {name} to apply the new configuration.");
    }
    Ok(())
}

/// Stop and remove the OS service — the inverse of [`install_and_enable_service`].
/// Linux+root: `systemctl disable --now` then delete the unit and reload. Windows
/// +admin: `sc.exe stop` then `sc.exe delete`. Idempotent: an already-absent
/// service is reported, not an error. When not elevated (or on macOS, which never
/// auto-installs), it prints the manual commands instead of failing — the caller
/// has already elevated in the normal service path, so this branch is the
/// best-effort fallback.
pub(crate) fn uninstall_service(service_name: &str) -> Result<()> {
    if cfg!(target_os = "linux") && is_root() {
        // disable --now both stops and disables; tolerate "not loaded".
        let _ = Command::new("systemctl")
            .args(["disable", "--now", service_name])
            .status();
        let unit = PathBuf::from(format!("/etc/systemd/system/{service_name}.service"));
        if unit.exists() {
            std::fs::remove_file(&unit).with_context(|| format!("remove {}", unit.display()))?;
        }
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        println!("Service {service_name} stopped and removed.");
    } else if cfg!(windows) && is_admin() {
        // sc.exe has no atomic remove; stop first (ignore "not running"), then
        // wait for the service process to actually exit. `sc stop` only signals
        // a stop — the daemon keeps its handles on the state dir open until it
        // exits, and the caller deletes that dir next, so a delete-then-remove
        // race would otherwise leave the dir half-removed. Then delete.
        let _ = Command::new("sc.exe").args(["stop", service_name]).status();
        wait_for_service_stopped(service_name);
        let deleted = Command::new("sc.exe")
            .args(["delete", service_name])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if deleted {
            println!("Service {service_name} removed.");
        } else {
            println!("Service {service_name} was not registered (nothing to remove).");
        }
    } else {
        println!("\n# ---- remove the service manually (run elevated) ----");
        if cfg!(windows) {
            println!("sc.exe stop {service_name}; sc.exe delete {service_name}");
        } else if cfg!(target_os = "macos") {
            println!("sudo launchctl unload -w /Library/LaunchDaemons/com.middlewhere.{service_name}.plist");
            println!("sudo rm -f /Library/LaunchDaemons/com.middlewhere.{service_name}.plist");
        } else {
            println!("sudo systemctl disable --now {service_name}");
            println!("sudo rm -f /etc/systemd/system/{service_name}.service");
            println!("sudo systemctl daemon-reload");
        }
    }
    Ok(())
}

/// Locale-independent service-state code from `sc query`: 1 = STOPPED.
const SERVICE_STATE_STOPPED: u32 = 1;

/// Poll until the service reports STOPPED or no longer exists (bounded, ~7.5s).
/// Used after `sc.exe stop` so the daemon has released its file handles on the
/// state dir before we delete the service and remove that dir. Compiled on all
/// platforms but only reached from the Windows branch of [`uninstall_service`].
fn wait_for_service_stopped(service_name: &str) {
    for _ in 0..30 {
        match Command::new("sc.exe")
            .args(["query", service_name])
            .output()
        {
            // Non-zero exit means the service is already gone.
            Ok(o) if !o.status.success() => return,
            Ok(o)
                if parse_sc_state(&String::from_utf8_lossy(&o.stdout))
                    == Some(SERVICE_STATE_STOPPED) =>
            {
                return
            }
            Ok(_) => {}
            Err(_) => return,
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// Parse the numeric service-state code from `sc query` stdout. The state line
/// reads `STATE : <N>  <WORD>`; `N` is a stable code (1 = STOPPED, 4 = RUNNING)
/// while `<WORD>` is *localized* on non-English Windows — so match the number,
/// not the word (the old `contains("STOPPED")` never fired on a localized box and
/// burned the full poll timeout). Returns None when no state line is present.
fn parse_sc_state(stdout: &str) -> Option<u32> {
    stdout.lines().find_map(|line| {
        let (label, value) = line.split_once(':')?;
        if !label.trim().eq_ignore_ascii_case("STATE") {
            return None;
        }
        value.split_whitespace().next()?.parse::<u32>().ok()
    })
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

    #[test]
    fn ps_single_quote_handles_quotes_spaces_and_empty() {
        assert_eq!(ps_single_quote(""), "''");
        assert_eq!(ps_single_quote("plain"), "'plain'");
        assert_eq!(ps_single_quote("my db"), "'my db'");
        assert_eq!(ps_single_quote("it's"), "'it''s'");
        assert_eq!(ps_single_quote("a'b'c"), "'a''b''c'");
    }

    #[test]
    fn gate_requires_stdin_terminal_only() {
        // Redirected stdout is fine (the parent mirrors output back); only a piped
        // stdin — which can't reach the elevated child — blocks the relaunch.
        assert!(can_relaunch_elevated(true));
        assert!(!can_relaunch_elevated(false));
    }

    #[test]
    fn powershell_path_is_absolute_under_system32() {
        let p = windows_powershell_path();
        assert!(
            p.ends_with(r"\System32\WindowsPowerShell\v1.0\powershell.exe"),
            "must be the absolute System32 powershell, got {p}"
        );
        assert!(
            p.contains(":\\"),
            "must be an absolute path (drive-rooted), got {p}"
        );
    }

    #[test]
    fn decode_child_output_handles_utf16_utf8_bom_and_empty() {
        // F1: WinPS 5.1 writes UTF-16LE + BOM; the old read_to_string dropped it.
        let mut utf16 = vec![0xFF, 0xFE];
        for u in "tok-42".encode_utf16() {
            utf16.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(decode_child_output(&utf16), "tok-42");
        assert_eq!(decode_child_output(b"plain utf8"), "plain utf8");
        assert_eq!(decode_child_output(b"\xEF\xBB\xBFwith-bom"), "with-bom");
        assert_eq!(decode_child_output(b""), "");
        // PowerShell's `1>` rewrites the child's \n as \r\n; undo it so a captured
        // token isn't left with a trailing CR.
        let mut crlf = vec![0xFF, 0xFE];
        for u in "tok\r\n".encode_utf16() {
            crlf.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(decode_child_output(&crlf), "tok\n");
    }

    #[test]
    fn encode_powershell_command_is_base64_utf16le() {
        // "AB" as UTF-16LE = 41 00 42 00; base64 of that is "QQBCAA==".
        assert_eq!(encode_powershell_command("AB"), "QQBCAA==");
    }

    #[test]
    fn inner_script_quotes_args_creates_files_and_guards_exit() {
        let out = Path::new("C:\\Temp\\e.out");
        let err = Path::new("C:\\Temp\\e.err");
        let args = vec![
            "grant".to_string(),
            "--database".to_string(),
            "my db".to_string(),
        ];
        let s = build_inner_script("C:\\Program Files\\mw\\mwsqlctl.exe", &args, out, err);
        // A space-containing arg stays one single-quoted token.
        assert!(
            s.contains("'my db'"),
            "arg with space must stay one token:\n{s}"
        );
        // CreateNew defeats a pre-planted symlink at the redirect target.
        assert!(
            s.contains("[IO.FileMode]::CreateNew"),
            "must create with CreateNew"
        );
        assert!(
            s.contains("1> ") && s.contains("2> "),
            "redirects both streams"
        );
        // F6: a child that never launched reports failure, not exit 0.
        assert!(
            s.contains("if ($null -eq $code) { $code = 1 }"),
            "null exit guard"
        );
        assert!(s.contains("catch"), "launch failure is caught");
        assert!(s.contains("exit $code"));
    }

    #[test]
    fn outer_script_uses_encodedcommand_waits_and_guards() {
        let s = build_outer_script("QQBCAA==");
        assert!(
            s.contains("-EncodedCommand"),
            "child gets one opaque encoded arg"
        );
        assert!(
            s.contains("'QQBCAA=='"),
            "encoded inner is a single quoted token"
        );
        assert!(s.contains("-Verb RunAs") && s.contains("-Wait") && s.contains("-PassThru"));
        // R3-F3: the elevated child is the absolute System32 powershell, not a
        // bare name that could resolve to a planted binary.
        assert!(
            s.contains(r"\System32\WindowsPowerShell\v1.0\powershell.exe"),
            "must launch the absolute powershell path:\n{s}"
        );
        assert!(s.contains("$p.ExitCode"), "mirrors child exit code");
        assert!(
            s.contains("if ($null -eq $code) { $code = 1 }"),
            "null exit guard"
        );
        assert!(
            s.contains(&ELEVATION_CANCELLED.to_string()),
            "cancel sentinel present"
        );
    }

    #[test]
    fn non_interactive_elevate_returns_err_not_ok() {
        // R-F2: with no terminal to confirm the sudo re-exec, elevate must FAIL
        // (non-zero) rather than report success having seeded/installed nothing —
        // otherwise a CI/Ansible/Docker `init` "succeeds" then trips on the next
        // command against an unconfigured state dir. `cargo test` runs with a
        // non-terminal stdin, so this hits the no-tty branch; skip if a runner
        // happens to attach a TTY (that branch needs none of this).
        if std::io::stdin().is_terminal() {
            return;
        }
        assert!(
            elevate_or_print("init", &[], "needs root").is_err(),
            "non-interactive elevate must return Err, not a no-op Ok"
        );
    }

    #[test]
    fn parse_sc_state_reads_numeric_code_regardless_of_locale() {
        // R-F5: match the numeric STATE code, not the localized word.
        let running = "SERVICE_NAME: mwsqld\n    TYPE               : 10  WIN32_OWN_PROCESS\n    STATE              : 4  RUNNING\n";
        let stopped = "    STATE              : 1  STOPPED\n";
        // Same code, German word — still parses as stopped (the whole point).
        let stopped_localized = "    STATE              : 1  BEENDET\n";
        assert_eq!(parse_sc_state(running), Some(4));
        assert_eq!(parse_sc_state(stopped), Some(SERVICE_STATE_STOPPED));
        assert_eq!(
            parse_sc_state(stopped_localized),
            Some(SERVICE_STATE_STOPPED),
            "a localized state word must still parse as stopped by its code"
        );
        assert_eq!(parse_sc_state("no state line here"), None);
    }
}
