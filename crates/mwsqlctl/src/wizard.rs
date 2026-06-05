//! Guided, service-first setup wizard (`mwsqlctl wizard` / `setup`).
//!
//! One command takes a junior operator from a fresh install to a running
//! systemd service: it self-elevates, creates the system account, seeds the
//! sealed config (bastions, credentials, envs — secrets prompted in-process,
//! never on argv or disk in cleartext), writes the hardened unit, and starts
//! it. `--user` instead does a no-elevation per-user install.
//!
//! Elevation is *elevate-first*: in service mode the wizard re-execs itself
//! under `sudo` BEFORE prompting for anything, so every secret is entered in
//! the one root process that writes the root-owned state dir. No secret ever
//! crosses the sudo boundary.

use std::ffi::OsString;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use mw_core::config::{EngineKind, Policy};
use mw_core::state::{default_state_dir, resolve_cli_target};

use crate::installer::InstallParams;
use crate::ops::{self, Target};
use crate::{bastion, cred, envs};

/// The raw flags the wizard resolves its mode and elevation from.
pub struct WizardOpts {
    pub state_dir: Option<PathBuf>,
    pub user: bool,
    pub file_keystore: bool,
    pub service_name: String,
    pub exec_path: Option<PathBuf>,
}

const ELEVATED_MARKER: &str = "MW_WIZARD_ELEVATED";

pub fn run(opts: WizardOpts) -> Result<()> {
    let service = !opts.user;

    // Interactive-only. Fail BEFORE doing anything — especially before
    // elevating — when there's no terminal to prompt on, so we never leave a
    // half-elevated, half-seeded state. (sudo preserves the TTY, so the
    // re-exec'd process still passes this.)
    if !std::io::stdin().is_terminal() {
        bail!(
            "the wizard is interactive and needs a terminal. Run it in a TTY, \
             or configure with the individual `mwsqlctl` commands."
        );
    }
    // service_name is baked into `useradd`, `chown`, `User=`, and the unit
    // path; reject anything that could break those before we touch the system.
    if service {
        validate_service_name(&opts.service_name)?;
    }

    // Elevate-first: only a Linux service deployment self-elevates, and only
    // when not already root. `is_root()` is the authoritative loop guard
    // (sudo resets the env, so the marker may not survive — that's fine).
    if service && cfg!(target_os = "linux") && !is_root() && !already_elevated() {
        return elevate_or_print(&opts);
    }

    let (state_dir, ks) = resolve_cli_target(opts.state_dir.clone(), opts.user, opts.file_keystore);
    let t = Target::new(&state_dir, &ks);

    intro(service, &state_dir);

    if service && cfg!(target_os = "linux") && is_root() {
        ensure_service_user(&opts.service_name)?;
    }

    // init-if-needed; an existing config is the re-run signal, not an error.
    if ops::is_initialized(&state_dir) {
        if existing_config_action(t)? == Existing::Quit {
            return Ok(());
        }
    } else {
        ops::init(t)?;
        println!("Initialized sealed config at {}", state_dir.display());
    }

    add_bastions_loop(t)?;
    add_credentials_loop(t)?;
    add_envs_loop(t)?;

    // Hand the seeded, root-written files to the service account so the
    // sandboxed daemon can read them.
    if service && cfg!(target_os = "linux") && is_root() {
        chown_state_dir(&state_dir, &opts.service_name)?;
    }

    if service {
        install_service_step(&opts, &state_dir)?;
    } else {
        println!("\nDone. Run it (no elevation needed):");
        println!("  mwsqld --user run");
    }
    Ok(())
}

fn intro(service: bool, state_dir: &Path) {
    if service {
        println!("middleWHERE setup — service deployment");
        println!("State dir: {} (root-owned)\n", state_dir.display());
    } else {
        println!("middleWHERE setup — per-user deployment");
        println!("State dir: {}\n", state_dir.display());
    }
}

/// A systemd service / unix account name we can safely bake into `useradd`,
/// `chown a:a`, `User=`, and `/etc/systemd/system/<name>.service`. Restrict to
/// a conservative `[a-z_][a-z0-9_-]*` token (the default `mwsqld` passes).
fn validate_service_name(name: &str) -> Result<()> {
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

// ---- line-based prompts (no TUI dependency; works on every target) -----

/// Print a label and read one trimmed line. EOF (closed stdin) is an error —
/// the wizard requires a real terminal (checked up front in `run`).
fn read_line(label: &str) -> Result<String> {
    print!("{label} ");
    io::stdout().flush().ok();
    let mut s = String::new();
    if io::stdin().lock().read_line(&mut s)? == 0 {
        bail!("unexpected end of input");
    }
    Ok(s.trim().to_string())
}

/// Required free text; re-asks on a blank line.
fn prompt_text(label: &str) -> Result<String> {
    loop {
        let s = read_line(label)?;
        if !s.is_empty() {
            return Ok(s);
        }
        eprintln!("  ! required");
    }
}

/// Free text with a default applied on a blank line.
fn prompt_text_default(label: &str, default: &str) -> Result<String> {
    let s = read_line(&format!("{label} [{default}]:"))?;
    Ok(if s.is_empty() { default.to_string() } else { s })
}

/// Optional free text; a blank line means None.
fn prompt_optional_text(label: &str) -> Result<Option<String>> {
    let s = read_line(label)?;
    Ok(if s.is_empty() { None } else { Some(s) })
}

fn confirm(label: &str, default_yes: bool) -> Result<bool> {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    loop {
        match read_line(&format!("{label} {hint}"))?
            .to_ascii_lowercase()
            .as_str()
        {
            "" => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => eprintln!("  ! please answer y or n"),
        }
    }
}

/// Numbered single-select; returns the chosen 0-based index.
fn select_index(label: &str, labels: &[&str]) -> Result<usize> {
    println!("{label}");
    for (i, o) in labels.iter().enumerate() {
        println!("  {}) {o}", i + 1);
    }
    loop {
        let s = read_line("  choose [number]:")?;
        if let Ok(n) = s.parse::<usize>() {
            if (1..=labels.len()).contains(&n) {
                return Ok(n - 1);
            }
        }
        eprintln!("  ! enter a number 1-{}", labels.len());
    }
}

/// Numbered single-select over owned strings; returns the chosen value.
fn select_owned(label: &str, options: &[String]) -> Result<String> {
    let refs: Vec<&str> = options.iter().map(String::as_str).collect();
    Ok(options[select_index(label, &refs)?].clone())
}

/// Prompt for a port, re-asking on a non-numeric entry instead of aborting the
/// whole wizard.
fn prompt_port(label: &str, default: u16) -> Result<u16> {
    loop {
        match prompt_text_default(label, &default.to_string())?.parse::<u16>() {
            Ok(p) => return Ok(p),
            Err(_) => eprintln!("  ! not a valid port (0-65535); try again"),
        }
    }
}

/// Like [`prompt_port`] but a blank line means "use the engine default" (None).
fn prompt_optional_port(label: &str) -> Result<Option<u16>> {
    loop {
        match prompt_optional_text(label)? {
            None => return Ok(None),
            Some(s) => match s.parse::<u16>() {
                Ok(p) => return Ok(Some(p)),
                Err(_) => eprintln!("  ! not a valid port (0-65535); try again"),
            },
        }
    }
}

// ---- elevation ---------------------------------------------------------

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    // SAFETY: geteuid is always-safe and never fails.
    unsafe { libc::geteuid() == 0 }
}
#[cfg(not(target_os = "linux"))]
fn is_root() -> bool {
    false
}

fn already_elevated() -> bool {
    std::env::var_os(ELEVATED_MARKER).is_some()
}

/// Build the argv passed to `sudo`: `-- <abs exe> wizard <forwarded flags>`.
/// Pure so it can be unit-tested without spawning. `--` stops sudo option
/// parsing; the absolute exe path bypasses sudo's secure_path PATH lookup.
// Only the unix re-exec path (and tests) call this; on Windows it's exercised
// solely by the test module.
#[cfg_attr(not(unix), allow(dead_code))]
fn build_sudo_argv(me: &Path, forward: &[OsString]) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec!["--".into(), me.as_os_str().to_owned(), "wizard".into()];
    argv.extend(forward.iter().cloned());
    argv
}

/// The non-secret flags to forward across the re-exec. Never `--user` (service
/// mode), never a secret.
fn forwarded_args(opts: &WizardOpts) -> Vec<OsString> {
    let mut v: Vec<OsString> = Vec::new();
    if let Some(sd) = &opts.state_dir {
        v.push("--state-dir".into());
        v.push(sd.as_os_str().to_owned());
    }
    if opts.file_keystore {
        v.push("--file-keystore".into());
    }
    v.push("--service-name".into());
    v.push(opts.service_name.clone().into());
    if let Some(ep) = &opts.exec_path {
        v.push("--exec-path".into());
        v.push(ep.as_os_str().to_owned());
    }
    v
}

fn elevate_or_print(opts: &WizardOpts) -> Result<()> {
    let me = std::env::current_exe().context("resolve current exe")?;
    if !me.exists() {
        bail!(
            "cannot locate own executable ({}) to re-run under sudo; \
             run: sudo <abs-path-to-mwsqlctl> wizard",
            me.display()
        );
    }
    let forward = forwarded_args(opts);
    // Name the dir we'll actually seed (an explicit --state-dir is forwarded
    // and wins), not just the default — the operator is approving sudo for it.
    let target_dir = opts.state_dir.clone().unwrap_or_else(default_state_dir);
    println!(
        "Service setup needs root: it creates the {svc} system account, writes\n\
         /etc/systemd/system/{svc}.service, and seeds {state}.",
        svc = opts.service_name,
        state = target_dir.display()
    );
    let proceed = confirm("Re-run this wizard under sudo now?", true).unwrap_or(false);
    if !proceed {
        println!("\nNo changes made. Run it yourself when ready:");
        print!("  sudo {} wizard", me.display());
        for a in &forward {
            print!(" {}", a.to_string_lossy());
        }
        println!();
        return Ok(());
    }
    re_exec_under_sudo(&me, &forward)
}

#[cfg(unix)]
fn re_exec_under_sudo(me: &Path, forward: &[OsString]) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let argv = build_sudo_argv(me, forward);
    // exec replaces this process; the only way it returns is failure.
    let err = Command::new("sudo")
        .args(&argv)
        .env(ELEVATED_MARKER, "1")
        .exec();
    Err(anyhow::Error::new(err).context("exec sudo (is sudo installed and on PATH?)"))
}
#[cfg(not(unix))]
fn re_exec_under_sudo(_me: &Path, _forward: &[OsString]) -> Result<()> {
    bail!("self-elevation is only supported on unix");
}

// ---- system account + ownership (linux) --------------------------------

#[cfg(target_os = "linux")]
fn ensure_service_user(name: &str) -> Result<()> {
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
fn ensure_service_user(_name: &str) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn chown_state_dir(dir: &Path, name: &str) -> Result<()> {
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
fn chown_state_dir(_dir: &Path, _name: &str) -> Result<()> {
    Ok(())
}

// ---- existing-config branch -------------------------------------------

#[derive(PartialEq, Eq)]
enum Existing {
    AddMore,
    Quit,
}

fn existing_config_action(t: Target) -> Result<Existing> {
    println!("Found an existing config at {}.", t.state_dir.display());
    loop {
        match select_index("What now?", &["Add more", "Show current", "Quit"])? {
            1 => show_current(t)?,
            2 => return Ok(Existing::Quit),
            _ => return Ok(Existing::AddMore),
        }
    }
}

fn show_current(t: Target) -> Result<()> {
    let bastions = bastion::list(t.state_dir, t.ks)?;
    let creds = cred::list(t.state_dir, t.ks)?;
    let envs = envs::list(t.state_dir, t.ks)?;
    println!("  bastions ({}):", bastions.len());
    for b in &bastions {
        println!(
            "    {} {}:{} user={} auth={}",
            b.name, b.host, b.port, b.ssh_user, b.auth_kind
        );
    }
    println!("  credentials ({}):", creds.len());
    for c in &creds {
        println!("    {} user={}", c.name, c.backend_user);
    }
    println!("  envs ({}):", envs.len());
    for e in &envs {
        println!(
            "    {} {} engine={} cred={} policy={} port={}",
            e.name, e.backend, e.engine, e.credential, e.policy, e.listen_port
        );
    }
    Ok(())
}

// ---- add loops ---------------------------------------------------------

fn add_bastions_loop(t: Target) -> Result<()> {
    while confirm("Add a bastion?", true)? {
        let name = prompt_text("Bastion name:")?;
        let host = prompt_text("SSH host:")?;
        let port = prompt_port("SSH port:", 22)?;
        let ssh_user = prompt_text("SSH user:")?;
        let key_file = match select_index("Auth method:", &["password", "private key file"])? {
            1 => Some(PathBuf::from(prompt_text("PEM private-key path:")?)),
            _ => None,
        };
        let fingerprints = match prompt_optional_text(
            "Pinned host-key fingerprint <algo>:<sha256_b64> (blank to skip):",
        )? {
            Some(fp) => vec![fp],
            None => vec![],
        };
        // add_bastion prompts the password / passphrase in-process (masked).
        match ops::add_bastion(
            t,
            ops::BastionInput {
                name: name.clone(),
                host,
                port,
                ssh_user,
                key_file,
                password_stdin: false,
                fingerprints,
            },
        ) {
            Ok(()) => println!("  added bastion {name}"),
            Err(e) => eprintln!("  ! {e}"),
        }
    }
    Ok(())
}

fn add_credentials_loop(t: Target) -> Result<()> {
    while confirm("Add a credential?", true)? {
        let name = prompt_text("Credential name:")?;
        let user = prompt_text("Backend DB user:")?;
        match ops::add_credential(t, &name, &user, false) {
            Ok(()) => println!("  added credential {name}"),
            Err(e) => eprintln!("  ! {e}"),
        }
    }
    Ok(())
}

fn add_envs_loop(t: Target) -> Result<()> {
    while confirm("Add an environment (a client listener)?", true)? {
        let creds = cred_names(t)?;
        if creds.is_empty() {
            println!("  (no credentials yet — add one first; skipping envs)");
            break;
        }
        let name = prompt_text("Env name:")?;
        let backend_host = prompt_text("Backend DB host:")?;
        let engine = match select_index("Engine:", &["mysql", "postgres"])? {
            1 => EngineKind::Postgres,
            _ => EngineKind::MySql,
        };
        let backend_port = prompt_optional_port("Backend port (blank = engine default):")?;
        let bastion = pick_optional("Bastion (reuse or none):", bastion_names(t)?)?;
        let credential = select_owned("Credential (reuse):", &creds)?;
        let policy = match select_index("Policy:", &["read-only", "read-write"])? {
            1 => Policy::ReadWrite,
            _ => Policy::ReadOnly,
        };
        match ops::add_env(
            t,
            ops::EnvInput {
                name: name.clone(),
                backend_host,
                backend_port,
                engine,
                database: None,
                bastion,
                credential,
                policy,
                listen_port: None,
                max_pool: None,
            },
        ) {
            Ok(out) => {
                println!("  env {name} -> 127.0.0.1:{}", out.listen_port);
                println!("    client:  mwsql login {name} --port {}", out.listen_port);
                println!("    token (save now, shown once): {}", out.token.expose());
            }
            Err(e) => eprintln!("  ! {e}"),
        }
    }
    Ok(())
}

fn bastion_names(t: Target) -> Result<Vec<String>> {
    Ok(bastion::list(t.state_dir, t.ks)?
        .into_iter()
        .map(|b| b.name)
        .collect())
}

fn cred_names(t: Target) -> Result<Vec<String>> {
    Ok(cred::list(t.state_dir, t.ks)?
        .into_iter()
        .map(|c| c.name)
        .collect())
}

fn pick_optional(msg: &str, names: Vec<String>) -> Result<Option<String>> {
    if names.is_empty() {
        return Ok(None);
    }
    let mut opts = vec!["(none)".to_string()];
    opts.extend(names);
    let pick = select_owned(msg, &opts)?;
    Ok(if pick == "(none)" { None } else { Some(pick) })
}

// ---- service install ---------------------------------------------------

fn install_service_step(opts: &WizardOpts, state_dir: &Path) -> Result<()> {
    let exec_path = match &opts.exec_path {
        Some(p) => p.clone(),
        None => ops::default_daemon_path()?,
    };
    let params = InstallParams::new(
        &opts.service_name,
        exec_path.to_string_lossy().to_string(),
        state_dir.to_string_lossy().to_string(),
    );
    let art = ops::build_service_artifact(&params, true)?;
    let unit_path = PathBuf::from(format!("/etc/systemd/system/{}.service", opts.service_name));

    if cfg!(target_os = "linux") && is_root() {
        ops::write_service_artifact(&unit_path, &art.artifact, true)?;
        run_cmd("systemctl", &["daemon-reload"])?;
        run_cmd("systemctl", &["enable", "--now", &opts.service_name])?;
        println!("\nService {} installed and started.", opts.service_name);
        println!("Follow logs:  journalctl -u {} -f", opts.service_name);
        println!("\nFor raw commands against this deployment, export once:");
        println!(
            "  export MW_STATE_DIR={} MW_FILE_KEYSTORE=1",
            state_dir.display()
        );
    } else {
        println!("\n# ---- {}.service ----", opts.service_name);
        print!("{}", art.artifact);
        println!("\n# ---- operator steps (run elevated) ----\n{}", art.steps);
    }
    Ok(())
}

fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
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

    fn opts() -> WizardOpts {
        WizardOpts {
            state_dir: Some(PathBuf::from("/var/lib/middlewhere")),
            user: false,
            file_keystore: true,
            service_name: "mwsqld".into(),
            exec_path: Some(PathBuf::from("/usr/local/bin/mwsqld")),
        }
    }

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
    fn sudo_argv_forwards_exe_then_subcommand() {
        // `me` is forwarded verbatim (it's `current_exe()` at runtime, already
        // absolute); build_sudo_argv only frames it as `-- <me> wizard …`.
        let me = std::env::current_exe().unwrap();
        let fwd = forwarded_args(&opts());
        let argv = build_sudo_argv(&me, &fwd);
        assert_eq!(argv[0], OsString::from("--"));
        assert_eq!(argv[1], me.as_os_str());
        assert_eq!(argv[2], OsString::from("wizard"));
        assert!(
            me.is_absolute(),
            "current_exe should be absolute, got {me:?}"
        );
        // The forwarded service flags follow the subcommand.
        let tail: Vec<String> = argv[3..]
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(tail.contains(&"--service-name".to_string()));
    }

    #[test]
    fn forwarded_args_never_include_user_and_carry_service_flags() {
        let fwd: Vec<String> = forwarded_args(&opts())
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(
            !fwd.iter().any(|a| a == "--user"),
            "must not forward --user"
        );
        assert!(fwd.contains(&"--state-dir".to_string()));
        assert!(fwd.contains(&"/var/lib/middlewhere".to_string()));
        assert!(fwd.contains(&"--file-keystore".to_string()));
        assert!(fwd.contains(&"--service-name".to_string()));
        assert!(fwd.contains(&"mwsqld".to_string()));
        assert!(fwd.contains(&"--exec-path".to_string()));
    }

    #[test]
    fn forwarded_args_minimal_when_no_overrides() {
        let o = WizardOpts {
            state_dir: None,
            user: false,
            file_keystore: false,
            service_name: "mwsqld".into(),
            exec_path: None,
        };
        let fwd: Vec<String> = forwarded_args(&o)
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            fwd,
            vec!["--service-name".to_string(), "mwsqld".to_string()]
        );
    }
}
