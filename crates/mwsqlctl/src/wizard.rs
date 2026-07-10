//! Guided connection configuration (`mwsqlctl wizard` / `setup`).
//!
//! The wizard configures an **already-installed** deployment: it adds bastions,
//! credentials, and envs (secrets prompted in-process, never on argv or disk in
//! cleartext) and restarts the service so the daemon binds the new listeners.
//! Installing the service itself (the system account, the unit, `enable --now`)
//! is `mwsqlctl init`'s job — run that first.
//!
//! In service mode the wizard self-elevates *before any prompt* (see
//! [`crate::service`]) so every secret is written by the one root process that
//! owns the state dir. `--user` configures the per-user deployment with no
//! elevation.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use mw_core::config::{EngineKind, Policy};
use mw_core::state::{default_state_dir, resolve_cli_target};

use crate::ops::{self, Target};
use crate::prompt::{
    confirm, prompt_optional_port, prompt_optional_text, prompt_port, prompt_text, select_index,
    select_owned,
};
use crate::{bastion, cred, envs, service};

/// The raw flags the wizard resolves its mode and elevation from.
pub struct WizardOpts {
    pub state_dir: Option<PathBuf>,
    pub user: bool,
    pub file_keystore: bool,
    /// Which service to restart after applying config (service mode only).
    pub service_name: String,
    /// Set on the Windows UAC-relaunched child (see [`crate::init::InitOpts`]).
    pub uac: bool,
}

pub fn run(opts: WizardOpts) -> Result<()> {
    run_inner(opts)
}

fn run_inner(opts: WizardOpts) -> Result<()> {
    let service = !opts.user;

    // Interactive-only. Fail BEFORE elevating when there's no terminal to
    // prompt on. (sudo preserves the TTY, so the re-exec'd process still
    // passes this.)
    if !std::io::stdin().is_terminal() {
        bail!(
            "the wizard is interactive and needs a terminal. Run it in a TTY, \
             or configure with the individual `mwsqlctl` commands."
        );
    }
    if service {
        // Baked into `systemctl restart <name>`; validate before we elevate.
        service::validate_service_name(&opts.service_name)?;
    }

    // Configuring writes to the root-owned/Admin-owned state dir, so service
    // mode needs root (Linux) / admin (Windows). Elevate-first before any
    // prompt: `sudo` re-exec on Linux, a UAC relaunch on Windows.
    if service && service::needs_service_elevation(opts.uac) {
        // Windows can't auto-elevate the wizard: a UAC child's stdout is
        // redirected to a temp file, so its many interactive prompts would be
        // invisible and it would block unseen. Send the operator to an elevated
        // terminal instead. On unix, sudo keeps the TTY, so the re-exec below
        // prompts normally.
        if cfg!(windows) {
            bail!(
                "administrator privileges are required. Re-run `mwsqlctl wizard` from \
                 an elevated terminal (Run as administrator), or pass --user to \
                 configure a per-user deployment."
            );
        }
        let forward = forwarded_args(&opts);
        let target_dir = opts.state_dir.clone().unwrap_or_else(default_state_dir);
        let reason = format!(
            "Configuring needs root: it writes secrets into the root-owned config\n\
             at {} and restarts {}.",
            target_dir.display(),
            opts.service_name
        );
        return service::elevate_for_service("wizard", &forward, &reason);
    }

    let (state_dir, ks) = resolve_cli_target(opts.state_dir.clone(), opts.user, opts.file_keystore);
    let t = Target::new(&state_dir, &ks);

    // The wizard configures; it does not install. An uninitialized state dir
    // means `init` hasn't run yet.
    if !ops::is_initialized(&state_dir) {
        if service {
            bail!(
                "no config at {} — run `mwsqlctl init` first to install the service",
                state_dir.display()
            );
        }
        bail!(
            "no config at {} — run `mwsqlctl --user init` first",
            state_dir.display()
        );
    }

    intro(service, &state_dir);

    // Re-run menu: this is always an existing config (init seeded it).
    if existing_config_action(t)? == Existing::Quit {
        return Ok(());
    }

    let changed = run_config(t)?;

    if service {
        finalize_service_config(&opts.service_name, &state_dir, changed)?;
    } else {
        println!("\nDone. Run it (no elevation needed):");
        println!("  mwsqld --user run");
    }
    Ok(())
}

fn intro(service: bool, state_dir: &Path) {
    if service {
        println!("middleWHERE — configure connections (service deployment)");
        println!("State dir: {} (root-owned)\n", state_dir.display());
    } else {
        println!("middleWHERE — configure connections (per-user deployment)");
        println!("State dir: {}\n", state_dir.display());
    }
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
    v
}

/// After config is written as root in service mode: hand the new files back to
/// the service account and restart so the daemon binds the new listeners.
/// Shared with `init`'s "configure now" path.
pub(crate) fn finalize_service_config(
    service_name: &str,
    state_dir: &Path,
    changed: bool,
) -> Result<()> {
    if cfg!(target_os = "linux") && service::is_root() {
        service::chown_state_dir(state_dir, service_name)?;
        if changed {
            service::restart_service(service_name)?;
        }
    } else if cfg!(windows) && service::is_admin() {
        // Elevated (UAC relaunch / admin shell): restart for real.
        if changed {
            service::restart_service(service_name)?;
        }
    } else if changed {
        println!("\nRestart the service to apply the new configuration:");
        if cfg!(windows) {
            println!("  Restart-Service {service_name}   # run elevated");
        } else if cfg!(target_os = "macos") {
            println!("  sudo launchctl kickstart -k system/com.middlewhere.{service_name}");
        } else {
            println!("  sudo systemctl restart {service_name}");
        }
    }
    Ok(())
}

// ---- existing-config branch -------------------------------------------

#[derive(PartialEq, Eq)]
enum Existing {
    AddMore,
    Quit,
}

fn existing_config_action(t: Target) -> Result<Existing> {
    loop {
        match select_index("What now?", &["Add more", "Show current", "Quit"])? {
            1 => show_current(t)?,
            2 => return Ok(Existing::Quit),
            _ => return Ok(Existing::AddMore),
        }
    }
}

fn show_current(t: Target) -> Result<()> {
    // Unseal the config once (one OS-keychain unlock in --user mode) and build
    // all three lists from it, rather than unsealing per list.
    let cfg = mw_core::state::load_config(t.state_dir, t.ks)?;
    let bastions = bastion::rows(&cfg);
    let creds = cred::rows(&cfg);
    let envs = envs::rows(&cfg);
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

/// The interactive add-bastions/credentials/envs flow. Assumes the config is
/// already initialized. Returns whether anything was added (so the caller knows
/// whether a service restart is warranted). Called both by the standalone
/// `wizard` and inline by `init`'s "configure now" prompt (already elevated).
pub(crate) fn run_config(t: Target) -> Result<bool> {
    let b = add_bastions_loop(t)?;
    let c = add_credentials_loop(t)?;
    let e = add_envs_loop(t)?;
    Ok(b || c || e)
}

fn add_bastions_loop(t: Target) -> Result<bool> {
    let mut added = false;
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
            None => {
                println!("{}", unpinned_bastion_warning(&host));
                vec![]
            }
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
            Ok(()) => {
                println!("  added bastion {name}");
                added = true;
            }
            Err(e) => eprintln!("  ! {e}"),
        }
    }
    Ok(added)
}

fn add_credentials_loop(t: Target) -> Result<bool> {
    let mut added = false;
    while confirm("Add a credential?", true)? {
        let name = prompt_text("Credential name:")?;
        let user = prompt_text("Backend DB user:")?;
        match ops::add_credential(t, &name, &user, false) {
            Ok(()) => {
                println!("  added credential {name}");
                added = true;
            }
            Err(e) => eprintln!("  ! {e}"),
        }
    }
    Ok(added)
}

fn add_envs_loop(t: Target) -> Result<bool> {
    let mut added = false;
    // The cred/bastion name lists don't change inside this loop (only envs are
    // added here), so unseal once up front instead of per iteration.
    let creds = cred_names(t)?;
    let bastions = bastion_names(t)?;
    while confirm("Add an environment (a client listener)?", true)? {
        if creds.is_empty() {
            println!("  (no credentials yet — add one first; skipping envs)");
            break;
        }
        let mut pending = prompt_env_input(&creds, bastions.clone())?;
        // Add, then validate the live connection. On a connect failure, ask the
        // operator what to do (keep / edit & retry / discard).
        loop {
            let name = pending.name.clone();
            let out = match ops::add_env(t, pending) {
                Ok(out) => out,
                Err(e) => {
                    eprintln!("  ! {e}");
                    break;
                }
            };
            let print_block = |o: &envs::NewEnvOutput| {
                crate::print_token_block(
                    &name,
                    o.listen_port,
                    o.token.expose(),
                    o.engine,
                    o.database.as_deref(),
                );
            };
            match crate::probe::validate(t.state_dir, t.ks, Some(&name)) {
                crate::probe::Validation::Ok => {
                    println!("  ✓ connected");
                    print_block(&out);
                    added = true;
                    break;
                }
                crate::probe::Validation::Skipped(note) => {
                    println!("  (validation skipped: {note})");
                    print_block(&out);
                    added = true;
                    break;
                }
                crate::probe::Validation::Failed(reason) => {
                    println!("  ✗ could not connect: {reason}");
                    match select_index("What now?", &["keep anyway", "edit & retry", "discard"])? {
                        0 => {
                            print_block(&out);
                            println!(
                                "  ! saved without a working connection — fix it and re-test:"
                            );
                            println!("      mwsqlctl env test {name}");
                            added = true;
                            break;
                        }
                        1 => {
                            envs::rm(t.state_dir, t.ks, &name)?;
                            pending = prompt_env_input(&creds, bastions.clone())?;
                            ensure_bastion_pinned(t, pending.bastion.as_deref())?;
                            continue;
                        }
                        _ => {
                            envs::rm(t.state_dir, t.ks, &name)?;
                            println!("  discarded {name}");
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(added)
}

/// Prompt the env fields into an [`ops::EnvInput`]. Factored out so the
/// validate-failed "edit & retry" path can re-collect them.
fn prompt_env_input(creds: &[String], bastions: Vec<String>) -> Result<ops::EnvInput> {
    let name = prompt_text("Env name:")?;
    let backend_host = prompt_text("Backend DB host:")?;
    let engine = match select_index("Engine:", &["mysql", "postgres"])? {
        1 => EngineKind::Postgres,
        _ => EngineKind::MySql,
    };
    let backend_port = prompt_optional_port("Backend port (blank = engine default):")?;
    let database = prompt_optional_text("Default database (blank = none):")?;
    let bastion = pick_optional("Bastion (reuse or none):", bastions)?;
    let credential = select_owned("Credential (reuse):", creds)?;
    let policy = match select_index("Policy:", &["read-only", "read-write"])? {
        1 => Policy::ReadWrite,
        _ => Policy::ReadOnly,
    };
    Ok(ops::EnvInput {
        name,
        backend_host,
        backend_port,
        engine,
        database,
        bastion,
        credential,
        policy,
        listen_port: None,
        max_pool: None,
    })
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

/// Warning shown when a bastion is left without a pinned host key. The daemon
/// refuses every connection through an unpinned bastion (and so do the probes
/// and service units), so the env can never validate until one is pinned.
fn unpinned_bastion_warning(host: &str) -> String {
    format!(
        "  ! no host-key fingerprint pinned. Connections through this bastion WILL be\n\
         \x20   refused until one is. Obtain it with:\n\
         \x20     ssh-keyscan {host} | ssh-keygen -lf -\n\
         \x20   then pin the SHA256 value as <algo>:<sha256_b64> (e.g. ssh-ed25519:AAAA…)."
    )
}

/// After a failed env validation, if the chosen bastion has no pinned host key
/// the connection can never succeed. Offer to pin one so the retry can work —
/// keeps the wizard's "edit & retry" loop recoverable.
fn ensure_bastion_pinned(t: Target, bastion: Option<&str>) -> Result<()> {
    let Some(name) = bastion else { return Ok(()) };
    let Some(row) = bastion::list(t.state_dir, t.ks)?
        .into_iter()
        .find(|b| b.name == name)
    else {
        return Ok(());
    };
    if row.pinned_fingerprints > 0 {
        return Ok(());
    }
    println!("{}", unpinned_bastion_warning(&row.host));
    if let Some(fp) = prompt_optional_text("  Pin it now as <algo>:<sha256_b64> (blank to skip):")?
    {
        bastion::set_fingerprint(t.state_dir, t.ks, name, ops::parse_fingerprint(&fp)?)?;
        println!("  pinned {name}");
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
            uac: false,
        }
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
    }

    #[test]
    fn forwarded_args_minimal_when_no_overrides() {
        let o = WizardOpts {
            state_dir: None,
            user: false,
            file_keystore: false,
            service_name: "mwsqld".into(),
            uac: false,
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

    #[test]
    fn unpinned_warning_states_refusal_and_how_to_obtain() {
        let w = unpinned_bastion_warning("db.example.com");
        assert!(w.contains("refused"), "must say connections are refused");
        assert!(
            w.contains("ssh-keyscan db.example.com"),
            "must hint how to obtain the fingerprint for the host"
        );
        assert!(
            w.contains("<algo>:<sha256_b64>"),
            "must state the expected pin format"
        );
    }
}
