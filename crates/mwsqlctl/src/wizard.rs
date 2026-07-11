//! Guided connection configuration (`mwsqlctl wizard` / `setup`).
//!
//! The wizard configures an **already-installed** deployment: it adds bastions,
//! credentials, and envs (secrets prompted in-process, never on argv or disk in
//! cleartext). Installing the service itself (the system account, the unit,
//! `enable --now`) is `mwsqlctl init`'s job — run that first.
//!
//! In service mode the wizard talks to the running daemon over the control
//! channel: it needs no elevation, and each change is applied live by the
//! privileged daemon (no file write + restart). `--user` configures the
//! per-user deployment directly against the sealed config file.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use mw_core::config::{EngineKind, HostKeyFingerprint, Policy};
use mw_core::control::{CredInputDto, Request, Response};
use mw_core::secret::SecretStr;
use mw_core::state::resolve_cli_target;

use crate::ops::{self, Target};
use crate::prompt::{
    confirm, prompt_optional_port, prompt_optional_text, prompt_port, prompt_text, select_index,
    select_owned,
};
use crate::{bastion, control_client, cred, envs, service};

/// The raw flags the wizard resolves its mode from.
pub struct WizardOpts {
    pub state_dir: Option<PathBuf>,
    pub user: bool,
    pub file_keystore: bool,
    /// Which service this configures (cosmetic in channel mode — the control
    /// socket is keyed on the fixed daemon name).
    pub service_name: String,
}

/// Where the wizard applies config: the running daemon over the control channel
/// (service mode), or the sealed config file in-process (`--user`).
enum Backend<'a> {
    Direct(Target<'a>),
    Channel(&'a Path),
}

impl Backend<'_> {
    fn bastion_infos(&self) -> Result<Vec<control_client::BastionInfo>> {
        match self {
            Backend::Direct(t) => Ok(bastion::list(t.state_dir, t.ks)?
                .into_iter()
                .map(|b| control_client::BastionInfo {
                    name: b.name,
                    host: b.host,
                    pinned: b.pinned_fingerprints,
                })
                .collect()),
            Backend::Channel(sd) => Ok(control_client::rows(sd, &Request::ListBastions)?
                .iter()
                .filter_map(|r| control_client::parse_bastion_row(r))
                .collect()),
        }
    }

    fn cred_names(&self) -> Result<Vec<String>> {
        match self {
            Backend::Direct(t) => Ok(cred::list(t.state_dir, t.ks)?
                .into_iter()
                .map(|c| c.name)
                .collect()),
            Backend::Channel(sd) => Ok(control_client::rows(sd, &Request::ListCreds)?
                .iter()
                .filter_map(|r| control_client::parse_cred_name(r))
                .collect()),
        }
    }

    fn add_bastion(&self, input: ops::BastionInput) -> Result<()> {
        match self {
            Backend::Direct(t) => ops::add_bastion(*t, input),
            Backend::Channel(sd) => {
                let auth = ops::resolve_bastion_auth(&input)?;
                let dto = control_client::bastion_dto(&input, auth)?;
                control_client::checked_call(sd, &Request::AddBastion(dto)).map(|_| ())
            }
        }
    }

    fn add_credential(&self, name: &str, user: &str) -> Result<()> {
        match self {
            Backend::Direct(t) => ops::add_credential(*t, name, user, false),
            Backend::Channel(sd) => {
                let pw = ops::read_secret("backend password: ", false)?;
                control_client::checked_call(
                    sd,
                    &Request::AddCred(CredInputDto {
                        name: name.to_string(),
                        backend_user: user.to_string(),
                        password: SecretStr::new(pw),
                    }),
                )
                .map(|_| ())
            }
        }
    }

    fn add_env(&self, input: ops::EnvInput) -> Result<envs::NewEnvOutput> {
        match self {
            Backend::Direct(t) => ops::add_env(*t, input),
            Backend::Channel(sd) => {
                let dto = control_client::env_dto(&input);
                match control_client::checked_call(sd, &Request::AddEnv(dto))? {
                    Response::Token(d) => Ok(envs::NewEnvOutput {
                        token: d.token,
                        listen_port: d.listen_port,
                        engine: d.engine,
                        database: d.database,
                    }),
                    other => bail!("unexpected response from the service: {other:?}"),
                }
            }
        }
    }

    fn rm_env(&self, name: &str) -> Result<()> {
        match self {
            Backend::Direct(t) => envs::rm(t.state_dir, t.ks, name),
            Backend::Channel(sd) => control_client::checked_call(
                sd,
                &Request::RmEnv {
                    name: name.to_string(),
                },
            )
            .map(|_| ()),
        }
    }

    fn set_fingerprint(&self, name: &str, fp: HostKeyFingerprint) -> Result<()> {
        match self {
            Backend::Direct(t) => bastion::set_fingerprint(t.state_dir, t.ks, name, fp),
            Backend::Channel(sd) => control_client::checked_call(
                sd,
                &Request::SetFingerprint {
                    bastion: name.to_string(),
                    fingerprint: fp,
                },
            )
            .map(|_| ()),
        }
    }

    fn validate(&self, env: &str) -> crate::probe::Validation {
        use crate::probe::Validation;
        match self {
            Backend::Direct(t) => crate::probe::validate(t.state_dir, t.ks, Some(env)),
            Backend::Channel(sd) => {
                match control_client::checked_call(
                    sd,
                    &Request::Probe {
                        env: Some(env.to_string()),
                        all: false,
                    },
                ) {
                    Ok(Response::ProbeResults(rs)) => match rs.into_iter().next() {
                        Some(r) if r.ok => Validation::Ok,
                        Some(r) if !r.supported => Validation::Skipped(r.reason),
                        Some(r) => Validation::Failed(if r.reason.is_empty() {
                            "connection failed".to_string()
                        } else {
                            r.reason
                        }),
                        None => Validation::Skipped("no environments configured".to_string()),
                    },
                    Ok(_) => {
                        Validation::Skipped("unexpected response from the service".to_string())
                    }
                    Err(e) => Validation::Skipped(format!("probe could not run: {e}")),
                }
            }
        }
    }

    fn show_current(&self) -> Result<()> {
        match self {
            Backend::Direct(t) => show_current_direct(*t),
            Backend::Channel(sd) => {
                let bastions = control_client::rows(sd, &Request::ListBastions)?;
                let creds = control_client::rows(sd, &Request::ListCreds)?;
                let envs = control_client::rows(sd, &Request::ListEnvs)?;
                println!("  bastions ({}):", bastions.len());
                for b in &bastions {
                    println!("    {b}");
                }
                println!("  credentials ({}):", creds.len());
                for c in &creds {
                    println!("    {c}");
                }
                println!("  envs ({}):", envs.len());
                for e in &envs {
                    println!("    {e}");
                }
                Ok(())
            }
        }
    }
}

pub fn run(opts: WizardOpts) -> Result<()> {
    run_inner(opts)
}

fn run_inner(opts: WizardOpts) -> Result<()> {
    let service = !opts.user;

    // Interactive-only. Fail before doing anything when there's no terminal.
    if !std::io::stdin().is_terminal() {
        bail!(
            "the wizard is interactive and needs a terminal. Run it in a TTY, \
             or configure with the individual `mwsqlctl` commands."
        );
    }
    if service {
        service::validate_service_name(&opts.service_name)?;
    }

    let (state_dir, ks) = resolve_cli_target(opts.state_dir.clone(), opts.user, opts.file_keystore);
    let backend = if service {
        Backend::Channel(&state_dir)
    } else {
        Backend::Direct(Target::new(&state_dir, &ks))
    };

    // Confirm the deployment is usable before prompting. Direct mode checks the
    // sealed config exists; channel mode probes the daemon — a running daemon has
    // already loaded its config, so reachability doubles as the initialized check.
    match &backend {
        Backend::Direct(t) => {
            if !ops::is_initialized(t.state_dir) {
                bail!(
                    "no config at {} — run `mwsqlctl --user init` first",
                    state_dir.display()
                );
            }
        }
        Backend::Channel(sd) => {
            control_client::checked_call(sd, &Request::ListEnvs)
                .context("configuring needs the running service (run `mwsqlctl init` first)")?;
        }
    }

    intro(service, &state_dir);

    // Re-run menu: this is always an existing config (init seeded it).
    if existing_config_action(&backend)? == Existing::Quit {
        return Ok(());
    }

    let changed = run_config_backend(&backend)?;

    if service {
        // The daemon applied each change live; nothing to chown or restart.
        if changed {
            println!("\nChanges applied to the running service.");
        }
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

/// After config is written as root in service mode: hand the new files back to
/// the service account and restart so the daemon binds the new listeners. Only
/// used by `init`'s already-elevated "configure now" path — the standalone
/// wizard applies changes live over the control channel and never lands here.
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

fn existing_config_action(backend: &Backend) -> Result<Existing> {
    loop {
        match select_index("What now?", &["Add more", "Show current", "Quit"])? {
            1 => backend.show_current()?,
            2 => return Ok(Existing::Quit),
            _ => return Ok(Existing::AddMore),
        }
    }
}

fn show_current_direct(t: Target) -> Result<()> {
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

/// The interactive add-bastions/credentials/envs flow. Assumes the deployment is
/// already initialized. Returns whether anything was added. Called both by the
/// standalone `wizard` (over whichever backend) and inline by `init`'s
/// "configure now" prompt (direct, already elevated).
pub(crate) fn run_config(t: Target) -> Result<bool> {
    run_config_backend(&Backend::Direct(t))
}

fn run_config_backend(b: &Backend) -> Result<bool> {
    let bastions = add_bastions_loop(b)?;
    let creds = add_credentials_loop(b)?;
    let envs = add_envs_loop(b)?;
    Ok(bastions || creds || envs)
}

fn add_bastions_loop(b: &Backend) -> Result<bool> {
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
        match b.add_bastion(ops::BastionInput {
            name: name.clone(),
            host,
            port,
            ssh_user,
            key_file,
            password_stdin: false,
            fingerprints,
        }) {
            Ok(()) => {
                println!("  added bastion {name}");
                added = true;
            }
            Err(e) => eprintln!("  ! {e}"),
        }
    }
    Ok(added)
}

fn add_credentials_loop(b: &Backend) -> Result<bool> {
    let mut added = false;
    while confirm("Add a credential?", true)? {
        let name = prompt_text("Credential name:")?;
        let user = prompt_text("Backend DB user:")?;
        match b.add_credential(&name, &user) {
            Ok(()) => {
                println!("  added credential {name}");
                added = true;
            }
            Err(e) => eprintln!("  ! {e}"),
        }
    }
    Ok(added)
}

fn add_envs_loop(b: &Backend) -> Result<bool> {
    let mut added = false;
    // The cred/bastion name lists don't change inside this loop (only envs are
    // added here), so fetch once up front instead of per iteration.
    let creds = b.cred_names()?;
    let bastions: Vec<String> = b.bastion_infos()?.into_iter().map(|i| i.name).collect();
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
            let out = match b.add_env(pending) {
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
            match b.validate(&name) {
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
                            b.rm_env(&name)?;
                            pending = prompt_env_input(&creds, bastions.clone())?;
                            ensure_bastion_pinned(b, pending.bastion.as_deref())?;
                            continue;
                        }
                        _ => {
                            b.rm_env(&name)?;
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
fn ensure_bastion_pinned(b: &Backend, bastion: Option<&str>) -> Result<()> {
    let Some(name) = bastion else { return Ok(()) };
    let Some(info) = b.bastion_infos()?.into_iter().find(|i| i.name == name) else {
        return Ok(());
    };
    if info.pinned > 0 {
        return Ok(());
    }
    println!("{}", unpinned_bastion_warning(&info.host));
    if let Some(fp) = prompt_optional_text("  Pin it now as <algo>:<sha256_b64> (blank to skip):")?
    {
        b.set_fingerprint(name, ops::parse_fingerprint(&fp)?)?;
        println!("  pinned {name}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
