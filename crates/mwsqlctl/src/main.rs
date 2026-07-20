use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use mw_core::config::{EngineKind, Policy};
use mw_core::state::{default_state_dir, env_flag, resolve_cli_target};

use mwsqlctl::installer::InstallParams;
use mwsqlctl::ops::{self, Target};
use mwsqlctl::{audit_tail, bastion, cred, envs, init, policy, uninstall, wizard};

#[derive(Parser)]
#[command(name = "mwsqlctl", version, about = "middleWHERE admin CLI")]
struct Cli {
    /// State directory (config.sealed + audit/). Defaults to the system
    /// service dir; `--user` switches to the per-user dir.
    #[arg(long, global = true, env = "MW_STATE_DIR")]
    state_dir: Option<PathBuf>,

    /// Per-user deployment: store under the home dir and use the OS keychain.
    /// Without it, the default targets the system service dir + file keystore.
    /// Also set by MW_USER=1.
    #[arg(long, global = true)]
    user: bool,

    /// Use a file-backed master key instead of the OS keystore. Also set by
    /// MW_FILE_KEYSTORE=1.
    #[arg(long, global = true)]
    file_keystore: bool,

    /// Internal: set on the Windows UAC-relaunched child so it does not
    /// re-elevate and pauses before its console closes.
    #[arg(long, global = true, hide = true)]
    uac: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Install middleWHERE as a managed service: self-elevates, creates the
    /// system account, seeds the sealed config, writes the hardened unit, and
    /// starts it, then offers to configure connections. Pass `--user` to seed a
    /// per-user config instead (no service, no elevation).
    Init(InitArgs),
    /// Remove a deployment (the inverse of `init`): self-elevates, stops and
    /// deletes the service, and wipes the sealed config, master key, and audit
    /// log. Destructive and irreversible — confirms first unless `--yes`. Pass
    /// `--user` to remove the per-user deployment (no service, no elevation).
    Uninstall(UninstallArgs),
    /// Manage bastions.
    #[command(subcommand)]
    Bastion(BastionCmd),
    /// Manage credentials.
    #[command(subcommand)]
    Cred(CredCmd),
    /// Manage envs (the client-facing listeners).
    #[command(subcommand)]
    Env(EnvCmd),
    /// Change an env's policy.
    Policy(PolicyArgs),
    /// Print the last N audit events.
    AuditTail(AuditTailArgs),
    /// Generate the OS service-manager artifact (systemd / launchd /
    /// Windows) plus the privileged operator steps. Never escalates or
    /// creates accounts itself.
    InstallService(InstallServiceArgs),
    /// Rotate an env's token and print everything a client identity needs to
    /// run `mwsql login`. The previous token is invalidated.
    Grant(GrantArgs),
    /// Import an existing `.env` + `secrets/` deployment into the sealed config.
    Import(ImportArgs),
    /// Configure connections (bastions, credentials, envs) on an
    /// already-installed deployment, then restart the service. Run `init`
    /// first. Service mode self-elevates; `--user` configures the per-user
    /// deployment.
    #[command(alias = "setup")]
    Wizard(WizardArgs),
}

#[derive(Args)]
struct InitArgs {
    /// Service name for the generated systemd unit + system account.
    #[arg(long, default_value = "mwsqld")]
    service_name: String,
    /// Path to the mwsqld binary baked into the unit. Defaults to a `mwsqld`
    /// sibling of this executable.
    #[arg(long)]
    exec_path: Option<PathBuf>,
}

#[derive(Args)]
struct WizardArgs {
    /// Service to restart after applying config (service mode).
    #[arg(long, default_value = "mwsqld")]
    service_name: String,
}

#[derive(Args)]
struct UninstallArgs {
    /// Service name to stop and remove (service mode).
    #[arg(long, default_value = "mwsqld")]
    service_name: String,
    /// Skip the "are you sure?" prompt. Required for non-interactive runs.
    #[arg(long, short = 'y')]
    yes: bool,
}

#[derive(Args)]
struct ImportArgs {
    /// Path to a directory containing `.env` and `secrets/`.
    #[arg(long)]
    from_dir: PathBuf,
}

#[derive(Args)]
struct GrantArgs {
    env: String,
    /// Optional label for who this grant is for (audit/readability only;
    /// does not write another user's keyring — that crosses an OS-principal
    /// boundary the client does itself via `mwsql login`).
    #[arg(long)]
    to: Option<String>,
}

#[derive(Args)]
struct InstallServiceArgs {
    /// Service name.
    #[arg(long, default_value = "mwsqld")]
    service_name: String,
    /// Path to the mwsqld binary baked into the unit. Defaults to a
    /// `mwsqld` sibling of this executable.
    #[arg(long)]
    exec_path: Option<PathBuf>,
    /// Write the artifact here instead of printing it. Caller must already
    /// be elevated; this does no escalation.
    #[arg(long)]
    write: Option<PathBuf>,
    /// Overwrite an existing file when used with --write.
    #[arg(long)]
    force: bool,
}

#[derive(Subcommand)]
enum BastionCmd {
    Add(BastionAddArgs),
    Rm { name: String },
    List,
}

#[derive(Args)]
struct BastionAddArgs {
    name: String,
    #[arg(long)]
    host: String,
    #[arg(long, default_value_t = 22)]
    port: u16,
    #[arg(long)]
    ssh_user: String,
    /// Read password from stdin (one line). Otherwise prompt interactively.
    #[arg(long, group = "auth")]
    password_stdin: bool,
    /// Read PEM-encoded private key from this path.
    #[arg(long, group = "auth")]
    key_file: Option<PathBuf>,
    /// Pinned host-key fingerprint in the form `<algo>:<sha256_b64>` (e.g.
    /// `ssh-ed25519:AAAA...`). May be repeated to pin multiple keys.
    #[arg(long = "fingerprint")]
    fingerprints: Vec<String>,
}

#[derive(Subcommand)]
enum CredCmd {
    Add {
        name: String,
        /// Backend database username this credential logs in as. Named
        /// `--db-user` (not `--user`) to avoid the global `--user` deployment
        /// flag.
        #[arg(long = "db-user")]
        db_user: String,
        #[arg(long)]
        password_stdin: bool,
    },
    Rotate {
        name: String,
        #[arg(long)]
        password_stdin: bool,
    },
    Rm {
        name: String,
    },
    List,
}

#[derive(Subcommand)]
enum EnvCmd {
    Add(EnvAddArgs),
    Rm {
        name: String,
    },
    RotateToken {
        name: String,
    },
    List,
    /// Probe an env's live connectivity (bastion + backend connect/auth) and
    /// report. Validates an existing env after the fact; `env add` already
    /// validates on creation.
    Test {
        /// Probe this env. Omit with --all to probe every env.
        name: Option<String>,
        /// Probe every configured env.
        #[arg(long)]
        all: bool,
    },
}

#[derive(Args)]
struct EnvAddArgs {
    name: String,
    #[arg(long)]
    backend_host: String,
    /// Backend port. Defaults to the engine's conventional port
    /// (mysql 3306, postgres 5432, mssql 1433).
    #[arg(long)]
    backend_port: Option<u16>,
    #[arg(long, value_enum, default_value_t = EngineKindArg::Mysql)]
    engine: EngineKindArg,
    #[arg(long)]
    database: Option<String>,
    #[arg(long)]
    bastion: Option<String>,
    #[arg(long)]
    credential: String,
    #[arg(long, value_enum, default_value_t = PolicyKindArg::ReadOnly)]
    policy: PolicyKindArg,
    #[arg(long)]
    listen_port: Option<u16>,
    #[arg(long)]
    max_pool: Option<u32>,
    /// Skip the post-add connectivity probe. By default `env add` validates the
    /// new connection and exits non-zero if it can't reach the backend.
    #[arg(long)]
    no_validate: bool,
}

#[derive(Copy, Clone, ValueEnum)]
enum EngineKindArg {
    Mysql,
    Postgres,
    Mssql,
}

impl From<EngineKindArg> for EngineKind {
    fn from(e: EngineKindArg) -> Self {
        match e {
            EngineKindArg::Mysql => EngineKind::MySql,
            EngineKindArg::Postgres => EngineKind::Postgres,
            EngineKindArg::Mssql => EngineKind::MsSql,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum PolicyKindArg {
    ReadOnly,
    ReadWrite,
}

impl From<PolicyKindArg> for Policy {
    fn from(p: PolicyKindArg) -> Self {
        match p {
            PolicyKindArg::ReadOnly => Policy::ReadOnly,
            PolicyKindArg::ReadWrite => Policy::ReadWrite,
        }
    }
}

#[derive(Args)]
struct PolicyArgs {
    env: String,
    #[arg(long, group = "target")]
    read_only: bool,
    #[arg(long, group = "target")]
    read_write: bool,
    #[arg(long)]
    i_know_what_im_doing: bool,
}

#[derive(Args)]
struct AuditTailArgs {
    #[arg(short = 'n', long, default_value_t = 20)]
    n: usize,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    // The bool flags also honor MW_USER / MW_FILE_KEYSTORE (truthy), which a
    // clap bool + env can't express ("1" wouldn't parse as a bool).
    let user = cli.user || env_flag("MW_USER");
    let file_keystore = cli.file_keystore || env_flag("MW_FILE_KEYSTORE");

    // init and the wizard own their own mode/elevation resolution from the raw
    // flags, so dispatch them before resolving a single Target.
    if let Cmd::Wizard(w) = &cli.cmd {
        return wizard::run(wizard::WizardOpts {
            state_dir: cli.state_dir.clone(),
            user,
            file_keystore,
            service_name: w.service_name.clone(),
            uac: cli.uac,
        });
    }
    if let Cmd::Init(a) = &cli.cmd {
        return init::run(init::InitOpts {
            state_dir: cli.state_dir.clone(),
            user,
            file_keystore,
            service_name: a.service_name.clone(),
            exec_path: a.exec_path.clone(),
            uac: cli.uac,
        });
    }
    if let Cmd::Uninstall(a) = &cli.cmd {
        return uninstall::run(uninstall::UninstallOpts {
            state_dir: cli.state_dir.clone(),
            user,
            file_keystore,
            service_name: a.service_name.clone(),
            yes: a.yes,
            uac: cli.uac,
        });
    }

    // Every remaining command reads/writes the sealed config except
    // install-service (which only renders an artifact from its args). On
    // Windows service mode those would fail against the admin-locked state dir,
    // so wrap them: auto-elevate (relaunch in an admin console) when needed.
    let service = !user;
    let needs_config = !matches!(cli.cmd, Cmd::InstallService(_));
    mwsqlctl::run_elevated_or(service, cli.uac, needs_config, move || {
        let (state_dir, ks) = resolve_cli_target(cli.state_dir.clone(), user, file_keystore);
        let t = Target::new(&state_dir, &ks);

        match cli.cmd {
            Cmd::Wizard(_) | Cmd::Init(_) | Cmd::Uninstall(_) => unreachable!("handled above"),
            Cmd::Bastion(BastionCmd::Add(a)) => {
                let name = a.name.clone();
                ops::add_bastion(
                    t,
                    ops::BastionInput {
                        name: a.name,
                        host: a.host,
                        port: a.port,
                        ssh_user: a.ssh_user,
                        key_file: a.key_file,
                        password_stdin: a.password_stdin,
                        fingerprints: a.fingerprints,
                    },
                )?;
                eprintln!("bastion {name:?} added");
            }
            Cmd::Bastion(BastionCmd::Rm { name }) => {
                bastion::rm(&state_dir, &ks, &name)?;
                eprintln!("bastion {:?} removed", name);
            }
            Cmd::Bastion(BastionCmd::List) => {
                for row in bastion::list(&state_dir, &ks)? {
                    println!(
                        "{}\t{}:{}\tuser={}\tauth={}\tfingerprints={}",
                        row.name,
                        row.host,
                        row.port,
                        row.ssh_user,
                        row.auth_kind,
                        row.pinned_fingerprints
                    );
                }
            }
            Cmd::Cred(CredCmd::Add {
                name,
                db_user,
                password_stdin,
            }) => {
                ops::add_credential(t, &name, &db_user, password_stdin)?;
                eprintln!("credential {name:?} added");
            }
            Cmd::Cred(CredCmd::Rotate {
                name,
                password_stdin,
            }) => {
                ops::rotate_credential(t, &name, password_stdin)?;
                eprintln!("credential {name:?} rotated");
            }
            Cmd::Cred(CredCmd::Rm { name }) => {
                cred::rm(&state_dir, &ks, &name)?;
                eprintln!("credential {:?} removed", name);
            }
            Cmd::Cred(CredCmd::List) => {
                for row in cred::list(&state_dir, &ks)? {
                    println!("{}\tuser={}", row.name, row.backend_user);
                }
            }
            Cmd::Env(EnvCmd::Add(a)) => {
                let name = a.name.clone();
                let no_validate = a.no_validate;
                let out = ops::add_env(
                    t,
                    ops::EnvInput {
                        name: a.name,
                        backend_host: a.backend_host,
                        backend_port: a.backend_port,
                        engine: a.engine.into(),
                        database: a.database,
                        bastion: a.bastion,
                        credential: a.credential,
                        policy: a.policy.into(),
                        listen_port: a.listen_port,
                        max_pool: a.max_pool,
                    },
                )?;
                eprintln!("env {name:?} added.");
                // The token is one-time — always print it, even if validation
                // then fails (the env is kept; the operator fixes and re-tests).
                mwsqlctl::print_token_block(
                    &name,
                    out.listen_port,
                    out.token.expose(),
                    out.engine,
                    out.database.as_deref(),
                );
                if !no_validate {
                    use mwsqlctl::probe::Validation;
                    match mwsqlctl::probe::validate(&state_dir, &ks, Some(&name)) {
                        Validation::Ok => eprintln!("✓ connected."),
                        Validation::Skipped(note) => eprintln!("validation skipped: {note}"),
                        Validation::Failed(reason) => {
                            // Keep the env; exit non-zero so CI/scripts notice.
                            bail!("env {name:?} added but could not connect: {reason}");
                        }
                    }
                }
            }
            Cmd::Env(EnvCmd::Rm { name }) => {
                envs::rm(&state_dir, &ks, &name)?;
                eprintln!("env {:?} removed", name);
            }
            Cmd::Env(EnvCmd::RotateToken { name }) => {
                let token = envs::rotate_token(&state_dir, &ks, &name)?;
                eprintln!("env {:?} token rotated. New token (save now):", name);
                println!("{}", token.expose());
            }
            Cmd::Env(EnvCmd::List) => {
                for row in envs::list(&state_dir, &ks)? {
                    println!(
                        "{}\t{}\tengine={}\tbastion={}\tcred={}\tpolicy={}\tport={}",
                        row.name,
                        row.backend,
                        row.engine,
                        row.bastion.as_deref().unwrap_or("-"),
                        row.credential,
                        row.policy,
                        row.listen_port
                    );
                }
            }
            Cmd::Env(EnvCmd::Test { name, all }) => {
                use mwsqlctl::probe::Validation;
                let target = match (&name, all) {
                    (Some(_), false) => name.as_deref(),
                    (None, true) => None,
                    (None, false) => bail!("specify an env name or --all"),
                    (Some(_), true) => bail!("specify an env name or --all, not both"),
                };
                match mwsqlctl::probe::validate(&state_dir, &ks, target) {
                    Validation::Ok => {
                        eprintln!("✓ {} connected.", name.as_deref().unwrap_or("all envs"))
                    }
                    Validation::Skipped(note) => eprintln!("validation skipped: {note}"),
                    Validation::Failed(reason) => bail!("connection failed: {reason}"),
                }
            }
            Cmd::Policy(p) => {
                let target = match (p.read_only, p.read_write) {
                    (true, false) => policy::PolicyTarget::ReadOnly,
                    (false, true) => policy::PolicyTarget::ReadWrite,
                    _ => bail!("specify exactly one of --read-only / --read-write"),
                };
                policy::set(&state_dir, &ks, &p.env, target, p.i_know_what_im_doing)?;
                eprintln!("env {:?} policy updated", p.env);
            }
            Cmd::AuditTail(a) => {
                for line in audit_tail::tail(&state_dir, a.n)? {
                    println!("{line}");
                }
            }
            Cmd::InstallService(a) => {
                // A generated service unit runs as a dedicated account, so it
                // always targets the system state dir regardless of --user. An
                // explicit --state-dir still wins. This command keeps the
                // DynamicUser unit; the wizard generates the fixed-user variant.
                let svc_state_dir = cli.state_dir.clone().unwrap_or_else(default_state_dir);
                let exec_path = match a.exec_path {
                    Some(p) => p,
                    None => ops::default_daemon_path()?,
                };
                let params = InstallParams::new(
                    &a.service_name,
                    exec_path.to_string_lossy().to_string(),
                    svc_state_dir.to_string_lossy().to_string(),
                );
                let art = ops::build_service_artifact(&params, false)?;
                if let Some(path) = a.write {
                    ops::write_service_artifact(&path, &art.artifact, a.force)?;
                    eprintln!("wrote {}", path.display());
                    eprintln!(
                        "\nNext steps (run with the privileges they require):\n{}",
                        art.steps
                    );
                } else {
                    print!("{}", art.artifact);
                    eprintln!("\n# ---- operator steps ----\n{}", art.steps);
                }
            }
            Cmd::Grant(g) => {
                let out = ops::grant(t, &g.env)?;
                if let Some(to) = &g.to {
                    eprintln!(
                        "granted env {:?} to {to} (token rotated; any prior token is now dead)",
                        g.env
                    );
                } else {
                    eprintln!("env {:?} token rotated; any prior token is now dead", g.env);
                }
                eprintln!("Deliver the token below to that identity over a secure channel.");
                mwsqlctl::print_token_block(
                    &g.env,
                    out.listen_port,
                    out.token.expose(),
                    out.engine,
                    out.database.as_deref(),
                );
            }
            Cmd::Import(i) => {
                let report = mwsqlctl::import_poc::import(&state_dir, &ks, &i.from_dir)?;
                eprintln!(
                    "imported {} bastion(s), {} credential(s), {} env(s):",
                    report.bastions.len(),
                    report.credentials.len(),
                    report.envs.len()
                );
                for (name, port) in &report.envs {
                    eprintln!("  env {name} -> 127.0.0.1:{port}");
                }
                if !report.warnings.is_empty() {
                    eprintln!("\nwarnings:");
                    for w in &report.warnings {
                        eprintln!("  ! {w}");
                    }
                }
                eprintln!("\n{}", mwsqlctl::import_poc::decommission_checklist());
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // Serializes tests that set process-global env so they never race.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    // Catches arg-definition conflicts (e.g. a subcommand flag colliding with a
    // global one) at test time instead of panicking at runtime on parse.
    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    // Regression: the global `--user` deployment flag (bool) must not collide
    // with `cred add`'s backend-user flag (String) — that paniced with a clap
    // downcast error. The latter is `--db-user`.
    #[test]
    fn cred_add_db_user_parses_without_global_user_collision() {
        let cli =
            Cli::try_parse_from(["mwsqlctl", "cred", "add", "local", "--db-user", "root"]).unwrap();
        assert!(!cli.user, "global --user must default off here");
        match cli.cmd {
            Cmd::Cred(CredCmd::Add { name, db_user, .. }) => {
                assert_eq!(name, "local");
                assert_eq!(db_user, "root");
            }
            _ => panic!("expected cred add"),
        }
    }

    #[test]
    fn uninstall_parses_yes_and_defaults_service_name() {
        let cli = Cli::try_parse_from(["mwsqlctl", "uninstall", "--yes"]).unwrap();
        match cli.cmd {
            Cmd::Uninstall(a) => {
                assert!(a.yes, "--yes must set yes");
                assert_eq!(a.service_name, "mwsqld");
            }
            _ => panic!("expected uninstall"),
        }
        // Short form and a custom service name also parse.
        let cli =
            Cli::try_parse_from(["mwsqlctl", "uninstall", "-y", "--service-name", "mw2"]).unwrap();
        match cli.cmd {
            Cmd::Uninstall(a) => {
                assert!(a.yes);
                assert_eq!(a.service_name, "mw2");
            }
            _ => panic!("expected uninstall"),
        }
    }

    #[test]
    fn env_supplies_state_dir_and_truthy_file_keystore() {
        let _g = env_lock();
        let prev_sd = std::env::var_os("MW_STATE_DIR");
        let prev_fk = std::env::var_os("MW_FILE_KEYSTORE");
        std::env::set_var("MW_STATE_DIR", "/tmp/mw-env-test");
        std::env::set_var("MW_FILE_KEYSTORE", "1");

        // MW_STATE_DIR flows through clap's `env` on the value arg.
        let cli = Cli::try_parse_from(["mwsqlctl", "init"]).unwrap();
        // MW_FILE_KEYSTORE="1" is OR'd in via env_flag (a clap bool+env would
        // reject "1"); the effective flag is what main computes.
        let file_keystore = cli.file_keystore || env_flag("MW_FILE_KEYSTORE");

        let restore = |k: &str, v: Option<std::ffi::OsString>| match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        };
        restore("MW_STATE_DIR", prev_sd);
        restore("MW_FILE_KEYSTORE", prev_fk);

        assert_eq!(
            cli.state_dir.as_deref(),
            Some(std::path::Path::new("/tmp/mw-env-test"))
        );
        assert!(
            file_keystore,
            "MW_FILE_KEYSTORE=1 must enable the file keystore"
        );
    }

    #[test]
    fn defaults_are_service_first_when_no_flags() {
        let _g = env_lock();
        // Clear env that could leak in from the host/CI.
        let prev_sd = std::env::var_os("MW_STATE_DIR");
        let prev_fk = std::env::var_os("MW_FILE_KEYSTORE");
        let prev_u = std::env::var_os("MW_USER");
        std::env::remove_var("MW_STATE_DIR");
        std::env::remove_var("MW_FILE_KEYSTORE");
        std::env::remove_var("MW_USER");

        let cli = Cli::try_parse_from(["mwsqlctl", "init"]).unwrap();

        let restore = |k: &str, v: Option<std::ffi::OsString>| match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        };
        restore("MW_STATE_DIR", prev_sd);
        restore("MW_FILE_KEYSTORE", prev_fk);
        restore("MW_USER", prev_u);

        assert!(cli.state_dir.is_none());
        assert!(!cli.user);
        let (dir, ks) = resolve_cli_target(cli.state_dir, cli.user, cli.file_keystore);
        assert_eq!(
            dir,
            default_state_dir(),
            "flagless default must be the service dir"
        );
        assert!(
            matches!(ks, mw_core::state::KeystoreChoice::File { .. }),
            "service-mode keystore must be file-backed"
        );
    }
}
