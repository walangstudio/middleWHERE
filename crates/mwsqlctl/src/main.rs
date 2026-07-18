use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use mw_core::config::{EngineKind, Policy};
use mw_core::control::{CredInputDto, NewEnvOutputDto, Request, Response};
use mw_core::secret::SecretStr;
use mw_core::state::{default_state_dir, env_flag, resolve_cli_target};

use mwsqlctl::installer::InstallParams;
use mwsqlctl::ops::{self, Target};
use mwsqlctl::{audit_tail, bastion, control_client, cred, envs, init, policy, uninstall, wizard};

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

    /// Edit the sealed config file directly instead of asking the running
    /// service. Against the system deployment this needs an already-elevated
    /// process (root / Administrator); the default talks to the service and
    /// needs no elevation. `--user` deployments are always direct.
    #[arg(long, global = true)]
    offline: bool,

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
    /// already-installed deployment. Run `init` first. Service mode talks to the
    /// running service over its control channel (no elevation, changes applied
    /// live); `--user` configures the per-user deployment directly.
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
    /// Also delete the append-only audit log. Off by default: uninstall
    /// preserves `<state_dir>/audit` for compliance / forensics.
    #[arg(long)]
    purge_audit: bool,
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
    /// `ssh-ed25519:AAAA...`). One pin per bastion.
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
            purge_audit: a.purge_audit,
            uac: cli.uac,
        });
    }
    // install-service only renders an artifact from its args (it never reads the
    // sealed config), so it's dispatched directly, no mode/privilege gate.
    if let Cmd::InstallService(a) = &cli.cmd {
        return run_install_service(a, cli.state_dir.clone());
    }

    // Every remaining command reads/writes the sealed config. In service mode we
    // ask the running daemon over the control channel (no elevation); `--user`
    // and `--offline` edit the config file in-process. `--offline` against the
    // root/service-owned system dir needs an already-privileged process — the CLI
    // no longer auto-elevates for config.
    let (state_dir, ks) = resolve_cli_target(cli.state_dir.clone(), user, file_keystore);
    let target_needs_root = state_dir == default_state_dir();
    if !control_client::offline_privilege_ok(
        cli.offline,
        target_needs_root,
        mwsqlctl::is_privileged(),
    ) {
        if cfg!(windows) {
            bail!(
                "--offline edits the root/service-owned sealed config directly, which \
                 needs Administrator. Re-run `mwsqlctl --offline …` from an elevated \
                 terminal, or drop --offline to use the running service."
            );
        }
        bail!(
            "--offline edits the root/service-owned sealed config directly, which needs \
             root. Re-run under `sudo mwsqlctl --offline …`, or drop --offline to use \
             the running service."
        );
    }
    // Only a flagless command targeting the system service dir talks to the
    // running daemon over the control channel. An explicit `--state-dir`, a
    // legacy per-user resolution, `--user`, or `--offline` edit a config file
    // directly — the channel always mutates the daemon's own loaded config, so
    // routing an explicit `--state-dir` there would silently hit the wrong one.
    let use_channel =
        control_client::decide_mode(user, cli.offline, cli.state_dir.as_deref(), &state_dir)
            == control_client::Mode::Channel;

    // Guard the Direct write path against a running daemon. A non-`--user` Direct
    // config MUTATION (`--offline`, or an explicit `--state-dir` routed to Direct)
    // edits the sealed config file the service owns: the daemon keeps serving the
    // old config (no live apply) and, with no cross-process lock, a concurrent
    // channel write can be lost. Refuse when the service is reachable; reads and
    // `--user` (the per-user dir the daemon never owns) stay allowed. Only probe
    // when it could matter, so reads never pay for a connect.
    if !use_channel {
        let is_mutation = cmd_is_mutation(&cli.cmd);
        let reachable = is_mutation && !user && control_client::is_reachable(&state_dir);
        if !control_client::direct_mutation_ok(user, is_mutation, reachable) {
            bail!(
                "the middleWHERE service is running and owns its config; drop \
                 --state-dir/--offline to configure it over the service, or stop \
                 the service first to edit a config file directly."
            );
        }
    }
    let t = Target::new(&state_dir, &ks);

    match cli.cmd {
        Cmd::Wizard(_) | Cmd::Init(_) | Cmd::Uninstall(_) | Cmd::InstallService(_) => {
            unreachable!("handled above")
        }
        Cmd::Bastion(BastionCmd::Add(a)) => {
            let name = a.name.clone();
            let input = ops::BastionInput {
                name: a.name,
                host: a.host,
                port: a.port,
                ssh_user: a.ssh_user,
                key_file: a.key_file,
                password_stdin: a.password_stdin,
                fingerprints: a.fingerprints,
            };
            if use_channel {
                // Resolve the secret locally, then send only the sealed DTO.
                let auth = ops::resolve_bastion_auth(&input)?;
                let dto = control_client::bastion_dto(&input, auth)?;
                expect_ok(&state_dir, Request::AddBastion(dto))?;
            } else {
                ops::add_bastion(t, input)?;
            }
            eprintln!("bastion {name:?} added");
        }
        Cmd::Bastion(BastionCmd::Rm { name }) => {
            if use_channel {
                expect_ok(&state_dir, Request::RmBastion { name: name.clone() })?;
            } else {
                bastion::rm(&state_dir, &ks, &name)?;
            }
            eprintln!("bastion {:?} removed", name);
        }
        Cmd::Bastion(BastionCmd::List) => {
            if use_channel {
                for row in control_client::rows(&state_dir, &Request::ListBastions)? {
                    println!("{row}");
                }
            } else {
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
        }
        Cmd::Cred(CredCmd::Add {
            name,
            db_user,
            password_stdin,
        }) => {
            if use_channel {
                let pw = ops::read_secret("backend password: ", password_stdin)?;
                expect_ok(
                    &state_dir,
                    Request::AddCred(CredInputDto {
                        name: name.clone(),
                        backend_user: db_user,
                        password: SecretStr::new(pw),
                    }),
                )?;
            } else {
                ops::add_credential(t, &name, &db_user, password_stdin)?;
            }
            eprintln!("credential {name:?} added");
        }
        Cmd::Cred(CredCmd::Rotate {
            name,
            password_stdin,
        }) => {
            if use_channel {
                let pw = ops::read_secret("new backend password: ", password_stdin)?;
                expect_ok(
                    &state_dir,
                    Request::RotateCred {
                        name: name.clone(),
                        password: SecretStr::new(pw),
                    },
                )?;
            } else {
                ops::rotate_credential(t, &name, password_stdin)?;
            }
            eprintln!("credential {name:?} rotated");
        }
        Cmd::Cred(CredCmd::Rm { name }) => {
            if use_channel {
                expect_ok(&state_dir, Request::RmCred { name: name.clone() })?;
            } else {
                cred::rm(&state_dir, &ks, &name)?;
            }
            eprintln!("credential {:?} removed", name);
        }
        Cmd::Cred(CredCmd::List) => {
            if use_channel {
                for row in control_client::rows(&state_dir, &Request::ListCreds)? {
                    println!("{row}");
                }
            } else {
                for row in cred::list(&state_dir, &ks)? {
                    println!("{}\tuser={}", row.name, row.backend_user);
                }
            }
        }
        Cmd::Env(EnvCmd::Add(a)) => {
            let name = a.name.clone();
            let no_validate = a.no_validate;
            let input = ops::EnvInput {
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
            };
            let out: NewEnvOutputDto = if use_channel {
                let dto = control_client::env_dto(&input);
                expect_token(&state_dir, Request::AddEnv(dto))?
            } else {
                ops::add_env(t, input)?.into()
            };
            eprintln!("env {name:?} added.");
            // The token is one-time — always print it, even if validation then
            // fails (the env is kept; the operator fixes and re-tests). A
            // persisted-but-not-live note (online apply failure) is surfaced too.
            mwsqlctl::render_new_env(&name, &out);
            if !no_validate {
                validate_after_add(use_channel, &state_dir, &ks, &name)?;
            }
        }
        Cmd::Env(EnvCmd::Rm { name }) => {
            if use_channel {
                expect_ok(&state_dir, Request::RmEnv { name: name.clone() })?;
            } else {
                envs::rm(&state_dir, &ks, &name)?;
            }
            eprintln!("env {:?} removed", name);
        }
        Cmd::Env(EnvCmd::RotateToken { name }) => {
            // rotate-token IS grant; take the full DTO from both paths so the
            // daemon's persisted-but-not-live note reaches the operator.
            let out: NewEnvOutputDto = if use_channel {
                expect_token(&state_dir, Request::Grant { env: name.clone() })?
            } else {
                ops::grant(t, &name)?.into()
            };
            eprintln!("env {:?} token rotated. New token (save now):", name);
            println!("{}", out.token.expose());
            mwsqlctl::render_token_note(&out.note);
        }
        Cmd::Env(EnvCmd::List) => {
            if use_channel {
                for row in control_client::rows(&state_dir, &Request::ListEnvs)? {
                    println!("{row}");
                }
            } else {
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
        }
        Cmd::Env(EnvCmd::Test { name, all }) => {
            let target = match (&name, all) {
                (Some(_), false) => name.as_deref(),
                (None, true) => None,
                (None, false) => bail!("specify an env name or --all"),
                (Some(_), true) => bail!("specify an env name or --all, not both"),
            };
            if use_channel {
                match control_client::checked_call(
                    &state_dir,
                    &Request::Probe {
                        env: target.map(|s| s.to_string()),
                        all,
                    },
                )? {
                    Response::ProbeResults(rs) => control_client::render_probe_results(&rs)?,
                    other => bail!("unexpected response from the service: {other:?}"),
                }
            } else {
                use mwsqlctl::probe::Validation;
                match mwsqlctl::probe::validate(&state_dir, &ks, target) {
                    Validation::Ok => {
                        eprintln!("✓ {} connected.", name.as_deref().unwrap_or("all envs"))
                    }
                    Validation::Skipped(note) => eprintln!("validation skipped: {note}"),
                    Validation::Failed(reason) => bail!("connection failed: {reason}"),
                }
            }
        }
        Cmd::Policy(p) => {
            let target = control_client::policy_target(p.read_only, p.read_write)?;
            if use_channel {
                expect_ok(
                    &state_dir,
                    Request::SetPolicy {
                        env: p.env.clone(),
                        target,
                        confirm_unsafe: p.i_know_what_im_doing,
                    },
                )?;
            } else {
                policy::set(&state_dir, &ks, &p.env, target, p.i_know_what_im_doing)?;
            }
            eprintln!("env {:?} policy updated", p.env);
        }
        Cmd::AuditTail(a) => {
            let lines = if use_channel {
                match control_client::checked_call(&state_dir, &Request::AuditTail { n: a.n })? {
                    Response::AuditLines(v) => v,
                    other => bail!("unexpected response from the service: {other:?}"),
                }
            } else {
                audit_tail::tail(&state_dir, a.n)?
            };
            for line in lines {
                println!("{line}");
            }
        }
        Cmd::Grant(g) => {
            let out: NewEnvOutputDto = if use_channel {
                expect_token(&state_dir, Request::Grant { env: g.env.clone() })?
            } else {
                ops::grant(t, &g.env)?.into()
            };
            if let Some(to) = &g.to {
                eprintln!(
                    "granted env {:?} to {to} (token rotated; any prior token is now dead)",
                    g.env
                );
            } else {
                eprintln!("env {:?} token rotated; any prior token is now dead", g.env);
            }
            eprintln!("Deliver the token below to that identity over a secure channel.");
            mwsqlctl::render_new_env(&g.env, &out);
        }
        Cmd::Import(i) => {
            let report = if use_channel {
                // Parse the legacy source locally; the daemon merges the fragment.
                let (fragment, report) = mwsqlctl::import_poc::build_from_dir(&i.from_dir)?;
                expect_ok(&state_dir, Request::Import(Box::new(fragment)))?;
                report
            } else {
                mwsqlctl::import_poc::import(&state_dir, &ks, &i.from_dir)?
            };
            print_import_report(&report);
        }
    }
    Ok(())
}

/// Whether a command mutates the sealed config (vs a read-only listing/probe).
/// Drives the "don't Direct-edit a running service's config" guard: only
/// mutations can cause the lost-update race, so reads stay allowed in Direct
/// mode. Wizard/Init/Uninstall/InstallService are dispatched before the guard
/// and classified as non-mutating so they never trip it; a newly added command
/// defaults to a mutation (the safe side of the guard).
fn cmd_is_mutation(cmd: &Cmd) -> bool {
    match cmd {
        Cmd::Bastion(BastionCmd::List)
        | Cmd::Cred(CredCmd::List)
        | Cmd::Env(EnvCmd::List)
        | Cmd::Env(EnvCmd::Test { .. })
        | Cmd::AuditTail(_)
        | Cmd::Wizard(_)
        | Cmd::Init(_)
        | Cmd::Uninstall(_)
        | Cmd::InstallService(_) => false,
        Cmd::Bastion(_)
        | Cmd::Cred(_)
        | Cmd::Env(_)
        | Cmd::Policy(_)
        | Cmd::Grant(_)
        | Cmd::Import(_) => true,
    }
}

/// Send a request that must return [`Response::Ok`], surfacing any other reply
/// as an error. Wraps the not-reachable case in the "start the service" hint.
fn expect_ok(state_dir: &Path, req: Request) -> Result<()> {
    match control_client::checked_call(state_dir, &req)? {
        Response::Ok => Ok(()),
        other => bail!("unexpected response from the service: {other:?}"),
    }
}

/// Send a request that must return a [`Response::Token`] (env add / grant).
fn expect_token(state_dir: &Path, req: Request) -> Result<NewEnvOutputDto> {
    match control_client::checked_call(state_dir, &req)? {
        Response::Token(dto) => Ok(dto),
        other => bail!("unexpected response from the service: {other:?}"),
    }
}

/// Post-`env add` connectivity check. Service mode probes through the daemon;
/// direct mode shells out to `mwsqld test`. Both keep the env on failure and
/// exit non-zero so CI/scripts notice.
fn validate_after_add(
    use_channel: bool,
    state_dir: &Path,
    ks: &mw_core::state::KeystoreChoice,
    name: &str,
) -> Result<()> {
    if use_channel {
        match control_client::checked_call(
            state_dir,
            &Request::Probe {
                env: Some(name.to_string()),
                all: false,
            },
        )? {
            Response::ProbeResults(rs) => control_client::render_probe_results(&rs)
                .map_err(|e| anyhow!("env {name:?} added but could not connect: {e}"))?,
            other => bail!("unexpected response from the service: {other:?}"),
        }
    } else {
        use mwsqlctl::probe::Validation;
        match mwsqlctl::probe::validate(state_dir, ks, Some(name)) {
            Validation::Ok => eprintln!("✓ connected."),
            Validation::Skipped(note) => eprintln!("validation skipped: {note}"),
            Validation::Failed(reason) => {
                bail!("env {name:?} added but could not connect: {reason}")
            }
        }
    }
    Ok(())
}

/// Render an import report — the same output whether the merge happened
/// in-process (`--user`/`--offline`) or through the daemon.
fn print_import_report(report: &mwsqlctl::import_poc::ImportReport) {
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

/// Render the service artifact for the current platform from `install-service`'s
/// args. Never reads config or elevates; the caller applies the printed steps.
fn run_install_service(a: &InstallServiceArgs, state_dir: Option<PathBuf>) -> Result<()> {
    // A generated service unit runs as a dedicated account, so it always targets
    // the system state dir regardless of --user. An explicit --state-dir still
    // wins. This keeps the DynamicUser unit; the wizard generates the fixed-user
    // variant.
    let svc_state_dir = state_dir.unwrap_or_else(default_state_dir);
    let exec_path = match a.exec_path.clone() {
        Some(p) => p,
        None => ops::default_daemon_path()?,
    };
    let params = InstallParams::new(
        &a.service_name,
        exec_path.to_string_lossy().to_string(),
        svc_state_dir.to_string_lossy().to_string(),
    );
    let art = ops::build_service_artifact(&params, false)?;
    if let Some(path) = a.write.clone() {
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
    Ok(())
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
                assert!(!a.purge_audit, "audit is preserved unless --purge-audit");
            }
            _ => panic!("expected uninstall"),
        }
        let cli = Cli::try_parse_from(["mwsqlctl", "uninstall", "-y", "--purge-audit"]).unwrap();
        match cli.cmd {
            Cmd::Uninstall(a) => assert!(a.purge_audit, "--purge-audit must set purge_audit"),
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
