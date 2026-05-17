use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use mw_core::config::{EngineKind, HostKeyFingerprint, Policy};
use mw_core::secret::{SecretBytes, SecretStr};
use mw_core::state::{default_state_dir, init as state_init, KeystoreChoice};

use mwsqlctl::installer::{self, InstallParams};
use mwsqlctl::{audit_tail, bastion, cred, envs, policy};

#[derive(Parser)]
#[command(name = "mwsqlctl", version, about = "middleWHERE admin CLI")]
struct Cli {
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[arg(long, global = true)]
    file_keystore: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a master key, seal an empty config, and create state dirs.
    Init,
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
    #[arg(long)] host: String,
    #[arg(long, default_value_t = 22)] port: u16,
    #[arg(long)] ssh_user: String,
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
        #[arg(long)] user: String,
        #[arg(long)] password_stdin: bool,
    },
    Rotate {
        name: String,
        #[arg(long)] password_stdin: bool,
    },
    Rm { name: String },
    List,
}

#[derive(Subcommand)]
enum EnvCmd {
    Add(EnvAddArgs),
    Rm { name: String },
    RotateToken { name: String },
    List,
}

#[derive(Args)]
struct EnvAddArgs {
    name: String,
    #[arg(long)] backend_host: String,
    /// Backend port. Defaults to the engine's conventional port
    /// (mysql 3306, postgres 5432, mssql 1433).
    #[arg(long)] backend_port: Option<u16>,
    #[arg(long, value_enum, default_value_t = EngineKindArg::Mysql)]
    engine: EngineKindArg,
    #[arg(long)] database: Option<String>,
    #[arg(long)] bastion: Option<String>,
    #[arg(long)] credential: String,
    #[arg(long, value_enum, default_value_t = PolicyKindArg::ReadOnly)]
    policy: PolicyKindArg,
    #[arg(long)] listen_port: Option<u16>,
    #[arg(long)] max_pool: Option<u32>,
}

#[derive(Copy, Clone, ValueEnum)]
enum EngineKindArg { Mysql, Postgres, Mssql }

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
enum PolicyKindArg { ReadOnly, ReadWrite }

impl From<PolicyKindArg> for Policy {
    fn from(p: PolicyKindArg) -> Self {
        match p {
            PolicyKindArg::ReadOnly  => Policy::ReadOnly,
            PolicyKindArg::ReadWrite => Policy::ReadWrite,
        }
    }
}

#[derive(Args)]
struct PolicyArgs {
    env: String,
    #[arg(long, group = "target")] read_only: bool,
    #[arg(long, group = "target")] read_write: bool,
    #[arg(long)] i_know_what_im_doing: bool,
}

#[derive(Args)]
struct AuditTailArgs {
    #[arg(short = 'n', long, default_value_t = 20)] n: usize,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let state_dir = cli.state_dir.unwrap_or_else(default_state_dir);
    let ks = if cli.file_keystore {
        KeystoreChoice::default_file(&state_dir)
    } else {
        KeystoreChoice::default_os()
    };

    match cli.cmd {
        Cmd::Init => {
            state_init(&state_dir, &ks)?;
            eprintln!("initialized at {}", state_dir.display());
        }
        Cmd::Bastion(BastionCmd::Add(a)) => {
            let auth = if let Some(path) = a.key_file {
                let pem = std::fs::read(&path)
                    .with_context(|| format!("read key {}", path.display()))?;
                let passphrase = if read_yes_no("key has a passphrase? [y/N]: ")? {
                    Some(SecretStr::new(read_secret("key passphrase: ", false)?))
                } else { None };
                bastion::BastionAuthInput::Key { pem: SecretBytes::new(pem), passphrase }
            } else {
                let pw = read_secret("bastion password: ", a.password_stdin)?;
                bastion::BastionAuthInput::Password(SecretStr::new(pw))
            };
            let fingerprint = a.fingerprints.first().map(|s| parse_fingerprint(s)).transpose()?;
            bastion::add(&state_dir, &ks, bastion::BastionAddArgs {
                name: &a.name, host: &a.host, port: a.port, ssh_user: &a.ssh_user,
                auth, fingerprint,
            })?;
            eprintln!("bastion {:?} added", a.name);
        }
        Cmd::Bastion(BastionCmd::Rm { name }) => {
            bastion::rm(&state_dir, &ks, &name)?;
            eprintln!("bastion {:?} removed", name);
        }
        Cmd::Bastion(BastionCmd::List) => {
            for row in bastion::list(&state_dir, &ks)? {
                println!("{}\t{}:{}\tuser={}\tauth={}\tfingerprints={}",
                    row.name, row.host, row.port, row.ssh_user, row.auth_kind, row.pinned_fingerprints);
            }
        }
        Cmd::Cred(CredCmd::Add { name, user, password_stdin }) => {
            let pw = read_secret("backend password: ", password_stdin)?;
            cred::add(&state_dir, &ks, &name, &user, SecretStr::new(pw))?;
            eprintln!("credential {:?} added", name);
        }
        Cmd::Cred(CredCmd::Rotate { name, password_stdin }) => {
            let pw = read_secret("new backend password: ", password_stdin)?;
            cred::rotate(&state_dir, &ks, &name, SecretStr::new(pw))?;
            eprintln!("credential {:?} rotated", name);
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
            let engine: EngineKind = a.engine.into();
            let out = envs::add(&state_dir, &ks, envs::EnvAddArgs {
                name: &a.name,
                backend_host: &a.backend_host,
                backend_port: a.backend_port.unwrap_or_else(|| engine.default_port()),
                default_database: a.database.as_deref(),
                bastion: a.bastion.as_deref(),
                credential: &a.credential,
                policy: a.policy.into(),
                listen_port: a.listen_port,
                max_pool: a.max_pool,
                engine,
            })?;
            eprintln!("env {:?} added, listening on 127.0.0.1:{}", a.name, out.listen_port);
            eprintln!("Client token (save now — will not be shown again):");
            println!("{}", out.token.expose());
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
                println!("{}\t{}\tengine={}\tbastion={}\tcred={}\tpolicy={}\tport={}",
                    row.name, row.backend, row.engine,
                    row.bastion.as_deref().unwrap_or("-"),
                    row.credential, row.policy, row.listen_port);
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
            let exec_path = match a.exec_path {
                Some(p) => p,
                None => default_daemon_path()?,
            };
            let params = InstallParams::new(
                &a.service_name,
                exec_path.to_string_lossy().to_string(),
                state_dir.to_string_lossy().to_string(),
            );
            let (artifact, steps): (String, String) = if cfg!(target_os = "linux") {
                (installer::systemd_unit(&params), installer::linux_operator_steps(&params))
            } else if cfg!(target_os = "macos") {
                (installer::launchd_plist(&params), installer::macos_account_steps(&params))
            } else if cfg!(windows) {
                (installer::windows_install_ps1(&params),
                 "# Windows — run the generated script elevated (Administrator).".to_string())
            } else {
                bail!("unsupported platform for install-service");
            };

            if let Some(path) = a.write {
                if path.exists() && !a.force {
                    bail!("{} exists; pass --force to overwrite", path.display());
                }
                std::fs::write(&path, &artifact)
                    .with_context(|| format!("write {}", path.display()))?;
                eprintln!("wrote {}", path.display());
                eprintln!("\nNext steps (run with the privileges they require):\n{steps}");
            } else {
                print!("{artifact}");
                eprintln!("\n# ---- operator steps ----\n{steps}");
            }
        }
        Cmd::Grant(g) => {
            let out = envs::grant(&state_dir, &ks, &g.env)?;
            if let Some(to) = &g.to {
                eprintln!("granted env {:?} to {to} (token rotated; any prior token is now dead)", g.env);
            } else {
                eprintln!("env {:?} token rotated; any prior token is now dead", g.env);
            }
            eprintln!("Deliver the line below to that identity over a secure channel.");
            eprintln!("They run it, then paste the token at the prompt:\n");
            eprintln!("  mwsql login {} --port {}", g.env, out.listen_port);
            eprintln!("\nToken (shown once):");
            println!("{}", out.token.expose());
        }
        Cmd::Import(i) => {
            let report = mwsqlctl::import_poc::import(&state_dir, &ks, &i.from_dir)?;
            eprintln!("imported {} bastion(s), {} credential(s), {} env(s):",
                report.bastions.len(), report.credentials.len(), report.envs.len());
            for (name, port) in &report.envs {
                eprintln!("  env {name} -> 127.0.0.1:{port}");
            }
            if !report.warnings.is_empty() {
                eprintln!("\nwarnings:");
                for w in &report.warnings { eprintln!("  ! {w}"); }
            }
            eprintln!("\n{}", mwsqlctl::import_poc::decommission_checklist());
        }
    }
    Ok(())
}

/// Resolve the mwsqld binary that should run as the service: a sibling
/// of the currently-running mwsqlctl executable.
fn default_daemon_path() -> Result<PathBuf> {
    let me = std::env::current_exe().context("resolve current exe")?;
    let dir = me.parent().ok_or_else(|| anyhow::anyhow!("exe has no parent dir"))?;
    let name = if cfg!(windows) { "mwsqld.exe" } else { "mwsqld" };
    Ok(dir.join(name))
}

fn read_secret(prompt: &str, from_stdin: bool) -> Result<String> {
    if from_stdin {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s.trim_end_matches(['\n', '\r']).to_string())
    } else if std::io::stdin().is_terminal() {
        Ok(rpassword::prompt_password(prompt)?)
    } else {
        bail!("stdin is not a terminal; pass --password-stdin");
    }
}

fn read_yes_no(prompt: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() { return Ok(false); }
    eprint!("{prompt}");
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

fn parse_fingerprint(s: &str) -> Result<HostKeyFingerprint> {
    let (algo, b64) = s.split_once(':')
        .ok_or_else(|| anyhow::anyhow!("fingerprint must be <algo>:<sha256_b64>"))?;
    Ok(HostKeyFingerprint { algo: algo.to_string(), sha256_b64: b64.to_string() })
}
