use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use mwsqld::{env_flag, init as init_state, load_config, resolve_cli_target, Daemon};

#[derive(Parser)]
#[command(
    name = "mwsqld",
    version,
    about = "middleWHERE secure SQL gateway daemon"
)]
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

    /// Use a file-backed master key instead of the OS keystore.
    /// Recommended only for headless Linux without D-Bus. Also set by
    /// MW_FILE_KEYSTORE=1.
    #[arg(long, global = true)]
    file_keystore: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a master key, seal an empty config, and create state dirs.
    Init,
    /// Load the sealed config and serve.
    Run {
        /// Bind interface for env listeners (default 127.0.0.1).
        #[arg(long, default_value = "127.0.0.1")]
        listen_host: String,
        /// Accept an unpinned bastion host key on first use (insecure).
        /// Without this, a bastion with no pinned host key is REFUSED.
        #[arg(long)]
        allow_tofu: bool,
    },
    /// Internal: launched by the Windows Service Control Manager. Not for
    /// interactive use.
    #[cfg(windows)]
    #[command(hide = true)]
    Service,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // The Windows service path must run BEFORE any tokio runtime: the SCM
    // dispatcher blocks and owns its own runtime internally.
    #[cfg(windows)]
    if let Cmd::Service = cli.cmd {
        return mwsqld::winsvc::run();
    }

    let user = cli.user || env_flag("MW_USER");
    let file_keystore = cli.file_keystore || env_flag("MW_FILE_KEYSTORE");
    let (state_dir, keystore) = resolve_cli_target(cli.state_dir, user, file_keystore);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        match cli.cmd {
            Cmd::Init => {
                init_state(&state_dir, &keystore)?;
                eprintln!("initialized at {}", state_dir.display());
                Ok(())
            }
            Cmd::Run {
                listen_host,
                allow_tofu,
            } => {
                // Process owns the global subscriber + audit writer guard for
                // its whole lifetime. Not done inside Daemon::bind on purpose.
                let _audit = mwsqld::install_audit(&state_dir)?;
                let cfg = load_config(&state_dir, &keystore)?;
                if cfg.envs.is_empty() {
                    eprintln!("warning: no envs configured. Use mwsqlctl to add some.");
                }
                let daemon = Daemon::bind(state_dir, &cfg, &listen_host, allow_tofu).await?;
                let (tx, rx) = tokio::sync::broadcast::channel(1);
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    let _ = tx.send(());
                });
                daemon.run(rx).await
            }
            #[cfg(windows)]
            Cmd::Service => unreachable!("handled before runtime"),
        }
    })
}
