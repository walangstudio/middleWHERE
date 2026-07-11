use std::path::PathBuf;

use anyhow::{bail, Result};
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
        /// Close a backend (server) connection after this many seconds of no
        /// activity, freeing the server-side connection; activity resets the
        /// timer. 0 disables reaping. When set, overrides every env's
        /// configured pool idle timeout; unset, each env uses its own
        /// (default 300).
        #[arg(long, value_name = "SECS")]
        idle_timeout_secs: Option<u32>,
    },
    /// Probe backend connectivity for one env (or all): open the bastion tunnel
    /// if any, force one real connect+auth, report, and exit. Reads the sealed
    /// config from disk; never starts a listener. `mwsqlctl` shells out to this
    /// to validate a connection at add time.
    Test {
        /// Probe this env. Mutually exclusive with --all.
        #[arg(long, conflicts_with = "all")]
        env: Option<String>,
        /// Probe every configured env.
        #[arg(long)]
        all: bool,
        /// Machine-readable output: one
        /// `{"ok":bool,"supported":bool,"env":str,"reason":str}` JSON line per
        /// env. `supported` is false for engines with no probe path (mssql).
        #[arg(long)]
        json: bool,
        /// Accept an unpinned bastion host key (TOFU) during the probe. Without
        /// it, a bastion with no pinned host key is refused.
        #[arg(long)]
        allow_tofu: bool,
    },
    /// Internal: launched by the Windows Service Control Manager. Not for
    /// interactive use.
    #[cfg(windows)]
    #[command(hide = true)]
    Service,
}

/// Minimal JSON string escaping for the `test --json` emitter (env names are
/// already `[a-z0-9_-]`, but a probe reason can carry quotes/newlines).
fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // The Windows service path must run BEFORE any tokio runtime: the SCM
    // dispatcher blocks and owns its own runtime internally. Resolve the same
    // target the binPath's `--state-dir`/`--file-keystore` flags select so the
    // service reads what `init` seeded, not the compiled-in default.
    #[cfg(windows)]
    if let Cmd::Service = cli.cmd {
        let user = cli.user || env_flag("MW_USER");
        let file_keystore = cli.file_keystore || env_flag("MW_FILE_KEYSTORE");
        let (state_dir, keystore) = resolve_cli_target(cli.state_dir.clone(), user, file_keystore);
        return mwsqld::winsvc::run(state_dir, keystore);
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
                idle_timeout_secs,
            } => {
                // Process owns the global subscriber + audit writer guard for
                // its whole lifetime. Not done inside Daemon::bind on purpose.
                let _audit = mwsqld::install_audit(&state_dir)?;
                let mut cfg = load_config(&state_dir, &keystore)?;
                if cfg.envs.is_empty() {
                    eprintln!("warning: no envs configured. Use mwsqlctl to add some.");
                }
                // The flag overrides every env's configured idle timeout. Only
                // this in-memory copy is touched; the sealed config on disk is
                // never rewritten.
                if let Some(secs) = idle_timeout_secs {
                    for env in cfg.envs.values_mut() {
                        env.pool.idle_timeout_secs = secs;
                    }
                }
                let daemon =
                    Daemon::bind(state_dir, &cfg, &listen_host, allow_tofu, keystore).await?;
                let (tx, rx) = tokio::sync::broadcast::channel(1);
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    let _ = tx.send(());
                });
                daemon.run(rx).await
            }
            Cmd::Test {
                env,
                all,
                json,
                allow_tofu,
            } => {
                let which = match (env, all) {
                    (Some(e), false) => mwsqld::Probe::One(e),
                    (None, true) => mwsqld::Probe::All,
                    (None, false) => bail!("specify --env <name> or --all"),
                    (Some(_), true) => unreachable!("clap conflicts_with prevents this"),
                };
                let cfg = load_config(&state_dir, &keystore)?;
                let results = mwsqld::test_envs(&cfg, which, allow_tofu).await;
                if results.is_empty() {
                    // Zero envs probed (e.g. `--all` on a freshly-init'd,
                    // env-less config). An empty set is NOT "all connected":
                    // say so plainly and exit 0 without asserting any
                    // connectivity was verified. In JSON mode emit an explicit
                    // marker so a caller (mwsqlctl's probe::validate) can tell
                    // "zero envs" apart from "all envs passed" — both otherwise
                    // print nothing and exit 0.
                    if json {
                        println!("{{\"envs\":0}}");
                    } else {
                        println!("no environments configured");
                    }
                    return Ok(());
                }
                let mut all_ok = true;
                for r in &results {
                    // An unsupported engine is reported but never fails the run.
                    all_ok &= r.ok || !r.supported;
                    if json {
                        println!(
                            "{{\"ok\":{},\"supported\":{},\"env\":\"{}\",\"reason\":\"{}\"}}",
                            r.ok,
                            r.supported,
                            json_escape(&r.env),
                            json_escape(&r.reason)
                        );
                    } else if r.ok {
                        println!("OK   {}", r.env);
                    } else if !r.supported {
                        println!("SKIP {}  {}", r.env, r.reason);
                    } else {
                        println!("ERR  {}  {}", r.env, r.reason);
                    }
                }
                use std::io::Write;
                std::io::stdout().flush().ok();
                if all_ok {
                    Ok(())
                } else {
                    // Non-zero exit without an extra anyhow error line (the
                    // per-env output above already says what failed).
                    std::process::exit(1);
                }
            }
            #[cfg(windows)]
            Cmd::Service => unreachable!("handled before runtime"),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    // Catches arg-definition conflicts (e.g. a `test` subcommand flag colliding
    // with a global one, or a stale `conflicts_with` target) at test time.
    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn json_escape_handles_quotes_and_control_chars() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("line1\nline2"), "line1\\nline2");
    }
}
