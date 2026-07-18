//! `mwsql` — the client-user wrapper.
//!
//!   mwsql login  <env> --port <p> [--host 127.0.0.1]   # store token
//!   mwsql logout <env>
//!   mwsql <env> [--db <name>] -e "SELECT 1"             # run
//!
//! Any plain MySQL client also works (`mysql -h 127.0.0.1 -P <port> -u <env>
//! -p<token>`); this wrapper just keeps the token out of shell history and
//! argv by reading it from the OS keyring.

use std::io::{IsTerminal, Read};

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};

use mwsql::{ClientTokenStore, OsClientStore, StoredCred};

#[derive(Parser)]
#[command(name = "mwsql", version, about = "middleWHERE client wrapper")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Store the token for an env in this user's keyring.
    Login(LoginArgs),
    /// Remove a stored env token.
    Logout { env: String },
    /// Run SQL against an env (default action for a bare env name).
    Run(RunArgs),
}

#[derive(Args)]
struct LoginArgs {
    env: String,
    #[arg(long)]
    port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// Read the token from stdin instead of an interactive prompt.
    #[arg(long)]
    token_stdin: bool,
}

#[derive(Args)]
struct RunArgs {
    env: String,
    #[arg(long)]
    db: Option<String>,
    /// SQL to execute. If omitted, read one statement from stdin.
    #[arg(short = 'e', long)]
    execute: Option<String>,
}

/// Bare `mwsql <env> ...` defaults to the `run` subcommand.
fn default_to_run(argv: &mut Vec<std::ffi::OsString>) {
    if let Some(first) = argv.get(1).and_then(|s| s.to_str()) {
        if !first.starts_with('-') && !["login", "logout", "run", "help"].contains(&first) {
            argv.insert(1, "run".into());
        }
    }
}

fn main() -> Result<()> {
    let mut argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    default_to_run(&mut argv);
    let cli = Cli::parse_from(argv);
    let store = OsClientStore::new();

    match cli.cmd {
        Cmd::Login(a) => {
            let token = if a.token_stdin {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s.trim_end_matches(['\n', '\r']).to_string()
            } else if std::io::stdin().is_terminal() {
                rpassword::prompt_password(format!("token for {}: ", a.env))?
            } else {
                bail!("stdin is not a terminal; pass --token-stdin");
            };
            if token.is_empty() {
                bail!("empty token");
            }
            store.save(
                &a.env,
                &StoredCred {
                    token,
                    host: a.host,
                    port: a.port,
                },
            )?;
            eprintln!("stored credentials for env {:?}", a.env);
        }
        Cmd::Logout { env } => {
            store.delete(&env)?;
            eprintln!("removed credentials for env {:?}", env);
        }
        Cmd::Run(a) => {
            let cred = store.load(&a.env)?;
            let sql = match a.execute {
                Some(s) => s,
                None => {
                    let mut s = String::new();
                    std::io::stdin().read_to_string(&mut s)?;
                    s.trim().to_string()
                }
            };
            if sql.is_empty() {
                bail!("no SQL given (use -e \"...\" or pipe via stdin)");
            }
            let rt = tokio::runtime::Runtime::new()?;
            let out = rt.block_on(mwsql::run_sql_as(&a.env, &cred, a.db.as_deref(), &sql))?;
            println!("{out}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewritten(args: &[&str]) -> Vec<String> {
        let mut argv: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
        default_to_run(&mut argv);
        argv.into_iter().map(|s| s.into_string().unwrap()).collect()
    }

    #[test]
    fn bare_env_gets_run_inserted() {
        assert_eq!(
            rewritten(&["mwsql", "stage1", "-e", "SELECT 1"]),
            ["mwsql", "run", "stage1", "-e", "SELECT 1"]
        );
    }

    #[test]
    fn subcommands_flags_and_empty_are_untouched() {
        for args in [
            vec!["mwsql", "login", "stage1", "--port", "6433"],
            vec!["mwsql", "logout", "stage1"],
            vec!["mwsql", "run", "stage1", "-e", "SELECT 1"],
            vec!["mwsql", "help"],
            vec!["mwsql", "--help"],
            vec!["mwsql"],
        ] {
            assert_eq!(rewritten(&args), args);
        }
    }

    #[test]
    fn rewritten_bare_env_parses_as_run() {
        let mut argv: Vec<std::ffi::OsString> = ["mwsql", "stage1", "-e", "SELECT 1"]
            .iter()
            .map(Into::into)
            .collect();
        default_to_run(&mut argv);
        let cli = Cli::try_parse_from(argv).expect("bare env must parse");
        match cli.cmd {
            Cmd::Run(a) => {
                assert_eq!(a.env, "stage1");
                assert_eq!(a.execute.as_deref(), Some("SELECT 1"));
            }
            _ => panic!("expected Run"),
        }
    }
}
