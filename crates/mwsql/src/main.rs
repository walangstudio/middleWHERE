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

fn main() -> Result<()> {
    let cli = Cli::parse();
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
