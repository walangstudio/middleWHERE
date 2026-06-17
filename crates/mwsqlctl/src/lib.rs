//! `mwsqlctl` library. All real work lives here so tests can drive each
//! mutation without spawning a subprocess. The bin is a thin clap wrapper.
//!
//! Concurrency: every public function in this crate is synchronous and
//! reads + writes the sealed config once. Long-term, the same surface will
//! gain an "online" counterpart that talks to a running daemon over IPC
//! (Phase 6b in the plan); today, offline-only.

pub mod audit_tail;
pub mod bastion;
pub mod cred;
pub mod envs;
pub mod import_poc;
pub mod init;
pub mod installer;
pub mod ops;
pub mod policy;
pub mod probe;
pub(crate) mod prompt;
pub(crate) mod service;
pub mod store;
pub mod uninstall;
pub mod wizard;

use mw_core::config::EngineKind;

/// Print the per-env client token as an unmissable block. The token is shown
/// **once** (only its hash is stored), so it must be impossible to scroll past
/// unnoticed. Used by `env add`, `grant`, and the wizard so the operator always
/// sees the same prominent output. Includes a DBeaver-style field list and a
/// paste-ready engine URI so a non-technical operator never has to translate a
/// terse one-liner into a client's connection dialog.
pub fn print_token_block(
    env: &str,
    port: u16,
    token: &str,
    engine: EngineKind,
    database: Option<&str>,
) {
    let bar = "=".repeat(70);
    println!("\n{bar}");
    println!("  CLIENT TOKEN  —  SAVE NOW (shown only once)");
    println!("{bar}");
    println!("  env:     {env}");
    println!("  token:   {token}");
    println!("  connect: mwsql login {env} --port {port}");
    println!();
    println!("  DBeaver / any SQL client — enter these fields:");
    println!("    Host:      127.0.0.1");
    println!("    Port:      {port}");
    println!(
        "    Database:  {}",
        database.unwrap_or("(none — pick in client)")
    );
    println!("    Username:  {env}");
    println!("    Password:  {token}");
    println!("    SSL:       off / disable");
    if let Some(uri) = engine_uri(engine, env, token, port, database) {
        println!();
        println!("  paste-ready URL (embeds the token — treat it like the password):");
        println!("    {uri}");
    }
    println!("{bar}\n");
}

/// A paste-ready client connection URI for the local proxy listener, or `None`
/// for engines without one (MsSql). The token is the password, so a persisted
/// URI persists the secret — the same exposure as the password field above.
/// All user-supplied components are percent-encoded.
pub fn engine_uri(
    engine: EngineKind,
    env: &str,
    token: &str,
    port: u16,
    database: Option<&str>,
) -> Option<String> {
    let authority = format!("{}:{}@127.0.0.1:{port}", pct(env), pct(token));
    let path = match database {
        Some(db) if !db.is_empty() => format!("/{}", pct(db)),
        _ => String::new(),
    };
    match engine {
        EngineKind::Postgres => Some(format!("postgresql://{authority}{path}?sslmode=disable")),
        EngineKind::MySql => Some(format!("mysql://{authority}{path}")),
        EngineKind::MsSql => None,
    }
}

/// Percent-encode everything outside the RFC 3986 unreserved set. Works byte-wise
/// so multi-byte UTF-8 is encoded correctly.
fn pct(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

/// Run a config-touching `mwsqlctl` command, auto-elevating on Windows service
/// mode so it does not just fail against the admin-locked state dir. The bin
/// wraps its command dispatch (everything except the self-elevating `init` /
/// `wizard`) in this.
pub fn run_elevated_or<F: FnOnce() -> anyhow::Result<()>>(
    service: bool,
    uac: bool,
    needs_config: bool,
    run: F,
) -> anyhow::Result<()> {
    crate::service::run_elevated_or(service, uac, needs_config, run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_uri_has_sslmode_disable_and_db_path() {
        let u = engine_uri(
            EngineKind::Postgres,
            "dev",
            "TOK_en-1",
            6033,
            Some("orders"),
        )
        .unwrap();
        assert_eq!(
            u,
            "postgresql://dev:TOK_en-1@127.0.0.1:6033/orders?sslmode=disable"
        );
    }

    #[test]
    fn mysql_uri_has_no_sslmode() {
        let u = engine_uri(EngineKind::MySql, "dev", "tok", 6040, Some("app")).unwrap();
        assert_eq!(u, "mysql://dev:tok@127.0.0.1:6040/app");
    }

    #[test]
    fn none_database_omits_path_segment() {
        let pg = engine_uri(EngineKind::Postgres, "dev", "tok", 6033, None).unwrap();
        assert_eq!(pg, "postgresql://dev:tok@127.0.0.1:6033?sslmode=disable");
        let my = engine_uri(EngineKind::MySql, "dev", "tok", 6033, None).unwrap();
        assert_eq!(my, "mysql://dev:tok@127.0.0.1:6033");
    }

    #[test]
    fn mssql_has_no_uri() {
        assert!(engine_uri(EngineKind::MsSql, "dev", "tok", 6033, Some("db")).is_none());
    }

    #[test]
    fn special_chars_are_percent_encoded() {
        // A database name with a space and an '@' must not break the authority.
        let u = engine_uri(EngineKind::Postgres, "dev", "p@ss/w", 6033, Some("my db")).unwrap();
        assert_eq!(
            u,
            "postgresql://dev:p%40ss%2Fw@127.0.0.1:6033/my%20db?sslmode=disable"
        );
    }
}
