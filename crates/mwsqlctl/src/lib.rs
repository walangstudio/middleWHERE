//! `mwsqlctl` library. All real work lives here so tests can drive each
//! mutation without spawning a subprocess. The bin is a thin clap wrapper.
//!
//! Two ways to reach the sealed config: the synchronous `ops`/`envs`/… modules
//! read + write the config file in-process (per-user, or the privileged
//! `--offline` path); [`control_client`] speaks to a running daemon over the
//! local control channel so service-mode config commands need no elevation.

pub mod audit_tail;
pub mod bastion;
pub mod control_client;
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
/// terse one-liner into a client's connection dialog. The whole banner goes to
/// stderr; stdout carries exactly one line — the bare token — so
/// `token=$(mwsqlctl grant …)` captures only the secret. On Windows from a
/// non-elevated shell this triggers a one-time UAC prompt and then mirrors the
/// bare token back to the (redirected) stdout, so the capture still works — it
/// just needs stdin to be a terminal.
pub fn print_token_block(
    env: &str,
    port: u16,
    token: &str,
    engine: EngineKind,
    database: Option<&str>,
) {
    let bar = "=".repeat(70);
    eprintln!("\n{bar}");
    eprintln!("  CLIENT TOKEN  —  SAVE NOW (shown only once)");
    eprintln!("{bar}");
    eprintln!("  env:     {env}");
    eprintln!("  token:   {token}");
    eprintln!("  connect: mwsql login {env} --port {port}");
    eprintln!();
    eprintln!("  DBeaver / any SQL client — enter these fields:");
    eprintln!("    Host:      127.0.0.1");
    eprintln!("    Port:      {port}");
    eprintln!(
        "    Database:  {}",
        database.unwrap_or("(none — pick in client)")
    );
    eprintln!("    Username:  {env}");
    eprintln!("    Password:  {token}");
    eprintln!("    SSL:       off / disable");
    if let Some(uri) = engine_uri(engine, env, token, port, database) {
        eprintln!();
        eprintln!("  paste-ready URL (embeds the token — treat it like the password):");
        eprintln!("    {uri}");
    }
    eprintln!("{bar}\n");
    println!("{token}");
}

/// Render a freshly minted env token from a control-channel [`NewEnvOutputDto`]:
/// the standard token block, then — when the daemon flagged the env as persisted
/// but not yet live (`note` is `Some`, only on the online path when the live bind
/// failed) — a WARNING to stderr so the operator knows a restart is needed. The
/// single render point for `env add`, `grant`, and the wizard, so every path
/// surfaces the note the same way. `note = None` (clean success, or any
/// direct/offline write) prints nothing extra.
pub fn render_new_env(env: &str, out: &mw_core::control::NewEnvOutputDto) {
    print_token_block(
        env,
        out.listen_port,
        out.token.expose(),
        out.engine,
        out.database.as_deref(),
    );
    if let Some(note) = &out.note {
        eprintln!("⚠ {note}");
    }
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

/// Whether this process is already privileged (root on unix, Administrator on
/// Windows). The `--offline` config path edits the root/service-owned sealed
/// config directly, so it requires this — the CLI no longer auto-elevates for
/// config commands.
pub fn is_privileged() -> bool {
    crate::service::is_root() || crate::service::is_admin()
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
