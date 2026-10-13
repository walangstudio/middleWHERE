//! Backend MySQL client: deadpool-managed `mysql_async::Conn` per env.
//!
//! Each env in the sealed config owns one [`BackendPool`]. The pool is lazy —
//! the first query opens the first connection. Recycle calls `SELECT 1` to
//! verify health when an idle conn is checked out.

use std::time::Duration;

use deadpool::managed::{Manager, Metrics, Pool, RecycleError, RecycleResult};
use mysql_async::{prelude::Queryable, Conn, OptsBuilder};

use mw_core::config::{Credential, Env};
use mw_core::secret::SecretStr;

#[derive(Clone, Debug)]
pub struct BackendOpts {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: SecretStr,
    pub database: Option<String>,
}

impl BackendOpts {
    pub fn from_env_credential(env: &Env, cred: &Credential) -> Self {
        Self {
            host: env.backend_host.clone(),
            port: env.backend_port,
            user: cred.backend_user.clone(),
            password: cred.backend_password.clone(),
            database: env.default_database.clone(),
        }
    }

    fn to_opts(&self) -> mysql_async::Opts {
        let mut b = OptsBuilder::default()
            .ip_or_hostname(self.host.clone())
            .tcp_port(self.port)
            .user(Some(self.user.clone()))
            .pass(Some(self.password.expose().to_string()))
            .stmt_cache_size(0);
        if let Some(db) = &self.database {
            b = b.db_name(Some(db.clone()));
        }
        b.into()
    }
}

pub struct BackendManager {
    opts: BackendOpts,
    /// The server's `innodb_rollback_on_timeout` (global, read-only), seen at
    /// connect. When on, a lock wait timeout rolls back the whole transaction.
    pub rollback_on_timeout: std::sync::atomic::AtomicBool,
}

impl BackendManager {
    pub fn new(opts: BackendOpts) -> Self {
        Self {
            opts,
            rollback_on_timeout: Default::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("mysql backend: {0}")]
    Mysql(#[from] mysql_async::Error),
    #[error("mysql backend session setup: {0}")]
    Setup(String),
}

/// sql_mode flags that change how MySQL lexes SQL away from what the firewall
/// (sqlparser's MySQL dialect) parses: backslash escapes in strings, and
/// double quotes as identifiers. `ANSI` is the combination mode that implies
/// `ANSI_QUOTES`.
const LEXER_MODES: &[&str] = &["NO_BACKSLASH_ESCAPES", "ANSI_QUOTES", "ANSI"];

/// Make the backend lex like the firewall: utf8mb4 client charset, and none of
/// [`LEXER_MODES`], whatever the server or `init_connect` configured.
/// Re-reads the result and refuses the connection if it didn't take. Clients
/// can't change these back: `sql_mode` and the charset variables are off the
/// SET allowlist.
async fn pin_session(conn: &mut Conn) -> Result<(), BackendError> {
    // autocommit too: the proxy reports the session's transaction state from
    // a known start, whatever init_connect or the server default says.
    conn.query_drop("SET NAMES utf8mb4, autocommit = 1").await?;
    let mode: String = conn
        .query_first("SELECT @@SESSION.sql_mode")
        .await?
        .unwrap_or_default();
    let kept: Vec<&str> = mode
        .split(',')
        .filter(|m| !m.is_empty() && !LEXER_MODES.contains(&m.to_ascii_uppercase().as_str()))
        .collect();
    // Mode names are [A-Z_]; anything else would not be safe to inline.
    if kept
        .iter()
        .any(|m| !m.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    {
        return Err(BackendError::Setup(format!("unexpected sql_mode {mode:?}")));
    }
    conn.query_drop(format!("SET SESSION sql_mode = '{}'", kept.join(",")))
        .await?;
    let (mode, charset): (String, String) = conn
        .query_first("SELECT @@SESSION.sql_mode, @@SESSION.character_set_client")
        .await?
        .unwrap_or_default();
    let upper = mode.to_ascii_uppercase();
    if upper.split(',').any(|m| LEXER_MODES.contains(&m)) || charset != "utf8mb4" {
        return Err(BackendError::Setup(format!(
            "backend kept sql_mode {mode:?} / charset {charset:?}"
        )));
    }
    Ok(())
}

impl Manager for BackendManager {
    type Type = Conn;
    type Error = BackendError;

    async fn create(&self) -> Result<Conn, BackendError> {
        let mut conn = Conn::new(self.opts.to_opts()).await?;
        pin_session(&mut conn).await?;
        // Option<String>: query_first panics on a value it can't convert, and
        // a proxy may answer NULL or "ON".
        match conn
            .query_first::<Option<String>, _>("SELECT @@GLOBAL.innodb_rollback_on_timeout")
            .await
        {
            Ok(Some(Some(v))) => self.rollback_on_timeout.store(
                v == "1" || v.eq_ignore_ascii_case("on"),
                std::sync::atomic::Ordering::Relaxed,
            ),
            // A server, or a proxy in front of one, that refuses the probe
            // keeps what an earlier connection saw. Only tunes rollback tracking.
            Ok(_) | Err(mysql_async::Error::Server(_)) => {}
            // Anything else may have left the connection broken.
            Err(e) => return Err(e.into()),
        }
        Ok(conn)
    }

    async fn recycle(&self, conn: &mut Conn, _: &Metrics) -> RecycleResult<BackendError> {
        conn.query_drop("SELECT 1")
            .await
            .map_err(|e| RecycleError::Backend(BackendError::Mysql(e)))
    }
}

pub type BackendPool = Pool<BackendManager>;

pub fn build_pool(opts: BackendOpts, max_size: u32) -> BackendPool {
    Pool::builder(BackendManager::new(opts))
        .max_size(max_size as usize)
        .runtime(deadpool::Runtime::Tokio1)
        .wait_timeout(Some(Duration::from_secs(30)))
        .create_timeout(Some(Duration::from_secs(15)))
        .recycle_timeout(Some(Duration::from_secs(5)))
        .build()
        .expect("pool build only fails on bad config")
}
