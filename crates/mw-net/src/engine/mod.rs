//! Engine abstraction seam.
//!
//! One `&'static dyn Engine` per backend kind, selected per env by
//! [`EngineKind`]. The daemon names no concrete engine type: it looks one up
//! via [`engine_for`] and drives `accept` -> `serve` against it. MySQL wraps
//! the existing concrete protocol code unchanged (byte-identical); other
//! engines bring their own server/client modules.

use std::any::Any;

use tokio::net::TcpStream;

use mw_core::config::{ClientAuth, EngineKind, Policy};

pub use crate::mysql_client::BackendOpts;

pub mod mysql;
pub mod mssql;
pub mod postgres;

/// Post-auth connection metadata, engine-neutral.
#[derive(Debug, Clone)]
pub struct Session {
    pub env_name: String,
    pub client_username_seen: String,
    pub database: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Handshake/auth failed. The engine has already written its protocol's
    /// native error frame; the caller just drops the socket.
    #[error("authentication failed")]
    Auth,
    #[error("engine not supported in this build")]
    Unsupported,
    #[error("backend: {0}")]
    Backend(String),
    #[error("{0}")]
    Other(String),
}

/// Per-env backend connection source. Concrete pools stay engine-typed inside
/// the impl; only `&dyn Backend` crosses into the daemon. Engines recover
/// their concrete type via `as_any` so MySQL keeps its zero-recode fast path.
pub trait Backend: Send + Sync {
    fn as_any(&self) -> &dyn Any;
}

#[async_trait::async_trait]
pub trait Engine: Send + Sync + 'static {
    fn kind(&self) -> EngineKind;

    /// Front-side handshake + auth termination. On failure the engine has
    /// already emitted its native error frame and returns [`EngineError`].
    async fn accept(
        &self,
        stream: &mut TcpStream,
        env_name: &str,
        auth: &ClientAuth,
        conn_id: u32,
    ) -> Result<Session, EngineError>;

    /// Build the per-env backend pool. Off the hot path (once per env).
    async fn build_backend(
        &self,
        opts: BackendOpts,
        max_size: u32,
    ) -> Result<Box<dyn Backend>, EngineError>;

    /// Post-auth command loop in this engine's wire protocol. Firewalls each
    /// statement, forwards allowed ones, streams results back. Returns when
    /// the client disconnects.
    async fn serve(
        &self,
        stream: &mut TcpStream,
        session: &Session,
        backend: &dyn Backend,
        policy: &Policy,
    ) -> Result<(), EngineError>;
}

/// Process-wide registry. Engines are zero-sized; one instance each.
pub fn engine_for(kind: EngineKind) -> &'static dyn Engine {
    use std::sync::OnceLock;
    static MYSQL: OnceLock<mysql::MySqlEngine> = OnceLock::new();
    static PG: OnceLock<postgres::PgEngine> = OnceLock::new();
    static MSSQL: OnceLock<mssql::MsSqlEngine> = OnceLock::new();
    match kind {
        EngineKind::MySql => MYSQL.get_or_init(mysql::MySqlEngine::new),
        EngineKind::Postgres => PG.get_or_init(postgres::PgEngine::new),
        EngineKind::MsSql => MSSQL.get_or_init(mssql::MsSqlEngine::new),
    }
}
