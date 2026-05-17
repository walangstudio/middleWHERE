//! MS SQL (TDS) engine: stub. The protocol surface (prelogin + auth + TDS
//! token streams) is not implemented; the daemon refuses MsSql envs at bind.

use tokio::net::TcpStream;

use mw_core::config::{ClientAuth, EngineKind, Policy};

use crate::engine::{Backend, BackendOpts, Engine, EngineError, Session};

pub struct MsSqlEngine;

impl MsSqlEngine {
    pub fn new() -> Self { Self }
}

impl Default for MsSqlEngine {
    fn default() -> Self { Self::new() }
}

#[async_trait::async_trait]
impl Engine for MsSqlEngine {
    fn kind(&self) -> EngineKind { EngineKind::MsSql }

    async fn accept(
        &self,
        _stream: &mut TcpStream,
        _env_name: &str,
        _auth: &ClientAuth,
        _conn_id: u32,
    ) -> Result<Session, EngineError> {
        Err(EngineError::Unsupported)
    }

    async fn build_backend(
        &self,
        _opts: BackendOpts,
        _max_size: u32,
    ) -> Result<Box<dyn Backend>, EngineError> {
        Err(EngineError::Unsupported)
    }

    async fn serve(
        &self,
        _stream: &mut TcpStream,
        _session: &Session,
        _backend: &dyn Backend,
        _policy: &Policy,
    ) -> Result<(), EngineError> {
        Err(EngineError::Unsupported)
    }
}
