//! MySQL engine: thin adapter over the existing, unchanged protocol modules.
//!
//! Behavior is byte-identical to the pre-seam daemon — `accept` calls the
//! same [`crate::mysql_server::handshake`], `serve` the same
//! [`crate::router::serve_session`] with its concrete `mysql_async` row path.
//! The trait only relocates the *call sites*, never the protocol logic.

use tokio::net::TcpStream;

use mw_core::config::{ClientAuth, EngineKind, Policy};

use crate::engine::{Backend, BackendOpts, Engine, EngineError, Session};
use crate::mysql_client::{build_pool, BackendPool};
use crate::mysql_server::handshake;
use crate::router::serve_session;

pub struct MySqlEngine;

impl MySqlEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MySqlEngine {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MySqlBackend(pub BackendPool);

impl Backend for MySqlBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[async_trait::async_trait]
impl Engine for MySqlEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::MySql
    }

    async fn accept(
        &self,
        stream: &mut TcpStream,
        env_name: &str,
        auth: &ClientAuth,
        conn_id: u32,
    ) -> Result<Session, EngineError> {
        match handshake(stream, env_name, auth, conn_id).await {
            Ok(s) => Ok(Session {
                env_name: s.env_name,
                client_username_seen: s.client_username_seen,
                database: s.database,
            }),
            // handshake already wrote the ERR packet; mirror the old daemon's
            // swallow-and-close behavior.
            Err(_) => Err(EngineError::Auth),
        }
    }

    async fn build_backend(
        &self,
        opts: BackendOpts,
        max_size: u32,
    ) -> Result<Box<dyn Backend>, EngineError> {
        Ok(Box::new(MySqlBackend(build_pool(opts, max_size))))
    }

    async fn serve(
        &self,
        stream: &mut TcpStream,
        session: &Session,
        backend: &dyn Backend,
        policy: &Policy,
    ) -> Result<(), EngineError> {
        let be = backend
            .as_any()
            .downcast_ref::<MySqlBackend>()
            .ok_or(EngineError::Unsupported)?;
        serve_session(
            stream,
            &session.env_name,
            &session.client_username_seen,
            &be.0,
            policy,
        )
        .await
        .map_err(|e| EngineError::Other(e.to_string()))
    }
}
