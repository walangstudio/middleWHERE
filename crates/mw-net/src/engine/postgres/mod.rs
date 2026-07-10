//! PostgreSQL engine: v3 wire protocol front, tokio-postgres backend.

mod client;
mod proto;
mod server;

use tokio::net::TcpStream;

use mw_core::config::{ClientAuth, EngineKind, Policy};

use crate::engine::{Backend, BackendOpts, Engine, EngineError, Session};
use client::{build_pg_pool, PgPool};

pub struct PgEngine;

impl PgEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PgEngine {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PgBackend(pub PgPool);

impl Backend for PgBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn reap_idle(&self, idle_timeout: std::time::Duration) -> usize {
        self.0
            .retain(|_, m| crate::idle::should_retain(m.last_used(), idle_timeout))
            .removed
            .len()
    }
}

#[async_trait::async_trait]
impl Engine for PgEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::Postgres
    }

    async fn accept(
        &self,
        stream: &mut TcpStream,
        env_name: &str,
        auth: &ClientAuth,
        _conn_id: u32,
    ) -> Result<Session, EngineError> {
        let s = server::handshake(stream, env_name, auth).await?;
        Ok(Session {
            env_name: env_name.to_string(),
            client_username_seen: s.user_seen,
            database: s.database,
        })
    }

    async fn build_backend(
        &self,
        opts: BackendOpts,
        max_size: u32,
    ) -> Result<Box<dyn Backend>, EngineError> {
        Ok(Box::new(PgBackend(build_pg_pool(opts, max_size))))
    }

    async fn probe(&self, backend: &dyn Backend) -> Result<(), EngineError> {
        let be = backend
            .as_any()
            .downcast_ref::<PgBackend>()
            .ok_or(EngineError::Unsupported)?;
        // Forces `PgManager::create` (a real tokio-postgres startup + auth).
        // The pooled `Client` and its spawned connection task drop on return.
        let _client =
            be.0.get()
                .await
                .map_err(|e| EngineError::Backend(e.to_string()))?;
        Ok(())
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
            .downcast_ref::<PgBackend>()
            .ok_or(EngineError::Unsupported)?;
        server::serve(
            stream,
            &session.env_name,
            &session.client_username_seen,
            &be.0,
            policy,
        )
        .await
    }
}
