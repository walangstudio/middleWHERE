//! Backend Postgres client: deadpool-managed `tokio_postgres::Client` per env.
//! Mirrors `mysql_client` 1:1; the one structural difference is that
//! tokio-postgres yields a separate connection task we must spawn to drive
//! the protocol.

use std::time::Duration;

use deadpool::managed::{Manager, Metrics, Pool, RecycleError, RecycleResult};
use tokio_postgres::{Client, NoTls};

use crate::engine::BackendOpts;

#[derive(Debug, thiserror::Error)]
pub enum PgBackendError {
    #[error("postgres backend: {0}")]
    Pg(#[from] tokio_postgres::Error),
}

pub struct PgManager {
    opts: BackendOpts,
}

impl PgManager {
    pub fn new(opts: BackendOpts) -> Self {
        Self { opts }
    }

    fn config(&self) -> tokio_postgres::Config {
        let mut c = tokio_postgres::Config::new();
        c.host(&self.opts.host)
            .port(self.opts.port)
            .user(&self.opts.user)
            .password(self.opts.password.expose());
        if let Some(db) = &self.opts.database {
            c.dbname(db);
        }
        c
    }
}

impl Manager for PgManager {
    type Type = Client;
    type Error = PgBackendError;

    async fn create(&self) -> Result<Client, PgBackendError> {
        let (client, conn) = self.config().connect(NoTls).await?;
        // The connection object owns the socket; it must be polled for the
        // client to make progress. Drop = disconnect, which is what we want
        // when the pooled Client is evicted.
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(client)
    }

    async fn recycle(&self, client: &mut Client, _: &Metrics) -> RecycleResult<PgBackendError> {
        client
            .simple_query("SELECT 1")
            .await
            .map(|_| ())
            .map_err(|e| RecycleError::Backend(PgBackendError::Pg(e)))
    }
}

pub type PgPool = Pool<PgManager>;

pub fn build_pg_pool(opts: BackendOpts, max_size: u32) -> PgPool {
    Pool::builder(PgManager::new(opts))
        .max_size(max_size as usize)
        .runtime(deadpool::Runtime::Tokio1)
        .wait_timeout(Some(Duration::from_secs(30)))
        .create_timeout(Some(Duration::from_secs(15)))
        .recycle_timeout(Some(Duration::from_secs(5)))
        .build()
        .expect("pool build only fails on bad config")
}
