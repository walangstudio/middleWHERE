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
}

impl BackendManager {
    pub fn new(opts: BackendOpts) -> Self { Self { opts } }
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("mysql backend: {0}")]
    Mysql(#[from] mysql_async::Error),
}

impl Manager for BackendManager {
    type Type = Conn;
    type Error = BackendError;

    async fn create(&self) -> Result<Conn, BackendError> {
        Ok(Conn::new(self.opts.to_opts()).await?)
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
