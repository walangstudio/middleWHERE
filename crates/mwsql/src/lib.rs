//! Client-side credential store + query runner for the `mwsql` wrapper.
//!
//! The wrapper is deliberately dumb: it holds no policy logic (the daemon's
//! AST firewall is the enforcement point) and never sees real DB
//! credentials. All it knows per env is `{token, host, port}` — minted by
//! `mwsqlctl grant`, delivered out-of-band, and stored by `mwsql
//! login` into the *client user's own* keyring (a different OS principal
//! than the daemon).

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Everything the wrapper needs to reach an env. Stored as JSON in one
/// keyring secret per env.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCred {
    pub token: String,
    pub host: String,
    pub port: u16,
}

pub trait ClientTokenStore {
    fn save(&self, env: &str, cred: &StoredCred) -> Result<()>;
    fn load(&self, env: &str) -> Result<StoredCred>;
    fn delete(&self, env: &str) -> Result<()>;
}

/// OS keyring backend. One entry per env under service `middlewhere-client`,
/// account = env name, secret = JSON-encoded [`StoredCred`].
pub struct OsClientStore {
    service: String,
}

impl OsClientStore {
    pub fn new() -> Self {
        Self {
            service: "middlewhere-client".into(),
        }
    }
    fn entry(&self, env: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, env).map_err(|e| anyhow!("keyring entry: {e}"))
    }
}

impl Default for OsClientStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientTokenStore for OsClientStore {
    fn save(&self, env: &str, cred: &StoredCred) -> Result<()> {
        let json = serde_json::to_string(cred)?;
        self.entry(env)?
            .set_password(&json)
            .map_err(|e| anyhow!("keyring set: {e}"))
    }
    fn load(&self, env: &str) -> Result<StoredCred> {
        let json = self.entry(env)?.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => {
                anyhow!("no credentials for env {env:?}; run: mwsql login {env} --port <p>")
            }
            other => anyhow!("keyring get: {other}"),
        })?;
        serde_json::from_str(&json).context("decode stored credential")
    }
    fn delete(&self, env: &str) -> Result<()> {
        match self.entry(env)?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow!("keyring delete: {e}")),
        }
    }
}

/// File backend: `<dir>/<env>.json`. Used in tests and as a fallback for
/// headless client environments without a secret service.
pub struct FileClientStore {
    dir: std::path::PathBuf,
}

impl FileClientStore {
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
    fn path(&self, env: &str) -> std::path::PathBuf {
        self.dir.join(format!("{env}.json"))
    }
}

impl ClientTokenStore for FileClientStore {
    fn save(&self, env: &str, cred: &StoredCred) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let p = self.path(env);
        write_private(&p, serde_json::to_string(cred)?.as_bytes())?;
        Ok(())
    }
    fn load(&self, env: &str) -> Result<StoredCred> {
        let p = self.path(env);
        let body = std::fs::read_to_string(&p).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow!("no credentials for env {env:?}; run: mwsql login {env} --port <p>")
            } else {
                anyhow!("read {}: {e}", p.display())
            }
        })?;
        serde_json::from_str(&body).context("decode stored credential")
    }
    fn delete(&self, env: &str) -> Result<()> {
        match std::fs::remove_file(self.path(env)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(anyhow!("delete: {e}")),
        }
    }
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

/// Connect as `env_name` with the stored token, run `sql`, render results.
/// The wrapper sends SQL verbatim — the daemon's policy engine is the gate.
pub async fn run_sql_as(
    env_name: &str,
    cred: &StoredCred,
    database: Option<&str>,
    sql: &str,
) -> Result<String> {
    use mysql_async::prelude::Queryable;
    use mysql_async::{Conn, OptsBuilder, Value};

    let mut b = OptsBuilder::default()
        .ip_or_hostname(cred.host.clone())
        .tcp_port(cred.port)
        .user(Some(env_name.to_string()))
        .pass(Some(cred.token.clone()))
        .stmt_cache_size(0);
    if let Some(db) = database {
        b = b.db_name(Some(db.to_string()));
    }
    let mut conn = Conn::new(b).await.with_context(|| "connect to proxy")?;
    let mut qr = conn
        .query_iter(sql.to_string())
        .await
        .with_context(|| "query rejected")?;

    let cols = qr.columns().map(|a| a.to_vec());
    let out = match cols {
        Some(c) if !c.is_empty() => {
            let headers: Vec<String> = c.iter().map(|x| x.name_str().to_string()).collect();
            let mut rows: Vec<Vec<String>> = Vec::new();
            while let Some(r) = qr.next().await? {
                let mut cells = Vec::with_capacity(headers.len());
                for i in 0..r.len() {
                    let v: &Value = r.as_ref(i).unwrap();
                    cells.push(render_value(v));
                }
                rows.push(cells);
            }
            render_table(&headers, &rows)
        }
        _ => {
            let _ = qr.drop_result().await;
            "OK".to_string()
        }
    };
    Ok(out)
}

fn render_value(v: &mysql_async::Value) -> String {
    use mysql_async::Value::*;
    match v {
        NULL => "NULL".into(),
        Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        Int(n) => n.to_string(),
        UInt(n) => n.to_string(),
        Float(f) => f.to_string(),
        Double(d) => d.to_string(),
        Date(y, mo, d, h, mi, s, _) => format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}"),
        Time(neg, d, h, mi, s, _) => format!(
            "{}{}:{:02}:{:02}:{:02}",
            if *neg { "-" } else { "" },
            d,
            h,
            mi,
            s
        ),
    }
}

fn render_table(headers: &[String], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(c.len());
            }
        }
    }
    let line = |cells: &[String]| -> String {
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{:<w$}", c, w = widths.get(i).copied().unwrap_or(0)))
            .collect::<Vec<_>>()
            .join("  ")
    };
    let mut s = String::new();
    s.push_str(&line(headers));
    s.push('\n');
    s.push_str(&"-".repeat(widths.iter().sum::<usize>() + 2 * widths.len().saturating_sub(1)));
    for r in rows {
        s.push('\n');
        s.push_str(&line(r));
    }
    s.push_str(&format!(
        "\n({} row{})",
        rows.len(),
        if rows.len() == 1 { "" } else { "s" }
    ));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileClientStore::new(tmp.path());
        let cred = StoredCred {
            token: "tk-123".into(),
            host: "127.0.0.1".into(),
            port: 6033,
        };
        store.save("stage_w9", &cred).unwrap();
        assert_eq!(store.load("stage_w9").unwrap(), cred);
        store.delete("stage_w9").unwrap();
        assert!(store.load("stage_w9").is_err());
        // delete is idempotent
        store.delete("stage_w9").unwrap();
    }

    #[test]
    fn missing_env_has_actionable_message() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileClientStore::new(tmp.path());
        let err = store.load("nope").unwrap_err().to_string();
        assert!(err.contains("mwsql login nope"), "{err}");
    }

    #[test]
    fn stored_cred_json_is_stable() {
        let c = StoredCred {
            token: "t".into(),
            host: "127.0.0.1".into(),
            port: 1,
        };
        let j = serde_json::to_string(&c).unwrap();
        assert_eq!(j, r#"{"token":"t","host":"127.0.0.1","port":1}"#);
    }

    #[test]
    fn table_render_basic() {
        let t = render_table(
            &["id".into(), "name".into()],
            &[
                vec!["1".into(), "alice".into()],
                vec!["2".into(), "bob".into()],
            ],
        );
        assert!(t.contains("id"));
        assert!(t.contains("alice"));
        assert!(t.contains("(2 rows)"));
    }
}
