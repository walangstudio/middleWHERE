//! End-to-end daemon test: init → load → bind → connect → shutdown.
//!
//! Uses a temp state dir + FileStore master key so it runs everywhere
//! (CI without DPAPI/Keychain/D-Bus). The backend portion runs only when
//! MYSQL_TEST_URL is set; without it, the test stops after asserting that
//! init/load/bind succeed and a graceful shutdown completes in time.

use std::collections::BTreeMap;
use std::time::Duration;

use mysql_async::{prelude::Queryable, Conn, OptsBuilder};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use mw_core::config::*;
use mw_core::keyring::{FileStore, MasterKeyStore};
use mw_core::seal::{seal, MasterKey, Passphrase};
use mw_core::secret::SecretStr;
use mw_core::token::double_sha1;
use mwsqld::{Daemon, KeystoreChoice, CONFIG_FILE_NAME};

const TOKEN: &str = "daemon-test-token-9f7a1d";

async fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn build_state(
    state_dir: &std::path::Path,
    env_name: &str,
    port: u16,
    backend_url: Option<&str>,
) -> KeystoreChoice {
    std::fs::create_dir_all(state_dir).unwrap();

    let mk = MasterKey::generate();
    let ks = KeystoreChoice::default_file(state_dir);
    if let KeystoreChoice::File { path } = &ks {
        FileStore::new(path).store(&mk).unwrap();
    }

    // Minimal Config. When MYSQL_TEST_URL is set, point the env at it;
    // otherwise use a placeholder that won't be reached (no connect attempt).
    let (backend_host, backend_port, backend_user, backend_pw, db) = match backend_url {
        Some(url) => {
            let o = mysql_async::Opts::from_url(url).expect("MYSQL_TEST_URL");
            (
                o.ip_or_hostname().to_string(),
                o.tcp_port(),
                o.user().unwrap_or("").to_string(),
                o.pass().unwrap_or("").to_string(),
                o.db_name().map(|s| s.to_string()),
            )
        }
        None => (
            "127.0.0.1".to_string(),
            3306,
            "noop".into(),
            "noop".into(),
            None,
        ),
    };

    let mut credentials = BTreeMap::new();
    credentials.insert(
        "only".to_string(),
        Credential {
            backend_user,
            backend_password: SecretStr::new(backend_pw),
        },
    );
    let mut envs = BTreeMap::new();
    envs.insert(
        env_name.to_string(),
        Env {
            backend_host,
            backend_port,
            default_database: db,
            bastion: None,
            credential: "only".into(),
            policy: Policy::ReadOnly,
            client_auth: ClientAuth::NativePassword {
                double_sha1: double_sha1(TOKEN.as_bytes()),
            },
            listen_port: port,
            pool: PoolSettings::default(),
            engine: mw_core::config::EngineKind::MySql,
        },
    );
    let cfg = Config {
        schema_version: CURRENT_SCHEMA_VERSION,
        bastions: BTreeMap::new(),
        credentials,
        envs,
    };

    let blob = seal(&cfg, &mk, &Passphrase::default()).unwrap();
    std::fs::write(state_dir.join(CONFIG_FILE_NAME), blob).unwrap();
    ks
}

#[tokio::test]
async fn init_load_bind_shutdown_no_backend() {
    let tmp = TempDir::new().unwrap();
    let port = pick_free_port().await;
    let ks = build_state(tmp.path(), "stage_w9", port, None);

    let cfg = mwsqld::load_config(tmp.path(), &ks).unwrap();
    let daemon = Daemon::bind(tmp.path().to_path_buf(), &cfg, "127.0.0.1", false, ks)
        .await
        .unwrap();
    assert_eq!(daemon.env_count().await, 1);

    let (tx, rx) = broadcast::channel(1);
    let h = tokio::spawn(daemon.run(rx));
    tokio::time::sleep(Duration::from_millis(100)).await;
    tx.send(()).unwrap();
    // Shutdown should complete within a reasonable window even with no traffic.
    tokio::time::timeout(Duration::from_secs(2), h)
        .await
        .expect("shutdown timed out")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn end_to_end_through_real_backend() {
    let Some(url) = std::env::var("MYSQL_TEST_URL").ok() else {
        eprintln!("skipping: MYSQL_TEST_URL not set");
        return;
    };
    let tmp = TempDir::new().unwrap();
    let port = pick_free_port().await;
    let ks = build_state(tmp.path(), "stage_w9", port, Some(&url));

    // This test asserts on the audit JSONL, so it must own the audit
    // subscriber. Daemon::bind no longer installs it (that's the binary's
    // job); install it here and hold the guard past the file assertion.
    let _audit = mwsqld::install_audit(tmp.path()).unwrap();

    let cfg = mwsqld::load_config(tmp.path(), &ks).unwrap();
    let daemon = Daemon::bind(tmp.path().to_path_buf(), &cfg, "127.0.0.1", false, ks)
        .await
        .unwrap();
    let (tx, rx) = broadcast::channel(1);
    let h = tokio::spawn(daemon.run(rx));

    // Wait briefly for the accept loop to be ready.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let opts: mysql_async::Opts = OptsBuilder::default()
        .ip_or_hostname("127.0.0.1")
        .tcp_port(port)
        .user(Some("stage_w9"))
        .pass(Some(TOKEN))
        .stmt_cache_size(0)
        .into();
    let mut conn = Conn::new(opts).await.expect("connect via daemon");
    let v: i64 = conn.query_first("SELECT 1").await.unwrap().unwrap();
    assert_eq!(v, 1);
    drop(conn);

    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), h)
        .await
        .expect("shutdown timed out")
        .unwrap()
        .unwrap();

    // Audit log should have at least one allow record.
    let audit_dir = tmp.path().join("audit");
    let entry = std::fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().starts_with("audit.jsonl"));
    if let Some(entry) = entry {
        let body = std::fs::read_to_string(entry.path()).unwrap_or_default();
        assert!(
            body.contains("\"decision\":\"allow\""),
            "expected an allow event in audit log, got: {body}"
        );
    }
}

#[tokio::test]
async fn init_refuses_to_overwrite() {
    let tmp = TempDir::new().unwrap();
    let ks = KeystoreChoice::default_file(tmp.path());
    mwsqld::init(tmp.path(), &ks).unwrap();
    let err = mwsqld::init(tmp.path(), &ks).unwrap_err();
    assert!(err.to_string().contains("already exists"));
}
