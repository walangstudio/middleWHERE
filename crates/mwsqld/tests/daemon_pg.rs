//! End-to-end Postgres engine test. Gated on PG_TEST_URL
//! (postgres://user:pass@host:port/db). Without it, only the no-backend
//! bind/shutdown path runs.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use mw_core::config::*;
use mw_core::keyring::{FileStore, MasterKeyStore};
use mw_core::seal::{seal, MasterKey, Passphrase};
use mw_core::secret::SecretStr;
use mw_core::token::sha256;
use mwsqld::{Daemon, KeystoreChoice, CONFIG_FILE_NAME};

const TOKEN: &str = "pg-daemon-test-token-3f9a2c";

async fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn build_pg_state(
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

    let (host, bport, user, pw, db) = match backend_url {
        Some(url) => {
            let c = tokio_postgres::Config::from_str(url).expect("valid PG_TEST_URL");
            let host = match c.get_hosts().first().expect("host") {
                tokio_postgres::config::Host::Tcp(h) => h.clone(),
                #[allow(unreachable_patterns)]
                _ => "127.0.0.1".to_string(),
            };
            let bport = *c.get_ports().first().unwrap_or(&5432);
            (
                host,
                bport,
                c.get_user().unwrap_or("").to_string(),
                String::from_utf8_lossy(c.get_password().unwrap_or(b"")).into_owned(),
                c.get_dbname().map(|s| s.to_string()),
            )
        }
        None => ("127.0.0.1".into(), 5432, "noop".into(), "noop".into(), None),
    };

    let mut credentials = BTreeMap::new();
    credentials.insert(
        "only".to_string(),
        Credential {
            backend_user: user,
            backend_password: SecretStr::new(pw),
        },
    );
    let mut envs = BTreeMap::new();
    envs.insert(
        env_name.to_string(),
        Env {
            backend_host: host,
            backend_port: bport,
            default_database: db,
            bastion: None,
            credential: "only".into(),
            policy: Policy::ReadOnly,
            client_auth: ClientAuth::PgCleartext {
                sha256: sha256(TOKEN.as_bytes()),
            },
            listen_port: port,
            pool: PoolSettings::default(),
            engine: EngineKind::Postgres,
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
async fn pg_bind_shutdown_no_backend() {
    let tmp = TempDir::new().unwrap();
    let port = pick_free_port().await;
    let ks = build_pg_state(tmp.path(), "pg_env", port, None);

    let cfg = mwsqld::load_config(tmp.path(), &ks).unwrap();
    let daemon = Daemon::bind(tmp.path().to_path_buf(), &cfg, "127.0.0.1", false, ks)
        .await
        .unwrap();
    assert_eq!(daemon.env_count().await, 1);

    let (tx, rx) = broadcast::channel(1);
    let h = tokio::spawn(std::sync::Arc::new(daemon).run(rx));
    tokio::time::sleep(Duration::from_millis(100)).await;
    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), h)
        .await
        .expect("shutdown timed out")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn pg_end_to_end_through_real_backend() {
    let Some(url) = std::env::var("PG_TEST_URL").ok() else {
        eprintln!("skipping: PG_TEST_URL not set");
        return;
    };
    let tmp = TempDir::new().unwrap();
    let port = pick_free_port().await;
    let ks = build_pg_state(tmp.path(), "pg_env", port, Some(&url));
    let cfg = mwsqld::load_config(tmp.path(), &ks).unwrap();
    let daemon = Daemon::bind(tmp.path().to_path_buf(), &cfg, "127.0.0.1", false, ks)
        .await
        .unwrap();
    let (tx, rx) = broadcast::channel(1);
    let h = tokio::spawn(std::sync::Arc::new(daemon).run(rx));
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Happy path: connect with the env name as user and the token as
    // password; an allowed SELECT returns a row.
    let conn_str =
        format!("host=127.0.0.1 port={port} user=pg_env password={TOKEN} dbname=postgres");
    let (client, connection) = tokio_postgres::connect(&conn_str, tokio_postgres::NoTls)
        .await
        .expect("connect through proxy");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let rows = client
        .simple_query("SELECT 1 AS one")
        .await
        .expect("select");
    let got = rows.iter().any(|m| {
        matches!(
            m, tokio_postgres::SimpleQueryMessage::Row(r) if r.get(0) == Some("1")
        )
    });
    assert!(got, "expected SELECT 1 to return 1 through the proxy");

    // Firewall: a write under ReadOnly must be rejected by the proxy.
    let err = client.simple_query("DROP TABLE IF EXISTS x").await;
    assert!(err.is_err(), "DROP must be denied by the firewall");

    // Extended query protocol (Parse/Bind/Describe/Execute) with a bound
    // scalar parameter — the path DBeaver/pgjdbc use.
    let row = client
        .query_one("SELECT ($1::int + 1) AS v", &[&41i32])
        .await
        .expect("extended scalar param");
    let v: i32 = row.get("v");
    assert_eq!(v, 42, "extended-protocol scalar param failed");

    // Binary array bind parameter via `= ANY($1)` (catalog-introspection
    // pattern). Exercises decode_bin_array end-to-end against real PG.
    let arr: Vec<i32> = vec![1, 3];
    let rows = client
        .query(
            "SELECT x FROM (VALUES (1),(2),(3)) t(x) WHERE x = ANY($1) ORDER BY x",
            &[&arr],
        )
        .await
        .expect("extended array param");
    let got: Vec<i32> = rows.iter().map(|r| r.get::<_, i32>("x")).collect();
    assert_eq!(got, vec![1, 3], "array ANY param failed");

    // Firewall still applies on the extended path.
    assert!(
        client
            .execute("CREATE TABLE evil(x int)", &[])
            .await
            .is_err(),
        "DDL must be denied on the extended path too"
    );

    // Wrong token must fail authentication.
    let bad = format!("host=127.0.0.1 port={port} user=pg_env password=wrong dbname=postgres");
    assert!(
        tokio_postgres::connect(&bad, tokio_postgres::NoTls)
            .await
            .is_err(),
        "wrong token must be rejected"
    );

    tx.send(()).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
}
