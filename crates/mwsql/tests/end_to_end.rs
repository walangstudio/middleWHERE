//! Full client chain: init → cred/env add → grant → FileClientStore login →
//! `mwsql::run_sql_as` through a live Daemon → SELECT 1.
//!
//! Gated on MYSQL_TEST_URL (the daemon needs a real backend to forward to).
//! Without it the test asserts the offline half — grant produces a token the
//! sealed config authenticates, and the client store round-trips it — then
//! returns.

use std::time::Duration;

use mw_core::config::Policy;
use mw_core::secret::SecretStr;
use mw_core::state::KeystoreChoice;
use mwsql::{ClientTokenStore, FileClientStore, StoredCred};
use mwsqlctl::{cred, envs};
use tempfile::TempDir;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_chain() {
    let tmp = TempDir::new().unwrap();
    let ks = KeystoreChoice::default_file(tmp.path());
    mw_core::state::init(tmp.path(), &ks).unwrap();

    // Point the env at MYSQL_TEST_URL if present; otherwise a placeholder
    // (the offline assertions don't connect).
    let (bh, bp, bu, bpw, bdb) = match std::env::var("MYSQL_TEST_URL").ok() {
        Some(url) => {
            let o = mysql_async::Opts::from_url(&url).expect("MYSQL_TEST_URL");
            (
                o.ip_or_hostname().to_string(),
                o.tcp_port(),
                o.user().unwrap_or("").to_string(),
                o.pass().unwrap_or("").to_string(),
                o.db_name().map(|s| s.to_string()),
            )
        }
        None => ("127.0.0.1".into(), 3306, "noop".into(), "noop".into(), None),
    };

    cred::add(tmp.path(), &ks, "c", &bu, SecretStr::new(bpw)).unwrap();
    let listen_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    envs::add(
        tmp.path(),
        &ks,
        envs::EnvAddArgs {
            name: "stage_w9",
            backend_host: &bh,
            backend_port: bp,
            default_database: bdb.as_deref(),
            bastion: None,
            credential: "c",
            policy: Policy::ReadOnly,
            listen_port: Some(listen_port),
            max_pool: None,
            engine: Default::default(),
        },
    )
    .unwrap();

    // grant → token; login stores {token,host,port} in the client store.
    let granted = envs::grant(tmp.path(), &ks, "stage_w9").unwrap();
    let store = FileClientStore::new(tmp.path().join("client"));
    store
        .save(
            "stage_w9",
            &StoredCred {
                token: granted.token.expose().to_string(),
                host: "127.0.0.1".into(),
                port: granted.listen_port,
            },
        )
        .unwrap();

    // Offline assertion: the stored token authenticates against the sealed
    // config's stored hash.
    let cfg = mw_core::state::load_config(tmp.path(), &ks).unwrap();
    let stored_cred = store.load("stage_w9").unwrap();
    match &cfg.envs.get("stage_w9").unwrap().client_auth {
        mw_core::config::ClientAuth::NativePassword { double_sha1 } => {
            assert_eq!(
                *double_sha1,
                mw_core::token::double_sha1(stored_cred.token.as_bytes())
            );
        }
        other => panic!("expected native password, got {other:?}"),
    }
    assert_eq!(stored_cred.port, listen_port);

    if std::env::var("MYSQL_TEST_URL").is_err() {
        eprintln!("offline half passed; skipping live query (MYSQL_TEST_URL unset)");
        return;
    }

    // Live half: bring up the daemon and run SELECT 1 via the wrapper.
    let cfg_loaded = mwsqld::load_config(tmp.path(), &ks).unwrap();
    let daemon = mwsqld::Daemon::bind(
        tmp.path().to_path_buf(),
        &cfg_loaded,
        "127.0.0.1",
        false,
        ks.clone(),
    )
    .await
    .unwrap();
    let (txc, rx) = tokio::sync::broadcast::channel(1);
    let h = tokio::spawn(std::sync::Arc::new(daemon).run(rx));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let out = mwsql::run_sql_as("stage_w9", &stored_cred, None, "SELECT 1 AS one")
        .await
        .expect("query via wrapper");
    assert!(out.contains("one"), "header missing: {out}");
    assert!(out.contains('1'), "value missing: {out}");
    assert!(out.contains("(1 row)"), "row count missing: {out}");

    txc.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), h)
        .await
        .expect("shutdown timed out")
        .unwrap()
        .unwrap();
}
