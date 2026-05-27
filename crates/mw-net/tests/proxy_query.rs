//! End-to-end test against a real MySQL backend.
//!
//! Skipped by default. Set MYSQL_TEST_URL=mysql://user:pass@host:port/db
//! to run. Spins up the proxy on 127.0.0.1:0 in front of the backend, then
//! connects through it with mysql_async and runs a SELECT.

use std::env;

use mysql_async::{prelude::Queryable, Conn, OptsBuilder, Pool as MyPool};

use mw_core::config::{ClientAuth, Policy};
use mw_core::token::double_sha1;
use mw_net::mysql_client::{build_pool, BackendOpts};
use mw_net::mysql_server::handshake;
use mw_net::router::serve_session;

const CLIENT_TOKEN: &str = "test-token-9f7a1d";

fn backend_url() -> Option<String> {
    env::var("MYSQL_TEST_URL").ok()
}

#[tokio::test]
async fn proxy_select_one_through_real_backend() {
    let Some(url) = backend_url() else {
        eprintln!("skipping: MYSQL_TEST_URL not set");
        return;
    };

    let opts = mysql_async::Opts::from_url(&url).expect("valid MYSQL_TEST_URL");
    let backend = BackendOpts {
        host: opts.ip_or_hostname().to_string(),
        port: opts.tcp_port(),
        user: opts.user().unwrap_or("").to_string(),
        password: mw_core::secret::SecretStr::new(opts.pass().unwrap_or("")),
        database: opts.db_name().map(|s| s.to_string()),
    };
    let pool = build_pool(backend, 4);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = ClientAuth::NativePassword {
        double_sha1: double_sha1(CLIENT_TOKEN.as_bytes()),
    };
    let pol = Policy::ReadOnly;

    tokio::spawn(async move {
        // Serve connections in a loop — the test opens more than one.
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            sock.set_nodelay(true).ok();
            let auth = auth.clone();
            let pool = pool.clone();
            let pol = pol.clone();
            tokio::spawn(async move {
                let Ok(session) = handshake(&mut sock, "stage_w9", &auth, 1).await else {
                    return;
                };
                let _ = serve_session(
                    &mut sock,
                    "stage_w9",
                    &session.client_username_seen,
                    &pool,
                    &pol,
                )
                .await;
            });
        }
    });

    let client_opts: mysql_async::Opts = OptsBuilder::default()
        .ip_or_hostname(addr.ip().to_string())
        .tcp_port(addr.port())
        .user(Some("stage_w9"))
        .pass(Some(CLIENT_TOKEN))
        .stmt_cache_size(0)
        .into();
    let mut conn = Conn::new(client_opts).await.expect("connect through proxy");
    let v: i64 = conn.query_first("SELECT 1").await.unwrap().unwrap();
    assert_eq!(v, 1);
    drop(conn);

    // Firewalled statement must be denied even when backend would accept it.
    let client_opts: mysql_async::Opts = OptsBuilder::default()
        .ip_or_hostname(addr.ip().to_string())
        .tcp_port(addr.port())
        .user(Some("stage_w9"))
        .pass(Some(CLIENT_TOKEN))
        .stmt_cache_size(0)
        .into();
    let _ = MyPool::new(client_opts);
    let mut conn = Conn::new(
        OptsBuilder::default()
            .ip_or_hostname(addr.ip().to_string())
            .tcp_port(addr.port())
            .user(Some("stage_w9"))
            .pass(Some(CLIENT_TOKEN))
            .stmt_cache_size(0),
    )
    .await
    .unwrap();
    let denied = conn.query_drop("DELETE FROM mysql.user WHERE 1=0").await;
    assert!(
        denied.is_err(),
        "policy must deny DELETE even on a no-op WHERE"
    );
}
