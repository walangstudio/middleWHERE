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
                    std::time::Duration::ZERO,
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

    // A denied query with a multibyte char across the 64-byte log cut used to
    // panic, aborting the daemon. The session must survive it.
    let prefix = "DELETE FROM t WHERE x='";
    let sql = format!("{prefix}{}é'", "a".repeat(63 - prefix.len()));
    assert!(!sql.is_char_boundary(64));
    assert!(conn.query_drop(sql).await.is_err());
    let v: i64 = conn.query_first("SELECT 1").await.unwrap().unwrap();
    assert_eq!(v, 1, "session survives a denied multibyte query");
}

/// Proxy in front of MYSQL_TEST_URL with a backend pool of `max_pool`.
async fn spawn_proxy(url: &str, max_pool: u32) -> std::net::SocketAddr {
    let opts = mysql_async::Opts::from_url(url).expect("valid MYSQL_TEST_URL");
    let pool = build_pool(
        BackendOpts {
            host: opts.ip_or_hostname().to_string(),
            port: opts.tcp_port(),
            user: opts.user().unwrap_or("").to_string(),
            password: mw_core::secret::SecretStr::new(opts.pass().unwrap_or("")),
            database: opts.db_name().map(|s| s.to_string()),
        },
        max_pool,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = ClientAuth::NativePassword {
        double_sha1: double_sha1(CLIENT_TOKEN.as_bytes()),
    };
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let (auth, pool) = (auth.clone(), pool.clone());
            tokio::spawn(async move {
                let Ok(s) = handshake(&mut sock, "stage_w9", &auth, 1).await else {
                    return;
                };
                let _ = serve_session(
                    &mut sock,
                    "stage_w9",
                    &s.client_username_seen,
                    &pool,
                    &Policy::Custom {
                        allow_dml: true,
                        allow_ddl: true,
                        allow_admin: false,
                    },
                    std::time::Duration::ZERO,
                )
                .await;
            });
        }
    });
    addr
}

async fn client(addr: std::net::SocketAddr) -> Conn {
    Conn::new(
        OptsBuilder::default()
            .ip_or_hostname(addr.ip().to_string())
            .tcp_port(addr.port())
            .user(Some("stage_w9"))
            .pass(Some(CLIENT_TOKEN))
            .stmt_cache_size(0),
    )
    .await
    .expect("connect through proxy")
}

/// Session state must stay inside its session: pinned for the session's
/// lifetime, never handed to the next client. Pool size 1 forces reuse of the
/// same backend connection if the proxy were still pooling per statement.
#[tokio::test]
async fn session_state_is_pinned_and_never_leaks_to_the_next_client() {
    let Some(url) = backend_url() else {
        eprintln!("skipping: MYSQL_TEST_URL not set");
        return;
    };
    let addr = spawn_proxy(&url, 1).await;

    let mut a = client(addr).await;
    a.query_drop("SET time_zone = '+05:00'").await.unwrap();
    let tz: String = a
        .query_first("SELECT @@session.time_zone")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tz, "+05:00", "SET must stick within the session");
    a.disconnect().await.unwrap();

    let mut b = client(addr).await;
    let tz: String = b
        .query_first("SELECT @@session.time_zone")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(tz, "+05:00", "session A's SET leaked into session B");

    // A transaction must run on one connection: the rollback undoes the insert.
    b.query_drop("CREATE TEMPORARY TABLE mw_tx (x INT) ENGINE=InnoDB")
        .await
        .unwrap();
    b.query_drop("BEGIN").await.unwrap();
    b.query_drop("INSERT INTO mw_tx VALUES (1)").await.unwrap();
    b.query_drop("ROLLBACK").await.unwrap();
    let n: i64 = b
        .query_first("SELECT COUNT(*) FROM mw_tx")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0, "ROLLBACK must undo the INSERT on the same connection");

    // Writes report what they did: ORMs check row counts and generated keys.
    b.query_drop("INSERT INTO mw_tx VALUES (1), (2)")
        .await
        .unwrap();
    assert_eq!(b.affected_rows(), 2);
    b.query_drop("CREATE TEMPORARY TABLE mw_ai (id INT AUTO_INCREMENT PRIMARY KEY, x INT)")
        .await
        .unwrap();
    b.query_drop("INSERT INTO mw_ai (x) VALUES (7)")
        .await
        .unwrap();
    assert_eq!(b.last_insert_id(), Some(1));

    // The server's error code survives, so drivers can tell a duplicate key
    // (or a deadlock) from a proxy failure.
    let dup = b
        .query_drop("INSERT INTO mw_ai (id, x) VALUES (1, 8)")
        .await
        .unwrap_err();
    match dup {
        mysql_async::Error::Server(se) => {
            assert_eq!((se.code, se.state.as_str()), (1062, "23000"));
            assert!(
                !se.message.contains("Duplicate"),
                "message must stay hidden"
            );
        }
        e => panic!("expected a server error, got {e}"),
    }
}

/// A backend configured with lexer-changing sql_mode flags must still lex like
/// the firewall: the proxy strips them on every backend connection. Under
/// ANSI_QUOTES, `"a\"` would be an identifier and the rest of the line code.
#[tokio::test]
async fn backend_lexer_modes_are_neutralized() {
    let Some(url) = backend_url() else {
        eprintln!("skipping: MYSQL_TEST_URL not set");
        return;
    };
    let mut admin = Conn::new(mysql_async::Opts::from_url(&url).unwrap())
        .await
        .unwrap();
    let saved: String = admin
        .query_first("SELECT @@GLOBAL.sql_mode")
        .await
        .unwrap()
        .unwrap();
    admin
        .query_drop("SET GLOBAL sql_mode = 'ANSI,NO_BACKSLASH_ESCAPES'")
        .await
        .unwrap();

    // Restore the shared server's mode before any assertion can panic.
    let observed = async {
        let addr = spawn_proxy(&url, 1).await;
        // No panicking helpers in here: the restore below must always run.
        let mut c = Conn::new(
            OptsBuilder::default()
                .ip_or_hostname(addr.ip().to_string())
                .tcp_port(addr.port())
                .user(Some("stage_w9"))
                .pass(Some(CLIENT_TOKEN))
                .stmt_cache_size(0),
        )
        .await?;
        let mode: Option<String> = c.query_first("SELECT @@SESSION.sql_mode").await?;
        let one: Vec<mysql_async::Row> = c.query(r#"SELECT "a\" , 2 -- ""#).await?;
        Ok::<_, mysql_async::Error>((mode, one))
    }
    .await;
    admin
        .query_drop(format!("SET GLOBAL sql_mode = '{saved}'"))
        .await
        .unwrap();
    let (mode, one) = observed.unwrap();
    let mode = mode.unwrap();
    for bad in ["ANSI_QUOTES", "NO_BACKSLASH_ESCAPES"] {
        assert!(!mode.contains(bad), "{bad} survived: {mode}");
    }
    assert!(
        !mode.split(',').any(|m| m == "ANSI"),
        "ANSI survived: {mode}"
    );
    assert_eq!(
        one[0].len(),
        1,
        "the quoted text must stay one string column"
    );
}
