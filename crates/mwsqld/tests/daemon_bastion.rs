//! Daemon end-to-end with bastion tunneling.
//!
//! Spins up an in-process russh server, configures one env to route through
//! it, then connects via mysql_async to the proxy and asserts SELECT 1.
//! Gated on MYSQL_TEST_URL — the in-process sshd needs a real MySQL to
//! direct-tcpip into.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use mysql_async::{prelude::Queryable, Conn, OptsBuilder};
use russh::keys::PrivateKey;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use mw_core::config::*;
use mw_core::keyring::{FileStore, MasterKeyStore};
use mw_core::seal::{seal, MasterKey, Passphrase};
use mw_core::secret::SecretStr;
use mw_core::token::double_sha1;
use mwsqld::{Daemon, KeystoreChoice, CONFIG_FILE_NAME};

const TOKEN: &str = "daemon-bastion-token-c7e1b2";
const SSH_USER: &str = "tester";
const SSH_PASSWORD: &str = "tunnel-pw-9f7a1d";

const TEST_HOST_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBjYB3+5hdIxwZUQWix9vH/LSQ2C+nvZaftFvADx4FEMgAAAJDWMN3Q1jDd
0AAAAAtzc2gtZWQyNTUxOQAAACBjYB3+5hdIxwZUQWix9vH/LSQ2C+nvZaftFvADx4FEMg
AAAEBc1+jlhd4Rab8V08LKYQ66QNsuuZIn9lArqKEKd08EUGNgHf7mF0jHBlRBaLH28f8t
JDYL6e9lp+0W8APHgUQyAAAACXRlc3Qtb25seQECAwQ=
-----END OPENSSH PRIVATE KEY-----
";

#[derive(Clone)]
struct TestSshServer;

impl server::Server for TestSshServer {
    type Handler = TestSshHandler;
    fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> TestSshHandler {
        TestSshHandler::default()
    }
}

#[derive(Default)]
struct TestSshHandler {}

impl server::Handler for TestSshHandler {
    type Error = russh::Error;
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == SSH_USER && password == SSH_PASSWORD {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let host = host_to_connect.to_string();
        let port = port_to_connect as u16;
        tokio::spawn(async move {
            let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        });
        Ok(true)
    }
    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

async fn spawn_sshd() -> (u16, HostKeyFingerprint) {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let host_key = PrivateKey::from_openssh(TEST_HOST_KEY).unwrap();
    let public = host_key.public_key().clone();
    let blob = public.to_bytes().unwrap();
    let digest = Sha256::digest(&blob);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    let fp = HostKeyFingerprint {
        algo: public.algorithm().to_string(),
        sha256_b64: b64,
    };

    let config = Arc::new(server::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        auth_rejection_time: Duration::from_millis(10),
        keys: vec![host_key],
        ..Default::default()
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let mut server = TestSshServer;
        loop {
            let (sock, peer) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let handler = server.new_client(Some(peer));
            let cfg = config.clone();
            tokio::spawn(async move {
                let _ = russh::server::run_stream(cfg, sock, handler).await;
            });
        }
    });

    (port, fp)
}

async fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

#[tokio::test]
async fn select_one_through_bastion() {
    let Some(url) = std::env::var("MYSQL_TEST_URL").ok() else {
        eprintln!("skipping: MYSQL_TEST_URL not set");
        return;
    };
    let opts = mysql_async::Opts::from_url(&url).expect("MYSQL_TEST_URL");
    let backend_host = opts.ip_or_hostname().to_string();
    let backend_port = opts.tcp_port();
    let backend_user = opts.user().unwrap_or("").to_string();
    let backend_pw = opts.pass().unwrap_or("").to_string();
    let backend_db = opts.db_name().map(|s| s.to_string());

    let (sshd_port, fp) = spawn_sshd().await;
    let tmp = TempDir::new().unwrap();
    let listen_port = pick_free_port().await;

    // Seal config with one bastion + one env that uses it.
    let mk = MasterKey::generate();
    let ks = KeystoreChoice::default_file(tmp.path());
    if let KeystoreChoice::File { path } = &ks {
        FileStore::new(path).store(&mk).unwrap();
    }
    let mut bastions = BTreeMap::new();
    bastions.insert(
        "jump".to_string(),
        Bastion {
            host: "127.0.0.1".into(),
            port: sshd_port,
            ssh_user: SSH_USER.into(),
            auth: BastionAuth::Password {
                password: SecretStr::new(SSH_PASSWORD),
            },
            pinned_host_keys: vec![fp],
        },
    );
    let mut credentials = BTreeMap::new();
    credentials.insert(
        "c".to_string(),
        Credential {
            backend_user,
            backend_password: SecretStr::new(backend_pw),
        },
    );
    let mut envs = BTreeMap::new();
    envs.insert(
        "stage_w9".to_string(),
        Env {
            backend_host,
            backend_port,
            default_database: backend_db,
            bastion: Some("jump".into()),
            credential: "c".into(),
            policy: Policy::ReadOnly,
            client_auth: ClientAuth::NativePassword {
                double_sha1: double_sha1(TOKEN.as_bytes()),
            },
            listen_port,
            pool: PoolSettings::default(),
            engine: mw_core::config::EngineKind::MySql,
        },
    );
    let cfg = Config {
        schema_version: CURRENT_SCHEMA_VERSION,
        bastions,
        credentials,
        envs,
    };
    let blob = seal(&cfg, &mk, &Passphrase::default()).unwrap();
    std::fs::write(tmp.path().join(CONFIG_FILE_NAME), blob).unwrap();

    let cfg_loaded = mwsqld::load_config(tmp.path(), &ks).unwrap();
    let daemon = Daemon::bind(
        tmp.path().to_path_buf(),
        &cfg_loaded,
        "127.0.0.1",
        false,
        ks,
    )
    .await
    .unwrap();
    let (tx, rx) = broadcast::channel(1);
    let h = tokio::spawn(std::sync::Arc::new(daemon).run(rx));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_opts: mysql_async::Opts = OptsBuilder::default()
        .ip_or_hostname("127.0.0.1")
        .tcp_port(listen_port)
        .user(Some("stage_w9"))
        .pass(Some(TOKEN))
        .stmt_cache_size(0)
        .into();
    let mut conn = Conn::new(client_opts)
        .await
        .expect("connect via daemon → bastion");
    let v: i64 = conn.query_first("SELECT 1").await.unwrap().unwrap();
    assert_eq!(v, 1);
    drop(conn);

    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), h)
        .await
        .expect("shutdown timed out")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn bind_fails_when_bastion_unreachable() {
    let tmp = TempDir::new().unwrap();
    let mk = MasterKey::generate();
    let ks = KeystoreChoice::default_file(tmp.path());
    if let KeystoreChoice::File { path } = &ks {
        FileStore::new(path).store(&mk).unwrap();
    }

    let mut bastions = BTreeMap::new();
    bastions.insert(
        "ghost".to_string(),
        Bastion {
            host: "127.0.0.1".into(),
            port: 1, // closed
            ssh_user: "x".into(),
            auth: BastionAuth::Password {
                password: SecretStr::new("x"),
            },
            pinned_host_keys: vec![],
        },
    );
    let mut credentials = BTreeMap::new();
    credentials.insert(
        "c".to_string(),
        Credential {
            backend_user: "u".into(),
            backend_password: SecretStr::new("p"),
        },
    );
    let listen_port = pick_free_port().await;
    let mut envs = BTreeMap::new();
    envs.insert(
        "e".to_string(),
        Env {
            backend_host: "127.0.0.1".into(),
            backend_port: 3306,
            default_database: None,
            bastion: Some("ghost".into()),
            credential: "c".into(),
            policy: Policy::ReadOnly,
            client_auth: ClientAuth::NativePassword {
                double_sha1: double_sha1(b"x"),
            },
            listen_port,
            pool: PoolSettings::default(),
            engine: mw_core::config::EngineKind::MySql,
        },
    );
    let cfg = Config {
        schema_version: CURRENT_SCHEMA_VERSION,
        bastions,
        credentials,
        envs,
    };
    let blob = seal(&cfg, &mk, &Passphrase::default()).unwrap();
    std::fs::write(tmp.path().join(CONFIG_FILE_NAME), blob).unwrap();

    let cfg_loaded = mwsqld::load_config(tmp.path(), &ks).unwrap();
    let res = Daemon::bind(
        tmp.path().to_path_buf(),
        &cfg_loaded,
        "127.0.0.1",
        false,
        ks,
    )
    .await;
    assert!(
        res.is_err(),
        "expected bind to fail when bastion unreachable"
    );
}
