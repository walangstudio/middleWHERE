//! Bastion tunneling end-to-end test against an in-process russh server.
//!
//! Topology:
//!     tokio TCP client
//!         └── 127.0.0.1:<local_fwd_port>     <-- LocalForward (our code)
//!              └── russh client session       <-- BastionSession (our code)
//!                   └── in-process russh server (this file)
//!                        └── direct-tcpip to 127.0.0.1:<echo_port>
//!                             └── echo TcpListener (this file)
//!
//! Asserts a write/read round-trip through the full chain, plus that a
//! mismatched pinned fingerprint refuses to connect.

use std::sync::Arc;

use russh::keys::PrivateKey;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use mw_core::config::{Bastion, BastionAuth, HostKeyFingerprint};
use mw_core::secret::SecretStr;
use mw_net::ssh::{start_local_forward, BastionRegistry};

const SSH_USER: &str = "tester";
const SSH_PASSWORD: &str = "tunnel-pw-9f7a1d";

/// Fixed Ed25519 OpenSSH-format key generated with `ssh-keygen -t ed25519`.
/// Test-only — never used outside this file.
const TEST_HOST_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBjYB3+5hdIxwZUQWix9vH/LSQ2C+nvZaftFvADx4FEMgAAAJDWMN3Q1jDd
0AAAAAtzc2gtZWQyNTUxOQAAACBjYB3+5hdIxwZUQWix9vH/LSQ2C+nvZaftFvADx4FEMg
AAAEBc1+jlhd4Rab8V08LKYQ66QNsuuZIn9lArqKEKd08EUGNgHf7mF0jHBlRBaLH28f8t
JDYL6e9lp+0W8APHgUQyAAAACXRlc3Qtb25seQECAwQ=
-----END OPENSSH PRIVATE KEY-----
";

/// Run a tiny TCP echo server on 127.0.0.1:0 in a background task. Returns
/// the port it bound to.
async fn spawn_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _peer)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() { return; }
                        }
                    }
                }
            });
        }
    });
    port
}

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

    async fn channel_eof(&mut self, _channel: ChannelId, _session: &mut Session)
        -> Result<(), Self::Error>
    { Ok(()) }
}

/// Spawn the russh server. Returns (port, host_key_fingerprint).
async fn spawn_sshd() -> (u16, HostKeyFingerprint) {
    let host_key = PrivateKey::from_openssh(TEST_HOST_KEY).unwrap();
    let public = host_key.public_key().clone();

    // Compute the same fingerprint our client handler produces.
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let blob = public.to_bytes().unwrap();
    let digest = Sha256::digest(&blob);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    let fp = HostKeyFingerprint { algo: public.algorithm().to_string(), sha256_b64: b64 };

    let config = Arc::new(server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(30)),
        auth_rejection_time: std::time::Duration::from_millis(10),
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

async fn build_bastion(host_port: u16, pinned: Vec<HostKeyFingerprint>) -> Bastion {
    Bastion {
        host: "127.0.0.1".into(),
        port: host_port,
        ssh_user: SSH_USER.into(),
        auth: BastionAuth::Password { password: SecretStr::new(SSH_PASSWORD) },
        pinned_host_keys: pinned,
    }
}

#[tokio::test]
async fn round_trip_through_tunnel() {
    let echo_port = spawn_echo_server().await;
    let (sshd_port, real_fp) = spawn_sshd().await;

    let bastion = build_bastion(sshd_port, vec![real_fp.clone()]).await;
    let registry = BastionRegistry::new();
    let slot = registry.get_or_open("test", &bastion, false).await.unwrap();

    let fwd = start_local_forward(slot, "127.0.0.1".to_string(), echo_port).await.unwrap();

    let mut client = TcpStream::connect(("127.0.0.1", fwd.local_port)).await.unwrap();
    client.write_all(b"hello-through-bastion").await.unwrap();
    let mut buf = [0u8; 32];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello-through-bastion");
}

#[tokio::test]
async fn fingerprint_mismatch_refuses_connection() {
    let (sshd_port, _real_fp) = spawn_sshd().await;
    let bogus = HostKeyFingerprint {
        algo: "ssh-ed25519".into(),
        sha256_b64: "not-the-right-fingerprint".into(),
    };
    let bastion = build_bastion(sshd_port, vec![bogus]).await;
    let registry = BastionRegistry::new();
    let res = registry.get_or_open("test", &bastion, false).await;
    let Err(err) = res else { panic!("expected refusal on fingerprint mismatch"); };
    let msg = format!("{err:#}");
    // russh surfaces this as either an auth/disconnect error.
    assert!(
        msg.to_lowercase().contains("key") || msg.to_lowercase().contains("disconnect")
            || msg.to_lowercase().contains("refuse") || msg.to_lowercase().contains("auth"),
        "unexpected error: {msg}",
    );
}

#[tokio::test]
async fn wrong_password_refuses_auth() {
    let (sshd_port, real_fp) = spawn_sshd().await;
    let mut b = build_bastion(sshd_port, vec![real_fp]).await;
    b.auth = BastionAuth::Password { password: SecretStr::new("wrong") };
    let registry = BastionRegistry::new();
    let res = registry.get_or_open("test", &b, false).await;
    let Err(err) = res else { panic!("expected refusal on wrong password"); };
    let msg = format!("{err:#}");
    assert!(msg.to_lowercase().contains("auth"), "unexpected error: {msg}");
}

#[tokio::test]
async fn empty_pin_list_refused_by_default() {
    let (sshd_port, _fp) = spawn_sshd().await;
    let bastion = build_bastion(sshd_port, vec![]).await; // no pinned keys
    let registry = BastionRegistry::new();
    let res = registry.get_or_open("test", &bastion, false).await;
    assert!(res.is_err(), "unpinned bastion must be refused without --allow-tofu");
}

#[tokio::test]
async fn empty_pin_list_accepted_with_allow_tofu() {
    let echo_port = spawn_echo_server().await;
    let (sshd_port, _fp) = spawn_sshd().await;
    let bastion = build_bastion(sshd_port, vec![]).await; // no pinned keys
    let registry = BastionRegistry::new();
    let slot = registry.get_or_open("test", &bastion, true).await
        .expect("allow_tofu must accept first-use");
    let fwd = start_local_forward(slot, "127.0.0.1".to_string(), echo_port).await.unwrap();
    let mut client = TcpStream::connect(("127.0.0.1", fwd.local_port)).await.unwrap();
    client.write_all(b"tofu-ok").await.unwrap();
    let mut buf = [0u8; 16];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"tofu-ok");
}
