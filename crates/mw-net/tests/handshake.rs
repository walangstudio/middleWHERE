//! Drive the real `handshake()` against an in-process fake client speaking
//! MySQL protocol over a tokio TCP pair. Covers happy path, wrong token,
//! wrong username, unsupported plugin, COM_PING reply, and COM_QUIT exit.

use mw_core::config::{ClientAuth, Policy};
use mw_core::secret::SecretStr;
use mw_core::token::{double_sha1, native_response};
use mw_net::framing::{read_packet, write_packet, SequenceCounter};
use mw_net::mysql_client::{build_pool, BackendOpts};
use mw_net::mysql_server::{handshake, testing};
use mw_net::router::serve_session;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

/// A pool pointing at an unreachable backend. The post-handshake tests here
/// only exercise COM_PING / COM_QUIT, which `serve_session` answers without
/// ever borrowing from the pool, so it is never connected.
fn dead_pool() -> mw_net::mysql_client::BackendPool {
    build_pool(
        BackendOpts {
            host: "127.0.0.1".into(),
            port: 1,
            user: "x".into(),
            password: SecretStr::new("x"),
            database: None,
        },
        1,
    )
}

/// Pull the 20-byte scramble out of an Initial Handshake Packet v10.
/// Layout: protocol(1) + server_version(NUL) + thread_id(4) + scramble_p1(8) +
/// filler(1) + caps_lo(2) + charset(1) + status(2) + caps_hi(2) +
/// auth_data_len(1) + reserved(10) + scramble_p2(12) + NUL + plugin_name(NUL)
fn parse_scramble_from_greeting(g: &[u8]) -> [u8; 20] {
    assert_eq!(g[0], 10, "expected protocol version 10");
    let nul = g[1..]
        .iter()
        .position(|&b| b == 0)
        .expect("server_version NUL");
    let mut cur = 1 + nul + 1 + 4;
    let mut out = [0u8; 20];
    out[..8].copy_from_slice(&g[cur..cur + 8]);
    cur += 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10;
    out[8..].copy_from_slice(&g[cur..cur + 12]);
    out
}

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
    let (server, _) = listener.accept().await.unwrap();
    let client = connect.await.unwrap();
    server.set_nodelay(true).unwrap();
    client.set_nodelay(true).unwrap();
    (server, client)
}

/// Drive a fake mysql client through the handshake. Returns the OK/ERR packet
/// the server emits in response to the handshake response.
async fn client_handshake_send<S>(
    stream: &mut S,
    username: &[u8],
    password: &[u8],
    auth_plugin: &[u8],
    db: Option<&[u8]>,
) -> (Vec<u8>, [u8; 20])
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut seq = SequenceCounter::default();
    let greeting = read_packet(stream, &mut seq).await.unwrap();
    let scramble = parse_scramble_from_greeting(&greeting);
    let response_bytes = native_response(password, &scramble);
    let payload = testing::build_handshake_response(username, &response_bytes, db, auth_plugin);
    write_packet(stream, &mut seq, &payload).await.unwrap();
    let reply = read_packet(stream, &mut seq).await.unwrap();
    (reply, scramble)
}

#[tokio::test]
async fn happy_path_auth_ok() {
    let auth = ClientAuth::NativePassword {
        double_sha1: double_sha1(b"correct-token"),
    };
    let (mut server, mut client) = pair().await;
    let server_task = tokio::spawn(async move {
        let session = handshake(&mut server, "stage_w9", &auth, 42).await.unwrap();
        assert_eq!(session.env_name, "stage_w9");
        assert_eq!(session.client_username_seen, "stage_w9");
        assert_eq!(session.database.as_deref(), Some("reports"));
        let pool = dead_pool();
        serve_session(
            &mut server,
            "stage_w9",
            &session.client_username_seen,
            &pool,
            &Policy::ReadOnly,
        )
        .await
        .unwrap();
    });

    let (reply, _) = client_handshake_send(
        &mut client,
        b"stage_w9",
        b"correct-token",
        b"mysql_native_password",
        Some(b"reports"),
    )
    .await;
    assert!(
        testing::is_ok_packet(&reply),
        "expected OK packet, got {:02x?}",
        reply
    );

    // COM_PING -> OK
    let mut seq = SequenceCounter::default();
    write_packet(&mut client, &mut seq, &[0x0E]).await.unwrap();
    let reply = read_packet(&mut client, &mut seq).await.unwrap();
    assert!(testing::is_ok_packet(&reply));

    // COM_QUIT -> server side returns from loop
    let mut seq = SequenceCounter::default();
    write_packet(&mut client, &mut seq, &[0x01]).await.unwrap();
    drop(client);
    server_task.await.unwrap();
}

#[tokio::test]
async fn wrong_token_denied() {
    let auth = ClientAuth::NativePassword {
        double_sha1: double_sha1(b"real-token"),
    };
    let (mut server, mut client) = pair().await;
    let server_task = tokio::spawn(async move {
        let err = handshake(&mut server, "stage_w9", &auth, 1)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            mw_net::mysql_server::HandshakeError::AuthFailed
        ));
    });
    let (reply, _) = client_handshake_send(
        &mut client,
        b"stage_w9",
        b"wrong-token",
        b"mysql_native_password",
        None,
    )
    .await;
    assert_eq!(
        testing::err_code_of(&reply),
        Some(1045),
        "expected ER_ACCESS_DENIED"
    );
    server_task.await.unwrap();
}

#[tokio::test]
async fn wrong_env_name_denied() {
    let auth = ClientAuth::NativePassword {
        double_sha1: double_sha1(b"tk"),
    };
    let (mut server, mut client) = pair().await;
    let server_task = tokio::spawn(async move {
        let _ = handshake(&mut server, "stage_w9", &auth, 1)
            .await
            .unwrap_err();
    });
    let (reply, _) = client_handshake_send(
        &mut client,
        b"prod_w9",
        b"tk",
        b"mysql_native_password",
        None,
    )
    .await;
    assert_eq!(testing::err_code_of(&reply), Some(1045));
    server_task.await.unwrap();
}

/// Pull the switch scramble out of an AuthSwitchRequest packet:
/// `0xFE | "mysql_native_password\0" | scramble(20) | 0x00`.
fn parse_auth_switch(asr: &[u8]) -> [u8; 20] {
    assert_eq!(
        asr[0],
        0xFE,
        "expected AuthSwitchRequest, got {:02x?}",
        &asr[..asr.len().min(8)]
    );
    let nul = asr[1..].iter().position(|&b| b == 0).expect("plugin NUL");
    assert_eq!(&asr[1..1 + nul], b"mysql_native_password");
    let start = 1 + nul + 1;
    let mut s = [0u8; 20];
    s.copy_from_slice(&asr[start..start + 20]);
    s
}

/// A client that defaults to a non-native plugin (e.g. Connector/J →
/// caching_sha2_password) must get a standard AuthSwitchRequest and succeed
/// after replying with a native response over the switch scramble.
#[tokio::test]
async fn non_native_plugin_auth_switch_ok() {
    let auth = ClientAuth::NativePassword {
        double_sha1: double_sha1(b"tk"),
    };
    let (mut server, mut client) = pair().await;
    let server_task = tokio::spawn(async move {
        let session = handshake(&mut server, "stage_w9", &auth, 1).await.unwrap();
        assert_eq!(session.client_username_seen, "stage_w9");
    });
    let mut seq = SequenceCounter::default();
    let _greeting = read_packet(&mut client, &mut seq).await.unwrap();
    let payload =
        testing::build_handshake_response(b"stage_w9", &[0u8; 20], None, b"caching_sha2_password");
    write_packet(&mut client, &mut seq, &payload).await.unwrap();
    let asr = read_packet(&mut client, &mut seq).await.unwrap();
    let switch_scr = parse_auth_switch(&asr);
    let resp = native_response(b"tk", &switch_scr);
    write_packet(&mut client, &mut seq, &resp).await.unwrap();
    let reply = read_packet(&mut client, &mut seq).await.unwrap();
    assert!(
        testing::is_ok_packet(&reply),
        "expected OK after auth switch, got {:02x?}",
        reply
    );
    server_task.await.unwrap();
}

#[tokio::test]
async fn auth_switch_wrong_token_denied() {
    let auth = ClientAuth::NativePassword {
        double_sha1: double_sha1(b"correct"),
    };
    let (mut server, mut client) = pair().await;
    let server_task = tokio::spawn(async move {
        let err = handshake(&mut server, "stage_w9", &auth, 1)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            mw_net::mysql_server::HandshakeError::AuthFailed
        ));
    });
    let mut seq = SequenceCounter::default();
    let _greeting = read_packet(&mut client, &mut seq).await.unwrap();
    let payload =
        testing::build_handshake_response(b"stage_w9", &[0u8; 20], None, b"caching_sha2_password");
    write_packet(&mut client, &mut seq, &payload).await.unwrap();
    let asr = read_packet(&mut client, &mut seq).await.unwrap();
    let switch_scr = parse_auth_switch(&asr);
    let resp = native_response(b"wrong", &switch_scr);
    write_packet(&mut client, &mut seq, &resp).await.unwrap();
    let reply = read_packet(&mut client, &mut seq).await.unwrap();
    assert_eq!(testing::err_code_of(&reply), Some(1045));
    server_task.await.unwrap();
}

// (Removed `com_query_returns_err_phase2`: it asserted the deleted Phase-2
// minimal command loop's behaviour. COM_QUERY routing is now covered
// end-to-end against a real backend by proxy_query.rs and the daemon tests.)
