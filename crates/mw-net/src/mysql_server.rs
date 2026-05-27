//! Server-side MySQL handshake + minimal command loop.
//!
//! Phase 2 scope: greet the client with an Initial Handshake Packet v10
//! advertising `mysql_native_password`, parse the Handshake Response 41,
//! verify the credentials against the env's stored `ClientAuth`, and run a
//! tiny command loop that handles COM_PING (OK) and COM_QUIT (close). All
//! other commands return an ERR packet — query routing arrives in Phase 3.
//!
//! References: MySQL Client/Server Protocol docs (Connection Phase Packets,
//! ProtocolText::Resultset, COM_QUERY).

use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, warn};

use mw_core::config::ClientAuth;
use mw_core::token::verify_native_response;

use crate::framing::{read_nul_string, read_packet, write_packet, FramingError, SequenceCounter};

/// Server banner we advertise. Must be >= 8.0.3: clients (notably
/// Connector/J, used by DBeaver) gate their connection-setup SQL on this
/// string and emit legacy probes like `@@query_cache_size` for older
/// versions, which a modern 8.x backend rejects with ERROR 1193. Kept at
/// 14 bytes + NUL so handshake framing offsets are unchanged.
const SERVER_VERSION: &[u8] = b"8.4.0-mdlwhere\0";
const AUTH_PLUGIN: &[u8] = b"mysql_native_password\0";

const CLIENT_PROTOCOL_41: u32 = 0x00000200;
const CLIENT_SECURE_CONNECTION: u32 = 0x00008000;
const CLIENT_PLUGIN_AUTH: u32 = 0x00080000;
const CLIENT_CONNECT_WITH_DB: u32 = 0x00000008;
const CLIENT_DEPRECATE_EOF: u32 = 0x01000000;

const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;

const ER_ACCESS_DENIED_ERROR: u16 = 1045;
const ER_HANDSHAKE_ERROR: u16 = 1043;

/// What the daemon decides about each authenticated connection.
#[derive(Debug, Clone)]
pub struct AcceptedSession {
    pub env_name: String,
    pub client_username_seen: String,
    pub database: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error(transparent)]
    Framing(#[from] FramingError),
    #[error("client closed during handshake")]
    ClientClosed,
    #[error("malformed handshake response: {0}")]
    Malformed(&'static str),
    #[error("client did not enable PROTOCOL_41")]
    LegacyProtocol,
    #[error("auth failed")]
    AuthFailed,
}

/// Build an Initial Handshake Packet v10 with a random 20-byte scramble.
fn build_initial_handshake(thread_id: u32, scramble: &[u8; 20]) -> Vec<u8> {
    let mut p = Vec::with_capacity(80);
    p.push(10); // protocol version
    p.extend_from_slice(SERVER_VERSION);
    p.extend_from_slice(&thread_id.to_le_bytes());
    p.extend_from_slice(&scramble[..8]); // auth-plugin-data-part-1
    p.push(0); // filler
    let caps = CLIENT_PROTOCOL_41
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH
        | CLIENT_CONNECT_WITH_DB
        | CLIENT_DEPRECATE_EOF;
    p.extend_from_slice(&(caps as u16).to_le_bytes()); // lower 2 bytes of caps
    p.push(0x21); // charset utf8mb4_general_ci
    p.extend_from_slice(&SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
    p.extend_from_slice(&((caps >> 16) as u16).to_le_bytes()); // upper 2 bytes
    p.push(21); // length of auth-plugin-data (always 21 when plugin auth enabled)
    p.extend_from_slice(&[0u8; 10]); // reserved
    p.extend_from_slice(&scramble[8..]); // auth-plugin-data-part-2 (12 bytes)
    p.push(0); // NUL terminator for part-2
    p.extend_from_slice(AUTH_PLUGIN);
    p
}

fn build_ok_packet() -> Vec<u8> {
    // OK header 0x00, affected_rows lenenc=0, last_insert_id lenenc=0,
    // status_flags u16, warnings u16. (CLIENT_PROTOCOL_41 path.)
    let mut p = Vec::with_capacity(7);
    p.push(0x00);
    p.push(0x00); // affected_rows = 0
    p.push(0x00); // last_insert_id = 0
    p.extend_from_slice(&SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes()); // warnings
    p
}

fn build_err_packet(code: u16, sqlstate: &[u8; 5], msg: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(9 + msg.len());
    p.push(0xFF);
    p.extend_from_slice(&code.to_le_bytes());
    p.push(b'#');
    p.extend_from_slice(sqlstate);
    p.extend_from_slice(msg.as_bytes());
    p
}

/// AuthSwitchRequest: `0xFE | plugin\0 | auth-data`. We always switch to
/// `mysql_native_password`; auth-data is the 20-byte scramble + NUL (the
/// client uses the first 20 bytes to compute its response).
fn build_auth_switch_request(scramble: &[u8; 20]) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + 22 + 21);
    p.push(0xFE);
    p.extend_from_slice(b"mysql_native_password\0");
    p.extend_from_slice(scramble);
    p.push(0);
    p
}

/// Parsed pieces of a Handshake Response 41 that we actually use.
#[derive(Debug)]
struct ParsedHandshakeResponse<'a> {
    client_caps: u32,
    username: &'a [u8],
    auth_response: &'a [u8],
    database: Option<&'a [u8]>,
    auth_plugin: Option<&'a [u8]>,
}

fn parse_handshake_response(buf: &[u8]) -> Result<ParsedHandshakeResponse<'_>, HandshakeError> {
    use HandshakeError::Malformed;
    if buf.len() < 32 {
        return Err(Malformed("response shorter than fixed header"));
    }
    let client_caps = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if client_caps & CLIENT_PROTOCOL_41 == 0 {
        return Err(HandshakeError::LegacyProtocol);
    }
    // skip max_packet_size (4) + charset (1) + reserved (23)
    let mut cur = 32;
    let (username, n) = read_nul_string(&buf[cur..]).ok_or(Malformed("missing username NUL"))?;
    cur += n;

    let auth_response: &[u8];
    if client_caps & CLIENT_SECURE_CONNECTION != 0 {
        // length-prefixed (1 byte) auth response
        if cur >= buf.len() {
            return Err(Malformed("missing auth-response length"));
        }
        let n = buf[cur] as usize;
        cur += 1;
        if cur + n > buf.len() {
            return Err(Malformed("auth-response truncated"));
        }
        auth_response = &buf[cur..cur + n];
        cur += n;
    } else {
        // legacy: NUL-terminated
        let (ar, n) =
            read_nul_string(&buf[cur..]).ok_or(Malformed("missing legacy auth-response NUL"))?;
        auth_response = ar;
        cur += n;
    }

    let database = if client_caps & CLIENT_CONNECT_WITH_DB != 0 {
        let (db, n) = read_nul_string(&buf[cur..]).ok_or(Malformed("missing database NUL"))?;
        cur += n;
        Some(db)
    } else {
        None
    };

    let auth_plugin = if client_caps & CLIENT_PLUGIN_AUTH != 0 {
        let (p, _n) = read_nul_string(&buf[cur..]).ok_or(Malformed("missing auth-plugin NUL"))?;
        Some(p)
    } else {
        None
    };

    Ok(ParsedHandshakeResponse {
        client_caps,
        username,
        auth_response,
        database,
        auth_plugin,
    })
}

/// Drive the handshake; on success, return what we accepted. On any failure
/// emit an ERR packet (best effort), then return the error.
pub async fn handshake<S>(
    stream: &mut S,
    expected_env_name: &str,
    auth: &ClientAuth,
    thread_id: u32,
) -> Result<AcceptedSession, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut seq = SequenceCounter::default();
    let mut scramble = [0u8; 20];
    OsRng.fill_bytes(&mut scramble);
    // Constrain every byte to printable, nonzero ASCII (0x21..=0x7e), exactly
    // like the real MySQL server. Some clients (Connector/J, used by DBeaver)
    // parse auth-plugin-data as a NUL-terminated string and truncate at the
    // first 0x00, deriving a different seed than a fixed-length reader (the
    // `mysql` CLI). A 0x00 anywhere in a random 20-byte scramble would make
    // those clients intermittently fail auth. ~6.2 bits/byte * 20 = 124 bits
    // of entropy remain — ample for a per-connection challenge.
    for b in scramble.iter_mut() {
        *b = 0x21 + (*b % (0x7e - 0x21 + 1));
    }
    let greeting = build_initial_handshake(thread_id, &scramble);
    write_packet(stream, &mut seq, &greeting).await?;

    let response = match read_packet(stream, &mut seq).await {
        Ok(p) => p,
        Err(FramingError::UnexpectedEof { .. }) => return Err(HandshakeError::ClientClosed),
        Err(e) => return Err(e.into()),
    };

    let parsed = match parse_handshake_response(&response) {
        Ok(p) => p,
        Err(e) => {
            let _ = write_packet(
                stream,
                &mut seq,
                &build_err_packet(ER_HANDSHAKE_ERROR, b"08S01", "bad handshake"),
            )
            .await;
            return Err(e);
        }
    };

    let username_seen = String::from_utf8_lossy(parsed.username).to_string();

    // We only verify `mysql_native_password`. Clients that default to a
    // different plugin (e.g. Connector/J → caching_sha2_password) or that
    // send an empty initial response expecting negotiation get a standard
    // AuthSwitchRequest to mysql_native_password — exactly what a real MySQL
    // server does. Clients already on native with a 20-byte response skip
    // this and the path is byte-identical to before.
    let needs_switch = match parsed.auth_plugin {
        Some(p) => p != b"mysql_native_password" || parsed.auth_response.len() != 20,
        None => parsed.auth_response.len() != 20,
    };
    let native_response: Vec<u8> = if needs_switch {
        write_packet(stream, &mut seq, &build_auth_switch_request(&scramble)).await?;
        match read_packet(stream, &mut seq).await {
            Ok(p) => p,
            Err(FramingError::UnexpectedEof { .. }) => return Err(HandshakeError::ClientClosed),
            Err(e) => return Err(e.into()),
        }
    } else {
        parsed.auth_response.to_vec()
    };

    // Evaluate BOTH checks unconditionally and combine without
    // short-circuiting. `&&` would skip the token hash work when the
    // username is wrong, turning response latency into an oracle for which
    // env names exist. `&` on bools always evaluates both operands; the
    // username compare is constant-time; verify_native_response is already
    // constant-time internally.
    let user_ok = bool::from(username_seen.as_bytes().ct_eq(expected_env_name.as_bytes()));
    let token_ok = match auth {
        ClientAuth::NativePassword { double_sha1 } => {
            verify_native_response(&scramble, &native_response, double_sha1)
        }
        // Non-MySQL auth material on a MySQL listener is a config error
        // (validate() rejects the pairing). Fail closed if one slips through.
        ClientAuth::PgCleartext { .. } => false,
    };
    let allowed = user_ok & token_ok;

    if !allowed {
        warn!(env = expected_env_name, user = %username_seen, "auth denied");
        let _ = write_packet(
            stream,
            &mut seq,
            &build_err_packet(ER_ACCESS_DENIED_ERROR, b"28000", "access denied"),
        )
        .await;
        return Err(HandshakeError::AuthFailed);
    }

    let database = parsed
        .database
        .map(|d| String::from_utf8_lossy(d).to_string());
    let _ = parsed.client_caps; // reserved for Phase 3 capability negotiation
    write_packet(stream, &mut seq, &build_ok_packet()).await?;
    info!(env = expected_env_name, user = %username_seen, db = ?database, "auth ok");
    Ok(AcceptedSession {
        env_name: expected_env_name.to_string(),
        client_username_seen: username_seen,
        database,
    })
}

/// Helpers exposed for in-process integration tests. `#[doc(hidden)]`: not
/// part of the public API and unused by the binaries (dead-code-stripped
/// from release builds); kept `pub` only so the integration test crates can
/// reach it.
#[doc(hidden)]
pub mod testing {
    use super::*;

    /// Build the bytes a real mysql client would send back. Caller chooses
    /// caps; we always include PROTOCOL_41 + SECURE_CONNECTION + PLUGIN_AUTH.
    pub fn build_handshake_response(
        username: &[u8],
        auth_response_20: &[u8; 20],
        database: Option<&[u8]>,
        auth_plugin: &[u8],
    ) -> Vec<u8> {
        let mut caps = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
        if database.is_some() {
            caps |= CLIENT_CONNECT_WITH_DB;
        }
        let mut p = Vec::with_capacity(64 + username.len());
        p.extend_from_slice(&caps.to_le_bytes());
        p.extend_from_slice(&(1u32 << 24).to_le_bytes()); // max_packet 16 MB
        p.push(0x21);
        p.extend_from_slice(&[0u8; 23]);
        p.extend_from_slice(username);
        p.push(0);
        p.push(20);
        p.extend_from_slice(auth_response_20);
        if let Some(db) = database {
            p.extend_from_slice(db);
            p.push(0);
        }
        p.extend_from_slice(auth_plugin);
        p.push(0);
        p
    }

    /// COM_QUERY needs the scramble used by the server during handshake to
    /// help tests reproduce client responses. Tests stub this via a fixed
    /// scramble path; production uses a fresh random scramble every connect.
    pub fn err_code_of(packet: &[u8]) -> Option<u16> {
        if packet.first() != Some(&0xFF) || packet.len() < 3 {
            return None;
        }
        Some(u16::from_le_bytes([packet[1], packet[2]]))
    }

    pub fn is_ok_packet(packet: &[u8]) -> bool {
        packet.first() == Some(&0x00) || packet.first() == Some(&0xFE)
    }
}

/// Byte-level golden tests. These freeze the exact MySQL wire bytes the
/// server emits so the multi-engine refactor (and any later edit) cannot
/// silently shift the MySQL protocol. Inputs are fixed; outputs are
/// asserted byte-for-byte.
#[cfg(test)]
mod golden {
    use super::*;

    #[test]
    fn initial_handshake_bytes_frozen() {
        let scramble: [u8; 20] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];
        let got = build_initial_handshake(0x11223344, &scramble);
        let expected: &[u8] = &[
            10, // protocol version
            // "8.4.0-mdlwhere\0"
            0x38, 0x2e, 0x34, 0x2e, 0x30, 0x2d, 0x6d, 0x64, 0x6c, 0x77, 0x68, 0x65, 0x72, 0x65,
            0x00, 0x44, 0x33, 0x22, 0x11, // thread id LE
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // scramble[..8]
            0x00, // filler
            0x08,
            0x82, // caps low (PROTOCOL_41|SECURE|PLUGIN_AUTH|CONNECT_WITH_DB|DEPRECATE_EOF) & 0xFFFF
            0x21, // charset
            0x02, 0x00, // server status (AUTOCOMMIT)
            0x08, 0x01, // caps high
            21,   // auth-plugin-data len
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // reserved[10]
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            0x14, // scramble[8..]
            0x00, // NUL after part-2
            // "mysql_native_password\0"
            0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70,
            0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00,
        ];
        assert_eq!(got, expected, "MySQL initial handshake bytes drifted");
    }

    #[test]
    fn auth_switch_request_bytes_frozen() {
        let scramble: [u8; 20] = [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
            0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
        ];
        let got = build_auth_switch_request(&scramble);
        let mut expected = vec![0xFE];
        expected.extend_from_slice(b"mysql_native_password\0");
        expected.extend_from_slice(&scramble);
        expected.push(0);
        assert_eq!(got, expected, "AuthSwitchRequest bytes drifted");
    }

    #[test]
    fn ok_packet_bytes_frozen() {
        assert_eq!(
            build_ok_packet(),
            vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn err_packet_bytes_frozen() {
        let got = build_err_packet(1045, b"28000", "access denied");
        let mut expected = vec![0xFF, 0x15, 0x04, b'#'];
        expected.extend_from_slice(b"28000");
        expected.extend_from_slice(b"access denied");
        assert_eq!(got, expected, "MySQL ERR packet bytes drifted");
    }
}
