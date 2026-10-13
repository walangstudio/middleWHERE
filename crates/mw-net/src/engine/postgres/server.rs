//! Server-side PostgreSQL v3 protocol: startup, cleartext-password auth
//! termination, and a Simple Query command loop. Extended query (Parse/Bind)
//! is rejected without desyncing the stream.

use std::collections::HashMap;
use std::time::Duration;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::{info, warn};

use mw_core::audit::{AuditEvent, Decision as AuditDecision};
use mw_core::config::{ClientAuth, Policy};
use mw_core::policy::{self, Decision, TxnEffect, TxnState};
use mw_core::token::verify_pg_cleartext;

use super::client::{PgManager, PgPool};
use super::proto::{self, PgProtoError, Startup};
use crate::engine::EngineError;
use crate::idle::{next_wait, within_idle};
use crate::session_conn::SessionConn;

type PinnedConn<'a> = SessionConn<'a, PgManager>;

const SQLSTATE_INVALID_PASSWORD: &str = "28P01";
const SQLSTATE_INSUFFICIENT_PRIVILEGE: &str = "42501";
const SQLSTATE_INTERNAL: &str = "58000";
const SQLSTATE_CONNECTION_FAILURE: &str = "08006";
const SQLSTATE_PROTOCOL_VIOLATION: &str = "08P01";
const SQLSTATE_FEATURE_NOT_SUPPORTED: &str = "0A000";
const SQLSTATE_CHARACTER_NOT_IN_REPERTOIRE: &str = "22021";

pub struct PgSession {
    pub user_seen: String,
    pub database: Option<String>,
}

impl From<PgProtoError> for EngineError {
    fn from(e: PgProtoError) -> Self {
        match e {
            PgProtoError::Closed => EngineError::Other("client closed".into()),
            other => EngineError::Other(other.to_string()),
        }
    }
}

/// Drive startup + auth. On any failure the client already has an
/// ErrorResponse (best effort); returns Err so the caller drops the socket.
pub async fn handshake(
    stream: &mut TcpStream,
    expected_env_name: &str,
    auth: &ClientAuth,
) -> Result<PgSession, EngineError> {
    // Startup phase: a client may first send SSLRequest/GSSENCRequest; we
    // answer 'N' (no encryption — loopback trust boundary) and read again.
    let params = loop {
        match proto::read_startup(stream).await? {
            Startup::Params(p) => break p,
            Startup::EncryptionRequest => {
                proto::write_raw(stream, b"N").await?;
            }
            Startup::Cancel => return Err(EngineError::Other("cancel request".into())),
        }
    };

    let user = params
        .iter()
        .find(|(k, _)| k == "user")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let database = params
        .iter()
        .find(|(k, _)| k == "database")
        .map(|(_, v)| v.clone());

    proto::write_raw(stream, &proto::auth_cleartext_request()).await?;

    let (tag, body) = proto::read_message(stream).await?;
    if tag != b'p' {
        let _ = proto::write_raw(
            stream,
            &proto::fatal_response(SQLSTATE_PROTOCOL_VIOLATION, "expected password message"),
        )
        .await;
        return Err(EngineError::Auth);
    }
    // PasswordMessage payload is the password followed by a NUL.
    let presented = match body.split(|&b| b == 0).next() {
        Some(p) => p,
        None => &body[..],
    };

    let user_ok = bool::from(user.as_bytes().ct_eq(expected_env_name.as_bytes()));
    let token_ok = match auth {
        ClientAuth::PgCleartext { sha256 } => verify_pg_cleartext(presented, sha256),
        // Wrong auth material for a PG listener is a config error
        // (validate() rejects the pairing). Fail closed.
        ClientAuth::NativePassword { .. } => false,
    };
    if !(user_ok & token_ok) {
        warn!(env = expected_env_name, user = %user, "pg auth denied");
        let _ = proto::write_raw(
            stream,
            &proto::fatal_response(SQLSTATE_INVALID_PASSWORD, "password authentication failed"),
        )
        .await;
        return Err(EngineError::Auth);
    }

    // Success: AuthenticationOk, a minimal but client-friendly set of
    // ParameterStatus, BackendKeyData, then ReadyForQuery.
    let mut greeting = Vec::new();
    greeting.extend_from_slice(&proto::auth_ok());
    for (k, v) in [
        ("server_version", "15.0 (middlewhere)"),
        ("server_encoding", "UTF8"),
        ("client_encoding", "UTF8"),
        ("DateStyle", "ISO, MDY"),
        ("integer_datetimes", "on"),
        ("standard_conforming_strings", "on"),
    ] {
        greeting.extend_from_slice(&proto::parameter_status(k, v));
    }
    greeting.extend_from_slice(&proto::backend_key_data(
        std::process::id() as i32,
        rand::random::<i32>(),
    ));
    greeting.extend_from_slice(&proto::ready_for_query(b'I'));
    proto::write_raw(stream, &greeting).await?;

    Ok(PgSession {
        user_seen: user,
        database,
    })
}

fn command_tag(sql: &str, rows: usize) -> String {
    let verb = sql
        .trim_start()
        .split(|c: char| c.is_whitespace() || c == '(')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    match verb.as_str() {
        "INSERT" => format!("INSERT 0 {rows}"),
        "SELECT" | "WITH" | "VALUES" | "SHOW" | "TABLE" => format!("SELECT {rows}"),
        "UPDATE" => format!("UPDATE {rows}"),
        "DELETE" => format!("DELETE {rows}"),
        other if !other.is_empty() => other.to_string(),
        _ => "SELECT 0".to_string(),
    }
}

// Postgres type OIDs we special-case for parameter inlining.
const OID_BOOL: i32 = 16;
const OID_INT8: i32 = 20;
const OID_INT2: i32 = 21;
const OID_INT4: i32 = 23;
const OID_OID: i32 = 26;
const OID_FLOAT4: i32 = 700;
const OID_FLOAT8: i32 = 701;
const OID_NUMERIC: i32 = 1700;

fn quote_lit(s: &str) -> String {
    // standard_conforming_strings is advertised on, so only ' needs doubling.
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push('\'');
        }
        out.push(c);
    }
    out.push('\'');
    out
}

fn is_numeric_oid(oid: i32) -> bool {
    matches!(
        oid,
        OID_INT2 | OID_INT4 | OID_INT8 | OID_OID | OID_FLOAT4 | OID_FLOAT8 | OID_NUMERIC
    )
}

/// True only if `s` is a syntactically valid SQL numeric literal. A
/// text-format param typed as numeric is otherwise inlined UNQUOTED; without
/// this check a value like `0 OR 1=1` / `1);DROP..` would be an injection
/// seam (defense-in-depth even though the AST firewall re-validates).
fn is_safe_numeric(s: &str) -> bool {
    let s = s.trim();
    if matches!(s, "NaN" | "Infinity" | "-Infinity" | "+Infinity") {
        return true;
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        i += 1;
    }
    let mut digits = false;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
        digits = true;
    }
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
            digits = true;
        }
    }
    if !digits {
        return false;
    }
    if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
        i += 1;
        if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
            i += 1;
        }
        let mut exp = false;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
            exp = true;
        }
        if !exp {
            return false;
        }
    }
    i == bytes.len()
}

/// Render a finite float; non-finite values are emitted as the quoted
/// SQL spellings PostgreSQL accepts (a bare `NaN`/`inf` token is invalid).
fn fmt_float(v: f64) -> String {
    if v.is_finite() {
        v.to_string()
    } else if v.is_nan() {
        "'NaN'".to_string()
    } else if v > 0.0 {
        "'Infinity'".to_string()
    } else {
        "'-Infinity'".to_string()
    }
}

/// SQL type name for an array element OID (used to cast empty arrays).
fn elem_type_name(oid: i32) -> &'static str {
    match oid {
        OID_BOOL => "bool",
        OID_INT2 => "int2",
        OID_INT4 => "int4",
        OID_INT8 => "int8",
        OID_OID => "oid",
        OID_FLOAT4 => "float4",
        OID_FLOAT8 => "float8",
        OID_NUMERIC => "numeric",
        1042 => "bpchar",
        1043 => "varchar",
        19 => "name",
        18 => "char",
        _ => "text",
    }
}

/// If `oid` is a PG array type, its element OID (for empty-array casts /
/// detecting the array path). Element OID inside a binary payload is
/// authoritative; this is the fallback.
fn array_elem_oid(oid: i32) -> Option<i32> {
    Some(match oid {
        1000 => OID_BOOL,
        1002 => 18,
        1003 => 19,
        1005 => OID_INT2,
        1007 => OID_INT4,
        1009 => 25,
        1014 => 1042,
        1015 => 1043,
        1016 => OID_INT8,
        1021 => OID_FLOAT4,
        1022 => OID_FLOAT8,
        1028 => OID_OID,
        1231 => OID_NUMERIC,
        _ => return None,
    })
}

/// Render a scalar (non-array) bound value as a SQL literal.
fn render_scalar(oid: i32, fmt: i16, bytes: Option<&[u8]>) -> Result<String, &'static str> {
    let b = match bytes {
        None => return Ok("NULL".to_string()),
        Some(b) => b,
    };
    if fmt == 1 {
        match oid {
            OID_BOOL => Ok(if b.first().copied().unwrap_or(0) != 0 {
                "TRUE"
            } else {
                "FALSE"
            }
            .into()),
            OID_INT2 if b.len() == 2 => Ok(i16::from_be_bytes([b[0], b[1]]).to_string()),
            OID_INT4 | OID_OID if b.len() == 4 => {
                Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]).to_string())
            }
            OID_INT8 if b.len() == 8 => {
                let mut a = [0u8; 8];
                a.copy_from_slice(&b[..8]);
                Ok(i64::from_be_bytes(a).to_string())
            }
            OID_FLOAT4 if b.len() == 4 => Ok(fmt_float(
                f32::from_be_bytes([b[0], b[1], b[2], b[3]]) as f64,
            )),
            OID_FLOAT8 if b.len() == 8 => {
                let mut a = [0u8; 8];
                a.copy_from_slice(&b[..8]);
                Ok(fmt_float(f64::from_be_bytes(a)))
            }
            // OID-family / register types are 4-byte big-endian integers
            // (regclass, regnamespace, regproc, regtype, xid, cid, ...).
            // DBeaver's catalog queries bind these heavily.
            2202 | 2203 | 2204 | 2205 | 2206 | 4089 | 24 | 28 | 29 | 2200 if b.len() == 4 => {
                Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]).to_string())
            }
            // Unknown binary type. If it contains a NUL it cannot be text
            // (which would corrupt the query string) — treat fixed 2/4/8-byte
            // payloads as big-endian integers (the realistic case: an
            // integer/OID type we didn't enumerate). Otherwise it is safe to
            // read as UTF-8 text.
            _ => {
                if b.contains(&0) {
                    match b.len() {
                        2 => Ok(i16::from_be_bytes([b[0], b[1]]).to_string()),
                        4 => Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]).to_string()),
                        8 => {
                            let mut a = [0u8; 8];
                            a.copy_from_slice(&b[..8]);
                            Ok(i64::from_be_bytes(a).to_string())
                        }
                        _ => Err("unsupported binary parameter (NUL)"),
                    }
                } else {
                    Ok(quote_lit(&String::from_utf8_lossy(b)))
                }
            }
        }
    } else {
        let s = String::from_utf8_lossy(b);
        if oid == OID_BOOL {
            let t = matches!(s.as_ref(), "t" | "true" | "TRUE" | "1" | "y" | "yes");
            Ok(if t { "TRUE" } else { "FALSE" }.into())
        } else if is_numeric_oid(oid) && is_safe_numeric(&s) {
            Ok(s.into_owned())
        } else {
            // Not a numeric type, or a numeric-typed value that is not a
            // valid numeric literal: quote it. A quoted value in a numeric
            // context fails cleanly on the backend (no injection).
            Ok(quote_lit(&s))
        }
    }
}

/// Decode a PostgreSQL binary array payload into (element OID, flattened
/// elements). Multi-dim arrays are flattened (sufficient for `= ANY()`).
#[allow(clippy::type_complexity)]
fn decode_bin_array(b: &[u8]) -> Result<(i32, Vec<Option<Vec<u8>>>), &'static str> {
    if b.len() < 12 {
        return Err("bad binary array");
    }
    let rd = |p: usize| i32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]);
    let ndim = rd(0);
    let elem_oid = rd(8);
    if ndim == 0 {
        return Ok((elem_oid, Vec::new()));
    }
    if !(1..=6).contains(&ndim) {
        return Err("bad binary array ndim");
    }
    let mut pos = 12;
    let mut total: i64 = 1;
    for _ in 0..ndim {
        if pos + 8 > b.len() {
            return Err("bad binary array dims");
        }
        let dim = rd(pos).max(0) as i64;
        total = total
            .checked_mul(dim)
            .filter(|t| *t <= 10_000_000)
            .ok_or("binary array too large")?;
        pos += 8;
    }
    let mut out = Vec::with_capacity(total.min(100_000) as usize);
    for _ in 0..total {
        if pos + 4 > b.len() {
            return Err("bad binary array elem len");
        }
        let len = rd(pos);
        pos += 4;
        if len < 0 {
            out.push(None);
        } else {
            let len = len as usize;
            if pos + len > b.len() {
                return Err("bad binary array elem");
            }
            out.push(Some(b[pos..pos + len].to_vec()));
            pos += len;
        }
    }
    Ok((elem_oid, out))
}

/// Render one bound parameter as a SQL literal. Handles arrays (`= ANY(?)`,
/// common in catalog introspection) by emitting an `ARRAY[...]` literal.
fn render_param(oid: i32, fmt: i16, bytes: &Option<Vec<u8>>) -> Result<String, &'static str> {
    let b = match bytes {
        None => return Ok("NULL".to_string()),
        Some(b) => b,
    };
    if let Some(fallback_elem) = array_elem_oid(oid) {
        if fmt == 1 {
            let (elem_oid, elems) = decode_bin_array(b)?;
            if elems.is_empty() {
                return Ok(format!("ARRAY[]::{}[]", elem_type_name(elem_oid)));
            }
            let mut parts = Vec::with_capacity(elems.len());
            for e in &elems {
                parts.push(render_scalar(elem_oid, 1, e.as_deref())?);
            }
            return Ok(format!("ARRAY[{}]", parts.join(",")));
        } else {
            // text format: bytes are a PG array literal e.g. {a,b}
            if b.contains(&0) {
                return Err("array text contains NUL");
            }
            return Ok(format!(
                "{}::{}[]",
                quote_lit(&String::from_utf8_lossy(b)),
                elem_type_name(fallback_elem)
            ));
        }
    }
    render_scalar(oid, fmt, Some(b))
}

/// Substitute `$1..$N` placeholders with rendered literals, skipping string
/// literals, quoted identifiers and comments so we never rewrite a `$n`
/// that is actually data.
fn inline_params(sql: &str, rendered: &[String]) -> String {
    enum St {
        Normal,
        SQuote,
        DQuote,
        Line,
        Block,
        Dollar(Vec<u8>),
    }
    let mut st = St::Normal;
    let b = sql.as_bytes();
    // Byte buffer (not String): copying raw bytes keeps multibyte UTF-8 in
    // the query text intact; rendered params are valid UTF-8 already.
    let mut out: Vec<u8> = Vec::with_capacity(sql.len() + 16);
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match &st {
            St::Normal => {
                if c == b'\'' {
                    st = St::SQuote;
                    out.push(c);
                    i += 1;
                } else if c == b'"' {
                    st = St::DQuote;
                    out.push(c);
                    i += 1;
                } else if c == b'-' && i + 1 < b.len() && b[i + 1] == b'-' {
                    st = St::Line;
                    out.extend_from_slice(b"--");
                    i += 2;
                } else if c == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
                    st = St::Block;
                    out.extend_from_slice(b"/*");
                    i += 2;
                } else if c == b'$' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
                    // $1.. positional parameter (PG dollar-quote tags may not
                    // start with a digit, so this is unambiguous).
                    let mut j = i + 1;
                    while j < b.len() && b[j].is_ascii_digit() {
                        j += 1;
                    }
                    let idx: usize = sql[i + 1..j].parse().unwrap_or(0);
                    if idx >= 1 && idx <= rendered.len() {
                        out.extend_from_slice(rendered[idx - 1].as_bytes());
                    } else {
                        out.extend_from_slice(&b[i..j]);
                    }
                    i = j;
                } else if c == b'$'
                    && i + 1 < b.len()
                    && (b[i + 1] == b'$' || b[i + 1] == b'_' || b[i + 1].is_ascii_alphabetic())
                {
                    // Dollar-quote open: $tag$ (tag may be empty as $$).
                    let mut j = i + 1;
                    while j < b.len() && (b[j] == b'_' || b[j].is_ascii_alphanumeric()) {
                        j += 1;
                    }
                    if j < b.len() && b[j] == b'$' {
                        let delim = b[i..=j].to_vec();
                        out.extend_from_slice(&delim);
                        st = St::Dollar(delim);
                        i = j + 1;
                    } else {
                        out.push(c);
                        i += 1;
                    }
                } else {
                    out.push(c);
                    i += 1;
                }
            }
            St::SQuote => {
                out.push(c);
                if c == b'\'' {
                    st = St::Normal;
                }
                i += 1;
            }
            St::DQuote => {
                out.push(c);
                if c == b'"' {
                    st = St::Normal;
                }
                i += 1;
            }
            St::Line => {
                out.push(c);
                if c == b'\n' {
                    st = St::Normal;
                }
                i += 1;
            }
            St::Block => {
                out.push(c);
                if c == b'*' && i + 1 < b.len() && b[i + 1] == b'/' {
                    out.push(b'/');
                    st = St::Normal;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            St::Dollar(delim) => {
                if b[i..].starts_with(delim.as_slice()) {
                    out.extend_from_slice(delim);
                    i += delim.len();
                    st = St::Normal;
                } else {
                    out.push(c);
                    i += 1;
                }
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn rfq_status(t: &TxnState) -> u8 {
    if t.failed {
        b'E'
    } else if t.in_txn {
        b'T'
    } else {
        b'I'
    }
}

type ResultSet = (Vec<String>, Vec<Vec<Option<Vec<u8>>>>, String);

/// The statement ran, but a value in its result isn't UTF-8 (a SQL_ASCII
/// database), which tokio-postgres can't hand over. Not a statement failure:
/// the backend did the work.
struct Undecodable;

/// Run already-firewalled SQL on the backend, collecting the full result. The
/// outer error is the backend's (the statement failed).
async fn run_query(
    client: &tokio_postgres::Client,
    sql: &str,
) -> Result<Result<ResultSet, Undecodable>, tokio_postgres::Error> {
    use tokio_postgres::SimpleQueryMessage;
    let msgs = client.simple_query(sql).await?;
    let mut cols: Vec<String> = Vec::new();
    let mut rows: Vec<Vec<Option<Vec<u8>>>> = Vec::new();
    let mut affected: u64 = 0;
    let mut undecodable = false;
    for m in msgs {
        match m {
            // Sent even for zero rows, so an empty SELECT keeps its columns.
            SimpleQueryMessage::RowDescription(desc) => {
                cols = desc.iter().map(|c| c.name().to_string()).collect();
            }
            SimpleQueryMessage::Row(r) => {
                if cols.is_empty() {
                    cols = r.columns().iter().map(|c| c.name().to_string()).collect();
                }
                // try_get, not get: get panics on a value that isn't UTF-8,
                // and a release build aborts the whole daemon.
                let row: Result<Vec<_>, _> = (0..r.columns().len())
                    .map(|i| r.try_get(i).map(|v| v.map(|s| s.as_bytes().to_vec())))
                    .collect();
                match row {
                    Ok(row) => rows.push(row),
                    Err(_) => undecodable = true,
                }
            }
            SimpleQueryMessage::CommandComplete(n) => affected = n,
            _ => {}
        }
    }
    let tag = if rows.is_empty() && cols.is_empty() {
        command_tag(sql, affected as usize)
    } else {
        command_tag(sql, rows.len())
    };
    if undecodable {
        return Ok(Err(Undecodable));
    }
    Ok(Ok((cols, rows, tag)))
}

async fn write_result_set<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    rs: &ResultSet,
) -> Result<(), EngineError> {
    let (cols, rows, tag) = rs;
    // NoData belongs to the extended protocol; a simple-query statement with no
    // result set (SET, BEGIN, ...) gets only CommandComplete.
    if !cols.is_empty() {
        // Simple-query path has no type info; advertise text (OID 25).
        let typed: Vec<(String, i32)> = cols.iter().map(|n| (n.clone(), 25)).collect();
        proto::write_raw(stream, &proto::row_description(&typed)).await?;
        for row in rows {
            proto::write_raw(stream, &proto::data_row(row)).await?;
        }
    }
    proto::write_raw(stream, &proto::command_complete(tag)).await?;
    Ok(())
}

/// The server's SQLSTATE, if the error came from the server, and an audit
/// reason. Display on a server error says only "db error".
fn backend_error(e: &tokio_postgres::Error) -> (Option<&str>, String) {
    match e.as_db_error() {
        Some(db) => (
            Some(db.code().code()),
            format!("backend: {} {}", db.code().code(), db.message()),
        ),
        None => (None, format!("backend: {e}")),
    }
}

/// SQLSTATEs the server sends right before it closes the connection:
/// shutdown, crash, idle-session and idle-in-transaction timeouts. The
/// client may not have seen the close yet.
fn hangs_up(state: Option<&str>) -> bool {
    matches!(state, Some("57P01" | "57P02" | "57P05" | "25P03"))
}

/// The client's frame for a backend failure, and whether the session is
/// over. The server's SQLSTATE, so retries still work; the message stays
/// hidden. FATAL when the connection is gone, as Postgres reports it.
fn failure_frame(state: Option<&str>, lost: bool, message: &str) -> (Vec<u8>, bool) {
    match state {
        Some(s) if hangs_up(state) => (proto::fatal_response(s, message), true),
        // Report the loss, not a server code that invites a retry.
        _ if lost => (
            proto::fatal_response(SQLSTATE_CONNECTION_FAILURE, message),
            true,
        ),
        _ => (
            proto::error_response(state.unwrap_or(SQLSTATE_INTERNAL), message),
            false,
        ),
    }
}

/// A backend call failed: the server's SQLSTATE, if it gave one, an audit
/// reason, and whether the connection is gone.
struct BackendFailure {
    state: Option<String>,
    reason: String,
    lost: bool,
}

/// Any error without a server code (closed, I/O, an unexpected or
/// unparsable message) leaves the backend in an unknown state: the statement
/// may have run, and the protocol may be out of step.
fn connection_lost(e: &tokio_postgres::Error, client: &tokio_postgres::Client) -> bool {
    e.as_db_error().is_none() || client.is_closed()
}

/// Ask the backend to Parse+Describe the statement so we can report accurate
/// ParameterDescription / RowDescription to the client (pgjdbc caches these
/// for server-side prepared-statement reuse and then sends no further
/// Describe). Returns (param type OIDs, [(col name, col type OID)]).
async fn backend_describe(
    conn: &mut PinnedConn<'_>,
    sql: &str,
) -> Result<(Vec<i32>, Vec<(String, i32)>), BackendFailure> {
    // No connection to lose yet: recoverable, as in exec.
    let client = conn.get().await.map_err(|e| BackendFailure {
        state: None,
        reason: format!("pool: {e}"),
        lost: false,
    })?;
    let stmt = client.prepare(sql).await.map_err(|e| {
        let (state, reason) = backend_error(&e);
        BackendFailure {
            state: state.map(str::to_string),
            reason,
            lost: connection_lost(&e, client),
        }
    })?;
    let params = stmt.params().iter().map(|t| t.oid() as i32).collect();
    let cols = stmt
        .columns()
        .iter()
        .map(|c| (c.name().to_string(), c.type_().oid() as i32))
        .collect();
    Ok((params, cols))
}

/// Firewall + execute, writing the protocol result frames (no ReadyForQuery,
/// no ParseComplete/BindComplete: the caller owns those). `with_description`
/// is false for an extended-protocol Execute, which must send only DataRows +
/// CommandComplete (the client got the field structure from Describe).
/// Returns whether it succeeded; on deny/backend failure it has already
/// written an ErrorResponse.
async fn exec<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    env_name: &str,
    client_user: &str,
    sql: &str,
    backend: &mut Pinned<'_>,
    pol: &Policy,
    with_description: bool,
) -> Result<bool, EngineError> {
    let started = std::time::Instant::now();
    let (decision, effects) = policy::check(sql, pol, &policy::PG_PROFILE);
    if let Decision::Deny(reason) = decision {
        info!(env = env_name, reason, "pg policy DENY");
        AuditEvent::new(
            env_name,
            client_user,
            sql,
            AuditDecision::Deny,
            Some(reason.to_string()),
            None,
            started.elapsed(),
        )
        .emit();
        proto::write_raw(
            stream,
            &proto::error_response(SQLSTATE_INSUFFICIENT_PRIVILEGE, reason),
        )
        .await?;
        return Ok(false);
    }
    let client = match backend.conn.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(env = env_name, err = %e, "pg backend unavailable");
            AuditEvent::new(
                env_name,
                client_user,
                sql,
                AuditDecision::Error,
                Some(format!("pool: {e}")),
                None,
                started.elapsed(),
            )
            .emit();
            proto::write_raw(
                stream,
                &proto::error_response(SQLSTATE_INTERNAL, "backend unavailable"),
            )
            .await?;
            return Ok(false);
        }
    };
    let ran = run_query(client, sql).await;
    backend.last_statement = std::time::Instant::now();
    // COMMIT of a failed transaction is a rollback; say so, as Postgres does.
    // The tag otherwise comes from the SQL text, which would claim "COMMIT".
    let committed_failed =
        backend.txn.failed && matches!(effects.as_slice(), [TxnEffect::End { .. }]);
    backend
        .txn
        .apply(&effects, ran.is_ok(), &policy::PG_PROFILE);
    let rs = match ran {
        Ok(Ok((cols, rows, tag))) => {
            let tag = if committed_failed {
                "ROLLBACK".to_string()
            } else {
                tag
            };
            (cols, rows, tag)
        }
        Ok(Err(Undecodable)) => {
            AuditEvent::new(
                env_name,
                client_user,
                sql,
                AuditDecision::Allow,
                Some("result not valid UTF-8".into()),
                None,
                started.elapsed(),
            )
            .emit();
            // Say it ran: "query failed" would invite a retry that repeats
            // a write.
            proto::write_raw(
                stream,
                &proto::error_response(
                    SQLSTATE_CHARACTER_NOT_IN_REPERTOIRE,
                    "the statement ran, but its result is not valid UTF-8",
                ),
            )
            .await?;
            return Ok(false);
        }
        Err(e) => {
            warn!(env = env_name, err = %e, "pg backend query error");
            let (state, reason) = backend_error(&e);
            AuditEvent::new(
                env_name,
                client_user,
                sql,
                AuditDecision::Error,
                Some(reason),
                None,
                started.elapsed(),
            )
            .emit();
            let (frame, lost) = failure_frame(state, connection_lost(&e, client), "query failed");
            proto::write_raw(stream, &frame).await?;
            // The pinned connection (and any open transaction) is gone; end
            // the session rather than continue on a fresh one.
            if lost {
                return Err(EngineError::Backend("backend connection lost".into()));
            }
            return Ok(false);
        }
    };
    if with_description {
        write_result_set(stream, &rs).await?;
    } else {
        for row in &rs.1 {
            proto::write_raw(stream, &proto::data_row(row)).await?;
        }
        proto::write_raw(stream, &proto::command_complete(&rs.2)).await?;
    }
    AuditEvent::new(
        env_name,
        client_user,
        sql,
        AuditDecision::Allow,
        None,
        Some(rs.1.len() as u64),
        started.elapsed(),
    )
    .emit();
    Ok(true)
}

/// The session's backend connection and the transaction state it is in.
struct Pinned<'a> {
    conn: PinnedConn<'a>,
    txn: TxnState,
    /// When the backend last ran a statement; bounds idle-in-transaction.
    last_statement: std::time::Instant,
}

struct Prepared {
    sql: String,
    /// Real parameter type OIDs from the backend prepare.
    param_oids: Vec<i32>,
    /// Real result columns (name, type OID) from the backend prepare.
    col_meta: Vec<(String, i32)>,
}

struct Portal {
    stmt: String,
    /// Parameter-inlined, executable SQL.
    sql: String,
}

pub async fn serve(
    stream: &mut TcpStream,
    env_name: &str,
    client_user: &str,
    pool: &PgPool,
    pol: &Policy,
    idle_timeout: Duration,
) -> Result<(), EngineError> {
    let mut backend = Pinned {
        conn: PinnedConn::new(pool),
        txn: TxnState::default(),
        last_statement: std::time::Instant::now(),
    };
    let mut prepared: HashMap<String, Prepared> = HashMap::new();
    let mut portals: HashMap<String, Portal> = HashMap::new();
    // Set once an error occurs in an extended-protocol series; suppresses
    // further work until the next Sync (matches PG skip-until-Sync rule).
    let mut skip_until_sync = false;

    loop {
        let wait = next_wait(idle_timeout, backend.txn.in_txn, backend.last_statement);
        let Some(msg) = within_idle(wait, proto::read_message(stream)).await else {
            info!(env = env_name, "closing idle session");
            // As Postgres's own idle timeouts say it. Best effort: the
            // client may be gone already.
            // Bounded: a client that stopped reading must not hold the
            // session (and its locks) open.
            let state = if backend.txn.in_txn { "25P03" } else { "57P05" };
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                proto::write_raw(
                    stream,
                    &proto::fatal_response(state, "terminating idle session"),
                ),
            )
            .await;
            return Ok(());
        };
        let (tag, body) = match msg {
            Ok(m) => m,
            Err(PgProtoError::Closed) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        match tag {
            // --- Simple query ---
            b'Q' => {
                let sql = body
                    .split(|&b| b == 0)
                    .next()
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .unwrap_or_default();
                if sql.trim().is_empty() {
                    proto::write_raw(stream, &proto::empty_query_response()).await?;
                } else {
                    let _ =
                        exec(stream, env_name, client_user, &sql, &mut backend, pol, true).await?;
                }
                proto::write_raw(stream, &proto::ready_for_query(rfq_status(&backend.txn))).await?;
            }

            // --- Extended query ---
            b'P' => {
                if skip_until_sync {
                    continue;
                }
                let Some(m) = proto::parse_parse(&body) else {
                    proto::write_raw(
                        stream,
                        &proto::error_response(SQLSTATE_FEATURE_NOT_SUPPORTED, "bad Parse"),
                    )
                    .await?;
                    skip_until_sync = true;
                    continue;
                };
                if let Decision::Deny(reason) = policy::evaluate(&m.query, pol, &policy::PG_PROFILE)
                {
                    info!(env = env_name, reason, "pg policy DENY (parse)");
                    AuditEvent::new(
                        env_name,
                        client_user,
                        &m.query,
                        AuditDecision::Deny,
                        Some(reason.to_string()),
                        None,
                        std::time::Duration::ZERO,
                    )
                    .emit();
                    proto::write_raw(
                        stream,
                        &proto::error_response(SQLSTATE_INSUFFICIENT_PRIVILEGE, reason),
                    )
                    .await?;
                    skip_until_sync = true;
                    continue;
                }
                // Parse+Describe on the backend for accurate param/result
                // metadata (pgjdbc relies on this for prepared reuse).
                match backend_describe(&mut backend.conn, &m.query).await {
                    Ok((param_oids, col_meta)) => {
                        prepared.insert(
                            m.stmt.clone(),
                            Prepared {
                                sql: m.query,
                                param_oids,
                                col_meta,
                            },
                        );
                        proto::write_raw(stream, &proto::parse_complete()).await?;
                    }
                    Err(BackendFailure {
                        state,
                        reason,
                        lost,
                    }) => {
                        // A failed prepare aborts an open transaction too.
                        backend
                            .txn
                            .apply(&[TxnEffect::Other], false, &policy::PG_PROFILE);
                        warn!(env = env_name, err = %reason, "pg backend parse failed");
                        AuditEvent::new(
                            env_name,
                            client_user,
                            &m.query,
                            AuditDecision::Error,
                            Some(reason),
                            None,
                            std::time::Duration::ZERO,
                        )
                        .emit();
                        let (frame, lost) =
                            failure_frame(state.as_deref(), lost, "statement parse failed");
                        proto::write_raw(stream, &frame).await?;
                        if lost {
                            return Err(EngineError::Backend("backend connection lost".into()));
                        }
                        skip_until_sync = true;
                    }
                }
            }
            b'B' => {
                if skip_until_sync {
                    continue;
                }
                let Some(m) = proto::parse_bind(&body) else {
                    proto::write_raw(
                        stream,
                        &proto::error_response(SQLSTATE_FEATURE_NOT_SUPPORTED, "bad Bind"),
                    )
                    .await?;
                    skip_until_sync = true;
                    continue;
                };
                let Some(prep) = prepared.get(&m.stmt) else {
                    proto::write_raw(
                        stream,
                        &proto::error_response(SQLSTATE_INTERNAL, "unknown prepared statement"),
                    )
                    .await?;
                    skip_until_sync = true;
                    continue;
                };
                let mut rendered = Vec::with_capacity(m.params.len());
                let mut bad: Option<&'static str> = None;
                for (i, val) in m.params.iter().enumerate() {
                    let oid = prep.param_oids.get(i).copied().unwrap_or(0);
                    let fmt = m.param_formats.get(i).copied().unwrap_or(0);
                    match render_param(oid, fmt, val) {
                        Ok(r) => rendered.push(r),
                        Err(e) => {
                            bad = Some(e);
                            break;
                        }
                    }
                }
                if let Some(e) = bad {
                    proto::write_raw(
                        stream,
                        &proto::error_response(SQLSTATE_FEATURE_NOT_SUPPORTED, e),
                    )
                    .await?;
                    skip_until_sync = true;
                    continue;
                }
                let inlined = inline_params(&prep.sql, &rendered);
                portals.insert(
                    m.portal.clone(),
                    Portal {
                        stmt: m.stmt.clone(),
                        sql: inlined,
                    },
                );
                proto::write_raw(stream, &proto::bind_complete()).await?;
            }
            b'D' => {
                if skip_until_sync {
                    continue;
                }
                let Some((kind, name)) = proto::parse_describe_or_close(&body) else {
                    proto::write_raw(stream, &proto::no_data()).await?;
                    continue;
                };
                let meta = if kind == b'S' {
                    prepared
                        .get(&name)
                        .map(|p| (Some(p.param_oids.clone()), p.col_meta.clone()))
                } else {
                    portals
                        .get(&name)
                        .and_then(|po| prepared.get(&po.stmt))
                        .map(|p| (None, p.col_meta.clone()))
                };
                match meta {
                    Some((param_oids, col_meta)) => {
                        if let Some(oids) = param_oids {
                            proto::write_raw(stream, &proto::parameter_description(&oids)).await?;
                        }
                        if col_meta.is_empty() {
                            proto::write_raw(stream, &proto::no_data()).await?;
                        } else {
                            proto::write_raw(stream, &proto::row_description(&col_meta)).await?;
                        }
                    }
                    None => proto::write_raw(stream, &proto::no_data()).await?,
                }
            }
            b'E' => {
                if skip_until_sync {
                    continue;
                }
                let portal_name = proto::parse_execute(&body).unwrap_or_default();
                let sql = match portals.get(&portal_name) {
                    Some(p) => p.sql.clone(),
                    None => {
                        proto::write_raw(
                            stream,
                            &proto::error_response(SQLSTATE_INTERNAL, "unknown portal"),
                        )
                        .await?;
                        skip_until_sync = true;
                        continue;
                    }
                };
                // Execute streams ONLY DataRows + CommandComplete; the client
                // already has the field structure from Describe.
                if !exec(
                    stream,
                    env_name,
                    client_user,
                    &sql,
                    &mut backend,
                    pol,
                    false,
                )
                .await?
                {
                    skip_until_sync = true;
                }
            }
            b'C' => {
                if let Some((kind, name)) = proto::parse_describe_or_close(&body) {
                    if kind == b'S' {
                        prepared.remove(&name);
                    } else {
                        portals.remove(&name);
                    }
                }
                proto::write_raw(stream, &proto::close_complete()).await?;
            }
            b'H' => { /* Flush: we write eagerly, nothing buffered */ }
            b'S' => {
                skip_until_sync = false;
                proto::write_raw(stream, &proto::ready_for_query(rfq_status(&backend.txn))).await?;
            }
            b'X' => return Ok(()),
            other => {
                warn!(env = env_name, tag = other, "pg: unsupported message");
                proto::write_raw(
                    stream,
                    &proto::error_response(SQLSTATE_FEATURE_NOT_SUPPORTED, "unsupported message"),
                )
                .await?;
                proto::write_raw(stream, &proto::ready_for_query(rfq_status(&backend.txn))).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hang_up_states_end_the_session_as_fatal() {
        for state in ["57P01", "57P02", "57P05", "25P03"] {
            let (frame, lost) = failure_frame(Some(state), false, "x");
            assert!(lost, "{state}");
            assert_eq!(frame, proto::fatal_response(state, "x"));
        }
        // Serialization failure, deadlock: retryable, the session goes on.
        for state in ["40001", "40P01"] {
            let (frame, lost) = failure_frame(Some(state), false, "x");
            assert!(!lost, "{state}");
            assert_eq!(frame, proto::error_response(state, "x"));
        }
        for state in [None, Some("40001")] {
            let (frame, lost) = failure_frame(state, true, "x");
            assert!(lost, "{state:?}");
            assert_eq!(frame, proto::fatal_response("08006", "x"));
        }
        // No server code on a live connection (pool, protocol): recoverable.
        let (frame, lost) = failure_frame(None, false, "x");
        assert!(!lost);
        assert_eq!(frame, proto::error_response(SQLSTATE_INTERNAL, "x"));
    }

    /// Build a 1-D PG binary array payload.
    fn bin_array(elem_oid: i32, elems: &[Option<&[u8]>]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&1i32.to_be_bytes()); // ndim
        v.extend_from_slice(&0i32.to_be_bytes()); // flags
        v.extend_from_slice(&elem_oid.to_be_bytes());
        v.extend_from_slice(&(elems.len() as i32).to_be_bytes()); // dim len
        v.extend_from_slice(&1i32.to_be_bytes()); // lower bound
        for e in elems {
            match e {
                None => v.extend_from_slice(&(-1i32).to_be_bytes()),
                Some(b) => {
                    v.extend_from_slice(&(b.len() as i32).to_be_bytes());
                    v.extend_from_slice(b);
                }
            }
        }
        v
    }

    #[test]
    fn quote_lit_escapes() {
        assert_eq!(quote_lit("ab"), "'ab'");
        assert_eq!(quote_lit("a'b"), "'a''b'");
        assert_eq!(quote_lit(""), "''");
        assert_eq!(quote_lit("''"), "''''''");
    }

    #[test]
    fn safe_numeric() {
        for ok in [
            "0",
            "123",
            "-1",
            "+7",
            "1.5",
            "-1.25",
            ".5",
            "1.",
            "1e10",
            "1.5e-3",
            "-2E+4",
            "NaN",
            "Infinity",
            "-Infinity",
        ] {
            assert!(is_safe_numeric(ok), "should accept {ok:?}");
        }
        for bad in [
            "", " ", "abc", "1 OR 1=1", "1;2", "1,2", "0x10", "1e", "--1", "1..2", "1 2", ") OR (",
            "1)",
        ] {
            assert!(!is_safe_numeric(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn float_formatting() {
        assert_eq!(fmt_float(1.5), "1.5");
        assert_eq!(fmt_float(f64::NAN), "'NaN'");
        assert_eq!(fmt_float(f64::INFINITY), "'Infinity'");
        assert_eq!(fmt_float(f64::NEG_INFINITY), "'-Infinity'");
    }

    #[test]
    fn render_scalar_null_and_bool() {
        assert_eq!(render_scalar(25, 0, None).unwrap(), "NULL");
        assert_eq!(render_scalar(OID_BOOL, 1, Some(&[1])).unwrap(), "TRUE");
        assert_eq!(render_scalar(OID_BOOL, 1, Some(&[0])).unwrap(), "FALSE");
        assert_eq!(render_scalar(OID_BOOL, 0, Some(b"t")).unwrap(), "TRUE");
        assert_eq!(render_scalar(OID_BOOL, 0, Some(b"false")).unwrap(), "FALSE");
    }

    #[test]
    fn render_scalar_binary_ints() {
        assert_eq!(
            render_scalar(OID_INT2, 1, Some(&7i16.to_be_bytes())).unwrap(),
            "7"
        );
        assert_eq!(
            render_scalar(OID_INT4, 1, Some(&513i32.to_be_bytes())).unwrap(),
            "513"
        );
        assert_eq!(
            render_scalar(OID_INT8, 1, Some(&9i64.to_be_bytes())).unwrap(),
            "9"
        );
        // regclass (2205) family decoded as i32
        assert_eq!(
            render_scalar(2205, 1, Some(&2200i32.to_be_bytes())).unwrap(),
            "2200"
        );
        // unknown binary with NUL, 4 bytes -> int
        assert_eq!(
            render_scalar(99999, 1, Some(&2200i32.to_be_bytes())).unwrap(),
            "2200"
        );
        // unknown binary, no NUL -> quoted text
        assert_eq!(render_scalar(99999, 1, Some(b"abc")).unwrap(), "'abc'");
        // unknown binary with NUL but odd length -> rejected
        assert!(render_scalar(99999, 1, Some(&[0, 1, 2])).is_err());
    }

    #[test]
    fn render_scalar_text_numeric_injection_guarded() {
        assert_eq!(render_scalar(OID_INT4, 0, Some(b"42")).unwrap(), "42");
        // numeric-typed but not a numeric literal: must be quoted, not raw
        assert_eq!(
            render_scalar(OID_INT4, 0, Some(b"0 OR 1=1")).unwrap(),
            "'0 OR 1=1'"
        );
        assert_eq!(
            render_scalar(25, 0, Some(b"O'Brien")).unwrap(),
            "'O''Brien'"
        );
    }

    #[test]
    fn decode_array_basic() {
        let payload = bin_array(25, &[Some(b"a"), Some(b"bb"), None]);
        let (oid, elems) = decode_bin_array(&payload).unwrap();
        assert_eq!(oid, 25);
        assert_eq!(elems, vec![Some(b"a".to_vec()), Some(b"bb".to_vec()), None]);
        // empty (ndim=0)
        let mut empty = Vec::new();
        empty.extend_from_slice(&0i32.to_be_bytes());
        empty.extend_from_slice(&0i32.to_be_bytes());
        empty.extend_from_slice(&25i32.to_be_bytes());
        assert_eq!(decode_bin_array(&empty).unwrap(), (25, vec![]));
        // malformed
        assert!(decode_bin_array(&[0, 1, 2]).is_err());
    }

    #[test]
    fn render_param_arrays() {
        // text[] (oid 1009) binary
        let p = Some(bin_array(25, &[Some(b"alpha"), Some(b"gamma")]));
        assert_eq!(render_param(1009, 1, &p).unwrap(), "ARRAY['alpha','gamma']");
        // int4[] (oid 1007) binary
        let p = Some(bin_array(
            OID_INT4,
            &[Some(&1i32.to_be_bytes()), Some(&3i32.to_be_bytes())],
        ));
        assert_eq!(render_param(1007, 1, &p).unwrap(), "ARRAY[1,3]");
        // empty array -> typed empty
        let mut empty = Vec::new();
        empty.extend_from_slice(&0i32.to_be_bytes());
        empty.extend_from_slice(&0i32.to_be_bytes());
        empty.extend_from_slice(&OID_INT4.to_be_bytes());
        assert_eq!(
            render_param(1007, 1, &Some(empty)).unwrap(),
            "ARRAY[]::int4[]"
        );
        // NULL whole param
        assert_eq!(render_param(1009, 1, &None).unwrap(), "NULL");
        // text-format array literal
        assert_eq!(
            render_param(1009, 0, &Some(b"{a,b}".to_vec())).unwrap(),
            "'{a,b}'::text[]"
        );
    }

    #[test]
    fn inline_basic_and_skips() {
        let r = ["1".to_string(), "'x'".to_string()];
        assert_eq!(inline_params("SELECT $1, $2", &r), "SELECT 1, 'x'");
        assert_eq!(inline_params("SELECT '$1'", &r), "SELECT '$1'");
        assert_eq!(inline_params("\"$1\" $1", &r), "\"$1\" 1");
        assert_eq!(inline_params("-- $1\n$1", &r), "-- $1\n1");
        assert_eq!(inline_params("/* $1 */ $1", &r), "/* $1 */ 1");
        // out-of-range / $0 left as-is
        assert_eq!(inline_params("$0 $9", &r), "$0 $9");
    }

    #[test]
    fn inline_multidigit_and_dollar_quote() {
        let r: Vec<String> = (1..=12).map(|n| n.to_string()).collect();
        assert_eq!(inline_params("v=$12", &r), "v=12");
        // $$...$$ body must not be substituted; $1 after it must be
        assert_eq!(inline_params("$$ $1 $$ $1", &r), "$$ $1 $$ 1");
        assert_eq!(
            inline_params("$tag$ a $1 $tag$ $2", &r),
            "$tag$ a $1 $tag$ 2"
        );
    }

    #[test]
    fn inline_preserves_multibyte() {
        let r = ["1".to_string()];
        // non-ASCII in a literal must survive byte-for-byte
        assert_eq!(inline_params("SELECT 'café', $1", &r), "SELECT 'café', 1");
    }

    #[test]
    fn command_tags() {
        assert_eq!(command_tag("SELECT * FROM t", 3), "SELECT 3");
        assert_eq!(command_tag("  with x as (..) select", 2), "SELECT 2");
        assert_eq!(command_tag("INSERT INTO t VALUES(1)", 1), "INSERT 0 1");
        assert_eq!(command_tag("SET application_name='x'", 0), "SET");
        assert_eq!(command_tag("BEGIN", 0), "BEGIN");
    }

    #[test]
    fn array_oid_maps() {
        assert_eq!(array_elem_oid(1009), Some(25));
        assert_eq!(array_elem_oid(1007), Some(OID_INT4));
        assert_eq!(array_elem_oid(23), None);
        assert_eq!(elem_type_name(25), "text");
        assert_eq!(elem_type_name(OID_INT4), "int4");
        assert_eq!(elem_type_name(99999), "text");
    }
}
