//! Per-session router. After handshake completes successfully, this loops
//! over command packets: COM_QUIT closes, COM_PING replies OK, COM_QUERY is
//! firewalled by [`mw_core::policy`] and then forwarded to the backend
//! pool. Anything else gets a polite ERR.

use std::time::{Duration, Instant};

use mysql_async::prelude::Queryable;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use mw_core::audit::{AuditEvent, Decision as AuditDecision};
use mw_core::config::Policy;
use mw_core::policy::{self, TxnState};

use crate::framing::{read_packet, write_lenenc_int, write_packet, FramingError, SequenceCounter};
use crate::idle::{next_wait, within_idle};
use crate::mysql_client::{BackendManager, BackendPool};
use crate::session_conn::SessionConn;
use crate::wire;

#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error(transparent)]
    Framing(#[from] FramingError),
    #[error("backend pool: {0}")]
    Pool(String),
    #[error("backend query: {0}")]
    Backend(#[from] mysql_async::Error),
}

const SERVER_STATUS_IN_TRANS: u16 = 0x0001;
const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;
const ER_PARSE_ERROR: u16 = 1064;
const ER_NOT_ALLOWED_COMMAND: u16 = 1148;
const ER_INTERNAL: u16 = 1815;
const ER_LOCK_WAIT_TIMEOUT: u16 = 1205;
const ER_LOCK_DEADLOCK: u16 = 1213;

pub async fn serve_session<S>(
    stream: &mut S,
    env_name: &str,
    client_user: &str,
    pool: &BackendPool,
    pol: &Policy,
    idle_timeout: Duration,
) -> Result<(), RouterError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut seq = SequenceCounter::default();
    let mut backend = Pinned {
        conn: SessionConn::new(pool),
        txn: TxnState::default(),
        last_statement: Instant::now(),
    };
    loop {
        seq.reset();
        let wait = next_wait(idle_timeout, backend.txn.in_txn, backend.last_statement);
        let Some(pkt) = within_idle(wait, read_packet(stream, &mut seq)).await else {
            debug!(env = env_name, "closing idle session");
            return Ok(());
        };
        let pkt = match pkt {
            Ok(p) => p,
            Err(FramingError::UnexpectedEof { .. }) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let Some(cmd) = pkt.first().copied() else {
            return Err(FramingError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "empty command packet",
            ))
            .into());
        };
        match cmd {
            0x01 => {
                debug!(env = env_name, "COM_QUIT");
                return Ok(());
            }
            0x0E => {
                write_packet(
                    stream,
                    &mut seq,
                    &ok_packet(0, 0, status_flags(&backend.txn)),
                )
                .await?;
            }
            0x03 => {
                let sql_bytes = &pkt[1..];
                let sql = String::from_utf8_lossy(sql_bytes);
                handle_com_query(
                    stream,
                    &mut seq,
                    env_name,
                    client_user,
                    &sql,
                    &mut backend,
                    pol,
                )
                .await?;
            }
            other => {
                warn!(
                    env = env_name,
                    cmd = format!("0x{other:02x}"),
                    "rejecting unsupported command"
                );
                write_packet(
                    stream,
                    &mut seq,
                    &err_packet(
                        ER_NOT_ALLOWED_COMMAND,
                        b"42000",
                        &format!("command 0x{other:02x} not supported"),
                    ),
                )
                .await?;
            }
        }
    }
}

/// The session's backend connection and the transaction state it is in.
struct Pinned<'a> {
    conn: SessionConn<'a, BackendManager>,
    txn: TxnState,
    /// When the backend last ran a statement; bounds idle-in-transaction.
    last_statement: Instant,
}

async fn handle_com_query<S>(
    stream: &mut S,
    seq: &mut SequenceCounter,
    env_name: &str,
    client_user: &str,
    sql: &str,
    backend: &mut Pinned<'_>,
    pol: &Policy,
) -> Result<(), RouterError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let (decision, effects) = policy::check(sql, pol, &policy::MYSQL_PROFILE);
    if let Some(reason) = decision.reason() {
        info!(
            env = env_name,
            reason = reason,
            sql_first = &sql[..sql.len().min(64)],
            "policy DENY"
        );
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
        write_packet(stream, seq, &err_packet(ER_PARSE_ERROR, b"42000", reason)).await?;
        return Ok(());
    }

    let Pinned {
        conn,
        txn,
        last_statement,
    } = backend;
    // Read at error time: the first connect is what records the setting.
    let manager = conn.manager();
    let conn = match conn.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(env = env_name, err = %e, "pool exhausted / unreachable");
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
            // Generic message to the client: the detail (host, schema,
            // mysql_async error) is in the audit log + warn! above, not on
            // the wire where the client could fingerprint the backend.
            write_packet(
                stream,
                seq,
                &err_packet(ER_INTERNAL, b"HY000", "backend unavailable"),
            )
            .await?;
            return Ok(());
        }
    };

    // The OK/EOF that ends a successful result must already carry the state
    // this statement leaves behind (e.g. IN_TRANS after BEGIN).
    let mut on_success = *txn;
    on_success.apply(&effects, true, &policy::MYSQL_PROFILE);
    let outcome = forward(stream, seq, conn, sql, status_flags(&on_success)).await?;
    *last_statement = Instant::now();
    match outcome {
        Ok(row_count) => {
            *txn = on_success;
            debug!(env = env_name, rows = row_count, "query ok");
            AuditEvent::new(
                env_name,
                client_user,
                sql,
                AuditDecision::Allow,
                None,
                Some(row_count),
                started.elapsed(),
            )
            .emit();
            Ok(())
        }
        Err(e) => {
            txn.apply(&effects, false, &policy::MYSQL_PROFILE);
            // The server rolled the whole transaction back: always on a
            // deadlock, and on a lock wait timeout when it's configured to.
            let rolled_back = match &e {
                mysql_async::Error::Server(se) => {
                    se.code == ER_LOCK_DEADLOCK
                        || (se.code == ER_LOCK_WAIT_TIMEOUT
                            && manager
                                .rollback_on_timeout
                                .load(std::sync::atomic::Ordering::Relaxed))
                }
                _ => false,
            };
            if rolled_back {
                txn.rolled_back();
            }
            warn!(env = env_name, err = %e, "backend rejected query");
            AuditEvent::new(
                env_name,
                client_user,
                sql,
                AuditDecision::Error,
                Some(format!("backend: {e}")),
                None,
                started.elapsed(),
            )
            .emit();
            // Valid at any point, including mid result set: ERR ends it.
            write_packet(
                stream,
                seq,
                // The server's code and SQLSTATE, so deadlock and lock-wait
                // retries still work; the message stays hidden.
                &match &e {
                    mysql_async::Error::Server(se) => err_packet(
                        se.code,
                        se.state.as_bytes().try_into().unwrap_or(b"HY000"),
                        "query execution failed",
                    ),
                    _ => err_packet(ER_INTERNAL, b"HY000", "query execution failed"),
                },
            )
            .await?;
            // A server-side SQL error leaves the pinned connection usable.
            // Anything else means it (and any transaction on it) is gone, or
            // left unread packets behind; end the session rather than
            // continue on a desynced or fresh connection.
            // Except the ones the server sends right before it hangs up:
            // shutdown, killed connection, idle timeout.
            if matches!(&e, mysql_async::Error::Server(se) if !matches!(se.code, 1053 | 1927 | 4031))
            {
                Ok(())
            } else {
                Err(e.into())
            }
        }
    }
}

/// Run `sql` on the backend and relay its result. The outer error is the
/// client socket; the inner one is the backend's, for the caller to report.
async fn forward<S>(
    stream: &mut S,
    seq: &mut SequenceCounter,
    conn: &mut mysql_async::Conn,
    sql: &str,
    status: u16,
) -> Result<Result<u64, mysql_async::Error>, RouterError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut qr = match conn.query_iter(sql.to_string()).await {
        Ok(qr) => qr,
        Err(e) => return Ok(Err(e)),
    };
    let columns = qr.columns().map(|arc| arc.to_vec());
    match columns {
        Some(cols) if !cols.is_empty() => {
            write_packet(stream, seq, &wire::column_count_packet(cols.len() as u64)).await?;
            for c in &cols {
                write_packet(stream, seq, &wire::column_def_packet(c)).await?;
            }
            let mut n: u64 = 0;
            loop {
                match qr.next().await {
                    Ok(Some(row)) => {
                        write_packet(stream, seq, &wire::row_text_packet(&row)).await?;
                        n += 1;
                    }
                    Ok(None) => break,
                    Err(e) => return Ok(Err(e)),
                }
            }
            write_packet(stream, seq, &wire::ok_eof_packet(0, 0, status)).await?;
            Ok(Ok(n))
        }
        _ => {
            // DML under a writable policy: ORMs check the row count
            // (optimistic locking) and read the generated key.
            let affected = qr.affected_rows();
            let last_id = qr.last_insert_id().unwrap_or(0);
            if let Err(e) = qr.drop_result().await {
                return Ok(Err(e));
            }
            write_packet(stream, seq, &ok_packet(affected, last_id, status)).await?;
            Ok(Ok(0))
        }
    }
}

fn status_flags(t: &TxnState) -> u16 {
    let mut f = 0;
    if t.autocommit {
        f |= SERVER_STATUS_AUTOCOMMIT;
    }
    if t.in_txn {
        f |= SERVER_STATUS_IN_TRANS;
    }
    f
}

fn ok_packet(affected_rows: u64, last_insert_id: u64, status: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(23);
    p.push(0x00);
    write_lenenc_int(&mut p, affected_rows);
    write_lenenc_int(&mut p, last_insert_id);
    p.extend_from_slice(&status.to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes());
    p
}

fn err_packet(code: u16, sqlstate: &[u8; 5], msg: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(9 + msg.len());
    p.push(0xFF);
    p.extend_from_slice(&code.to_le_bytes());
    p.push(b'#');
    p.extend_from_slice(sqlstate);
    p.extend_from_slice(msg.as_bytes());
    p
}
