//! Per-session router. After handshake completes successfully, this loops
//! over command packets: COM_QUIT closes, COM_PING replies OK, COM_QUERY is
//! firewalled by [`mw_core::policy`] and then forwarded to the backend
//! pool. Anything else gets a polite ERR.

use std::time::Instant;

use mysql_async::prelude::Queryable;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use mw_core::audit::{AuditEvent, Decision as AuditDecision};
use mw_core::config::Policy;
use mw_core::policy;

use crate::framing::{read_packet, write_packet, FramingError, SequenceCounter};
use crate::mysql_client::BackendPool;
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

const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;
const ER_PARSE_ERROR:           u16 = 1064;
const ER_NOT_ALLOWED_COMMAND:   u16 = 1148;
const ER_INTERNAL:              u16 = 1815;

pub async fn serve_session<S>(
    stream: &mut S,
    env_name: &str,
    client_user: &str,
    pool: &BackendPool,
    pol: &Policy,
) -> Result<(), RouterError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut seq = SequenceCounter::default();
    loop {
        seq.reset();
        let pkt = match read_packet(stream, &mut seq).await {
            Ok(p) => p,
            Err(FramingError::UnexpectedEof { .. }) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let Some(cmd) = pkt.first().copied() else {
            return Err(FramingError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData, "empty command packet")).into());
        };
        match cmd {
            0x01 => {
                debug!(env = env_name, "COM_QUIT");
                return Ok(());
            }
            0x0E => {
                write_packet(stream, &mut seq, &ok_packet()).await?;
            }
            0x03 => {
                let sql_bytes = &pkt[1..];
                let sql = String::from_utf8_lossy(sql_bytes);
                handle_com_query(stream, &mut seq, env_name, client_user, &sql, pool, pol).await?;
            }
            other => {
                warn!(env = env_name, cmd = format!("0x{other:02x}"), "rejecting unsupported command");
                write_packet(stream, &mut seq,
                    &err_packet(ER_NOT_ALLOWED_COMMAND, b"42000",
                        &format!("command 0x{other:02x} not supported"))).await?;
            }
        }
    }
}

async fn handle_com_query<S>(
    stream: &mut S,
    seq: &mut SequenceCounter,
    env_name: &str,
    client_user: &str,
    sql: &str,
    pool: &BackendPool,
    pol: &Policy,
) -> Result<(), RouterError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let decision = policy::evaluate(sql, pol, &policy::MYSQL_PROFILE);
    if let Some(reason) = decision.reason() {
        info!(env = env_name, reason = reason, sql_first = &sql[..sql.len().min(64)],
              "policy DENY");
        AuditEvent::new(env_name, client_user, sql,
            AuditDecision::Deny, Some(reason.to_string()), None, started.elapsed()).emit();
        write_packet(stream, seq, &err_packet(ER_PARSE_ERROR, b"42000", reason)).await?;
        return Ok(());
    }

    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!(env = env_name, err = %e, "pool exhausted / unreachable");
            AuditEvent::new(env_name, client_user, sql,
                AuditDecision::Error, Some(format!("pool: {e}")), None, started.elapsed()).emit();
            // Generic message to the client: the detail (host, schema,
            // mysql_async error) is in the audit log + warn! above, not on
            // the wire where the client could fingerprint the backend.
            write_packet(stream, seq,
                &err_packet(ER_INTERNAL, b"HY000", "backend unavailable")).await?;
            return Ok(());
        }
    };

    let result = conn.query_iter(sql.to_string()).await;
    let mut qr = match result {
        Ok(qr) => qr,
        Err(e) => {
            warn!(env = env_name, err = %e, "backend rejected query");
            AuditEvent::new(env_name, client_user, sql,
                AuditDecision::Error, Some(format!("backend: {e}")), None, started.elapsed()).emit();
            write_packet(stream, seq,
                &err_packet(ER_INTERNAL, b"HY000", "query execution failed")).await?;
            return Ok(());
        }
    };

    let columns = qr.columns().map(|arc| arc.to_vec());
    let row_count: u64 = match columns {
        Some(cols) if !cols.is_empty() => {
            write_packet(stream, seq, &wire::column_count_packet(cols.len() as u64)).await?;
            for c in &cols {
                write_packet(stream, seq, &wire::column_def_packet(c)).await?;
            }
            let mut n: u64 = 0;
            while let Some(row) = qr.next().await? {
                write_packet(stream, seq, &wire::row_text_packet(&row)).await?;
                n += 1;
            }
            write_packet(stream, seq, &wire::ok_eof_packet(0, 0)).await?;
            n
        }
        _ => {
            let _ = qr.drop_result().await;
            write_packet(stream, seq, &ok_packet()).await?;
            0
        }
    };
    debug!(env = env_name, rows = row_count, "query ok");
    AuditEvent::new(env_name, client_user, sql,
        AuditDecision::Allow, None, Some(row_count), started.elapsed()).emit();
    Ok(())
}

fn ok_packet() -> Vec<u8> {
    let mut p = Vec::with_capacity(7);
    p.push(0x00);
    p.push(0x00); // affected_rows lenenc=0
    p.push(0x00); // last_insert_id lenenc=0
    p.extend_from_slice(&SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
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
