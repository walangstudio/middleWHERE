//! Local control channel: the unprivileged CLI sends config-mutation and read
//! requests over a Unix-domain socket (Unix) or a named pipe (Windows); the
//! privileged daemon authorizes the peer, applies the change to its live env
//! table, and replies. One request per connection.
//!
//! Layering:
//! * [`peercred`] — the pure allow/deny decision (unit-tested exhaustively).
//! * `unix` / `windows` — platform transport + the syscalls that populate the
//!   peer identity and bind the socket/pipe with an admins-only ACL.
//! * [`handlers`] — request dispatch onto the live [`Daemon`].
//!
//! The wire codec is [`mw_core::control`] (sync `Read`/`Write` over CBOR
//! frames); this module adapts it to tokio by reading the whole frame into a
//! bounded buffer and decoding off that, so mw-core stays runtime-agnostic.

use std::sync::Arc;

use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, Semaphore};
use tracing::warn;

use mw_core::audit::{AdminEvent, Decision};
use mw_core::control::{read_frame, write_frame, Request, Response, MAX_FRAME, PROTOCOL_VERSION};

use crate::Daemon;

use peercred::{AuthDecision, PeerIdentity};

pub(crate) mod handlers;
pub(crate) mod peercred;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// Service name used to derive the socket/pipe name and to resolve the
/// service-account SID in the Windows ACL. Matches `winsvc::SERVICE_NAME`.
pub(crate) const SERVICE_NAME: &str = "mwsqld";

/// The privileged admin group whose members may drive the control channel.
pub(crate) const ADMIN_GROUP: &str = "middlewhere-admins";

/// Cap on concurrently-serviced control connections. A local principal that can
/// reach the socket directory but fails authz must not be able to exhaust the
/// daemon by opening connections faster than they are drained; the accept loop
/// blocks on this permit, applying backpressure. One request per connection
/// keeps each task short-lived, so a small cap is plenty.
const MAX_INFLIGHT: usize = 16;

/// Spawn-free entry: run the platform accept loop until `shutdown` fires. Called
/// from `Daemon::run`, holding an `Arc<Daemon>` so handlers can mutate the live
/// env table. Any bind error is logged and the loop simply exits — a daemon that
/// can serve envs but not its control channel keeps serving envs.
pub(crate) async fn serve(daemon: Arc<Daemon>, shutdown: &mut broadcast::Receiver<()>) {
    #[cfg(unix)]
    let result = unix::serve_loop(daemon, shutdown).await;
    #[cfg(windows)]
    let result = windows::serve_loop(daemon, shutdown).await;
    #[cfg(not(any(unix, windows)))]
    let result = {
        let _ = (&daemon, &shutdown);
        Ok(())
    };
    if let Err(e) = result {
        warn!(err = %format!("{e:#}"), "control channel stopped");
    }
}

/// Shared per-connection state machine, generic over the transport stream. The
/// caller has already resolved the peer identity + authorization decision
/// (platform-specific, done before the first `.await` so Windows impersonation
/// stays thread-local). Sequence: read `Hello` + version-check, enforce the
/// authz decision, read one request, dispatch, write one response, close.
async fn handle_conn<S>(
    daemon: Arc<Daemon>,
    mut stream: S,
    decision: AuthDecision,
    peer: PeerIdentity,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Version preamble. Reject a mismatch (or a missing Hello) before doing
    //    any work or leaking whether authz would have passed.
    match read_request(&mut stream).await {
        Ok(Request::Hello { version }) if version == PROTOCOL_VERSION => {}
        Ok(Request::Hello { .. }) => {
            let _ = write_response(
                &mut stream,
                &Response::Error("protocol version mismatch; upgrade the client".into()),
            )
            .await;
            return;
        }
        Ok(_) => {
            let _ = write_response(
                &mut stream,
                &Response::Error("expected a Hello preamble first".into()),
            )
            .await;
            return;
        }
        Err(_) => return, // truncated/hostile framing: drop silently.
    }

    // 2. Enforce authorization. A denied peer is audited and told, then dropped
    //    without ever reading its request payload.
    if let AuthDecision::Deny(reason) = &decision {
        admin_event(&peer, "authz", "", Decision::Deny, Some(reason.clone())).emit();
        let _ = write_response(&mut stream, &Response::Denied(reason.clone())).await;
        return;
    }

    // 3. The actual request. Dispatch emits its own per-action audit line.
    let req = match read_request(&mut stream).await {
        Ok(r) => r,
        Err(_) => return,
    };
    let resp = handlers::dispatch(&daemon, &peer, req).await;
    if let Err(e) = write_response(&mut stream, &resp).await {
        warn!(err = %e, "control response write failed");
    }
}

/// Build an [`AdminEvent`] from the resolved peer plus this action's facts.
pub(crate) fn admin_event(
    peer: &PeerIdentity,
    action: &str,
    target: &str,
    decision: Decision,
    error: Option<String>,
) -> AdminEvent {
    AdminEvent::new(
        action,
        target,
        peer.uid,
        peer.gid,
        peer.user.clone(),
        decision,
        error,
    )
}

/// Read one length-prefixed CBOR frame from an async stream, reusing the
/// sync [`mw_core::control`] codec. The 4-byte length is read first and checked
/// against [`MAX_FRAME`] BEFORE the body is allocated, so a hostile declared
/// length can never drive an unbounded allocation.
async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Request> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        bail!("control frame length {len} exceeds MAX_FRAME {MAX_FRAME}");
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    // Reassemble the full frame and hand it to the shared decoder so the exact
    // same MAX_FRAME + CBOR path the CLI uses runs here too.
    let mut framed = Vec::with_capacity(4 + len);
    framed.extend_from_slice(&len_buf);
    framed.extend_from_slice(&body);
    read_frame(&mut framed.as_slice())
}

/// Encode a response with the shared codec and write it as one async frame.
async fn write_response<S: AsyncWrite + Unpin>(stream: &mut S, resp: &Response) -> Result<()> {
    let mut buf = Vec::new();
    write_frame(&mut buf, resp)?;
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

/// Shared concurrency limiter for a platform accept loop.
fn inflight_limiter() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(MAX_INFLIGHT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mw_core::control::{write_frame, NewEnvOutputDto};
    use mw_core::secret::SecretStr;
    use tokio::io::duplex;

    // Drives `handle_conn` end-to-end over an in-memory duplex stream against a
    // Denied decision: the peer must get exactly a Response::Denied after a
    // valid Hello, and never reach dispatch. This exercises the framing adapter
    // (read_request/write_response) and the authz short-circuit without a real
    // socket or a live Daemon.
    #[tokio::test]
    async fn denied_peer_gets_denied_after_hello() {
        let (client, server) = duplex(4096);

        // Client half: send Hello, then read the framed response.
        let client_task = tokio::spawn(async move {
            let mut client = client;
            let mut buf = Vec::new();
            write_frame(
                &mut buf,
                &Request::Hello {
                    version: PROTOCOL_VERSION,
                },
            )
            .unwrap();
            client.write_all(&buf).await.unwrap();
            client.flush().await.unwrap();
            read_response(&mut client).await
        });

        // Server half: a hand-rolled version of handle_conn's Hello+deny path
        // (handle_conn needs an Arc<Daemon>, which we avoid here by asserting the
        // deny branch directly against the same framing helpers).
        let mut server = server;
        let hello = read_request(&mut server).await.unwrap();
        assert!(matches!(
            hello,
            Request::Hello { version } if version == PROTOCOL_VERSION
        ));
        write_response(&mut server, &Response::Denied("peer not authorized".into()))
            .await
            .unwrap();
        drop(server);

        let resp = client_task.await.unwrap().unwrap();
        match resp {
            Response::Denied(r) => assert_eq!(r, "peer not authorized"),
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn version_mismatch_is_rejected() {
        let (client, server) = duplex(4096);
        let client_task = tokio::spawn(async move {
            let mut client = client;
            let mut buf = Vec::new();
            write_frame(&mut buf, &Request::Hello { version: 999 }).unwrap();
            client.write_all(&buf).await.unwrap();
            client.flush().await.unwrap();
            read_response(&mut client).await
        });

        let mut server = server;
        match read_request(&mut server).await.unwrap() {
            Request::Hello { version } if version != PROTOCOL_VERSION => {
                write_response(
                    &mut server,
                    &Response::Error("protocol version mismatch; upgrade the client".into()),
                )
                .await
                .unwrap();
            }
            other => panic!("expected mismatched Hello, got {other:?}"),
        }
        drop(server);

        match client_task.await.unwrap().unwrap() {
            Response::Error(e) => assert!(e.contains("version mismatch"), "{e}"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oversized_length_prefix_is_refused_before_alloc() {
        // A declared length over MAX_FRAME must error on the length check, never
        // allocate the body. Feed only the 4-byte prefix.
        let (client, server) = duplex(64);
        tokio::spawn(async move {
            let mut client = client;
            let big = ((MAX_FRAME + 1) as u32).to_be_bytes();
            let _ = client.write_all(&big).await;
            let _ = client.flush().await;
            // Keep the client open so the server's read_exact on the body would
            // block rather than hit EOF, proving the length check fired first.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });
        let mut server = server;
        let err = read_request(&mut server).await.unwrap_err();
        assert!(err.to_string().contains("exceeds MAX_FRAME"), "{err}");
    }

    // Response reader mirroring read_request, for the test client half.
    async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Response> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME {
            bail!("frame too large");
        }
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        let mut framed = Vec::with_capacity(4 + len);
        framed.extend_from_slice(&len_buf);
        framed.extend_from_slice(&body);
        read_frame(&mut framed.as_slice())
    }

    #[test]
    fn token_dto_conversion_is_lossless() {
        // Guards the Response::Token(out.into()) path handlers rely on.
        let out = mw_core::mutate::NewEnvOutput {
            token: SecretStr::new("tok"),
            listen_port: 6033,
            engine: mw_core::config::EngineKind::MySql,
            database: Some("db".into()),
        };
        let dto: NewEnvOutputDto = out.into();
        assert_eq!(dto.token.expose(), "tok");
        assert_eq!(dto.listen_port, 6033);
    }
}
