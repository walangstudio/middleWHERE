//! Bastion SSH tunneling via russh.
//!
//! Architecture: one persistent `russh::client::Handle` per distinct
//! [`Bastion.name`] kept in a [`BastionRegistry`]. To reach a backend through
//! a bastion we don't try to inject an `AsyncRead+AsyncWrite` into
//! `mysql_async` (it doesn't expose one) — instead we run a tiny
//! local-port forwarder per (env, backend) tuple. The forwarder accepts on
//! `127.0.0.1:0`, opens a `direct-tcpip` channel through the russh session,
//! and `copy_bidirectional`-s bytes. The pool's `BackendOpts` is rewritten to
//! point at `127.0.0.1:<local_port>` so mysql_async is none the wiser.
//!
//! Host keys are pinned in the sealed config. With an empty pin list the
//! handler logs a TOFU warning and accepts — Phase 7b will add capture into
//! mwsqlctl so first-connect can be turned into a permanent pin.
//!
//! Reconnect-on-failure is intentionally minimal in this phase: a failed
//! `open_direct_tcpip` returns the error to the pool, which surfaces as a
//! backend-unavailable result to the client; the next request will trigger
//! a fresh session on demand. Exponential-backoff keepalive is a follow-up.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use russh::client::{self, Handle};
use russh::keys::PublicKey;
use sha2::{Digest, Sha256};
use tokio::io::copy_bidirectional;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use mw_core::config::{Bastion, BastionAuth, HostKeyFingerprint};

/// russh client Handler that enforces the env's pinned host-key list.
pub struct ClientHandler {
    pinned: Vec<HostKeyFingerprint>,
    /// When the pin list is empty: accept the key on first use (logged) only
    /// if true; otherwise refuse. Default posture is refuse — an unpinned
    /// bastion is a MitM path to the real DB password.
    allow_tofu: bool,
    /// Filled with the server's actual key after `check_server_key`.
    /// Useful for TOFU capture from `mwsqlctl bastion add --tofu`.
    pub captured: Arc<RwLock<Option<HostKeyFingerprint>>>,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        let blob = key.to_bytes().map_err(|_| russh::Error::Inconsistent)?;
        let digest = Sha256::digest(&blob);
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
        let algo = key.algorithm().to_string();
        let observed = HostKeyFingerprint {
            algo: algo.clone(),
            sha256_b64: b64.clone(),
        };
        *self.captured.write().await = Some(observed);

        if self.pinned.is_empty() {
            if self.allow_tofu {
                warn!(algo = %algo, sha256 = %b64,
                    "no pinned host keys — accepting on first use (--allow-tofu). \
                     Pin this fingerprint and drop the flag.");
                return Ok(true);
            }
            warn!(algo = %algo, sha256 = %b64,
                "no pinned host keys — REFUSING. Pin this fingerprint in the \
                 bastion config, or start the daemon with --allow-tofu to accept \
                 first-use (insecure).");
            return Ok(false);
        }
        let ok = self
            .pinned
            .iter()
            .any(|p| p.algo == algo && p.sha256_b64 == b64);
        if !ok {
            warn!(algo = %algo, sha256 = %b64,
                "host key did NOT match any pinned fingerprint — refusing");
        }
        Ok(ok)
    }
}

/// One authenticated SSH session.
pub struct BastionSession {
    handle: Handle<ClientHandler>,
    pub captured_fingerprint: Option<HostKeyFingerprint>,
}

impl BastionSession {
    pub async fn open(b: &Bastion, allow_tofu: bool) -> Result<Self> {
        let config = Arc::new(client::Config::default());
        let captured = Arc::new(RwLock::new(None));
        let handler = ClientHandler {
            pinned: b.pinned_host_keys.clone(),
            allow_tofu,
            captured: captured.clone(),
        };

        let mut handle = client::connect(config, (b.host.as_str(), b.port), handler)
            .await
            .with_context(|| format!("ssh connect {}:{}", b.host, b.port))?;

        let authed = match &b.auth {
            BastionAuth::Password { password } => {
                handle
                    .authenticate_password(b.ssh_user.clone(), password.expose())
                    .await?
            }
            BastionAuth::Key { .. } => {
                return Err(anyhow!("ssh key auth not yet wired (Phase 7b)"))
            }
        };
        if !authed.success() {
            return Err(anyhow!("ssh auth failed for {}@{}", b.ssh_user, b.host));
        }
        info!(host = %b.host, port = b.port, user = %b.ssh_user, "bastion session open");

        let fp = captured.read().await.clone();
        Ok(Self {
            handle,
            captured_fingerprint: fp,
        })
    }

    pub async fn open_direct_tcpip(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<russh::Channel<client::Msg>> {
        let ch = self
            .handle
            .channel_open_direct_tcpip(target_host, target_port as u32, "127.0.0.1", 0)
            .await
            .with_context(|| format!("direct-tcpip {}:{}", target_host, target_port))?;
        Ok(ch)
    }
}

/// Registry of bastion sessions keyed by `Bastion.name`. Sessions are
/// opened lazily on first need and shared across envs that reference the
/// same bastion.
#[derive(Default, Clone)]
pub struct BastionRegistry {
    #[allow(clippy::type_complexity)]
    inner: Arc<RwLock<HashMap<String, Arc<RwLock<Option<BastionSession>>>>>>,
}

impl BastionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get_or_open(
        &self,
        name: &str,
        bastion: &Bastion,
        allow_tofu: bool,
    ) -> Result<Arc<RwLock<Option<BastionSession>>>> {
        // Fast path: existing live slot.
        {
            let r = self.inner.read().await;
            if let Some(slot) = r.get(name) {
                if slot.read().await.is_some() {
                    return Ok(slot.clone());
                }
            }
        }
        // Slow path: create/upgrade.
        let slot = {
            let mut w = self.inner.write().await;
            w.entry(name.to_string())
                .or_insert_with(|| Arc::new(RwLock::new(None)))
                .clone()
        };
        let mut s = slot.write().await;
        if s.is_none() {
            *s = Some(BastionSession::open(bastion, allow_tofu).await?);
        }
        drop(s);
        Ok(slot)
    }

    /// Forget the cached session for `name` so the next [`Self::get_or_open`]
    /// opens a fresh one, re-authenticating and re-checking the host-key pin.
    /// Called on bastion removal and fingerprint re-pin: without it a
    /// name-keyed slot would keep serving the OLD tunnel (old host, old key)
    /// forever. Returns whether an entry was cached.
    ///
    /// Only the registry's reference is dropped, never the session itself. A
    /// live forward holds a read guard on its slot for the whole lifetime of
    /// each tunneled connection, so taking the write lock here would block the
    /// caller (which holds the config-write lock) until every in-flight query
    /// through that bastion finished. Instead the session closes on its own
    /// once the last forward still holding it goes away, which matches how a
    /// credential rotation already behaves: in-flight sessions finish on the
    /// old tunnel, new connections get the re-checked one.
    pub async fn evict(&self, name: &str) -> bool {
        self.inner.write().await.remove(name).is_some()
    }
}

/// One local-port forwarder. `local_port` is the address the backend pool
/// should connect to; the task copies bytes between that local socket and
/// a freshly-opened `direct-tcpip` channel for each accepted connection.
///
/// Dropping a `LocalForward` ABORTS its accept task (see the `Drop` impl): a bare
/// `JoinHandle` only detaches on drop, which would leave the 127.0.0.1 listener
/// (and, via the captured bastion-session slot, the SSH tunnel) running forever
/// after a live `env rm` / credential-or-bastion rotate / probe teardown.
pub struct LocalForward {
    pub local_port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LocalForward {
    fn drop(&mut self) {
        // Stop the accept loop so the local listener is released and no new
        // tunnels are opened through the bastion once this forward is discarded.
        self.task.abort();
    }
}

/// Bind a local listener on 127.0.0.1:0 and start forwarding accepted conns
/// through `slot`'s SSH session to `(target_host, target_port)`.
pub async fn start_local_forward(
    slot: Arc<RwLock<Option<BastionSession>>>,
    target_host: String,
    target_port: u16,
) -> Result<LocalForward> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_port = listener.local_addr()?.port();
    let task = tokio::spawn(async move {
        loop {
            let (mut client_sock, _peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    warn!(err = %e, "forwarder accept failed; exiting loop");
                    return;
                }
            };
            let slot = slot.clone();
            let target_host = target_host.clone();
            tokio::spawn(async move {
                let s = slot.read().await;
                let Some(session) = s.as_ref() else {
                    warn!("bastion session vanished mid-flight");
                    return;
                };
                let ch = match session.open_direct_tcpip(&target_host, target_port).await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(err = %e, "direct-tcpip open failed");
                        return;
                    }
                };
                let mut server_stream = ch.into_stream();
                if let Err(e) = copy_bidirectional(&mut client_sock, &mut server_stream).await {
                    debug!(err = %e, "tunnel closed");
                }
            });
        }
    });
    Ok(LocalForward { local_port, task })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mw_core::secret::SecretStr;

    fn unreachable_bastion() -> Bastion {
        Bastion {
            host: "127.0.0.1".into(),
            // Port 1: nothing listens there; connect fails fast.
            port: 1,
            ssh_user: "u".into(),
            auth: BastionAuth::Password {
                password: SecretStr::new("p"),
            },
            pinned_host_keys: Vec::new(),
        }
    }

    #[tokio::test]
    async fn evict_removes_slot_so_next_open_reconnects() {
        let reg = BastionRegistry::new();
        assert!(!reg.evict("nope").await, "unknown name is a no-op");

        assert!(reg
            .get_or_open("b", &unreachable_bastion(), false)
            .await
            .is_err());
        assert!(reg.inner.read().await.contains_key("b"));
        assert!(reg.evict("b").await);
        assert!(!reg.inner.read().await.contains_key("b"));
    }

    /// A forward holds a read guard on its slot for the whole life of a
    /// tunneled connection. Evicting must not wait on it: the caller holds the
    /// config-write lock, so one long-running query would otherwise wedge every
    /// admin command until it finished.
    #[tokio::test]
    async fn evict_does_not_wait_on_a_live_forwards_read_guard() {
        let reg = BastionRegistry::new();
        let slot = Arc::new(RwLock::new(None));
        reg.inner.write().await.insert("b".into(), slot.clone());

        let held = slot.read().await;
        let evicted = tokio::time::timeout(std::time::Duration::from_secs(5), reg.evict("b"))
            .await
            .expect("evict blocked on a live forward's read guard");
        drop(held);
        assert!(evicted);
    }
}
