//! Daemon orchestration: build per-env pools, bind listeners, dispatch
//! sessions, audit, shut down cleanly.
//!
//! State lifecycle (init/load/save) lives in `mw_core::state`; this
//! crate re-exports the bits the binary CLI needs.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, watch, Mutex, Notify};
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::Instant;
use tracing::{error, info, warn};

use mw_core::config::{ClientAuth, Config, EngineKind, Env, Policy};
use mw_net::engine::{engine_for, Backend, BackendOpts, Engine};
use mw_net::idle::reaper_interval;
use mw_net::ssh::{start_local_forward, BastionRegistry, LocalForward};

pub use mw_core::state::{
    default_state_dir, default_user_state_dir, env_flag, init, load_config, resolve_cli_target,
    save_config, KeystoreChoice, CONFIG_FILE_NAME, FILE_MASTER_KEY_NAME,
};

pub(crate) mod control;

#[cfg(windows)]
pub mod winsvc;

#[derive(Clone)]
pub struct EnvRuntime {
    pub name: String,
    pub engine: &'static dyn Engine,
    /// `Arc`, not `Box`, so a policy/authz swap can publish a fresh runtime
    /// snapshot while an in-flight session keeps the SAME pool alive.
    pub backend: Arc<dyn Backend>,
    pub policy: Policy,
    pub client_auth: ClientAuth,
    pub listen_addr: SocketAddr,
    /// Close this env's backend connections after this much inactivity. Zero
    /// disables idle reaping for the env.
    pub idle_timeout: Duration,
    /// SSH tunnels this snapshot's pool dials through, tied to the SNAPSHOT's
    /// lifetime (not the [`EnvHandle`]). A rotate publishes a NEW runtime with
    /// NEW forwards; an in-flight session holding the OLD snapshot keeps the OLD
    /// forwards `Arc` alive (so its pool's `127.0.0.1:<port>` listener stays up)
    /// until that session ends, then the old [`LocalForward`]s drop and abort —
    /// no mid-session break AND no tunnel leak. `Arc` so an authz/policy swap
    /// (which reuses the pool) shares the same tunnels. Empty when no bastion.
    ///
    /// Held only for this lifetime/RAII effect — never read by name in non-test
    /// code, hence `allow(dead_code)`; dropping it (with the snapshot) is what
    /// tears the tunnels down.
    #[allow(dead_code)]
    forwards: Arc<Vec<LocalForward>>,
}

/// Live handle to one running env. The accept loop reads `current` on every
/// connect, so publishing a new [`EnvRuntime`] via `current.send_replace` swaps
/// what NEW connections see without disturbing in-flight ones. `abort` stops
/// this env's accept loop (dropping its `sessions` JoinSet, so its live
/// sessions too). This env's SSH tunnels live inside the published
/// [`EnvRuntime`], not here, so an in-flight snapshot keeps them across a swap.
struct EnvHandle {
    current: watch::Sender<Arc<EnvRuntime>>,
    abort: AbortHandle,
    /// Kept for status/bookkeeping. The env's SSH tunnels now live inside the
    /// published [`EnvRuntime`] (not here), so an in-flight snapshot keeps its
    /// tunnels alive across a swap; see [`EnvRuntime::forwards`].
    #[allow(dead_code)]
    listen_addr: SocketAddr,
}

/// The daemon's live env table. An async mutex so the future control channel
/// can add/remove/swap envs while the accept + reap loops read it.
type EnvRegistry = Arc<Mutex<HashMap<String, EnvHandle>>>;

/// Install the process-global tracing + audit subscriber. This belongs in
/// the binary entrypoint, NOT in `Daemon::bind` — library code must not
/// seize the global subscriber as a side effect (it panics on a second
/// install and misroutes audit events when embedded or tested). The binary
/// calls this once and holds the returned guard for the process lifetime.
pub use mw_core::audit::install_subscriber as install_audit;
pub use tracing_appender::non_blocking::WorkerGuard as AuditGuard;

pub struct Daemon {
    pub state_dir: PathBuf,
    envs: EnvRegistry,
    /// Internal shutdown fan-out: every accept loop + the reaper subscribe to
    /// it; `run` fires it when the external shutdown signal arrives.
    shutdown: broadcast::Sender<()>,
    /// Wakes the reaper when the live env set changes so it retunes its sweep
    /// cadence at once. `apply_add_env` signals it, so a live-added env with a
    /// short idle timeout is swept within its own window instead of waiting out
    /// the previous (possibly 60s) interval.
    reap_wake: Arc<Notify>,
    // Below are threaded for Phase 5's live-mutation handlers; nothing reads
    // them yet.
    #[allow(dead_code)]
    ks: KeystoreChoice,
    #[allow(dead_code)]
    listen_host: String,
    #[allow(dead_code)]
    allow_tofu: bool,
    /// Held so bastion SSH sessions stay open and re-usable across a live add.
    #[allow(dead_code)]
    bastions: BastionRegistry,
    /// Serializes a future load -> mutate -> save -> apply cycle.
    #[allow(dead_code)]
    config_write: Arc<Mutex<()>>,
}

impl Daemon {
    pub async fn bind(
        state_dir: PathBuf,
        cfg: &Config,
        listen_host: &str,
        allow_tofu: bool,
        ks: KeystoreChoice,
    ) -> Result<Self> {
        let bastions = BastionRegistry::new();
        let envs: EnvRegistry = Arc::new(Mutex::new(HashMap::new()));
        let (shutdown, _) = broadcast::channel(1);

        for (env_name, env) in &cfg.envs {
            // Stub engines: skip rather than fail the whole daemon so the
            // working envs still come up.
            if env.engine == EngineKind::MsSql {
                warn!(
                    env = env_name,
                    "engine 'mssql' not implemented; skipping env"
                );
                continue;
            }
            // Postgres uses cleartext-password auth; the token would cross the
            // wire in clear on a non-loopback bind. Refuse unless explicitly
            // overridden.
            if env.engine == EngineKind::Postgres
                && !is_loopback_host(listen_host)
                && std::env::var("MIDDLEWHERE_ALLOW_INSECURE_PG_CLEARTEXT").is_err()
            {
                return Err(anyhow!(
                    "env {env_name}: postgres cleartext auth on non-loopback bind \
                     {listen_host:?} is refused; bind 127.0.0.1 or set \
                     MIDDLEWHERE_ALLOW_INSECURE_PG_CLEARTEXT=1"
                ));
            }
            let runtime =
                build_env_runtime(env_name, env, cfg, listen_host, &bastions, allow_tofu).await?;
            let listener = TcpListener::bind(runtime.listen_addr)
                .await
                .with_context(|| format!("bind {} for env {}", runtime.listen_addr, env_name))?;
            info!(env = env_name, addr = %listener.local_addr()?, "listening");
            let handle = spawn_env(Arc::new(runtime), listener, &shutdown);
            envs.lock().await.insert(env_name.clone(), handle);
        }

        Ok(Self {
            state_dir,
            envs,
            shutdown,
            reap_wake: Arc::new(Notify::new()),
            ks,
            listen_host: listen_host.to_string(),
            allow_tofu,
            bastions,
            config_write: Arc::new(Mutex::new(())),
        })
    }

    /// Takes `Arc<Self>` so the control-channel task can hold a live handle to
    /// the daemon and call the `apply_*` mutators while the accept/reap loops
    /// keep running. The two binary call sites wrap the bound daemon in an `Arc`.
    pub async fn run(self: Arc<Self>, mut shutdown: broadcast::Receiver<()>) -> Result<()> {
        // One sweep task serves every env; it breaks on the internal shutdown
        // fan-out below. ALWAYS spawned (even for a zero-env / all-zero-timeout
        // daemon) so envs added live over the control channel are still reaped;
        // the loop skips zero-timeout envs per tick, so an all-zero deployment is
        // cheap.
        let reap_abort = {
            let reap_envs = self.envs.clone();
            let reap_wake = self.reap_wake.clone();
            let mut sub = self.shutdown.subscribe();
            tokio::spawn(async move { reap_loop(reap_envs, reap_wake, &mut sub).await })
                .abort_handle()
        };

        // Control channel: apply CLI-sent config mutations on the live daemon.
        // Shares the same internal shutdown fan-out as the env accept loops, so
        // Ctrl-C / SCM stop tears it down too — no new shutdown source.
        let control_abort = {
            let daemon = Arc::clone(&self);
            let mut sub = self.shutdown.subscribe();
            tokio::spawn(async move { control::serve(daemon, &mut sub).await }).abort_handle()
        };

        let _ = shutdown.recv().await;
        info!("shutdown signal received");
        // Fan the shutdown out so every accept loop breaks its select and drains
        // its sessions, then abort each handle as the definitive teardown —
        // dropping an accept loop drops its `sessions` JoinSet, exactly as the
        // old `accept_set.shutdown().await` did.
        let _ = self.shutdown.send(());
        for (_, handle) in self.envs.lock().await.drain() {
            handle.abort.abort();
        }
        reap_abort.abort();
        control_abort.abort();
        info!("clean exit");
        Ok(())
    }

    /// Number of live envs currently served. Used by tests and, later, status.
    pub async fn env_count(&self) -> usize {
        self.envs.lock().await.len()
    }
}

/// Start one env's accept loop and return its live handle. Used by
/// [`Daemon::bind`] for the initial env set and by [`Daemon::apply_add_env`]
/// for a live add. The loop reads the watched runtime on each accept, so a
/// later `send_replace` swaps new connections without touching in-flight ones.
fn spawn_env(
    runtime: Arc<EnvRuntime>,
    listener: TcpListener,
    shutdown: &broadcast::Sender<()>,
) -> EnvHandle {
    let listen_addr = runtime.listen_addr;
    let (current, rx) = watch::channel(runtime);
    let mut sub = shutdown.subscribe();
    let task = tokio::spawn(async move { accept_loop(listener, rx, &mut sub).await });
    EnvHandle {
        current,
        abort: task.abort_handle(),
        listen_addr,
    }
}

/// Live config-apply surface. Phase 5's control handlers call these after
/// validating + persisting a mutation; nothing calls them yet (hence the
/// `#[allow(dead_code)]`). Each keeps the observable rule: an in-flight session
/// keeps the runtime snapshot it started with; only new connects see a swap.
#[allow(dead_code)]
impl Daemon {
    /// Add an env to the live daemon: build its pool + forwards, bind its
    /// listener (a port conflict fails HERE), and start serving it.
    pub(crate) async fn apply_add_env(&self, cfg: &Config, env: &Env, name: &str) -> Result<()> {
        let runtime = build_env_runtime(
            name,
            env,
            cfg,
            &self.listen_host,
            &self.bastions,
            self.allow_tofu,
        )
        .await?;
        let listener = TcpListener::bind(runtime.listen_addr)
            .await
            .with_context(|| format!("bind {} for env {}", runtime.listen_addr, name))?;
        let handle = spawn_env(Arc::new(runtime), listener, &self.shutdown);
        self.envs.lock().await.insert(name.to_string(), handle);
        // Retune the reaper now, so this env's (possibly short) idle window takes
        // effect immediately rather than after a sleep sized for the old cadence.
        self.reap_wake.notify_one();
        Ok(())
    }

    /// Remove an env: drop it from the registry and abort its accept loop,
    /// which drops its `sessions` JoinSet and its forwards.
    pub(crate) async fn apply_rm_env(&self, name: &str) {
        if let Some(handle) = self.envs.lock().await.remove(name) {
            handle.abort.abort();
        }
    }

    /// Swap the client-auth for an env, reusing the existing pool + forwards.
    pub(crate) async fn apply_swap_authz(
        &self,
        name: &str,
        new_client_auth: ClientAuth,
    ) -> Result<()> {
        self.swap_runtime(name, move |rt| rt.client_auth = new_client_auth)
            .await
    }

    /// Swap the firewall policy for an env, reusing the existing pool + forwards.
    pub(crate) async fn apply_swap_policy(&self, name: &str, new_policy: Policy) -> Result<()> {
        self.swap_runtime(name, move |rt| rt.policy = new_policy)
            .await
    }

    /// Rebuild an env's backend pool (credential/bastion change): establish a
    /// fresh pool + forwards and publish them as a new [`EnvRuntime`] snapshot.
    /// In-flight sessions keep their OLD snapshot — and, because the forwards now
    /// live inside the runtime, their OLD tunnels — until they finish; the old
    /// [`LocalForward`]s drop (and abort) only when the last such snapshot is
    /// gone, so a rotate never breaks a live session and never leaks a tunnel.
    pub(crate) async fn apply_rebuild_backend(
        &self,
        cfg: &Config,
        env: &Env,
        name: &str,
    ) -> Result<()> {
        let runtime = build_env_runtime(
            name,
            env,
            cfg,
            &self.listen_host,
            &self.bastions,
            self.allow_tofu,
        )
        .await?;
        let guard = self.envs.lock().await;
        let handle = guard
            .get(name)
            .ok_or_else(|| anyhow!("no such env {name}"))?;
        handle.current.send_replace(Arc::new(runtime));
        Ok(())
    }

    /// Clone the current runtime, mutate one field, publish it. Shared by the
    /// authz/policy swaps; the clone reuses the same backend Arc + forwards.
    async fn swap_runtime(&self, name: &str, mutate: impl FnOnce(&mut EnvRuntime)) -> Result<()> {
        let guard = self.envs.lock().await;
        let handle = guard
            .get(name)
            .ok_or_else(|| anyhow!("no such env {name}"))?;
        let mut next = (**handle.current.borrow()).clone();
        mutate(&mut next);
        handle.current.send_replace(Arc::new(next));
        Ok(())
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// Resolve the credential, open the bastion forward (if any), and build the
/// engine's backend pool. Shared by `Daemon::bind` (which then binds a
/// listener) and [`test_envs`] (which then probes one live connection). The
/// pool itself is lazy: this opens the SSH tunnel but NOT a backend connection
/// — startup stays as forgiving as before. Any pushed [`LocalForward`] must
/// outlive the returned backend (its pool dials 127.0.0.1:<local_port>).
async fn establish_backend(
    name: &str,
    env: &Env,
    cfg: &Config,
    bastions: &BastionRegistry,
    forwards: &mut Vec<LocalForward>,
    allow_tofu: bool,
) -> Result<(&'static dyn Engine, Box<dyn Backend>)> {
    let cred = cfg.credentials.get(&env.credential).ok_or_else(|| {
        anyhow!(
            "env {name} references unknown credential {}",
            env.credential
        )
    })?;
    let mut opts = BackendOpts::from_env_credential(env, cred);

    // If this env tunnels through a bastion, open the SSH session (sharing
    // any existing one for the same bastion name), allocate a local-port
    // forward to the real backend, and rewrite opts to point at it. The
    // engine's backend pool then connects to 127.0.0.1:<local_port>.
    if let Some(bastion_name) = &env.bastion {
        let bastion = cfg
            .bastions
            .get(bastion_name)
            .ok_or_else(|| anyhow!("env {name} references unknown bastion {bastion_name}"))?;
        let session = bastions
            .get_or_open(bastion_name, bastion, allow_tofu)
            .await
            .with_context(|| format!("opening bastion session {bastion_name} for env {name}"))?;
        let fwd = start_local_forward(session, opts.host.clone(), opts.port)
            .await
            .with_context(|| format!("start local forward for env {name}"))?;
        info!(env = name, bastion = bastion_name,
              backend = %format!("{}:{}", opts.host, opts.port),
              local = fwd.local_port,
              "tunnel established");
        opts.host = "127.0.0.1".to_string();
        opts.port = fwd.local_port;
        forwards.push(fwd);
    }

    let engine = engine_for(env.engine);
    let backend = engine
        .build_backend(opts, env.pool.max_size.max(1))
        .await
        .map_err(|e| anyhow!("env {name}: build backend ({:?}): {e}", env.engine))?;
    Ok((engine, backend))
}

/// Build one env's runtime, including the SSH forwards its pool dials through.
/// The forwards are held INSIDE the runtime (as a shared `Arc`), tied to the
/// snapshot's lifetime, so a later swap that publishes a new snapshot with new
/// forwards leaves an in-flight session's old tunnels intact until it ends.
async fn build_env_runtime(
    name: &str,
    env: &Env,
    cfg: &Config,
    listen_host: &str,
    bastions: &BastionRegistry,
    allow_tofu: bool,
) -> Result<EnvRuntime> {
    let mut forwards: Vec<LocalForward> = Vec::new();
    let (engine, backend) =
        establish_backend(name, env, cfg, bastions, &mut forwards, allow_tofu).await?;
    let listen_addr: SocketAddr = format!("{listen_host}:{}", env.listen_port)
        .parse()
        .map_err(|e| anyhow!("bad listen addr for env {name}: {e}"))?;
    Ok(EnvRuntime {
        name: name.to_string(),
        engine,
        backend: Arc::from(backend),
        policy: env.policy.clone(),
        client_auth: env.client_auth.clone(),
        listen_addr,
        idle_timeout: Duration::from_secs(env.pool.idle_timeout_secs as u64),
        forwards: Arc::new(forwards),
    })
}

/// Which envs `test_envs` probes.
pub enum Probe {
    One(String),
    All,
}

/// Outcome of probing one env: `ok` plus a human-readable `reason` on failure.
/// `supported` is false when the engine has no probe path yet (MsSql); such an
/// env is reported but must never count as a connection failure.
pub struct EnvProbeResult {
    pub env: String,
    pub ok: bool,
    pub supported: bool,
    pub reason: String,
}

/// Probe backend connectivity for one env (or all). For each env this opens the
/// bastion tunnel (if any) and forces a single real connect+auth against the
/// backend, then tears it all down. Used by `mwsqld test`; never binds a
/// listener and never mutates state. MsSql is reported as unsupported, not a
/// hard error.
pub async fn test_envs(cfg: &Config, which: Probe, allow_tofu: bool) -> Vec<EnvProbeResult> {
    let names: Vec<String> = match which {
        Probe::One(n) => vec![n],
        Probe::All => cfg.envs.keys().cloned().collect(),
    };
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        out.push(probe_one_env(cfg, &name, allow_tofu).await);
    }
    out
}

async fn probe_one_env(cfg: &Config, name: &str, allow_tofu: bool) -> EnvProbeResult {
    let fail = |reason: String| EnvProbeResult {
        env: name.to_string(),
        ok: false,
        supported: true,
        reason,
    };
    let Some(env) = cfg.envs.get(name) else {
        return fail(format!("no env named {name:?}"));
    };
    if env.engine == EngineKind::MsSql {
        return EnvProbeResult {
            env: name.to_string(),
            ok: false,
            supported: false,
            reason: "engine mssql not supported yet".to_string(),
        };
    }
    // Fresh registry/forwards per env; both must outlive the probe, so they are
    // held in this scope until after the connect completes.
    let bastions = BastionRegistry::new();
    let mut forwards: Vec<LocalForward> = Vec::new();
    let result: Result<()> = async {
        let (engine, backend) =
            establish_backend(name, env, cfg, &bastions, &mut forwards, allow_tofu).await?;
        engine
            .probe(backend.as_ref())
            .await
            .map_err(|e| anyhow!("{e}"))?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => EnvProbeResult {
            env: name.to_string(),
            ok: true,
            supported: true,
            reason: String::new(),
        },
        Err(e) => fail(format!("{e:#}")),
    }
}

/// Periodically close backend connections that have gone idle past their env's
/// timeout, freeing the server-side connection. Zero-timeout envs are skipped.
/// Runs until shutdown; the sweep itself never touches an in-flight query (only
/// connections sitting idle in the pool are candidates).
///
/// The sweep is scheduled on an ABSOLUTE deadline, not a fresh relative sleep, so
/// a burst of live adds can only pull it EARLIER, never push it later. The cadence
/// is the CURRENT registry's tightest non-zero idle timeout (falling back to
/// [`REAP_FALLBACK_INTERVAL`] when nothing has a timeout). A live add signals
/// `wake`; the deadline is then recomputed as `min(deadline, now + new_cadence)` —
/// a tighter cadence sweeps a new short-timeout env within its own window, while a
/// sustained stream of adds can't starve the sweep by continually resetting a
/// relative sleep. When every env is zero-timeout the loop idles at the fallback
/// cadence and does nothing (no busy-loop).
async fn reap_loop(envs: EnvRegistry, wake: Arc<Notify>, shutdown: &mut broadcast::Receiver<()>) {
    let mut deadline = Instant::now() + current_reap_interval(&envs).await;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.recv() => break,
            // A live add may tighten the cadence: pull the deadline earlier if the
            // new env's window ends sooner, but NEVER delay it — a burst of adds
            // must not push the sweep past the previously-scheduled deadline.
            _ = wake.notified() => {
                let cadence = current_reap_interval(&envs).await;
                deadline = deadline.min(Instant::now() + cadence);
            }
            _ = tokio::time::sleep_until(deadline) => {
                // Snapshot the current runtimes, then reap OFF-lock: `reap_idle`
                // only touches idle pooled conns (never an in-flight query), and
                // holding the registry mutex across it would block a live swap.
                let snapshots: Vec<Arc<EnvRuntime>> = {
                    let guard = envs.lock().await;
                    guard.values().map(|h| h.current.borrow().clone()).collect()
                };
                for rt in snapshots {
                    if rt.idle_timeout.is_zero() {
                        continue;
                    }
                    let closed = rt.backend.reap_idle(rt.idle_timeout);
                    if closed > 0 {
                        info!(
                            env = %rt.name,
                            closed,
                            timeout_secs = rt.idle_timeout.as_secs(),
                            "closed idle backend connections"
                        );
                    }
                }
                // Schedule the next sweep a full (freshly recomputed) cadence out.
                deadline = Instant::now() + current_reap_interval(&envs).await;
            }
        }
    }
}

/// Fallback reap cadence when no live env has a non-zero idle timeout. Matches
/// `reaper_interval`'s 60s ceiling, so an all-zero deployment wakes at most once a
/// minute and finds nothing to do (cheap idle, no busy-loop).
const REAP_FALLBACK_INTERVAL: Duration = Duration::from_secs(60);

/// Sweep cadence for the CURRENT env set: `reaper_interval` of the tightest
/// non-zero idle timeout live right now, else [`REAP_FALLBACK_INTERVAL`].
async fn current_reap_interval(envs: &EnvRegistry) -> Duration {
    let guard = envs.lock().await;
    guard
        .values()
        .map(|h| h.current.borrow().idle_timeout)
        .filter(|d| !d.is_zero())
        .min()
        .map(reaper_interval)
        .unwrap_or(REAP_FALLBACK_INTERVAL)
}

async fn accept_loop(
    listener: TcpListener,
    rx: watch::Receiver<Arc<EnvRuntime>>,
    shutdown: &mut broadcast::Receiver<()>,
) {
    let mut sessions: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.recv() => break,
            accept = listener.accept() => match accept {
                Ok((sock, peer)) => {
                    // Snapshot the current runtime for THIS connection; a later
                    // swap won't disturb it.
                    let rt = rx.borrow().clone();
                    sessions.spawn(async move {
                        let env = rt.name.clone();
                        if let Err(e) = handle_one(rt, sock, peer).await {
                            warn!(env = %env, peer = %peer, err = %e, "session error");
                        }
                    });
                }
                Err(e) => {
                    error!(env = %rx.borrow().name, err = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
    sessions.shutdown().await;
}

async fn handle_one(
    rt: Arc<EnvRuntime>,
    mut sock: tokio::net::TcpStream,
    _peer: SocketAddr,
) -> Result<()> {
    sock.set_nodelay(true).ok();
    let conn_id = std::process::id().wrapping_add(rand::random::<u32>());
    match rt
        .engine
        .accept(&mut sock, &rt.name, &rt.client_auth, conn_id)
        .await
    {
        Ok(session) => {
            rt.engine
                .serve(&mut sock, &session, rt.backend.as_ref(), &rt.policy)
                .await?;
        }
        Err(_) => { /* accept already wrote the protocol's ERR frame */ }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mw_core::config::{ClientAuth, Env, PoolSettings};

    struct StubBackend;
    impl Backend for StubBackend {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn watch_snapshot_isolates_in_flight_sessions() {
        // A running env publishes its runtime through a watch channel. An
        // in-flight session snapshots it on connect; a later swap (as
        // `apply_swap_policy` does) must NOT change what that snapshot sees,
        // only what a fresh connect sees — and it must reuse the same pool.
        let rt = EnvRuntime {
            name: "e".into(),
            engine: engine_for(EngineKind::MySql),
            backend: Arc::new(StubBackend) as Arc<dyn Backend>,
            policy: Policy::ReadOnly,
            client_auth: ClientAuth::NativePassword {
                double_sha1: [0; 20],
            },
            listen_addr: "127.0.0.1:1".parse().unwrap(),
            idle_timeout: Duration::ZERO,
            forwards: Arc::new(Vec::new()),
        };
        let (tx, rx) = watch::channel(Arc::new(rt));

        // In-flight session grabs its snapshot.
        let snapshot = rx.borrow().clone();
        assert!(matches!(snapshot.policy, Policy::ReadOnly));

        // Swap policy the way `swap_runtime` does: clone current, mutate, publish.
        let mut next = (**rx.borrow()).clone();
        next.policy = Policy::ReadWrite;
        tx.send_replace(Arc::new(next));

        // The in-flight snapshot is untouched...
        assert!(matches!(snapshot.policy, Policy::ReadOnly));
        // ...and shares the SAME backend Arc (pool reuse, no rebuild)...
        assert!(Arc::ptr_eq(&snapshot.backend, &rx.borrow().backend));
        // ...and the SAME forwards Arc (authz/policy swaps reuse the tunnels)...
        assert!(Arc::ptr_eq(&snapshot.forwards, &rx.borrow().forwards));
        // ...but a fresh connect sees the new policy.
        assert!(matches!(rx.borrow().policy, Policy::ReadWrite));
    }

    // Helper: an EnvRuntime carrying a specific forwards Arc, for the lifetime
    // test below. No real tunnels needed — we assert on Arc strong counts.
    fn runtime_with_forwards(forwards: Arc<Vec<LocalForward>>) -> EnvRuntime {
        EnvRuntime {
            name: "e".into(),
            engine: engine_for(EngineKind::MySql),
            backend: Arc::new(StubBackend) as Arc<dyn Backend>,
            policy: Policy::ReadOnly,
            client_auth: ClientAuth::NativePassword {
                double_sha1: [0; 20],
            },
            listen_addr: "127.0.0.1:1".parse().unwrap(),
            idle_timeout: Duration::ZERO,
            forwards,
        }
    }

    #[test]
    fn rebuild_keeps_old_forwards_until_last_snapshot_drops() {
        // F1: a rebuild (apply_rebuild_backend) publishes a NEW runtime with NEW
        // forwards. An in-flight session holding the OLD snapshot must keep the
        // OLD forwards Arc alive (its tunnels stay up) until it drops; only then
        // do the old LocalForwards drop (and, in production, abort). No leak, no
        // mid-session break.
        //
        // Strong-count bookkeeping: cloning `Arc<EnvRuntime>` shares ONE inner
        // `forwards` Arc, so the count tracks how many live EnvRuntime instances
        // embed it (plus our test handle).
        let old_forwards = Arc::new(Vec::new());
        let (tx, rx) = watch::channel(Arc::new(runtime_with_forwards(old_forwards.clone())));

        // In-flight session snapshots the old runtime (same EnvRuntime instance).
        let snapshot = rx.borrow().clone();
        assert_eq!(
            Arc::strong_count(&old_forwards),
            2,
            "test handle + the one old EnvRuntime's field"
        );

        // Rebuild: publish a new runtime with NEW forwards. send_replace drops the
        // watch's Arc to the OLD EnvRuntime, but `snapshot` still holds it.
        let new_forwards = Arc::new(Vec::new());
        tx.send_replace(Arc::new(runtime_with_forwards(new_forwards.clone())));

        // THE F1 INVARIANT: the old forwards are NOT dropped — the in-flight
        // snapshot still keeps the old EnvRuntime (and thus its tunnels) alive.
        assert_eq!(
            Arc::strong_count(&old_forwards),
            2,
            "old forwards still alive via the in-flight snapshot after the swap"
        );
        // New connects see the new forwards.
        assert!(Arc::ptr_eq(&rx.borrow().forwards, &new_forwards));

        // The last snapshot ends -> old EnvRuntime drops -> old forwards released
        // (in production, LocalForward::drop aborts the listener here).
        drop(snapshot);
        assert_eq!(
            Arc::strong_count(&old_forwards),
            1,
            "released once the last snapshot is gone (only our test handle remains)"
        );
    }

    fn mssql_config() -> Config {
        let mut cfg = Config::default();
        cfg.envs.insert(
            "warehouse".into(),
            Env {
                backend_host: "h".into(),
                backend_port: 1433,
                default_database: None,
                bastion: None,
                credential: "c".into(),
                policy: Policy::ReadOnly,
                client_auth: ClientAuth::NativePassword {
                    double_sha1: [0; 20],
                },
                listen_port: 6033,
                pool: PoolSettings::default(),
                engine: EngineKind::MsSql,
            },
        );
        cfg
    }

    #[tokio::test]
    async fn probing_zero_envs_yields_no_results() {
        // `mwsqld test --all` on a freshly-init'd, env-less config probes
        // nothing. The empty result set must NOT be reported as "all
        // connected"; the CLI treats it as an informational no-op instead.
        let cfg = Config::default();
        assert!(cfg.envs.is_empty());
        let results = test_envs(&cfg, Probe::All, false).await;
        assert!(results.is_empty(), "no env => no probe result");
    }

    #[tokio::test]
    async fn mssql_env_is_unsupported_not_a_connect_failure() {
        let cfg = mssql_config();
        let results = test_envs(&cfg, Probe::One("warehouse".into()), false).await;
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert!(!r.ok, "mssql env cannot report a live connection");
        assert!(
            !r.supported,
            "mssql must be flagged unsupported, not failed"
        );
        assert!(r.reason.contains("not supported"), "{}", r.reason);
    }

    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingBackend(Arc<AtomicUsize>);
    impl Backend for CountingBackend {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn reap_idle(&self, _idle_timeout: Duration) -> usize {
            self.0.fetch_add(1, Ordering::SeqCst);
            0
        }
    }

    fn runtime_with_timeout(backend: Arc<dyn Backend>, idle_timeout: Duration) -> EnvRuntime {
        EnvRuntime {
            name: "e".into(),
            engine: engine_for(EngineKind::MySql),
            backend,
            policy: Policy::ReadOnly,
            client_auth: ClientAuth::NativePassword {
                double_sha1: [0; 20],
            },
            listen_addr: "127.0.0.1:1".parse().unwrap(),
            idle_timeout,
            forwards: Arc::new(Vec::new()),
        }
    }

    fn env_handle(rt: EnvRuntime) -> EnvHandle {
        let (current, _rx) = watch::channel(Arc::new(rt));
        EnvHandle {
            current,
            abort: tokio::spawn(async {}).abort_handle(),
            listen_addr: "127.0.0.1:1".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn cadence_tracks_the_tightest_live_timeout() {
        // D3: the reaper sizes its sleep from the LIVE registry each iteration.
        let envs: EnvRegistry = Arc::new(Mutex::new(HashMap::new()));
        // Empty: the cheap fallback, not a busy-loop.
        assert_eq!(current_reap_interval(&envs).await, REAP_FALLBACK_INTERVAL);

        // A zero-timeout env still yields the fallback (reaping is disabled for
        // it, so it must not drive the cadence to zero).
        let count = Arc::new(AtomicUsize::new(0));
        let zero = runtime_with_timeout(Arc::new(CountingBackend(count.clone())), Duration::ZERO);
        envs.lock().await.insert("z".into(), env_handle(zero));
        assert_eq!(current_reap_interval(&envs).await, REAP_FALLBACK_INTERVAL);

        // A short-timeout env tightens the cadence to reaper_interval(timeout).
        let short = runtime_with_timeout(
            Arc::new(CountingBackend(count.clone())),
            Duration::from_secs(6),
        );
        envs.lock().await.insert("s".into(), env_handle(short));
        assert_eq!(
            current_reap_interval(&envs).await,
            reaper_interval(Duration::from_secs(6))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn reaper_retunes_on_a_live_add_without_waiting_out_the_base_interval() {
        // D3: a daemon that started empty sleeps at the 60s fallback. A live add
        // must NOT sit idle behind that sleep — signalling `wake` retunes the
        // cadence to the new env's window, so its first sweep lands promptly.
        let envs: EnvRegistry = Arc::new(Mutex::new(HashMap::new()));
        let wake = Arc::new(Notify::new());
        let (_sd, mut sd_rx) = broadcast::channel(1);

        let reap_envs = envs.clone();
        let reap_wake = wake.clone();
        let task = tokio::spawn(async move { reap_loop(reap_envs, reap_wake, &mut sd_rx).await });

        // Let the loop park on its first (empty-registry, 60s fallback) sleep.
        tokio::task::yield_now().await;

        // Live-add a short-timeout env and signal the reaper, exactly as
        // apply_add_env does. reaper_interval(10s) = 5s.
        let count = Arc::new(AtomicUsize::new(0));
        let rt = runtime_with_timeout(
            Arc::new(CountingBackend(count.clone())),
            Duration::from_secs(10),
        );
        envs.lock().await.insert("e".into(), env_handle(rt));
        wake.notify_one();

        // Let the loop consume the wake and re-park on the fresh 5s sleep.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Advancing only 5s (< the 60s base) must trigger a sweep — proof the
        // live add didn't wait out the previous interval.
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "live-added env swept at its own cadence, not the 60s base"
        );

        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn burst_of_live_adds_does_not_starve_the_sweep() {
        // R4-2: the sweep is anchored to an ABSOLUTE deadline, so a sustained
        // stream of live adds (each firing `wake`) can only pull it earlier, never
        // push it later. A naive relative sleep restarted on every wake would keep
        // sliding the sweep out and starve idle-conn reaping for the whole burst.
        let envs: EnvRegistry = Arc::new(Mutex::new(HashMap::new()));
        let wake = Arc::new(Notify::new());
        let (_sd, mut sd_rx) = broadcast::channel(1);
        let count = Arc::new(AtomicUsize::new(0));

        let reap_envs = envs.clone();
        let reap_wake = wake.clone();
        let task = tokio::spawn(async move { reap_loop(reap_envs, reap_wake, &mut sd_rx).await });

        // Park on the empty-registry 60s fallback deadline.
        tokio::task::yield_now().await;

        // Three adds 2s apart, each a 10s-timeout env (reaper_interval=5s). The
        // first anchors the deadline at ~t0+5; later adds must NOT push it past
        // that. A relative-sleep reaper would re-arm to (last add t0+4)+5s = t0+9.
        for i in 0..3 {
            let rt = runtime_with_timeout(
                Arc::new(CountingBackend(count.clone())),
                Duration::from_secs(10),
            );
            envs.lock().await.insert(format!("e{i}"), env_handle(rt));
            wake.notify_one();
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
            if i < 2 {
                tokio::time::advance(Duration::from_secs(2)).await;
            }
        }

        // Now at ~t0+4 with the deadline anchored at ~t0+5. Cross it.
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert!(
            count.load(Ordering::SeqCst) > 0,
            "anchored deadline swept despite the burst; a relative sleep would have starved it"
        );

        task.abort();
    }
}
