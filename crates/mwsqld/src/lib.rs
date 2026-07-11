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
use tokio::sync::{broadcast, watch, Mutex};
use tokio::task::{AbortHandle, JoinSet};
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
}

/// Live handle to one running env. The accept loop reads `current` on every
/// connect, so publishing a new [`EnvRuntime`] via `current.send_replace` swaps
/// what NEW connections see without disturbing in-flight ones. `abort` stops
/// this env's accept loop (dropping its `sessions` JoinSet, so its live
/// sessions too); `forwards` are the SSH tunnels this env's pool dials through.
struct EnvHandle {
    current: watch::Sender<Arc<EnvRuntime>>,
    abort: AbortHandle,
    #[allow(dead_code)] // Phase 5 (live add/rebuild) reads these.
    listen_addr: SocketAddr,
    #[allow(dead_code)]
    forwards: Vec<LocalForward>,
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
    /// Reaper cadence, fixed at bind (a later live add won't retune it). Tracks
    /// the tightest initial idle timeout, or a 300s floor when the initial env
    /// set is empty or all-zero — the common case now that a daemon starts with
    /// no envs and gets them added live over the control channel. The reaper is
    /// ALWAYS spawned and snapshots the live registry each tick, so live-added
    /// envs are reaped; a fully-zero-timeout deployment just does nothing per tick.
    reap_interval: Duration,
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
        let mut idle_timeouts = Vec::new();

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
            let (runtime, forwards) =
                build_env_runtime(env_name, env, cfg, listen_host, &bastions, allow_tofu).await?;
            let listener = TcpListener::bind(runtime.listen_addr)
                .await
                .with_context(|| format!("bind {} for env {}", runtime.listen_addr, env_name))?;
            info!(env = env_name, addr = %listener.local_addr()?, "listening");
            idle_timeouts.push(runtime.idle_timeout);
            let handle = spawn_env(Arc::new(runtime), listener, forwards, &shutdown);
            envs.lock().await.insert(env_name.clone(), handle);
        }

        // One reaper serves every env. Cadence = the tightest non-zero initial
        // timeout, else a 300s floor: envs are commonly added LIVE after the
        // daemon starts empty, so a bind-time "no timeouts" snapshot must NOT
        // disable reaping. The reaper is always spawned in `run`.
        let reap_interval = idle_timeouts
            .into_iter()
            .filter(|d| !d.is_zero())
            .min()
            .map(reaper_interval)
            .unwrap_or_else(|| reaper_interval(Duration::from_secs(300)));

        Ok(Self {
            state_dir,
            envs,
            shutdown,
            reap_interval,
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
            let mut sub = self.shutdown.subscribe();
            let interval = self.reap_interval;
            tokio::spawn(async move { reap_loop(reap_envs, interval, &mut sub).await })
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
    forwards: Vec<LocalForward>,
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
        forwards,
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
        let (runtime, forwards) = build_env_runtime(
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
        let handle = spawn_env(Arc::new(runtime), listener, forwards, &self.shutdown);
        self.envs.lock().await.insert(name.to_string(), handle);
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
    /// fresh pool + forwards and publish them. In-flight sessions keep their old
    /// snapshot until they reconnect; the old forwards are dropped here.
    pub(crate) async fn apply_rebuild_backend(
        &self,
        cfg: &Config,
        env: &Env,
        name: &str,
    ) -> Result<()> {
        let (runtime, forwards) = build_env_runtime(
            name,
            env,
            cfg,
            &self.listen_host,
            &self.bastions,
            self.allow_tofu,
        )
        .await?;
        let mut guard = self.envs.lock().await;
        let handle = guard
            .get_mut(name)
            .ok_or_else(|| anyhow!("no such env {name}"))?;
        handle.forwards = forwards;
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

/// Build one env's runtime plus the SSH forwards it owns. The forwards are
/// returned (not pushed into a shared vec) so each env can hold and replace its
/// own tunnels; they must outlive the returned backend (its pool dials them).
async fn build_env_runtime(
    name: &str,
    env: &Env,
    cfg: &Config,
    listen_host: &str,
    bastions: &BastionRegistry,
    allow_tofu: bool,
) -> Result<(EnvRuntime, Vec<LocalForward>)> {
    let mut forwards: Vec<LocalForward> = Vec::new();
    let (engine, backend) =
        establish_backend(name, env, cfg, bastions, &mut forwards, allow_tofu).await?;
    let listen_addr: SocketAddr = format!("{listen_host}:{}", env.listen_port)
        .parse()
        .map_err(|e| anyhow!("bad listen addr for env {name}: {e}"))?;
    let runtime = EnvRuntime {
        name: name.to_string(),
        engine,
        backend: Arc::from(backend),
        policy: env.policy.clone(),
        client_auth: env.client_auth.clone(),
        listen_addr,
        idle_timeout: Duration::from_secs(env.pool.idle_timeout_secs as u64),
    };
    Ok((runtime, forwards))
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
async fn reap_loop(envs: EnvRegistry, interval: Duration, shutdown: &mut broadcast::Receiver<()>) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            biased;
            _ = shutdown.recv() => break,
            _ = ticker.tick() => {
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
            }
        }
    }
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
        // ...but a fresh connect sees the new policy.
        assert!(matches!(rx.borrow().policy, Policy::ReadWrite));
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
}
