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
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use mw_core::config::{ClientAuth, Config, EngineKind, Env, Policy};
use mw_net::engine::{engine_for, Backend, BackendOpts, Engine};
use mw_net::idle::reaper_interval;
use mw_net::ssh::{start_local_forward, BastionRegistry, LocalForward};

pub use mw_core::state::{
    default_state_dir, default_user_state_dir, env_flag, init, load_config, resolve_cli_target,
    save_config, KeystoreChoice, CONFIG_FILE_NAME, FILE_MASTER_KEY_NAME,
};

#[cfg(windows)]
pub mod winsvc;

pub struct EnvRuntime {
    pub name: String,
    pub engine: &'static dyn Engine,
    pub backend: Box<dyn Backend>,
    pub policy: Policy,
    pub client_auth: ClientAuth,
    pub listen_addr: SocketAddr,
    /// Close this env's backend connections after this much inactivity. Zero
    /// disables idle reaping for the env.
    pub idle_timeout: Duration,
}

/// Install the process-global tracing + audit subscriber. This belongs in
/// the binary entrypoint, NOT in `Daemon::bind` — library code must not
/// seize the global subscriber as a side effect (it panics on a second
/// install and misroutes audit events when embedded or tested). The binary
/// calls this once and holds the returned guard for the process lifetime.
pub use mw_core::audit::install_subscriber as install_audit;
pub use tracing_appender::non_blocking::WorkerGuard as AuditGuard;

pub struct Daemon {
    pub state_dir: PathBuf,
    pub envs: Arc<HashMap<String, EnvRuntime>>,
    pub bound: Vec<(String, TcpListener)>,
    _bastions: BastionRegistry,
    _forwards: Vec<LocalForward>,
}

impl Daemon {
    pub async fn bind(
        state_dir: PathBuf,
        cfg: &Config,
        listen_host: &str,
        allow_tofu: bool,
    ) -> Result<Self> {
        let bastions = BastionRegistry::new();
        let mut envs = HashMap::new();
        let mut bound = Vec::new();
        let mut forwards: Vec<LocalForward> = Vec::new();

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
            let runtime = build_env_runtime(
                env_name,
                env,
                cfg,
                listen_host,
                &bastions,
                &mut forwards,
                allow_tofu,
            )
            .await?;
            let listener = TcpListener::bind(runtime.listen_addr)
                .await
                .with_context(|| format!("bind {} for env {}", runtime.listen_addr, env_name))?;
            info!(env = env_name, addr = %listener.local_addr()?, "listening");
            bound.push((env_name.clone(), listener));
            envs.insert(env_name.clone(), runtime);
        }
        Ok(Self {
            state_dir,
            envs: Arc::new(envs),
            bound,
            _bastions: bastions,
            _forwards: forwards,
        })
    }

    pub async fn run(self, mut shutdown: broadcast::Receiver<()>) -> Result<()> {
        let envs = self.envs.clone();
        let mut accept_set: JoinSet<()> = JoinSet::new();
        for (env_name, listener) in self.bound {
            let envs = envs.clone();
            let mut sub = shutdown.resubscribe();
            accept_set.spawn(async move {
                accept_loop(&env_name, listener, envs, &mut sub).await;
            });
        }
        // Reap idle backend connections. One sweep task serves every env; its
        // cadence tracks the tightest configured timeout. Skipped entirely when
        // no env has a non-zero timeout (idle reaping fully disabled).
        if let Some(min_timeout) = envs
            .values()
            .map(|e| e.idle_timeout)
            .filter(|d| !d.is_zero())
            .min()
        {
            let reap_envs = envs.clone();
            let interval = reaper_interval(min_timeout);
            let mut sub = shutdown.resubscribe();
            accept_set.spawn(async move {
                reap_loop(reap_envs, interval, &mut sub).await;
            });
        }
        let _ = shutdown.recv().await;
        info!("shutdown signal received");
        accept_set.shutdown().await;
        info!("clean exit");
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

async fn build_env_runtime(
    name: &str,
    env: &Env,
    cfg: &Config,
    listen_host: &str,
    bastions: &BastionRegistry,
    forwards: &mut Vec<LocalForward>,
    allow_tofu: bool,
) -> Result<EnvRuntime> {
    let (engine, backend) =
        establish_backend(name, env, cfg, bastions, forwards, allow_tofu).await?;
    let listen_addr: SocketAddr = format!("{listen_host}:{}", env.listen_port)
        .parse()
        .map_err(|e| anyhow!("bad listen addr for env {name}: {e}"))?;
    Ok(EnvRuntime {
        name: name.to_string(),
        engine,
        backend,
        policy: env.policy.clone(),
        client_auth: env.client_auth.clone(),
        listen_addr,
        idle_timeout: Duration::from_secs(env.pool.idle_timeout_secs as u64),
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
async fn reap_loop(
    envs: Arc<HashMap<String, EnvRuntime>>,
    interval: Duration,
    shutdown: &mut broadcast::Receiver<()>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            biased;
            _ = shutdown.recv() => break,
            _ = ticker.tick() => {
                for rt in envs.values() {
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
    env_name: &str,
    listener: TcpListener,
    envs: Arc<HashMap<String, EnvRuntime>>,
    shutdown: &mut broadcast::Receiver<()>,
) {
    let mut sessions: JoinSet<()> = JoinSet::new();
    let env_name = env_name.to_string();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.recv() => break,
            accept = listener.accept() => match accept {
                Ok((sock, peer)) => {
                    let env_name = env_name.clone();
                    let envs = envs.clone();
                    sessions.spawn(async move {
                        if let Err(e) = handle_one(env_name.clone(), envs, sock, peer).await {
                            warn!(env = %env_name, peer = %peer, err = %e, "session error");
                        }
                    });
                }
                Err(e) => {
                    error!(env = %env_name, err = %e, "accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }
    sessions.shutdown().await;
}

async fn handle_one(
    env_name: String,
    envs: Arc<HashMap<String, EnvRuntime>>,
    mut sock: tokio::net::TcpStream,
    _peer: SocketAddr,
) -> Result<()> {
    sock.set_nodelay(true).ok();
    let env = envs
        .get(&env_name)
        .ok_or_else(|| anyhow!("env vanished mid-flight"))?;
    let conn_id = std::process::id().wrapping_add(rand::random::<u32>());
    match env
        .engine
        .accept(&mut sock, &env.name, &env.client_auth, conn_id)
        .await
    {
        Ok(session) => {
            env.engine
                .serve(&mut sock, &session, env.backend.as_ref(), &env.policy)
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
