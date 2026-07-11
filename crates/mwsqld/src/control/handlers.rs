//! Control-request dispatch: apply one CLI-sent mutation or read to the live
//! daemon. Every mutation runs under `daemon.config_write` (serializing the
//! load -> mutate -> save -> apply cycle), persists via
//! [`mw_core::state::with_config`] (validate + atomic reseal), then reflects the
//! change onto the running env table through the `Daemon::apply_*` methods.
//!
//! Persist-then-apply ordering: `with_config` writes the sealed config first; if
//! the live apply then fails (e.g. a port is momentarily taken) the config is
//! already durable, so we return an error telling the operator to restart the
//! service rather than panicking or leaving disk and memory disagreeing.

use std::sync::Arc;

use anyhow::Result;

use mw_core::audit::Decision;
use mw_core::config::{Config, EngineKind};
use mw_core::control::{
    BastionInputDto, CredInputDto, EnvInputDto, ProbeResultDto, Request, Response,
};
use mw_core::mutate::{
    add_bastion, add_cred, add_env, grant_env, merge_import, rm_bastion, rm_cred, rm_env,
    rotate_cred, set_fingerprint, set_policy, BastionAddArgs, EnvAddArgs, PolicyTarget,
};
use mw_core::state::{load_config, with_config};

use super::peercred::PeerIdentity;
use super::{admin_event, Daemon};
use crate::{test_envs, Probe};

/// Apply one request. Returns the [`Response`] to frame back to the client;
/// never panics on client input.
pub(crate) async fn dispatch(daemon: &Arc<Daemon>, peer: &PeerIdentity, req: Request) -> Response {
    match req {
        // A stray second Hello is a protocol error, not a mutation.
        Request::Hello { .. } => Response::Error("unexpected Hello after handshake".into()),

        // ---- bastion mutations ----
        Request::AddBastion(dto) => add_bastion_req(daemon, peer, dto).await,
        Request::RmBastion { name } => {
            simple_mutation(daemon, peer, "rm_bastion", &name.clone(), move |cfg| {
                rm_bastion(cfg, &name)
            })
            .await
        }
        Request::SetFingerprint {
            bastion,
            fingerprint,
        } => {
            simple_mutation(
                daemon,
                peer,
                "set_fingerprint",
                &bastion.clone(),
                move |cfg| set_fingerprint(cfg, &bastion, fingerprint),
            )
            .await
        }

        // ---- credential mutations ----
        Request::AddCred(dto) => {
            let CredInputDto {
                name,
                backend_user,
                password,
            } = dto;
            let target = name.clone();
            simple_mutation(daemon, peer, "add_cred", &target, move |cfg| {
                add_cred(cfg, &name, &backend_user, password)
            })
            .await
        }
        Request::RotateCred { name, password } => {
            rotate_cred_req(daemon, peer, name, password).await
        }
        Request::RmCred { name } => {
            simple_mutation(daemon, peer, "rm_cred", &name.clone(), move |cfg| {
                rm_cred(cfg, &name)
            })
            .await
        }

        // ---- env + token lifecycle ----
        Request::AddEnv(dto) => add_env_req(daemon, peer, dto).await,
        Request::RmEnv { name } => rm_env_req(daemon, peer, name).await,
        Request::Grant { env } => grant_req(daemon, peer, env).await,
        Request::SetPolicy {
            env,
            target,
            confirm_unsafe,
        } => set_policy_req(daemon, peer, env, target, confirm_unsafe).await,
        Request::Import(cfg) => import_req(daemon, peer, *cfg).await,

        // ---- reads ----
        Request::ListBastions => list_bastions(daemon, peer),
        Request::ListCreds => list_creds(daemon, peer),
        Request::ListEnvs => list_envs(daemon, peer),
        Request::AuditTail { n } => audit_tail(daemon, peer, n),
        Request::Probe { env, all } => probe_req(daemon, peer, env, all).await,
    }
}

// ---------------------------------------------------------------------------
// mutation helpers
// ---------------------------------------------------------------------------

/// A mutation whose only live effect is the persisted config (no env-table
/// apply): add/remove an unreferenced bastion/credential, pin a fingerprint.
/// Runs the transform under the config-write lock and audits the outcome.
async fn simple_mutation<F>(
    daemon: &Arc<Daemon>,
    peer: &PeerIdentity,
    action: &str,
    target: &str,
    transform: F,
) -> Response
where
    F: FnOnce(&mut Config) -> Result<()> + Send,
{
    let _guard = daemon.config_write.lock().await;
    match with_config(&daemon.state_dir, &daemon.ks, transform) {
        Ok(()) => {
            admin_event(peer, action, target, Decision::Allow, None).emit();
            Response::Ok
        }
        Err(e) => fail(peer, action, target, e),
    }
}

async fn add_bastion_req(
    daemon: &Arc<Daemon>,
    peer: &PeerIdentity,
    dto: BastionInputDto,
) -> Response {
    let target = dto.name.clone();
    let _guard = daemon.config_write.lock().await;
    let result = with_config(&daemon.state_dir, &daemon.ks, |cfg| {
        add_bastion(
            cfg,
            BastionAddArgs {
                name: &dto.name,
                host: &dto.host,
                port: dto.port,
                ssh_user: &dto.ssh_user,
                auth: dto.auth,
                fingerprint: dto.fingerprint,
            },
        )
    });
    match result {
        // A brand-new bastion is referenced by no env yet, so nothing on the
        // live env table needs rebuilding.
        Ok(()) => {
            admin_event(peer, "add_bastion", &target, Decision::Allow, None).emit();
            Response::Ok
        }
        Err(e) => fail(peer, "add_bastion", &target, e),
    }
}

async fn rotate_cred_req(
    daemon: &Arc<Daemon>,
    peer: &PeerIdentity,
    name: String,
    password: mw_core::secret::SecretStr,
) -> Response {
    let _guard = daemon.config_write.lock().await;
    {
        let name_for_tx = name.clone();
        if let Err(e) = with_config(&daemon.state_dir, &daemon.ks, move |cfg| {
            rotate_cred(cfg, &name_for_tx, password)
        }) {
            return fail(peer, "rotate_cred", &name, e);
        }
    }
    // The new password only reaches live sessions once each env that uses this
    // credential rebuilds its backend pool. Reload the sealed config and rebuild
    // every affected env.
    let cfg = match load_config(&daemon.state_dir, &daemon.ks) {
        Ok(c) => c,
        Err(e) => return fail(peer, "rotate_cred", &name, e),
    };
    let affected: Vec<String> = cfg
        .envs
        .iter()
        .filter(|(_, e)| e.credential == name)
        .map(|(n, _)| n.clone())
        .collect();
    for env_name in &affected {
        if let Some(env) = cfg.envs.get(env_name) {
            if let Err(e) = daemon.apply_rebuild_backend(&cfg, env, env_name).await {
                return persisted_but_apply_failed(peer, "rotate_cred", &name, env_name, e);
            }
        }
    }
    admin_event(peer, "rotate_cred", &name, Decision::Allow, None).emit();
    Response::Ok
}

async fn add_env_req(daemon: &Arc<Daemon>, peer: &PeerIdentity, dto: EnvInputDto) -> Response {
    let target = dto.name.clone();
    let _guard = daemon.config_write.lock().await;
    let backend_port = dto
        .backend_port
        .unwrap_or_else(|| dto.engine.default_port());
    let out = {
        let dto = &dto;
        with_config(&daemon.state_dir, &daemon.ks, |cfg| {
            add_env(
                cfg,
                EnvAddArgs {
                    name: &dto.name,
                    backend_host: &dto.backend_host,
                    backend_port,
                    default_database: dto.database.as_deref(),
                    bastion: dto.bastion.as_deref(),
                    credential: &dto.credential,
                    policy: dto.policy.clone(),
                    listen_port: dto.listen_port,
                    max_pool: dto.max_pool,
                    engine: dto.engine,
                },
            )
        })
    };
    let out = match out {
        Ok(o) => o,
        Err(e) => return fail(peer, "add_env", &target, e),
    };
    // Spin the new env up on the live daemon: this binds its listener, so a port
    // conflict surfaces here (after the config is already durable).
    let cfg = match load_config(&daemon.state_dir, &daemon.ks) {
        Ok(c) => c,
        Err(e) => return fail(peer, "add_env", &target, e),
    };
    match cfg.envs.get(&target) {
        Some(env) => {
            if let Err(e) = daemon.apply_add_env(&cfg, env, &target).await {
                return persisted_but_apply_failed(peer, "add_env", &target, &target, e);
            }
        }
        None => return fail_msg(peer, "add_env", &target, "env vanished after save"),
    }
    admin_event(peer, "add_env", &target, Decision::Allow, None).emit();
    Response::Token(out.into())
}

async fn rm_env_req(daemon: &Arc<Daemon>, peer: &PeerIdentity, name: String) -> Response {
    let _guard = daemon.config_write.lock().await;
    {
        let name_for_tx = name.clone();
        if let Err(e) = with_config(&daemon.state_dir, &daemon.ks, move |cfg| {
            rm_env(cfg, &name_for_tx)
        }) {
            return fail(peer, "rm_env", &name, e);
        }
    }
    daemon.apply_rm_env(&name).await;
    admin_event(peer, "rm_env", &name, Decision::Allow, None).emit();
    Response::Ok
}

async fn grant_req(daemon: &Arc<Daemon>, peer: &PeerIdentity, env: String) -> Response {
    let _guard = daemon.config_write.lock().await;
    let out = {
        let env = env.clone();
        with_config(&daemon.state_dir, &daemon.ks, move |cfg| {
            grant_env(cfg, &env)
        })
    };
    let out = match out {
        Ok(o) => o,
        Err(e) => return fail(peer, "grant", &env, e),
    };
    // Publish the rotated client-auth so new client connections must present the
    // new token; in-flight sessions keep their snapshot (pool reused).
    let cfg = match load_config(&daemon.state_dir, &daemon.ks) {
        Ok(c) => c,
        Err(e) => return fail(peer, "grant", &env, e),
    };
    match cfg.envs.get(&env) {
        Some(e) => {
            let new_auth = e.client_auth.clone();
            if let Err(err) = daemon.apply_swap_authz(&env, new_auth).await {
                return persisted_but_apply_failed(peer, "grant", &env, &env, err);
            }
        }
        None => return fail_msg(peer, "grant", &env, "env vanished after save"),
    }
    admin_event(peer, "grant", &env, Decision::Allow, None).emit();
    Response::Token(out.into())
}

async fn set_policy_req(
    daemon: &Arc<Daemon>,
    peer: &PeerIdentity,
    env: String,
    target: PolicyTarget,
    confirm_unsafe: bool,
) -> Response {
    // Enforce the read-write confirmation daemon-side, mirroring the old CLI
    // gate: a client that omits confirm_unsafe cannot flip an env to read-write.
    if target == PolicyTarget::ReadWrite && !confirm_unsafe {
        let reason = "switching an env to read-write requires explicit confirmation".to_string();
        admin_event(
            peer,
            "set_policy",
            &env,
            Decision::Deny,
            Some(reason.clone()),
        )
        .emit();
        return Response::Denied(reason);
    }
    let _guard = daemon.config_write.lock().await;
    {
        let env_for_tx = env.clone();
        if let Err(e) = with_config(&daemon.state_dir, &daemon.ks, move |cfg| {
            set_policy(cfg, &env_for_tx, target)
        }) {
            return fail(peer, "set_policy", &env, e);
        }
    }
    let cfg = match load_config(&daemon.state_dir, &daemon.ks) {
        Ok(c) => c,
        Err(e) => return fail(peer, "set_policy", &env, e),
    };
    match cfg.envs.get(&env) {
        Some(e) => {
            let new_policy = e.policy.clone();
            if let Err(err) = daemon.apply_swap_policy(&env, new_policy).await {
                return persisted_but_apply_failed(peer, "set_policy", &env, &env, err);
            }
        }
        None => return fail_msg(peer, "set_policy", &env, "env vanished after save"),
    }
    admin_event(peer, "set_policy", &env, Decision::Allow, None).emit();
    Response::Ok
}

async fn import_req(daemon: &Arc<Daemon>, peer: &PeerIdentity, fragment: Config) -> Response {
    let new_envs: Vec<String> = fragment.envs.keys().cloned().collect();
    let target = new_envs.join(",");
    let _guard = daemon.config_write.lock().await;
    if let Err(e) = with_config(&daemon.state_dir, &daemon.ks, move |cfg| {
        merge_import(cfg, fragment)
    }) {
        return fail(peer, "import", &target, e);
    }
    // Every imported env is new (merge_import refuses name collisions), so each
    // needs to be brought up on the live daemon.
    let cfg = match load_config(&daemon.state_dir, &daemon.ks) {
        Ok(c) => c,
        Err(e) => return fail(peer, "import", &target, e),
    };
    for env_name in &new_envs {
        if let Some(env) = cfg.envs.get(env_name) {
            if let Err(e) = daemon.apply_add_env(&cfg, env, env_name).await {
                return persisted_but_apply_failed(peer, "import", &target, env_name, e);
            }
        }
    }
    admin_event(peer, "import", &target, Decision::Allow, None).emit();
    Response::Ok
}

// ---------------------------------------------------------------------------
// reads
// ---------------------------------------------------------------------------

fn list_bastions(daemon: &Arc<Daemon>, peer: &PeerIdentity) -> Response {
    let cfg = match load_config(&daemon.state_dir, &daemon.ks) {
        Ok(c) => c,
        Err(e) => return fail(peer, "list_bastions", "", e),
    };
    // Secret-free: name, ssh endpoint, auth kind, count of pinned fingerprints.
    let rows = cfg
        .bastions
        .iter()
        .map(|(name, b)| {
            let auth = match &b.auth {
                mw_core::config::BastionAuth::Password { .. } => "password",
                mw_core::config::BastionAuth::Key { .. } => "key",
            };
            format!(
                "{}\t{}@{}:{}\t{}\tpinned={}",
                name,
                b.ssh_user,
                b.host,
                b.port,
                auth,
                b.pinned_host_keys.len()
            )
        })
        .collect();
    Response::Rows(rows)
}

fn list_creds(daemon: &Arc<Daemon>, peer: &PeerIdentity) -> Response {
    let cfg = match load_config(&daemon.state_dir, &daemon.ks) {
        Ok(c) => c,
        Err(e) => return fail(peer, "list_creds", "", e),
    };
    // Secret-free: name + backend user only; the password never leaves the seal.
    let rows = cfg
        .credentials
        .iter()
        .map(|(name, c)| format!("{}\t{}", name, c.backend_user))
        .collect();
    Response::Rows(rows)
}

fn list_envs(daemon: &Arc<Daemon>, peer: &PeerIdentity) -> Response {
    let cfg = match load_config(&daemon.state_dir, &daemon.ks) {
        Ok(c) => c,
        Err(e) => return fail(peer, "list_envs", "", e),
    };
    let rows = cfg
        .envs
        .iter()
        .map(|(name, e)| {
            format!(
                "{}\t{}:{}\t{}\t{}\tbastion={}\tcred={}\tport={}",
                name,
                e.backend_host,
                e.backend_port,
                engine_label(e.engine),
                policy_label(&e.policy),
                e.bastion.as_deref().unwrap_or("-"),
                e.credential,
                e.listen_port
            )
        })
        .collect();
    Response::Rows(rows)
}

fn engine_label(e: EngineKind) -> &'static str {
    match e {
        EngineKind::MySql => "mysql",
        EngineKind::Postgres => "postgres",
        EngineKind::MsSql => "mssql",
    }
}

fn policy_label(p: &mw_core::config::Policy) -> &'static str {
    match p {
        mw_core::config::Policy::ReadOnly => "read-only",
        mw_core::config::Policy::ReadWrite => "read-write",
        mw_core::config::Policy::Custom { .. } => "custom",
    }
}

/// Tail the daemon's own audit JSONL. The CLI cannot read the (root-owned) audit
/// dir, so it asks the daemon. `tracing_appender::rolling::daily` names files
/// `audit.jsonl.YYYY-MM-DD`; lexicographic order gives the most recent day.
fn audit_tail(daemon: &Arc<Daemon>, peer: &PeerIdentity, n: usize) -> Response {
    let dir = daemon.state_dir.join("audit");
    if !dir.exists() {
        return Response::AuditLines(Vec::new());
    }
    let entries = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) => return fail_msg(peer, "audit_tail", "", &format!("read audit dir: {e}")),
    };
    let mut files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("audit.jsonl"))
        .collect();
    files.sort_by_key(|e| e.file_name());
    let Some(latest) = files.last() else {
        return Response::AuditLines(Vec::new());
    };
    let body = match std::fs::read_to_string(latest.path()) {
        Ok(b) => b,
        Err(e) => return fail_msg(peer, "audit_tail", "", &format!("read audit file: {e}")),
    };
    let lines: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    Response::AuditLines(lines[start..].iter().map(|s| (*s).to_string()).collect())
}

async fn probe_req(
    daemon: &Arc<Daemon>,
    peer: &PeerIdentity,
    env: Option<String>,
    all: bool,
) -> Response {
    let which = if all {
        Probe::All
    } else if let Some(e) = env {
        Probe::One(e)
    } else {
        return fail_msg(peer, "probe", "", "specify an env or set all=true");
    };
    let cfg = match load_config(&daemon.state_dir, &daemon.ks) {
        Ok(c) => c,
        Err(e) => return fail(peer, "probe", "", e),
    };
    let results = test_envs(&cfg, which, daemon.allow_tofu).await;
    Response::ProbeResults(
        results
            .into_iter()
            .map(|r| ProbeResultDto {
                env: r.env,
                ok: r.ok,
                supported: r.supported,
                reason: r.reason,
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// failure paths (all audited)
// ---------------------------------------------------------------------------

/// A mutation/read that failed before touching the live env table. Audited as a
/// deny with the error; returned to the client as `Response::Error`.
fn fail(peer: &PeerIdentity, action: &str, target: &str, e: anyhow::Error) -> Response {
    let msg = format!("{e:#}");
    admin_event(peer, action, target, Decision::Error, Some(msg.clone())).emit();
    Response::Error(msg)
}

fn fail_msg(peer: &PeerIdentity, action: &str, target: &str, msg: &str) -> Response {
    admin_event(peer, action, target, Decision::Error, Some(msg.to_string())).emit();
    Response::Error(msg.to_string())
}

/// The config was persisted but the live apply failed. The two now disagree
/// until a restart re-reads the durable config; say so plainly instead of
/// panicking or silently dropping the change.
fn persisted_but_apply_failed(
    peer: &PeerIdentity,
    action: &str,
    target: &str,
    env: &str,
    e: anyhow::Error,
) -> Response {
    let msg = format!(
        "config persisted but env {env} could not be applied live \
         (restart the service to finish applying): {e:#}"
    );
    admin_event(peer, action, target, Decision::Error, Some(msg.clone())).emit();
    Response::Error(msg)
}
