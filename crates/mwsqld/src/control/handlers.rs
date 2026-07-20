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
use tracing::warn;

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
            let target = name.clone();
            let resp = simple_mutation(daemon, peer, "rm_bastion", &target, move |cfg| {
                rm_bastion(cfg, &name)
            })
            .await;
            // Drop any cached SSH session so a later bastion of the same name
            // cannot silently inherit the removed one's tunnel. rm_bastion only
            // succeeds when no env references it, so nothing needs rebuilding.
            if matches!(resp, Response::Ok) {
                daemon.bastions.evict(&target).await;
            }
            resp
        }
        Request::SetFingerprint {
            bastion,
            fingerprint,
        } => set_fingerprint_req(daemon, peer, bastion, fingerprint).await,

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
/// apply): add/remove an unreferenced bastion/credential.
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

/// Pin (or correct) a bastion's host-key fingerprint and make it bite without
/// a restart: forget the cached SSH session, then rebuild every env that
/// references the bastion so its next tunnel re-runs the host-key check against
/// the new pin. Without the evict+rebuild a TOFU-accepted (possibly MITM'd)
/// session would keep serving until the daemon restarted, which is exactly what
/// pinning exists to stop.
///
/// Graceful while the rebuild SUCCEEDS: sessions already in flight finish on
/// the old tunnel, only new connections get the re-checked one. Cutting live
/// sessions would mean blocking on each forward's read guard, wedging every
/// admin command behind the longest-running query.
///
/// A rebuild that FAILS must fail closed. `apply_rebuild_backend` builds before
/// it publishes, so a rejected host key leaves the old runtime in place - and
/// that old runtime is the tunnel the operator just declared untrusted. Serving
/// new connections through it would invert the whole point of re-pinning, so
/// the env is taken offline instead and the operator is told so plainly.
async fn set_fingerprint_req(
    daemon: &Arc<Daemon>,
    peer: &PeerIdentity,
    bastion: String,
    fingerprint: mw_core::config::HostKeyFingerprint,
) -> Response {
    let _guard = daemon.config_write.lock().await;
    {
        let bastion_for_tx = bastion.clone();
        if let Err(e) = with_config(&daemon.state_dir, &daemon.ks, move |cfg| {
            set_fingerprint(cfg, &bastion_for_tx, fingerprint)
        }) {
            return fail(peer, "set_fingerprint", &bastion, e);
        }
    }
    daemon.bastions.evict(&bastion).await;
    let cfg = match load_config(&daemon.state_dir, &daemon.ks) {
        Ok(c) => c,
        Err(e) => return fail(peer, "set_fingerprint", &bastion, e),
    };
    let affected: Vec<String> = cfg
        .envs
        .iter()
        .filter(|(_, e)| e.bastion.as_deref() == Some(bastion.as_str()))
        .map(|(n, _)| n.clone())
        .collect();
    // Rebuild every affected env even if one fails: bailing early would leave
    // the rest still pinned to the old key with nothing to retry them.
    let mut stopped = Vec::new();
    for env_name in &affected {
        let Some(env) = cfg.envs.get(env_name) else {
            continue;
        };
        // An env in the config that the daemon never brought up (an unsupported
        // engine is skipped at bind) has no tunnel to re-check and nothing to
        // stop. Rebuilding it would only report a spurious "no such env".
        if !daemon.has_env(env_name).await {
            continue;
        }
        if let Err(e) = daemon.apply_rebuild_backend(&cfg, env, env_name).await {
            daemon.apply_rm_env(env_name).await;
            stopped.push(format!("{env_name}: {e:#}"));
        }
    }
    if !stopped.is_empty() {
        return stopped_after_failed_repin(peer, &bastion, &stopped);
    }
    admin_event(peer, "set_fingerprint", &bastion, Decision::Allow, None).emit();
    Response::Ok
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
                // The env + its token hash are already durable. The minted token
                // is ONE-TIME — never swallow it, or the operator is locked out
                // of an env that now exists. Return it with the not-yet-live
                // condition recorded in the audit log; a restart binds the env.
                return token_but_not_live(peer, "add_env", &target, out, e);
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
                // The rotated token hash is durable; the cleartext is one-time.
                // Return it rather than stranding the operator with a token they
                // just invalidated but never received.
                return token_but_not_live(peer, "grant", &env, out, err);
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
//
// Successful reads are audited too (not just denials/errors): an authorized
// but compromised admin account enumerating the topology, credential names,
// or audit history should leave a forensic trail.

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
    admin_event(peer, "list_bastions", "", Decision::Allow, None).emit();
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
    admin_event(peer, "list_creds", "", Decision::Allow, None).emit();
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
    admin_event(peer, "list_envs", "", Decision::Allow, None).emit();
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
/// Deliberately NOT audited on success. This handler reads the very file
/// `admin_event` writes to, so emitting per read would push the mutations and
/// denials an operator is hunting straight out of the tail window they asked
/// for. Failures are still audited: those are rare and do not self-pollute.
fn audit_tail(daemon: &Arc<Daemon>, peer: &PeerIdentity, n: usize) -> Response {
    let target = format!("n={n}");
    let dir = daemon.state_dir.join("audit");
    if !dir.exists() {
        return Response::AuditLines(Vec::new());
    }
    let entries = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) => return fail_msg(peer, "audit_tail", &target, &format!("read audit dir: {e}")),
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
        Err(e) => {
            return fail_msg(
                peer,
                "audit_tail",
                &target,
                &format!("read audit file: {e}"),
            )
        }
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
    let target = match &which {
        Probe::All => "all".to_string(),
        Probe::One(e) => e.clone(),
    };
    let results = test_envs(&cfg, which, daemon.allow_tofu).await;
    admin_event(peer, "probe", &target, Decision::Allow, None).emit();
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

/// The config change is durable but the env isn't serving yet; shared by the
/// audit note and the user-facing advisory so the two never drift.
const NOT_YET_LIVE: &str = "persisted but not yet live";

/// A token-minting mutation (add_env / grant) whose config persisted but whose
/// live apply then failed. The minted cleartext is ONE-TIME, so it must reach
/// the operator even though the env isn't live yet — dropping it would strand an
/// env that now exists. Audit the not-yet-live condition + warn, and surface it
/// to the operator via the token response's `NewEnvOutputDto.note`, which the CLI
/// renders alongside the token; the daemon log carries the fuller detail.
fn token_but_not_live(
    peer: &PeerIdentity,
    action: &str,
    target: &str,
    out: mw_core::mutate::NewEnvOutput,
    e: anyhow::Error,
) -> Response {
    let note =
        format!("{action} on {target} {NOT_YET_LIVE} (restart the service to bind it): {e:#}");
    admin_event(peer, action, target, Decision::Error, Some(note.clone())).emit();
    warn!("{note}");
    // Carry a user-facing advisory in the token response so the CLI can warn the
    // operator that the env isn't serving yet (vs a clean success, note=None).
    let mut dto: mw_core::control::NewEnvOutputDto = out.into();
    dto.note = Some(format!(
        "{NOT_YET_LIVE} — restart the service to bind this env"
    ));
    Response::Token(dto)
}

/// The config was persisted but the live apply failed. The two now disagree
/// until a restart re-reads the durable config; say so plainly instead of
/// panicking or silently dropping the change.
/// A re-pin whose rebuild failed: the env was STOPPED rather than left serving
/// through the tunnel whose host key was just rejected. Says that outright -
/// "could not be applied" would read as a warning when the gateway has actually
/// taken an env offline, and the operator needs to know which ones and why.
fn stopped_after_failed_repin(peer: &PeerIdentity, bastion: &str, stopped: &[String]) -> Response {
    let msg = format!(
        "new fingerprint saved for bastion {bastion}, but {} env(s) could not \
         reconnect under it and were STOPPED rather than left on the old, \
         now-untrusted tunnel: {}. Verify the bastion's real host key, then \
         re-add or restart to bring them back.",
        stopped.len(),
        stopped.join("; ")
    );
    admin_event(
        peer,
        "set_fingerprint",
        bastion,
        Decision::Error,
        Some(msg.clone()),
    )
    .emit();
    warn!("{msg}");
    Response::Error(msg)
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use mw_core::config::{ClientAuth, HostKeyFingerprint, Policy};
    use mw_core::control::PROTOCOL_VERSION;
    use mw_core::mutate::BastionAuthInput;
    use mw_core::secret::SecretStr;
    use mw_core::state::{init, KeystoreChoice};

    /// A live, env-less daemon with a sealed empty config on disk, mirroring
    /// `control::tests::empty_daemon`. The returned `TempDir` must be kept in
    /// scope for the daemon's lifetime.
    async fn empty_daemon() -> (Arc<Daemon>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let ks = KeystoreChoice::default_file(tmp.path());
        init(tmp.path(), &ks).unwrap();
        let daemon = Daemon::bind(
            tmp.path().to_path_buf(),
            &Config::default(),
            "127.0.0.1",
            false,
            ks,
        )
        .await
        .unwrap();
        (Arc::new(daemon), tmp)
    }

    fn peer() -> PeerIdentity {
        PeerIdentity::default()
    }

    fn bastion_dto(name: &str) -> BastionInputDto {
        BastionInputDto {
            name: name.into(),
            host: "h".into(),
            port: 22,
            ssh_user: "u".into(),
            auth: BastionAuthInput::Password(SecretStr::new("pw")),
            fingerprint: None,
        }
    }

    fn cred_dto(name: &str) -> CredInputDto {
        CredInputDto {
            name: name.into(),
            backend_user: "u".into(),
            password: SecretStr::new("p"),
        }
    }

    /// backend_host 127.0.0.1 + listen_port 0 so this never touches a real
    /// backend (the pool build is lazy, no connect) and never collides with
    /// another test's listener: the OS picks a free ephemeral port for us.
    fn env_dto(name: &str, credential: &str) -> EnvInputDto {
        EnvInputDto {
            name: name.into(),
            backend_host: "127.0.0.1".into(),
            backend_port: None,
            engine: EngineKind::MySql,
            database: None,
            bastion: None,
            credential: credential.into(),
            policy: Policy::ReadOnly,
            listen_port: Some(0),
            max_pool: None,
        }
    }

    async fn add_cred_and_env(daemon: &Arc<Daemon>, cred_name: &str, env_name: &str) {
        let resp = dispatch(daemon, &peer(), Request::AddCred(cred_dto(cred_name))).await;
        assert!(matches!(&resp, Response::Ok), "add_cred failed: {resp:?}");
        let resp = dispatch(
            daemon,
            &peer(),
            Request::AddEnv(env_dto(env_name, cred_name)),
        )
        .await;
        assert!(
            matches!(&resp, Response::Token(_)),
            "add_env failed: {resp:?}"
        );
    }

    #[tokio::test]
    async fn add_bastion_persists() {
        let (daemon, _tmp) = empty_daemon().await;
        let resp = dispatch(&daemon, &peer(), Request::AddBastion(bastion_dto("b"))).await;
        match resp {
            Response::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        let cfg = load_config(&daemon.state_dir, &daemon.ks).unwrap();
        assert!(cfg.bastions.contains_key("b"));
    }

    #[tokio::test]
    async fn add_cred_persists() {
        let (daemon, _tmp) = empty_daemon().await;
        let resp = dispatch(&daemon, &peer(), Request::AddCred(cred_dto("c"))).await;
        match resp {
            Response::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        let cfg = load_config(&daemon.state_dir, &daemon.ks).unwrap();
        assert_eq!(cfg.credentials["c"].backend_user, "u");
    }

    #[tokio::test]
    async fn add_env_on_free_port_goes_live_and_persists() {
        let (daemon, _tmp) = empty_daemon().await;
        let resp = dispatch(&daemon, &peer(), Request::AddCred(cred_dto("c"))).await;
        assert!(matches!(&resp, Response::Ok), "add_cred failed: {resp:?}");
        assert_eq!(daemon.env_count().await, 0);

        let resp = dispatch(&daemon, &peer(), Request::AddEnv(env_dto("e", "c"))).await;
        match resp {
            Response::Token(dto) => {
                assert!(!dto.token.expose().is_empty());
                assert!(dto.note.is_none(), "clean add must carry no advisory");
            }
            other => panic!("expected Token, got {other:?}"),
        }
        assert_eq!(daemon.env_count().await, 1);
        let cfg = load_config(&daemon.state_dir, &daemon.ks).unwrap();
        assert!(cfg.envs.contains_key("e"));
    }

    #[tokio::test]
    async fn grant_issues_new_token_and_persists_new_client_auth() {
        let (daemon, _tmp) = empty_daemon().await;
        add_cred_and_env(&daemon, "c", "e").await;
        let before = load_config(&daemon.state_dir, &daemon.ks).unwrap();
        let old_hash = match &before.envs["e"].client_auth {
            ClientAuth::NativePassword { double_sha1 } => *double_sha1,
            other => panic!("expected native password, got {other:?}"),
        };

        let resp = dispatch(&daemon, &peer(), Request::Grant { env: "e".into() }).await;
        let new_token = match resp {
            Response::Token(dto) => dto.token,
            other => panic!("expected Token, got {other:?}"),
        };
        assert!(!new_token.expose().is_empty());

        let after = load_config(&daemon.state_dir, &daemon.ks).unwrap();
        let new_hash = match &after.envs["e"].client_auth {
            ClientAuth::NativePassword { double_sha1 } => *double_sha1,
            other => panic!("expected native password, got {other:?}"),
        };
        assert_ne!(old_hash, new_hash, "grant must rotate the stored auth hash");
    }

    #[tokio::test]
    async fn set_policy_read_write_without_confirm_is_denied() {
        let (daemon, _tmp) = empty_daemon().await;
        add_cred_and_env(&daemon, "c", "e").await;
        let resp = dispatch(
            &daemon,
            &peer(),
            Request::SetPolicy {
                env: "e".into(),
                target: PolicyTarget::ReadWrite,
                confirm_unsafe: false,
            },
        )
        .await;
        match resp {
            Response::Denied(reason) => assert!(reason.contains("confirm"), "{reason}"),
            other => panic!("expected Denied, got {other:?}"),
        }
        let cfg = load_config(&daemon.state_dir, &daemon.ks).unwrap();
        assert!(matches!(cfg.envs["e"].policy, Policy::ReadOnly));
    }

    #[tokio::test]
    async fn set_policy_read_write_with_confirm_persists() {
        let (daemon, _tmp) = empty_daemon().await;
        add_cred_and_env(&daemon, "c", "e").await;
        let resp = dispatch(
            &daemon,
            &peer(),
            Request::SetPolicy {
                env: "e".into(),
                target: PolicyTarget::ReadWrite,
                confirm_unsafe: true,
            },
        )
        .await;
        match resp {
            Response::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        let cfg = load_config(&daemon.state_dir, &daemon.ks).unwrap();
        assert!(matches!(cfg.envs["e"].policy, Policy::ReadWrite));
    }

    #[tokio::test]
    async fn rm_env_removes_live_and_persisted() {
        let (daemon, _tmp) = empty_daemon().await;
        add_cred_and_env(&daemon, "c", "e").await;
        assert_eq!(daemon.env_count().await, 1);

        let resp = dispatch(&daemon, &peer(), Request::RmEnv { name: "e".into() }).await;
        match resp {
            Response::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        assert_eq!(daemon.env_count().await, 0);
        let cfg = load_config(&daemon.state_dir, &daemon.ks).unwrap();
        assert!(!cfg.envs.contains_key("e"));
    }

    #[tokio::test]
    async fn rm_bastion_persists_and_leaves_no_cached_session() {
        let (daemon, _tmp) = empty_daemon().await;
        let resp = dispatch(&daemon, &peer(), Request::AddBastion(bastion_dto("b"))).await;
        assert!(
            matches!(&resp, Response::Ok),
            "add_bastion failed: {resp:?}"
        );

        let resp = dispatch(&daemon, &peer(), Request::RmBastion { name: "b".into() }).await;
        match resp {
            Response::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        let cfg = load_config(&daemon.state_dir, &daemon.ks).unwrap();
        assert!(!cfg.bastions.contains_key("b"));
        // No env ever referenced "b", so no session was ever cached; the
        // eviction the handler already ran is a no-op here (evict returns
        // false), proving it doesn't error on a bastion with nothing cached.
        assert!(!daemon.bastions.evict("b").await);
    }

    #[tokio::test]
    async fn set_fingerprint_persists_new_pin_for_unreferenced_bastion() {
        let (daemon, _tmp) = empty_daemon().await;
        let resp = dispatch(&daemon, &peer(), Request::AddBastion(bastion_dto("b"))).await;
        assert!(
            matches!(&resp, Response::Ok),
            "add_bastion failed: {resp:?}"
        );

        let resp = dispatch(
            &daemon,
            &peer(),
            Request::SetFingerprint {
                bastion: "b".into(),
                fingerprint: HostKeyFingerprint {
                    algo: "ssh-ed25519".into(),
                    sha256_b64: "AAAA".into(),
                },
            },
        )
        .await;
        match resp {
            Response::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        let cfg = load_config(&daemon.state_dir, &daemon.ks).unwrap();
        let pins = &cfg.bastions["b"].pinned_host_keys;
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].sha256_b64, "AAAA");
    }

    /// An env can sit in the config without being served: `bind` skips engines
    /// that are not implemented. Re-pinning its bastion has nothing to rebuild
    /// for it, and must not report a healthy re-pin as a failure that sends the
    /// operator off to restart a working daemon. Drop the `has_env` guard in
    /// `set_fingerprint_req` and this fails with "no such env".
    #[tokio::test]
    async fn set_fingerprint_ignores_an_env_that_was_never_brought_up() {
        let (daemon, _tmp) = empty_daemon().await;
        assert!(matches!(
            dispatch(&daemon, &peer(), Request::AddBastion(bastion_dto("b"))).await,
            Response::Ok
        ));
        dispatch(&daemon, &peer(), Request::AddCred(cred_dto("c"))).await;

        // MsSql is stubbed, so bind/apply skip it: in the config, never live.
        let mut dto = env_dto("stub", "c");
        dto.engine = EngineKind::MsSql;
        dto.bastion = Some("b".into());
        dispatch(&daemon, &peer(), Request::AddEnv(dto)).await;
        assert!(!daemon.has_env("stub").await, "precondition: not live");

        let resp = dispatch(
            &daemon,
            &peer(),
            Request::SetFingerprint {
                bastion: "b".into(),
                fingerprint: HostKeyFingerprint {
                    algo: "ssh-ed25519".into(),
                    sha256_b64: "BBBB".into(),
                },
            },
        )
        .await;
        match resp {
            Response::Ok => {}
            other => panic!("a non-live env must not fail the re-pin, got {other:?}"),
        }
    }

    /// Minimal in-process sshd: a host key and password auth, nothing else.
    /// Enough for `build_env_runtime`, which opens the session and binds a
    /// local forward but never opens a channel until a client connects, and the
    /// backend pool is lazy so no database is needed either.
    mod sshd {
        use russh::server::{self, Auth, Handler, Server as _};
        use std::sync::Arc;

        const HOST_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBjYB3+5hdIxwZUQWix9vH/LSQ2C+nvZaftFvADx4FEMgAAAJDWMN3Q1jDd
0AAAAAtzc2gtZWQyNTUxOQAAACBjYB3+5hdIxwZUQWix9vH/LSQ2C+nvZaftFvADx4FEMg
AAAEBc1+jlhd4Rab8V08LKYQ66QNsuuZIn9lArqKEKd08EUGNgHf7mF0jHBlRBaLH28f8t
JDYL6e9lp+0W8APHgUQyAAAACXRlc3Qtb25seQECAwQ=
-----END OPENSSH PRIVATE KEY-----
";
        pub const USER: &str = "tester";
        pub const PASSWORD: &str = "tunnel-pw-9f7a1d";

        #[derive(Clone)]
        struct Srv;
        #[derive(Default)]
        pub struct H;

        impl server::Server for Srv {
            type Handler = H;
            fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> H {
                H
            }
        }

        impl Handler for H {
            type Error = russh::Error;
            async fn auth_password(&mut self, u: &str, p: &str) -> Result<Auth, Self::Error> {
                if u == USER && p == PASSWORD {
                    Ok(Auth::Accept)
                } else {
                    Ok(Auth::reject())
                }
            }
        }

        /// Start on an ephemeral port and return it. The task is detached; it
        /// dies with the test runtime.
        pub async fn start() -> u16 {
            let key = russh::keys::PrivateKey::from_openssh(HOST_KEY).unwrap();
            let config = Arc::new(server::Config {
                keys: vec![key],
                ..Default::default()
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                let _ = Srv.run_on_socket(config, &listener).await;
            });
            port
        }
    }

    /// The security-critical path: a re-pin whose reconnect FAILS must take the
    /// env offline, never leave it serving through the tunnel the operator just
    /// declared untrusted. Revert the `apply_rm_env` in `set_fingerprint_req`
    /// and this fails with the env still live.
    #[tokio::test]
    async fn failed_repin_stops_the_env_instead_of_serving_the_old_tunnel() {
        let port = sshd::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let ks = KeystoreChoice::default_file(tmp.path());
        init(tmp.path(), &ks).unwrap();

        // Bastion with no pins + allow_tofu, so the FIRST connect succeeds.
        mw_core::state::with_config(tmp.path(), &ks, |cfg| {
            mw_core::mutate::add_bastion(
                cfg,
                BastionAddArgs {
                    name: "b",
                    host: "127.0.0.1",
                    port,
                    ssh_user: sshd::USER,
                    auth: BastionAuthInput::Password(SecretStr::new(sshd::PASSWORD)),
                    fingerprint: None,
                },
            )?;
            mw_core::mutate::add_cred(cfg, "c", "u", SecretStr::new("p"))?;
            mw_core::mutate::add_env(
                cfg,
                EnvAddArgs {
                    name: "e",
                    backend_host: "127.0.0.1",
                    backend_port: 3306,
                    default_database: None,
                    bastion: Some("b"),
                    credential: "c",
                    policy: Policy::ReadOnly,
                    listen_port: Some(0),
                    max_pool: None,
                    engine: EngineKind::MySql,
                },
            )?;
            Ok(())
        })
        .unwrap();

        let cfg = load_config(tmp.path(), &ks).unwrap();
        let daemon = Arc::new(
            Daemon::bind(tmp.path().to_path_buf(), &cfg, "127.0.0.1", true, ks)
                .await
                .unwrap(),
        );
        assert!(daemon.has_env("e").await, "precondition: env is serving");

        // Pin a fingerprint the test sshd cannot present: the reconnect is
        // refused by check_server_key, exactly as a MITM'd host would be.
        let resp = dispatch(
            &daemon,
            &peer(),
            Request::SetFingerprint {
                bastion: "b".into(),
                fingerprint: HostKeyFingerprint {
                    algo: "ssh-ed25519".into(),
                    sha256_b64: "definitely-not-the-real-key".into(),
                },
            },
        )
        .await;

        match resp {
            Response::Error(msg) => assert!(msg.contains("STOPPED"), "{msg}"),
            other => panic!("a failed re-pin must not report success: {other:?}"),
        }
        assert!(
            !daemon.has_env("e").await,
            "env still serving through the rejected tunnel: fail-open regression"
        );
    }

    #[tokio::test]
    async fn second_hello_is_a_protocol_error() {
        let (daemon, _tmp) = empty_daemon().await;
        let resp = dispatch(
            &daemon,
            &peer(),
            Request::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .await;
        match resp {
            Response::Error(msg) => assert!(msg.contains("Hello"), "{msg}"),
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
