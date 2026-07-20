//! Blocking control-channel client. `mwsqlctl` is synchronous (no tokio), so it
//! speaks the shared [`mw_core::control`] codec directly over a Unix-domain
//! socket (Unix) or a named pipe (Windows). One request per connection: connect,
//! send `Hello`, send the request, read one `Response`.
//!
//! This is the online counterpart to the offline `ops`/`envs`/… modules: in
//! service mode the CLI no longer elevates to write the root-owned sealed config
//! itself — it asks the running privileged daemon over this channel, which
//! authorizes the peer by kernel credentials (root/Administrators or the
//! `middlewhere-admins` group).

use std::io::{Read, Write};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};

use mw_core::control::{
    read_frame, write_frame, BastionInputDto, EnvInputDto, ProbeResultDto, Request, Response,
    PROTOCOL_VERSION,
};
use mw_core::mutate::{BastionAuthInput, PolicyTarget};

use crate::ops;

/// Socket/pipe name the daemon keys its control channel on. Matches mwsqld's
/// `control::SERVICE_NAME`. Config commands carry no `--service-name`, so this is
/// the fixed default the CLI dials.
pub const CONTROL_SERVICE_NAME: &str = "mwsqld";

/// The privileged group whose members may drive the control channel; only used
/// to phrase the "you're not authorized" hint. Mirrors `control::ADMIN_GROUP`.
const ADMIN_GROUP: &str = "middlewhere-admins";

/// A failed control-channel call, split so the router can tell "the daemon isn't
/// running" (worth an `--offline` hint) apart from every other failure.
#[derive(Debug)]
pub enum CallError {
    /// Nothing is listening — no socket/pipe, or a stale socket with no daemon
    /// behind it. The service is almost certainly not running.
    Unreachable(String),
    /// Everything else: a framing/protocol error, a transport permission denial,
    /// or a `Denied`/`Error` response from the daemon.
    Failed(anyhow::Error),
}

// ---------------------------------------------------------------------------
// mode decision (pure — unit-tested)
// ---------------------------------------------------------------------------

/// How a config/read command reaches the sealed config.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Mode {
    /// Talk to the running daemon over the control channel (service mode).
    Channel,
    /// Read/write the sealed config file in-process (`--user`, or `--offline`).
    Direct,
}

/// Resolve the access mode. The control channel ALWAYS mutates whatever config
/// the running daemon loaded — it cannot target a specific directory — so the
/// channel is only correct when the caller means "the running system service".
/// Channel iff a flagless command (no `--user`, no `--offline`, no explicit
/// `--state-dir`/`MW_STATE_DIR`) resolves to the system service dir; everything
/// else edits a config file directly:
///   - an explicit `--state-dir` names a specific config → Direct (going to the
///     channel would silently mutate the daemon's production config instead);
///   - a v0.2.x legacy per-user resolution (a resolved dir other than the system
///     service dir) → Direct;
///   - `--user` / `--offline` → Direct.
///
/// Both derived inputs are computed here — `state_dir_arg.is_some()` for the
/// explicit-dir test and `resolved_state_dir == default_state_dir()` for the
/// system-target test — so the router and wizard pass only raw inputs and the
/// derivation can't drift between call sites.
///
/// If no daemon is up on the channel path, [`call`] returns
/// [`CallError::Unreachable`] and the CLI prints the recovery hint.
pub fn decide_mode(
    user: bool,
    offline: bool,
    state_dir_arg: Option<&Path>,
    resolved_state_dir: &Path,
) -> Mode {
    let state_dir_explicit = state_dir_arg.is_some();
    let target_is_system = resolved_state_dir == mw_core::state::default_state_dir();
    if !user && !offline && !state_dir_explicit && target_is_system {
        Mode::Channel
    } else {
        Mode::Direct
    }
}

/// Whether a Direct (config-file-editing) command is safe to run without the
/// running service in the loop. Only a **mutation** can clobber the daemon: the
/// Direct path writes the sealed config with no cross-process lock and no live
/// apply, so against a running service it both loses updates (a concurrent
/// channel write can win) and leaves the daemon serving the old config. Reads are
/// always fine, and `--user` targets the per-user dir the daemon never owns.
/// `reachable` is [`is_reachable`]'s result; callers should only probe (and pass
/// `true`) when it could matter — a non-`--user` mutation.
pub fn direct_mutation_ok(is_user: bool, is_mutation: bool, reachable: bool) -> bool {
    !is_mutation || is_user || !reachable
}

/// `--offline` edits the sealed config directly. When that config is the
/// root/service-owned system dir, the process must already be privileged — the
/// CLI no longer auto-elevates for config. Returns whether the offline access is
/// permitted (always true when not offline or the target is user-writable).
pub fn offline_privilege_ok(offline: bool, target_needs_root: bool, privileged: bool) -> bool {
    !offline || !target_needs_root || privileged
}

// ---------------------------------------------------------------------------
// request builders (pure — unit-tested)
// ---------------------------------------------------------------------------

/// Build an [`AddBastion`](Request::AddBastion) payload from the CLI's bastion
/// input plus the already-resolved auth secret (prompted/read locally). Shares
/// `ops::single_fingerprint` with the offline path so both reject a second pin
/// instead of one silently keeping the first.
pub fn bastion_dto(input: &ops::BastionInput, auth: BastionAuthInput) -> Result<BastionInputDto> {
    let fingerprint = ops::single_fingerprint(&input.fingerprints)?;
    Ok(BastionInputDto {
        name: input.name.clone(),
        host: input.host.clone(),
        port: input.port,
        ssh_user: input.ssh_user.clone(),
        auth,
        fingerprint,
    })
}

/// Build an [`AddEnv`](Request::AddEnv) payload from the CLI's env input. The
/// daemon applies the engine-default port when `backend_port` is `None`, exactly
/// as the offline path does.
pub fn env_dto(input: &ops::EnvInput) -> EnvInputDto {
    EnvInputDto {
        name: input.name.clone(),
        backend_host: input.backend_host.clone(),
        backend_port: input.backend_port,
        engine: input.engine,
        database: input.database.clone(),
        bastion: input.bastion.clone(),
        credential: input.credential.clone(),
        policy: input.policy.clone(),
        listen_port: input.listen_port,
        max_pool: input.max_pool,
    }
}

/// Map the `policy` subcommand's two toggle flags to a [`PolicyTarget`]. Exactly
/// one must be set, matching the offline dispatch.
pub fn policy_target(read_only: bool, read_write: bool) -> Result<PolicyTarget> {
    match (read_only, read_write) {
        (true, false) => Ok(PolicyTarget::ReadOnly),
        (false, true) => Ok(PolicyTarget::ReadWrite),
        _ => bail!("specify exactly one of --read-only / --read-write"),
    }
}

// ---------------------------------------------------------------------------
// row parsers (pure — unit-tested). The daemon returns tab-delimited rows; the
// wizard needs a few fields back as structured data for its selection prompts.
// ---------------------------------------------------------------------------

/// A bastion's name, host, and pinned-fingerprint count, parsed from a
/// `ListBastions` row (`name\tuser@host:port\tauth\tpinned=N`).
#[derive(Debug, PartialEq, Eq)]
pub struct BastionInfo {
    pub name: String,
    pub host: String,
    pub pinned: usize,
}

pub fn parse_bastion_row(row: &str) -> Option<BastionInfo> {
    let mut f = row.split('\t');
    let name = f.next()?.to_string();
    let endpoint = f.next()?; // user@host:port
    let _auth = f.next()?;
    let pinned = f.next()?.strip_prefix("pinned=")?.parse().ok()?;
    let host_port = endpoint
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(endpoint);
    let host = host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_port)
        .to_string();
    Some(BastionInfo { name, host, pinned })
}

/// A credential name, parsed from a `ListCreds` row (`name\tuser`).
pub fn parse_cred_name(row: &str) -> Option<String> {
    row.split('\t').next().map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

/// Render probe results like `env test`: `✓` per connected env, a skip note for
/// an unsupported engine, `✗` for a real failure. Returns `Err` (non-zero exit)
/// if any *supported* env failed, matching the offline env-test semantics.
pub fn render_probe_results(results: &[ProbeResultDto]) -> Result<()> {
    if results.is_empty() {
        eprintln!("validation skipped: no environments configured");
        return Ok(());
    }
    let mut failed = Vec::new();
    for r in results {
        if r.ok {
            eprintln!("✓ {} connected.", r.env);
        } else if !r.supported {
            eprintln!("validation skipped ({}): {}", r.env, r.reason);
        } else {
            eprintln!("✗ {}: {}", r.env, r.reason);
            failed.push(r.env.clone());
        }
    }
    if !failed.is_empty() {
        bail!("connection failed: {}", failed.join(", "));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// transport
// ---------------------------------------------------------------------------

/// Connect, handshake, send `req`, read one response. `state_dir` supplies the
/// Unix fallback socket path so it matches the daemon's own resolution.
pub fn call(service_name: &str, state_dir: &Path, req: &Request) -> Result<Response, CallError> {
    #[cfg(unix)]
    {
        let _ = service_name;
        call_unix(service_name, state_dir, req)
    }
    #[cfg(windows)]
    {
        let _ = state_dir;
        call_windows(service_name, req)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (service_name, state_dir, req);
        Err(CallError::Failed(anyhow!(
            "no control-channel transport on this platform"
        )))
    }
}

/// Cheap liveness probe: is a daemon actually listening on the control channel?
/// Connect (and nothing more) to the socket/pipe the router would dial — a
/// successful connect means a daemon answered. A missing or stale endpoint
/// (connect-refused / not-found) is not-reachable; any other error means the
/// endpoint exists (the daemon is up but e.g. we lack rights), so it counts as
/// reachable — matching [`call`]'s [`CallError::Unreachable`] classification.
/// Used to guard a Direct config mutation from clobbering a running service.
pub fn is_reachable(state_dir: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;
        let path = unix_socket_path(state_dir, CONTROL_SERVICE_NAME);
        match UnixStream::connect(&path) {
            Ok(_) => true,
            Err(e) => !matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ),
        }
    }
    #[cfg(windows)]
    {
        let _ = state_dir;
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;
        const ERROR_FILE_NOT_FOUND: i32 = 2;
        const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
        let pipe = format!(r"\\.\pipe\middlewhere-{CONTROL_SERVICE_NAME}-control");
        match OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(&pipe)
        {
            Ok(_) => true,
            // Only "no such pipe" is not-reachable; busy/access-denied still mean
            // the daemon is up.
            Err(e) => e.raw_os_error() != Some(ERROR_FILE_NOT_FOUND),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = state_dir;
        false
    }
}

/// Call the daemon, turning a not-reachable error into a clear "start the
/// service / use --offline" message. Shared by the router and the wizard, which
/// have both already committed to the channel.
pub fn checked_call(state_dir: &Path, req: &Request) -> Result<Response> {
    match call(CONTROL_SERVICE_NAME, state_dir, req) {
        Ok(r) => Ok(r),
        Err(CallError::Unreachable(ep)) => bail!(
            "the middleWHERE service isn't reachable at {ep}; start it, pass \
             --user for a per-user deployment, or run {} to edit the sealed \
             config directly.",
            offline_hint()
        ),
        Err(CallError::Failed(e)) => Err(e),
    }
}

/// [`checked_call`] specialized to a read that must return `Rows`.
pub fn rows(state_dir: &Path, req: &Request) -> Result<Vec<String>> {
    match checked_call(state_dir, req)? {
        Response::Rows(v) => Ok(v),
        other => bail!("expected a row listing from the daemon, got {other:?}"),
    }
}

/// The platform-appropriate `--offline` invocation for error hints.
fn offline_hint() -> &'static str {
    if cfg!(windows) {
        "`mwsqlctl --offline <cmd>` from an elevated terminal"
    } else {
        "`sudo mwsqlctl --offline <cmd>`"
    }
}

/// Run the handshake + one request/response over an established stream.
fn exchange<S: Read + Write>(stream: &mut S, req: &Request) -> Result<Response> {
    write_frame(
        stream,
        &Request::Hello {
            version: PROTOCOL_VERSION,
        },
    )
    .context("send handshake")?;
    write_frame(stream, req).context("send request")?;
    read_frame(stream).context("read response")
}

/// Map the daemon's reply into the client's `Result`: a `Denied`/`Error`
/// response is an error, a framing failure is an error, anything else is the
/// value the caller renders.
fn finish(exchanged: Result<Response>) -> Result<Response, CallError> {
    match exchanged {
        Ok(Response::Denied(m)) => Err(CallError::Failed(anyhow!(
            "permission denied: {m} (are you in the {ADMIN_GROUP} group?)"
        ))),
        Ok(Response::Error(m)) => Err(CallError::Failed(anyhow!("{m}"))),
        Ok(ok) => Ok(ok),
        Err(e) => Err(CallError::Failed(e)),
    }
}

#[cfg(unix)]
fn call_unix(service_name: &str, state_dir: &Path, req: &Request) -> Result<Response, CallError> {
    use std::os::unix::net::UnixStream;

    let path = unix_socket_path(state_dir, service_name);
    let mut stream = match UnixStream::connect(&path) {
        Ok(s) => s,
        Err(e) => {
            return Err(match e.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                    CallError::Unreachable(path.display().to_string())
                }
                std::io::ErrorKind::PermissionDenied => CallError::Failed(anyhow!(
                    "permission denied opening the control socket {} \
                     (need root or membership in {ADMIN_GROUP})",
                    path.display()
                )),
                _ => CallError::Failed(
                    anyhow::Error::new(e).context(format!("connect {}", path.display())),
                ),
            });
        }
    };
    finish(exchange(&mut stream, req))
}

/// The daemon binds `<runtime>/<svc>.sock` when its runtime dir is usable, else
/// `<state_dir>/control.sock`. Dial the runtime socket when it actually exists,
/// else the state-dir fallback — the same per-OS candidates in the same order as
/// mwsqld `control::unix::resolve_socket`. The runtime dir comes from the single
/// source of truth [`mw_core::control::runtime_dir_for`] so CLI and daemon can
/// never diverge.
#[cfg(unix)]
fn unix_socket_path(state_dir: &Path, svc: &str) -> std::path::PathBuf {
    if let Some(dir) = mw_core::control::runtime_dir_for(std::env::consts::OS) {
        let sock = dir.join(format!("{svc}.sock"));
        if sock.exists() {
            return sock;
        }
    }
    state_dir.join("control.sock")
}

#[cfg(windows)]
fn call_windows(service_name: &str, req: &Request) -> Result<Response, CallError> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_PIPE_BUSY: i32 = 231;
    // SECURITY_IMPERSONATION_LEVEL::SecurityIdentification << 16. Opening the
    // pipe with this (std ORs in SECURITY_SQOS_PRESENT for us) caps the daemon's
    // ImpersonateNamedPipeClient at IDENTIFICATION: it may check our token's
    // membership but never act *as* us. Defense-in-depth against a compromised
    // daemon — the DACL already restricts who can open the pipe at all.
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

    let pipe = format!(r"\\.\pipe\middlewhere-{service_name}-control");
    // A busy pipe means the daemon is up but every instance is momentarily in
    // use; back off briefly and retry rather than failing the command.
    let mut file = None;
    for attempt in 0..10 {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(&pipe)
        {
            Ok(f) => {
                file = Some(f);
                break;
            }
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                let _ = attempt;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                return Err(CallError::Unreachable(pipe));
            }
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
                return Err(CallError::Failed(anyhow!(
                    "permission denied opening the control pipe (need Administrator \
                     or membership in {ADMIN_GROUP})"
                )));
            }
            Err(e) => {
                return Err(CallError::Failed(
                    anyhow::Error::new(e).context(format!("open control pipe {pipe}")),
                ));
            }
        }
    }
    let Some(mut file) = file else {
        return Err(CallError::Failed(anyhow!(
            "control pipe {pipe} stayed busy; the service is running but overloaded — retry"
        )));
    };
    finish(exchange(&mut file, req))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mw_core::config::{EngineKind, Policy};
    use mw_core::secret::SecretStr;

    fn bastion_input() -> ops::BastionInput {
        ops::BastionInput {
            name: "jump".into(),
            host: "db.example.com".into(),
            port: 2222,
            ssh_user: "ops".into(),
            key_file: None,
            password_stdin: false,
            fingerprints: vec!["ssh-ed25519:AAAA".into()],
        }
    }

    #[test]
    fn bastion_dto_carries_fields_and_parses_first_fingerprint() {
        let input = bastion_input();
        let dto = bastion_dto(&input, BastionAuthInput::Password(SecretStr::new("pw"))).unwrap();
        assert_eq!(dto.name, "jump");
        assert_eq!(dto.host, "db.example.com");
        assert_eq!(dto.port, 2222);
        assert_eq!(dto.ssh_user, "ops");
        let fp = dto.fingerprint.expect("fingerprint parsed");
        assert_eq!(fp.algo, "ssh-ed25519");
        assert_eq!(fp.sha256_b64, "AAAA");
        assert!(matches!(dto.auth, BastionAuthInput::Password(_)));
    }

    #[test]
    fn bastion_dto_without_fingerprint_is_none() {
        let mut input = bastion_input();
        input.fingerprints.clear();
        let dto = bastion_dto(&input, BastionAuthInput::Password(SecretStr::new("pw"))).unwrap();
        assert!(dto.fingerprint.is_none());
    }

    #[test]
    fn env_dto_maps_all_fields() {
        let input = ops::EnvInput {
            name: "stage".into(),
            backend_host: "10.0.0.5".into(),
            backend_port: Some(5433),
            engine: EngineKind::Postgres,
            database: Some("orders".into()),
            bastion: Some("jump".into()),
            credential: "ro".into(),
            policy: Policy::ReadOnly,
            listen_port: Some(6055),
            max_pool: Some(12),
        };
        let dto = env_dto(&input);
        assert_eq!(dto.name, "stage");
        assert_eq!(dto.backend_host, "10.0.0.5");
        assert_eq!(dto.backend_port, Some(5433));
        assert_eq!(dto.engine, EngineKind::Postgres);
        assert_eq!(dto.database.as_deref(), Some("orders"));
        assert_eq!(dto.bastion.as_deref(), Some("jump"));
        assert_eq!(dto.credential, "ro");
        assert_eq!(dto.listen_port, Some(6055));
        assert_eq!(dto.max_pool, Some(12));
    }

    #[test]
    fn policy_target_requires_exactly_one_flag() {
        assert_eq!(policy_target(true, false).unwrap(), PolicyTarget::ReadOnly);
        assert_eq!(policy_target(false, true).unwrap(), PolicyTarget::ReadWrite);
        assert!(policy_target(false, false).is_err());
        assert!(policy_target(true, true).is_err());
    }

    #[test]
    fn decide_mode_channel_only_for_flagless_system_target() {
        // (user, offline, state_dir_arg, resolved_state_dir) — the helper derives
        // state_dir_explicit + target_is_system from the last two.
        let sys = mw_core::state::default_state_dir();
        let other = std::path::Path::new("/srv/mw-elsewhere");
        // The ONLY channel case: flagless, no explicit --state-dir, resolves to
        // the system service dir.
        assert_eq!(decide_mode(false, false, None, &sys), Mode::Channel);
        // Flagless but resolved to a legacy per-user dir → direct (edit it in
        // place; there is no system daemon to talk to).
        assert_eq!(decide_mode(false, false, None, other), Mode::Direct);
        // An explicit --state-dir names a specific config → direct, even when it
        // happens to equal the system dir; the channel can't target a dir, so
        // routing it to the channel would silently mutate the daemon's config.
        assert_eq!(decide_mode(false, false, Some(&sys), &sys), Mode::Direct);
        assert_eq!(decide_mode(false, false, Some(other), other), Mode::Direct);
        // The explicit flags force direct.
        assert_eq!(decide_mode(true, false, None, &sys), Mode::Direct); // --user
        assert_eq!(decide_mode(false, true, None, &sys), Mode::Direct); // --offline
    }

    #[test]
    fn direct_mutation_blocked_only_when_reachable_nonuser_mutation() {
        // Reads never touch the daemon's config → always allowed.
        assert!(direct_mutation_ok(false, false, true));
        // A non-user mutation with the service up is the one refused case.
        assert!(!direct_mutation_ok(false, true, true));
        // Same mutation, no daemon up → fine to edit the file directly.
        assert!(direct_mutation_ok(false, true, false));
        // --user targets the per-user dir the daemon never owns → allowed even
        // when a system daemon happens to be reachable.
        assert!(direct_mutation_ok(true, true, true));
    }

    #[test]
    fn offline_against_system_dir_requires_privilege() {
        // Not offline: always fine, privilege irrelevant.
        assert!(offline_privilege_ok(false, true, false));
        // Offline against a user-writable target: fine unprivileged.
        assert!(offline_privilege_ok(true, false, false));
        // Offline against the root-owned system dir: needs privilege.
        assert!(!offline_privilege_ok(true, true, false));
        assert!(offline_privilege_ok(true, true, true));
    }

    #[test]
    fn parse_bastion_row_extracts_name_host_and_pin_count() {
        let info = parse_bastion_row("jump\tops@db.example.com:2222\tkey\tpinned=2").unwrap();
        assert_eq!(
            info,
            BastionInfo {
                name: "jump".into(),
                host: "db.example.com".into(),
                pinned: 2,
            }
        );
        // No user@ prefix still yields the host.
        let info = parse_bastion_row("b\thost:22\tpassword\tpinned=0").unwrap();
        assert_eq!(info.host, "host");
        assert_eq!(info.pinned, 0);
        assert!(parse_bastion_row("malformed").is_none());
    }

    #[test]
    fn parse_cred_name_takes_first_field() {
        assert_eq!(parse_cred_name("ro\tdbuser").as_deref(), Some("ro"));
        assert_eq!(parse_cred_name("solo").as_deref(), Some("solo"));
    }

    #[test]
    fn probe_render_fails_only_on_supported_failure() {
        let ok = || ProbeResultDto {
            env: "a".into(),
            ok: true,
            supported: true,
            reason: String::new(),
        };
        let unsupported = || ProbeResultDto {
            env: "m".into(),
            ok: false,
            supported: false,
            reason: "engine mssql not supported yet".into(),
        };
        let hard = || ProbeResultDto {
            env: "b".into(),
            ok: false,
            supported: true,
            reason: "connection refused".into(),
        };
        assert!(render_probe_results(&[ok(), unsupported()]).is_ok());
        assert!(render_probe_results(&[]).is_ok());
        let err = render_probe_results(&[ok(), unsupported(), hard()]).unwrap_err();
        assert!(err.to_string().contains("connection failed"), "{err}");
    }
}
