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

/// Resolve the access mode from the two flags. `--user` is always direct (a
/// per-user deployment has no service); `--offline` forces direct even in
/// service mode; otherwise service mode goes through the channel.
pub fn decide_mode(user: bool, offline: bool) -> Mode {
    if user || offline {
        Mode::Direct
    } else {
        Mode::Channel
    }
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
/// input plus the already-resolved auth secret (prompted/read locally). Parses
/// the first pinned fingerprint, mirroring the offline `ops::add_bastion`.
pub fn bastion_dto(input: &ops::BastionInput, auth: BastionAuthInput) -> Result<BastionInputDto> {
    let fingerprint = input
        .fingerprints
        .first()
        .map(|s| ops::parse_fingerprint(s))
        .transpose()?;
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

/// Call the daemon, turning a not-reachable error into a clear "start the
/// service / use --offline" message. Shared by the router and the wizard, which
/// have both already committed to the channel.
pub fn checked_call(state_dir: &Path, req: &Request) -> Result<Response> {
    match call(CONTROL_SERVICE_NAME, state_dir, req) {
        Ok(r) => Ok(r),
        Err(CallError::Unreachable(ep)) => bail!(
            "the middleWHERE service isn't reachable at {ep}; start it, or run \
             {} to edit the sealed config directly.",
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

/// The daemon prefers `/run/middlewhere/<svc>.sock`, falling back to
/// `<state_dir>/control.sock`. Dial the run-dir socket when it exists, else the
/// state-dir fallback — mirroring the daemon's own choice.
#[cfg(unix)]
fn unix_socket_path(state_dir: &Path, svc: &str) -> std::path::PathBuf {
    let run = Path::new("/run/middlewhere").join(format!("{svc}.sock"));
    if run.exists() {
        run
    } else {
        state_dir.join("control.sock")
    }
}

#[cfg(windows)]
fn call_windows(service_name: &str, req: &Request) -> Result<Response, CallError> {
    use std::fs::OpenOptions;

    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_PIPE_BUSY: i32 = 231;

    let pipe = format!(r"\\.\pipe\middlewhere-{service_name}-control");
    // A busy pipe means the daemon is up but every instance is momentarily in
    // use; back off briefly and retry rather than failing the command.
    let mut file = None;
    for attempt in 0..10 {
        match OpenOptions::new().read(true).write(true).open(&pipe) {
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
    fn decide_mode_channel_only_for_online_service() {
        assert_eq!(decide_mode(false, false), Mode::Channel);
        assert_eq!(decide_mode(true, false), Mode::Direct); // --user
        assert_eq!(decide_mode(false, true), Mode::Direct); // --offline
        assert_eq!(decide_mode(true, true), Mode::Direct);
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
