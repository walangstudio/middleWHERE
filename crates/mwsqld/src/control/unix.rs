//! Unix control transport: a Unix-domain socket plus the `SO_PEERCRED`/
//! `getpeereid` + `getpwuid`/`getgrnam` resolution that turns a connection into
//! a [`PeerIdentity`] and an [`AuthDecision`].
//!
//! Socket security is layered: the socket file is `chmod 0660`, group-owned by
//! `middlewhere-admins`, AND every connection is re-checked with peer
//! credentials (the filesystem ACL is a first gate, not the only one). If the
//! admins group does not exist yet the socket is tightened to owner-only rather
//! than left open — fail safe.
//!
//! The shared runtime dir (`/run/middlewhere` on Linux, `/var/run/middlewhere`
//! on macOS) is created owner-only by the service manager, so its group must be
//! reopened to `middlewhere-admins` at `0710` too — otherwise a non-service
//! admin is "other" on the dir (perms 0) and gets EACCES before ever reaching
//! the socket. Same fail-safe posture: on any error the dir is left owner-only.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use tracing::{info, warn};

use super::peercred::{authorize_unix, AuthDecision, GroupInfo, PeerIdentity, UnixPeer};
use super::{handle_conn, inflight_limiter, ADMIN_GROUP, SERVICE_NAME};
use crate::Daemon;

pub(crate) async fn serve_loop(
    daemon: Arc<Daemon>,
    shutdown: &mut broadcast::Receiver<()>,
) -> Result<()> {
    let (path, runtime_dir) = resolve_socket(&daemon.state_dir, SERVICE_NAME);
    // When the socket lives in the shared runtime dir, reopen that dir's group
    // traversal to the admins group BEFORE binding, so a non-service admin can
    // reach the socket. The state-dir fallback needs no such step (it is
    // owner-only by design and holds the sealed config).
    if let Some(dir) = &runtime_dir {
        secure_runtime_dir(dir);
    }
    let listener = bind_listener(&path)?;
    info!(socket = %path.display(), "control channel listening");

    let sem = inflight_limiter();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.recv() => break,
            accept = listener.accept() => match accept {
                Ok((stream, _addr)) => {
                    // Bound in-flight handlers: a local principal that can reach
                    // the socket but fails authz cannot exhaust the daemon.
                    let permit = match Arc::clone(&sem).acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    let daemon = Arc::clone(&daemon);
                    tokio::spawn(async move {
                        let _permit = permit;
                        // Capture the fd; `stream` owns it and stays alive inside
                        // handle_conn, so the resolver reads valid creds. On Unix
                        // SO_PEERCRED needs no prior client write, but resolving
                        // after the read keeps one code path with Windows.
                        let fd = stream.as_raw_fd();
                        handle_conn(daemon, stream, move || resolve_peer(fd)).await;
                    });
                }
                Err(e) => {
                    warn!(err = %e, "control accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }
    // Tidy up so the next start's bind guard sees no stale socket.
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// The platform runtime dir for the control socket, from mw-core's single source
/// of truth (shared with the CLI).
fn runtime_dir_candidate() -> Option<PathBuf> {
    mw_core::control::runtime_dir_for(std::env::consts::OS)
}

/// Pick the socket path and, when it lives in the shared runtime dir, that dir
/// (so the caller can secure its group traversal). The `<state_dir>/control.sock`
/// fallback returns `None` for the parent on purpose: the state dir is already
/// `0700` owner-only and holds `config.sealed` — it must NEVER be widened to
/// `0710`. Pure, so both branches are unit-tested.
fn choose_socket(
    runtime: Option<&Path>,
    runtime_usable: bool,
    state_dir: &Path,
    svc: &str,
) -> (PathBuf, Option<PathBuf>) {
    match runtime {
        Some(dir) if runtime_usable => (dir.join(format!("{svc}.sock")), Some(dir.to_path_buf())),
        _ => (state_dir.join("control.sock"), None),
    }
}

/// Resolve the socket path against the live filesystem (runtime dir existence +
/// writability), returning the parent runtime dir to secure when it is used.
fn resolve_socket(state_dir: &Path, svc: &str) -> (PathBuf, Option<PathBuf>) {
    let candidate = runtime_dir_candidate();
    let usable = candidate
        .as_deref()
        .map(|d| d.is_dir() && dir_is_writable(d))
        .unwrap_or(false);
    choose_socket(candidate.as_deref(), usable, state_dir, svc)
}

fn dir_is_writable(dir: &Path) -> bool {
    match std::ffi::CString::new(dir.as_os_str().as_bytes()) {
        Ok(c) => unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 },
        Err(_) => false,
    }
}

fn bind_listener(path: &Path) -> Result<UnixListener> {
    // lstat (NOT stat): never follow a symlink/reparse at the socket path, and
    // unlink ONLY a genuine stale socket — anything else is refused so a planted
    // symlink can't redirect the bind.
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_socket() => {
            std::fs::remove_file(path)
                .with_context(|| format!("unlink stale control socket {}", path.display()))?;
        }
        Ok(_) => bail!(
            "control socket path {} exists and is not a socket; refusing to replace it",
            path.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("lstat {}", path.display())),
    }

    let listener = UnixListener::bind(path)
        .with_context(|| format!("bind control socket {}", path.display()))?;
    apply_socket_perms(path);
    Ok(listener)
}

/// Group-own the socket to `middlewhere-admins` at 0660, or tighten to
/// owner-only if that group does not exist yet (fail safe, never group/world
/// open). Peer-credential authz still runs per connection regardless.
fn apply_socket_perms(path: &Path) {
    match resolve_group(ADMIN_GROUP) {
        Some(g) => {
            set_mode(path, 0o660);
            if let Some(cpath) = cpath(path) {
                // uid_t::MAX == (uid_t)-1 == "leave owner unchanged".
                let rc = unsafe { libc::chown(cpath.as_ptr(), libc::uid_t::MAX, g.gid) };
                if rc != 0 {
                    warn!(
                        err = %std::io::Error::last_os_error(),
                        "chown control socket to {ADMIN_GROUP} failed; tightening to owner-only"
                    );
                    set_mode(path, 0o600);
                }
            }
        }
        None => {
            warn!(
                group = ADMIN_GROUP,
                "group not found; control socket left owner-only until it exists"
            );
            set_mode(path, 0o600);
        }
    }
}

/// Make the shared runtime dir traversable by `middlewhere-admins`: chgrp it to
/// the admins gid and chmod `0710` (owner rwx, group `--x` traverse-only, other
/// none). The service manager creates the dir owner-only, so a non-service
/// admins member is "other" and gets EACCES traversing it — the socket's own
/// `0660` group perms are then unreachable. This reopens traversal to admins
/// ONLY; non-admins stay denied at the dir.
///
/// No root needed: the daemon's euid owns the dir (systemd `RuntimeDirectory` /
/// the macOS setup) AND the service user is itself a member of the admins group,
/// so a non-root chgrp to that group is permitted.
///
/// FAIL-SAFE: any error (group unresolvable, not a real directory, chgrp/chmod
/// fails) leaves the dir owner-only — never widened. An lstat guard + `lchown`
/// mean a symlink/reparse swapped in at the dir path is never followed.
fn secure_runtime_dir(dir: &Path) {
    // lstat (NOT stat): never chgrp/chmod through a symlink/reparse at the dir.
    match std::fs::symlink_metadata(dir) {
        Ok(md) if md.file_type().is_dir() => {}
        Ok(_) => {
            warn!(
                dir = %dir.display(),
                "runtime dir path is not a directory; leaving it owner-only"
            );
            return;
        }
        Err(e) => {
            warn!(err = %e, dir = %dir.display(), "cannot stat runtime dir; leaving it owner-only");
            return;
        }
    }
    let Some(g) = resolve_group(ADMIN_GROUP) else {
        warn!(
            group = ADMIN_GROUP, dir = %dir.display(),
            "group not found; runtime dir left owner-only until it exists"
        );
        return;
    };
    let Some(cdir) = cpath(dir) else { return };
    // `lchown` (not chown): if the final component were swapped for a symlink
    // after the lstat, lchown changes the link, not its target. `uid_t::MAX` ==
    // leave the owner unchanged.
    if unsafe { libc::lchown(cdir.as_ptr(), libc::uid_t::MAX, g.gid) } != 0 {
        warn!(
            err = %std::io::Error::last_os_error(), dir = %dir.display(),
            "chgrp runtime dir to {ADMIN_GROUP} failed; leaving it owner-only"
        );
        return;
    }
    // 0710: admins traverse (--x), nobody else. Never group/world readable.
    set_mode(dir, 0o710);
}

fn set_mode(path: &Path, mode: u32) {
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        warn!(err = %e, path = %path.display(), mode = format!("{mode:o}"), "chmod failed");
    }
}

fn cpath(path: &Path) -> Option<std::ffi::CString> {
    std::ffi::CString::new(path.as_os_str().as_bytes()).ok()
}

/// Resolve the connecting peer and decide. FAIL-CLOSED: any resolution error
/// yields `Deny` with a best-effort [`PeerIdentity`] for the audit record.
fn resolve_peer(fd: RawFd) -> (AuthDecision, PeerIdentity) {
    let (uid, gid) = match peer_creds(fd) {
        Some(c) => c,
        None => {
            return (
                AuthDecision::Deny("could not read peer credentials".into()),
                PeerIdentity::default(),
            );
        }
    };
    let mut peer = PeerIdentity {
        uid: Some(uid),
        gid: Some(gid),
        user: String::new(),
    };
    let (user, primary_gid) = match resolve_user(uid) {
        Some(u) => u,
        None => {
            return (
                AuthDecision::Deny(format!("could not resolve uid {uid} to a user")),
                peer,
            );
        }
    };
    peer.user = user.clone();
    let admins = match resolve_group(ADMIN_GROUP) {
        Some(g) => g,
        None => {
            return (
                AuthDecision::Deny(format!("group {ADMIN_GROUP} not found; refusing")),
                peer,
            );
        }
    };
    let decision = authorize_unix(
        &UnixPeer {
            uid,
            primary_gid,
            user,
        },
        &admins,
    );
    (decision, peer)
}

/// `(uid, gid)` of the process on the other end of the socket.
#[cfg(target_os = "linux")]
fn peer_creds(fd: RawFd) -> Option<(u32, u32)> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    Some((cred.uid, cred.gid))
}

#[cfg(target_os = "macos")]
fn peer_creds(fd: RawFd) -> Option<(u32, u32)> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if rc != 0 {
        return None;
    }
    Some((uid, gid))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peer_creds(_fd: RawFd) -> Option<(u32, u32)> {
    // Fail-closed on a unix without a known peer-cred syscall.
    None
}

/// Resolve a uid to `(username, primary_gid)` via the reentrant `getpwuid_r`
/// (thread-safe, unlike `getpwuid`'s static buffer — several handlers may run
/// concurrently).
fn resolve_user(uid: u32) -> Option<(String, u32)> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    loop {
        let rc =
            unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
        if rc == 0 {
            break;
        }
        if rc == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        return None;
    }
    if result.is_null() {
        return None;
    }
    let name = unsafe { cstr_to_string(pwd.pw_name)? };
    Some((name, pwd.pw_gid))
}

/// Resolve a group name to its gid + supplementary member usernames via the
/// reentrant `getgrnam_r`.
fn resolve_group(name: &str) -> Option<GroupInfo> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::group = std::ptr::null_mut();
    loop {
        let rc = unsafe {
            libc::getgrnam_r(
                cname.as_ptr(),
                &mut grp,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == 0 {
            break;
        }
        if rc == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        return None;
    }
    if result.is_null() {
        return None;
    }
    let mut members = Vec::new();
    unsafe {
        let mut p = grp.gr_mem;
        if !p.is_null() {
            while !(*p).is_null() {
                if let Some(s) = cstr_to_string(*p) {
                    members.push(s);
                }
                p = p.add(1);
            }
        }
    }
    Some(GroupInfo {
        gid: grp.gr_gid,
        members,
    })
}

/// # Safety
/// `p` must be null or a valid, NUL-terminated C string for the read.
unsafe fn cstr_to_string(p: *const libc::c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    Some(std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usable_runtime_dir_is_preferred_and_flagged_for_securing() {
        let rt = PathBuf::from("/run/middlewhere");
        let sd = Path::new("/var/lib/middlewhere");
        let (path, parent) = choose_socket(Some(&rt), true, sd, "mwsqld");
        assert_eq!(path, PathBuf::from("/run/middlewhere/mwsqld.sock"));
        // The parent is returned so the caller reopens its group traversal.
        assert_eq!(parent.as_deref(), Some(rt.as_path()));
    }

    #[test]
    fn unusable_runtime_dir_falls_back_without_widening_parent() {
        let rt = PathBuf::from("/run/middlewhere");
        let sd = Path::new("/var/lib/middlewhere");
        // Present but not writable/usable -> state-dir socket, and NO parent to
        // widen (the 0700 state dir must never become 0710).
        let (path, parent) = choose_socket(Some(&rt), false, sd, "mwsqld");
        assert_eq!(path, PathBuf::from("/var/lib/middlewhere/control.sock"));
        assert!(parent.is_none());
    }

    #[test]
    fn no_runtime_dir_falls_back_without_widening_parent() {
        let sd = Path::new("/var/lib/middlewhere");
        let (path, parent) = choose_socket(None, false, sd, "mwsqld");
        assert_eq!(path, PathBuf::from("/var/lib/middlewhere/control.sock"));
        assert!(parent.is_none());
    }
}
