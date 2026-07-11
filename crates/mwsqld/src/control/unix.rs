//! Unix control transport: a Unix-domain socket plus the `SO_PEERCRED`/
//! `getpeereid` + `getpwuid`/`getgrnam` resolution that turns a connection into
//! a [`PeerIdentity`] and an [`AuthDecision`].
//!
//! Socket security is layered: the socket file is `chmod 0660`, group-owned by
//! `middlewhere-admins`, AND every connection is re-checked with peer
//! credentials (the filesystem ACL is a first gate, not the only one). If the
//! admins group does not exist yet the socket is tightened to owner-only rather
//! than left open — fail safe.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tracing::{info, warn};

use super::peercred::{authorize_unix, AuthDecision, GroupInfo, PeerIdentity, UnixPeer};
use super::{handle_conn, inflight_limiter, ADMIN_GROUP, SERVICE_NAME};
use crate::Daemon;

pub(crate) async fn serve_loop(
    daemon: Arc<Daemon>,
    shutdown: &mut broadcast::Receiver<()>,
) -> Result<()> {
    let path = socket_path(&daemon.state_dir, SERVICE_NAME);
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
                        let (decision, peer) = resolve_peer(&stream);
                        handle_conn(daemon, stream, decision, peer).await;
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

/// Prefer the runtime dir the installer provisions; fall back to the state dir
/// (which the daemon already owns) so the control channel works even before the
/// installer lands the `/run` dir.
fn socket_path(state_dir: &Path, svc: &str) -> PathBuf {
    let run = Path::new("/run/middlewhere");
    if run.is_dir() && dir_is_writable(run) {
        run.join(format!("{svc}.sock"))
    } else {
        state_dir.join("control.sock")
    }
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

fn set_mode(path: &Path, mode: u32) {
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        warn!(err = %e, mode = format!("{mode:o}"), "chmod control socket failed");
    }
}

fn cpath(path: &Path) -> Option<std::ffi::CString> {
    std::ffi::CString::new(path.as_os_str().as_bytes()).ok()
}

/// Resolve the connecting peer and decide. FAIL-CLOSED: any resolution error
/// yields `Deny` with a best-effort [`PeerIdentity`] for the audit record.
fn resolve_peer(stream: &UnixStream) -> (AuthDecision, PeerIdentity) {
    let fd = stream.as_raw_fd();
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
