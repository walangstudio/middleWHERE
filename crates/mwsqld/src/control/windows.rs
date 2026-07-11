//! Windows control transport: a named pipe secured two ways —
//!
//! 1. an explicit DACL granting only `middlewhere-admins`, `BUILTIN\
//!    Administrators`, and `LocalSystem` (everyone else denied by omission), and
//! 2. per-connection authorization by impersonating the pipe client and testing
//!    its token membership with `CheckTokenMembership` (race-free — no
//!    pid->OpenProcess round trip that a pid-reuse attacker could exploit).
//!
//! `RevertToSelf` is guaranteed on EVERY path (success, deny, error, panic) by a
//! Drop guard, and impersonation runs inside `block_in_place` so it never
//! crosses a thread boundary while the thread token is swapped.

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::broadcast;
use tracing::{info, warn};

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, LookupAccountNameW,
    LookupAccountSidW, RevertToSelf, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

use super::peercred::{authorize_windows, AuthDecision, PeerIdentity};
use super::{handle_conn, inflight_limiter, ADMIN_GROUP, SERVICE_NAME};
use crate::Daemon;

/// SDDL revision (SDDL_REVISION_1).
const SDDL_REVISION_1: u32 = 1;
/// WELL_KNOWN_SID_TYPE::WinBuiltinAdministratorsSid.
const WIN_BUILTIN_ADMINISTRATORS_SID: i32 = 26;
/// Max byte length of a SID (SECURITY_MAX_SID_SIZE).
const SECURITY_MAX_SID_SIZE: usize = 68;

pub(crate) async fn serve_loop(
    daemon: Arc<Daemon>,
    shutdown: &mut broadcast::Receiver<()>,
) -> Result<()> {
    let pipe_name = format!(r"\\.\pipe\middlewhere-{SERVICE_NAME}-control");
    // Resolve the admins group SID once (raw bytes for CheckTokenMembership,
    // string form for the DACL). Missing group -> None: the DACL still grants
    // BUILTIN\Administrators + SY (fail safe, not open), and per-conn authz
    // falls back to the BUILTIN\Administrators check.
    let admins_sid = resolve_group_sid(ADMIN_GROUP);
    if admins_sid.is_none() {
        warn!(
            group = ADMIN_GROUP,
            "group SID not resolvable; control pipe granted to BUILTIN\\Administrators only"
        );
    }

    let sem = inflight_limiter();
    // The FIRST instance failing is fatal to the channel (logged by the caller);
    // in-loop failures below are non-fatal (log + continue) so one transient
    // error can't kill the control channel for the daemon's lifetime.
    let mut server = create_instance(&pipe_name, true, &admins_sid)?;
    info!(pipe = %pipe_name, "control channel listening");

    loop {
        tokio::select! {
            biased;
            _ = shutdown.recv() => break,
            res = server.connect() => match res {
                Ok(()) => match create_instance(&pipe_name, false, &admins_sid) {
                    Ok(next) => {
                        let permit = match Arc::clone(&sem).acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => break,
                        };
                        let conn = std::mem::replace(&mut server, next);
                        let daemon = Arc::clone(&daemon);
                        let admins_sid = admins_sid.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            // Carry the pipe handle into the resolver (see
                            // PipeHandle). The resolver runs AFTER handle_conn has
                            // read the client's frames, so impersonation succeeds;
                            // block_in_place keeps the impersonation thread-local
                            // with no await between impersonate and revert.
                            let handle = PipeHandle(conn.as_raw_handle());
                            handle_conn(daemon, conn, move || {
                                // Rebind the whole PipeHandle: edition-2021 disjoint
                                // capture would otherwise grab the !Send raw field
                                // and make the task future !Send.
                                let handle = handle;
                                tokio::task::block_in_place(|| resolve_peer(handle.0, &admins_sid))
                            })
                            .await;
                        });
                    }
                    Err(e) => {
                        // No replacement listener: don't tear down the channel.
                        // Drop this client, reuse the current instance as the
                        // next listener after a short backoff.
                        warn!(
                            err = %format!("{e:#}"),
                            "could not create replacement control pipe instance; dropping connection"
                        );
                        let _ = server.disconnect();
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                },
                Err(e) => {
                    warn!(err = %e, "named pipe connect failed");
                    match create_instance(&pipe_name, false, &admins_sid) {
                        Ok(s) => server = s,
                        Err(e2) => {
                            warn!(
                                err = %format!("{e2:#}"),
                                "could not recreate control pipe instance; backing off"
                            );
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// A raw pipe `HANDLE` is `*mut c_void` (`!Send`), but a Windows handle is valid
/// process-wide; carrying it into the connection task for the thread-local
/// impersonation (done under `block_in_place`) is sound.
struct PipeHandle(HANDLE);
// SAFETY: the handle references a kernel pipe object usable from any thread in
// the process; we only read it, under block_in_place, on one worker thread.
unsafe impl Send for PipeHandle {}

/// Create one pipe instance with the admins-only DACL. `first` sets
/// `first_pipe_instance` so a squatter cannot pre-create the pipe name and
/// intercept clients.
fn create_instance(
    pipe_name: &str,
    first: bool,
    admins_sid: &Option<Vec<u8>>,
) -> Result<NamedPipeServer> {
    let sddl = build_sddl(admins_sid);
    let wsddl = wide(&sddl);
    let mut psd: *mut c_void = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wsddl.as_ptr(),
            SDDL_REVISION_1,
            &mut psd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(anyhow!(
            "build control-pipe security descriptor from SDDL {sddl:?}: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd,
        bInheritHandle: 0,
    };
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first);
    let server = unsafe {
        opts.create_with_security_attributes_raw(
            pipe_name,
            &mut sa as *mut SECURITY_ATTRIBUTES as *mut c_void,
        )
    };
    // The pipe object copied the descriptor at creation; free our copy.
    unsafe { LocalFree(psd as HLOCAL) };
    server.with_context(|| format!("create control pipe instance {pipe_name}"))
}

/// `D:` DACL granting GENERIC_ALL to the admins group (when resolvable),
/// `BUILTIN\Administrators` (BA), and `LocalSystem` (SY). No other ACEs and no
/// inheritance, so every other principal is denied by omission.
fn build_sddl(admins_sid: &Option<Vec<u8>>) -> String {
    let mut sddl = String::from("D:");
    if let Some(sid) = admins_sid {
        if let Some(s) = sid_to_string(sid.as_ptr() as *const c_void) {
            sddl.push_str(&format!("(A;;GA;;;{s})"));
        }
    }
    sddl.push_str("(A;;GA;;;BA)(A;;GA;;;SY)");
    sddl
}

/// Resolve the peer's token membership. FAIL-CLOSED: an impersonation or token
/// error yields `Deny` with a best-effort [`PeerIdentity`]. `RevertToSelf` runs
/// on every exit via the Drop guard. `handle` is the pipe-server handle; the
/// caller has already read the client's frames, so impersonation succeeds.
fn resolve_peer(handle: HANDLE, admins_sid: &Option<Vec<u8>>) -> (AuthDecision, PeerIdentity) {
    if unsafe { ImpersonateNamedPipeClient(handle) } == 0 {
        return (
            AuthDecision::Deny(format!(
                "could not impersonate pipe client: {}",
                std::io::Error::last_os_error()
            )),
            PeerIdentity::default(),
        );
    }
    // From here on, RevertToSelf is guaranteed even on early return or panic.
    let _revert = RevertGuard;

    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        return (
            AuthDecision::Deny(format!(
                "could not open pipe-client thread token: {}",
                std::io::Error::last_os_error()
            )),
            PeerIdentity::default(),
        );
    }

    let peer = PeerIdentity {
        uid: None,
        gid: None,
        user: token_user_display(token).unwrap_or_else(|| "<unknown>".to_string()),
    };

    let is_admins_member = admins_sid
        .as_ref()
        .map(|sid| check_membership(token, sid.as_ptr() as *const c_void))
        .unwrap_or(false);
    let is_builtin_admin = well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)
        .map(|sid| check_membership(token, sid.as_ptr() as *const c_void))
        .unwrap_or(false);

    unsafe { CloseHandle(token) };
    let decision = authorize_windows(is_admins_member, is_builtin_admin);
    (decision, peer)
}

/// RAII: `RevertToSelf` on drop, so the thread token is always restored no
/// matter how `resolve_peer` exits.
struct RevertGuard;
impl Drop for RevertGuard {
    fn drop(&mut self) {
        unsafe { RevertToSelf() };
    }
}

/// True iff `token` is a member of `sid`. FAIL-CLOSED: a failed check is treated
/// as "not a member".
fn check_membership(token: HANDLE, sid: *const c_void) -> bool {
    let mut is_member: i32 = 0;
    let ok = unsafe { CheckTokenMembership(token, sid as *mut c_void, &mut is_member) };
    ok != 0 && is_member != 0
}

/// Best-effort `DOMAIN\name` (or string SID) of the token's user, for the audit
/// record only — never used in the authz decision.
fn token_user_display(token: HANDLE) -> Option<String> {
    let mut needed: u32 = 0;
    // First call sizes the buffer; it "fails" with ERROR_INSUFFICIENT_BUFFER.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return None;
    }
    let tu = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid = tu.User.Sid;
    account_name(sid).or_else(|| sid_to_string(sid as *const c_void))
}

/// `DOMAIN\name` for a SID via `LookupAccountSidW`, or `None` if it can't be
/// resolved (a local account with no domain, a deleted SID, etc.).
fn account_name(sid: *mut c_void) -> Option<String> {
    let mut name_len: u32 = 0;
    let mut dom_len: u32 = 0;
    let mut sid_use: i32 = 0;
    unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid,
            std::ptr::null_mut(),
            &mut name_len,
            std::ptr::null_mut(),
            &mut dom_len,
            &mut sid_use,
        )
    };
    if name_len == 0 {
        return None;
    }
    let mut name = vec![0u16; name_len as usize];
    let mut dom = vec![0u16; dom_len as usize];
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            dom.as_mut_ptr(),
            &mut dom_len,
            &mut sid_use,
        )
    };
    if ok == 0 {
        return None;
    }
    let name = wide_to_string(&name);
    let dom = wide_to_string(&dom);
    if dom.is_empty() {
        Some(name)
    } else {
        Some(format!("{dom}\\{name}"))
    }
}

/// Resolve a group/account name to its raw SID bytes via `LookupAccountNameW`.
fn resolve_group_sid(name: &str) -> Option<Vec<u8>> {
    let wname = wide(name);
    let mut sid_len: u32 = 0;
    let mut dom_len: u32 = 0;
    let mut sid_use: i32 = 0;
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            wname.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_len,
            std::ptr::null_mut(),
            &mut dom_len,
            &mut sid_use,
        )
    };
    if sid_len == 0 {
        return None;
    }
    let mut sid = vec![0u8; sid_len as usize];
    let mut dom = vec![0u16; dom_len as usize];
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            wname.as_ptr(),
            sid.as_mut_ptr() as *mut c_void,
            &mut sid_len,
            dom.as_mut_ptr(),
            &mut dom_len,
            &mut sid_use,
        )
    };
    if ok == 0 {
        return None;
    }
    Some(sid)
}

fn well_known_sid(kind: i32) -> Option<Vec<u8>> {
    let mut size: u32 = SECURITY_MAX_SID_SIZE as u32;
    let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE];
    let ok = unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            sid.as_mut_ptr() as *mut c_void,
            &mut size,
        )
    };
    if ok == 0 {
        return None;
    }
    sid.truncate(size as usize);
    Some(sid)
}

fn sid_to_string(sid: *const c_void) -> Option<String> {
    let mut pstr: *mut u16 = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid as *mut c_void, &mut pstr) } == 0 {
        return None;
    }
    let s = unsafe { wide_ptr_to_string(pstr) };
    unsafe { LocalFree(pstr as HLOCAL) };
    Some(s)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Decode a `Vec<u16>` up to its first NUL.
fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

/// # Safety
/// `p` must be a valid, NUL-terminated wide string.
unsafe fn wide_ptr_to_string(p: *const u16) -> String {
    let mut len = 0isize;
    while *p.offset(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(p, len as usize);
    String::from_utf16_lossy(slice)
}
