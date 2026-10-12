//! Windows account SIDs, shared by the daemon's control-pipe DACL and the
//! CLI's pipe-owner check.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, PSID, TOKEN_QUERY, TOKEN_USER};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// `S-1-5-...` form of a SID.
///
/// # Safety
/// `sid` must point to a valid SID.
pub unsafe fn sid_string(sid: PSID) -> Option<String> {
    let mut s: *mut u16 = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 {
        return None;
    }
    let len = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(s, len) });
    unsafe { LocalFree(s as HLOCAL) };
    Some(text)
}

/// The string SID of the account this process runs as.
pub fn process_user_sid() -> Option<String> {
    let mut tok: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) } == 0 {
        return None;
    }
    // TOKEN_USER plus its SID fits comfortably; u64 keeps the buffer aligned.
    let mut buf = [0u64; 16];
    let mut n = 0;
    let ok = unsafe {
        GetTokenInformation(
            tok,
            TokenUser,
            buf.as_mut_ptr() as *mut c_void,
            std::mem::size_of_val(&buf) as u32,
            &mut n,
        )
    };
    unsafe { CloseHandle(tok) };
    if ok == 0 {
        return None;
    }
    // SAFETY: GetTokenInformation filled buf with a TOKEN_USER whose SID
    // lives in the same buffer.
    unsafe { sid_string((*(buf.as_ptr() as *const TOKEN_USER)).User.Sid) }
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_user_sid_is_a_sid() {
        let sid = super::process_user_sid().expect("own SID");
        assert!(sid.starts_with("S-1-"), "{sid}");
    }
}
