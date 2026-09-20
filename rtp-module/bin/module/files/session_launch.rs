use std::env;
use std::ffi::c_void;
use std::path::PathBuf;
use windows::core::{w, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, LookupPrivilegeValueW, SecurityIdentification,
    TokenPrimary, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ALL_ACCESS, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSActive, WTSDisconnected, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSGetActiveConsoleSessionId, WTSQueryUserToken, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows::Win32::UI::Shell::GetUserProfileDirectoryW;
use crate::files::util::{log_line, self_dir};

fn log(msg: &str) {
    log_line(&self_dir().join("rtp_logs"), msg);
}

fn enable_tcb_privilege() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut luid = LUID::default();
        if LookupPrivilegeValueW(None, w!("SeTcbPrivilege"), &mut luid).is_err() {
            let _ = CloseHandle(token);
            return false;
        }
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let ok = AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None).is_ok();
        let _ = CloseHandle(token);
        ok
    }
}

fn notifier_path() -> Option<PathBuf> {
    let exe = env::current_exe().ok()?;
    let path = exe.parent()?.join("axnotify.exe");
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

pub fn active_console_session() -> Option<u32> {
    let id = unsafe { WTSGetActiveConsoleSessionId() };
    if id == 0xFFFFFFFF {
        None
    } else {
        Some(id)
    }
}

pub fn session_of_pid(pid: u32) -> Option<u32> {
    let mut session_id = 0u32;
    unsafe {
        if ProcessIdToSessionId(pid, &mut session_id).is_err() {
            return None;
        }
    }
    Some(session_id)
}

pub fn logged_on_sessions() -> Vec<u32> {
    let mut out = Vec::new();
    unsafe {
        let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        if WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut info, &mut count).is_err() {
            return out;
        }
        for i in 0..count as usize {
            let session = &*info.add(i);
            if session.SessionId != 0 && (session.State == WTSActive || session.State == WTSDisconnected) {
                out.push(session.SessionId);
            }
        }
        WTSFreeMemory(info as *mut c_void);
    }
    out
}

pub fn profile_dir_for_session(session_id: u32) -> Option<PathBuf> {
    if !enable_tcb_privilege() {
        return None;
    }
    unsafe {
        let mut user_token = HANDLE::default();
        if WTSQueryUserToken(session_id, &mut user_token).is_err() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = GetUserProfileDirectoryW(user_token, PWSTR(buf.as_mut_ptr()), &mut size).is_ok();
        let _ = CloseHandle(user_token);
        if !ok {
            return None;
        }
        let len = buf.iter().position(|&c| c == 0).unwrap_or(0);
        if len == 0 {
            return None;
        }
        Some(PathBuf::from(String::from_utf16_lossy(&buf[..len])))
    }
}

pub fn launch_notifier(session_id: u32) {
    let Some(path) = notifier_path() else {
        log(&format!("notifier launch skipped for session {}: axnotify.exe not found next to the service", session_id));
        return;
    };
    if !enable_tcb_privilege() {
        log("notifier launch failed: could not enable SeTcbPrivilege");
        return;
    }
    unsafe {
        let mut user_token = HANDLE::default();
        if let Err(e) = WTSQueryUserToken(session_id, &mut user_token) {
            log(&format!("notifier launch skipped for session {}: no user token ({:?})", session_id, e));
            return;
        }

        let mut primary_token = HANDLE::default();
        let duplicated = DuplicateTokenEx(
            user_token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityIdentification,
            TokenPrimary,
            &mut primary_token,
        )
        .is_ok();
        let _ = CloseHandle(user_token);
        if !duplicated {
            log(&format!("notifier launch failed for session {}: token duplication failed", session_id));
            return;
        }

        let mut env_block: *mut c_void = std::ptr::null_mut();
        let _ = CreateEnvironmentBlock(&mut env_block, primary_token, false);

        let mut cmdline: Vec<u16> = format!("\"{}\"", path.display())
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut startup_info = STARTUPINFOW::default();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut process_info = PROCESS_INFORMATION::default();

        let created = CreateProcessAsUserW(
            primary_token,
            None,
            PWSTR(cmdline.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            Some(env_block),
            None,
            &startup_info,
            &mut process_info,
        );
        match created {
            Ok(_) => log(&format!("notifier started in session {}", session_id)),
            Err(e) => log(&format!("notifier launch failed in session {} for {}: {:?}", session_id, path.display(), e)),
        }

        if !env_block.is_null() {
            let _ = DestroyEnvironmentBlock(env_block);
        }
        if !process_info.hProcess.is_invalid() {
            let _ = CloseHandle(process_info.hProcess);
        }
        if !process_info.hThread.is_invalid() {
            let _ = CloseHandle(process_info.hThread);
        }
        let _ = CloseHandle(primary_token);
    }
}

pub fn launch_notifier_active_session() {
    if let Some(session_id) = active_console_session() {
        launch_notifier(session_id);
    }
}
