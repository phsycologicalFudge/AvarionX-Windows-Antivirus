use crate::files::quarantine::{quarantine_path, restore_id};
use std::ffi::c_void;
use std::io::{BufRead, BufReader};
use std::os::windows::io::FromRawHandle;
use std::time::Duration;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, ERROR_PIPE_CONNECTED};
use windows::Win32::Security::{
    InitializeSecurityDescriptor, RevertToSelf, SetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_INBOUND;
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, ImpersonateNamedPipeClient,
    PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};

const PIPE_NAME: PCWSTR = w!("\\\\.\\pipe\\AvarionXCommand");

struct Impersonation;

impl Drop for Impersonation {
    fn drop(&mut self) {
        unsafe {
            let _ = RevertToSelf();
        }
    }
}

fn impersonate(pipe: HANDLE) -> Option<Impersonation> {
    unsafe {
        if ImpersonateNamedPipeClient(pipe).is_err() {
            return None;
        }
    }
    Some(Impersonation)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn build_open_security_attributes(sd: &mut SECURITY_DESCRIPTOR) -> SECURITY_ATTRIBUTES {
    unsafe {
        let sd_ptr = PSECURITY_DESCRIPTOR(sd as *mut _ as *mut c_void);
        let _ = InitializeSecurityDescriptor(sd_ptr, 1);
        let _ = SetSecurityDescriptorDacl(sd_ptr, true, None, false);
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd_ptr.0,
            bInheritHandle: false.into(),
        }
    }
}

pub fn start_listener() {
    std::thread::spawn(accept_loop);
}

fn accept_loop() {
    loop {
        let mut sd = SECURITY_DESCRIPTOR::default();
        let sa = build_open_security_attributes(&mut sd);
        let handle = unsafe {
            CreateNamedPipeW(
                PIPE_NAME,
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                8,
                4096,
                4096,
                0,
                Some(&sa),
            )
        };
        if handle.is_invalid() {
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }
        let connect_result = unsafe { ConnectNamedPipe(handle, None) };
        let connected =
            connect_result.is_ok() || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        if !connected {
            unsafe {
                let _ = CloseHandle(handle);
            }
            continue;
        }
        let file = unsafe { std::fs::File::from_raw_handle(handle.0 as *mut c_void) };
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            let trimmed = line.trim();
            if let Some(path) = trimmed.strip_prefix("quarantine:") {
                if let Some(_as_caller) = impersonate(handle) {
                    let _ = quarantine_path(path, None);
                }
            } else if let Some(id) = trimmed.strip_prefix("restore:") {
                if valid_id(id) {
                    if let Some(_as_caller) = impersonate(handle) {
                        let _ = restore_id(id);
                    }
                }
            }
        }
        unsafe {
            let _ = DisconnectNamedPipe(handle);
        }
    }
}
