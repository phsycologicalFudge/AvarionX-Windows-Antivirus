use crate::{log_line, Detection, UserEvent};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::FromRawHandle;
use std::thread;
use std::time::Duration;
use tao::event_loop::EventLoopProxy;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;

const PIPE_NAME: PCWSTR = w!("\\\\.\\pipe\\AvarionXNotify");
const COMMAND_PIPE_NAME: PCWSTR = w!("\\\\.\\pipe\\AvarionXCommand");

pub fn send_command(cmd: &str) {
    unsafe {
        let _ = WaitNamedPipeW(COMMAND_PIPE_NAME, 2000);
    }
    let handle: windows::core::Result<HANDLE> = unsafe {
        CreateFileW(
            COMMAND_PIPE_NAME,
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            HANDLE::default(),
        )
    };
    if let Ok(handle) = handle {
        let mut file = unsafe { std::fs::File::from_raw_handle(handle.0 as *mut std::ffi::c_void) };
        let _ = file.write_all(cmd.as_bytes());
        let _ = file.write_all(b"\n");
    }
}

fn parse_detection(line: &str) -> Option<Detection> {
    let v: Value = serde_json::from_str(line).ok()?;
    let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let exe = v.get("exe").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let threat = v
        .get("threat_names")
        .and_then(|x| x.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Malicious".to_string());
    let quarantine_id = v
        .get("quarantine_id")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    Some(Detection {
        name,
        exe,
        threat,
        quarantine_id,
    })
}

fn connect_and_listen(proxy: &EventLoopProxy<UserEvent>) -> windows::core::Result<()> {
    unsafe {
        let _ = WaitNamedPipeW(PIPE_NAME, 5000);
    }
    let handle: HANDLE = unsafe {
        CreateFileW(
            PIPE_NAME,
            FILE_GENERIC_READ.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            HANDLE::default(),
        )?
    };
    log_line("connected to AvarionXNotify pipe");
    let file = unsafe { std::fs::File::from_raw_handle(handle.0 as *mut std::ffi::c_void) };
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        log_line(&format!("detection line: {}", trimmed));
        if let Some(det) = parse_detection(trimmed) {
            let _ = proxy.send_event(UserEvent::Detection(det));
        } else {
            log_line("failed to parse detection line");
        }
    }
    log_line("pipe closed, reconnecting");
    Ok(())
}

pub fn spawn_pipe_thread(proxy: EventLoopProxy<UserEvent>) {
    thread::spawn(move || loop {
        let _ = connect_and_listen(&proxy);
        thread::sleep(Duration::from_millis(300));
    });
}
