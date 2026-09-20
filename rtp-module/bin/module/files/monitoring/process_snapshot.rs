use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use serde_json::json;
use windows::core::PWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE};
use crate::files::detection::engine::{derive_label, evaluate_path, is_malicious, signature_names};
use crate::files::detection::store::write_detection;
use crate::files::pipe_notify::broadcaster;
use crate::files::quarantine::{is_excluded, quarantine_path};
use crate::files::session_launch::{active_console_session, session_of_pid};
use crate::files::util::{log_line, now_ms};

pub fn terminate_pid(pid: u32) -> bool {
    unsafe {
        match OpenProcess(PROCESS_TERMINATE, false, pid) {
            Ok(handle) => {
                let ok = TerminateProcess(handle, 1).is_ok();
                let _ = CloseHandle(handle);
                ok
            }
            Err(_) => false,
        }
    }
}

pub fn get_full_exe_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut size);
        let _ = CloseHandle(handle);
        if ok.is_ok() {
            Some(String::from_utf16_lossy(&buf[..size as usize]))
        } else {
            None
        }
    }
}

pub fn snapshot_processes() -> HashMap<u32, (String, u32)> {
    let mut map = HashMap::new();
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return map,
        };
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szExeFile).trim_end_matches('\0').to_string();
                map.insert(entry.th32ProcessID, (name, entry.th32ParentProcessID));
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    map
}

pub fn should_track(name: &str, parent_name: &str) -> bool {
    let n = name.to_lowercase();
    if matches!(n.as_str(), "system" | "idle" | "registry" | "memory compression") {
        return false;
    }
    let p = parent_name.to_lowercase();
    if matches!(p.as_str(), "services.exe" | "svchost.exe" | "wininit.exe" | "smss.exe" | "csrss.exe" | "winlogon.exe" | "lsass.exe") {
        return false;
    }
    true
}

fn notify_session_for(pid: u32) -> Option<u32> {
    match session_of_pid(pid) {
        Some(session) if session != 0 => Some(session),
        _ => active_console_session(),
    }
}

pub fn handle_candidate(pid: u32, name: &str, exe: &str, source: &str, logs_dir: &Path) {
    if exe.is_empty() {
        return;
    }
    log_line(logs_dir, &format!("{}(pid={}) {} {}", source, pid, name, exe));
    if is_excluded(exe) {
        return;
    }
    let verdict = evaluate_path(exe);
    let bad = is_malicious(&verdict);
    if bad {
        let session = notify_session_for(pid);
        let stopped = terminate_pid(pid);
        let label = derive_label(&verdict, exe);
        let quarantine_id = quarantine_path(exe, Some(&label)).ok();
        let sig_names = signature_names(&verdict, exe);
        log_line(logs_dir, &format!("MALICIOUS source={} pid={} exe={} stopped={} quarantined={} verdict={}", source, pid, exe, stopped, quarantine_id.is_some(), verdict));
        let det = json!({
            "type": "rtp_detection",
            "ts": now_ms(),
            "pid": pid,
            "exe": exe,
            "source": source,
            "stopped": stopped,
            "quarantine_id": quarantine_id,
            "verdict": verdict,
            "name": name,
            "label": label,
            "threat_names": sig_names,
        });
        write_detection(logs_dir, &det);
        if let Some(session) = session {
            broadcaster().send_to_session(session, &det.to_string());
        }
    } else {
        log_line(logs_dir, &format!("ok source={} pid={} exe={} verdict={}", source, pid, exe, verdict));
    }
}

pub fn run_snapshot_loop(known: &mut HashMap<u32, (String, u32)>, logs_dir: &Path) {
    loop {
        std::thread::sleep(Duration::from_secs(5));
        let cur = snapshot_processes();
        for (pid, (name, ppid)) in cur.iter() {
            if known.contains_key(pid) {
                continue;
            }
            let parent_name = known.get(ppid).map(|(n, _)| n.clone()).unwrap_or_default();
            if should_track(name, &parent_name) {
                if let Some(exe) = get_full_exe_path(*pid) {
                    handle_candidate(*pid, name, &exe, "snapshot", logs_dir);
                }
            }
        }
        *known = cur;
    }
}