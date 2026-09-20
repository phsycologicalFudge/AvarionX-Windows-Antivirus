use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use notify::{RecursiveMode, Watcher};
use serde_json::json;
use crate::files::detection::engine::{derive_label, evaluate_path, is_malicious, signature_names};
use crate::files::detection::store::write_detection;
use crate::files::pipe_notify::broadcaster;
use crate::files::quarantine::{is_excluded, quarantine_path};
use crate::files::session_launch::{launch_notifier, logged_on_sessions, profile_dir_for_session};
use crate::files::util::{log_line, now_ms};

fn watch_session_downloads(session: u32, downloads_dir: PathBuf, stop: Arc<AtomicBool>, logs_dir: PathBuf) {
    let (tx, rx) = channel();
    let mut watcher = match notify::recommended_watcher(tx) {
        Ok(w) => w,
        Err(e) => {
            log_line(&logs_dir, &format!("watcher init failed for session {}: {}", session, e));
            return;
        }
    };
    if watcher.watch(&downloads_dir, RecursiveMode::Recursive).is_err() {
        log_line(&logs_dir, &format!("watcher watch() failed for session {}: {}", session, downloads_dir.display()));
        return;
    }
    log_line(&logs_dir, &format!("watching session {}: {}", session, downloads_dir.display()));
    let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
    while !stop.load(Ordering::Relaxed) {
        while let Ok(Ok(event)) = rx.try_recv() {
            for path in event.paths {
                pending.insert(path, Instant::now());
            }
        }
        let now = Instant::now();
        let ready: Vec<PathBuf> = pending.iter().filter(|(_, t)| now.duration_since(**t) > Duration::from_millis(800)).map(|(p, _)| p.clone()).collect();
        for path in ready {
            pending.remove(&path);
            if !path.is_file() {
                continue;
            }
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let exe = path.to_string_lossy().to_string();
            if is_excluded(&exe) {
                continue;
            }
            let verdict = evaluate_path(&exe);
            let bad = is_malicious(&verdict);
            if bad {
                let sig_names = signature_names(&verdict, &exe);
                let label = derive_label(&verdict, &exe);
                let quarantine_id = quarantine_path(&exe, Some(&label)).ok();
                log_line(&logs_dir, &format!("MALICIOUS download session={} {} quarantined={} verdict={}", session, exe, quarantine_id.is_some(), verdict));
                let det = json!({
                    "type": "rtp_detection",
                    "ts": now_ms(),
                    "pid": 0,
                    "exe": exe,
                    "source": "download",
                    "stopped": false,
                    "quarantine_id": quarantine_id,
                    "verdict": verdict,
                    "name": name,
                    "label": label,
                    "threat_names": sig_names,
                });
                write_detection(&logs_dir, &det);
                broadcaster().send_to_session(session, &det.to_string());
            } else {
                log_line(&logs_dir, &format!("ok download session={} {} verdict={}", session, exe, verdict));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    log_line(&logs_dir, &format!("stopped watching session {}", session));
}

pub fn run_download_watchers(logs_dir: &Path) {
    let logs = logs_dir.to_path_buf();
    let mut active: HashMap<(u32, PathBuf), (Arc<AtomicBool>, JoinHandle<()>)> = HashMap::new();
    let mut notified: HashSet<u32> = HashSet::new();
    loop {
        let sessions = logged_on_sessions();
        for session in &sessions {
            let session = *session;
            let Some(profile) = profile_dir_for_session(session) else {
                continue;
            };
            if notified.insert(session) {
                launch_notifier(session);
            }
            let downloads_dir = profile.join("Downloads");
            if !downloads_dir.is_dir() {
                continue;
            }
            let key = (session, downloads_dir.clone());
            if active.contains_key(&key) {
                continue;
            }
            let stop = Arc::new(AtomicBool::new(false));
            let stop_flag = stop.clone();
            let thread_logs = logs.clone();
            let handle = std::thread::spawn(move || watch_session_downloads(session, downloads_dir, stop_flag, thread_logs));
            active.insert(key, (stop, handle));
        }
        let gone: Vec<(u32, PathBuf)> = active.keys().filter(|k| !sessions.contains(&k.0)).cloned().collect();
        for key in gone {
            if let Some((stop, _)) = active.remove(&key) {
                stop.store(true, Ordering::Relaxed);
            }
        }
        notified.retain(|s| sessions.contains(s));
        std::thread::sleep(Duration::from_secs(5));
    }
}
