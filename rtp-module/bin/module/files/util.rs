use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

pub fn now_str() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn log_line(logs_dir: &Path, msg: &str) {
    let _ = fs::create_dir_all(logs_dir);
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(logs_dir.join("rtp_main.log")) {
        let _ = writeln!(f, "[{}] {}", now_str(), msg);
    }
}

pub fn self_dir() -> PathBuf {
    env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf())).unwrap_or_else(|| PathBuf::from("."))
}
