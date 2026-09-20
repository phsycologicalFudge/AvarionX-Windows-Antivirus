use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use once_cell::sync::OnceCell;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use crate::files::util::{log_line, now_ms, self_dir};

pub const CLOUD_REGISTER_ENDPOINT: &str = "https://api.colourswift.com/hash_cloud/register";
pub const CLOUD_CHECK_ENDPOINT: &str = "https://api.colourswift.com/hash_cloud/check_batch";
const CLOUD_REFRESH_THRESHOLD_DAYS: f64 = 3.0;
const CLOUD_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CLOUD_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
static CLOUD_TOKEN: OnceCell<Mutex<Option<String>>> = OnceCell::new();
static LAST_CLOUD_FAILURE_LOG: AtomicI64 = AtomicI64::new(0);

fn cloud_state_dir() -> PathBuf {
    let base = env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    PathBuf::from(base).join("ColourSwift").join("cloud")
}

fn load_cloud_state() -> Value {
    let path = cloud_state_dir().join("auth.json");
    fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| json!({}))
}

fn save_cloud_state(state: &Value) {
    let dir = cloud_state_dir();
    let _ = fs::create_dir_all(&dir);
    if let Ok(text) = serde_json::to_string(state) {
        let _ = fs::write(dir.join("auth.json"), text);
    }
}

fn generate_uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

fn hash_uuid(uuid: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(uuid.as_bytes());
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

fn get_or_create_uuid() -> String {
    let mut state = load_cloud_state();
    if let Some(u) = state.get("client_uuid").and_then(|x| x.as_str()) {
        return u.to_string();
    }
    let uuid = generate_uuid_v4();
    state["client_uuid"] = json!(uuid);
    save_cloud_state(&state);
    uuid
}

fn cloud_register(logs_dir: &Path) -> Option<String> {
    let uuid = get_or_create_uuid();
    let client_hash = hash_uuid(&uuid);
    let resp = ureq::post(CLOUD_REGISTER_ENDPOINT)
        .timeout(CLOUD_REQUEST_TIMEOUT)
        .set("Content-Type", "application/json")
        .send_json(json!({"client_hash": client_hash}));
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            log_line(logs_dir, &format!("cloud register request failed: {}", e));
            return None;
        }
    };
    let data: Value = match resp.into_json() {
        Ok(v) => v,
        Err(e) => {
            log_line(logs_dir, &format!("cloud register bad response: {}", e));
            return None;
        }
    };
    let Some(token) = data.get("session_token").and_then(|x| x.as_str()) else {
        log_line(logs_dir, "cloud register response missing session_token");
        return None;
    };
    let Some(expires_in) = data.get("expires_in").and_then(|x| x.as_i64()) else {
        log_line(logs_dir, "cloud register response missing expires_in");
        return None;
    };
    let token = token.to_string();
    let expires_at = now_ms() / 1000 + expires_in;
    let mut state = load_cloud_state();
    state["session_token"] = json!(token);
    state["session_expires_at"] = json!(expires_at);
    save_cloud_state(&state);
    log_line(logs_dir, "cloud session registered");
    Some(token)
}

fn ensure_cloud_registered(logs_dir: &Path) -> Option<String> {
    let state = load_cloud_state();
    if let (Some(token), Some(expires_at)) = (state.get("session_token").and_then(|x| x.as_str()), state.get("session_expires_at").and_then(|x| x.as_i64())) {
        let now = now_ms() / 1000;
        let days_left = (expires_at - now) as f64 / 86400.0;
        if days_left > CLOUD_REFRESH_THRESHOLD_DAYS {
            return Some(token.to_string());
        }
    }
    cloud_register(logs_dir)
}

fn cloud_token_cell() -> &'static Mutex<Option<String>> {
    CLOUD_TOKEN.get_or_init(|| Mutex::new(None))
}

fn refresh_cloud_token(logs_dir: &Path) {
    if let Some(token) = ensure_cloud_registered(logs_dir) {
        *cloud_token_cell().lock().unwrap() = Some(token);
    } else {
        log_line(logs_dir, "cloud registration failed");
    }
}

pub fn current_cloud_token() -> Option<String> {
    cloud_token_cell().lock().unwrap().clone()
}

pub fn run_cloud_auth_loop(logs_dir: &Path) {
    refresh_cloud_token(logs_dir);
    loop {
        std::thread::sleep(Duration::from_secs(6 * 3600));
        refresh_cloud_token(logs_dir);
    }
}

fn log_cloud_failure(msg: &str) {
    let now = now_ms() / 1000;
    if now - LAST_CLOUD_FAILURE_LOG.load(Ordering::Relaxed) < 60 {
        return;
    }
    LAST_CLOUD_FAILURE_LOG.store(now, Ordering::Relaxed);
    log_line(&self_dir().join("rtp_logs"), msg);
}

pub fn cloud_check_batch(hashes: &[String], api_key: &str) -> Vec<String> {
    if hashes.is_empty() {
        return Vec::new();
    }
    let result = ureq::post(CLOUD_CHECK_ENDPOINT)
        .timeout(CLOUD_CHECK_TIMEOUT)
        .set("Content-Type", "application/json")
        .set("x-cs-key", api_key)
        .send_json(json!(hashes));
    match result {
        Ok(resp) => {
            let data: Value = resp.into_json().unwrap_or_else(|_| json!({}));
            data.get("found").and_then(|f| f.as_array()).map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default()
        }
        Err(e) => {
            log_cloud_failure(&format!("cloud check failed: {}", e));
            Vec::new()
        }
    }
}