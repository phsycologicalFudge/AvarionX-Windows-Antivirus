use std::env;
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use colourswift_av::av_reload;
use serde_json::Value;
use crate::files::util::log_line;

pub const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(3 * 3600);
const UPDATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const GITHUB_RELEASE_API: &str = "https://api.github.com/repos/phsycologicalFudge/WinAVDatabase/releases/latest";
static EMBEDDED_DEFS: &[u8] = include_bytes!("../../../defs/defs.cs");
static EMBEDDED_VERSION: &str = include_str!("../../../defs/version.json");

pub fn defs_dir() -> PathBuf {
    let base = env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    PathBuf::from(base).join("ColourSwift").join("defs")
}

pub fn ensure_defs_unpacked(logs_dir: &Path) -> PathBuf {
    let dir = defs_dir();
    let _ = fs::create_dir_all(&dir);
    let defs_path = dir.join("defs.cs");
    let version_path = dir.join("version.json");
    if !defs_path.exists() {
        log_line(logs_dir, "no local defs found, unpacking bundled default");
        let _ = fs::write(&defs_path, EMBEDDED_DEFS);
        let _ = fs::write(&version_path, EMBEDDED_VERSION.as_bytes());
    }
    defs_path
}

fn local_version(logs_dir: &Path) -> String {
    let path = defs_dir().join("version.json");
    match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v.get("version").and_then(|x| x.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| "0.0.0".to_string()),
        Err(_) => {
            log_line(logs_dir, "no local version.json, defaulting to 0.0.0");
            "0.0.0".to_string()
        }
    }
}

fn version_parts(v: &str) -> [i64; 3] {
    let mut out = [0i64; 3];
    for (i, part) in v.split('.').take(3).enumerate() {
        out[i] = part.parse().unwrap_or(0);
    }
    out
}

fn is_newer(a: &str, b: &str) -> bool {
    version_parts(a) > version_parts(b)
}

fn fetch_latest_release() -> Option<Value> {
    let resp = ureq::get(GITHUB_RELEASE_API)
        .timeout(UPDATE_REQUEST_TIMEOUT)
        .set("User-Agent", "AvarionX-axservice")
        .call()
        .ok()?;
    resp.into_json::<Value>().ok()
}

fn download_asset(url: &str) -> Option<Vec<u8>> {
    let resp = ureq::get(url)
        .timeout(UPDATE_REQUEST_TIMEOUT)
        .set("User-Agent", "AvarionX-axservice")
        .call()
        .ok()?;
    let mut buf = Vec::new();
    resp.into_reader().read_to_end(&mut buf).ok()?;
    Some(buf)
}

pub fn run_update_check(logs_dir: &Path) {
    check_for_update(logs_dir);
    loop {
        std::thread::sleep(UPDATE_CHECK_INTERVAL);
        check_for_update(logs_dir);
    }
}

fn check_for_update(logs_dir: &Path) {
    log_line(logs_dir, "checking for defs update");

    let Some(release) = fetch_latest_release() else {
        log_line(logs_dir, "update check failed: no response");
        return;
    };

    let server_version = release.get("tag_name").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if server_version.is_empty() {
        return;
    }

    let local = local_version(logs_dir);
    if !is_newer(&server_version, &local) {
        log_line(logs_dir, &format!("defs up to date: local={} server={}", local, server_version));
        return;
    }

    log_line(logs_dir, &format!("update available: local={} server={}", local, server_version));

    let assets = release.get("assets").and_then(|a| a.as_array()).cloned().unwrap_or_default();
    let defs_url = assets.iter().find(|a| a.get("name").and_then(|n| n.as_str()) == Some("defs.cs")).and_then(|a| a.get("browser_download_url")).and_then(|u| u.as_str()).map(|s| s.to_string());
    let version_url = assets.iter().find(|a| a.get("name").and_then(|n| n.as_str()) == Some("version.json")).and_then(|a| a.get("browser_download_url")).and_then(|u| u.as_str()).map(|s| s.to_string());

    let (Some(defs_url), Some(version_url)) = (defs_url, version_url) else {
        log_line(logs_dir, "update release missing expected assets");
        return;
    };

    let Some(defs_bytes) = download_asset(&defs_url) else {
        log_line(logs_dir, "defs.cs download failed");
        return;
    };
    let Some(version_bytes) = download_asset(&version_url) else {
        log_line(logs_dir, "version.json download failed");
        return;
    };

    let dir = defs_dir();
    let defs_path = dir.join("defs.cs");
    let defs_tmp = dir.join("defs.cs.tmp");
    let version_path = dir.join("version.json");
    let version_tmp = dir.join("version.json.tmp");

    if fs::write(&defs_tmp, &defs_bytes).is_err() || fs::rename(&defs_tmp, &defs_path).is_err() {
        log_line(logs_dir, "failed to write defs.cs");
        return;
    }
    let _ = fs::write(&version_tmp, &version_bytes);
    let _ = fs::rename(&version_tmp, &version_path);

    let Ok(defs_c) = CString::new(defs_path.to_string_lossy().to_string()) else {
        return;
    };
    let reload_rc = unsafe { av_reload(defs_c.as_ptr(), std::ptr::null()) };
    log_line(logs_dir, &format!("engine reload rc={}", reload_rc));
}