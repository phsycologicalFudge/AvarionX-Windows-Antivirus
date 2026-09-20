use chrono::Utc;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn quarantine_dir() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    let dir = PathBuf::from(base)
        .join("ColourSwift")
        .join("AvarionX")
        .join("Quarantine");
    if !dir.exists() {
        let _ = fs::create_dir_all(&dir);
        grant_authenticated_users(&dir);
    }
    dir
}

fn grant_authenticated_users(dir: &PathBuf) {
    let _ = std::process::Command::new("icacls")
        .arg(dir)
        .arg("/grant")
        .arg("*S-1-5-11:(OI)(CI)M")
        .output();
}

fn new_id() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    format!("{:x}_{:x}", now.as_secs(), now.subsec_nanos())
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn sha256_hex(path: &PathBuf) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect())
}

pub fn quarantine_path(src: &str, label: Option<&str>) -> io::Result<String> {
    let dir = quarantine_dir();
    let src_path = PathBuf::from(src);
    let metadata = fs::metadata(&src_path)?;
    let size = metadata.len();
    let name = src_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let ext = src_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_string();
    let id = new_id();
    let q_path = dir.join(&id);
    fs::copy(&src_path, &q_path)?;
    let date = Utc::now().to_rfc3339();
    let sha_field = match sha256_hex(&q_path) {
        Some(h) => format!(",\"sha256\":\"{}\"", h),
        None => String::new(),
    };
    let label_field = match label {
        Some(l) if !l.is_empty() => format!(",\"label\":\"{}\"", escape_json(l)),
        _ => String::new(),
    };
    let json = format!(
        "{{\"id\":\"{id}\",\"qPath\":\"{qpath}\",\"name\":\"{name}\",\"originalPath\":\"{orig}\",\"originalExt\":\"{ext}\",\"size\":{size},\"date\":\"{date}\"{sha_field}{label_field}}}",
        id = id,
        qpath = escape_json(&q_path.to_string_lossy()),
        name = escape_json(&name),
        orig = escape_json(src),
        ext = escape_json(&ext),
        size = size,
        date = date,
        sha_field = sha_field,
        label_field = label_field,
    );
    fs::write(dir.join(format!("{}.json", id)), json)?;
    let _ = fs::remove_file(&src_path);
    Ok(id)
}

fn config_dir() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(base)
        .join("ColourSwift")
        .join("AvarionX")
        .join("Config")
}

fn user_exclusions_path() -> PathBuf {
    config_dir().join("user_exclusions.json")
}

fn run_icacls(args: &[&str]) {
    let _ = std::process::Command::new("icacls").args(args).output();
}

pub fn ensure_config_dir() -> PathBuf {
    let dir = config_dir();
    let _ = fs::create_dir_all(&dir);
    let d = dir.to_string_lossy().to_string();
    run_icacls(&[d.as_str(), "/setowner", "*S-1-5-32-544", "/T"]);
    run_icacls(&[d.as_str(), "/grant:r", "*S-1-5-18:(OI)(CI)F", "/T"]);
    run_icacls(&[d.as_str(), "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/T"]);
    run_icacls(&[d.as_str(), "/grant:r", "*S-1-5-11:(OI)(CI)RX", "/T"]);
    run_icacls(&[d.as_str(), "/inheritance:r", "/T"]);
    dir
}

fn normalize_sha_exclusion(raw: &str) -> Option<String> {
    let s = raw.trim().to_lowercase();
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(s)
    } else {
        None
    }
}

fn normalize_folder_exclusion(raw: &str) -> Option<String> {
    let cleaned = raw.trim().replace('/', "\\");
    let cleaned = cleaned.trim_end_matches('\\').to_string();
    let b = cleaned.as_bytes();
    let drive = b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b.len() == 2 || b[2] == b'\\');
    let unc = cleaned.starts_with("\\\\") && cleaned.len() > 2;
    if cleaned.contains('\0') || !(drive || unc) {
        return None;
    }
    Some(cleaned)
}

pub fn add_user_exclusion(kind: &str, value: &str) -> bool {
    let normalized = match kind {
        "shas" => normalize_sha_exclusion(value),
        "folders" => normalize_folder_exclusion(value),
        _ => None,
    };
    let Some(entry) = normalized else {
        return false;
    };
    let dir = ensure_config_dir();
    let current = load_user_exclusions();
    let mut folders = string_list(&current, "folders");
    let mut shas = string_list(&current, "shas");
    let list = if kind == "shas" { &mut shas } else { &mut folders };
    if !list.iter().any(|e| e.eq_ignore_ascii_case(&entry)) {
        list.push(entry);
    }
    let body = serde_json::json!({ "folders": folders, "shas": shas }).to_string();
    let tmp = dir.join("user_exclusions.json.tmp");
    fs::write(&tmp, body).is_ok() && fs::rename(&tmp, dir.join("user_exclusions.json")).is_ok()
}

fn load_user_exclusions() -> Value {
    fs::read_to_string(user_exclusions_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null)
}

fn string_list(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default()
}

pub fn user_excluded_shas() -> HashSet<String> {
    string_list(&load_user_exclusions(), "shas")
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect()
}

fn is_folder_excluded(path: &str) -> bool {
    let target = path.replace('/', "\\").to_lowercase();
    string_list(&load_user_exclusions(), "folders").iter().any(|f| {
        let folder = f.replace('/', "\\").trim_end_matches('\\').to_lowercase();
        !folder.is_empty() && (target == folder || target.starts_with(&format!("{}\\", folder)))
    })
}

pub fn is_excluded(path: &str) -> bool {
    is_folder_excluded(path)
}

pub fn restore_id(id: &str) -> io::Result<()> {
    let dir = quarantine_dir();
    let meta_path = dir.join(format!("{}.json", id));
    let raw = fs::read_to_string(&meta_path)?;
    let meta: Value = serde_json::from_str(&raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let q_path = meta
        .get("qPath")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing qPath"))?;
    let orig = meta
        .get("originalPath")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing originalPath"))?;
    let orig_path = PathBuf::from(orig);
    if let Some(parent) = orig_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    let out_path = if orig_path.exists() {
        let dir = orig_path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let stem = orig_path.file_stem().and_then(|s| s.to_str()).unwrap_or("restored");
        let ext = orig_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext.is_empty() {
            dir.join(format!("{}_restored", stem))
        } else {
            dir.join(format!("{}_restored.{}", stem, ext))
        }
    } else {
        orig_path
    };
    fs::copy(q_path, &out_path)?;
    let _ = fs::remove_file(q_path);
    let _ = fs::remove_file(&meta_path);
    Ok(())
}