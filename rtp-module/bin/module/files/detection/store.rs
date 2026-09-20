use std::fs;
use std::path::Path;
use serde_json::Value;

pub fn write_detection(logs_dir: &Path, det: &Value) {
    let dir = logs_dir.join("detections");
    let _ = fs::create_dir_all(&dir);
    let ts = det.get("ts").and_then(|x| x.as_i64()).unwrap_or(0);
    let pid = det.get("pid").and_then(|x| x.as_i64()).unwrap_or(0);
    let name = det.get("name").and_then(|x| x.as_str()).unwrap_or("");
    let safe_name: String = name.chars().filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_').take(40).collect();
    let path = dir.join(format!("{}_{}_{}.json", ts, pid, safe_name));
    let tmp = dir.join(format!("{}_{}_{}.json.tmp", ts, pid, safe_name));
    if let Ok(text) = serde_json::to_string(det) {
        let _ = fs::write(&tmp, text);
        let _ = fs::rename(&tmp, &path);
    }
}
