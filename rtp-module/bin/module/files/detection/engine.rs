use std::ffi::CString;
use std::fs;
use colourswift_av::cli_api;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use crate::files::cloud::{cloud_check_batch, current_cloud_token};
use crate::files::quarantine::user_excluded_shas;

fn sha256_file(path: &str) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect())
}

pub fn evaluate_path(exe: &str) -> Value {
    let excluded_shas = user_excluded_shas();
    let token = current_cloud_token();
    let sha = if token.is_some() || !excluded_shas.is_empty() {
        sha256_file(exe)
    } else {
        None
    };
    if let Some(sha) = &sha {
        if excluded_shas.contains(sha) {
            return json!({"verdict": "clean", "source": "excluded", "sha256": sha});
        }
    }
    if let (Some(token), Some(sha)) = (&token, &sha) {
        let hits = cloud_check_batch(&[sha.clone()], token);
        if hits.contains(sha) {
            return json!({"verdict": "malicious", "source": "cloud", "sha256": sha});
        }
    }
    scan_path(exe)
}

fn scan_path(path: &str) -> Value {
    let c_path = match CString::new(path) {
        Ok(c) => c,
        Err(_) => return json!({"verdict": "error", "reason": "bad_path"}),
    };
    let raw = cli_api::scan(c_path.as_ptr());
    match serde_json::from_str::<Value>(&raw) {
        Ok(v) => v,
        Err(_) => json!({"verdict": "unknown", "raw": raw}),
    }
}

pub fn is_malicious(verdict: &Value) -> bool {
    let v = verdict.get("verdict").and_then(|x| x.as_str()).unwrap_or("").to_lowercase();
    if matches!(v.as_str(), "malicious" | "malware" | "infected" | "bad" | "deny" | "block") {
        return true;
    }
    if v.contains("malware") || v.contains("infect") {
        return true;
    }
    let raw = verdict.get("raw").and_then(|x| x.as_str()).unwrap_or("").to_lowercase();
    if raw.contains("malicious") || raw.contains("malware") || raw.contains("infected") {
        return true;
    }
    verdict.get("hits")
        .and_then(|h| h.as_object())
        .map(|hits| !hits.is_empty())
        .unwrap_or(false)
}

pub fn signature_names(verdict: &Value, exe: &str) -> Vec<String> {
    verdict.get("hits")
        .and_then(|h| h.get(exe))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}


const SIG_NOISE: [&str; 5] = ["androidos", "and", "byte", "simple", "complex"];

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn drop_redundant_platform(parts: Vec<String>) -> Vec<String> {
    let redundant = parts.first().map_or(false, |p| p.to_lowercase() == "android");
    if redundant {
        parts[1..].to_vec()
    } else {
        parts
    }
}

fn filter_sig_parts(parts: &[&str]) -> Vec<String> {
    parts
        .iter()
        .filter(|p| !SIG_NOISE.contains(&p.to_lowercase().as_str()) && !is_digits(p))
        .map(|p| p.to_string())
        .collect()
}

fn join_or_raw(parts: Vec<String>, raw: &str) -> String {
    if parts.is_empty() {
        raw.to_string()
    } else {
        parts.join(".")
    }
}

pub fn parse_sig_name(raw: &str) -> String {
    if raw.is_empty() {
        return "Suspicious.Item".to_string();
    }
    let parts: Vec<&str> = raw.split('.').collect();
    let lower = |i: usize| parts[i].to_lowercase();

    if parts.len() >= 3 && lower(0) == "androidos" && lower(2) == "origin" {
        return format!("Andr/{}.Origin", parts[1]);
    }

    if parts.len() >= 4 && lower(2) == "androidos" {
        return join_or_raw(drop_redundant_platform(filter_sig_parts(&parts)), raw);
    }

    if parts.len() >= 3 && lower(2) == "byte" {
        let mut keep: Vec<String> = vec![parts[0].to_string()];
        keep.extend(parts[1].split('_').map(|s| s.to_string()));
        return join_or_raw(drop_redundant_platform(keep), raw);
    }

    join_or_raw(drop_redundant_platform(filter_sig_parts(&parts)), raw)
}

pub fn signals_of(verdict: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(hits) = verdict.get("hits").and_then(|h| h.as_object()) {
        for v in hits.values() {
            if let Some(arr) = v.as_array() {
                for s in arr {
                    if let Some(s) = s.as_str() {
                        out.push(s.to_string());
                    }
                }
            }
        }
    }
    let from_cloud = verdict.get("source").and_then(|x| x.as_str()) == Some("cloud");
    if from_cloud && !out.iter().any(|s| s == "HashMatch") {
        out.push("HashMatch".to_string());
    }
    out
}

fn is_apk_path(path: &str) -> bool {
    path.to_lowercase().ends_with(".apk")
}

fn is_hash_signal(signals: &[String]) -> bool {
    signals.iter().any(|s| s == "HashMatch" || s.starts_with("SignerMatch("))
}

fn is_ml_signal(signals: &[String]) -> bool {
    signals.iter().any(|s| s.starts_with("ML_Detection("))
}

fn structured_hash_label(path: &str) -> String {
    if is_apk_path(path) {
        "Android.KnownMalware.HashMatch".to_string()
    } else {
        "Generic.KnownMalware.HashMatch".to_string()
    }
}

pub fn derive_label(verdict: &Value, exe: &str) -> String {
    let signals = signals_of(verdict);

    if is_hash_signal(&signals) {
        return structured_hash_label(exe);
    }

    let signature = signals.iter().find(|s| {
        !s.starts_with("ML_Detection(") && s.as_str() != "HashMatch" && !s.starts_with("SignerMatch(")
    });
    if let Some(sig) = signature {
        return parse_sig_name(sig);
    }

    if is_ml_signal(&signals) && is_apk_path(exe) {
        return "Andr/VXgen2".to_string();
    }

    "Suspicious.Item".to_string()
}
