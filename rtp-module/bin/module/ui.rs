#![windows_subsystem = "windows"]
#![cfg(not(target_os = "android"))]

use std::ffi::CString;
use std::fs::{remove_file, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;
use uuid::Uuid;

use colourswift_av::cli_api;
use eframe::egui;
use serde_json::Value;

static VXPACK_BYTES: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/defs/defs.vxpack"));

static VXKEY_BYTES: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/defs/defs_key.bin"));

struct ScanMsg {
    raw: String,
    elapsed_ms: u128,
}

struct ScannerApp {
    scan_path: String,
    no_bloom: bool,
    no_yara: bool,
    no_ml: bool,

    running: bool,
    output: String,

    rx: Option<mpsc::Receiver<ScanMsg>>,
}

impl Default for ScannerApp {
    fn default() -> Self {
        Self {
            scan_path: String::new(),
            no_bloom: false,
            no_yara: false,
            no_ml: false,
            running: false,
            output: String::new(),
            rx: None,
        }
    }
}

impl ScannerApp {
    fn start_scan(&mut self) {
        let scan_path = self.scan_path.clone();
        let no_bloom = self.no_bloom;
        let no_yara = self.no_yara;
        let no_ml = self.no_ml;

        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.running = true;
        self.output.clear();

        thread::spawn(move || {
            let start = Instant::now();

            let scan = PathBuf::from(&scan_path);

            if !scan.exists() {
                let _ = tx.send(ScanMsg {
                    raw: "Invalid scan path".to_string(),
                    elapsed_ms: start.elapsed().as_millis(),
                });
                return;
            }

            let scan_c = CString::new(scan.to_string_lossy().to_string()).unwrap();

            let temp_dir = std::env::temp_dir().join(format!(".csav_{}", Uuid::new_v4()));
            std::fs::create_dir(&temp_dir).unwrap();

            let vxpack_path = temp_dir.join("defs.vxpack");
            let key_path = temp_dir.join("defs_key.bin");

            std::fs::write(&vxpack_path, VXPACK_BYTES).unwrap();
            std::fs::write(&key_path, VXKEY_BYTES).unwrap();

            let defs_c = CString::new(vxpack_path.to_string_lossy().to_string()).unwrap();
            let key_c = CString::new(key_path.to_string_lossy().to_string()).unwrap();

            let init_rc = cli_api::init_with_key(defs_c.as_ptr(), key_c.as_ptr());

            std::fs::remove_file(&vxpack_path).ok();
            std::fs::remove_file(&key_path).ok();
            std::fs::remove_dir(&temp_dir).ok();

            if init_rc != 0 {
                let _ = tx.send(ScanMsg {
                    raw: "Engine init failed".to_string(),
                    elapsed_ms: start.elapsed().as_millis(),
                });
                return;
            }

            if init_rc != 0 {
                let _ = tx.send(ScanMsg {
                    raw: "Engine init failed".to_string(),
                    elapsed_ms: start.elapsed().as_millis(),
                });
                return;
            }

            if no_bloom {
                cli_api::disable_bloom(true);
            }
            cli_api::disable_yara(no_yara);
            cli_api::disable_ml(no_ml);

            let result = cli_api::scan(scan_c.as_ptr());

            let _ = tx.send(ScanMsg {
                raw: result,
                elapsed_ms: start.elapsed().as_millis(),
            });
        });
    }

    fn write_temp_defs(bytes: &[u8]) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(".csav_defs_{}.vx", Uuid::new_v4()));

        let mut f = File::create(&path).expect("temp defs create failed");
        f.write_all(bytes).expect("temp defs write failed");
        f.flush().ok();

        path
    }

    fn format_elapsed(elapsed_ms: u128) -> String {
        let secs = elapsed_ms / 1000;
        let ms = elapsed_ms % 1000;
        format!("{}.{:03}s", secs, ms)
    }

    fn format_result(&self, raw: &str, elapsed_ms: u128) -> String {
        let elapsed = Self::format_elapsed(elapsed_ms);

        let parsed: Result<Value, _> = serde_json::from_str(raw);
        if parsed.is_err() {
            let mut out = String::new();
            out.push_str("Scan complete\n\n");
            out.push_str(&format!("Time         : {}\n", elapsed));
            out.push_str("Files scanned : 0\n");
            out.push_str("Detections    : 0\n\n");
            out.push_str(raw);
            return out;
        }

        let json = parsed.unwrap();
        let scanned = json
            .get("scanned")
            .and_then(|v| v.as_u64())
            .or_else(|| json.get("files_scanned").and_then(|v| v.as_u64()))
            .or_else(|| json.get("scanned_files").and_then(|v| v.as_u64()))
            .or_else(|| json.get("count").and_then(|v| v.as_u64()))
            .or_else(|| {
                json.get("stats")
                    .and_then(|s| s.get("scanned"))
                    .and_then(|v| v.as_u64())
            })
            .or_else(|| {
                json.get("stats")
                    .and_then(|s| s.get("files_scanned"))
                    .and_then(|v| v.as_u64())
            })
            .unwrap_or(0);

        let hits_obj = json
            .get("hits")
            .and_then(|v| v.as_object())
            .or_else(|| json.get("detections").and_then(|v| v.as_object()));
        let detections = hits_obj.map(|m| m.len()).unwrap_or(0);

        let mut out = String::new();
        out.push_str("Scan complete\n\n");
        out.push_str(&format!("Time         : {}\n", elapsed));
        out.push_str(&format!("Files scanned : {}\n", scanned));
        out.push_str(&format!("Detections    : {}\n", detections));

        if let Some(map) = hits_obj {
            if !map.is_empty() {
                out.push_str("\nDetections list\n\n");
                for (path, hit) in map {
                    match hit {
                        Value::String(s) => {
                            out.push_str(path);
                            out.push_str("  ->  ");
                            out.push_str(s);
                            out.push('\n');
                        }
                        Value::Array(arr) => {
                            for h in arr {
                                if let Some(s) = h.as_str() {
                                    out.push_str(path);
                                    out.push_str("  ->  ");
                                    out.push_str(s);
                                    out.push('\n');
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        out
    }
}

impl eframe::App for ScannerApp {
    fn update(&mut self, _ctx: &egui::Context, _: &mut eframe::Frame) {
        egui::CentralPanel::default().show(_ctx, |ui| {
            ui.heading("ColourSwift Scanner");

            ui.add_space(10.0);

            ui.add_space(6.0);

            ui.label("Scan target");
            ui.text_edit_singleline(&mut self.scan_path);

            ui.add_space(10.0);

            if ui
                .add_enabled(!self.running, egui::Button::new("Scan"))
                .clicked()
            {
                self.start_scan();
            }

            ui.add_space(10.0);

            if let Some(rx) = &self.rx {
                if let Ok(msg) = rx.try_recv() {
                    self.output = self.format_result(&msg.raw, msg.elapsed_ms);
                    self.running = false;
                    self.rx = None;
                }
            }

            ui.separator();

            egui::ScrollArea::vertical()
                .max_height(340.0)
                .show(ui, |ui| {
                    ui.monospace(&self.output);
                });
        });
    }
}

fn main() {
    let options = eframe::NativeOptions::default();

    eframe::run_native(
        "CS Security Scanner",
        options,
        Box::new(|_| Box::new(ScannerApp::default())),
    )
    .unwrap();
}
