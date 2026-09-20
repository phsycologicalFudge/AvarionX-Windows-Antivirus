use std::env;
use std::ffi::{c_void, CString};
use std::fs;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::time::Duration;
use colourswift_av::cli_api;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use crate::files::cloud::run_cloud_auth_loop;
use crate::files::detection::defs::{ensure_defs_unpacked, run_update_check};
use crate::files::monitoring::download_watch::run_download_watchers;
use crate::files::monitoring::process_snapshot::{run_snapshot_loop, snapshot_processes};
use crate::files::monitoring::wmi_watch::run_wmi_loop;
use crate::files::service::control::{install_service, run_as_service, start_existing_service, stop_service, uninstall_service};
use crate::files::service::single_instance::acquire_single_instance;
use crate::files::util::{log_line, self_dir};

mod files;

const CREATE_NO_WINDOW: u32 = 0x08000000;
const ELEVATION_CANCELLED: i32 = 1223;
const ELEVATION_REQUIRED: i32 = 5;

fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

fn relaunch_elevated(verb: &str) -> i32 {
    let exe = match env::current_exe() {
        Ok(p) => p,
        Err(_) => return 1,
    };
    let quote = |s: &str| s.replace('\'', "''");
    let script = format!(
        "try {{ $p = Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode }} catch {{ exit {} }}",
        quote(&exe.to_string_lossy()),
        quote(verb),
        ELEVATION_CANCELLED
    );
    let system_root = env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let powershell = format!(r"{}\System32\WindowsPowerShell\v1.0\powershell.exe", system_root);
    match Command::new(powershell)
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
    {
        Ok(status) => status.code().unwrap_or(1),
        Err(_) => 1,
    }
}

fn report(ok: bool, done: &str, failed: &str, err: Option<String>) -> i32 {
    if ok {
        println!("{}", done);
        0
    } else {
        println!("{}: {}", failed, err.unwrap_or_default());
        1
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    for verb in ["--install", "--uninstall", "--stop"] {
        if args.iter().any(|a| a == verb) && !is_elevated() {
            std::process::exit(relaunch_elevated(verb));
        }
    }

    for (verb, kind) in [("--exclude-sha", "shas"), ("--exclude-folder", "folders")] {
        if let Some(i) = args.iter().position(|a| a == verb) {
            if !is_elevated() {
                std::process::exit(ELEVATION_REQUIRED);
            }
            let ok = args
                .get(i + 1)
                .map(|v| crate::files::quarantine::add_user_exclusion(kind, v))
                .unwrap_or(false);
            std::process::exit(if ok { 0 } else { 1 });
        }
    }

    if args.iter().any(|a| a == "--install") {
        let r = install_service();
        std::process::exit(report(r.is_ok(), "service installed", "install failed", r.err().map(|e| format!("{:?}", e))));
    }

    if args.iter().any(|a| a == "--start") {
        let r = start_existing_service();
        std::process::exit(report(r.is_ok(), "service started", "start failed", r.err().map(|e| format!("{:?}", e))));
    }

    if args.iter().any(|a| a == "--stop") {
        let r = stop_service();
        std::process::exit(report(r.is_ok(), "service stopped", "stop failed", r.err().map(|e| format!("{:?}", e))));
    }

    if args.iter().any(|a| a == "--uninstall") {
        let r = uninstall_service();
        std::process::exit(report(r.is_ok(), "service uninstalled", "uninstall failed", r.err().map(|e| format!("{:?}", e))));
    }

    if args.iter().any(|a| a == "--run-as-service") {
        if let Err(e) = run_as_service() {
            eprintln!("service dispatcher failed: {:?}", e);
        }
        return;
    }

    run_core();
}

pub fn run_core() {
    let self_directory = self_dir();
    let logs_dir = self_directory.join("rtp_logs");
    let _ = fs::create_dir_all(&logs_dir);

    let _mutex_guard = match acquire_single_instance() {
        Some(h) => h,
        None => {
            log_line(&logs_dir, "RTP already running, exiting");
            return;
        }
    };

    let defs_path = ensure_defs_unpacked(&logs_dir);

    log_line(&logs_dir, &format!("self_dir={}", self_directory.display()));
    log_line(&logs_dir, &format!("defs={}", defs_path.display()));

    if !defs_path.exists() {
        log_line(&logs_dir, "engine defs missing, exiting");
        return;
    }

    let defs_c = CString::new(defs_path.to_string_lossy().to_string()).unwrap();
    let init_rc = cli_api::init(defs_c.as_ptr());
    if init_rc != 0 {
        log_line(&logs_dir, "engine init failed");
        return;
    }

    let update_logs = logs_dir.clone();
    std::thread::spawn(move || run_update_check(&update_logs));

    let cloud_logs = logs_dir.clone();
    std::thread::spawn(move || run_cloud_auth_loop(&cloud_logs));

    let dl_logs = logs_dir.clone();
    std::thread::spawn(move || run_download_watchers(&dl_logs));

    let _ = crate::files::quarantine::ensure_config_dir();
    crate::files::pipe_command::start_listener();

    let proc_logs = logs_dir.clone();
    std::thread::spawn(move || {
        let mut known = snapshot_processes();
        let snap_logs = proc_logs.clone();
        let mut snap_known = known.clone();
        std::thread::spawn(move || run_snapshot_loop(&mut snap_known, &snap_logs));
        run_wmi_loop(&mut known, &proc_logs);
    });

    loop {
        std::thread::sleep(Duration::from_millis(500));
    }
}