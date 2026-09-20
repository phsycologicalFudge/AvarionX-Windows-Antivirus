use std::env;
use std::ffi::OsString;
use std::os::windows::process::CommandExt;
use std::time::Duration;
use windows_service::define_windows_service;
use windows_service::service::{ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType, SessionChangeReason};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use crate::run_core;
use crate::files::monitoring::process_snapshot::{get_full_exe_path, snapshot_processes, terminate_pid};
use crate::files::session_launch::{launch_notifier, launch_notifier_active_session};
use crate::files::util::self_dir;

const CREATE_NO_WINDOW: u32 = 0x08000000;
const ERROR_SERVICE_EXISTS: i32 = 1073;
const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;

pub const SERVICE_NAME: &str = "AxService";
pub const SERVICE_DISPLAY_NAME: &str = "ColourSwift AvarionX Protection";

define_windows_service!(ffi_service_main, service_main);

pub fn install_service() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT)?;
    let exe_path = env::current_exe().unwrap();
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path.clone(),
        launch_arguments: vec![OsString::from("--run-as-service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START;
    let service = match manager.create_service(&service_info, access) {
        Ok(s) => s,
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(ERROR_SERVICE_EXISTS) => {
            let s = manager.open_service(SERVICE_NAME, access)?;
            s.change_config(&service_info)?;
            s
        }
        Err(e) => return Err(e),
    };
    let _ = service.set_description("Realtime protection engine for AVarionX");
    restrict_service_control();
    if let Err(e) = service.start(&[] as &[&std::ffi::OsStr]) {
        let already = matches!(&e, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(ERROR_SERVICE_ALREADY_RUNNING));
        if !already {
            return Err(e);
        }
    }
    install_notifier_logon_task(&exe_path);
    Ok(())
}

fn restrict_service_control() {
    const SDDL: &str = "D:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)";
    let _ = std::process::Command::new("sc")
        .args(["sdset", SERVICE_NAME, SDDL])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

fn install_notifier_logon_task(service_exe: &std::path::Path) {
    let axnotify_path = service_exe
        .parent()
        .map(|p| p.join("axnotify.exe"))
        .unwrap_or_else(|| std::path::PathBuf::from("axnotify.exe"));
    if !axnotify_path.exists() {
        return;
    }
    let _ = std::process::Command::new("schtasks")
        .args([
            "/Create",
            "/TN",
            "AvarionXNotify",
            "/TR",
            &format!("\"{}\"", axnotify_path.display()),
            "/SC",
            "ONLOGON",
            "/RL",
            "LIMITED",
            "/F",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

pub fn start_existing_service() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start(&[] as &[&std::ffi::OsStr])?;
    Ok(())
}

pub fn stop_service() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
    if let Ok(status) = service.query_status() {
        if status.current_state == ServiceState::Stopped {
            return Ok(());
        }
    }
    match service.stop() {
        Ok(_) => Ok(()),
        Err(e) => match service.query_status() {
            Ok(status) if matches!(status.current_state, ServiceState::Stopped | ServiceState::StopPending) => Ok(()),
            _ => Err(e),
        },
    }
}

pub fn uninstall_service() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::STOP)?;
    let _ = service.stop();
    let _ = std::process::Command::new("schtasks")
        .args(["/Delete", "/TN", "AvarionXNotify", "/F"])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    service.delete()
}

fn service_main(_arguments: Vec<OsString>) {
    let _ = run_service();
}

fn stop_notifiers() {
    let target = self_dir().join("axnotify.exe").to_string_lossy().to_lowercase();
    for (pid, (name, _)) in snapshot_processes() {
        if !name.eq_ignore_ascii_case("axnotify.exe") {
            continue;
        }
        let ours = get_full_exe_path(pid)
            .map(|p| p.to_lowercase() == target)
            .unwrap_or(false);
        if ours {
            terminate_pid(pid);
        }
    }
}

pub fn run_service() -> windows_service::Result<()> {
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let core_tx = stop_tx.clone();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::SessionChange(param) => {
                if matches!(param.reason, SessionChangeReason::SessionLogon | SessionChangeReason::ConsoleConnect) {
                    launch_notifier(param.notification.session_id);
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SESSION_CHANGE,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    launch_notifier_active_session();

    std::thread::spawn(move || {
        run_core();
        let _ = core_tx.send(());
    });

    let _ = stop_rx.recv();

    stop_notifiers();

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    std::process::exit(0);
}

pub fn run_as_service() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}