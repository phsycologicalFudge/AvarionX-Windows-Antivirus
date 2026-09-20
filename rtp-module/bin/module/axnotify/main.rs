mod pipe;
mod popup;
mod webview;
use pipe::spawn_pipe_thread;
use popup::PopupManager;
use std::io::Write;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoop, EventLoopBuilder};
use tao::window::WindowId;
use windows::core::w;
use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
use windows::Win32::System::Threading::CreateMutexW;

pub struct Detection {
    name: String,
    exe: String,
    threat: String,
    quarantine_id: Option<String>,
}

pub enum UserEvent {
    Detection(Detection),
    Close(WindowId),
    Reveal(WindowId),
}

fn log_line(msg: &str) {
    let dir = std::env::var("LOCALAPPDATA")
        .map(|d| std::path::PathBuf::from(d).join("ColourSwift").join("AvarionX"))
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let _ = std::fs::create_dir_all(&dir);
    let line = format!("[{}] {}\n", chrono_stamp(), msg);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("axnotify.log")) {
        let _ = f.write_all(line.as_bytes());
    }
}

fn chrono_stamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}

fn acquire_single_instance() -> Option<HANDLE> {
    unsafe {
        let handle = CreateMutexW(None, true, w!("AvarionXNotify")).ok()?;
        if GetLastError() == ERROR_ALREADY_EXISTS {
            None
        } else {
            Some(handle)
        }
    }
}

fn main() {
    log_line("axnotify starting");
    let Some(_mutex_guard) = acquire_single_instance() else {
        log_line("another instance already running, exiting");
        return;
    };
    log_line("acquired single instance lock");
    let event_loop: EventLoop<UserEvent> = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    spawn_pipe_thread(proxy.clone());
    let mut manager = PopupManager::new();
    let mut warmed = false;
    event_loop.run(move |event, target, control_flow| {
        *control_flow = ControlFlow::Wait;
        if !warmed {
            manager.warm_up(target);
            warmed = true;
        }
        match event {
            Event::UserEvent(UserEvent::Detection(det)) => {
                manager.add(target, proxy.clone(), det);
            }
            Event::UserEvent(UserEvent::Close(id)) => {
                manager.remove(target, proxy.clone(), id);
            }
            Event::UserEvent(UserEvent::Reveal(id)) => {
                manager.reveal(id);
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                window_id,
                ..
            } => {
                manager.remove(target, proxy.clone(), window_id);
            }
            _ => {}
        }
    });
}
