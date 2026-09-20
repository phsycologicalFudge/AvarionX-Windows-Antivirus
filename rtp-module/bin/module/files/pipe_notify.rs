use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, ERROR_PIPE_CONNECTED};
use windows::Win32::Security::{
    InitializeSecurityDescriptor, SetSecurityDescriptorDacl, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{WriteFile, PIPE_ACCESS_OUTBOUND};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientSessionId,
    PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};

const PIPE_NAME: PCWSTR = w!("\\\\.\\pipe\\AvarionXNotify");

#[derive(Clone, Copy)]
struct SendHandle(HANDLE);

unsafe impl Send for SendHandle {}
unsafe impl Sync for SendHandle {}

const BACKLOG_CAP: usize = 32;
const BACKLOG_TTL: Duration = Duration::from_secs(30);
const MAX_INSTANCES: u32 = 255;

struct Client {
    handle: SendHandle,
    session: u32,
}

struct Pending {
    session: u32,
    at: Instant,
    payload: Vec<u8>,
}

struct State {
    clients: Vec<Client>,
    backlog: VecDeque<Pending>,
}

#[derive(Clone)]
pub struct NotifyBroadcaster {
    state: Arc<Mutex<State>>,
}

impl NotifyBroadcaster {
    fn start() -> Self {
        let state = Arc::new(Mutex::new(State {
            clients: Vec::new(),
            backlog: VecDeque::new(),
        }));
        let accept_state = state.clone();
        std::thread::spawn(move || accept_loop(accept_state));
        Self { state }
    }

    pub fn send_to_session(&self, session: u32, json_line: &str) {
        let mut payload = json_line.as_bytes().to_vec();
        payload.push(b'\n');
        let mut state = self.state.lock().unwrap();
        let mut delivered = false;
        state.clients.retain(|c| {
            if c.session != session {
                return true;
            }
            if write_to_client(c.handle.0, &payload) {
                delivered = true;
                true
            } else {
                unsafe {
                    let _ = DisconnectNamedPipe(c.handle.0);
                    let _ = CloseHandle(c.handle.0);
                }
                false
            }
        });
        if !delivered {
            state.backlog.retain(|p| p.at.elapsed() < BACKLOG_TTL);
            if state.backlog.len() == BACKLOG_CAP {
                state.backlog.pop_front();
            }
            state.backlog.push_back(Pending {
                session,
                at: Instant::now(),
                payload,
            });
        }
    }
}

static BROADCASTER: OnceLock<NotifyBroadcaster> = OnceLock::new();

pub fn broadcaster() -> &'static NotifyBroadcaster {
    BROADCASTER.get_or_init(NotifyBroadcaster::start)
}

fn write_to_client(handle: HANDLE, payload: &[u8]) -> bool {
    let mut written = 0u32;
    unsafe { WriteFile(handle, Some(payload), Some(&mut written), None).is_ok() }
}

fn build_open_security_attributes(sd: &mut SECURITY_DESCRIPTOR) -> SECURITY_ATTRIBUTES {
    unsafe {
        let sd_ptr = PSECURITY_DESCRIPTOR(sd as *mut _ as *mut c_void);
        let _ = InitializeSecurityDescriptor(sd_ptr, 1);
        let _ = SetSecurityDescriptorDacl(sd_ptr, true, None, false);
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd_ptr.0,
            bInheritHandle: false.into(),
        }
    }
}

fn close_pipe(handle: HANDLE) {
    unsafe {
        let _ = DisconnectNamedPipe(handle);
        let _ = CloseHandle(handle);
    }
}

fn accept_loop(state: Arc<Mutex<State>>) {
    loop {
        let mut sd = SECURITY_DESCRIPTOR::default();
        let sa = build_open_security_attributes(&mut sd);
        let handle = unsafe {
            CreateNamedPipeW(
                PIPE_NAME,
                PIPE_ACCESS_OUTBOUND,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                MAX_INSTANCES,
                4096,
                4096,
                0,
                Some(&sa),
            )
        };
        if handle.is_invalid() {
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }
        let connect_result = unsafe { ConnectNamedPipe(handle, None) };
        let connected = connect_result.is_ok() || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        if !connected {
            unsafe {
                let _ = CloseHandle(handle);
            }
            continue;
        }
        let mut session = 0u32;
        if unsafe { GetNamedPipeClientSessionId(handle, &mut session) }.is_err() {
            close_pipe(handle);
            continue;
        }
        let mut st = state.lock().unwrap();
        st.backlog.retain(|p| p.at.elapsed() < BACKLOG_TTL);
        let mut ok = true;
        let mut kept = VecDeque::new();
        while let Some(p) = st.backlog.pop_front() {
            if p.session == session {
                if ok && !write_to_client(handle, &p.payload) {
                    ok = false;
                }
            } else {
                kept.push_back(p);
            }
        }
        st.backlog = kept;
        if ok {
            st.clients.push(Client {
                handle: SendHandle(handle),
                session,
            });
        } else {
            close_pipe(handle);
        }
    }
}
