use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    TdhGetProperty, TdhGetPropertySize, CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, PROPERTY_DATA_DESCRIPTOR, TRACE_LEVEL_INFORMATION,
    WNODE_FLAG_TRACED_GUID,
};
use crate::files::monitoring::process_snapshot::{handle_candidate, should_track};
use crate::files::util::log_line;

const SESSION_NAME: &str = "AxService-PM";
const KERNEL_PROCESS_PROVIDER: GUID = GUID::from_u128(0x22FB2CD6_0E7B_422B_A0C7_2FAD1FD0E716);
const PROCESS_START_EVENT_ID: u16 = 1;
const INVALID_PROCESSTRACE_HANDLE: PROCESSTRACE_HANDLE = PROCESSTRACE_HANDLE { Value: u64::MAX };

struct EtwCtx<'a> {
    known: &'a mut HashMap<u32, (String, u32)>,
    logs_dir: &'a Path,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn get_property_bytes(event: &EVENT_RECORD, name: &str) -> Option<Vec<u8>> {
    let name_wide = wide(name);
    let mut desc = PROPERTY_DATA_DESCRIPTOR::default();
    desc.PropertyName = name_wide.as_ptr() as u64;
    desc.ArrayIndex = u32::MAX;
    let mut size = 0u32;
    if TdhGetPropertySize(event, None, &[desc], &mut size) != 0 || size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    if TdhGetProperty(event, None, &[desc], &mut buf) != 0 {
        return None;
    }
    Some(buf)
}

unsafe fn get_property_u32(event: &EVENT_RECORD, name: &str) -> Option<u32> {
    let buf = get_property_bytes(event, name)?;
    if buf.len() >= 4 {
        Some(u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]))
    } else {
        None
    }
}

unsafe fn get_property_wstring(event: &EVENT_RECORD, name: &str) -> Option<String> {
    let buf = get_property_bytes(event, name)?;
    let wide: Vec<u16> = buf
        .chunks_exact(2)
        .map(|c| u16::from_ne_bytes([c[0], c[1]]))
        .collect();
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    Some(String::from_utf16_lossy(&wide[..end]))
}

unsafe extern "system" fn event_callback(event: *mut EVENT_RECORD) {
    let event = &*event;
    if event.EventHeader.ProviderId != KERNEL_PROCESS_PROVIDER {
        return;
    }
    if event.EventHeader.EventDescriptor.Id != PROCESS_START_EVENT_ID {
        return;
    }
    if event.UserContext.is_null() {
        return;
    }
    let ctx = &mut *(event.UserContext as *mut EtwCtx);
    let pid = get_property_u32(event, "ProcessID").unwrap_or(0);
    let ppid = get_property_u32(event, "ParentProcessID").unwrap_or(0);
    let exe = get_property_wstring(event, "ImageName").unwrap_or_default();
    let name = Path::new(&exe)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent_name = ctx.known.get(&ppid).map(|(n, _)| n.clone()).unwrap_or_default();
    ctx.known.insert(pid, (name.clone(), ppid));
    if should_track(&name, &parent_name) {
        handle_candidate(pid, &name, &exe, "etw", ctx.logs_dir);
    }
}

pub fn run_etw_loop(known: &mut HashMap<u32, (String, u32)>, logs_dir: &Path) {
    unsafe {
        let session_wide = wide(SESSION_NAME);
        let struct_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let buf_size = struct_size + session_wide.len() * 2;

        let mut stop_buf = vec![0u8; buf_size];
        let stop_props = stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*stop_props).Wnode.BufferSize = buf_size as u32;
        (*stop_props).LoggerNameOffset = struct_size as u32;
        let _ = ControlTraceW(CONTROLTRACE_HANDLE::default(), PCWSTR(session_wide.as_ptr()), stop_props, EVENT_TRACE_CONTROL_STOP);

        let mut start_buf = vec![0u8; buf_size];
        let props = start_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = buf_size as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).Wnode.ClientContext = 1;
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).LoggerNameOffset = struct_size as u32;

        let mut session_handle = CONTROLTRACE_HANDLE::default();
        let start_result = StartTraceW(&mut session_handle, PCWSTR(session_wide.as_ptr()), props);
        if start_result != ERROR_SUCCESS {
            log_line(logs_dir, &format!("process monitor start failed: {:?}", start_result));
            return;
        }

        let enable_result = EnableTraceEx2(
            session_handle,
            &KERNEL_PROCESS_PROVIDER,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_INFORMATION as u8,
            0,
            0,
            0,
            None,
        );
        if enable_result != ERROR_SUCCESS {
            log_line(logs_dir, &format!("process monitor enable failed: {:?}", enable_result));
            let _ = ControlTraceW(session_handle, PCWSTR::null(), props, EVENT_TRACE_CONTROL_STOP);
            return;
        }

        let mut ctx = EtwCtx { known, logs_dir };
        let mut logger_name = session_wide.clone();
        let mut logfile = EVENT_TRACE_LOGFILEW::default();
        logfile.LoggerName = PWSTR(logger_name.as_mut_ptr());
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event_callback);
        logfile.Context = &mut ctx as *mut EtwCtx as *mut c_void;

        let trace_handle = OpenTraceW(&mut logfile);
        if trace_handle == INVALID_PROCESSTRACE_HANDLE {
            log_line(logs_dir, "process monitor open failed");
            let _ = ControlTraceW(session_handle, PCWSTR::null(), props, EVENT_TRACE_CONTROL_STOP);
            return;
        }

        let process_result = ProcessTrace(&[trace_handle], None, None);
        if process_result != ERROR_SUCCESS {
            log_line(logs_dir, &format!("process monitor ended: {:?}", process_result));
        }

        let _ = CloseTrace(trace_handle);
        let _ = ControlTraceW(session_handle, PCWSTR::null(), props, EVENT_TRACE_CONTROL_STOP);
    }
}