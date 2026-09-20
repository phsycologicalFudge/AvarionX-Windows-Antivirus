use windows::core::w;
use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
use windows::Win32::System::Threading::CreateMutexW;

pub fn acquire_single_instance() -> Option<HANDLE> {
    unsafe {
        let handle = CreateMutexW(None, true, w!("Global\\AvarionXRtpService")).ok()?;
        if GetLastError() == ERROR_ALREADY_EXISTS {
            None
        } else {
            Some(handle)
        }
    }
}
