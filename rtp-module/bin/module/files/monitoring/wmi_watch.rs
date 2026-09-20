use std::collections::HashMap;
use std::path::Path;
use windows::core::{w, BSTR, HSTRING, IUnknown, Interface, VARIANT};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoSetProxyBlanket, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Wmi::{IWbemClassObject, IWbemLocator, IWbemServices, WbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY};
use crate::files::monitoring::process_snapshot::{handle_candidate, should_track};
use crate::files::util::log_line;

fn get_prop_string(obj: &IWbemClassObject, prop: &str) -> Option<String> {
    unsafe {
        let mut val = VARIANT::default();
        let wide = HSTRING::from(prop);
        if obj.Get(&wide, 0, &mut val, Some(std::ptr::null_mut()), Some(std::ptr::null_mut())).is_err() {
            return None;
        }
        BSTR::try_from(&val).ok().map(|b| b.to_string())
    }
}

fn get_prop_u32(obj: &IWbemClassObject, prop: &str) -> Option<u32> {
    unsafe {
        let mut val = VARIANT::default();
        let wide = HSTRING::from(prop);
        if obj.Get(&wide, 0, &mut val, Some(std::ptr::null_mut()), Some(std::ptr::null_mut())).is_err() {
            return None;
        }
        u32::try_from(&val).ok()
    }
}

pub fn run_wmi_loop(known: &mut HashMap<u32, (String, u32)>, logs_dir: &Path) {
    unsafe {
        if CoInitializeEx(None, COINIT_MULTITHREADED).is_err() {
            log_line(logs_dir, "wmi CoInitializeEx failed");
            return;
        }
        let _ = CoInitializeSecurity(None, -1, None, None, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, None, EOAC_NONE, None);
        let locator: IWbemLocator = match CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) {
            Ok(l) => l,
            Err(e) => {
                log_line(logs_dir, &format!("wmi locator failed: {:?}", e));
                return;
            }
        };
        let services: IWbemServices = match locator.ConnectServer(&BSTR::from("ROOT\\CIMV2"), &BSTR::new(), &BSTR::new(), &BSTR::new(), 0, &BSTR::new(), None) {
            Ok(s) => s,
            Err(e) => {
                log_line(logs_dir, &format!("wmi connect failed: {:?}", e));
                return;
            }
        };
        let _ = CoSetProxyBlanket(&services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, None, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, None, EOAC_NONE);
        let query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'";
        let enumerator = match services.ExecNotificationQuery(&BSTR::from("WQL"), &BSTR::from(query), WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, None) {
            Ok(e) => e,
            Err(e) => {
                log_line(logs_dir, &format!("wmi query failed: {:?}", e));
                return;
            }
        };
        loop {
            let mut objects: [Option<IWbemClassObject>; 1] = [None];
            let mut returned = 0u32;
            let _ = enumerator.Next(1000, &mut objects, &mut returned);
            if returned == 0 {
                continue;
            }
            let Some(obj) = &objects[0] else { continue };
            let mut target = VARIANT::default();
            if obj.Get(w!("TargetInstance"), 0, &mut target, Some(std::ptr::null_mut()), Some(std::ptr::null_mut())).is_err() {
                continue;
            }
            let instance: IWbemClassObject = match IUnknown::try_from(&target).ok().and_then(|u| u.cast().ok()) {
                Some(i) => i,
                None => continue,
            };
            let pid = get_prop_u32(&instance, "ProcessId").unwrap_or(0);
            let ppid = get_prop_u32(&instance, "ParentProcessId").unwrap_or(0);
            let name = get_prop_string(&instance, "Name").unwrap_or_default();
            let exe = get_prop_string(&instance, "ExecutablePath").unwrap_or_default();
            let parent_name = known.get(&ppid).map(|(n, _)| n.clone()).unwrap_or_default();
            known.insert(pid, (name.clone(), ppid));
            if should_track(&name, &parent_name) {
                handle_candidate(pid, &name, &exe, "wmi", logs_dir);
            }
        }
    }
}
