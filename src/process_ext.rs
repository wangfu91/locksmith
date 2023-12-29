use anyhow::anyhow;
use windows::{
    core::Error,
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation},
    Win32::{
        Foundation::{FALSE, HMODULE, MAX_PATH, STATUS_INFO_LENGTH_MISMATCH},
        System::{
            ProcessStatus::{EnumProcessModules, GetModuleBaseNameW, GetModuleFileNameExW},
            Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
            WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
        },
    },
};

use crate::to_string::ToString;
use crate::{path_ext::win32_path_to_nt_path, safe_handle::SafeHandle};

pub struct ProcessInfo {
    pub pid: u32,
    pub process_name: String,
    pub process_full_path: String,
    pub modules: Vec<String>,
}

pub fn enum_processes() -> anyhow::Result<Vec<ProcessInfo>> {
    let mut buffer = vec![0u8; 512 * 1024];
    let mut return_len = 0u32;

    loop {
        let nt_status = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut return_len,
            )
        };

        if nt_status == STATUS_INFO_LENGTH_MISMATCH {
            buffer.resize(return_len as usize, 0);
            continue;
        }

        if nt_status.is_err() {
            println!(
                "NtQuerySystemInformation failed, nt_status: {:?}",
                nt_status
            );
            return Err(anyhow!(
                "NtQuerySystemInformation failed, nt_status: {:?}",
                nt_status
            ));
        }

        break;
    }

    let mut process_info_collection = Vec::<ProcessInfo>::new();

    let mut offset = 0usize;
    loop {
        let process_info: SYSTEM_PROCESS_INFORMATION = unsafe {
            std::ptr::read(buffer.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION)
        };

        if process_info.NextEntryOffset == 0 {
            break;
        }

        offset += process_info.NextEntryOffset as usize;

        let pid = process_info.UniqueProcessId.0 as u32;
        let process_name = process_info.ImageName.to_string();

        let process_full_path =
            pid_to_process_full_path(pid).unwrap_or_else(|_| "unknown".to_string());

        let module_nt_paths = enum_process_modules(pid).unwrap_or_else(|_| Vec::new());

        let process_info = ProcessInfo {
            pid,
            process_name,
            process_full_path,
            modules: module_nt_paths,
        };

        process_info_collection.push(process_info);
    }

    Ok(process_info_collection)
}

pub fn pid_to_process_name(pid: u32) -> anyhow::Result<String> {
    let process_handle =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)? };
    let safe_process_handle = SafeHandle::new(process_handle);
    let mut buffer = vec![0u16; MAX_PATH as usize];
    let len = unsafe { GetModuleBaseNameW(safe_process_handle.handle, None, &mut buffer) };
    let process_name = String::from_utf16_lossy(&buffer[..len as usize]);
    Ok(process_name)
}

pub fn pid_to_process_full_path(pid: u32) -> anyhow::Result<String> {
    let process_handle =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)? };
    let safe_process_handle = SafeHandle::new(process_handle);
    let mut buffer = vec![0u16; MAX_PATH as usize];
    let len = unsafe { GetModuleFileNameExW(safe_process_handle.handle, None, &mut buffer) };
    let process_full_path = String::from_utf16_lossy(&buffer[..len as usize]);
    Ok(process_full_path)
}

pub fn enum_process_modules(pid: u32) -> anyhow::Result<Vec<String>> {
    // https://learn.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes
    let process_handle =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)? };
    let safe_process_handle = SafeHandle::new(process_handle);
    let mut buffer = vec![0u8; MAX_PATH as usize];
    let mut needed = 0u32;
    loop {
        let result = unsafe {
            EnumProcessModules(
                safe_process_handle.handle,
                buffer.as_mut_ptr() as _,
                buffer.len() as u32,
                &mut needed,
            )
        };

        if result.is_err() {
            return Err(anyhow!(
                "EnumProcessModules failed with error: {:?}",
                result
            ));
        }

        if (needed as usize) > buffer.len() {
            buffer.resize(needed as usize, 0);
            continue;
        }

        break;
    }

    let size_of_single_module = std::mem::size_of::<HMODULE>() as u32;
    let module_count = needed / size_of_single_module;

    let mut moudle_nt_path_collection = Vec::<String>::with_capacity(module_count as usize);

    for i in 0..module_count {
        let module = unsafe {
            *(buffer.as_ptr().add((i * size_of_single_module) as usize) as *const HMODULE)
        };
        let module_name = get_process_moudle_name(&safe_process_handle, module)?;
        let module_nt_path = win32_path_to_nt_path(module_name)?;
        moudle_nt_path_collection.push(module_nt_path);
    }

    Ok(moudle_nt_path_collection)
}

pub fn get_process_moudle_name(
    safe_process_handle: &SafeHandle,
    module: HMODULE,
) -> anyhow::Result<String> {
    let mut buffer = vec![0u16; MAX_PATH as usize];

    let actual_length =
        unsafe { GetModuleFileNameExW(safe_process_handle.handle, module, &mut buffer) };

    if actual_length == 0 {
        return Err(anyhow!(
            "GetModuleFileNameExW failed, error: {}",
            Error::from_win32()
        ));
    }
    let process_name = String::from_utf16_lossy(&buffer[..actual_length as usize]);
    Ok(process_name)
}
