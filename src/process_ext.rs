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

use crate::safe_handle::SafeHandle;
use crate::to_string::ToString;

pub fn enum_processes() {
    let mut buffer = vec![0u8; 256 * 1024];
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
            return;
        }

        break;
    }

    let mut offset = 0usize;
    loop {
        let process: SYSTEM_PROCESS_INFORMATION = unsafe {
            std::ptr::read(buffer.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION)
        };

        if process.NextEntryOffset == 0 {
            break;
        }

        offset += process.NextEntryOffset as usize;

        let pid = process.UniqueProcessId.0;
        let process_name = process.ImageName.to_string();

        println!("pid={}, process_name={}", pid, process_name);
    }
}

pub fn pid_to_full_path(pid: u32) -> anyhow::Result<String> {
    let process_handle =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)? };
    let safe_process_handle = SafeHandle::new(process_handle);
    let mut buffer = vec![0u16; MAX_PATH as usize];
    let len = unsafe { GetModuleBaseNameW(safe_process_handle.handle, None, &mut buffer) };
    let process_name = String::from_utf16_lossy(&buffer[..len as usize]);
    Ok(process_name)
}

pub fn enum_process_modules(pid: u32) -> anyhow::Result<()> {
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

    let size_of_module = std::mem::size_of::<HMODULE>() as u32;
    let module_count = needed / size_of_module;
    for i in 0..module_count {
        let module =
            unsafe { *(buffer.as_ptr().add((i * size_of_module) as usize) as *const HMODULE) };
        let process_name = get_process_moudle_name(&safe_process_handle, module)?;
        println!("pid = {}, module: {}", pid, process_name);
    }

    Ok(())
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
