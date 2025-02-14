use anyhow::{anyhow, Context};
use windows::{
    core::{Error, PWSTR},
    Wdk::System::SystemInformation::SystemProcessInformation,
    Win32::{
        Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, HMODULE, MAX_PATH},
        Security::{
            GetTokenInformation, LookupAccountSidW, TokenUser, SID_NAME_USE, TOKEN_QUERY,
            TOKEN_USER,
        },
        System::{
            ProcessStatus::{EnumProcessModules, GetModuleBaseNameW, GetModuleFileNameExW},
            Threading::{
                OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
            },
            WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
        },
    },
};

use crate::safe_handle::SafeHandle;
use crate::{nt_ext, path_ext, string_ext::ToString};

pub struct ProcessInfo {
    pub pid: u32,
    pub process_name: String,
    pub process_full_path: String,
    pub modules: Vec<String>,
}

pub fn enum_processes() -> anyhow::Result<Vec<ProcessInfo>> {
    let buffer = nt_ext::nt_query_information_loop(SystemProcessInformation)?;

    let mut process_info_collection = Vec::<ProcessInfo>::new();

    let mut offset = 0usize;
    loop {
        let process_info: SYSTEM_PROCESS_INFORMATION = unsafe {
            std::ptr::read_unaligned(
                buffer.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION
            )
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

pub fn enum_process_modules(pid: u32) -> anyhow::Result<Vec<String>> {
    // https://learn.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes
    let process_handle =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)? };
    let safe_process_handle = SafeHandle::new(process_handle);
    let mut buffer = vec![0u8; MAX_PATH as usize];

    let mut size_needed = 0u32;
    loop {
        if let Err(err) = unsafe {
            EnumProcessModules(
                safe_process_handle.handle,
                buffer.as_mut_ptr() as _,
                buffer.len() as u32,
                &mut size_needed,
            )
        } {
            return Err(anyhow!("EnumProcessModules failed with error: {:?}", err));
        }

        if (size_needed as usize) > buffer.len() {
            buffer.resize(size_needed as usize, 0);
            continue;
        }

        break;
    }

    let size_of_single_module = std::mem::size_of::<HMODULE>() as u32;
    let module_count = size_needed / size_of_single_module;

    let mut moudle_nt_path_collection = Vec::<String>::with_capacity(module_count as usize);

    for i in 0..module_count {
        let module = unsafe {
            std::ptr::read_unaligned(
                buffer.as_ptr().add((i * size_of_single_module) as usize) as *const HMODULE
            )
        };
        let module_name = get_moudle_name(&safe_process_handle, Some(module))?;
        let module_nt_path = path_ext::win32_path_to_nt_path(module_name)?;
        moudle_nt_path_collection.push(module_nt_path);
    }

    Ok(moudle_nt_path_collection)
}

fn get_moudle_name(
    safe_process_handle: &SafeHandle,
    module: Option<HMODULE>,
) -> anyhow::Result<String> {
    let mut buffer = vec![0u16; MAX_PATH as usize];

    let actual_len =
        unsafe { GetModuleFileNameExW(Some(safe_process_handle.handle), module, &mut buffer) };

    if ERROR_INSUFFICIENT_BUFFER == unsafe { GetLastError() } {
        // Plus one for the null terminator.
        buffer.resize((actual_len + 1) as usize, 0);
        unsafe { GetModuleFileNameExW(Some(safe_process_handle.handle), module, &mut buffer) };
    }

    if actual_len == 0 {
        return Err(anyhow!(
            "GetModuleFileNameExW failed, error: {}",
            Error::from_win32()
        ));
    }

    let module_name = String::from_utf16_lossy(&buffer);
    Ok(module_name)
}

pub fn _pid_to_user(pid: u32) -> anyhow::Result<(String, String)> {
    let open_process_result = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
    let process_handle = match open_process_result {
        Ok(handle) => handle,
        Err(err) => {
            return Err(anyhow!(
                "OpenProcess failed, pid: {}, error: {}",
                pid,
                err.to_string()
            ));
        }
    };

    let safe_process = SafeHandle::new(process_handle);

    let mut token = Default::default();
    unsafe { OpenProcessToken(safe_process.handle, TOKEN_QUERY, &mut token)? }
    let safe_token = SafeHandle::new(token);

    // Get required buffer size
    let mut token_size = 0u32;
    if let Err(err) =
        unsafe { GetTokenInformation(safe_token.handle, TokenUser, None, 0, &mut token_size) }
    {
        if err.code() != ERROR_INSUFFICIENT_BUFFER.into() {
            return Err(anyhow!("GetTokenInformation failed with error: {:?}", err));
        }
    }

    // Allocate buffer and get token information
    let mut token_buffer = vec![0u8; token_size as usize];
    unsafe {
        GetTokenInformation(
            safe_token.handle,
            TokenUser,
            Some(token_buffer.as_mut_ptr() as _),
            token_size,
            &mut token_size,
        )
        .with_context(|| "GetTokenInformation failed")?
    };
    let token_user =
        unsafe { std::ptr::read_unaligned(token_buffer.as_ptr() as *const TOKEN_USER) };
    let psid = token_user.User.Sid;

    // Get required buffer sizes for user and domain
    let mut user_size = 0u32;
    let mut domain_size = 0u32;
    let mut sid_name_use = SID_NAME_USE::default();
    if let Err(err) = unsafe {
        LookupAccountSidW(
            None,
            psid,
            None,
            &mut user_size,
            None,
            &mut domain_size,
            &mut sid_name_use,
        )
    } {
        if err.code() != ERROR_INSUFFICIENT_BUFFER.into() {
            return Err(anyhow!("LookupAccountSidW failed with error: {:?}", err));
        }
    }

    // Allocate buffers and get user/domain names
    let mut user_buffer = vec![0u16; user_size as usize];
    let mut domain_buffer = vec![0u16; domain_size as usize];

    unsafe {
        LookupAccountSidW(
            None,
            psid,
            Some(PWSTR::from_raw(user_buffer.as_mut_ptr())),
            &mut user_size,
            Some(PWSTR::from_raw(domain_buffer.as_mut_ptr())),
            &mut domain_size,
            &mut sid_name_use,
        )?
    }

    let domain_name = String::from_utf16_lossy(&domain_buffer[..domain_size as usize]);
    let user_name = String::from_utf16_lossy(&user_buffer[..user_size as usize]);

    Ok((domain_name, user_name))
}

pub fn pid_to_process_name(pid: u32) -> anyhow::Result<String> {
    let process_handle =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)? };
    let safe_process_handle = SafeHandle::new(process_handle);
    let mut buffer = vec![0u16; MAX_PATH as usize];
    let len = unsafe { GetModuleBaseNameW(safe_process_handle.handle, None, &mut buffer) };
    if len == 0 {
        return Err(anyhow!(
            "GetModuleBaseNameW failed, error: {}",
            Error::from_win32()
        ));
    }
    let process_name = String::from_utf16_lossy(&buffer[..len as usize]);
    Ok(process_name)
}

pub fn pid_to_process_full_path(pid: u32) -> anyhow::Result<String> {
    let process_handle =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)? };
    let safe_process_handle = SafeHandle::new(process_handle);

    let process_full_path = get_moudle_name(&safe_process_handle, None)?;
    Ok(process_full_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // cargo test test_enum_processes -- --nocapture
    #[test]
    fn test_enum_processes() {
        let process_infos = enum_processes().unwrap();
        assert!(!process_infos.is_empty());

        for process_info in process_infos {
            println!("pid: {}", process_info.pid);
            println!("name: {}", process_info.process_name);
            println!("path: {}", process_info.process_full_path);
            for module in process_info.modules {
                println!("\tmodule: {}", module);
            }
            println!();
        }
    }
}
