use anyhow::{Context, anyhow};
use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf};
use windows::{
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES, HANDLE, HMODULE, MAX_PATH},
        Security::{
            GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
            TokenUser,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            ProcessStatus::{
                EnumProcessModules, GetMappedFileNameW, GetModuleBaseNameW, GetModuleFileNameExW,
            },
            Threading::{
                OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_READ,
                TerminateProcess,
            },
        },
    },
    core::{Error, Owned, PWSTR},
};

use crate::wide_query;

pub struct ProcessInfo {
    pub pid: u32,
    pub process_name: OsString,
    pub process_full_path: PathBuf,
    pub modules: Vec<PathBuf>,
}

pub fn enum_processes() -> anyhow::Result<Vec<ProcessInfo>> {
    let mut process_info_collection = Vec::<ProcessInfo>::new();
    for entry in process_snapshot()? {
        let pid = entry.th32ProcessID;
        let name_len = entry
            .szExeFile
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(entry.szExeFile.len());
        let process_name = OsString::from_wide(&entry.szExeFile[..name_len]);

        let process_full_path =
            pid_to_process_full_path(pid).unwrap_or_else(|_| PathBuf::from("unknown"));

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

pub fn process_snapshot() -> anyhow::Result<Vec<PROCESSENTRY32W>> {
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };
    // SAFETY: the successful snapshot call creates a fresh owned handle.
    let snapshot = unsafe { Owned::new(raw) };
    let mut first = true;
    collect_snapshot(|entry| {
        if std::mem::replace(&mut first, false) {
            unsafe { Process32FirstW(*snapshot, entry) }
        } else {
            unsafe { Process32NextW(*snapshot, entry) }
        }
    })
}

fn collect_snapshot(
    mut next: impl FnMut(&mut PROCESSENTRY32W) -> windows::core::Result<()>,
) -> anyhow::Result<Vec<PROCESSENTRY32W>> {
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut entries = Vec::new();
    loop {
        match next(&mut entry) {
            Ok(()) => entries.push(entry),
            Err(error) if error.code() == ERROR_NO_MORE_FILES.into() => return Ok(entries),
            Err(error) => return Err(error.into()),
        }
    }
}

pub fn enum_process_modules(pid: u32) -> anyhow::Result<Vec<PathBuf>> {
    // https://learn.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes
    let process_handle =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)? };
    // SAFETY: OpenProcess returned a fresh handle; ownership transfers to this scope.
    let safe_process_handle = unsafe { Owned::new(process_handle) };
    let modules = query_modules(|buffer| {
        let mut needed = 0;
        // SAFETY: the live process handle and typed writable module array are valid.
        unsafe {
            EnumProcessModules(
                *safe_process_handle,
                buffer.as_mut_ptr(),
                std::mem::size_of_val(buffer) as u32,
                &mut needed,
            )
        }?;
        Ok(needed as usize)
    })
    .context("EnumProcessModules failed")?;
    modules
        .into_iter()
        .map(|module| mapped_module_path(&safe_process_handle, module))
        .collect()
}

fn query_modules(
    mut query: impl FnMut(&mut [HMODULE]) -> anyhow::Result<usize>,
) -> anyhow::Result<Vec<HMODULE>> {
    const MAX_MODULES: usize = 65_536;
    let mut modules = vec![HMODULE::default(); 128];
    for _ in 0..8 {
        let bytes = query(&mut modules)?;
        anyhow::ensure!(
            bytes.is_multiple_of(std::mem::size_of::<HMODULE>()),
            "Module list returned a partial record"
        );
        let count = bytes / std::mem::size_of::<HMODULE>();
        anyhow::ensure!(
            count <= MAX_MODULES,
            "Module list exceeds the capacity limit"
        );
        if count <= modules.len() {
            modules.truncate(count);
            return Ok(modules);
        }
        let next = count
            .saturating_add(count / 4)
            .max(modules.len() * 2)
            .min(MAX_MODULES);
        modules.try_reserve_exact(next - modules.len())?;
        modules.resize(next, HMODULE::default());
    }
    anyhow::bail!("Module list exceeded the retry limit")
}
/// Ask for the existing mapping's name; never reopen a foreign loader path.
fn mapped_module_path(process: &Owned<HANDLE>, module: HMODULE) -> anyhow::Result<PathBuf> {
    let buffer = wide_query::query(|buffer| {
        // SAFETY: the process handle is live; the API queries the remote address,
        // rather than dereferencing it in this process. The output slice is valid.
        let length = unsafe { GetMappedFileNameW(**process, module.0, buffer) } as usize;
        if length == 0 {
            return Err(Error::from_thread().into());
        }
        Ok((length < buffer.len()).then_some(length))
    })
    .context("GetMappedFileNameW failed")?;
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

fn get_module_name(
    safe_process_handle: &Owned<HANDLE>,
    module: Option<HMODULE>,
) -> anyhow::Result<PathBuf> {
    let buffer = wide_query::query(|buffer| {
        let length =
            unsafe { GetModuleFileNameExW(Some(**safe_process_handle), module, buffer) } as usize;
        if length == 0 {
            return Err(Error::from_thread().into());
        }
        Ok((length < buffer.len()).then_some(length))
    })
    .context("GetModuleFileNameExW failed")?;
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

pub fn _pid_to_user(pid: u32) -> anyhow::Result<(String, String)> {
    let open_process_result = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
    let process_handle = match open_process_result {
        Ok(handle) => handle,
        Err(err) => {
            return Err(anyhow!("OpenProcess failed, pid: {}, error: {}", pid, err));
        }
    };

    // SAFETY: OpenProcess returned a fresh handle owned exclusively here.
    let safe_process = unsafe { Owned::new(process_handle) };

    let mut token = Default::default();
    unsafe { OpenProcessToken(*safe_process, TOKEN_QUERY, &mut token)? }
    // SAFETY: successful OpenProcessToken returned a new owned token handle.
    let safe_token = unsafe { Owned::new(token) };

    // Get required buffer size
    let mut token_size = 0u32;
    if let Err(err) =
        unsafe { GetTokenInformation(*safe_token, TokenUser, None, 0, &mut token_size) }
        && err.code() != ERROR_INSUFFICIENT_BUFFER.into()
    {
        return Err(anyhow!("GetTokenInformation failed with error: {:?}", err));
    }

    // Allocate buffer and get token information
    let mut token_buffer = vec![0u8; token_size as usize];
    unsafe {
        GetTokenInformation(
            *safe_token,
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
    } && err.code() != ERROR_INSUFFICIENT_BUFFER.into()
    {
        return Err(anyhow!("LookupAccountSidW failed with error: {:?}", err));
    }

    // Allocate buffers and get user and domain
    let mut user_buffer = vec![0u16; user_size as usize];
    let mut domain_buffer = vec![0u16; domain_size as usize];
    unsafe {
        LookupAccountSidW(
            None,
            psid,
            Some(PWSTR(user_buffer.as_mut_ptr())),
            &mut user_size,
            Some(PWSTR(domain_buffer.as_mut_ptr())),
            &mut domain_size,
            &mut sid_name_use,
        )
        .with_context(|| "LookupAccountSidW failed")?
    };

    let user = String::from_utf16_lossy(&user_buffer[..user_size as usize]);
    let domain = String::from_utf16_lossy(&domain_buffer[..domain_size as usize]);

    Ok((user, domain))
}

pub fn pid_to_process_name(pid: u32) -> anyhow::Result<OsString> {
    let process_handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )?
    };
    // SAFETY: OpenProcess returned a fresh handle; ownership transfers to this scope.
    let safe_process_handle = unsafe { Owned::new(process_handle) };

    let mut buffer = vec![0u16; MAX_PATH as usize];
    let actual_len = unsafe { GetModuleBaseNameW(*safe_process_handle, None, &mut buffer) };

    if actual_len == 0 {
        return Err(anyhow!(
            "GetModuleBaseNameW failed, error: {}",
            Error::from_thread()
        ));
    }

    let process_name = OsString::from_wide(&buffer[..actual_len as usize]);
    Ok(process_name)
}

pub fn pid_to_process_full_path(pid: u32) -> anyhow::Result<PathBuf> {
    let process_handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )?
    };
    // SAFETY: OpenProcess returned a fresh handle; ownership transfers to this scope.
    let safe_process_handle = unsafe { Owned::new(process_handle) };

    get_module_name(&safe_process_handle, None)
}

pub fn kill_process_by_pid(pid: u32) -> anyhow::Result<()> {
    let process_handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid)? };
    // SAFETY: OpenProcess returned a fresh handle; ownership transfers to this scope.
    let safe_process_handle = unsafe { Owned::new(process_handle) };

    unsafe {
        TerminateProcess(*safe_process_handle, 1)
            .context(format!("Failed to terminate process with PID: {pid}"))?
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_module_array_retries_and_rejects_bad_lengths() {
        let mut attempts = 0;
        let modules = query_modules(|buffer| {
            attempts += 1;
            if attempts == 1 {
                return Ok(512 * std::mem::size_of::<HMODULE>());
            }
            buffer[0] = HMODULE(17usize as *mut _);
            buffer[1] = HMODULE(99usize as *mut _);
            Ok(2 * std::mem::size_of::<HMODULE>())
        })
        .unwrap();
        assert_eq!(
            modules
                .iter()
                .map(|module| module.0 as usize)
                .collect::<Vec<_>>(),
            [17, 99]
        );
        assert_eq!(attempts, 2);
        assert!(query_modules(|_| Ok(1)).is_err());
        assert!(query_modules(|_| Ok(usize::MAX)).is_err());
        assert!(query_modules(|_| Ok(0)).unwrap().is_empty());
    }

    #[test]
    fn snapshot_retains_single_first_and_last_entries() {
        for expected in [vec![17], vec![17, 42, 99]] {
            let mut ids = expected.iter();
            let entries = collect_snapshot(|entry| match ids.next() {
                Some(&pid) => {
                    entry.th32ProcessID = pid;
                    Ok(())
                }
                None => Err(Error::from_hresult(ERROR_NO_MORE_FILES.into())),
            })
            .unwrap();
            assert_eq!(
                entries
                    .iter()
                    .map(|entry| entry.th32ProcessID)
                    .collect::<Vec<_>>(),
                expected
            );
        }
        assert!(
            collect_snapshot(|_| Err(Error::from_hresult(
                windows::Win32::Foundation::ERROR_ACCESS_DENIED.into()
            )))
            .is_err()
        );
    }

    #[test]
    fn live_snapshot_includes_this_process() {
        assert!(
            process_snapshot()
                .unwrap()
                .iter()
                .any(|entry| entry.th32ProcessID == std::process::id())
        );
    }

    #[test]
    fn mapped_executable_and_dll_match_existing_file_names() {
        let pid = std::process::id();
        let raw = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
            .unwrap();
        // SAFETY: the successful call returned a new owned process handle.
        let process = unsafe { Owned::new(raw) };
        let mut modules = [HMODULE::default(); 1024];
        let mut needed = 0;
        unsafe {
            EnumProcessModules(
                *process,
                modules.as_mut_ptr(),
                std::mem::size_of_val(&modules) as u32,
                &mut needed,
            )
        }
        .unwrap();
        assert!(needed as usize <= std::mem::size_of_val(&modules));
        let modules = &modules[..needed as usize / std::mem::size_of::<HMODULE>()];
        assert!(modules.len() >= 2);
        for &module in modules.iter().take(2) {
            let loader_path = get_module_name(&process, Some(module)).unwrap();
            // This control explicitly opens our own known executable/DLL, not a foreign path.
            let expected = crate::path_ext::win32_path_to_nt_path(loader_path).unwrap();
            assert_eq!(mapped_module_path(&process, module).unwrap(), expected);
        }
        assert!(mapped_module_path(&process, HMODULE::default()).is_err());
    }

    // cargo test test_enum_processes -- --nocapture
    #[test]
    fn test_enum_processes() {
        let process_infos = enum_processes().unwrap();
        assert!(!process_infos.is_empty());

        for process_info in process_infos {
            println!("pid: {}", process_info.pid);
            println!("name: {}", process_info.process_name.to_string_lossy());
            println!("path: {}", process_info.process_full_path.display());
            for module in process_info.modules {
                println!("\tmodule: {}", module.display());
            }
            println!();
        }
    }
}
