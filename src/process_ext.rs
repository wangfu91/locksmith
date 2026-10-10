use anyhow::{Context, anyhow};
use std::{
    collections::HashSet,
    ffi::OsString,
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    rc::Rc,
};
use windows::{
    Win32::{
        Foundation::{
            ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NO_MORE_FILES, HANDLE, HMODULE,
        },
        Security::{
            GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
            TokenUser,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            ProcessStatus::{EnumProcessModules, GetMappedFileNameW},
            Threading::{
                OpenProcess, OpenProcessToken, PROCESS_ACCESS_RIGHTS, PROCESS_NAME_WIN32,
                PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
                PROCESS_VM_READ, QueryFullProcessImageNameW, TerminateProcess,
            },
        },
    },
    core::{Error, Owned, PWSTR},
};

use crate::{diagnostics::Diagnostics, path_ext::Target, wide_query};
#[cfg(test)]
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;

/// A process identity retained from discovery through display and termination.
/// The owning handle is private; raw copies only borrow it for system calls.
#[derive(Debug)]
pub struct Process {
    pub pid: u32,
    handle: Owned<HANDLE>,
    can_terminate: bool,
}

impl Process {
    pub fn open(
        pid: u32,
        rights: PROCESS_ACCESS_RIGHTS,
        kill: bool,
    ) -> windows::core::Result<Self> {
        let opened = if kill {
            unsafe { OpenProcess(rights | PROCESS_TERMINATE, false, pid) }.ok()
        } else {
            None
        };
        let can_terminate = opened.is_some();
        let raw = match opened {
            Some(handle) => handle,
            None => unsafe { OpenProcess(rights, false, pid) }?,
        };
        // SAFETY: only a freshly returned handle is transferred into its sole owner.
        Ok(Self {
            pid,
            handle: unsafe { Owned::new(raw) },
            can_terminate,
        })
    }

    pub fn raw(&self) -> HANDLE {
        *self.handle
    }

    pub fn image_path(&self) -> anyhow::Result<PathBuf> {
        let units = wide_query::query(|buffer| {
            let mut length = buffer.len() as u32;
            // SAFETY: retained process handle and writable UTF-16 buffer are live.
            match unsafe {
                QueryFullProcessImageNameW(
                    self.raw(),
                    PROCESS_NAME_WIN32,
                    PWSTR(buffer.as_mut_ptr()),
                    &mut length,
                )
            } {
                Ok(()) => Ok(Some(length as usize)),
                Err(error) if error.code() == ERROR_INSUFFICIENT_BUFFER.into() => Ok(None),
                Err(error) => Err(error.into()),
            }
        })?;
        Ok(PathBuf::from(OsString::from_wide(&units)))
    }

    pub fn terminate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.can_terminate,
            "Termination access was unavailable when the process was discovered"
        );
        // SAFETY: this is the same owned handle used while discovering the match.
        unsafe { TerminateProcess(self.raw(), 1) }.context("TerminateProcess failed")?;
        Ok(())
    }
}
pub struct ProcessScan {
    pub processes: Vec<Rc<Process>>,
    pub diagnostics: Diagnostics,
}

pub struct ModuleScan {
    pub matched: bool,
    pub diagnostics: Diagnostics,
}

pub fn scan_process_modules(
    target: &Target,
    already_matched: &HashSet<u32>,
    kill: bool,
) -> anyhow::Result<ProcessScan> {
    let mut scan = ProcessScan {
        processes: Vec::new(),
        diagnostics: Diagnostics::default(),
    };
    for entry in process_snapshot()? {
        let pid = entry.th32ProcessID;
        if pid == 0 || already_matched.contains(&pid) {
            continue;
        }
        let process = match Process::open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, kill) {
            Ok(process) => Rc::new(process),
            Err(error) => {
                scan.diagnostics
                    .record(format!("PID {pid}: process query failed: {error:#}"));
                continue;
            }
        };
        match enum_process_modules(&process, |path| target.matches(path)) {
            Ok(modules) => {
                scan.diagnostics.merge(modules.diagnostics);
                if modules.matched {
                    scan.processes.push(process);
                }
            }
            Err(error) => scan
                .diagnostics
                .record(format!("PID {pid}: module scan failed: {error:#}")),
        }
    }
    Ok(scan)
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

pub fn enum_process_modules(
    process: &Process,
    matches: impl FnMut(&Path) -> bool,
) -> anyhow::Result<ModuleScan> {
    let modules = query_modules(|buffer| {
        let mut needed = 0;
        // SAFETY: the live process handle and typed writable module array are valid.
        unsafe {
            EnumProcessModules(
                process.raw(),
                buffer.as_mut_ptr(),
                std::mem::size_of_val(buffer) as u32,
                &mut needed,
            )
        }?;
        Ok(needed as usize)
    })
    .context("EnumProcessModules failed")?;
    Ok(collect_module_paths(
        modules,
        |module| mapped_module_path(&process.handle, module),
        matches,
    ))
}

fn collect_module_paths(
    modules: impl IntoIterator<Item = HMODULE>,
    mut query: impl FnMut(HMODULE) -> anyhow::Result<PathBuf>,
    mut matches: impl FnMut(&Path) -> bool,
) -> ModuleScan {
    let mut scan = ModuleScan {
        matched: false,
        diagnostics: Diagnostics::default(),
    };
    for module in modules {
        match query(module) {
            Ok(path) => {
                if matches(&path) {
                    scan.matched = true;
                    break;
                }
            }
            Err(error) => scan
                .diagnostics
                .record(format!("Module path query failed: {error:#}")),
        }
    }
    scan
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
            let error = Error::from_thread();
            // Windows versions can report truncation as a zero-length failure,
            // in addition to the documented full-buffer length return.
            if error.code() == ERROR_INSUFFICIENT_BUFFER.into() {
                return Ok(None);
            }
            return Err(error.into());
        }
        Ok((length < buffer.len()).then_some(length))
    });
    match buffer {
        Ok(units) => Ok(PathBuf::from(OsString::from_wide(&units))),
        Err(error)
            if error
                .downcast_ref::<Error>()
                .is_some_and(|error| error.code() == ERROR_MORE_DATA.into()) =>
        {
            // Some PSAPI implementations use a fixed internal name buffer even
            // when the caller provides more space. Query that same mapping via
            // NT instead; never fall back to opening a foreign filename.
            crate::nt_ext::mapped_file_name(process, module.0)
                .context("Native mapped filename query failed")
        }
        Err(error) => Err(error.context("GetMappedFileNameW failed")),
    }
}

#[cfg(test)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_dll_path_is_complete_after_multiple_real_buffer_retries() {
        use std::os::windows::ffi::OsStrExt;
        use windows::{Win32::System::LibraryLoader::LoadLibraryW, core::HSTRING};
        struct TestTree(PathBuf);
        impl Drop for TestTree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root =
            std::env::temp_dir().join(format!("locksmith-long-module-{}", std::process::id()));
        // Ownership of cleanup begins only after creating a new, dedicated directory.
        std::fs::create_dir(&root).unwrap();
        let tree = TestTree(root);
        let mut directory = tree.0.canonicalize().unwrap();
        for index in 0..9 {
            directory.push(format!("层级{index}-{}", "目录".repeat(35)));
            std::fs::create_dir(&directory).unwrap();
        }
        let dll = directory.join(format!("locksmith-test-{}.dll", std::process::id()));
        let source = PathBuf::from(std::env::var_os("WINDIR").unwrap())
            .join("System32")
            .join("version.dll");
        // Load only a trusted local Windows DLL copied into our isolated test tree.
        std::fs::copy(source, &dll).unwrap();
        let raw = unsafe { LoadLibraryW(&HSTRING::from(dll.as_path())) }.unwrap();
        // SAFETY: LoadLibraryW returned a new reference, released by Owned<HMODULE>.
        let module = unsafe { Owned::new(raw) };
        let process = Process::open(
            std::process::id(),
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
        )
        .unwrap();
        let mapped = mapped_module_path(&process.handle, *module).unwrap();
        assert!(mapped.as_os_str().encode_wide().count() > 520);
        let target = Target::open(&dll).unwrap();
        assert!(target.matches(&mapped));
        let scan = enum_process_modules(&process, |path| target.matches(path)).unwrap();
        assert!(scan.matched);
        drop(target);
        drop(module);
    }

    #[test]
    fn module_queries_stop_after_first_confirmed_match() {
        let modules = [
            HMODULE(std::ptr::without_provenance_mut(17)),
            HMODULE(std::ptr::without_provenance_mut(42)),
        ];
        let mut queried = Vec::new();
        let scan = collect_module_paths(
            modules,
            |module| {
                queried.push(module.0 as usize);
                Ok(PathBuf::from("target.dll"))
            },
            |_| true,
        );
        assert!(scan.matched);
        assert_eq!(queried, [17]);
        assert_eq!(scan.diagnostics.failed_operations, 0);
    }

    #[test]
    fn termination_uses_retained_handle_not_a_pid_lookup() {
        use std::{
            os::windows::process::CommandExt,
            process::{Child, Command},
        };
        struct ChildGuard(Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = ChildGuard(
            Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Start-Sleep -Seconds 60",
                ])
                .creation_flags(0x08000000)
                .spawn()
                .unwrap(),
        );
        let mut process =
            Process::open(child.0.id(), PROCESS_QUERY_LIMITED_INFORMATION, true).unwrap();
        assert_eq!(
            process
                .image_path()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_lowercase(),
            "powershell.exe"
        );
        // Deliberately invalidate the stored PID: termination must still use the
        // original child handle, and must never try to open this sentinel PID.
        process.pid = u32::MAX;
        process.terminate().unwrap();
        assert!(!child.0.wait().unwrap().success());
    }

    #[test]
    fn module_failure_preserves_successes_and_continues() {
        let modules = [
            HMODULE(std::ptr::without_provenance_mut(1)),
            HMODULE(std::ptr::without_provenance_mut(2)),
            HMODULE(std::ptr::without_provenance_mut(3)),
        ];
        let scan = collect_module_paths(
            modules,
            |module| match module.0 as usize {
                2 => anyhow::bail!("module unloaded"),
                number => Ok(PathBuf::from(format!("module{number}.dll"))),
            },
            |path| path == Path::new("module3.dll"),
        );
        assert!(scan.matched);
        assert_eq!(scan.diagnostics.failed_operations, 1);
    }

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
            assert_eq!(
                crate::nt_ext::mapped_file_name(&process, module.0).unwrap(),
                expected
            );
        }
        assert!(mapped_module_path(&process, HMODULE::default()).is_err());
        assert!(crate::nt_ext::mapped_file_name(&process, std::ptr::null()).is_err());
    }

    #[test]
    fn live_module_scan_finds_this_executable() {
        let target = Target::open(std::env::current_exe().unwrap()).unwrap();
        let scan = scan_process_modules(&target, &HashSet::new(), false).unwrap();
        assert!(
            scan.processes
                .iter()
                .any(|process| process.pid == std::process::id())
        );
    }
}
