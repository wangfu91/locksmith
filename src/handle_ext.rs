use std::{collections::HashMap, ffi::c_void, path::PathBuf, rc::Rc};

use crate::diagnostics::Diagnostics;
use anyhow::anyhow;
use windows::{
    Wdk::{
        Foundation::{OBJECT_INFORMATION_CLASS, OBJECT_NAME_INFORMATION, ObjectTypeInformation},
        System::SystemInformation::SYSTEM_INFORMATION_CLASS,
    },
    Win32::{
        Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE},
        Storage::FileSystem::{FILE_TYPE_DISK, GetFileType},
        System::{
            Threading::{GetCurrentProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION},
            WindowsProgramming::PUBLIC_OBJECT_TYPE_INFORMATION,
        },
    },
    core::Owned,
};

use crate::string_ext;
use crate::{nt_ext, process_ext::Process};

#[derive(Debug)]
pub struct HandleInfo {
    pub process: Rc<Process>,
    pub nt_path: PathBuf,
}

pub struct HandleScan {
    pub handles: Vec<HandleInfo>,
    pub diagnostics: Diagnostics,
}

pub fn enum_handles(kill: bool) -> anyhow::Result<HandleScan> {
    const SYSTEM_EXTENDED_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS =
        SYSTEM_INFORMATION_CLASS(64);
    let buffer = nt_ext::nt_query_information_loop(SYSTEM_EXTENDED_HANDLE_INFORMATION)?;
    let mut cache = HashMap::new();
    let mut scan = HandleScan {
        handles: Vec::new(),
        diagnostics: Diagnostics::default(),
    };
    for entry in handle_entries(&buffer)? {
        let Ok(pid) = u32::try_from(entry.unique_process_id) else {
            scan.diagnostics
                .record("Handle table contains an invalid process ID");
            continue;
        };
        let Some(process) = cached_process(&mut cache, pid, kill, &mut scan.diagnostics) else {
            continue;
        };
        match get_handle_info(entry, process) {
            Ok(Some(info)) => scan.handles.push(info),
            Ok(None) => {}
            Err(error) => scan
                .diagnostics
                .record(format!("PID {pid}: handle query failed: {error:#}")),
        }
    }
    Ok(scan)
}

fn cached_process(
    cache: &mut HashMap<u32, Option<Rc<Process>>>,
    pid: u32,
    kill: bool,
    diagnostics: &mut Diagnostics,
) -> Option<Rc<Process>> {
    cache
        .entry(pid)
        .or_insert_with(|| {
            // Query rights improve display metadata, but aren't required for duplication.
            let opened = Process::open(
                pid,
                PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                kill,
            )
            .or_else(|_| Process::open(pid, PROCESS_DUP_HANDLE, kill));
            match opened {
                Ok(process) => Some(Rc::new(process)),
                Err(error) => {
                    diagnostics.record(format!("PID {pid}: cannot open process handles: {error}"));
                    None
                }
            }
        })
        .clone()
}

fn get_handle_info(
    entry: SystemHandleTableEntryInfoEx,
    process: Rc<Process>,
) -> anyhow::Result<Option<HandleInfo>> {
    let mut duplicate = HANDLE::default();
    // SAFETY: the retained source process and output pointer are live. A stale
    // snapshot handle value can fail, but never transfers ownership of the source.
    unsafe {
        DuplicateHandle(
            process.raw(),
            HANDLE(entry.handle_value as *mut c_void),
            GetCurrentProcess(),
            &mut duplicate,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }?;
    // SAFETY: successful DuplicateHandle created a new independent owned handle.
    let duplicate = unsafe { Owned::new(duplicate) };
    if !is_handle_type_file(&duplicate)? {
        return Ok(None);
    }
    let nt_path = handle_to_nt_path(&duplicate)?;
    Ok(Some(HandleInfo { process, nt_path }))
}
pub fn is_handle_type_file(safe_file_handle: &Owned<HANDLE>) -> anyhow::Result<bool> {
    let buffer = nt_ext::nt_query_object_loop(safe_file_handle, ObjectTypeInformation)?;

    let object_type_info = unsafe {
        if buffer.len() < std::mem::size_of::<PUBLIC_OBJECT_TYPE_INFORMATION>() {
            return Err(anyhow!(
                "Buffer too small for PUBLIC_OBJECT_TYPE_INFORMATION"
            ));
        }

        std::ptr::read_unaligned(buffer.as_ptr() as *const PUBLIC_OBJECT_TYPE_INFORMATION)
    };

    let object_type_name = string_ext::from_buffer(&buffer, object_type_info.TypeName)?;
    if object_type_name != "File" {
        return Ok(false);
    }
    let file_type = unsafe { GetFileType(**safe_file_handle) };
    if file_type != FILE_TYPE_DISK {
        return Ok(false);
    }

    Ok(true)
}

pub fn handle_to_nt_path(safe_file_handle: &Owned<HANDLE>) -> anyhow::Result<PathBuf> {
    let object_name_information = OBJECT_INFORMATION_CLASS(1);
    let buffer = nt_ext::nt_query_object_loop(safe_file_handle, object_name_information)?;

    let object_name_info = unsafe {
        if buffer.len() < std::mem::size_of::<OBJECT_NAME_INFORMATION>() {
            return Err(anyhow!("Buffer too small for OBJECT_NAME_INFORMATION"));
        }

        std::ptr::read_unaligned(buffer.as_ptr() as *const OBJECT_NAME_INFORMATION)
    };

    let object_name = string_ext::from_buffer(&buffer, object_name_info.Name)?;
    Ok(PathBuf::from(object_name))
}

/// Validate the complete fixed-size table once, then iterate bounded chunks.
fn handle_entries(
    buffer: &[u8],
) -> anyhow::Result<impl Iterator<Item = SystemHandleTableEntryInfoEx> + '_> {
    const WORD: usize = std::mem::size_of::<usize>();
    const ENTRY: usize = std::mem::size_of::<SystemHandleTableEntryInfoEx>();
    let header = buffer
        .get(..2 * WORD)
        .ok_or_else(|| anyhow!("Handle table header is truncated"))?;
    let count = usize::from_ne_bytes(header[..WORD].try_into()?);
    let length = count
        .checked_mul(ENTRY)
        .ok_or_else(|| anyhow!("Handle count overflow"))?;
    let end = (2 * WORD)
        .checked_add(length)
        .ok_or_else(|| anyhow!("Handle table range overflow"))?;
    let records = buffer
        .get(2 * WORD..end)
        .ok_or_else(|| anyhow!("Handle table records are truncated"))?;
    Ok(records.as_chunks::<ENTRY>().0.iter().map(|chunk| {
        // SAFETY: a whole record is present. The C layout contains only integers
        // and opaque pointers (valid for every bit pattern), never dereferenced.
        unsafe { std::ptr::read_unaligned(chunk.as_ptr().cast::<SystemHandleTableEntryInfoEx>()) }
    }))
}
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemHandleTableEntryInfoEx {
    object: *mut ::core::ffi::c_void,
    unique_process_id: usize,
    handle_value: usize,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_cache_reuses_identity_and_reports_open_failure_once() {
        let mut cache = HashMap::new();
        let mut diagnostics = Diagnostics::default();
        let first =
            cached_process(&mut cache, std::process::id(), false, &mut diagnostics).unwrap();
        for _ in 0..100 {
            let again =
                cached_process(&mut cache, std::process::id(), false, &mut diagnostics).unwrap();
            assert!(Rc::ptr_eq(&first, &again));
            assert!(cached_process(&mut cache, u32::MAX, false, &mut diagnostics).is_none());
        }
        assert_eq!(diagnostics.failed_operations, 1);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn handle_table_validates_count_before_iterating() {
        let word = std::mem::size_of::<usize>();
        let entry_size = std::mem::size_of::<SystemHandleTableEntryInfoEx>();
        let pid_offset = std::mem::offset_of!(SystemHandleTableEntryInfoEx, unique_process_id);
        for expected in [vec![], vec![17usize], vec![17usize, 42, 99]] {
            let mut buffer = vec![0; 2 * word + expected.len() * entry_size];
            buffer[..word].copy_from_slice(&expected.len().to_ne_bytes());
            for (index, pid) in expected.iter().enumerate() {
                let offset = 2 * word + index * entry_size + pid_offset;
                buffer[offset..offset + word].copy_from_slice(&pid.to_ne_bytes());
            }
            assert_eq!(
                handle_entries(&buffer)
                    .unwrap()
                    .map(|entry| entry.unique_process_id)
                    .collect::<Vec<_>>(),
                expected
            );
            if !expected.is_empty() {
                assert!(handle_entries(&buffer[..buffer.len() - 1]).is_err());
            }
        }
        assert!(handle_entries(&[]).is_err());
        let mut overflow = vec![0; 2 * word];
        overflow[..word].copy_from_slice(&usize::MAX.to_ne_bytes());
        assert!(handle_entries(&overflow).is_err());
    }

    // cargo test test_enum_handles -- --nocapture
    #[test]
    fn test_enum_handles() {
        let handle_infos = enum_handles(false).unwrap().handles;
        assert!(!handle_infos.is_empty());

        for handle_info in handle_infos {
            println!(
                "pid={}, nt_path={}",
                handle_info.process.pid,
                handle_info.nt_path.display()
            );
        }
    }
}
