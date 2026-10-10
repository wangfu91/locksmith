use std::{collections::HashMap, ffi::c_void, path::PathBuf, rc::Rc};

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
use crate::{nt_ext, path_ext::Target, process_ext::Process};

#[derive(Debug)]
pub struct HandleInfo {
    pub process: Rc<Process>,
    pub nt_path: PathBuf,
}

pub fn enum_handles(kill: bool, target: &Target) -> anyhow::Result<Vec<HandleInfo>> {
    const SYSTEM_EXTENDED_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS =
        SYSTEM_INFORMATION_CLASS(64);
    let buffer = nt_ext::nt_query_information_loop(SYSTEM_EXTENDED_HANDLE_INFORMATION)?;
    let own_pid = std::process::id() as usize;
    let target_value = target.handle().0 as usize;
    let file_type = file_object_type(handle_entries(&buffer)?, own_pid, target_value);
    let mut cache = HashMap::new();
    let mut matched = std::collections::HashSet::new();
    let mut handles = Vec::new();
    for entry in handle_entries(&buffer)? {
        if entry.unique_process_id == own_pid && entry.handle_value == target_value {
            continue; // Our target query handle is not evidence of a locker.
        }
        if !is_file_candidate(entry, file_type) {
            continue;
        }
        let Ok(pid) = u32::try_from(entry.unique_process_id) else {
            continue;
        };
        if matched.contains(&pid) {
            continue;
        }
        let Some(process) = cached_process(&mut cache, pid, kill) else {
            continue;
        };
        match get_handle_info(entry, process, file_type.is_some()) {
            Ok(Some(info)) if target.matches(&info.nt_path) => {
                matched.insert(pid);
                handles.push(info);
            }
            _ => {}
        }
    }
    Ok(handles)
}

fn cached_process(
    cache: &mut HashMap<u32, Option<Rc<Process>>>,
    pid: u32,
    kill: bool,
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
            // Inaccessible and exited processes are routine during a system scan.
            opened.ok().map(Rc::new)
        })
        .clone()
}

fn get_handle_info(
    entry: SystemHandleTableEntryInfoEx,
    process: Rc<Process>,
    known_file_type: bool,
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
    if unsafe { GetFileType(*duplicate) } != FILE_TYPE_DISK {
        return Ok(None);
    }
    if !known_file_type && !is_handle_type_file(&duplicate)? {
        return Ok(None);
    }
    let nt_path = handle_to_nt_path(&duplicate)?;
    Ok(Some(HandleInfo { process, nt_path }))
}

fn file_object_type(
    mut entries: impl Iterator<Item = SystemHandleTableEntryInfoEx>,
    own_pid: usize,
    target_value: usize,
) -> Option<u16> {
    entries
        .find(|entry| entry.unique_process_id == own_pid && entry.handle_value == target_value)
        .map(|entry| entry.object_type_index)
        .filter(|index| *index != 0)
}

fn is_file_candidate(entry: SystemHandleTableEntryInfoEx, file_type: Option<u16>) -> bool {
    file_type.is_none_or(|index| entry.object_type_index == index)
}
fn is_handle_type_file(safe_file_handle: &Owned<HANDLE>) -> anyhow::Result<bool> {
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
    Ok(object_type_name == "File")
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
#[derive(Debug, Clone, Copy, Default)]
struct SystemHandleTableEntryInfoEx {
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
    fn file_type_filter_uses_live_sample_and_has_a_fallback() {
        let file = SystemHandleTableEntryInfoEx {
            unique_process_id: 17,
            handle_value: 42,
            object_type_index: 73,
            ..Default::default()
        };
        let other = SystemHandleTableEntryInfoEx {
            object_type_index: 8,
            ..Default::default()
        };
        let index = file_object_type([other, file].into_iter(), 17, 42);
        assert_eq!(index, Some(73));
        assert!(is_file_candidate(file, index));
        assert!(!is_file_candidate(other, index));
        assert_eq!(file_object_type([other].into_iter(), 17, 42), None);
        assert!(is_file_candidate(other, None));
    }

    #[test]
    fn target_query_handle_is_excluded_but_other_own_file_handles_match() {
        let path = std::env::temp_dir().join(format!(
            "locksmith-handle-filter-{}.tmp",
            std::process::id()
        ));
        std::fs::write(&path, b"test").unwrap();
        let result = (|| {
            let target = Target::open(&path)?;
            let first = enum_handles(false, &target)?;
            assert!(!first.iter().any(
                |info| info.process.pid == std::process::id() && target.matches(&info.nt_path)
            ));
            let held = std::fs::File::open(&path)?;
            let second = enum_handles(false, &target)?;
            assert!(second.iter().any(
                |info| info.process.pid == std::process::id() && target.matches(&info.nt_path)
            ));
            drop(held);
            anyhow::Ok(())
        })();
        let cleanup = std::fs::remove_file(&path);
        result.unwrap();
        cleanup.unwrap();
    }

    #[test]
    fn process_cache_reuses_identity_and_caches_open_failures() {
        let mut cache = HashMap::new();
        let first = cached_process(&mut cache, std::process::id(), false).unwrap();
        for _ in 0..100 {
            let again = cached_process(&mut cache, std::process::id(), false).unwrap();
            assert!(Rc::ptr_eq(&first, &again));
            assert!(cached_process(&mut cache, u32::MAX, false).is_none());
        }
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
        let executable = std::env::current_exe().unwrap();
        let held = std::fs::File::open(&executable).unwrap();
        let target = Target::open(&executable).unwrap();
        let handle_infos = enum_handles(false, &target).unwrap();
        assert!(
            handle_infos
                .iter()
                .any(|info| info.process.pid == std::process::id())
        );
        assert!(
            handle_infos
                .iter()
                .all(|info| target.matches(&info.nt_path))
        );
        let unique: std::collections::HashSet<_> =
            handle_infos.iter().map(|info| info.process.pid).collect();
        assert_eq!(unique.len(), handle_infos.len());
        drop(held);
    }
}
