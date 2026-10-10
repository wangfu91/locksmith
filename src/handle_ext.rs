use std::{ffi::c_void, path::PathBuf};

use anyhow::anyhow;
use log::debug;
use windows::{
    Wdk::{
        Foundation::{OBJECT_INFORMATION_CLASS, OBJECT_NAME_INFORMATION, ObjectTypeInformation},
        System::SystemInformation::SYSTEM_INFORMATION_CLASS,
    },
    Win32::{
        Foundation::{
            DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE,
            ERROR_NOT_SUPPORTED, HANDLE,
        },
        Storage::FileSystem::{FILE_TYPE_DISK, GetFileType},
        System::{
            Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE},
            WindowsProgramming::PUBLIC_OBJECT_TYPE_INFORMATION,
        },
    },
    core::Owned,
};

use crate::nt_ext;
use crate::string_ext;

#[derive(Debug)]
pub struct HandleInfo {
    pub pid: u32,
    pub nt_path: PathBuf,
}

pub fn enum_handles() -> anyhow::Result<Vec<HandleInfo>> {
    const SYSTEM_EXTENDED_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS =
        SYSTEM_INFORMATION_CLASS(64);

    let buffer = nt_ext::nt_query_information_loop(SYSTEM_EXTENDED_HANDLE_INFORMATION)?;

    let mut handle_info_collection = Vec::new();
    for entry in handle_entries(&buffer)? {
        if let Some(info) = get_handle_info(entry) {
            handle_info_collection.push(info);
        }
    }
    Ok(handle_info_collection)
}

pub fn get_handle_info(handle_entry: SystemHandleTableEntryInfoEx) -> Option<HandleInfo> {
    let pid = handle_entry.unique_process_id as u32;

    let open_process_result = unsafe { OpenProcess(PROCESS_DUP_HANDLE, false, pid) };
    match open_process_result {
        Err(err) => {
            if err.code() != ERROR_ACCESS_DENIED.into() {
                debug!("OpenProcess failed, pid: {pid}, error: {err:?}");
            }
            None
        }
        Ok(process_handle) => {
            // SAFETY: OpenProcess returned a new handle owned by this scope.
            let safe_process_handle = unsafe { Owned::new(process_handle) };
            let mut dup_handle = HANDLE::default();
            if let Err(err) = unsafe {
                DuplicateHandle(
                    *safe_process_handle,
                    HANDLE(handle_entry.handle_value as isize as *mut c_void),
                    GetCurrentProcess(),
                    &mut dup_handle,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
            } {
                if err.code() != ERROR_NOT_SUPPORTED.into()
                    && err.code() != ERROR_ACCESS_DENIED.into()
                    && err.code() != ERROR_INVALID_HANDLE.into()
                {
                    debug!("DuplicateHandle failed, pid: {pid}, error: {err:?}");
                }
                return None;
            }
            // SAFETY: successful DuplicateHandle created an independent owned handle.
            let safe_dup_handle = unsafe { Owned::new(dup_handle) };

            match is_handle_type_file(&safe_dup_handle) {
                Ok(true) => {}
                Ok(false) | Err(_) => return None,
            }

            let handle_to_nt_path_result = handle_to_nt_path(&safe_dup_handle);
            match handle_to_nt_path_result {
                Ok(nt_path) => Some(HandleInfo { pid, nt_path }),
                Err(err) => {
                    debug!("handle_to_nt_path failed, pid: {pid}, error: {err:?}");
                    None
                }
            }
        }
    }
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
        let handle_infos = enum_handles().unwrap();
        assert!(!handle_infos.is_empty());

        for handle_info in handle_infos {
            println!(
                "pid={}, nt_path={}",
                handle_info.pid,
                handle_info.nt_path.display()
            );
        }
    }
}
