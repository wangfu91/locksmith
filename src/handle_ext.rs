use std::ffi::c_void;

use anyhow::anyhow;
use log::{debug, warn};
use windows::{
    Wdk::{
        Foundation::{ObjectTypeInformation, OBJECT_INFORMATION_CLASS, OBJECT_NAME_INFORMATION},
        System::SystemInformation::SYSTEM_INFORMATION_CLASS,
    },
    Win32::{
        Foundation::{
            DuplicateHandle, DUPLICATE_SAME_ACCESS, ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE,
            ERROR_NOT_SUPPORTED, HANDLE,
        },
        Storage::FileSystem::{GetFileType, FILE_TYPE_DISK},
        System::{
            Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE},
            WindowsProgramming::PUBLIC_OBJECT_TYPE_INFORMATION,
        },
    },
};

use crate::string_ext::ToString;
use crate::{nt_ext, safe_handle::SafeHandle};

#[derive(Debug)]
pub struct HandleInfo {
    pub pid: u32,
    pub nt_path: String,
}

pub fn enum_handles() -> anyhow::Result<Vec<HandleInfo>> {
    const SYSTEM_EXTENDED_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS =
        SYSTEM_INFORMATION_CLASS(64);

    let buffer = nt_ext::nt_query_information_loop(SYSTEM_EXTENDED_HANDLE_INFORMATION)?;

    let handle_info = unsafe {
        if buffer.len() < std::mem::size_of::<SystemHandleInformationEx>() {
            return Err(anyhow!("Buffer too small for SystemHandleInformationEx"));
        }
        std::ptr::read_unaligned(buffer.as_ptr() as *const SystemHandleInformationEx)
    };

    let handle_count = handle_info.number_of_handles;

    // Skip over the first two fields of the SystemHandleInformationEx struct.
    let mut offset = 2 * std::mem::size_of::<usize>();

    let mut handle_info_collection = Vec::with_capacity(handle_count);

    for _ in 0..handle_count {
        let handle_entry: SystemHandleTableEntryInfoEx = unsafe {
            std::ptr::read_unaligned(
                buffer.as_ptr().add(offset) as *const SystemHandleTableEntryInfoEx
            )
        };

        offset += std::mem::size_of::<SystemHandleTableEntryInfoEx>();

        if let Some(handle_info) = get_handle_info(handle_entry) {
            handle_info_collection.push(handle_info);
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
                debug!("OpenProcess failed, pid: {}, error: {:?}", pid, err);
            }
            None
        }
        Ok(process_handle) => {
            let safe_process_handle = SafeHandle::new(process_handle);
            let mut safe_dup_handle = SafeHandle::new(HANDLE::default());
            if let Err(err) = unsafe {
                DuplicateHandle(
                    safe_process_handle.handle,
                    HANDLE(handle_entry.handle_value as isize as *mut c_void),
                    GetCurrentProcess(),
                    &mut safe_dup_handle.handle,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
            } {
                if err.code() != ERROR_NOT_SUPPORTED.into()
                    && err.code() != ERROR_ACCESS_DENIED.into()
                    && err.code() != ERROR_INVALID_HANDLE.into()
                {
                    warn!("DuplicateHandle failed, pid: {}, error: {:?}", pid, err);
                }
                return None;
            }

            match is_handle_type_file(&safe_dup_handle) {
                Ok(true) => {}
                Ok(false) | Err(_) => return None,
            }

            let handle_to_nt_path_result = handle_to_nt_path(&safe_dup_handle);
            match handle_to_nt_path_result {
                Ok(nt_path) => Some(HandleInfo { pid, nt_path }),
                Err(err) => {
                    warn!("handle_to_nt_path failed, pid: {}, error: {:?}", pid, err);
                    None
                }
            }
        }
    }
}

pub fn is_handle_type_file(safe_file_handle: &SafeHandle) -> anyhow::Result<bool> {
    let buffer = nt_ext::nt_query_object_loop(safe_file_handle, ObjectTypeInformation)?;

    let object_type_info = unsafe {
        if buffer.len() < std::mem::size_of::<PUBLIC_OBJECT_TYPE_INFORMATION>() {
            return Err(anyhow!(
                "Buffer too small for PUBLIC_OBJECT_TYPE_INFORMATION"
            ));
        }

        std::ptr::read_unaligned(buffer.as_ptr() as *const PUBLIC_OBJECT_TYPE_INFORMATION)
    };

    let object_type_name = object_type_info.TypeName.to_string();
    if object_type_name != "File" {
        return Ok(false);
    }
    let file_type = unsafe { GetFileType(safe_file_handle.handle) };
    if file_type != FILE_TYPE_DISK {
        return Ok(false);
    }

    Ok(true)
}

pub fn handle_to_nt_path(safe_file_handle: &SafeHandle) -> anyhow::Result<String> {
    let object_name_information = OBJECT_INFORMATION_CLASS(1);
    let buffer = nt_ext::nt_query_object_loop(safe_file_handle, object_name_information)?;

    let object_name_info = unsafe {
        if buffer.len() < std::mem::size_of::<OBJECT_NAME_INFORMATION>() {
            return Err(anyhow!("Buffer too small for OBJECT_NAME_INFORMATION"));
        }

        std::ptr::read_unaligned(buffer.as_ptr() as *const OBJECT_NAME_INFORMATION)
    };

    let object_name = object_name_info.Name.to_string();
    Ok(object_name)
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SystemHandleInformationEx {
    number_of_handles: usize,
    reserved: usize,
    handles: [SystemHandleTableEntryInfoEx; 1],
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

    // cargo test test_enum_handles -- --nocapture
    #[test]
    fn test_enum_handles() {
        let handle_infos = enum_handles().unwrap();
        assert!(!handle_infos.is_empty());

        for handle_info in handle_infos {
            println!("pid={}, nt_path={}", handle_info.pid, handle_info.nt_path);
        }
    }
}
