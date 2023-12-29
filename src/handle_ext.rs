use anyhow::anyhow;
use windows::{
    Wdk::{
        Foundation::{
            NtQueryObject, ObjectTypeInformation, OBJECT_INFORMATION_CLASS, OBJECT_NAME_INFORMATION,
        },
        System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
    },
    Win32::{
        Foundation::{
            DuplicateHandle, DUPLICATE_SAME_ACCESS, FALSE, HANDLE, MAX_PATH,
            STATUS_BUFFER_OVERFLOW, STATUS_INFO_LENGTH_MISMATCH,
        },
        Storage::FileSystem::{GetFileType, FILE_TYPE_DISK},
        System::{
            Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE},
            WindowsProgramming::PUBLIC_OBJECT_TYPE_INFORMATION,
        },
    },
};

use crate::safe_handle::SafeHandle;
use crate::to_string::ToString;

#[derive(Debug)]
pub struct HandleInfo {
    pub pid: u32,
    pub handle: SafeHandle,
    pub type_name: String,
    pub nt_path: String,
}

pub fn enum_handles() -> anyhow::Result<Vec<HandleInfo>> {
    const SYSTEM_EXTENDED_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS =
        SYSTEM_INFORMATION_CLASS(64i32);

    let mut buffer = vec![0u8; 1024 * 1024];
    let mut return_len = 0u32;

    loop {
        let nt_status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
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
            return Err(anyhow!(
                "NtQuerySystemInformation failed, nt_status: {:?}",
                nt_status
            ));
        }

        break;
    }

    let handle_info = unsafe { &*(buffer.as_ptr() as *const SystemHandleInformationEx) };
    let handle_count = handle_info.number_of_handles;
    println!("handle_count: {}", handle_count);

    let mut offset = 2 * std::mem::size_of::<usize>();

    let mut handle_info_collection = Vec::with_capacity(handle_count);

    for _ in 0..handle_count {
        let handle: SystemHandleTableEntryInfoEx = unsafe {
            std::ptr::read(buffer.as_ptr().add(offset) as *const SystemHandleTableEntryInfoEx)
        };

        offset += std::mem::size_of::<SystemHandleTableEntryInfoEx>();

        if let Some(handle_info) = process_handle_entry(handle) {
            handle_info_collection.push(handle_info);
        }
    }

    Ok(handle_info_collection)
}

pub fn process_handle_entry(handle: SystemHandleTableEntryInfoEx) -> Option<HandleInfo> {
    let pid = handle.unique_process_id as u32;

    let process_handle_result = unsafe { OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid) };
    if process_handle_result.is_err() {
        return None;
    }

    let safe_process_handle = SafeHandle::new(process_handle_result.unwrap());
    let mut safe_dup_handle = SafeHandle::new(HANDLE::default());
    let dup_handle_result = unsafe {
        DuplicateHandle(
            safe_process_handle.handle,
            HANDLE(handle.handle_value as isize),
            GetCurrentProcess(),
            &mut safe_dup_handle.handle,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS,
        )
    };

    if dup_handle_result.is_err() {
        return None;
    }

    if !is_handle_type_file(&safe_dup_handle) {
        return None;
    }

    let to_nt_path_result = handle_to_nt_path(&safe_dup_handle);

    match to_nt_path_result {
        Ok(nt_path) => Some(HandleInfo {
            pid,
            handle: safe_dup_handle,
            type_name: "File".to_string(),
            nt_path,
        }),
        Err(_e) => None,
    }
}

pub fn is_handle_type_file(safe_file_handle: &SafeHandle) -> bool {
    let mut return_length = 0u32;
    let mut buffer = vec![0u8; MAX_PATH as usize];
    loop {
        let nt_status = unsafe {
            NtQueryObject(
                safe_file_handle.handle,
                ObjectTypeInformation,
                Some(buffer.as_mut_ptr() as *mut _),
                buffer.len() as u32,
                Some(&mut return_length),
            )
        };

        if nt_status == STATUS_INFO_LENGTH_MISMATCH || nt_status == STATUS_BUFFER_OVERFLOW {
            buffer.resize(return_length as usize, 0);
            continue;
        }

        if nt_status.is_err() {
            println!("NtQueryObject failed, nt_status: {:?}", nt_status);
            return false;
        }

        break;
    }

    let object_type_info = unsafe { &*(buffer.as_ptr() as *const PUBLIC_OBJECT_TYPE_INFORMATION) };

    let object_type_name = object_type_info.TypeName.to_string();
    if object_type_name != "File" {
        return false;
    }
    let file_type = unsafe { GetFileType(safe_file_handle.handle) };
    if file_type != FILE_TYPE_DISK {
        return false;
    }

    true
}

pub fn handle_to_nt_path(safe_file_handle: &SafeHandle) -> anyhow::Result<String> {
    let object_name_information = OBJECT_INFORMATION_CLASS(1);
    let mut return_length = 0u32;
    let mut buffer = vec![0u8; MAX_PATH as usize];
    loop {
        let nt_status = unsafe {
            NtQueryObject(
                safe_file_handle.handle,
                object_name_information,
                Some(buffer.as_mut_ptr() as *mut _),
                buffer.len() as u32,
                Some(&mut return_length),
            )
        };

        if nt_status == STATUS_INFO_LENGTH_MISMATCH || nt_status == STATUS_BUFFER_OVERFLOW {
            buffer.resize(return_length as usize, 0);
            continue;
        }

        if nt_status.is_err() {
            println!("NtQueryObject failed, nt_status: {:?}", nt_status);
            return Err(anyhow!("NtQueryObject failed, nt_status: {:?}", nt_status));
        }

        break;
    }

    let object_name_info = unsafe { &*(buffer.as_ptr() as *const OBJECT_NAME_INFORMATION) };
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
