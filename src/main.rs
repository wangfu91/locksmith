use std::{ffi::OsString, mem::size_of, os::windows::ffi::OsStringExt};

use windows::{
    Wdk::{
        Foundation::{
            NtQueryObject, ObjectTypeInformation, OBJECT_INFORMATION_CLASS, OBJECT_NAME_INFORMATION,
        },
        System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
    },
    Win32::{
        Foundation::{
            CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, FALSE, HANDLE,
            STATUS_INFO_LENGTH_MISMATCH,
        },
        Storage::FileSystem::{GetFileType, FILE_TYPE_DISK},
        System::{
            Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE},
            WindowsProgramming::PUBLIC_OBJECT_TYPE_INFORMATION,
        },
    },
};

fn main() {
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

        println!("nt_status: {:?}", nt_status);

        if nt_status == STATUS_INFO_LENGTH_MISMATCH {
            // STATUS_INFO_LENGTH_MISMATCH, increase the buffer size and try again.
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

    let handle_info = unsafe { &*(buffer.as_ptr() as *const SystemHandleInformationEx) };

    let handle_count = handle_info.number_of_handles;
    println!("handle_count: {}", handle_count);

    let mut offset = 2 * size_of::<usize>();

    for _ in 0..handle_count {
        let handle: SystemHandleTableEntryInfoEx = unsafe {
            std::ptr::read(buffer.as_ptr().add(offset) as *const SystemHandleTableEntryInfoEx)
        };

        offset += size_of::<SystemHandleTableEntryInfoEx>();

        //println!("handle: {:?}", handle);
        let pid = handle.unique_process_id;
        //println!("pid: {}", pid);

        // https://stackoverflow.com/questions/46384048/enumerate-handles

        let process_handle = unsafe { OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid as u32) };

        if let Err(e) = process_handle {
            //println!("OpenProcess failed, e: {:?}", e);
            continue;
        }

        let process_handle = process_handle.unwrap();

        let mut dup_handle = HANDLE::default();

        let dup_handle_result = unsafe {
            DuplicateHandle(
                process_handle,
                HANDLE(handle.handle_value as isize),
                GetCurrentProcess(),
                &mut dup_handle,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS,
            )
        };

        if let Err(e) = dup_handle_result {
            //println!("DuplicateHandle failed, e: {:?}", e);
            continue;
        }

        let mut return_length = 0u32;
        let mut object_type_info = vec![0u8; 1024];
        let nt_status = unsafe {
            NtQueryObject(
                dup_handle,
                ObjectTypeInformation,
                Some(object_type_info.as_mut_ptr() as *mut _),
                object_type_info.len() as u32,
                Some(&mut return_length),
            )
        };

        if nt_status.is_err() {
            println!("NtQueryObject failed, nt_status: {:?}", nt_status);
            let _ = unsafe { CloseHandle(dup_handle) };
            continue;
        }

        let object_type_info =
            unsafe { &*(object_type_info.as_ptr() as *const PUBLIC_OBJECT_TYPE_INFORMATION) };

        let slice = unsafe {
            std::slice::from_raw_parts(
                object_type_info.TypeName.Buffer.as_ptr(),
                object_type_info.TypeName.Length as usize / std::mem::size_of::<u16>(),
            )
        };

        let os_string = OsString::from_wide(slice);
        let object_type_name = os_string.to_string_lossy().to_string();
        //println!("pid: {}", pid);
        //println!("object_type_name: {}", object_type_name);

        if object_type_name != "File" {
            let _ = unsafe { CloseHandle(dup_handle) };
            continue;
        }

        let file_type = unsafe { GetFileType(dup_handle) };
        //println!("file_type: {:?}", file_type);
        if file_type != FILE_TYPE_DISK {
            let _ = unsafe { CloseHandle(dup_handle) };
            continue;
        }

        let ObjectNameInformation = OBJECT_INFORMATION_CLASS(1);
        let mut return_length = 0u32;
        let mut buffer = vec![0u8; 1024];

        let nt_status = unsafe {
            NtQueryObject(
                dup_handle,
                ObjectNameInformation,
                Some(buffer.as_mut_ptr() as *mut _),
                buffer.len() as u32,
                Some(&mut return_length),
            )
        };

        if nt_status.is_err() {
            println!("NtQueryObject failed, nt_status: {:?}", nt_status);
            let _ = unsafe { CloseHandle(dup_handle) };
            continue;
        }

        let object_name_info = unsafe { &*(buffer.as_ptr() as *const OBJECT_NAME_INFORMATION) };

        let slice = unsafe {
            std::slice::from_raw_parts(
                object_name_info.Name.Buffer.as_ptr(),
                object_name_info.Name.Length as usize / std::mem::size_of::<u16>(),
            )
        };
        let os_string = OsString::from_wide(slice);
        let object_name = os_string.to_string_lossy().to_string();
        println!("pid = {}, object_name: {}", pid, object_name);

        let _ = unsafe { CloseHandle(dup_handle) };
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct SystemHandleInformationEx {
    number_of_handles: usize,
    reserved: usize,
    handles: [SystemHandleTableEntryInfoEx; 1],
}

#[repr(C)]
#[derive(Debug)]
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
