use anyhow::anyhow;
use windows::{
    Wdk::{
        Foundation::{NtQueryObject, OBJECT_INFORMATION_CLASS},
        System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
    },
    Win32::Foundation::{MAX_PATH, STATUS_BUFFER_OVERFLOW, STATUS_INFO_LENGTH_MISMATCH},
};

use crate::safe_handle::SafeHandle;

pub fn nt_query_information_loop(
    sys_info_class: SYSTEM_INFORMATION_CLASS,
) -> anyhow::Result<Vec<u8>> {
    let mut buffer = vec![0u8; 1024 * 1024];

    loop {
        let mut return_len = 0u32;
        let nt_status = unsafe {
            NtQuerySystemInformation(
                sys_info_class,
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

    Ok(buffer)
}

pub fn nt_query_object_loop(
    safe_handle: &SafeHandle,
    obj_info_class: OBJECT_INFORMATION_CLASS,
) -> anyhow::Result<Vec<u8>> {
    let mut buffer = vec![0u8; MAX_PATH as usize];

    loop {
        let mut return_len = 0u32;
        let nt_status = unsafe {
            NtQueryObject(
                Some(safe_handle.handle),
                obj_info_class,
                Some(buffer.as_mut_ptr() as *mut _),
                buffer.len() as u32,
                Some(&mut return_len),
            )
        };

        if nt_status == STATUS_INFO_LENGTH_MISMATCH || nt_status == STATUS_BUFFER_OVERFLOW {
            buffer.resize(return_len as usize, 0);
            continue;
        }

        if nt_status.is_err() {
            return Err(anyhow!("NtQueryObject failed, nt_status: {:?}", nt_status));
        }

        break;
    }

    Ok(buffer)
}
