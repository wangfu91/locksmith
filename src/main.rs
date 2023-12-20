use std::mem::size_of;

use windows::{
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
    Win32::{
        Foundation::{FALSE, STATUS_INFO_LENGTH_MISMATCH},
        System::Threading::{OpenProcess, PROCESS_DUP_HANDLE},
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
            println!("STATUS_INFO_LENGTH_MISMATCH, double the buffer size and try again");
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

    let handle_info = unsafe { &*(buffer.as_ptr() as *const SYSTEM_HANDLE_INFORMATION_EX) };

    let handle_count = handle_info.NumberOfHandles;
    println!("handle_count: {}", handle_count);

    for i in 0..handle_count {
        let handle =
            unsafe {
                std::ptr::read(
                    handle_info.Handles.as_ptr().offset(
                        (i * size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>() as u32) as isize,
                    ) as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX,
                )
            };

        println!("handle: {:?}", handle);
        let pid = handle.UniqueProcessId;
        println!("pid: {}", pid);

        if pid == 0 {
            continue;
        }

        // https://stackoverflow.com/questions/46384048/enumerate-handles

        let process_handle = unsafe { OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid) };

        //
    }

    println!("handle_info: {:?}", handle_info);
}

#[derive(Debug)]
pub struct SYSTEM_HANDLE_INFORMATION_EX {
    pub NumberOfHandles: u32,
    pub Reserved: u32,
    pub Handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX; 1],
}

#[derive(Debug)]
pub struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    pub Object: *mut ::core::ffi::c_void,
    pub UniqueProcessId: u32,
    pub HandleValue: u32,
    pub GrantedAccess: u32,
    pub CreatorBackTraceIndex: u16,
    pub ObjectTypeIndex: u16,
    pub HandleAttributes: u32,
    pub Reserved: u32,
}
