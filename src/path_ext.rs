use anyhow::anyhow;
use windows::{
    core::HSTRING,
    Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            CreateFileW, GetFileType, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, OPEN_EXISTING,
        },
    },
};

use crate::{handle_ext::handle_to_nt_path, safe_handle::SafeHandle};

pub fn win32_path_to_nt_path(win32_path: String) -> anyhow::Result<String> {
    let handle = unsafe {
        CreateFileW(
            &HSTRING::from(win32_path),
            0u32,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            HANDLE::default(),
        )?
    };

    if handle.is_invalid() {
        return Err(anyhow!("CreateFileW failed"));
    }

    let safe_handle = SafeHandle::new(handle);

    let file_type = unsafe { GetFileType(safe_handle.handle) };
    if file_type != FILE_TYPE_DISK {
        return Err(anyhow!("file_type != FILE_TYPE_DISK"));
    }

    let nt_path = handle_to_nt_path(&safe_handle)?;
    Ok(nt_path)
}
