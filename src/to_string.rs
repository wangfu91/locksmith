use std::{ffi::OsString, os::windows::ffi::OsStringExt};

use windows::Win32::Foundation::UNICODE_STRING;

pub trait ToString {
    fn to_string(&self) -> String;
}

impl ToString for UNICODE_STRING {
    fn to_string(&self) -> String {
        let slice = unsafe {
            std::slice::from_raw_parts(
                self.Buffer.as_ptr(),
                self.Length as usize / std::mem::size_of::<u16>(),
            )
        };
        let os_string = OsString::from_wide(slice);
        os_string.to_string_lossy().to_string()
    }
}
