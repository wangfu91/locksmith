use std::{ffi::OsString, os::windows::ffi::OsStringExt};

use windows::Win32::Foundation::UNICODE_STRING;

pub trait ToString {
    fn to_string(&self) -> String;
}

impl ToString for UNICODE_STRING {
    fn to_string(&self) -> String {
        if self.Buffer.is_null() || self.Length == 0 {
            return String::new();
        }

        // Check if Length is valid (must be even as UTF-16 uses 2 bytes per character)
        if self.Length % 2 != 0 {
            return String::new();
        }

        // Calculate character count (divide byte length by size of u16)
        let char_count = self.Length as usize / std::mem::size_of::<u16>();

        // Safety check for Windows Max long path length
        if char_count > 32768 {
            return String::new();
        }

        let slice = unsafe { std::slice::from_raw_parts(self.Buffer.as_ptr(), char_count) };

        let os_string = OsString::from_wide(slice);
        os_string.to_string_lossy().to_string()
    }
}
