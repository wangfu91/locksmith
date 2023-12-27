use windows::Win32::Foundation::{CloseHandle, HANDLE};

#[derive(Debug)]
pub struct SafeHandle {
    pub handle: HANDLE,
}

impl SafeHandle {
    pub fn new(handle: HANDLE) -> Self {
        Self { handle }
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
