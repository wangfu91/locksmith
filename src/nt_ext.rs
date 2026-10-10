use anyhow::{Result, bail, ensure};
use windows::{
    Wdk::{
        Foundation::{NtQueryObject, OBJECT_INFORMATION_CLASS},
        Storage::FileSystem::{MEMORY_INFORMATION_CLASS, NtQueryVirtualMemory},
        System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
    },
    Win32::Foundation::{
        HANDLE, NTSTATUS, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL,
        STATUS_INFO_LENGTH_MISMATCH, UNICODE_STRING,
    },
    core::Owned,
};

/// Native equivalent of the mapped-file-name query, with a caller-sized buffer.
/// Class 2 returns a UNICODE_STRING followed by its data (phnt ntmmapi.h).
pub fn mapped_file_name(
    process: &Owned<HANDLE>,
    address: *const std::ffi::c_void,
) -> Result<std::path::PathBuf> {
    const MAPPED_FILENAME: MEMORY_INFORMATION_CLASS = MEMORY_INFORMATION_CLASS(2);
    let buffer = query_buffer(512, 1024 * 1024, |buffer, needed| {
        let mut length = 0usize;
        // SAFETY: live process and output buffers; the remote address is queried,
        // not dereferenced locally. The information class returns only name data.
        let status = unsafe {
            NtQueryVirtualMemory(
                **process,
                Some(address),
                MAPPED_FILENAME,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                Some(&mut length),
            )
        };
        *needed = u32::try_from(length).unwrap_or(u32::MAX);
        status
    })?;
    ensure!(
        buffer.len() >= std::mem::size_of::<UNICODE_STRING>(),
        "Mapped filename header is truncated"
    );
    // SAFETY: a complete C header of integers and an opaque pointer is present.
    let name = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<UNICODE_STRING>()) };
    Ok(std::path::PathBuf::from(crate::string_ext::from_buffer(
        &buffer, name,
    )?))
}

pub fn nt_query_information_loop(class: SYSTEM_INFORMATION_CLASS) -> Result<Vec<u8>> {
    query_buffer(1024 * 1024, 128 * 1024 * 1024, |buffer, needed| {
        // SAFETY: the writable slice and the returned-length pointer are live.
        unsafe {
            NtQuerySystemInformation(
                class,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                needed,
            )
        }
    })
}

pub fn nt_query_object_loop(
    handle: &Owned<HANDLE>,
    class: OBJECT_INFORMATION_CLASS,
) -> Result<Vec<u8>> {
    query_buffer(512, 1024 * 1024, |buffer, needed| {
        // SAFETY: the borrowed handle, writable slice and length pointer are live.
        unsafe {
            NtQueryObject(
                Some(**handle),
                class,
                Some(buffer.as_mut_ptr().cast()),
                buffer.len() as u32,
                Some(needed),
            )
        }
    })
}

fn query_buffer(
    initial: usize,
    maximum: usize,
    mut query: impl FnMut(&mut [u8], &mut u32) -> NTSTATUS,
) -> Result<Vec<u8>> {
    let mut buffer = vec![0; initial];
    for _ in 0..8 {
        let mut needed = 0;
        let status = query(&mut buffer, &mut needed);
        if status == STATUS_INFO_LENGTH_MISMATCH
            || status == STATUS_BUFFER_OVERFLOW
            || status == STATUS_BUFFER_TOO_SMALL
        {
            let required = needed as usize;
            ensure!(
                required <= maximum,
                "System query exceeds the buffer capacity limit"
            );
            ensure!(
                buffer.len() < maximum,
                "System query reached the buffer capacity limit"
            );
            let next = required
                .saturating_add(required / 4)
                .max(buffer.len() * 2)
                .min(maximum);
            buffer.try_reserve_exact(next - buffer.len())?;
            buffer.resize(next, 0);
            continue;
        }
        status.ok()?;
        ensure!(
            needed > 0 && needed as usize <= buffer.len(),
            "System query returned an invalid output length"
        );
        buffer.truncate(needed as usize);
        return Ok(buffer);
    }
    bail!("System query exceeded the retry limit")
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::STATUS_SUCCESS;

    #[test]
    fn query_grows_with_headroom_and_uses_success_length() {
        let mut calls = 0;
        let result = query_buffer(8, 1024, |buffer, needed| {
            calls += 1;
            if calls < 3 {
                *needed = if calls == 1 { 32 } else { 96 };
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            *needed = 3;
            buffer[..3].copy_from_slice(b"abc");
            STATUS_SUCCESS
        })
        .unwrap();
        assert_eq!(result, b"abc");
        assert_eq!(calls, 3);
    }

    #[test]
    fn query_stops_on_churn_huge_sizes_and_invalid_results() {
        let mut calls = 0;
        assert!(
            query_buffer(8, 1 << 20, |_, needed| {
                calls += 1;
                *needed = 0;
                STATUS_BUFFER_TOO_SMALL
            })
            .is_err()
        );
        assert_eq!(calls, 8);
        assert!(
            query_buffer(8, 1024, |_, needed| {
                *needed = u32::MAX;
                STATUS_INFO_LENGTH_MISMATCH
            })
            .is_err()
        );
        assert!(
            query_buffer(8, 1024, |_, needed| {
                *needed = 9;
                STATUS_SUCCESS
            })
            .is_err()
        );
    }
}
