use std::{ffi::OsString, os::windows::ffi::OsStringExt};

use anyhow::{Context, Result, ensure};
use windows::Win32::Foundation::UNICODE_STRING;

/// Copy a kernel-returned string only from the live buffer that owns its bytes.
/// The descriptor pointer is never dereferenced; slicing establishes the bounds.
pub fn from_buffer(buffer: &[u8], value: UNICODE_STRING) -> Result<OsString> {
    ensure!(
        value.Length.is_multiple_of(2) && value.MaximumLength.is_multiple_of(2),
        "Invalid UTF-16 byte length"
    );
    ensure!(
        value.Length <= value.MaximumLength,
        "String exceeds its declared capacity"
    );
    if value.Length == 0 {
        return Ok(OsString::new());
    }
    let offset = (value.Buffer.as_ptr() as usize)
        .checked_sub(buffer.as_ptr() as usize)
        .context("String pointer precedes its owning buffer")?;
    let end = offset
        .checked_add(value.Length as usize)
        .context("String range overflow")?;
    let bytes = buffer
        .get(offset..end)
        .context("String extends outside its owning buffer")?;
    let units: Vec<_> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_ne_bytes(*pair))
        .collect();
    Ok(OsString::from_wide(&units))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PWSTR;

    #[test]
    fn copies_only_bounded_bytes_without_loss() {
        let units = [b'A' as u16, 0xd800, 0x4e2d];
        let buffer: Vec<_> = units.iter().flat_map(|unit| unit.to_ne_bytes()).collect();
        let value = UNICODE_STRING {
            Length: buffer.len() as u16,
            MaximumLength: buffer.len() as u16,
            Buffer: PWSTR(buffer.as_ptr() as *mut u16),
        };
        assert_eq!(
            from_buffer(&buffer, value)
                .unwrap()
                .encode_wide()
                .collect::<Vec<_>>(),
            units
        );
        assert!(from_buffer(&buffer, UNICODE_STRING { Length: 3, ..value }).is_err());
        assert!(
            from_buffer(
                &buffer,
                UNICODE_STRING {
                    MaximumLength: 2,
                    ..value
                }
            )
            .is_err()
        );
        assert!(from_buffer(&buffer[..2], value).is_err());
        assert!(
            from_buffer(
                &buffer,
                UNICODE_STRING {
                    Buffer: PWSTR::null(),
                    ..value
                }
            )
            .is_err()
        );
        assert!(
            from_buffer(
                &buffer,
                UNICODE_STRING {
                    Buffer: PWSTR(buffer.as_ptr().wrapping_add(buffer.len()) as *mut u16),
                    ..value
                }
            )
            .is_err()
        );
    }
}
