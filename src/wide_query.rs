use anyhow::{Result, bail};

/// Query a UTF-16 string, growing on `None` (insufficient space).
/// Lengths exclude the terminator; never expose a truncated successful result.
pub fn query(mut query: impl FnMut(&mut [u16]) -> Result<Option<usize>>) -> Result<Vec<u16>> {
    const MAX_UNITS: usize = 32_768;
    let mut buffer = vec![0; 260];
    loop {
        if let Some(length) = query(&mut buffer)? {
            if length >= buffer.len() {
                bail!("String query returned an invalid length");
            }
            buffer.truncate(length);
            return Ok(buffer);
        }
        if buffer.len() == MAX_UNITS {
            bail!("String query exceeds the supported Windows path length");
        }
        buffer.resize((buffer.len() * 2).min(MAX_UNITS), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_until_the_entire_path_fits() {
        let expected: Vec<_> = format!("C:\\{}\\模块.dll", "目录".repeat(900))
            .encode_utf16()
            .collect();
        let mut attempts = 0;
        let actual = query(|buffer| {
            attempts += 1;
            if expected.len() >= buffer.len() {
                buffer.copy_from_slice(&expected[..buffer.len()]);
                return Ok(None);
            }
            buffer[..expected.len()].copy_from_slice(&expected);
            Ok(Some(expected.len()))
        })
        .unwrap();
        assert_eq!(actual, expected);
        assert!(attempts > 2);
    }

    #[test]
    fn excessive_growth_and_invalid_lengths_are_errors() {
        assert!(query(|_| Ok(None)).is_err());
        assert!(query(|buffer| Ok(Some(buffer.len() + 1))).is_err());
        assert!(query(|_| anyhow::bail!("query failed")).is_err());
    }
}
