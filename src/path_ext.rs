use anyhow::anyhow;
use windows::{
    Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TYPE_DISK, GetFileType, OPEN_EXISTING,
    },
    core::HSTRING,
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
            None,
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

/// Checks if the `reference_path` is the same as or an ancestor of the `subject_path`.
///
/// This function is useful for determining if a file or directory (`subject_path`)
/// is located within or is the same as a given directory (`reference_path`).
///
/// It handles cases where `subject_path` is exactly `reference_path`, or where
/// `subject_path` is a deeper path under `reference_path`.
///
/// # Arguments
///
/// * `reference_path`: The path that is being checked against (e.g., a directory).
/// * `subject_path`: The path that is being checked (e.g., a file or subdirectory).
///
/// # Returns
///
/// `true` if `reference_path` is the same as or an ancestor of `subject_path`,
/// `false` otherwise. On Windows, the comparison is case-insensitive.
pub fn is_same_or_ancestor_of(reference_path: &str, subject_path: &str) -> bool {
    let ref_len = reference_path.len();
    let sub_len = subject_path.len();

    // Case 1: Exact match (case-insensitive)
    if ref_len == sub_len {
        return reference_path.eq_ignore_ascii_case(subject_path);
    }

    // Case 2: reference_path might be an ancestor.
    // For reference_path to be an ancestor, subject_path must be longer,
    // and subject_path must start with reference_path (case-insensitive).
    if sub_len > ref_len {
        // Check if subject_path starts with reference_path (case-insensitive)
        if !subject_path[..ref_len].eq_ignore_ascii_case(reference_path) {
            return false;
        }

        // If reference_path ends with a path separator, then subject_path starting with it is enough.
        // e.g., ref = "C:\\foo\\", sub = "C:\\foo\\bar.txt"
        if reference_path.ends_with('\\') {
            // Check for trailing backslash
            return true;
        } else {
            // If reference_path does not end with a separator,
            // the character in subject_path immediately after the reference_path prefix must be a separator.
            // e.g., ref = "C:\\foo", sub = "C:\\foo\\bar.txt"
            return subject_path.as_bytes().get(ref_len) == Some(&b'\\'); // Check for backslash at join point
        }
    }

    // Otherwise, reference_path is not the same or an ancestor (e.g., reference_path is longer, or completely different)
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_same_or_ancestor_of_exact_match() {
        assert!(is_same_or_ancestor_of(
            r"\\Device\HarddiskVolume1\Users",
            r"\\Device\HarddiskVolume1\Users"
        ));
    }

    #[test]
    fn test_is_same_or_ancestor_of_subject_is_child() {
        assert!(is_same_or_ancestor_of(
            r"\\Device\HarddiskVolume1\Users",
            r"\\Device\HarddiskVolume1\Users\TestUser"
        ));
    }

    #[test]
    fn test_is_same_or_ancestor_of_subject_is_grandchild() {
        assert!(is_same_or_ancestor_of(
            r"\\Device\HarddiskVolume1\Users",
            r"\\Device\HarddiskVolume1\Users\TestUser\file.txt"
        ));
    }

    #[test]
    fn test_is_same_or_ancestor_of_different_paths() {
        assert!(!is_same_or_ancestor_of(
            r"\\Device\HarddiskVolume1\Users",
            r"\\Device\HarddiskVolume1\Windows"
        ));
    }

    #[test]
    fn test_is_same_or_ancestor_of_partial_match_not_ancestor() {
        assert!(!is_same_or_ancestor_of(
            r"\\Device\HarddiskVolume1\Users",
            r"\\Device\HarddiskVolume1\User"
        ));
    }

    #[test]
    fn test_is_same_or_ancestor_of_reference_is_child_of_subject() {
        assert!(!is_same_or_ancestor_of(
            r"\\Device\HarddiskVolume1\Users\TestUser",
            r"\\Device\HarddiskVolume1\Users"
        ));
    }

    #[test]
    fn test_is_same_or_ancestor_of_empty_paths() {
        assert!(is_same_or_ancestor_of("", ""));
        assert!(!is_same_or_ancestor_of("a", ""));
        assert!(!is_same_or_ancestor_of("", "a"));
    }

    #[test]
    fn test_is_same_or_ancestor_of_no_trailing_slash_on_reference() {
        assert!(is_same_or_ancestor_of(
            r"\\Device\HarddiskVolume1\Users",
            r"\\Device\HarddiskVolume1\Users\Test"
        ));
    }

    #[test]
    fn test_is_same_or_ancestor_of_subject_is_shorter_and_starts_with() {
        assert!(!is_same_or_ancestor_of(
            r"\\Device\HarddiskVolume1\Users\Project",
            r"\\Device\HarddiskVolume1\Users"
        ));
    }

    #[test]
    fn test_is_same_or_ancestor_of_different_casing() {
        // On Windows, comparison should be case-insensitive.
        assert!(is_same_or_ancestor_of(
            r"\\DEVICE\HarddiskVolume1\Users",
            r"\\Device\HarddiskVolume1\Users"
        ));
        assert!(is_same_or_ancestor_of(
            r"\\Device\HarddiskVolume1\Users",
            r"\\Device\HarddiskVolume1\USERS\TestUser"
        ));
        assert!(is_same_or_ancestor_of(
            r"\\Device\HarddiskVolume1\USERS\",
            r"\\Device\HarddiskVolume1\Users\TestUser"
        ));
    }
    #[test]
    fn test_is_same_or_ancestor_of_reference_ends_with_slash() {
        // The function should correctly handle if reference_path ends with a slash,
        // though NT paths typically don't.

        assert!(is_same_or_ancestor_of(
            r"\\Device\HarddiskVolume1\Users\",
            r"\\Device\HarddiskVolume1\Users\TestUser"
        ));
        assert!(is_same_or_ancestor_of(
            r"\\Device\HarddiskVolume1\Users\",
            r"\\Device\HarddiskVolume1\Users\"
        ));
        assert!(!is_same_or_ancestor_of(
            r"\\Device\HarddiskVolume1\Users\",
            r"\\Device\HarddiskVolume1\Users" // Subject does not have trailing slash
        ));
    }

    #[test]
    fn test_is_same_or_ancestor_of_not_direct_child() {
        // Example: ref = "A\B", subject = "A\BC" (should be false)
        assert!(!is_same_or_ancestor_of(
            r"\\Device\HarddiskVolume1\Us",
            r"\\Device\HarddiskVolume1\Users"
        ));
    }
}
