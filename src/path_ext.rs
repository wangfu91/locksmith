use anyhow::{Context, anyhow};
use std::{
    ffi::OsStr,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
};
use windows::{
    Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType, OPEN_EXISTING,
    },
    core::{HSTRING, Owned},
};

use crate::handle_ext::handle_to_nt_path;

pub struct Target {
    pub nt_path: PathBuf,
    reference: Vec<u16>,
    is_directory: bool,
    _handle: Owned<windows::Win32::Foundation::HANDLE>,
}

impl Target {
    pub fn open(win32_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let handle = unsafe {
            CreateFileW(
                &HSTRING::from(win32_path.as_ref()),
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

        // SAFETY: CreateFileW returned a new handle owned exclusively by this scope.
        let safe_handle = unsafe { Owned::new(handle) };

        let file_type = unsafe { GetFileType(*safe_handle) };
        if file_type != FILE_TYPE_DISK {
            return Err(anyhow!("file_type != FILE_TYPE_DISK"));
        }

        let nt_path = handle_to_nt_path(&safe_handle)?;
        anyhow::ensure!(!nt_path.as_os_str().is_empty(), "Target has no native path");
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(*safe_handle, &mut information) }
            .context("Cannot query target attributes")?;
        let reference = nt_path.as_os_str().encode_wide().collect();
        Ok(Self {
            nt_path,
            reference,
            is_directory: information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0,
            _handle: safe_handle,
        })
    }

    pub fn matches(&self, subject: impl AsRef<OsStr>) -> bool {
        if subject.as_ref() == self.nt_path.as_os_str() {
            return true;
        }
        let units: Vec<_> = subject.as_ref().encode_wide().collect();
        (self.is_directory || self.reference.len() == units.len())
            && matches_wide(&self.reference, &units)
    }
}

#[cfg(test)]
pub fn win32_path_to_nt_path(path: impl AsRef<Path>) -> anyhow::Result<PathBuf> {
    Ok(Target::open(path)?.nt_path)
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
#[cfg(test)]
pub fn is_same_or_ancestor_of(
    reference_path: impl AsRef<OsStr>,
    subject_path: impl AsRef<OsStr>,
) -> bool {
    let reference: Vec<_> = reference_path.as_ref().encode_wide().collect();
    let subject: Vec<_> = subject_path.as_ref().encode_wide().collect();
    matches_wide(&reference, &subject)
}

pub fn matches_wide(reference: &[u16], subject: &[u16]) -> bool {
    if reference.is_empty() {
        return subject.is_empty();
    }
    let Some(prefix) = subject.get(..reference.len()) else {
        return false;
    };
    // The binding represents the lengths as i32.
    if reference.len() > i32::MAX as usize {
        return false;
    }
    // SAFETY: the slices provide readable UTF-16 units and checked API lengths.
    if unsafe { windows::Win32::Globalization::CompareStringOrdinal(reference, prefix, true) }
        != windows::Win32::Globalization::CSTR_EQUAL
    {
        return false;
    }
    reference.len() == subject.len()
        || reference.last() == Some(&0x5c)
        || subject.get(reference.len()) == Some(&0x5c)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};

    #[test]
    fn files_match_exact_paths_and_directories_include_descendants() {
        let dir = std::env::temp_dir().join(format!("locksmith-target-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("data.txt");
        let result = (|| {
            std::fs::write(&file, b"test")?;
            let file_target = Target::open(&file)?;
            let dir_target = Target::open(&dir)?;
            assert!(file_target.matches(&file_target.nt_path));
            assert!(!file_target.matches(file_target.nt_path.join("child")));
            assert!(dir_target.matches(&file_target.nt_path));
            assert!(dir_target.matches(&dir_target.nt_path));
            let sibling = format!("{}-sibling", dir_target.nt_path.display());
            assert!(!dir_target.matches(sibling));
            anyhow::Ok(())
        })();
        let cleanup_file = std::fs::remove_file(&file);
        let cleanup_dir = std::fs::remove_dir(&dir);
        result.unwrap();
        cleanup_file.unwrap();
        cleanup_dir.unwrap();
    }

    #[test]
    fn preserves_unpaired_utf16_in_paths_and_matching() {
        let name: Vec<_> = format!("locksmith-native-{}-", std::process::id())
            .encode_utf16()
            .chain([0xd800])
            .chain(".tmp".encode_utf16())
            .collect();
        let file = std::env::temp_dir().join(OsString::from_wide(&name));
        let result = (|| {
            let opened = std::fs::File::create(&file)?;
            let native = win32_path_to_nt_path(&file)?;
            let native_units: Vec<_> = native.as_os_str().encode_wide().collect();
            assert!(native_units.ends_with(&name));
            assert!(is_same_or_ancestor_of(&native, &native));
            let mut altered = native_units.clone();
            *altered.iter_mut().find(|unit| **unit == 0xd800).unwrap() = 0xfffd;
            assert!(!is_same_or_ancestor_of(
                &native,
                OsString::from_wide(&altered)
            ));
            drop(opened);
            anyhow::Ok(())
        })();
        let cleanup = std::fs::remove_file(&file);
        result.unwrap();
        cleanup.unwrap();
    }

    #[test]
    fn windows_unicode_case_and_component_boundaries() {
        assert!(is_same_or_ancestor_of(
            r"C:\Ärger\ДАННЫЕ",
            r"c:\ärger\данные\文件.txt"
        ));
        assert!(is_same_or_ancestor_of(r"C:\Ärger", r"C:\ärger"));
        assert!(!is_same_or_ancestor_of(r"C:\Ärger", r"C:\ärgerlich\file"));
    }

    #[test]
    fn unrelated_unicode_prefix_does_not_panic() {
        assert!(!is_same_or_ancestor_of(r"C:\a", r"C:\你好\b"));
        assert!(!is_same_or_ancestor_of(r"C:\ab", r"C:\😀\b"));
    }

    #[test]
    fn unicode_paths_match_at_valid_boundaries() {
        assert!(is_same_or_ancestor_of(r"C:\你好", r"C:\你好"));
        assert!(is_same_or_ancestor_of(r"C:\你好", r"C:\你好\b"));
        assert!(!is_same_or_ancestor_of(r"C:\你", r"C:\你好\b"));
    }

    #[test]
    fn test_is_same_or_ancestor_of_exact_match() {
        assert!(is_same_or_ancestor_of(r"C:\Users", r"C:\Users"));
    }

    #[test]
    fn test_is_same_or_ancestor_of_subject_is_child() {
        assert!(is_same_or_ancestor_of(r"C:\Users", r"C:\Users\TestUser"));
    }

    #[test]
    fn test_is_same_or_ancestor_of_subject_is_grandchild() {
        assert!(is_same_or_ancestor_of(
            r"C:\Users",
            r"C:\Users\TestUser\file.txt"
        ));
    }

    #[test]
    fn test_is_same_or_ancestor_of_different_paths() {
        assert!(!is_same_or_ancestor_of(r"C:\Users", r"C:\Windows"));
    }

    #[test]
    fn test_is_same_or_ancestor_of_partial_match_not_ancestor() {
        assert!(!is_same_or_ancestor_of(r"C:\Users", r"C:\User"));
    }

    #[test]
    fn test_is_same_or_ancestor_of_reference_is_child_of_subject() {
        assert!(!is_same_or_ancestor_of(r"C:\Users\TestUser", r"C:\Users"));
    }

    #[test]
    fn test_is_same_or_ancestor_of_empty_paths() {
        assert!(is_same_or_ancestor_of("", ""));
        assert!(!is_same_or_ancestor_of("a", ""));
        assert!(!is_same_or_ancestor_of("", "a"));
    }

    #[test]
    fn test_is_same_or_ancestor_of_no_trailing_slash_on_reference() {
        assert!(is_same_or_ancestor_of(r"C:\Users", r"C:\Users\Test"));
    }

    #[test]
    fn test_is_same_or_ancestor_of_subject_is_shorter_and_starts_with() {
        assert!(!is_same_or_ancestor_of(r"C:\Users\Project", r"C:\Users"));
    }

    #[test]
    fn test_is_same_or_ancestor_of_different_casing() {
        // On Windows, comparison should be case-insensitive.
        assert!(is_same_or_ancestor_of(r"C:\Users", r"C:\Users"));
        assert!(is_same_or_ancestor_of(r"C:\Users", r"C:\USERS\TestUser"));
        assert!(is_same_or_ancestor_of(r"C:\USERS\", r"C:\Users\TestUser"));
    }
    #[test]
    fn test_is_same_or_ancestor_of_reference_ends_with_slash() {
        // The function should correctly handle if reference_path ends with a slash,
        // though NT paths typically don't.

        assert!(is_same_or_ancestor_of(r"C:\Users\", r"C:\Users\TestUser"));
        assert!(is_same_or_ancestor_of(r"C:\Users\", r"C:\Users\"));
        assert!(!is_same_or_ancestor_of(
            r"C:\Users\",
            r"C:\Users" // Subject does not have trailing slash
        ));
    }

    #[test]
    fn test_is_same_or_ancestor_of_not_direct_child() {
        // Example: ref = "A\B", subject = "A\BC" (should be false)
        assert!(!is_same_or_ancestor_of(r"C:\Us", r"C:\Users"));
    }
}
