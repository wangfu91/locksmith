use std::process::Command;

struct TestTree(std::path::PathBuf);
impl TestTree {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("locksmith-cli-{name}-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for TestTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_found_this_process(result: &std::process::Output) {
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        result.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8_lossy(&result.stdout);
    assert!(
        output
            .lines()
            .any(|line| line == format!("pid: {}", std::process::id())),
        "{output}"
    );
}

#[test]
fn scans_long_native_file_names_and_their_parent_directory() {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    let tree = TestTree::new("native-long");
    let mut directory = tree.0.canonicalize().unwrap();
    for index in 0..8 {
        directory.push(format!("目录{index}-{}", "路径".repeat(35)));
        std::fs::create_dir(&directory).unwrap();
    }
    let name: Vec<_> = "Ä-data-"
        .encode_utf16()
        .chain([0xd800])
        .chain(".txt".encode_utf16())
        .collect();
    let path = directory.join(OsString::from_wide(&name));
    std::fs::write(&path, b"test").unwrap();
    let held = std::fs::File::open(&path).unwrap();
    for target in [&path, &directory] {
        let output = Command::new(env!("CARGO_BIN_EXE_locksmith"))
            .arg(target)
            .output()
            .unwrap();
        assert_found_this_process(&output);
    }
    drop(held);
}

#[test]
fn cancelling_kill_keeps_the_file_owner_running() {
    use std::{io::Write, process::Stdio};
    let tree = TestTree::new("cancel");
    let path = tree.0.join("held.txt");
    std::fs::write(&path, b"test").unwrap();
    let held = std::fs::File::open(&path).unwrap();
    let mut scanner = Command::new(env!("CARGO_BIN_EXE_locksmith"))
        .arg(&path)
        .arg("--kill")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    scanner.stdin.take().unwrap().write_all(b"n\n").unwrap();
    let output = scanner.wait_with_output().unwrap();
    assert_found_this_process(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("Operation cancelled by user"));
    drop(held);
}

#[test]
fn missing_path_is_an_operational_failure() {
    let path =
        std::env::temp_dir().join(format!("locksmith-does-not-exist-{}", std::process::id()));
    assert!(!path.exists());
    let result = Command::new(env!("CARGO_BIN_EXE_locksmith"))
        .arg(path)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("Path does not exist"));
}

#[test]
fn help_and_argument_errors_have_expected_statuses() {
    let version = Command::new(env!("CARGO_BIN_EXE_locksmith"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        concat!("locksmith ", env!("CARGO_PKG_VERSION"))
    );
    assert!(
        Command::new(env!("CARGO_BIN_EXE_locksmith"))
            .arg("--help")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(
        Command::new(env!("CARGO_BIN_EXE_locksmith"))
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
}
