use std::process::Command;

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
