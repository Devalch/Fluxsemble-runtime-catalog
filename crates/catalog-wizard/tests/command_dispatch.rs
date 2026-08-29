use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn temporary_home(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time")
        .as_nanos();
    let home = std::env::temp_dir().join(format!("catalog-wizard-{name}-{unique}"));
    fs::create_dir(&home).expect("create temporary home");
    home
}

#[test]
fn check_dispatches_to_a_safe_setup_check_without_writing_home() {
    let home = temporary_home("check");
    let output = Command::new(env!("CARGO_BIN_EXE_catalog-wizard"))
        .arg("check")
        .current_dir(workspace_root())
        .env("HOME", &home)
        .env("USER", "catalog-wizard-test")
        .output()
        .expect("run catalog-wizard check");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
    assert_eq!(output.stderr, b"Local setup check failed.\n");
    assert!(
        fs::read_dir(&home)
            .expect("read temporary home")
            .next()
            .is_none()
    );
    fs::remove_dir(&home).expect("remove temporary home");
}

#[test]
fn rotate_key_dispatches_to_the_guided_flow_without_writing_home() {
    let home = temporary_home("rotate-key");
    let root = workspace_root();
    let keyring = root.join("config/production-signing-keys-v1.json");
    let keyring_before = fs::read(&keyring).expect("read reviewed keyring");
    let output = Command::new(env!("CARGO_BIN_EXE_catalog-wizard"))
        .arg("rotate-key")
        .current_dir(root)
        .env("HOME", &home)
        .stdin(Stdio::null())
        .output()
        .expect("run catalog-wizard rotate-key");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"New private signing key path: ");
    assert_eq!(output.stderr, b"Rotate-key setup stopped safely.\n");
    assert!(
        fs::read_dir(&home)
            .expect("read temporary home")
            .next()
            .is_none()
    );
    assert_eq!(
        fs::read(keyring).expect("reread reviewed keyring"),
        keyring_before
    );
    fs::remove_dir(&home).expect("remove temporary home");
}
