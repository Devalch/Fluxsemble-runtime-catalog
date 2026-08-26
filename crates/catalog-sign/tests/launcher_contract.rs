use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn launcher_cli_is_a_closed_ordered_ceremony() {
    let launcher = env!("CARGO_BIN_EXE_catalog-sign-launcher");
    for arguments in [
        vec![],
        vec!["assemble-intent"],
        vec![
            "assemble-intent",
            "--input",
            "/tmp/input",
            "--config",
            "/tmp/config",
            "--output",
            "/tmp/output",
        ],
        vec![
            "sign",
            "--config",
            "/tmp/config",
            "--input",
            "/tmp/input",
            "--output",
            "/tmp/output",
        ],
        vec![
            "finalize",
            "--config",
            "/tmp/config",
            "--input",
            "/tmp/input",
            "--key",
            "/tmp/key",
            "--output",
            "/tmp/output",
        ],
        vec![
            "shell",
            "--config",
            "/tmp/config",
            "--input",
            "/tmp/input",
            "--output",
            "/tmp/output",
        ],
    ] {
        let output = Command::new(launcher).args(arguments).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"catalog signing launcher failed\n");
    }
}

#[test]
fn real_launcher_authenticates_static_signer_and_transfer_before_isolated_failure() {
    let root = TempRoot::new();
    let input = root.path.join("input");
    write_transfer(&input);
    let static_source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-linux-musl/release/catalog-sign")
        .canonicalize()
        .expect("build the authorized musl signer before this integration test");
    let signer = root.path.join("catalog-sign-static");
    fs::copy(static_source, &signer).unwrap();
    fs::set_permissions(&signer, fs::Permissions::from_mode(0o500)).unwrap();
    let config = root.path.join("launcher-config-v1.json");
    write_config(&config, &signer, &sha256(&fs::read(&signer).unwrap()));
    let output = root.path.join("output");

    let result = Command::new(env!("CARGO_BIN_EXE_catalog-sign-launcher"))
        .args([
            "assemble-intent",
            "--config",
            config.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !result.status.success(),
        "synthetic intent must not gain production admission"
    );
    assert!(result.stdout.is_empty());
    assert_eq!(result.stderr, b"catalog signing launcher failed\n");
    assert!(
        output.is_dir(),
        "valid static/config/input checks did not reach the isolated ceremony: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read_dir(&output).unwrap().count(), 0);

    let fixture_key = root.path.join("nonproduction-fixture-key.pem");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/nonproduction-ed25519-pkcs8.pem"),
        &fixture_key,
    )
    .unwrap();
    fs::set_permissions(&fixture_key, fs::Permissions::from_mode(0o400)).unwrap();
    let sign_output = root.path.join("sign-output");
    let sign_result = Command::new(env!("CARGO_BIN_EXE_catalog-sign-launcher"))
        .args([
            "sign",
            "--config",
            config.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--key",
            fixture_key.to_str().unwrap(),
            "--output",
            sign_output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!sign_result.status.success());
    assert!(sign_result.stdout.is_empty());
    assert_eq!(sign_result.stderr, b"catalog signing launcher failed\n");
    assert!(
        sign_output.is_dir(),
        "sign-mode fixture plumbing did not reach isolation"
    );
    assert_eq!(fs::read_dir(&sign_output).unwrap().count(), 0);

    let dynamic = root.path.join("dynamic-signer");
    fs::copy(env!("CARGO_BIN_EXE_catalog-sign"), &dynamic).unwrap();
    fs::set_permissions(&dynamic, fs::Permissions::from_mode(0o500)).unwrap();
    let dynamic_config = root.path.join("dynamic-config-v1.json");
    write_config(
        &dynamic_config,
        &dynamic,
        &sha256(&fs::read(&dynamic).unwrap()),
    );
    let rejected_output = root.path.join("dynamic-output");
    let rejected = Command::new(env!("CARGO_BIN_EXE_catalog-sign-launcher"))
        .args([
            "assemble-intent",
            "--config",
            dynamic_config.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--output",
            rejected_output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        !rejected_output.exists(),
        "dynamic signer was admitted before output visibility"
    );

    let substituted = root.path.join("substituted-config-v1.json");
    write_config(&substituted, &signer, &"00".repeat(32));
    let substituted_output = root.path.join("substituted-output");
    let rejected = Command::new(env!("CARGO_BIN_EXE_catalog-sign-launcher"))
        .args([
            "finalize",
            "--config",
            substituted.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--output",
            substituted_output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        !substituted_output.exists(),
        "signer hash substitution reached output visibility"
    );
}

#[test]
fn signer_path_substitution_after_open_and_at_bind_time_fails_closed() {
    for checkpoint in ["after-open", "bind-time"] {
        let root = TempRoot::new();
        let input = root.path.join("input");
        write_transfer_with_object(&input, &vec![b'x'; 16 * 1024 * 1024]);
        let static_source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/x86_64-unknown-linux-musl/release/catalog-sign")
            .canonicalize()
            .unwrap();
        let signer = root.path.join("catalog-sign-static");
        fs::copy(static_source, &signer).unwrap();
        fs::set_permissions(&signer, fs::Permissions::from_mode(0o500)).unwrap();
        let config = root.path.join("launcher-config-v1.json");
        write_config(&config, &signer, &sha256(&fs::read(&signer).unwrap()));
        let output = root.path.join("output");
        let mut child = Command::new(env!("CARGO_BIN_EXE_catalog-sign-launcher"))
            .args([
                "assemble-intent",
                "--config",
                config.to_str().unwrap(),
                "--input",
                input.to_str().unwrap(),
                "--output",
                output.to_str().unwrap(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        if checkpoint == "after-open" {
            wait_until(|| process_has_open_path(child.id(), &signer));
        } else {
            wait_until(|| output.is_dir());
        }
        let retained = root.path.join(format!("retained-{checkpoint}"));
        fs::rename(&signer, &retained).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_catalog-sign"), &signer).unwrap();
        fs::set_permissions(&signer, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(!child.wait().unwrap().success());
        if checkpoint == "after-open" {
            assert!(
                !output.exists(),
                "after-open substitution reached output visibility"
            );
        } else {
            assert!(output.is_dir());
            assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
        }
    }
}

#[test]
fn launcher_source_has_the_fixed_bubblewrap_capability_only() {
    let source = include_str!("../src/bin/catalog-sign-launcher.rs");
    assert!(source.contains("std::process::Command::new"));
    assert!(source.contains("--unshare-all"));
    assert!(source.contains("--unshare-net"));
    assert!(source.contains("--clearenv"));
    assert!(source.contains("--seccomp"));
    assert!(source.contains("--ro-bind-fd"));
    assert!(source.contains("--bind-fd"));
    assert!(!source.contains("sh -c"));
    assert!(!source.contains("/bin/sh"));
}

fn write_transfer(path: &Path) {
    write_transfer_with_object(path, b"object");
}

fn write_transfer_with_object(path: &Path, object: &[u8]) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    for directory in ["objects", "records"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.join(directory))
            .unwrap();
    }
    let object_digest = sha256(object);
    write_read_only(&path.join(format!("objects/{object_digest}")), object);
    let mut entries = vec![json!({
        "relative_path": format!("objects/{object_digest}"),
        "mode": "0400",
        "size": object.len() as u64,
        "sha256": object_digest,
    })];
    let mut records = Vec::new();
    for (role, bytes) in [
        ("package_inputs", b"inputs".as_slice()),
        ("release_intent", b"intent".as_slice()),
    ] {
        let digest = sha256(bytes);
        let relative = format!("records/{digest}");
        write_read_only(&path.join(&relative), bytes);
        entries.push(json!({"relative_path": relative, "mode": "0400", "size": bytes.len() as u64, "sha256": digest}));
        records.push(json!({"role": role, "relative_path": relative, "sha256": digest}));
    }
    let inventory = serde_jcs::to_vec(&json!({
        "schema_version": 1,
        "source_kind": "release_intent",
        "source_sha256": "11".repeat(32),
        "compatibility_input_sha256": "22".repeat(32),
        "objects": [{
            "relative_path": format!("objects/{object_digest}"),
            "source_url": "https://registry.npmjs.org/object/-/object-1.0.0.tgz",
            "size": object.len() as u64,
            "sha256": object_digest,
        }],
    }))
    .unwrap();
    let inventory_digest = sha256(&inventory);
    write_read_only(&path.join("verified-input-bundle-v1.json"), &inventory);
    entries.push(json!({
        "relative_path": "verified-input-bundle-v1.json",
        "mode": "0400",
        "size": inventory.len() as u64,
        "sha256": inventory_digest,
    }));
    entries.sort_by(|left, right| {
        left["relative_path"]
            .as_str()
            .cmp(&right["relative_path"].as_str())
    });
    let manifest = serde_jcs::to_vec(&json!({
        "schema_version": 1,
        "kind": "verified_input",
        "source_commit": null,
        "source_tree_sha256": null,
        "records": records,
        "entries": entries,
    }))
    .unwrap();
    write_read_only(&path.join("transfer-manifest-v1.json"), &manifest);
}

fn write_config(path: &Path, signer: &Path, signer_sha256: &str) {
    let config = serde_jcs::to_vec(&json!({
        "schema_version": 1,
        "bwrap_path": "/usr/bin/bwrap",
        "bwrap_sha256": sha256(&fs::read("/usr/bin/bwrap").unwrap()),
        "signer_path": signer,
        "signer_sha256": signer_sha256,
    }))
    .unwrap();
    fs::write(path, config).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn write_read_only(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn process_has_open_path(process: u32, expected: &Path) -> bool {
    fs::read_dir(format!("/proc/{process}/fd"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| fs::read_link(entry.path()).ok())
        .any(|target| target == expected)
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(1));
    }
    panic!("launcher checkpoint was not observed");
}

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "catalog-launcher-contract-{}-{nonce}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
