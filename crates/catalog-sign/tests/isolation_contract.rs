use std::{
    ffi::CString,
    fs,
    os::{
        fd::RawFd,
        unix::{
            fs::{DirBuilderExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use catalog_sign::{SignError, enter_signer_isolation};
use sha2::{Digest, Sha256};

#[test]
fn direct_and_exact_marker_only_sign_fail_before_key_open_or_output() {
    assert!(matches!(
        enter_signer_isolation(),
        Err(SignError::IsolationRejected)
    ));

    let root = TempRoot::new();
    let key = root.path.join("nonproduction-fixture-key.pem");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/nonproduction-ed25519-pkcs8.pem"),
        &key,
    )
    .unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();

    for marker_only in [false, true] {
        let output = root.path.join(if marker_only {
            "marker-only-output"
        } else {
            "direct-output"
        });
        let witness = InotifyKeyOpenWitness::new(&key);
        let mut command = Command::new(env!("CARGO_BIN_EXE_catalog-sign"));
        command.env_clear().args([
            "sign",
            "--input",
            "/input",
            "--key",
            key.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ]);
        if marker_only {
            for (name, value) in complete_marker_environment() {
                command.env(name, value);
            }
            // SAFETY: this child-only hook invokes async-signal-safe setrlimit before exec.
            unsafe {
                command.pre_exec(|| {
                    let limit = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let result = command.output().unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert_eq!(result.stderr, b"catalog signing failed\n");
        assert!(!output.exists());
        assert!(
            !witness.observed_open(),
            "rejected inner execution opened the fixture key"
        );
    }
}

#[test]
fn real_launcher_prefilter_and_inner_filter_emit_kernel_attestation() {
    let root = TempRoot::new();
    let input = root.path.join("input");
    let output = root.path.join("output");
    write_verified_public_transfer(&input);
    catalog_sign::verify_transferred_bundle(&input).unwrap();
    let input_manifest = fs::read(input.join("transfer-manifest-v1.json")).unwrap();

    let source_static = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-linux-musl/release/catalog-sign")
        .canonicalize()
        .expect("build the authorized musl release signer before this integration test");
    let static_signer = root.path.join("catalog-sign-static");
    fs::copy(source_static, &static_signer).unwrap();
    fs::set_permissions(&static_signer, fs::Permissions::from_mode(0o500)).unwrap();
    let config = root.path.join("launcher-config-v1.json");
    let config_bytes = serde_jcs::to_vec(&serde_json::json!({
        "schema_version": 1,
        "bwrap_path": "/usr/bin/bwrap",
        "bwrap_sha256": format!("{:x}", Sha256::digest(fs::read("/usr/bin/bwrap").unwrap())),
        "signer_path": static_signer,
        "signer_sha256": format!("{:x}", Sha256::digest(fs::read(&static_signer).unwrap())),
    }))
    .unwrap();
    fs::write(&config, config_bytes).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

    let digest = format!("{:x}", Sha256::digest(&input_manifest));
    let result = Command::new(env!("CARGO_BIN_EXE_catalog-sign-launcher"))
        .args([
            "isolation-probe",
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
        result.status.success(),
        "probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"catalog signer completed\n");
    assert!(result.stderr.is_empty());

    let probe: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("isolation-probe-v1.json")).unwrap()).unwrap();
    for syscall in [
        "socket",
        "connect",
        "fork",
        "vfork",
        "clone",
        "clone3",
        "ptrace",
        "execve",
        "execveat",
        "unshare",
        "setns",
        "mount",
        "umount2",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
    ] {
        assert_eq!(probe["inner_filter_errno"][syscall], libc::EPERM);
    }
    for syscall in [
        "socket",
        "connect",
        "fork",
        "unshare",
        "setns",
        "mount",
        "umount2",
        "open_tree",
        "move_mount",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
    ] {
        assert_eq!(probe["launcher_prefilter_errno"][syscall], libc::EPERM);
    }
    assert_eq!(probe["launcher_prefilter_errno"]["execve"], libc::ENOENT);
    assert_eq!(probe["core_limit_soft"], 0);
    assert_eq!(probe["core_limit_hard"], 0);
    assert_eq!(probe["dumpable"], false);
    let mounts = probe["mount_points"].as_array().unwrap();
    assert!(mounts.iter().any(|value| value == "/input"));
    assert!(mounts.iter().any(|value| value == "/output"));
    assert!(
        !mounts
            .iter()
            .any(|value| value.as_str().unwrap().contains("runtime-catalog"))
    );
    let environment = probe["environment_names"].as_array().unwrap();
    for denied in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "SSH_AUTH_SOCK",
        "HOME_REPOSITORY",
    ] {
        assert!(!environment.iter().any(|name| name == denied));
    }

    let reverse_bytes = fs::read(output.join("transfer-manifest-v1.json")).unwrap();
    let reverse: serde_json::Value = serde_json::from_slice(&reverse_bytes).unwrap();
    assert_eq!(serde_jcs::to_vec(&reverse).unwrap(), reverse_bytes);
    assert_eq!(reverse["kind"], "signer_output");
    assert_eq!(reverse["input_transfer_sha256"], digest);
    assert_eq!(reverse["isolation_attestation"]["mode"], "isolation-probe");
    assert_eq!(reverse["isolation_attestation"]["core_limit_soft"], 0);
    assert_eq!(reverse["isolation_attestation"]["core_limit_hard"], 0);
    assert_eq!(reverse["isolation_attestation"]["dumpable"], false);
    assert_eq!(reverse["isolation_attestation"]["private_tmpfs_root"], true);
    assert_eq!(
        reverse["isolation_attestation"]["launcher_prefilter_errno"]["io_uring_setup"],
        libc::EPERM
    );
    assert_eq!(reverse["entries"].as_array().unwrap().len(), 1);
    assert!(
        !String::from_utf8(reverse_bytes)
            .unwrap()
            .contains(root.path.to_str().unwrap())
    );
}

#[test]
fn isolation_entry_is_the_first_operation_in_inner_main() {
    let source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs")).unwrap();
    let body = source.split_once("fn main() {").unwrap().1;
    let first_statement = body
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap()
        .trim();
    assert_eq!(
        first_statement,
        "let isolation = match catalog_sign::enter_signer_isolation() {"
    );
    assert!(
        source.find("enter_signer_isolation").unwrap()
            < source
                .find("let _compiled_identity = production_key_identity()")
                .unwrap()
    );
    assert!(
        source.find("enter_signer_isolation").unwrap() < source.find("std::env::args").unwrap()
    );
}

fn write_verified_public_transfer(path: &Path) {
    use serde_json::json;

    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    for directory in ["objects", "records"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.join(directory))
            .unwrap();
    }
    let object = b"public-object";
    let object_digest = format!("{:x}", Sha256::digest(object));
    write_read_only(&path.join(format!("objects/{object_digest}")), object);
    let mut entries = vec![json!({
        "relative_path": format!("objects/{object_digest}"),
        "mode": "0400",
        "size": object.len() as u64,
        "sha256": object_digest,
    })];
    let mut records = Vec::new();
    for (role, bytes) in [
        ("package_inputs", b"public-inputs".as_slice()),
        ("release_intent", b"public-intent".as_slice()),
    ] {
        let digest = format!("{:x}", Sha256::digest(bytes));
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
            "source_url": "https://registry.npmjs.org/public-object/-/public-object-1.0.0.tgz",
            "size": object.len() as u64,
            "sha256": object_digest,
        }],
    }))
    .unwrap();
    let inventory_digest = format!("{:x}", Sha256::digest(&inventory));
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

fn write_read_only(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
}

fn complete_marker_environment() -> Vec<(&'static str, String)> {
    let namespace = |name: &str| {
        fs::read_link(format!("/proc/self/ns/{name}"))
            .unwrap()
            .to_string_lossy()
            .into_owned()
    };
    vec![
        ("HOME", "/home/signer".to_owned()),
        ("PATH", "/bin".to_owned()),
        ("PWD", "/home/signer".to_owned()),
        ("LANG", "C".to_owned()),
        ("LC_ALL", "C".to_owned()),
        ("TZ", "UTC".to_owned()),
        ("CATALOG_SIGN_ISOLATION", "launcher-v1".to_owned()),
        ("CATALOG_SIGN_MODE", "sign".to_owned()),
        ("CATALOG_SIGN_CONFIG_SHA256", "01".repeat(32)),
        ("CATALOG_SIGN_INPUT_SHA256", "00".repeat(32)),
        ("CATALOG_SIGN_SIGNER_SHA256", "02".repeat(32)),
        (
            "CATALOG_SIGN_EUID",
            // SAFETY: geteuid has no preconditions.
            unsafe { libc::geteuid() }.to_string(),
        ),
        (
            "CATALOG_SIGN_EGID",
            // SAFETY: getegid has no preconditions.
            unsafe { libc::getegid() }.to_string(),
        ),
        ("CATALOG_SIGN_HOST_PID_NS", namespace("pid")),
        ("CATALOG_SIGN_HOST_USER_NS", namespace("user")),
        ("CATALOG_SIGN_HOST_MOUNT_NS", namespace("mnt")),
        ("CATALOG_SIGN_HOST_NETWORK_NS", namespace("net")),
    ]
}

struct InotifyKeyOpenWitness {
    descriptor: RawFd,
}

impl InotifyKeyOpenWitness {
    fn new(path: &Path) -> Self {
        // SAFETY: inotify_init1 has no pointer arguments.
        let descriptor = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        assert!(descriptor >= 0);
        let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: descriptor and NUL-terminated path are valid for this syscall.
        let watch = unsafe {
            libc::inotify_add_watch(descriptor, path.as_ptr(), libc::IN_OPEN | libc::IN_ACCESS)
        };
        assert!(watch >= 0);
        Self { descriptor }
    }

    fn observed_open(&self) -> bool {
        let mut buffer = [0_u8; 512];
        // SAFETY: descriptor is open and buffer is writable for its exact length.
        let result =
            unsafe { libc::read(self.descriptor, buffer.as_mut_ptr().cast(), buffer.len()) };
        if result >= 0 {
            return result > 0;
        }
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );
        false
    }
}

impl Drop for InotifyKeyOpenWitness {
    fn drop(&mut self) {
        // SAFETY: descriptor is uniquely owned by this witness.
        unsafe { libc::close(self.descriptor) };
    }
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
            "catalog-isolation-contract-{}-{nonce}",
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
