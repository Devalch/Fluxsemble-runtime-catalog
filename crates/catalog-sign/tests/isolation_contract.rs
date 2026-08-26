use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use catalog_sign::{SignError, enter_signer_isolation};
use sha2::{Digest, Sha256};

#[test]
fn direct_and_marker_only_inner_execution_fail_closed() {
    assert_eq!(enter_signer_isolation(), Err(SignError::IsolationRejected));

    let direct = Command::new(env!("CARGO_BIN_EXE_catalog-sign"))
        .args([
            "assemble-intent",
            "--input",
            "/input",
            "--output",
            "/output/candidate.json",
        ])
        .output()
        .unwrap();
    assert!(!direct.status.success());
    assert!(direct.stdout.is_empty());
    assert_eq!(direct.stderr, b"catalog signing failed\n");

    let marker_only = Command::new(env!("CARGO_BIN_EXE_catalog-sign"))
        .env_clear()
        .env("CATALOG_SIGN_ISOLATION", "1")
        .env("CATALOG_SIGN_MODE", "assemble-intent")
        .env("CATALOG_SIGN_INPUT_SHA256", "00".repeat(32))
        .args([
            "assemble-intent",
            "--input",
            "/input",
            "--output",
            "/output/candidate.json",
        ])
        .output()
        .unwrap();
    assert!(!marker_only.status.success());
    assert!(marker_only.stdout.is_empty());
    assert_eq!(marker_only.stderr, b"catalog signing failed\n");
}

#[test]
fn real_bubblewrap_and_seccomp_probe_denies_syscalls_and_emits_authenticated_output() {
    let root = TempRoot::new();
    let input = root.path.join("input");
    let output = root.path.join("output");
    write_verified_public_transfer(&input);
    fs::DirBuilder::new().mode(0o700).create(&output).unwrap();
    catalog_sign::verify_transferred_bundle(&input).unwrap();
    let input_manifest = fs::read(input.join("transfer-manifest-v1.json")).unwrap();

    let source_static = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-linux-musl/release/catalog-sign")
        .canonicalize()
        .expect("build the authorized musl release signer before this integration test");
    let static_signer = root.path.join("catalog-sign-static");
    fs::copy(source_static, &static_signer).unwrap();
    fs::set_permissions(&static_signer, fs::Permissions::from_mode(0o500)).unwrap();
    let seccomp = write_launcher_seccomp(&root.path.join("launcher-seccomp.bpf"));
    clear_close_on_exec(seccomp.as_raw_fd());

    let namespace = |name: &str| {
        fs::read_link(format!("/proc/self/ns/{name}"))
            .unwrap()
            .to_string_lossy()
            .into_owned()
    };
    let digest = format!("{:x}", Sha256::digest(&input_manifest));
    let result = Command::new("/usr/bin/bwrap")
        .args([
            "--unshare-all",
            "--unshare-net",
            "--die-with-parent",
            "--new-session",
            "--as-pid-1",
            "--clearenv",
            "--setenv",
            "HOME",
            "/home/signer",
            "--setenv",
            "PATH",
            "/bin",
            "--setenv",
            "LANG",
            "C",
            "--setenv",
            "LC_ALL",
            "C",
            "--setenv",
            "TZ",
            "UTC",
            "--setenv",
            "CATALOG_SIGN_ISOLATION",
            "launcher-v1",
            "--setenv",
            "CATALOG_SIGN_MODE",
            "isolation-probe",
            "--setenv",
            "CATALOG_SIGN_INPUT_SHA256",
            &digest,
            "--setenv",
            "CATALOG_SIGN_EUID",
            &unsafe { libc::geteuid() }.to_string(),
            "--setenv",
            "CATALOG_SIGN_EGID",
            &unsafe { libc::getegid() }.to_string(),
            "--setenv",
            "CATALOG_SIGN_HOST_PID_NS",
            &namespace("pid"),
            "--setenv",
            "CATALOG_SIGN_HOST_USER_NS",
            &namespace("user"),
            "--setenv",
            "CATALOG_SIGN_HOST_MOUNT_NS",
            &namespace("mnt"),
            "--setenv",
            "CATALOG_SIGN_HOST_NETWORK_NS",
            &namespace("net"),
            "--cap-drop",
            "ALL",
            "--dir",
            "/bin",
            "--ro-bind",
            static_signer.to_str().unwrap(),
            "/bin/catalog-sign",
            "--ro-bind",
            input.to_str().unwrap(),
            "/input",
            "--bind",
            output.to_str().unwrap(),
            "/output",
            "--dir",
            "/home",
            "--dir",
            "/home/signer",
            "--chmod",
            "0700",
            "/home/signer",
            "--tmpfs",
            "/tmp",
            "--chmod",
            "0700",
            "/tmp",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--chdir",
            "/home/signer",
            "--seccomp",
            &seccomp.as_raw_fd().to_string(),
            "--",
            "/bin/catalog-sign",
            "__isolation-probe",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"isolation probe complete\n");
    assert!(result.stderr.is_empty());

    let probe: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("isolation-probe-v1.json")).unwrap()).unwrap();
    for syscall in [
        "socket", "connect", "fork", "vfork", "clone", "clone3", "ptrace", "execve", "execveat",
        "unshare", "setns", "mount", "umount2",
    ] {
        assert_eq!(probe["denied_errno"][syscall], libc::EPERM);
    }
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

fn write_launcher_seccomp(path: &Path) -> fs::File {
    let denied = [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_shutdown,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_ptrace,
        libc::SYS_execveat,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_mount_setattr,
    ];
    let statement = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code, k, jt, jf| libc::sock_filter { code, jt, jf, k };
    let mut filters = vec![
        statement(0x20, 4),
        jump(0x15, 0xc000_003e, 1, 0),
        statement(0x06, 0x8000_0000),
        statement(0x20, 0),
        jump(0x35, 0x4000_0000, 0, 1),
        statement(0x06, 0x8000_0000),
    ];
    for syscall in denied {
        filters.push(jump(0x15, syscall as u32, 0, 1));
        filters.push(statement(0x06, 0x0005_0000 | libc::EPERM as u32));
    }
    filters.push(statement(0x06, 0x7fff_0000));
    let bytes = unsafe {
        std::slice::from_raw_parts(
            filters.as_ptr().cast::<u8>(),
            filters.len() * std::mem::size_of::<libc::sock_filter>(),
        )
    };
    fs::write(path, bytes).unwrap();
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.flush().unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file
}

fn clear_close_on_exec(descriptor: i32) {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
        0
    );
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
