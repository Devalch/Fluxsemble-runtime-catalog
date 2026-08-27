use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{SignError, signing::VerifiedTransferredBundle, verify_transferred_bundle};

const MARKER: &str = "launcher-v1";
const OUTPUT_MANIFEST: &str = "/output/transfer-manifest-v1.json";
const RECOVERY_BINDING: &str = "/output/sign-recovery-binding-v1.json";
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_OUTPUT_ENTRIES: usize = 64;
const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationMode {
    AssembleIntent,
    Finalize,
    Sign,
    RecoverSign,
    IsolationProbe,
}

impl IsolationMode {
    fn parse(value: &str) -> Result<Self, SignError> {
        match value {
            "assemble-intent" => Ok(Self::AssembleIntent),
            "finalize" => Ok(Self::Finalize),
            "sign" => Ok(Self::Sign),
            "recover-sign" => Ok(Self::RecoverSign),
            "isolation-probe" => Ok(Self::IsolationProbe),
            _ => Err(rejected()),
        }
    }

    fn requires_key(self) -> bool {
        self == Self::Sign
    }
}

/// Public evidence emitted into the reverse transfer, not isolation authority.
///
/// It deliberately cannot be deserialized into an authority-bearing value.
///
/// ```compile_fail
/// let _: catalog_sign::IsolationAttestationV1 = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationAttestationV1 {
    schema_version: u16,
    mode: IsolationMode,
    original_operation_mode: IsolationMode,
    input_transfer_sha256: String,
    launcher_config_sha256: String,
    signer_sha256: String,
    no_new_privileges: bool,
    launcher_seccomp_filter: bool,
    launcher_prefilter_errno: BTreeMap<String, i32>,
    inner_seccomp_filter: bool,
    core_limit_soft: u64,
    core_limit_hard: u64,
    dumpable: bool,
    private_tmpfs_root: bool,
    pid_namespace: String,
    user_namespace: String,
    mount_namespace: String,
    network_namespace: String,
    mount_points: Vec<String>,
    environment_names: Vec<String>,
}

impl IsolationAttestationV1 {
    #[must_use]
    pub const fn mode(&self) -> IsolationMode {
        self.mode
    }

    #[must_use]
    pub fn input_transfer_sha256(&self) -> &str {
        &self.input_transfer_sha256
    }
}

/// Non-constructible authority proving the current process passed the complete inner boundary.
///
/// ```compile_fail
/// let _ = catalog_sign::SignerIsolation {};
/// ```
pub struct SignerIsolation {
    attestation: IsolationAttestationV1,
    verified_transfer: VerifiedTransferredBundle,
}

impl SignerIsolation {
    #[must_use]
    pub fn attestation(&self) -> &IsolationAttestationV1 {
        &self.attestation
    }

    pub(crate) fn verified_transfer(&self) -> &VerifiedTransferredBundle {
        &self.verified_transfer
    }
}

/// Verifies every launcher-established fact and installs the final signer seccomp policy.
///
/// This function is intentionally the first operation in the inner binary. It performs no
/// argument parsing, production-identity lookup, output preflight, or signing-key access.
pub fn enter_signer_isolation() -> Result<SignerIsolation, SignError> {
    // Exec can restore dumpability, so the inner boundary disables it again as its first action.
    // SAFETY: PR_SET_DUMPABLE has no pointer argument and affects only this process.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(rejected());
    }
    // SAFETY: PR_GET_DUMPABLE has no pointer argument.
    let dumpable_status = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    if dumpable_status != 0 {
        return Err(rejected());
    }
    let dumpable = false;
    let (core_limit_soft, core_limit_hard) = core_limits()?;
    if core_limit_soft != 0 || core_limit_hard != 0 {
        return Err(rejected());
    }
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(rejected());
    }

    let environment = exact_environment()?;
    let mode = IsolationMode::parse(value(&environment, "CATALOG_SIGN_MODE")?)?;
    let expected_input_digest = value(&environment, "CATALOG_SIGN_INPUT_SHA256")?;
    let launcher_config_sha256 = value(&environment, "CATALOG_SIGN_CONFIG_SHA256")?;
    let signer_sha256 = value(&environment, "CATALOG_SIGN_SIGNER_SHA256")?;
    if !valid_sha256(expected_input_digest)
        || !valid_sha256(launcher_config_sha256)
        || !valid_sha256(signer_sha256)
    {
        return Err(rejected());
    }

    // SAFETY: PR_SET_NO_NEW_PRIVS has no pointer argument and is process-local.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(rejected());
    }
    // SAFETY: both prctl reads have no pointer argument.
    let no_new_privileges = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1;
    // SAFETY: PR_GET_SECCOMP has no pointer argument.
    let launcher_seccomp_filter = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) }
        == libc::SECCOMP_MODE_FILTER as i32;
    if !no_new_privileges || !launcher_seccomp_filter {
        return Err(rejected());
    }
    let launcher_prefilter_errno = verify_launcher_prefilter()?;

    let namespaces = verify_namespaces(&environment)?;
    let mount_points = verify_mounts(mode)?;
    verify_empty_directory(Path::new("/home/signer"))?;
    verify_empty_directory(Path::new("/tmp"))?;
    verify_network_namespace()?;
    verify_capabilities_and_kernel_status()?;
    verify_open_descriptors()?;
    let verified_transfer = verify_transferred_bundle(Path::new("/input"))?;
    let input_transfer_sha256 = verified_transfer.transfer_manifest_sha256().to_owned();
    if input_transfer_sha256 != expected_input_digest {
        return Err(rejected());
    }

    install_inner_seccomp_filter()?;
    // SAFETY: PR_GET_SECCOMP has no pointer argument.
    let inner_seccomp_filter = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) }
        == libc::SECCOMP_MODE_FILTER as i32;
    if !inner_seccomp_filter {
        return Err(rejected());
    }

    Ok(SignerIsolation {
        attestation: IsolationAttestationV1 {
            schema_version: 1,
            mode,
            original_operation_mode: if mode == IsolationMode::RecoverSign {
                IsolationMode::Sign
            } else {
                mode
            },
            input_transfer_sha256,
            launcher_config_sha256: launcher_config_sha256.to_owned(),
            signer_sha256: signer_sha256.to_owned(),
            no_new_privileges,
            launcher_seccomp_filter,
            launcher_prefilter_errno,
            inner_seccomp_filter,
            core_limit_soft,
            core_limit_hard,
            dumpable,
            private_tmpfs_root: true,
            pid_namespace: namespaces[0].clone(),
            user_namespace: namespaces[1].clone(),
            mount_namespace: namespaces[2].clone(),
            network_namespace: namespaces[3].clone(),
            mount_points,
            environment_names: environment.keys().cloned().collect(),
        },
        verified_transfer,
    })
}

fn exact_environment() -> Result<BTreeMap<String, String>, SignError> {
    let environment = std::env::vars().collect::<BTreeMap<_, _>>();
    let expected = BTreeSet::from([
        "CATALOG_SIGN_EGID",
        "CATALOG_SIGN_EUID",
        "CATALOG_SIGN_HOST_MOUNT_NS",
        "CATALOG_SIGN_HOST_NETWORK_NS",
        "CATALOG_SIGN_HOST_PID_NS",
        "CATALOG_SIGN_HOST_USER_NS",
        "CATALOG_SIGN_CONFIG_SHA256",
        "CATALOG_SIGN_INPUT_SHA256",
        "CATALOG_SIGN_SIGNER_SHA256",
        "CATALOG_SIGN_ISOLATION",
        "CATALOG_SIGN_MODE",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PWD",
        "TZ",
    ]);
    if environment
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected
        || value(&environment, "CATALOG_SIGN_ISOLATION")? != MARKER
        || value(&environment, "HOME")? != "/home/signer"
        || value(&environment, "PATH")? != "/bin"
        || value(&environment, "PWD")? != "/home/signer"
        || value(&environment, "LANG")? != "C"
        || value(&environment, "LC_ALL")? != "C"
        || value(&environment, "TZ")? != "UTC"
        || value(&environment, "CATALOG_SIGN_EUID")?
            .parse::<u32>()
            .ok()
            != Some(current_euid())
        || value(&environment, "CATALOG_SIGN_EGID")?
            .parse::<u32>()
            .ok()
            != Some(current_egid())
        || environment
            .keys()
            .any(|name| sensitive_environment_name(name))
    {
        return Err(rejected());
    }
    Ok(environment)
}

fn value<'a>(environment: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, SignError> {
    environment
        .get(name)
        .map(String::as_str)
        .ok_or_else(rejected)
}

fn sensitive_environment_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "PROXY",
        "GITHUB",
        "GH_",
        "TOKEN",
        "CREDENTIAL",
        "SSH",
        "AGENT",
        "REPOSITORY",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "XDG_",
    ]
    .iter()
    .any(|needle| upper.contains(needle))
}

fn verify_namespaces(environment: &BTreeMap<String, String>) -> Result<[String; 4], SignError> {
    if std::process::id() != 1 {
        return Err(rejected());
    }
    let names = ["pid", "user", "mnt", "net"];
    let host_names = [
        "CATALOG_SIGN_HOST_PID_NS",
        "CATALOG_SIGN_HOST_USER_NS",
        "CATALOG_SIGN_HOST_MOUNT_NS",
        "CATALOG_SIGN_HOST_NETWORK_NS",
    ];
    let mut isolated = Vec::with_capacity(4);
    for (name, host_name) in names.into_iter().zip(host_names) {
        let namespace = fs::read_link(format!("/proc/self/ns/{name}"))
            .map_err(|_| rejected())?
            .to_string_lossy()
            .into_owned();
        if !valid_namespace_identity(&namespace)
            || namespace == value(environment, host_name)?
            || !valid_namespace_identity(value(environment, host_name)?)
        {
            return Err(rejected());
        }
        isolated.push(namespace);
    }
    isolated.try_into().map_err(|_| rejected())
}

fn valid_namespace_identity(value: &str) -> bool {
    value
        .split_once(":[")
        .and_then(|(kind, inode)| inode.strip_suffix(']').map(|inode| (kind, inode)))
        .is_some_and(|(kind, inode)| {
            matches!(kind, "pid" | "user" | "mnt" | "net")
                && !inode.is_empty()
                && inode.bytes().all(|byte| byte.is_ascii_digit())
        })
}

struct MountRecord {
    mount_id: u64,
    parent_id: u64,
    root: String,
    options: BTreeSet<String>,
    optional_fields: Vec<String>,
    filesystem: String,
    source: String,
    super_options: BTreeSet<String>,
}

fn verify_mounts(mode: IsolationMode) -> Result<Vec<String>, SignError> {
    let bytes = fs::read_to_string("/proc/self/mountinfo").map_err(|_| rejected())?;
    if bytes.len() > 64 * 1024 || bytes.is_empty() {
        return Err(rejected());
    }
    let mut mounts = BTreeMap::new();
    for line in bytes.lines() {
        let (left, right) = line.split_once(" - ").ok_or_else(rejected)?;
        let fields = left.split_ascii_whitespace().collect::<Vec<_>>();
        let right_fields = right.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 || right_fields.len() != 3 {
            return Err(rejected());
        }
        let point = decode_mount_field(fields[4])?;
        let record = MountRecord {
            mount_id: fields[0].parse().map_err(|_| rejected())?,
            parent_id: fields[1].parse().map_err(|_| rejected())?,
            root: decode_mount_field(fields[3])?,
            options: fields[5].split(',').map(str::to_owned).collect(),
            optional_fields: fields[6..]
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            filesystem: right_fields[0].to_owned(),
            source: right_fields[1].to_owned(),
            super_options: right_fields[2].split(',').map(str::to_owned).collect(),
        };
        if mounts.insert(point, record).is_some() {
            return Err(rejected());
        }
    }
    let mut expected = BTreeSet::from([
        "/",
        "/bin/catalog-sign",
        "/dev",
        "/dev/full",
        "/dev/null",
        "/dev/pts",
        "/dev/random",
        "/dev/tty",
        "/dev/urandom",
        "/dev/zero",
        "/input",
        "/output",
        "/proc",
        "/tmp",
    ]);
    if mode.requires_key() {
        expected.insert("/key/runtime-catalog-private.pem");
    }
    if mounts.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(rejected());
    }
    verify_private_root_topology(&mounts)?;
    for path in ["/bin/catalog-sign", "/input"] {
        if !mount_is_read_only(&mounts, path) {
            return Err(rejected());
        }
    }
    if mode.requires_key() && !mount_is_read_only(&mounts, "/key/runtime-catalog-private.pem") {
        return Err(rejected());
    }
    if mount_is_read_only(&mounts, "/output")
        || mounts
            .get("/proc")
            .is_none_or(|mount| mount.filesystem != "proc")
        || mounts
            .get("/dev")
            .is_none_or(|mount| mount.filesystem != "tmpfs")
        || mounts
            .get("/dev/pts")
            .is_none_or(|mount| mount.filesystem != "devpts")
        || mounts
            .get("/tmp")
            .is_none_or(|mount| mount.filesystem != "tmpfs")
    {
        return Err(rejected());
    }
    Ok(mounts.into_keys().collect())
}

fn decode_mount_field(value: &str) -> Result<String, SignError> {
    let mut output = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if index + 3 >= bytes.len() {
                return Err(rejected());
            }
            let octal = &bytes[index + 1..index + 4];
            if !octal.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
                return Err(rejected());
            }
            output.push((octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + (octal[2] - b'0'));
            index += 4;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).map_err(|_| rejected())
}

fn verify_private_root_topology(mounts: &BTreeMap<String, MountRecord>) -> Result<(), SignError> {
    let root = mounts.get("/").ok_or_else(rejected)?;
    let expected_root_options = BTreeSet::from([
        "rw".to_owned(),
        "nosuid".to_owned(),
        "nodev".to_owned(),
        "relatime".to_owned(),
    ]);
    let expected_uid = format!("uid={}", current_euid());
    let expected_gid = format!("gid={}", current_egid());
    let metadata = fs::symlink_metadata("/").map_err(|_| rejected())?;
    if root.root != "/newroot"
        || root.filesystem != "tmpfs"
        || root.source != "tmpfs"
        || root.options != expected_root_options
        || !root.optional_fields.is_empty()
        || !root.super_options.contains("rw")
        || !root.super_options.contains(&expected_uid)
        || !root.super_options.contains(&expected_gid)
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_euid()
        || metadata.permissions().mode() & 0o7777 != 0o555
    {
        return Err(rejected());
    }

    let dev_id = mounts.get("/dev").ok_or_else(rejected)?.mount_id;
    let mount_ids = mounts
        .values()
        .map(|mount| mount.mount_id)
        .collect::<BTreeSet<_>>();
    if mount_ids.contains(&root.parent_id) {
        return Err(rejected());
    }
    for (path, mount) in mounts {
        if path == "/" {
            continue;
        }
        let expected_parent = if path.starts_with("/dev/") {
            dev_id
        } else {
            root.mount_id
        };
        if mount.parent_id != expected_parent {
            return Err(rejected());
        }
    }
    Ok(())
}

fn mount_is_read_only(mounts: &BTreeMap<String, MountRecord>, path: &str) -> bool {
    mounts
        .get(path)
        .is_some_and(|mount| mount.options.contains("ro"))
}

fn verify_empty_directory(path: &Path) -> Result<(), SignError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| rejected())?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || fs::read_dir(path).map_err(|_| rejected())?.next().is_some()
    {
        return Err(rejected());
    }
    Ok(())
}

fn verify_network_namespace() -> Result<(), SignError> {
    let devices = fs::read_to_string("/proc/net/dev").map_err(|_| rejected())?;
    let interfaces = devices
        .lines()
        .skip(2)
        .map(|line| line.split_once(':').map(|(name, _)| name.trim()))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(rejected)?;
    let routes = fs::read_to_string("/proc/net/route").map_err(|_| rejected())?;
    if interfaces != ["lo"] || routes.lines().skip(1).any(|line| !line.trim().is_empty()) {
        return Err(rejected());
    }
    Ok(())
}

fn verify_capabilities_and_kernel_status() -> Result<(), SignError> {
    let status = fs::read_to_string("/proc/self/status").map_err(|_| rejected())?;
    let fields = status
        .lines()
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name, value.trim()))
        })
        .collect::<BTreeMap<_, _>>();
    for field in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
        if fields.get(field).copied() != Some("0000000000000000") {
            return Err(rejected());
        }
    }
    if fields.get("NoNewPrivs").copied() != Some("1") || fields.get("Seccomp").copied() != Some("2")
    {
        return Err(rejected());
    }
    Ok(())
}

fn verify_open_descriptors() -> Result<(), SignError> {
    let directory = fs::read_dir("/proc/self/fd").map_err(|_| rejected())?;
    let mut descriptors = BTreeSet::new();
    for entry in directory {
        let entry = entry.map_err(|_| rejected())?;
        let descriptor = entry
            .file_name()
            .into_string()
            .ok()
            .and_then(|value| value.parse::<i32>().ok())
            .ok_or_else(rejected)?;
        descriptors.insert(descriptor);
    }
    if descriptors.len() != 4 || ![0, 1, 2].iter().all(|fd| descriptors.contains(fd)) {
        return Err(rejected());
    }
    Ok(())
}

fn core_limits() -> Result<(u64, u64), SignError> {
    let mut limits = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: limits points to writable storage for one rlimit value.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, limits.as_mut_ptr()) } != 0 {
        return Err(rejected());
    }
    // SAFETY: successful getrlimit initialized limits.
    let limits = unsafe { limits.assume_init() };
    Ok((limits.rlim_cur, limits.rlim_max))
}

fn verify_launcher_prefilter() -> Result<BTreeMap<String, i32>, SignError> {
    let mut observed = BTreeMap::new();

    let socket = unsafe { libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0) };
    expect_prefilter_errno("socket", socket, libc::EPERM, &mut observed, true)?;

    // SAFETY: the launcher filter resolves before the invalid descriptor is used.
    let connect = unsafe { libc::syscall(libc::SYS_connect, -1, 0, 0) };
    expect_prefilter_errno("connect", connect, libc::EPERM, &mut observed, false)?;

    // A missing process-creation denial must not leave a child behind.
    // SAFETY: fork has no pointer arguments; an unexpected child exits immediately.
    let fork = unsafe { libc::syscall(libc::SYS_fork) };
    if fork == 0 {
        // SAFETY: _exit terminates only the unexpected child without running inherited destructors.
        unsafe { libc::_exit(125) };
    }
    if fork > 0 {
        let mut status = 0;
        // SAFETY: fork returned this child pid and status is writable.
        unsafe { libc::waitpid(fork as libc::pid_t, &mut status, 0) };
        return Err(rejected());
    }
    expect_prefilter_errno("fork", fork, libc::EPERM, &mut observed, false)?;

    let missing = CString::new("/catalog-sign-fixed-nonexistent-exec").expect("fixed path");
    let argv = [missing.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null::<libc::c_char>()];
    // The launcher must permit its one signer exec. This fixed missing target therefore proves the
    // final exec-denying inner filter is not yet installed: ENOENT, not EPERM, is authoritative.
    // SAFETY: path, argv, and envp remain valid for the syscall duration.
    let execve = unsafe {
        libc::syscall(
            libc::SYS_execve,
            missing.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };
    expect_prefilter_errno("execve", execve, libc::ENOENT, &mut observed, false)?;

    let mut io_uring_parameters = [0_u64; 32];
    // SAFETY: the filter rejects before the kernel consumes this writable, over-sized parameter
    // storage. Any unexpected returned ring descriptor is closed by expect_prefilter_errno.
    let setup = unsafe {
        libc::syscall(
            libc::SYS_io_uring_setup,
            1,
            io_uring_parameters.as_mut_ptr(),
        )
    };
    expect_prefilter_errno("io_uring_setup", setup, libc::EPERM, &mut observed, true)?;
    // SAFETY: denied policy resolves before the invalid ring descriptor is inspected.
    let enter = unsafe { libc::syscall(libc::SYS_io_uring_enter, -1, 0, 0, 0, 0, 0) };
    expect_prefilter_errno("io_uring_enter", enter, libc::EPERM, &mut observed, false)?;
    // SAFETY: denied policy resolves before the invalid ring descriptor is inspected.
    let register = unsafe { libc::syscall(libc::SYS_io_uring_register, -1, 0, 0, 0) };
    expect_prefilter_errno(
        "io_uring_register",
        register,
        libc::EPERM,
        &mut observed,
        false,
    )?;

    // unshare(0) is a safe no-op when allowed, while setns(-1, 0) is EBADF when allowed. Their
    // EPERM results therefore distinguish the inherited filter from capability-only failures.
    // SAFETY: both syscalls use scalar arguments only.
    let unshare = unsafe { libc::syscall(libc::SYS_unshare, 0) };
    expect_prefilter_errno("unshare", unshare, libc::EPERM, &mut observed, false)?;
    // SAFETY: invalid descriptor is intentional and the filter resolves first.
    let setns = unsafe { libc::syscall(libc::SYS_setns, -1, 0) };
    expect_prefilter_errno("setns", setns, libc::EPERM, &mut observed, false)?;

    let missing_mount = CString::new("/catalog-sign-fixed-nonexistent-mount").expect("fixed path");
    // SAFETY: the filter resolves before any null mount arguments can be consumed.
    let mount = unsafe { libc::syscall(libc::SYS_mount, 0, missing_mount.as_ptr(), 0, 0, 0) };
    expect_prefilter_errno("mount", mount, libc::EPERM, &mut observed, false)?;
    // SAFETY: fixed path is NUL-terminated and the filter resolves before lookup.
    let umount = unsafe { libc::syscall(libc::SYS_umount2, missing_mount.as_ptr(), 0) };
    expect_prefilter_errno("umount2", umount, libc::EPERM, &mut observed, false)?;
    let relative = CString::new(".").expect("fixed relative path");
    // Without the filter these invalid descriptors produce EBADF before any mount authority can be
    // used, so EPERM safely distinguishes the inherited mount-family policy.
    // SAFETY: fixed path is valid and the launcher filter resolves before descriptor lookup.
    let open_tree = unsafe { libc::syscall(libc::SYS_open_tree, -1, relative.as_ptr(), 0) };
    expect_prefilter_errno("open_tree", open_tree, libc::EPERM, &mut observed, true)?;
    // SAFETY: both fixed paths are valid and the launcher filter resolves before descriptor lookup.
    let move_mount = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            -1,
            relative.as_ptr(),
            -1,
            relative.as_ptr(),
            0,
        )
    };
    expect_prefilter_errno("move_mount", move_mount, libc::EPERM, &mut observed, false)?;

    Ok(observed)
}

fn expect_prefilter_errno(
    name: &str,
    result: libc::c_long,
    expected: i32,
    observed: &mut BTreeMap<String, i32>,
    close_unexpected_descriptor: bool,
) -> Result<(), SignError> {
    if result >= 0 {
        if close_unexpected_descriptor {
            // SAFETY: a nonnegative syscall result in these probes is an owned descriptor.
            unsafe { libc::close(result as i32) };
        }
        return Err(rejected());
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if errno != expected {
        return Err(rejected());
    }
    observed.insert(name.to_owned(), errno);
    Ok(())
}

fn install_inner_seccomp_filter() -> Result<(), SignError> {
    let denied = inner_denied_syscalls();
    let mut filters = seccomp_filter(&denied);
    let program = libc::sock_fprog {
        len: u16::try_from(filters.len()).map_err(|_| rejected())?,
        filter: filters.as_mut_ptr(),
    };
    // SAFETY: program points to initialized classic-BPF instructions for the syscall duration.
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &raw const program,
            0,
            0,
        )
    } != 0
    {
        return Err(rejected());
    }
    Ok(())
}

fn inner_denied_syscalls() -> Vec<i64> {
    vec![
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
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_ptrace,
        libc::SYS_execve,
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
    ]
}

fn seccomp_filter(denied: &[i64]) -> Vec<libc::sock_filter> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JGE_K: u16 = 0x35;
    const BPF_RET_K: u16 = 0x06;
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    let statement = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code, k, jt, jf| libc::sock_filter { code, jt, jf, k };
    let mut filters = vec![
        statement(BPF_LD_W_ABS, 4),
        jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        statement(BPF_LD_W_ABS, 0),
        jump(BPF_JMP_JGE_K, X32_SYSCALL_BIT, 0, 1),
        statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
    ];
    for syscall in denied {
        filters.push(jump(BPF_JMP_JEQ_K, *syscall as u32, 0, 1));
        filters.push(statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    filters.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW));
    filters
}

#[derive(Debug, Serialize)]
struct ProbeReportV1 {
    schema_version: u16,
    launcher_prefilter_errno: BTreeMap<String, i32>,
    inner_filter_errno: BTreeMap<String, i32>,
    core_limit_soft: u64,
    core_limit_hard: u64,
    dumpable: bool,
    environment_names: Vec<String>,
    mount_points: Vec<String>,
}

/// Exercises denied raw syscalls only after successful isolation. The probe has no key mount and
/// cannot authorize normal signing behavior.
pub(crate) fn run_isolation_probe(isolation: &SignerIsolation) -> Result<(), SignError> {
    let attestation = isolation.attestation();
    if attestation.mode != IsolationMode::IsolationProbe {
        return Err(rejected());
    }
    let mut inner_filter_errno = BTreeMap::new();
    let probes: [(&str, i64, [usize; 3]); 16] = [
        (
            "socket",
            libc::SYS_socket,
            [libc::AF_INET as usize, libc::SOCK_STREAM as usize, 0],
        ),
        ("connect", libc::SYS_connect, [usize::MAX, 0, 0]),
        ("fork", libc::SYS_fork, [0, 0, 0]),
        ("vfork", libc::SYS_vfork, [0, 0, 0]),
        ("clone", libc::SYS_clone, [libc::SIGCHLD as usize, 0, 0]),
        ("clone3", libc::SYS_clone3, [0, 0, 0]),
        ("ptrace", libc::SYS_ptrace, [0, 0, 0]),
        ("execve", libc::SYS_execve, [0, 0, 0]),
        ("execveat", libc::SYS_execveat, [0, 0, 0]),
        (
            "unshare",
            libc::SYS_unshare,
            [libc::CLONE_NEWNS as usize, 0, 0],
        ),
        (
            "setns",
            libc::SYS_setns,
            [usize::MAX, libc::CLONE_NEWNS as usize, 0],
        ),
        ("mount", libc::SYS_mount, [0, 0, 0]),
        ("umount2", libc::SYS_umount2, [0, 0, 0]),
        ("io_uring_setup", libc::SYS_io_uring_setup, [1, 0, 0]),
        (
            "io_uring_enter",
            libc::SYS_io_uring_enter,
            [usize::MAX, 0, 0],
        ),
        (
            "io_uring_register",
            libc::SYS_io_uring_register,
            [usize::MAX, 0, 0],
        ),
    ];
    for (name, syscall, arguments) in probes {
        // SAFETY: the denied filter resolves before pointer arguments are dereferenced.
        let result = unsafe { libc::syscall(syscall, arguments[0], arguments[1], arguments[2]) };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if result != -1 || errno != libc::EPERM {
            return Err(rejected());
        }
        inner_filter_errno.insert(name.to_owned(), errno);
    }
    let report = ProbeReportV1 {
        schema_version: 1,
        launcher_prefilter_errno: attestation.launcher_prefilter_errno.clone(),
        inner_filter_errno,
        core_limit_soft: attestation.core_limit_soft,
        core_limit_hard: attestation.core_limit_hard,
        dumpable: attestation.dumpable,
        environment_names: attestation.environment_names.clone(),
        mount_points: attestation.mount_points.clone(),
    };
    let bytes = serde_jcs::to_vec(&report).map_err(|_| rejected())?;
    write_fresh_public_file(Path::new("/output/isolation-probe-v1.json"), &bytes)
}

#[derive(Debug, Serialize)]
struct ReverseTransferManifestV1<'a> {
    schema_version: u16,
    kind: &'static str,
    input_transfer_sha256: &'a str,
    isolation_attestation: &'a IsolationAttestationV1,
    entries: Vec<ReverseTransferEntryV1>,
}

#[derive(Debug, Serialize)]
struct ReverseTransferEntryV1 {
    relative_path: String,
    mode: String,
    size: u64,
    sha256: String,
}

pub fn emit_reverse_transfer_manifest(isolation: &SignerIsolation) -> Result<(), SignError> {
    let attestation = isolation.attestation();
    let expected_top = match attestation.mode {
        IsolationMode::AssembleIntent | IsolationMode::Finalize => "candidate.json",
        IsolationMode::Sign | IsolationMode::RecoverSign => "signed-release-bundle",
        IsolationMode::IsolationProbe => "isolation-probe-v1.json",
    };
    let output = Path::new("/output");
    let names = directory_names(output)?;
    let manifest_exists = names.contains("transfer-manifest-v1.json");
    let recovery_binding_exists = names.contains("sign-recovery-binding-v1.json");
    let mut expected_names = BTreeSet::from([expected_top.to_owned()]);
    if manifest_exists {
        expected_names.insert("transfer-manifest-v1.json".to_owned());
    }
    if recovery_binding_exists {
        expected_names.insert("sign-recovery-binding-v1.json".to_owned());
    }
    if names != expected_names
        || (matches!(
            attestation.mode,
            IsolationMode::Sign | IsolationMode::RecoverSign
        ) && !manifest_exists
            && !recovery_binding_exists)
        || (!matches!(
            attestation.mode,
            IsolationMode::Sign | IsolationMode::RecoverSign
        ) && recovery_binding_exists)
    {
        return Err(rejected());
    }
    let mut paths = Vec::new();
    collect_output_paths(output, Path::new(expected_top), &mut paths)?;
    if paths.is_empty() || paths.len() > MAX_OUTPUT_ENTRIES {
        return Err(rejected());
    }
    paths.sort();
    let mut total = 0_u64;
    let mut entries = Vec::with_capacity(paths.len());
    for relative in paths {
        let path = output.join(&relative);
        let metadata = fs::symlink_metadata(&path).map_err(|_| rejected())?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != current_euid()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != 0o400
            || metadata.len() == 0
            || metadata.len() > MAX_OUTPUT_BYTES
        {
            return Err(rejected());
        }
        total = total.checked_add(metadata.len()).ok_or_else(rejected)?;
        if total > MAX_OUTPUT_BYTES {
            return Err(rejected());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| rejected())?;
        entries.push(ReverseTransferEntryV1 {
            relative_path: relative.to_string_lossy().into_owned(),
            mode: "0400".to_owned(),
            size: metadata.len(),
            sha256: hash_descriptor(&file, metadata.len())?,
        });
    }
    if manifest_exists {
        verify_existing_reverse_manifest(attestation, &entries)?;
    } else {
        let manifest = ReverseTransferManifestV1 {
            schema_version: 1,
            kind: "signer_output",
            input_transfer_sha256: attestation.input_transfer_sha256(),
            isolation_attestation: attestation,
            entries,
        };
        let bytes = serde_jcs::to_vec(&manifest).map_err(|_| rejected())?;
        write_fresh_public_file(Path::new(OUTPUT_MANIFEST), &bytes)?;
    }
    if recovery_binding_exists {
        settle_recovery_binding(attestation)?;
    }
    fs::File::open(output)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| rejected())
}

fn settle_recovery_binding(attestation: &IsolationAttestationV1) -> Result<(), SignError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(RECOVERY_BINDING)
        .map_err(|_| rejected())?;
    let metadata = file.metadata().map_err(|_| rejected())?;
    if metadata.uid() != current_euid()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o400
        || metadata.len() == 0
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err(rejected());
    }
    let mut retained = file.try_clone().map_err(|_| rejected())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    retained.read_to_end(&mut bytes).map_err(|_| rejected())?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| rejected())?;
    if serde_jcs::to_vec(&value).map_err(|_| rejected())? != bytes
        || value.as_object().is_none_or(|object| object.len() != 7)
        || value["schema_version"] != 1
        || value["kind"] != "sign_recovery_binding"
        || value["original_operation_mode"] != "sign"
        || value["input_transfer_sha256"] != attestation.input_transfer_sha256
        || value["launcher_config_sha256"] != attestation.launcher_config_sha256
        || value["signer_sha256"] != attestation.signer_sha256
        || !valid_settled_staging_binding(&value["staging"])
    {
        return Err(rejected());
    }
    let output = fs::File::open("/output").map_err(|_| rejected())?;
    let name = CString::new("sign-recovery-binding-v1.json").expect("fixed recovery binding");
    // SAFETY: retained output and exact verified one-link regular name are valid.
    if unsafe { libc::unlinkat(output.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(SignError::OutputDurabilityUncertain);
    }
    output
        .sync_all()
        .map_err(|_| SignError::OutputDurabilityUncertain)
}

fn verify_existing_reverse_manifest(
    current: &IsolationAttestationV1,
    expected_entries: &[ReverseTransferEntryV1],
) -> Result<(), SignError> {
    let path = Path::new(OUTPUT_MANIFEST);
    let metadata = fs::symlink_metadata(path).map_err(|_| rejected())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_euid()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o400
        || metadata.len() == 0
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err(rejected());
    }
    let bytes = fs::read(path).map_err(|_| rejected())?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| rejected())?;
    if serde_jcs::to_vec(&value).map_err(|_| rejected())? != bytes
        || value.as_object().is_none_or(|object| object.len() != 5)
        || value["schema_version"] != 1
        || value["kind"] != "signer_output"
        || value["input_transfer_sha256"] != current.input_transfer_sha256()
        || value["isolation_attestation"]["launcher_config_sha256"]
            != current.launcher_config_sha256
        || value["isolation_attestation"]["signer_sha256"] != current.signer_sha256
        || value["entries"] != serde_json::to_value(expected_entries).map_err(|_| rejected())?
    {
        return Err(rejected());
    }
    let historical_mode = value
        .pointer("/isolation_attestation/mode")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(rejected)?;
    let historical_original = value
        .pointer("/isolation_attestation/original_operation_mode")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(rejected)?;
    let mode_matches = match current.mode {
        IsolationMode::RecoverSign => {
            authorized_recovery_mode_combination(historical_original, historical_mode)
        }
        IsolationMode::AssembleIntent => {
            historical_original == "assemble-intent" && historical_mode == "assemble-intent"
        }
        IsolationMode::Finalize => {
            historical_original == "finalize" && historical_mode == "finalize"
        }
        IsolationMode::Sign => historical_original == "sign" && historical_mode == "sign",
        IsolationMode::IsolationProbe => {
            historical_original == "isolation-probe" && historical_mode == "isolation-probe"
        }
    };
    if !mode_matches {
        return Err(rejected());
    }
    Ok(())
}

fn authorized_recovery_mode_combination(original: &str, completion: &str) -> bool {
    original == "sign" && matches!(completion, "sign" | "recover-sign")
}

fn valid_settled_staging_binding(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == 6
        && object
            .get("relative_name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(valid_staging_name)
        && object
            .get("device")
            .and_then(serde_json::Value::as_u64)
            .is_some()
        && object
            .get("inode")
            .and_then(serde_json::Value::as_u64)
            .is_some()
        && object.get("uid").and_then(serde_json::Value::as_u64) == Some(u64::from(current_euid()))
        && object.get("mode").and_then(serde_json::Value::as_u64) == Some(0o700)
        && object
            .get("cleanup_authorized")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
}

fn valid_staging_name(name: &str) -> bool {
    const PREFIX: &str = ".catalog-sign-stage-";
    name.len() == PREFIX.len() + 32
        && name.starts_with(PREFIX)
        && name[PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn collect_output_paths(
    root: &Path,
    relative: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), SignError> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|_| rejected())?;
    if metadata.file_type().is_symlink() || metadata.uid() != current_euid() {
        return Err(rejected());
    }
    if metadata.is_file() {
        output.push(relative.to_owned());
        return Ok(());
    }
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.nlink() != 2
    {
        return Err(rejected());
    }
    for name in directory_names(&path)? {
        collect_output_paths(root, &relative.join(name), output)?;
    }
    Ok(())
}

fn directory_names(path: &Path) -> Result<BTreeSet<String>, SignError> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(path).map_err(|_| rejected())? {
        let entry = entry.map_err(|_| rejected())?;
        let name = entry.file_name().into_string().map_err(|_| rejected())?;
        if !safe_component(&name) || !names.insert(name) {
            return Err(rejected());
        }
    }
    Ok(names)
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReverseManifestCheckpoint {
    Link,
    ParentFsync,
    Reopen,
}

#[cfg(test)]
thread_local! {
    static REVERSE_MANIFEST_FAULT: std::cell::Cell<Option<ReverseManifestCheckpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn set_reverse_manifest_fault(checkpoint: ReverseManifestCheckpoint) {
    REVERSE_MANIFEST_FAULT.set(Some(checkpoint));
}

#[cfg(test)]
fn take_reverse_manifest_fault(checkpoint: ReverseManifestCheckpoint) -> bool {
    REVERSE_MANIFEST_FAULT.with(|fault| {
        if fault.get() == Some(checkpoint) {
            fault.set(None);
            true
        } else {
            false
        }
    })
}

fn write_fresh_public_file(path: &Path, bytes: &[u8]) -> Result<(), SignError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(rejected());
    }
    let parent_path = path.parent().ok_or_else(rejected)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| safe_component(name))
        .ok_or_else(rejected)?;
    let parent = fs::File::open(parent_path).map_err(|_| rejected())?;
    let dot = CString::new(".").expect("fixed temporary path");
    // SAFETY: retained directory and fixed path are valid; O_TMPFILE has no visible partial name.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            dot.as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(rejected());
    }
    // SAFETY: openat returned one owned descriptor.
    let mut file = unsafe { fs::File::from_raw_fd(descriptor) };
    file.write_all(bytes).map_err(|_| rejected())?;
    file.flush().map_err(|_| rejected())?;
    file.set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(|_| rejected())?;
    file.sync_all().map_err(|_| rejected())?;
    verify_exact_public_file(&file, bytes, 0)?;
    #[cfg(test)]
    if take_reverse_manifest_fault(ReverseManifestCheckpoint::Link) {
        return Err(rejected());
    }
    let name = CString::new(name).map_err(|_| rejected())?;
    // SAFETY: AT_EMPTY_PATH links the exact settled unnamed inode without replacement.
    if unsafe {
        libc::linkat(
            file.as_raw_fd(),
            c"".as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    } != 0
    {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(rejected());
        }
        let existing = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| rejected())?;
        return verify_exact_public_file(&existing, bytes, 1);
    }
    #[cfg(test)]
    if take_reverse_manifest_fault(ReverseManifestCheckpoint::ParentFsync) {
        return Err(SignError::OutputDurabilityUncertain);
    }
    parent
        .sync_all()
        .map_err(|_| SignError::OutputDurabilityUncertain)?;
    #[cfg(test)]
    if take_reverse_manifest_fault(ReverseManifestCheckpoint::Reopen) {
        return Err(SignError::OutputDurabilityUncertain);
    }
    let reopened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| rejected())?;
    verify_exact_public_file(&reopened, bytes, 1)
}

fn verify_exact_public_file(file: &fs::File, expected: &[u8], links: u64) -> Result<(), SignError> {
    let metadata = file.metadata().map_err(|_| rejected())?;
    if metadata.len() != expected.len() as u64
        || metadata.uid() != current_euid()
        || metadata.nlink() != links
        || metadata.permissions().mode() & 0o7777 != 0o400
        || hash_descriptor(file, metadata.len())? != sha256(expected)
    {
        return Err(rejected());
    }
    Ok(())
}

fn hash_descriptor(file: &fs::File, expected_size: u64) -> Result<String, SignError> {
    let mut file = file.try_clone().map_err(|_| rejected())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| rejected())?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| rejected())?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(rejected)?;
        if total > expected_size {
            return Err(rejected());
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_size {
        return Err(rejected());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'/')
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn current_egid() -> u32 {
    // SAFETY: getegid has no preconditions.
    unsafe { libc::getegid() }
}

const fn rejected() -> SignError {
    SignError::IsolationRejected
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    #[test]
    fn recovery_mode_combinations_are_exact() {
        assert!(authorized_recovery_mode_combination("sign", "sign"));
        assert!(authorized_recovery_mode_combination("sign", "recover-sign"));
        for (original, completion) in [
            ("recover-sign", "recover-sign"),
            ("recover-sign", "sign"),
            ("sign", "assemble-intent"),
            ("sign", "finalize"),
            ("finalize", "recover-sign"),
        ] {
            assert!(!authorized_recovery_mode_combination(original, completion));
        }
    }

    #[test]
    fn reverse_manifest_visibility_faults_are_atomic_and_idempotently_completable() {
        let root = TempDirectory::new();
        let bytes = br#"{"kind":"signer_output","schema_version":1}"#;
        for checkpoint in [
            ReverseManifestCheckpoint::Link,
            ReverseManifestCheckpoint::ParentFsync,
            ReverseManifestCheckpoint::Reopen,
        ] {
            let path = root
                .path
                .join(format!("manifest-{}.json", checkpoint as u8));
            set_reverse_manifest_fault(checkpoint);
            assert!(write_fresh_public_file(&path, bytes).is_err());
            if checkpoint == ReverseManifestCheckpoint::Link {
                assert!(!path.exists());
            } else {
                assert_eq!(fs::read(&path).unwrap(), bytes);
                write_fresh_public_file(&path, bytes).unwrap();
                assert_eq!(fs::read(&path).unwrap(), bytes);
            }
        }

        let conflicting = root.path.join("conflicting.json");
        fs::write(&conflicting, b"conflicting-partial").unwrap();
        fs::set_permissions(&conflicting, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(write_fresh_public_file(&conflicting, bytes).is_err());
        assert_eq!(fs::read(conflicting).unwrap(), b"conflicting-partial");
    }

    struct TempDirectory {
        path: PathBuf,
    }

    impl TempDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "catalog-reverse-manifest-test-{}-{nonce}",
                std::process::id()
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
