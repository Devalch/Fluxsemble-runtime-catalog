use std::{
    ffi::{CString, OsStr},
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    process::Stdio,
};

use catalog_sign::{SignError, verify_transferred_bundle};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_BWRAP_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SIGNER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_KEY_BYTES: u64 = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LauncherConfigV1 {
    schema_version: u16,
    bwrap_path: String,
    bwrap_sha256: String,
    signer_path: String,
    signer_sha256: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ceremony {
    AssembleIntent,
    Finalize,
    Sign,
}

impl Ceremony {
    const fn command(self) -> &'static str {
        match self {
            Self::AssembleIntent => "assemble-intent",
            Self::Finalize => "finalize",
            Self::Sign => "sign",
        }
    }
}

struct Request {
    ceremony: Ceremony,
    config: PathBuf,
    input: PathBuf,
    key: Option<PathBuf>,
    output: PathBuf,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    uid: u32,
    mode: u32,
    links: u64,
}

impl Identity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
            links: metadata.nlink(),
        }
    }
}

struct VerifiedExecutable {
    path: PathBuf,
    file: fs::File,
    identity: Identity,
    sha256: String,
}

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    match parse_request(&arguments).and_then(launch) {
        Ok(()) => println!("catalog signer completed"),
        Err(_) => fail(),
    }
}

fn fail() -> ! {
    eprintln!("catalog signing launcher failed");
    std::process::exit(1);
}

fn parse_request(args: &[std::ffi::OsString]) -> Result<Request, SignError> {
    if args.iter().any(|argument| argument.as_bytes().contains(&0))
        || args
            .iter()
            .map(|argument| argument.as_bytes().len())
            .sum::<usize>()
            > 20 * 1024
    {
        return Err(rejected());
    }
    let value = |index: usize| {
        args.get(index)
            .filter(|value| !value.is_empty() && value.as_bytes().len() <= 4_096)
            .map(PathBuf::from)
            .ok_or_else(rejected)
    };
    match args.first().and_then(|value| value.to_str()) {
        Some("assemble-intent") | Some("finalize") if args.len() == 7 => {
            if args[1] != "--config" || args[3] != "--input" || args[5] != "--output" {
                return Err(rejected());
            }
            Ok(Request {
                ceremony: if args[0] == "assemble-intent" {
                    Ceremony::AssembleIntent
                } else {
                    Ceremony::Finalize
                },
                config: value(2)?,
                input: value(4)?,
                key: None,
                output: value(6)?,
            })
        }
        Some("sign") if args.len() == 9 => {
            if args[1] != "--config"
                || args[3] != "--input"
                || args[5] != "--key"
                || args[7] != "--output"
            {
                return Err(rejected());
            }
            Ok(Request {
                ceremony: Ceremony::Sign,
                config: value(2)?,
                input: value(4)?,
                key: Some(value(6)?),
                output: value(8)?,
            })
        }
        _ => Err(rejected()),
    }
}

fn launch(request: Request) -> Result<(), SignError> {
    let (config, config_file, config_identity, config_sha256) = read_config(&request.config)?;
    let bwrap = verify_bwrap(&config)?;
    let signer = verify_static_signer(&config)?;
    rebind_exact(
        &request.config,
        &config_file,
        config_identity,
        FilePolicy::Config,
    )?;
    verify_descriptor_digest(&config_file, config_identity.size, &config_sha256)?;

    let input_path = require_canonical_absolute(&request.input)?;
    let verified_input = verify_transferred_bundle(&input_path)?;
    let (input, input_transfer_sha256) = verified_input.isolated_launch_capability()?;
    let input_identity = Identity::from_metadata(&input.metadata().map_err(|_| rejected())?);

    // Every public input and executable substitution check precedes any key descriptor open.
    rebind_executable(&bwrap, FilePolicy::Bwrap)?;
    rebind_executable(&signer, FilePolicy::Signer)?;
    verified_input.isolated_launch_capability()?;

    let key = request
        .key
        .as_ref()
        .map(|path| open_key_capability(path))
        .transpose()?;
    if (request.ceremony == Ceremony::Sign) != key.is_some() {
        return Err(rejected());
    }

    // Final named-identity checkpoints happen before the fresh output becomes visible.
    rebind_executable(&bwrap, FilePolicy::Bwrap)?;
    rebind_executable(&signer, FilePolicy::Signer)?;
    verify_input_capability(&input, input_identity)?;
    if let Some((path, file, identity)) = &key {
        rebind_exact(path, file, *identity, FilePolicy::Key)?;
    }

    let output = create_fresh_output(&request.output)?;
    let output_identity = Identity::from_metadata(&output.metadata().map_err(|_| rejected())?);
    verify_output_capability(&output, output_identity)?;
    rebind_executable(&bwrap, FilePolicy::Bwrap)?;
    rebind_executable(&signer, FilePolicy::Signer)?;
    verified_input.isolated_launch_capability()?;
    rebind_executable(&signer, FilePolicy::Signer)?;
    verify_input_capability(&input, input_identity)?;
    if let Some((path, file, identity)) = &key {
        rebind_exact(path, file, *identity, FilePolicy::Key)?;
    }

    let seccomp = create_launcher_seccomp()?;
    let inherited = [
        Some(signer.file.as_raw_fd()),
        Some(input.as_raw_fd()),
        Some(output.as_raw_fd()),
        key.as_ref().map(|(_, file, _)| file.as_raw_fd()),
        Some(seccomp.as_raw_fd()),
    ];
    for descriptor in inherited.into_iter().flatten() {
        set_close_on_exec(descriptor, false)?;
    }

    let host_namespaces = host_namespace_identities()?;
    let bwrap_exec = format!("/proc/self/fd/{}", bwrap.file.as_raw_fd());
    let mut command = std::process::Command::new(&bwrap_exec);
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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
            request.ceremony.command(),
            "--setenv",
            "CATALOG_SIGN_INPUT_SHA256",
            &input_transfer_sha256,
            "--setenv",
            "CATALOG_SIGN_EUID",
            &current_euid().to_string(),
            "--setenv",
            "CATALOG_SIGN_EGID",
            &current_egid().to_string(),
            "--setenv",
            "CATALOG_SIGN_HOST_PID_NS",
            &host_namespaces[0],
            "--setenv",
            "CATALOG_SIGN_HOST_USER_NS",
            &host_namespaces[1],
            "--setenv",
            "CATALOG_SIGN_HOST_MOUNT_NS",
            &host_namespaces[2],
            "--setenv",
            "CATALOG_SIGN_HOST_NETWORK_NS",
            &host_namespaces[3],
            "--cap-drop",
            "ALL",
            "--dir",
            "/bin",
            "--ro-bind-fd",
            &signer.file.as_raw_fd().to_string(),
            "/bin/catalog-sign",
            "--ro-bind-fd",
            &input.as_raw_fd().to_string(),
            "/input",
            "--bind-fd",
            &output.as_raw_fd().to_string(),
            "/output",
        ]);
    if let Some((_, key, _)) = &key {
        command.args([
            "--dir",
            "/key",
            "--ro-bind-fd",
            &key.as_raw_fd().to_string(),
            "/key/runtime-catalog-private.pem",
        ]);
    }
    command.args([
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
    ]);
    match request.ceremony {
        Ceremony::AssembleIntent | Ceremony::Finalize => {
            command.args([
                request.ceremony.command(),
                "--input",
                "/input",
                "--output",
                "/output/candidate.json",
            ]);
        }
        Ceremony::Sign => {
            command.args([
                "sign",
                "--input",
                "/input",
                "--key",
                "/key/runtime-catalog-private.pem",
                "--output",
                "/output/signed-release-bundle",
            ]);
        }
    }

    let status = command.status().map_err(|_| rejected())?;
    if !status.success() {
        return Err(rejected());
    }
    verify_output_capability(&output, output_identity)?;
    let manifest = output.join_path("transfer-manifest-v1.json")?;
    let metadata = manifest.metadata().map_err(|_| rejected())?;
    if !secure_regular(&metadata, current_euid(), 0o400, MAX_CONFIG_BYTES * 64) {
        return Err(rejected());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum FilePolicy {
    Config,
    Bwrap,
    Signer,
    Key,
}

fn read_config(path: &Path) -> Result<(LauncherConfigV1, fs::File, Identity, String), SignError> {
    let canonical = require_canonical_absolute(path)?;
    let file = open_absolute_no_links(
        &canonical,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
    )?;
    let before = file.metadata().map_err(|_| rejected())?;
    if !secure_regular(&before, current_euid(), 0o600, MAX_CONFIG_BYTES) || before.len() == 0 {
        return Err(rejected());
    }
    let identity = Identity::from_metadata(&before);
    let bytes = read_bounded(&file, before.len())?;
    let config: LauncherConfigV1 = serde_json::from_slice(&bytes).map_err(|_| rejected())?;
    if config.schema_version != 1
        || serde_jcs::to_vec(&config_to_value(&config)).map_err(|_| rejected())? != bytes
        || !valid_sha256(&config.bwrap_sha256)
        || !valid_sha256(&config.signer_sha256)
    {
        return Err(rejected());
    }
    let digest = sha256(&bytes);
    rebind_exact(&canonical, &file, identity, FilePolicy::Config)?;
    verify_descriptor_digest(&file, identity.size, &digest)?;
    Ok((config, file, identity, digest))
}

fn config_to_value(config: &LauncherConfigV1) -> serde_json::Value {
    serde_json::json!({
        "schema_version": config.schema_version,
        "bwrap_path": config.bwrap_path,
        "bwrap_sha256": config.bwrap_sha256,
        "signer_path": config.signer_path,
        "signer_sha256": config.signer_sha256,
    })
}

fn verify_bwrap(config: &LauncherConfigV1) -> Result<VerifiedExecutable, SignError> {
    let path = require_canonical_absolute(Path::new(&config.bwrap_path))?;
    let file = open_absolute_no_links(&path, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK)?;
    let metadata = file.metadata().map_err(|_| rejected())?;
    if !secure_regular(&metadata, 0, 0o755, MAX_BWRAP_BYTES)
        || hash_descriptor(&file, metadata.len())? != config.bwrap_sha256
    {
        return Err(rejected());
    }
    let executable = VerifiedExecutable {
        path,
        file,
        identity: Identity::from_metadata(&metadata),
        sha256: config.bwrap_sha256.clone(),
    };
    rebind_executable(&executable, FilePolicy::Bwrap)?;
    Ok(executable)
}

fn verify_static_signer(config: &LauncherConfigV1) -> Result<VerifiedExecutable, SignError> {
    let path = require_canonical_absolute(Path::new(&config.signer_path))?;
    let file = open_absolute_no_links(&path, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK)?;
    let metadata = file.metadata().map_err(|_| rejected())?;
    if !secure_regular(&metadata, current_euid(), 0o500, MAX_SIGNER_BYTES)
        || hash_descriptor(&file, metadata.len())? != config.signer_sha256
        || !is_static_x86_64_elf(&file, metadata.len())?
    {
        return Err(rejected());
    }
    let executable = VerifiedExecutable {
        path,
        file,
        identity: Identity::from_metadata(&metadata),
        sha256: config.signer_sha256.clone(),
    };
    rebind_executable(&executable, FilePolicy::Signer)?;
    Ok(executable)
}

fn rebind_executable(executable: &VerifiedExecutable, policy: FilePolicy) -> Result<(), SignError> {
    rebind_exact(
        &executable.path,
        &executable.file,
        executable.identity,
        policy,
    )?;
    verify_descriptor_digest(
        &executable.file,
        executable.identity.size,
        &executable.sha256,
    )
}

fn rebind_exact(
    path: &Path,
    retained: &fs::File,
    identity: Identity,
    policy: FilePolicy,
) -> Result<(), SignError> {
    let rebound =
        open_absolute_no_links(path, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK)?;
    let retained_metadata = retained.metadata().map_err(|_| rejected())?;
    let rebound_metadata = rebound.metadata().map_err(|_| rejected())?;
    if Identity::from_metadata(&retained_metadata) != identity
        || Identity::from_metadata(&rebound_metadata) != identity
    {
        return Err(rejected());
    }
    let secure = match policy {
        FilePolicy::Config => {
            secure_regular(&retained_metadata, current_euid(), 0o600, MAX_CONFIG_BYTES)
        }
        FilePolicy::Bwrap => secure_regular(&retained_metadata, 0, 0o755, MAX_BWRAP_BYTES),
        FilePolicy::Signer => {
            secure_regular(&retained_metadata, current_euid(), 0o500, MAX_SIGNER_BYTES)
        }
        FilePolicy::Key => secure_key(&retained_metadata),
    };
    if !secure {
        return Err(rejected());
    }
    Ok(())
}

fn open_key_capability(path: &Path) -> Result<(PathBuf, fs::File, Identity), SignError> {
    let canonical = require_canonical_absolute(path)?;
    let file = open_absolute_no_links(
        &canonical,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
    )?;
    let metadata = file.metadata().map_err(|_| rejected())?;
    if !secure_key(&metadata) {
        return Err(rejected());
    }
    let identity = Identity::from_metadata(&metadata);
    rebind_exact(&canonical, &file, identity, FilePolicy::Key)?;
    Ok((canonical, file, identity))
}

fn secure_key(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.nlink() == 1
        && matches!(metadata.permissions().mode() & 0o7777, 0o400 | 0o600)
        && metadata.len() > 0
        && metadata.len() <= MAX_KEY_BYTES
}

fn verify_input_capability(input: &fs::File, identity: Identity) -> Result<(), SignError> {
    let metadata = input.metadata().map_err(|_| rejected())?;
    if Identity::from_metadata(&metadata) != identity
        || !metadata.is_dir()
        || metadata.uid() != current_euid()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(rejected());
    }
    Ok(())
}

struct OutputCapability {
    parent: fs::File,
    name: CString,
    file: fs::File,
}

impl OutputCapability {
    fn as_raw_fd(&self) -> i32 {
        self.file.as_raw_fd()
    }

    fn metadata(&self) -> std::io::Result<fs::Metadata> {
        self.file.metadata()
    }

    fn join_path(&self, name: &str) -> Result<fs::File, SignError> {
        let name = CString::new(name).map_err(|_| rejected())?;
        // SAFETY: descriptor and validated fixed component are valid.
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            return Err(rejected());
        }
        // SAFETY: openat returned one owned descriptor.
        Ok(unsafe { fs::File::from_raw_fd(descriptor) })
    }
}

fn create_fresh_output(path: &Path) -> Result<OutputCapability, SignError> {
    if !path.is_absolute() || path.as_os_str().as_bytes().len() > 4_096 {
        return Err(rejected());
    }
    let name = path
        .file_name()
        .filter(|name| safe_component(name))
        .ok_or_else(rejected)?;
    let parent_path = path.parent().ok_or_else(rejected)?;
    let parent_path = require_canonical_absolute(parent_path)?;
    let parent = open_absolute_no_links(
        &parent_path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )?;
    let metadata = parent.metadata().map_err(|_| rejected())?;
    if !secure_private_directory(&metadata) {
        return Err(rejected());
    }
    let name = CString::new(name.as_bytes()).map_err(|_| rejected())?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent/name/stat are valid.
    let present = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if present == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        return Err(rejected());
    }
    // SAFETY: retained parent/name/mode are valid and mkdirat does not replace.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(rejected());
    }
    parent.sync_all().map_err(|_| rejected())?;
    // SAFETY: name was just created and O_NOFOLLOW prevents substitution.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(rejected());
    }
    // SAFETY: openat returned one owned descriptor.
    let file = unsafe { fs::File::from_raw_fd(descriptor) };
    let output = OutputCapability { parent, name, file };
    let identity = Identity::from_metadata(&output.file.metadata().map_err(|_| rejected())?);
    verify_output_capability(&output, identity)?;
    Ok(output)
}

fn verify_output_capability(
    output: &OutputCapability,
    identity: Identity,
) -> Result<(), SignError> {
    let metadata = output.file.metadata().map_err(|_| rejected())?;
    if !secure_private_directory(&metadata) || Identity::from_metadata(&metadata) != identity {
        return Err(rejected());
    }
    // SAFETY: retained parent/name are valid and no-follow rebinds the visible name.
    let descriptor = unsafe {
        libc::openat(
            output.parent.as_raw_fd(),
            output.name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(rejected());
    }
    // SAFETY: openat returned one owned descriptor.
    let rebound = unsafe { fs::File::from_raw_fd(descriptor) };
    if Identity::from_metadata(&rebound.metadata().map_err(|_| rejected())?) != identity {
        return Err(rejected());
    }
    Ok(())
}

fn require_canonical_absolute(path: &Path) -> Result<PathBuf, SignError> {
    if !path.is_absolute() || path.as_os_str().as_bytes().len() > 4_096 {
        return Err(rejected());
    }
    let canonical = fs::canonicalize(path).map_err(|_| rejected())?;
    if canonical != path {
        return Err(rejected());
    }
    Ok(canonical)
}

fn open_absolute_no_links(path: &Path, final_flags: i32) -> Result<fs::File, SignError> {
    if !path.is_absolute() {
        return Err(rejected());
    }
    let root = CString::new("/").expect("fixed root path");
    // SAFETY: fixed path and flags are valid.
    let root_fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if root_fd < 0 {
        return Err(rejected());
    }
    // SAFETY: open returned one owned descriptor.
    let mut current = unsafe { fs::File::from_raw_fd(root_fd) };
    let components = path.components().skip(1).collect::<Vec<_>>();
    if components.is_empty() {
        return Err(rejected());
    }
    for (index, component) in components.iter().enumerate() {
        let value = match component {
            std::path::Component::Normal(value) if safe_component(value) => value,
            _ => return Err(rejected()),
        };
        let value = CString::new(value.as_bytes()).map_err(|_| rejected())?;
        let flags = if index + 1 == components.len() {
            final_flags | libc::O_NOFOLLOW
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
        };
        // SAFETY: retained directory, component, and flags are valid.
        let descriptor = unsafe { libc::openat(current.as_raw_fd(), value.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(rejected());
        }
        // SAFETY: openat returned one owned descriptor.
        let next = unsafe { fs::File::from_raw_fd(descriptor) };
        if index + 1 != components.len()
            && !safe_ancestor(&next.metadata().map_err(|_| rejected())?)
        {
            return Err(rejected());
        }
        current = next;
    }
    Ok(current)
}

fn safe_ancestor(metadata: &fs::Metadata) -> bool {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return false;
    }
    let mode = metadata.permissions().mode() & 0o7777;
    (metadata.uid() == 0 && matches!(mode, 0o555 | 0o755 | 0o1777))
        || (metadata.uid() == current_euid() && mode == 0o700)
}

fn secure_regular(metadata: &fs::Metadata, owner: u32, mode: u32, maximum: u64) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == owner
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == mode
        && metadata.len() > 0
        && metadata.len() <= maximum
}

fn secure_private_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.permissions().mode() & 0o7777 == 0o700
}

fn safe_component(value: &OsStr) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 255
        && !matches!(bytes, b"." | b"..")
        && !bytes.contains(&b'/')
        && !bytes.contains(&0)
}

fn verify_descriptor_digest(file: &fs::File, size: u64, expected: &str) -> Result<(), SignError> {
    if hash_descriptor(file, size)? != expected {
        return Err(rejected());
    }
    Ok(())
}

fn read_bounded(file: &fs::File, size: u64) -> Result<Vec<u8>, SignError> {
    let mut file = file.try_clone().map_err(|_| rejected())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| rejected())?;
    let mut bytes = Vec::with_capacity(size as usize);
    (&mut file)
        .take(size + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| rejected())?;
    if bytes.len() as u64 != size {
        return Err(rejected());
    }
    Ok(bytes)
}

fn hash_descriptor(file: &fs::File, size: u64) -> Result<String, SignError> {
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
        if total > size {
            return Err(rejected());
        }
        hasher.update(&buffer[..read]);
    }
    if total != size {
        return Err(rejected());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn is_static_x86_64_elf(file: &fs::File, size: u64) -> Result<bool, SignError> {
    if size < 64 {
        return Ok(false);
    }
    let bytes = read_bounded(file, size)?;
    if &bytes[..4] != b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || u16_le(&bytes, 18)? != 62
        || !matches!(u16_le(&bytes, 16)?, 2 | 3)
        || u16_le(&bytes, 54)? != 56
    {
        return Ok(false);
    }
    let offset = usize::try_from(u64_le(&bytes, 32)?).map_err(|_| rejected())?;
    let count = usize::from(u16_le(&bytes, 56)?);
    if count == 0
        || count > 128
        || offset
            .checked_add(count * 56)
            .is_none_or(|end| end > bytes.len())
    {
        return Ok(false);
    }
    let mut load = false;
    for index in 0..count {
        let kind = u32_le(&bytes, offset + index * 56)?;
        if matches!(kind, 2 | 3) {
            return Ok(false);
        }
        load |= kind == 1;
    }
    Ok(load)
}

fn u16_le(bytes: &[u8], offset: usize) -> Result<u16, SignError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(rejected)
}
fn u32_le(bytes: &[u8], offset: usize) -> Result<u32, SignError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(rejected)
}
fn u64_le(bytes: &[u8], offset: usize) -> Result<u64, SignError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(rejected)
}

fn create_launcher_seccomp() -> Result<fs::File, SignError> {
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
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
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
    let filters = seccomp_filter(&denied);
    let name = CString::new("catalog-sign-seccomp").expect("fixed memfd name");
    // SAFETY: fixed name and close-on-exec flag are valid.
    let descriptor =
        unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), libc::MFD_CLOEXEC) } as i32;
    if descriptor < 0 {
        return Err(rejected());
    }
    // SAFETY: memfd_create returned one owned descriptor.
    let mut file = unsafe { fs::File::from_raw_fd(descriptor) };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            filters.as_ptr().cast::<u8>(),
            filters.len() * std::mem::size_of::<libc::sock_filter>(),
        )
    };
    file.write_all(bytes).map_err(|_| rejected())?;
    file.flush().map_err(|_| rejected())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| rejected())?;
    Ok(file)
}

fn seccomp_filter(denied: &[i64]) -> Vec<libc::sock_filter> {
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
        filters.push(jump(0x15, *syscall as u32, 0, 1));
        filters.push(statement(0x06, 0x0005_0000 | libc::EPERM as u32));
    }
    filters.push(statement(0x06, 0x7fff_0000));
    filters
}

fn set_close_on_exec(descriptor: i32, close: bool) -> Result<(), SignError> {
    // SAFETY: fcntl reads flags for an open retained descriptor.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 {
        return Err(rejected());
    }
    let updated = if close {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    // SAFETY: F_SETFD updates only descriptor flags.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, updated) } != 0 {
        return Err(rejected());
    }
    Ok(())
}

fn host_namespace_identities() -> Result<[String; 4], SignError> {
    let mut values = Vec::with_capacity(4);
    for name in ["pid", "user", "mnt", "net"] {
        let value = fs::read_link(format!("/proc/self/ns/{name}"))
            .map_err(|_| rejected())?
            .to_string_lossy()
            .into_owned();
        if !value.starts_with(&format!("{name}:[")) || !value.ends_with(']') {
            return Err(rejected());
        }
        values.push(value);
    }
    values.try_into().map_err(|_| rejected())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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
