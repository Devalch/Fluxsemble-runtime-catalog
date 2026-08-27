use std::{
    ffi::{CString, OsStr, OsString},
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::broker::{BrokerRequestV1, BrokerResponseV1};

const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_STDERR_BYTES: usize = 4 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);
#[cfg(test)]
const BROKER_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(not(test))]
const BROKER_TIMEOUT: Duration = Duration::from_secs(300);

/// Owner-private configuration for the unauthenticated publisher-side broker client. It contains
/// only exact broker executable and Task 9 broker-configuration identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherBrokerClientConfigV1 {
    pub schema_version: u16,
    pub catalog_gh_broker_path: String,
    pub catalog_gh_broker_sha256: String,
    pub publisher_broker_config_path: String,
    pub publisher_broker_config_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrokerIdentityDigests {
    pub broker_client_config_sha256: String,
    pub broker_executable_sha256: String,
    pub publisher_broker_config_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BrokerClientError;

struct RetainedFile {
    path: PathBuf,
    file: fs::File,
    identity: Identity,
    sha256: String,
    kind: RetainedFileKind,
}

#[derive(Clone, Copy)]
enum RetainedFileKind {
    ClientConfig,
    PublisherConfig,
    BrokerExecutable,
}

pub(crate) struct BrokerClient {
    config: RetainedFile,
    executable: RetainedFile,
    publisher_config: RetainedFile,
    identity: BrokerIdentityDigests,
}

impl BrokerClient {
    pub(crate) fn open(config_path: &Path) -> Result<Self, BrokerClientError> {
        let config = retain_file(config_path, RetainedFileKind::ClientConfig, None)?;
        let value: PublisherBrokerClientConfigV1 =
            parse_canonical(&read_exact_file(&config.file, config.identity.size)?)?;
        if value.schema_version != 1
            || !valid_sha256(&value.catalog_gh_broker_sha256)
            || !valid_sha256(&value.publisher_broker_config_sha256)
        {
            return Err(BrokerClientError);
        }
        let executable = retain_file(
            Path::new(&value.catalog_gh_broker_path),
            RetainedFileKind::BrokerExecutable,
            Some(&value.catalog_gh_broker_sha256),
        )?;
        validate_elf_executable(&executable.file, executable.identity.size)?;
        let publisher_config = retain_file(
            Path::new(&value.publisher_broker_config_path),
            RetainedFileKind::PublisherConfig,
            Some(&value.publisher_broker_config_sha256),
        )?;
        if config.path == executable.path
            || config.path == publisher_config.path
            || executable.path == publisher_config.path
        {
            return Err(BrokerClientError);
        }
        let identity = BrokerIdentityDigests {
            broker_client_config_sha256: config.sha256.clone(),
            broker_executable_sha256: executable.sha256.clone(),
            publisher_broker_config_sha256: publisher_config.sha256.clone(),
        };
        let client = Self {
            config,
            executable,
            publisher_config,
            identity,
        };
        client.revalidate()?;
        Ok(client)
    }

    pub(crate) fn identity_digests(&self) -> Result<BrokerIdentityDigests, BrokerClientError> {
        self.revalidate()?;
        Ok(self.identity.clone())
    }

    pub(crate) fn execute(
        &self,
        request: &BrokerRequestV1,
    ) -> Result<BrokerResponseV1, BrokerClientError> {
        let request_bytes = request
            .to_canonical_bytes()
            .map_err(|_| BrokerClientError)?;
        if request_bytes.len() > MAX_REQUEST_BYTES {
            return Err(BrokerClientError);
        }
        self.revalidate()?;
        let response = self.execute_process(request_bytes)?;
        // A replacement during a remote request is uncertainty, even when the retained broker
        // completed with a typed response. No later workflow mutation can then be attempted.
        self.revalidate()?;
        Ok(response)
    }

    fn revalidate(&self) -> Result<(), BrokerClientError> {
        revalidate_file(&self.config)?;
        revalidate_file(&self.executable)?;
        revalidate_file(&self.publisher_config)?;
        Ok(())
    }

    fn execute_process(
        &self,
        request_bytes: Vec<u8>,
    ) -> Result<BrokerResponseV1, BrokerClientError> {
        let executable_fd = self.executable.file.as_raw_fd();
        let executable_path = OsString::from(format!("/proc/self/fd/{executable_fd}"));
        let mut command = Command::new(executable_path);
        command.args([
            OsStr::new("--config"),
            self.publisher_config.path.as_os_str(),
            OsStr::new("--expected-config-sha256"),
            OsStr::new(&self.identity.publisher_broker_config_sha256),
        ]);
        command.env_clear();
        command.env("LANG", "C");
        command.env("LC_ALL", "C");
        command.env("TZ", "UTC");
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        // SAFETY: setpgid, prctl, and fcntl affect only the post-fork child. The retained
        // descriptor remains live in the parent for every operation-pinned request.
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                let flags = libc::fcntl(executable_fd, libc::F_GETFD);
                if flags < 0
                    || libc::fcntl(executable_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|_| BrokerClientError)?;
        let process_group = child.id() as i32;
        let stdin = child.stdin.take().ok_or(BrokerClientError)?;
        let stdout = child.stdout.take().ok_or(BrokerClientError)?;
        let stderr = child.stderr.take().ok_or(BrokerClientError)?;
        let (sender, receiver) = mpsc::channel();
        let writer = spawn_writer(stdin, request_bytes, sender.clone());
        let stdout_reader =
            spawn_reader(stdout, MAX_RESPONSE_BYTES, PipeKind::Stdout, sender.clone());
        let stderr_reader = spawn_reader(stderr, MAX_STDERR_BYTES, PipeKind::Stderr, sender);
        let deadline = Instant::now() + BROKER_TIMEOUT;
        let mut supervised = supervise(&mut child, &receiver, deadline);
        if supervised.is_ok() && !process_group_absent(process_group) {
            supervised = Err(BrokerClientError);
        }
        if supervised.is_err() {
            terminate_and_reap(&mut child);
        }
        let _ = writer.join();
        let _ = stdout_reader.join();
        let _ = stderr_reader.join();
        let (status, stdout, stderr) = supervised?;
        if !status.success() || !stderr.is_empty() {
            return Err(BrokerClientError);
        }
        BrokerResponseV1::from_canonical_bytes(&stdout).map_err(|_| BrokerClientError)
    }
}

enum PipeKind {
    Stdin,
    Stdout,
    Stderr,
}

struct PipeEvent {
    kind: PipeKind,
    result: Result<Vec<u8>, BrokerClientError>,
}

fn spawn_writer(
    mut stdin: std::process::ChildStdin,
    bytes: Vec<u8>,
    sender: mpsc::Sender<PipeEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let result = stdin
            .write_all(&bytes)
            .and_then(|()| stdin.flush())
            .map(|()| Vec::new())
            .map_err(|_| BrokerClientError);
        drop(stdin);
        let _ = sender.send(PipeEvent {
            kind: PipeKind::Stdin,
            result,
        });
    })
}

fn spawn_reader<R: Read + Send + 'static>(
    mut reader: R,
    maximum: usize,
    kind: PipeKind,
    sender: mpsc::Sender<PipeEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = match (&mut reader)
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
        {
            Ok(_) if bytes.len() <= maximum => Ok(bytes),
            Ok(_) | Err(_) => Err(BrokerClientError),
        };
        let _ = sender.send(PipeEvent { kind, result });
    })
}

fn supervise(
    child: &mut Child,
    receiver: &mpsc::Receiver<PipeEvent>,
    deadline: Instant,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), BrokerClientError> {
    let mut status = None;
    let mut stdin_done = false;
    let mut stdout = None;
    let mut stderr = None;
    loop {
        while let Ok(event) = receiver.try_recv() {
            let bytes = event.result?;
            match event.kind {
                PipeKind::Stdin => stdin_done = true,
                PipeKind::Stdout => stdout = Some(bytes),
                PipeKind::Stderr => stderr = Some(bytes),
            }
        }
        if status.is_none() {
            status = child.try_wait().map_err(|_| BrokerClientError)?;
        }
        if status.is_some() && stdin_done && stdout.is_some() && stderr.is_some() {
            return Ok((
                status.ok_or(BrokerClientError)?,
                stdout.ok_or(BrokerClientError)?,
                stderr.ok_or(BrokerClientError)?,
            ));
        }
        if Instant::now() >= deadline {
            return Err(BrokerClientError);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn process_group_absent(process_group: i32) -> bool {
    // SAFETY: signal zero performs only an existence/permission check on the dedicated group.
    let result = unsafe { libc::kill(-process_group, 0) };
    result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

fn terminate_and_reap(child: &mut Child) {
    let pid = child.id() as i32;
    // SAFETY: a positive child PID names the process group established in pre_exec.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
    size: u64,
}

impl Identity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
            links: metadata.nlink(),
            size: metadata.len(),
        }
    }
}

fn retain_file(
    path: &Path,
    kind: RetainedFileKind,
    expected_sha256: Option<&str>,
) -> Result<RetainedFile, BrokerClientError> {
    let path = canonical_existing_path(path)?;
    let file = open_absolute_no_links(&path)?;
    let metadata = file.metadata().map_err(|_| BrokerClientError)?;
    if !secure_file(&metadata, kind) {
        return Err(BrokerClientError);
    }
    let identity = Identity::from_metadata(&metadata);
    let bytes = read_exact_file(&file, identity.size)?;
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    if expected_sha256.is_some_and(|expected| expected != sha256) {
        return Err(BrokerClientError);
    }
    if matches!(kind, RetainedFileKind::ClientConfig) {
        let _: PublisherBrokerClientConfigV1 = parse_canonical(&bytes)?;
    }
    let retained = RetainedFile {
        path,
        file,
        identity,
        sha256,
        kind,
    };
    revalidate_file(&retained)?;
    Ok(retained)
}

fn revalidate_file(retained: &RetainedFile) -> Result<(), BrokerClientError> {
    let metadata = retained.file.metadata().map_err(|_| BrokerClientError)?;
    let named = open_absolute_no_links(&retained.path)?;
    let named_metadata = named.metadata().map_err(|_| BrokerClientError)?;
    if !secure_file(&metadata, retained.kind)
        || !secure_file(&named_metadata, retained.kind)
        || Identity::from_metadata(&metadata) != retained.identity
        || Identity::from_metadata(&named_metadata) != retained.identity
        || format!(
            "{:x}",
            Sha256::digest(read_exact_file(&retained.file, retained.identity.size)?)
        ) != retained.sha256
        || format!(
            "{:x}",
            Sha256::digest(read_exact_file(&named, retained.identity.size)?)
        ) != retained.sha256
    {
        return Err(BrokerClientError);
    }
    Ok(())
}

fn secure_file(metadata: &fs::Metadata, kind: RetainedFileKind) -> bool {
    let common = metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.nlink() == 1
        && metadata.len() > 0;
    match kind {
        RetainedFileKind::ClientConfig | RetainedFileKind::PublisherConfig => {
            common
                && metadata.uid() == current_euid()
                && metadata.permissions().mode() & 0o7777 == 0o600
                && metadata.len() <= MAX_CONFIG_BYTES
        }
        RetainedFileKind::BrokerExecutable => {
            let mode = metadata.permissions().mode() & 0o7777;
            common
                && (metadata.uid() == 0 || metadata.uid() == current_euid())
                && mode & 0o022 == 0
                && mode & 0o111 != 0
                && metadata.len() <= MAX_EXECUTABLE_BYTES
        }
    }
}

fn parse_canonical<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, BrokerClientError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(BrokerClientError);
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| BrokerClientError)?;
    if serde_jcs::to_vec(&value).map_err(|_| BrokerClientError)? != bytes {
        return Err(BrokerClientError);
    }
    serde_json::from_value(value).map_err(|_| BrokerClientError)
}

fn read_exact_file(file: &fs::File, size: u64) -> Result<Vec<u8>, BrokerClientError> {
    let mut file = file.try_clone().map_err(|_| BrokerClientError)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| BrokerClientError)?;
    let mut bytes = Vec::with_capacity(usize::try_from(size).map_err(|_| BrokerClientError)?);
    (&mut file)
        .take(size + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BrokerClientError)?;
    if bytes.len() as u64 != size {
        return Err(BrokerClientError);
    }
    Ok(bytes)
}

fn canonical_existing_path(path: &Path) -> Result<PathBuf, BrokerClientError> {
    valid_absolute_path(path)?;
    let canonical = fs::canonicalize(path).map_err(|_| BrokerClientError)?;
    if canonical != path {
        return Err(BrokerClientError);
    }
    Ok(canonical)
}

fn open_absolute_no_links(path: &Path) -> Result<fs::File, BrokerClientError> {
    valid_absolute_path(path)?;
    let root = CString::new("/").expect("fixed root");
    // SAFETY: fixed absolute root and no-follow flags are valid.
    let descriptor = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(BrokerClientError);
    }
    // SAFETY: open returned one owned descriptor.
    let mut current = unsafe { fs::File::from_raw_fd(descriptor) };
    let components = path.components().skip(1).collect::<Vec<_>>();
    if components.is_empty() {
        return Err(BrokerClientError);
    }
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(value) = component else {
            return Err(BrokerClientError);
        };
        let value = CString::new(value.as_bytes()).map_err(|_| BrokerClientError)?;
        let flags = if index + 1 == components.len() {
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
        };
        // SAFETY: retained directory, lexical component, and no-follow flags are valid.
        let next = unsafe { libc::openat(current.as_raw_fd(), value.as_ptr(), flags) };
        if next < 0 {
            return Err(BrokerClientError);
        }
        // SAFETY: openat returned one owned descriptor.
        let next = unsafe { fs::File::from_raw_fd(next) };
        if index + 1 != components.len()
            && !secure_ancestor(&next.metadata().map_err(|_| BrokerClientError)?)
        {
            return Err(BrokerClientError);
        }
        current = next;
    }
    Ok(current)
}

fn valid_absolute_path(path: &Path) -> Result<(), BrokerClientError> {
    if !path.is_absolute() || path.as_os_str().as_bytes().len() > MAX_PATH_BYTES {
        return Err(BrokerClientError);
    }
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value)
                if !value.as_bytes().is_empty()
                    && value.as_bytes().len() <= 255
                    && !value.as_bytes().contains(&0) => {}
            _ => return Err(BrokerClientError),
        }
    }
    Ok(())
}

fn secure_ancestor(metadata: &fs::Metadata) -> bool {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return false;
    }
    let mode = metadata.permissions().mode() & 0o7777;
    (metadata.uid() == 0 && matches!(mode, 0o555 | 0o755 | 0o1777))
        || (metadata.uid() == current_euid() && matches!(mode, 0o700 | 0o755))
}

fn validate_elf_executable(file: &fs::File, size: u64) -> Result<(), BrokerClientError> {
    if size < 64 {
        return Err(BrokerClientError);
    }
    let mut file = file.try_clone().map_err(|_| BrokerClientError)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| BrokerClientError)?;
    let mut header = [0_u8; 64];
    file.read_exact(&mut header)
        .map_err(|_| BrokerClientError)?;
    if &header[..4] != b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || u16::from_le_bytes([header[18], header[19]]) != 62
        || u16::from_le_bytes([header[52], header[53]]) != 64
        || u16::from_le_bytes([header[54], header[55]]) != 56
    {
        return Err(BrokerClientError);
    }
    let offset = u64::from_le_bytes(header[32..40].try_into().map_err(|_| BrokerClientError)?);
    let count = u16::from_le_bytes([header[56], header[57]]);
    let table_size = u64::from(count).checked_mul(56).ok_or(BrokerClientError)?;
    if count == 0
        || count > 1_024
        || offset < 64
        || offset
            .checked_add(table_size)
            .filter(|end| *end <= size)
            .is_none()
    {
        return Err(BrokerClientError);
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| BrokerClientError)?;
    let mut executable_load = false;
    for _ in 0..count {
        let mut entry = [0_u8; 56];
        file.read_exact(&mut entry).map_err(|_| BrokerClientError)?;
        let kind = u32::from_le_bytes(entry[0..4].try_into().map_err(|_| BrokerClientError)?);
        let flags = u32::from_le_bytes(entry[4..8].try_into().map_err(|_| BrokerClientError)?);
        if kind == 1 && flags & 1 != 0 {
            executable_load = true;
        }
    }
    executable_load.then_some(()).ok_or(BrokerClientError)
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
