use std::{
    collections::BTreeSet,
    error::Error,
    ffi::{CStr, CString, OsStr, OsString},
    fmt, fs,
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{MetadataExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Component, Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize, de};
use serde_json::Value;
use sha2::{Digest, Sha256};

const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_CHILD_STDERR_BYTES: usize = 64 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
#[cfg(test)]
const MAX_ASSET_BYTES: u64 = 64 * 1024;
#[cfg(not(test))]
const MAX_ASSET_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_JSON_DEPTH: usize = 16;
const MAX_JSON_NODES: usize = 1_024;
const MAX_COLLECTION_MEMBERS: usize = 256;
const MAX_RELEASE_ASSETS: usize = 128;
#[cfg(test)]
const CHILD_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(not(test))]
const CHILD_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const IO_CHUNK_BYTES: usize = 8 * 1024;
const ELF_HEADER_BYTES: usize = 64;
const ELF_PROGRAM_HEADER_BYTES: u64 = 56;
const MAX_ELF_PROGRAM_HEADERS: u16 = 1_024;
const FAILURE_LINE: &[u8] = b"github broker failed\n";

/// Strict configuration for the broker's executable and credential-directory capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherBrokerConfigV1 {
    pub schema_version: u16,
    pub gh_path: String,
    pub gh_sha256: String,
    pub github_config_dir: String,
}

/// The only requests that can cross the authenticated GitHub CLI boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrokerRequestV1 {
    CreateTag {
        schema_version: u16,
        repository: String,
        tag: String,
        commit_sha: String,
    },
    ReadTag {
        schema_version: u16,
        repository: String,
        tag: String,
    },
    CreateDraft {
        schema_version: u16,
        repository: String,
        tag: String,
        target_commitish: String,
        title: String,
        notes: String,
        prerelease: bool,
    },
    ReadDraft {
        schema_version: u16,
        repository: String,
        tag: String,
    },
    UploadAsset {
        schema_version: u16,
        repository: String,
        release_id: String,
        tag: String,
        name: String,
        input_path: String,
    },
    DownloadAsset {
        schema_version: u16,
        repository: String,
        asset_id: String,
        name: String,
        output_path: String,
    },
    PublishDraft {
        schema_version: u16,
        repository: String,
        release_id: String,
    },
}

impl BrokerRequestV1 {
    pub const fn all_kinds() -> &'static [&'static str; 7] {
        &[
            "create_tag",
            "read_tag",
            "create_draft",
            "read_draft",
            "upload_asset",
            "download_asset",
            "publish_draft",
        ]
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, BrokerProtocolError> {
        parse_canonical(bytes, MAX_REQUEST_BYTES).and_then(|request: Self| {
            request.validate().map_err(|_| BrokerProtocolError)?;
            Ok(request)
        })
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, BrokerProtocolError> {
        self.validate().map_err(|_| BrokerProtocolError)?;
        serde_jcs::to_vec(self).map_err(|_| BrokerProtocolError)
    }

    fn validate(&self) -> Result<(), BrokerError> {
        match self {
            Self::CreateTag {
                schema_version,
                repository,
                tag,
                commit_sha,
            } => {
                valid_schema(*schema_version)?;
                valid_repository(repository)?;
                valid_tag(tag)?;
                valid_sha1(commit_sha)
            }
            Self::ReadTag {
                schema_version,
                repository,
                tag,
            }
            | Self::ReadDraft {
                schema_version,
                repository,
                tag,
            } => {
                valid_schema(*schema_version)?;
                valid_repository(repository)?;
                valid_tag(tag)
            }
            Self::CreateDraft {
                schema_version,
                repository,
                tag,
                target_commitish,
                title,
                notes,
                prerelease: _,
            } => {
                valid_schema(*schema_version)?;
                valid_repository(repository)?;
                valid_tag(tag)?;
                valid_sha1(target_commitish)?;
                valid_title(title)?;
                valid_notes(notes)
            }
            Self::UploadAsset {
                schema_version,
                repository,
                release_id,
                tag,
                name,
                input_path,
            } => {
                valid_schema(*schema_version)?;
                valid_repository(repository)?;
                valid_decimal_id(release_id)?;
                valid_tag(tag)?;
                valid_asset_name(name)?;
                valid_path_text(input_path)
            }
            Self::DownloadAsset {
                schema_version,
                repository,
                asset_id,
                name,
                output_path,
            } => {
                valid_schema(*schema_version)?;
                valid_repository(repository)?;
                valid_decimal_id(asset_id)?;
                valid_asset_name(name)?;
                valid_path_text(output_path)
            }
            Self::PublishDraft {
                schema_version,
                repository,
                release_id,
            } => {
                valid_schema(*schema_version)?;
                valid_repository(repository)?;
                valid_decimal_id(release_id)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerTagObjectTypeV1 {
    Commit,
    Tag,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerReleaseAssetV1 {
    pub asset_id: String,
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerTransferredAssetV1 {
    pub asset_id: String,
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerAssetUploadStatusV1 {
    AssetUploaded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerPublicationStatusV1 {
    Published,
}

/// Safe public projection of a broker operation. Child output is never forwarded wholesale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrokerResponseV1 {
    Tag {
        schema_version: u16,
        tag: String,
        commit_sha: String,
        object_type: BrokerTagObjectTypeV1,
    },
    Draft {
        schema_version: u16,
        release_id: String,
        tag: String,
        target_commitish: String,
        draft: bool,
        prerelease: bool,
        assets: Vec<BrokerReleaseAssetV1>,
    },
    AssetUploaded {
        schema_version: u16,
        status: BrokerAssetUploadStatusV1,
        name: String,
        size: u64,
        sha256: String,
    },
    Asset {
        schema_version: u16,
        asset: BrokerTransferredAssetV1,
    },
    Published {
        schema_version: u16,
        release_id: String,
        status: BrokerPublicationStatusV1,
    },
}

impl BrokerResponseV1 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, BrokerProtocolError> {
        parse_canonical(bytes, MAX_RESPONSE_BYTES as u64).and_then(|response: Self| {
            response.validate().map_err(|_| BrokerProtocolError)?;
            Ok(response)
        })
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, BrokerProtocolError> {
        self.validate().map_err(|_| BrokerProtocolError)?;
        serde_jcs::to_vec(self).map_err(|_| BrokerProtocolError)
    }

    fn validate(&self) -> Result<(), BrokerError> {
        match self {
            Self::Tag {
                schema_version,
                tag,
                commit_sha,
                object_type: _,
            } => {
                valid_schema(*schema_version)?;
                valid_tag(tag)?;
                valid_sha1(commit_sha)
            }
            Self::Draft {
                schema_version,
                release_id,
                tag,
                target_commitish,
                draft: _,
                prerelease: _,
                assets,
            } => {
                valid_schema(*schema_version)?;
                valid_decimal_id(release_id)?;
                valid_tag(tag)?;
                valid_sha1(target_commitish)?;
                valid_release_assets(assets)
            }
            Self::AssetUploaded {
                schema_version,
                status: BrokerAssetUploadStatusV1::AssetUploaded,
                name,
                size,
                sha256,
            } => {
                valid_schema(*schema_version)?;
                valid_asset_name(name)?;
                if *size == 0 || *size > MAX_ASSET_BYTES {
                    return Err(rejected());
                }
                valid_sha256(sha256)
            }
            Self::Asset {
                schema_version,
                asset,
            } => {
                valid_schema(*schema_version)?;
                valid_decimal_id(&asset.asset_id)?;
                valid_asset_name(&asset.name)?;
                if asset.size == 0 || asset.size > MAX_ASSET_BYTES {
                    return Err(rejected());
                }
                valid_sha256(&asset.sha256)
            }
            Self::Published {
                schema_version,
                release_id,
                status: BrokerPublicationStatusV1::Published,
            } => {
                valid_schema(*schema_version)?;
                valid_decimal_id(release_id)
            }
        }
    }
}

/// Public protocol parse/validation failure with no request or path content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrokerProtocolError;

impl fmt::Display for BrokerProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("github broker protocol rejected")
    }
}

impl Error for BrokerProtocolError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BrokerError;

impl fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("github broker failed")
    }
}

impl Error for BrokerError {}

const fn rejected() -> BrokerError {
    BrokerError
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    owner: u32,
    mode: u32,
    links: u64,
}

impl Identity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            owner: metadata.uid(),
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

struct VerifiedDirectory {
    path: PathBuf,
    file: fs::File,
    identity: Identity,
}

struct VerifiedBrokerConfig {
    value: PublisherBrokerConfigV1,
    path: PathBuf,
    file: fs::File,
    identity: Identity,
    sha256: String,
    executable: VerifiedExecutable,
    config_directory: VerifiedDirectory,
}

struct VerifiedUploadSource {
    file: fs::File,
    path: PathBuf,
    identity: Identity,
    size: u64,
    sha256: String,
}

struct UploadCapability {
    directory_path: PathBuf,
    directory: fs::File,
    directory_identity: Identity,
    name: CString,
    path: PathBuf,
    file: fs::File,
    identity: Identity,
    size: u64,
    sha256: String,
}

impl Drop for UploadCapability {
    fn drop(&mut self) {
        if let Ok(rebound) = openat_regular(&self.directory, &self.name, libc::O_RDONLY)
            && rebound
                .metadata()
                .ok()
                .map(|metadata| Identity::from_metadata(&metadata))
                .is_some_and(|identity| same_file_node(identity, self.identity))
        {
            // SAFETY: retained private parent and exact validated component are valid.
            unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
        if verify_directory_rebind(
            &self.directory_path,
            &self.directory,
            self.directory_identity,
        )
        .is_ok()
        {
            let _ = fs::remove_dir(&self.directory_path);
        }
    }
}

struct DownloadCapability {
    parent: fs::File,
    parent_identity: Identity,
    parent_path: PathBuf,
    name: CString,
    file: fs::File,
    identity: Identity,
    settled: bool,
}

impl Drop for DownloadCapability {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let Ok(metadata) = self.file.metadata() else {
            return;
        };
        if !same_file_node(Identity::from_metadata(&metadata), self.identity) {
            return;
        }
        let Ok(rebound) = openat_regular(&self.parent, &self.name, libc::O_RDONLY) else {
            return;
        };
        let Ok(rebound_metadata) = rebound.metadata() else {
            return;
        };
        if !same_file_node(Identity::from_metadata(&rebound_metadata), self.identity) {
            return;
        }
        // SAFETY: retained parent and validated single component are valid.
        unsafe {
            libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0);
        }
    }
}

impl DownloadCapability {
    fn finish(
        &mut self,
        streamed_size: u64,
        streamed_sha256: &str,
    ) -> Result<(u64, String), BrokerError> {
        let metadata = self.file.metadata().map_err(|_| rejected())?;
        if !secure_download_file(&metadata, self.identity, 0o600)
            || metadata.len() == 0
            || metadata.len() > MAX_ASSET_BYTES
        {
            return Err(rejected());
        }
        self.file.sync_all().map_err(|_| rejected())?;
        // SAFETY: this retained descriptor belongs to the fresh output file.
        if unsafe { libc::fchmod(self.file.as_raw_fd(), 0o400) } != 0 {
            return Err(rejected());
        }
        self.file.sync_all().map_err(|_| rejected())?;
        let after = self.file.metadata().map_err(|_| rejected())?;
        let final_identity = Identity::from_metadata(&after);
        if final_identity.device != self.identity.device
            || final_identity.inode != self.identity.inode
            || final_identity.owner != self.identity.owner
            || final_identity.links != 1
            || final_identity.mode != 0o400
            || final_identity.size == 0
            || final_identity.size > MAX_ASSET_BYTES
        {
            return Err(rejected());
        }
        let digest = hash_descriptor(&self.file, final_identity.size)?;
        verify_directory_rebind(&self.parent_path, &self.parent, self.parent_identity)?;
        let rebound = openat_regular(&self.parent, &self.name, libc::O_RDONLY)?;
        let rebound_metadata = rebound.metadata().map_err(|_| rejected())?;
        if final_identity.size != streamed_size
            || digest != streamed_sha256
            || Identity::from_metadata(&rebound_metadata) != final_identity
            || hash_descriptor(&rebound, final_identity.size)? != digest
        {
            return Err(rejected());
        }
        self.identity = final_identity;
        self.settled = true;
        Ok((final_identity.size, digest))
    }
}

struct FreshHome {
    path: PathBuf,
    file: fs::File,
    identity: Identity,
}

impl Drop for FreshHome {
    fn drop(&mut self) {
        let Ok(rebound) = open_absolute_no_links(
            &self.path,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        ) else {
            return;
        };
        let Ok(metadata) = rebound.metadata() else {
            return;
        };
        if Identity::from_metadata(&metadata) == self.identity {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

#[cfg(test)]
pub(crate) trait BrokerTestCheckpoints {
    fn after_executable_hash(&mut self) {}
    fn before_spawn(&mut self) {}
    fn after_final_rebind(&mut self) {}
}

#[cfg(test)]
struct NoopTestCheckpoints;
#[cfg(test)]
impl BrokerTestCheckpoints for NoopTestCheckpoints {}

#[cfg(not(test))]
fn execute(config_path: &Path, request: &BrokerRequestV1) -> Result<BrokerResponseV1, BrokerError> {
    execute_impl(config_path, request)
}

#[cfg(test)]
fn execute(config_path: &Path, request: &BrokerRequestV1) -> Result<BrokerResponseV1, BrokerError> {
    execute_impl(config_path, request, &mut NoopTestCheckpoints)
}

#[cfg(test)]
pub(crate) fn execute_with_test_checkpoints(
    config_path: &Path,
    request: &BrokerRequestV1,
    checkpoints: &mut dyn BrokerTestCheckpoints,
) -> Result<BrokerResponseV1, BrokerError> {
    execute_impl(config_path, request, checkpoints)
}

fn execute_impl(
    config_path: &Path,
    request: &BrokerRequestV1,
    #[cfg(test)] checkpoints: &mut dyn BrokerTestCheckpoints,
) -> Result<BrokerResponseV1, BrokerError> {
    // No credential or process capability is opened before the complete typed request validates.
    request.validate()?;
    let config = read_config(
        config_path,
        #[cfg(test)]
        checkpoints,
    )?;
    let upload = match request {
        BrokerRequestV1::UploadAsset {
            input_path, name, ..
        } => Some(materialize_upload(Path::new(input_path), name)?),
        _ => None,
    };
    let mut download = match request {
        BrokerRequestV1::DownloadAsset { output_path, .. } => {
            Some(create_download(Path::new(output_path))?)
        }
        _ => None,
    };
    let home = create_fresh_home()?;
    #[cfg(test)]
    checkpoints.before_spawn();

    rebind_config(&config)?;
    rebind_executable(&config.executable)?;
    rebind_directory(&config.config_directory)?;
    verify_home(&home)?;
    if let Some(capability) = &upload {
        rebind_upload(capability)?;
    }
    if let Some(capability) = &download {
        verify_download_before_spawn(capability)?;
    }
    #[cfg(test)]
    checkpoints.after_final_rebind();

    let plan = command_plan(request, upload.as_ref())?;
    let executable_path = OsString::from(format!(
        "/proc/self/fd/{}",
        config.executable.file.as_raw_fd()
    ));
    let mut command = Command::new(executable_path);
    command.args(&plan.arguments);
    command.env_clear();
    command.env("HOME", &home.path);
    command.env(
        "GH_CONFIG_DIR",
        format!("/proc/self/fd/{}", config.config_directory.file.as_raw_fd()),
    );
    command.env("LANG", "C");
    command.env("LC_ALL", "C");
    command.env("TZ", "UTC");
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let executable_descriptor = config.executable.file.as_raw_fd();
    let config_directory_descriptor = config.config_directory.file.as_raw_fd();
    // SAFETY: setpgid and fcntl are async-signal-safe and touch only child descriptor state.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for descriptor in [executable_descriptor, config_directory_descriptor] {
                let flags = libc::fcntl(descriptor, libc::F_GETFD);
                if flags < 0
                    || libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let deadline = Instant::now() + CHILD_TIMEOUT;
    let mut child = command.spawn().map_err(|_| rejected())?;
    let supervised = supervise_child(
        &mut child,
        plan.stdin.as_deref().unwrap_or_default(),
        download.as_mut(),
        deadline,
    )?;

    let response = if let Some(capability) = &mut download {
        let stream = supervised.download.ok_or_else(rejected)?;
        let (size, sha256) = capability.finish(stream.size, &stream.sha256)?;
        let BrokerRequestV1::DownloadAsset { asset_id, name, .. } = request else {
            return Err(rejected());
        };
        BrokerResponseV1::Asset {
            schema_version: 1,
            asset: BrokerTransferredAssetV1 {
                asset_id: asset_id.clone(),
                name: name.clone(),
                size,
                sha256,
            },
        }
    } else {
        project_child_response(request, &supervised.stdout, upload.as_ref())?
    };
    response.validate()?;
    Ok(response)
}

struct CommandPlan {
    arguments: Vec<OsString>,
    stdin: Option<Vec<u8>>,
}

fn command_plan(
    request: &BrokerRequestV1,
    upload: Option<&UploadCapability>,
) -> Result<CommandPlan, BrokerError> {
    match request {
        BrokerRequestV1::CreateTag {
            repository,
            tag,
            commit_sha,
            ..
        } => Ok(api_command_plan(
            "POST",
            format!("/repos/{repository}/git/refs"),
            "Accept: application/vnd.github+json",
            Some(canonical_value(&serde_json::json!({
                "ref": format!("refs/tags/{tag}"),
                "sha": commit_sha,
            }))?),
        )),
        BrokerRequestV1::ReadTag {
            repository, tag, ..
        } => Ok(api_command_plan(
            "GET",
            format!("/repos/{repository}/git/ref/tags/{tag}"),
            "Accept: application/vnd.github+json",
            None,
        )),
        BrokerRequestV1::CreateDraft {
            repository,
            tag,
            target_commitish,
            title,
            notes,
            prerelease,
            ..
        } => Ok(api_command_plan(
            "POST",
            format!("/repos/{repository}/releases"),
            "Accept: application/vnd.github+json",
            Some(canonical_value(&serde_json::json!({
                "body": notes,
                "draft": true,
                "name": title,
                "prerelease": prerelease,
                "tag_name": tag,
                "target_commitish": target_commitish,
            }))?),
        )),
        BrokerRequestV1::ReadDraft {
            repository, tag, ..
        } => Ok(api_command_plan(
            "GET",
            format!("/repos/{repository}/releases/tags/{tag}"),
            "Accept: application/vnd.github+json",
            None,
        )),
        BrokerRequestV1::UploadAsset {
            repository, tag, ..
        } => {
            let capability = upload.ok_or_else(rejected)?;
            Ok(CommandPlan {
                arguments: vec![
                    OsString::from("release"),
                    OsString::from("upload"),
                    OsString::from(tag),
                    capability.path.as_os_str().to_owned(),
                    OsString::from("--repo"),
                    OsString::from(repository),
                ],
                stdin: None,
            })
        }
        BrokerRequestV1::DownloadAsset {
            repository,
            asset_id,
            ..
        } => Ok(api_command_plan(
            "GET",
            format!("/repos/{repository}/releases/assets/{asset_id}"),
            "Accept: application/octet-stream",
            None,
        )),
        BrokerRequestV1::PublishDraft {
            repository,
            release_id,
            ..
        } => Ok(api_command_plan(
            "PATCH",
            format!("/repos/{repository}/releases/{release_id}"),
            "Accept: application/vnd.github+json",
            Some(canonical_value(&serde_json::json!({"draft": false}))?),
        )),
    }
}

fn api_command_plan(
    method: &'static str,
    endpoint: String,
    accept: &'static str,
    stdin: Option<Vec<u8>>,
) -> CommandPlan {
    let mut arguments = vec![
        OsString::from("api"),
        OsString::from("--method"),
        OsString::from(method),
        OsString::from(endpoint),
        OsString::from("--header"),
        OsString::from(accept),
        OsString::from("--header"),
        OsString::from("X-GitHub-Api-Version: 2022-11-28"),
    ];
    if stdin.is_some() {
        arguments.extend([OsString::from("--input"), OsString::from("-")]);
    }
    CommandPlan { arguments, stdin }
}

fn project_child_response(
    request: &BrokerRequestV1,
    bytes: &[u8],
    upload: Option<&UploadCapability>,
) -> Result<BrokerResponseV1, BrokerError> {
    match request {
        BrokerRequestV1::CreateTag { tag, .. } | BrokerRequestV1::ReadTag { tag, .. } => {
            let value = parse_json_value(bytes, MAX_RESPONSE_BYTES as u64, false)?;
            let root = object(&value)?;
            if string_field(root, "ref")? != format!("refs/tags/{tag}") {
                return Err(rejected());
            }
            let target = object(root.get("object").ok_or_else(rejected)?)?;
            let commit_sha = string_field(target, "sha")?.to_owned();
            valid_sha1(&commit_sha)?;
            let object_type = match string_field(target, "type")? {
                "commit" => BrokerTagObjectTypeV1::Commit,
                "tag" => BrokerTagObjectTypeV1::Tag,
                _ => return Err(rejected()),
            };
            Ok(BrokerResponseV1::Tag {
                schema_version: 1,
                tag: tag.clone(),
                commit_sha,
                object_type,
            })
        }
        BrokerRequestV1::CreateDraft { .. } | BrokerRequestV1::ReadDraft { .. } => {
            let value = parse_json_value(bytes, MAX_RESPONSE_BYTES as u64, false)?;
            project_draft(&value)
        }
        BrokerRequestV1::UploadAsset { name, .. } => {
            let upload = upload.ok_or_else(rejected)?;
            Ok(BrokerResponseV1::AssetUploaded {
                schema_version: 1,
                status: BrokerAssetUploadStatusV1::AssetUploaded,
                name: name.clone(),
                size: upload.size,
                sha256: upload.sha256.clone(),
            })
        }
        BrokerRequestV1::PublishDraft { release_id, .. } => {
            let value = parse_json_value(bytes, MAX_RESPONSE_BYTES as u64, false)?;
            let child = object(&value)?;
            if decimal_json_field(child, "id")? != *release_id || bool_field(child, "draft")? {
                return Err(rejected());
            }
            Ok(BrokerResponseV1::Published {
                schema_version: 1,
                release_id: release_id.clone(),
                status: BrokerPublicationStatusV1::Published,
            })
        }
        BrokerRequestV1::DownloadAsset { .. } => Err(rejected()),
    }
}

fn project_draft(value: &Value) -> Result<BrokerResponseV1, BrokerError> {
    let child = object(value)?;
    let release_id = decimal_json_field(child, "id")?;
    let tag = string_field(child, "tag_name")?.to_owned();
    let target_commitish = string_field(child, "target_commitish")?.to_owned();
    let draft = bool_field(child, "draft")?;
    let prerelease = bool_field(child, "prerelease")?;
    valid_tag(&tag)?;
    valid_sha1(&target_commitish)?;
    let values = child
        .get("assets")
        .and_then(Value::as_array)
        .ok_or_else(rejected)?;
    if values.len() > MAX_RELEASE_ASSETS {
        return Err(rejected());
    }
    let mut assets = Vec::with_capacity(values.len());
    for value in values {
        let asset = object(value)?;
        let projected = BrokerReleaseAssetV1 {
            asset_id: decimal_json_field(asset, "id")?,
            name: string_field(asset, "name")?.to_owned(),
            size: u64_field(asset, "size")?,
        };
        valid_decimal_id(&projected.asset_id)?;
        valid_asset_name(&projected.name)?;
        if projected.size == 0 || projected.size > MAX_ASSET_BYTES {
            return Err(rejected());
        }
        assets.push(projected);
    }
    valid_release_assets(&assets)?;
    Ok(BrokerResponseV1::Draft {
        schema_version: 1,
        release_id,
        tag,
        target_commitish,
        draft,
        prerelease,
        assets,
    })
}

fn read_config(
    path: &Path,
    #[cfg(test)] checkpoints: &mut dyn BrokerTestCheckpoints,
) -> Result<VerifiedBrokerConfig, BrokerError> {
    let path = canonical_existing_path(path)?;
    let file = open_absolute_no_links(&path, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK)?;
    let before = file.metadata().map_err(|_| rejected())?;
    if !secure_config_file(&before) {
        return Err(rejected());
    }
    let identity = Identity::from_metadata(&before);
    let bytes = read_descriptor(&file, identity.size, MAX_CONFIG_BYTES)?;
    let value: PublisherBrokerConfigV1 =
        parse_canonical(&bytes, MAX_CONFIG_BYTES).map_err(|_| rejected())?;
    if value.schema_version != 1 || !valid_sha256_text(&value.gh_sha256) {
        return Err(rejected());
    }
    let sha256 = sha256(&bytes);
    let after = file.metadata().map_err(|_| rejected())?;
    if Identity::from_metadata(&after) != identity {
        return Err(rejected());
    }
    verify_named_file(&path, &file, identity, secure_config_file)?;

    let executable_path = canonical_existing_path(Path::new(&value.gh_path))?;
    let executable_file = open_absolute_no_links(
        &executable_path,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
    )?;
    let executable_before = executable_file.metadata().map_err(|_| rejected())?;
    if !secure_executable(&executable_before) {
        return Err(rejected());
    }
    let executable_identity = Identity::from_metadata(&executable_before);
    let executable_sha256 = hash_descriptor(&executable_file, executable_identity.size)?;
    if executable_sha256 != value.gh_sha256 {
        return Err(rejected());
    }
    validate_elf_executable(&executable_file, executable_identity.size)?;
    let executable_after = executable_file.metadata().map_err(|_| rejected())?;
    if Identity::from_metadata(&executable_after) != executable_identity {
        return Err(rejected());
    }
    #[cfg(test)]
    checkpoints.after_executable_hash();
    let executable = VerifiedExecutable {
        path: executable_path,
        file: executable_file,
        identity: executable_identity,
        sha256: executable_sha256,
    };
    rebind_executable(&executable)?;

    let config_directory_path = canonical_existing_path(Path::new(&value.github_config_dir))?;
    let config_directory_file = open_absolute_no_links(
        &config_directory_path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )?;
    let directory_metadata = config_directory_file.metadata().map_err(|_| rejected())?;
    if !secure_private_directory(&directory_metadata) {
        return Err(rejected());
    }
    let config_directory = VerifiedDirectory {
        path: config_directory_path,
        file: config_directory_file,
        identity: Identity::from_metadata(&directory_metadata),
    };
    rebind_directory(&config_directory)?;

    Ok(VerifiedBrokerConfig {
        value,
        path,
        file,
        identity,
        sha256,
        executable,
        config_directory,
    })
}

fn rebind_config(config: &VerifiedBrokerConfig) -> Result<(), BrokerError> {
    verify_named_file(
        &config.path,
        &config.file,
        config.identity,
        secure_config_file,
    )?;
    if hash_descriptor(&config.file, config.identity.size)? != config.sha256
        || config.value.schema_version != 1
    {
        return Err(rejected());
    }
    Ok(())
}

fn rebind_executable(executable: &VerifiedExecutable) -> Result<(), BrokerError> {
    verify_named_file(
        &executable.path,
        &executable.file,
        executable.identity,
        secure_executable,
    )?;
    if hash_descriptor(&executable.file, executable.identity.size)? != executable.sha256 {
        return Err(rejected());
    }
    Ok(())
}

fn rebind_directory(directory: &VerifiedDirectory) -> Result<(), BrokerError> {
    verify_directory_rebind(&directory.path, &directory.file, directory.identity)
}

fn open_upload_source(path: &Path) -> Result<VerifiedUploadSource, BrokerError> {
    let path = canonical_existing_path(path)?;
    let file = open_absolute_no_links(&path, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK)?;
    let before = file.metadata().map_err(|_| rejected())?;
    if !secure_upload_file(&before) {
        return Err(rejected());
    }
    let identity = Identity::from_metadata(&before);
    let sha256 = hash_descriptor(&file, identity.size)?;
    let source = VerifiedUploadSource {
        file,
        path,
        identity,
        size: identity.size,
        sha256,
    };
    rebind_upload_source(&source)?;
    Ok(source)
}

fn rebind_upload_source(source: &VerifiedUploadSource) -> Result<(), BrokerError> {
    verify_named_file(
        &source.path,
        &source.file,
        source.identity,
        secure_upload_file,
    )?;
    if hash_descriptor(&source.file, source.size)? != source.sha256 {
        return Err(rejected());
    }
    Ok(())
}

fn materialize_upload(path: &Path, asset_name: &str) -> Result<UploadCapability, BrokerError> {
    let source = open_upload_source(path)?;
    let (directory_path, directory, directory_identity) =
        create_private_directory(b"/tmp/catalog-gh-broker-upload-XXXXXX\0")?;
    let name = CString::new(asset_name.as_bytes()).map_err(|_| rejected())?;
    // SAFETY: retained owner-private parent, validated exact asset component, and no-clobber flags.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o400,
        )
    };
    if descriptor < 0 {
        let _ = fs::remove_dir(&directory_path);
        return Err(rejected());
    }
    // SAFETY: openat returned one newly owned descriptor.
    let file = unsafe { fs::File::from_raw_fd(descriptor) };
    let initial = Identity::from_metadata(&file.metadata().map_err(|_| rejected())?);
    let mut capability = UploadCapability {
        path: directory_path.join(asset_name),
        directory_path,
        directory,
        directory_identity,
        name,
        file,
        identity: initial,
        size: 0,
        sha256: String::new(),
    };
    if !secure_download_file(
        &capability.file.metadata().map_err(|_| rejected())?,
        initial,
        0o400,
    ) || initial.size != 0
    {
        return Err(rejected());
    }

    rebind_upload_source(&source)?;
    let mut source_reader = source.file.try_clone().map_err(|_| rejected())?;
    source_reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| rejected())?;
    let mut copied = 0_u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source_reader.read(&mut buffer).map_err(|_| rejected())?;
        if read == 0 {
            break;
        }
        copied = copied.checked_add(read as u64).ok_or_else(rejected)?;
        if copied > source.size || copied > MAX_ASSET_BYTES {
            return Err(rejected());
        }
        capability
            .file
            .write_all(&buffer[..read])
            .map_err(|_| rejected())?;
        hasher.update(&buffer[..read]);
    }
    let digest = format!("{:x}", hasher.finalize());
    if copied != source.size || digest != source.sha256 {
        return Err(rejected());
    }
    capability.file.sync_all().map_err(|_| rejected())?;
    rebind_upload_source(&source)?;
    let metadata = capability.file.metadata().map_err(|_| rejected())?;
    let identity = Identity::from_metadata(&metadata);
    if !secure_download_file(&metadata, identity, 0o400)
        || identity.size != copied
        || hash_descriptor(&capability.file, copied)? != digest
    {
        return Err(rejected());
    }
    capability.identity = identity;
    capability.size = copied;
    capability.sha256 = digest;
    rebind_upload(&capability)?;
    Ok(capability)
}

fn rebind_upload(capability: &UploadCapability) -> Result<(), BrokerError> {
    verify_directory_rebind(
        &capability.directory_path,
        &capability.directory,
        capability.directory_identity,
    )?;
    let metadata = capability.file.metadata().map_err(|_| rejected())?;
    let rebound = openat_regular(&capability.directory, &capability.name, libc::O_RDONLY)?;
    let rebound_metadata = rebound.metadata().map_err(|_| rejected())?;
    if Identity::from_metadata(&metadata) != capability.identity
        || Identity::from_metadata(&rebound_metadata) != capability.identity
        || !secure_upload_file(&metadata)
        || !secure_upload_file(&rebound_metadata)
        || hash_descriptor(&capability.file, capability.size)? != capability.sha256
        || hash_descriptor(&rebound, capability.size)? != capability.sha256
    {
        return Err(rejected());
    }
    Ok(())
}

fn create_download(path: &Path) -> Result<DownloadCapability, BrokerError> {
    valid_absolute_lexical_path(path)?;
    if path.as_os_str().as_bytes().len() > MAX_PATH_BYTES || path.file_name().is_none() {
        return Err(rejected());
    }
    let parent_path = path.parent().ok_or_else(rejected)?;
    let parent_path = canonical_existing_path(parent_path)?;
    if path.parent() != Some(parent_path.as_path()) {
        return Err(rejected());
    }
    let parent = open_absolute_no_links(
        &parent_path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )?;
    let parent_metadata = parent.metadata().map_err(|_| rejected())?;
    if !secure_private_directory(&parent_metadata) {
        return Err(rejected());
    }
    let parent_identity = Identity::from_metadata(&parent_metadata);
    let name = path
        .file_name()
        .filter(|name| safe_component(name))
        .and_then(|name| CString::new(name.as_bytes()).ok())
        .ok_or_else(rejected)?;
    // SAFETY: retained private parent, validated component, no-follow and no-clobber flags are valid.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(rejected());
    }
    // SAFETY: openat returned one newly owned descriptor.
    let file = unsafe { fs::File::from_raw_fd(descriptor) };
    let metadata = file.metadata().map_err(|_| rejected())?;
    let identity = Identity::from_metadata(&metadata);
    if !secure_download_file(&metadata, identity, 0o600) || identity.size != 0 {
        return Err(rejected());
    }
    Ok(DownloadCapability {
        parent,
        parent_identity,
        parent_path,
        name,
        file,
        identity,
        settled: false,
    })
}

fn verify_download_before_spawn(capability: &DownloadCapability) -> Result<(), BrokerError> {
    verify_directory_rebind(
        &capability.parent_path,
        &capability.parent,
        capability.parent_identity,
    )?;
    let metadata = capability.file.metadata().map_err(|_| rejected())?;
    if !secure_download_file(&metadata, capability.identity, 0o600) || metadata.len() != 0 {
        return Err(rejected());
    }
    let rebound = openat_regular(&capability.parent, &capability.name, libc::O_RDWR)?;
    if Identity::from_metadata(&rebound.metadata().map_err(|_| rejected())?) != capability.identity
    {
        return Err(rejected());
    }
    Ok(())
}

fn create_private_directory(
    fixed_template: &[u8],
) -> Result<(PathBuf, fs::File, Identity), BrokerError> {
    if !fixed_template.ends_with(b"XXXXXX\0") {
        return Err(rejected());
    }
    let mut template = fixed_template.to_vec();
    // SAFETY: the fixed template is writable, NUL-terminated, and ends in six X bytes.
    let pointer = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
    if pointer.is_null() {
        return Err(rejected());
    }
    // SAFETY: successful mkdtemp returned the same live NUL-terminated template buffer.
    let path = PathBuf::from(OsString::from_vec(
        unsafe { CStr::from_ptr(pointer) }.to_bytes().to_vec(),
    ));
    let file = open_absolute_no_links(&path, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)?;
    let metadata = file.metadata().map_err(|_| rejected())?;
    if !secure_private_directory(&metadata) || metadata.nlink() != 2 {
        let _ = fs::remove_dir(&path);
        return Err(rejected());
    }
    let identity = Identity::from_metadata(&metadata);
    Ok((path, file, identity))
}

fn create_fresh_home() -> Result<FreshHome, BrokerError> {
    let (path, file, identity) = create_private_directory(b"/tmp/catalog-gh-broker-home-XXXXXX\0")?;
    let home = FreshHome {
        path,
        file,
        identity,
    };
    verify_home(&home)?;
    Ok(home)
}

fn verify_home(home: &FreshHome) -> Result<(), BrokerError> {
    verify_directory_rebind(&home.path, &home.file, home.identity)?;
    // SAFETY: resetting the retained directory stream offset does not change its identity.
    if unsafe { libc::lseek(home.file.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(rejected());
    }
    let mut buffer = [0_u8; 8 * 1024];
    // SAFETY: retained directory descriptor and writable getdents buffer are valid.
    let read = unsafe {
        libc::syscall(
            libc::SYS_getdents64,
            home.file.as_raw_fd(),
            buffer.as_mut_ptr(),
            buffer.len(),
        )
    };
    if read < 0 {
        return Err(rejected());
    }
    // An empty directory contains only `.` and `..`; Linux emits exactly two records here.
    let mut offset = 0_usize;
    let mut names = BTreeSet::new();
    while offset < read as usize {
        if offset + 19 > read as usize {
            return Err(rejected());
        }
        let record_length = u16::from_ne_bytes([buffer[offset + 16], buffer[offset + 17]]) as usize;
        if record_length < 19 || offset + record_length > read as usize {
            return Err(rejected());
        }
        let raw_name = &buffer[offset + 19..offset + record_length];
        let end = raw_name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(raw_name.len());
        names.insert(&raw_name[..end]);
        offset += record_length;
    }
    if names != BTreeSet::from([b".".as_slice(), b"..".as_slice()]) {
        return Err(rejected());
    }
    Ok(())
}

struct DownloadStream {
    size: u64,
    sha256: String,
}

struct SupervisedOutput {
    stdout: Vec<u8>,
    download: Option<DownloadStream>,
}

struct DownloadAccumulator {
    size: u64,
    hasher: Sha256,
}

fn supervise_child(
    child: &mut Child,
    stdin_bytes: &[u8],
    download: Option<&mut DownloadCapability>,
    deadline: Instant,
) -> Result<SupervisedOutput, BrokerError> {
    match supervise_io(child, stdin_bytes, download, deadline) {
        Ok(output) => Ok(output),
        Err(error) => {
            terminate_and_reap(child, deadline);
            Err(error)
        }
    }
}

fn supervise_io(
    child: &mut Child,
    stdin_bytes: &[u8],
    mut download: Option<&mut DownloadCapability>,
    deadline: Instant,
) -> Result<SupervisedOutput, BrokerError> {
    let mut stdin = Some(child.stdin.take().ok_or_else(rejected)?);
    let mut stdout = child.stdout.take().ok_or_else(rejected)?;
    let mut stderr = child.stderr.take().ok_or_else(rejected)?;
    set_nonblocking(stdin.as_ref().ok_or_else(rejected)?)?;
    set_nonblocking(&stdout)?;
    set_nonblocking(&stderr)?;

    let mut stdin_position = 0_usize;
    let mut stdin_open = !stdin_bytes.is_empty();
    if !stdin_open {
        stdin.take();
    }
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut stdout_bytes = Vec::with_capacity(16 * 1024);
    let mut stderr_bytes = Vec::with_capacity(8 * 1024);
    let mut download_accumulator = download.as_ref().map(|_| DownloadAccumulator {
        size: 0,
        hasher: Sha256::new(),
    });
    let mut leader_status: Option<ExitStatus> = None;

    loop {
        let now = Instant::now();
        if deadline.saturating_duration_since(now) <= Duration::from_millis(100) {
            return Err(rejected());
        }

        let mut descriptors = Vec::with_capacity(3);
        if stdin_open {
            descriptors.push(libc::pollfd {
                fd: stdin.as_ref().ok_or_else(rejected)?.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            });
        }
        if stdout_open {
            descriptors.push(libc::pollfd {
                fd: stdout.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if stderr_open {
            descriptors.push(libc::pollfd {
                fd: stderr.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        let wait = deadline.saturating_duration_since(now).min(POLL_INTERVAL);
        let timeout = i32::try_from(wait.as_millis().max(1)).unwrap_or(i32::MAX);
        // SAFETY: the pollfd vector is valid for its exact initialized length.
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                timeout,
            )
        };
        if result < 0 {
            if std::io::Error::last_os_error().kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(rejected());
        }

        let mut index = 0_usize;
        if stdin_open {
            let events = descriptors[index].revents;
            index += 1;
            if events & (libc::POLLOUT | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                match write_nonblocking_stdin(
                    stdin.as_mut().ok_or_else(rejected)?,
                    stdin_bytes,
                    &mut stdin_position,
                ) {
                    Ok(true) => {
                        stdin_open = false;
                        stdin.take();
                    }
                    Ok(false) => {}
                    Err(_) => return Err(rejected()),
                }
            }
        }
        if stdout_open {
            let events = descriptors[index].revents;
            index += 1;
            if events & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                stdout_open = if let (Some(capability), Some(accumulator)) =
                    (download.as_deref_mut(), download_accumulator.as_mut())
                {
                    !drain_download_stdout(&mut stdout, capability, accumulator, deadline)?
                } else {
                    !drain_bounded_pipe(&mut stdout, &mut stdout_bytes, MAX_RESPONSE_BYTES)?
                };
            }
        }
        if stderr_open {
            let events = descriptors[index].revents;
            if events & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                stderr_open =
                    !drain_bounded_pipe(&mut stderr, &mut stderr_bytes, MAX_CHILD_STDERR_BYTES)?;
            }
        }

        if leader_status.is_none() {
            leader_status = child.try_wait().map_err(|_| rejected())?;
        }
        if leader_status.is_some_and(|status| !status.success()) {
            return Err(rejected());
        }
        if leader_status.is_some() && !stdin_open && !stdout_open && !stderr_open {
            let download = download_accumulator.map(|accumulator| DownloadStream {
                size: accumulator.size,
                sha256: format!("{:x}", accumulator.hasher.finalize()),
            });
            return Ok(SupervisedOutput {
                stdout: stdout_bytes,
                download,
            });
        }
    }
}

fn set_nonblocking(descriptor: &impl AsRawFd) -> Result<(), BrokerError> {
    // SAFETY: F_GETFL/F_SETFL operate on the retained pipe descriptor.
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe {
            libc::fcntl(
                descriptor.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            )
        } != 0
    {
        return Err(rejected());
    }
    Ok(())
}

fn write_nonblocking_stdin(
    stdin: &mut ChildStdin,
    bytes: &[u8],
    position: &mut usize,
) -> Result<bool, BrokerError> {
    let end = position.saturating_add(IO_CHUNK_BYTES).min(bytes.len());
    match stdin.write(&bytes[*position..end]) {
        Ok(0) => Err(rejected()),
        Ok(written) => {
            *position += written;
            Ok(*position == bytes.len())
        }
        Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(false),
        Err(_) => Err(rejected()),
    }
}

fn drain_bounded_pipe<R: Read>(
    pipe: &mut R,
    captured: &mut Vec<u8>,
    maximum: usize,
) -> Result<bool, BrokerError> {
    loop {
        let remaining = maximum.saturating_sub(captured.len());
        let mut buffer = [0_u8; IO_CHUNK_BYTES];
        let requested = if remaining == 0 {
            1
        } else {
            remaining.min(buffer.len())
        };
        match pipe.read(&mut buffer[..requested]) {
            Ok(0) => return Ok(true),
            Ok(read) if remaining == 0 || read > remaining => return Err(rejected()),
            Ok(read) => captured.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(rejected()),
        }
    }
}

fn drain_download_stdout(
    stdout: &mut ChildStdout,
    capability: &mut DownloadCapability,
    accumulator: &mut DownloadAccumulator,
    deadline: Instant,
) -> Result<bool, BrokerError> {
    loop {
        if Instant::now() >= deadline {
            return Err(rejected());
        }
        let remaining = MAX_ASSET_BYTES.saturating_sub(accumulator.size);
        let mut buffer = [0_u8; IO_CHUNK_BYTES];
        let requested = if remaining == 0 {
            1
        } else {
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| rejected())?
        };
        match stdout.read(&mut buffer[..requested]) {
            Ok(0) => return Ok(true),
            Ok(_) if remaining == 0 => return Err(rejected()),
            Ok(read) => {
                capability
                    .file
                    .write_all(&buffer[..read])
                    .map_err(|_| rejected())?;
                accumulator.size = accumulator
                    .size
                    .checked_add(read as u64)
                    .ok_or_else(rejected)?;
                accumulator.hasher.update(&buffer[..read]);
                if Instant::now() >= deadline {
                    return Err(rejected());
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(rejected()),
        }
    }
}

fn terminate_and_reap(child: &mut Child, deadline: Instant) {
    let pid = child.id() as i32;
    // SAFETY: the child created its own process group with PGID equal to its PID.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => {
                let mut no_descriptors: [libc::pollfd; 0] = [];
                // SAFETY: zero descriptors and a one-millisecond timeout are valid.
                unsafe {
                    libc::poll(no_descriptors.as_mut_ptr(), 0, 1);
                }
            }
        }
    }
    // SIGKILL has already been delivered; this final wait robustly reaps the leader.
    let _ = child.wait();
}

fn canonical_value(value: &Value) -> Result<Vec<u8>, BrokerError> {
    serde_jcs::to_vec(value).map_err(|_| rejected())
}

fn valid_schema(schema_version: u16) -> Result<(), BrokerError> {
    if schema_version != 1 {
        return Err(rejected());
    }
    Ok(())
}

fn valid_repository(repository: &str) -> Result<(), BrokerError> {
    if repository.len() > 140 || repository.matches('/').count() != 1 {
        return Err(rejected());
    }
    let (owner, name) = repository.split_once('/').ok_or_else(rejected)?;
    if owner.is_empty()
        || owner.len() > 39
        || name.is_empty()
        || name.len() > 100
        || !owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !owner
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !owner
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        || owner.contains("--")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || !name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !name
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        || name.contains("..")
    {
        return Err(rejected());
    }
    Ok(())
}

fn valid_tag(tag: &str) -> Result<(), BrokerError> {
    if tag == "transport-v1" {
        return Ok(());
    }
    let sequence = tag
        .strip_prefix("catalog-v1-sequence-")
        .filter(|value| !value.is_empty() && value.len() <= 20)
        .ok_or_else(rejected)?;
    if !sequence.bytes().all(|byte| byte.is_ascii_digit())
        || sequence.starts_with('0')
        || sequence
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
    {
        return Err(rejected());
    }
    Ok(())
}

fn valid_sha1(value: &str) -> Result<(), BrokerError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(rejected());
    }
    Ok(())
}

fn valid_sha256(value: &str) -> Result<(), BrokerError> {
    if !valid_sha256_text(value) {
        return Err(rejected());
    }
    Ok(())
}

fn valid_sha256_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_decimal_id(value: &str) -> Result<(), BrokerError> {
    if value.is_empty()
        || value.len() > 19
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.starts_with('0')
        || value.parse::<u64>().ok().filter(|id| *id > 0).is_none()
    {
        return Err(rejected());
    }
    Ok(())
}

fn valid_asset_name(value: &str) -> Result<(), BrokerError> {
    if value.is_empty()
        || value.len() > 255
        || value.starts_with('.')
        || value.ends_with('.')
        || value.contains("..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(rejected());
    }
    Ok(())
}

fn valid_title(value: &str) -> Result<(), BrokerError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(rejected());
    }
    Ok(())
}

fn valid_notes(value: &str) -> Result<(), BrokerError> {
    if value.len() > 16 * 1024
        || value.contains('\r')
        || value
            .chars()
            .any(|character| character.is_control() && character != '\n')
    {
        return Err(rejected());
    }
    Ok(())
}

fn valid_path_text(value: &str) -> Result<(), BrokerError> {
    if value.as_bytes().contains(&0) || value.len() > MAX_PATH_BYTES {
        return Err(rejected());
    }
    valid_absolute_lexical_path(Path::new(value))
}

fn valid_absolute_lexical_path(path: &Path) -> Result<(), BrokerError> {
    if !path.is_absolute() {
        return Err(rejected());
    }
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) if safe_component(value) => {}
            _ => return Err(rejected()),
        }
    }
    Ok(())
}

fn valid_release_assets(assets: &[BrokerReleaseAssetV1]) -> Result<(), BrokerError> {
    if assets.len() > MAX_RELEASE_ASSETS {
        return Err(rejected());
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for asset in assets {
        valid_decimal_id(&asset.asset_id)?;
        valid_asset_name(&asset.name)?;
        if asset.size == 0
            || asset.size > MAX_ASSET_BYTES
            || !ids.insert(asset.asset_id.as_str())
            || !names.insert(asset.name.as_str())
        {
            return Err(rejected());
        }
    }
    Ok(())
}

fn canonical_existing_path(path: &Path) -> Result<PathBuf, BrokerError> {
    valid_absolute_lexical_path(path)?;
    if path.as_os_str().as_bytes().len() > MAX_PATH_BYTES {
        return Err(rejected());
    }
    let canonical = fs::canonicalize(path).map_err(|_| rejected())?;
    if canonical != path {
        return Err(rejected());
    }
    Ok(canonical)
}

fn open_absolute_no_links(path: &Path, final_flags: i32) -> Result<fs::File, BrokerError> {
    valid_absolute_lexical_path(path)?;
    let root = CString::new("/").expect("fixed root");
    // SAFETY: fixed absolute root and flags are valid.
    let descriptor = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(rejected());
    }
    // SAFETY: open returned one newly owned descriptor.
    let mut current = unsafe { fs::File::from_raw_fd(descriptor) };
    let components = path.components().skip(1).collect::<Vec<_>>();
    if components.is_empty() {
        return Err(rejected());
    }
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(value) = component else {
            return Err(rejected());
        };
        if !safe_component(value) {
            return Err(rejected());
        }
        let value = CString::new(value.as_bytes()).map_err(|_| rejected())?;
        let flags = if index + 1 == components.len() {
            final_flags | libc::O_NOFOLLOW
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
        };
        // SAFETY: retained directory, validated component, and flags are valid.
        let next_descriptor = unsafe { libc::openat(current.as_raw_fd(), value.as_ptr(), flags) };
        if next_descriptor < 0 {
            return Err(rejected());
        }
        // SAFETY: openat returned one newly owned descriptor.
        let next = unsafe { fs::File::from_raw_fd(next_descriptor) };
        if index + 1 != components.len()
            && !safe_ancestor(&next.metadata().map_err(|_| rejected())?)
        {
            return Err(rejected());
        }
        current = next;
    }
    Ok(current)
}

fn openat_regular(parent: &fs::File, name: &CStr, access: i32) -> Result<fs::File, BrokerError> {
    // SAFETY: retained parent, validated component, and flags are valid.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            access | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(rejected());
    }
    // SAFETY: openat returned one newly owned descriptor.
    Ok(unsafe { fs::File::from_raw_fd(descriptor) })
}

fn safe_ancestor(metadata: &fs::Metadata) -> bool {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return false;
    }
    let mode = metadata.permissions().mode() & 0o7777;
    (metadata.uid() == 0 && matches!(mode, 0o555 | 0o755 | 0o1777))
        || (metadata.uid() == current_euid() && mode == 0o700)
}

fn secure_config_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == 0o600
        && metadata.len() > 0
        && metadata.len() <= MAX_CONFIG_BYTES
}

fn secure_executable(metadata: &fs::Metadata) -> bool {
    let mode = metadata.permissions().mode() & 0o7777;
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && (metadata.uid() == 0 || metadata.uid() == current_euid())
        && metadata.nlink() == 1
        && mode & 0o022 == 0
        && mode & 0o111 != 0
        && metadata.len() > 0
        && metadata.len() <= MAX_EXECUTABLE_BYTES
}

fn secure_private_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.permissions().mode() & 0o7777 == 0o700
}

fn secure_upload_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == 0o400
        && metadata.len() > 0
        && metadata.len() <= MAX_ASSET_BYTES
}

fn secure_download_file(metadata: &fs::Metadata, identity: Identity, mode: u32) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == mode
        && metadata.dev() == identity.device
        && metadata.ino() == identity.inode
}

fn safe_component(value: &OsStr) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 255
        && !matches!(bytes, b"." | b"..")
        && !bytes.contains(&b'/')
        && !bytes.contains(&0)
}

fn verify_named_file(
    path: &Path,
    retained: &fs::File,
    identity: Identity,
    policy: fn(&fs::Metadata) -> bool,
) -> Result<(), BrokerError> {
    let retained_metadata = retained.metadata().map_err(|_| rejected())?;
    let rebound =
        open_absolute_no_links(path, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK)?;
    let rebound_metadata = rebound.metadata().map_err(|_| rejected())?;
    if Identity::from_metadata(&retained_metadata) != identity
        || Identity::from_metadata(&rebound_metadata) != identity
        || !policy(&retained_metadata)
        || !policy(&rebound_metadata)
    {
        return Err(rejected());
    }
    Ok(())
}

fn verify_directory_rebind(
    path: &Path,
    retained: &fs::File,
    identity: Identity,
) -> Result<(), BrokerError> {
    let retained_metadata = retained.metadata().map_err(|_| rejected())?;
    let rebound =
        open_absolute_no_links(path, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)?;
    let rebound_metadata = rebound.metadata().map_err(|_| rejected())?;
    if !same_directory_identity(Identity::from_metadata(&retained_metadata), identity)
        || !same_directory_identity(Identity::from_metadata(&rebound_metadata), identity)
        || !secure_private_directory(&retained_metadata)
        || !secure_private_directory(&rebound_metadata)
    {
        return Err(rejected());
    }
    Ok(())
}

fn same_file_node(left: Identity, right: Identity) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && left.owner == right.owner
        && left.links == right.links
}

fn same_directory_identity(left: Identity, right: Identity) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && left.owner == right.owner
        && left.mode == right.mode
}

fn validate_elf_executable(file: &fs::File, size: u64) -> Result<(), BrokerError> {
    if size < ELF_HEADER_BYTES as u64 {
        return Err(rejected());
    }
    let mut header = [0_u8; ELF_HEADER_BYTES];
    read_descriptor_at(file, 0, &mut header)?;
    if &header[0..4] != b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || !matches!(header[7], 0 | 3)
        || header[8] != 0
        || !matches!(u16::from_le_bytes([header[16], header[17]]), 2 | 3)
        || u16::from_le_bytes([header[18], header[19]]) != 62
        || u32::from_le_bytes(header[20..24].try_into().map_err(|_| rejected())?) != 1
        || u16::from_le_bytes([header[52], header[53]]) != ELF_HEADER_BYTES as u16
        || u64::from(u16::from_le_bytes([header[54], header[55]])) != ELF_PROGRAM_HEADER_BYTES
    {
        return Err(rejected());
    }
    let program_offset = u64::from_le_bytes(header[32..40].try_into().map_err(|_| rejected())?);
    let program_count = u16::from_le_bytes([header[56], header[57]]);
    let table_size = u64::from(program_count)
        .checked_mul(ELF_PROGRAM_HEADER_BYTES)
        .ok_or_else(rejected)?;
    if program_offset < ELF_HEADER_BYTES as u64
        || program_count == 0
        || program_count > MAX_ELF_PROGRAM_HEADERS
        || program_offset
            .checked_add(table_size)
            .filter(|end| *end <= size)
            .is_none()
    {
        return Err(rejected());
    }

    let mut has_load = false;
    let mut has_executable_load = false;
    for index in 0..program_count {
        let offset = program_offset
            .checked_add(u64::from(index) * ELF_PROGRAM_HEADER_BYTES)
            .ok_or_else(rejected)?;
        let mut program = [0_u8; ELF_PROGRAM_HEADER_BYTES as usize];
        read_descriptor_at(file, offset, &mut program)?;
        let kind = u32::from_le_bytes(program[0..4].try_into().map_err(|_| rejected())?);
        let flags = u32::from_le_bytes(program[4..8].try_into().map_err(|_| rejected())?);
        let file_offset = u64::from_le_bytes(program[8..16].try_into().map_err(|_| rejected())?);
        let virtual_address =
            u64::from_le_bytes(program[16..24].try_into().map_err(|_| rejected())?);
        let file_size = u64::from_le_bytes(program[32..40].try_into().map_err(|_| rejected())?);
        let memory_size = u64::from_le_bytes(program[40..48].try_into().map_err(|_| rejected())?);
        let alignment = u64::from_le_bytes(program[48..56].try_into().map_err(|_| rejected())?);
        if file_offset
            .checked_add(file_size)
            .filter(|end| *end <= size)
            .is_none()
        {
            return Err(rejected());
        }
        if kind == 1 {
            if file_size > memory_size
                || !(alignment <= 1 || alignment.is_power_of_two())
                || (alignment > 1 && file_offset % alignment != virtual_address % alignment)
            {
                return Err(rejected());
            }
            has_load = true;
            has_executable_load |= flags & 1 != 0;
        } else if kind == 3 {
            if !(2..=4_096).contains(&file_size) {
                return Err(rejected());
            }
            let mut interpreter = vec![0_u8; file_size as usize];
            read_descriptor_at(file, file_offset, &mut interpreter)?;
            if interpreter.last() != Some(&0)
                || interpreter[..interpreter.len() - 1].contains(&0)
                || interpreter.first() != Some(&b'/')
            {
                return Err(rejected());
            }
        }
    }
    if !has_load || !has_executable_load {
        return Err(rejected());
    }
    Ok(())
}

fn read_descriptor_at(
    file: &fs::File,
    offset: u64,
    destination: &mut [u8],
) -> Result<(), BrokerError> {
    let mut completed = 0_usize;
    while completed < destination.len() {
        let absolute = offset
            .checked_add(completed as u64)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(rejected)?;
        // SAFETY: retained file, writable destination slice, bounded count, and checked offset.
        let read = unsafe {
            libc::pread(
                file.as_raw_fd(),
                destination[completed..].as_mut_ptr().cast(),
                destination.len() - completed,
                absolute,
            )
        };
        if read <= 0 {
            return Err(rejected());
        }
        completed += read as usize;
    }
    Ok(())
}

fn read_descriptor(file: &fs::File, size: u64, maximum: u64) -> Result<Vec<u8>, BrokerError> {
    if size == 0 || size > maximum {
        return Err(rejected());
    }
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

fn hash_descriptor(file: &fs::File, size: u64) -> Result<String, BrokerError> {
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

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn object(value: &Value) -> Result<&serde_json::Map<String, Value>, BrokerError> {
    value.as_object().ok_or_else(rejected)
}

fn string_field<'a>(
    value: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a str, BrokerError> {
    value.get(name).and_then(Value::as_str).ok_or_else(rejected)
}

fn bool_field(value: &serde_json::Map<String, Value>, name: &str) -> Result<bool, BrokerError> {
    value
        .get(name)
        .and_then(Value::as_bool)
        .ok_or_else(rejected)
}

fn u64_field(value: &serde_json::Map<String, Value>, name: &str) -> Result<u64, BrokerError> {
    value.get(name).and_then(Value::as_u64).ok_or_else(rejected)
}

fn decimal_json_field(
    value: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<String, BrokerError> {
    let id = u64_field(value, name)?;
    let value = id.to_string();
    valid_decimal_id(&value)?;
    Ok(value)
}

fn parse_canonical<T>(bytes: &[u8], maximum: u64) -> Result<T, BrokerProtocolError>
where
    T: for<'de> Deserialize<'de>,
{
    let value = parse_json_value(bytes, maximum, true).map_err(|_| BrokerProtocolError)?;
    serde_json::from_value(value).map_err(|_| BrokerProtocolError)
}

fn parse_json_value(bytes: &[u8], maximum: u64, canonical: bool) -> Result<Value, BrokerError> {
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(rejected());
    }
    let strict: StrictJson = serde_json::from_slice(bytes).map_err(|_| rejected())?;
    validate_json_bounds(&strict.0)?;
    if canonical && serde_jcs::to_vec(&strict.0).map_err(|_| rejected())? != bytes {
        return Err(rejected());
    }
    Ok(strict.0)
}

struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = StrictJson;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a duplicate-free JSON value")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .map(StrictJson)
                    .ok_or_else(|| E::custom("non-finite number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_string(value.to_owned())
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                StrictJson::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictJson>()? {
                    values.push(value.0);
                }
                Ok(StrictJson(Value::Array(values)))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON member"));
                    }
                    let value = map.next_value::<StrictJson>()?;
                    values.insert(key, value.0);
                }
                Ok(StrictJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn validate_json_bounds(value: &Value) -> Result<(), BrokerError> {
    fn walk(
        value: &Value,
        depth: usize,
        nodes: &mut usize,
        members: &mut usize,
    ) -> Result<(), BrokerError> {
        *nodes = nodes.checked_add(1).ok_or_else(rejected)?;
        if depth > MAX_JSON_DEPTH || *nodes > MAX_JSON_NODES {
            return Err(rejected());
        }
        match value {
            Value::Array(values) => {
                if values.len() > MAX_COLLECTION_MEMBERS {
                    return Err(rejected());
                }
                *members = members.checked_add(values.len()).ok_or_else(rejected)?;
                for value in values {
                    walk(value, depth + 1, nodes, members)?;
                }
            }
            Value::Object(values) => {
                if values.len() > MAX_COLLECTION_MEMBERS {
                    return Err(rejected());
                }
                *members = members.checked_add(values.len()).ok_or_else(rejected)?;
                for (name, value) in values {
                    if name.len() > 256 {
                        return Err(rejected());
                    }
                    walk(value, depth + 1, nodes, members)?;
                }
            }
            Value::String(value) if value.len() > 32 * 1024 => return Err(rejected()),
            _ => {}
        }
        if *members > MAX_JSON_NODES {
            return Err(rejected());
        }
        Ok(())
    }
    walk(value, 0, &mut 0, &mut 0)
}

pub(crate) fn run_process() -> Result<(), BrokerError> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2
        || arguments[0] != "--config"
        || arguments[1].is_empty()
        || arguments[1].as_bytes().len() > MAX_PATH_BYTES
    {
        return Err(rejected());
    }
    let config = PathBuf::from(&arguments[1]);
    let mut request_bytes = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut request_bytes)
        .map_err(|_| rejected())?;
    if request_bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(rejected());
    }
    let request = BrokerRequestV1::from_canonical_bytes(&request_bytes).map_err(|_| rejected())?;
    let response = execute(&config, &request)?;
    let bytes = response.to_canonical_bytes().map_err(|_| rejected())?;
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|_| rejected())?;
    std::io::stdout().flush().map_err(|_| rejected())
}

pub(crate) fn fail_process() -> ! {
    let _ = std::io::stderr().write_all(FAILURE_LINE);
    std::process::exit(1)
}
