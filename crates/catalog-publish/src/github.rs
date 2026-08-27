use std::{
    ffi::{CStr, CString, OsString},
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStringExt,
            fs::{MetadataExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::{
    broker::{
        BrokerAssetUploadStatusV1, BrokerPublicationStatusV1, BrokerRequestV1, BrokerResponseV1,
    },
    broker_client::{BrokerClient, BrokerIdentityDigests},
};

const MAX_ASSET_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_CATALOG_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemoteBoundaryError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteTag {
    pub tag: String,
    pub commit_sha: String,
    pub object_type: crate::broker::BrokerTagObjectTypeV1,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteReleaseAsset {
    pub asset_id: String,
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteRelease {
    pub release_id: String,
    pub tag: String,
    pub target_commitish: String,
    pub title: String,
    pub notes: String,
    pub draft: bool,
    pub prerelease: bool,
    pub assets: Vec<RemoteReleaseAsset>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteAsset {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

pub(crate) struct UploadSource<'a> {
    asset: &'a RemoteAsset,
    file: &'a fs::File,
}

impl<'a> UploadSource<'a> {
    pub(crate) const fn new(asset: &'a RemoteAsset, file: &'a fs::File) -> Self {
        Self { asset, file }
    }

    pub(crate) fn name(&self) -> &str {
        &self.asset.name
    }

    pub(crate) const fn size(&self) -> u64 {
        self.asset.size
    }

    pub(crate) fn sha256(&self) -> &str {
        &self.asset.sha256
    }

    pub(crate) fn read_exact(&self) -> Result<Vec<u8>, RemoteBoundaryError> {
        if self.asset.size == 0 || self.asset.size > MAX_ASSET_BYTES {
            return Err(RemoteBoundaryError);
        }
        let mut input = self.file.try_clone().map_err(|_| RemoteBoundaryError)?;
        input
            .seek(SeekFrom::Start(0))
            .map_err(|_| RemoteBoundaryError)?;
        let capacity = usize::try_from(self.asset.size).map_err(|_| RemoteBoundaryError)?;
        let mut bytes = Vec::with_capacity(capacity);
        (&mut input)
            .take(self.asset.size + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RemoteBoundaryError)?;
        if bytes.len() as u64 != self.asset.size || sha256(&bytes) != self.asset.sha256 {
            return Err(RemoteBoundaryError);
        }
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DownloadedAsset {
    pub asset_id: String,
    pub name: String,
    pub bytes: Vec<u8>,
}

/// Closed workflow-facing authenticated authority. There is deliberately no delete, replace,
/// arbitrary route, host, argument, token, or credential method.
pub(crate) trait BrokerTransport {
    fn identity_digests(&mut self) -> Result<BrokerIdentityDigests, RemoteBoundaryError>;
    fn create_tag(
        &mut self,
        repository: &str,
        tag: &str,
        commit: &str,
    ) -> Result<(), RemoteBoundaryError>;
    fn read_tag(&mut self, repository: &str, tag: &str) -> Result<RemoteTag, RemoteBoundaryError>;
    fn read_draft(
        &mut self,
        repository: &str,
        tag: &str,
    ) -> Result<Option<RemoteRelease>, RemoteBoundaryError>;
    #[allow(clippy::too_many_arguments)]
    fn create_draft(
        &mut self,
        repository: &str,
        tag: &str,
        target_commitish: &str,
        title: &str,
        notes: &str,
        prerelease: bool,
    ) -> Result<(), RemoteBoundaryError>;
    fn upload_asset(
        &mut self,
        repository: &str,
        tag: &str,
        source: &UploadSource<'_>,
    ) -> Result<(), RemoteBoundaryError>;
    fn download_asset(
        &mut self,
        repository: &str,
        asset: &RemoteReleaseAsset,
    ) -> Result<DownloadedAsset, RemoteBoundaryError>;
    fn publish_draft(
        &mut self,
        repository: &str,
        release_id: &str,
    ) -> Result<(), RemoteBoundaryError>;
}

/// Closed fake latest authority. Production directly consumes only catalog-latest-transport's
/// fixed async API; this seam exists solely for deterministic no-network workflow tests.
#[cfg(test)]
pub(crate) trait LatestTransport {
    fn fetch_catalog(&mut self, expected: &RemoteAsset) -> Result<Vec<u8>, RemoteBoundaryError>;
}

pub(crate) struct GitHubBroker {
    client: BrokerClient,
}

impl GitHubBroker {
    pub(crate) fn new(config: &Path) -> Result<Self, RemoteBoundaryError> {
        Ok(Self {
            client: BrokerClient::open(config).map_err(|_| RemoteBoundaryError)?,
        })
    }

    fn execute(&self, request: BrokerRequestV1) -> Result<BrokerResponseV1, RemoteBoundaryError> {
        self.client
            .execute(&request)
            .map_err(|_| RemoteBoundaryError)
    }
}

impl BrokerTransport for GitHubBroker {
    fn identity_digests(&mut self) -> Result<BrokerIdentityDigests, RemoteBoundaryError> {
        self.client
            .identity_digests()
            .map_err(|_| RemoteBoundaryError)
    }

    fn create_tag(
        &mut self,
        repository: &str,
        tag: &str,
        commit: &str,
    ) -> Result<(), RemoteBoundaryError> {
        match self.execute(BrokerRequestV1::CreateTag {
            schema_version: 1,
            repository: repository.to_owned(),
            tag: tag.to_owned(),
            commit_sha: commit.to_owned(),
        })? {
            BrokerResponseV1::Tag { .. } => Ok(()),
            _ => Err(RemoteBoundaryError),
        }
    }

    fn read_tag(&mut self, repository: &str, tag: &str) -> Result<RemoteTag, RemoteBoundaryError> {
        match self.execute(BrokerRequestV1::ReadTag {
            schema_version: 1,
            repository: repository.to_owned(),
            tag: tag.to_owned(),
        })? {
            BrokerResponseV1::Tag {
                tag,
                commit_sha,
                object_type,
                ..
            } => Ok(RemoteTag {
                tag,
                commit_sha,
                object_type,
            }),
            _ => Err(RemoteBoundaryError),
        }
    }

    fn read_draft(
        &mut self,
        repository: &str,
        tag: &str,
    ) -> Result<Option<RemoteRelease>, RemoteBoundaryError> {
        match self.execute(BrokerRequestV1::ReadDraft {
            schema_version: 1,
            repository: repository.to_owned(),
            tag: tag.to_owned(),
        })? {
            BrokerResponseV1::DraftMissing { tag: actual, .. } if actual == tag => Ok(None),
            BrokerResponseV1::Draft {
                release_id,
                tag,
                target_commitish,
                title,
                notes,
                draft,
                prerelease,
                assets,
                ..
            } => Ok(Some(RemoteRelease {
                release_id,
                tag,
                target_commitish,
                title,
                notes,
                draft,
                prerelease,
                assets: assets
                    .into_iter()
                    .map(|asset| RemoteReleaseAsset {
                        asset_id: asset.asset_id,
                        name: asset.name,
                        size: asset.size,
                    })
                    .collect(),
            })),
            _ => Err(RemoteBoundaryError),
        }
    }

    fn create_draft(
        &mut self,
        repository: &str,
        tag: &str,
        target_commitish: &str,
        title: &str,
        notes: &str,
        prerelease: bool,
    ) -> Result<(), RemoteBoundaryError> {
        match self.execute(BrokerRequestV1::CreateDraft {
            schema_version: 1,
            repository: repository.to_owned(),
            tag: tag.to_owned(),
            target_commitish: target_commitish.to_owned(),
            title: title.to_owned(),
            notes: notes.to_owned(),
            prerelease,
        })? {
            BrokerResponseV1::Draft { .. } => Ok(()),
            _ => Err(RemoteBoundaryError),
        }
    }

    fn upload_asset(
        &mut self,
        repository: &str,
        tag: &str,
        source: &UploadSource<'_>,
    ) -> Result<(), RemoteBoundaryError> {
        let scratch = ScratchDirectory::new(b"/tmp/catalog-publish-upload-XXXXXX\0")?;
        let path = scratch.write_source(source)?;
        let response = self.execute(BrokerRequestV1::UploadAsset {
            schema_version: 1,
            repository: repository.to_owned(),
            tag: tag.to_owned(),
            name: source.name().to_owned(),
            input_path: path.to_str().ok_or(RemoteBoundaryError)?.to_owned(),
        })?;
        match response {
            BrokerResponseV1::AssetUploaded {
                status: BrokerAssetUploadStatusV1::AssetUploaded,
                name,
                size,
                sha256,
                ..
            } if name == source.name() && size == source.size() && sha256 == source.sha256() => {
                Ok(())
            }
            _ => Err(RemoteBoundaryError),
        }
    }

    fn download_asset(
        &mut self,
        repository: &str,
        asset: &RemoteReleaseAsset,
    ) -> Result<DownloadedAsset, RemoteBoundaryError> {
        let scratch = ScratchDirectory::new(b"/tmp/catalog-publish-download-XXXXXX\0")?;
        let output = scratch.path.join(&asset.name);
        let response = self.execute(BrokerRequestV1::DownloadAsset {
            schema_version: 1,
            repository: repository.to_owned(),
            asset_id: asset.asset_id.clone(),
            name: asset.name.clone(),
            output_path: output.to_str().ok_or(RemoteBoundaryError)?.to_owned(),
        })?;
        let transferred = match response {
            BrokerResponseV1::Asset {
                asset: transferred, ..
            } if transferred.asset_id == asset.asset_id
                && transferred.name == asset.name
                && transferred.size == asset.size =>
            {
                transferred
            }
            _ => return Err(RemoteBoundaryError),
        };
        let bytes = scratch.read_output(&asset.name, asset.size, &transferred.sha256)?;
        Ok(DownloadedAsset {
            asset_id: transferred.asset_id,
            name: transferred.name,
            bytes,
        })
    }

    fn publish_draft(
        &mut self,
        repository: &str,
        release_id: &str,
    ) -> Result<(), RemoteBoundaryError> {
        match self.execute(BrokerRequestV1::PublishDraft {
            schema_version: 1,
            repository: repository.to_owned(),
            release_id: release_id.to_owned(),
        })? {
            BrokerResponseV1::Published {
                release_id: actual,
                status: BrokerPublicationStatusV1::Published,
                ..
            } if actual == release_id => Ok(()),
            _ => Err(RemoteBoundaryError),
        }
    }
}

pub(crate) struct CredentialFreeLatest;

impl CredentialFreeLatest {
    pub(crate) async fn fetch_catalog(
        expected: &RemoteAsset,
    ) -> Result<Vec<u8>, RemoteBoundaryError> {
        if expected.name != "catalog-v1.json"
            || expected.size == 0
            || expected.size > MAX_CATALOG_BYTES
        {
            return Err(RemoteBoundaryError);
        }
        let fetched = catalog_latest_transport::fetch_runtime_catalog_latest_exact(
            expected.size,
            &expected.sha256,
        )
        .await
        .map_err(|_| RemoteBoundaryError)?;
        let bytes = fetched.into_bytes();
        if bytes.len() as u64 != expected.size || sha256(&bytes) != expected.sha256 {
            return Err(RemoteBoundaryError);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ScratchIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
}

impl ScratchIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
            links: metadata.nlink(),
        }
    }
}

struct ScratchDirectory {
    path: PathBuf,
    directory: fs::File,
    identity: ScratchIdentity,
}

impl ScratchDirectory {
    fn new(template: &[u8]) -> Result<Self, RemoteBoundaryError> {
        if !template.ends_with(b"XXXXXX\0") {
            return Err(RemoteBoundaryError);
        }
        let mut bytes = template.to_vec();
        // SAFETY: the private fixed template is writable and NUL terminated.
        let pointer = unsafe { libc::mkdtemp(bytes.as_mut_ptr().cast()) };
        if pointer.is_null() {
            return Err(RemoteBoundaryError);
        }
        // SAFETY: successful mkdtemp returned the same live terminated buffer.
        let path = PathBuf::from(OsString::from_vec(
            unsafe { CStr::from_ptr(pointer) }.to_bytes().to_vec(),
        ));
        let component =
            CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| RemoteBoundaryError)?;
        // SAFETY: fixed absolute mkdtemp output and no-follow directory flags are valid.
        let descriptor = unsafe {
            libc::open(
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(RemoteBoundaryError);
        }
        // SAFETY: open returned one owned descriptor.
        let directory = unsafe { fs::File::from_raw_fd(descriptor) };
        let metadata = directory.metadata().map_err(|_| RemoteBoundaryError)?;
        if !secure_scratch_directory(&metadata) {
            return Err(RemoteBoundaryError);
        }
        let scratch = Self {
            path,
            directory,
            identity: ScratchIdentity::from_metadata(&metadata),
        };
        scratch.revalidate_directory()?;
        Ok(scratch)
    }

    fn canonical_directory(&self) -> Result<fs::File, RemoteBoundaryError> {
        let path = CString::new(self.path.as_os_str().as_encoded_bytes())
            .map_err(|_| RemoteBoundaryError)?;
        // SAFETY: admitted absolute mkdtemp path and no-follow directory flags are valid.
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(RemoteBoundaryError);
        }
        // SAFETY: open returned one owned descriptor.
        Ok(unsafe { fs::File::from_raw_fd(descriptor) })
    }

    fn revalidate_directory(&self) -> Result<(), RemoteBoundaryError> {
        let retained = self.directory.metadata().map_err(|_| RemoteBoundaryError)?;
        let canonical = self.canonical_directory()?;
        let canonical_metadata = canonical.metadata().map_err(|_| RemoteBoundaryError)?;
        if !secure_scratch_directory(&retained)
            || !secure_scratch_directory(&canonical_metadata)
            || ScratchIdentity::from_metadata(&retained) != self.identity
            || ScratchIdentity::from_metadata(&canonical_metadata) != self.identity
        {
            return Err(RemoteBoundaryError);
        }
        Ok(())
    }

    fn write_source(&self, source: &UploadSource<'_>) -> Result<PathBuf, RemoteBoundaryError> {
        self.revalidate_directory()?;
        let name = safe_name(source.name())?;
        // SAFETY: retained private directory, validated name, and no-clobber flags are valid.
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(RemoteBoundaryError);
        }
        // SAFETY: openat returned one owned descriptor.
        let mut output = unsafe { fs::File::from_raw_fd(descriptor) };
        let bytes = source.read_exact()?;
        output.write_all(&bytes).map_err(|_| RemoteBoundaryError)?;
        output.flush().map_err(|_| RemoteBoundaryError)?;
        output
            .set_permissions(fs::Permissions::from_mode(0o400))
            .map_err(|_| RemoteBoundaryError)?;
        output.sync_all().map_err(|_| RemoteBoundaryError)?;
        let metadata = output.metadata().map_err(|_| RemoteBoundaryError)?;
        let rebound = open_scratch_file(&self.directory, &name)?;
        let rebound_metadata = rebound.metadata().map_err(|_| RemoteBoundaryError)?;
        if !secure_scratch_file(&metadata, 0o400, source.size())
            || !secure_scratch_file(&rebound_metadata, 0o400, source.size())
            || ScratchIdentity::from_metadata(&metadata)
                != ScratchIdentity::from_metadata(&rebound_metadata)
            || read_scratch_file(&rebound, source.size())? != bytes
            || sha256(&bytes) != source.sha256()
        {
            return Err(RemoteBoundaryError);
        }
        self.directory.sync_all().map_err(|_| RemoteBoundaryError)?;
        self.revalidate_directory()?;
        Ok(self.path.join(source.name()))
    }

    fn read_output(
        &self,
        name: &str,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<Vec<u8>, RemoteBoundaryError> {
        self.revalidate_directory()?;
        let name = safe_name(name)?;
        let retained = open_scratch_file(&self.directory, &name)?;
        let retained_metadata = retained.metadata().map_err(|_| RemoteBoundaryError)?;
        let canonical_directory = self.canonical_directory()?;
        let canonical_directory_metadata = canonical_directory
            .metadata()
            .map_err(|_| RemoteBoundaryError)?;
        if ScratchIdentity::from_metadata(&canonical_directory_metadata) != self.identity {
            return Err(RemoteBoundaryError);
        }
        let canonical = open_scratch_file(&canonical_directory, &name)?;
        let canonical_metadata = canonical.metadata().map_err(|_| RemoteBoundaryError)?;
        if !secure_scratch_file(&retained_metadata, 0o400, expected_size)
            || !secure_scratch_file(&canonical_metadata, 0o400, expected_size)
            || ScratchIdentity::from_metadata(&retained_metadata)
                != ScratchIdentity::from_metadata(&canonical_metadata)
        {
            return Err(RemoteBoundaryError);
        }
        let bytes = read_scratch_file(&retained, expected_size)?;
        if read_scratch_file(&canonical, expected_size)? != bytes
            || sha256(&bytes) != expected_sha256
        {
            return Err(RemoteBoundaryError);
        }
        self.revalidate_directory()?;
        Ok(bytes)
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        if self.revalidate_directory().is_err() {
            return;
        }
        let Ok(entries) = fs::read_dir(&self.path) else {
            return;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return;
            };
            let Ok(name) = safe_name(&name) else {
                return;
            };
            let Ok(file) = open_scratch_file(&self.directory, &name) else {
                return;
            };
            let Ok(metadata) = file.metadata() else {
                return;
            };
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != current_euid()
                || metadata.nlink() != 1
            {
                return;
            }
            // SAFETY: retained exact directory and re-opened validated component are valid.
            if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return;
            }
        }
        let _ = self.directory.sync_all();
        if self.revalidate_directory().is_ok() {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

fn secure_scratch_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.nlink() == 2
        && metadata.permissions().mode() & 0o7777 == 0o700
}

fn secure_scratch_file(metadata: &fs::Metadata, mode: u32, size: u64) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == mode
        && metadata.len() == size
}

fn open_scratch_file(directory: &fs::File, name: &CStr) -> Result<fs::File, RemoteBoundaryError> {
    // SAFETY: retained private directory and validated component are valid.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(RemoteBoundaryError);
    }
    // SAFETY: openat returned one owned descriptor.
    Ok(unsafe { fs::File::from_raw_fd(descriptor) })
}

fn read_scratch_file(file: &fs::File, expected_size: u64) -> Result<Vec<u8>, RemoteBoundaryError> {
    let capacity = usize::try_from(expected_size).map_err(|_| RemoteBoundaryError)?;
    let mut file = file.try_clone().map_err(|_| RemoteBoundaryError)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| RemoteBoundaryError)?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(expected_size + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RemoteBoundaryError)?;
    if bytes.len() as u64 != expected_size {
        return Err(RemoteBoundaryError);
    }
    Ok(bytes)
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

#[allow(dead_code)]
#[cfg(test)]
pub(crate) fn scratch_directory_swap_is_rejected_for_test() -> bool {
    let Ok(scratch) = ScratchDirectory::new(b"/tmp/catalog-publish-rebind-test-XXXXXX\0") else {
        return false;
    };
    let detached = scratch.path.with_extension("detached");
    if fs::rename(&scratch.path, &detached).is_err()
        || fs::create_dir(&scratch.path).is_err()
        || fs::set_permissions(&scratch.path, fs::Permissions::from_mode(0o700)).is_err()
    {
        return false;
    }
    let rejected = scratch.revalidate_directory().is_err();
    let _ = fs::remove_dir(&scratch.path);
    let _ = fs::rename(&detached, &scratch.path);
    drop(scratch);
    rejected
}

fn safe_name(name: &str) -> Result<CString, RemoteBoundaryError> {
    if name.is_empty()
        || name.len() > 255
        || name.starts_with('.')
        || name.ends_with('.')
        || name.contains("..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RemoteBoundaryError);
    }
    CString::new(name).map_err(|_| RemoteBoundaryError)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
