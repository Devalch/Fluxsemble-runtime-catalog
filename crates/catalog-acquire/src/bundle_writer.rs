use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
};

use catalog_core::{InputSourceKind, VerifiedInputBundleV1, verified_input_bundle_digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AcquireError, VerifiedArchive};

const VERIFIED_INPUT_NAME: &str = "verified-input-bundle-v1.json";
const TRANSFER_MANIFEST_NAME: &str = "transfer-manifest-v1.json";
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 32_768;

pub struct PublicBundleObject {
    file: fs::File,
    source_url: String,
    size: u64,
    sha256: String,
}

impl PublicBundleObject {
    #[must_use]
    pub fn from_archive(archive: VerifiedArchive) -> Self {
        let source_url = archive.source_url().to_owned();
        let size = archive.size();
        let sha256 = archive.sha256().to_owned();
        Self {
            file: archive.into_file(),
            source_url,
            size,
            sha256,
        }
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn verified_file(
        file: fs::File,
        source_url: String,
        size: u64,
        sha256: String,
    ) -> Result<Self, AcquireError> {
        let mut object = Self {
            file,
            source_url,
            size,
            sha256,
        };
        verify_object_descriptor(&mut object.file, object.size, &object.sha256)?;
        Ok(object)
    }
}

pub struct BundleRecord {
    pub role: String,
    pub bytes: Vec<u8>,
}

pub struct VerifiedBundleWriteRequest {
    pub source_kind: InputSourceKind,
    pub source_sha256: String,
    pub compatibility_input_sha256: String,
    pub source_commit: Option<String>,
    pub source_tree_sha256: Option<String>,
    pub records: Vec<BundleRecord>,
    pub objects: Vec<PublicBundleObject>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferManifestV1 {
    schema_version: u16,
    kind: String,
    source_commit: Option<String>,
    source_tree_sha256: Option<String>,
    records: Vec<TransferRecordRef>,
    entries: Vec<TransferEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferRecordRef {
    role: String,
    relative_path: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferEntry {
    relative_path: String,
    mode: String,
    size: u64,
    sha256: String,
}

pub struct VerifiedTransferredBundle {
    _root: fs::File,
    _manifest: TransferManifestV1,
    manifest_bytes: Vec<u8>,
    files: Vec<(TransferEntry, fs::File)>,
    bundle_sha256: String,
    object_count: usize,
    total_bytes: u64,
    verified_input: VerifiedInputBundleV1,
}

impl VerifiedTransferredBundle {
    #[must_use]
    pub fn bundle_sha256(&self) -> &str {
        &self.bundle_sha256
    }

    #[must_use]
    pub const fn object_count(&self) -> usize {
        self.object_count
    }

    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    #[must_use]
    pub fn verified_input(&self) -> &VerifiedInputBundleV1 {
        &self.verified_input
    }

    fn root_identity(&self) -> FileIdentity {
        FileIdentity::from_metadata(
            &self
                ._root
                .metadata()
                .expect("retained verified bundle root metadata"),
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

struct TrackedOutputFile {
    directory: Option<String>,
    name: String,
    identity: FileIdentity,
    _file: fs::File,
}

/// A fresh output namespace retained as directory capabilities for its complete lifetime.
///
/// Failure cleanup deliberately leaves the owner-private root in place: Linux has no atomic
/// unlink-by-directory-fd operation that can prove a pathname still names this exact directory.
pub(crate) struct OutputRoot {
    parent: fs::File,
    name: CString,
    root: fs::File,
    identity: FileIdentity,
    directories: BTreeMap<String, fs::File>,
    files: Vec<TrackedOutputFile>,
    committed: bool,
}

impl OutputRoot {
    pub(crate) fn create(path: &Path) -> Result<Self, AcquireError> {
        Self::create_with_policy(path, false)
    }

    pub(crate) fn create_new(path: &Path) -> Result<Self, AcquireError> {
        Self::create_with_policy(path, true)
    }

    fn create_with_policy(path: &Path, require_absent: bool) -> Result<Self, AcquireError> {
        let (parent, name) = open_output_parent(path)?;
        let root = match open_directory_at(&parent, &name) {
            Ok(root) => {
                let metadata = root.metadata().map_err(|_| AcquireError::Bundle)?;
                if require_absent || !secure_directory(&metadata) || !directory_is_empty(&root)? {
                    return Err(AcquireError::Bundle);
                }
                root
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // SAFETY: parent and NUL-terminated name are retained and mode is owner-private.
                if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                    return Err(AcquireError::Bundle);
                }
                parent.sync_all().map_err(|_| AcquireError::Bundle)?;
                open_directory_at(&parent, &name).map_err(|_| AcquireError::Bundle)?
            }
            Err(_) => return Err(AcquireError::Bundle),
        };
        let metadata = root.metadata().map_err(|_| AcquireError::Bundle)?;
        if !secure_directory(&metadata) {
            return Err(AcquireError::Bundle);
        }
        Ok(Self {
            parent,
            name,
            identity: FileIdentity::from_metadata(&metadata),
            root,
            directories: BTreeMap::new(),
            files: Vec::new(),
            committed: false,
        })
    }

    pub(crate) fn create_directory(&mut self, name: &str) -> Result<(), AcquireError> {
        if !safe_component(name) || self.directories.contains_key(name) {
            return Err(AcquireError::Bundle);
        }
        let name_c = CString::new(name).map_err(|_| AcquireError::Bundle)?;
        // SAFETY: root and NUL-terminated name are valid and mode is owner-private.
        if unsafe { libc::mkdirat(self.root.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
            return Err(AcquireError::Bundle);
        }
        let directory = open_directory_at(&self.root, &name_c).map_err(|_| AcquireError::Bundle)?;
        if !secure_directory(&directory.metadata().map_err(|_| AcquireError::Bundle)?) {
            return Err(AcquireError::Bundle);
        }
        self.root.sync_all().map_err(|_| AcquireError::Bundle)?;
        self.directories.insert(name.to_owned(), directory);
        Ok(())
    }

    pub(crate) fn write_file(&mut self, relative: &str, bytes: &[u8]) -> Result<(), AcquireError> {
        let digest = sha256(bytes);
        let mut file = self.create_file(relative)?;
        file.write_all(bytes).map_err(|_| AcquireError::Bundle)?;
        self.settle_file(relative, file, bytes.len() as u64, &digest)
    }

    fn copy_file(
        &mut self,
        relative: &str,
        source: &mut fs::File,
        size: u64,
        digest: &str,
    ) -> Result<(), AcquireError> {
        source
            .seek(SeekFrom::Start(0))
            .map_err(|_| AcquireError::Bundle)?;
        let mut target = self.create_file(relative)?;
        let copied = std::io::copy(source, &mut target).map_err(|_| AcquireError::Bundle)?;
        source
            .seek(SeekFrom::Start(0))
            .map_err(|_| AcquireError::Bundle)?;
        if copied != size {
            return Err(AcquireError::Bundle);
        }
        self.settle_file(relative, target, size, digest)
    }

    fn create_file(&mut self, relative: &str) -> Result<fs::File, AcquireError> {
        let (directory, name) = split_output_relative(relative)?;
        let parent = self.directory(directory)?;
        let file = open_component(
            parent,
            name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o600,
        )
        .map_err(|_| AcquireError::Bundle)?;
        let tracked = file.try_clone().map_err(|_| AcquireError::Bundle)?;
        let identity =
            FileIdentity::from_metadata(&tracked.metadata().map_err(|_| AcquireError::Bundle)?);
        self.files.push(TrackedOutputFile {
            directory: directory.map(str::to_owned),
            name: name.to_owned(),
            identity,
            _file: tracked,
        });
        Ok(file)
    }

    fn settle_file(
        &self,
        relative: &str,
        mut file: fs::File,
        size: u64,
        digest: &str,
    ) -> Result<(), AcquireError> {
        file.flush().map_err(|_| AcquireError::Bundle)?;
        file.sync_all().map_err(|_| AcquireError::Bundle)?;
        file.set_permissions(fs::Permissions::from_mode(0o400))
            .map_err(|_| AcquireError::Bundle)?;
        file.sync_all().map_err(|_| AcquireError::Bundle)?;
        let identity =
            FileIdentity::from_metadata(&file.metadata().map_err(|_| AcquireError::Bundle)?);
        drop(file);
        let directory = split_output_relative(relative)?.0;
        self.directory(directory)?
            .sync_all()
            .map_err(|_| AcquireError::Bundle)?;
        let (file, metadata) = self.open_file(relative)?;
        if FileIdentity::from_metadata(&metadata) != identity {
            return Err(AcquireError::Bundle);
        }
        let entry = entry(relative, size, digest);
        let name = split_output_relative(relative)?.1;
        let _ = verify_open_file_from(self.directory(directory)?, name, file, &entry)?;
        Ok(())
    }

    pub(crate) fn open_file(
        &self,
        relative: &str,
    ) -> Result<(fs::File, fs::Metadata), AcquireError> {
        let (directory, name) = split_output_relative(relative)?;
        let file = open_component(
            self.directory(directory)?,
            name,
            libc::O_RDONLY | libc::O_CLOEXEC,
            0,
        )
        .map_err(|_| AcquireError::Bundle)?;
        let metadata = file.metadata().map_err(|_| AcquireError::Bundle)?;
        Ok((file, metadata))
    }

    fn directory(&self, name: Option<&str>) -> Result<&fs::File, AcquireError> {
        match name {
            None => Ok(&self.root),
            Some(name) => self.directories.get(name).ok_or(AcquireError::Bundle),
        }
    }

    pub(crate) fn sync(&self) -> Result<(), AcquireError> {
        for directory in self.directories.values() {
            directory.sync_all().map_err(|_| AcquireError::Bundle)?;
        }
        self.root.sync_all().map_err(|_| AcquireError::Bundle)
    }

    fn cloned_root(&self) -> Result<fs::File, AcquireError> {
        self.root.try_clone().map_err(|_| AcquireError::Bundle)
    }

    fn identity(&self) -> FileIdentity {
        self.identity
    }

    pub(crate) fn commit(&mut self) -> Result<(), AcquireError> {
        let named =
            open_directory_at(&self.parent, &self.name).map_err(|_| AcquireError::Bundle)?;
        if FileIdentity::from_metadata(&named.metadata().map_err(|_| AcquireError::Bundle)?)
            != self.identity
        {
            return Err(AcquireError::Bundle);
        }
        self.committed = true;
        Ok(())
    }
}

impl Drop for OutputRoot {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for tracked in self.files.iter().rev() {
            let parent = match tracked.directory.as_deref() {
                Some(name) => self.directories.get(name),
                None => Some(&self.root),
            };
            let Some(parent) = parent else {
                continue;
            };
            let Ok(name) = CString::new(tracked.name.as_str()) else {
                continue;
            };
            let Ok(candidate) =
                open_component(parent, &tracked.name, libc::O_RDONLY | libc::O_CLOEXEC, 0)
            else {
                continue;
            };
            let Ok(metadata) = candidate.metadata() else {
                continue;
            };
            if FileIdentity::from_metadata(&metadata) != tracked.identity {
                continue;
            }
            // SAFETY: deletion is relative to the retained original directory capability.
            let _ = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
        }
        for (name, directory) in self.directories.iter().rev() {
            let _ = directory.sync_all();
            let Ok(name_c) = CString::new(name.as_str()) else {
                continue;
            };
            let Ok(named) = open_directory_at(&self.root, &name_c) else {
                continue;
            };
            let Ok(retained_metadata) = directory.metadata() else {
                continue;
            };
            let Ok(named_metadata) = named.metadata() else {
                continue;
            };
            if FileIdentity::from_metadata(&retained_metadata)
                != FileIdentity::from_metadata(&named_metadata)
            {
                continue;
            }
            // SAFETY: removal is relative to the retained original root and never recurses.
            let _ = unsafe {
                libc::unlinkat(self.root.as_raw_fd(), name_c.as_ptr(), libc::AT_REMOVEDIR)
            };
        }
        let _ = self.root.sync_all();
    }
}

pub fn write_verified_bundle(
    request: VerifiedBundleWriteRequest,
    output: &Path,
) -> Result<VerifiedInputBundleV1, AcquireError> {
    write_verified_bundle_with_decision(request, output, || true)
}

pub(crate) fn write_verified_bundle_with_decision(
    request: VerifiedBundleWriteRequest,
    output: &Path,
    decide_publication: impl FnOnce() -> bool,
) -> Result<VerifiedInputBundleV1, AcquireError> {
    validate_claims(&request)?;
    let mut output_root = OutputRoot::create(output)?;
    output_root.create_directory("objects")?;
    output_root.create_directory("records")?;

    let mut entries = Vec::new();
    let mut records = Vec::new();
    let mut role_names = BTreeSet::new();
    for record in request.records {
        if !safe_role(&record.role)
            || !role_names.insert(record.role.clone())
            || record.bytes.is_empty()
            || record.bytes.len() as u64 > MAX_MANIFEST_BYTES
        {
            return Err(AcquireError::Bundle);
        }
        let digest = sha256(&record.bytes);
        let relative = format!("records/{digest}");
        output_root.write_file(&relative, &record.bytes)?;
        entries.push(entry(&relative, record.bytes.len() as u64, &digest));
        records.push(TransferRecordRef {
            role: record.role,
            relative_path: relative,
            sha256: digest,
        });
    }
    records.sort_by(|left, right| left.role.cmp(&right.role));

    let mut object_records = BTreeMap::<String, (String, u64)>::new();
    for mut object in request.objects {
        verify_object_descriptor(&mut object.file, object.size, &object.sha256)?;
        match object_records.get(&object.sha256) {
            Some((url, size)) if url == &object.source_url && *size == object.size => continue,
            Some(_) => return Err(AcquireError::Bundle),
            None => {}
        }
        let relative = format!("objects/{}", object.sha256);
        output_root.copy_file(&relative, &mut object.file, object.size, &object.sha256)?;
        entries.push(entry(&relative, object.size, &object.sha256));
        object_records.insert(object.sha256, (object.source_url, object.size));
    }
    if object_records.is_empty() {
        return Err(AcquireError::Bundle);
    }
    let objects = object_records
        .iter()
        .map(|(digest, (url, size))| {
            serde_json::json!({
                "relative_path": format!("objects/{digest}"),
                "source_url": url,
                "size": size,
                "sha256": digest,
            })
        })
        .collect::<Vec<_>>();
    let bundle_value = serde_json::json!({
        "schema_version": 1,
        "source_kind": request.source_kind,
        "source_sha256": request.source_sha256,
        "compatibility_input_sha256": request.compatibility_input_sha256,
        "objects": objects,
    });
    let bundle_bytes = serde_jcs::to_vec(&bundle_value).map_err(|_| AcquireError::Bundle)?;
    let verified =
        VerifiedInputBundleV1::from_json(&bundle_bytes).map_err(|_| AcquireError::Bundle)?;
    output_root.write_file(VERIFIED_INPUT_NAME, &bundle_bytes)?;
    entries.push(entry(
        VERIFIED_INPUT_NAME,
        bundle_bytes.len() as u64,
        &sha256(&bundle_bytes),
    ));

    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let manifest = TransferManifestV1 {
        schema_version: 1,
        kind: "verified_input".to_owned(),
        source_commit: request.source_commit,
        source_tree_sha256: request.source_tree_sha256,
        records,
        entries,
    };
    validate_manifest(&manifest)?;
    let manifest_bytes = serde_jcs::to_vec(&manifest).map_err(|_| AcquireError::Bundle)?;
    output_root.write_file(TRANSFER_MANIFEST_NAME, &manifest_bytes)?;
    output_root.sync()?;
    let reopened = verify_transferred_bundle_root(output_root.cloned_root()?)?;
    if reopened.verified_input != verified || reopened.root_identity() != output_root.identity() {
        return Err(AcquireError::Bundle);
    }
    if !decide_publication() {
        return Err(AcquireError::Cancelled);
    }
    output_root.commit()?;
    Ok(verified)
}

pub fn verify_transferred_bundle(path: &Path) -> Result<VerifiedTransferredBundle, AcquireError> {
    verify_transferred_bundle_root(open_secure_root(path)?)
}

fn verify_transferred_bundle_root(
    root: fs::File,
) -> Result<VerifiedTransferredBundle, AcquireError> {
    let (manifest_file, manifest_metadata) = open_relative(&root, TRANSFER_MANIFEST_NAME)?;
    if !secure_file(&manifest_metadata) || manifest_metadata.len() > MAX_MANIFEST_BYTES {
        return Err(AcquireError::Bundle);
    }
    let manifest_bytes = read_exact_file(manifest_file, manifest_metadata.len(), None)?;
    let manifest: TransferManifestV1 =
        serde_json::from_slice(&manifest_bytes).map_err(|_| AcquireError::Bundle)?;
    if serde_jcs::to_vec(&manifest).map_err(|_| AcquireError::Bundle)? != manifest_bytes {
        return Err(AcquireError::Bundle);
    }
    validate_manifest(&manifest)?;
    let actual = enumerate_tree(&root)?;
    let expected = manifest
        .entries
        .iter()
        .map(|entry| entry.relative_path.clone())
        .chain(std::iter::once(TRANSFER_MANIFEST_NAME.to_owned()))
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(AcquireError::Bundle);
    }

    let mut files = Vec::with_capacity(manifest.entries.len());
    let mut total = 0_u64;
    for entry in &manifest.entries {
        let (file, metadata) = open_relative(&root, &entry.relative_path)?;
        if !secure_file(&metadata) || metadata.len() != entry.size {
            return Err(AcquireError::Bundle);
        }
        let file = verify_open_file(&root, &entry.relative_path, file, entry)?;
        total = total.checked_add(entry.size).ok_or(AcquireError::Bundle)?;
        files.push((entry.clone(), file));
    }
    let verified_entry = manifest
        .entries
        .iter()
        .find(|entry| entry.relative_path == VERIFIED_INPUT_NAME)
        .filter(|entry| entry.size <= MAX_MANIFEST_BYTES)
        .ok_or(AcquireError::Bundle)?;
    let (_, verified_file) = files
        .iter_mut()
        .find(|(entry, _)| entry.relative_path == VERIFIED_INPUT_NAME)
        .ok_or(AcquireError::Bundle)?;
    verified_file
        .seek(SeekFrom::Start(0))
        .map_err(|_| AcquireError::Bundle)?;
    let mut verified_bytes = Vec::with_capacity(verified_entry.size as usize);
    verified_file
        .read_to_end(&mut verified_bytes)
        .map_err(|_| AcquireError::Bundle)?;
    verified_file
        .seek(SeekFrom::Start(0))
        .map_err(|_| AcquireError::Bundle)?;
    let verified_input =
        VerifiedInputBundleV1::from_json(&verified_bytes).map_err(|_| AcquireError::Bundle)?;
    if serde_jcs::to_vec(&verified_input).map_err(|_| AcquireError::Bundle)? != verified_bytes {
        return Err(AcquireError::Bundle);
    }
    let manifested_objects = manifest
        .entries
        .iter()
        .filter(|entry| entry.relative_path.starts_with("objects/"))
        .map(|entry| {
            (
                entry.relative_path.as_str(),
                entry.size,
                entry.sha256.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    let verified_objects = verified_input
        .objects()
        .iter()
        .map(|object| {
            (
                object.relative_path().as_str(),
                object.size(),
                object.sha256().as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    if manifested_objects != verified_objects {
        return Err(AcquireError::Bundle);
    }
    for record in &manifest.records {
        let entry = manifest
            .entries
            .iter()
            .find(|entry| entry.relative_path == record.relative_path)
            .ok_or(AcquireError::Bundle)?;
        if entry.sha256 != record.sha256 || !entry.relative_path.starts_with("records/") {
            return Err(AcquireError::Bundle);
        }
    }
    let object_count = verified_input.objects().len();
    let bundle_sha256 = sha256(&manifest_bytes);
    Ok(VerifiedTransferredBundle {
        _root: root,
        _manifest: manifest,
        manifest_bytes,
        files,
        bundle_sha256,
        object_count,
        total_bytes: total,
        verified_input,
    })
}

pub fn export_transfer_bundle(
    bundle: &Path,
    output: &Path,
) -> Result<VerifiedTransferredBundle, AcquireError> {
    let mut verified = verify_transferred_bundle(bundle)?;
    let mut output_root = OutputRoot::create(output)?;
    output_root.create_directory("objects")?;
    output_root.create_directory("records")?;
    for (entry, file) in &mut verified.files {
        output_root.copy_file(&entry.relative_path, file, entry.size, &entry.sha256)?;
    }
    output_root.write_file(TRANSFER_MANIFEST_NAME, &verified.manifest_bytes)?;
    output_root.sync()?;
    let exported = verify_transferred_bundle_root(output_root.cloned_root()?)?;
    if exported.root_identity() != output_root.identity() {
        return Err(AcquireError::Bundle);
    }
    output_root.commit()?;
    Ok(exported)
}

fn validate_claims(request: &VerifiedBundleWriteRequest) -> Result<(), AcquireError> {
    if !valid_sha256(&request.source_sha256)
        || !valid_sha256(&request.compatibility_input_sha256)
        || request
            .source_commit
            .as_ref()
            .is_some_and(|value| !valid_commit(value))
        || request
            .source_tree_sha256
            .as_ref()
            .is_some_and(|value| !valid_sha256(value))
        || request.source_commit.is_some() != request.source_tree_sha256.is_some()
        || (request.source_kind == InputSourceKind::CatalogSource
            && request.source_commit.is_none())
        || (request.source_kind == InputSourceKind::ReleaseIntent
            && request.source_commit.is_some())
    {
        return Err(AcquireError::Bundle);
    }
    Ok(())
}

fn validate_manifest(manifest: &TransferManifestV1) -> Result<(), AcquireError> {
    if manifest.schema_version != 1
        || manifest.kind != "verified_input"
        || manifest.entries.is_empty()
        || manifest.entries.len() > MAX_ENTRIES
        || manifest
            .entries
            .windows(2)
            .any(|pair| pair[0].relative_path >= pair[1].relative_path)
        || manifest
            .records
            .windows(2)
            .any(|pair| pair[0].role >= pair[1].role)
        || manifest
            .source_commit
            .as_ref()
            .is_some_and(|value| !valid_commit(value))
        || manifest
            .source_tree_sha256
            .as_ref()
            .is_some_and(|value| !valid_sha256(value))
        || manifest.source_commit.is_some() != manifest.source_tree_sha256.is_some()
    {
        return Err(AcquireError::Bundle);
    }
    let mut total = 0_u64;
    for entry in &manifest.entries {
        if !safe_relative(&entry.relative_path)
            || entry.relative_path == TRANSFER_MANIFEST_NAME
            || entry.mode != "0400"
            || entry.size == 0
            || entry.size > MAX_ENTRY_BYTES
            || !valid_sha256(&entry.sha256)
            || (entry.relative_path.starts_with("objects/")
                && entry.relative_path != format!("objects/{}", entry.sha256))
            || (entry.relative_path.starts_with("records/")
                && entry.relative_path != format!("records/{}", entry.sha256))
        {
            return Err(AcquireError::Bundle);
        }
        total = total.checked_add(entry.size).ok_or(AcquireError::Bundle)?;
        if total > MAX_TOTAL_BYTES {
            return Err(AcquireError::Bundle);
        }
    }
    if !manifest
        .entries
        .iter()
        .any(|entry| entry.relative_path == VERIFIED_INPUT_NAME)
        || manifest.records.is_empty()
        || manifest.records.iter().any(|record| {
            !safe_role(&record.role)
                || !valid_sha256(&record.sha256)
                || record.relative_path != format!("records/{}", record.sha256)
        })
    {
        return Err(AcquireError::Bundle);
    }
    Ok(())
}

fn open_output_parent(path: &Path) -> Result<(fs::File, CString), AcquireError> {
    let name = path.file_name().ok_or(AcquireError::Bundle)?;
    if !safe_component_bytes(name.as_bytes()) {
        return Err(AcquireError::Bundle);
    }
    let name = CString::new(name.as_bytes()).map_err(|_| AcquireError::Bundle)?;
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_name =
        CString::new(parent_path.as_os_str().as_bytes()).map_err(|_| AcquireError::Bundle)?;
    let parent = openat2_raw(
        libc::AT_FDCWD,
        &parent_name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
        // RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS.
        0x02 | 0x04,
    )
    .map_err(|_| AcquireError::Bundle)?;
    Ok((parent, name))
}

fn open_directory_at(parent: &fs::File, name: &CString) -> std::io::Result<fs::File> {
    openat2_raw(
        parent.as_raw_fd(),
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
        // RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH.
        0x02 | 0x04 | 0x08,
    )
}

fn directory_is_empty(directory: &fs::File) -> Result<bool, AcquireError> {
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    Ok(fs::read_dir(proc_path)
        .map_err(|_| AcquireError::Bundle)?
        .next()
        .is_none())
}

fn split_output_relative(relative: &str) -> Result<(Option<&str>, &str), AcquireError> {
    if !safe_relative(relative) {
        return Err(AcquireError::Bundle);
    }
    match relative.split_once('/') {
        None => Ok((None, relative)),
        Some((directory, name)) if safe_component(directory) && safe_component(name) => {
            Ok((Some(directory), name))
        }
        Some(_) => Err(AcquireError::Bundle),
    }
}

fn safe_component(value: &str) -> bool {
    safe_component_bytes(value.as_bytes())
}

fn safe_component_bytes(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != b"."
        && value != b".."
        && !value.contains(&b'/')
        && !value.contains(&0)
        && !value.iter().any(u8::is_ascii_control)
}

fn open_component(
    parent: &fs::File,
    name: &str,
    flags: i32,
    mode: u32,
) -> std::io::Result<fs::File> {
    if !safe_component(name) {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    let name = CString::new(name).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    openat2_raw(
        parent.as_raw_fd(),
        &name,
        flags,
        mode,
        // RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH.
        0x02 | 0x04 | 0x08,
    )
}

fn open_secure_root(path: &Path) -> Result<fs::File, AcquireError> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).map_err(|_| AcquireError::Bundle)?;
    if !secure_directory(&file.metadata().map_err(|_| AcquireError::Bundle)?) {
        return Err(AcquireError::Bundle);
    }
    Ok(file)
}

fn open_relative(
    root: &fs::File,
    relative: &str,
) -> Result<(fs::File, fs::Metadata), AcquireError> {
    let file = open_beneath(root, relative, libc::O_RDONLY | libc::O_CLOEXEC, 0)?;
    let metadata = file.metadata().map_err(|_| AcquireError::Bundle)?;
    Ok((file, metadata))
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn open_beneath(
    root: &fs::File,
    relative: &str,
    flags: i32,
    mode: u32,
) -> Result<fs::File, AcquireError> {
    if !safe_relative(relative) {
        return Err(AcquireError::Bundle);
    }
    let name = CString::new(relative).map_err(|_| AcquireError::Bundle)?;
    openat2_raw(
        root.as_raw_fd(),
        &name,
        flags,
        mode,
        // RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH.
        0x02 | 0x04 | 0x08,
    )
    .map_err(|_| AcquireError::Bundle)
}

fn openat2_raw(
    directory: i32,
    name: &CString,
    flags: i32,
    mode: u32,
    resolve: u64,
) -> std::io::Result<fs::File> {
    let how = OpenHow {
        flags: flags as u64,
        mode: u64::from(mode),
        resolve,
    };
    // SAFETY: all pointers reference initialized values for the duration of the syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory,
            name.as_ptr(),
            &raw const how,
            std::mem::size_of::<OpenHow>(),
        )
    } as i32;
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful openat2 returns one owned descriptor.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn verify_open_file(
    root: &fs::File,
    relative: &str,
    mut file: fs::File,
    entry: &TransferEntry,
) -> Result<fs::File, AcquireError> {
    let before = file.metadata().map_err(|_| AcquireError::Bundle)?;
    if !secure_file(&before) || before.len() != entry.size {
        return Err(AcquireError::Bundle);
    }
    let actual = hash_file(&mut file, entry.size)?;
    let after = file.metadata().map_err(|_| AcquireError::Bundle)?;
    let (_, named) = open_relative(root, relative)?;
    if actual != entry.sha256
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.dev() != named.dev()
        || before.ino() != named.ino()
        || !secure_file(&after)
    {
        return Err(AcquireError::Bundle);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| AcquireError::Bundle)?;
    Ok(file)
}

fn verify_open_file_from(
    parent: &fs::File,
    name: &str,
    mut file: fs::File,
    entry: &TransferEntry,
) -> Result<fs::File, AcquireError> {
    let before = file.metadata().map_err(|_| AcquireError::Bundle)?;
    if !secure_file(&before) || before.len() != entry.size {
        return Err(AcquireError::Bundle);
    }
    let actual = hash_file(&mut file, entry.size)?;
    let after = file.metadata().map_err(|_| AcquireError::Bundle)?;
    let named = open_component(parent, name, libc::O_RDONLY | libc::O_CLOEXEC, 0)
        .and_then(|file| file.metadata())
        .map_err(|_| AcquireError::Bundle)?;
    if actual != entry.sha256
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.dev() != named.dev()
        || before.ino() != named.ino()
        || !secure_file(&after)
    {
        return Err(AcquireError::Bundle);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| AcquireError::Bundle)?;
    Ok(file)
}

fn verify_object_descriptor(
    file: &mut fs::File,
    size: u64,
    digest: &str,
) -> Result<(), AcquireError> {
    let metadata = file.metadata().map_err(|_| AcquireError::Bundle)?;
    if !secure_file(&metadata) || metadata.len() != size || hash_file(file, size)? != digest {
        return Err(AcquireError::Bundle);
    }
    file.seek(SeekFrom::Start(0))
        .map(|_| ())
        .map_err(|_| AcquireError::Bundle)
}

fn hash_file(file: &mut fs::File, expected: u64) -> Result<String, AcquireError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| AcquireError::Bundle)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(|_| AcquireError::Bundle)?;
        if read == 0 {
            break;
        }
        size = size.checked_add(read as u64).ok_or(AcquireError::Bundle)?;
        if size > expected {
            return Err(AcquireError::Bundle);
        }
        hasher.update(&buffer[..read]);
    }
    if size != expected {
        return Err(AcquireError::Bundle);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_exact_file(
    mut file: fs::File,
    size: u64,
    digest: Option<&str>,
) -> Result<Vec<u8>, AcquireError> {
    if size > MAX_MANIFEST_BYTES || size > usize::MAX as u64 {
        return Err(AcquireError::Bundle);
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| AcquireError::Bundle)?;
    if bytes.len() as u64 != size || digest.is_some_and(|value| sha256(&bytes) != value) {
        return Err(AcquireError::Bundle);
    }
    Ok(bytes)
}

fn enumerate_tree(root: &fs::File) -> Result<BTreeSet<String>, AcquireError> {
    let proc_root = PathBuf::from(format!("/proc/self/fd/{}", root.as_raw_fd()));
    let mut result = BTreeSet::new();
    enumerate_directory(&proc_root, "", &mut result)?;
    Ok(result)
}

fn enumerate_directory(
    path: &Path,
    prefix: &str,
    result: &mut BTreeSet<String>,
) -> Result<(), AcquireError> {
    for item in fs::read_dir(path).map_err(|_| AcquireError::Bundle)? {
        let item = item.map_err(|_| AcquireError::Bundle)?;
        let name = item
            .file_name()
            .into_string()
            .map_err(|_| AcquireError::Bundle)?;
        if name == "." || name == ".." || name.contains('/') {
            return Err(AcquireError::Bundle);
        }
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let metadata = fs::symlink_metadata(item.path()).map_err(|_| AcquireError::Bundle)?;
        if metadata.file_type().is_symlink() {
            return Err(AcquireError::Bundle);
        }
        if metadata.is_dir() {
            if !secure_directory(&metadata) || !matches!(relative.as_str(), "objects" | "records") {
                return Err(AcquireError::Bundle);
            }
            enumerate_directory(&item.path(), &relative, result)?;
        } else if metadata.is_file() {
            if !result.insert(relative) {
                return Err(AcquireError::Bundle);
            }
        } else {
            return Err(AcquireError::Bundle);
        }
    }
    Ok(())
}

fn entry(path: &str, size: u64, digest: &str) -> TransferEntry {
    TransferEntry {
        relative_path: path.to_owned(),
        mode: "0400".to_owned(),
        size,
        sha256: digest.to_owned(),
    }
}

fn secure_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.permissions().mode() & 0o777 == 0o700
}

fn secure_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o777 == 0o400
}

fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn safe_role(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and no side effects.
    unsafe { libc::geteuid() }
}

#[allow(dead_code)]
fn _bind_core_digest(bundle: &VerifiedInputBundleV1) -> Result<[u8; 32], AcquireError> {
    verified_input_bundle_digest(bundle).map_err(|_| AcquireError::Bundle)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::OutputRoot;

    #[test]
    fn cleanup_stays_on_the_retained_root_after_directory_replacement() {
        let parent = TempDirectory::new();
        let output = parent.path.join("bundle");
        let moved = parent.path.join("original");
        let mut root = populated_output(&output);

        fs::rename(&output, &moved).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&output).unwrap();
        fs::write(output.join("sentinel"), b"replacement").unwrap();
        root.write_file("records/late", b"late").unwrap();
        assert!(!output.join("records/late").exists());
        assert!(moved.join("records/late").exists());

        drop(root);

        assert_eq!(fs::read(output.join("sentinel")).unwrap(), b"replacement");
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 0);
    }

    #[test]
    fn cleanup_stays_on_the_retained_root_after_symlink_replacement() {
        let parent = TempDirectory::new();
        let output = parent.path.join("bundle");
        let moved = parent.path.join("original");
        let outside = parent.path.join("outside");
        fs::DirBuilder::new().mode(0o700).create(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"outside").unwrap();
        let root = populated_output(&output);

        fs::rename(&output, &moved).unwrap();
        symlink(&outside, &output).unwrap();
        drop(root);

        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"outside");
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 0);
    }

    #[test]
    fn cleanup_does_not_unlink_a_replacement_file_inside_the_original_root() {
        let parent = TempDirectory::new();
        let output = parent.path.join("bundle");
        let mut root = OutputRoot::create(&output).unwrap();
        root.write_file("record", b"original").unwrap();
        fs::rename(output.join("record"), output.join("moved-record")).unwrap();
        fs::write(output.join("record"), b"replacement").unwrap();
        fs::set_permissions(output.join("record"), fs::Permissions::from_mode(0o400)).unwrap();

        drop(root);

        assert_eq!(fs::read(output.join("record")).unwrap(), b"replacement");
        assert_eq!(fs::read(output.join("moved-record")).unwrap(), b"original");
    }

    #[test]
    fn cleanup_does_not_unlink_a_replacement_directory_inside_the_original_root() {
        let parent = TempDirectory::new();
        let output = parent.path.join("bundle");
        let mut root = OutputRoot::create(&output).unwrap();
        root.create_directory("records").unwrap();
        root.write_file("records/record", b"original").unwrap();
        fs::rename(output.join("records"), output.join("moved-records")).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(output.join("records"))
            .unwrap();
        fs::write(output.join("records/sentinel"), b"replacement").unwrap();

        drop(root);

        assert_eq!(
            fs::read(output.join("records/sentinel")).unwrap(),
            b"replacement"
        );
        assert_eq!(
            fs::read_dir(output.join("moved-records")).unwrap().count(),
            0
        );
    }

    fn populated_output(path: &Path) -> OutputRoot {
        let mut root = OutputRoot::create(path).unwrap();
        root.create_directory("objects").unwrap();
        root.create_directory("records").unwrap();
        root.write_file("top-level", b"top").unwrap();
        root.write_file("objects/object", b"object").unwrap();
        root.write_file("records/record", b"record").unwrap();
        root
    }

    struct TempDirectory {
        path: PathBuf,
    }

    impl TempDirectory {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "catalog-output-root-test-{}-{nanos}",
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
