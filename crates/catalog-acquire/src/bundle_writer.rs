use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
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

struct OutputCleanup {
    path: PathBuf,
    identity: FileIdentity,
    remove_root: bool,
    committed: bool,
}

impl OutputCleanup {
    fn new(path: &Path, root: &fs::File, remove_root: bool) -> Result<Self, AcquireError> {
        Ok(Self {
            path: path.to_owned(),
            identity: FileIdentity::from_metadata(
                &root.metadata().map_err(|_| AcquireError::Bundle)?,
            ),
            remove_root,
            committed: false,
        })
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for OutputCleanup {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let Ok(root) = open_secure_root(&self.path) else {
            return;
        };
        let Ok(metadata) = root.metadata() else {
            return;
        };
        if FileIdentity::from_metadata(&metadata) != self.identity {
            return;
        }
        for file in [VERIFIED_INPUT_NAME, TRANSFER_MANIFEST_NAME] {
            let _ = fs::remove_file(self.path.join(file));
        }
        for directory in ["objects", "records"] {
            let _ = fs::remove_dir_all(self.path.join(directory));
        }
        let _ = root.sync_all();
        drop(root);
        if self.remove_root {
            let _ = fs::remove_dir(&self.path);
        }
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
    let (root, created) = create_fresh_root(output)?;
    let mut cleanup = OutputCleanup::new(output, &root, created)?;
    create_child_directory(&root, "objects")?;
    create_child_directory(&root, "records")?;

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
        write_new_file(&root, &relative, &record.bytes)?;
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
        copy_new_file(
            &root,
            &relative,
            &mut object.file,
            object.size,
            &object.sha256,
        )?;
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
    write_new_file(&root, VERIFIED_INPUT_NAME, &bundle_bytes)?;
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
    write_new_file(&root, TRANSFER_MANIFEST_NAME, &manifest_bytes)?;
    sync_tree(&root)?;
    drop(root);
    let reopened = verify_transferred_bundle(output)?;
    if reopened.verified_input != verified || reopened.root_identity() != cleanup.identity {
        return Err(AcquireError::Bundle);
    }
    if !decide_publication() {
        return Err(AcquireError::Cancelled);
    }
    cleanup.commit();
    Ok(verified)
}

pub fn verify_transferred_bundle(path: &Path) -> Result<VerifiedTransferredBundle, AcquireError> {
    let root = open_secure_root(path)?;
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
    let (output_root, created) = create_fresh_root(output)?;
    let mut cleanup = OutputCleanup::new(output, &output_root, created)?;
    create_child_directory(&output_root, "objects")?;
    create_child_directory(&output_root, "records")?;
    for (entry, file) in &mut verified.files {
        copy_new_file(
            &output_root,
            &entry.relative_path,
            file,
            entry.size,
            &entry.sha256,
        )?;
    }
    write_new_file(
        &output_root,
        TRANSFER_MANIFEST_NAME,
        &verified.manifest_bytes,
    )?;
    sync_tree(&output_root)?;
    drop(output_root);
    let exported = verify_transferred_bundle(output)?;
    if exported.root_identity() != cleanup.identity {
        return Err(AcquireError::Bundle);
    }
    cleanup.commit();
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

fn create_fresh_root(path: &Path) -> Result<(fs::File, bool), AcquireError> {
    let created = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !secure_directory(&metadata)
                || fs::read_dir(path)
                    .map_err(|_| AcquireError::Bundle)?
                    .next()
                    .is_some()
            {
                return Err(AcquireError::Bundle);
            }
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(false)
                .mode(0o700)
                .create(path)
                .map_err(|_| AcquireError::Bundle)?;
            true
        }
        Err(_) => return Err(AcquireError::Bundle),
    };
    open_secure_root(path).map(|root| (root, created))
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

fn create_child_directory(root: &fs::File, name: &str) -> Result<(), AcquireError> {
    let name = CString::new(name).map_err(|_| AcquireError::Bundle)?;
    // SAFETY: root and NUL-terminated name are valid; mode is owner-private.
    let status = unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), 0o700) };
    if status != 0 {
        return Err(AcquireError::Bundle);
    }
    root.sync_all().map_err(|_| AcquireError::Bundle)
}

fn write_new_file(root: &fs::File, relative: &str, bytes: &[u8]) -> Result<(), AcquireError> {
    let mut file = create_relative(root, relative)?;
    file.write_all(bytes).map_err(|_| AcquireError::Bundle)?;
    settle_written(root, relative, file, bytes.len() as u64, &sha256(bytes))
}

fn copy_new_file(
    root: &fs::File,
    relative: &str,
    source: &mut fs::File,
    size: u64,
    digest: &str,
) -> Result<(), AcquireError> {
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| AcquireError::Bundle)?;
    let mut target = create_relative(root, relative)?;
    let copied = std::io::copy(source, &mut target).map_err(|_| AcquireError::Bundle)?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| AcquireError::Bundle)?;
    if copied != size {
        return Err(AcquireError::Bundle);
    }
    settle_written(root, relative, target, size, digest)
}

fn create_relative(root: &fs::File, relative: &str) -> Result<fs::File, AcquireError> {
    open_beneath(
        root,
        relative,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
        0o600,
    )
}

fn settle_written(
    root: &fs::File,
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
    drop(file);
    root.sync_all().map_err(|_| AcquireError::Bundle)?;
    let (file, _metadata) = open_relative(root, relative)?;
    let entry = entry(relative, size, digest);
    let _ = verify_open_file(root, relative, file, &entry)?;
    Ok(())
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
    let how = OpenHow {
        flags: flags as u64,
        mode: u64::from(mode),
        // RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH.
        resolve: 0x02 | 0x04 | 0x08,
    };
    // SAFETY: all pointers reference initialized values for the duration of the syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            name.as_ptr(),
            &raw const how,
            std::mem::size_of::<OpenHow>(),
        )
    } as i32;
    if fd < 0 {
        return Err(AcquireError::Bundle);
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

fn sync_tree(root: &fs::File) -> Result<(), AcquireError> {
    for directory in ["objects", "records"] {
        let (file, metadata) = open_relative(root, directory)?;
        if !secure_directory(&metadata) {
            return Err(AcquireError::Bundle);
        }
        file.sync_all().map_err(|_| AcquireError::Bundle)?;
    }
    root.sync_all().map_err(|_| AcquireError::Bundle)
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
