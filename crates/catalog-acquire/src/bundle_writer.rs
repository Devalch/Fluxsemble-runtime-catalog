use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CStr, CString},
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::Path,
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

struct PreparedBundleRecord {
    relative_path: String,
    bytes: Vec<u8>,
}

struct VerifiedBundlePreflight {
    records: Vec<PreparedBundleRecord>,
    objects: Vec<PublicBundleObject>,
    bundle_bytes: Vec<u8>,
    verified: VerifiedInputBundleV1,
    manifest_bytes: Vec<u8>,
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

struct RetainedTransferDirectory {
    identity: FileIdentity,
    names: BTreeSet<String>,
    file: fs::File,
}

struct EnumeratedTransferTree {
    root_names: BTreeSet<String>,
    entries: BTreeSet<String>,
    directories: BTreeMap<String, RetainedTransferDirectory>,
}

impl EnumeratedTransferTree {
    fn parent_and_name<'a>(
        &'a self,
        root: &'a fs::File,
        relative: &'a str,
    ) -> Result<(&'a fs::File, &'a str), AcquireError> {
        let (directory, name) = split_output_relative(relative)?;
        match directory {
            None => Ok((root, name)),
            Some(directory) => self
                .directories
                .get(directory)
                .map(|retained| (&retained.file, name))
                .ok_or(AcquireError::Bundle),
        }
    }

    fn revalidate(&self, root: &fs::File) -> Result<(), AcquireError> {
        if enumerate_names(root)? != self.root_names {
            return Err(AcquireError::Bundle);
        }
        for (name, retained) in &self.directories {
            let name_c = CString::new(name.as_str()).map_err(|_| AcquireError::Bundle)?;
            verify_named_directory(root, &name_c, &retained.file, retained.identity, 2)?;
            if enumerate_names(&retained.file)? != retained.names {
                return Err(AcquireError::Bundle);
            }
        }
        Ok(())
    }
}

struct TrackedDirectory {
    identity: FileIdentity,
    file: fs::File,
}

struct TrackedOutputFile {
    directory: Option<String>,
    name: String,
    identity: FileIdentity,
    size: u64,
    sha256: String,
    file: fs::File,
}

/// An unpublished payload retained beneath one owner-private staging container.
///
/// Staging is intentionally never deleted. The only output namespace mutation after creation is
/// the one-shot, no-clobber rename of `payload` from the retained container descriptor. Linux
/// cannot rename a directory by retained-fd identity, so principals with this effective UID and
/// access to the exact private parent are trusted producer principals; stronger hostility requires
/// separate UID, mount, or container isolation.
pub(crate) struct OutputRoot {
    parent: fs::File,
    final_name: CString,
    container_name: CString,
    container: fs::File,
    container_identity: FileIdentity,
    payload: fs::File,
    payload_identity: FileIdentity,
    directories: BTreeMap<String, TrackedDirectory>,
    files: BTreeMap<String, TrackedOutputFile>,
    prepared: bool,
    published: bool,
}

impl OutputRoot {
    pub(crate) fn create(path: &Path) -> Result<Self, AcquireError> {
        let (parent, final_name) = open_output_parent(path)?;
        let parent_metadata = parent.metadata().map_err(|_| AcquireError::Bundle)?;
        if !secure_directory(&parent_metadata) || name_exists_at(&parent, &final_name)? {
            return Err(AcquireError::Bundle);
        }

        let (container_name, container) = create_staging_container(&parent)?;
        let container_metadata = container.metadata().map_err(|_| AcquireError::Bundle)?;
        if !secure_directory(&container_metadata) || container_metadata.nlink() != 2 {
            return Err(AcquireError::Bundle);
        }
        let payload_name = CString::new("payload").expect("fixed output payload name");
        // SAFETY: the retained container and fixed NUL-terminated name are valid.
        if unsafe { libc::mkdirat(container.as_raw_fd(), payload_name.as_ptr(), 0o700) } != 0 {
            return Err(AcquireError::Bundle);
        }
        let payload =
            open_directory_at(&container, &payload_name).map_err(|_| AcquireError::Bundle)?;
        let payload_metadata = payload.metadata().map_err(|_| AcquireError::Bundle)?;
        if !secure_directory(&payload_metadata) || payload_metadata.nlink() != 2 {
            return Err(AcquireError::Bundle);
        }
        container.sync_all().map_err(|_| AcquireError::Bundle)?;

        Ok(Self {
            parent,
            final_name,
            container_name,
            container_identity: FileIdentity::from_metadata(&container_metadata),
            container,
            payload_identity: FileIdentity::from_metadata(&payload_metadata),
            payload,
            directories: BTreeMap::new(),
            files: BTreeMap::new(),
            prepared: false,
            published: false,
        })
    }

    pub(crate) fn create_directory(&mut self, name: &str) -> Result<(), AcquireError> {
        if !safe_component(name) || self.directories.contains_key(name) {
            return Err(AcquireError::Bundle);
        }
        let name_c = CString::new(name).map_err(|_| AcquireError::Bundle)?;
        // SAFETY: payload and NUL-terminated name are valid and mode is owner-private.
        if unsafe { libc::mkdirat(self.payload.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
            return Err(AcquireError::Bundle);
        }
        let directory =
            open_directory_at(&self.payload, &name_c).map_err(|_| AcquireError::Bundle)?;
        let metadata = directory.metadata().map_err(|_| AcquireError::Bundle)?;
        if !secure_directory(&metadata) || metadata.nlink() != 2 {
            return Err(AcquireError::Bundle);
        }
        self.payload.sync_all().map_err(|_| AcquireError::Bundle)?;
        self.directories.insert(
            name.to_owned(),
            TrackedDirectory {
                identity: FileIdentity::from_metadata(&metadata),
                file: directory,
            },
        );
        Ok(())
    }

    pub(crate) fn write_file(&mut self, relative: &str, bytes: &[u8]) -> Result<(), AcquireError> {
        let digest = sha256(bytes);
        let (mut file, identity) = self.create_file(relative)?;
        file.write_all(bytes).map_err(|_| AcquireError::Bundle)?;
        self.settle_file(relative, file, identity, bytes.len() as u64, &digest)
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
        let (mut target, identity) = self.create_file(relative)?;
        let copy_result = (|| {
            let copied = {
                let mut bounded = Read::take(&mut *source, size);
                std::io::copy(&mut bounded, &mut target).map_err(|_| AcquireError::Bundle)?
            };
            if copied != size {
                return Err(AcquireError::Bundle);
            }
            let mut probe = [0_u8; 1];
            if source.read(&mut probe).map_err(|_| AcquireError::Bundle)? != 0 {
                return Err(AcquireError::Bundle);
            }
            Ok(())
        })();
        let rewind_result = source
            .seek(SeekFrom::Start(0))
            .map(|_| ())
            .map_err(|_| AcquireError::Bundle);
        rewind_result?;
        copy_result?;
        self.settle_file(relative, target, identity, size, digest)
    }

    fn create_file(&self, relative: &str) -> Result<(fs::File, FileIdentity), AcquireError> {
        if self.files.contains_key(relative) {
            return Err(AcquireError::Bundle);
        }
        let (directory, name) = split_output_relative(relative)?;
        let file = open_component(
            self.directory(directory)?,
            name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o600,
        )
        .map_err(|_| AcquireError::Bundle)?;
        let identity =
            FileIdentity::from_metadata(&file.metadata().map_err(|_| AcquireError::Bundle)?);
        Ok((file, identity))
    }

    fn settle_file(
        &mut self,
        relative: &str,
        mut file: fs::File,
        identity: FileIdentity,
        size: u64,
        digest: &str,
    ) -> Result<(), AcquireError> {
        file.flush().map_err(|_| AcquireError::Bundle)?;
        file.set_permissions(fs::Permissions::from_mode(0o400))
            .map_err(|_| AcquireError::Bundle)?;
        file.sync_all().map_err(|_| AcquireError::Bundle)?;
        let (directory, name) = split_output_relative(relative)?;
        self.directory(directory)?
            .sync_all()
            .map_err(|_| AcquireError::Bundle)?;
        let metadata = file.metadata().map_err(|_| AcquireError::Bundle)?;
        if FileIdentity::from_metadata(&metadata) != identity
            || !secure_file(&metadata)
            || metadata.len() != size
        {
            return Err(AcquireError::Bundle);
        }
        let tracked = TrackedOutputFile {
            directory: directory.map(str::to_owned),
            name: name.to_owned(),
            identity,
            size,
            sha256: digest.to_owned(),
            file,
        };
        verify_tracked_file(self.directory(directory)?, &tracked)?;
        self.files.insert(relative.to_owned(), tracked);
        Ok(())
    }

    pub(crate) fn verify_file_bytes(
        &self,
        relative: &str,
        expected: &[u8],
    ) -> Result<(), AcquireError> {
        let tracked = self.files.get(relative).ok_or(AcquireError::Bundle)?;
        let parent = self.directory(tracked.directory.as_deref())?;
        verify_tracked_file(parent, tracked)?;
        let mut file = tracked.file.try_clone().map_err(|_| AcquireError::Bundle)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| AcquireError::Bundle)?;
        let mut actual = Vec::with_capacity(expected.len());
        file.take(expected.len() as u64 + 1)
            .read_to_end(&mut actual)
            .map_err(|_| AcquireError::Bundle)?;
        if actual != expected {
            return Err(AcquireError::Bundle);
        }
        Ok(())
    }

    fn directory(&self, name: Option<&str>) -> Result<&fs::File, AcquireError> {
        match name {
            None => Ok(&self.payload),
            Some(name) => self
                .directories
                .get(name)
                .map(|directory| &directory.file)
                .ok_or(AcquireError::Bundle),
        }
    }

    pub(crate) fn sync(&self) -> Result<(), AcquireError> {
        for tracked in self.files.values() {
            tracked.file.sync_all().map_err(|_| AcquireError::Bundle)?;
        }
        for directory in self.directories.values() {
            directory
                .file
                .sync_all()
                .map_err(|_| AcquireError::Bundle)?;
        }
        self.payload.sync_all().map_err(|_| AcquireError::Bundle)?;
        self.container
            .sync_all()
            .map_err(|_| AcquireError::Bundle)?;
        self.parent.sync_all().map_err(|_| AcquireError::Bundle)
    }

    fn cloned_root(&self) -> Result<fs::File, AcquireError> {
        self.payload.try_clone().map_err(|_| AcquireError::Bundle)
    }

    fn identity(&self) -> FileIdentity {
        self.payload_identity
    }

    fn verify_tracked_tree(&self) -> Result<(), AcquireError> {
        let parent_metadata = self.parent.metadata().map_err(|_| AcquireError::Bundle)?;
        if !secure_directory(&parent_metadata) {
            return Err(AcquireError::Bundle);
        }
        verify_named_directory(
            &self.parent,
            &self.container_name,
            &self.container,
            self.container_identity,
            3,
        )?;
        if enumerate_names(&self.container)? != BTreeSet::from(["payload".to_owned()]) {
            return Err(AcquireError::Bundle);
        }

        let payload_name = CString::new("payload").expect("fixed output payload name");
        verify_named_directory(
            &self.container,
            &payload_name,
            &self.payload,
            self.payload_identity,
            2 + self.directories.len() as u64,
        )?;
        let expected_payload = self
            .directories
            .keys()
            .cloned()
            .chain(
                self.files
                    .values()
                    .filter(|file| file.directory.is_none())
                    .map(|file| file.name.clone()),
            )
            .collect::<BTreeSet<_>>();
        if enumerate_names(&self.payload)? != expected_payload {
            return Err(AcquireError::Bundle);
        }

        for (name, directory) in &self.directories {
            let name_c = CString::new(name.as_str()).map_err(|_| AcquireError::Bundle)?;
            verify_named_directory(
                &self.payload,
                &name_c,
                &directory.file,
                directory.identity,
                2,
            )?;
            let expected = self
                .files
                .values()
                .filter(|file| file.directory.as_deref() == Some(name.as_str()))
                .map(|file| file.name.clone())
                .collect::<BTreeSet<_>>();
            if enumerate_names(&directory.file)? != expected {
                return Err(AcquireError::Bundle);
            }
        }
        for tracked in self.files.values() {
            verify_tracked_file(self.directory(tracked.directory.as_deref())?, tracked)?;
        }
        Ok(())
    }

    /// Settles and fully verifies the unpublished tree before publication is authorized.
    pub(crate) fn prepare(&mut self) -> Result<(), AcquireError> {
        if self.prepared || self.published {
            return Err(AcquireError::Bundle);
        }
        self.sync()?;
        self.verify_tracked_tree()?;
        self.prepared = true;
        Ok(())
    }

    fn verify_publication_binding(&self) -> Result<(), AcquireError> {
        let parent_metadata = self.parent.metadata().map_err(|_| AcquireError::Bundle)?;
        if !secure_directory(&parent_metadata) {
            return Err(AcquireError::Bundle);
        }
        verify_named_directory(
            &self.parent,
            &self.container_name,
            &self.container,
            self.container_identity,
            3,
        )?;
        if enumerate_names(&self.container)? != BTreeSet::from(["payload".to_owned()]) {
            return Err(AcquireError::Bundle);
        }
        let payload_name = CString::new("payload").expect("fixed output payload name");
        verify_named_directory(
            &self.container,
            &payload_name,
            &self.payload,
            self.payload_identity,
            2 + self.directories.len() as u64,
        )
    }

    /// Attempts the final publication claim and immediately performs the one-shot rename.
    ///
    /// A successful rename is committed even if the following parent fsync fails. That error means
    /// durability is indeterminate; callers must not attempt cleanup or a second publication.
    pub(crate) fn publish(
        &mut self,
        claim_publication: impl FnOnce() -> bool,
    ) -> Result<(), AcquireError> {
        if !self.prepared || self.published {
            return Err(AcquireError::Bundle);
        }
        let payload_name = CString::new("payload").expect("fixed output payload name");
        self.verify_publication_binding()?;
        if !claim_publication() {
            return Err(AcquireError::Cancelled);
        }
        // SAFETY: both retained directory descriptors and NUL-terminated names are valid. The
        // no-replace flag makes this syscall the sole publication linearization point. The
        // authorization claim immediately above is the last operation before this syscall.
        let renamed = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.container.as_raw_fd(),
                payload_name.as_ptr(),
                self.parent.as_raw_fd(),
                self.final_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if renamed != 0 {
            return Err(AcquireError::Bundle);
        }
        self.published = true;
        self.parent.sync_all().map_err(|_| AcquireError::Bundle)
    }
}

pub fn write_verified_bundle(
    request: VerifiedBundleWriteRequest,
    output: &Path,
) -> Result<VerifiedInputBundleV1, AcquireError> {
    write_verified_bundle_with_publication(request, output, || true, || true)
}

pub(crate) fn write_verified_bundle_with_publication(
    request: VerifiedBundleWriteRequest,
    output: &Path,
    authorize_publication: impl FnOnce() -> bool,
    claim_publication: impl FnOnce() -> bool,
) -> Result<VerifiedInputBundleV1, AcquireError> {
    let preflight = preflight_verified_bundle(request)?;
    write_preflight_bundle(preflight, output, authorize_publication, claim_publication)
}

#[cfg(test)]
fn write_verified_bundle_after_preflight_for_test(
    request: VerifiedBundleWriteRequest,
    output: &Path,
    after_preflight: impl FnOnce(),
) -> Result<VerifiedInputBundleV1, AcquireError> {
    let preflight = preflight_verified_bundle(request)?;
    after_preflight();
    write_preflight_bundle(preflight, output, || true, || true)
}

fn write_preflight_bundle(
    preflight: VerifiedBundlePreflight,
    output: &Path,
    authorize_publication: impl FnOnce() -> bool,
    claim_publication: impl FnOnce() -> bool,
) -> Result<VerifiedInputBundleV1, AcquireError> {
    let mut output_root = OutputRoot::create(output)?;
    output_root.create_directory("objects")?;
    output_root.create_directory("records")?;

    for record in preflight.records {
        output_root.write_file(&record.relative_path, &record.bytes)?;
    }
    for mut object in preflight.objects {
        let relative = format!("objects/{}", object.sha256);
        output_root.copy_file(&relative, &mut object.file, object.size, &object.sha256)?;
    }
    output_root.write_file(VERIFIED_INPUT_NAME, &preflight.bundle_bytes)?;
    output_root.write_file(TRANSFER_MANIFEST_NAME, &preflight.manifest_bytes)?;
    output_root.sync()?;
    let reopened = verify_transferred_bundle_root(output_root.cloned_root()?)?;
    if reopened.verified_input != preflight.verified
        || reopened.root_identity() != output_root.identity()
    {
        return Err(AcquireError::Bundle);
    }
    output_root.prepare()?;
    if !authorize_publication() {
        return Err(AcquireError::Cancelled);
    }
    output_root.publish(claim_publication)?;
    Ok(preflight.verified)
}

fn preflight_verified_bundle(
    mut request: VerifiedBundleWriteRequest,
) -> Result<VerifiedBundlePreflight, AcquireError> {
    validate_claims(&request)?;
    let declared_entries = request
        .records
        .len()
        .checked_add(request.objects.len())
        .and_then(|count| count.checked_add(1))
        .ok_or(AcquireError::Bundle)?;
    if request.records.len() > MAX_ENTRIES
        || request.objects.len() > MAX_ENTRIES
        || declared_entries > MAX_ENTRIES
    {
        return Err(AcquireError::Bundle);
    }

    let mut entries = Vec::with_capacity(declared_entries);
    let mut manifest_records = Vec::with_capacity(request.records.len());
    let mut prepared_records = Vec::with_capacity(request.records.len());
    let mut role_names = BTreeSet::new();
    let mut record_paths = BTreeSet::new();
    let mut total = 0_u64;
    for record in request.records {
        let size = record.bytes.len() as u64;
        if !safe_role(&record.role)
            || !role_names.insert(record.role.clone())
            || size == 0
            || size > MAX_MANIFEST_BYTES
            || size > MAX_ENTRY_BYTES
        {
            return Err(AcquireError::Bundle);
        }
        let digest = sha256(&record.bytes);
        let relative_path = format!("records/{digest}");
        if !record_paths.insert(relative_path.clone()) {
            return Err(AcquireError::Bundle);
        }
        total = checked_preflight_total(total, size)?;
        entries.push(entry(&relative_path, size, &digest));
        manifest_records.push(TransferRecordRef {
            role: record.role,
            relative_path: relative_path.clone(),
            sha256: digest,
        });
        prepared_records.push(PreparedBundleRecord {
            relative_path,
            bytes: record.bytes,
        });
    }
    manifest_records.sort_by(|left, right| left.role.cmp(&right.role));

    let mut object_records = BTreeMap::<String, (String, u64)>::new();
    for object in &request.objects {
        if object.size == 0 || object.size > MAX_ENTRY_BYTES || !valid_sha256(&object.sha256) {
            return Err(AcquireError::Bundle);
        }
        match object_records.get(&object.sha256) {
            Some((url, size)) if url == &object.source_url && *size == object.size => {}
            Some(_) => return Err(AcquireError::Bundle),
            None => {
                total = checked_preflight_total(total, object.size)?;
                entries.push(entry(
                    &format!("objects/{}", object.sha256),
                    object.size,
                    &object.sha256,
                ));
                object_records.insert(
                    object.sha256.clone(),
                    (object.source_url.clone(), object.size),
                );
            }
        }
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
    if bundle_bytes.is_empty() || bundle_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(AcquireError::Bundle);
    }
    checked_preflight_total(total, bundle_bytes.len() as u64)?;
    let verified =
        VerifiedInputBundleV1::from_json(&bundle_bytes).map_err(|_| AcquireError::Bundle)?;
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
        records: manifest_records,
        entries,
    };
    validate_manifest(&manifest)?;
    let manifest_bytes = serde_jcs::to_vec(&manifest).map_err(|_| AcquireError::Bundle)?;
    if manifest_bytes.is_empty() || manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(AcquireError::Bundle);
    }

    let mut prepared_objects = Vec::with_capacity(object_records.len());
    let mut seen_objects = BTreeSet::new();
    for mut object in request.objects.drain(..) {
        verify_object_descriptor(&mut object.file, object.size, &object.sha256)?;
        if seen_objects.insert(object.sha256.clone()) {
            prepared_objects.push(object);
        }
    }

    Ok(VerifiedBundlePreflight {
        records: prepared_records,
        objects: prepared_objects,
        bundle_bytes,
        verified,
        manifest_bytes,
    })
}

fn checked_preflight_total(total: u64, size: u64) -> Result<u64, AcquireError> {
    let total = total.checked_add(size).ok_or(AcquireError::Bundle)?;
    if total > MAX_TOTAL_BYTES {
        return Err(AcquireError::Bundle);
    }
    Ok(total)
}

pub fn verify_transferred_bundle(path: &Path) -> Result<VerifiedTransferredBundle, AcquireError> {
    verify_transferred_bundle_root(open_secure_root(path)?)
}

fn verify_transferred_bundle_root(
    root: fs::File,
) -> Result<VerifiedTransferredBundle, AcquireError> {
    let mut manifest_file = open_component(
        &root,
        TRANSFER_MANIFEST_NAME,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    )
    .map_err(|_| AcquireError::Bundle)?;
    let manifest_metadata = manifest_file.metadata().map_err(|_| AcquireError::Bundle)?;
    if !secure_file(&manifest_metadata) || manifest_metadata.len() > MAX_MANIFEST_BYTES {
        return Err(AcquireError::Bundle);
    }
    let manifest_bytes = read_exact_file(
        manifest_file
            .try_clone()
            .map_err(|_| AcquireError::Bundle)?,
        manifest_metadata.len(),
        None,
    )?;
    let manifest: TransferManifestV1 =
        serde_json::from_slice(&manifest_bytes).map_err(|_| AcquireError::Bundle)?;
    if serde_jcs::to_vec(&manifest).map_err(|_| AcquireError::Bundle)? != manifest_bytes {
        return Err(AcquireError::Bundle);
    }
    validate_manifest(&manifest)?;
    let tree = enumerate_tree(&root)?;
    let expected = manifest
        .entries
        .iter()
        .map(|entry| entry.relative_path.clone())
        .chain(std::iter::once(TRANSFER_MANIFEST_NAME.to_owned()))
        .collect::<BTreeSet<_>>();
    if tree.entries != expected {
        return Err(AcquireError::Bundle);
    }

    let mut files = Vec::with_capacity(manifest.entries.len());
    let mut total = 0_u64;
    for entry in &manifest.entries {
        let (parent, name) = tree.parent_and_name(&root, &entry.relative_path)?;
        let file = open_component(parent, name, libc::O_RDONLY | libc::O_CLOEXEC, 0)
            .map_err(|_| AcquireError::Bundle)?;
        let metadata = file.metadata().map_err(|_| AcquireError::Bundle)?;
        if !secure_file(&metadata) || metadata.len() != entry.size {
            return Err(AcquireError::Bundle);
        }
        let file = verify_open_file(parent, name, file, entry)?;
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
    for (entry, file) in &mut files {
        let (parent, name) = tree.parent_and_name(&root, &entry.relative_path)?;
        let retained = file.try_clone().map_err(|_| AcquireError::Bundle)?;
        *file = verify_open_file(parent, name, retained, entry)?;
    }
    let manifest_entry = entry(
        TRANSFER_MANIFEST_NAME,
        manifest_metadata.len(),
        &sha256(&manifest_bytes),
    );
    manifest_file = verify_open_file(
        &root,
        TRANSFER_MANIFEST_NAME,
        manifest_file,
        &manifest_entry,
    )?;
    manifest_file
        .seek(SeekFrom::Start(0))
        .map_err(|_| AcquireError::Bundle)?;
    tree.revalidate(&root)?;

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
    let verified = verify_transferred_bundle(bundle)?;
    export_preflight_bundle(verified, output)
}

#[cfg(test)]
fn export_transfer_bundle_after_preflight_for_test(
    bundle: &Path,
    output: &Path,
    after_preflight: impl FnOnce(),
) -> Result<VerifiedTransferredBundle, AcquireError> {
    let verified = verify_transferred_bundle(bundle)?;
    after_preflight();
    export_preflight_bundle(verified, output)
}

fn export_preflight_bundle(
    mut verified: VerifiedTransferredBundle,
    output: &Path,
) -> Result<VerifiedTransferredBundle, AcquireError> {
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
    output_root.prepare()?;
    output_root.publish(|| true)?;
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

fn name_exists_at(parent: &fs::File, name: &CString) -> Result<bool, AcquireError> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the retained descriptor, NUL-terminated name, and output pointer are valid.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOENT) => Ok(false),
        _ => Err(AcquireError::Bundle),
    }
}

fn create_staging_container(parent: &fs::File) -> Result<(CString, fs::File), AcquireError> {
    for _ in 0..128 {
        let mut random = [0_u8; 16];
        fill_random(&mut random)?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let name = CString::new(format!(".catalog-acquire-stage-{suffix}"))
            .map_err(|_| AcquireError::Bundle)?;
        // SAFETY: the retained parent and NUL-terminated bounded name are valid.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
            parent.sync_all().map_err(|_| AcquireError::Bundle)?;
            let directory = open_directory_at(parent, &name).map_err(|_| AcquireError::Bundle)?;
            return Ok((name, directory));
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(AcquireError::Bundle);
        }
    }
    Err(AcquireError::Bundle)
}

fn fill_random(output: &mut [u8]) -> Result<(), AcquireError> {
    let mut filled = 0;
    while filled < output.len() {
        // SAFETY: the remaining output slice is writable for the supplied length. A zero flag uses
        // the kernel CSPRNG and does not permit a weaker fallback.
        let read = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                output[filled..].as_mut_ptr(),
                output.len() - filled,
                0,
            )
        };
        if read > 0 {
            filled = filled
                .checked_add(read as usize)
                .ok_or(AcquireError::Bundle)?;
            continue;
        }
        if read < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(AcquireError::Bundle);
    }
    Ok(())
}

fn verify_named_directory(
    parent: &fs::File,
    name: &CString,
    retained: &fs::File,
    identity: FileIdentity,
    expected_nlink: u64,
) -> Result<(), AcquireError> {
    let before = retained.metadata().map_err(|_| AcquireError::Bundle)?;
    let named = open_directory_at(parent, name).map_err(|_| AcquireError::Bundle)?;
    let named_metadata = named.metadata().map_err(|_| AcquireError::Bundle)?;
    let after = retained.metadata().map_err(|_| AcquireError::Bundle)?;
    if FileIdentity::from_metadata(&before) != identity
        || FileIdentity::from_metadata(&named_metadata) != identity
        || FileIdentity::from_metadata(&after) != identity
        || !secure_directory(&before)
        || !secure_directory(&named_metadata)
        || !secure_directory(&after)
        || before.nlink() != expected_nlink
        || named_metadata.nlink() != expected_nlink
        || after.nlink() != expected_nlink
        || before.len() != named_metadata.len()
        || before.len() != after.len()
    {
        return Err(AcquireError::Bundle);
    }
    Ok(())
}

fn verify_tracked_file(parent: &fs::File, tracked: &TrackedOutputFile) -> Result<(), AcquireError> {
    let mut retained = tracked.file.try_clone().map_err(|_| AcquireError::Bundle)?;
    let before = retained.metadata().map_err(|_| AcquireError::Bundle)?;
    if FileIdentity::from_metadata(&before) != tracked.identity
        || !secure_file(&before)
        || before.len() != tracked.size
    {
        return Err(AcquireError::Bundle);
    }
    let digest = hash_file(&mut retained, tracked.size)?;
    let after = retained.metadata().map_err(|_| AcquireError::Bundle)?;
    let named = open_component(parent, &tracked.name, libc::O_RDONLY | libc::O_CLOEXEC, 0)
        .map_err(|_| AcquireError::Bundle)?;
    let named_metadata = named.metadata().map_err(|_| AcquireError::Bundle)?;
    if digest != tracked.sha256
        || FileIdentity::from_metadata(&after) != tracked.identity
        || FileIdentity::from_metadata(&named_metadata) != tracked.identity
        || !secure_file(&after)
        || !secure_file(&named_metadata)
        || after.len() != tracked.size
        || named_metadata.len() != tracked.size
    {
        return Err(AcquireError::Bundle);
    }
    Ok(())
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

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
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
        .map_err(|_| AcquireError::Bundle)?
        .metadata()
        .map_err(|_| AcquireError::Bundle)?;
    if actual != entry.sha256
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.dev() != named.dev()
        || before.ino() != named.ino()
        || before.len() != after.len()
        || before.len() != named.len()
        || !secure_file(&after)
        || !secure_file(&named)
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

fn enumerate_tree(root: &fs::File) -> Result<EnumeratedTransferTree, AcquireError> {
    let root_names = enumerate_names(root)?;
    let mut entries = BTreeSet::new();
    let mut directories = BTreeMap::new();
    for name in &root_names {
        if matches!(name.as_str(), "objects" | "records") {
            let name_c = CString::new(name.as_str()).map_err(|_| AcquireError::Bundle)?;
            let directory = open_directory_at(root, &name_c).map_err(|_| AcquireError::Bundle)?;
            let metadata = directory.metadata().map_err(|_| AcquireError::Bundle)?;
            if !secure_directory(&metadata) || metadata.nlink() != 2 {
                return Err(AcquireError::Bundle);
            }
            let names = enumerate_names(&directory)?;
            for child in &names {
                let file = open_component(&directory, child, libc::O_RDONLY | libc::O_CLOEXEC, 0)
                    .map_err(|_| AcquireError::Bundle)?;
                if !file.metadata().map_err(|_| AcquireError::Bundle)?.is_file()
                    || !entries.insert(format!("{name}/{child}"))
                {
                    return Err(AcquireError::Bundle);
                }
            }
            directories.insert(
                name.clone(),
                RetainedTransferDirectory {
                    identity: FileIdentity::from_metadata(&metadata),
                    names,
                    file: directory,
                },
            );
        } else {
            let file = open_component(root, name, libc::O_RDONLY | libc::O_CLOEXEC, 0)
                .map_err(|_| AcquireError::Bundle)?;
            if !file.metadata().map_err(|_| AcquireError::Bundle)?.is_file()
                || !entries.insert(name.clone())
            {
                return Err(AcquireError::Bundle);
            }
        }
    }
    Ok(EnumeratedTransferTree {
        root_names,
        entries,
        directories,
    })
}

fn enumerate_names(directory: &fs::File) -> Result<BTreeSet<String>, AcquireError> {
    // SAFETY: fcntl duplicates one valid retained descriptor with close-on-exec.
    let descriptor = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(AcquireError::Bundle);
    }
    // SAFETY: fdopendir takes ownership of the duplicated descriptor on success.
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        // SAFETY: fdopendir did not take ownership on failure.
        let _ = unsafe { libc::close(descriptor) };
        return Err(AcquireError::Bundle);
    }

    // SAFETY: stream is valid; reset the shared duplicated directory offset before enumeration.
    unsafe { libc::rewinddir(stream) };
    let result = (|| {
        let mut names = BTreeSet::new();
        loop {
            // SAFETY: this process targets Linux, where __errno_location returns thread-local errno.
            unsafe { *libc::__errno_location() = 0 };
            // SAFETY: stream remains valid and is only used on this thread.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                // SAFETY: errno is read immediately after readdir returned null.
                if unsafe { *libc::__errno_location() } != 0 {
                    return Err(AcquireError::Bundle);
                }
                break;
            }
            // SAFETY: readdir returns a dirent with a NUL-terminated d_name field.
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            let name = std::str::from_utf8(bytes).map_err(|_| AcquireError::Bundle)?;
            if !safe_component(name) || !names.insert(name.to_owned()) {
                return Err(AcquireError::Bundle);
            }
        }
        Ok(names)
    })();
    // SAFETY: restore the retained directory's shared offset before closing the duplicate.
    unsafe { libc::rewinddir(stream) };
    // SAFETY: closedir consumes the stream and closes the duplicated descriptor.
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(AcquireError::Bundle);
    }
    result
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
        && metadata.permissions().mode() & 0o7777 == 0o700
}

fn secure_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == 0o400
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
        ffi::OsStr,
        fs,
        io::{Seek, SeekFrom, Write},
        os::unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, PermissionsExt, symlink},
        },
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use catalog_core::InputSourceKind;

    use super::{
        AcquireError, BundleRecord, MAX_ENTRIES, MAX_ENTRY_BYTES, OutputRoot, PublicBundleObject,
        VerifiedBundleWriteRequest, export_transfer_bundle_after_preflight_for_test,
        write_verified_bundle, write_verified_bundle_after_preflight_for_test,
    };

    #[test]
    fn output_parent_must_be_exact_owner_private_and_symlink_free() {
        let parent = TempDirectory::new();
        for mode in [0o755, 0o1700, 0o2700, 0o4700] {
            fs::set_permissions(&parent.path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                OutputRoot::create(&parent.path.join(format!("bundle-{mode:o}"))).is_err(),
                "parent mode {mode:o} was accepted"
            );
        }
        fs::set_permissions(&parent.path, fs::Permissions::from_mode(0o700)).unwrap();

        let real = parent.path.join("real");
        fs::DirBuilder::new().mode(0o700).create(&real).unwrap();
        let linked = parent.path.join("linked");
        symlink(&real, &linked).unwrap();
        assert!(OutputRoot::create(&linked.join("bundle")).is_err());
    }

    #[test]
    fn writer_bounds_are_rejected_before_any_staging_container_is_created() {
        let oversized_parent = TempDirectory::new();
        let oversized_output = oversized_parent.path.join("oversized");
        let source = source_file(&oversized_parent.path);
        let oversized = VerifiedBundleWriteRequest {
            source_kind: InputSourceKind::ReleaseIntent,
            source_sha256: "11".repeat(32),
            compatibility_input_sha256: "22".repeat(32),
            source_commit: None,
            source_tree_sha256: None,
            records: vec![BundleRecord {
                role: "record".to_owned(),
                bytes: b"record".to_vec(),
            }],
            objects: vec![PublicBundleObject {
                file: source,
                source_url: "https://registry.npmjs.org/object/-/object-1.0.0.tgz".to_owned(),
                size: MAX_ENTRY_BYTES + 1,
                sha256: "aa".repeat(32),
            }],
        };
        assert!(write_verified_bundle(oversized, &oversized_output).is_err());
        assert_no_output_or_stage(&oversized_parent.path, &oversized_output);

        let overcount_parent = TempDirectory::new();
        let overcount_output = overcount_parent.path.join("overcount");
        let overcount = VerifiedBundleWriteRequest {
            source_kind: InputSourceKind::ReleaseIntent,
            source_sha256: "11".repeat(32),
            compatibility_input_sha256: "22".repeat(32),
            source_commit: None,
            source_tree_sha256: None,
            records: (0..MAX_ENTRIES)
                .map(|index| BundleRecord {
                    role: format!("record_{index}"),
                    bytes: b"record".to_vec(),
                })
                .collect(),
            objects: vec![PublicBundleObject {
                file: source_file(&overcount_parent.path),
                source_url: "https://registry.npmjs.org/object/-/object-1.0.0.tgz".to_owned(),
                size: 6,
                sha256: super::sha256(b"object"),
            }],
        };
        assert!(write_verified_bundle(overcount, &overcount_output).is_err());
        assert_no_output_or_stage(&overcount_parent.path, &overcount_output);
    }

    #[test]
    fn checked_total_is_rejected_before_object_reads_or_stage_creation() {
        let parent = TempDirectory::new();
        let output = parent.path.join("over-total");
        let objects = (1_u8..=9)
            .map(|index| PublicBundleObject {
                file: source_file(&parent.path),
                source_url: format!(
                    "https://registry.npmjs.org/object-{index}/-/object-{index}-1.0.0.tgz"
                ),
                size: MAX_ENTRY_BYTES,
                sha256: format!("{index:064x}"),
            })
            .collect();
        let request = VerifiedBundleWriteRequest {
            source_kind: InputSourceKind::ReleaseIntent,
            source_sha256: "11".repeat(32),
            compatibility_input_sha256: "22".repeat(32),
            source_commit: None,
            source_tree_sha256: None,
            records: vec![BundleRecord {
                role: "record".to_owned(),
                bytes: b"record".to_vec(),
            }],
            objects,
        };

        assert!(write_verified_bundle(request, &output).is_err());
        assert_no_output_or_stage(&parent.path, &output);
    }

    #[test]
    fn bundle_source_growth_after_preflight_never_exceeds_the_declared_stage_bound() {
        let parent = TempDirectory::new();
        let output = parent.path.join("bundle");
        let (source, mut retained_writer) = retained_writable_source(&parent.path);
        let request = fixture_request(source);

        let result = write_verified_bundle_after_preflight_for_test(request, &output, move || {
            append_arbitrary_growth(&mut retained_writer);
        });

        assert_eq!(result, Err(AcquireError::Bundle));
        assert!(!output.exists());
        assert_staged_objects_are_bounded(&parent.path, 6);
    }

    #[test]
    fn export_source_growth_after_preflight_never_exceeds_the_declared_stage_bound() {
        let parent = TempDirectory::new();
        let bundle = parent.path.join("bundle");
        write_verified_bundle(fixture_request(source_file(&parent.path)), &bundle).unwrap();
        let object = fs::read_dir(bundle.join("objects"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap();
        let mut retained_writer = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&object)
            .unwrap();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o400)).unwrap();
        let output = parent.path.join("exported");

        let result = export_transfer_bundle_after_preflight_for_test(&bundle, &output, move || {
            append_arbitrary_growth(&mut retained_writer)
        });

        assert!(result.is_err());
        assert!(!output.exists());
        assert_staged_objects_are_bounded(&parent.path, 6);
    }

    #[test]
    fn staging_names_are_csprng_derived_not_pid_or_sequence_derived() {
        let source = include_str!("bundle_writer.rs");
        let start = source.find("fn create_staging_container").unwrap();
        let end = source[start..].find("fn verify_named_directory").unwrap() + start;
        let implementation = &source[start..end];
        assert!(implementation.contains("SYS_getrandom"));
        assert!(!implementation.contains(concat!("Atomic", "U64")));
        assert!(!implementation.contains(concat!("process", "::id")));

        let parent = TempDirectory::new();
        let first = OutputRoot::create(&parent.path.join("first")).unwrap();
        let second = OutputRoot::create(&parent.path.join("second")).unwrap();
        let first_name = first.container_name.to_str().unwrap();
        let second_name = second.container_name.to_str().unwrap();
        for name in [first_name, second_name] {
            let suffix = name.strip_prefix(".catalog-acquire-stage-").unwrap();
            assert_eq!(suffix.len(), 32);
            assert!(suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
        assert_ne!(first_name, second_name);
    }

    #[test]
    fn final_name_is_absent_until_atomic_no_clobber_publication() {
        let parent = TempDirectory::new();
        let output = parent.path.join("bundle");
        let mut root = populated_output(&output);
        root.prepare().unwrap();
        assert!(!output.exists());

        fs::DirBuilder::new().mode(0o700).create(&output).unwrap();
        fs::write(output.join("sentinel"), b"replacement").unwrap();
        assert!(root.publish(|| true).is_err());
        drop(root);

        assert_eq!(fs::read(output.join("sentinel")).unwrap(), b"replacement");
    }

    #[test]
    fn staging_container_name_replacement_fails_closed_without_redirection() {
        let parent = TempDirectory::new();
        let output = parent.path.join("bundle");
        let mut root = populated_output(&output);
        let stage = stage_path(&parent.path, &root);
        let moved = parent.path.join("moved-stage");
        fs::rename(&stage, &moved).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&stage).unwrap();
        fs::write(stage.join("sentinel"), b"replacement").unwrap();

        assert!(root.prepare().is_err());
        drop(root);

        assert!(!output.exists());
        assert_eq!(fs::read(stage.join("sentinel")).unwrap(), b"replacement");
        assert!(moved.join("payload/objects/object").exists());
    }

    #[test]
    fn drop_never_deletes_replacement_file_or_directory_names() {
        let parent = TempDirectory::new();
        let output = parent.path.join("bundle");
        let root = populated_output(&output);
        let payload = stage_path(&parent.path, &root).join("payload");

        fs::rename(
            payload.join("records/record"),
            payload.join("records/moved-record"),
        )
        .unwrap();
        fs::write(payload.join("records/record"), b"replacement").unwrap();
        fs::set_permissions(
            payload.join("records/record"),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        fs::rename(payload.join("objects"), payload.join("moved-objects")).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(payload.join("objects"))
            .unwrap();
        fs::write(payload.join("objects/sentinel"), b"replacement").unwrap();

        drop(root);

        assert!(!output.exists());
        assert_eq!(
            fs::read(payload.join("records/record")).unwrap(),
            b"replacement"
        );
        assert_eq!(
            fs::read(payload.join("objects/sentinel")).unwrap(),
            b"replacement"
        );
        assert_eq!(
            fs::read(payload.join("records/moved-record")).unwrap(),
            b"record"
        );
        assert_eq!(
            fs::read(payload.join("moved-objects/object")).unwrap(),
            b"object"
        );
    }

    #[test]
    fn prepare_rejects_child_file_mode_inventory_and_symlink_mutations() {
        for mutation in [
            Mutation::ChildReplacement,
            Mutation::FileReplacement,
            Mutation::IdenticalBytesWrongMode,
            Mutation::DifferentBytes,
            Mutation::Hardlink,
            Mutation::ExtraEntry,
            Mutation::Symlink,
        ] {
            let parent = TempDirectory::new();
            let output = parent.path.join("bundle");
            let mut root = populated_output(&output);
            let payload = stage_path(&parent.path, &root).join("payload");
            mutate(&payload, mutation);

            assert!(root.prepare().is_err(), "mutation {mutation:?}");
            assert!(!output.exists(), "mutation {mutation:?} was published");
        }
    }

    #[test]
    fn exact_special_modes_are_rejected_before_publication() {
        for special_bit in [0o1000, 0o2000, 0o4000] {
            for target in [
                SpecialModeTarget::Container,
                SpecialModeTarget::Payload,
                SpecialModeTarget::ChildDirectory,
                SpecialModeTarget::File,
            ] {
                let parent = TempDirectory::new();
                let output = parent.path.join("bundle");
                let mut root = populated_output(&output);
                let stage = stage_path(&parent.path, &root);
                let (path, ordinary_mode) = match target {
                    SpecialModeTarget::Container => (stage, 0o700),
                    SpecialModeTarget::Payload => (stage.join("payload"), 0o700),
                    SpecialModeTarget::ChildDirectory => (stage.join("payload/objects"), 0o700),
                    SpecialModeTarget::File => (stage.join("payload/objects/object"), 0o400),
                };
                fs::set_permissions(
                    path,
                    fs::Permissions::from_mode(ordinary_mode | special_bit),
                )
                .unwrap();

                assert!(
                    root.prepare().is_err(),
                    "special mode bit {special_bit:o} on {target:?} was accepted"
                );
                assert!(!output.exists());
            }
        }
    }

    #[test]
    fn successful_prepare_and_publish_exposes_exact_payload_once() {
        let parent = TempDirectory::new();
        let output = parent.path.join("bundle");
        let mut root = populated_output(&output);
        root.prepare().unwrap();
        root.publish(|| true).unwrap();

        assert_eq!(fs::read(output.join("objects/object")).unwrap(), b"object");
        assert_eq!(fs::read(output.join("records/record")).unwrap(), b"record");
        assert!(root.publish(|| true).is_err());
    }

    #[derive(Debug, Clone, Copy)]
    enum SpecialModeTarget {
        Container,
        Payload,
        ChildDirectory,
        File,
    }

    #[derive(Debug, Clone, Copy)]
    enum Mutation {
        ChildReplacement,
        FileReplacement,
        IdenticalBytesWrongMode,
        DifferentBytes,
        Hardlink,
        ExtraEntry,
        Symlink,
    }

    fn mutate(payload: &Path, mutation: Mutation) {
        let object = payload.join("objects/object");
        match mutation {
            Mutation::ChildReplacement => {
                fs::rename(payload.join("objects"), payload.join("original-objects")).unwrap();
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(payload.join("objects"))
                    .unwrap();
                fs::write(&object, b"object").unwrap();
                fs::set_permissions(&object, fs::Permissions::from_mode(0o400)).unwrap();
            }
            Mutation::FileReplacement => {
                fs::rename(&object, payload.join("objects/original-object")).unwrap();
                fs::write(&object, b"object").unwrap();
                fs::set_permissions(&object, fs::Permissions::from_mode(0o400)).unwrap();
            }
            Mutation::IdenticalBytesWrongMode => {
                fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap();
            }
            Mutation::DifferentBytes => {
                fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap();
                fs::write(&object, b"tamper").unwrap();
                fs::set_permissions(&object, fs::Permissions::from_mode(0o400)).unwrap();
            }
            Mutation::Hardlink => {
                let outside = payload
                    .parent()
                    .and_then(Path::parent)
                    .unwrap()
                    .join("outside-hardlink");
                fs::hard_link(&object, outside).unwrap();
            }
            Mutation::ExtraEntry => {
                fs::write(payload.join("extra"), b"extra").unwrap();
                fs::set_permissions(payload.join("extra"), fs::Permissions::from_mode(0o400))
                    .unwrap();
            }
            Mutation::Symlink => {
                fs::remove_file(&object).unwrap();
                symlink("../top-level", object).unwrap();
            }
        }
    }

    fn source_file(parent: &Path) -> fs::File {
        let path = parent.join(format!(
            "source-object-{}",
            fs::read_dir(parent).unwrap().count()
        ));
        fs::write(&path, b"object").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        fs::File::open(path).unwrap()
    }

    fn retained_writable_source(parent: &Path) -> (fs::File, fs::File) {
        let path = parent.join("retained-writable-source");
        let mut writer = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        writer.write_all(b"object").unwrap();
        writer.seek(SeekFrom::Start(0)).unwrap();
        let source = writer.try_clone().unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
        (source, writer)
    }

    fn fixture_request(source: fs::File) -> VerifiedBundleWriteRequest {
        VerifiedBundleWriteRequest {
            source_kind: InputSourceKind::ReleaseIntent,
            source_sha256: "11".repeat(32),
            compatibility_input_sha256: "22".repeat(32),
            source_commit: None,
            source_tree_sha256: None,
            records: vec![BundleRecord {
                role: "record".to_owned(),
                bytes: b"record".to_vec(),
            }],
            objects: vec![PublicBundleObject {
                file: source,
                source_url: "https://registry.npmjs.org/object/-/object-1.0.0.tgz".to_owned(),
                size: 6,
                sha256: super::sha256(b"object"),
            }],
        }
    }

    fn append_arbitrary_growth(writer: &mut fs::File) {
        writer.seek(SeekFrom::End(0)).unwrap();
        writer.write_all(&vec![b'x'; 2 * 1024 * 1024]).unwrap();
        writer.flush().unwrap();
    }

    fn assert_staged_objects_are_bounded(parent: &Path, declared_size: u64) {
        let mut staged_objects = 0;
        for stage in fs::read_dir(parent).unwrap().filter_map(Result::ok) {
            if !stage
                .file_name()
                .to_string_lossy()
                .starts_with(".catalog-acquire-stage-")
            {
                continue;
            }
            let objects = stage.path().join("payload/objects");
            let Ok(entries) = fs::read_dir(objects) else {
                continue;
            };
            for object in entries.filter_map(Result::ok) {
                staged_objects += 1;
                assert!(
                    object.metadata().unwrap().len() <= declared_size,
                    "staged object exceeded its declared size"
                );
            }
        }
        assert!(staged_objects > 0, "growth test did not reach stage copy");
    }

    fn assert_no_output_or_stage(parent: &Path, output: &Path) {
        assert!(!output.exists());
        assert!(
            fs::read_dir(parent)
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".catalog-acquire-stage-"))
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

    fn stage_path(parent: &Path, root: &OutputRoot) -> PathBuf {
        parent.join(OsStr::from_bytes(root.container_name.to_bytes()))
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
