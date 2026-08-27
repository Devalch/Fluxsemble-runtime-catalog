use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::{CStr, CString},
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        },
    },
    path::{Component, Path},
};

use catalog_core::{
    BundleInventoryV1, CatalogPayloadV1, SignedReleaseBundleManifestV1, VerifiedCatalogV1,
    VerifiedReleaseBundleManifestV1, verify_signed_catalog, verify_signed_release_bundle_manifest,
    verify_signed_release_inventory,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const TRANSFER_MANIFEST: &str = "transfer-manifest-v1.json";
const SIGNED_BUNDLE: &str = "signed-release-bundle";
const CATALOG: &str = "catalog-v1.json";
const RELEASE_MANIFEST: &str = "signed-release-bundle-manifest-v1.json";
const CHECKSUMS: &str = "checksums-sha256.txt";
const RECOVERY_RECORD: &str = "recovery-v1.json";
const RECOVERY_TEMP: &str = ".recovery-v1.tmp";
const LATEST_REFERENCE: &str = "catalog-v1.ref";
const LATEST_TEMP: &str = ".catalog-v1.ref.tmp";
const REMOTE_OPERATION: &str = "remote-operation-v1.json";
const REMOTE_OPERATION_TEMP: &str = ".remote-operation-v1.tmp";
const DRAFT_RECEIPT: &str = "draft-receipt-v1.json";
const RELEASE_APPROVAL: &str = "release-approval-v1.json";
const PUBLICATION_RECEIPT: &str = "publication-receipt-v1.json";
const LATEST_RECEIPT: &str = "latest-receipt-v1.json";
const MAX_PATH_BYTES: usize = 4_096;
const MAX_TRANSFER_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TRANSFER_ENTRIES: usize = 64;
const MAX_STATE_RECORD_BYTES: u64 = 256 * 1024;
const MAX_REFERENCE_BYTES: u64 = 128 * 1024;
const MAX_PERSISTENT_OBJECTS: u64 = 4_096;
const MAX_PERSISTENT_OBJECT_BYTES: u64 = MAX_TRANSFER_BYTES;
const MAX_PERSISTENT_CUMULATIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_PERSISTENT_OBJECT_NAME_BYTES: u64 = 64;
const MAX_PERSISTENT_NAME_BYTES: u64 = MAX_PERSISTENT_OBJECTS * MAX_PERSISTENT_OBJECT_NAME_BYTES;
const MAX_PERSISTENT_ENUMERATION_WORK: u64 = MAX_PERSISTENT_OBJECTS + 2;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const OPERATION_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-local-operation:v1\0";

/// Stable local-publication outcomes. No variant contains a host path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    Staged,
    RecoveryCommitted,
    RecoveryAborted,
}

/// Stable failure classes used by the CLI exit contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureOutcome {
    Normal,
    FailedPriorPreserved,
    OutcomeUncertain,
    RecoveryRequired,
}

/// Closed, non-echoing publisher error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishError {
    outcome: FailureOutcome,
}

impl PublishError {
    #[must_use]
    pub const fn outcome(&self) -> FailureOutcome {
        self.outcome
    }
}

impl fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("catalog publication failed")
    }
}

impl Error for PublishError {}

const fn failed(outcome: FailureOutcome) -> PublishError {
    PublishError { outcome }
}

const fn rejected() -> PublishError {
    failed(FailureOutcome::Normal)
}

const fn prior_preserved() -> PublishError {
    failed(FailureOutcome::FailedPriorPreserved)
}

const fn uncertain() -> PublishError {
    failed(FailureOutcome::OutcomeUncertain)
}

const fn recovery_required() -> PublishError {
    failed(FailureOutcome::RecoveryRequired)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum IsolationMode {
    Sign,
    RecoverSign,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IsolationAttestationV1 {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReverseTransferManifestV1 {
    schema_version: u16,
    kind: String,
    input_transfer_sha256: String,
    isolation_attestation: IsolationAttestationV1,
    entries: Vec<ReverseTransferEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReverseTransferEntryV1 {
    relative_path: String,
    mode: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

struct RetainedFile {
    name: String,
    file: fs::File,
    identity: FileIdentity,
    size: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalObjectV1 {
    name: String,
    object: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogReleaseBindingV1 {
    provider: String,
    target: String,
    version: String,
}

/// Canonical authority body hashed for `operation_id`. The prior reference is represented by the
/// SHA-256 of its exact canonical bytes to avoid recursively embedding the full publication chain.
/// Only the redundant operation ID and the recovery record's mutable phase live outside this body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationBodyV1 {
    schema_version: u16,
    reverse_transfer_manifest: LocalObjectV1,
    input_transfer_sha256: String,
    isolation_original_mode: IsolationMode,
    isolation_completion_mode: IsolationMode,
    catalog_envelope: LocalObjectV1,
    catalog_payload_sha256: String,
    catalog_sequence: u64,
    catalog_releases: Vec<CatalogReleaseBindingV1>,
    release_manifest: LocalObjectV1,
    release_tag: String,
    source_commit: String,
    source_tree_sha256: String,
    qualification_sha256: String,
    qualification_reference: String,
    checksums: LocalObjectV1,
    support_assets: Vec<LocalObjectV1>,
    objects: Vec<LocalObjectV1>,
    prior_reference_sha256: Option<String>,
    latest_temporary_identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalCatalogReferenceV1 {
    schema_version: u16,
    operation_id: String,
    operation: OperationBodyV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryRecordV1 {
    schema_version: u16,
    operation_id: String,
    operation: OperationBodyV1,
    intended_reference: LocalCatalogReferenceV1,
    prior_state: String,
    prior_reference: Option<LocalCatalogReferenceV1>,
    phase: String,
}

/// A complete reverse transfer held by descriptor capability after both public signatures,
/// inventory, checksums, release bindings, modes, hashes, and names were independently verified.
pub struct VerifiedTransferredSignedBundle {
    root: fs::File,
    root_identity: FileIdentity,
    root_names: BTreeSet<String>,
    bundle: fs::File,
    bundle_identity: FileIdentity,
    bundle_names: BTreeSet<String>,
    transfer_manifest: RetainedFile,
    files: BTreeMap<String, RetainedFile>,
    manifest: ReverseTransferManifestV1,
    release_manifest: SignedReleaseBundleManifestV1,
    signed_transfer_sha256: String,
    catalog_payload_sha256: String,
    catalog_releases: Vec<CatalogReleaseBindingV1>,
    sequence: u64,
    policy: VerificationPolicy,
}

impl fmt::Debug for VerifiedTransferredSignedBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTransferredSignedBundle")
            .field("sequence", &self.sequence)
            .field("tag", &self.tag())
            .field("objects", &self.files.len())
            .finish_non_exhaustive()
    }
}

impl VerifiedTransferredSignedBundle {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub fn tag(&self) -> &str {
        self.release_manifest.tag().as_str()
    }

    #[must_use]
    pub fn signed_transfer_sha256(&self) -> &str {
        &self.signed_transfer_sha256
    }

    #[must_use]
    pub fn input_transfer_sha256(&self) -> &str {
        &self.manifest.input_transfer_sha256
    }

    #[must_use]
    pub fn object_count(&self) -> usize {
        self.files.len() + 1
    }

    fn object_from_retained(file: &RetainedFile) -> LocalObjectV1 {
        LocalObjectV1 {
            name: file.name.clone(),
            object: format!("objects/{}", file.sha256),
            size: file.size,
            sha256: file.sha256.clone(),
        }
    }

    fn objects(&self) -> Vec<LocalObjectV1> {
        let mut objects = std::iter::once(Self::object_from_retained(&self.transfer_manifest))
            .chain(self.files.values().map(Self::object_from_retained))
            .collect::<Vec<_>>();
        objects.sort_by(|left, right| left.name.cmp(&right.name));
        objects
    }

    fn operation_body(
        &self,
        prior_reference_sha256: Option<String>,
        latest_temporary_identity: FileIdentity,
    ) -> Result<OperationBodyV1, PublishError> {
        let object = |name: &str| {
            self.files
                .get(name)
                .map(Self::object_from_retained)
                .ok_or_else(rejected)
        };
        let qualification_sha256 = self.release_manifest.qualification_sha256().as_str();
        let qualification_reference = format!("qualification-{qualification_sha256}.json");
        let support_assets = self
            .release_manifest
            .assets()
            .iter()
            .map(|asset| object(asset.name().as_str()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(OperationBodyV1 {
            schema_version: 1,
            reverse_transfer_manifest: Self::object_from_retained(&self.transfer_manifest),
            input_transfer_sha256: self.manifest.input_transfer_sha256.clone(),
            isolation_original_mode: self
                .manifest
                .isolation_attestation
                .original_operation_mode
                .clone(),
            isolation_completion_mode: self.manifest.isolation_attestation.mode.clone(),
            catalog_envelope: object(CATALOG)?,
            catalog_payload_sha256: self.catalog_payload_sha256.clone(),
            catalog_sequence: self.sequence,
            catalog_releases: self.catalog_releases.clone(),
            release_manifest: object(RELEASE_MANIFEST)?,
            release_tag: self.tag().to_owned(),
            source_commit: self.release_manifest.source_commit().as_str().to_owned(),
            source_tree_sha256: self
                .release_manifest
                .source_tree_sha256()
                .as_str()
                .to_owned(),
            qualification_sha256: qualification_sha256.to_owned(),
            qualification_reference,
            checksums: object(CHECKSUMS)?,
            support_assets,
            objects: self.objects(),
            prior_reference_sha256,
            latest_temporary_identity,
        })
    }

    fn reverify_all(&self) -> Result<(), PublishError> {
        let root_metadata = self.root.metadata().map_err(|_| rejected())?;
        if !secure_directory(&root_metadata)
            || root_metadata.nlink() != 3
            || FileIdentity::from_metadata(&root_metadata) != self.root_identity
            || enumerate_names(&self.root, TRANSFER_ROOT_ENUMERATION_LIMITS)? != self.root_names
        {
            return Err(rejected());
        }
        let rebound_bundle = open_directory_at(&self.root, SIGNED_BUNDLE)?;
        let bundle_metadata = rebound_bundle.metadata().map_err(|_| rejected())?;
        if !secure_directory(&bundle_metadata)
            || bundle_metadata.nlink() != 2
            || FileIdentity::from_metadata(&bundle_metadata) != self.bundle_identity
            || enumerate_names(&self.bundle, TRANSFER_BUNDLE_ENUMERATION_LIMITS)?
                != self.bundle_names
        {
            return Err(rejected());
        }
        verify_retained(&self.root, &self.transfer_manifest)?;
        for retained in self.files.values() {
            verify_retained(&self.bundle, retained)?;
        }
        Ok(())
    }
}

#[cfg_attr(test, allow(dead_code))]
#[derive(Clone, Copy)]
enum VerificationPolicy {
    Production,
    #[cfg(test)]
    Fixture,
}

/// Independently verifies a complete signed reverse transfer using only catalog-core's compiled
/// production public identity. It performs no state mutation and retains every admitted file.
pub fn verify_transferred_signed_bundle(
    path: &Path,
) -> Result<VerifiedTransferredSignedBundle, PublishError> {
    verify_transferred_signed_bundle_with(path, VerificationPolicy::Production)
}

/// Fixture authority exists only when this source is compiled as a test module. It is absent from
/// the production library and `catalog-publish` binary.
#[allow(dead_code)]
#[cfg(test)]
pub fn verify_transferred_fixture_signed_bundle(
    path: &Path,
) -> Result<VerifiedTransferredSignedBundle, PublishError> {
    verify_transferred_signed_bundle_with(path, VerificationPolicy::Fixture)
}

fn verify_transferred_signed_bundle_with(
    path: &Path,
    policy: VerificationPolicy,
) -> Result<VerifiedTransferredSignedBundle, PublishError> {
    let root = open_absolute_directory(path)?;
    let root_metadata = root.metadata().map_err(|_| rejected())?;
    if !secure_directory(&root_metadata) || root_metadata.nlink() != 3 {
        return Err(rejected());
    }
    let root_identity = FileIdentity::from_metadata(&root_metadata);
    let root_names = enumerate_names(&root, TRANSFER_ROOT_ENUMERATION_LIMITS)?;
    if root_names != BTreeSet::from([TRANSFER_MANIFEST.to_owned(), SIGNED_BUNDLE.to_owned()]) {
        return Err(rejected());
    }
    let bundle = open_directory_at(&root, SIGNED_BUNDLE)?;
    let bundle_metadata = bundle.metadata().map_err(|_| rejected())?;
    if !secure_directory(&bundle_metadata) || bundle_metadata.nlink() != 2 {
        return Err(rejected());
    }
    let bundle_identity = FileIdentity::from_metadata(&bundle_metadata);
    let bundle_names = enumerate_names(&bundle, TRANSFER_BUNDLE_ENUMERATION_LIMITS)?;

    let transfer_file = open_regular_at(&root, TRANSFER_MANIFEST)?;
    let transfer_metadata = transfer_file.metadata().map_err(|_| rejected())?;
    if !secure_file(&transfer_metadata)
        || transfer_metadata.len() == 0
        || transfer_metadata.len() > MAX_TRANSFER_MANIFEST_BYTES
    {
        return Err(rejected());
    }
    let transfer_bytes = read_descriptor(&transfer_file, transfer_metadata.len())?;
    let signed_transfer_sha256 = sha256(&transfer_bytes);
    let manifest: ReverseTransferManifestV1 =
        serde_json::from_slice(&transfer_bytes).map_err(|_| rejected())?;
    if serde_jcs::to_vec(&manifest).map_err(|_| rejected())? != transfer_bytes {
        return Err(rejected());
    }
    validate_reverse_manifest(&manifest)?;
    let transfer_manifest = RetainedFile {
        name: TRANSFER_MANIFEST.to_owned(),
        file: transfer_file,
        identity: FileIdentity::from_metadata(&transfer_metadata),
        size: transfer_metadata.len(),
        sha256: signed_transfer_sha256.clone(),
    };

    let expected_names = manifest
        .entries
        .iter()
        .map(|entry| {
            entry
                .relative_path
                .strip_prefix("signed-release-bundle/")
                .filter(|name| safe_asset_name(name))
                .map(str::to_owned)
                .ok_or_else(rejected)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if expected_names != bundle_names || expected_names.len() != manifest.entries.len() {
        return Err(rejected());
    }

    let mut files = BTreeMap::new();
    for entry in &manifest.entries {
        let name = entry
            .relative_path
            .strip_prefix("signed-release-bundle/")
            .ok_or_else(rejected)?;
        let file = open_regular_at(&bundle, name)?;
        let metadata = file.metadata().map_err(|_| rejected())?;
        if !secure_file(&metadata)
            || metadata.len() != entry.size
            || hash_descriptor(&file, entry.size)? != entry.sha256
        {
            return Err(rejected());
        }
        if files
            .insert(
                name.to_owned(),
                RetainedFile {
                    name: name.to_owned(),
                    file,
                    identity: FileIdentity::from_metadata(&metadata),
                    size: entry.size,
                    sha256: entry.sha256.clone(),
                },
            )
            .is_some()
        {
            return Err(rejected());
        }
    }

    let catalog_file = files.get(CATALOG).ok_or_else(rejected)?;
    let release_file = files.get(RELEASE_MANIFEST).ok_or_else(rejected)?;
    let checksums_file = files.get(CHECKSUMS).ok_or_else(rejected)?;
    if catalog_file.size > MAX_TRANSFER_MANIFEST_BYTES
        || release_file.size > MAX_TRANSFER_MANIFEST_BYTES
        || checksums_file.size > MAX_TRANSFER_MANIFEST_BYTES
    {
        return Err(rejected());
    }
    let catalog_bytes = read_descriptor(&catalog_file.file, catalog_file.size)?;
    let release_bytes = read_descriptor(&release_file.file, release_file.size)?;
    let checksums_bytes = read_descriptor(&checksums_file.file, checksums_file.size)?;

    let catalog = verify_catalog_with_policy(&catalog_bytes, policy)?;
    let release = verify_release_manifest_with_policy(&release_bytes, policy)?;
    let sequence = catalog.payload().sequence().get();
    let catalog_payload_sha256 = encode_hex(catalog.payload_sha256());
    let catalog_releases = catalog_release_bindings(catalog.payload())?;
    let release_manifest = release.manifest().clone();
    if release_manifest.tag().as_str() != format!("catalog-v1-sequence-{sequence}") {
        return Err(rejected());
    }

    let inventory_entries = files
        .values()
        .map(|file| {
            serde_json::json!({
                "relative_path": file.name,
                "mode": "0400",
                "size": file.size,
                "sha256": file.sha256,
            })
        })
        .collect::<Vec<_>>();
    let inventory = BundleInventoryV1::from_json(
        &serde_jcs::to_vec(&serde_json::json!({
            "schema_version": 1,
            "kind": "signed_release",
            "entries": inventory_entries,
        }))
        .map_err(|_| rejected())?,
    )
    .map_err(|_| rejected())?;
    verify_signed_release_inventory(&inventory, &release_manifest).map_err(|_| rejected())?;
    verify_release_bindings(&files, &release_manifest, &checksums_bytes)?;

    let verified = VerifiedTransferredSignedBundle {
        root,
        root_identity,
        root_names,
        bundle,
        bundle_identity,
        bundle_names,
        transfer_manifest,
        files,
        manifest,
        release_manifest,
        signed_transfer_sha256,
        catalog_payload_sha256,
        catalog_releases,
        sequence,
        policy,
    };
    verified.reverify_all()?;
    Ok(verified)
}

fn verify_catalog_with_policy(
    bytes: &[u8],
    policy: VerificationPolicy,
) -> Result<VerifiedCatalogV1, PublishError> {
    match policy {
        VerificationPolicy::Production => verify_signed_catalog(bytes).map_err(|_| rejected()),
        #[cfg(test)]
        VerificationPolicy::Fixture => {
            catalog_core::verify_fixture_signed_catalog(bytes).map_err(|_| rejected())
        }
    }
}

fn verify_release_manifest_with_policy(
    bytes: &[u8],
    policy: VerificationPolicy,
) -> Result<VerifiedReleaseBundleManifestV1, PublishError> {
    match policy {
        VerificationPolicy::Production => {
            verify_signed_release_bundle_manifest(bytes).map_err(|_| rejected())
        }
        #[cfg(test)]
        VerificationPolicy::Fixture => {
            catalog_core::verify_fixture_signed_release_bundle_manifest(bytes)
                .map_err(|_| rejected())
        }
    }
}

fn persistent_verification_policy() -> VerificationPolicy {
    #[cfg(test)]
    return VerificationPolicy::Fixture;
    #[cfg(not(test))]
    VerificationPolicy::Production
}

fn catalog_release_bindings(
    payload: &CatalogPayloadV1,
) -> Result<Vec<CatalogReleaseBindingV1>, PublishError> {
    let bindings = payload
        .providers()
        .iter()
        .flat_map(|provider| {
            provider
                .releases()
                .iter()
                .map(|release| CatalogReleaseBindingV1 {
                    provider: provider.provider_id().to_owned(),
                    target: release.target().as_str().to_owned(),
                    version: release.version().as_str().to_owned(),
                })
        })
        .collect::<Vec<_>>();
    if bindings.is_empty() {
        return Err(rejected());
    }
    Ok(bindings)
}

fn validate_reverse_manifest(manifest: &ReverseTransferManifestV1) -> Result<(), PublishError> {
    if manifest.schema_version != 1
        || manifest.kind != "signer_output"
        || !valid_sha256(&manifest.input_transfer_sha256)
        || manifest.entries.is_empty()
        || manifest.entries.len() > MAX_TRANSFER_ENTRIES
        || manifest
            .entries
            .windows(2)
            .any(|pair| pair[0].relative_path >= pair[1].relative_path)
    {
        return Err(rejected());
    }
    validate_attestation(
        &manifest.isolation_attestation,
        &manifest.input_transfer_sha256,
    )?;
    let mut total = 0_u64;
    for entry in &manifest.entries {
        let Some(name) = entry.relative_path.strip_prefix("signed-release-bundle/") else {
            return Err(rejected());
        };
        if !safe_asset_name(name)
            || entry.mode != "0400"
            || entry.size == 0
            || entry.size > MAX_ENTRY_BYTES
            || !valid_sha256(&entry.sha256)
        {
            return Err(rejected());
        }
        total = total.checked_add(entry.size).ok_or_else(rejected)?;
        if total > MAX_TRANSFER_BYTES {
            return Err(rejected());
        }
    }
    Ok(())
}

fn validate_attestation(
    attestation: &IsolationAttestationV1,
    input_transfer_sha256: &str,
) -> Result<(), PublishError> {
    let expected_prefilter = BTreeMap::from([
        ("connect".to_owned(), libc::EPERM),
        ("execve".to_owned(), libc::ENOENT),
        ("fork".to_owned(), libc::EPERM),
        ("io_uring_enter".to_owned(), libc::EPERM),
        ("io_uring_register".to_owned(), libc::EPERM),
        ("io_uring_setup".to_owned(), libc::EPERM),
        ("mount".to_owned(), libc::EPERM),
        ("move_mount".to_owned(), libc::EPERM),
        ("open_tree".to_owned(), libc::EPERM),
        ("setns".to_owned(), libc::EPERM),
        ("socket".to_owned(), libc::EPERM),
        ("umount2".to_owned(), libc::EPERM),
        ("unshare".to_owned(), libc::EPERM),
    ]);
    let expected_environment = [
        "CATALOG_SIGN_CONFIG_SHA256",
        "CATALOG_SIGN_EGID",
        "CATALOG_SIGN_EUID",
        "CATALOG_SIGN_HOST_MOUNT_NS",
        "CATALOG_SIGN_HOST_NETWORK_NS",
        "CATALOG_SIGN_HOST_PID_NS",
        "CATALOG_SIGN_HOST_USER_NS",
        "CATALOG_SIGN_INPUT_SHA256",
        "CATALOG_SIGN_ISOLATION",
        "CATALOG_SIGN_MODE",
        "CATALOG_SIGN_SIGNER_SHA256",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PWD",
        "TZ",
    ];
    let mut expected_mounts = vec![
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
    ];
    if attestation.mode == IsolationMode::Sign {
        expected_mounts.push("/key/runtime-catalog-private.pem");
        expected_mounts.sort_unstable();
    }
    if attestation.schema_version != 1
        || !matches!(
            (&attestation.original_operation_mode, &attestation.mode),
            (
                IsolationMode::Sign,
                IsolationMode::Sign | IsolationMode::RecoverSign
            )
        )
        || attestation.input_transfer_sha256 != input_transfer_sha256
        || !valid_sha256(&attestation.launcher_config_sha256)
        || !valid_sha256(&attestation.signer_sha256)
        || !attestation.no_new_privileges
        || !attestation.launcher_seccomp_filter
        || attestation.launcher_prefilter_errno != expected_prefilter
        || !attestation.inner_seccomp_filter
        || attestation.core_limit_soft != 0
        || attestation.core_limit_hard != 0
        || attestation.dumpable
        || !attestation.private_tmpfs_root
        || !valid_namespace(&attestation.pid_namespace, "pid")
        || !valid_namespace(&attestation.user_namespace, "user")
        || !valid_namespace(&attestation.mount_namespace, "mnt")
        || !valid_namespace(&attestation.network_namespace, "net")
        || attestation
            .mount_points
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected_mounts
        || attestation
            .environment_names
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected_environment
    {
        return Err(rejected());
    }
    Ok(())
}

fn verify_release_bindings(
    files: &BTreeMap<String, RetainedFile>,
    manifest: &SignedReleaseBundleManifestV1,
    checksums: &[u8],
) -> Result<(), PublishError> {
    let expected_names = std::iter::once(CATALOG.to_owned())
        .chain(
            manifest
                .assets()
                .iter()
                .map(|asset| asset.name().as_str().to_owned()),
        )
        .chain([RELEASE_MANIFEST.to_owned(), CHECKSUMS.to_owned()])
        .collect::<BTreeSet<_>>();
    if files.keys().cloned().collect::<BTreeSet<_>>() != expected_names {
        return Err(rejected());
    }
    let catalog = files.get(CATALOG).ok_or_else(rejected)?;
    if manifest.catalog_envelope().name().as_str() != CATALOG
        || manifest.catalog_envelope().size() != catalog.size
        || manifest.catalog_envelope().sha256().as_str() != catalog.sha256
    {
        return Err(rejected());
    }
    for asset in manifest.assets() {
        let file = files.get(asset.name().as_str()).ok_or_else(rejected)?;
        if asset.size() != file.size || asset.sha256().as_str() != file.sha256 {
            return Err(rejected());
        }
    }
    let expected_checksums = files
        .iter()
        .filter(|(name, _)| name.as_str() != CHECKSUMS)
        .map(|(name, file)| format!("{}  {name}\n", file.sha256))
        .collect::<String>()
        .into_bytes();
    if checksums != expected_checksums {
        return Err(rejected());
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct EnumerationLimits {
    maximum_entries: u64,
    maximum_name_bytes: u64,
    maximum_cumulative_name_bytes: u64,
    maximum_work: u64,
}

const TRANSFER_ROOT_ENUMERATION_LIMITS: EnumerationLimits = EnumerationLimits {
    maximum_entries: 2,
    maximum_name_bytes: 255,
    maximum_cumulative_name_bytes: 255 * 2,
    maximum_work: 4,
};
const TRANSFER_BUNDLE_ENUMERATION_LIMITS: EnumerationLimits = EnumerationLimits {
    maximum_entries: MAX_TRANSFER_ENTRIES as u64,
    maximum_name_bytes: 255,
    maximum_cumulative_name_bytes: 255 * MAX_TRANSFER_ENTRIES as u64,
    maximum_work: MAX_TRANSFER_ENTRIES as u64 + 2,
};
const STATE_ROOT_ENUMERATION_LIMITS: EnumerationLimits = EnumerationLimits {
    maximum_entries: 2,
    maximum_name_bytes: 7,
    maximum_cumulative_name_bytes: 13,
    maximum_work: 4,
};
const STATE_LATEST_ENUMERATION_LIMITS: EnumerationLimits = EnumerationLimits {
    maximum_entries: 10,
    maximum_name_bytes: 64,
    maximum_cumulative_name_bytes: 640,
    maximum_work: 12,
};

#[derive(Clone, Copy)]
struct PersistentStateLimits {
    maximum_object_count: u64,
    maximum_object_bytes: u64,
    maximum_cumulative_bytes: u64,
    maximum_name_bytes: u64,
    maximum_cumulative_name_bytes: u64,
    maximum_enumeration_work: u64,
}

const PERSISTENT_STATE_LIMITS: PersistentStateLimits = PersistentStateLimits {
    maximum_object_count: MAX_PERSISTENT_OBJECTS,
    maximum_object_bytes: MAX_PERSISTENT_OBJECT_BYTES,
    maximum_cumulative_bytes: MAX_PERSISTENT_CUMULATIVE_BYTES,
    maximum_name_bytes: MAX_PERSISTENT_OBJECT_NAME_BYTES,
    maximum_cumulative_name_bytes: MAX_PERSISTENT_NAME_BYTES,
    maximum_enumeration_work: MAX_PERSISTENT_ENUMERATION_WORK,
};

#[allow(dead_code)]
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub struct TestPersistentStateLimits {
    pub maximum_object_count: u64,
    pub maximum_object_bytes: u64,
    pub maximum_cumulative_bytes: u64,
    pub maximum_name_bytes: u64,
    pub maximum_cumulative_name_bytes: u64,
    pub maximum_enumeration_work: u64,
}

#[cfg(test)]
impl Default for TestPersistentStateLimits {
    fn default() -> Self {
        Self {
            maximum_object_count: MAX_PERSISTENT_OBJECTS,
            maximum_object_bytes: MAX_PERSISTENT_OBJECT_BYTES,
            maximum_cumulative_bytes: MAX_PERSISTENT_CUMULATIVE_BYTES,
            maximum_name_bytes: MAX_PERSISTENT_OBJECT_NAME_BYTES,
            maximum_cumulative_name_bytes: MAX_PERSISTENT_NAME_BYTES,
            maximum_enumeration_work: MAX_PERSISTENT_ENUMERATION_WORK,
        }
    }
}

#[cfg(test)]
impl From<TestPersistentStateLimits> for PersistentStateLimits {
    fn from(limits: TestPersistentStateLimits) -> Self {
        Self {
            maximum_object_count: limits.maximum_object_count,
            maximum_object_bytes: limits.maximum_object_bytes,
            maximum_cumulative_bytes: limits.maximum_cumulative_bytes,
            maximum_name_bytes: limits.maximum_name_bytes,
            maximum_cumulative_name_bytes: limits.maximum_cumulative_name_bytes,
            maximum_enumeration_work: limits.maximum_enumeration_work,
        }
    }
}

struct StateCapabilities {
    parent: fs::File,
    root_name: String,
    root: fs::File,
    root_identity: FileIdentity,
    objects: fs::File,
    objects_identity: FileIdentity,
    latest: fs::File,
    latest_identity: FileIdentity,
    limits: PersistentStateLimits,
}

impl StateCapabilities {
    fn revalidate(&self) -> Result<(), PublishError> {
        let root = self.root.metadata().map_err(|_| rejected())?;
        let objects = self.objects.metadata().map_err(|_| rejected())?;
        let latest = self.latest.metadata().map_err(|_| rejected())?;
        let rebound_root = open_directory_at(&self.parent, &self.root_name)?;
        let rebound_root_metadata = rebound_root.metadata().map_err(|_| rejected())?;
        let rebound_objects = open_directory_at(&self.root, "objects")?;
        let rebound_objects_metadata = rebound_objects.metadata().map_err(|_| rejected())?;
        let rebound_latest = open_directory_at(&self.root, "latest")?;
        let rebound_latest_metadata = rebound_latest.metadata().map_err(|_| rejected())?;
        if !same_directory_policy_facts(&root, &rebound_root_metadata)
            || FileIdentity::from_metadata(&rebound_root_metadata) != self.root_identity
            || !secure_directory(&root)
            || root.nlink() != 4
            || FileIdentity::from_metadata(&root) != self.root_identity
            || enumerate_names(&self.root, STATE_ROOT_ENUMERATION_LIMITS)?
                != BTreeSet::from(["latest".to_owned(), "objects".to_owned()])
            || !same_directory_policy_facts(&objects, &rebound_objects_metadata)
            || FileIdentity::from_metadata(&rebound_objects_metadata) != self.objects_identity
            || !secure_directory(&objects)
            || objects.nlink() != 2
            || FileIdentity::from_metadata(&objects) != self.objects_identity
            || !same_directory_policy_facts(&latest, &rebound_latest_metadata)
            || FileIdentity::from_metadata(&rebound_latest_metadata) != self.latest_identity
            || !secure_directory(&latest)
            || latest.nlink() != 2
            || FileIdentity::from_metadata(&latest) != self.latest_identity
        {
            return Err(rejected());
        }

        let object_enumeration_limits = EnumerationLimits {
            maximum_entries: self.limits.maximum_object_count,
            maximum_name_bytes: self.limits.maximum_name_bytes,
            maximum_cumulative_name_bytes: self.limits.maximum_cumulative_name_bytes,
            maximum_work: self.limits.maximum_enumeration_work,
        };
        let mut cumulative_bytes = 0_u64;
        stream_names_bounded(&self.objects, object_enumeration_limits, |name| {
            if !valid_sha256(name) {
                return Err(rejected());
            }
            let file = open_regular_at(&self.objects, name)?;
            let metadata = file.metadata().map_err(|_| rejected())?;
            if !secure_file(&metadata)
                || metadata.len() == 0
                || metadata.len() > self.limits.maximum_object_bytes
            {
                return Err(rejected());
            }
            cumulative_bytes = bounded_add(
                cumulative_bytes,
                metadata.len(),
                self.limits.maximum_cumulative_bytes,
            )?;
            if hash_descriptor(&file, metadata.len())? != name {
                return Err(rejected());
            }
            Ok(())
        })?;

        let allowed = BTreeSet::from([
            LATEST_REFERENCE.to_owned(),
            LATEST_TEMP.to_owned(),
            RECOVERY_RECORD.to_owned(),
            RECOVERY_TEMP.to_owned(),
            REMOTE_OPERATION.to_owned(),
            REMOTE_OPERATION_TEMP.to_owned(),
            DRAFT_RECEIPT.to_owned(),
            RELEASE_APPROVAL.to_owned(),
            PUBLICATION_RECEIPT.to_owned(),
            LATEST_RECEIPT.to_owned(),
        ]);
        if !enumerate_names(&self.latest, STATE_LATEST_ENUMERATION_LIMITS)?.is_subset(&allowed) {
            return Err(rejected());
        }
        Ok(())
    }
}

pub(crate) struct RemoteLocalAsset {
    name: String,
    file: fs::File,
    identity: FileIdentity,
    size: u64,
    sha256: String,
}

impl RemoteLocalAsset {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) const fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn file(&self) -> &fs::File {
        &self.file
    }
}

pub(crate) struct RemoteWorkflowState {
    state: StateCapabilities,
    policy: VerificationPolicy,
    reference: LocalCatalogReferenceV1,
    reference_bytes: Vec<u8>,
    title: String,
    notes: String,
    assets: Vec<RemoteLocalAsset>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteRecordKind {
    Operation,
    DraftReceipt,
    Approval,
    PublicationReceipt,
    LatestReceipt,
}

impl RemoteRecordKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Operation => REMOTE_OPERATION,
            Self::DraftReceipt => DRAFT_RECEIPT,
            Self::Approval => RELEASE_APPROVAL,
            Self::PublicationReceipt => PUBLICATION_RECEIPT,
            Self::LatestReceipt => LATEST_RECEIPT,
        }
    }
}

impl RemoteWorkflowState {
    pub(crate) fn local_operation_id(&self) -> &str {
        &self.reference.operation_id
    }

    pub(crate) fn signed_transfer_sha256(&self) -> &str {
        &self.reference.operation.reverse_transfer_manifest.sha256
    }

    pub(crate) const fn sequence(&self) -> u64 {
        self.reference.operation.catalog_sequence
    }

    pub(crate) fn tag(&self) -> &str {
        &self.reference.operation.release_tag
    }

    pub(crate) fn source_commit(&self) -> &str {
        &self.reference.operation.source_commit
    }

    pub(crate) fn source_tree_sha256(&self) -> &str {
        &self.reference.operation.source_tree_sha256
    }

    pub(crate) fn title(&self) -> &str {
        &self.title
    }

    pub(crate) fn notes(&self) -> &str {
        &self.notes
    }

    pub(crate) fn assets(&self) -> &[RemoteLocalAsset] {
        &self.assets
    }

    pub(crate) fn catalog_asset(&self) -> Result<&RemoteLocalAsset, PublishError> {
        self.assets
            .last()
            .filter(|asset| asset.name == CATALOG)
            .ok_or_else(rejected)
    }

    pub(crate) fn revalidate(&self) -> Result<(), PublishError> {
        self.state.revalidate()?;
        let names = enumerate_names(&self.state.latest, STATE_LATEST_ENUMERATION_LIMITS)?;
        if names.contains(RECOVERY_RECORD)
            || names.contains(RECOVERY_TEMP)
            || names.contains(LATEST_TEMP)
            || names.contains(REMOTE_OPERATION_TEMP)
        {
            return Err(recovery_required());
        }
        let current = read_optional_state_file(
            &self.state.latest,
            LATEST_REFERENCE,
            MAX_REFERENCE_BYTES,
            false,
        )?
        .ok_or_else(rejected)?;
        if current != self.reference_bytes {
            return Err(recovery_required());
        }
        verify_local_reference(&self.state, &self.reference, self.policy)?;
        for asset in &self.assets {
            let metadata = asset.file.metadata().map_err(|_| rejected())?;
            let rebound = open_regular_at(&self.state.objects, &asset.sha256)?;
            let rebound_metadata = rebound.metadata().map_err(|_| rejected())?;
            if !secure_file(&metadata)
                || !secure_file(&rebound_metadata)
                || FileIdentity::from_metadata(&metadata) != asset.identity
                || FileIdentity::from_metadata(&rebound_metadata) != asset.identity
                || metadata.len() != asset.size
                || hash_descriptor(&asset.file, asset.size)? != asset.sha256
                || hash_descriptor(&rebound, asset.size)? != asset.sha256
            {
                return Err(recovery_required());
            }
        }
        Ok(())
    }

    pub(crate) fn read_record(
        &self,
        kind: RemoteRecordKind,
    ) -> Result<Option<Vec<u8>>, PublishError> {
        self.revalidate()?;
        read_optional_state_file(
            &self.state.latest,
            kind.name(),
            MAX_STATE_RECORD_BYTES,
            false,
        )
    }

    pub(crate) fn write_record_no_clobber(
        &self,
        kind: RemoteRecordKind,
        bytes: &[u8],
    ) -> Result<(), PublishError> {
        self.revalidate()?;
        if let Some(existing) = read_optional_state_file(
            &self.state.latest,
            kind.name(),
            MAX_STATE_RECORD_BYTES,
            false,
        )? {
            return (existing == bytes)
                .then_some(())
                .ok_or_else(recovery_required);
        }
        write_unnamed_and_link(&self.state.latest, kind.name(), bytes, 0o400)?;
        self.state.latest.sync_all().map_err(|_| uncertain())?;
        let readback = read_optional_state_file(
            &self.state.latest,
            kind.name(),
            MAX_STATE_RECORD_BYTES,
            false,
        )?
        .ok_or_else(uncertain)?;
        if readback != bytes {
            return Err(uncertain());
        }
        self.revalidate()
    }

    pub(crate) fn replace_operation_record(
        &self,
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<(), PublishError> {
        self.revalidate()?;
        if replacement.is_empty() || replacement.len() as u64 > MAX_STATE_RECORD_BYTES {
            return Err(rejected());
        }
        let current = read_optional_state_file(
            &self.state.latest,
            REMOTE_OPERATION,
            MAX_STATE_RECORD_BYTES,
            false,
        )?
        .ok_or_else(recovery_required)?;
        if current != expected || name_exists(&self.state.latest, REMOTE_OPERATION_TEMP)? {
            return Err(recovery_required());
        }
        write_unnamed_and_link(
            &self.state.latest,
            REMOTE_OPERATION_TEMP,
            replacement,
            0o400,
        )?;
        let gated = read_optional_state_file(
            &self.state.latest,
            REMOTE_OPERATION,
            MAX_STATE_RECORD_BYTES,
            false,
        )?
        .ok_or_else(uncertain)?;
        if gated != expected {
            return Err(uncertain());
        }
        let old = CString::new(REMOTE_OPERATION_TEMP).expect("fixed remote operation temporary");
        let new = CString::new(REMOTE_OPERATION).expect("fixed remote operation record");
        // SAFETY: both fixed names are within the retained owner-private latest directory.
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.state.latest.as_raw_fd(),
                old.as_ptr(),
                self.state.latest.as_raw_fd(),
                new.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(uncertain());
        }
        self.state.latest.sync_all().map_err(|_| uncertain())?;
        let readback = read_optional_state_file(
            &self.state.latest,
            REMOTE_OPERATION,
            MAX_STATE_RECORD_BYTES,
            false,
        )?
        .ok_or_else(uncertain)?;
        if readback != replacement {
            return Err(uncertain());
        }
        self.revalidate()
    }
}

pub(crate) fn open_remote_workflow_state(
    state_path: &Path,
) -> Result<RemoteWorkflowState, PublishError> {
    open_remote_workflow_state_with(state_path, VerificationPolicy::Production)
}

#[allow(dead_code)]
#[cfg(test)]
pub(crate) fn open_fixture_remote_workflow_state(
    state_path: &Path,
) -> Result<RemoteWorkflowState, PublishError> {
    open_remote_workflow_state_with(state_path, VerificationPolicy::Fixture)
}

fn open_remote_workflow_state_with(
    state_path: &Path,
    policy: VerificationPolicy,
) -> Result<RemoteWorkflowState, PublishError> {
    let state = open_existing_state(state_path)?;
    state.revalidate()?;
    let names = enumerate_names(&state.latest, STATE_LATEST_ENUMERATION_LIMITS)?;
    if names.contains(RECOVERY_RECORD)
        || names.contains(RECOVERY_TEMP)
        || names.contains(LATEST_TEMP)
        || names.contains(REMOTE_OPERATION_TEMP)
    {
        return Err(recovery_required());
    }
    let reference_bytes =
        read_optional_state_file(&state.latest, LATEST_REFERENCE, MAX_REFERENCE_BYTES, false)?
            .ok_or_else(rejected)?;
    let reference = parse_reference(&reference_bytes)?;
    verify_local_reference(&state, &reference, policy)?;
    let retained = verify_record_objects(&state, &reference.operation)?;
    let catalog = retained.get(CATALOG).ok_or_else(rejected)?;
    let catalog_bytes = read_descriptor(&catalog.file, catalog.size)?;
    let verified_catalog = verify_catalog_with_policy(&catalog_bytes, policy)?;
    let releases = verified_catalog
        .payload()
        .providers()
        .iter()
        .flat_map(|provider| provider.releases())
        .collect::<Vec<_>>();
    let [release] = releases.as_slice() else {
        return Err(rejected());
    };
    let title = release.release_metadata().title().as_str().to_owned();
    let notes = release.release_metadata().notes().as_str().to_owned();

    let mut ordered = retained
        .into_values()
        .filter(|asset| asset.name != TRANSFER_MANIFEST && asset.name != CATALOG)
        .collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.name.cmp(&right.name));
    let catalog = verify_record_objects(&state, &reference.operation)?
        .remove(CATALOG)
        .ok_or_else(rejected)?;
    ordered.push(catalog);
    let assets = ordered
        .into_iter()
        .map(|asset| RemoteLocalAsset {
            name: asset.name,
            file: asset.file,
            identity: asset.identity,
            size: asset.size,
            sha256: asset.sha256,
        })
        .collect();
    let remote = RemoteWorkflowState {
        state,
        policy,
        reference,
        reference_bytes,
        title,
        notes,
        assets,
    };
    remote.revalidate()?;
    Ok(remote)
}

fn same_directory_policy_facts(retained: &fs::Metadata, rebound: &fs::Metadata) -> bool {
    retained.uid() == rebound.uid()
        && retained.permissions().mode() & 0o7777 == rebound.permissions().mode() & 0o7777
        && retained.nlink() == rebound.nlink()
        && secure_directory(retained)
        && secure_directory(rebound)
}

/// Stages every retained public release object into exact owner-private local state.
pub fn stage_local(
    bundle: &VerifiedTransferredSignedBundle,
    state: &Path,
) -> Result<PublishOutcome, PublishError> {
    #[cfg(test)]
    return stage_local_inner(bundle, state, TestPlan::default(), PERSISTENT_STATE_LIMITS);
    #[cfg(not(test))]
    stage_local_inner(bundle, state, (), PERSISTENT_STATE_LIMITS)
}

#[allow(dead_code)]
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPoint {
    BeforeObjectWrite,
    AfterObjects,
    BeforeRecoveryRecord,
    AfterRecoveryRecord,
    AfterLatestTempDurable,
    AfterLatestRename,
    AfterLatestReadback,
    BeforeLatestDirectorySync,
    AfterLatestDirectorySync,
}

#[allow(dead_code)]
#[cfg(test)]
impl FaultPoint {
    pub const fn label(self) -> &'static str {
        match self {
            Self::BeforeObjectWrite => "before-object-write",
            Self::AfterObjects => "after-objects",
            Self::BeforeRecoveryRecord => "before-recovery-record",
            Self::AfterRecoveryRecord => "after-recovery-record",
            Self::AfterLatestTempDurable => "after-latest-temp-durable",
            Self::AfterLatestRename => "after-latest-rename",
            Self::AfterLatestReadback => "after-latest-readback",
            Self::BeforeLatestDirectorySync => "before-latest-directory-sync",
            Self::AfterLatestDirectorySync => "after-latest-directory-sync",
        }
    }
}

#[allow(dead_code)]
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateCheckpoint {
    AfterOpen,
    BeforeChildCreation,
    BeforeMutation,
    BeforeSuccess,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StateBoundary {
    AfterOpen,
    BeforeChildCreation,
    BeforeMutation,
    BeforeSuccess,
}

#[cfg(test)]
impl From<StateCheckpoint> for StateBoundary {
    fn from(checkpoint: StateCheckpoint) -> Self {
        match checkpoint {
            StateCheckpoint::AfterOpen => Self::AfterOpen,
            StateCheckpoint::BeforeChildCreation => Self::BeforeChildCreation,
            StateCheckpoint::BeforeMutation => Self::BeforeMutation,
            StateCheckpoint::BeforeSuccess => Self::BeforeSuccess,
        }
    }
}

#[cfg(test)]
struct TestPause {
    checkpoint: StateBoundary,
    reached: std::sync::mpsc::SyncSender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
#[derive(Default)]
struct TestPlan {
    fault: Option<FaultPoint>,
    pause: Option<TestPause>,
    crash_ready: Option<std::path::PathBuf>,
}

#[cfg(not(test))]
type TestPlan = ();

#[allow(dead_code)]
#[cfg(test)]
pub fn stage_local_with_fault(
    bundle: &VerifiedTransferredSignedBundle,
    state: &Path,
    fault: FaultPoint,
) -> Result<PublishOutcome, PublishError> {
    stage_local_inner(
        bundle,
        state,
        TestPlan {
            fault: Some(fault),
            pause: None,
            crash_ready: None,
        },
        PERSISTENT_STATE_LIMITS,
    )
}

#[allow(dead_code)]
#[cfg(test)]
pub fn stage_local_with_checkpoint(
    bundle: &VerifiedTransferredSignedBundle,
    state: &Path,
    checkpoint: StateCheckpoint,
    reached: std::sync::mpsc::SyncSender<()>,
    resume: std::sync::mpsc::Receiver<()>,
) -> Result<PublishOutcome, PublishError> {
    stage_local_inner(
        bundle,
        state,
        TestPlan {
            fault: None,
            pause: Some(TestPause {
                checkpoint: checkpoint.into(),
                reached,
                resume,
            }),
            crash_ready: None,
        },
        PERSISTENT_STATE_LIMITS,
    )
}

#[allow(dead_code)]
#[cfg(test)]
pub fn stage_local_with_persistent_limits(
    bundle: &VerifiedTransferredSignedBundle,
    state: &Path,
    limits: TestPersistentStateLimits,
) -> Result<PublishOutcome, PublishError> {
    stage_local_inner(bundle, state, TestPlan::default(), limits.into())
}

#[allow(dead_code)]
#[cfg(test)]
pub fn stage_local_with_sigkill_checkpoint(
    bundle: &VerifiedTransferredSignedBundle,
    state: &Path,
    ready: &Path,
) -> Result<PublishOutcome, PublishError> {
    stage_local_inner(
        bundle,
        state,
        TestPlan {
            fault: None,
            pause: None,
            crash_ready: Some(ready.to_owned()),
        },
        PERSISTENT_STATE_LIMITS,
    )
}

#[derive(Clone, Copy)]
enum Checkpoint {
    BeforeObjectWrite,
    AfterObjects,
    BeforeRecoveryRecord,
    AfterRecoveryRecord,
    AfterLatestTempDurable,
    AfterLatestRename,
    AfterLatestReadback,
    BeforeLatestDirectorySync,
    AfterLatestDirectorySync,
}

#[cfg(test)]
fn fault_at(plan: &TestPlan, checkpoint: Checkpoint) -> bool {
    matches!(
        (plan.fault, checkpoint),
        (
            Some(FaultPoint::BeforeObjectWrite),
            Checkpoint::BeforeObjectWrite
        ) | (Some(FaultPoint::AfterObjects), Checkpoint::AfterObjects)
            | (
                Some(FaultPoint::BeforeRecoveryRecord),
                Checkpoint::BeforeRecoveryRecord
            )
            | (
                Some(FaultPoint::AfterRecoveryRecord),
                Checkpoint::AfterRecoveryRecord
            )
            | (
                Some(FaultPoint::AfterLatestTempDurable),
                Checkpoint::AfterLatestTempDurable
            )
            | (
                Some(FaultPoint::AfterLatestRename),
                Checkpoint::AfterLatestRename
            )
            | (
                Some(FaultPoint::AfterLatestReadback),
                Checkpoint::AfterLatestReadback
            )
            | (
                Some(FaultPoint::BeforeLatestDirectorySync),
                Checkpoint::BeforeLatestDirectorySync
            )
            | (
                Some(FaultPoint::AfterLatestDirectorySync),
                Checkpoint::AfterLatestDirectorySync
            )
    )
}

#[cfg(not(test))]
const fn fault_at(_plan: &TestPlan, _checkpoint: Checkpoint) -> bool {
    false
}

#[cfg(test)]
fn crash_pause_after_latest_temp(plan: &TestPlan) -> Result<(), PublishError> {
    if let Some(ready) = &plan.crash_ready {
        let file = fs::File::create(ready).map_err(|_| recovery_required())?;
        file.sync_all().map_err(|_| recovery_required())?;
        loop {
            // SAFETY: pause blocks until a signal; the SIGKILL test never returns through cleanup.
            unsafe { libc::pause() };
        }
    }
    Ok(())
}

#[cfg(not(test))]
const fn crash_pause_after_latest_temp(_plan: &TestPlan) -> Result<(), PublishError> {
    Ok(())
}

#[cfg(test)]
fn pause_at(plan: &TestPlan, checkpoint: StateBoundary) -> Result<(), PublishError> {
    if let Some(pause) = &plan.pause
        && pause.checkpoint == checkpoint
    {
        pause.reached.send(()).map_err(|_| rejected())?;
        pause.resume.recv().map_err(|_| rejected())?;
    }
    Ok(())
}

#[cfg(not(test))]
const fn pause_at(_plan: &TestPlan, _checkpoint: StateBoundary) -> Result<(), PublishError> {
    Ok(())
}

fn stage_local_inner(
    bundle: &VerifiedTransferredSignedBundle,
    state_path: &Path,
    plan: TestPlan,
    limits: PersistentStateLimits,
) -> Result<PublishOutcome, PublishError> {
    bundle.reverify_all().map_err(|_| prior_preserved())?;
    let state = prepare_state(state_path, limits, &plan).map_err(|_| prior_preserved())?;
    pause_at(&plan, StateBoundary::AfterOpen).map_err(|_| prior_preserved())?;
    state.revalidate().map_err(|_| prior_preserved())?;
    let latest_names = enumerate_names(&state.latest, STATE_LATEST_ENUMERATION_LIMITS)
        .map_err(|_| prior_preserved())?;
    if latest_names.contains(RECOVERY_RECORD)
        || latest_names.contains(RECOVERY_TEMP)
        || latest_names.contains(LATEST_TEMP)
    {
        return Err(recovery_required());
    }
    let prior_bytes =
        read_optional_state_file(&state.latest, LATEST_REFERENCE, MAX_REFERENCE_BYTES, false)
            .map_err(|_| prior_preserved())?;
    let prior = prior_bytes
        .as_deref()
        .map(parse_reference)
        .transpose()
        .map_err(|_| prior_preserved())?;
    if let Some(reference) = &prior {
        verify_local_reference(&state, reference, bundle.policy).map_err(|_| prior_preserved())?;
    }
    let existing_candidate = prior
        .as_ref()
        .is_some_and(|reference| operation_matches_bundle(&reference.operation, bundle));
    if prior.as_ref().is_some_and(|current| {
        current.operation.catalog_sequence > bundle.sequence
            || (current.operation.catalog_sequence == bundle.sequence && !existing_candidate)
    }) {
        return Err(prior_preserved());
    }

    if fault_at(&plan, Checkpoint::BeforeObjectWrite) {
        return Err(prior_preserved());
    }
    pause_at(&plan, StateBoundary::BeforeMutation).map_err(|_| prior_preserved())?;
    state.revalidate().map_err(|_| prior_preserved())?;
    validate_staging_inventory(bundle, state.limits).map_err(|_| prior_preserved())?;
    publish_or_reuse_object(&state.objects, &bundle.transfer_manifest)
        .map_err(|_| prior_preserved())?;
    for source in bundle.files.values() {
        publish_or_reuse_object(&state.objects, source).map_err(|_| prior_preserved())?;
    }
    bundle.reverify_all().map_err(|_| prior_preserved())?;
    state.objects.sync_all().map_err(|_| prior_preserved())?;
    if fault_at(&plan, Checkpoint::AfterObjects) {
        return Err(prior_preserved());
    }
    if existing_candidate {
        pause_at(&plan, StateBoundary::BeforeSuccess).map_err(|_| prior_preserved())?;
        revalidate_before_staged_success(&state).map_err(|_| prior_preserved())?;
        return Ok(PublishOutcome::Staged);
    }

    let latest_temporary = open_latest_temporary(&state).map_err(|_| prior_preserved())?;
    let prior_reference_sha256 = prior_bytes.as_deref().map(sha256);
    let operation = bundle.operation_body(prior_reference_sha256, latest_temporary.identity)?;
    let operation_id = operation_id(&operation).map_err(|_| prior_preserved())?;
    let intended = LocalCatalogReferenceV1 {
        schema_version: 1,
        operation_id: operation_id.clone(),
        operation: operation.clone(),
    };
    let intended_bytes = serde_jcs::to_vec(&intended).map_err(|_| prior_preserved())?;
    if intended_bytes.len() as u64 > MAX_REFERENCE_BYTES {
        return Err(prior_preserved());
    }
    finalize_latest_temporary(&latest_temporary, &intended_bytes).map_err(|_| prior_preserved())?;
    if fault_at(&plan, Checkpoint::BeforeRecoveryRecord) {
        return Err(prior_preserved());
    }

    let record = build_recovery_record(operation_id, operation, intended.clone(), prior.clone())?;
    validate_recovery_inventory(&record.operation, state.limits).map_err(|_| prior_preserved())?;
    let record_bytes = serde_jcs::to_vec(&record).map_err(|_| prior_preserved())?;
    if record_bytes.len() as u64 > MAX_STATE_RECORD_BYTES {
        return Err(prior_preserved());
    }
    let transaction = install_recovery_record(&state, &record_bytes).map_err(|_| {
        if name_exists(&state.latest, RECOVERY_RECORD).unwrap_or(true)
            || name_exists(&state.latest, RECOVERY_TEMP).unwrap_or(true)
        {
            recovery_required()
        } else {
            prior_preserved()
        }
    })?;
    if fault_at(&plan, Checkpoint::AfterRecoveryRecord) {
        return Err(recovery_required());
    }

    let gated =
        read_optional_state_file(&state.latest, LATEST_REFERENCE, MAX_REFERENCE_BYTES, false)
            .map_err(|_| uncertain())?;
    if gated != prior_bytes {
        return Err(uncertain());
    }
    link_latest_temporary(&state, &latest_temporary, &intended_bytes).map_err(|_| uncertain())?;
    if fault_at(&plan, Checkpoint::AfterLatestTempDurable) {
        return Err(recovery_required());
    }
    crash_pause_after_latest_temp(&plan)?;
    rename_latest_temporary(&state, &latest_temporary, &intended_bytes, prior.is_some())
        .map_err(|_| uncertain())?;
    if fault_at(&plan, Checkpoint::AfterLatestRename) {
        return Err(uncertain());
    }
    let readback =
        read_optional_state_file(&state.latest, LATEST_REFERENCE, MAX_REFERENCE_BYTES, false)
            .map_err(|_| uncertain())?;
    if readback.as_deref() != Some(intended_bytes.as_slice()) {
        return Err(uncertain());
    }
    if fault_at(&plan, Checkpoint::AfterLatestReadback)
        || fault_at(&plan, Checkpoint::BeforeLatestDirectorySync)
    {
        return Err(uncertain());
    }
    state.latest.sync_all().map_err(|_| uncertain())?;
    if fault_at(&plan, Checkpoint::AfterLatestDirectorySync) {
        return Err(uncertain());
    }
    verify_recovery_relation(&state, &record, &intended_bytes, bundle.policy)
        .map_err(|_| uncertain())?;
    cleanup_recovery_record(&state, &transaction).map_err(|_| uncertain())?;
    pause_at(&plan, StateBoundary::BeforeSuccess).map_err(|_| uncertain())?;
    revalidate_before_staged_success(&state).map_err(|_| uncertain())?;
    Ok(PublishOutcome::Staged)
}

fn revalidate_before_staged_success(state: &StateCapabilities) -> Result<(), PublishError> {
    state.revalidate()
}

fn validate_staging_inventory(
    bundle: &VerifiedTransferredSignedBundle,
    limits: PersistentStateLimits,
) -> Result<(), PublishError> {
    let count = u64::try_from(bundle.files.len() + 1).map_err(|_| rejected())?;
    if count == 0 || count > limits.maximum_object_count {
        return Err(rejected());
    }
    let mut cumulative_bytes = 0_u64;
    for source in std::iter::once(&bundle.transfer_manifest).chain(bundle.files.values()) {
        if source.sha256.len() as u64 > limits.maximum_name_bytes
            || source.size == 0
            || source.size > limits.maximum_object_bytes
        {
            return Err(rejected());
        }
        cumulative_bytes = bounded_add(
            cumulative_bytes,
            source.size,
            limits.maximum_cumulative_bytes,
        )?;
    }
    Ok(())
}

fn validate_recovery_inventory(
    operation: &OperationBodyV1,
    limits: PersistentStateLimits,
) -> Result<(), PublishError> {
    let count = u64::try_from(operation.objects.len()).map_err(|_| rejected())?;
    if count == 0 || count > limits.maximum_object_count {
        return Err(rejected());
    }
    let mut cumulative_bytes = 0_u64;
    for object in &operation.objects {
        if object.sha256.len() as u64 > limits.maximum_name_bytes
            || object.size == 0
            || object.size > limits.maximum_object_bytes
        {
            return Err(rejected());
        }
        cumulative_bytes = bounded_add(
            cumulative_bytes,
            object.size,
            limits.maximum_cumulative_bytes,
        )?;
    }
    Ok(())
}

fn build_recovery_record(
    operation_id: String,
    operation: OperationBodyV1,
    intended: LocalCatalogReferenceV1,
    prior: Option<LocalCatalogReferenceV1>,
) -> Result<RecoveryRecordV1, PublishError> {
    let prior_bytes = prior
        .as_ref()
        .map(serde_jcs::to_vec)
        .transpose()
        .map_err(|_| rejected())?;
    if operation.prior_reference_sha256 != prior_bytes.as_deref().map(sha256) {
        return Err(rejected());
    }
    Ok(RecoveryRecordV1 {
        schema_version: 1,
        operation_id,
        operation,
        intended_reference: intended,
        prior_state: if prior.is_some() {
            "prior_reference".to_owned()
        } else {
            "no_rollback_candidate".to_owned()
        },
        prior_reference: prior,
        phase: "prepared".to_owned(),
    })
}

fn operation_id(operation: &OperationBodyV1) -> Result<String, PublishError> {
    let canonical = serde_jcs::to_vec(operation).map_err(|_| rejected())?;
    let mut hasher = Sha256::new();
    hasher.update(OPERATION_DOMAIN);
    hasher.update(canonical);
    Ok(format!("{:x}", hasher.finalize()))
}

fn operation_matches_bundle(
    operation: &OperationBodyV1,
    bundle: &VerifiedTransferredSignedBundle,
) -> bool {
    let Ok(expected) = bundle.operation_body(
        operation.prior_reference_sha256.clone(),
        operation.latest_temporary_identity,
    ) else {
        return false;
    };
    expected == *operation
}

struct TransactionGuard {
    file: fs::File,
    identity: FileIdentity,
}

fn install_recovery_record(
    state: &StateCapabilities,
    bytes: &[u8],
) -> Result<TransactionGuard, PublishError> {
    if name_exists(&state.latest, RECOVERY_RECORD)? || name_exists(&state.latest, RECOVERY_TEMP)? {
        return Err(recovery_required());
    }
    let file = write_unnamed_and_link(&state.latest, RECOVERY_TEMP, bytes, 0o400)?;
    acquire_lock(&file)?;
    let identity = FileIdentity::from_metadata(&file.metadata().map_err(|_| rejected())?);
    link_exact(&state.latest, RECOVERY_TEMP, RECOVERY_RECORD)?;
    state.latest.sync_all().map_err(|_| recovery_required())?;
    let marker = open_regular_at(&state.latest, RECOVERY_RECORD)?;
    let marker_metadata = marker.metadata().map_err(|_| recovery_required())?;
    if FileIdentity::from_metadata(&marker_metadata) != identity
        || marker_metadata.nlink() != 2
        || read_descriptor(&marker, marker_metadata.len())? != bytes
    {
        return Err(recovery_required());
    }
    Ok(TransactionGuard { file, identity })
}

struct LatestTemporary {
    file: fs::File,
    identity: FileIdentity,
}

fn open_latest_temporary(state: &StateCapabilities) -> Result<LatestTemporary, PublishError> {
    if name_exists(&state.latest, LATEST_TEMP)? {
        return Err(recovery_required());
    }
    let file = open_unnamed(&state.latest, 0o600)?;
    let identity = FileIdentity::from_metadata(&file.metadata().map_err(|_| rejected())?);
    Ok(LatestTemporary { file, identity })
}

fn finalize_latest_temporary(
    temporary: &LatestTemporary,
    bytes: &[u8],
) -> Result<(), PublishError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_REFERENCE_BYTES {
        return Err(rejected());
    }
    let mut file = temporary.file.try_clone().map_err(|_| rejected())?;
    file.write_all(bytes).map_err(|_| rejected())?;
    file.flush().map_err(|_| rejected())?;
    file.set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(|_| rejected())?;
    file.sync_all().map_err(|_| rejected())?;
    let metadata = temporary.file.metadata().map_err(|_| rejected())?;
    if FileIdentity::from_metadata(&metadata) != temporary.identity
        || !secure_file_allow_links(&metadata, 0)
        || metadata.len() != bytes.len() as u64
        || read_descriptor(&temporary.file, metadata.len())? != bytes
    {
        return Err(rejected());
    }
    Ok(())
}

fn link_latest_temporary(
    state: &StateCapabilities,
    temporary: &LatestTemporary,
    bytes: &[u8],
) -> Result<(), PublishError> {
    link_unnamed(&temporary.file, &state.latest, LATEST_TEMP)?;
    state.latest.sync_all().map_err(|_| recovery_required())?;
    let rebound = open_regular_at(&state.latest, LATEST_TEMP)?;
    let metadata = rebound.metadata().map_err(|_| recovery_required())?;
    if FileIdentity::from_metadata(&metadata) != temporary.identity
        || !secure_file(&metadata)
        || metadata.len() != bytes.len() as u64
        || read_descriptor(&rebound, metadata.len())? != bytes
        || hash_descriptor(&rebound, metadata.len())? != sha256(bytes)
    {
        return Err(recovery_required());
    }
    Ok(())
}

fn rename_latest_temporary(
    state: &StateCapabilities,
    temporary: &LatestTemporary,
    bytes: &[u8],
    prior_exists: bool,
) -> Result<(), PublishError> {
    let old = CString::new(LATEST_TEMP).expect("fixed latest temporary");
    let new = CString::new(LATEST_REFERENCE).expect("fixed latest reference");
    let flags = if prior_exists {
        0
    } else {
        libc::RENAME_NOREPLACE
    };
    // SAFETY: retained directory and fixed names are valid; renameat2 is atomic.
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            state.latest.as_raw_fd(),
            old.as_ptr(),
            state.latest.as_raw_fd(),
            new.as_ptr(),
            flags,
        )
    };
    if status != 0 {
        return Err(recovery_required());
    }
    let rebound = open_regular_at(&state.latest, LATEST_REFERENCE)?;
    let metadata = rebound.metadata().map_err(|_| rejected())?;
    if FileIdentity::from_metadata(&metadata) != temporary.identity
        || !secure_file(&metadata)
        || read_descriptor(&rebound, metadata.len())? != bytes
    {
        return Err(uncertain());
    }
    Ok(())
}

/// Recovers only the exact durable operation already recorded in local state.
pub fn recover_local(state_path: &Path) -> Result<PublishOutcome, PublishError> {
    #[cfg(test)]
    return recover_local_inner(state_path, TestPlan::default());
    #[cfg(not(test))]
    recover_local_inner(state_path, ())
}

#[allow(dead_code)]
#[cfg(test)]
pub fn recover_local_with_checkpoint(
    state: &Path,
    checkpoint: StateCheckpoint,
    reached: std::sync::mpsc::SyncSender<()>,
    resume: std::sync::mpsc::Receiver<()>,
) -> Result<PublishOutcome, PublishError> {
    recover_local_inner(
        state,
        TestPlan {
            fault: None,
            pause: Some(TestPause {
                checkpoint: checkpoint.into(),
                reached,
                resume,
            }),
            crash_ready: None,
        },
    )
}

fn recover_local_inner(state_path: &Path, plan: TestPlan) -> Result<PublishOutcome, PublishError> {
    let state = open_existing_state(state_path).map_err(|_| uncertain())?;
    let policy = persistent_verification_policy();
    pause_at(&plan, StateBoundary::AfterOpen).map_err(|_| uncertain())?;
    state.revalidate().map_err(|_| uncertain())?;
    let latest_temporary_exists =
        name_exists(&state.latest, LATEST_TEMP).map_err(|_| uncertain())?;
    let marker_exists = name_exists(&state.latest, RECOVERY_RECORD).map_err(|_| uncertain())?;
    let recovery_temporary_exists =
        name_exists(&state.latest, RECOVERY_TEMP).map_err(|_| uncertain())?;
    if !marker_exists {
        if recovery_temporary_exists || latest_temporary_exists {
            return Err(recovery_required());
        }
        let outcome = clean_recovery_outcome(&state, policy)?;
        pause_at(&plan, StateBoundary::BeforeSuccess).map_err(|_| uncertain())?;
        revalidate_before_recovered_success(&state).map_err(|_| uncertain())?;
        return Ok(outcome);
    }

    let marker = open_regular_at(&state.latest, RECOVERY_RECORD).map_err(|_| uncertain())?;
    acquire_lock(&marker)?;
    let marker_metadata = marker.metadata().map_err(|_| uncertain())?;
    if !secure_file_allow_links(
        &marker_metadata,
        if recovery_temporary_exists { 2 } else { 1 },
    ) || marker_metadata.len() == 0
        || marker_metadata.len() > MAX_STATE_RECORD_BYTES
    {
        return Err(uncertain());
    }
    let identity = FileIdentity::from_metadata(&marker_metadata);
    let bytes = read_descriptor(&marker, marker_metadata.len()).map_err(|_| uncertain())?;
    if recovery_temporary_exists {
        let temporary = open_regular_at(&state.latest, RECOVERY_TEMP).map_err(|_| uncertain())?;
        let metadata = temporary.metadata().map_err(|_| uncertain())?;
        if FileIdentity::from_metadata(&metadata) != identity
            || metadata.nlink() != 2
            || read_descriptor(&temporary, metadata.len()).map_err(|_| uncertain())? != bytes
        {
            return Err(uncertain());
        }
    }
    let record = parse_recovery_record(&bytes, state.limits)?;
    verify_operation(&state, &record.operation, policy).map_err(|_| uncertain())?;
    if let Some(prior) = &record.prior_reference {
        verify_operation(&state, &prior.operation, policy).map_err(|_| uncertain())?;
    }
    let intended_bytes = serde_jcs::to_vec(&record.intended_reference).map_err(|_| uncertain())?;
    let prior_bytes = record
        .prior_reference
        .as_ref()
        .map(serde_jcs::to_vec)
        .transpose()
        .map_err(|_| uncertain())?;
    let current =
        read_optional_state_file(&state.latest, LATEST_REFERENCE, MAX_REFERENCE_BYTES, false)
            .map_err(|_| uncertain())?;
    let transaction = TransactionGuard {
        file: marker,
        identity,
    };

    if latest_temporary_exists {
        let latest_temporary =
            verify_bound_latest_temporary(&state, &record.operation, &intended_bytes)
                .map_err(|_| recovery_required())?;
        if current.as_deref() == Some(intended_bytes.as_slice()) {
            return Err(recovery_required());
        }
        if current != prior_bytes {
            return Err(recovery_required());
        }
        pause_at(&plan, StateBoundary::BeforeMutation).map_err(|_| uncertain())?;
        state.revalidate().map_err(|_| uncertain())?;
        verify_operation(&state, &record.operation, policy).map_err(|_| uncertain())?;
        verify_exact_prior(&state, &record, &prior_bytes, policy)?;
        unlink_bound_latest_temporary(
            &state,
            &latest_temporary,
            &record.operation,
            &intended_bytes,
        )?;
        state.latest.sync_all().map_err(|_| uncertain())?;
        verify_exact_prior(&state, &record, &prior_bytes, policy)?;
        cleanup_recovery_record(&state, &transaction).map_err(|_| uncertain())?;
        pause_at(&plan, StateBoundary::BeforeSuccess).map_err(|_| uncertain())?;
        revalidate_before_recovered_success(&state).map_err(|_| uncertain())?;
        return Ok(PublishOutcome::RecoveryAborted);
    }

    let outcome = if current.as_deref() == Some(intended_bytes.as_slice()) {
        PublishOutcome::RecoveryCommitted
    } else if current == prior_bytes {
        PublishOutcome::RecoveryAborted
    } else {
        return Err(uncertain());
    };
    state.latest.sync_all().map_err(|_| uncertain())?;
    pause_at(&plan, StateBoundary::BeforeMutation).map_err(|_| uncertain())?;
    state.revalidate().map_err(|_| uncertain())?;
    verify_operation(&state, &record.operation, policy).map_err(|_| uncertain())?;
    match outcome {
        PublishOutcome::RecoveryCommitted => {
            let rebound = read_optional_state_file(
                &state.latest,
                LATEST_REFERENCE,
                MAX_REFERENCE_BYTES,
                false,
            )
            .map_err(|_| uncertain())?;
            if rebound.as_deref() != Some(intended_bytes.as_slice()) {
                return Err(uncertain());
            }
            verify_local_reference(&state, &record.intended_reference, policy)
                .map_err(|_| uncertain())?;
        }
        PublishOutcome::RecoveryAborted => {
            verify_exact_prior(&state, &record, &prior_bytes, policy)?;
        }
        PublishOutcome::Staged => return Err(uncertain()),
    }
    cleanup_recovery_record(&state, &transaction).map_err(|_| uncertain())?;
    pause_at(&plan, StateBoundary::BeforeSuccess).map_err(|_| uncertain())?;
    revalidate_before_recovered_success(&state).map_err(|_| uncertain())?;
    Ok(outcome)
}

fn revalidate_before_recovered_success(state: &StateCapabilities) -> Result<(), PublishError> {
    state.revalidate()
}

fn clean_recovery_outcome(
    state: &StateCapabilities,
    policy: VerificationPolicy,
) -> Result<PublishOutcome, PublishError> {
    let current =
        read_optional_state_file(&state.latest, LATEST_REFERENCE, MAX_REFERENCE_BYTES, false)
            .map_err(|_| uncertain())?;
    match current {
        None => Ok(PublishOutcome::RecoveryAborted),
        Some(bytes) => {
            let reference = parse_reference(&bytes).map_err(|_| uncertain())?;
            verify_local_reference(state, &reference, policy).map_err(|_| uncertain())?;
            Ok(PublishOutcome::RecoveryCommitted)
        }
    }
}

fn parse_recovery_record(
    bytes: &[u8],
    limits: PersistentStateLimits,
) -> Result<RecoveryRecordV1, PublishError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_RECORD_BYTES {
        return Err(uncertain());
    }
    let record: RecoveryRecordV1 = serde_json::from_slice(bytes).map_err(|_| uncertain())?;
    if serde_jcs::to_vec(&record).map_err(|_| uncertain())? != bytes
        || record.schema_version != 1
        || record.phase != "prepared"
        || !matches!(
            (record.prior_state.as_str(), record.prior_reference.as_ref()),
            ("no_rollback_candidate", None) | ("prior_reference", Some(_))
        )
        || record.operation_id != record.intended_reference.operation_id
        || record.operation != record.intended_reference.operation
    {
        return Err(uncertain());
    }
    validate_reference(&record.intended_reference).map_err(|_| uncertain())?;
    if let Some(prior) = &record.prior_reference {
        validate_reference(prior).map_err(|_| uncertain())?;
    }
    validate_recovery_inventory(&record.operation, limits).map_err(|_| uncertain())?;
    let prior_bytes = record
        .prior_reference
        .as_ref()
        .map(serde_jcs::to_vec)
        .transpose()
        .map_err(|_| uncertain())?;
    if record.operation.prior_reference_sha256 != prior_bytes.as_deref().map(sha256)
        || operation_id(&record.operation).map_err(|_| uncertain())? != record.operation_id
    {
        return Err(uncertain());
    }
    Ok(record)
}

fn validate_local_object(object: &LocalObjectV1) -> Result<(), PublishError> {
    if !safe_asset_name(&object.name)
        || !valid_sha256(&object.sha256)
        || object.object != format!("objects/{}", object.sha256)
        || object.size == 0
        || object.size > MAX_ENTRY_BYTES
    {
        return Err(rejected());
    }
    Ok(())
}

fn validate_operation(operation: &OperationBodyV1) -> Result<(), PublishError> {
    if operation.schema_version != 1
        || operation.reverse_transfer_manifest.name != TRANSFER_MANIFEST
        || !valid_sha256(&operation.input_transfer_sha256)
        || operation.isolation_original_mode != IsolationMode::Sign
        || !matches!(
            operation.isolation_completion_mode,
            IsolationMode::Sign | IsolationMode::RecoverSign
        )
        || operation.catalog_envelope.name != CATALOG
        || !valid_sha256(&operation.catalog_payload_sha256)
        || operation.catalog_sequence == 0
        || operation.catalog_releases.is_empty()
        || operation.release_manifest.name != RELEASE_MANIFEST
        || operation.release_tag != format!("catalog-v1-sequence-{}", operation.catalog_sequence)
        || !valid_commit(&operation.source_commit)
        || !valid_sha256(&operation.source_tree_sha256)
        || !valid_sha256(&operation.qualification_sha256)
        || operation.qualification_reference
            != format!("qualification-{}.json", operation.qualification_sha256)
        || operation.checksums.name != CHECKSUMS
        || operation.support_assets.is_empty()
        || operation
            .support_assets
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        || operation.objects.is_empty()
        || operation.objects.len() > MAX_TRANSFER_ENTRIES + 1
        || operation
            .objects
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        || operation
            .prior_reference_sha256
            .as_ref()
            .is_some_and(|digest| !valid_sha256(digest))
    {
        return Err(rejected());
    }
    for release in &operation.catalog_releases {
        if release.provider.is_empty()
            || release.provider.len() > 255
            || !release.provider.is_ascii()
            || release.target != "linux_x86_64"
            || release.version.is_empty()
            || release.version.len() > 255
            || !release.version.is_ascii()
        {
            return Err(rejected());
        }
    }
    for object in std::iter::once(&operation.reverse_transfer_manifest)
        .chain([
            &operation.catalog_envelope,
            &operation.release_manifest,
            &operation.checksums,
        ])
        .chain(operation.support_assets.iter())
        .chain(operation.objects.iter())
    {
        validate_local_object(object)?;
    }
    let mut expected_objects = std::iter::once(operation.reverse_transfer_manifest.clone())
        .chain([
            operation.catalog_envelope.clone(),
            operation.release_manifest.clone(),
            operation.checksums.clone(),
        ])
        .chain(operation.support_assets.iter().cloned())
        .collect::<Vec<_>>();
    expected_objects.sort_by(|left, right| left.name.cmp(&right.name));
    if expected_objects != operation.objects
        || !operation
            .support_assets
            .iter()
            .any(|asset| asset.name == operation.qualification_reference)
    {
        return Err(rejected());
    }
    Ok(())
}

fn verify_record_objects(
    state: &StateCapabilities,
    operation: &OperationBodyV1,
) -> Result<BTreeMap<String, RetainedFile>, PublishError> {
    validate_recovery_inventory(operation, state.limits)?;
    let mut cumulative_bytes = 0_u64;
    let mut retained = BTreeMap::new();
    for object in &operation.objects {
        let file = open_regular_at(&state.objects, &object.sha256)?;
        let metadata = file.metadata().map_err(|_| rejected())?;
        if !secure_file(&metadata) || metadata.len() != object.size {
            return Err(rejected());
        }
        cumulative_bytes = bounded_add(
            cumulative_bytes,
            metadata.len(),
            state.limits.maximum_cumulative_bytes,
        )?;
        if hash_descriptor(&file, object.size)? != object.sha256 {
            return Err(rejected());
        }
        if retained
            .insert(
                object.name.clone(),
                RetainedFile {
                    name: object.name.clone(),
                    identity: FileIdentity::from_metadata(&metadata),
                    size: object.size,
                    sha256: object.sha256.clone(),
                    file,
                },
            )
            .is_some()
        {
            return Err(rejected());
        }
    }
    Ok(retained)
}

fn verify_persisted_retained(
    state: &StateCapabilities,
    retained: &BTreeMap<String, RetainedFile>,
) -> Result<(), PublishError> {
    for file in retained.values() {
        let before = file.file.metadata().map_err(|_| rejected())?;
        let rebound = open_regular_at(&state.objects, &file.sha256)?;
        let rebound_metadata = rebound.metadata().map_err(|_| rejected())?;
        if !secure_file(&before)
            || !secure_file(&rebound_metadata)
            || FileIdentity::from_metadata(&before) != file.identity
            || FileIdentity::from_metadata(&rebound_metadata) != file.identity
            || before.len() != file.size
            || hash_descriptor(&rebound, file.size)? != file.sha256
        {
            return Err(rejected());
        }
    }
    Ok(())
}

fn verify_operation(
    state: &StateCapabilities,
    operation: &OperationBodyV1,
    policy: VerificationPolicy,
) -> Result<(), PublishError> {
    validate_operation(operation)?;
    let mut retained = verify_record_objects(state, operation)?;
    let reverse = retained.remove(TRANSFER_MANIFEST).ok_or_else(rejected)?;
    let reverse_bytes = read_descriptor(&reverse.file, reverse.size)?;
    if sha256(&reverse_bytes) != operation.reverse_transfer_manifest.sha256 {
        return Err(rejected());
    }
    let manifest: ReverseTransferManifestV1 =
        serde_json::from_slice(&reverse_bytes).map_err(|_| rejected())?;
    if serde_jcs::to_vec(&manifest).map_err(|_| rejected())? != reverse_bytes {
        return Err(rejected());
    }
    validate_reverse_manifest(&manifest)?;
    if manifest.input_transfer_sha256 != operation.input_transfer_sha256
        || manifest.isolation_attestation.original_operation_mode
            != operation.isolation_original_mode
        || manifest.isolation_attestation.mode != operation.isolation_completion_mode
        || manifest.entries.len() != retained.len()
    {
        return Err(rejected());
    }
    for (entry, object) in manifest.entries.iter().zip(retained.values()) {
        if entry.relative_path != format!("signed-release-bundle/{}", object.name)
            || entry.mode != "0400"
            || entry.size != object.size
            || entry.sha256 != object.sha256
        {
            return Err(rejected());
        }
    }

    let catalog_file = retained.get(CATALOG).ok_or_else(rejected)?;
    let release_file = retained.get(RELEASE_MANIFEST).ok_or_else(rejected)?;
    let checksums_file = retained.get(CHECKSUMS).ok_or_else(rejected)?;
    let catalog_bytes = read_descriptor(&catalog_file.file, catalog_file.size)?;
    let release_bytes = read_descriptor(&release_file.file, release_file.size)?;
    let checksums_bytes = read_descriptor(&checksums_file.file, checksums_file.size)?;
    let catalog = verify_catalog_with_policy(&catalog_bytes, policy)?;
    let release = verify_release_manifest_with_policy(&release_bytes, policy)?;
    let release_manifest = release.manifest();
    let inventory_entries = retained
        .values()
        .map(|file| {
            serde_json::json!({
                "relative_path": file.name,
                "mode": "0400",
                "size": file.size,
                "sha256": file.sha256,
            })
        })
        .collect::<Vec<_>>();
    let inventory = BundleInventoryV1::from_json(
        &serde_jcs::to_vec(&serde_json::json!({
            "schema_version": 1,
            "kind": "signed_release",
            "entries": inventory_entries,
        }))
        .map_err(|_| rejected())?,
    )
    .map_err(|_| rejected())?;
    verify_signed_release_inventory(&inventory, release_manifest).map_err(|_| rejected())?;
    verify_release_bindings(&retained, release_manifest, &checksums_bytes)?;

    let actual_support_assets = release_manifest
        .assets()
        .iter()
        .map(|asset| {
            retained
                .get(asset.name().as_str())
                .map(VerifiedTransferredSignedBundle::object_from_retained)
                .ok_or_else(rejected)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if encode_hex(catalog.payload_sha256()) != operation.catalog_payload_sha256
        || catalog.payload().sequence().get() != operation.catalog_sequence
        || catalog_release_bindings(catalog.payload())? != operation.catalog_releases
        || operation.catalog_envelope
            != VerifiedTransferredSignedBundle::object_from_retained(catalog_file)
        || operation.release_manifest
            != VerifiedTransferredSignedBundle::object_from_retained(release_file)
        || operation.checksums
            != VerifiedTransferredSignedBundle::object_from_retained(checksums_file)
        || release_manifest.tag().as_str() != operation.release_tag
        || release_manifest.source_commit().as_str() != operation.source_commit
        || release_manifest.source_tree_sha256().as_str() != operation.source_tree_sha256
        || release_manifest.qualification_sha256().as_str() != operation.qualification_sha256
        || actual_support_assets != operation.support_assets
    {
        return Err(rejected());
    }
    retained.insert(TRANSFER_MANIFEST.to_owned(), reverse);
    verify_persisted_retained(state, &retained)?;
    state.revalidate()?;
    Ok(())
}

fn verify_recovery_relation(
    state: &StateCapabilities,
    record: &RecoveryRecordV1,
    intended_bytes: &[u8],
    policy: VerificationPolicy,
) -> Result<(), PublishError> {
    let record_bytes =
        read_optional_state_file(&state.latest, RECOVERY_RECORD, MAX_STATE_RECORD_BYTES, true)?
            .ok_or_else(rejected)?;
    if parse_recovery_record(&record_bytes, state.limits)? != *record {
        return Err(rejected());
    }
    let latest =
        read_optional_state_file(&state.latest, LATEST_REFERENCE, MAX_REFERENCE_BYTES, false)?
            .ok_or_else(rejected)?;
    if latest != intended_bytes {
        return Err(rejected());
    }
    verify_operation(state, &record.operation, policy)?;
    verify_local_reference(state, &record.intended_reference, policy)
}

fn verify_exact_prior(
    state: &StateCapabilities,
    record: &RecoveryRecordV1,
    prior_bytes: &Option<Vec<u8>>,
    policy: VerificationPolicy,
) -> Result<(), PublishError> {
    let current =
        read_optional_state_file(&state.latest, LATEST_REFERENCE, MAX_REFERENCE_BYTES, false)
            .map_err(|_| uncertain())?;
    if current != *prior_bytes {
        return Err(uncertain());
    }
    if let Some(prior) = &record.prior_reference {
        verify_local_reference(state, prior, policy).map_err(|_| uncertain())?;
    }
    Ok(())
}

fn verify_bound_latest_temporary(
    state: &StateCapabilities,
    operation: &OperationBodyV1,
    intended_bytes: &[u8],
) -> Result<fs::File, PublishError> {
    let file = open_regular_at(&state.latest, LATEST_TEMP)?;
    let metadata = file.metadata().map_err(|_| rejected())?;
    if !secure_file(&metadata)
        || FileIdentity::from_metadata(&metadata) != operation.latest_temporary_identity
        || metadata.len() != intended_bytes.len() as u64
        || read_descriptor(&file, metadata.len())? != intended_bytes
        || hash_descriptor(&file, metadata.len())? != sha256(intended_bytes)
    {
        return Err(rejected());
    }
    let rebound = open_regular_at(&state.latest, LATEST_TEMP)?;
    let rebound_metadata = rebound.metadata().map_err(|_| rejected())?;
    if !secure_file(&rebound_metadata)
        || FileIdentity::from_metadata(&rebound_metadata) != operation.latest_temporary_identity
        || FileIdentity::from_metadata(&rebound_metadata) != FileIdentity::from_metadata(&metadata)
    {
        return Err(rejected());
    }
    Ok(file)
}

fn unlink_bound_latest_temporary(
    state: &StateCapabilities,
    retained: &fs::File,
    operation: &OperationBodyV1,
    intended_bytes: &[u8],
) -> Result<(), PublishError> {
    let rebound = verify_bound_latest_temporary(state, operation, intended_bytes)
        .map_err(|_| recovery_required())?;
    let retained_metadata = retained.metadata().map_err(|_| recovery_required())?;
    let rebound_metadata = rebound.metadata().map_err(|_| recovery_required())?;
    if FileIdentity::from_metadata(&retained_metadata) != operation.latest_temporary_identity
        || FileIdentity::from_metadata(&rebound_metadata) != operation.latest_temporary_identity
    {
        return Err(recovery_required());
    }
    unlink_name(&state.latest, LATEST_TEMP).map_err(|_| recovery_required())
}

fn cleanup_recovery_record(
    state: &StateCapabilities,
    transaction: &TransactionGuard,
) -> Result<(), PublishError> {
    let marker = open_regular_at(&state.latest, RECOVERY_RECORD)?;
    let metadata = marker.metadata().map_err(|_| rejected())?;
    if FileIdentity::from_metadata(&metadata) != transaction.identity
        || FileIdentity::from_metadata(&transaction.file.metadata().map_err(|_| rejected())?)
            != transaction.identity
    {
        return Err(rejected());
    }
    if name_exists(&state.latest, RECOVERY_TEMP)? {
        let temporary = open_regular_at(&state.latest, RECOVERY_TEMP)?;
        let metadata = temporary.metadata().map_err(|_| rejected())?;
        if FileIdentity::from_metadata(&metadata) != transaction.identity {
            return Err(rejected());
        }
        unlink_name(&state.latest, RECOVERY_TEMP)?;
        state.latest.sync_all().map_err(|_| rejected())?;
    }
    let marker = open_regular_at(&state.latest, RECOVERY_RECORD)?;
    let metadata = marker.metadata().map_err(|_| rejected())?;
    if FileIdentity::from_metadata(&metadata) != transaction.identity || metadata.nlink() != 1 {
        return Err(rejected());
    }
    unlink_name(&state.latest, RECOVERY_RECORD)?;
    state.latest.sync_all().map_err(|_| rejected())
}

fn parse_reference(bytes: &[u8]) -> Result<LocalCatalogReferenceV1, PublishError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_REFERENCE_BYTES {
        return Err(rejected());
    }
    let reference: LocalCatalogReferenceV1 =
        serde_json::from_slice(bytes).map_err(|_| rejected())?;
    if serde_jcs::to_vec(&reference).map_err(|_| rejected())? != bytes {
        return Err(rejected());
    }
    validate_reference(&reference)?;
    Ok(reference)
}

fn validate_reference(reference: &LocalCatalogReferenceV1) -> Result<(), PublishError> {
    if reference.schema_version != 1
        || !valid_sha256(&reference.operation_id)
        || operation_id(&reference.operation)? != reference.operation_id
    {
        return Err(rejected());
    }
    validate_operation(&reference.operation)
}

fn verify_local_reference(
    state: &StateCapabilities,
    reference: &LocalCatalogReferenceV1,
    policy: VerificationPolicy,
) -> Result<(), PublishError> {
    validate_reference(reference)?;
    let expected = serde_jcs::to_vec(reference).map_err(|_| rejected())?;
    let file = open_regular_at(&state.latest, LATEST_REFERENCE)?;
    let metadata = file.metadata().map_err(|_| rejected())?;
    if !secure_file(&metadata)
        || FileIdentity::from_metadata(&metadata) != reference.operation.latest_temporary_identity
        || metadata.len() != expected.len() as u64
        || read_descriptor(&file, metadata.len())? != expected
    {
        return Err(rejected());
    }
    verify_operation(state, &reference.operation, policy)
}

fn publish_or_reuse_object(objects: &fs::File, source: &RetainedFile) -> Result<(), PublishError> {
    if name_exists(objects, &source.sha256)? {
        let existing = open_regular_at(objects, &source.sha256)?;
        let metadata = existing.metadata().map_err(|_| rejected())?;
        if !secure_file(&metadata)
            || metadata.len() != source.size
            || hash_descriptor(&existing, source.size)? != source.sha256
        {
            return Err(rejected());
        }
        objects.sync_all().map_err(|_| rejected())?;
        return Ok(());
    }
    let mut output = open_unnamed(objects, 0o600)?;
    let before = source.file.metadata().map_err(|_| rejected())?;
    if !secure_file(&before)
        || before.len() != source.size
        || FileIdentity::from_metadata(&before) != source.identity
    {
        return Err(rejected());
    }
    let mut input = source.file.try_clone().map_err(|_| rejected())?;
    input.seek(SeekFrom::Start(0)).map_err(|_| rejected())?;
    let mut total = 0_u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let count = input.read(&mut buffer).map_err(|_| rejected())?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or_else(rejected)?;
        if total > source.size {
            return Err(rejected());
        }
        hasher.update(&buffer[..count]);
        output.write_all(&buffer[..count]).map_err(|_| rejected())?;
    }
    let after = source.file.metadata().map_err(|_| rejected())?;
    if total != source.size
        || format!("{:x}", hasher.finalize()) != source.sha256
        || FileIdentity::from_metadata(&after) != source.identity
        || after.len() != source.size
    {
        return Err(rejected());
    }
    output.flush().map_err(|_| rejected())?;
    output
        .set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(|_| rejected())?;
    output.sync_all().map_err(|_| rejected())?;
    let output_metadata = output.metadata().map_err(|_| rejected())?;
    if !secure_file_allow_links(&output_metadata, 0)
        || output_metadata.len() != source.size
        || hash_descriptor(&output, source.size)? != source.sha256
    {
        return Err(rejected());
    }
    link_unnamed(&output, objects, &source.sha256)?;
    objects.sync_all().map_err(|_| rejected())?;
    let rebound = open_regular_at(objects, &source.sha256)?;
    let metadata = rebound.metadata().map_err(|_| rejected())?;
    if FileIdentity::from_metadata(&metadata) != FileIdentity::from_metadata(&output_metadata)
        || !secure_file(&metadata)
        || hash_descriptor(&rebound, source.size)? != source.sha256
    {
        return Err(rejected());
    }
    Ok(())
}

fn prepare_state(
    path: &Path,
    limits: PersistentStateLimits,
    plan: &TestPlan,
) -> Result<StateCapabilities, PublishError> {
    let (parent, name) = open_absolute_parent(path)?;
    let existed = name_exists(&parent, &name)?;
    if !existed {
        let component = CString::new(name.as_bytes()).map_err(|_| rejected())?;
        // SAFETY: retained parent and validated final component are valid.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o700) } != 0 {
            return Err(rejected());
        }
        parent.sync_all().map_err(|_| rejected())?;
    }
    let root = open_directory_at_os(&parent, std::ffi::OsStr::new(&name))?;
    if existed {
        let existing_names = validate_existing_state_layout(&root)?;
        if existing_names.len() != 2 {
            pause_at(plan, StateBoundary::BeforeChildCreation)?;
        }
    }
    ensure_state_child(&root, "objects")?;
    ensure_state_child(&root, "latest")?;
    state_from_root(parent, name, root, limits)
}

fn open_existing_state(path: &Path) -> Result<StateCapabilities, PublishError> {
    let (parent, name) = open_absolute_parent(path)?;
    let root = open_directory_at_os(&parent, std::ffi::OsStr::new(&name))?;
    state_from_root(parent, name, root, PERSISTENT_STATE_LIMITS)
}

fn validate_existing_state_layout(root: &fs::File) -> Result<BTreeSet<String>, PublishError> {
    let root_metadata = root.metadata().map_err(|_| rejected())?;
    if !secure_directory(&root_metadata) {
        return Err(rejected());
    }
    let names = enumerate_names(root, STATE_ROOT_ENUMERATION_LIMITS)?;
    let allowed = BTreeSet::from(["latest".to_owned(), "objects".to_owned()]);
    if !names.is_subset(&allowed) {
        return Err(rejected());
    }
    for name in &names {
        validate_state_child(root, name)?;
    }
    if root_metadata.nlink() != 2 + names.len() as u64 {
        return Err(rejected());
    }
    Ok(names)
}

fn state_from_root(
    parent: fs::File,
    root_name: String,
    root: fs::File,
    limits: PersistentStateLimits,
) -> Result<StateCapabilities, PublishError> {
    let root_metadata = root.metadata().map_err(|_| rejected())?;
    if !secure_directory(&root_metadata) || root_metadata.nlink() != 4 {
        return Err(rejected());
    }
    if enumerate_names(&root, STATE_ROOT_ENUMERATION_LIMITS)?
        != BTreeSet::from(["latest".to_owned(), "objects".to_owned()])
    {
        return Err(rejected());
    }
    let objects = open_directory_at(&root, "objects")?;
    let latest = open_directory_at(&root, "latest")?;
    let objects_metadata = objects.metadata().map_err(|_| rejected())?;
    let latest_metadata = latest.metadata().map_err(|_| rejected())?;
    if !secure_directory(&objects_metadata)
        || objects_metadata.nlink() != 2
        || !secure_directory(&latest_metadata)
        || latest_metadata.nlink() != 2
    {
        return Err(rejected());
    }
    Ok(StateCapabilities {
        parent,
        root_name,
        root_identity: FileIdentity::from_metadata(&root_metadata),
        objects_identity: FileIdentity::from_metadata(&objects_metadata),
        latest_identity: FileIdentity::from_metadata(&latest_metadata),
        root,
        objects,
        latest,
        limits,
    })
}

fn ensure_state_child(root: &fs::File, name: &str) -> Result<(), PublishError> {
    if !name_exists(root, name)? {
        let component = CString::new(name).expect("fixed state directory");
        // SAFETY: retained parent and fixed component are valid. EEXIST is revalidated below.
        if unsafe { libc::mkdirat(root.as_raw_fd(), component.as_ptr(), 0o700) } != 0
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
        {
            return Err(rejected());
        }
        root.sync_all().map_err(|_| rejected())?;
    }
    validate_state_child(root, name)
}

fn validate_state_child(root: &fs::File, name: &str) -> Result<(), PublishError> {
    let child = open_directory_at(root, name)?;
    let metadata = child.metadata().map_err(|_| rejected())?;
    if !secure_directory(&metadata) || metadata.nlink() != 2 {
        return Err(rejected());
    }
    Ok(())
}

fn open_absolute_parent(path: &Path) -> Result<(fs::File, String), PublishError> {
    validate_absolute_path(path)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| safe_component(name))
        .ok_or_else(rejected)?
        .to_owned();
    let parent = path.parent().ok_or_else(rejected)?;
    Ok((open_absolute_directory(parent)?, name))
}

fn open_absolute_directory(path: &Path) -> Result<fs::File, PublishError> {
    validate_absolute_path(path)?;
    let mut directory = fs::File::open("/").map_err(|_| rejected())?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(component) => {
                directory = open_directory_at_os(&directory, component)?;
            }
            _ => return Err(rejected()),
        }
    }
    Ok(directory)
}

fn validate_absolute_path(path: &Path) -> Result<(), PublishError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || bytes.is_empty()
        || bytes.len() > MAX_PATH_BYTES
        || bytes.contains(&0)
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(rejected());
    }
    Ok(())
}

fn open_directory_at(parent: &fs::File, name: &str) -> Result<fs::File, PublishError> {
    if !safe_component(name) {
        return Err(rejected());
    }
    open_directory_at_os(parent, std::ffi::OsStr::new(name))
}

fn open_directory_at_os(
    parent: &fs::File,
    name: &std::ffi::OsStr,
) -> Result<fs::File, PublishError> {
    let name = CString::new(name.as_bytes()).map_err(|_| rejected())?;
    openat2(
        parent.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0x02 | 0x04 | 0x08,
    )
}

fn open_regular_at(parent: &fs::File, name: &str) -> Result<fs::File, PublishError> {
    if !safe_component(name) {
        return Err(rejected());
    }
    let name = CString::new(name).map_err(|_| rejected())?;
    openat2(
        parent.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0x02 | 0x04 | 0x08,
    )
}

fn openat2(
    directory: i32,
    name: &CString,
    flags: i32,
    resolve: u64,
) -> Result<fs::File, PublishError> {
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve,
    };
    // SAFETY: pointers reference initialized values for the syscall duration.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory,
            name.as_ptr(),
            &raw const how,
            std::mem::size_of::<OpenHow>(),
        )
    } as i32;
    if descriptor < 0 {
        return Err(rejected());
    }
    // SAFETY: successful openat2 returns one owned descriptor.
    Ok(unsafe { fs::File::from_raw_fd(descriptor) })
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn enumerate_names(
    directory: &fs::File,
    limits: EnumerationLimits,
) -> Result<BTreeSet<String>, PublishError> {
    let mut names = BTreeSet::new();
    stream_names_bounded(directory, limits, |name| {
        if !names.insert(name.to_owned()) {
            return Err(rejected());
        }
        Ok(())
    })?;
    Ok(names)
}

fn stream_names_bounded(
    directory: &fs::File,
    limits: EnumerationLimits,
    mut visit: impl FnMut(&str) -> Result<(), PublishError>,
) -> Result<(), PublishError> {
    // SAFETY: fcntl duplicates the retained descriptor.
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(rejected());
    }
    // SAFETY: fdopendir consumes the duplicate on success.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: fdopendir did not consume the duplicate on failure.
        let _ = unsafe { libc::close(duplicate) };
        return Err(rejected());
    }
    // SAFETY: stream is valid and thread-confined.
    unsafe { libc::rewinddir(stream) };
    let result = (|| {
        let mut entries = 0_u64;
        let mut cumulative_name_bytes = 0_u64;
        let mut work = 0_u64;
        loop {
            // SAFETY: errno is thread-local on Linux.
            unsafe { *libc::__errno_location() = 0 };
            // SAFETY: stream remains valid.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                // SAFETY: read immediately after readdir.
                if unsafe { *libc::__errno_location() } != 0 {
                    return Err(rejected());
                }
                break;
            }
            work = bounded_add(work, 1, limits.maximum_work)?;
            // SAFETY: d_name is NUL terminated.
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            entries = bounded_add(entries, 1, limits.maximum_entries)?;
            let name_bytes = u64::try_from(bytes.len()).map_err(|_| rejected())?;
            if name_bytes > limits.maximum_name_bytes {
                return Err(rejected());
            }
            cumulative_name_bytes = bounded_add(
                cumulative_name_bytes,
                name_bytes,
                limits.maximum_cumulative_name_bytes,
            )?;
            let name = std::str::from_utf8(bytes).map_err(|_| rejected())?;
            if !safe_component(name) {
                return Err(rejected());
            }
            visit(name)?;
        }
        Ok(())
    })();
    // SAFETY: closes the stream and duplicate descriptor.
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(rejected());
    }
    result
}

fn bounded_add(current: u64, amount: u64, maximum: u64) -> Result<u64, PublishError> {
    let next = current.checked_add(amount).ok_or_else(rejected)?;
    if next > maximum {
        return Err(rejected());
    }
    Ok(next)
}

fn verify_retained(parent: &fs::File, retained: &RetainedFile) -> Result<(), PublishError> {
    let before = retained.file.metadata().map_err(|_| rejected())?;
    if !secure_file(&before)
        || before.len() != retained.size
        || FileIdentity::from_metadata(&before) != retained.identity
        || hash_descriptor(&retained.file, retained.size)? != retained.sha256
    {
        return Err(rejected());
    }
    let rebound = open_regular_at(parent, &retained.name)?;
    let rebound_metadata = rebound.metadata().map_err(|_| rejected())?;
    let after = retained.file.metadata().map_err(|_| rejected())?;
    if FileIdentity::from_metadata(&after) != retained.identity
        || FileIdentity::from_metadata(&rebound_metadata) != retained.identity
        || after.len() != retained.size
        || !secure_file(&rebound_metadata)
    {
        return Err(rejected());
    }
    Ok(())
}

fn read_optional_state_file(
    parent: &fs::File,
    name: &str,
    maximum: u64,
    allow_two_links: bool,
) -> Result<Option<Vec<u8>>, PublishError> {
    if !name_exists(parent, name)? {
        return Ok(None);
    }
    let file = open_regular_at(parent, name)?;
    let metadata = file.metadata().map_err(|_| rejected())?;
    let links = if allow_two_links { 1..=2 } else { 1..=1 };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_euid()
        || !links.contains(&metadata.nlink())
        || metadata.permissions().mode() & 0o7777 != 0o400
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(rejected());
    }
    read_descriptor(&file, metadata.len()).map(Some)
}

fn read_descriptor(file: &fs::File, expected_size: u64) -> Result<Vec<u8>, PublishError> {
    let capacity = usize::try_from(expected_size).map_err(|_| rejected())?;
    let mut file = file.try_clone().map_err(|_| rejected())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| rejected())?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(expected_size + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| rejected())?;
    if bytes.len() as u64 != expected_size {
        return Err(rejected());
    }
    Ok(bytes)
}

fn hash_descriptor(file: &fs::File, expected_size: u64) -> Result<String, PublishError> {
    let mut file = file.try_clone().map_err(|_| rejected())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| rejected())?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let count = file.read(&mut buffer).map_err(|_| rejected())?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or_else(rejected)?;
        if total > expected_size {
            return Err(rejected());
        }
        hasher.update(&buffer[..count]);
    }
    if total != expected_size {
        return Err(rejected());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_unnamed_and_link(
    parent: &fs::File,
    name: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<fs::File, PublishError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_RECORD_BYTES {
        return Err(rejected());
    }
    let mut file = open_unnamed(parent, 0o600)?;
    file.write_all(bytes).map_err(|_| rejected())?;
    file.flush().map_err(|_| rejected())?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|_| rejected())?;
    file.sync_all().map_err(|_| rejected())?;
    let metadata = file.metadata().map_err(|_| rejected())?;
    if !secure_file_allow_links(&metadata, 0)
        || metadata.len() != bytes.len() as u64
        || read_descriptor(&file, metadata.len())? != bytes
    {
        return Err(rejected());
    }
    link_unnamed(&file, parent, name)?;
    parent.sync_all().map_err(|_| rejected())?;
    let rebound = open_regular_at(parent, name)?;
    let rebound_metadata = rebound.metadata().map_err(|_| rejected())?;
    if FileIdentity::from_metadata(&rebound_metadata) != FileIdentity::from_metadata(&metadata)
        || !secure_file(&rebound_metadata)
        || read_descriptor(&rebound, rebound_metadata.len())? != bytes
    {
        return Err(rejected());
    }
    Ok(file)
}

fn open_unnamed(parent: &fs::File, mode: u32) -> Result<fs::File, PublishError> {
    // SAFETY: retained directory, fixed dot path, and mode are valid for O_TMPFILE.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c".".as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            mode,
        )
    };
    if descriptor < 0 {
        return Err(rejected());
    }
    // SAFETY: openat returned one owned descriptor.
    Ok(unsafe { fs::File::from_raw_fd(descriptor) })
}

fn link_unnamed(file: &fs::File, parent: &fs::File, name: &str) -> Result<(), PublishError> {
    if !safe_component(name) {
        return Err(rejected());
    }
    let name = CString::new(name).map_err(|_| rejected())?;
    // SAFETY: AT_EMPTY_PATH links the retained unnamed inode without replacement.
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
        return Err(rejected());
    }
    Ok(())
}

fn link_exact(parent: &fs::File, existing: &str, new: &str) -> Result<(), PublishError> {
    let existing = CString::new(existing).map_err(|_| rejected())?;
    let new = CString::new(new).map_err(|_| rejected())?;
    // SAFETY: retained parent and validated fixed names are valid; linkat never replaces.
    if unsafe {
        libc::linkat(
            parent.as_raw_fd(),
            existing.as_ptr(),
            parent.as_raw_fd(),
            new.as_ptr(),
            0,
        )
    } != 0
    {
        return Err(recovery_required());
    }
    Ok(())
}

fn acquire_lock(file: &fs::File) -> Result<(), PublishError> {
    // SAFETY: flock acts only on the retained transaction descriptor.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(recovery_required());
    }
    Ok(())
}

fn name_exists(parent: &fs::File, name: &str) -> Result<bool, PublishError> {
    if !safe_component(name) {
        return Err(rejected());
    }
    let name = CString::new(name).map_err(|_| rejected())?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: retained parent, name, and output pointer are valid.
    let status = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status == 0 {
        return Ok(true);
    }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        return Ok(false);
    }
    Err(rejected())
}

fn unlink_name(parent: &fs::File, name: &str) -> Result<(), PublishError> {
    let name = CString::new(name).map_err(|_| rejected())?;
    // SAFETY: retained parent and fixed validated name are valid.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(rejected());
    }
    Ok(())
}

fn secure_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.permissions().mode() & 0o7777 == 0o700
}

fn secure_file(metadata: &fs::Metadata) -> bool {
    secure_file_allow_links(metadata, 1)
}

fn secure_file_allow_links(metadata: &fs::Metadata, links: u64) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.nlink() == links
        && metadata.permissions().mode() & 0o7777 == 0o400
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !matches!(value, "." | "..")
        && value.is_ascii()
        && !value.contains(['/', '\\'])
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn safe_asset_name(value: &str) -> bool {
    safe_component(value) && !value.bytes().any(|byte| byte.is_ascii_whitespace())
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

fn valid_namespace(value: &str, expected_kind: &str) -> bool {
    value
        .split_once(":[")
        .and_then(|(kind, inode)| inode.strip_suffix(']').map(|inode| (kind, inode)))
        .is_some_and(|(kind, inode)| {
            kind == expected_kind
                && !inode.is_empty()
                && inode.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod persistent_arithmetic_tests {
    use super::{bounded_add, rejected};

    #[test]
    fn persistent_budget_checked_arithmetic_rejects_overflow_and_limit_crossing() {
        assert_eq!(bounded_add(u64::MAX, 1, u64::MAX), Err(rejected()));
        assert_eq!(bounded_add(2, 1, 2), Err(rejected()));
        assert_eq!(bounded_add(1, 1, 2), Ok(2));
    }
}
