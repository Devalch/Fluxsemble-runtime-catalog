use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CStr, CString},
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
};

use catalog_core::{
    BundleInventoryV1, CatalogPayloadV1, CatalogSourceV1, CompatibilityQualificationV1,
    InitialPiReleaseIntentV1, InputSourceKind, ProviderExtensionV1, SignedReleaseBundleManifestV1,
    VerifiedInputBundleV1, canonical_catalog_payload, catalog_source_digest,
    compatibility_input_digest, initial_release_intent_digest, production_key_identity,
    qualification_record_digest, release_bundle_signing_bytes, verify_qualification,
    verify_signed_catalog, verify_signed_release_bundle_manifest, verify_signed_release_inventory,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{SignError, is_absolute_bounded_path, key::read_production_signing_key};

const VERIFIED_INPUT_NAME: &str = "verified-input-bundle-v1.json";
const TRANSFER_MANIFEST_NAME: &str = "transfer-manifest-v1.json";
const CATALOG_NAME: &str = "catalog-v1.json";
const CHECKSUMS_NAME: &str = "checksums-sha256.txt";
const RELEASE_MANIFEST_NAME: &str = "signed-release-bundle-manifest-v1.json";
const RECOVERY_BINDING_NAME: &str = "sign-recovery-binding-v1.json";
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 32_768;
const MAX_ARGUMENTS: usize = 7;
const MAX_ARGUMENT_BYTES: usize = 16 * 1024;
const INTENT_SEMANTICS_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-intent-semantics:v1\0";
const APPROVED_PACKAGE_INPUT_DOMAIN: &[u8] =
    b"fluxsemble:runtime-catalog-approved-package-input-manifest:v1\0";
const APPROVED_RELEASE_SEMANTIC_DOMAIN: &[u8] =
    b"fluxsemble:runtime-catalog-approved-release-semantics:v1\0";
// These compiled digests are independently rederived from the committed public evidence fixtures
// in tests. Production admission reads no fixture and has no external repository dependency.
const APPROVED_PACKAGE_INPUT_DOMAIN_SHA256: &str =
    "04ff8560de163983621e86598c8eb6b80fabb32cfced020602c14ed45818f9ef";
const APPROVED_RELEASE_SEMANTIC_SHA256: &str =
    "46116101d1ffa3b1184d14347f62478fbc3a2d609afc3ba0bf6b2505265e8441";
const ROOT_NAME: &str = "@earendil-works/pi-coding-agent";
const ROOT_VERSION: &str = "0.83.0";
const ROOT_ARTIFACT_URL: &str =
    "https://registry.npmjs.org/@earendil-works/pi-coding-agent/-/pi-coding-agent-0.83.0.tgz";
const ROOT_ARTIFACT_SIZE: u64 = 4_992_066;
const ROOT_ARTIFACT_SHA256: &str =
    "7097fe4b38762dda7ec78001e7b90430c849fbaf717325bfe8109744e32255e6";
const ROOT_REGISTRY_INTEGRITY: &str = "sha512-uYhF+FsZxogoSX/AxBcUdiY+ZklubwaXyAoEGA2eQwsHcyEAhUYIKh/WLXe/a8+k8eTCmxb+ZN2Zo9mzQtzbWw==";
const ROOT_MANIFEST_SIZE: u64 = 3_560;
const ROOT_MANIFEST_SHA256: &str =
    "e02deae1cec07035807436c1864c88342e2f7d49050d03b858a3719f0c7aedbf";
const SHRINKWRAP_SIZE: u64 = 61_540;
const SHRINKWRAP_SHA256: &str = "9a17a6b9ba0a57b37773644f7945b1bf0bc10aa8923b87233fee6f75af1e1772";
const NODE_VERSION: &str = "22.19.0";
const NODE_ARTIFACT_URL: &str = "https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.xz";
const NODE_ARTIFACT_SIZE: u64 = 30_479_988;
const NODE_ARTIFACT_SHA256: &str =
    "c0649af18e6a24f6fe5535a3e86b341dd49a8e71117c8b68bde973ef834f16f2";
const LOCKED_COUNT: usize = 139;
const PRE_PRUNE_COUNT: u16 = 131;
const APPLICABLE_COUNT: u16 = 130;

const PRUNED: [(&str, &[&str]); 9] = [
    (
        "node_modules/@mariozechner/clipboard-darwin-arm64",
        &["declaration.cpu", "declaration.os", "lock.cpu", "lock.os"],
    ),
    (
        "node_modules/@mariozechner/clipboard-darwin-universal",
        &["declaration.os", "lock.os"],
    ),
    (
        "node_modules/@mariozechner/clipboard-darwin-x64",
        &["declaration.os", "lock.os"],
    ),
    (
        "node_modules/@mariozechner/clipboard-linux-arm64-gnu",
        &["declaration.cpu", "lock.cpu"],
    ),
    (
        "node_modules/@mariozechner/clipboard-linux-arm64-musl",
        &["declaration.cpu", "declaration.libc", "lock.cpu"],
    ),
    (
        "node_modules/@mariozechner/clipboard-linux-riscv64-gnu",
        &["declaration.cpu", "lock.cpu"],
    ),
    (
        "node_modules/@mariozechner/clipboard-linux-x64-musl",
        &["declaration.libc"],
    ),
    (
        "node_modules/@mariozechner/clipboard-win32-arm64-msvc",
        &["declaration.cpu", "declaration.os", "lock.cpu", "lock.os"],
    ),
    (
        "node_modules/@mariozechner/clipboard-win32-x64-msvc",
        &["declaration.os", "lock.os"],
    ),
];

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

struct RetainedDirectory {
    identity: FileIdentity,
    names: BTreeSet<String>,
    file: fs::File,
}

struct RetainedFile {
    entry: TransferEntry,
    file: fs::File,
    identity: FileIdentity,
}

/// A transferred acquisition bundle independently reopened by the signer.
pub struct VerifiedTransferredBundle {
    root: fs::File,
    root_identity: FileIdentity,
    root_names: BTreeSet<String>,
    directories: BTreeMap<String, RetainedDirectory>,
    files: BTreeMap<String, RetainedFile>,
    manifest: TransferManifestV1,
    inventory: VerifiedInputBundleV1,
}

impl std::fmt::Debug for VerifiedTransferredBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedTransferredBundle")
            .field("source_kind", &self.inventory.source_kind())
            .field("objects", &self.inventory.objects().len())
            .finish_non_exhaustive()
    }
}

impl VerifiedTransferredBundle {
    #[must_use]
    pub fn inventory(&self) -> &VerifiedInputBundleV1 {
        &self.inventory
    }

    #[must_use]
    pub fn source_commit(&self) -> Option<&str> {
        self.manifest.source_commit.as_deref()
    }

    #[must_use]
    pub fn source_tree_sha256(&self) -> Option<&str> {
        self.manifest.source_tree_sha256.as_deref()
    }

    #[must_use]
    pub(crate) fn transfer_manifest_sha256(&self) -> &str {
        &self
            .files
            .get(TRANSFER_MANIFEST_NAME)
            .expect("verified transfer retains its manifest")
            .entry
            .sha256
    }

    /// Revalidates the retained transfer and duplicates its exact root for the audited launcher.
    pub fn isolated_launch_capability(&self) -> Result<(fs::File, String), SignError> {
        self.reverify_all()?;
        // SAFETY: fcntl duplicates the retained root and keeps it close-on-exec until the launcher
        // has completed every substitution checkpoint.
        let descriptor = unsafe { libc::fcntl(self.root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if descriptor < 0 {
            return Err(bundle_rejected());
        }
        // SAFETY: F_DUPFD_CLOEXEC returned one newly owned descriptor.
        let root = unsafe { fs::File::from_raw_fd(descriptor) };
        let manifest = self
            .files
            .get(TRANSFER_MANIFEST_NAME)
            .ok_or_else(bundle_rejected)?;
        Ok((root, manifest.entry.sha256.clone()))
    }

    fn record_bytes(&self, role: &str) -> Result<Vec<u8>, SignError> {
        let record = self
            .manifest
            .records
            .iter()
            .find(|record| record.role == role)
            .ok_or_else(bundle_rejected)?;
        self.read_small_file(&record.relative_path)
    }

    fn read_small_file(&self, relative: &str) -> Result<Vec<u8>, SignError> {
        let retained = self.files.get(relative).ok_or_else(bundle_rejected)?;
        if retained.entry.size > MAX_MANIFEST_BYTES {
            return Err(bundle_rejected());
        }
        verify_retained_file(self, retained)?;
        let mut file = retained.file.try_clone().map_err(|_| bundle_rejected())?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| bundle_rejected())?;
        let mut bytes = Vec::with_capacity(retained.entry.size as usize);
        (&mut file)
            .take(retained.entry.size + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| bundle_rejected())?;
        if bytes.len() as u64 != retained.entry.size || sha256(&bytes) != retained.entry.sha256 {
            return Err(bundle_rejected());
        }
        Ok(bytes)
    }

    fn reverify_all(&self) -> Result<(), SignError> {
        verify_root_binding(self)?;
        for retained in self.files.values() {
            verify_retained_file(self, retained)?;
        }
        verify_root_binding(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateAsset {
    name: String,
    bytes: Vec<u8>,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FinalBindings {
    source_commit: String,
    source_tree_sha256: String,
    qualification_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedBundleEntryV1 {
    name: String,
    size: u64,
    sha256: String,
}

impl UnsignedBundleEntryV1 {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Fully assembled unsigned bytes. Intent candidates deliberately have no final bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedReleaseCandidateV1 {
    canonical_payload: Vec<u8>,
    runtime_semantic_sha256: String,
    tag: String,
    support_assets: Vec<CandidateAsset>,
    final_bindings: Option<FinalBindings>,
}

impl UnsignedReleaseCandidateV1 {
    #[must_use]
    pub fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }

    #[must_use]
    pub fn runtime_semantic_sha256(&self) -> &str {
        &self.runtime_semantic_sha256
    }

    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    #[must_use]
    pub const fn is_production_signable(&self) -> bool {
        self.final_bindings.is_some()
    }

    #[must_use]
    pub fn support_asset_names(&self) -> Vec<&str> {
        self.support_assets
            .iter()
            .map(|asset| asset.name.as_str())
            .collect()
    }

    #[must_use]
    pub fn unsigned_inventory(&self) -> Vec<UnsignedBundleEntryV1> {
        let mut entries = self
            .support_assets
            .iter()
            .map(|asset| UnsignedBundleEntryV1 {
                name: asset.name.clone(),
                size: asset.bytes.len() as u64,
                sha256: asset.sha256.clone(),
            })
            .collect::<Vec<_>>();
        entries.push(UnsignedBundleEntryV1 {
            name: "catalog-v1-payload.json".to_owned(),
            size: self.canonical_payload.len() as u64,
            sha256: sha256(&self.canonical_payload),
        });
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        entries
    }
}

struct SignReleaseRequest<'a> {
    pub bundle: &'a VerifiedTransferredBundle,
    pub source: &'a CatalogSourceV1,
    pub qualification: &'a CompatibilityQualificationV1,
    pub key_path: &'a Path,
    pub output: &'a Path,
}

#[derive(Debug)]
pub struct SignedReleaseBundleV1 {
    output: PathBuf,
    inventory: BundleInventoryV1,
    manifest: SignedReleaseBundleManifestV1,
}

impl SignedReleaseBundleV1 {
    #[must_use]
    pub fn output(&self) -> &Path {
        &self.output
    }

    #[must_use]
    pub fn inventory(&self) -> &BundleInventoryV1 {
        &self.inventory
    }

    #[must_use]
    pub fn manifest(&self) -> &SignedReleaseBundleManifestV1 {
        &self.manifest
    }
}

pub fn verify_transferred_bundle(path: &Path) -> Result<VerifiedTransferredBundle, SignError> {
    if !is_absolute_bounded_path(path) {
        return Err(bundle_rejected());
    }
    let root = open_absolute_directory(path)?;
    let root_metadata = root.metadata().map_err(|_| bundle_rejected())?;
    if !secure_directory(&root_metadata) || root_metadata.nlink() != 4 {
        return Err(bundle_rejected());
    }
    let root_identity = FileIdentity::from_metadata(&root_metadata);
    let root_names = enumerate_names(&root)?;
    if root_names
        != BTreeSet::from([
            "objects".to_owned(),
            "records".to_owned(),
            TRANSFER_MANIFEST_NAME.to_owned(),
            VERIFIED_INPUT_NAME.to_owned(),
        ])
    {
        return Err(bundle_rejected());
    }

    let mut directories = BTreeMap::new();
    for name in ["objects", "records"] {
        let directory = open_directory_at(&root, name)?;
        let metadata = directory.metadata().map_err(|_| bundle_rejected())?;
        if !secure_directory(&metadata) || metadata.nlink() != 2 {
            return Err(bundle_rejected());
        }
        directories.insert(
            name.to_owned(),
            RetainedDirectory {
                identity: FileIdentity::from_metadata(&metadata),
                names: enumerate_names(&directory)?,
                file: directory,
            },
        );
    }

    let manifest_file = open_regular_at(&root, TRANSFER_MANIFEST_NAME)?;
    let manifest_metadata = manifest_file.metadata().map_err(|_| bundle_rejected())?;
    if !secure_file(&manifest_metadata)
        || manifest_metadata.len() == 0
        || manifest_metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err(bundle_rejected());
    }
    let manifest_entry = TransferEntry {
        relative_path: TRANSFER_MANIFEST_NAME.to_owned(),
        mode: "0400".to_owned(),
        size: manifest_metadata.len(),
        sha256: hash_file(&manifest_file, manifest_metadata.len())?,
    };
    let manifest_bytes = read_small_descriptor(&manifest_file, manifest_metadata.len())?;
    let manifest: TransferManifestV1 =
        serde_json::from_slice(&manifest_bytes).map_err(|_| bundle_rejected())?;
    if serde_jcs::to_vec(&manifest).map_err(|_| bundle_rejected())? != manifest_bytes {
        return Err(bundle_rejected());
    }
    validate_transfer_manifest(&manifest)?;

    let expected_paths = manifest
        .entries
        .iter()
        .map(|entry| entry.relative_path.clone())
        .chain(std::iter::once(TRANSFER_MANIFEST_NAME.to_owned()))
        .collect::<BTreeSet<_>>();
    let actual_paths = flatten_tree(&root_names, &directories)?;
    if actual_paths != expected_paths {
        return Err(bundle_rejected());
    }

    let mut files = BTreeMap::new();
    for entry in &manifest.entries {
        let (parent, name) = parent_and_name(&root, &directories, &entry.relative_path)?;
        let file = open_regular_at(parent, name)?;
        let metadata = file.metadata().map_err(|_| bundle_rejected())?;
        if !secure_file(&metadata) || metadata.len() != entry.size {
            return Err(bundle_rejected());
        }
        if hash_file(&file, entry.size)? != entry.sha256 {
            return Err(bundle_rejected());
        }
        files.insert(
            entry.relative_path.clone(),
            RetainedFile {
                entry: entry.clone(),
                file,
                identity: FileIdentity::from_metadata(&metadata),
            },
        );
    }
    files.insert(
        TRANSFER_MANIFEST_NAME.to_owned(),
        RetainedFile {
            entry: manifest_entry,
            identity: FileIdentity::from_metadata(&manifest_metadata),
            file: manifest_file,
        },
    );

    let inventory_file = files.get(VERIFIED_INPUT_NAME).ok_or_else(bundle_rejected)?;
    let inventory_bytes = read_small_retained(inventory_file)?;
    let inventory =
        VerifiedInputBundleV1::from_json(&inventory_bytes).map_err(|_| bundle_rejected())?;
    if serde_jcs::to_vec(&inventory).map_err(|_| bundle_rejected())? != inventory_bytes {
        return Err(bundle_rejected());
    }
    cross_bind_transfer(&manifest, &inventory)?;

    let verified = VerifiedTransferredBundle {
        root,
        root_identity,
        root_names,
        directories,
        files,
        manifest,
        inventory,
    };
    verified.reverify_all()?;
    Ok(verified)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FinalizationStage {
    Started,
    TransferredRecordsBound,
    VerifyQualificationEntered,
    VerifyQualificationRejected,
    QualificationVerified,
    SourceDigestRejected,
    CompatibilityDigestRejected,
    QualificationDigestRejected,
    ApprovalTimeRejected,
    FinalBindingsVerified,
}

#[cfg(test)]
thread_local! {
    static LAST_FINALIZATION_STAGE: std::cell::Cell<Option<FinalizationStage>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn mark_finalization_stage(stage: FinalizationStage) {
    LAST_FINALIZATION_STAGE.set(Some(stage));
}

#[cfg(test)]
fn last_finalization_stage_for_test() -> Option<FinalizationStage> {
    LAST_FINALIZATION_STAGE.get()
}

#[derive(Clone, Copy)]
enum ReleaseAdmissionPolicy {
    Production,
    // This private test-only seam begins after exact production admission and enters the same
    // candidate/object/finalization body. It creates no production bypass or exported authority.
    #[cfg(test)]
    PostAdmissionTest,
}

#[cfg(test)]
fn assemble_release_intent_after_admission_for_test(
    bundle: &VerifiedTransferredBundle,
    intent: &InitialPiReleaseIntentV1,
) -> Result<UnsignedReleaseCandidateV1, SignError> {
    assemble_release_intent_with_policy(bundle, intent, ReleaseAdmissionPolicy::PostAdmissionTest)
}

#[cfg(test)]
fn finalize_candidate_after_admission_for_test(
    bundle: &VerifiedTransferredBundle,
    source: &CatalogSourceV1,
    qualification: &CompatibilityQualificationV1,
) -> Result<UnsignedReleaseCandidateV1, SignError> {
    mark_finalization_stage(FinalizationStage::Started);
    finalize_candidate_with_policy(
        bundle,
        source,
        qualification,
        ReleaseAdmissionPolicy::PostAdmissionTest,
    )
}

pub fn assemble_release_intent(
    bundle: &VerifiedTransferredBundle,
    intent: &InitialPiReleaseIntentV1,
) -> Result<UnsignedReleaseCandidateV1, SignError> {
    assemble_release_intent_with_policy(bundle, intent, ReleaseAdmissionPolicy::Production)
}

fn assemble_release_intent_with_policy(
    bundle: &VerifiedTransferredBundle,
    intent: &InitialPiReleaseIntentV1,
    policy: ReleaseAdmissionPolicy,
) -> Result<UnsignedReleaseCandidateV1, SignError> {
    bundle.reverify_all()?;
    if bundle.inventory.source_kind() != InputSourceKind::ReleaseIntent
        || bundle.manifest.source_commit.is_some()
        || bundle.manifest.source_tree_sha256.is_some()
    {
        return Err(candidate_rejected());
    }
    let intent_bytes = bundle.record_bytes("release_intent")?;
    let transferred_intent =
        InitialPiReleaseIntentV1::from_json(&intent_bytes).map_err(|_| candidate_rejected())?;
    if &transferred_intent != intent
        || serde_jcs::to_vec(intent).map_err(|_| candidate_rejected())? != intent_bytes
        || bundle.inventory.source_sha256().as_str()
            != encode_hex(&initial_release_intent_digest(intent).map_err(|_| candidate_rejected())?)
    {
        return Err(candidate_rejected());
    }
    let semantic = intent_semantic_digest(intent)?;
    if bundle.inventory.compatibility_input_sha256().as_str() != semantic {
        return Err(candidate_rejected());
    }
    assemble_common(bundle, intent, semantic, None, policy)
}

pub fn finalize_candidate(
    bundle: &VerifiedTransferredBundle,
    source: &CatalogSourceV1,
    qualification: &CompatibilityQualificationV1,
) -> Result<UnsignedReleaseCandidateV1, SignError> {
    finalize_candidate_with_policy(
        bundle,
        source,
        qualification,
        ReleaseAdmissionPolicy::Production,
    )
}

fn finalize_candidate_with_policy(
    bundle: &VerifiedTransferredBundle,
    source: &CatalogSourceV1,
    qualification: &CompatibilityQualificationV1,
    policy: ReleaseAdmissionPolicy,
) -> Result<UnsignedReleaseCandidateV1, SignError> {
    bundle.reverify_all()?;
    if bundle.inventory.source_kind() != InputSourceKind::CatalogSource {
        return Err(candidate_rejected());
    }
    let source_bytes = bundle.record_bytes("catalog_source")?;
    let transferred_source =
        CatalogSourceV1::from_json(&source_bytes).map_err(|_| candidate_rejected())?;
    let qualification_bytes = bundle.record_bytes("qualification")?;
    let transferred_qualification = CompatibilityQualificationV1::from_json(&qualification_bytes)
        .map_err(|_| candidate_rejected())?;
    if &transferred_source != source
        || &transferred_qualification != qualification
        || serde_jcs::to_vec(source).map_err(|_| candidate_rejected())? != source_bytes
        || serde_jcs::to_vec(qualification).map_err(|_| candidate_rejected())?
            != qualification_bytes
    {
        return Err(candidate_rejected());
    }
    #[cfg(test)]
    mark_finalization_stage(FinalizationStage::TransferredRecordsBound);
    #[cfg(test)]
    mark_finalization_stage(FinalizationStage::VerifyQualificationEntered);
    if verify_qualification(source, qualification).is_err() {
        #[cfg(test)]
        mark_finalization_stage(FinalizationStage::VerifyQualificationRejected);
        return Err(candidate_rejected());
    }
    #[cfg(test)]
    mark_finalization_stage(FinalizationStage::QualificationVerified);
    let source_digest = catalog_source_digest(source).map_err(|_| candidate_rejected())?;
    let compatibility = compatibility_input_digest(source.intent(), source.build())
        .map_err(|_| candidate_rejected())?;
    let qualification_digest =
        qualification_record_digest(qualification).map_err(|_| candidate_rejected())?;
    if bundle.inventory.source_sha256().as_str() != encode_hex(&source_digest) {
        #[cfg(test)]
        mark_finalization_stage(FinalizationStage::SourceDigestRejected);
        return Err(candidate_rejected());
    }
    if bundle.inventory.compatibility_input_sha256().as_str() != encode_hex(&compatibility) {
        #[cfg(test)]
        mark_finalization_stage(FinalizationStage::CompatibilityDigestRejected);
        return Err(candidate_rejected());
    }
    if source.qualification().sha256().as_str() != encode_hex(&qualification_digest) {
        #[cfg(test)]
        mark_finalization_stage(FinalizationStage::QualificationDigestRejected);
        return Err(candidate_rejected());
    }
    if qualification.release_owner_approved_at() > source.intent().generated_at() {
        #[cfg(test)]
        mark_finalization_stage(FinalizationStage::ApprovalTimeRejected);
        return Err(candidate_rejected());
    }
    #[cfg(test)]
    mark_finalization_stage(FinalizationStage::FinalBindingsVerified);
    let source_commit = bundle
        .manifest
        .source_commit
        .as_ref()
        .filter(|value| valid_commit(value))
        .ok_or_else(candidate_rejected)?
        .clone();
    let source_tree_sha256 = bundle
        .manifest
        .source_tree_sha256
        .as_ref()
        .filter(|value| valid_sha256(value))
        .ok_or_else(candidate_rejected)?
        .clone();
    let semantic = intent_semantic_digest(source.intent())?;
    let qualification_sha256 = encode_hex(&qualification_digest);
    let final_bindings = FinalBindings {
        source_commit,
        source_tree_sha256,
        qualification_sha256: qualification_sha256.clone(),
    };
    let mut candidate = assemble_common(
        bundle,
        source.intent(),
        semantic.clone(),
        Some(final_bindings),
        policy,
    )?;
    candidate.support_assets.push(CandidateAsset {
        name: format!("qualification-{qualification_sha256}.json"),
        sha256: sha256(&qualification_bytes),
        bytes: qualification_bytes,
    });
    candidate
        .support_assets
        .sort_by(|left, right| left.name.cmp(&right.name));
    if candidate
        .support_assets
        .windows(2)
        .any(|pair| pair[0].name == pair[1].name)
        || candidate.runtime_semantic_sha256 != semantic
    {
        return Err(candidate_rejected());
    }
    require_candidate_bounds(&candidate)?;
    Ok(candidate)
}

fn assemble_common(
    bundle: &VerifiedTransferredBundle,
    intent: &InitialPiReleaseIntentV1,
    runtime_semantic_sha256: String,
    final_bindings: Option<FinalBindings>,
    policy: ReleaseAdmissionPolicy,
) -> Result<UnsignedReleaseCandidateV1, SignError> {
    require_first_tuple(intent)?;
    let package_inputs_bytes = bundle.record_bytes("package_inputs")?;
    let package_inputs = parse_package_inputs(&package_inputs_bytes)?;
    require_release_admission(intent, &package_inputs_bytes, policy)?;
    let payload = catalog_payload_for_intent(intent)?;
    let canonical_payload =
        canonical_catalog_payload(&payload).map_err(|_| candidate_rejected())?;
    let support_assets = verify_complete_object_graph(bundle, intent, &package_inputs)?;
    let candidate = UnsignedReleaseCandidateV1 {
        canonical_payload,
        runtime_semantic_sha256,
        tag: intent.tag().as_str().to_owned(),
        support_assets,
        final_bindings,
    };
    require_candidate_bounds(&candidate)?;
    Ok(candidate)
}

fn require_candidate_bounds(candidate: &UnsignedReleaseCandidateV1) -> Result<(), SignError> {
    if candidate.canonical_payload.is_empty()
        || candidate.canonical_payload.len() as u64 > MAX_MANIFEST_BYTES
        || candidate.support_assets.is_empty()
        || candidate.support_assets.len() > MAX_ENTRIES.saturating_sub(3)
    {
        return Err(candidate_rejected());
    }
    let mut total = candidate.canonical_payload.len() as u64;
    for asset in &candidate.support_assets {
        if asset.bytes.is_empty()
            || asset.bytes.len() as u64 > MAX_MANIFEST_BYTES
            || asset.bytes.len() as u64 > MAX_ENTRY_BYTES
            || asset.sha256 != sha256(&asset.bytes)
        {
            return Err(candidate_rejected());
        }
        total = total
            .checked_add(asset.bytes.len() as u64)
            .ok_or_else(candidate_rejected)?;
        if total > MAX_TOTAL_BYTES {
            return Err(candidate_rejected());
        }
    }
    Ok(())
}

fn sign_release(request: SignReleaseRequest<'_>) -> Result<SignedReleaseBundleV1, SignError> {
    let candidate = finalize_candidate(request.bundle, request.source, request.qualification)?;
    let output = OutputPreflight::new(request.output)?;
    let signing_key = read_production_signing_key(request.key_path)?;
    let signed_bytes = sign_candidate(
        &candidate,
        signing_key.as_dalek(),
        production_key_identity().key_id(),
    )?;
    drop(signing_key);
    verify_signed_bytes(&signed_bytes, SignatureVerificationPolicy::Production)?;
    write_signed_output(
        output,
        signed_bytes,
        SignatureVerificationPolicy::Production,
    )
}

struct SignedBytes {
    files: BTreeMap<String, Vec<u8>>,
    inventory: BundleInventoryV1,
    manifest: SignedReleaseBundleManifestV1,
}

fn sign_candidate(
    candidate: &UnsignedReleaseCandidateV1,
    signing_key: &SigningKey,
    key_id: &str,
) -> Result<SignedBytes, SignError> {
    let bindings = candidate
        .final_bindings
        .as_ref()
        .ok_or_else(candidate_rejected)?;
    let catalog_signature = signing_key.sign(&candidate.canonical_payload);
    let payload_value: Value =
        serde_json::from_slice(&candidate.canonical_payload).map_err(|_| candidate_rejected())?;
    let catalog_bytes = serde_jcs::to_vec(&json!({
        "envelope_version": 1,
        "signature_algorithm": "ed25519",
        "key_id": key_id,
        "payload": payload_value,
        "signature": encode_base64url_no_pad(&catalog_signature.to_bytes()),
    }))
    .map_err(|_| candidate_rejected())?;

    let mut assets = candidate
        .support_assets
        .iter()
        .map(|asset| {
            (
                asset.name.clone(),
                asset.bytes.clone(),
                asset.sha256.clone(),
            )
        })
        .collect::<Vec<_>>();
    assets.sort_by(|left, right| left.0.cmp(&right.0));
    if assets.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(candidate_rejected());
    }

    let catalog_sha256 = sha256(&catalog_bytes);
    let asset_values = assets
        .iter()
        .map(|(name, bytes, digest)| {
            json!({"name": name, "size": bytes.len() as u64, "sha256": digest})
        })
        .collect::<Vec<_>>();
    let unsigned_manifest_value = json!({
        "schema_version": 1,
        "source_commit": bindings.source_commit,
        "source_tree_sha256": bindings.source_tree_sha256,
        "qualification_sha256": bindings.qualification_sha256,
        "tag": candidate.tag,
        "catalog_envelope": {
            "name": CATALOG_NAME,
            "size": catalog_bytes.len() as u64,
            "sha256": catalog_sha256,
        },
        "assets": asset_values,
        "signature": {"key_id": key_id, "signature": "A".repeat(86)},
    });
    let unsigned_manifest = parse_canonical_manifest_value(&unsigned_manifest_value)?;
    let release_signature = signing_key
        .sign(&release_bundle_signing_bytes(&unsigned_manifest).map_err(|_| candidate_rejected())?);
    let mut signed_manifest_value = unsigned_manifest_value;
    signed_manifest_value["signature"]["signature"] =
        Value::String(encode_base64url_no_pad(&release_signature.to_bytes()));
    let manifest_bytes =
        serde_jcs::to_vec(&signed_manifest_value).map_err(|_| candidate_rejected())?;
    let manifest = SignedReleaseBundleManifestV1::from_json(&manifest_bytes)
        .map_err(|_| candidate_rejected())?;

    let mut files = BTreeMap::new();
    files.insert(CATALOG_NAME.to_owned(), catalog_bytes);
    for ((name, bytes, _), manifest_asset) in assets.into_iter().zip(manifest.assets()) {
        if name != manifest_asset.name().as_str()
            || bytes.len() as u64 != manifest_asset.size()
            || sha256(&bytes) != manifest_asset.sha256().as_str()
        {
            return Err(candidate_rejected());
        }
        files.insert(name, bytes);
    }
    files.insert(RELEASE_MANIFEST_NAME.to_owned(), manifest_bytes);
    let checksums = files
        .iter()
        .map(|(name, bytes)| format!("{}  {name}\n", sha256(bytes)))
        .collect::<String>()
        .into_bytes();
    files.insert(CHECKSUMS_NAME.to_owned(), checksums);
    let inventory = inventory_for_files(&files)?;
    verify_signed_release_inventory(&inventory, &manifest).map_err(|_| candidate_rejected())?;
    Ok(SignedBytes {
        files,
        inventory,
        manifest,
    })
}

fn parse_canonical_manifest_value(
    value: &Value,
) -> Result<SignedReleaseBundleManifestV1, SignError> {
    SignedReleaseBundleManifestV1::from_json(
        &serde_jcs::to_vec(value).map_err(|_| candidate_rejected())?,
    )
    .map_err(|_| candidate_rejected())
}

fn inventory_for_files(files: &BTreeMap<String, Vec<u8>>) -> Result<BundleInventoryV1, SignError> {
    let entries = files
        .iter()
        .map(|(name, bytes)| {
            json!({
                "relative_path": name,
                "mode": "0400",
                "size": bytes.len() as u64,
                "sha256": sha256(bytes),
            })
        })
        .collect::<Vec<_>>();
    BundleInventoryV1::from_json(
        &serde_jcs::to_vec(&json!({
            "schema_version": 1,
            "kind": "signed_release",
            "entries": entries,
        }))
        .map_err(|_| candidate_rejected())?,
    )
    .map_err(|_| candidate_rejected())
}

#[derive(Clone, Copy)]
enum SignatureVerificationPolicy {
    Production,
    #[cfg(any(test, feature = "fixture-tools"))]
    Fixture,
}

fn verify_signed_bytes(
    bytes: &SignedBytes,
    policy: SignatureVerificationPolicy,
) -> Result<(), SignError> {
    verify_signed_release_inventory(&bytes.inventory, &bytes.manifest)
        .map_err(|_| verification_failed())?;
    let catalog = bytes
        .files
        .get(CATALOG_NAME)
        .ok_or_else(verification_failed)?;
    let manifest = bytes
        .files
        .get(RELEASE_MANIFEST_NAME)
        .ok_or_else(verification_failed)?;
    match policy {
        SignatureVerificationPolicy::Production => {
            verify_signed_catalog(catalog).map_err(|_| verification_failed())?;
            verify_signed_release_bundle_manifest(manifest).map_err(|_| verification_failed())?;
        }
        #[cfg(any(test, feature = "fixture-tools"))]
        SignatureVerificationPolicy::Fixture => {
            verify_fixture_signatures(catalog, manifest)?;
        }
    }
    for entry in bytes.inventory.entries() {
        let file = bytes
            .files
            .get(entry.relative_path().as_str())
            .ok_or_else(verification_failed)?;
        if file.len() as u64 != entry.size() || sha256(file) != entry.sha256().as_str() {
            return Err(verification_failed());
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "fixture-tools"))]
fn verify_fixture_signatures(catalog_bytes: &[u8], manifest_bytes: &[u8]) -> Result<(), SignError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    const FIXTURE_PUBLIC_KEY: [u8; 32] = [
        0x1b, 0xd3, 0x6a, 0xfe, 0xe9, 0x32, 0x3f, 0x1e, 0x38, 0x13, 0xf6, 0x8c, 0x4d, 0x5f, 0x2f,
        0x2b, 0x1b, 0xae, 0x44, 0xc0, 0xef, 0x69, 0x17, 0x62, 0x8e, 0xd6, 0xaf, 0xe1, 0x6a, 0xae,
        0x44, 0xa9,
    ];
    const FIXTURE_KEY_ID: &str = "catalog-test-key-v1";

    let verifying_key =
        VerifyingKey::from_bytes(&FIXTURE_PUBLIC_KEY).map_err(|_| verification_failed())?;
    let envelope: Value =
        serde_json::from_slice(catalog_bytes).map_err(|_| verification_failed())?;
    if envelope.as_object().is_none_or(|object| object.len() != 5)
        || envelope["envelope_version"] != 1
        || envelope["signature_algorithm"] != "ed25519"
        || envelope["key_id"] != FIXTURE_KEY_ID
    {
        return Err(verification_failed());
    }
    let payload = CatalogPayloadV1::from_json(
        &serde_json::to_vec(&envelope["payload"]).map_err(|_| verification_failed())?,
    )
    .map_err(|_| verification_failed())?;
    let canonical_payload =
        canonical_catalog_payload(&payload).map_err(|_| verification_failed())?;
    let catalog_signature = envelope["signature"]
        .as_str()
        .and_then(decode_fixture_signature_for_test)
        .ok_or_else(verification_failed)?;
    verifying_key
        .verify_strict(
            &canonical_payload,
            &Signature::from_bytes(&catalog_signature),
        )
        .map_err(|_| verification_failed())?;

    let manifest = SignedReleaseBundleManifestV1::from_json(manifest_bytes)
        .map_err(|_| verification_failed())?;
    if manifest.signature().key_id().as_str() != FIXTURE_KEY_ID {
        return Err(verification_failed());
    }
    let release_signature =
        decode_fixture_signature_for_test(manifest.signature().signature().as_str())
            .ok_or_else(verification_failed)?;
    verifying_key
        .verify_strict(
            &release_bundle_signing_bytes(&manifest).map_err(|_| verification_failed())?,
            &Signature::from_bytes(&release_signature),
        )
        .map_err(|_| verification_failed())
}

#[cfg(any(test, feature = "fixture-tools"))]
fn decode_fixture_signature_for_test(value: &str) -> Option<[u8; 64]> {
    if value.len() != 86 || value.contains('=') {
        return None;
    }
    let decode = |byte| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    };
    let mut output = [0_u8; 64];
    let mut output_index = 0;
    for chunk in value.as_bytes().chunks(4) {
        let a = decode(chunk[0])?;
        let b = decode(chunk[1])?;
        output[output_index] = (a << 2) | (b >> 4);
        output_index += 1;
        if chunk.len() >= 3 {
            let c = decode(chunk[2])?;
            output[output_index] = (b << 4) | (c >> 2);
            output_index += 1;
            if chunk.len() == 4 {
                let d = decode(chunk[3])?;
                output[output_index] = (c << 6) | d;
                output_index += 1;
            } else if c & 0x03 != 0 {
                return None;
            }
        }
    }
    (output_index == output.len() && encode_base64url_no_pad(&output) == value).then_some(output)
}

fn write_signed_output(
    preflight: OutputPreflight,
    bytes: SignedBytes,
    verification_policy: SignatureVerificationPolicy,
) -> Result<SignedReleaseBundleV1, SignError> {
    let mut output = StagedOutput::create(preflight)?;
    for (name, contents) in &bytes.files {
        output.write_file(name, contents)?;
    }
    output.verify_files(&bytes.files)?;
    verify_signed_bytes(&bytes, verification_policy)?;
    let publication = output.publish();
    let mut cleanup = Ok(PublicationDurability::Durable);
    if output.published {
        let reopened = reopen_signed_output(&output.final_path, &bytes.files)?;
        if reopened != bytes.files {
            return Err(verification_failed());
        }
        verify_signed_bytes(&bytes, verification_policy)?;
        if publication.is_ok() {
            cleanup = output.settle_verified_staging();
        }
        #[cfg(test)]
        if take_publish_fault(PublishCheckpoint::FinalReopen).is_some() {
            return Err(SignError::OutputDurabilityUncertain);
        }
    }
    let durability = publication?;
    let cleanup_durability = cleanup?;
    if durability == PublicationDurability::Uncertain
        || cleanup_durability == PublicationDurability::Uncertain
    {
        return Err(SignError::OutputDurabilityUncertain);
    }
    Ok(SignedReleaseBundleV1 {
        output: output.final_path,
        inventory: bytes.inventory,
        manifest: bytes.manifest,
    })
}

fn reopen_signed_output(
    path: &Path,
    expected: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, Vec<u8>>, SignError> {
    let root = open_absolute_directory(path).map_err(|_| verification_failed())?;
    let metadata = root.metadata().map_err(|_| verification_failed())?;
    if !secure_directory(&metadata) || metadata.nlink() != 2 {
        return Err(verification_failed());
    }
    let names = enumerate_names(&root).map_err(|_| verification_failed())?;
    if names != expected.keys().cloned().collect() {
        return Err(verification_failed());
    }
    let mut reopened = BTreeMap::new();
    for (name, bytes) in expected {
        let file = open_regular_at(&root, name).map_err(|_| verification_failed())?;
        let metadata = file.metadata().map_err(|_| verification_failed())?;
        if !secure_file(&metadata) || metadata.len() != bytes.len() as u64 {
            return Err(verification_failed());
        }
        let actual =
            read_small_descriptor(&file, metadata.len()).map_err(|_| verification_failed())?;
        if actual != *bytes {
            return Err(verification_failed());
        }
        reopened.insert(name.clone(), actual);
    }
    Ok(reopened)
}

fn recover_signed_output(
    path: &Path,
    candidate: &UnsignedReleaseCandidateV1,
    verification_policy: SignatureVerificationPolicy,
) -> Result<SignedReleaseBundleV1, SignError> {
    let parent_path = path.parent().ok_or_else(verification_failed)?;
    let root = open_absolute_directory(path).map_err(|_| verification_failed())?;
    let metadata = root.metadata().map_err(|_| verification_failed())?;
    if !secure_directory(&metadata) || metadata.nlink() != 2 {
        return Err(verification_failed());
    }
    let names = enumerate_names(&root).map_err(|_| verification_failed())?;
    if names.len() < 3 || names.len() > MAX_ENTRIES {
        return Err(verification_failed());
    }
    let mut files = BTreeMap::new();
    for name in names {
        if !safe_component(&name) {
            return Err(verification_failed());
        }
        let file = open_regular_at(&root, &name).map_err(|_| verification_failed())?;
        let metadata = file.metadata().map_err(|_| verification_failed())?;
        if !secure_file(&metadata) || metadata.len() == 0 || metadata.len() > MAX_ENTRY_BYTES {
            return Err(verification_failed());
        }
        files.insert(
            name,
            read_small_descriptor(&file, metadata.len()).map_err(|_| verification_failed())?,
        );
    }
    let catalog = files.get(CATALOG_NAME).ok_or_else(verification_failed)?;
    let envelope: Value = serde_json::from_slice(catalog).map_err(|_| verification_failed())?;
    let payload = CatalogPayloadV1::from_json(
        &serde_json::to_vec(&envelope["payload"]).map_err(|_| verification_failed())?,
    )
    .map_err(|_| verification_failed())?;
    if canonical_catalog_payload(&payload).map_err(|_| verification_failed())?
        != candidate.canonical_payload
    {
        return Err(verification_failed());
    }
    let manifest_bytes = files
        .get(RELEASE_MANIFEST_NAME)
        .ok_or_else(verification_failed)?;
    let manifest = SignedReleaseBundleManifestV1::from_json(manifest_bytes)
        .map_err(|_| verification_failed())?;
    let bindings = candidate
        .final_bindings
        .as_ref()
        .ok_or_else(verification_failed)?;
    if manifest.tag().as_str() != candidate.tag
        || manifest.source_commit().as_str() != bindings.source_commit
        || manifest.source_tree_sha256().as_str() != bindings.source_tree_sha256
        || manifest.qualification_sha256().as_str() != bindings.qualification_sha256
        || manifest.assets().len() != candidate.support_assets.len()
    {
        return Err(verification_failed());
    }
    for (asset, expected) in manifest.assets().iter().zip(&candidate.support_assets) {
        if asset.name().as_str() != expected.name
            || asset.size() != expected.bytes.len() as u64
            || asset.sha256().as_str() != expected.sha256
            || files.get(&expected.name) != Some(&expected.bytes)
        {
            return Err(verification_failed());
        }
    }
    let expected_checksums = files
        .iter()
        .filter(|(name, _)| name.as_str() != CHECKSUMS_NAME)
        .map(|(name, bytes)| format!("{}  {name}\n", sha256(bytes)))
        .collect::<String>()
        .into_bytes();
    if files.get(CHECKSUMS_NAME) != Some(&expected_checksums) {
        return Err(verification_failed());
    }
    let inventory = inventory_for_files(&files)?;
    let signed = SignedBytes {
        files,
        inventory: inventory.clone(),
        manifest: manifest.clone(),
    };
    verify_signed_bytes(&signed, verification_policy)?;
    // Destructive settlement is deliberately last: the complete visible candidate and both
    // public signature domains have already been independently reconstructed and verified.
    settle_bound_empty_staging(parent_path)?;
    Ok(SignedReleaseBundleV1 {
        output: path.to_owned(),
        inventory,
        manifest,
    })
}

#[derive(Clone)]
struct RecoveryStageBinding {
    relative_name: String,
    identity: FileIdentity,
    uid: u32,
    mode: u32,
    cleanup_authorized: bool,
}

fn settle_bound_empty_staging(parent_path: &Path) -> Result<(), SignError> {
    let parent = open_absolute_directory(parent_path).map_err(|_| verification_failed())?;
    let Some(mut binding) = read_recovery_stage_binding(&parent)? else {
        // A completed retry has no temporary binding. It removes nothing; the outer reverse
        // verifier authenticates the exact existing manifest and rejects every extra stage.
        return name_exists_at(
            &parent,
            &CString::new(TRANSFER_MANIFEST_NAME).expect("fixed manifest name"),
        )
        .and_then(|exists| exists.then_some(()).ok_or_else(verification_failed));
    };
    let bound_name =
        CString::new(binding.relative_name.as_str()).map_err(|_| verification_failed())?;
    let stage_exists = name_exists_at(&parent, &bound_name).map_err(|_| verification_failed())?;
    if !stage_exists {
        return Err(verification_failed());
    }
    let directory =
        open_directory_at(&parent, &binding.relative_name).map_err(|_| verification_failed())?;
    let metadata = directory.metadata().map_err(|_| verification_failed())?;
    if FileIdentity::from_metadata(&metadata) != binding.identity
        || metadata.uid() != binding.uid
        || metadata.permissions().mode() & 0o7777 != binding.mode
        || !secure_directory(&metadata)
        || metadata.nlink() != 2
        || !enumerate_names(&directory)
            .map_err(|_| verification_failed())?
            .is_empty()
    {
        return Err(verification_failed());
    }
    if !binding.cleanup_authorized {
        authorize_recovery_stage_cleanup(&parent, &binding)?;
        binding.cleanup_authorized = true;
    }
    // SAFETY: retained parent and exact rebound, identity-matched empty directory are valid.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), bound_name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(verification_failed());
    }
    parent.sync_all().map_err(|_| verification_failed())
}

fn catalog_payload_for_intent(
    intent: &InitialPiReleaseIntentV1,
) -> Result<CatalogPayloadV1, SignError> {
    let release = serde_json::to_value(intent.release()).map_err(|_| candidate_rejected())?;
    let release_record = release.get("release").ok_or_else(candidate_rejected)?;
    let payload = json!({
        "schema_version": 1,
        "sequence": intent.sequence().to_string(),
        "generated_at": intent.generated_at(),
        "expires_at": intent.expires_at(),
        "compatibility_ranges": [intent.fluxsemble_requirement()],
        "providers": [{
            "provider_id": intent.release().provider(),
            "allowed_origins": intent.release().allowed_origins(),
            "releases": [release_record],
        }],
    });
    CatalogPayloadV1::from_json(&serde_json::to_vec(&payload).map_err(|_| candidate_rejected())?)
        .map_err(|_| candidate_rejected())
}

fn require_first_tuple(intent: &InitialPiReleaseIntentV1) -> Result<(), SignError> {
    if intent.fluxsemble_requirement().as_str() != "=0.1.0"
        || intent.release().provider() != "builtin:pi"
        || intent.release().target().as_str() != "linux_x86_64"
        || intent.release().pi_version().as_str() != ROOT_VERSION
        || intent.release().node_version().as_str() != NODE_VERSION
        || intent.tag().as_str() != format!("catalog-v1-sequence-{}", intent.sequence())
        || intent.generated_at() >= intent.expires_at()
    {
        return Err(candidate_rejected());
    }
    Ok(())
}

fn require_release_admission(
    intent: &InitialPiReleaseIntentV1,
    package_inputs_bytes: &[u8],
    policy: ReleaseAdmissionPolicy,
) -> Result<(), SignError> {
    match policy {
        ReleaseAdmissionPolicy::Production => {
            require_approved_production_tuple(intent)?;
            if approved_package_input_digest(package_inputs_bytes)
                != APPROVED_PACKAGE_INPUT_DOMAIN_SHA256
                || approved_release_semantic_digest(intent)? != APPROVED_RELEASE_SEMANTIC_SHA256
            {
                return Err(candidate_rejected());
            }
            Ok(())
        }
        #[cfg(test)]
        ReleaseAdmissionPolicy::PostAdmissionTest => Ok(()),
    }
}

fn approved_package_input_digest(canonical_package_inputs: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(APPROVED_PACKAGE_INPUT_DOMAIN);
    hasher.update(canonical_package_inputs);
    format!("{:x}", hasher.finalize())
}

fn require_approved_production_tuple(intent: &InitialPiReleaseIntentV1) -> Result<(), SignError> {
    let value = serde_json::to_value(intent).map_err(|_| candidate_rejected())?;
    let tag = intent.tag().as_str();
    let root_manifest_name = format!("pi-package-{ROOT_MANIFEST_SHA256}.json");
    let shrinkwrap_name = format!("pi-shrinkwrap-{SHRINKWRAP_SHA256}.json");
    let release_prefix =
        format!("https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/{tag}/");
    let root_manifest_url = format!("{release_prefix}{root_manifest_name}");
    let shrinkwrap_url = format!("{release_prefix}{shrinkwrap_name}");

    let exact_strings = [
        ("/fluxsemble_requirement", "=0.1.0"),
        ("/release/provider", "builtin:pi"),
        ("/release/release/version", ROOT_VERSION),
        ("/release/release/target", "linux_x86_64"),
        (
            "/release/release/components/0/component_id",
            "component:node",
        ),
        ("/release/release/components/0/version", NODE_VERSION),
        (
            "/release/release/components/0/artifacts/0/artifact_id",
            "artifact:node-linux-x86_64",
        ),
        (
            "/release/release/components/0/artifacts/0/url",
            NODE_ARTIFACT_URL,
        ),
        (
            "/release/release/components/0/artifacts/0/size_bytes",
            "30479988",
        ),
        (
            "/release/release/components/0/artifacts/0/sha256",
            NODE_ARTIFACT_SHA256,
        ),
        ("/release/release/components/1/component_id", "component:pi"),
        ("/release/release/components/1/version", ROOT_VERSION),
        (
            "/release/release/components/1/artifacts/0/artifact_id",
            "artifact:pi-coding-agent",
        ),
        (
            "/release/release/components/1/artifacts/0/url",
            ROOT_ARTIFACT_URL,
        ),
        (
            "/release/release/components/1/artifacts/0/size_bytes",
            "4992066",
        ),
        (
            "/release/release/components/1/artifacts/0/sha256",
            ROOT_ARTIFACT_SHA256,
        ),
        ("/release/release/provider_extension/kind", "pi"),
        (
            "/release/release/provider_extension/metadata/approved_package/name",
            ROOT_NAME,
        ),
        (
            "/release/release/provider_extension/metadata/approved_package/version",
            ROOT_VERSION,
        ),
        (
            "/release/release/provider_extension/metadata/expected_entrypoint",
            "dist/cli.js",
        ),
        (
            "/release/release/provider_extension/metadata/component_id",
            "component:pi",
        ),
        (
            "/release/release/provider_extension/metadata/package_artifact_id",
            "artifact:pi-coding-agent",
        ),
        (
            "/release/release/provider_extension/metadata/registry_integrity",
            ROOT_REGISTRY_INTEGRITY,
        ),
        (
            "/release/release/provider_extension/metadata/root_package_manifest/url",
            root_manifest_url.as_str(),
        ),
        (
            "/release/release/provider_extension/metadata/root_package_manifest/size_bytes",
            "3560",
        ),
        (
            "/release/release/provider_extension/metadata/root_package_manifest/sha256",
            ROOT_MANIFEST_SHA256,
        ),
        (
            "/release/release/provider_extension/metadata/shipped_shrinkwrap/root_package/name",
            ROOT_NAME,
        ),
        (
            "/release/release/provider_extension/metadata/shipped_shrinkwrap/root_package/version",
            ROOT_VERSION,
        ),
        (
            "/release/release/provider_extension/metadata/shipped_shrinkwrap/artifact/url",
            shrinkwrap_url.as_str(),
        ),
        (
            "/release/release/provider_extension/metadata/shipped_shrinkwrap/artifact/size_bytes",
            "61540",
        ),
        (
            "/release/release/provider_extension/metadata/shipped_shrinkwrap/artifact/sha256",
            SHRINKWRAP_SHA256,
        ),
    ];
    if exact_strings.iter().any(|(pointer, expected)| {
        value.pointer(pointer).and_then(Value::as_str) != Some(*expected)
    }) || value.pointer("/release/allowed_origins")
        != Some(&json!([
            "https://github.com",
            "https://nodejs.org",
            "https://registry.npmjs.org"
        ]))
        || value.pointer("/release/release/compatibility_ranges") != Some(&json!(["=0.1.0"]))
        || value
            .pointer("/release/release/components")
            .and_then(Value::as_array)
            .is_none_or(|components| components.len() != 2)
        || value
            .pointer("/release/release/components/0/artifacts")
            .and_then(Value::as_array)
            .is_none_or(|artifacts| artifacts.len() != 1)
        || value
            .pointer("/release/release/components/1/artifacts")
            .and_then(Value::as_array)
            .is_none_or(|artifacts| artifacts.len() != 1)
        || value
            .pointer(
                "/release/release/provider_extension/metadata/shipped_shrinkwrap/lockfile_version",
            )
            .and_then(Value::as_u64)
            != Some(3)
        || value
            .pointer(
                "/release/release/provider_extension/metadata/shipped_shrinkwrap/locked_packages",
            )
            .and_then(Value::as_array)
            .is_none_or(|packages| packages.len() != LOCKED_COUNT)
    {
        return Err(candidate_rejected());
    }
    if intent.release().catalog_release().components()[0].artifacts()[0]
        .size_bytes()
        .get()
        != NODE_ARTIFACT_SIZE
        || intent.release().catalog_release().components()[1].artifacts()[0]
            .size_bytes()
            .get()
            != ROOT_ARTIFACT_SIZE
        || match intent.release().catalog_release().provider_extension() {
            ProviderExtensionV1::Pi(metadata) => {
                metadata.root_package_manifest().size_bytes().get() != ROOT_MANIFEST_SIZE
                    || metadata.shipped_shrinkwrap().artifact().size_bytes().get()
                        != SHRINKWRAP_SIZE
            }
            ProviderExtensionV1::None => true,
        }
    {
        return Err(candidate_rejected());
    }
    Ok(())
}

fn verify_complete_object_graph(
    bundle: &VerifiedTransferredBundle,
    intent: &InitialPiReleaseIntentV1,
    package_inputs: &PackageInputManifestV1,
) -> Result<Vec<CandidateAsset>, SignError> {
    let release = intent.release().catalog_release();
    let metadata = match release.provider_extension() {
        ProviderExtensionV1::Pi(metadata) => metadata.as_ref(),
        ProviderExtensionV1::None => return Err(candidate_rejected()),
    };
    let node = release
        .components()
        .iter()
        .find(|component| component.component_id().as_str() == "component:node")
        .and_then(|component| (component.artifacts().len() == 1).then(|| &component.artifacts()[0]))
        .ok_or_else(candidate_rejected)?;
    let pi = release
        .components()
        .iter()
        .find(|component| component.component_id() == metadata.component_id())
        .and_then(|component| {
            component
                .artifacts()
                .iter()
                .find(|artifact| artifact.artifact_id() == metadata.package_artifact_id())
        })
        .ok_or_else(candidate_rejected)?;

    if package_inputs.root.name != ROOT_NAME
        || package_inputs.root.version != ROOT_VERSION
        || package_inputs.root.archive_size != pi.size_bytes().get()
        || package_inputs.root.archive_sha256 != pi.sha256().as_str()
        || package_inputs.root.manifest_size != metadata.root_package_manifest().size_bytes().get()
        || package_inputs.root.manifest_sha256 != metadata.root_package_manifest().sha256().as_str()
        || package_inputs.root.shrinkwrap_size
            != metadata.shipped_shrinkwrap().artifact().size_bytes().get()
        || package_inputs.root.shrinkwrap_sha256
            != metadata.shipped_shrinkwrap().artifact().sha256().as_str()
        || metadata.shipped_shrinkwrap().locked_packages().len() != LOCKED_COUNT
        || metadata.shipped_shrinkwrap().locked_packages().len()
            != package_inputs.locked_packages.len()
        || package_inputs.root.archive_member_count == 0
    {
        return Err(candidate_rejected());
    }

    let mut expected = BTreeMap::<String, (String, u64)>::new();
    insert_expected(
        &mut expected,
        node.url().as_str(),
        node.size_bytes().get(),
        node.sha256().as_str(),
    )?;
    insert_expected(
        &mut expected,
        pi.url().as_str(),
        pi.size_bytes().get(),
        pi.sha256().as_str(),
    )?;
    insert_expected(
        &mut expected,
        metadata.root_package_manifest().url().as_str(),
        metadata.root_package_manifest().size_bytes().get(),
        metadata.root_package_manifest().sha256().as_str(),
    )?;
    insert_expected(
        &mut expected,
        metadata.shipped_shrinkwrap().artifact().url().as_str(),
        metadata.shipped_shrinkwrap().artifact().size_bytes().get(),
        metadata.shipped_shrinkwrap().artifact().sha256().as_str(),
    )?;
    for (observed, declared) in package_inputs
        .locked_packages
        .iter()
        .zip(metadata.shipped_shrinkwrap().locked_packages())
    {
        if observed.locator != declared.locator().as_str()
            || observed.name != declared.name().as_str()
            || observed.version != declared.version().as_str()
            || observed.resolved_url != declared.resolved_url().as_str()
            || observed.registry_integrity != declared.registry_integrity().as_str()
            || observed.archive_sha256 != declared.archive_sha256().as_str()
            || observed.archive_size == 0
            || observed.declaration_sha256.len() != 64
            || !valid_sha256(&observed.declaration_sha256)
            || observed.archive_member_count == 0
        {
            return Err(candidate_rejected());
        }
        insert_expected(
            &mut expected,
            &observed.resolved_url,
            observed.archive_size,
            &observed.archive_sha256,
        )?;
    }

    let actual = bundle
        .inventory
        .objects()
        .iter()
        .map(|object| {
            (
                object.sha256().as_str().to_owned(),
                (object.source_url().as_str().to_owned(), object.size()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if actual != expected {
        return Err(candidate_rejected());
    }

    let mut assets = Vec::new();
    for descriptor in [
        metadata.root_package_manifest(),
        metadata.shipped_shrinkwrap().artifact(),
    ] {
        let name = digest_bearing_asset_name(
            descriptor.url().as_str(),
            descriptor.sha256().as_str(),
            intent.tag().as_str(),
        )?;
        let relative = format!("objects/{}", descriptor.sha256().as_str());
        let bytes = bundle.read_small_file(&relative)?;
        if bytes.len() as u64 != descriptor.size_bytes().get()
            || sha256(&bytes) != descriptor.sha256().as_str()
        {
            return Err(candidate_rejected());
        }
        assets.push(CandidateAsset {
            name,
            sha256: sha256(&bytes),
            bytes,
        });
    }
    assets.sort_by(|left, right| left.name.cmp(&right.name));
    if assets.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err(candidate_rejected());
    }
    Ok(assets)
}

fn digest_bearing_asset_name(url: &str, digest: &str, tag: &str) -> Result<String, SignError> {
    let prefix =
        format!("https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/{tag}/");
    let name = url.strip_prefix(&prefix).ok_or_else(candidate_rejected)?;
    if name.is_empty()
        || name.len() > 255
        || !name.contains(digest)
        || name.contains(['/', '\\'])
        || !name.is_ascii()
        || name
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(candidate_rejected());
    }
    Ok(name.to_owned())
}

fn insert_expected(
    expected: &mut BTreeMap<String, (String, u64)>,
    url: &str,
    size: u64,
    digest: &str,
) -> Result<(), SignError> {
    if size == 0 || size > MAX_ENTRY_BYTES || !valid_sha256(digest) {
        return Err(candidate_rejected());
    }
    match expected.insert(digest.to_owned(), (url.to_owned(), size)) {
        Some(previous) if previous != (url.to_owned(), size) => Err(candidate_rejected()),
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageInputManifestV1 {
    schema_version: u16,
    target_os: String,
    target_cpu: String,
    target_libc: String,
    root: ObservedRootInput,
    locked_packages: Vec<ObservedLockedInput>,
    pre_prune_package_count: u16,
    applicable_package_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedRootInput {
    name: String,
    version: String,
    archive_size: u64,
    archive_sha256: String,
    manifest_size: u64,
    manifest_sha256: String,
    shrinkwrap_size: u64,
    shrinkwrap_sha256: String,
    archive_member_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedLockedInput {
    locator: String,
    name: String,
    version: String,
    resolved_url: String,
    registry_integrity: String,
    archive_size: u64,
    archive_sha256: String,
    declaration_sha256: String,
    archive_member_count: u32,
    applicability: LinuxApplicability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum LinuxApplicability {
    Applicable,
    Pruned { reasons: Vec<String> },
}

fn parse_package_inputs(bytes: &[u8]) -> Result<PackageInputManifestV1, SignError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(candidate_rejected());
    }
    let manifest: PackageInputManifestV1 =
        serde_json::from_slice(bytes).map_err(|_| candidate_rejected())?;
    if serde_jcs::to_vec(&manifest).map_err(|_| candidate_rejected())? != bytes
        || manifest.schema_version != 1
        || manifest.target_os != "linux"
        || manifest.target_cpu != "x64"
        || manifest.target_libc != "glibc"
        || manifest.root.name != ROOT_NAME
        || manifest.root.version != ROOT_VERSION
        || manifest.locked_packages.len() != LOCKED_COUNT
        || manifest.pre_prune_package_count != PRE_PRUNE_COUNT
        || manifest.applicable_package_count != APPLICABLE_COUNT
        || manifest
            .locked_packages
            .windows(2)
            .any(|pair| pair[0].locator >= pair[1].locator)
        || manifest
            .locked_packages
            .iter()
            .filter(|record| matches!(record.applicability, LinuxApplicability::Applicable))
            .count()
            != usize::from(APPLICABLE_COUNT)
    {
        return Err(candidate_rejected());
    }
    let pruned = manifest
        .locked_packages
        .iter()
        .filter_map(|record| match &record.applicability {
            LinuxApplicability::Applicable => None,
            LinuxApplicability::Pruned { reasons } => {
                Some((record.locator.as_str(), reasons.as_slice()))
            }
        })
        .collect::<Vec<_>>();
    if pruned.len() != PRUNED.len()
        || pruned.iter().zip(PRUNED).any(|(actual, expected)| {
            actual.0 != expected.0
                || actual.1.iter().map(String::as_str).collect::<Vec<_>>() != expected.1
        })
    {
        return Err(candidate_rejected());
    }
    Ok(manifest)
}

fn intent_semantic_digest(intent: &InitialPiReleaseIntentV1) -> Result<String, SignError> {
    release_semantic_digest(INTENT_SEMANTICS_DOMAIN, intent)
}

fn approved_release_semantic_digest(
    intent: &InitialPiReleaseIntentV1,
) -> Result<String, SignError> {
    release_semantic_digest(APPROVED_RELEASE_SEMANTIC_DOMAIN, intent)
}

fn release_semantic_digest(
    domain: &[u8],
    intent: &InitialPiReleaseIntentV1,
) -> Result<String, SignError> {
    #[derive(Serialize)]
    struct Semantic<'a> {
        fluxsemble_requirement: &'a catalog_core::ExactVersionRequirement,
        release: &'a catalog_core::InitialPiReleaseSemanticsV1,
    }
    let canonical = serde_jcs::to_vec(&Semantic {
        fluxsemble_requirement: intent.fluxsemble_requirement(),
        release: intent.release(),
    })
    .map_err(|_| candidate_rejected())?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_transfer_manifest(manifest: &TransferManifestV1) -> Result<(), SignError> {
    if manifest.schema_version != 1
        || manifest.kind != "verified_input"
        || manifest.entries.is_empty()
        || manifest.entries.len() > MAX_ENTRIES
        || manifest.records.is_empty()
        || manifest
            .entries
            .windows(2)
            .any(|pair| pair[0].relative_path >= pair[1].relative_path)
        || manifest
            .records
            .windows(2)
            .any(|pair| pair[0].role >= pair[1].role)
        || manifest.source_commit.is_some() != manifest.source_tree_sha256.is_some()
        || manifest
            .source_commit
            .as_ref()
            .is_some_and(|value| !valid_commit(value))
        || manifest
            .source_tree_sha256
            .as_ref()
            .is_some_and(|value| !valid_sha256(value))
    {
        return Err(bundle_rejected());
    }
    let mut total = 0_u64;
    for entry in &manifest.entries {
        if !safe_relative(&entry.relative_path)
            || entry.relative_path == TRANSFER_MANIFEST_NAME
            || entry.mode != "0400"
            || entry.size == 0
            || entry.size > MAX_ENTRY_BYTES
            || !valid_sha256(&entry.sha256)
            || entry
                .relative_path
                .strip_prefix("objects/")
                .is_some_and(|name| name != entry.sha256)
            || entry
                .relative_path
                .strip_prefix("records/")
                .is_some_and(|name| name != entry.sha256)
        {
            return Err(bundle_rejected());
        }
        total = total.checked_add(entry.size).ok_or_else(bundle_rejected)?;
        if total > MAX_TOTAL_BYTES {
            return Err(bundle_rejected());
        }
    }
    for record in &manifest.records {
        if !safe_role(&record.role)
            || !valid_sha256(&record.sha256)
            || record.relative_path != format!("records/{}", record.sha256)
            || !manifest.entries.iter().any(|entry| {
                entry.relative_path == record.relative_path && entry.sha256 == record.sha256
            })
        {
            return Err(bundle_rejected());
        }
    }
    Ok(())
}

fn cross_bind_transfer(
    manifest: &TransferManifestV1,
    inventory: &VerifiedInputBundleV1,
) -> Result<(), SignError> {
    let manifested = manifest
        .entries
        .iter()
        .filter(|entry| entry.relative_path.starts_with("objects/"))
        .map(|entry| (&entry.relative_path, entry.size, &entry.sha256))
        .collect::<BTreeSet<_>>();
    let inventoried = inventory
        .objects()
        .iter()
        .map(|entry| {
            (
                entry.relative_path().as_str().to_owned(),
                entry.size(),
                entry.sha256().as_str().to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    let manifested_owned = manifested
        .into_iter()
        .map(|(path, size, digest)| (path.clone(), size, digest.clone()))
        .collect::<BTreeSet<_>>();
    if manifested_owned != inventoried
        || !manifest
            .entries
            .iter()
            .any(|entry| entry.relative_path == VERIFIED_INPUT_NAME)
    {
        return Err(bundle_rejected());
    }
    let roles = manifest
        .records
        .iter()
        .map(|record| record.role.as_str())
        .collect::<Vec<_>>();
    let expected = match inventory.source_kind() {
        InputSourceKind::ReleaseIntent => vec!["package_inputs", "release_intent"],
        InputSourceKind::CatalogSource => vec!["catalog_source", "package_inputs", "qualification"],
    };
    if roles != expected
        || (inventory.source_kind() == InputSourceKind::CatalogSource)
            != manifest.source_commit.is_some()
    {
        return Err(bundle_rejected());
    }
    Ok(())
}

fn flatten_tree(
    root_names: &BTreeSet<String>,
    directories: &BTreeMap<String, RetainedDirectory>,
) -> Result<BTreeSet<String>, SignError> {
    let mut paths = BTreeSet::new();
    for name in root_names {
        if let Some(directory) = directories.get(name) {
            for child in &directory.names {
                if !paths.insert(format!("{name}/{child}")) {
                    return Err(bundle_rejected());
                }
            }
        } else if !paths.insert(name.clone()) {
            return Err(bundle_rejected());
        }
    }
    Ok(paths)
}

fn verify_root_binding(bundle: &VerifiedTransferredBundle) -> Result<(), SignError> {
    let metadata = bundle.root.metadata().map_err(|_| bundle_rejected())?;
    if !secure_directory(&metadata)
        || metadata.nlink() != 4
        || FileIdentity::from_metadata(&metadata) != bundle.root_identity
        || enumerate_names(&bundle.root)? != bundle.root_names
    {
        return Err(bundle_rejected());
    }
    for (name, directory) in &bundle.directories {
        let rebound = open_directory_at(&bundle.root, name)?;
        let metadata = rebound.metadata().map_err(|_| bundle_rejected())?;
        if !secure_directory(&metadata)
            || metadata.nlink() != 2
            || FileIdentity::from_metadata(&metadata) != directory.identity
            || enumerate_names(&directory.file)? != directory.names
        {
            return Err(bundle_rejected());
        }
    }
    Ok(())
}

fn verify_retained_file(
    bundle: &VerifiedTransferredBundle,
    retained: &RetainedFile,
) -> Result<(), SignError> {
    let (parent, name) = parent_and_name(
        &bundle.root,
        &bundle.directories,
        &retained.entry.relative_path,
    )?;
    let before = retained.file.metadata().map_err(|_| bundle_rejected())?;
    if !secure_file(&before)
        || before.len() != retained.entry.size
        || FileIdentity::from_metadata(&before) != retained.identity
        || hash_file(&retained.file, retained.entry.size)? != retained.entry.sha256
    {
        return Err(bundle_rejected());
    }
    let rebound = open_regular_at(parent, name)?;
    let rebound = rebound.metadata().map_err(|_| bundle_rejected())?;
    if !secure_file(&rebound)
        || rebound.len() != retained.entry.size
        || FileIdentity::from_metadata(&rebound) != retained.identity
    {
        return Err(bundle_rejected());
    }
    Ok(())
}

fn read_small_retained(retained: &RetainedFile) -> Result<Vec<u8>, SignError> {
    if retained.entry.size > MAX_MANIFEST_BYTES {
        return Err(bundle_rejected());
    }
    let bytes = read_small_descriptor(&retained.file, retained.entry.size)?;
    if sha256(&bytes) != retained.entry.sha256 {
        return Err(bundle_rejected());
    }
    Ok(bytes)
}

fn parent_and_name<'a>(
    root: &'a fs::File,
    directories: &'a BTreeMap<String, RetainedDirectory>,
    relative: &'a str,
) -> Result<(&'a fs::File, &'a str), SignError> {
    match relative.split_once('/') {
        None => Ok((root, relative)),
        Some((directory, name)) => directories
            .get(directory)
            .filter(|_| safe_component(name))
            .map(|directory| (&directory.file, name))
            .ok_or_else(bundle_rejected),
    }
}

fn open_absolute_directory(path: &Path) -> Result<fs::File, SignError> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| bundle_rejected())?;
    openat2(
        libc::AT_FDCWD,
        &path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0x02 | 0x04,
    )
}

fn open_directory_at(parent: &fs::File, name: &str) -> Result<fs::File, SignError> {
    let name = CString::new(name).map_err(|_| bundle_rejected())?;
    openat2(
        parent.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0x02 | 0x04 | 0x08,
    )
}

fn open_regular_at(parent: &fs::File, name: &str) -> Result<fs::File, SignError> {
    if !safe_component(name) {
        return Err(bundle_rejected());
    }
    let name = CString::new(name).map_err(|_| bundle_rejected())?;
    openat2(
        parent.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0x02 | 0x04 | 0x08,
    )
}

fn openat2(
    directory: i32,
    name: &CString,
    flags: i32,
    resolve: u64,
) -> Result<fs::File, SignError> {
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
        return Err(bundle_rejected());
    }
    // SAFETY: a successful openat2 returns one owned descriptor.
    Ok(unsafe { fs::File::from_raw_fd(descriptor) })
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn enumerate_names(directory: &fs::File) -> Result<BTreeSet<String>, SignError> {
    // SAFETY: fcntl duplicates the retained descriptor.
    let descriptor = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(bundle_rejected());
    }
    // SAFETY: fdopendir takes the duplicate on success.
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        // SAFETY: fdopendir did not consume the duplicate on failure.
        let _ = unsafe { libc::close(descriptor) };
        return Err(bundle_rejected());
    }
    // SAFETY: stream is valid and thread-confined.
    unsafe { libc::rewinddir(stream) };
    let result = (|| {
        let mut names = BTreeSet::new();
        loop {
            // SAFETY: Linux errno is thread-local.
            unsafe { *libc::__errno_location() = 0 };
            // SAFETY: stream remains valid.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                // SAFETY: read immediately after readdir.
                if unsafe { *libc::__errno_location() } != 0 {
                    return Err(bundle_rejected());
                }
                break;
            }
            // SAFETY: d_name is NUL terminated.
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            let name = std::str::from_utf8(bytes).map_err(|_| bundle_rejected())?;
            if !safe_component(name) || !names.insert(name.to_owned()) {
                return Err(bundle_rejected());
            }
        }
        Ok(names)
    })();
    // SAFETY: closes stream and duplicate descriptor.
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(bundle_rejected());
    }
    result
}

fn hash_file(file: &fs::File, expected_size: u64) -> Result<String, SignError> {
    let mut file = file.try_clone().map_err(|_| bundle_rejected())?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| bundle_rejected())?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| bundle_rejected())?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(bundle_rejected)?;
        if total > expected_size {
            return Err(bundle_rejected());
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_size {
        return Err(bundle_rejected());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_small_descriptor(file: &fs::File, size: u64) -> Result<Vec<u8>, SignError> {
    if size > MAX_MANIFEST_BYTES {
        return Err(bundle_rejected());
    }
    let mut file = file.try_clone().map_err(|_| bundle_rejected())?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| bundle_rejected())?;
    let mut bytes = Vec::with_capacity(size as usize);
    (&mut file)
        .take(size + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| bundle_rejected())?;
    if bytes.len() as u64 != size {
        return Err(bundle_rejected());
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

struct OutputPreflight {
    parent: fs::File,
    final_name: CString,
    final_path: PathBuf,
}

impl OutputPreflight {
    fn new(path: &Path) -> Result<Self, SignError> {
        if !is_absolute_bounded_path(path) {
            return Err(output_rejected());
        }
        let name = path
            .file_name()
            .filter(|name| safe_component_bytes(name.as_bytes()))
            .ok_or_else(output_rejected)?;
        let final_name = CString::new(name.as_bytes()).map_err(|_| output_rejected())?;
        let parent_path = path.parent().ok_or_else(output_rejected)?;
        let parent = open_absolute_directory(parent_path).map_err(|_| output_rejected())?;
        let metadata = parent.metadata().map_err(|_| output_rejected())?;
        if !secure_directory(&metadata) || name_exists_at(&parent, &final_name)? {
            return Err(output_rejected());
        }
        Ok(Self {
            parent,
            final_name,
            final_path: path.to_owned(),
        })
    }
}

/// Owner-private staging follows Task 5's explicit boundary: same-euid principals that can enter
/// this exact mode-0700 staging namespace are trusted producer principals. The random name is
/// CSPRNG-derived, publication is one no-clobber rename, and uncertain stages are never deleted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationDurability {
    Durable,
    Uncertain,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishCheckpoint {
    BeforeRename,
    RenameVisibility,
    FirstParentFsync,
    EmptyContainerUnlink,
    FinalParentFsync,
    FinalReopen,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishFault {
    Once,
    Persistent,
    Interrupt,
}

#[cfg(test)]
thread_local! {
    static PUBLISH_FAULT: std::cell::Cell<Option<(PublishCheckpoint, PublishFault)>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn set_publish_fault(checkpoint: PublishCheckpoint, fault: PublishFault) {
    PUBLISH_FAULT.set(Some((checkpoint, fault)));
}

#[cfg(test)]
fn take_publish_fault(checkpoint: PublishCheckpoint) -> Option<PublishFault> {
    PUBLISH_FAULT.with(|configured| {
        let current = configured.get();
        if current.is_some_and(|(actual, _)| actual == checkpoint) {
            if current.is_some_and(|(_, fault)| fault != PublishFault::Persistent) {
                configured.set(None);
            }
            current.map(|(_, fault)| fault)
        } else {
            None
        }
    })
}

struct StagedOutput {
    parent: fs::File,
    final_name: CString,
    final_path: PathBuf,
    container_name: CString,
    container: fs::File,
    payload: fs::File,
    files: BTreeMap<String, (fs::File, FileIdentity, u64, String)>,
    published: bool,
}

impl StagedOutput {
    fn create(preflight: OutputPreflight) -> Result<Self, SignError> {
        let (container_name, container) = create_staging_container(&preflight.parent)?;
        let payload_name = CString::new("payload").expect("fixed payload name");
        // SAFETY: descriptor and fixed name are valid.
        if unsafe { libc::mkdirat(container.as_raw_fd(), payload_name.as_ptr(), 0o700) } != 0 {
            return Err(output_rejected());
        }
        let payload = open_directory_at(&container, "payload").map_err(|_| output_rejected())?;
        let metadata = payload.metadata().map_err(|_| output_rejected())?;
        if !secure_directory(&metadata) || metadata.nlink() != 2 {
            return Err(output_rejected());
        }
        container.sync_all().map_err(|_| output_rejected())?;
        bind_recovery_stage(&preflight.parent, &container_name, &container)?;
        Ok(Self {
            parent: preflight.parent,
            final_name: preflight.final_name,
            final_path: preflight.final_path,
            container_name,
            container,
            payload,
            files: BTreeMap::new(),
            published: false,
        })
    }

    fn write_file(&mut self, name: &str, bytes: &[u8]) -> Result<(), SignError> {
        if !safe_component(name) || self.files.contains_key(name) || bytes.is_empty() {
            return Err(output_rejected());
        }
        let name_c = CString::new(name).map_err(|_| output_rejected())?;
        // SAFETY: descriptor/name/mode are valid and O_EXCL prevents clobber.
        let descriptor = unsafe {
            libc::openat(
                self.payload.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(output_rejected());
        }
        // SAFETY: openat returned one owned descriptor.
        let mut file = unsafe { fs::File::from_raw_fd(descriptor) };
        file.write_all(bytes).map_err(|_| output_rejected())?;
        file.flush().map_err(|_| output_rejected())?;
        file.set_permissions(fs::Permissions::from_mode(0o400))
            .map_err(|_| output_rejected())?;
        file.sync_all().map_err(|_| output_rejected())?;
        let metadata = file.metadata().map_err(|_| output_rejected())?;
        if !secure_file(&metadata) || metadata.len() != bytes.len() as u64 {
            return Err(output_rejected());
        }
        self.files.insert(
            name.to_owned(),
            (
                file,
                FileIdentity::from_metadata(&metadata),
                bytes.len() as u64,
                sha256(bytes),
            ),
        );
        Ok(())
    }

    fn verify_files(&self, expected: &BTreeMap<String, Vec<u8>>) -> Result<(), SignError> {
        if enumerate_names(&self.payload).map_err(|_| output_rejected())?
            != expected.keys().cloned().collect()
        {
            return Err(output_rejected());
        }
        for (name, bytes) in expected {
            let (file, identity, size, digest) =
                self.files.get(name).ok_or_else(output_rejected)?;
            let metadata = file.metadata().map_err(|_| output_rejected())?;
            let rebound = open_regular_at(&self.payload, name).map_err(|_| output_rejected())?;
            let rebound = rebound.metadata().map_err(|_| output_rejected())?;
            if !secure_file(&metadata)
                || *identity != FileIdentity::from_metadata(&metadata)
                || *identity != FileIdentity::from_metadata(&rebound)
                || *size != bytes.len() as u64
                || digest != &sha256(bytes)
                || hash_file(file, *size).map_err(|_| output_rejected())? != *digest
            {
                return Err(output_rejected());
            }
        }
        self.payload.sync_all().map_err(|_| output_rejected())?;
        self.container.sync_all().map_err(|_| output_rejected())?;
        Ok(())
    }

    fn publish(&mut self) -> Result<PublicationDurability, SignError> {
        if self.published || name_exists_at(&self.parent, &self.final_name)? {
            return Err(output_rejected());
        }
        #[cfg(test)]
        if take_publish_fault(PublishCheckpoint::BeforeRename).is_some() {
            return Err(output_rejected());
        }
        let container = open_directory_at(
            &self.parent,
            self.container_name
                .to_str()
                .map_err(|_| output_rejected())?,
        )
        .map_err(|_| output_rejected())?;
        if FileIdentity::from_metadata(&container.metadata().map_err(|_| output_rejected())?)
            != FileIdentity::from_metadata(
                &self.container.metadata().map_err(|_| output_rejected())?,
            )
        {
            return Err(output_rejected());
        }
        let payload_name = CString::new("payload").expect("fixed payload name");
        // SAFETY: all descriptors and names are valid. RENAME_NOREPLACE is atomic.
        let status = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.container.as_raw_fd(),
                payload_name.as_ptr(),
                self.parent.as_raw_fd(),
                self.final_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if status != 0 {
            return Err(output_rejected());
        }
        self.published = true;
        let mut durability = PublicationDurability::Durable;
        #[cfg(test)]
        if take_publish_fault(PublishCheckpoint::RenameVisibility).is_some() {
            return Err(SignError::OutputDurabilityUncertain);
        }
        #[cfg(test)]
        let skip_first_fsync = take_publish_fault(PublishCheckpoint::FirstParentFsync).is_some();
        #[cfg(not(test))]
        let skip_first_fsync = false;
        if skip_first_fsync || self.parent.sync_all().is_err() {
            durability = PublicationDurability::Uncertain;
        }
        Ok(durability)
    }

    fn settle_verified_staging(&self) -> Result<PublicationDurability, SignError> {
        // The caller reopens and publicly verifies the visible output before reaching this exact
        // retained stage identity. Unknown or nonempty evidence is never removed.
        let container_metadata = self
            .container
            .metadata()
            .map_err(|_| SignError::OutputDurabilityUncertain)?;
        if !secure_directory(&container_metadata)
            || container_metadata.nlink() != 2
            || !enumerate_names(&self.container)
                .map_err(|_| SignError::OutputDurabilityUncertain)?
                .is_empty()
        {
            return Err(SignError::OutputDurabilityUncertain);
        }
        authorize_bound_stage_cleanup(&self.parent, &self.container_name, &self.container)?;
        let mut durability = PublicationDurability::Durable;
        #[cfg(test)]
        let unlink_fault = take_publish_fault(PublishCheckpoint::EmptyContainerUnlink);
        #[cfg(test)]
        if matches!(
            unlink_fault,
            Some(PublishFault::Persistent | PublishFault::Interrupt)
        ) {
            return Err(SignError::OutputDurabilityUncertain);
        }
        #[cfg(test)]
        if unlink_fault == Some(PublishFault::Once) {
            durability = PublicationDurability::Uncertain;
        }
        // SAFETY: the retained parent, exact random name, and identity-checked empty stage are valid.
        if unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.container_name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(SignError::OutputDurabilityUncertain);
        }
        #[cfg(test)]
        let skip_final_fsync = take_publish_fault(PublishCheckpoint::FinalParentFsync).is_some();
        #[cfg(not(test))]
        let skip_final_fsync = false;
        if skip_final_fsync || self.parent.sync_all().is_err() {
            durability = PublicationDurability::Uncertain;
        }
        Ok(durability)
    }
}

fn bind_recovery_stage(
    parent: &fs::File,
    name: &CString,
    directory: &fs::File,
) -> Result<(), SignError> {
    let Some(mut file) = open_recovery_binding(parent, true)? else {
        return Err(output_rejected());
    };
    let metadata = file.metadata().map_err(|_| output_rejected())?;
    if !secure_recovery_binding(&metadata, 0o600) {
        return Err(output_rejected());
    }
    let (mut value, stage) = parse_recovery_binding(&file)?;
    if stage.is_some() {
        return Err(output_rejected());
    }
    let directory_metadata = directory.metadata().map_err(|_| output_rejected())?;
    let name = name.to_str().map_err(|_| output_rejected())?;
    if !valid_staging_name(name)
        || !secure_directory(&directory_metadata)
        || directory_metadata.nlink() != 3
    {
        return Err(output_rejected());
    }
    value["staging"] = json!({
        "relative_name": name,
        "device": directory_metadata.dev(),
        "inode": directory_metadata.ino(),
        "uid": directory_metadata.uid(),
        "mode": directory_metadata.permissions().mode() & 0o7777,
        "cleanup_authorized": false,
    });
    rewrite_recovery_binding(&mut file, parent, &value, 0o600)
}

fn authorize_bound_stage_cleanup(
    parent: &fs::File,
    name: &CString,
    directory: &fs::File,
) -> Result<(), SignError> {
    let Some(file) = open_recovery_binding(parent, false)? else {
        return Err(output_rejected());
    };
    let (_, binding) = parse_recovery_binding(&file)?;
    let binding = binding.ok_or_else(output_rejected)?;
    let metadata = directory.metadata().map_err(|_| output_rejected())?;
    if name.to_str().ok() != Some(binding.relative_name.as_str())
        || FileIdentity::from_metadata(&metadata) != binding.identity
        || metadata.uid() != binding.uid
        || metadata.permissions().mode() & 0o7777 != binding.mode
    {
        return Err(output_rejected());
    }
    if binding.cleanup_authorized {
        return Ok(());
    }
    authorize_recovery_stage_cleanup(parent, &binding)
}

fn authorize_recovery_stage_cleanup(
    parent: &fs::File,
    expected: &RecoveryStageBinding,
) -> Result<(), SignError> {
    let mut file = open_recovery_binding(parent, true)?.ok_or_else(output_rejected)?;
    let metadata = file.metadata().map_err(|_| output_rejected())?;
    if !secure_recovery_binding(&metadata, 0o600) {
        return Err(output_rejected());
    }
    let (mut value, actual) = parse_recovery_binding(&file)?;
    let actual = actual.ok_or_else(output_rejected)?;
    if actual.relative_name != expected.relative_name
        || actual.identity != expected.identity
        || actual.uid != expected.uid
        || actual.mode != expected.mode
        || actual.cleanup_authorized
    {
        return Err(output_rejected());
    }
    value["staging"]["cleanup_authorized"] = Value::Bool(true);
    rewrite_recovery_binding(&mut file, parent, &value, 0o400)
}

fn read_recovery_stage_binding(
    parent: &fs::File,
) -> Result<Option<RecoveryStageBinding>, SignError> {
    let Some(file) = open_recovery_binding(parent, false)? else {
        return Ok(None);
    };
    let metadata = file.metadata().map_err(|_| verification_failed())?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !matches!(mode, 0o400 | 0o600) || !secure_recovery_binding(&metadata, mode) {
        return Err(verification_failed());
    }
    let (_, binding) = parse_recovery_binding(&file).map_err(|_| verification_failed())?;
    let binding = binding.ok_or_else(verification_failed)?;
    if (binding.cleanup_authorized && mode != 0o400)
        || (!binding.cleanup_authorized && mode != 0o600)
    {
        return Err(verification_failed());
    }
    Ok(Some(binding))
}

fn open_recovery_binding(parent: &fs::File, writable: bool) -> Result<Option<fs::File>, SignError> {
    let name = CString::new(RECOVERY_BINDING_NAME).expect("fixed recovery binding name");
    let flags = if writable {
        libc::O_RDWR
    } else {
        libc::O_RDONLY
    };
    // SAFETY: retained parent, fixed name, and no-follow flags are valid.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(output_rejected());
    }
    // SAFETY: openat returned one owned descriptor.
    Ok(Some(unsafe { fs::File::from_raw_fd(descriptor) }))
}

fn secure_recovery_binding(metadata: &fs::Metadata, mode: u32) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == mode
        && metadata.len() > 0
        && metadata.len() <= MAX_MANIFEST_BYTES
}

fn parse_recovery_binding(
    file: &fs::File,
) -> Result<(Value, Option<RecoveryStageBinding>), SignError> {
    let metadata = file.metadata().map_err(|_| output_rejected())?;
    let bytes = read_small_descriptor(file, metadata.len()).map_err(|_| output_rejected())?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| output_rejected())?;
    if serde_jcs::to_vec(&value).map_err(|_| output_rejected())? != bytes
        || value.as_object().is_none_or(|object| object.len() != 7)
        || value["schema_version"] != 1
        || value["kind"] != "sign_recovery_binding"
        || value["original_operation_mode"] != "sign"
        || ![
            "input_transfer_sha256",
            "launcher_config_sha256",
            "signer_sha256",
        ]
        .iter()
        .all(|name| value[*name].as_str().is_some_and(valid_sha256))
    {
        return Err(output_rejected());
    }
    if value["staging"].is_null() {
        return Ok((value, None));
    }
    let object = value["staging"].as_object().ok_or_else(output_rejected)?;
    if object.len() != 6 {
        return Err(output_rejected());
    }
    let relative_name = object
        .get("relative_name")
        .and_then(Value::as_str)
        .filter(|name| valid_staging_name(name))
        .ok_or_else(output_rejected)?
        .to_owned();
    let device = object
        .get("device")
        .and_then(Value::as_u64)
        .ok_or_else(output_rejected)?;
    let inode = object
        .get("inode")
        .and_then(Value::as_u64)
        .ok_or_else(output_rejected)?;
    let uid = object
        .get("uid")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value == current_euid())
        .ok_or_else(output_rejected)?;
    let mode = object
        .get("mode")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value == 0o700)
        .ok_or_else(output_rejected)?;
    let cleanup_authorized = object
        .get("cleanup_authorized")
        .and_then(Value::as_bool)
        .ok_or_else(output_rejected)?;
    Ok((
        value,
        Some(RecoveryStageBinding {
            relative_name,
            identity: FileIdentity { device, inode },
            uid,
            mode,
            cleanup_authorized,
        }),
    ))
}

fn rewrite_recovery_binding(
    file: &mut fs::File,
    parent: &fs::File,
    value: &Value,
    mode: u32,
) -> Result<(), SignError> {
    let bytes = serde_jcs::to_vec(value).map_err(|_| output_rejected())?;
    file.set_len(0).map_err(|_| output_rejected())?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| output_rejected())?;
    file.write_all(&bytes).map_err(|_| output_rejected())?;
    file.flush().map_err(|_| output_rejected())?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|_| output_rejected())?;
    file.sync_all().map_err(|_| output_rejected())?;
    let metadata = file.metadata().map_err(|_| output_rejected())?;
    if !secure_recovery_binding(&metadata, mode)
        || hash_file(file, metadata.len()).map_err(|_| output_rejected())? != sha256(&bytes)
    {
        return Err(output_rejected());
    }
    parent.sync_all().map_err(|_| output_rejected())
}

fn valid_staging_name(name: &str) -> bool {
    const PREFIX: &str = ".catalog-sign-stage-";
    name.len() == PREFIX.len() + 32
        && name.starts_with(PREFIX)
        && name[PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn create_staging_container(parent: &fs::File) -> Result<(CString, fs::File), SignError> {
    for _ in 0..128 {
        let mut random = [0_u8; 16];
        // SAFETY: getrandom writes at most the provided buffer length.
        let read =
            unsafe { libc::syscall(libc::SYS_getrandom, random.as_mut_ptr(), random.len(), 0) };
        if read != random.len() as i64 {
            return Err(output_rejected());
        }
        let name = CString::new(format!(
            ".catalog-sign-stage-{}",
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
        .map_err(|_| output_rejected())?;
        // SAFETY: parent/name/mode are valid.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
            let directory =
                open_directory_at(parent, name.to_str().map_err(|_| output_rejected())?)
                    .map_err(|_| output_rejected())?;
            let metadata = directory.metadata().map_err(|_| output_rejected())?;
            if !secure_directory(&metadata) || metadata.nlink() != 2 {
                return Err(output_rejected());
            }
            parent.sync_all().map_err(|_| output_rejected())?;
            return Ok((name, directory));
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(output_rejected());
        }
    }
    Err(output_rejected())
}

fn name_exists_at(parent: &fs::File, name: &CString) -> Result<bool, SignError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent/name/stat pointer are valid.
    let status = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status == 0 {
        return Ok(true);
    }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        return Ok(false);
    }
    Err(output_rejected())
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

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn safe_component(value: &str) -> bool {
    safe_component_bytes(value.as_bytes())
}

fn safe_component_bytes(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !matches!(value, b"." | b"..")
        && !value.contains(&b'/')
        && !value.contains(&0)
        && value.iter().all(u8::is_ascii)
        && !value.iter().any(u8::is_ascii_control)
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

fn encode_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn encode_base64url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        output.push(char::from(ALPHABET[usize::from(chunk[0] >> 2)]));
        output.push(char::from(
            ALPHABET
                [usize::from(((chunk[0] & 3) << 4) | (chunk.get(1).copied().unwrap_or(0) >> 4))],
        ));
        if let Some(second) = chunk.get(1) {
            output.push(char::from(
                ALPHABET
                    [usize::from(((second & 15) << 2) | (chunk.get(2).copied().unwrap_or(0) >> 6))],
            ));
        }
        if let Some(third) = chunk.get(2) {
            output.push(char::from(ALPHABET[usize::from(third & 63)]));
        }
    }
    output
}

pub fn assemble_release_intent_from_path(
    path: &Path,
) -> Result<UnsignedReleaseCandidateV1, SignError> {
    let bundle = verify_transferred_bundle(path)?;
    let bytes = bundle.record_bytes("release_intent")?;
    let intent = InitialPiReleaseIntentV1::from_json(&bytes).map_err(|_| candidate_rejected())?;
    assemble_release_intent(&bundle, &intent)
}

pub fn finalize_candidate_from_path(path: &Path) -> Result<UnsignedReleaseCandidateV1, SignError> {
    let bundle = verify_transferred_bundle(path)?;
    let source = CatalogSourceV1::from_json(&bundle.record_bytes("catalog_source")?)
        .map_err(|_| candidate_rejected())?;
    let qualification =
        CompatibilityQualificationV1::from_json(&bundle.record_bytes("qualification")?)
            .map_err(|_| candidate_rejected())?;
    finalize_candidate(&bundle, &source, &qualification)
}

pub(crate) fn run_isolated_cli(
    bundle: &VerifiedTransferredBundle,
    args: &[String],
) -> Result<String, SignError> {
    if args.is_empty()
        || args.len() > MAX_ARGUMENTS
        || args.iter().map(String::len).sum::<usize>() > MAX_ARGUMENT_BYTES
        || args.iter().any(|value| value.as_bytes().contains(&0))
    {
        return Err(SignError::ArgumentRejected);
    }
    match args[0].as_str() {
        "assemble-intent" => {
            let values = exact_flags(&args[1..], &["--input", "--output"])?;
            let bytes = bundle.record_bytes("release_intent")?;
            let intent =
                InitialPiReleaseIntentV1::from_json(&bytes).map_err(|_| candidate_rejected())?;
            let candidate = assemble_release_intent(bundle, &intent)?;
            write_candidate(Path::new(&values[1]), &candidate)?;
            Ok(format!(
                "assembled runtime_semantic_sha256={}",
                candidate.runtime_semantic_sha256()
            ))
        }
        "finalize" => {
            let values = exact_flags(&args[1..], &["--input", "--output"])?;
            let source = CatalogSourceV1::from_json(&bundle.record_bytes("catalog_source")?)
                .map_err(|_| candidate_rejected())?;
            let qualification =
                CompatibilityQualificationV1::from_json(&bundle.record_bytes("qualification")?)
                    .map_err(|_| candidate_rejected())?;
            let candidate = finalize_candidate(bundle, &source, &qualification)?;
            write_candidate(Path::new(&values[1]), &candidate)?;
            Ok(format!(
                "finalized runtime_semantic_sha256={}",
                candidate.runtime_semantic_sha256()
            ))
        }
        "sign" => {
            let values = exact_flags(&args[1..], &["--input", "--key", "--output"])?;
            let source = CatalogSourceV1::from_json(&bundle.record_bytes("catalog_source")?)
                .map_err(|_| candidate_rejected())?;
            let qualification =
                CompatibilityQualificationV1::from_json(&bundle.record_bytes("qualification")?)
                    .map_err(|_| candidate_rejected())?;
            let signed = sign_release(SignReleaseRequest {
                bundle,
                source: &source,
                qualification: &qualification,
                key_path: Path::new(&values[1]),
                output: Path::new(&values[2]),
            })?;
            Ok(format!(
                "signed key_id={} tag={}",
                signed.manifest.signature().key_id().as_str(),
                signed.manifest.tag().as_str()
            ))
        }
        "recover-sign" => {
            exact_flags(&args[1..], &["--input", "--output"])?;
            recover_production_isolated_output(bundle)?;
            Ok("signed output recovered".to_owned())
        }
        _ => Err(SignError::ArgumentRejected),
    }
}

pub(crate) fn recover_production_isolated_output(
    bundle: &VerifiedTransferredBundle,
) -> Result<(), SignError> {
    let source = CatalogSourceV1::from_json(&bundle.record_bytes("catalog_source")?)
        .map_err(|_| candidate_rejected())?;
    let qualification =
        CompatibilityQualificationV1::from_json(&bundle.record_bytes("qualification")?)
            .map_err(|_| candidate_rejected())?;
    let candidate = finalize_candidate(bundle, &source, &qualification)?;
    recover_signed_output(
        Path::new("/output/signed-release-bundle"),
        &candidate,
        SignatureVerificationPolicy::Production,
    )
    .map(|_| ())
}

#[cfg(feature = "fixture-tools")]
pub(crate) fn run_fixture_isolated_cli(
    bundle: &VerifiedTransferredBundle,
    args: &[String],
) -> Result<String, SignError> {
    if args.is_empty()
        || args.len() > MAX_ARGUMENTS
        || args.iter().map(String::len).sum::<usize>() > MAX_ARGUMENT_BYTES
        || args.iter().any(|value| value.as_bytes().contains(&0))
    {
        return Err(SignError::ArgumentRejected);
    }
    let candidate = fixture_candidate(bundle)?;
    if args[0] == "recover-sign" {
        let values = exact_flags(&args[1..], &["--input", "--output"])?;
        recover_signed_output(
            Path::new(&values[1]),
            &candidate,
            SignatureVerificationPolicy::Fixture,
        )?;
        return Ok("fixture signed output recovered".to_owned());
    }
    if args[0] != "sign" {
        return Err(SignError::ArgumentRejected);
    }
    let values = exact_flags(&args[1..], &["--input", "--key", "--output"])?;
    let output = Path::new(&values[2]);
    let preflight = OutputPreflight::new(output)?;
    let signing_key = crate::key::read_fixture_signing_key(Path::new(&values[1]))?;
    let signed_bytes = sign_candidate(&candidate, signing_key.as_dalek(), "catalog-test-key-v1")?;
    drop(signing_key);
    verify_signed_bytes(&signed_bytes, SignatureVerificationPolicy::Fixture)?;
    let signed = write_signed_output(
        preflight,
        signed_bytes,
        SignatureVerificationPolicy::Fixture,
    )?;
    Ok(format!(
        "fixture signed key_id={} tag={}",
        signed.manifest.signature().key_id().as_str(),
        signed.manifest.tag().as_str()
    ))
}

#[cfg(feature = "fixture-tools")]
pub(crate) fn recover_fixture_isolated_output(
    bundle: &VerifiedTransferredBundle,
) -> Result<(), SignError> {
    let candidate = fixture_candidate(bundle)?;
    recover_signed_output(
        Path::new("/output/signed-release-bundle"),
        &candidate,
        SignatureVerificationPolicy::Fixture,
    )
    .map(|_| ())
}

#[cfg(feature = "fixture-tools")]
fn fixture_candidate(
    bundle: &VerifiedTransferredBundle,
) -> Result<UnsignedReleaseCandidateV1, SignError> {
    bundle.reverify_all()?;
    let payload = CatalogPayloadV1::from_json(include_bytes!(
        "../../../conformance/catalog-v1/valid-payload.json"
    ))
    .map_err(|_| candidate_rejected())?;
    let canonical_payload =
        canonical_catalog_payload(&payload).map_err(|_| candidate_rejected())?;
    let object = bundle
        .inventory
        .objects()
        .first()
        .ok_or_else(candidate_rejected)?;
    let object_bytes = bundle.read_small_file(object.relative_path().as_str())?;
    let qualification = bundle.record_bytes("qualification")?;
    let source_commit = bundle
        .source_commit()
        .ok_or_else(candidate_rejected)?
        .to_owned();
    let source_tree_sha256 = bundle
        .source_tree_sha256()
        .ok_or_else(candidate_rejected)?
        .to_owned();
    let asset_name = format!("fixture-asset-{}.bin", object.sha256().as_str());
    let candidate = UnsignedReleaseCandidateV1 {
        runtime_semantic_sha256: sha256(&canonical_payload),
        canonical_payload,
        tag: "catalog-v1-sequence-42".to_owned(),
        support_assets: vec![CandidateAsset {
            name: asset_name,
            bytes: object_bytes,
            sha256: object.sha256().as_str().to_owned(),
        }],
        final_bindings: Some(FinalBindings {
            source_commit,
            source_tree_sha256,
            qualification_sha256: sha256(&qualification),
        }),
    };
    require_candidate_bounds(&candidate)?;
    Ok(candidate)
}

fn exact_flags(args: &[String], flags: &[&str]) -> Result<Vec<String>, SignError> {
    if args.len() != flags.len() * 2 {
        return Err(SignError::ArgumentRejected);
    }
    let mut values = Vec::with_capacity(flags.len());
    for (pair, expected) in args.chunks_exact(2).zip(flags) {
        if pair[0] != *expected || pair[1].is_empty() || pair[1].len() > 4_096 {
            return Err(SignError::ArgumentRejected);
        }
        values.push(pair[1].clone());
    }
    Ok(values)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CandidateOutputCheckpoint {
    Link,
    ParentFsync,
    FinalReopen,
}

fn write_candidate(path: &Path, candidate: &UnsignedReleaseCandidateV1) -> Result<(), SignError> {
    write_candidate_atomically(path, &candidate.canonical_payload, |_| Ok(()))
}

fn write_candidate_atomically(
    path: &Path,
    bytes: &[u8],
    mut checkpoint: impl FnMut(CandidateOutputCheckpoint) -> Result<(), SignError>,
) -> Result<(), SignError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(output_rejected());
    }
    let preflight = OutputPreflight::new(path)?;
    let dot = CString::new(".").expect("fixed temporary-file path");
    // SAFETY: the retained parent descriptor, fixed path, flags, and mode are valid. O_TMPFILE
    // creates an unnamed inode, so every failure before link leaves no visible partial output.
    let descriptor = unsafe {
        libc::openat(
            preflight.parent.as_raw_fd(),
            dot.as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(output_rejected());
    }
    // SAFETY: openat returned one newly owned descriptor.
    let mut temporary = unsafe { fs::File::from_raw_fd(descriptor) };
    let initial = temporary.metadata().map_err(|_| output_rejected())?;
    if !secure_candidate_file(&initial, 0o600, 0) || initial.len() != 0 {
        return Err(output_rejected());
    }
    let identity = FileIdentity::from_metadata(&initial);
    temporary.write_all(bytes).map_err(|_| output_rejected())?;
    temporary.flush().map_err(|_| output_rejected())?;
    temporary.sync_all().map_err(|_| output_rejected())?;
    // SAFETY: the descriptor remains valid and 0400 is the exact settled mode.
    if unsafe { libc::fchmod(temporary.as_raw_fd(), 0o400) } != 0 {
        return Err(output_rejected());
    }
    temporary.sync_all().map_err(|_| output_rejected())?;
    let settled = temporary.metadata().map_err(|_| output_rejected())?;
    if !secure_candidate_file(&settled, 0o400, 0)
        || settled.len() != bytes.len() as u64
        || FileIdentity::from_metadata(&settled) != identity
        || hash_file(&temporary, bytes.len() as u64).map_err(|_| output_rejected())?
            != sha256(bytes)
    {
        return Err(output_rejected());
    }
    checkpoint(CandidateOutputCheckpoint::Link)?;
    if !secure_directory(&preflight.parent.metadata().map_err(|_| output_rejected())?)
        || name_exists_at(&preflight.parent, &preflight.final_name)?
    {
        return Err(output_rejected());
    }
    // SAFETY: AT_EMPTY_PATH links the exact retained unnamed inode. linkat has no replacement
    // behavior, so a concurrently created destination fails closed without clobbering it.
    if unsafe {
        libc::linkat(
            temporary.as_raw_fd(),
            c"".as_ptr(),
            preflight.parent.as_raw_fd(),
            preflight.final_name.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    } != 0
    {
        return Err(output_rejected());
    }

    // From this point the complete, settled file is committed. A parent-fsync error reports
    // durability indeterminate and deliberately does not remove or replace the committed name.
    checkpoint(CandidateOutputCheckpoint::ParentFsync)?;
    preflight.parent.sync_all().map_err(|_| output_rejected())?;
    checkpoint(CandidateOutputCheckpoint::FinalReopen)?;
    let reopened = open_regular_at(
        &preflight.parent,
        preflight
            .final_name
            .to_str()
            .map_err(|_| output_rejected())?,
    )
    .map_err(|_| output_rejected())?;
    let reopened_metadata = reopened.metadata().map_err(|_| output_rejected())?;
    if !secure_candidate_file(&reopened_metadata, 0o400, 1)
        || reopened_metadata.len() != bytes.len() as u64
        || FileIdentity::from_metadata(&reopened_metadata) != identity
        || hash_file(&reopened, bytes.len() as u64).map_err(|_| output_rejected())? != sha256(bytes)
    {
        return Err(output_rejected());
    }
    Ok(())
}

fn secure_candidate_file(metadata: &fs::Metadata, mode: u32, links: u64) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == current_euid()
        && metadata.nlink() == links
        && metadata.permissions().mode() & 0o7777 == mode
}

#[cfg(feature = "fixture-tools")]
pub fn generate_fixture_envelope(payload_bytes: &[u8]) -> Result<Vec<u8>, SignError> {
    const FIXTURE_KEY_ID: &str = "catalog-test-key-v1";
    if FIXTURE_KEY_ID == production_key_identity().key_id() {
        return Err(SignError::SigningKeyRejected);
    }
    let payload = CatalogPayloadV1::from_json(payload_bytes).map_err(|_| candidate_rejected())?;
    let canonical = canonical_catalog_payload(&payload).map_err(|_| candidate_rejected())?;
    let key = crate::key::fixture_signing_key()?;
    let signature = key.as_dalek().sign(&canonical);
    drop(key);
    let payload: Value = serde_json::from_slice(&canonical).map_err(|_| candidate_rejected())?;
    let envelope = serde_jcs::to_vec(&json!({
        "envelope_version": 1,
        "signature_algorithm": "ed25519",
        "key_id": FIXTURE_KEY_ID,
        "payload": payload,
        "signature": encode_base64url_no_pad(&signature.to_bytes()),
    }))
    .map_err(|_| candidate_rejected())?;
    catalog_core::verify_fixture_signed_catalog(&envelope).map_err(|_| verification_failed())?;
    Ok(envelope)
}

const fn bundle_rejected() -> SignError {
    SignError::TransferredBundleRejected
}
const fn candidate_rejected() -> SignError {
    SignError::CandidateRejected
}
const fn output_rejected() -> SignError {
    SignError::OutputRejected
}
const fn verification_failed() -> SignError {
    SignError::VerificationFailed
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use catalog_core::{
        CatalogSourceV1, CompatibilityQualificationV1, FluxsembleBuildBindingV1,
        InitialPiReleaseIntentV1, compatibility_input_digest, qualification_record_digest,
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::key::{fixture_signing_key_for_test, key_open_count, reset_key_open_count};

    const SRI: &str = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    const MAX_AUTHENTIC_CORPUS_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

    #[test]
    fn committed_approved_evidence_derives_compiled_admission_digests() {
        let package_inputs_bytes =
            include_bytes!("../tests/fixtures/approved-release/package-input-manifest-v1.json");
        let package_inputs = parse_package_inputs(package_inputs_bytes).unwrap();
        assert_eq!(
            serde_jcs::to_vec(&package_inputs).unwrap(),
            package_inputs_bytes
        );
        assert_eq!(package_inputs_bytes.len(), 78_346);
        assert_eq!(
            sha256(package_inputs_bytes),
            "d511e45be4fc28ec20c62c2450b61ab61e61fbbd12024a1e95698ab0b702a02d"
        );
        assert_eq!(
            approved_package_input_digest(package_inputs_bytes),
            APPROVED_PACKAGE_INPUT_DOMAIN_SHA256
        );

        let intent_bytes =
            include_bytes!("../tests/fixtures/approved-release/initial-release-intent-v1.json");
        let intent = InitialPiReleaseIntentV1::from_json(intent_bytes).unwrap();
        assert_eq!(serde_jcs::to_vec(&intent).unwrap(), intent_bytes);
        assert_eq!(
            approved_release_semantic_digest(&intent).unwrap(),
            APPROVED_RELEASE_SEMANTIC_SHA256
        );
        require_release_admission(
            &intent,
            package_inputs_bytes,
            ReleaseAdmissionPolicy::Production,
        )
        .unwrap();
    }

    #[test]
    fn approved_evidence_manifest_is_canonical_and_binds_local_fixture_files() {
        let evidence_bytes =
            include_bytes!("../tests/fixtures/approved-release/evidence-manifest-v1.json");
        let evidence: Value = serde_json::from_slice(evidence_bytes).unwrap();
        assert_eq!(serde_jcs::to_vec(&evidence).unwrap(), evidence_bytes);
        assert_eq!(
            evidence.pointer("/source/initial_runtime_matrix/sha256"),
            Some(&json!(
                "6f389eb3b8b040acda99e63b8dfb0be710dc666182438b7b1c5881e430076d53"
            ))
        );
        assert_eq!(
            evidence.pointer("/source/approval_report/sha256"),
            Some(&json!(
                "c4864c7bdccaf5ee9fa2e607ecf46a1657c8026fa6af0f492e021cf4724c4996"
            ))
        );
        assert_eq!(
            evidence.pointer("/immutable_release_semantic/excluded_freshness_fields"),
            Some(&json!(["sequence", "tag", "generated_at", "expires_at"]))
        );
        assert_eq!(
            evidence.pointer(
                "/task_6_initial_release_approval/representative_fixture_freshness/compiled_production_authority"
            ),
            Some(&json!(false))
        );

        let expected = [
            (
                "initial-release-intent-v1.json",
                include_bytes!("../tests/fixtures/approved-release/initial-release-intent-v1.json")
                    .as_slice(),
            ),
            (
                "package-input-manifest-v1.json",
                include_bytes!("../tests/fixtures/approved-release/package-input-manifest-v1.json")
                    .as_slice(),
            ),
        ];
        let entries = evidence["fixture_files"].as_array().unwrap();
        assert_eq!(entries.len(), expected.len());
        for (entry, (name, bytes)) in entries.iter().zip(expected) {
            assert_eq!(entry["path"], name);
            assert_eq!(entry["size"], bytes.len() as u64);
            assert_eq!(entry["sha256"], sha256(bytes));
        }
    }

    #[test]
    fn strict_approved_fixtures_reject_duplicates_and_mutation() {
        let package_inputs_bytes =
            include_bytes!("../tests/fixtures/approved-release/package-input-manifest-v1.json");
        let duplicate_package = String::from_utf8(package_inputs_bytes.to_vec())
            .unwrap()
            .replacen(
                "\"schema_version\":1,",
                "\"schema_version\":1,\"schema_version\":1,",
                1,
            );
        assert!(parse_package_inputs(duplicate_package.as_bytes()).is_err());

        let intent_bytes =
            include_bytes!("../tests/fixtures/approved-release/initial-release-intent-v1.json");
        let duplicate_intent = String::from_utf8(intent_bytes.to_vec()).unwrap().replacen(
            "\"fluxsemble_requirement\":\"=0.1.0\",",
            "\"fluxsemble_requirement\":\"=0.1.0\",\"fluxsemble_requirement\":\"=0.1.0\",",
            1,
        );
        assert!(InitialPiReleaseIntentV1::from_json(duplicate_intent.as_bytes()).is_err());

        let mut package_mutation: Value = serde_json::from_slice(package_inputs_bytes).unwrap();
        package_mutation["root"]["archive_member_count"] = json!(885);
        let package_mutation = serde_jcs::to_vec(&package_mutation).unwrap();
        parse_package_inputs(&package_mutation).unwrap();
        assert_ne!(sha256(&package_mutation), sha256(package_inputs_bytes));
        assert_ne!(
            approved_package_input_digest(&package_mutation),
            APPROVED_PACKAGE_INPUT_DOMAIN_SHA256
        );
        reset_key_open_count();
        assert_eq!(
            require_release_admission(
                &approved_evidence_intent(),
                &package_mutation,
                ReleaseAdmissionPolicy::Production,
            ),
            Err(SignError::CandidateRejected)
        );
        assert_eq!(key_open_count(), 0);
    }

    #[test]
    fn complete_immutable_release_projection_rejects_every_leaf_and_structural_mutation() {
        let package_inputs =
            include_bytes!("../tests/fixtures/approved-release/package-input-manifest-v1.json");
        let baseline_bytes =
            include_bytes!("../tests/fixtures/approved-release/initial-release-intent-v1.json");
        let baseline: Value = serde_json::from_slice(baseline_bytes).unwrap();
        let mut pointers = Vec::new();
        collect_leaf_pointers(
            &baseline["fluxsemble_requirement"],
            "/fluxsemble_requirement",
            &mut pointers,
        );
        collect_leaf_pointers(&baseline["release"], "/release", &mut pointers);
        assert!(
            pointers.len() > 850,
            "complete locked closure was not enumerated"
        );
        for required in [
            "/release/release/release_metadata/title",
            "/release/release/release_metadata/notes",
            "/release/release/components/0/artifacts/0/inventory/0/path",
            "/release/release/components/0/artifacts/0/inventory/0/size_bytes",
            "/release/release/components/0/artifacts/0/inventory/0/sha256",
            "/release/release/components/1/artifacts/0/inventory/0/path",
            "/release/release/components/1/artifacts/0/inventory/0/size_bytes",
            "/release/release/components/1/artifacts/0/inventory/0/sha256",
            "/release/release/provider_extension/metadata/shipped_shrinkwrap/locked_packages/138/archive_sha256",
        ] {
            assert!(
                pointers.iter().any(|pointer| pointer == required),
                "missing {required}"
            );
        }

        reset_key_open_count();
        let mut parsed_mutations = 0_usize;
        for pointer in &pointers {
            let mut mutation = baseline.clone();
            let original = mutation.pointer(pointer).unwrap().clone();
            *mutation.pointer_mut(pointer).unwrap() = mutated_leaf(&original);
            let bytes = serde_jcs::to_vec(&mutation).unwrap();
            if let Ok(intent) = InitialPiReleaseIntentV1::from_json(&bytes) {
                parsed_mutations += 1;
                assert_eq!(
                    require_release_admission(
                        &intent,
                        package_inputs,
                        ReleaseAdmissionPolicy::Production,
                    ),
                    Err(SignError::CandidateRejected),
                    "production admission accepted immutable leaf {pointer}"
                );
            }
            assert_eq!(key_open_count(), 0, "key opened for {pointer}");
        }
        assert!(
            parsed_mutations > 700,
            "mutations did not exercise the compiled semantic gate"
        );

        for pointer in [
            "/release/release/release_metadata/title",
            "/release/release/release_metadata/notes",
            "/release/release/components/0/artifacts/0/inventory/0/path",
            "/release/release/components/0/artifacts/0/inventory/0/size_bytes",
            "/release/release/components/0/artifacts/0/inventory/0/sha256",
            "/release/release/components/1/artifacts/0/inventory/0/size_bytes",
            "/release/release/components/1/artifacts/0/inventory/0/sha256",
            "/release/release/provider_extension/metadata/shipped_shrinkwrap/locked_packages/0/archive_sha256",
        ] {
            let mut mutation = baseline.clone();
            let original = mutation.pointer(pointer).unwrap().clone();
            *mutation.pointer_mut(pointer).unwrap() = mutated_leaf(&original);
            let intent =
                InitialPiReleaseIntentV1::from_json(&serde_jcs::to_vec(&mutation).unwrap())
                    .unwrap_or_else(|_| {
                        panic!("strict model rejected semantic-gate probe {pointer}")
                    });
            require_approved_production_tuple(&intent).unwrap();
            assert_ne!(
                approved_release_semantic_digest(&intent).unwrap(),
                APPROVED_RELEASE_SEMANTIC_SHA256,
                "semantic digest omitted {pointer}"
            );
        }

        for (name, mutation) in structural_release_mutations(&baseline) {
            let bytes = serde_jcs::to_vec(&mutation).unwrap();
            if let Ok(intent) = InitialPiReleaseIntentV1::from_json(&bytes) {
                assert_eq!(
                    require_release_admission(
                        &intent,
                        package_inputs,
                        ReleaseAdmissionPolicy::Production,
                    ),
                    Err(SignError::CandidateRejected),
                    "production admission accepted structural mutation {name}"
                );
            }
            assert_eq!(key_open_count(), 0, "key opened for {name}");
        }
    }

    #[test]
    fn immutable_semantic_excludes_only_representative_freshness() {
        let approved = approved_evidence_intent();
        let baseline = approved_release_semantic_digest(&approved).unwrap();
        let mut value: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/approved-release/initial-release-intent-v1.json"
        ))
        .unwrap();
        value["generated_at"] = json!("2026-08-27T00:00:00Z");
        value["expires_at"] = json!("2026-09-27T00:00:00Z");
        let freshness =
            InitialPiReleaseIntentV1::from_json(&serde_jcs::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            approved_release_semantic_digest(&freshness).unwrap(),
            baseline
        );
        require_release_admission(
            &freshness,
            include_bytes!("../tests/fixtures/approved-release/package-input-manifest-v1.json"),
            ReleaseAdmissionPolicy::Production,
        )
        .unwrap();

        value["sequence"] = json!("2");
        value["tag"] = json!("catalog-v1-sequence-2");
        let retagged =
            InitialPiReleaseIntentV1::from_json(&serde_jcs::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            require_release_admission(
                &retagged,
                include_bytes!("../tests/fixtures/approved-release/package-input-manifest-v1.json"),
                ReleaseAdmissionPolicy::Production,
            ),
            Err(SignError::CandidateRejected),
            "tag-bound support URLs admitted a different initial tag"
        );
    }

    #[test]
    fn individual_production_tuple_checks_remain_defense_in_depth() {
        let approved = approved_evidence_intent();
        require_approved_production_tuple(&approved).unwrap();
        let baseline: Value =
            serde_json::from_slice(&serde_jcs::to_vec(&approved).unwrap()).unwrap();
        for (pointer, replacement) in [
            ("/release/provider", json!("builtin:other")),
            ("/release/release/target", json!("linux_arm64")),
            (
                "/release/release/components/0/artifacts/0/url",
                json!("https://nodejs.org/dist/v22.19.0/substituted.tar.xz"),
            ),
            (
                "/release/release/components/0/artifacts/0/size_bytes",
                json!("30479989"),
            ),
            (
                "/release/release/components/0/artifacts/0/sha256",
                json!("11".repeat(32)),
            ),
            (
                "/release/release/components/1/artifacts/0/url",
                json!("https://registry.npmjs.org/substituted.tgz"),
            ),
            (
                "/release/release/components/1/artifacts/0/size_bytes",
                json!("4992067"),
            ),
            (
                "/release/release/components/1/artifacts/0/sha256",
                json!("12".repeat(32)),
            ),
            (
                "/release/release/provider_extension/metadata/registry_integrity",
                json!(SRI),
            ),
            (
                "/release/release/provider_extension/metadata/root_package_manifest/url",
                json!("https://github.com/substituted.json"),
            ),
            (
                "/release/release/provider_extension/metadata/root_package_manifest/size_bytes",
                json!("3561"),
            ),
            (
                "/release/release/provider_extension/metadata/root_package_manifest/sha256",
                json!("13".repeat(32)),
            ),
            (
                "/release/release/provider_extension/metadata/shipped_shrinkwrap/artifact/url",
                json!("https://github.com/substituted-shrinkwrap.json"),
            ),
            (
                "/release/release/provider_extension/metadata/shipped_shrinkwrap/artifact/size_bytes",
                json!("61541"),
            ),
            (
                "/release/release/provider_extension/metadata/shipped_shrinkwrap/artifact/sha256",
                json!("14".repeat(32)),
            ),
        ] {
            let mut mutation = baseline.clone();
            *mutation.pointer_mut(pointer).unwrap() = replacement;
            if let Ok(intent) =
                InitialPiReleaseIntentV1::from_json(&serde_jcs::to_vec(&mutation).unwrap())
            {
                assert!(
                    require_approved_production_tuple(&intent).is_err(),
                    "production policy accepted mutation at {pointer}"
                );
            }
        }
    }

    fn approved_evidence_intent() -> InitialPiReleaseIntentV1 {
        InitialPiReleaseIntentV1::from_json(include_bytes!(
            "../tests/fixtures/approved-release/initial-release-intent-v1.json"
        ))
        .unwrap()
    }

    fn collect_leaf_pointers(value: &Value, pointer: &str, output: &mut Vec<String>) {
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    let key = key.replace('~', "~0").replace('/', "~1");
                    collect_leaf_pointers(child, &format!("{pointer}/{key}"), output);
                }
            }
            Value::Array(array) => {
                for (index, child) in array.iter().enumerate() {
                    collect_leaf_pointers(child, &format!("{pointer}/{index}"), output);
                }
            }
            _ => output.push(pointer.to_owned()),
        }
    }

    fn mutated_leaf(original: &Value) -> Value {
        match original {
            Value::String(value)
                if value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')) =>
            {
                let mut mutated = value.as_bytes().to_vec();
                mutated[0] = if mutated[0] == b'a' { b'b' } else { b'a' };
                json!(String::from_utf8(mutated).unwrap())
            }
            Value::String(value) if value.bytes().all(|byte| byte.is_ascii_digit()) => {
                json!((value.parse::<u64>().unwrap() + 1).to_string())
            }
            Value::String(value) if value.starts_with("sha512-") => {
                let mut mutated = value.as_bytes().to_vec();
                mutated[7] = if mutated[7] == b'A' { b'B' } else { b'A' };
                json!(String::from_utf8(mutated).unwrap())
            }
            Value::String(value) if value == "=0.1.0" => json!("=0.1.1"),
            Value::String(value) if value == "0.83.0" => json!("0.83.1"),
            Value::String(value) if value == "22.19.0" => json!("22.19.1"),
            Value::String(value) if value.starts_with("https://") => {
                json!(format!("{value}-task6-mutation"))
            }
            Value::String(value) => json!(format!("{value}-task6-mutation")),
            Value::Number(value) => json!(value.as_u64().unwrap() + 1),
            Value::Bool(value) => json!(!value),
            Value::Null | Value::Array(_) | Value::Object(_) => {
                panic!("mutation helper expected a scalar")
            }
        }
    }

    fn structural_release_mutations(baseline: &Value) -> Vec<(&'static str, Value)> {
        let mut mutations = Vec::new();

        let mut allowed_origin_extra = baseline.clone();
        allowed_origin_extra["release"]["allowed_origins"]
            .as_array_mut()
            .unwrap()
            .push(json!("https://z-task6.example"));
        mutations.push(("allowed origin extra", allowed_origin_extra));

        let mut allowed_origin_reorder = baseline.clone();
        allowed_origin_reorder["release"]["allowed_origins"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        mutations.push(("allowed origin reorder", allowed_origin_reorder));

        let mut component_reorder = baseline.clone();
        component_reorder["release"]["release"]["components"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        mutations.push(("component reorder", component_reorder));

        let mut component_extra = baseline.clone();
        let mut extra = component_extra["release"]["release"]["components"][0].clone();
        extra["component_id"] = json!("component:node-extra");
        extra["artifacts"][0]["artifact_id"] = json!("artifact:node-extra");
        component_extra["release"]["release"]["components"]
            .as_array_mut()
            .unwrap()
            .insert(1, extra);
        mutations.push(("component extra", component_extra));

        let mut artifact_extra = baseline.clone();
        let mut extra =
            artifact_extra["release"]["release"]["components"][0]["artifacts"][0].clone();
        extra["artifact_id"] = json!("artifact:node-linux-x86_64-extra");
        artifact_extra["release"]["release"]["components"][0]["artifacts"]
            .as_array_mut()
            .unwrap()
            .push(extra);
        mutations.push(("artifact extra", artifact_extra));

        for (name, component, path) in [
            ("node inventory extra", 0, "bin/node-extra"),
            ("pi inventory extra", 1, "dist/cli-extra.js"),
        ] {
            let mut mutation = baseline.clone();
            mutation["release"]["release"]["components"][component]["artifacts"][0]["inventory"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "path": path,
                    "size_bytes": "1",
                    "sha256": "ab".repeat(32),
                }));
            mutations.push((name, mutation));
        }

        let mut extension_extra = baseline.clone();
        extension_extra["release"]["release"]["provider_extension"]["metadata"]["unapproved_task6_field"] =
            json!(true);
        mutations.push(("provider extension extra", extension_extra));

        let locked_pointer =
            "/release/release/provider_extension/metadata/shipped_shrinkwrap/locked_packages";
        let mut locked_extra = baseline.clone();
        locked_extra
            .pointer_mut(locked_pointer)
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(json!({
                "locator": "node_modules/zz-task6-extra",
                "name": "zz-task6-extra",
                "version": "1.0.0",
                "resolved_url": "https://registry.npmjs.org/zz-task6-extra/-/zz-task6-extra-1.0.0.tgz",
                "registry_integrity": SRI,
                "archive_sha256": "ab".repeat(32),
            }));
        mutations.push(("provider extension locked record extra", locked_extra));

        let mut locked_reorder = baseline.clone();
        locked_reorder
            .pointer_mut(locked_pointer)
            .unwrap()
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        mutations.push(("provider extension locked record reorder", locked_reorder));

        mutations
    }

    #[test]
    fn public_production_entry_points_reject_synthetic_tuples_before_key_open() {
        let fixture = CandidateFixture::new();
        let intent_bundle = verify_transferred_bundle(&fixture.intent_bundle).unwrap();
        let final_bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
        reset_key_open_count();
        assert_eq!(
            assemble_release_intent(&intent_bundle, &fixture.intent),
            Err(SignError::CandidateRejected)
        );
        assert_eq!(
            finalize_candidate(&final_bundle, &fixture.source, &fixture.qualification),
            Err(SignError::CandidateRejected)
        );
        let output = fixture.root.path.join("production-rejected-output");
        assert!(matches!(
            sign_release(SignReleaseRequest {
                bundle: &final_bundle,
                source: &fixture.source,
                qualification: &fixture.qualification,
                key_path: &fixture.fixture_key,
                output: &output,
            }),
            Err(SignError::CandidateRejected)
        ));
        assert_eq!(key_open_count(), 0);
        assert!(!output.exists());
    }

    #[test]
    fn intent_and_final_candidates_bind_the_same_runtime_semantics_and_only_final_can_sign() {
        let fixture = CandidateFixture::new();
        let intent_bundle = verify_transferred_bundle(&fixture.intent_bundle).unwrap();
        let intent =
            assemble_release_intent_after_admission_for_test(&intent_bundle, &fixture.intent)
                .unwrap();
        assert!(!intent.is_production_signable());

        let final_bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
        let final_candidate = finalize_candidate_after_admission_for_test(
            &final_bundle,
            &fixture.source,
            &fixture.qualification,
        )
        .unwrap();
        assert!(final_candidate.is_production_signable());
        assert_eq!(
            final_candidate.runtime_semantic_sha256(),
            intent.runtime_semantic_sha256()
        );
        assert_eq!(
            final_candidate.canonical_payload(),
            intent.canonical_payload()
        );
        assert_eq!(intent.support_asset_names().len(), 2);
        assert_eq!(intent.unsigned_inventory().len(), 3);
        let final_inventory = final_candidate.unsigned_inventory();
        assert_eq!(final_candidate.support_asset_names().len(), 3);
        assert_eq!(final_inventory.len(), 4);
        assert!(
            final_inventory
                .windows(2)
                .all(|pair| pair[0].name() < pair[1].name())
        );
        assert!(
            final_inventory
                .iter()
                .all(|entry| entry.size() > 0 && valid_sha256(entry.sha256()))
        );
    }

    #[test]
    fn fixture_signing_exercises_both_domains_atomic_output_and_complete_inventory() {
        let fixture = CandidateFixture::new();
        let bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
        let candidate = finalize_candidate_after_admission_for_test(
            &bundle,
            &fixture.source,
            &fixture.qualification,
        )
        .unwrap();
        let key = fixture_signing_key_for_test();
        let signed = sign_candidate(&candidate, key.as_dalek(), "catalog-test-key-v1").unwrap();
        drop(key);
        verify_signed_bytes(&signed, SignatureVerificationPolicy::Fixture).unwrap();
        let unmodified_catalog = signed.files.get(CATALOG_NAME).unwrap();
        let unmodified_release = signed.files.get(RELEASE_MANIFEST_NAME).unwrap();
        verify_fixture_signatures(unmodified_catalog, unmodified_release).unwrap();
        #[cfg(feature = "fixture-tools")]
        {
            catalog_core::verify_fixture_signed_catalog(unmodified_catalog).unwrap();
            catalog_core::verify_fixture_signed_release_bundle_manifest(unmodified_release)
                .unwrap();
        }

        let catalog_value: Value = serde_json::from_slice(unmodified_catalog).unwrap();
        let release_value: Value = serde_json::from_slice(unmodified_release).unwrap();
        let catalog_signature = catalog_value["signature"].as_str().unwrap().to_owned();
        let release_signature = release_value["signature"]["signature"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut catalog_cross_domain = catalog_value.clone();
        catalog_cross_domain["signature"] = json!(&release_signature);
        assert!(
            verify_fixture_signatures(
                &serde_jcs::to_vec(&catalog_cross_domain).unwrap(),
                unmodified_release,
            )
            .is_err()
        );
        let mut release_cross_domain = release_value.clone();
        release_cross_domain["signature"]["signature"] = json!(&catalog_signature);
        assert!(
            verify_fixture_signatures(
                unmodified_catalog,
                &serde_jcs::to_vec(&release_cross_domain).unwrap(),
            )
            .is_err()
        );
        let mut release_bit_flip = release_value;
        let mut altered = release_signature.as_bytes().to_vec();
        altered[0] = if altered[0] == b'A' { b'B' } else { b'A' };
        release_bit_flip["signature"]["signature"] = json!(String::from_utf8(altered).unwrap());
        assert!(
            verify_fixture_signatures(
                unmodified_catalog,
                &serde_jcs::to_vec(&release_bit_flip).unwrap(),
            )
            .is_err()
        );

        assert_eq!(
            signed.inventory.entries().len(),
            signed.manifest.assets().len() + 3
        );
        assert_eq!(signed.manifest.source_commit().as_str(), "55".repeat(20));
        assert_eq!(signed.manifest.tag().as_str(), "catalog-v1-sequence-1");

        let output = fixture.root.path.join("signed-output");
        write_test_recovery_binding(&fixture.root.path);
        let result = write_signed_output(
            OutputPreflight::new(&output).unwrap(),
            signed,
            SignatureVerificationPolicy::Fixture,
        )
        .unwrap();
        assert_eq!(result.output(), output);
        assert_eq!(mode(&output), 0o700);
        for entry in fs::read_dir(&output).unwrap() {
            assert_eq!(mode(&entry.unwrap().path()), 0o400);
        }
        assert!(
            OutputPreflight::new(&output).is_err(),
            "no-clobber output was reusable"
        );
    }

    #[test]
    fn missing_binding_before_stage_binding_rejects_without_visibility_and_retains_evidence() {
        let fixture = CandidateFixture::new();
        let bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
        let candidate = finalize_candidate_after_admission_for_test(
            &bundle,
            &fixture.source,
            &fixture.qualification,
        )
        .unwrap();
        let key = fixture_signing_key_for_test();
        let signed = sign_candidate(&candidate, key.as_dalek(), "catalog-test-key-v1").unwrap();
        drop(key);
        let output = fixture.root.path.join("missing-binding-output");

        assert_eq!(
            write_signed_output(
                OutputPreflight::new(&output).unwrap(),
                signed,
                SignatureVerificationPolicy::Fixture,
            )
            .unwrap_err(),
            SignError::OutputRejected
        );
        assert!(!output.exists(), "payload became visible without a binding");
        assert!(
            !fixture.root.path.join(TRANSFER_MANIFEST_NAME).exists(),
            "reverse manifest became visible without a binding"
        );
        let retained_stages = fs::read_dir(&fixture.root.path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".catalog-sign-stage-")
            })
            .collect::<Vec<_>>();
        assert_eq!(retained_stages.len(), 1);
        assert!(retained_stages[0].join("payload").is_dir());
    }

    #[test]
    fn missing_binding_before_cleanup_rejects_without_unlinking_stage() {
        let fixture = CandidateFixture::new();
        let output_path = fixture.root.path.join("missing-cleanup-binding-output");
        write_test_recovery_binding(&fixture.root.path);
        let mut output = StagedOutput::create(OutputPreflight::new(&output_path).unwrap()).unwrap();
        let stage = fixture
            .root
            .path
            .join(output.container_name.to_str().unwrap());
        output.publish().unwrap();
        fs::remove_file(fixture.root.path.join(RECOVERY_BINDING_NAME)).unwrap();

        assert_eq!(
            output.settle_verified_staging().unwrap_err(),
            SignError::OutputRejected
        );
        assert!(stage.exists(), "unbound stage was unlinked");
    }

    #[test]
    fn signed_output_faults_preserve_visibility_and_support_exact_public_recovery() {
        for checkpoint in [
            PublishCheckpoint::BeforeRename,
            PublishCheckpoint::RenameVisibility,
            PublishCheckpoint::FirstParentFsync,
            PublishCheckpoint::EmptyContainerUnlink,
            PublishCheckpoint::FinalParentFsync,
            PublishCheckpoint::FinalReopen,
        ] {
            let fixture = CandidateFixture::new();
            let bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
            let candidate = finalize_candidate_after_admission_for_test(
                &bundle,
                &fixture.source,
                &fixture.qualification,
            )
            .unwrap();
            let key = fixture_signing_key_for_test();
            let signed = sign_candidate(&candidate, key.as_dalek(), "catalog-test-key-v1").unwrap();
            drop(key);
            let output = fixture
                .root
                .path
                .join(format!("fault-{checkpoint:?}-signed-output"));
            write_test_recovery_binding(&fixture.root.path);
            set_publish_fault(
                checkpoint,
                if checkpoint == PublishCheckpoint::RenameVisibility {
                    PublishFault::Interrupt
                } else {
                    PublishFault::Once
                },
            );
            let result = write_signed_output(
                OutputPreflight::new(&output).unwrap(),
                signed,
                SignatureVerificationPolicy::Fixture,
            );
            if checkpoint == PublishCheckpoint::BeforeRename {
                assert_eq!(result.unwrap_err(), SignError::OutputRejected);
                assert!(!output.exists());
                continue;
            }
            assert_eq!(result.unwrap_err(), SignError::OutputDurabilityUncertain);
            let before = reopen_recovery_snapshot(&output);
            if checkpoint == PublishCheckpoint::RenameVisibility {
                recover_signed_output(&output, &candidate, SignatureVerificationPolicy::Fixture)
                    .unwrap();
                assert_eq!(reopen_recovery_snapshot(&output), before);
                fs::remove_file(fixture.root.path.join(RECOVERY_BINDING_NAME)).unwrap();
                let completed = fixture.root.path.join(TRANSFER_MANIFEST_NAME);
                fs::write(&completed, b"completed-reverse").unwrap();
                fs::set_permissions(&completed, fs::Permissions::from_mode(0o400)).unwrap();
                recover_signed_output(&output, &candidate, SignatureVerificationPolicy::Fixture)
                    .unwrap();
            } else {
                assert!(
                    recover_signed_output(
                        &output,
                        &candidate,
                        SignatureVerificationPolicy::Fixture
                    )
                    .is_err()
                );
                assert_eq!(reopen_recovery_snapshot(&output), before);
            }
        }

        let fixture = CandidateFixture::new();
        let bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
        let candidate = finalize_candidate_after_admission_for_test(
            &bundle,
            &fixture.source,
            &fixture.qualification,
        )
        .unwrap();
        let key = fixture_signing_key_for_test();
        let signed = sign_candidate(&candidate, key.as_dalek(), "catalog-test-key-v1").unwrap();
        drop(key);
        let output = fixture.root.path.join("persistent-cleanup-output");
        write_test_recovery_binding(&fixture.root.path);
        set_publish_fault(
            PublishCheckpoint::EmptyContainerUnlink,
            PublishFault::Persistent,
        );
        assert_eq!(
            write_signed_output(
                OutputPreflight::new(&output).unwrap(),
                signed,
                SignatureVerificationPolicy::Fixture,
            )
            .unwrap_err(),
            SignError::OutputDurabilityUncertain
        );
        let staging = fs::read_dir(&fixture.root.path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".catalog-sign-stage-")
            })
            .unwrap();
        fs::write(staging.join("unknown-evidence"), b"retain").unwrap();
        assert!(
            recover_signed_output(&output, &candidate, SignatureVerificationPolicy::Fixture)
                .is_err()
        );
        assert_eq!(
            fs::read(staging.join("unknown-evidence")).unwrap(),
            b"retain"
        );
        set_publish_fault(PublishCheckpoint::BeforeRename, PublishFault::Once);
    }

    fn write_test_recovery_binding(parent: &Path) {
        let path = parent.join(RECOVERY_BINDING_NAME);
        if path.exists() {
            fs::remove_file(&path).unwrap();
        }
        fs::write(
            &path,
            serde_jcs::to_vec(&json!({
                "schema_version": 1,
                "kind": "sign_recovery_binding",
                "original_operation_mode": "sign",
                "input_transfer_sha256": "11".repeat(32),
                "launcher_config_sha256": "22".repeat(32),
                "signer_sha256": "33".repeat(32),
                "staging": null,
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::File::open(&path).unwrap().sync_all().unwrap();
        fs::File::open(parent).unwrap().sync_all().unwrap();
    }

    fn recovery_stage_name(parent: &Path) -> String {
        let value: Value =
            serde_json::from_slice(&fs::read(parent.join(RECOVERY_BINDING_NAME)).unwrap()).unwrap();
        value["staging"]["relative_name"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn interrupted_signed_output(
        label: &str,
    ) -> (
        CandidateFixture,
        UnsignedReleaseCandidateV1,
        PathBuf,
        String,
    ) {
        let fixture = CandidateFixture::new();
        let bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
        let candidate = finalize_candidate_after_admission_for_test(
            &bundle,
            &fixture.source,
            &fixture.qualification,
        )
        .unwrap();
        let key = fixture_signing_key_for_test();
        let signed = sign_candidate(&candidate, key.as_dalek(), "catalog-test-key-v1").unwrap();
        drop(key);
        let output = fixture.root.path.join(format!("{label}-output"));
        write_test_recovery_binding(&fixture.root.path);
        set_publish_fault(PublishCheckpoint::RenameVisibility, PublishFault::Interrupt);
        assert_eq!(
            write_signed_output(
                OutputPreflight::new(&output).unwrap(),
                signed,
                SignatureVerificationPolicy::Fixture,
            )
            .unwrap_err(),
            SignError::OutputDurabilityUncertain
        );
        let stage = recovery_stage_name(&fixture.root.path);
        (fixture, candidate, output, stage)
    }

    #[test]
    fn recovery_settles_only_the_verified_exact_bound_stage() {
        let (fixture, candidate, output, bound) = interrupted_signed_output("unrelated");
        let unrelated = fixture
            .root
            .path
            .join(".catalog-sign-stage-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&unrelated)
            .unwrap();
        recover_signed_output(&output, &candidate, SignatureVerificationPolicy::Fixture).unwrap();
        assert!(!fixture.root.path.join(bound).exists());
        assert!(unrelated.exists(), "unrelated stage was deleted");

        let (fixture, candidate, output, bound) = interrupted_signed_output("replaced");
        let bound_path = fixture.root.path.join(&bound);
        let retained = fixture.root.path.join("retained-original-stage");
        fs::rename(&bound_path, &retained).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&bound_path)
            .unwrap();
        assert!(
            recover_signed_output(&output, &candidate, SignatureVerificationPolicy::Fixture)
                .is_err()
        );
        assert!(bound_path.exists() && retained.exists());

        let (fixture, candidate, output, bound) = interrupted_signed_output("missing-stage");
        fs::remove_dir(fixture.root.path.join(&bound)).unwrap();
        assert!(
            recover_signed_output(&output, &candidate, SignatureVerificationPolicy::Fixture)
                .is_err()
        );
        assert!(!fixture.root.path.join(bound).exists());

        let (fixture, candidate, output, bound) = interrupted_signed_output("unbound");
        fs::remove_file(fixture.root.path.join(RECOVERY_BINDING_NAME)).unwrap();
        assert!(
            recover_signed_output(&output, &candidate, SignatureVerificationPolicy::Fixture)
                .is_err()
        );
        assert!(fixture.root.path.join(bound).exists());

        let (fixture, candidate, output, bound) = interrupted_signed_output("invalid-output");
        let catalog = output.join(CATALOG_NAME);
        fs::set_permissions(&catalog, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            recover_signed_output(&output, &candidate, SignatureVerificationPolicy::Fixture)
                .is_err()
        );
        assert!(fixture.root.path.join(bound).exists());

        let (fixture, candidate, output, bound) = interrupted_signed_output("missing-output");
        fs::rename(&output, fixture.root.path.join("preserved-visible-output")).unwrap();
        assert!(
            recover_signed_output(&output, &candidate, SignatureVerificationPolicy::Fixture)
                .is_err()
        );
        assert!(fixture.root.path.join(bound).exists());

        let (fixture, candidate, output, bound) = interrupted_signed_output("nonempty");
        fs::write(fixture.root.path.join(&bound).join("unknown"), b"retain").unwrap();
        assert!(
            recover_signed_output(&output, &candidate, SignatureVerificationPolicy::Fixture)
                .is_err()
        );
        assert!(fixture.root.path.join(bound).join("unknown").exists());

        let (fixture, candidate, output, bound) = interrupted_signed_output("before-binding");
        write_test_recovery_binding(&fixture.root.path);
        assert!(
            recover_signed_output(&output, &candidate, SignatureVerificationPolicy::Fixture)
                .is_err()
        );
        assert!(fixture.root.path.join(bound).exists());
    }

    fn reopen_recovery_snapshot(path: &Path) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().into_string().unwrap(),
                    fs::read(entry.path()).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn candidate_file_publication_is_atomic_no_clobber_and_reopened_exactly() {
        use std::os::unix::fs::symlink;

        let fixture = CandidateFixture::new();
        let bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
        let candidate = finalize_candidate_after_admission_for_test(
            &bundle,
            &fixture.source,
            &fixture.qualification,
        )
        .unwrap();

        let output = fixture.root.path.join("candidate.json");
        write_candidate(&output, &candidate).unwrap();
        assert_eq!(mode(&output), 0o400);
        assert_eq!(fs::read(&output).unwrap(), candidate.canonical_payload());

        fs::set_permissions(&output, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&output, b"existing-sentinel").unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            write_candidate(&output, &candidate),
            Err(SignError::OutputRejected)
        );
        assert_eq!(fs::read(&output).unwrap(), b"existing-sentinel");

        let failed = fixture.root.path.join("failed-before-link.json");
        assert_eq!(
            write_candidate_atomically(&failed, candidate.canonical_payload(), |stage| {
                (stage != CandidateOutputCheckpoint::Link)
                    .then_some(())
                    .ok_or_else(output_rejected)
            }),
            Err(SignError::OutputRejected)
        );
        assert!(!failed.exists(), "an unnamed failed write became visible");

        let indeterminate = fixture.root.path.join("durability-indeterminate.json");
        assert_eq!(
            write_candidate_atomically(&indeterminate, candidate.canonical_payload(), |stage| {
                (stage != CandidateOutputCheckpoint::ParentFsync)
                    .then_some(())
                    .ok_or_else(output_rejected)
            },),
            Err(SignError::OutputRejected)
        );
        assert_eq!(mode(&indeterminate), 0o400);
        assert_eq!(
            fs::read(&indeterminate).unwrap(),
            candidate.canonical_payload()
        );

        let linked_parent = fixture.root.path.join("linked-parent");
        symlink(&fixture.root.path, &linked_parent).unwrap();
        assert_eq!(
            write_candidate(&linked_parent.join("outside.json"), &candidate),
            Err(SignError::OutputRejected)
        );
        assert!(!fixture.root.path.join("outside.json").exists());
    }

    #[test]
    fn self_consistent_transfer_mutations_reach_the_intended_downstream_binding_seams() {
        let source_fixture = CandidateFixture::with_finalization_mutation(
            |source| {
                source["qualification"]["relative_path"] =
                    json!("qualifications/mutated-source-path.json");
            },
            |_| {},
            false,
        );
        let source_bundle = verify_transferred_bundle(&source_fixture.final_bundle).unwrap();
        assert_transferred_finalization_arguments_match(&source_bundle, &source_fixture);
        verify_qualification(&source_fixture.source, &source_fixture.qualification).unwrap();
        let source_digest = encode_hex(&catalog_source_digest(&source_fixture.source).unwrap());
        assert_ne!(
            source_bundle.inventory().source_sha256().as_str(),
            source_digest
        );
        assert_eq!(
            source_bundle
                .inventory()
                .compatibility_input_sha256()
                .as_str(),
            encode_hex(
                &compatibility_input_digest(
                    source_fixture.source.intent(),
                    source_fixture.source.build(),
                )
                .unwrap(),
            )
        );
        assert_eq!(
            finalize_candidate_after_admission_for_test(
                &source_bundle,
                &source_fixture.source,
                &source_fixture.qualification,
            ),
            Err(SignError::CandidateRejected)
        );
        assert_eq!(
            last_finalization_stage_for_test(),
            Some(FinalizationStage::SourceDigestRejected),
            "source mutation did not pass qualification and reach the stale source-digest seam"
        );

        for (name, pointer, replacement) in [
            ("build", "/build/application_sha256", json!("91".repeat(32))),
            (
                "profile",
                "/build/compatibility_profile_sha256",
                json!("92".repeat(32)),
            ),
        ] {
            let fixture = CandidateFixture::with_finalization_mutation(
                |source| *source.pointer_mut(pointer).unwrap() = replacement,
                |_| {},
                true,
            );
            let bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
            assert_transferred_finalization_arguments_match(&bundle, &fixture);
            assert_eq!(
                bundle.inventory().source_sha256().as_str(),
                encode_hex(&catalog_source_digest(&fixture.source).unwrap()),
                "{name} mutation did not receive its matching transferred source digest"
            );
            assert_ne!(
                fixture.qualification.fluxsemble(),
                fixture.source.build(),
                "{name} mutation unexpectedly updated the qualification build binding"
            );
            assert!(verify_qualification(&fixture.source, &fixture.qualification).is_err());
            assert_eq!(
                finalize_candidate_after_admission_for_test(
                    &bundle,
                    &fixture.source,
                    &fixture.qualification,
                ),
                Err(SignError::CandidateRejected)
            );
            assert_eq!(
                last_finalization_stage_for_test(),
                Some(FinalizationStage::VerifyQualificationRejected),
                "{name} mutation did not reach verify_qualification"
            );
        }

        let qualification_fixture = CandidateFixture::with_finalization_mutation(
            |_| {},
            |qualification| {
                qualification["reviewer"] = json!("mutated-fixture-reviewer");
            },
            true,
        );
        let qualification_bundle =
            verify_transferred_bundle(&qualification_fixture.final_bundle).unwrap();
        assert_transferred_finalization_arguments_match(
            &qualification_bundle,
            &qualification_fixture,
        );
        assert_eq!(
            qualification_bundle.inventory().source_sha256().as_str(),
            encode_hex(&catalog_source_digest(&qualification_fixture.source).unwrap())
        );
        assert_eq!(
            qualification_fixture.qualification.fluxsemble(),
            qualification_fixture.source.build()
        );
        assert_eq!(
            qualification_fixture
                .qualification
                .compatibility_input_sha256()
                .as_str(),
            encode_hex(
                &compatibility_input_digest(
                    qualification_fixture.source.intent(),
                    qualification_fixture.source.build(),
                )
                .unwrap(),
            )
        );
        assert_ne!(
            qualification_fixture
                .source
                .qualification()
                .sha256()
                .as_str(),
            encode_hex(&qualification_record_digest(&qualification_fixture.qualification).unwrap(),),
            "qualification mutation unexpectedly updated the source qualification digest"
        );
        assert!(
            verify_qualification(
                &qualification_fixture.source,
                &qualification_fixture.qualification,
            )
            .is_err()
        );
        assert_eq!(
            finalize_candidate_after_admission_for_test(
                &qualification_bundle,
                &qualification_fixture.source,
                &qualification_fixture.qualification,
            ),
            Err(SignError::CandidateRejected)
        );
        assert_eq!(
            last_finalization_stage_for_test(),
            Some(FinalizationStage::VerifyQualificationRejected),
            "qualification mutation did not reach its unchanged source-digest binding"
        );
    }

    #[test]
    fn post_admission_seam_keeps_tag_time_url_and_tuple_policy_coverage() {
        let fixture = CandidateFixture::new();
        let bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
        finalize_candidate_after_admission_for_test(
            &bundle,
            &fixture.source,
            &fixture.qualification,
        )
        .expect("the private post-admission seam must enter the complete shared body");
        let base: Value =
            serde_json::from_slice(&serde_jcs::to_vec(&fixture.source).unwrap()).unwrap();
        let mut mutations = Vec::new();

        let mut tag = base.clone();
        tag["intent"]["sequence"] = json!("2");
        tag["intent"]["tag"] = json!("catalog-v1-sequence-2");
        mutations.push(("tag", tag));
        let mut time = base.clone();
        time["intent"]["generated_at"] = json!("2026-08-27T00:00:00Z");
        time["intent"]["expires_at"] = json!("2026-09-27T00:00:00Z");
        mutations.push(("time", time));
        let mut support_url = base.clone();
        let original = support_url
            .pointer(
                "/intent/release/release/provider_extension/metadata/root_package_manifest/url",
            )
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        *support_url
            .pointer_mut(
                "/intent/release/release/provider_extension/metadata/root_package_manifest/url",
            )
            .unwrap() = json!(original.replace("pi-package", "other-package"));
        mutations.push(("url", support_url));
        let mut tuple = base;
        for pointer in [
            "/intent/release/release/version",
            "/intent/release/release/components/1/version",
            "/intent/release/release/provider_extension/metadata/approved_package/version",
            "/intent/release/release/provider_extension/metadata/shipped_shrinkwrap/root_package/version",
        ] {
            *tuple.pointer_mut(pointer).unwrap() = json!("0.84.0");
        }
        mutations.push(("tuple", tuple));

        reset_key_open_count();
        for (name, mutation) in mutations {
            let source =
                CatalogSourceV1::from_json(&serde_jcs::to_vec(&mutation).unwrap()).unwrap();
            assert_eq!(
                finalize_candidate_after_admission_for_test(
                    &bundle,
                    &source,
                    &fixture.qualification,
                ),
                Err(SignError::CandidateRejected),
                "{name} mutation did not reach its shared finalization rejection seam"
            );
            assert_eq!(key_open_count(), 0, "key opened for {name} mutation");
        }

        let tag_fixture = CandidateFixture::with_intent_mutation(|intent| {
            intent["sequence"] = json!("2");
            intent["tag"] = json!("catalog-v1-sequence-2");
        });
        let tag_bundle = verify_transferred_bundle(&tag_fixture.final_bundle).unwrap();
        assert_eq!(
            finalize_candidate_after_admission_for_test(
                &tag_bundle,
                &tag_fixture.source,
                &tag_fixture.qualification,
            ),
            Err(SignError::CandidateRejected),
            "self-consistent retagging did not reach tag-bound support URL policy"
        );

        let url_fixture = CandidateFixture::with_intent_mutation(|intent| {
            let url = intent
                .pointer("/release/release/provider_extension/metadata/root_package_manifest/url")
                .unwrap()
                .as_str()
                .unwrap()
                .replace("pi-package", "other-package");
            *intent
                .pointer_mut(
                    "/release/release/provider_extension/metadata/root_package_manifest/url",
                )
                .unwrap() = json!(url);
        });
        let url_bundle = verify_transferred_bundle(&url_fixture.final_bundle).unwrap();
        assert_eq!(
            finalize_candidate_after_admission_for_test(
                &url_bundle,
                &url_fixture.source,
                &url_fixture.qualification,
            ),
            Err(SignError::CandidateRejected),
            "self-consistent URL mutation did not reach complete object-graph policy"
        );

        let time_fixture = CandidateFixture::with_intent_mutation(|intent| {
            intent["generated_at"] = json!("2026-08-27T00:00:00Z");
            intent["expires_at"] = json!("2026-09-27T00:00:00Z");
        });
        let time_bundle = verify_transferred_bundle(&time_fixture.final_bundle).unwrap();
        finalize_candidate_after_admission_for_test(
            &time_bundle,
            &time_fixture.source,
            &time_fixture.qualification,
        )
        .expect("valid bound freshness must reach and pass shared finalization policy");

        let tuple_fixture = CandidateFixture::with_intent_mutation(|intent| {
            for pointer in [
                "/release/release/version",
                "/release/release/components/1/version",
                "/release/release/provider_extension/metadata/approved_package/version",
                "/release/release/provider_extension/metadata/shipped_shrinkwrap/root_package/version",
            ] {
                *intent.pointer_mut(pointer).unwrap() = json!("0.84.0");
            }
        });
        let tuple_bundle = verify_transferred_bundle(&tuple_fixture.final_bundle).unwrap();
        assert_eq!(
            finalize_candidate_after_admission_for_test(
                &tuple_bundle,
                &tuple_fixture.source,
                &tuple_fixture.qualification,
            ),
            Err(SignError::CandidateRejected),
            "self-consistent tuple mutation did not reach first-tuple policy"
        );
        assert_eq!(key_open_count(), 0);
    }

    #[test]
    #[ignore = "set CATALOG_AUTHENTIC_PUBLIC_CORPUS to an authenticated public Pi 0.83.0 corpus"]
    fn environment_supplied_public_corpus_exercises_public_production_assembly_and_finalization() {
        let corpus = std::env::var_os("CATALOG_AUTHENTIC_PUBLIC_CORPUS")
            .map(PathBuf::from)
            .expect("CATALOG_AUTHENTIC_PUBLIC_CORPUS is required");
        let fixture = CandidateFixture::from_approved_corpus(&corpus);

        let intent_bundle = verify_transferred_bundle(&fixture.intent_bundle).unwrap();
        let intent_candidate = assemble_release_intent(&intent_bundle, &fixture.intent).unwrap();
        assert!(!intent_candidate.is_production_signable());

        let final_bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
        let final_candidate =
            finalize_candidate(&final_bundle, &fixture.source, &fixture.qualification).unwrap();
        assert!(final_candidate.is_production_signable());
        assert_eq!(
            final_candidate.runtime_semantic_sha256(),
            intent_candidate.runtime_semantic_sha256()
        );
        assert_eq!(
            final_candidate.canonical_payload(),
            intent_candidate.canonical_payload()
        );

        reset_key_open_count();
        let output = fixture.root.path.join("authentic-public-production-output");
        assert!(
            matches!(
                sign_release(SignReleaseRequest {
                    bundle: &final_bundle,
                    source: &fixture.source,
                    qualification: &fixture.qualification,
                    key_path: &fixture.fixture_key,
                    output: &output,
                }),
                Err(SignError::SigningKeyRejected)
            ),
            "the public fixture key must never acquire production signing authority"
        );
        assert_eq!(
            key_open_count(),
            1,
            "authentic admission did not reach key open"
        );
        assert!(!output.exists());

        if let Some(export) = std::env::var_os("CATALOG_AUTHENTIC_JOURNEY_EXPORT") {
            let export = PathBuf::from(export);
            assert!(export.is_absolute());
            copy_transfer_tree(&fixture.intent_bundle, &export.join("intent-input"));
            copy_transfer_tree(&fixture.final_bundle, &export.join("final-input"));
        }
    }

    #[test]
    fn authenticated_corpus_reader_enforces_root_and_component_directory_policy() {
        let temporary = TempDirectory::new();
        let root = temporary.path.join("corpus-root");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let nested = root.join("nested");
        fs::DirBuilder::new().mode(0o700).create(&nested).unwrap();

        for (label, metadata) in [
            ("root", root.metadata().unwrap()),
            ("nested", nested.metadata().unwrap()),
        ] {
            assert!(
                secure_public_corpus_directory_for_owner(&metadata, current_euid()),
                "current owner did not satisfy the {label} directory policy"
            );
            assert!(
                !secure_public_corpus_directory_for_owner(
                    &metadata,
                    current_euid().wrapping_add(1)
                ),
                "a deterministic synthetic foreign owner satisfied the {label} directory policy"
            );
        }

        for mode in [0o700, 0o755] {
            fs::set_permissions(&root, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                AuthenticatedCorpus::open(&root).is_ok(),
                "rejected safe root mode {mode:o}"
            );
        }
        for mode in [0o777, 0o1700, 0o2755] {
            fs::set_permissions(&root, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                AuthenticatedCorpus::open(&root).is_err(),
                "accepted unsafe root mode {mode:o}"
            );
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        let corpus = AuthenticatedCorpus::open(&root).unwrap();
        let bytes = b"authenticated nested object";
        let digest = sha256(bytes);
        let object = nested.join("object.bin");
        fs::write(&object, bytes).unwrap();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o644)).unwrap();

        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            corpus
                .read_object("nested/object.bin", bytes.len() as u64, &digest)
                .is_err(),
            "an unsafe retained root remained usable"
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        for mode in [0o700, 0o755] {
            fs::set_permissions(&nested, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                corpus
                    .read_object("nested/object.bin", bytes.len() as u64, &digest)
                    .unwrap(),
                bytes,
                "rejected safe intermediate mode {mode:o}"
            );
        }
        for mode in [0o777, 0o1700, 0o2755] {
            fs::set_permissions(&nested, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                corpus
                    .read_object("nested/object.bin", bytes.len() as u64, &digest)
                    .is_err(),
                "accepted unsafe intermediate mode {mode:o}"
            );
        }
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();

        let result = corpus.read_object_with_checkpoints(
            "nested/object.bin",
            bytes.len() as u64,
            &digest,
            || {},
            || {},
            || {},
            || {
                fs::set_permissions(&nested, fs::Permissions::from_mode(0o777)).unwrap();
            },
        );
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            result.is_err(),
            "a full-path rebind accepted an intermediate directory made unsafe"
        );
    }

    #[test]
    fn authenticated_corpus_reader_enforces_complete_file_and_capability_policy() {
        use std::os::unix::fs::symlink;

        let root = TempDirectory::new();
        let linked_root = root.path.with_extension("linked-root");
        symlink(&root.path, &linked_root).unwrap();
        assert!(AuthenticatedCorpus::open(&linked_root).is_err());
        fs::remove_file(&linked_root).unwrap();
        let corpus = AuthenticatedCorpus::open(&root.path).unwrap();
        let bytes = b"authenticated public object";
        let digest = sha256(bytes);

        let regular = root.path.join("regular.bin");
        fs::write(&regular, bytes).unwrap();
        fs::set_permissions(&regular, fs::Permissions::from_mode(0o644)).unwrap();
        let regular_metadata = regular.metadata().unwrap();
        assert!(secure_public_corpus_file_for_owner(
            &regular_metadata,
            current_euid()
        ));
        assert!(
            !secure_public_corpus_file_for_owner(&regular_metadata, current_euid().wrapping_add(1)),
            "a deterministic synthetic foreign owner satisfied the corpus policy"
        );
        assert_eq!(
            corpus
                .read_object("regular.bin", bytes.len() as u64, &digest)
                .unwrap(),
            bytes
        );
        assert!(
            corpus
                .read_object("regular.bin", bytes.len() as u64 - 1, &digest)
                .is_err()
        );
        assert!(
            corpus
                .read_object("regular.bin", bytes.len() as u64, &sha256(b"wrong"))
                .is_err()
        );

        symlink("regular.bin", root.path.join("linked.bin")).unwrap();
        assert!(
            corpus
                .read_object("linked.bin", bytes.len() as u64, &digest)
                .is_err()
        );
        let real_directory = root.path.join("real-directory");
        fs::DirBuilder::new()
            .mode(0o755)
            .create(&real_directory)
            .unwrap();
        fs::write(real_directory.join("nested.bin"), bytes).unwrap();
        fs::set_permissions(
            real_directory.join("nested.bin"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        symlink("real-directory", root.path.join("linked-directory")).unwrap();
        assert!(
            corpus
                .read_object("linked-directory/nested.bin", bytes.len() as u64, &digest,)
                .is_err()
        );

        fs::hard_link(&regular, root.path.join("hard-linked.bin")).unwrap();
        assert!(
            corpus
                .read_object("regular.bin", bytes.len() as u64, &digest)
                .is_err()
        );
        fs::remove_file(root.path.join("hard-linked.bin")).unwrap();
        for mode in [0o000, 0o440, 0o666, 0o700, 0o1000, 0o2644] {
            fs::set_permissions(&regular, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                corpus
                    .read_object("regular.bin", bytes.len() as u64, &digest)
                    .is_err(),
                "accepted mode {mode:o}"
            );
        }
        fs::set_permissions(&regular, fs::Permissions::from_mode(0o644)).unwrap();

        let fifo_name = CString::new(root.path.join("object.fifo").as_os_str().as_bytes()).unwrap();
        // SAFETY: the path is a valid NUL-terminated string and the mode is bounded.
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        assert!(corpus.read_object("object.fifo", 1, &sha256(b"x")).is_err());

        let oversized = root.path.join("oversized.bin");
        let oversized_file = fs::File::create(&oversized).unwrap();
        oversized_file
            .set_len(MAX_AUTHENTIC_CORPUS_OBJECT_BYTES + 1)
            .unwrap();
        drop(oversized_file);
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            corpus
                .read_object(
                    "oversized.bin",
                    MAX_AUTHENTIC_CORPUS_OBJECT_BYTES + 1,
                    &sha256(b""),
                )
                .is_err()
        );

        let changed = root.path.join("changed-during-read.bin");
        fs::write(&changed, bytes).unwrap();
        fs::set_permissions(&changed, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            corpus
                .read_object_with_checkpoints(
                    "changed-during-read.bin",
                    bytes.len() as u64,
                    &digest,
                    || {},
                    || {
                        fs::set_permissions(&changed, fs::Permissions::from_mode(0o600)).unwrap();
                        fs::set_permissions(&changed, fs::Permissions::from_mode(0o644)).unwrap();
                    },
                    || {},
                    || {},
                )
                .is_err(),
            "pre/post descriptor identity mutation was accepted"
        );

        let growth = root.path.join("growth.bin");
        fs::write(&growth, bytes).unwrap();
        fs::set_permissions(&growth, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            corpus
                .read_object_with_checkpoints(
                    "growth.bin",
                    bytes.len() as u64,
                    &digest,
                    || {
                        use std::io::Write as _;
                        fs::OpenOptions::new()
                            .append(true)
                            .open(&growth)
                            .unwrap()
                            .write_all(b"!")
                            .unwrap();
                    },
                    || {},
                    || {},
                    || {},
                )
                .is_err(),
            "bounded one-byte excess probe accepted file growth"
        );

        let replace = root.path.join("replace.bin");
        let displaced = root.path.join("displaced.bin");
        fs::write(&replace, bytes).unwrap();
        fs::set_permissions(&replace, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            corpus
                .read_object_with_checkpoint("replace.bin", bytes.len() as u64, &digest, || {
                    fs::rename(&replace, &displaced).unwrap();
                    fs::write(&replace, bytes).unwrap();
                    fs::set_permissions(&replace, fs::Permissions::from_mode(0o644)).unwrap();
                },)
                .is_err(),
            "retained final-name identity mutation was accepted"
        );

        let nested = root.path.join("full-relative");
        let moved_nested = root.path.join("moved-full-relative");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("replace.bin"), bytes).unwrap();
        fs::set_permissions(
            nested.join("replace.bin"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(
            corpus
                .read_object_with_checkpoints(
                    "full-relative/replace.bin",
                    bytes.len() as u64,
                    &digest,
                    || {},
                    || {},
                    || {},
                    || {
                        fs::rename(&nested, &moved_nested).unwrap();
                        fs::create_dir(&nested).unwrap();
                        fs::write(nested.join("replace.bin"), bytes).unwrap();
                        fs::set_permissions(
                            nested.join("replace.bin"),
                            fs::Permissions::from_mode(0o644),
                        )
                        .unwrap();
                    },
                )
                .is_err(),
            "full-relative-path identity mutation was accepted"
        );
    }

    #[test]
    fn object_substitution_is_rejected_before_key_open() {
        let fixture = CandidateFixture::new();
        let bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
        let relative = bundle.inventory().objects()[0].relative_path().as_str();
        let path = fixture.final_bundle.join(relative);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"substituted-object").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        reset_key_open_count();
        let output = fixture.root.path.join("object-substitution-output");
        assert!(
            sign_release(SignReleaseRequest {
                bundle: &bundle,
                source: &fixture.source,
                qualification: &fixture.qualification,
                key_path: &fixture.fixture_key,
                output: &output,
            })
            .is_err()
        );
        assert_eq!(key_open_count(), 0);
        assert!(!output.exists());
    }

    #[test]
    fn retained_manifest_rejects_a_to_b_identity_substitution_before_key_open() {
        let fixture = CandidateFixture::new();
        let bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
        let manifest = fixture.final_bundle.join(TRANSFER_MANIFEST_NAME);
        let displaced = fixture.final_bundle.join("manifest-a.displaced");
        fs::rename(&manifest, &displaced).unwrap();
        fs::copy(&displaced, &manifest).unwrap();
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o400)).unwrap();

        reset_key_open_count();
        let output = fixture.root.path.join("manifest-a-to-b-output");
        assert!(
            sign_release(SignReleaseRequest {
                bundle: &bundle,
                source: &fixture.source,
                qualification: &fixture.qualification,
                key_path: &fixture.fixture_key,
                output: &output,
            })
            .is_err()
        );
        assert_eq!(key_open_count(), 0);
        assert!(!output.exists());
    }

    #[test]
    fn declared_dependency_without_a_transferred_object_is_rejected_before_key_open() {
        let fixture = CandidateFixture::with_intent_mutation(|intent| {
            intent
                .pointer_mut(
                    "/release/release/provider_extension/metadata/shipped_shrinkwrap/locked_packages",
                )
                .unwrap()
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "locator": "node_modules/zz-untransferred",
                    "name": "zz-untransferred",
                    "version": "1.0.0",
                    "resolved_url": "https://registry.npmjs.org/zz-untransferred/-/zz-untransferred-1.0.0.tgz",
                    "registry_integrity": SRI,
                    "archive_sha256": "99".repeat(32),
                }));
        });
        let bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
        reset_key_open_count();
        let output = fixture.root.path.join("incomplete-graph-output");
        assert!(matches!(
            sign_release(SignReleaseRequest {
                bundle: &bundle,
                source: &fixture.source,
                qualification: &fixture.qualification,
                key_path: &fixture.fixture_key,
                output: &output,
            }),
            Err(SignError::CandidateRejected)
        ));
        assert_eq!(key_open_count(), 0);
        assert!(!output.exists());
    }

    #[test]
    fn release_signature_binds_source_tree_tag_qualification_assets_and_catalog() {
        use ed25519_dalek::{Signature, Verifier};

        let fixture = CandidateFixture::new();
        let bundle = verify_transferred_bundle(&fixture.final_bundle).unwrap();
        let candidate = finalize_candidate_after_admission_for_test(
            &bundle,
            &fixture.source,
            &fixture.qualification,
        )
        .unwrap();
        let key = fixture_signing_key_for_test();
        let signed = sign_candidate(&candidate, key.as_dalek(), "catalog-test-key-v1").unwrap();
        let original: Value =
            serde_json::from_slice(signed.files.get(RELEASE_MANIFEST_NAME).unwrap()).unwrap();
        let signature_text = original["signature"]["signature"].as_str().unwrap();
        let signature = Signature::from_bytes(&decode_base64url_signature(signature_text));
        let verifying_key = key.as_dalek().verifying_key();

        for (pointer, replacement) in [
            ("/source_commit", json!("77".repeat(20))),
            ("/source_tree_sha256", json!("78".repeat(32))),
            ("/qualification_sha256", json!("79".repeat(32))),
            ("/tag", json!("catalog-v1-sequence-2")),
            ("/assets/0/name", json!("a-substituted-asset.json")),
            ("/assets/0/sha256", json!("80".repeat(32))),
            ("/catalog_envelope/sha256", json!("81".repeat(32))),
        ] {
            let mut mutation = original.clone();
            *mutation.pointer_mut(pointer).unwrap() = replacement;
            let manifest =
                SignedReleaseBundleManifestV1::from_json(&serde_jcs::to_vec(&mutation).unwrap())
                    .unwrap();
            assert!(
                verifying_key
                    .verify(
                        &release_bundle_signing_bytes(&manifest).unwrap(),
                        &signature,
                    )
                    .is_err(),
                "signature did not bind {pointer}"
            );
        }
    }

    fn decode_base64url_signature(encoded: &str) -> [u8; 64] {
        fn value(byte: u8) -> u8 {
            match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => panic!("invalid fixture signature"),
            }
        }
        let mut decoded = Vec::new();
        for chunk in encoded.as_bytes().chunks(4) {
            let a = value(chunk[0]);
            let b = value(chunk[1]);
            decoded.push((a << 2) | (b >> 4));
            if chunk.len() >= 3 {
                let c = value(chunk[2]);
                decoded.push((b << 4) | (c >> 2));
                if chunk.len() == 4 {
                    decoded.push((c << 6) | value(chunk[3]));
                }
            }
        }
        decoded.try_into().unwrap()
    }

    struct CandidateFixture {
        root: TempDirectory,
        fixture_key: PathBuf,
        intent_bundle: PathBuf,
        final_bundle: PathBuf,
        intent: InitialPiReleaseIntentV1,
        source: CatalogSourceV1,
        qualification: CompatibilityQualificationV1,
    }

    impl CandidateFixture {
        fn new() -> Self {
            Self::with_intent_mutation(|_| {})
        }

        fn with_intent_mutation(mutate: impl FnOnce(&mut Value)) -> Self {
            Self::with_finalization_mutations(mutate, |_| {}, |_| {}, true)
        }

        fn with_finalization_mutation(
            mutate_source: impl FnOnce(&mut Value),
            mutate_qualification: impl FnOnce(&mut Value),
            bind_inventory_to_mutated_source: bool,
        ) -> Self {
            Self::with_finalization_mutations(
                |_| {},
                mutate_source,
                mutate_qualification,
                bind_inventory_to_mutated_source,
            )
        }

        fn with_finalization_mutations(
            mutate_intent: impl FnOnce(&mut Value),
            mutate_source: impl FnOnce(&mut Value),
            mutate_qualification: impl FnOnce(&mut Value),
            bind_inventory_to_mutated_source: bool,
        ) -> Self {
            let root = TempDirectory::new();
            let (mut intent_value, package_inputs, objects) = intent_fixture();
            mutate_intent(&mut intent_value);
            let intent =
                InitialPiReleaseIntentV1::from_json(&serde_jcs::to_vec(&intent_value).unwrap())
                    .unwrap();
            let semantic = intent_semantic_digest(&intent).unwrap();
            let intent_bundle = root.path.join("intent-bundle");
            write_transfer(
                &intent_bundle,
                InputSourceKind::ReleaseIntent,
                encode_hex(&initial_release_intent_digest(&intent).unwrap()),
                semantic,
                None,
                vec![
                    ("package_inputs".to_owned(), package_inputs.clone()),
                    (
                        "release_intent".to_owned(),
                        serde_jcs::to_vec(&intent).unwrap(),
                    ),
                ],
                &objects,
            );

            let build_value = json!({
                "implementation_commit": "44".repeat(20),
                "application_sha256": "11".repeat(32),
                "daemon_sha256": "22".repeat(32),
                "compatibility_profile_id": "runtime-catalog-compatibility-v1",
                "compatibility_profile_sha256": "33".repeat(32),
            });
            let build =
                FluxsembleBuildBindingV1::from_json(&serde_jcs::to_vec(&build_value).unwrap())
                    .unwrap();
            let compatibility = encode_hex(&compatibility_input_digest(&intent, &build).unwrap());
            let mut qualification_value = json!({
                "schema_version": 1,
                "compatibility_input_sha256": compatibility,
                "fluxsemble": build_value,
                "provider": "builtin:pi",
                "target": "linux_x86_64",
                "pi_version": intent.release().pi_version().as_str(),
                "node_version": intent.release().node_version().as_str(),
                "checks": {
                    "catalog_v1_conformance": "passed",
                    "managed_installation": "passed",
                    "node_probe": "passed",
                    "pi_probe": "passed",
                    "pi_rpc_readiness": "passed",
                    "activation": "passed",
                    "managed_resolution": "passed",
                    "required_failure": "passed",
                    "cancellation": "passed",
                },
                "reviewer": "fixture-reviewer",
                "release_owner_approved_at": "2026-08-25T00:00:00Z",
                "residual_risks": ["Fixture-only qualification."],
            });
            let baseline_qualification = CompatibilityQualificationV1::from_json(
                &serde_jcs::to_vec(&qualification_value).unwrap(),
            )
            .unwrap();
            let qualification_digest =
                encode_hex(&qualification_record_digest(&baseline_qualification).unwrap());
            let mut source_value = json!({
                "intent": intent_value,
                "build": build,
                "qualification": {
                    "relative_path": "qualifications/fixture-v1.json",
                    "sha256": qualification_digest,
                },
            });
            let baseline_source =
                CatalogSourceV1::from_json(&serde_jcs::to_vec(&source_value).unwrap()).unwrap();
            mutate_source(&mut source_value);
            mutate_qualification(&mut qualification_value);
            let source =
                CatalogSourceV1::from_json(&serde_jcs::to_vec(&source_value).unwrap()).unwrap();
            let qualification = CompatibilityQualificationV1::from_json(
                &serde_jcs::to_vec(&qualification_value).unwrap(),
            )
            .unwrap();
            let inventory_source_digest = if bind_inventory_to_mutated_source {
                catalog_source_digest(&source).unwrap()
            } else {
                catalog_source_digest(&baseline_source).unwrap()
            };
            let final_bundle = root.path.join("final-bundle");
            write_transfer(
                &final_bundle,
                InputSourceKind::CatalogSource,
                encode_hex(&inventory_source_digest),
                compatibility,
                Some(("55".repeat(20), "66".repeat(32))),
                vec![
                    (
                        "catalog_source".to_owned(),
                        serde_jcs::to_vec(&source).unwrap(),
                    ),
                    ("package_inputs".to_owned(), package_inputs),
                    (
                        "qualification".to_owned(),
                        serde_jcs::to_vec(&qualification).unwrap(),
                    ),
                ],
                &objects,
            );
            let fixture_key = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/nonproduction-ed25519-pkcs8.pem");
            Self {
                root,
                fixture_key,
                intent_bundle,
                final_bundle,
                intent,
                source,
                qualification,
            }
        }

        fn from_approved_corpus(corpus_path: &Path) -> Self {
            assert!(
                corpus_path.is_absolute(),
                "authenticated corpus path must be absolute"
            );
            let corpus = AuthenticatedCorpus::open(corpus_path)
                .expect("authenticated corpus root must satisfy the retained capability policy");
            let root = TempDirectory::new();
            let intent_bytes =
                include_bytes!("../tests/fixtures/approved-release/initial-release-intent-v1.json");
            let intent_value: Value = serde_json::from_slice(intent_bytes).unwrap();
            let intent = InitialPiReleaseIntentV1::from_json(intent_bytes).unwrap();
            let package_inputs =
                include_bytes!("../tests/fixtures/approved-release/package-input-manifest-v1.json")
                    .to_vec();
            let package_manifest = parse_package_inputs(&package_inputs).unwrap();
            let release = intent.release().catalog_release();
            let metadata = match release.provider_extension() {
                ProviderExtensionV1::Pi(metadata) => metadata.as_ref(),
                ProviderExtensionV1::None => panic!("approved evidence has no Pi metadata"),
            };
            let node = &release.components()[0].artifacts()[0];
            let pi = &release.components()[1].artifacts()[0];
            let mut objects = FixtureObjects::new();
            objects.insert(
                node.sha256().as_str().to_owned(),
                (
                    node.url().as_str().to_owned(),
                    corpus
                        .read_object(
                            "toolchain/node/node-v22.19.0-linux-x64.tar.xz",
                            node.size_bytes().get(),
                            node.sha256().as_str(),
                        )
                        .expect("authenticated Node archive must remain descriptor-bound"),
                ),
            );
            objects.insert(
                pi.sha256().as_str().to_owned(),
                (
                    pi.url().as_str().to_owned(),
                    corpus
                        .read_object(
                            &format!("packages/archives/{}.tgz", pi.sha256().as_str()),
                            pi.size_bytes().get(),
                            pi.sha256().as_str(),
                        )
                        .expect("authenticated Pi archive must remain descriptor-bound"),
                ),
            );
            for record in &package_manifest.locked_packages {
                objects.insert(
                    record.archive_sha256.clone(),
                    (
                        record.resolved_url.clone(),
                        corpus
                            .read_object(
                                &format!("packages/archives/{}.tgz", record.archive_sha256),
                                record.archive_size,
                                &record.archive_sha256,
                            )
                            .expect("authenticated package archive must remain descriptor-bound"),
                    ),
                );
            }
            for (descriptor, relative) in [
                (
                    metadata.root_package_manifest(),
                    "packages/installed-declarations/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855/package.json",
                ),
                (
                    metadata.shipped_shrinkwrap().artifact(),
                    "packages/installed-declarations/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855/npm-shrinkwrap.json",
                ),
            ] {
                objects.insert(
                    descriptor.sha256().as_str().to_owned(),
                    (
                        descriptor.url().as_str().to_owned(),
                        corpus
                            .read_object(
                                relative,
                                descriptor.size_bytes().get(),
                                descriptor.sha256().as_str(),
                            )
                            .expect(
                                "authenticated package declaration must remain descriptor-bound",
                            ),
                    ),
                );
            }

            let semantic = intent_semantic_digest(&intent).unwrap();
            let intent_bundle = root.path.join("approved-intent-bundle");
            write_transfer(
                &intent_bundle,
                InputSourceKind::ReleaseIntent,
                encode_hex(&initial_release_intent_digest(&intent).unwrap()),
                semantic,
                None,
                vec![
                    ("package_inputs".to_owned(), package_inputs.clone()),
                    ("release_intent".to_owned(), intent_bytes.to_vec()),
                ],
                &objects,
            );

            let build_value = json!({
                "implementation_commit": "44".repeat(20),
                "application_sha256": "11".repeat(32),
                "daemon_sha256": "22".repeat(32),
                "compatibility_profile_id": "runtime-catalog-compatibility-v1",
                "compatibility_profile_sha256": "33".repeat(32),
            });
            let build =
                FluxsembleBuildBindingV1::from_json(&serde_jcs::to_vec(&build_value).unwrap())
                    .unwrap();
            let compatibility = encode_hex(&compatibility_input_digest(&intent, &build).unwrap());
            let qualification_value = json!({
                "schema_version": 1,
                "compatibility_input_sha256": compatibility,
                "fluxsemble": build_value,
                "provider": "builtin:pi",
                "target": "linux_x86_64",
                "pi_version": ROOT_VERSION,
                "node_version": NODE_VERSION,
                "checks": {
                    "catalog_v1_conformance": "passed",
                    "managed_installation": "passed",
                    "node_probe": "passed",
                    "pi_probe": "passed",
                    "pi_rpc_readiness": "passed",
                    "activation": "passed",
                    "managed_resolution": "passed",
                    "required_failure": "passed",
                    "cancellation": "passed",
                },
                "reviewer": "approved-public-evidence-test",
                "release_owner_approved_at": "2026-08-25T00:00:00Z",
                "residual_risks": ["Production private key intentionally unavailable."],
            });
            let qualification = CompatibilityQualificationV1::from_json(
                &serde_jcs::to_vec(&qualification_value).unwrap(),
            )
            .unwrap();
            let qualification_digest =
                encode_hex(&qualification_record_digest(&qualification).unwrap());
            let source_value = json!({
                "intent": intent_value,
                "build": build,
                "qualification": {
                    "relative_path": "qualifications/approved-public-evidence-v1.json",
                    "sha256": qualification_digest,
                },
            });
            let source =
                CatalogSourceV1::from_json(&serde_jcs::to_vec(&source_value).unwrap()).unwrap();
            verify_qualification(&source, &qualification).unwrap();
            let final_bundle = root.path.join("approved-final-bundle");
            write_transfer(
                &final_bundle,
                InputSourceKind::CatalogSource,
                encode_hex(&catalog_source_digest(&source).unwrap()),
                compatibility,
                Some(("55".repeat(20), "66".repeat(32))),
                vec![
                    (
                        "catalog_source".to_owned(),
                        serde_jcs::to_vec(&source).unwrap(),
                    ),
                    ("package_inputs".to_owned(), package_inputs),
                    (
                        "qualification".to_owned(),
                        serde_jcs::to_vec(&qualification).unwrap(),
                    ),
                ],
                &objects,
            );
            let fixture_key = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/nonproduction-ed25519-pkcs8.pem");
            Self {
                root,
                fixture_key,
                intent_bundle,
                final_bundle,
                intent,
                source,
                qualification,
            }
        }
    }

    fn assert_transferred_finalization_arguments_match(
        bundle: &VerifiedTransferredBundle,
        fixture: &CandidateFixture,
    ) {
        let transferred_source =
            CatalogSourceV1::from_json(&bundle.record_bytes("catalog_source").unwrap()).unwrap();
        let transferred_qualification =
            CompatibilityQualificationV1::from_json(&bundle.record_bytes("qualification").unwrap())
                .unwrap();
        assert_eq!(transferred_source, fixture.source);
        assert_eq!(transferred_qualification, fixture.qualification);
    }

    struct AuthenticatedCorpus {
        root: fs::File,
    }

    struct OpenedCorpusObject {
        file: fs::File,
        parent: fs::File,
        final_name: CString,
    }

    impl AuthenticatedCorpus {
        fn open(path: &Path) -> Result<Self, SignError> {
            if !is_absolute_bounded_path(path) {
                return Err(bundle_rejected());
            }
            let root = open_absolute_directory(path)?;
            let metadata = root.metadata().map_err(|_| bundle_rejected())?;
            if !secure_public_corpus_directory(&metadata) {
                return Err(bundle_rejected());
            }
            Ok(Self { root })
        }

        fn read_object(
            &self,
            relative: &str,
            expected_size: u64,
            expected_sha256: &str,
        ) -> Result<Vec<u8>, SignError> {
            self.read_object_with_checkpoints(
                relative,
                expected_size,
                expected_sha256,
                || {},
                || {},
                || {},
                || {},
            )
        }

        fn read_object_with_checkpoint(
            &self,
            relative: &str,
            expected_size: u64,
            expected_sha256: &str,
            before_retained_name_rebind: impl FnOnce(),
        ) -> Result<Vec<u8>, SignError> {
            self.read_object_with_checkpoints(
                relative,
                expected_size,
                expected_sha256,
                || {},
                || {},
                before_retained_name_rebind,
                || {},
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn read_object_with_checkpoints(
            &self,
            relative: &str,
            expected_size: u64,
            expected_sha256: &str,
            before_read: impl FnOnce(),
            after_read: impl FnOnce(),
            before_retained_name_rebind: impl FnOnce(),
            before_full_path_rebind: impl FnOnce(),
        ) -> Result<Vec<u8>, SignError> {
            if !safe_relative(relative)
                || expected_size == 0
                || expected_size > MAX_AUTHENTIC_CORPUS_OBJECT_BYTES
                || !valid_sha256(expected_sha256)
            {
                return Err(bundle_rejected());
            }
            let OpenedCorpusObject {
                mut file,
                parent,
                final_name,
            } = self.open_relative_with_parent(relative)?;
            let before = file.metadata().map_err(|_| bundle_rejected())?;
            if !secure_public_corpus_file(&before) || before.len() != expected_size {
                return Err(bundle_rejected());
            }
            let before = PublicCorpusMetadata::from_metadata(&before);
            before_read();
            let mut bytes = Vec::with_capacity(expected_size as usize);
            (&mut file)
                .take(expected_size + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| bundle_rejected())?;
            after_read();
            let after = file.metadata().map_err(|_| bundle_rejected())?;
            if bytes.len() as u64 != expected_size
                || PublicCorpusMetadata::from_metadata(&after) != before
                || sha256(&bytes) != expected_sha256
            {
                return Err(bundle_rejected());
            }

            before_retained_name_rebind();
            let retained_name = openat2(
                parent.as_raw_fd(),
                &final_name,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
                // RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH.
                0x02 | 0x04 | 0x08,
            )?;
            let retained_name = retained_name.metadata().map_err(|_| bundle_rejected())?;
            if !secure_public_corpus_file(&retained_name)
                || retained_name.len() != expected_size
                || PublicCorpusMetadata::from_metadata(&retained_name) != before
            {
                return Err(bundle_rejected());
            }

            before_full_path_rebind();
            let full_path = self.open_relative(relative)?;
            let full_path = full_path.metadata().map_err(|_| bundle_rejected())?;
            if !secure_public_corpus_file(&full_path)
                || full_path.len() != expected_size
                || PublicCorpusMetadata::from_metadata(&full_path) != before
            {
                return Err(bundle_rejected());
            }
            Ok(bytes)
        }

        fn validated_root(&self) -> Result<fs::File, SignError> {
            let metadata = self.root.metadata().map_err(|_| bundle_rejected())?;
            if !secure_public_corpus_directory(&metadata) {
                return Err(bundle_rejected());
            }
            self.root.try_clone().map_err(|_| bundle_rejected())
        }

        fn open_relative_with_parent(
            &self,
            relative: &str,
        ) -> Result<OpenedCorpusObject, SignError> {
            if !safe_relative(relative) {
                return Err(bundle_rejected());
            }
            let (parent_name, final_name) = relative
                .rsplit_once('/')
                .map_or((None, relative), |(parent, name)| (Some(parent), name));
            let mut parent = self.validated_root()?;
            if let Some(parent_name) = parent_name {
                for component in parent_name.split('/') {
                    let component = CString::new(component).map_err(|_| bundle_rejected())?;
                    let child = openat2(
                        parent.as_raw_fd(),
                        &component,
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                        // RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH.
                        0x02 | 0x04 | 0x08,
                    )?;
                    let metadata = child.metadata().map_err(|_| bundle_rejected())?;
                    if !secure_public_corpus_directory(&metadata) {
                        return Err(bundle_rejected());
                    }
                    parent = child;
                }
            }
            let final_name = CString::new(final_name).map_err(|_| bundle_rejected())?;
            let file = openat2(
                parent.as_raw_fd(),
                &final_name,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
                // RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH.
                0x02 | 0x04 | 0x08,
            )?;
            Ok(OpenedCorpusObject {
                file,
                parent,
                final_name,
            })
        }

        fn open_relative(&self, relative: &str) -> Result<fs::File, SignError> {
            let OpenedCorpusObject { file, .. } = self.open_relative_with_parent(relative)?;
            Ok(file)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct PublicCorpusMetadata {
        device: u64,
        inode: u64,
        size: u64,
        owner: u32,
        links: u64,
        mode: u32,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    }

    impl PublicCorpusMetadata {
        fn from_metadata(metadata: &fs::Metadata) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                size: metadata.len(),
                owner: metadata.uid(),
                links: metadata.nlink(),
                mode: metadata.permissions().mode() & 0o7777,
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            }
        }
    }

    fn secure_public_corpus_directory(metadata: &fs::Metadata) -> bool {
        secure_public_corpus_directory_for_owner(metadata, current_euid())
    }

    fn secure_public_corpus_directory_for_owner(
        metadata: &fs::Metadata,
        expected_owner: u32,
    ) -> bool {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == expected_owner
            && matches!(metadata.permissions().mode() & 0o7777, 0o700 | 0o755)
    }

    fn secure_public_corpus_file(metadata: &fs::Metadata) -> bool {
        secure_public_corpus_file_for_owner(metadata, current_euid())
    }

    fn secure_public_corpus_file_for_owner(metadata: &fs::Metadata, expected_owner: u32) -> bool {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == expected_owner
            && metadata.nlink() == 1
            && matches!(
                metadata.permissions().mode() & 0o7777,
                0o400 | 0o444 | 0o600 | 0o644
            )
    }

    type FixtureObjects = BTreeMap<String, (String, Vec<u8>)>;

    fn intent_fixture() -> (Value, Vec<u8>, FixtureObjects) {
        let mut payload: Value = serde_json::from_slice(include_bytes!(
            "../../../conformance/catalog-v1/valid-payload.json"
        ))
        .unwrap();
        payload["sequence"] = json!("1");
        payload["generated_at"] = json!("2026-08-26T00:00:00Z");
        payload["expires_at"] = json!("2026-09-26T00:00:00Z");
        payload["providers"][0]["allowed_origins"] = json!([
            "https://github.com",
            "https://nodejs.org",
            "https://registry.npmjs.org"
        ]);
        let release = &mut payload["providers"][0]["releases"][0];
        let mut objects = BTreeMap::new();

        let node = b"fixture-node".to_vec();
        let node_digest = sha256(&node);
        release["components"][0]["artifacts"][0]["size_bytes"] = json!(node.len().to_string());
        release["components"][0]["artifacts"][0]["sha256"] = json!(node_digest);
        let node_url = release["components"][0]["artifacts"][0]["url"]
            .as_str()
            .unwrap()
            .to_owned();
        objects.insert(node_digest, (node_url, node));

        let root_archive = b"fixture-pi-root".to_vec();
        let root_digest = sha256(&root_archive);
        release["components"][1]["artifacts"][0]["size_bytes"] =
            json!(root_archive.len().to_string());
        release["components"][1]["artifacts"][0]["sha256"] = json!(root_digest);
        let root_url = release["components"][1]["artifacts"][0]["url"]
            .as_str()
            .unwrap()
            .to_owned();
        objects.insert(root_digest.clone(), (root_url, root_archive));

        let manifest_bytes = br#"{"name":"fixture"}"#.to_vec();
        let manifest_digest = sha256(&manifest_bytes);
        let manifest_name = format!("pi-package-{manifest_digest}.json");
        let manifest_url = format!(
            "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/catalog-v1-sequence-1/{manifest_name}"
        );
        let shrinkwrap_bytes = br#"{"lockfileVersion":3}"#.to_vec();
        let shrinkwrap_digest = sha256(&shrinkwrap_bytes);
        let shrinkwrap_name = format!("pi-shrinkwrap-{shrinkwrap_digest}.json");
        let shrinkwrap_url = format!(
            "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/catalog-v1-sequence-1/{shrinkwrap_name}"
        );
        let metadata = &mut release["provider_extension"]["metadata"];
        metadata["root_package_manifest"] = json!({
            "url": manifest_url,
            "size_bytes": manifest_bytes.len().to_string(),
            "sha256": manifest_digest,
        });
        metadata["shipped_shrinkwrap"]["artifact"] = json!({
            "url": shrinkwrap_url,
            "size_bytes": shrinkwrap_bytes.len().to_string(),
            "sha256": shrinkwrap_digest,
        });
        objects.insert(manifest_digest.clone(), (manifest_url, manifest_bytes));
        objects.insert(
            shrinkwrap_digest.clone(),
            (shrinkwrap_url, shrinkwrap_bytes),
        );

        let mut locators = (0..130)
            .map(|index| format!("node_modules/fixture-package-{index:03}"))
            .chain(PRUNED.iter().map(|(locator, _)| (*locator).to_owned()))
            .collect::<Vec<_>>();
        locators.sort();
        let mut locked = Vec::new();
        let mut observed = Vec::new();
        for (index, locator) in locators.iter().enumerate() {
            let name = locator.strip_prefix("node_modules/").unwrap().to_owned();
            let bytes = format!("archive-{index}-{locator}").into_bytes();
            let digest = sha256(&bytes);
            let url =
                format!("https://registry.npmjs.org/fixture-{index}/-/fixture-{index}-1.0.0.tgz");
            let applicability = PRUNED
                .iter()
                .find(|(pruned, _)| *pruned == locator)
                .map_or_else(
                    || json!({"kind": "applicable"}),
                    |(_, reasons)| json!({"kind": "pruned", "reasons": reasons}),
                );
            locked.push(json!({
                "locator": locator,
                "name": name,
                "version": "1.0.0",
                "resolved_url": url,
                "registry_integrity": SRI,
                "archive_sha256": digest,
            }));
            observed.push(json!({
                "locator": locator,
                "name": name,
                "version": "1.0.0",
                "resolved_url": url,
                "registry_integrity": SRI,
                "archive_size": bytes.len() as u64,
                "archive_sha256": digest,
                "declaration_sha256": sha256(format!("declaration-{index}").as_bytes()),
                "archive_member_count": 1,
                "applicability": applicability,
            }));
            objects.insert(digest, (url, bytes));
        }
        metadata["shipped_shrinkwrap"]["locked_packages"] = Value::Array(locked);

        let package_inputs = serde_jcs::to_vec(&json!({
            "schema_version": 1,
            "target_os": "linux",
            "target_cpu": "x64",
            "target_libc": "glibc",
            "root": {
                "name": ROOT_NAME,
                "version": ROOT_VERSION,
                "archive_size": objects[&root_digest].1.len() as u64,
                "archive_sha256": root_digest,
                "manifest_size": objects[&manifest_digest].1.len() as u64,
                "manifest_sha256": manifest_digest,
                "shrinkwrap_size": objects[&shrinkwrap_digest].1.len() as u64,
                "shrinkwrap_sha256": shrinkwrap_digest,
                "archive_member_count": 1,
            },
            "locked_packages": observed,
            "pre_prune_package_count": PRE_PRUNE_COUNT,
            "applicable_package_count": APPLICABLE_COUNT,
        }))
        .unwrap();
        let intent = json!({
            "sequence": "1",
            "tag": "catalog-v1-sequence-1",
            "generated_at": "2026-08-26T00:00:00Z",
            "expires_at": "2026-09-26T00:00:00Z",
            "fluxsemble_requirement": "=0.1.0",
            "release": {
                "provider": payload["providers"][0]["provider_id"],
                "allowed_origins": payload["providers"][0]["allowed_origins"],
                "release": payload["providers"][0]["releases"][0],
            },
        });
        (intent, package_inputs, objects)
    }

    fn write_transfer(
        path: &Path,
        source_kind: InputSourceKind,
        source_sha256: String,
        compatibility_input_sha256: String,
        claims: Option<(String, String)>,
        mut records: Vec<(String, Vec<u8>)>,
        objects: &BTreeMap<String, (String, Vec<u8>)>,
    ) {
        fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        for directory in ["objects", "records"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path.join(directory))
                .unwrap();
        }
        records.sort_by(|left, right| left.0.cmp(&right.0));
        let mut entries = Vec::new();
        let mut record_refs = Vec::new();
        for (role, bytes) in records {
            let digest = sha256(&bytes);
            let relative = format!("records/{digest}");
            write_read_only(&path.join(&relative), &bytes);
            entries.push(json!({"relative_path": relative, "mode": "0400", "size": bytes.len() as u64, "sha256": digest}));
            record_refs.push(json!({"role": role, "relative_path": relative, "sha256": digest}));
        }
        let mut inventory_objects = Vec::new();
        for (digest, (url, bytes)) in objects {
            let relative = format!("objects/{digest}");
            write_read_only(&path.join(&relative), bytes);
            entries.push(json!({"relative_path": relative, "mode": "0400", "size": bytes.len() as u64, "sha256": digest}));
            inventory_objects.push(json!({"relative_path": relative, "source_url": url, "size": bytes.len() as u64, "sha256": digest}));
        }
        let inventory = serde_jcs::to_vec(&json!({
            "schema_version": 1,
            "source_kind": source_kind,
            "source_sha256": source_sha256,
            "compatibility_input_sha256": compatibility_input_sha256,
            "objects": inventory_objects,
        }))
        .unwrap();
        let inventory_digest = sha256(&inventory);
        write_read_only(&path.join(VERIFIED_INPUT_NAME), &inventory);
        entries.push(json!({"relative_path": VERIFIED_INPUT_NAME, "mode": "0400", "size": inventory.len() as u64, "sha256": inventory_digest}));
        entries.sort_by(|left, right| {
            left["relative_path"]
                .as_str()
                .cmp(&right["relative_path"].as_str())
        });
        let (source_commit, source_tree_sha256) =
            claims.map_or((None, None), |(commit, tree)| (Some(commit), Some(tree)));
        let manifest = serde_jcs::to_vec(&json!({
            "schema_version": 1,
            "kind": "verified_input",
            "source_commit": source_commit,
            "source_tree_sha256": source_tree_sha256,
            "records": record_refs,
            "entries": entries,
        }))
        .unwrap();
        write_read_only(&path.join(TRANSFER_MANIFEST_NAME), &manifest);
    }

    fn copy_transfer_tree(source: &Path, destination: &Path) {
        fs::DirBuilder::new()
            .mode(fs::symlink_metadata(source).unwrap().permissions().mode() & 0o7777)
            .create(destination)
            .unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            let target = destination.join(entry.file_name());
            if metadata.is_dir() {
                copy_transfer_tree(&entry.path(), &target);
            } else {
                assert!(metadata.is_file() && !metadata.file_type().is_symlink());
                fs::copy(entry.path(), &target).unwrap();
                fs::set_permissions(
                    target,
                    fs::Permissions::from_mode(metadata.permissions().mode() & 0o7777),
                )
                .unwrap();
            }
        }
    }

    fn write_read_only(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
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
                "catalog-sign-candidate-test-{}-{nonce}",
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
