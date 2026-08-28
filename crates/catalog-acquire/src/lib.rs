mod archive;
mod bundle_writer;
mod http;
mod npm;

pub use archive::*;
pub use bundle_writer::*;
pub use http::*;
pub use npm::*;

use std::{
    num::NonZeroU64,
    path::PathBuf,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};

use tokio::sync::Notify;

use catalog_core::{
    ArtifactDescriptor, CatalogSourceV1, CompatibilityQualificationV1, InitialPiReleaseIntentV1,
    InputSourceKind, PiCatalogExtensionMetadata, ProviderExtensionV1, catalog_source_digest,
    compatibility_input_digest, initial_release_intent_digest, verify_qualification,
};
use sha2::{Digest, Sha256};

pub enum AcquireReleaseSource {
    Intent {
        intent: InitialPiReleaseIntentV1,
    },
    Final {
        source: Box<CatalogSourceV1>,
        qualification: Box<CompatibilityQualificationV1>,
        source_commit: String,
        source_tree_sha256: String,
    },
}

pub struct AcquireReleaseRequest {
    pub source: AcquireReleaseSource,
    pub package_inputs: PackageInputManifestV1,
    pub cache_root: PathBuf,
    pub output: PathBuf,
    pub cancellation: AcquisitionCancellation,
}

pub struct DiscoverInputsRequest {
    pub intent: InitialPiReleaseIntentV1,
    pub cache_root: PathBuf,
    pub output: PathBuf,
    pub cancellation: AcquisitionCancellation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportAcquisition {
    ExtractFromVerifiedRoot,
}

const fn support_acquisition(source_kind: InputSourceKind) -> SupportAcquisition {
    match source_kind {
        InputSourceKind::ReleaseIntent => SupportAcquisition::ExtractFromVerifiedRoot,
        InputSourceKind::CatalogSource => SupportAcquisition::ExtractFromVerifiedRoot,
    }
}

pub async fn discover_inputs(
    request: DiscoverInputsRequest,
) -> Result<PackageInputManifestV1, AcquireError> {
    let metadata = pi_metadata(&request.intent)?;
    let root_descriptor = pi_artifact(&request.intent, metadata)?;
    let root_fetched = fetch_artifact(
        &request.cache_root,
        root_descriptor,
        request.intent.release().allowed_origins(),
        Some(metadata.registry_integrity()),
        &request.cancellation,
    )
    .await?;
    let mut root = verify_fetched_archive(
        root_fetched,
        root_descriptor.url().as_str().to_owned(),
        root_descriptor.size_bytes().get(),
        root_descriptor.sha256().as_str().to_owned(),
        Some(metadata.registry_integrity().as_str().to_owned()),
        &request.cancellation,
    )
    .await?;
    let mut locked = Vec::with_capacity(metadata.shipped_shrinkwrap().locked_packages().len());
    for record in metadata.shipped_shrinkwrap().locked_packages() {
        let fetched = fetch_locked(
            &request.cache_root,
            record,
            request.intent.release().allowed_origins(),
            None,
            &request.cancellation,
        )
        .await?;
        let fetched_size = fetched.size();
        locked.push(
            verify_fetched_archive(
                fetched,
                record.resolved_url().as_str().to_owned(),
                fetched_size,
                record.archive_sha256().as_str().to_owned(),
                Some(record.registry_integrity().as_str().to_owned()),
                &request.cancellation,
            )
            .await?,
        );
    }
    let intent = request.intent;
    let output = request.output;
    run_publication_blocking(&request.cancellation, move |control| {
        let observed = discover_package_inputs(&intent, &mut root, &mut locked)?;
        write_discovery(
            &output,
            &observed,
            || control.wait_for_authorization(),
            || control.claim_publication(),
        )?;
        Ok(observed)
    })
    .await
}

pub async fn acquire_release(
    request: AcquireReleaseRequest,
) -> Result<catalog_core::VerifiedInputBundleV1, AcquireError> {
    let SourceMaterial {
        intent,
        source_kind,
        source_digest,
        compatibility_digest,
        source_claims,
        mut records,
    } = source_material(request.source)?;
    let metadata = pi_metadata(&intent)?;
    let node_descriptor = node_artifact(&intent)?;
    let root_descriptor = pi_artifact(&intent, metadata)?;

    let node_fetched = fetch_artifact(
        &request.cache_root,
        node_descriptor,
        intent.release().allowed_origins(),
        None,
        &request.cancellation,
    )
    .await?;
    let root_fetched = fetch_artifact(
        &request.cache_root,
        root_descriptor,
        intent.release().allowed_origins(),
        Some(metadata.registry_integrity()),
        &request.cancellation,
    )
    .await?;
    let mut locked = Vec::with_capacity(metadata.shipped_shrinkwrap().locked_packages().len());
    for record in metadata.shipped_shrinkwrap().locked_packages() {
        let size = request
            .package_inputs
            .archive_size_for(record.locator().as_str())
            .ok_or(AcquireError::Graph)?;
        let fetched = fetch_locked(
            &request.cache_root,
            record,
            intent.release().allowed_origins(),
            Some(size),
            &request.cancellation,
        )
        .await?;
        locked.push(
            verify_fetched_archive(
                fetched,
                record.resolved_url().as_str().to_owned(),
                size,
                record.archive_sha256().as_str().to_owned(),
                Some(record.registry_integrity().as_str().to_owned()),
                &request.cancellation,
            )
            .await?,
        );
    }
    let node = verify_fetched_archive(
        node_fetched,
        node_descriptor.url().as_str().to_owned(),
        node_descriptor.size_bytes().get(),
        node_descriptor.sha256().as_str().to_owned(),
        None,
        &request.cancellation,
    )
    .await?;
    let root = verify_fetched_archive(
        root_fetched,
        root_descriptor.url().as_str().to_owned(),
        root_descriptor.size_bytes().get(),
        root_descriptor.sha256().as_str().to_owned(),
        Some(metadata.registry_integrity().as_str().to_owned()),
        &request.cancellation,
    )
    .await?;
    let manifest_url = metadata.root_package_manifest().url().as_str().to_owned();
    let manifest_size = metadata.root_package_manifest().size_bytes().get();
    let manifest_sha256 = metadata
        .root_package_manifest()
        .sha256()
        .as_str()
        .to_owned();
    let shrinkwrap_url = metadata
        .shipped_shrinkwrap()
        .artifact()
        .url()
        .as_str()
        .to_owned();
    let shrinkwrap_size = metadata.shipped_shrinkwrap().artifact().size_bytes().get();
    let shrinkwrap_sha256 = metadata
        .shipped_shrinkwrap()
        .artifact()
        .sha256()
        .as_str()
        .to_owned();
    records.push(BundleRecord {
        role: "package_inputs".to_owned(),
        bytes: request.package_inputs.canonical_bytes()?,
    });
    let package_inputs = request.package_inputs;
    let output = request.output;
    let cache_root = request.cache_root;
    run_publication_blocking(&request.cancellation, move |control| {
        let graph = verify_npm_graph(NpmGraphRequest {
            intent,
            node_archive: node,
            root_archive: root,
            locked_archives: locked,
            package_inputs,
        })?;
        let (_, node, root, locked, _, root_manifest, shrinkwrap) = graph.into_parts();
        if sha256(&root_manifest) != manifest_sha256 || sha256(&shrinkwrap) != shrinkwrap_sha256 {
            return Err(AcquireError::Graph);
        }
        let (manifest_object, shrinkwrap_object) = match support_acquisition(source_kind) {
            SupportAcquisition::ExtractFromVerifiedRoot => (
                PublicBundleObject::from_extracted_bytes(
                    &cache_root,
                    manifest_url,
                    manifest_size,
                    manifest_sha256,
                    &root_manifest,
                )?,
                PublicBundleObject::from_extracted_bytes(
                    &cache_root,
                    shrinkwrap_url,
                    shrinkwrap_size,
                    shrinkwrap_sha256,
                    &shrinkwrap,
                )?,
            ),
        };
        let mut objects = vec![
            PublicBundleObject::from_archive(node),
            PublicBundleObject::from_archive(root),
            manifest_object,
            shrinkwrap_object,
        ];
        objects.extend(locked.into_iter().map(PublicBundleObject::from_archive));
        let (source_commit, source_tree_sha256) =
            source_claims.map_or((None, None), |(commit, tree)| (Some(commit), Some(tree)));
        write_verified_bundle_with_publication(
            VerifiedBundleWriteRequest {
                source_kind,
                source_sha256: source_digest,
                compatibility_input_sha256: compatibility_digest,
                source_commit,
                source_tree_sha256,
                records,
                objects,
            },
            &output,
            || control.wait_for_authorization(),
            || control.claim_publication(),
        )
    })
    .await
}

async fn verify_fetched_archive(
    fetched: FetchedObject,
    source_url: String,
    size: u64,
    sha256: String,
    sri: Option<String>,
    cancellation: &AcquisitionCancellation,
) -> Result<VerifiedArchive, AcquireError> {
    run_blocking(cancellation, move || {
        VerifiedArchive::verify(fetched.into_file(), source_url, size, sha256, sri)
    })
    .await
}

async fn run_blocking<T: Send + 'static>(
    cancellation: &AcquisitionCancellation,
    operation: impl FnOnce() -> Result<T, AcquireError> + Send + 'static,
) -> Result<T, AcquireError> {
    if cancellation.is_cancelled() {
        return Err(AcquireError::Cancelled);
    }
    let mut task = tokio::task::spawn_blocking(operation);
    tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            let _ = task.await.map_err(|_| AcquireError::Input)?;
            Err(AcquireError::Cancelled)
        }
        result = &mut task => result.map_err(|_| AcquireError::Input)?,
    }
}

async fn run_publication_blocking<T: Send + 'static>(
    cancellation: &AcquisitionCancellation,
    operation: impl FnOnce(PublicationControl) -> Result<T, AcquireError> + Send + 'static,
) -> Result<T, AcquireError> {
    if cancellation.is_cancelled() {
        return Err(AcquireError::Cancelled);
    }
    let control = PublicationControl::new();
    let mut guard = PublicationGuard::new(control.clone());
    let operation_control = control.clone();
    let mut task = tokio::task::spawn_blocking(move || operation(operation_control));
    tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            let abort_won = guard.abort();
            let result = task.await.map_err(|_| AcquireError::Input)?;
            if abort_won {
                Err(AcquireError::Cancelled)
            } else {
                result
            }
        }
        () = control.ready() => {
            if cancellation.is_cancelled() {
                let abort_won = guard.abort();
                let result = task.await.map_err(|_| AcquireError::Input)?;
                return if abort_won {
                    Err(AcquireError::Cancelled)
                } else {
                    result
                };
            }
            if !guard.authorize() {
                let _ = task.await.map_err(|_| AcquireError::Input)?;
                return Err(AcquireError::Cancelled);
            }
            tokio::select! {
                biased;
                () = cancellation.cancelled() => {
                    let abort_won = guard.abort();
                    let result = task.await.map_err(|_| AcquireError::Input)?;
                    if abort_won {
                        Err(AcquireError::Cancelled)
                    } else {
                        result
                    }
                }
                result = &mut task => {
                    guard.abort();
                    result.map_err(|_| AcquireError::Input)?
                }
            }
        }
        result = &mut task => {
            guard.abort();
            result.map_err(|_| AcquireError::Input)?
        }
    }
}

const PUBLICATION_WORKING: u8 = 0;
const PUBLICATION_READY: u8 = 1;
const PUBLICATION_AUTHORIZED: u8 = 2;
const PUBLICATION_ABORT: u8 = 3;
const PUBLICATION_CLAIMED: u8 = 4;

#[derive(Clone)]
struct PublicationControl {
    inner: Arc<PublicationControlInner>,
}

struct PublicationControlInner {
    state: AtomicU8,
    notify: Notify,
    lock: Mutex<()>,
    decision: Condvar,
}

impl PublicationControl {
    fn new() -> Self {
        Self {
            inner: Arc::new(PublicationControlInner {
                state: AtomicU8::new(PUBLICATION_WORKING),
                notify: Notify::new(),
                lock: Mutex::new(()),
                decision: Condvar::new(),
            }),
        }
    }

    async fn ready(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.inner.state.load(Ordering::Acquire) != PUBLICATION_WORKING {
                return;
            }
            notified.await;
        }
    }

    #[cfg(test)]
    async fn wait_until_aborted_for_test(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.inner.state.load(Ordering::Acquire) == PUBLICATION_ABORT {
                return;
            }
            notified.await;
        }
    }

    fn wait_for_authorization(&self) -> bool {
        if !self.transition(PUBLICATION_WORKING, PUBLICATION_READY) {
            return false;
        }
        let mut lock = self.inner.lock.lock().expect("publication decision lock");
        while self.inner.state.load(Ordering::Acquire) == PUBLICATION_READY {
            lock = self
                .inner
                .decision
                .wait(lock)
                .expect("publication decision wait");
        }
        self.inner.state.load(Ordering::Acquire) == PUBLICATION_AUTHORIZED
    }

    fn authorize(&self) -> bool {
        self.transition(PUBLICATION_READY, PUBLICATION_AUTHORIZED)
    }

    fn claim_publication(&self) -> bool {
        self.transition(PUBLICATION_AUTHORIZED, PUBLICATION_CLAIMED)
    }

    fn abort(&self) -> bool {
        let _lock = self.inner.lock.lock().expect("publication decision lock");
        loop {
            let current = self.inner.state.load(Ordering::Acquire);
            match current {
                PUBLICATION_ABORT => return true,
                PUBLICATION_CLAIMED => return false,
                PUBLICATION_WORKING | PUBLICATION_READY | PUBLICATION_AUTHORIZED => {
                    if self
                        .inner
                        .state
                        .compare_exchange(
                            current,
                            PUBLICATION_ABORT,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        self.inner.notify.notify_waiters();
                        self.inner.decision.notify_all();
                        return true;
                    }
                }
                _ => return false,
            }
        }
    }

    fn transition(&self, current: u8, next: u8) -> bool {
        let _lock = self.inner.lock.lock().expect("publication decision lock");
        let transitioned = self
            .inner
            .state
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if transitioned {
            self.inner.notify.notify_waiters();
            self.inner.decision.notify_all();
        }
        transitioned
    }
}

struct PublicationGuard {
    control: PublicationControl,
    active: bool,
}

impl PublicationGuard {
    fn new(control: PublicationControl) -> Self {
        Self {
            control,
            active: true,
        }
    }

    fn authorize(&self) -> bool {
        self.control.authorize()
    }

    fn abort(&mut self) -> bool {
        let won = self.control.abort();
        self.active = false;
        won
    }
}

impl Drop for PublicationGuard {
    fn drop(&mut self) {
        if self.active {
            self.control.abort();
        }
    }
}

struct SourceMaterial {
    intent: InitialPiReleaseIntentV1,
    source_kind: InputSourceKind,
    source_digest: String,
    compatibility_digest: String,
    source_claims: Option<(String, String)>,
    records: Vec<BundleRecord>,
}

fn source_material(source: AcquireReleaseSource) -> Result<SourceMaterial, AcquireError> {
    match source {
        AcquireReleaseSource::Intent { intent } => {
            let bytes = serde_jcs::to_vec(&intent).map_err(|_| AcquireError::Input)?;
            let source_digest =
                hex(&initial_release_intent_digest(&intent).map_err(|_| AcquireError::Input)?);
            let compatibility = intent_semantic_digest(&intent)?;
            Ok(SourceMaterial {
                intent,
                source_kind: InputSourceKind::ReleaseIntent,
                source_digest,
                compatibility_digest: compatibility,
                source_claims: None,
                records: vec![BundleRecord {
                    role: "release_intent".to_owned(),
                    bytes,
                }],
            })
        }
        AcquireReleaseSource::Final {
            source,
            qualification,
            source_commit,
            source_tree_sha256,
        } => {
            verify_qualification(&source, &qualification).map_err(|_| AcquireError::Input)?;
            if !valid_commit(&source_commit) || !valid_sha256(&source_tree_sha256) {
                return Err(AcquireError::Input);
            }
            let source_bytes = serde_jcs::to_vec(&source).map_err(|_| AcquireError::Input)?;
            let qualification_bytes =
                serde_jcs::to_vec(&qualification).map_err(|_| AcquireError::Input)?;
            let source_digest =
                hex(&catalog_source_digest(&source).map_err(|_| AcquireError::Input)?);
            let compatibility = hex(&compatibility_input_digest(source.intent(), source.build())
                .map_err(|_| AcquireError::Input)?);
            let intent = source.intent().clone();
            Ok(SourceMaterial {
                intent,
                source_kind: InputSourceKind::CatalogSource,
                source_digest,
                compatibility_digest: compatibility,
                source_claims: Some((source_commit, source_tree_sha256)),
                records: vec![
                    BundleRecord {
                        role: "catalog_source".to_owned(),
                        bytes: source_bytes,
                    },
                    BundleRecord {
                        role: "qualification".to_owned(),
                        bytes: qualification_bytes,
                    },
                ],
            })
        }
    }
}

async fn fetch_artifact(
    cache: &std::path::Path,
    descriptor: &ArtifactDescriptor,
    allowed_origins: &[catalog_core::AllowedOrigin],
    sri: Option<&catalog_core::RegistryIntegrity>,
    cancellation: &AcquisitionCancellation,
) -> Result<FetchedObject, AcquireError> {
    let request = FetchRequest::from_catalog_values(
        descriptor.url(),
        allowed_origins,
        Some(descriptor.size_bytes().get()),
        NonZeroU64::new(descriptor.size_bytes().get()).ok_or(AcquireError::Input)?,
        descriptor.sha256(),
        sri,
    );
    fetcher_for_url(cache, descriptor.url().as_str())?
        .fetch_exact(request, cancellation)
        .await
}

async fn fetch_locked(
    cache: &std::path::Path,
    record: &catalog_core::LockedPackageRecord,
    allowed_origins: &[catalog_core::AllowedOrigin],
    expected_size: Option<u64>,
    cancellation: &AcquisitionCancellation,
) -> Result<FetchedObject, AcquireError> {
    let maximum = expected_size.unwrap_or(512 * 1024 * 1024);
    let request = FetchRequest::from_catalog_values(
        record.resolved_url(),
        allowed_origins,
        expected_size,
        NonZeroU64::new(maximum).ok_or(AcquireError::Input)?,
        record.archive_sha256(),
        Some(record.registry_integrity()),
    );
    CredentialFreeFetcher::new(cache)?
        .fetch_exact(request, cancellation)
        .await
}

fn fetcher_for_url(
    cache: &std::path::Path,
    url: &str,
) -> Result<CredentialFreeFetcher, AcquireError> {
    if url.starts_with("https://github.com/") {
        CredentialFreeFetcher::for_github_release_assets(cache)
    } else {
        CredentialFreeFetcher::new(cache)
    }
}

fn pi_metadata(
    intent: &InitialPiReleaseIntentV1,
) -> Result<&PiCatalogExtensionMetadata, AcquireError> {
    match intent.release().catalog_release().provider_extension() {
        ProviderExtensionV1::Pi(metadata) => Ok(metadata),
        ProviderExtensionV1::None => Err(AcquireError::Input),
    }
}

fn pi_artifact<'a>(
    intent: &'a InitialPiReleaseIntentV1,
    metadata: &PiCatalogExtensionMetadata,
) -> Result<&'a ArtifactDescriptor, AcquireError> {
    intent
        .release()
        .catalog_release()
        .components()
        .iter()
        .find(|component| component.component_id() == metadata.component_id())
        .and_then(|component| {
            component
                .artifacts()
                .iter()
                .find(|artifact| artifact.artifact_id() == metadata.package_artifact_id())
        })
        .ok_or(AcquireError::Input)
}

fn node_artifact(intent: &InitialPiReleaseIntentV1) -> Result<&ArtifactDescriptor, AcquireError> {
    let component = intent
        .release()
        .catalog_release()
        .components()
        .iter()
        .find(|component| component.component_id().as_str() == "component:node")
        .ok_or(AcquireError::Input)?;
    if component.artifacts().len() != 1 {
        return Err(AcquireError::Input);
    }
    let artifact = component.artifacts().first().ok_or(AcquireError::Input)?;
    archive::require_pinned_node_identity(
        artifact.url().as_str(),
        artifact.size_bytes().get(),
        artifact.sha256().as_str(),
    )?;
    Ok(artifact)
}

fn write_discovery(
    output: &std::path::Path,
    manifest: &PackageInputManifestV1,
    authorize_publication: impl FnOnce() -> bool,
    claim_publication: impl FnOnce() -> bool,
) -> Result<(), AcquireError> {
    const DISCOVERY_NAME: &str = "observed-package-inputs-v1.json";

    let bytes = manifest.canonical_bytes()?;
    let mut output_root = bundle_writer::OutputRoot::create(output)?;
    output_root.write_file(DISCOVERY_NAME, &bytes)?;
    output_root.verify_file_bytes(DISCOVERY_NAME, &bytes)?;
    output_root.prepare()?;
    if !authorize_publication() {
        return Err(AcquireError::Cancelled);
    }
    output_root.publish(claim_publication)
}

fn intent_semantic_digest(intent: &InitialPiReleaseIntentV1) -> Result<String, AcquireError> {
    #[derive(serde::Serialize)]
    struct Semantic<'a> {
        fluxsemble_requirement: &'a catalog_core::ExactVersionRequirement,
        release: &'a catalog_core::InitialPiReleaseSemanticsV1,
    }
    let canonical = serde_jcs::to_vec(&Semantic {
        fluxsemble_requirement: intent.fluxsemble_requirement(),
        release: intent.release(),
    })
    .map_err(|_| AcquireError::Input)?;
    let mut hasher = Sha256::new();
    hasher.update(b"fluxsemble:runtime-catalog-intent-semantics:v1\0");
    hasher.update(canonical);
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
        path::PathBuf,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use serde_json::json;

    use super::{
        AcquireError, AcquisitionCancellation, PackageInputManifestV1, SupportAcquisition,
        run_publication_blocking, support_acquisition, write_discovery,
    };

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

    #[test]
    fn prepublication_sources_extract_support_from_verified_root_without_network() {
        for source_kind in [
            catalog_core::InputSourceKind::ReleaseIntent,
            catalog_core::InputSourceKind::CatalogSource,
        ] {
            assert_eq!(
                support_acquisition(source_kind),
                SupportAcquisition::ExtractFromVerifiedRoot,
            );
        }
    }

    #[test]
    fn discovery_publishes_one_verified_read_only_file_atomically() {
        let parent = TempDirectory::new();
        let output = parent.path.join("discovery");
        let expected = manifest().canonical_bytes().unwrap();
        write_discovery(
            &output,
            &manifest(),
            || {
                assert!(
                    !output.exists(),
                    "final name must stay unpublished while tentative"
                );
                true
            },
            || true,
        )
        .unwrap();

        let file = output.join("observed-package-inputs-v1.json");
        assert_eq!(fs::read(&file).unwrap(), expected);
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert_eq!(fs::read_dir(&output).unwrap().count(), 1);
    }

    #[test]
    fn discovery_rejects_replaced_staging_container_before_worker_claim() {
        let parent = TempDirectory::new();
        let output = parent.path.join("discovery");
        let result = write_discovery(
            &output,
            &manifest(),
            || {
                let staged = fs::read_dir(&parent.path)
                    .unwrap()
                    .filter_map(Result::ok)
                    .find(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".catalog-acquire-stage-")
                    })
                    .unwrap()
                    .path();
                fs::rename(&staged, staged.with_extension("original")).unwrap();
                fs::DirBuilder::new().mode(0o700).create(&staged).unwrap();
                true
            },
            || true,
        );
        assert_eq!(result, Err(AcquireError::Bundle));
        assert!(!output.exists());
    }

    #[test]
    fn discovery_abort_leaves_the_final_output_name_absent() {
        let parent = TempDirectory::new();
        let output = parent.path.join("discovery");
        assert_eq!(
            write_discovery(&output, &manifest(), || false, || true),
            Err(AcquireError::Cancelled)
        );
        assert!(!output.exists());
    }

    #[test]
    fn discovery_abort_never_deletes_a_late_final_directory_name() {
        let parent = TempDirectory::new();
        let output = parent.path.join("discovery");
        let result = write_discovery(
            &output,
            &manifest(),
            || {
                assert!(
                    !output.exists(),
                    "final name must stay unpublished while tentative"
                );
                fs::DirBuilder::new().mode(0o700).create(&output).unwrap();
                fs::write(output.join("sentinel"), b"replacement").unwrap();
                false
            },
            || true,
        );
        assert_eq!(result, Err(AcquireError::Cancelled));
        assert_eq!(fs::read(output.join("sentinel")).unwrap(), b"replacement");
        assert!(!output.join("observed-package-inputs-v1.json").exists());
    }

    #[test]
    fn discovery_abort_never_follows_or_deletes_a_late_final_symlink() {
        let parent = TempDirectory::new();
        let output = parent.path.join("discovery");
        let outside = parent.path.join("outside");
        fs::DirBuilder::new().mode(0o700).create(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"outside").unwrap();
        let result = write_discovery(
            &output,
            &manifest(),
            || {
                assert!(
                    !output.exists(),
                    "final name must stay unpublished while tentative"
                );
                symlink(&outside, &output).unwrap();
                false
            },
            || true,
        );
        assert_eq!(result, Err(AcquireError::Cancelled));
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"outside");
        assert!(!outside.join("observed-package-inputs-v1.json").exists());
    }

    #[tokio::test]
    async fn discovery_cancellation_leaves_final_absent_and_cannot_publish_late() {
        let parent = TempDirectory::new();
        let output = parent.path.join("discovery");
        let replacement = output.clone();
        let operation_output = output.clone();
        let cancellation = AcquisitionCancellation::new();
        let operation_cancellation = cancellation.clone();
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            run_publication_blocking(&operation_cancellation, move |control| {
                write_discovery(
                    &operation_output,
                    &manifest(),
                    || {
                        let _ = reached_tx.send(());
                        control.wait_for_authorization()
                    },
                    || control.claim_publication(),
                )
            })
            .await
        });
        reached_rx.await.unwrap();
        assert!(!output.exists());
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&replacement)
            .unwrap();
        fs::write(replacement.join("sentinel"), b"replacement").unwrap();
        cancellation.cancel();

        assert_eq!(task.await.unwrap(), Err(AcquireError::Cancelled));
        assert_eq!(
            fs::read(replacement.join("sentinel")).unwrap(),
            b"replacement"
        );
        assert!(!replacement.join("observed-package-inputs-v1.json").exists());
    }

    #[tokio::test]
    async fn cancellation_after_authorization_but_before_worker_claim_aborts_publication() {
        for attempt in 0..32 {
            let parent = TempDirectory::new();
            let output = parent.path.join("discovery");
            let operation_output = output.clone();
            let cancellation = AcquisitionCancellation::new();
            let operation_cancellation = cancellation.clone();
            let (authorized_tx, authorized_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let task = tokio::spawn(async move {
                run_publication_blocking(&operation_cancellation, move |control| {
                    write_discovery(
                        &operation_output,
                        &manifest(),
                        || {
                            let authorized = control.wait_for_authorization();
                            if authorized {
                                let _ = authorized_tx.send(control.clone());
                                release_rx.recv().unwrap();
                            }
                            authorized
                        },
                        || control.claim_publication(),
                    )
                })
                .await
            });
            let control = authorized_rx.await.unwrap();
            assert!(!output.exists(), "attempt {attempt}");

            cancellation.cancel();
            tokio::time::timeout(
                Duration::from_secs(5),
                control.wait_until_aborted_for_test(),
            )
            .await
            .unwrap();
            release_tx.send(()).unwrap();

            assert_eq!(
                task.await.unwrap(),
                Err(AcquireError::Cancelled),
                "attempt {attempt}"
            );
            assert!(!output.exists(), "attempt {attempt}");
        }
    }

    #[tokio::test]
    async fn dropping_after_authorization_but_before_worker_claim_aborts_publication() {
        let parent = TempDirectory::new();
        let output = parent.path.join("discovery");
        let operation_output = output.clone();
        let cancellation = AcquisitionCancellation::new();
        let (authorized_tx, authorized_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (settled_tx, settled_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            run_publication_blocking(&cancellation, move |control| {
                let result = write_discovery(
                    &operation_output,
                    &manifest(),
                    || {
                        let authorized = control.wait_for_authorization();
                        if authorized {
                            let _ = authorized_tx.send(());
                            release_rx.recv().unwrap();
                        }
                        authorized
                    },
                    || control.claim_publication(),
                );
                let _ = settled_tx.send(result);
                result
            })
            .await
        });
        authorized_rx.await.unwrap();
        assert!(!output.exists());

        task.abort();
        let _ = task.await;
        release_tx.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), settled_rx)
                .await
                .unwrap()
                .unwrap(),
            Err(AcquireError::Cancelled)
        );
        assert!(!output.exists());
    }

    #[tokio::test]
    async fn dropping_discovery_future_aborts_and_settles_without_late_publication() {
        let parent = TempDirectory::new();
        let output = parent.path.join("discovery");
        let outside = parent.path.join("outside");
        fs::DirBuilder::new().mode(0o700).create(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"outside").unwrap();
        let operation_output = output.clone();
        let cancellation = AcquisitionCancellation::new();
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (settled_tx, settled_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            run_publication_blocking(&cancellation, move |control| {
                let result = write_discovery(
                    &operation_output,
                    &manifest(),
                    || {
                        let _ = reached_tx.send(());
                        control.wait_for_authorization()
                    },
                    || control.claim_publication(),
                );
                let _ = settled_tx.send(());
                result
            })
            .await
        });
        reached_rx.await.unwrap();
        assert!(!output.exists());
        symlink(&outside, &output).unwrap();

        task.abort();
        let _ = task.await;
        tokio::time::timeout(Duration::from_secs(5), settled_rx)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"outside");
        assert!(!outside.join("observed-package-inputs-v1.json").exists());
    }

    fn manifest() -> PackageInputManifestV1 {
        let mut packages = PRUNED
            .into_iter()
            .map(|(locator, reasons)| {
                json!({
                    "locator": locator,
                    "name": "package",
                    "version": "1.0.0",
                    "resolved_url": "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
                    "registry_integrity": format!("sha512-{}", "A".repeat(88)),
                    "archive_size": 1,
                    "archive_sha256": "1".repeat(64),
                    "declaration_sha256": "2".repeat(64),
                    "archive_member_count": 1,
                    "applicability": {"kind":"pruned", "reasons": reasons},
                })
            })
            .collect::<Vec<_>>();
        packages.extend((0..130).map(|index| {
            json!({
                "locator": format!("node_modules/package-{index:03}"),
                "name": format!("package-{index:03}"),
                "version": "1.0.0",
                "resolved_url": format!("https://registry.npmjs.org/package-{index:03}/-/package-{index:03}-1.0.0.tgz"),
                "registry_integrity": format!("sha512-{}", "A".repeat(88)),
                "archive_size": 1,
                "archive_sha256": "1".repeat(64),
                "declaration_sha256": "2".repeat(64),
                "archive_member_count": 1,
                "applicability": {"kind":"applicable"},
            })
        }));
        let value = json!({
            "schema_version": 1,
            "target_os": "linux",
            "target_cpu": "x64",
            "target_libc": "glibc",
            "root": {
                "name": "@earendil-works/pi-coding-agent",
                "version": "0.83.0",
                "archive_size": 1,
                "archive_sha256": "1".repeat(64),
                "manifest_size": 1,
                "manifest_sha256": "2".repeat(64),
                "shrinkwrap_size": 1,
                "shrinkwrap_sha256": "3".repeat(64),
                "archive_member_count": 1
            },
            "locked_packages": packages,
            "pre_prune_package_count": 131,
            "applicable_package_count": 130
        });
        PackageInputManifestV1::from_json(&serde_json::to_vec(&value).unwrap()).unwrap()
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
                "catalog-discovery-test-{}-{nanos}",
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
