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
    ArtifactDescriptor, CatalogSourceV1, CompatibilityQualificationV1, ImmutableFileDescriptor,
    InitialPiReleaseIntentV1, InputSourceKind, PiCatalogExtensionMetadata, ProviderExtensionV1,
    catalog_source_digest, compatibility_input_digest, initial_release_intent_digest,
    verify_qualification,
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
        write_discovery(&output, &observed, || control.wait_for_decision())?;
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
    let manifest_fetched = fetch_immutable(
        &request.cache_root,
        metadata.root_package_manifest(),
        &intent,
        &request.cancellation,
    )
    .await?;
    let shrinkwrap_fetched = fetch_immutable(
        &request.cache_root,
        metadata.shipped_shrinkwrap().artifact(),
        &intent,
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
    let manifest_object = verify_public_object(
        manifest_fetched,
        metadata.root_package_manifest().url().as_str().to_owned(),
        metadata.root_package_manifest().size_bytes().get(),
        metadata
            .root_package_manifest()
            .sha256()
            .as_str()
            .to_owned(),
        &request.cancellation,
    )
    .await?;
    let shrinkwrap_object = verify_public_object(
        shrinkwrap_fetched,
        metadata
            .shipped_shrinkwrap()
            .artifact()
            .url()
            .as_str()
            .to_owned(),
        metadata.shipped_shrinkwrap().artifact().size_bytes().get(),
        metadata
            .shipped_shrinkwrap()
            .artifact()
            .sha256()
            .as_str()
            .to_owned(),
        &request.cancellation,
    )
    .await?;

    records.push(BundleRecord {
        role: "package_inputs".to_owned(),
        bytes: request.package_inputs.canonical_bytes()?,
    });
    let package_inputs = request.package_inputs;
    let output = request.output;
    run_publication_blocking(&request.cancellation, move |control| {
        let graph = verify_npm_graph(NpmGraphRequest {
            intent,
            node_archive: node,
            root_archive: root,
            locked_archives: locked,
            package_inputs,
        })?;
        let (_, node, root, locked, _, root_manifest, shrinkwrap) = graph.into_parts();
        if sha256(&root_manifest) != manifest_object_digest(&manifest_object)
            || sha256(&shrinkwrap) != manifest_object_digest(&shrinkwrap_object)
        {
            return Err(AcquireError::Graph);
        }
        let mut objects = vec![
            PublicBundleObject::from_archive(node),
            PublicBundleObject::from_archive(root),
            manifest_object,
            shrinkwrap_object,
        ];
        objects.extend(locked.into_iter().map(PublicBundleObject::from_archive));
        let (source_commit, source_tree_sha256) =
            source_claims.map_or((None, None), |(commit, tree)| (Some(commit), Some(tree)));
        write_verified_bundle_with_decision(
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
            || control.wait_for_decision(),
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

async fn verify_public_object(
    fetched: FetchedObject,
    source_url: String,
    size: u64,
    sha256: String,
    cancellation: &AcquisitionCancellation,
) -> Result<PublicBundleObject, AcquireError> {
    run_blocking(cancellation, move || {
        PublicBundleObject::verified_file(fetched.into_file(), source_url, size, sha256)
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
            guard.abort();
            let _ = task.await.map_err(|_| AcquireError::Input)?;
            Err(AcquireError::Cancelled)
        }
        () = control.tentative() => {
            if cancellation.is_cancelled() {
                guard.abort();
                let _ = task.await.map_err(|_| AcquireError::Input)?;
                return Err(AcquireError::Cancelled);
            }
            guard.commit();
            task.await.map_err(|_| AcquireError::Input)?
        }
        result = &mut task => {
            guard.abort();
            result.map_err(|_| AcquireError::Input)?
        }
    }
}

const PUBLICATION_WORKING: u8 = 0;
const PUBLICATION_TENTATIVE: u8 = 1;
const PUBLICATION_COMMIT: u8 = 2;
const PUBLICATION_ABORT: u8 = 3;

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

    async fn tentative(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.inner.state.load(Ordering::Acquire) != PUBLICATION_WORKING {
                return;
            }
            notified.await;
        }
    }

    fn wait_for_decision(&self) -> bool {
        if self
            .inner
            .state
            .compare_exchange(
                PUBLICATION_WORKING,
                PUBLICATION_TENTATIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        self.inner.notify.notify_waiters();
        let mut lock = self.inner.lock.lock().expect("publication decision lock");
        while self.inner.state.load(Ordering::Acquire) == PUBLICATION_TENTATIVE {
            lock = self
                .inner
                .decision
                .wait(lock)
                .expect("publication decision wait");
        }
        self.inner.state.load(Ordering::Acquire) == PUBLICATION_COMMIT
    }

    fn decide(&self, state: u8) {
        let _lock = self.inner.lock.lock().expect("publication decision lock");
        let current = self.inner.state.load(Ordering::Acquire);
        if current != PUBLICATION_COMMIT && current != PUBLICATION_ABORT {
            self.inner.state.store(state, Ordering::Release);
            self.inner.notify.notify_waiters();
            self.inner.decision.notify_all();
        }
    }
}

struct PublicationGuard {
    control: PublicationControl,
    decided: bool,
}

impl PublicationGuard {
    fn new(control: PublicationControl) -> Self {
        Self {
            control,
            decided: false,
        }
    }

    fn commit(&mut self) {
        self.control.decide(PUBLICATION_COMMIT);
        self.decided = true;
    }

    fn abort(&mut self) {
        self.control.decide(PUBLICATION_ABORT);
        self.decided = true;
    }
}

impl Drop for PublicationGuard {
    fn drop(&mut self) {
        if !self.decided {
            self.control.decide(PUBLICATION_ABORT);
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

async fn fetch_immutable(
    cache: &std::path::Path,
    descriptor: &ImmutableFileDescriptor,
    intent: &InitialPiReleaseIntentV1,
    cancellation: &AcquisitionCancellation,
) -> Result<FetchedObject, AcquireError> {
    let request = FetchRequest::from_catalog_values(
        descriptor.url(),
        intent.release().allowed_origins(),
        Some(descriptor.size_bytes().get()),
        NonZeroU64::new(descriptor.size_bytes().get()).ok_or(AcquireError::Input)?,
        descriptor.sha256(),
        None,
    );
    fetcher_for_url(cache, descriptor.url().as_str())?
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
    component.artifacts().first().ok_or(AcquireError::Input)
}

fn write_discovery(
    output: &std::path::Path,
    manifest: &PackageInputManifestV1,
    decide_publication: impl FnOnce() -> bool,
) -> Result<(), AcquireError> {
    match std::fs::symlink_metadata(output) {
        Ok(_) => return Err(AcquireError::Bundle),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(AcquireError::Bundle),
    }
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(false)
        .mode(0o700)
        .create(output)
        .map_err(|_| AcquireError::Bundle)?;
    let mut cleanup = DiscoveryCleanup {
        path: output.to_owned(),
        committed: false,
    };
    let path = output.join("observed-package-inputs-v1.json");
    let mut options = std::fs::OpenOptions::new();
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let mut file = options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| AcquireError::Bundle)?;
    file.write_all(&manifest.canonical_bytes()?)
        .map_err(|_| AcquireError::Bundle)?;
    file.sync_all().map_err(|_| AcquireError::Bundle)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o400))
        .map_err(|_| AcquireError::Bundle)?;
    file.sync_all().map_err(|_| AcquireError::Bundle)?;
    std::fs::File::open(output)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| AcquireError::Bundle)?;
    if !decide_publication() {
        return Err(AcquireError::Cancelled);
    }
    cleanup.committed = true;
    Ok(())
}

struct DiscoveryCleanup {
    path: PathBuf,
    committed: bool,
}

impl Drop for DiscoveryCleanup {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
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

fn manifest_object_digest(object: &PublicBundleObject) -> String {
    object.sha256().to_owned()
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
