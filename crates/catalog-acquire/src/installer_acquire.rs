//! Original acquisition owner for versioned installer releases.
use crate::{
    AcquireError, AcquisitionCancellation, BundleRecord, DiscoverPiReleaseRequest,
    PackageInputManifestV2, PiInstallerDiscoveryPolicy, PublicBundleObject,
    ReleaseDiscoveryTransport, VerifiedBundleWriteRequest,
    archive::inspect_npm_archive,
    discover_pi_installer_release_with_transport,
    npm::{HttpReleaseDiscoveryTransport, sha256, verified_bytes},
};
use catalog_core::{CatalogSourceV2, InputSourceKind, PiReleaseIntentV2, VerifiedInputBundleV1};
use std::{cell::RefCell, collections::BTreeMap, path::PathBuf};

type ExpectedObjects = BTreeMap<String, (u64, String)>;

pub enum AcquireInstallerReleaseSource {
    Intent {
        intent: PiReleaseIntentV2,
    },
    Final {
        source: Box<CatalogSourceV2>,
        qualification_bytes: Vec<u8>,
        source_commit: String,
        source_tree_sha256: String,
    },
}
pub struct AcquireInstallerReleaseRequest {
    pub source: AcquireInstallerReleaseSource,
    pub package_inputs: PackageInputManifestV2,
    pub cache_root: PathBuf,
    pub output: PathBuf,
    pub cancellation: AcquisitionCancellation,
}

pub async fn acquire_installer_release(
    request: AcquireInstallerReleaseRequest,
) -> Result<VerifiedInputBundleV1, AcquireError> {
    let cancellation = request.cancellation.clone();
    crate::run_publication_blocking(&cancellation, move |control| {
        acquire_with_control(
            request,
            &HttpReleaseDiscoveryTransport::new()?,
            || control.wait_for_authorization(),
            || control.claim_publication(),
        )
    })
    .await
}

/// Deterministic public transport seam; all original graph and exact-source checks still run.
#[doc(hidden)]
pub fn acquire_installer_release_with_transport(
    request: AcquireInstallerReleaseRequest,
    transport: &dyn ReleaseDiscoveryTransport,
) -> Result<VerifiedInputBundleV1, AcquireError> {
    acquire_with_control(request, transport, || true, || true)
}

fn acquire_with_control(
    request: AcquireInstallerReleaseRequest,
    transport: &dyn ReleaseDiscoveryTransport,
    authorize: impl FnOnce() -> bool,
    claim: impl FnOnce() -> bool,
) -> Result<VerifiedInputBundleV1, AcquireError> {
    let (intent, kind, source_digest, source_claims, mut records) = match request.source {
        AcquireInstallerReleaseSource::Intent { intent } => {
            let digest = catalog_core::pi_release_intent_v2_digest(&intent)
                .map_err(|_| AcquireError::Input)?;
            let record = BundleRecord {
                role: "release_intent".into(),
                bytes: serde_jcs::to_vec(&intent).map_err(|_| AcquireError::Input)?,
            };
            (
                intent,
                InputSourceKind::ReleaseIntent,
                digest,
                None,
                vec![record],
            )
        }
        AcquireInstallerReleaseSource::Final {
            source,
            qualification_bytes,
            source_commit,
            source_tree_sha256,
        } => {
            source
                .finalize(&qualification_bytes)
                .map_err(|_| AcquireError::Input)?;
            let digest =
                catalog_core::catalog_source_v2_digest(&source).map_err(|_| AcquireError::Input)?;
            let records = vec![
                BundleRecord {
                    role: "catalog_source".into(),
                    bytes: serde_jcs::to_vec(&source).map_err(|_| AcquireError::Input)?,
                },
                BundleRecord {
                    role: "qualification".into(),
                    bytes: qualification_bytes,
                },
            ];
            (
                source.intent().clone(),
                InputSourceKind::CatalogSource,
                digest,
                Some((source_commit, source_tree_sha256)),
                records,
            )
        }
    };
    request
        .package_inputs
        .validate_for_profile(intent.profile())?;
    let mut expected = ExpectedObjects::new();
    for source in [
        request.package_inputs.installer_manifest_source(),
        request.package_inputs.installer_lock_source(),
    ] {
        insert_expected(
            &mut expected,
            source.url(),
            source.size_bytes(),
            source.sha256(),
        )?;
    }
    for source in request.package_inputs.auxiliary_inputs() {
        insert_expected(
            &mut expected,
            source.url(),
            source.size_bytes(),
            source.sha256(),
        )?;
    }
    for component in intent.profile().components() {
        for artifact in component.artifacts() {
            insert_expected(
                &mut expected,
                artifact.url().as_str(),
                artifact.size_bytes().get(),
                artifact.sha256().as_str(),
            )?;
        }
    }
    for package in intent.profile().locked_packages() {
        let size = request
            .package_inputs
            .archive_size_for(package.locator().as_str())
            .ok_or(AcquireError::Graph)?;
        insert_expected(
            &mut expected,
            package.resolved_url().as_str(),
            size,
            package.archive_sha256().as_str(),
        )?;
    }
    let bound = BoundTransport {
        transport,
        expected,
        observed: RefCell::new(BTreeMap::new()),
        cancellation: &request.cancellation,
    };
    let rediscovered = discover_pi_installer_release_with_transport(
        DiscoverPiReleaseRequest {
            sequence: intent.sequence(),
            generated_at: intent.generated_at().as_str().into(),
            expires_at: intent.expires_at().as_str().into(),
            pi_version: intent.profile().pi_package().version().as_str().into(),
            node_version: intent.profile().node_version().as_str().into(),
            target: intent.profile().target().as_str().into(),
            title: intent.title().into(),
            notes: intent.notes().into(),
            installer_policy: Some(PiInstallerDiscoveryPolicy {
                consumer_requirement: intent.profile().consumer_requirement().as_str().into(),
                required_contracts: intent.profile().required_contracts().clone(),
            }),
        },
        &bound,
    )?;
    if rediscovered.profile != *intent.profile()
        || rediscovered.inputs != request.package_inputs
        || request.cancellation.is_cancelled()
    {
        return Err(AcquireError::Graph);
    }
    let mut objects = bound.observed.into_inner();
    if objects.len() != bound.expected.len() {
        return Err(AcquireError::Graph);
    }
    // External installer assets retain original fetch provenance in the V2 record. Their exact
    // bytes are materialized under final publication descriptors only after full graph replay.
    for (source, descriptor) in [
        (
            request.package_inputs.installer_manifest_source(),
            intent.profile().installer_manifest(),
        ),
        (
            request.package_inputs.installer_lock_source(),
            intent.profile().installer_lock(),
        ),
    ] {
        let bytes = objects.remove(source.url()).ok_or(AcquireError::Graph)?;
        if bytes.len() as u64 != descriptor.size_bytes().get()
            || sha256(&bytes) != descriptor.sha256().as_str()
        {
            return Err(AcquireError::Graph);
        }
        objects.insert(descriptor.url().as_str().into(), bytes);
    }
    let pi = intent
        .profile()
        .locked_packages()
        .iter()
        .find(|p| p.locator() == intent.profile().pi_package_locator())
        .ok_or(AcquireError::Graph)?;
    let mut archive = verified_bytes(
        objects
            .get(pi.resolved_url().as_str())
            .ok_or(AcquireError::Graph)?
            .clone(),
        pi.resolved_url().as_str(),
        Some(pi.registry_integrity().as_str()),
    )?;
    let manifest = inspect_npm_archive(&mut archive, false)?.declaration;
    let descriptor = intent.profile().pi_manifest();
    if manifest.len() as u64 != descriptor.size_bytes().get()
        || sha256(&manifest) != descriptor.sha256().as_str()
    {
        return Err(AcquireError::Graph);
    }
    objects.insert(descriptor.url().as_str().into(), manifest);
    let mut public_objects = Vec::new();
    for (url, bytes) in objects {
        public_objects.push(PublicBundleObject::from_extracted_bytes(
            &request.cache_root,
            url,
            bytes.len() as u64,
            sha256(&bytes),
            &bytes,
        )?);
    }
    records.push(BundleRecord {
        role: "package_inputs".into(),
        bytes: request.package_inputs.canonical_bytes()?,
    });
    let (source_commit, source_tree_sha256) =
        source_claims.map_or((None, None), |(c, t)| (Some(c), Some(t)));
    let subject = catalog_core::pi_release_subject_sha256(intent.profile())
        .map_err(|_| AcquireError::Graph)?;
    if request.cancellation.is_cancelled() {
        return Err(AcquireError::Cancelled);
    }
    crate::bundle_writer::write_verified_bundle_with_publication(
        VerifiedBundleWriteRequest {
            source_kind: kind,
            source_sha256: hex(&source_digest),
            compatibility_input_sha256: hex(&subject),
            source_commit,
            source_tree_sha256,
            records,
            objects: public_objects,
        },
        &request.output,
        authorize,
        claim,
    )
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn insert_expected(
    expected: &mut ExpectedObjects,
    url: &str,
    size: u64,
    digest: &str,
) -> Result<(), AcquireError> {
    if expected
        .insert(url.into(), (size, digest.into()))
        .is_some_and(|old| old != (size, digest.into()))
    {
        return Err(AcquireError::Graph);
    }
    Ok(())
}
struct BoundTransport<'a> {
    transport: &'a dyn ReleaseDiscoveryTransport,
    expected: ExpectedObjects,
    observed: RefCell<BTreeMap<String, Vec<u8>>>,
    cancellation: &'a AcquisitionCancellation,
}
impl ReleaseDiscoveryTransport for BoundTransport<'_> {
    fn fetch(&self, url: &str, maximum: usize) -> Result<Vec<u8>, AcquireError> {
        if self.cancellation.is_cancelled() {
            return Err(AcquireError::Cancelled);
        }
        let expected = self.expected.get(url);
        let limit = expected.map_or(maximum, |(size, _)| maximum.min(*size as usize));
        let bytes = self.transport.fetch(url, limit)?;
        if let Some((size, digest)) = expected {
            if bytes.len() as u64 != *size || sha256(&bytes) != *digest {
                return Err(AcquireError::DigestMismatch);
            }
            self.observed.borrow_mut().insert(url.into(), bytes.clone());
        }
        Ok(bytes)
    }
}
