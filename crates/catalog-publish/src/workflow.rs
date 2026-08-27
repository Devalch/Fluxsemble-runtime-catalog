use std::{
    collections::BTreeSet,
    error::Error,
    fmt, fs,
    io::{Seek, SeekFrom, Write},
    os::{fd::FromRawFd, unix::fs::PermissionsExt},
    path::Path,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::{
    github::{
        BrokerTransport, CredentialFreeLatest, DownloadedAsset, GitHubBroker, RemoteAsset,
        RemoteBoundaryError, RemoteRelease, RemoteReleaseAsset, RemoteTag, UploadSource,
    },
    local::{
        FailureOutcome, PublishError, RemoteRecordKind, RemoteWorkflowLock, RemoteWorkflowState,
        open_remote_workflow_state,
    },
};

#[cfg(test)]
use crate::github::LatestTransport;

const REPOSITORY: &str = "Devalch/Fluxsemble-runtime-catalog";
const OPERATION_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-remote-operation:v1\0";
const DRAFT_RECEIPT_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-draft-receipt:v1\0";
const APPROVAL_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-release-approval:v1\0";
const PUBLICATION_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-publication-receipt:v1\0";
const LATEST_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-latest-receipt:v1\0";
const TRANSPORT_OPERATION_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-transport-operation:v1\0";
const TRANSPORT_RECEIPT_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-transport-receipt:v1\0";
const MAX_RECORD_BYTES: usize = 256 * 1024;
const TRANSPORT_MANIFEST: &[u8] = include_bytes!("../../../conformance/transport/manifest-v1.json");
const TRANSPORT_ASSET: &[u8] =
    include_bytes!("../../../conformance/transport/github-release-asset-v1.txt");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteWorkflowOutcome {
    DraftStaged,
    Approved,
    PublishedAndLatestVerified,
    LatestVerified,
    TransportFixturePublished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteWorkflowError {
    outcome: FailureOutcome,
}

impl RemoteWorkflowError {
    #[must_use]
    pub const fn outcome(&self) -> FailureOutcome {
        self.outcome
    }
}

impl fmt::Display for RemoteWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("remote catalog publication failed")
    }
}

impl Error for RemoteWorkflowError {}

const fn failed(outcome: FailureOutcome) -> RemoteWorkflowError {
    RemoteWorkflowError { outcome }
}

const fn rejected() -> RemoteWorkflowError {
    failed(FailureOutcome::Normal)
}

const fn uncertain() -> RemoteWorkflowError {
    failed(FailureOutcome::OutcomeUncertain)
}

const fn recovery_required() -> RemoteWorkflowError {
    failed(FailureOutcome::RecoveryRequired)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteOperationBodyV1 {
    repository: String,
    local_operation_id: String,
    signed_transfer_sha256: String,
    broker_client_config_sha256: String,
    broker_executable_sha256: String,
    publisher_broker_config_sha256: String,
    source_commit: String,
    source_tree_sha256: String,
    sequence: u64,
    tag: String,
    title: String,
    notes: String,
    assets: Vec<RemoteAsset>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemoteOperationPhaseV1 {
    Prepared,
    TagVerified,
    DraftBound,
    Uploading,
    AssetsVerified,
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteOperationV1 {
    schema_version: u16,
    remote_operation_id: String,
    operation: RemoteOperationBodyV1,
    release_id: Option<String>,
    verified_assets: u16,
    phase: RemoteOperationPhaseV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteReceiptAssetV1 {
    asset_id: String,
    name: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftReceiptBodyV1 {
    repository: String,
    release_id: String,
    tag: String,
    tag_commit: String,
    target_commitish: String,
    source_tree_sha256: String,
    title: String,
    notes: String,
    draft: bool,
    prerelease: bool,
    local_operation_id: String,
    remote_operation_id: String,
    signed_transfer_sha256: String,
    broker_client_config_sha256: String,
    broker_executable_sha256: String,
    publisher_broker_config_sha256: String,
    assets: Vec<RemoteReceiptAssetV1>,
    phase: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftReceiptV1 {
    schema_version: u16,
    receipt_id: String,
    body: DraftReceiptBodyV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseApprovalV1 {
    schema_version: u16,
    approval_id: String,
    status: String,
    draft_receipt_sha256: String,
    draft_receipt_id: String,
    repository: String,
    release_id: String,
    tag: String,
    source_commit: String,
    local_operation_id: String,
    remote_operation_id: String,
    assets: Vec<RemoteReceiptAssetV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceiptV1 {
    schema_version: u16,
    publication_id: String,
    phase: String,
    approval_sha256: String,
    draft_receipt_sha256: String,
    repository: String,
    release_id: String,
    tag: String,
    source_commit: String,
    assets: Vec<RemoteReceiptAssetV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LatestReceiptV1 {
    schema_version: u16,
    latest_id: String,
    phase: String,
    publication_sha256: String,
    repository: String,
    release_id: String,
    tag: String,
    catalog: RemoteAsset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportManifestV1 {
    schema_version: u16,
    repository: String,
    tag: String,
    title: String,
    notes: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<RemoteAsset>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportOperationV1 {
    schema_version: u16,
    transport_operation_id: String,
    repository: String,
    local_operation_id: String,
    signed_transfer_sha256: String,
    source_commit: String,
    manifest_sha256: String,
    broker_client_config_sha256: String,
    broker_executable_sha256: String,
    publisher_broker_config_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportReceiptV1 {
    schema_version: u16,
    transport_receipt_id: String,
    transport_operation_id: String,
    repository: String,
    source_commit: String,
    release_id: String,
    tag: String,
    asset: RemoteReceiptAssetV1,
    phase: String,
}

struct OperationHandle {
    record: RemoteOperationV1,
    bytes: Vec<u8>,
}

/// Stages the exact production local candidate through the fixed authenticated broker.
pub fn stage_remote(
    state_path: &Path,
    broker_config: &Path,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    let state = open_remote_workflow_state(state_path).map_err(local_error)?;
    let mut broker = GitHubBroker::new(broker_config).map_err(|_| recovery_required())?;
    stage_remote_inner(&state, &mut broker)
}

#[allow(dead_code)]
#[cfg(test)]
pub(crate) fn stage_remote_fixture_with(
    state_path: &Path,
    broker: &mut dyn BrokerTransport,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    let state =
        crate::local::open_fixture_remote_workflow_state(state_path).map_err(local_error)?;
    stage_remote_inner(&state, broker)
}

fn stage_remote_inner(
    state: &RemoteWorkflowState,
    broker: &mut dyn BrokerTransport,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    let lock = state.acquire_workflow_lock().map_err(local_error)?;
    lock.revalidate().map_err(local_error)?;
    let broker_identity = broker.identity_digests().map_err(|_| recovery_required())?;
    let body = operation_body(state, broker_identity)?;
    settle_pending_operation(state, &lock, Some(&body))?;
    lock.revalidate().map_err(local_error)?;
    let remote_operation_id = domain_digest(OPERATION_DOMAIN, &body)?;
    let initial = RemoteOperationV1 {
        schema_version: 1,
        remote_operation_id,
        operation: body,
        release_id: None,
        verified_assets: 0,
        phase: RemoteOperationPhaseV1::Prepared,
    };
    let mut operation = begin_operation(state, initial)?;

    // Create is intentionally attempted on every pre-receipt retry. A failure is resolved only by
    // the immediately following exact readback; tags are never replaced.
    lock.revalidate().map_err(local_error)?;
    let _create_result = broker.create_tag(
        REPOSITORY,
        &operation.record.operation.tag,
        &operation.record.operation.source_commit,
    );
    let tag = broker
        .read_tag(REPOSITORY, &operation.record.operation.tag)
        .map_err(|_| mark_uncertain(state, &mut operation))?;
    require_exact_tag(
        &tag,
        &operation.record.operation.tag,
        &operation.record.operation.source_commit,
    )
    .inspect_err(|_| {
        let _ = mark_operation_uncertain(state, &mut operation);
    })?;
    let verified_assets = operation.record.verified_assets;
    update_operation(
        state,
        &mut operation,
        None,
        verified_assets,
        RemoteOperationPhaseV1::TagVerified,
    )?;

    let release = ensure_exact_draft(state, &lock, broker, &mut operation, false)?;
    let release_id = release.release_id.clone();
    let verified_assets = operation.record.verified_assets;
    update_operation(
        state,
        &mut operation,
        Some(release_id.clone()),
        verified_assets,
        RemoteOperationPhaseV1::DraftBound,
    )?;

    let receipt_assets = verify_and_upload_all(state, &lock, broker, &mut operation, &release_id)?;
    update_operation(
        state,
        &mut operation,
        Some(release_id.clone()),
        u16::try_from(receipt_assets.len()).map_err(|_| rejected())?,
        RemoteOperationPhaseV1::AssetsVerified,
    )?;

    lock.revalidate().map_err(local_error)?;
    let final_tag = broker
        .read_tag(REPOSITORY, &operation.record.operation.tag)
        .map_err(|_| mark_uncertain(state, &mut operation))?;
    require_exact_tag(
        &final_tag,
        &operation.record.operation.tag,
        &operation.record.operation.source_commit,
    )
    .inspect_err(|_| {
        let _ = mark_operation_uncertain(state, &mut operation);
    })?;
    let final_release = broker
        .read_draft(REPOSITORY, &operation.record.operation.tag)
        .map_err(|_| mark_uncertain(state, &mut operation))?
        .ok_or_else(|| mark_uncertain(state, &mut operation))?;
    require_release(
        &final_release,
        &operation.record.operation,
        Some(&release_id),
        true,
        false,
    )
    .and_then(|()| require_complete_assets(&final_release.assets, &receipt_assets))
    .and_then(|()| redownload_receipt_assets(broker, &final_release, &receipt_assets))
    .inspect_err(|_| {
        let _ = mark_operation_uncertain(state, &mut operation);
    })?;

    let receipt_body = DraftReceiptBodyV1 {
        repository: REPOSITORY.to_owned(),
        release_id,
        tag: final_tag.tag,
        tag_commit: final_tag.commit_sha.clone(),
        target_commitish: final_release.target_commitish,
        source_tree_sha256: operation.record.operation.source_tree_sha256.clone(),
        title: final_release.title,
        notes: final_release.notes,
        draft: true,
        prerelease: false,
        local_operation_id: operation.record.operation.local_operation_id.clone(),
        remote_operation_id: operation.record.remote_operation_id.clone(),
        signed_transfer_sha256: operation.record.operation.signed_transfer_sha256.clone(),
        broker_client_config_sha256: operation
            .record
            .operation
            .broker_client_config_sha256
            .clone(),
        broker_executable_sha256: operation.record.operation.broker_executable_sha256.clone(),
        publisher_broker_config_sha256: operation
            .record
            .operation
            .publisher_broker_config_sha256
            .clone(),
        assets: receipt_assets,
        phase: "draft_verified".to_owned(),
    };
    let receipt = DraftReceiptV1 {
        schema_version: 1,
        receipt_id: domain_digest(DRAFT_RECEIPT_DOMAIN, &receipt_body)?,
        body: receipt_body,
    };
    validate_draft_receipt(&receipt, state)?;
    let bytes = canonical(&receipt)?;
    state
        .write_record_no_clobber(RemoteRecordKind::DraftReceipt, &bytes)
        .map_err(local_error)?;
    lock.revalidate().map_err(local_error)?;
    Ok(RemoteWorkflowOutcome::DraftStaged)
}

/// Performs only the local explicit digest approval transition.
pub fn approve_remote(
    state_path: &Path,
    draft_receipt_sha256: &str,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    let state = open_remote_workflow_state(state_path).map_err(local_error)?;
    approve_inner(&state, draft_receipt_sha256)
}

#[allow(dead_code)]
#[cfg(test)]
pub(crate) fn approve_remote_fixture(
    state_path: &Path,
    draft_receipt_sha256: &str,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    let state =
        crate::local::open_fixture_remote_workflow_state(state_path).map_err(local_error)?;
    approve_inner(&state, draft_receipt_sha256)
}

fn approve_inner(
    state: &RemoteWorkflowState,
    supplied_sha256: &str,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    let lock = state.acquire_workflow_lock().map_err(local_error)?;
    settle_pending_operation(state, &lock, None)?;
    lock.revalidate().map_err(local_error)?;
    require_sha256(supplied_sha256)?;
    let receipt_bytes = state
        .read_record(RemoteRecordKind::DraftReceipt)
        .map_err(local_error)?
        .ok_or_else(recovery_required)?;
    if sha256(&receipt_bytes) != supplied_sha256 {
        return Err(rejected());
    }
    let receipt: DraftReceiptV1 = parse_canonical(&receipt_bytes)?;
    validate_draft_receipt(&receipt, state)?;
    let approval_body = (
        supplied_sha256,
        &receipt.receipt_id,
        &receipt.body.repository,
        &receipt.body.release_id,
        &receipt.body.tag,
        &receipt.body.tag_commit,
        &receipt.body.local_operation_id,
        &receipt.body.remote_operation_id,
        &receipt.body.assets,
        "approved",
    );
    let approval = ReleaseApprovalV1 {
        schema_version: 1,
        approval_id: domain_digest(APPROVAL_DOMAIN, &approval_body)?,
        status: "approved".to_owned(),
        draft_receipt_sha256: supplied_sha256.to_owned(),
        draft_receipt_id: receipt.receipt_id.clone(),
        repository: receipt.body.repository.clone(),
        release_id: receipt.body.release_id.clone(),
        tag: receipt.body.tag.clone(),
        source_commit: receipt.body.tag_commit.clone(),
        local_operation_id: receipt.body.local_operation_id.clone(),
        remote_operation_id: receipt.body.remote_operation_id.clone(),
        assets: receipt.body.assets.clone(),
    };
    validate_approval(&approval, &receipt, state)?;
    state
        .write_record_no_clobber(RemoteRecordKind::Approval, &canonical(&approval)?)
        .map_err(local_error)?;
    Ok(RemoteWorkflowOutcome::Approved)
}

/// Publishes only the approved exact draft and then awaits fixed latest verification. The async
/// API never creates a runtime; the CLI owns its one outer runtime.
pub async fn publish_remote(
    state_path: &Path,
    approval_path: &Path,
    broker_config: &Path,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    require_approval_path(state_path, approval_path)?;
    let state = open_remote_workflow_state(state_path).map_err(local_error)?;
    let mut broker = GitHubBroker::new(broker_config).map_err(|_| recovery_required())?;
    publish_broker_inner(&state, &mut broker)?;
    verify_latest_production_inner(&state).await?;
    Ok(RemoteWorkflowOutcome::PublishedAndLatestVerified)
}

#[allow(dead_code)]
#[cfg(test)]
pub(crate) fn publish_remote_fixture_with(
    state_path: &Path,
    approval_path: &Path,
    broker: &mut dyn BrokerTransport,
    latest: &mut dyn LatestTransport,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    require_approval_path(state_path, approval_path)?;
    let state =
        crate::local::open_fixture_remote_workflow_state(state_path).map_err(local_error)?;
    publish_broker_inner(&state, broker)?;
    verify_latest_inner(&state, latest)?;
    Ok(RemoteWorkflowOutcome::PublishedAndLatestVerified)
}

fn publish_broker_inner(
    state: &RemoteWorkflowState,
    broker: &mut dyn BrokerTransport,
) -> Result<(), RemoteWorkflowError> {
    let lock = state.acquire_workflow_lock().map_err(local_error)?;
    lock.revalidate().map_err(local_error)?;
    let broker_identity = broker.identity_digests().map_err(|_| recovery_required())?;
    let expected_operation = operation_body(state, broker_identity.clone())?;
    settle_pending_operation(state, &lock, Some(&expected_operation))?;
    lock.revalidate().map_err(local_error)?;
    let receipt_bytes = state
        .read_record(RemoteRecordKind::DraftReceipt)
        .map_err(local_error)?
        .ok_or_else(recovery_required)?;
    let receipt: DraftReceiptV1 = parse_canonical(&receipt_bytes)?;
    validate_draft_receipt(&receipt, state)?;
    let approval_bytes = state
        .read_record(RemoteRecordKind::Approval)
        .map_err(local_error)?
        .ok_or_else(recovery_required)?;
    let approval: ReleaseApprovalV1 = parse_canonical(&approval_bytes)?;
    validate_approval(&approval, &receipt, state)?;
    if broker_identity.broker_client_config_sha256 != receipt.body.broker_client_config_sha256
        || broker_identity.broker_executable_sha256 != receipt.body.broker_executable_sha256
        || broker_identity.publisher_broker_config_sha256
            != receipt.body.publisher_broker_config_sha256
    {
        return Err(recovery_required());
    }

    lock.revalidate().map_err(local_error)?;
    let tag = broker
        .read_tag(REPOSITORY, &receipt.body.tag)
        .map_err(|_| recovery_required())?;
    require_exact_tag(&tag, &receipt.body.tag, &receipt.body.tag_commit)?;
    let before = broker
        .read_draft(REPOSITORY, &receipt.body.tag)
        .map_err(|_| recovery_required())?
        .ok_or_else(recovery_required)?;
    require_receipt_release(&before, &receipt, None)?;
    redownload_receipt_assets(broker, &before, &receipt.body.assets)?;

    let existing_publication = state
        .read_record(RemoteRecordKind::PublicationReceipt)
        .map_err(local_error)?;
    if existing_publication.is_none() && before.draft {
        lock.revalidate().map_err(local_error)?;
        let _publish_result = broker.publish_draft(REPOSITORY, &receipt.body.release_id);
    }
    let after = broker
        .read_draft(REPOSITORY, &receipt.body.tag)
        .map_err(|_| recovery_required())?
        .ok_or_else(recovery_required)?;
    require_receipt_release(&after, &receipt, Some(false))?;
    redownload_receipt_assets(broker, &after, &receipt.body.assets)?;

    let publication_body = (
        sha256(&approval_bytes),
        sha256(&receipt_bytes),
        &receipt.body.repository,
        &receipt.body.release_id,
        &receipt.body.tag,
        &receipt.body.tag_commit,
        &receipt.body.assets,
        "published_latest_pending",
    );
    let publication = PublicationReceiptV1 {
        schema_version: 1,
        publication_id: domain_digest(PUBLICATION_DOMAIN, &publication_body)?,
        phase: "published_latest_pending".to_owned(),
        approval_sha256: sha256(&approval_bytes),
        draft_receipt_sha256: sha256(&receipt_bytes),
        repository: receipt.body.repository.clone(),
        release_id: receipt.body.release_id.clone(),
        tag: receipt.body.tag.clone(),
        source_commit: receipt.body.tag_commit.clone(),
        assets: receipt.body.assets.clone(),
    };
    validate_publication(&publication, &approval, &receipt)?;
    let publication_bytes = canonical(&publication)?;
    if let Some(existing) = existing_publication {
        if existing != publication_bytes {
            return Err(recovery_required());
        }
    } else {
        state
            .write_record_no_clobber(RemoteRecordKind::PublicationReceipt, &publication_bytes)
            .map_err(local_error)?;
    }
    lock.revalidate().map_err(local_error)?;
    Ok(())
}

/// Retries only fixed credential-free latest verification; it accepts no broker configuration.
pub async fn verify_latest_remote(
    state_path: &Path,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    let state = open_remote_workflow_state(state_path).map_err(local_error)?;
    verify_latest_production_inner(&state).await
}

async fn verify_latest_production_inner(
    state: &RemoteWorkflowState,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    let lock = state.acquire_workflow_lock().map_err(local_error)?;
    settle_pending_operation(state, &lock, None)?;
    lock.revalidate().map_err(local_error)?;
    let verification = prepare_latest(state)?;
    let bytes = CredentialFreeLatest::fetch_catalog(&verification.expected)
        .await
        .map_err(|_| recovery_required())?;
    complete_latest(state, verification, bytes)
}

#[allow(dead_code)]
#[cfg(test)]
pub(crate) fn verify_latest_fixture_with(
    state_path: &Path,
    latest: &mut dyn LatestTransport,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    let state =
        crate::local::open_fixture_remote_workflow_state(state_path).map_err(local_error)?;
    verify_latest_inner(&state, latest)
}

#[cfg(test)]
fn verify_latest_inner(
    state: &RemoteWorkflowState,
    latest: &mut dyn LatestTransport,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    let lock = state.acquire_workflow_lock().map_err(local_error)?;
    settle_pending_operation(state, &lock, None)?;
    lock.revalidate().map_err(local_error)?;
    let verification = prepare_latest(state)?;
    let bytes = latest
        .fetch_catalog(&verification.expected)
        .map_err(|_| recovery_required())?;
    complete_latest(state, verification, bytes)
}

struct LatestVerification {
    publication_bytes: Vec<u8>,
    publication: PublicationReceiptV1,
    expected: RemoteAsset,
}

fn prepare_latest(state: &RemoteWorkflowState) -> Result<LatestVerification, RemoteWorkflowError> {
    state.revalidate().map_err(local_error)?;
    let publication_bytes = state
        .read_record(RemoteRecordKind::PublicationReceipt)
        .map_err(local_error)?
        .ok_or_else(recovery_required)?;
    let publication: PublicationReceiptV1 = parse_canonical(&publication_bytes)?;
    let receipt_bytes = state
        .read_record(RemoteRecordKind::DraftReceipt)
        .map_err(local_error)?
        .ok_or_else(recovery_required)?;
    let receipt: DraftReceiptV1 = parse_canonical(&receipt_bytes)?;
    validate_draft_receipt(&receipt, state)?;
    let approval_bytes = state
        .read_record(RemoteRecordKind::Approval)
        .map_err(local_error)?
        .ok_or_else(recovery_required)?;
    let approval: ReleaseApprovalV1 = parse_canonical(&approval_bytes)?;
    validate_approval(&approval, &receipt, state)?;
    validate_publication(&publication, &approval, &receipt)?;
    if publication.repository != REPOSITORY || publication.source_commit != state.source_commit() {
        return Err(recovery_required());
    }
    let catalog = state.catalog_asset().map_err(local_error)?;
    Ok(LatestVerification {
        publication_bytes,
        publication,
        expected: RemoteAsset {
            name: catalog.name().to_owned(),
            size: catalog.size(),
            sha256: catalog.sha256().to_owned(),
        },
    })
}

fn complete_latest(
    state: &RemoteWorkflowState,
    verification: LatestVerification,
    bytes: Vec<u8>,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    let LatestVerification {
        publication_bytes,
        publication,
        expected,
    } = verification;
    if bytes.len() as u64 != expected.size || sha256(&bytes) != expected.sha256 {
        return Err(recovery_required());
    }
    state.revalidate().map_err(local_error)?;
    let latest_body = (
        sha256(&publication_bytes),
        &publication.repository,
        &publication.release_id,
        &publication.tag,
        &expected,
        "latest_verified",
    );
    let receipt = LatestReceiptV1 {
        schema_version: 1,
        latest_id: domain_digest(LATEST_DOMAIN, &latest_body)?,
        phase: "latest_verified".to_owned(),
        publication_sha256: sha256(&publication_bytes),
        repository: publication.repository,
        release_id: publication.release_id,
        tag: publication.tag,
        catalog: expected,
    };
    state
        .write_record_no_clobber(RemoteRecordKind::LatestReceipt, &canonical(&receipt)?)
        .map_err(local_error)?;
    Ok(RemoteWorkflowOutcome::LatestVerified)
}

/// Publishes only the committed support-only transport prerelease fixture.
pub fn publish_transport_fixture(
    state_path: &Path,
    broker_config: &Path,
    source_commit: &str,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    let state = open_remote_workflow_state(state_path).map_err(local_error)?;
    let mut broker = GitHubBroker::new(broker_config).map_err(|_| recovery_required())?;
    publish_transport_fixture_inner(&state, &mut broker, source_commit)
}

#[allow(dead_code)]
#[cfg(test)]
pub(crate) fn publish_transport_fixture_with(
    state_path: &Path,
    broker: &mut dyn BrokerTransport,
    source_commit: &str,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    let state =
        crate::local::open_fixture_remote_workflow_state(state_path).map_err(local_error)?;
    publish_transport_fixture_inner(&state, broker, source_commit)
}

fn publish_transport_fixture_inner(
    state: &RemoteWorkflowState,
    broker: &mut dyn BrokerTransport,
    source_commit: &str,
) -> Result<RemoteWorkflowOutcome, RemoteWorkflowError> {
    let lock = state.acquire_workflow_lock().map_err(local_error)?;
    settle_pending_operation(state, &lock, None)?;
    lock.revalidate().map_err(local_error)?;
    require_commit(source_commit)?;
    let manifest: TransportManifestV1 = parse_canonical(TRANSPORT_MANIFEST)?;
    validate_transport_manifest(&manifest)?;
    let broker_identity = broker.identity_digests().map_err(|_| recovery_required())?;
    let transport_operation = transport_operation(state, source_commit, broker_identity)?;
    let transport_operation_bytes = canonical(&transport_operation)?;
    state
        .write_record_no_clobber(
            RemoteRecordKind::TransportOperation,
            &transport_operation_bytes,
        )
        .map_err(local_error)?;
    if let Some(receipt_bytes) = state
        .read_record(RemoteRecordKind::TransportReceipt)
        .map_err(local_error)?
    {
        let receipt: TransportReceiptV1 = parse_canonical(&receipt_bytes)?;
        validate_transport_receipt(&receipt, &transport_operation, &manifest)?;
        let tag = broker
            .read_tag(REPOSITORY, &manifest.tag)
            .map_err(|_| uncertain())?;
        require_exact_tag(&tag, &manifest.tag, source_commit)?;
        let release = broker
            .read_draft(REPOSITORY, &manifest.tag)
            .map_err(|_| uncertain())?
            .ok_or_else(uncertain)?;
        require_transport_release(&release, &manifest, source_commit, Some(false))?;
        if release.release_id != receipt.release_id {
            return Err(uncertain());
        }
        let [asset] = release.assets.as_slice() else {
            return Err(recovery_required());
        };
        if asset.asset_id != receipt.asset.asset_id {
            return Err(recovery_required());
        }
        verify_download(broker, REPOSITORY, asset, &manifest.assets[0])?;
        lock.revalidate().map_err(local_error)?;
        return Ok(RemoteWorkflowOutcome::TransportFixturePublished);
    }
    lock.revalidate().map_err(local_error)?;
    let _create_result = broker.create_tag(REPOSITORY, &manifest.tag, source_commit);
    let tag = broker
        .read_tag(REPOSITORY, &manifest.tag)
        .map_err(|_| uncertain())?;
    require_exact_tag(&tag, &manifest.tag, source_commit)?;
    let mut release = broker
        .read_draft(REPOSITORY, &manifest.tag)
        .map_err(|_| uncertain())?;
    if release.is_none() {
        lock.revalidate().map_err(local_error)?;
        let _create_result = broker.create_draft(
            REPOSITORY,
            &manifest.tag,
            source_commit,
            &manifest.title,
            &manifest.notes,
            true,
        );
        release = broker
            .read_draft(REPOSITORY, &manifest.tag)
            .map_err(|_| uncertain())?;
    }
    let mut release = release.ok_or_else(uncertain)?;
    require_transport_release(&release, &manifest, source_commit, None)?;
    let file = readonly_memfd("catalog-transport-fixture", TRANSPORT_ASSET)?;
    if release.assets.is_empty() {
        let before = broker
            .read_draft(REPOSITORY, &manifest.tag)
            .map_err(|_| uncertain())?
            .ok_or_else(uncertain)?;
        require_transport_release(&before, &manifest, source_commit, Some(true))?;
        let source = UploadSource::new(&manifest.assets[0], &file);
        lock.revalidate().map_err(local_error)?;
        let _upload_result = broker.upload_asset(REPOSITORY, &manifest.tag, &source);
        let after = broker
            .read_draft(REPOSITORY, &manifest.tag)
            .map_err(|_| uncertain())?
            .ok_or_else(uncertain)?;
        require_transport_release(&after, &manifest, source_commit, Some(true))?;
        if after.release_id != before.release_id {
            return Err(uncertain());
        }
        require_single_new_asset(&before.assets, &after.assets, &manifest.assets[0])?;
        release = after;
    }
    let [asset] = release.assets.as_slice() else {
        return Err(recovery_required());
    };
    verify_download(broker, REPOSITORY, asset, &manifest.assets[0])?;
    let verified_tag = broker
        .read_tag(REPOSITORY, &manifest.tag)
        .map_err(|_| uncertain())?;
    require_exact_tag(&verified_tag, &manifest.tag, source_commit)?;
    if release.draft {
        lock.revalidate().map_err(local_error)?;
        let _publish_result = broker.publish_draft(REPOSITORY, &release.release_id);
    }
    let published = broker
        .read_draft(REPOSITORY, &manifest.tag)
        .map_err(|_| uncertain())?
        .ok_or_else(uncertain)?;
    require_transport_release(&published, &manifest, source_commit, Some(false))?;
    if published.release_id != release.release_id {
        return Err(uncertain());
    }
    let published_tag = broker
        .read_tag(REPOSITORY, &manifest.tag)
        .map_err(|_| uncertain())?;
    require_exact_tag(&published_tag, &manifest.tag, source_commit)?;
    let [published_asset] = published.assets.as_slice() else {
        return Err(recovery_required());
    };
    verify_download(broker, REPOSITORY, published_asset, &manifest.assets[0])?;
    let receipt_body = (
        &transport_operation.transport_operation_id,
        REPOSITORY,
        source_commit,
        &published.release_id,
        &manifest.tag,
        &published_asset.asset_id,
        &manifest.assets[0],
        "published_verified",
    );
    let receipt = TransportReceiptV1 {
        schema_version: 1,
        transport_receipt_id: domain_digest(TRANSPORT_RECEIPT_DOMAIN, &receipt_body)?,
        transport_operation_id: transport_operation.transport_operation_id.clone(),
        repository: REPOSITORY.to_owned(),
        source_commit: source_commit.to_owned(),
        release_id: published.release_id,
        tag: manifest.tag.clone(),
        asset: RemoteReceiptAssetV1 {
            asset_id: published_asset.asset_id.clone(),
            name: manifest.assets[0].name.clone(),
            size: manifest.assets[0].size,
            sha256: manifest.assets[0].sha256.clone(),
        },
        phase: "published_verified".to_owned(),
    };
    validate_transport_receipt(&receipt, &transport_operation, &manifest)?;
    state
        .write_record_no_clobber(RemoteRecordKind::TransportReceipt, &canonical(&receipt)?)
        .map_err(local_error)?;
    lock.revalidate().map_err(local_error)?;
    Ok(RemoteWorkflowOutcome::TransportFixturePublished)
}

fn transport_operation(
    state: &RemoteWorkflowState,
    source_commit: &str,
    broker_identity: crate::broker_client::BrokerIdentityDigests,
) -> Result<TransportOperationV1, RemoteWorkflowError> {
    require_sha256(&broker_identity.broker_client_config_sha256)?;
    require_sha256(&broker_identity.broker_executable_sha256)?;
    require_sha256(&broker_identity.publisher_broker_config_sha256)?;
    let body = (
        REPOSITORY,
        state.local_operation_id(),
        state.signed_transfer_sha256(),
        source_commit,
        sha256(TRANSPORT_MANIFEST),
        &broker_identity.broker_client_config_sha256,
        &broker_identity.broker_executable_sha256,
        &broker_identity.publisher_broker_config_sha256,
    );
    Ok(TransportOperationV1 {
        schema_version: 1,
        transport_operation_id: domain_digest(TRANSPORT_OPERATION_DOMAIN, &body)?,
        repository: REPOSITORY.to_owned(),
        local_operation_id: state.local_operation_id().to_owned(),
        signed_transfer_sha256: state.signed_transfer_sha256().to_owned(),
        source_commit: source_commit.to_owned(),
        manifest_sha256: sha256(TRANSPORT_MANIFEST),
        broker_client_config_sha256: broker_identity.broker_client_config_sha256,
        broker_executable_sha256: broker_identity.broker_executable_sha256,
        publisher_broker_config_sha256: broker_identity.publisher_broker_config_sha256,
    })
}

fn validate_transport_receipt(
    receipt: &TransportReceiptV1,
    operation: &TransportOperationV1,
    manifest: &TransportManifestV1,
) -> Result<(), RemoteWorkflowError> {
    let body = (
        &receipt.transport_operation_id,
        receipt.repository.as_str(),
        receipt.source_commit.as_str(),
        &receipt.release_id,
        &receipt.tag,
        &receipt.asset.asset_id,
        &manifest.assets[0],
        receipt.phase.as_str(),
    );
    if receipt.schema_version != 1
        || receipt.transport_receipt_id != domain_digest(TRANSPORT_RECEIPT_DOMAIN, &body)?
        || receipt.transport_operation_id != operation.transport_operation_id
        || receipt.repository != REPOSITORY
        || receipt.source_commit != operation.source_commit
        || receipt.tag != manifest.tag
        || receipt.phase != "published_verified"
        || !valid_decimal_id(&receipt.release_id)
        || !valid_decimal_id(&receipt.asset.asset_id)
        || receipt.asset.name != manifest.assets[0].name
        || receipt.asset.size != manifest.assets[0].size
        || receipt.asset.sha256 != manifest.assets[0].sha256
    {
        return Err(recovery_required());
    }
    Ok(())
}

fn operation_body(
    state: &RemoteWorkflowState,
    broker_identity: crate::broker_client::BrokerIdentityDigests,
) -> Result<RemoteOperationBodyV1, RemoteWorkflowError> {
    require_sha256(&broker_identity.broker_client_config_sha256)?;
    require_sha256(&broker_identity.broker_executable_sha256)?;
    require_sha256(&broker_identity.publisher_broker_config_sha256)?;
    let assets = state
        .assets()
        .iter()
        .map(|asset| RemoteAsset {
            name: asset.name().to_owned(),
            size: asset.size(),
            sha256: asset.sha256().to_owned(),
        })
        .collect::<Vec<_>>();
    require_asset_inventory(&assets, true)?;
    let body = RemoteOperationBodyV1 {
        repository: REPOSITORY.to_owned(),
        local_operation_id: state.local_operation_id().to_owned(),
        signed_transfer_sha256: state.signed_transfer_sha256().to_owned(),
        broker_client_config_sha256: broker_identity.broker_client_config_sha256,
        broker_executable_sha256: broker_identity.broker_executable_sha256,
        publisher_broker_config_sha256: broker_identity.publisher_broker_config_sha256,
        source_commit: state.source_commit().to_owned(),
        source_tree_sha256: state.source_tree_sha256().to_owned(),
        sequence: state.sequence(),
        tag: state.tag().to_owned(),
        title: state.title().to_owned(),
        notes: state.notes().to_owned(),
        assets,
    };
    validate_operation_body(&body)?;
    Ok(body)
}

fn settle_pending_operation(
    state: &RemoteWorkflowState,
    lock: &RemoteWorkflowLock<'_>,
    expected_body: Option<&RemoteOperationBodyV1>,
) -> Result<(), RemoteWorkflowError> {
    let (main_bytes, temporary_bytes) = state
        .read_operation_candidates(lock)
        .map_err(|_| uncertain())?;
    let main = main_bytes
        .as_deref()
        .map(parse_canonical::<RemoteOperationV1>)
        .transpose()
        .map_err(|_| uncertain())?;
    let temporary = temporary_bytes
        .as_deref()
        .map(parse_canonical::<RemoteOperationV1>)
        .transpose()
        .map_err(|_| uncertain())?;
    if let Some(operation) = &main {
        validate_operation_binding(operation, state, expected_body).map_err(|_| uncertain())?;
    }
    let Some(temporary) = temporary else {
        if let Some(main_bytes) = main_bytes.as_deref() {
            state
                .settle_visible_operation(lock, main_bytes)
                .map_err(|_| uncertain())?;
        }
        return Ok(());
    };
    validate_operation_binding(&temporary, state, expected_body).map_err(|_| uncertain())?;

    let (promote, permitted) = match &main {
        None => (
            true,
            temporary.phase == RemoteOperationPhaseV1::Prepared
                && temporary.release_id.is_none()
                && temporary.verified_assets == 0
                && expected_body.is_some(),
        ),
        Some(main) if main == &temporary => (false, true),
        Some(main) if schema_authorized_next(main, &temporary) => (true, true),
        Some(main) if schema_authorized_next(&temporary, main) => (false, true),
        Some(_) => (false, false),
    };
    if !permitted {
        return Err(uncertain());
    }
    state
        .settle_operation_candidate(
            lock,
            main_bytes.as_deref(),
            temporary_bytes.as_deref().ok_or_else(uncertain)?,
            promote,
        )
        .map_err(|_| uncertain())
}

fn schema_authorized_next(current: &RemoteOperationV1, next: &RemoteOperationV1) -> bool {
    if current.schema_version != next.schema_version
        || current.remote_operation_id != next.remote_operation_id
        || current.operation != next.operation
        || next.verified_assets < current.verified_assets
        || next.verified_assets > current.verified_assets.saturating_add(1)
        || current.release_id.is_some() && current.release_id != next.release_id
    {
        return false;
    }
    if next.phase == RemoteOperationPhaseV1::Uncertain {
        return next.release_id == current.release_id
            && next.verified_assets == current.verified_assets;
    }
    match current.phase {
        RemoteOperationPhaseV1::Prepared => {
            next.phase == RemoteOperationPhaseV1::TagVerified
                && next.release_id.is_none()
                && next.verified_assets == 0
        }
        RemoteOperationPhaseV1::TagVerified => {
            next.phase == RemoteOperationPhaseV1::DraftBound
                && next.release_id.is_some()
                && next.verified_assets == 0
        }
        RemoteOperationPhaseV1::DraftBound => {
            next.phase == RemoteOperationPhaseV1::Uploading
                && next.release_id == current.release_id
                && next.verified_assets == 1
        }
        RemoteOperationPhaseV1::Uploading => {
            (next.phase == RemoteOperationPhaseV1::Uploading
                && next.release_id == current.release_id
                && next.verified_assets == current.verified_assets + 1)
                || (next.phase == RemoteOperationPhaseV1::AssetsVerified
                    && next.release_id == current.release_id
                    && next.verified_assets == current.operation.assets.len() as u16
                    && current.verified_assets == next.verified_assets)
        }
        RemoteOperationPhaseV1::AssetsVerified => false,
        RemoteOperationPhaseV1::Uncertain => operation_phase_shape(next),
    }
}

fn validate_operation_binding(
    operation: &RemoteOperationV1,
    state: &RemoteWorkflowState,
    expected_body: Option<&RemoteOperationBodyV1>,
) -> Result<(), RemoteWorkflowError> {
    validate_operation(operation)?;
    if expected_body.is_some_and(|expected| &operation.operation != expected)
        || operation.operation.local_operation_id != state.local_operation_id()
        || operation.operation.signed_transfer_sha256 != state.signed_transfer_sha256()
        || operation.operation.source_commit != state.source_commit()
        || operation.operation.source_tree_sha256 != state.source_tree_sha256()
        || operation.operation.sequence != state.sequence()
        || operation.operation.tag != state.tag()
        || operation.operation.title != state.title()
        || operation.operation.notes != state.notes()
        || operation.operation.assets.len() != state.assets().len()
        || operation
            .operation
            .assets
            .iter()
            .zip(state.assets())
            .any(|(operated, local)| {
                operated.name != local.name()
                    || operated.size != local.size()
                    || operated.sha256 != local.sha256()
            })
    {
        return Err(recovery_required());
    }
    Ok(())
}

fn begin_operation(
    state: &RemoteWorkflowState,
    initial: RemoteOperationV1,
) -> Result<OperationHandle, RemoteWorkflowError> {
    validate_operation(&initial)?;
    let initial_bytes = canonical(&initial)?;
    match state
        .read_record(RemoteRecordKind::Operation)
        .map_err(local_error)?
    {
        None => {
            state
                .write_record_no_clobber(RemoteRecordKind::Operation, &initial_bytes)
                .map_err(local_error)?;
            Ok(OperationHandle {
                record: initial,
                bytes: initial_bytes,
            })
        }
        Some(bytes) => {
            let existing: RemoteOperationV1 = parse_canonical(&bytes)?;
            validate_operation(&existing)?;
            if existing.remote_operation_id != initial.remote_operation_id
                || existing.operation != initial.operation
            {
                return Err(recovery_required());
            }
            Ok(OperationHandle {
                record: existing,
                bytes,
            })
        }
    }
}

fn update_operation(
    state: &RemoteWorkflowState,
    handle: &mut OperationHandle,
    release_id: Option<String>,
    verified_assets: u16,
    phase: RemoteOperationPhaseV1,
) -> Result<(), RemoteWorkflowError> {
    let mut next = handle.record.clone();
    next.release_id = release_id.or_else(|| next.release_id.clone());
    next.verified_assets = next.verified_assets.max(verified_assets);
    next.phase = monotonic_phase(&handle.record, phase, next.verified_assets);
    validate_operation(&next)?;
    let bytes = canonical(&next)?;
    if bytes != handle.bytes {
        state
            .replace_operation_record(&handle.bytes, &bytes)
            .map_err(local_error)?;
        handle.record = next;
        handle.bytes = bytes;
    }
    Ok(())
}

fn monotonic_phase(
    current: &RemoteOperationV1,
    requested: RemoteOperationPhaseV1,
    verified_assets: u16,
) -> RemoteOperationPhaseV1 {
    if requested == RemoteOperationPhaseV1::Uncertain {
        return requested;
    }
    if current.phase == RemoteOperationPhaseV1::Uncertain {
        if verified_assets > 0 {
            return if requested == RemoteOperationPhaseV1::AssetsVerified {
                requested
            } else {
                RemoteOperationPhaseV1::Uploading
            };
        }
        if current.release_id.is_some() {
            return if matches!(
                requested,
                RemoteOperationPhaseV1::DraftBound
                    | RemoteOperationPhaseV1::Uploading
                    | RemoteOperationPhaseV1::AssetsVerified
            ) {
                RemoteOperationPhaseV1::DraftBound
            } else {
                RemoteOperationPhaseV1::Uncertain
            };
        }
        return if requested == RemoteOperationPhaseV1::TagVerified {
            requested
        } else {
            RemoteOperationPhaseV1::Uncertain
        };
    }
    let rank = |phase| match phase {
        RemoteOperationPhaseV1::Prepared => 0,
        RemoteOperationPhaseV1::TagVerified => 1,
        RemoteOperationPhaseV1::DraftBound => 2,
        RemoteOperationPhaseV1::Uploading => 3,
        RemoteOperationPhaseV1::AssetsVerified => 4,
        RemoteOperationPhaseV1::Uncertain => 5,
    };
    if rank(requested) < rank(current.phase) {
        current.phase
    } else {
        requested
    }
}

fn mark_operation_uncertain(
    state: &RemoteWorkflowState,
    handle: &mut OperationHandle,
) -> Result<(), RemoteWorkflowError> {
    let release_id = handle.record.release_id.clone();
    let verified_assets = handle.record.verified_assets;
    update_operation(
        state,
        handle,
        release_id,
        verified_assets,
        RemoteOperationPhaseV1::Uncertain,
    )
}

fn mark_uncertain(
    state: &RemoteWorkflowState,
    handle: &mut OperationHandle,
) -> RemoteWorkflowError {
    let _ = mark_operation_uncertain(state, handle);
    uncertain()
}

fn ensure_exact_draft(
    state: &RemoteWorkflowState,
    lock: &RemoteWorkflowLock<'_>,
    broker: &mut dyn BrokerTransport,
    operation: &mut OperationHandle,
    prerelease: bool,
) -> Result<RemoteRelease, RemoteWorkflowError> {
    let mut release = broker
        .read_draft(REPOSITORY, &operation.record.operation.tag)
        .map_err(|_| mark_uncertain(state, operation))?;
    if release.is_none() {
        lock.revalidate().map_err(local_error)?;
        let _create_result = broker.create_draft(
            REPOSITORY,
            &operation.record.operation.tag,
            &operation.record.operation.source_commit,
            &operation.record.operation.title,
            &operation.record.operation.notes,
            prerelease,
        );
        release = broker
            .read_draft(REPOSITORY, &operation.record.operation.tag)
            .map_err(|_| mark_uncertain(state, operation))?;
    }
    let release = release.ok_or_else(|| mark_uncertain(state, operation))?;
    require_release(
        &release,
        &operation.record.operation,
        operation.record.release_id.as_deref(),
        true,
        prerelease,
    )
    .inspect_err(|_| {
        let _ = mark_operation_uncertain(state, operation);
    })?;
    Ok(release)
}

fn verify_and_upload_all(
    state: &RemoteWorkflowState,
    lock: &RemoteWorkflowLock<'_>,
    broker: &mut dyn BrokerTransport,
    operation: &mut OperationHandle,
    release_id: &str,
) -> Result<Vec<RemoteReceiptAssetV1>, RemoteWorkflowError> {
    let mut receipts = Vec::with_capacity(operation.record.operation.assets.len());
    for index in 0..operation.record.operation.assets.len() {
        let expected = operation.record.operation.assets[index].clone();
        let before = broker
            .read_draft(REPOSITORY, &operation.record.operation.tag)
            .map_err(|_| mark_uncertain(state, operation))?
            .ok_or_else(|| mark_uncertain(state, operation))?;
        require_release(
            &before,
            &operation.record.operation,
            Some(release_id),
            true,
            false,
        )?;
        require_asset_prefix(&before.assets, &operation.record.operation.assets)?;
        let remote_asset = if before.assets.len() > index {
            before.assets[index].clone()
        } else {
            if before.assets.len() != index {
                return Err(mark_uncertain(state, operation));
            }
            lock.revalidate().map_err(local_error)?;
            let local = state
                .assets()
                .get(index)
                .filter(|asset| {
                    asset.name() == expected.name
                        && asset.size() == expected.size
                        && asset.sha256() == expected.sha256
                })
                .ok_or_else(recovery_required)?;
            let source = UploadSource::new(&expected, local.file());
            let upload_result =
                broker.upload_asset(REPOSITORY, &operation.record.operation.tag, &source);
            let after = broker
                .read_draft(REPOSITORY, &operation.record.operation.tag)
                .map_err(|_| mark_uncertain(state, operation))?
                .ok_or_else(|| mark_uncertain(state, operation))?;
            require_release(
                &after,
                &operation.record.operation,
                Some(release_id),
                true,
                false,
            )
            .inspect_err(|_| {
                let _ = mark_operation_uncertain(state, operation);
            })?;
            require_single_new_asset(&before.assets, &after.assets, &expected).inspect_err(
                |_| {
                    let _ = mark_operation_uncertain(state, operation);
                },
            )?;
            if upload_result.is_err() && after.assets.len() != index + 1 {
                return Err(mark_uncertain(state, operation));
            }
            after.assets[index].clone()
        };
        verify_download(broker, REPOSITORY, &remote_asset, &expected).inspect_err(|_| {
            let _ = mark_operation_uncertain(state, operation);
        })?;
        receipts.push(RemoteReceiptAssetV1 {
            asset_id: remote_asset.asset_id,
            name: expected.name,
            size: expected.size,
            sha256: expected.sha256,
        });
        update_operation(
            state,
            operation,
            Some(release_id.to_owned()),
            u16::try_from(index + 1).map_err(|_| rejected())?,
            RemoteOperationPhaseV1::Uploading,
        )?;
    }
    Ok(receipts)
}

fn require_exact_tag(
    actual: &RemoteTag,
    expected_tag: &str,
    expected_commit: &str,
) -> Result<(), RemoteWorkflowError> {
    if actual.tag != expected_tag
        || actual.commit_sha != expected_commit
        || actual.object_type != crate::broker::BrokerTagObjectTypeV1::Commit
    {
        return Err(recovery_required());
    }
    Ok(())
}

fn require_release(
    release: &RemoteRelease,
    operation: &RemoteOperationBodyV1,
    release_id: Option<&str>,
    draft: bool,
    prerelease: bool,
) -> Result<(), RemoteWorkflowError> {
    if release_id.is_some_and(|expected| release.release_id != expected)
        || release.tag != operation.tag
        || release.target_commitish != operation.source_commit
        || release.title != operation.title
        || release.notes != operation.notes
        || release.draft != draft
        || release.prerelease != prerelease
    {
        return Err(recovery_required());
    }
    require_asset_prefix(&release.assets, &operation.assets)
}

fn require_receipt_release(
    release: &RemoteRelease,
    receipt: &DraftReceiptV1,
    expected_draft: Option<bool>,
) -> Result<(), RemoteWorkflowError> {
    if release.release_id != receipt.body.release_id
        || release.tag != receipt.body.tag
        || release.target_commitish != receipt.body.target_commitish
        || release.title != receipt.body.title
        || release.notes != receipt.body.notes
        || expected_draft.is_some_and(|draft| release.draft != draft)
        || release.prerelease
    {
        return Err(recovery_required());
    }
    require_complete_assets(&release.assets, &receipt.body.assets)
}

fn require_asset_prefix(
    remote: &[RemoteReleaseAsset],
    expected: &[RemoteAsset],
) -> Result<(), RemoteWorkflowError> {
    if remote.len() > expected.len() {
        return Err(recovery_required());
    }
    let mut ids = BTreeSet::new();
    for (actual, expected) in remote.iter().zip(expected) {
        if actual.name != expected.name
            || actual.size != expected.size
            || !ids.insert(actual.asset_id.as_str())
        {
            return Err(recovery_required());
        }
    }
    Ok(())
}

fn require_single_new_asset(
    before: &[RemoteReleaseAsset],
    after: &[RemoteReleaseAsset],
    expected: &RemoteAsset,
) -> Result<(), RemoteWorkflowError> {
    if after.len() != before.len() + 1
        || after[..before.len()] != *before
        || after.last().is_none_or(|asset| {
            asset.name != expected.name
                || asset.size != expected.size
                || before.iter().any(|prior| prior.asset_id == asset.asset_id)
        })
    {
        return Err(uncertain());
    }
    Ok(())
}

fn require_complete_assets(
    remote: &[RemoteReleaseAsset],
    expected: &[RemoteReceiptAssetV1],
) -> Result<(), RemoteWorkflowError> {
    if remote.len() != expected.len()
        || remote.iter().zip(expected).any(|(actual, expected)| {
            actual.asset_id != expected.asset_id
                || actual.name != expected.name
                || actual.size != expected.size
        })
    {
        return Err(recovery_required());
    }
    Ok(())
}

fn redownload_receipt_assets(
    broker: &mut dyn BrokerTransport,
    release: &RemoteRelease,
    expected: &[RemoteReceiptAssetV1],
) -> Result<(), RemoteWorkflowError> {
    require_complete_assets(&release.assets, expected)?;
    for (remote, expected) in release.assets.iter().zip(expected) {
        verify_download(
            broker,
            REPOSITORY,
            remote,
            &RemoteAsset {
                name: expected.name.clone(),
                size: expected.size,
                sha256: expected.sha256.clone(),
            },
        )?;
    }
    Ok(())
}

fn verify_download(
    broker: &mut dyn BrokerTransport,
    repository: &str,
    remote: &RemoteReleaseAsset,
    expected: &RemoteAsset,
) -> Result<(), RemoteWorkflowError> {
    let DownloadedAsset {
        asset_id,
        name,
        bytes,
    } = broker
        .download_asset(repository, remote)
        .map_err(|_| uncertain())?;
    if asset_id != remote.asset_id
        || name != remote.name
        || remote.name != expected.name
        || remote.size != expected.size
        || bytes.len() as u64 != expected.size
        || sha256(&bytes) != expected.sha256
    {
        return Err(recovery_required());
    }
    Ok(())
}

fn validate_operation(operation: &RemoteOperationV1) -> Result<(), RemoteWorkflowError> {
    validate_operation_body(&operation.operation)?;
    if operation.schema_version != 1
        || operation.remote_operation_id != domain_digest(OPERATION_DOMAIN, &operation.operation)?
        || operation.verified_assets as usize > operation.operation.assets.len()
        || operation
            .release_id
            .as_ref()
            .is_some_and(|release_id| !valid_decimal_id(release_id))
        || !operation_phase_shape(operation)
    {
        return Err(recovery_required());
    }
    Ok(())
}

fn operation_phase_shape(operation: &RemoteOperationV1) -> bool {
    match operation.phase {
        RemoteOperationPhaseV1::Prepared | RemoteOperationPhaseV1::TagVerified => {
            operation.release_id.is_none() && operation.verified_assets == 0
        }
        RemoteOperationPhaseV1::DraftBound => {
            operation.release_id.is_some() && operation.verified_assets == 0
        }
        RemoteOperationPhaseV1::Uploading => {
            operation.release_id.is_some()
                && operation.verified_assets > 0
                && (operation.verified_assets as usize) <= operation.operation.assets.len()
        }
        RemoteOperationPhaseV1::AssetsVerified => {
            operation.release_id.is_some()
                && operation.verified_assets as usize == operation.operation.assets.len()
        }
        RemoteOperationPhaseV1::Uncertain => {
            operation.release_id.is_some() || operation.verified_assets == 0
        }
    }
}

fn validate_operation_body(body: &RemoteOperationBodyV1) -> Result<(), RemoteWorkflowError> {
    if body.repository != REPOSITORY
        || !valid_sha256(&body.local_operation_id)
        || !valid_sha256(&body.signed_transfer_sha256)
        || !valid_sha256(&body.broker_client_config_sha256)
        || !valid_sha256(&body.broker_executable_sha256)
        || !valid_sha256(&body.publisher_broker_config_sha256)
        || !valid_commit(&body.source_commit)
        || !valid_sha256(&body.source_tree_sha256)
        || body.sequence == 0
        || body.tag != format!("catalog-v1-sequence-{}", body.sequence)
        || body.title.is_empty()
        || body.title.len() > 256
        || body.notes.len() > 16 * 1024
    {
        return Err(rejected());
    }
    require_asset_inventory(&body.assets, true)
}

fn validate_draft_receipt(
    receipt: &DraftReceiptV1,
    state: &RemoteWorkflowState,
) -> Result<(), RemoteWorkflowError> {
    let operation_bytes = state
        .read_record(RemoteRecordKind::Operation)
        .map_err(local_error)?
        .ok_or_else(recovery_required)?;
    let operation: RemoteOperationV1 = parse_canonical(&operation_bytes)?;
    validate_operation(&operation)?;
    if receipt.schema_version != 1
        || receipt.receipt_id != domain_digest(DRAFT_RECEIPT_DOMAIN, &receipt.body)?
        || receipt.body.repository != REPOSITORY
        || receipt.body.release_id.is_empty()
        || receipt.body.tag != state.tag()
        || receipt.body.tag_commit != state.source_commit()
        || receipt.body.target_commitish != state.source_commit()
        || receipt.body.source_tree_sha256 != state.source_tree_sha256()
        || receipt.body.title != state.title()
        || receipt.body.notes != state.notes()
        || !receipt.body.draft
        || receipt.body.prerelease
        || receipt.body.local_operation_id != state.local_operation_id()
        || receipt.body.signed_transfer_sha256 != state.signed_transfer_sha256()
        || receipt.body.phase != "draft_verified"
        || receipt.body.remote_operation_id != operation.remote_operation_id
        || receipt.body.broker_client_config_sha256
            != operation.operation.broker_client_config_sha256
        || receipt.body.broker_executable_sha256 != operation.operation.broker_executable_sha256
        || receipt.body.publisher_broker_config_sha256
            != operation.operation.publisher_broker_config_sha256
        || operation.release_id.as_deref() != Some(receipt.body.release_id.as_str())
        || operation.phase != RemoteOperationPhaseV1::AssetsVerified
        || operation.verified_assets as usize != operation.operation.assets.len()
    {
        return Err(recovery_required());
    }
    let expected = state.assets();
    if receipt.body.assets.len() != expected.len()
        || receipt.body.assets.len() != operation.operation.assets.len()
        || receipt
            .body
            .assets
            .iter()
            .zip(expected.iter().zip(&operation.operation.assets))
            .any(|(receipt, (local, operated))| {
                receipt.name != local.name()
                    || receipt.size != local.size()
                    || receipt.sha256 != local.sha256()
                    || receipt.name != operated.name
                    || receipt.size != operated.size
                    || receipt.sha256 != operated.sha256
                    || !valid_decimal_id(&receipt.asset_id)
            })
    {
        return Err(recovery_required());
    }
    Ok(())
}

fn validate_approval(
    approval: &ReleaseApprovalV1,
    receipt: &DraftReceiptV1,
    state: &RemoteWorkflowState,
) -> Result<(), RemoteWorkflowError> {
    let approval_body = (
        approval.draft_receipt_sha256.as_str(),
        &approval.draft_receipt_id,
        &approval.repository,
        &approval.release_id,
        &approval.tag,
        &approval.source_commit,
        &approval.local_operation_id,
        &approval.remote_operation_id,
        &approval.assets,
        approval.status.as_str(),
    );
    if approval.schema_version != 1
        || approval.approval_id != domain_digest(APPROVAL_DOMAIN, &approval_body)?
        || approval.status != "approved"
        || approval.draft_receipt_sha256 != sha256(&canonical(receipt)?)
        || approval.draft_receipt_id != receipt.receipt_id
        || approval.repository != receipt.body.repository
        || approval.release_id != receipt.body.release_id
        || approval.tag != receipt.body.tag
        || approval.source_commit != receipt.body.tag_commit
        || approval.local_operation_id != state.local_operation_id()
        || approval.remote_operation_id != receipt.body.remote_operation_id
        || approval.assets != receipt.body.assets
    {
        return Err(recovery_required());
    }
    Ok(())
}

fn validate_publication(
    publication: &PublicationReceiptV1,
    approval: &ReleaseApprovalV1,
    receipt: &DraftReceiptV1,
) -> Result<(), RemoteWorkflowError> {
    let body = (
        publication.approval_sha256.as_str(),
        publication.draft_receipt_sha256.as_str(),
        &publication.repository,
        &publication.release_id,
        &publication.tag,
        &publication.source_commit,
        &publication.assets,
        publication.phase.as_str(),
    );
    if publication.schema_version != 1
        || publication.publication_id != domain_digest(PUBLICATION_DOMAIN, &body)?
        || publication.phase != "published_latest_pending"
        || publication.approval_sha256 != sha256(&canonical(approval)?)
        || publication.draft_receipt_sha256 != sha256(&canonical(receipt)?)
        || publication.repository != approval.repository
        || publication.release_id != approval.release_id
        || publication.tag != approval.tag
        || publication.source_commit != approval.source_commit
        || publication.assets != approval.assets
    {
        return Err(recovery_required());
    }
    Ok(())
}

fn require_asset_inventory(
    assets: &[RemoteAsset],
    catalog_last: bool,
) -> Result<(), RemoteWorkflowError> {
    if assets.is_empty()
        || assets.len() > 128
        || assets.iter().any(|asset| {
            asset.name.is_empty()
                || asset.name.len() > 255
                || asset.size == 0
                || !valid_sha256(&asset.sha256)
        })
        || assets
            .windows(2)
            .take(assets.len().saturating_sub(2))
            .any(|pair| pair[0].name >= pair[1].name)
        || catalog_last
            && assets
                .last()
                .is_none_or(|asset| asset.name != "catalog-v1.json")
        || assets[..assets.len().saturating_sub(1)]
            .iter()
            .any(|asset| asset.name == "catalog-v1.json")
    {
        return Err(rejected());
    }
    Ok(())
}

fn validate_transport_manifest(manifest: &TransportManifestV1) -> Result<(), RemoteWorkflowError> {
    if manifest.schema_version != 1
        || manifest.repository != REPOSITORY
        || manifest.tag != "transport-v1"
        || manifest.title != "Fluxsemble runtime catalog transport fixture v1"
        || manifest.notes != "Permanent credential-free GitHub release asset transport fixture."
        || !manifest.draft
        || !manifest.prerelease
        || manifest.assets
            != [RemoteAsset {
                name: "github-release-asset-v1.txt".to_owned(),
                size: TRANSPORT_ASSET.len() as u64,
                sha256: sha256(TRANSPORT_ASSET),
            }]
        || manifest
            .assets
            .iter()
            .any(|asset| asset.name == "catalog-v1.json")
    {
        return Err(rejected());
    }
    Ok(())
}

fn require_transport_release(
    release: &RemoteRelease,
    manifest: &TransportManifestV1,
    source_commit: &str,
    draft: Option<bool>,
) -> Result<(), RemoteWorkflowError> {
    if release.tag != manifest.tag
        || release.target_commitish != source_commit
        || release.title != manifest.title
        || release.notes != manifest.notes
        || draft.is_some_and(|expected| release.draft != expected)
        || !release.prerelease
    {
        return Err(recovery_required());
    }
    require_asset_prefix(&release.assets, &manifest.assets)
}

fn require_approval_path(state: &Path, approval: &Path) -> Result<(), RemoteWorkflowError> {
    if approval != state.join("latest/release-approval-v1.json") {
        return Err(rejected());
    }
    Ok(())
}

fn readonly_memfd(label: &str, bytes: &[u8]) -> Result<fs::File, RemoteWorkflowError> {
    let label = std::ffi::CString::new(label).map_err(|_| rejected())?;
    // SAFETY: fixed label and CLOEXEC memfd flags are valid.
    let descriptor =
        unsafe { libc::syscall(libc::SYS_memfd_create, label.as_ptr(), libc::MFD_CLOEXEC) } as i32;
    if descriptor < 0 {
        return Err(rejected());
    }
    // SAFETY: memfd_create returned one owned descriptor.
    let mut file = unsafe { fs::File::from_raw_fd(descriptor) };
    file.write_all(bytes).map_err(|_| rejected())?;
    file.flush().map_err(|_| rejected())?;
    file.set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(|_| rejected())?;
    file.sync_all().map_err(|_| rejected())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| rejected())?;
    Ok(file)
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, RemoteWorkflowError> {
    let bytes = serde_jcs::to_vec(value).map_err(|_| rejected())?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(rejected());
    }
    Ok(bytes)
}

fn parse_canonical<T>(bytes: &[u8]) -> Result<T, RemoteWorkflowError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(recovery_required());
    }
    let value = serde_json::from_slice(bytes).map_err(|_| recovery_required())?;
    if serde_jcs::to_vec(&value).map_err(|_| recovery_required())? != bytes {
        return Err(recovery_required());
    }
    Ok(value)
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, RemoteWorkflowError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical(value)?);
    Ok(format!("{:x}", hasher.finalize()))
}

fn require_sha256(value: &str) -> Result<(), RemoteWorkflowError> {
    if valid_sha256(value) {
        Ok(())
    } else {
        Err(rejected())
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn require_commit(value: &str) -> Result<(), RemoteWorkflowError> {
    if valid_commit(value) {
        Ok(())
    } else {
        Err(rejected())
    }
}

fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_decimal_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 19
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|value| value > 0)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn local_error(error: PublishError) -> RemoteWorkflowError {
    failed(error.outcome())
}

impl From<RemoteBoundaryError> for RemoteWorkflowError {
    fn from(_: RemoteBoundaryError) -> Self {
        uncertain()
    }
}
