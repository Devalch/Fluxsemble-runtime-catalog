//! Explicit, digest-approved local broker repair transition. Never mutates GitHub.
use super::*;
use crate::broker_client::BrokerIdentityDigests;

const RECOVERY_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-broker-recovery:v1\0";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedAssets {
    release_id: String,
    assets: Vec<RemoteReceiptAssetV1>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryBody {
    local_reference_sha256: String,
    prior_operation_sha256: String,
    prior_operation: RemoteOperationV1,
    replacement_operation_sha256: String,
    replacement_operation: RemoteOperationV1,
    retained: RetainedAssets,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryPlan {
    schema_version: u16,
    recovery_id: String,
    body: RecoveryBody,
}

/// Offline planning: opens only the public local state/config/ELF and reviewed observation.
/// No authenticated broker process is launched and no operation/proof is written.
pub fn plan_broker_recovery(
    state_path: &Path,
    config: &Path,
    retained_path: &Path,
) -> Result<Vec<u8>, RemoteWorkflowError> {
    let state = open_remote_workflow_state(state_path).map_err(local_error)?;
    let mut broker = GitHubBroker::new(config).map_err(|_| recovery_required())?;
    let identity = broker.identity_digests()?;
    let retained = crate::local::read_recovery_input(retained_path).map_err(local_error)?;
    plan(&state, identity, &retained)
}

/// Owner-approved local authority transition. Its only remote operations are exact reads/downloads.
pub fn recover_broker(
    state_path: &Path,
    config: &Path,
    plan_path: &Path,
    approved_sha256: &str,
) -> Result<(), RemoteWorkflowError> {
    let bytes = crate::local::read_recovery_input(plan_path).map_err(local_error)?;
    require_sha256(approved_sha256)?;
    if sha256(&bytes) != approved_sha256 {
        return Err(rejected());
    }
    let state = open_remote_workflow_state(state_path).map_err(local_error)?;
    let mut broker = GitHubBroker::new(config).map_err(|_| recovery_required())?;
    recover(&state, &bytes, approved_sha256, &mut broker)
}

fn plan(
    state: &RemoteWorkflowState,
    identity: BrokerIdentityDigests,
    retained: &[u8],
) -> Result<Vec<u8>, RemoteWorkflowError> {
    let lock = state.acquire_workflow_lock().map_err(local_error)?;
    require_pre_receipt(state, &lock)?;
    if state
        .read_record_locked(&lock, RemoteRecordKind::BrokerRecovery)
        .map_err(local_error)?
        .is_some()
    {
        return Err(recovery_required());
    }
    let (main, temporary) = state
        .read_operation_candidates(&lock)
        .map_err(local_error)?;
    if temporary.is_some() {
        return Err(recovery_required());
    }
    let bytes = main.ok_or_else(recovery_required)?;
    let prior: RemoteOperationV1 = parse_canonical(&bytes)?;
    validate_operation_binding(&prior, state, None)?;
    let replacement_body = operation_body(state, identity)?;
    let mut replacement = prior.clone();
    replacement.remote_operation_id = domain_digest(OPERATION_DOMAIN, &replacement_body)?;
    replacement.operation = replacement_body;
    replacement.broker_recovery_required = true;
    let body = RecoveryBody {
        local_reference_sha256: state.reference_sha256(),
        prior_operation_sha256: sha256(&bytes),
        prior_operation: prior,
        replacement_operation_sha256: sha256(&canonical(&replacement)?),
        replacement_operation: replacement,
        retained: parse_canonical(retained)?,
    };
    let plan = RecoveryPlan {
        schema_version: 1,
        recovery_id: domain_digest(RECOVERY_DOMAIN, &body)?,
        body,
    };
    validate_plan(&plan, state)?;
    canonical(&plan)
}

fn validate_plan(
    plan: &RecoveryPlan,
    state: &RemoteWorkflowState,
) -> Result<(), RemoteWorkflowError> {
    let body = &plan.body;
    let prior = &body.prior_operation;
    let next = &body.replacement_operation;
    validate_operation_binding(prior, state, None)?;
    validate_operation_binding(next, state, None)?;
    if prior.broker_recovery_required
        || !prior.observed_remote_assets.is_empty()
        || !next.broker_recovery_required
        || plan.schema_version != 1
        || plan.recovery_id != domain_digest(RECOVERY_DOMAIN, body)?
        || body.local_reference_sha256 != state.reference_sha256()
        || body.prior_operation_sha256 != sha256(&canonical(prior)?)
        || body.replacement_operation_sha256 != sha256(&canonical(next)?)
        || prior.phase != RemoteOperationPhaseV1::Uncertain
        || prior.release_id.as_deref() != Some(body.retained.release_id.as_str())
        || !valid_decimal_id(&body.retained.release_id)
        || next.phase != prior.phase
        || next.verified_assets != prior.verified_assets
        || next.release_id != prior.release_id
        || body.retained.assets.is_empty()
        || body.retained.assets.len() < prior.verified_assets as usize
        || body.retained.assets.len() >= prior.operation.assets.len()
        || next.operation.publisher_broker_config_sha256
            != prior.operation.publisher_broker_config_sha256
        || next.operation.broker_client_config_sha256 == prior.operation.broker_client_config_sha256
        || next.operation.broker_executable_sha256 == prior.operation.broker_executable_sha256
    {
        return Err(recovery_required());
    }
    // Only the two broker pins and their derived operation ID may change. Recorded progress is kept.
    let mut permitted = prior.clone();
    permitted.broker_recovery_required = true;
    permitted.operation.broker_client_config_sha256 =
        next.operation.broker_client_config_sha256.clone();
    permitted.operation.broker_executable_sha256 = next.operation.broker_executable_sha256.clone();
    permitted.remote_operation_id = domain_digest(OPERATION_DOMAIN, &permitted.operation)?;
    if &permitted != next {
        return Err(recovery_required());
    }
    let mut ids = BTreeSet::new();
    for (asset, expected) in body.retained.assets.iter().zip(&next.operation.assets) {
        if !valid_decimal_id(&asset.asset_id)
            || !ids.insert(&asset.asset_id)
            || asset.name != expected.name
            || asset.size != expected.size
            || asset.sha256 != expected.sha256
        {
            return Err(recovery_required());
        }
    }
    Ok(())
}

fn require_pre_receipt(
    state: &RemoteWorkflowState,
    lock: &RemoteWorkflowLock<'_>,
) -> Result<(), RemoteWorkflowError> {
    for kind in [
        RemoteRecordKind::DraftReceipt,
        RemoteRecordKind::Approval,
        RemoteRecordKind::PublicationReceipt,
        RemoteRecordKind::LatestReceipt,
    ] {
        if state
            .read_record_locked(lock, kind)
            .map_err(local_error)?
            .is_some()
        {
            return Err(recovery_required());
        }
    }
    Ok(())
}

fn recover(
    state: &RemoteWorkflowState,
    bytes: &[u8],
    approved: &str,
    broker: &mut dyn BrokerTransport,
) -> Result<(), RemoteWorkflowError> {
    require_sha256(approved)?;
    if sha256(bytes) != approved {
        return Err(rejected());
    }
    let plan: RecoveryPlan = parse_canonical(bytes)?;
    validate_plan(&plan, state)?;
    let lock = state.acquire_workflow_lock().map_err(local_error)?;
    require_pre_receipt(state, &lock)?;
    let old = canonical(&plan.body.prior_operation)?;
    let next = canonical(&plan.body.replacement_operation)?;
    let certificate = state
        .read_record_locked(&lock, RemoteRecordKind::BrokerRecovery)
        .map_err(local_error)?;
    if certificate.as_deref().is_some_and(|v| v != bytes) {
        return Err(recovery_required());
    }
    let (main, temporary) = state
        .read_operation_candidates(&lock)
        .map_err(local_error)?;
    let old_main = main.as_deref() == Some(old.as_slice());
    let new_main = main.as_deref() == Some(next.as_slice());
    if (!old_main && !new_main)
        || (new_main && certificate.is_none())
        || temporary.as_deref().is_some_and(|v| v != next.as_slice())
        || (temporary.is_some() && (certificate.is_none() || !old_main))
    {
        return Err(recovery_required());
    }
    let expected = &plan.body.replacement_operation.operation;
    let identity = broker.identity_digests()?;
    if identity.broker_client_config_sha256 != expected.broker_client_config_sha256
        || identity.broker_executable_sha256 != expected.broker_executable_sha256
        || identity.publisher_broker_config_sha256 != expected.publisher_broker_config_sha256
    {
        return Err(recovery_required());
    }
    // Exact observations before ANY local transition; no CreateTag/CreateDraft/Upload/Publish exists here.
    check_remote_baseline(broker, &plan)?;
    lock.revalidate().map_err(local_error)?;
    if state
        .read_operation_candidates(&lock)
        .map_err(local_error)?
        != (main.clone(), temporary.clone())
    {
        return Err(uncertain());
    }
    if certificate.is_none() {
        state
            .write_record_no_clobber(RemoteRecordKind::BrokerRecovery, bytes)
            .map_err(local_error)?;
    }
    if let Some(temp) = temporary.as_deref() {
        state
            .settle_operation_candidate(&lock, main.as_deref(), temp, true)
            .map_err(local_error)?;
    } else if old_main {
        state
            .replace_operation_record(&old, &next)
            .map_err(local_error)?;
    } else {
        state
            .settle_visible_operation(&lock, &next)
            .map_err(local_error)?;
    }
    validate_current(state, &lock, &plan.body.replacement_operation)?;
    Ok(())
}

fn check_remote_baseline(
    broker: &mut dyn BrokerTransport,
    plan: &RecoveryPlan,
) -> Result<(), RemoteWorkflowError> {
    let op = &plan.body.replacement_operation.operation;
    let tag = broker.read_tag(REPOSITORY, &op.tag)?;
    require_exact_tag(&tag, &op.tag, &op.source_commit)?;
    let release = broker
        .read_draft(REPOSITORY, &op.tag)?
        .ok_or_else(recovery_required)?;
    require_release(
        &release,
        op,
        Some(&plan.body.retained.release_id),
        true,
        false,
    )?;
    require_complete_assets(&release.assets, &plan.body.retained.assets)?;
    redownload_receipt_assets(broker, &release, &plan.body.retained.assets)?;
    let final_tag = broker.read_tag(REPOSITORY, &op.tag)?;
    require_exact_tag(&final_tag, &op.tag, &op.source_commit)?;
    let final_release = broker
        .read_draft(REPOSITORY, &op.tag)?
        .ok_or_else(recovery_required)?;
    require_release(
        &final_release,
        op,
        Some(&plan.body.retained.release_id),
        true,
        false,
    )?;
    require_complete_assets(&final_release.assets, &plan.body.retained.assets)
}

/// Every normal reader must reject pending/malformed proof or a non-successor main operation.
pub(super) fn validate_current(
    state: &RemoteWorkflowState,
    lock: &RemoteWorkflowLock<'_>,
    current: &RemoteOperationV1,
) -> Result<Option<RecoveryPlan>, RemoteWorkflowError> {
    let Some(bytes) = state
        .read_record_locked(lock, RemoteRecordKind::BrokerRecovery)
        .map_err(local_error)?
    else {
        if current.broker_recovery_required || !current.observed_remote_assets.is_empty() {
            return Err(recovery_required());
        }
        return Ok(None);
    };
    let plan: RecoveryPlan = parse_canonical(&bytes)?;
    validate_plan(&plan, state)?;
    let initial = &plan.body.replacement_operation;
    if !current.broker_recovery_required
        || current.schema_version != initial.schema_version
        || current.operation != initial.operation
        || current.remote_operation_id != initial.remote_operation_id
        || current.release_id != initial.release_id
        || current.verified_assets < initial.verified_assets
        || !matches!(
            current.phase,
            RemoteOperationPhaseV1::Uncertain
                | RemoteOperationPhaseV1::Uploading
                | RemoteOperationPhaseV1::AssetsVerified
        )
    {
        return Err(recovery_required());
    }
    if !current.observed_remote_assets.is_empty()
        && (current.observed_remote_assets.len() <= plan.body.retained.assets.len()
            || !current
                .observed_remote_assets
                .starts_with(&plan.body.retained.assets))
    {
        return Err(recovery_required());
    }
    Ok(Some(plan))
}

pub(super) fn require_preserved(
    state: &RemoteWorkflowState,
    lock: &RemoteWorkflowLock<'_>,
    plan: &RecoveryPlan,
    release: &RemoteRelease,
) -> Result<(), RemoteWorkflowError> {
    let bytes = state
        .read_record_locked(lock, RemoteRecordKind::BrokerRecovery)
        .map_err(local_error)?
        .ok_or_else(recovery_required)?;
    if bytes != canonical(plan)? || release.release_id != plan.body.retained.release_id {
        return Err(recovery_required());
    }
    let main = state
        .read_record_locked(lock, RemoteRecordKind::Operation)
        .map_err(local_error)?
        .ok_or_else(recovery_required)?;
    let operation: RemoteOperationV1 = parse_canonical(&main)?;
    validate_operation(&operation)?;
    validate_current(state, lock, &operation)?;
    // Preserve original assets and subsequently observed suffix IDs before verification completion.
    for expected in plan
        .body
        .retained
        .assets
        .iter()
        .chain(&operation.observed_remote_assets)
    {
        let actual = matching_remote_asset(
            &release.assets,
            &RemoteAsset {
                name: expected.name.clone(),
                size: expected.size,
                sha256: expected.sha256.clone(),
            },
        )?;
        if actual.asset_id != expected.asset_id {
            return Err(recovery_required());
        }
    }
    Ok(())
}

pub(super) fn observe_suffix(
    state: &RemoteWorkflowState,
    plan: &RecoveryPlan,
    operation: &mut OperationHandle,
    observed: &[RemoteReceiptAssetV1],
) -> Result<(), RemoteWorkflowError> {
    if observed.len() <= plan.body.retained.assets.len() {
        return Ok(());
    }
    if observed.len() <= operation.record.observed_remote_assets.len() {
        if !operation
            .record
            .observed_remote_assets
            .starts_with(observed)
        {
            return Err(recovery_required());
        }
        return Ok(());
    }
    if !observed.starts_with(&plan.body.retained.assets)
        || !observed.starts_with(&operation.record.observed_remote_assets)
    {
        return Err(recovery_required());
    }
    let mut next = operation.record.clone();
    next.observed_remote_assets = observed.to_vec();
    validate_operation(&next)?;
    if !schema_authorized_next(&operation.record, &next) {
        return Err(recovery_required());
    }
    let bytes = canonical(&next)?;
    state
        .replace_operation_record(&operation.bytes, &bytes)
        .map_err(local_error)?;
    operation.record = next;
    operation.bytes = bytes;
    Ok(())
}

pub(super) fn require_receipt_ids(
    state: &RemoteWorkflowState,
    current: &RemoteOperationV1,
    assets: &[RemoteReceiptAssetV1],
) -> Result<(), RemoteWorkflowError> {
    let proof = state
        .read_record(RemoteRecordKind::BrokerRecovery)
        .map_err(local_error)?;
    match proof {
        None if !current.broker_recovery_required && current.observed_remote_assets.is_empty() => {
            Ok(())
        }
        Some(bytes) => {
            let plan: RecoveryPlan = parse_canonical(&bytes)?;
            validate_plan(&plan, state)?;
            if !current.broker_recovery_required
                || current.operation != plan.body.replacement_operation.operation
                || current.remote_operation_id
                    != plan.body.replacement_operation.remote_operation_id
                || current.release_id != plan.body.replacement_operation.release_id
                || current.observed_remote_assets != assets
                || assets.len() != current.operation.assets.len()
                || !assets.starts_with(&plan.body.retained.assets)
            {
                return Err(recovery_required());
            }
            Ok(())
        }
        _ => Err(recovery_required()),
    }
}

#[allow(dead_code)]
#[cfg(test)]
pub(crate) fn plan_broker_recovery_fixture(
    state: &Path,
    identity: BrokerIdentityDigests,
    retained: &[u8],
) -> Result<Vec<u8>, RemoteWorkflowError> {
    plan(
        &crate::local::open_fixture_remote_workflow_state(state).map_err(local_error)?,
        identity,
        retained,
    )
}
#[allow(dead_code)]
#[cfg(test)]
pub(crate) fn recover_broker_fixture(
    state: &Path,
    bytes: &[u8],
    digest: &str,
    broker: &mut dyn BrokerTransport,
) -> Result<(), RemoteWorkflowError> {
    recover(
        &crate::local::open_fixture_remote_workflow_state(state).map_err(local_error)?,
        bytes,
        digest,
        broker,
    )
}
