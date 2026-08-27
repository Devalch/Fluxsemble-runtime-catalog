#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    os::{
        fd::AsRawFd,
        unix::{fs::MetadataExt, process::ExitStatusExt},
    },
    path::Path,
    process::Command,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

#[allow(dead_code)]
#[path = "../src/local.rs"]
mod local;
mod support;

use local::{FailureOutcome, FaultPoint, PublishOutcome, StateCheckpoint};
use support::{TempTree, fixture_transfer, private_directory, set_mode};

fn stage_baseline(temp: &TempTree) -> (std::path::PathBuf, Vec<u8>) {
    let transfer = temp.path("baseline-transfer");
    let state = temp.path("state");
    fixture_transfer(&transfer, 42, b"baseline");
    let verified = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
    local::stage_local(&verified, &state).unwrap();
    let latest = fs::read(state.join("latest/catalog-v1.ref")).unwrap();
    (state, latest)
}

fn write_read_only(path: &Path, bytes: &[u8]) {
    set_mode(path, 0o600);
    fs::write(path, bytes).unwrap();
    set_mode(path, 0o400);
}

fn operation_id(operation: &serde_json::Value) -> String {
    const DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-local-operation:v1\0";
    let canonical = serde_jcs::to_vec(operation).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(canonical);
    format!("{:x}", hasher.finalize())
}

fn recompute_operation_id(value: &mut serde_json::Value) {
    let operation = value["operation"].clone();
    value["intended_reference"]["operation"] = operation.clone();
    let operation_id = operation_id(&operation);
    value["operation_id"] = serde_json::json!(operation_id);
    value["intended_reference"]["operation_id"] = value["operation_id"].clone();
}

fn recompute_reference_operation_id(value: &mut serde_json::Value) {
    value["operation_id"] = serde_json::json!(operation_id(&value["operation"]));
}

fn replace_bound_object_digest(
    operation: &mut serde_json::Value,
    binding: &str,
    name: &str,
    digest: &str,
) {
    operation[binding]["sha256"] = serde_json::json!(digest);
    operation[binding]["object"] = serde_json::json!(format!("objects/{digest}"));
    let object = operation["objects"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|object| object["name"] == name)
        .unwrap();
    object["sha256"] = serde_json::json!(digest);
    object["object"] = serde_json::json!(format!("objects/{digest}"));
}

#[test]
#[ignore = "launched explicitly as the SIGKILL child"]
fn sigkill_latest_temp_child() {
    let Ok(transfer) = std::env::var("CATALOG_PUBLISH_SIGKILL_TRANSFER") else {
        return;
    };
    let state = std::env::var("CATALOG_PUBLISH_SIGKILL_STATE").unwrap();
    let ready = std::env::var("CATALOG_PUBLISH_SIGKILL_READY").unwrap();
    let verified = local::verify_transferred_fixture_signed_bundle(Path::new(&transfer)).unwrap();
    let result =
        local::stage_local_with_sigkill_checkpoint(&verified, Path::new(&state), Path::new(&ready));
    panic!("SIGKILL checkpoint returned unexpectedly: {result:?}");
}

fn run_sigkill_latest_temp_case(prior_exists: bool) {
    let label = if prior_exists {
        "sigkill-temp-prior"
    } else {
        "sigkill-temp-absent"
    };
    let temp = TempTree::new(label);
    let (state, prior) = if prior_exists {
        let (state, prior) = stage_baseline(&temp);
        (state, Some(prior))
    } else {
        (temp.path("state"), None)
    };
    let transfer = temp.path("candidate-transfer");
    let ready = temp.path("latest-temp-ready");
    fixture_transfer(&transfer, 43, label.as_bytes());

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "sigkill_latest_temp_child",
            "--ignored",
            "--nocapture",
        ])
        .env("CATALOG_PUBLISH_SIGKILL_TRANSFER", &transfer)
        .env("CATALOG_PUBLISH_SIGKILL_STATE", &state)
        .env("CATALOG_PUBLISH_SIGKILL_READY", &ready)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(
            Instant::now() < deadline,
            "child did not reach durable checkpoint"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "child exited before SIGKILL"
        );
        thread::sleep(Duration::from_millis(10));
    }
    // SAFETY: the child PID is live and owned by this test.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGKILL) }, 0);
    let status = child.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));

    let latest = state.join("latest");
    let names = fs::read_dir(&latest)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<BTreeSet<_>>();
    let mut expected = BTreeSet::from([
        ".catalog-v1.ref.tmp".to_owned(),
        ".recovery-v1.tmp".to_owned(),
        "recovery-v1.json".to_owned(),
    ]);
    if prior_exists {
        expected.insert("catalog-v1.ref".to_owned());
    }
    assert_eq!(names, expected, "exact durable pre-rename state");
    assert_eq!(
        fs::read(latest.join("catalog-v1.ref")).ok(),
        prior,
        "latest remains the exact prior or exact absence"
    );
    let record_bytes = fs::read(latest.join("recovery-v1.json")).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&record_bytes).unwrap();
    assert_eq!(serde_jcs::to_vec(&record).unwrap(), record_bytes);
    assert_eq!(record["phase"], "prepared");
    assert_eq!(
        fs::read(latest.join(".catalog-v1.ref.tmp")).unwrap(),
        serde_jcs::to_vec(&record["intended_reference"]).unwrap(),
        "durable temp is the exact canonical intended reference"
    );
    let temp_metadata = fs::metadata(latest.join(".catalog-v1.ref.tmp")).unwrap();
    assert_eq!(temp_metadata.nlink(), 1);
    assert_eq!(temp_metadata.mode() & 0o7777, 0o400);
    assert_eq!(
        record["operation"]["latest_temporary_identity"]["device"],
        temp_metadata.dev()
    );
    assert_eq!(
        record["operation"]["latest_temporary_identity"]["inode"],
        temp_metadata.ino()
    );

    assert_eq!(
        local::recover_local(&state).unwrap(),
        PublishOutcome::RecoveryAborted
    );
    assert!(!latest.join(".catalog-v1.ref.tmp").exists());
    assert!(!latest.join("recovery-v1.json").exists());
    assert!(!latest.join(".recovery-v1.tmp").exists());
    assert_eq!(fs::read(latest.join("catalog-v1.ref")).ok(), prior);
    assert_eq!(
        local::recover_local(&state).unwrap(),
        if prior_exists {
            PublishOutcome::RecoveryCommitted
        } else {
            PublishOutcome::RecoveryAborted
        },
        "repeated recovery is idempotent after exact cleanup"
    );
}

#[test]
fn sigkill_after_durable_latest_temp_recovers_exact_prior_and_absence() {
    run_sigkill_latest_temp_case(true);
    run_sigkill_latest_temp_case(false);
}

#[test]
fn dropped_after_record_visibility_recovers_by_exact_abort_to_prior() {
    let temp = TempTree::new("abort-prior");
    let (state, prior) = stage_baseline(&temp);
    let transfer = temp.path("candidate-transfer");
    fixture_transfer(&transfer, 43, b"candidate");
    let candidate = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();

    let error = local::stage_local_with_fault(&candidate, &state, FaultPoint::AfterRecoveryRecord)
        .unwrap_err();
    assert_eq!(error.outcome(), FailureOutcome::RecoveryRequired);
    assert_eq!(
        fs::read(state.join("latest/catalog-v1.ref")).unwrap(),
        prior
    );
    let contender = local::stage_local(&candidate, &state).unwrap_err();
    assert_eq!(contender.outcome(), FailureOutcome::RecoveryRequired);
    assert_eq!(
        fs::read(state.join("latest/catalog-v1.ref")).unwrap(),
        prior
    );
    let record = fs::read(state.join("latest/recovery-v1.json")).unwrap();
    let record_text = String::from_utf8(record).unwrap();
    assert!(!record_text.contains(state.to_str().unwrap()));
    assert!(!record_text.contains(transfer.to_str().unwrap()));

    assert_eq!(
        local::recover_local(&state).unwrap(),
        PublishOutcome::RecoveryAborted
    );
    assert_eq!(
        fs::read(state.join("latest/catalog-v1.ref")).unwrap(),
        prior
    );
    assert!(!state.join("latest/recovery-v1.json").exists());
    assert_eq!(
        local::recover_local(&state).unwrap(),
        PublishOutcome::RecoveryCommitted,
        "clean repeated recovery is idempotent for an existing exact latest"
    );
}

#[test]
fn no_rollback_candidate_aborts_to_exact_absence() {
    let temp = TempTree::new("abort-absent");
    let transfer = temp.path("candidate-transfer");
    let state = temp.path("state");
    fixture_transfer(&transfer, 42, b"candidate");
    let candidate = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
    let error = local::stage_local_with_fault(&candidate, &state, FaultPoint::AfterRecoveryRecord)
        .unwrap_err();
    assert_eq!(error.outcome(), FailureOutcome::RecoveryRequired);
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("latest/recovery-v1.json")).unwrap()).unwrap();
    assert_eq!(record["prior_state"], "no_rollback_candidate");
    assert!(record["prior_reference"].is_null());

    assert_eq!(
        local::recover_local(&state).unwrap(),
        PublishOutcome::RecoveryAborted
    );
    assert!(!state.join("latest/catalog-v1.ref").exists());
    assert_eq!(
        local::recover_local(&state).unwrap(),
        PublishOutcome::RecoveryAborted
    );
}

#[test]
fn every_postrename_visibility_drop_recovers_by_exact_commit() {
    for fault in [
        FaultPoint::AfterLatestRename,
        FaultPoint::AfterLatestReadback,
        FaultPoint::BeforeLatestDirectorySync,
        FaultPoint::AfterLatestDirectorySync,
    ] {
        let temp = TempTree::new(fault.label());
        let (state, prior) = stage_baseline(&temp);
        let transfer = temp.path("candidate-transfer");
        fixture_transfer(&transfer, 43, fault.label().as_bytes());
        let candidate = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();

        let error = local::stage_local_with_fault(&candidate, &state, fault).unwrap_err();
        assert_eq!(
            error.outcome(),
            FailureOutcome::OutcomeUncertain,
            "{fault:?}"
        );
        assert_ne!(
            fs::read(state.join("latest/catalog-v1.ref")).unwrap(),
            prior
        );
        assert!(state.join("latest/recovery-v1.json").exists());
        assert_eq!(
            local::recover_local(&state).unwrap(),
            PublishOutcome::RecoveryCommitted,
            "{fault:?}"
        );
        assert!(!state.join("latest/recovery-v1.json").exists());
    }
}

#[test]
fn malformed_oversize_noncanonical_and_conflicting_recovery_is_preserved() {
    for (label, bytes) in [
        ("malformed", b"{}".to_vec()),
        ("noncanonical", b"{ \"schema_version\": 1 }".to_vec()),
        ("oversize", vec![b'x'; 257 * 1024]),
    ] {
        let temp = TempTree::new(label);
        let transfer = temp.path("candidate-transfer");
        let state = temp.path("state");
        fixture_transfer(&transfer, 42, b"candidate");
        let candidate = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
        let _ = local::stage_local_with_fault(&candidate, &state, FaultPoint::AfterRecoveryRecord);
        let marker = state.join("latest/recovery-v1.json");
        set_mode(&marker, 0o600);
        fs::write(&marker, &bytes).unwrap();
        set_mode(&marker, 0o400);
        let before = fs::read(&marker).unwrap();

        let error = local::recover_local(&state).unwrap_err();
        assert_eq!(error.outcome(), FailureOutcome::OutcomeUncertain);
        assert_eq!(fs::read(marker).unwrap(), before);
    }

    let temp = TempTree::new("conflicting");
    let transfer = temp.path("candidate-transfer");
    let state = temp.path("state");
    fixture_transfer(&transfer, 42, b"candidate");
    let candidate = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
    let _ = local::stage_local_with_fault(&candidate, &state, FaultPoint::AfterRecoveryRecord);
    let marker = state.join("latest/recovery-v1.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
    value["catalog_payload_sha256"] = serde_json::json!("99".repeat(32));
    let conflicting = serde_jcs::to_vec(&value).unwrap();
    set_mode(&marker, 0o600);
    fs::write(&marker, &conflicting).unwrap();
    set_mode(&marker, 0o400);
    let error = local::recover_local(&state).unwrap_err();
    assert_eq!(error.outcome(), FailureOutcome::OutcomeUncertain);
    assert_eq!(fs::read(marker).unwrap(), conflicting);
}

#[test]
fn every_canonical_operation_field_contradiction_preserves_all_recovery_evidence() {
    for label in [
        "source-commit",
        "source-tree",
        "qualification",
        "input-transfer",
        "isolation-mode",
        "reverse-manifest",
        "release-manifest",
        "catalog-envelope",
        "catalog-payload",
        "catalog-release",
        "release-tag-sequence",
        "checksums",
        "support-asset",
        "object-inventory",
        "prior-reference-digest",
        "intended-reference",
        "prior-reference",
        "operation-id",
    ] {
        let temp = TempTree::new(&format!("record-contradiction-{label}"));
        let (state, prior) = stage_baseline(&temp);
        let transfer = temp.path("candidate-transfer");
        fixture_transfer(&transfer, 43, label.as_bytes());
        let candidate = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
        let error =
            local::stage_local_with_fault(&candidate, &state, FaultPoint::AfterRecoveryRecord)
                .unwrap_err();
        assert_eq!(error.outcome(), FailureOutcome::RecoveryRequired);
        let marker = state.join("latest/recovery-v1.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
        let digest = "99".repeat(32);
        match label {
            "source-commit" => {
                value["operation"]["source_commit"] = serde_json::json!("66".repeat(20));
            }
            "source-tree" => {
                value["operation"]["source_tree_sha256"] = serde_json::json!(digest);
            }
            "qualification" => {
                value["operation"]["qualification_sha256"] = serde_json::json!(digest);
                value["operation"]["qualification_reference"] =
                    serde_json::json!(format!("qualification-{digest}.json"));
            }
            "input-transfer" => {
                value["operation"]["input_transfer_sha256"] = serde_json::json!(digest);
            }
            "isolation-mode" => {
                value["operation"]["isolation_completion_mode"] = serde_json::json!("recover-sign");
            }
            "reverse-manifest" => replace_bound_object_digest(
                &mut value["operation"],
                "reverse_transfer_manifest",
                "transfer-manifest-v1.json",
                &digest,
            ),
            "release-manifest" => replace_bound_object_digest(
                &mut value["operation"],
                "release_manifest",
                "signed-release-bundle-manifest-v1.json",
                &digest,
            ),
            "catalog-envelope" => replace_bound_object_digest(
                &mut value["operation"],
                "catalog_envelope",
                "catalog-v1.json",
                &digest,
            ),
            "catalog-payload" => {
                value["operation"]["catalog_payload_sha256"] = serde_json::json!(digest);
            }
            "catalog-release" => {
                value["operation"]["catalog_releases"][0]["provider"] =
                    serde_json::json!("builtin:changed");
            }
            "release-tag-sequence" => {
                value["operation"]["catalog_sequence"] = serde_json::json!(44);
                value["operation"]["release_tag"] = serde_json::json!("catalog-v1-sequence-44");
            }
            "checksums" => replace_bound_object_digest(
                &mut value["operation"],
                "checksums",
                "checksums-sha256.txt",
                &digest,
            ),
            "support-asset" => {
                let name = value["operation"]["support_assets"][0]["name"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                value["operation"]["support_assets"][0]["sha256"] = serde_json::json!(digest);
                value["operation"]["support_assets"][0]["object"] =
                    serde_json::json!(format!("objects/{digest}"));
                let object = value["operation"]["objects"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|object| object["name"] == name)
                    .unwrap();
                object["sha256"] = serde_json::json!(digest);
                object["object"] = serde_json::json!(format!("objects/{digest}"));
            }
            "object-inventory" => {
                value["operation"]["objects"].as_array_mut().unwrap().pop();
            }
            "prior-reference-digest" => {
                value["operation"]["prior_reference_sha256"] = serde_json::json!(digest);
            }
            "intended-reference" | "prior-reference" | "operation-id" => {}
            _ => unreachable!(),
        }
        recompute_operation_id(&mut value);
        match label {
            "intended-reference" => {
                value["intended_reference"]["operation"]["input_transfer_sha256"] =
                    serde_json::json!(digest);
            }
            "prior-reference" => {
                value["prior_reference"]["operation_id"] = serde_json::json!(digest);
            }
            "operation-id" => {
                value["operation_id"] = serde_json::json!(digest);
                value["intended_reference"]["operation_id"] = serde_json::json!(digest);
            }
            _ => {}
        }
        let conflicting = serde_jcs::to_vec(&value).unwrap();
        write_read_only(&marker, &conflicting);
        let latest_before = state_file_snapshot(&state.join("latest"));
        let objects_before = state_file_snapshot(&state.join("objects"));

        let error = local::recover_local(&state).unwrap_err();
        assert_eq!(error.outcome(), FailureOutcome::OutcomeUncertain, "{label}");
        assert_eq!(
            state_file_snapshot(&state.join("latest")),
            latest_before,
            "latest evidence changed for {label}"
        );
        assert_eq!(
            state_file_snapshot(&state.join("objects")),
            objects_before,
            "immutable evidence changed for {label}"
        );
        assert_eq!(
            fs::read(state.join("latest/catalog-v1.ref")).unwrap(),
            prior
        );
    }
}

#[test]
fn completed_reference_signed_payload_sequence_tag_and_provider_contradictions_are_preserved() {
    for label in ["payload", "sequence-tag", "provider"] {
        let temp = TempTree::new(&format!("latest-contradiction-{label}"));
        let (state, _) = stage_baseline(&temp);
        let latest = state.join("latest/catalog-v1.ref");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&latest).unwrap()).unwrap();
        match label {
            "payload" => {
                value["operation"]["catalog_payload_sha256"] = serde_json::json!("99".repeat(32));
            }
            "sequence-tag" => {
                value["operation"]["catalog_sequence"] = serde_json::json!(43);
                value["operation"]["release_tag"] = serde_json::json!("catalog-v1-sequence-43");
            }
            "provider" => {
                value["operation"]["catalog_releases"][0]["provider"] =
                    serde_json::json!("builtin:changed");
            }
            _ => unreachable!(),
        }
        recompute_reference_operation_id(&mut value);
        let conflicting = serde_jcs::to_vec(&value).unwrap();
        write_read_only(&latest, &conflicting);

        let error = local::recover_local(&state).unwrap_err();
        assert_eq!(error.outcome(), FailureOutcome::OutcomeUncertain, "{label}");
        assert_eq!(fs::read(&latest).unwrap(), conflicting, "{label}");
    }
}

#[test]
fn unexpected_latest_object_substitution_and_lock_contention_preserve_evidence() {
    let temp = TempTree::new("recovery-contention");
    let transfer = temp.path("candidate-transfer");
    let state = temp.path("state");
    fixture_transfer(&transfer, 42, b"candidate");
    let candidate = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
    let _ = local::stage_local_with_fault(&candidate, &state, FaultPoint::AfterRecoveryRecord);
    let marker_path = state.join("latest/recovery-v1.json");
    let marker = File::open(&marker_path).unwrap();
    assert_eq!(unsafe { libc::flock(marker.as_raw_fd(), libc::LOCK_EX) }, 0);
    let contender = local::recover_local(&state).unwrap_err();
    assert_eq!(contender.outcome(), FailureOutcome::RecoveryRequired);
    assert!(marker_path.exists());
    assert_eq!(unsafe { libc::flock(marker.as_raw_fd(), libc::LOCK_UN) }, 0);
    drop(marker);

    let object = fs::read_dir(state.join("objects"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    set_mode(&object, 0o600);
    let substituted = local::recover_local(&state).unwrap_err();
    assert_eq!(substituted.outcome(), FailureOutcome::OutcomeUncertain);
    assert!(marker_path.exists());
    set_mode(&object, 0o400);

    fs::write(state.join("latest/catalog-v1.ref"), b"unexpected").unwrap();
    set_mode(&state.join("latest/catalog-v1.ref"), 0o400);
    let before = fs::read(state.join("latest/catalog-v1.ref")).unwrap();
    let error = local::recover_local(&state).unwrap_err();
    assert_eq!(error.outcome(), FailureOutcome::OutcomeUncertain);
    assert_eq!(
        fs::read(state.join("latest/catalog-v1.ref")).unwrap(),
        before
    );
    assert!(marker_path.exists());
}

#[test]
fn latest_temp_mode_link_hash_identity_and_prior_relation_mismatches_are_preserved() {
    for label in [
        "mode",
        "hardlink",
        "bytes",
        "replacement",
        "unexpected-prior",
        "intended-alongside-temp",
    ] {
        let temp = TempTree::new(&format!("latest-temp-mismatch-{label}"));
        let (state, _) = stage_baseline(&temp);
        let transfer = temp.path("candidate-transfer");
        fixture_transfer(&transfer, 43, label.as_bytes());
        let candidate = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
        let error =
            local::stage_local_with_fault(&candidate, &state, FaultPoint::AfterLatestTempDurable)
                .unwrap_err();
        assert_eq!(error.outcome(), FailureOutcome::RecoveryRequired);
        let latest = state.join("latest");
        let latest_temp = latest.join(".catalog-v1.ref.tmp");
        match label {
            "mode" => set_mode(&latest_temp, 0o600),
            "hardlink" => fs::hard_link(&latest_temp, temp.path("temp-hardlink")).unwrap(),
            "bytes" => write_read_only(&latest_temp, b"wrong canonical bytes"),
            "replacement" => {
                let exact = fs::read(&latest_temp).unwrap();
                fs::remove_file(&latest_temp).unwrap();
                fs::write(&latest_temp, exact).unwrap();
                set_mode(&latest_temp, 0o400);
            }
            "unexpected-prior" => {
                write_read_only(&latest.join("catalog-v1.ref"), b"unexpected prior");
            }
            "intended-alongside-temp" => {
                let intended = fs::read(&latest_temp).unwrap();
                write_read_only(&latest.join("catalog-v1.ref"), &intended);
            }
            _ => unreachable!(),
        }
        let latest_before = state_file_snapshot(&latest);
        let objects_before = state_file_snapshot(&state.join("objects"));
        let error = local::recover_local(&state).unwrap_err();
        assert_eq!(error.outcome(), FailureOutcome::RecoveryRequired, "{label}");
        assert_eq!(state_file_snapshot(&latest), latest_before, "{label}");
        assert_eq!(
            state_file_snapshot(&state.join("objects")),
            objects_before,
            "{label}"
        );
    }
}

#[test]
fn stale_temp_linked_state_and_mode_or_link_drift_fail_without_cleanup() {
    let temp = TempTree::new("drift");
    let (state, prior) = stage_baseline(&temp);
    fs::write(state.join("latest/.recovery-v1.tmp"), b"stale").unwrap();
    set_mode(&state.join("latest/.recovery-v1.tmp"), 0o400);
    let error = local::recover_local(&state).unwrap_err();
    assert_eq!(error.outcome(), FailureOutcome::RecoveryRequired);
    assert!(state.join("latest/.recovery-v1.tmp").exists());
    assert_eq!(
        fs::read(state.join("latest/catalog-v1.ref")).unwrap(),
        prior
    );

    fs::remove_file(state.join("latest/.recovery-v1.tmp")).unwrap();
    set_mode(&state.join("latest"), 0o755);
    assert!(local::recover_local(&state).is_err());
    set_mode(&state.join("latest"), 0o700);

    let hardlink = temp.path("latest-hardlink");
    fs::hard_link(state.join("latest/catalog-v1.ref"), &hardlink).unwrap();
    assert!(local::recover_local(&state).is_err());
    assert!(hardlink.exists());

    let alias = temp.path("state-alias");
    std::os::unix::fs::symlink(&state, &alias).unwrap();
    assert!(local::recover_local(&alias).is_err());
}

#[test]
fn recover_cli_is_strictly_recover_only_and_accepts_no_candidate() {
    let temp = TempTree::new("recover-cli");
    let state = temp.path("state");
    private_directory(&state);
    private_directory(&state.join("objects"));
    private_directory(&state.join("latest"));
    let binary = env!("CARGO_BIN_EXE_catalog-publish");

    let recovered = Command::new(binary)
        .args(["recover-local", "--state", state.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(recovered.status.success());
    assert_eq!(recovered.stdout, b"recovery aborted\n");
    assert!(recovered.stderr.is_empty());

    for arguments in [
        vec![
            "recover-local",
            "--state",
            state.to_str().unwrap(),
            "--bundle",
            "/tmp/candidate",
        ],
        vec!["recover-local", "--bundle", "/tmp/candidate"],
    ] {
        let rejected = Command::new(binary).args(arguments).output().unwrap();
        assert!(!rejected.status.success());
        assert!(rejected.stdout.is_empty());
        assert_eq!(rejected.stderr, b"catalog publication failed\n");
    }
}

#[derive(Clone, Copy, Debug)]
enum SwappedStateComponent {
    Root,
    Objects,
    Latest,
}

fn state_file_snapshot(directory: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_str().unwrap().to_owned(),
                fs::read(path).unwrap(),
            )
        })
        .collect()
}

fn replace_canonical_state(
    temp: &TempTree,
    state: &std::path::Path,
    component: SwappedStateComponent,
) {
    match component {
        SwappedStateComponent::Root => {
            fs::rename(state, temp.path("detached-state")).unwrap();
            private_directory(state);
            private_directory(&state.join("objects"));
            private_directory(&state.join("latest"));
        }
        SwappedStateComponent::Objects => {
            fs::rename(state.join("objects"), temp.path("detached-objects")).unwrap();
            private_directory(&state.join("objects"));
        }
        SwappedStateComponent::Latest => {
            fs::rename(state.join("latest"), temp.path("detached-latest")).unwrap();
            private_directory(&state.join("latest"));
        }
    }
}

#[test]
fn canonical_state_swaps_never_claim_recovered_success() {
    for checkpoint in [
        StateCheckpoint::AfterOpen,
        StateCheckpoint::BeforeMutation,
        StateCheckpoint::BeforeSuccess,
    ] {
        for component in [
            SwappedStateComponent::Root,
            SwappedStateComponent::Objects,
            SwappedStateComponent::Latest,
        ] {
            let temp = TempTree::new(&format!("recover-swap-{checkpoint:?}-{component:?}"));
            let (state, _) = stage_baseline(&temp);
            let transfer = temp.path("candidate-transfer");
            fixture_transfer(&transfer, 43, b"candidate");
            let candidate = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
            let _ =
                local::stage_local_with_fault(&candidate, &state, FaultPoint::AfterRecoveryRecord);
            let worker_state = state.clone();
            let (reached_tx, reached_rx) = mpsc::sync_channel(0);
            let (resume_tx, resume_rx) = mpsc::sync_channel(0);
            let worker = thread::spawn(move || {
                local::recover_local_with_checkpoint(
                    &worker_state,
                    checkpoint,
                    reached_tx,
                    resume_rx,
                )
            });

            reached_rx.recv().unwrap();
            replace_canonical_state(&temp, &state, component);
            let replacement_objects = state_file_snapshot(&state.join("objects"));
            let replacement_latest = state_file_snapshot(&state.join("latest"));
            resume_tx.send(()).unwrap();
            assert!(
                worker.join().unwrap().is_err(),
                "{checkpoint:?} {component:?}"
            );
            assert_eq!(
                state_file_snapshot(&state.join("objects")),
                replacement_objects,
                "canonical replacement objects changed at {checkpoint:?} {component:?}"
            );
            assert_eq!(
                state_file_snapshot(&state.join("latest")),
                replacement_latest,
                "canonical replacement latest changed at {checkpoint:?} {component:?}"
            );
        }
    }
}
