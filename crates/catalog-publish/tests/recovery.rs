#![cfg(unix)]

use std::{
    fs::{self, File},
    os::fd::AsRawFd,
    process::Command,
};

#[allow(dead_code)]
#[path = "../src/local.rs"]
mod local;
mod support;

use local::{FailureOutcome, FaultPoint, PublishOutcome};
use support::{TempTree, fixture_transfer, set_mode};

fn stage_baseline(temp: &TempTree) -> (std::path::PathBuf, Vec<u8>) {
    let transfer = temp.path("baseline-transfer");
    let state = temp.path("state");
    fixture_transfer(&transfer, 42, b"baseline");
    let verified = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
    local::stage_local(&verified, &state).unwrap();
    let latest = fs::read(state.join("latest/catalog-v1.ref")).unwrap();
    (state, latest)
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
        ("oversize", vec![b'x'; 65 * 1024]),
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
    let (state, _) = stage_baseline(&temp);
    let binary = env!("CARGO_BIN_EXE_catalog-publish");

    let recovered = Command::new(binary)
        .args(["recover-local", "--state", state.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(recovered.status.success());
    assert_eq!(recovered.stdout, b"recovery committed\n");
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
