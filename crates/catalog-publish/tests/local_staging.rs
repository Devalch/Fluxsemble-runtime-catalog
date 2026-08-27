#![cfg(unix)]

use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, sync::mpsc, thread};

#[allow(dead_code)]
#[path = "../src/local.rs"]
mod local;
mod support;

use local::{
    FailureOutcome, FaultPoint, PublishOutcome, StateCheckpoint, TestPersistentStateLimits,
};
use support::{TempTree, fixture_transfer, private_directory, set_mode};

#[test]
fn reverse_transfer_and_both_signatures_are_verified_before_state_mutation() {
    let temp = TempTree::new("verify");
    let transfer = temp.path("transfer");
    fixture_transfer(&transfer, 42, b"support-asset");

    let verified = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
    assert_eq!(verified.sequence(), 42);
    assert_eq!(verified.tag(), "catalog-v1-sequence-42");
    assert_eq!(verified.object_count(), 4);
    assert!(!temp.path("state").exists());

    assert!(
        catalog_publish::verify_transferred_signed_bundle(&transfer).is_err(),
        "the production public identity accepted fixture signatures"
    );
}

#[test]
fn digest_addressed_objects_and_latest_are_exact_immutable_and_reusable() {
    let temp = TempTree::new("stage");
    let transfer = temp.path("transfer");
    let state = temp.path("state");
    fixture_transfer(&transfer, 42, b"support-asset");
    let verified = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();

    assert_eq!(
        local::stage_local(&verified, &state).unwrap(),
        PublishOutcome::Staged
    );
    assert_eq!(
        fs::read_dir(&state)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<std::collections::BTreeSet<_>>(),
        ["latest".to_owned(), "objects".to_owned()].into()
    );
    let objects = fs::read_dir(state.join("objects"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(objects.len(), 4);
    for object in &objects {
        let name = object.file_name().unwrap().to_str().unwrap();
        assert_eq!(name.len(), 64);
        assert!(name.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(
            fs::metadata(object).unwrap().permissions().mode() & 0o7777,
            0o400
        );
    }
    assert_eq!(
        fs::metadata(state.join("latest/catalog-v1.ref"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o400
    );
    assert!(!state.join("latest/recovery-v1.json").exists());
    assert!(!state.join("latest/.recovery-v1.tmp").exists());
    assert!(!state.join("latest/.catalog-v1.ref.tmp").exists());

    let before = fs::read(state.join("latest/catalog-v1.ref")).unwrap();
    assert_eq!(
        local::stage_local(&verified, &state).unwrap(),
        PublishOutcome::Staged
    );
    assert_eq!(
        fs::read(state.join("latest/catalog-v1.ref")).unwrap(),
        before
    );
}

#[test]
fn previsibility_failures_preserve_prior_and_may_leave_only_safe_objects() {
    for fault in [
        FaultPoint::BeforeObjectWrite,
        FaultPoint::AfterObjects,
        FaultPoint::BeforeRecoveryRecord,
    ] {
        let temp = TempTree::new(fault.label());
        let transfer = temp.path("transfer");
        let state = temp.path("state");
        fixture_transfer(&transfer, 42, b"support-asset");
        let verified = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
        let error = local::stage_local_with_fault(&verified, &state, fault).unwrap_err();
        assert_eq!(error.outcome(), FailureOutcome::FailedPriorPreserved);
        assert!(!state.join("latest/catalog-v1.ref").exists(), "{fault:?}");
        assert!(!state.join("latest/recovery-v1.json").exists(), "{fault:?}");
    }
}

#[test]
fn conflicting_object_state_directory_drift_and_stale_temps_fail_closed() {
    let temp = TempTree::new("fail-closed");
    let transfer = temp.path("transfer");
    let state = temp.path("state");
    fixture_transfer(&transfer, 42, b"support-asset");
    let verified = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
    local::stage_local(&verified, &state).unwrap();
    let latest = fs::read(state.join("latest/catalog-v1.ref")).unwrap();

    let object = fs::read_dir(state.join("objects"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    set_mode(&object, 0o600);
    assert!(local::stage_local(&verified, &state).is_err());
    assert_eq!(
        fs::read(state.join("latest/catalog-v1.ref")).unwrap(),
        latest
    );
    set_mode(&object, 0o400);

    fs::write(state.join("latest/.catalog-v1.ref.tmp"), b"stale").unwrap();
    set_mode(&state.join("latest/.catalog-v1.ref.tmp"), 0o400);
    assert!(local::stage_local(&verified, &state).is_err());
    assert!(state.join("latest/.catalog-v1.ref.tmp").exists());
    assert_eq!(
        fs::read(state.join("latest/catalog-v1.ref")).unwrap(),
        latest
    );
}

#[test]
fn sequence_tag_or_digest_conflicts_never_replace_latest() {
    let temp = TempTree::new("sequence-conflict");
    let first_transfer = temp.path("first-transfer");
    let same_sequence = temp.path("same-sequence");
    let state = temp.path("state");
    fixture_transfer(&first_transfer, 42, b"first");
    fixture_transfer(&same_sequence, 42, b"different");
    let first = local::verify_transferred_fixture_signed_bundle(&first_transfer).unwrap();
    let conflict = local::verify_transferred_fixture_signed_bundle(&same_sequence).unwrap();
    local::stage_local(&first, &state).unwrap();
    let latest = fs::read(state.join("latest/catalog-v1.ref")).unwrap();

    assert!(local::stage_local(&conflict, &state).is_err());
    assert_eq!(
        fs::read(state.join("latest/catalog-v1.ref")).unwrap(),
        latest
    );
}

#[test]
fn transfer_schema_attestation_signatures_inventory_and_checksums_fail_closed() {
    let temp = TempTree::new("transfer-schema");
    for (label, pointer, replacement) in [
        ("mode", "/entries/0/mode", serde_json::json!("0444")),
        ("size", "/entries/0/size", serde_json::json!(1)),
        (
            "hash",
            "/entries/0/sha256",
            serde_json::json!("00".repeat(32)),
        ),
        (
            "input-binding",
            "/isolation_attestation/input_transfer_sha256",
            serde_json::json!("66".repeat(32)),
        ),
        (
            "original-mode",
            "/isolation_attestation/original_operation_mode",
            serde_json::json!("recover-sign"),
        ),
        (
            "attestation-predicate",
            "/isolation_attestation/no_new_privileges",
            serde_json::json!(false),
        ),
    ] {
        let transfer = temp.path(label);
        fixture_transfer(&transfer, 42, b"support-asset");
        let manifest = transfer.join("transfer-manifest-v1.json");
        set_mode(&manifest, 0o600);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
        *value.pointer_mut(pointer).unwrap() = replacement;
        fs::write(&manifest, serde_jcs::to_vec(&value).unwrap()).unwrap();
        set_mode(&manifest, 0o400);
        assert!(
            local::verify_transferred_fixture_signed_bundle(&transfer).is_err(),
            "{label}"
        );
    }

    let duplicate = temp.path("duplicate-path");
    fixture_transfer(&duplicate, 42, b"support-asset");
    let manifest = duplicate.join("transfer-manifest-v1.json");
    set_mode(&manifest, 0o600);
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    let repeated = value["entries"][0].clone();
    value["entries"].as_array_mut().unwrap().insert(1, repeated);
    fs::write(&manifest, serde_jcs::to_vec(&value).unwrap()).unwrap();
    set_mode(&manifest, 0o400);
    assert!(local::verify_transferred_fixture_signed_bundle(&duplicate).is_err());

    for (label, relative, replacement) in [
        ("catalog-signature", "catalog-v1.json", b"{}".as_slice()),
        ("checksums", "checksums-sha256.txt", b"wrong\n".as_slice()),
    ] {
        let transfer = temp.path(label);
        fixture_transfer(&transfer, 42, b"support-asset");
        let file = transfer.join("signed-release-bundle").join(relative);
        set_mode(&file, 0o600);
        fs::write(&file, replacement).unwrap();
        set_mode(&file, 0o400);
        let manifest = transfer.join("transfer-manifest-v1.json");
        set_mode(&manifest, 0o600);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
        let entry = value["entries"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["relative_path"] == format!("signed-release-bundle/{relative}"))
            .unwrap();
        entry["size"] = serde_json::json!(replacement.len() as u64);
        entry["sha256"] = serde_json::json!(support::sha256(replacement));
        fs::write(&manifest, serde_jcs::to_vec(&value).unwrap()).unwrap();
        set_mode(&manifest, 0o400);
        assert!(
            local::verify_transferred_fixture_signed_bundle(&transfer).is_err(),
            "{label}"
        );
    }
}

#[test]
fn transferred_links_writable_content_and_identity_substitution_are_rejected() {
    use std::os::unix::fs::symlink;

    let temp = TempTree::new("transfer-rejections");
    let transfer = temp.path("transfer");
    fixture_transfer(&transfer, 42, b"support-asset");
    let catalog = transfer.join("signed-release-bundle/catalog-v1.json");
    set_mode(&catalog, 0o600);
    assert!(local::verify_transferred_fixture_signed_bundle(&transfer).is_err());
    set_mode(&catalog, 0o400);

    let extra = transfer.join("signed-release-bundle/extra");
    fs::write(&extra, b"extra").unwrap();
    set_mode(&extra, 0o400);
    assert!(local::verify_transferred_fixture_signed_bundle(&transfer).is_err());
    fs::remove_file(extra).unwrap();

    let linked = temp.path("linked");
    fs::hard_link(&catalog, &linked).unwrap();
    assert!(local::verify_transferred_fixture_signed_bundle(&transfer).is_err());
    fs::remove_file(linked).unwrap();

    let original = transfer.join("signed-release-bundle");
    let moved = transfer.join("real-bundle");
    fs::rename(&original, &moved).unwrap();
    symlink(&moved, &original).unwrap();
    assert!(local::verify_transferred_fixture_signed_bundle(&transfer).is_err());
}

#[test]
fn preexisting_partial_state_is_validated_before_missing_children_are_created() {
    for existing_child in [None, Some("objects"), Some("latest")] {
        let label = existing_child.unwrap_or("empty");
        let temp = TempTree::new(&format!("partial-state-{label}"));
        let transfer = temp.path("transfer");
        let state = temp.path("state");
        fixture_transfer(&transfer, 42, label.as_bytes());
        private_directory(&state);
        if let Some(child) = existing_child {
            private_directory(&state.join(child));
        }
        let verified = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();

        assert_eq!(
            local::stage_local(&verified, &state).unwrap(),
            PublishOutcome::Staged,
            "{label}"
        );
        assert!(state.join("objects").is_dir(), "{label}");
        assert!(state.join("latest").is_dir(), "{label}");
    }
}

#[test]
fn unknown_or_unsafe_preexisting_state_is_rejected_without_mutation_or_cleanup() {
    let temp = TempTree::new("unknown-preexisting-state");
    let transfer = temp.path("transfer");
    let state = temp.path("state");
    fixture_transfer(&transfer, 42, b"unknown");
    private_directory(&state);
    let sentinel = state.join("sentinel");
    fs::write(&sentinel, b"preserve exactly").unwrap();
    set_mode(&sentinel, 0o600);
    let verified = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();

    assert!(local::stage_local(&verified, &state).is_err());
    assert_eq!(fs::read(&sentinel).unwrap(), b"preserve exactly");
    assert_eq!(
        fs::read_dir(&state)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>(),
        vec!["sentinel"]
    );

    for unsafe_kind in ["linked", "mode"] {
        let state = temp.path(&format!("unsafe-{unsafe_kind}"));
        private_directory(&state);
        if unsafe_kind == "linked" {
            std::os::unix::fs::symlink(
                temp.path("unknown-preexisting-state"),
                state.join("objects"),
            )
            .unwrap();
        } else {
            private_directory(&state.join("objects"));
            set_mode(&state.join("objects"), 0o755);
        }
        assert!(
            local::stage_local(&verified, &state).is_err(),
            "{unsafe_kind}"
        );
        assert!(
            fs::symlink_metadata(state.join("objects")).is_ok(),
            "{unsafe_kind}"
        );
        assert!(!state.join("latest").exists(), "{unsafe_kind}");
    }
}

#[test]
fn concurrently_appearing_fixed_child_is_validated_without_cleanup() {
    for safe in [true, false] {
        let temp = TempTree::new(if safe {
            "concurrent-safe-child"
        } else {
            "concurrent-unsafe-child"
        });
        let transfer = temp.path("transfer");
        let state = temp.path("state");
        fixture_transfer(&transfer, 42, b"concurrent-child");
        private_directory(&state);
        let verified = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
        let worker_state = state.clone();
        let (reached_tx, reached_rx) = mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = mpsc::sync_channel(0);
        let worker = thread::spawn(move || {
            local::stage_local_with_checkpoint(
                &verified,
                &worker_state,
                StateCheckpoint::BeforeChildCreation,
                reached_tx,
                resume_rx,
            )
        });

        reached_rx.recv().unwrap();
        if safe {
            private_directory(&state.join("objects"));
        } else {
            std::os::unix::fs::symlink(temp.path("state"), state.join("objects")).unwrap();
        }
        resume_tx.send(()).unwrap();
        let result = worker.join().unwrap();
        if safe {
            assert_eq!(result.unwrap(), PublishOutcome::Staged);
        } else {
            assert!(result.is_err());
            assert!(
                fs::symlink_metadata(state.join("objects"))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert!(!state.join("latest").exists());
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum SwappedStateComponent {
    Root,
    Objects,
    Latest,
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
fn canonical_state_swaps_never_claim_staged_success() {
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
            let temp = TempTree::new(&format!("stage-swap-{checkpoint:?}-{component:?}"));
            let baseline_transfer = temp.path("baseline-transfer");
            let candidate_transfer = temp.path("candidate-transfer");
            let state = temp.path("state");
            fixture_transfer(&baseline_transfer, 42, b"baseline");
            fixture_transfer(&candidate_transfer, 43, b"candidate");
            let baseline =
                local::verify_transferred_fixture_signed_bundle(&baseline_transfer).unwrap();
            local::stage_local(&baseline, &state).unwrap();
            let candidate =
                local::verify_transferred_fixture_signed_bundle(&candidate_transfer).unwrap();
            let worker_state = state.clone();
            let (reached_tx, reached_rx) = mpsc::sync_channel(0);
            let (resume_tx, resume_rx) = mpsc::sync_channel(0);
            let worker = thread::spawn(move || {
                local::stage_local_with_checkpoint(
                    &candidate,
                    &worker_state,
                    checkpoint,
                    reached_tx,
                    resume_rx,
                )
            });

            reached_rx.recv().unwrap();
            replace_canonical_state(&temp, &state, component);
            let replacement_objects = persistent_object_snapshot(&state);
            let replacement_latest = state_file_snapshot(&state.join("latest"));
            resume_tx.send(()).unwrap();
            assert!(
                worker.join().unwrap().is_err(),
                "{checkpoint:?} {component:?}"
            );
            assert_eq!(
                persistent_object_snapshot(&state),
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

fn state_file_snapshot(directory: &std::path::Path) -> BTreeMap<String, (Vec<u8>, u32)> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            let bytes = fs::read(&path).unwrap();
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
            (name, (bytes, mode))
        })
        .collect()
}

fn persistent_object_snapshot(state: &std::path::Path) -> BTreeMap<String, (Vec<u8>, u32)> {
    fs::read_dir(state.join("objects"))
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            let bytes = fs::read(&path).unwrap();
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
            (name, (bytes, mode))
        })
        .collect()
}

#[test]
fn persistent_state_count_bytes_names_and_enumeration_work_are_bounded() {
    let temp = TempTree::new("persistent-bounds");
    let transfer = temp.path("transfer");
    let state = temp.path("state");
    fixture_transfer(&transfer, 42, b"bounded-state");
    let verified = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
    local::stage_local(&verified, &state).unwrap();
    let baseline = persistent_object_snapshot(&state);
    let total_bytes = baseline
        .values()
        .map(|(bytes, _)| bytes.len() as u64)
        .sum::<u64>();

    for limits in [
        TestPersistentStateLimits {
            maximum_object_count: baseline.len() as u64 - 1,
            ..TestPersistentStateLimits::default()
        },
        TestPersistentStateLimits {
            maximum_cumulative_bytes: total_bytes - 1,
            ..TestPersistentStateLimits::default()
        },
        TestPersistentStateLimits {
            maximum_enumeration_work: baseline.len() as u64 + 1,
            ..TestPersistentStateLimits::default()
        },
    ] {
        assert!(local::stage_local_with_persistent_limits(&verified, &state, limits).is_err());
        assert_eq!(persistent_object_snapshot(&state), baseline);
    }

    let oversized_name = "a".repeat(65);
    let oversized_path = state.join("objects").join(&oversized_name);
    fs::write(&oversized_path, b"preserved oversized name").unwrap();
    set_mode(&oversized_path, 0o400);
    let with_oversized_name = persistent_object_snapshot(&state);
    assert!(local::stage_local(&verified, &state).is_err());
    assert_eq!(persistent_object_snapshot(&state), with_oversized_name);
}
