#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[allow(dead_code)]
#[path = "../src/broker.rs"]
mod broker;
#[allow(dead_code)]
#[path = "../src/broker_client.rs"]
mod broker_client;
#[allow(dead_code)]
#[path = "../src/github.rs"]
mod github;
#[allow(dead_code)]
#[path = "../src/local.rs"]
mod local;
#[allow(dead_code)]
mod support;
#[allow(dead_code)]
#[path = "../src/workflow.rs"]
mod workflow;

use broker_client::BrokerIdentityDigests;
use github::{
    BrokerTransport, DownloadedAsset, LatestTransport, RemoteAsset, RemoteBoundaryError,
    RemoteRelease, RemoteReleaseAsset, RemoteTag, UploadSource,
};
use sha2::{Digest, Sha256};
use support::{TempTree, fixture_transfer};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const CONFIG_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const PRODUCTION_ASSETS: &[&str] = &[
    "checksums-sha256.txt",
    "qualification-1dbf39600b5761d58378447f494a50c8b9c01b559b6ef420720f99f4e45717c9.json",
    "signed-release-bundle-manifest-v1.json",
    "catalog-v1.json",
];

const STAGE_MUTATION_RETRY_CASES: &[(&str, Failure)] = &[
    ("create_tag", Failure::Before),
    ("create_tag", Failure::After),
    ("create_draft", Failure::Before),
    ("create_draft", Failure::After),
    ("upload:checksums-sha256.txt", Failure::Before),
    ("upload:checksums-sha256.txt", Failure::After),
    (
        "upload:qualification-1dbf39600b5761d58378447f494a50c8b9c01b559b6ef420720f99f4e45717c9.json",
        Failure::Before,
    ),
    (
        "upload:qualification-1dbf39600b5761d58378447f494a50c8b9c01b559b6ef420720f99f4e45717c9.json",
        Failure::After,
    ),
    (
        "upload:signed-release-bundle-manifest-v1.json",
        Failure::Before,
    ),
    (
        "upload:signed-release-bundle-manifest-v1.json",
        Failure::After,
    ),
    ("upload:catalog-v1.json", Failure::Before),
    ("upload:catalog-v1.json", Failure::After),
];

const STAGE_OBSERVATION_RETRY_CASES: &[(&str, Failure)] = &[
    ("read_tag", Failure::Before),
    ("read_draft", Failure::Before),
    ("download:checksums-sha256.txt", Failure::Before),
    (
        "download:qualification-1dbf39600b5761d58378447f494a50c8b9c01b559b6ef420720f99f4e45717c9.json",
        Failure::Before,
    ),
    (
        "download:signed-release-bundle-manifest-v1.json",
        Failure::Before,
    ),
    ("download:catalog-v1.json", Failure::Before),
];

const PUBLISH_RETRY_CASES: &[(&str, Failure)] = &[
    ("publish_draft", Failure::Before),
    ("publish_draft", Failure::After),
];

const ASSET_DRIFT_CASES: &[&str] = &["id", "name", "size", "bytes", "duplicate", "extra"];
const RELEASE_DRIFT_CASES: &[&str] = &[
    "release_id",
    "target",
    "title",
    "notes",
    "draft",
    "prerelease",
];

const TRANSPORT_RETRY_CASES: &[(&str, Failure)] = &[
    ("create_tag", Failure::Before),
    ("create_tag", Failure::After),
    ("create_draft", Failure::Before),
    ("create_draft", Failure::After),
    ("upload:github-release-asset-v1.txt", Failure::Before),
    ("upload:github-release-asset-v1.txt", Failure::After),
    ("publish_draft", Failure::Before),
    ("publish_draft", Failure::After),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    Before,
    After,
}

#[derive(Default)]
struct RecoveryBroker {
    tag: Option<RemoteTag>,
    release: Option<RemoteRelease>,
    bytes: BTreeMap<String, Vec<u8>>,
    next_asset: u64,
    fail: Option<(String, Failure)>,
    drift_after_upload: bool,
    sort_assets_on_read: bool,
    tag_mutations: usize,
    draft_mutations: usize,
    upload_mutations: BTreeMap<String, usize>,
    publish_calls: usize,
}

impl RecoveryBroker {
    fn boundary(&mut self, name: &str) -> Result<bool, RemoteBoundaryError> {
        match self
            .fail
            .as_ref()
            .filter(|(call, _)| call == name)
            .map(|(_, timing)| *timing)
        {
            Some(Failure::Before) => {
                self.fail = None;
                Err(RemoteBoundaryError)
            }
            Some(Failure::After) => Ok(true),
            None => Ok(false),
        }
    }

    fn fail_after(&mut self) -> Result<(), RemoteBoundaryError> {
        self.fail = None;
        Err(RemoteBoundaryError)
    }
}

impl BrokerTransport for RecoveryBroker {
    fn identity_digests(&mut self) -> Result<BrokerIdentityDigests, RemoteBoundaryError> {
        Ok(BrokerIdentityDigests {
            broker_client_config_sha256: CONFIG_SHA256.to_owned(),
            broker_executable_sha256: CONFIG_SHA256.to_owned(),
            publisher_broker_config_sha256: CONFIG_SHA256.to_owned(),
        })
    }

    fn create_tag(
        &mut self,
        _repository: &str,
        tag: &str,
        commit: &str,
    ) -> Result<(), RemoteBoundaryError> {
        let after = self.boundary("create_tag")?;
        if self.tag.is_some() {
            return Err(RemoteBoundaryError);
        }
        self.tag_mutations += 1;
        self.tag = Some(RemoteTag {
            tag: tag.to_owned(),
            commit_sha: commit.to_owned(),
            object_type: broker::BrokerTagObjectTypeV1::Commit,
        });
        if after { self.fail_after() } else { Ok(()) }
    }

    fn read_tag(
        &mut self,
        _repository: &str,
        _tag: &str,
    ) -> Result<RemoteTag, RemoteBoundaryError> {
        self.boundary("read_tag")?;
        self.tag.clone().ok_or(RemoteBoundaryError)
    }

    fn read_draft(
        &mut self,
        _repository: &str,
        _tag: &str,
    ) -> Result<Option<RemoteRelease>, RemoteBoundaryError> {
        self.boundary("read_draft")?;
        let mut release = self.release.clone();
        if self.sort_assets_on_read {
            if let Some(release) = &mut release {
                release
                    .assets
                    .sort_by(|left, right| left.name.cmp(&right.name));
            }
        }
        Ok(release)
    }

    fn create_draft(
        &mut self,
        _repository: &str,
        tag: &str,
        target_commitish: &str,
        title: &str,
        notes: &str,
        prerelease: bool,
    ) -> Result<(), RemoteBoundaryError> {
        let after = self.boundary("create_draft")?;
        if self.release.is_some() {
            return Err(RemoteBoundaryError);
        }
        self.draft_mutations += 1;
        self.release = Some(RemoteRelease {
            release_id: "7".to_owned(),
            tag: tag.to_owned(),
            target_commitish: target_commitish.to_owned(),
            title: title.to_owned(),
            notes: notes.to_owned(),
            draft: true,
            prerelease,
            assets: Vec::new(),
        });
        if after { self.fail_after() } else { Ok(()) }
    }

    fn upload_asset(
        &mut self,
        _repository: &str,
        _tag: &str,
        source: &UploadSource<'_>,
    ) -> Result<(), RemoteBoundaryError> {
        let call = format!("upload:{}", source.name());
        let after = self.boundary(&call)?;
        let bytes = source.read_exact().map_err(|_| RemoteBoundaryError)?;
        let id = (11 + self.next_asset).to_string();
        self.next_asset += 1;
        let release = self.release.as_mut().ok_or(RemoteBoundaryError)?;
        if release
            .assets
            .iter()
            .any(|asset| asset.name == source.name())
        {
            return Err(RemoteBoundaryError);
        }
        release.assets.push(RemoteReleaseAsset {
            asset_id: id.clone(),
            name: source.name().to_owned(),
            size: source.size(),
        });
        *self
            .upload_mutations
            .entry(source.name().to_owned())
            .or_default() += 1;
        self.bytes.insert(id, bytes);
        if self.drift_after_upload {
            self.drift_after_upload = false;
            release.release_id = "8".to_owned();
        }
        if after { self.fail_after() } else { Ok(()) }
    }

    fn download_asset(
        &mut self,
        _repository: &str,
        asset: &RemoteReleaseAsset,
    ) -> Result<DownloadedAsset, RemoteBoundaryError> {
        self.boundary(&format!("download:{}", asset.name))?;
        Ok(DownloadedAsset {
            asset_id: asset.asset_id.clone(),
            name: asset.name.clone(),
            bytes: self
                .bytes
                .get(&asset.asset_id)
                .cloned()
                .ok_or(RemoteBoundaryError)?,
        })
    }

    fn publish_draft(
        &mut self,
        _repository: &str,
        release_id: &str,
    ) -> Result<(), RemoteBoundaryError> {
        let after = self.boundary("publish_draft")?;
        self.publish_calls += 1;
        let release = self
            .release
            .as_mut()
            .filter(|release| release.release_id == release_id)
            .ok_or(RemoteBoundaryError)?;
        release.draft = false;
        if after { self.fail_after() } else { Ok(()) }
    }
}

#[derive(Clone)]
struct SharedRecoveryBroker {
    inner: Arc<Mutex<RecoveryBroker>>,
    gate: Option<Arc<IdentityGate>>,
}

struct IdentityGate {
    first: AtomicBool,
    entered: Barrier,
    resume: Barrier,
}

impl IdentityGate {
    fn new() -> Self {
        Self {
            first: AtomicBool::new(true),
            entered: Barrier::new(2),
            resume: Barrier::new(2),
        }
    }

    fn block_first(&self) {
        if self.first.swap(false, Ordering::SeqCst) {
            self.entered.wait();
            self.resume.wait();
        }
    }
}

impl BrokerTransport for SharedRecoveryBroker {
    fn identity_digests(&mut self) -> Result<BrokerIdentityDigests, RemoteBoundaryError> {
        if let Some(gate) = &self.gate {
            gate.block_first();
        }
        self.inner.lock().unwrap().identity_digests()
    }

    fn create_tag(
        &mut self,
        repository: &str,
        tag: &str,
        commit: &str,
    ) -> Result<(), RemoteBoundaryError> {
        self.inner
            .lock()
            .unwrap()
            .create_tag(repository, tag, commit)
    }

    fn read_tag(&mut self, repository: &str, tag: &str) -> Result<RemoteTag, RemoteBoundaryError> {
        self.inner.lock().unwrap().read_tag(repository, tag)
    }

    fn read_draft(
        &mut self,
        repository: &str,
        tag: &str,
    ) -> Result<Option<RemoteRelease>, RemoteBoundaryError> {
        self.inner.lock().unwrap().read_draft(repository, tag)
    }

    fn create_draft(
        &mut self,
        repository: &str,
        tag: &str,
        target_commitish: &str,
        title: &str,
        notes: &str,
        prerelease: bool,
    ) -> Result<(), RemoteBoundaryError> {
        self.inner.lock().unwrap().create_draft(
            repository,
            tag,
            target_commitish,
            title,
            notes,
            prerelease,
        )
    }

    fn upload_asset(
        &mut self,
        repository: &str,
        tag: &str,
        source: &UploadSource<'_>,
    ) -> Result<(), RemoteBoundaryError> {
        self.inner
            .lock()
            .unwrap()
            .upload_asset(repository, tag, source)
    }

    fn download_asset(
        &mut self,
        repository: &str,
        asset: &RemoteReleaseAsset,
    ) -> Result<DownloadedAsset, RemoteBoundaryError> {
        self.inner.lock().unwrap().download_asset(repository, asset)
    }

    fn publish_draft(
        &mut self,
        repository: &str,
        release_id: &str,
    ) -> Result<(), RemoteBoundaryError> {
        self.inner
            .lock()
            .unwrap()
            .publish_draft(repository, release_id)
    }
}

struct BytesLatest(Vec<u8>);

impl LatestTransport for BytesLatest {
    fn fetch_catalog(&mut self, _expected: &RemoteAsset) -> Result<Vec<u8>, RemoteBoundaryError> {
        Ok(self.0.clone())
    }
}

#[test]
#[ignore = "launched explicitly as the remote SIGKILL child"]
fn remote_record_sigkill_child() {
    let Ok(state) = std::env::var("CATALOG_REMOTE_SIGKILL_STATE") else {
        return;
    };
    let mode = std::env::var("CATALOG_REMOTE_SIGKILL_MODE").unwrap();
    let operation_checkpoint = std::env::var("CATALOG_REMOTE_OPERATION_SIGKILL_CHECKPOINT").ok();
    let record_checkpoint = std::env::var("CATALOG_REMOTE_RECORD_SIGKILL_CHECKPOINT").ok();
    let ready = PathBuf::from(std::env::var("CATALOG_REMOTE_OPERATION_SIGKILL_READY").unwrap());
    local::configure_remote_sigkill_checkpoint(
        operation_checkpoint.as_deref(),
        record_checkpoint.as_deref(),
        &ready,
    );
    let state = Path::new(&state);
    let mut broker = RecoveryBroker::default();
    if mode == "stage" {
        let result = workflow::stage_remote_fixture_with(state, &mut broker);
        panic!("remote stage checkpoint returned unexpectedly: {result:?}");
    }
    workflow::stage_remote_fixture_with(state, &mut broker).unwrap();
    let receipt = fs::read(state.join("latest/draft-receipt-v1.json")).unwrap();
    let approval = workflow::approve_remote_fixture(state, &sha256(&receipt));
    if mode == "approve" {
        panic!("remote approval checkpoint returned unexpectedly: {approval:?}");
    }
    assert_eq!(approval.unwrap(), workflow::RemoteWorkflowOutcome::Approved);
    let approval_path = state.join("latest/release-approval-v1.json");
    let mut latest = BytesLatest(catalog_bytes(state));
    let result =
        workflow::publish_remote_fixture_with(state, &approval_path, &mut broker, &mut latest);
    panic!("remote publication checkpoint returned unexpectedly: {result:?}");
}

fn staged(label: &str) -> (TempTree, PathBuf) {
    let temp = TempTree::new(label);
    let transfer = temp.path("transfer");
    let state = temp.path("state");
    fixture_transfer(&transfer, 42, b"qualification");
    let verified = local::verify_transferred_fixture_signed_bundle(&transfer).unwrap();
    local::stage_local(&verified, &state).unwrap();
    (temp, state)
}

fn fresh_transport_state(label: &str) -> (TempTree, PathBuf) {
    let temp = TempTree::new(label);
    let state = temp.path("transport-state");
    (temp, state)
}

fn catalog_bytes(state: &Path) -> Vec<u8> {
    let reference: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("latest/catalog-v1.ref")).unwrap()).unwrap();
    let digest = reference["operation"]["catalog_envelope"]["sha256"]
        .as_str()
        .unwrap();
    fs::read(state.join("objects").join(digest)).unwrap()
}

fn stage_approve(state: &Path, broker: &mut RecoveryBroker) -> PathBuf {
    workflow::stage_remote_fixture_with(state, broker).unwrap();
    let receipt = fs::read(state.join("latest/draft-receipt-v1.json")).unwrap();
    workflow::approve_remote_fixture(state, &sha256(&receipt)).unwrap();
    state.join("latest/release-approval-v1.json")
}

#[test]
fn complete_per_asset_before_after_retry_matrix_resumes_only_exact_state() {
    for &(call, timing) in STAGE_MUTATION_RETRY_CASES
        .iter()
        .chain(STAGE_OBSERVATION_RETRY_CASES)
    {
        let (_temp, state) = staged(&format!(
            "recover-{call}-{}",
            matches!(timing, Failure::After)
        ));
        let mut broker = RecoveryBroker {
            fail: Some((call.to_owned(), timing)),
            ..Default::default()
        };
        let _ = workflow::stage_remote_fixture_with(&state, &mut broker);
        workflow::stage_remote_fixture_with(&state, &mut broker).unwrap();
        let release = broker.release.as_ref().unwrap();
        let mut names = release
            .assets
            .iter()
            .map(|asset| asset.name.clone())
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), release.assets.len(), "{call}");
        assert_eq!(broker.tag.as_ref().unwrap().commit_sha, COMMIT, "{call}");
        assert_eq!(broker.tag_mutations, 1, "{call}");
        assert_eq!(broker.draft_mutations, 1, "{call}");
        for asset in PRODUCTION_ASSETS {
            assert_eq!(
                broker.upload_mutations.get(*asset),
                Some(&1),
                "{call}:{asset}"
            );
        }
        assert_eq!(
            release
                .assets
                .iter()
                .map(|asset| asset.name.as_str())
                .collect::<Vec<_>>(),
            PRODUCTION_ASSETS,
            "support-first/catalog-last order changed for {call}"
        );
    }
}

#[test]
fn name_reordered_remote_assets_resume_without_reupload() {
    let (_temp, state) = staged("name-reordered-assets");
    let mut broker = RecoveryBroker {
        sort_assets_on_read: true,
        ..Default::default()
    };

    let _ = workflow::stage_remote_fixture_with(&state, &mut broker);
    let release = broker.release.as_ref().unwrap();
    assert_eq!(release.assets.len(), PRODUCTION_ASSETS.len());
    let mutations = broker.upload_mutations.clone();

    workflow::stage_remote_fixture_with(&state, &mut broker).unwrap();
    assert_eq!(broker.upload_mutations, mutations);
    for asset in PRODUCTION_ASSETS {
        assert_eq!(broker.upload_mutations.get(*asset), Some(&1));
    }

    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("latest/draft-receipt-v1.json")).unwrap())
            .unwrap();
    assert_eq!(
        receipt["body"]["assets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|asset| asset["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        PRODUCTION_ASSETS
    );
}

#[test]
fn real_sigkill_operation_and_all_local_receipt_checkpoints_settle_on_exact_retry() {
    for checkpoint in ["durable-pre-rename", "post-rename-pre-fsync"] {
        let (_temp, state) = staged(&format!("sigkill-stage-{checkpoint}"));
        run_remote_sigkill_child(&state, "stage", Some(checkpoint), None);
        let temporary = state.join("latest/.remote-operation-v1.tmp");
        assert_eq!(temporary.exists(), checkpoint == "durable-pre-rename");
        let mut broker = RecoveryBroker {
            tag: Some(RemoteTag {
                tag: "catalog-v1-sequence-42".to_owned(),
                commit_sha: COMMIT.to_owned(),
                object_type: broker::BrokerTagObjectTypeV1::Commit,
            }),
            tag_mutations: 1,
            ..Default::default()
        };
        workflow::stage_remote_fixture_with(&state, &mut broker).unwrap();
        assert!(!temporary.exists());
        assert_eq!(broker.tag_mutations, 1, "{checkpoint}");
        assert_eq!(broker.draft_mutations, 1, "{checkpoint}");
        assert!(broker.upload_mutations.values().all(|count| *count == 1));
    }

    let (_temp, state) = staged("sigkill-draft-receipt");
    run_remote_sigkill_child(&state, "stage", None, Some("draft-receipt-v1.json"));
    let mut broker = broker_from_receipt(&state, true);
    workflow::stage_remote_fixture_with(&state, &mut broker).unwrap();
    assert_eq!(broker.tag_mutations, 0);
    assert_eq!(broker.draft_mutations, 0);
    assert!(broker.upload_mutations.is_empty());

    let (_temp, state) = staged("sigkill-approval-receipt");
    run_remote_sigkill_child(&state, "approve", None, Some("release-approval-v1.json"));
    let receipt = fs::read(state.join("latest/draft-receipt-v1.json")).unwrap();
    workflow::approve_remote_fixture(&state, &sha256(&receipt)).unwrap();

    let (_temp, state) = staged("sigkill-publication-receipt");
    run_remote_sigkill_child(&state, "publish", None, Some("publication-receipt-v1.json"));
    assert!(state.join("latest/publication-receipt-v1.json").exists());
    let approval = state.join("latest/release-approval-v1.json");
    let mut broker = broker_from_receipt(&state, false);
    let mut latest = BytesLatest(catalog_bytes(&state));
    workflow::publish_remote_fixture_with(&state, &approval, &mut broker, &mut latest).unwrap();
    assert_eq!(broker.publish_calls, 0, "durable receipt retry republished");
    assert!(state.join("latest/latest-receipt-v1.json").exists());

    let (_temp, state) = staged("sigkill-latest-receipt");
    run_remote_sigkill_child(&state, "publish", None, Some("latest-receipt-v1.json"));
    let mut latest = BytesLatest(catalog_bytes(&state));
    workflow::verify_latest_fixture_with(&state, &mut latest).unwrap();
}

fn run_remote_sigkill_child(
    state: &Path,
    mode: &str,
    operation_checkpoint: Option<&str>,
    record_checkpoint: Option<&str>,
) {
    let ready = state.parent().unwrap().join(format!(
        "remote-ready-{mode}-{}",
        operation_checkpoint.or(record_checkpoint).unwrap()
    ));
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "remote_record_sigkill_child",
            "--ignored",
            "--nocapture",
        ])
        .env("CATALOG_REMOTE_SIGKILL_STATE", state)
        .env("CATALOG_REMOTE_SIGKILL_MODE", mode)
        .env("CATALOG_REMOTE_OPERATION_SIGKILL_READY", &ready);
    if let Some(checkpoint) = operation_checkpoint {
        command.env("CATALOG_REMOTE_OPERATION_SIGKILL_CHECKPOINT", checkpoint);
    }
    if let Some(checkpoint) = record_checkpoint {
        command.env("CATALOG_REMOTE_RECORD_SIGKILL_CHECKPOINT", checkpoint);
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready.exists() {
        assert!(Instant::now() < deadline, "child missed {mode} checkpoint");
        assert!(
            child.try_wait().unwrap().is_none(),
            "child exited before {mode} checkpoint"
        );
        thread::sleep(Duration::from_millis(10));
    }
    // SAFETY: this test owns the live dedicated child PID.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGKILL) }, 0);
    assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
}

fn broker_from_receipt(state: &Path, draft: bool) -> RecoveryBroker {
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("latest/draft-receipt-v1.json")).unwrap())
            .unwrap();
    let assets = receipt["body"]["assets"].as_array().unwrap();
    let mut bytes = BTreeMap::new();
    let remote_assets = assets
        .iter()
        .map(|asset| {
            let id = asset["asset_id"].as_str().unwrap().to_owned();
            let digest = asset["sha256"].as_str().unwrap();
            bytes.insert(
                id.clone(),
                fs::read(state.join("objects").join(digest)).unwrap(),
            );
            RemoteReleaseAsset {
                asset_id: id,
                name: asset["name"].as_str().unwrap().to_owned(),
                size: asset["size"].as_u64().unwrap(),
            }
        })
        .collect();
    RecoveryBroker {
        tag: Some(RemoteTag {
            tag: receipt["body"]["tag"].as_str().unwrap().to_owned(),
            commit_sha: receipt["body"]["tag_commit"].as_str().unwrap().to_owned(),
            object_type: broker::BrokerTagObjectTypeV1::Commit,
        }),
        release: Some(RemoteRelease {
            release_id: receipt["body"]["release_id"].as_str().unwrap().to_owned(),
            tag: receipt["body"]["tag"].as_str().unwrap().to_owned(),
            target_commitish: receipt["body"]["target_commitish"]
                .as_str()
                .unwrap()
                .to_owned(),
            title: receipt["body"]["title"].as_str().unwrap().to_owned(),
            notes: receipt["body"]["notes"].as_str().unwrap().to_owned(),
            draft,
            prerelease: false,
            assets: remote_assets,
        }),
        bytes,
        ..Default::default()
    }
}

#[test]
fn every_asset_and_release_identity_drift_is_rejected_without_new_mutation() {
    for (index, asset_name) in PRODUCTION_ASSETS.iter().enumerate() {
        for drift in ASSET_DRIFT_CASES {
            let (_temp, state) = staged(&format!("asset-drift-{index}-{drift}"));
            let mut broker = RecoveryBroker::default();
            workflow::stage_remote_fixture_with(&state, &mut broker).unwrap();
            let asset = broker.release.as_ref().unwrap().assets[index].clone();
            match *drift {
                "id" => broker.release.as_mut().unwrap().assets[index]
                    .asset_id
                    .push('9'),
                "name" => broker.release.as_mut().unwrap().assets[index]
                    .name
                    .push('x'),
                "size" => broker.release.as_mut().unwrap().assets[index].size += 1,
                "bytes" => {
                    broker
                        .bytes
                        .insert(asset.asset_id.clone(), b"wrong exact bytes".to_vec());
                }
                "duplicate" => broker.release.as_mut().unwrap().assets.push(asset.clone()),
                "extra" => broker
                    .release
                    .as_mut()
                    .unwrap()
                    .assets
                    .push(RemoteReleaseAsset {
                        asset_id: "999".to_owned(),
                        name: "unexpected-extra.bin".to_owned(),
                        size: 1,
                    }),
                _ => unreachable!(),
            }
            let mutations = broker.upload_mutations.clone();
            assert!(
                workflow::stage_remote_fixture_with(&state, &mut broker).is_err(),
                "{asset_name}:{drift}"
            );
            assert_eq!(broker.upload_mutations, mutations, "{asset_name}:{drift}");
        }
    }

    for drift in RELEASE_DRIFT_CASES {
        let (_temp, state) = staged(&format!("release-drift-{drift}"));
        let mut broker = RecoveryBroker::default();
        workflow::stage_remote_fixture_with(&state, &mut broker).unwrap();
        let release = broker.release.as_mut().unwrap();
        match *drift {
            "release_id" => release.release_id = "8".to_owned(),
            "target" => release.target_commitish = "1".repeat(40),
            "title" => release.title.push('x'),
            "notes" => release.notes.push('x'),
            "draft" => release.draft = false,
            "prerelease" => release.prerelease = true,
            _ => unreachable!(),
        }
        let mutations = broker.upload_mutations.clone();
        assert!(
            workflow::stage_remote_fixture_with(&state, &mut broker).is_err(),
            "{drift}"
        );
        assert_eq!(broker.upload_mutations, mutations, "{drift}");
    }
}

#[test]
fn concurrent_release_id_drift_and_wrong_downloaded_bytes_preserve_uncertainty() {
    let (_temp, state) = staged("concurrent-drift");
    let mut broker = RecoveryBroker {
        drift_after_upload: true,
        ..Default::default()
    };
    assert!(workflow::stage_remote_fixture_with(&state, &mut broker).is_err());
    let operation = fs::read_to_string(state.join("latest/remote-operation-v1.json")).unwrap();
    assert!(operation.contains("uncertain"));
    assert!(!state.join("latest/draft-receipt-v1.json").exists());

    let (_temp, state) = staged("wrong-download");
    let mut broker = RecoveryBroker {
        fail: Some(("download:checksums-sha256.txt".to_owned(), Failure::Before)),
        ..Default::default()
    };
    assert!(workflow::stage_remote_fixture_with(&state, &mut broker).is_err());
    let asset = broker.release.as_ref().unwrap().assets[0].clone();
    broker
        .bytes
        .insert(asset.asset_id, b"wrong replacement bytes".to_vec());
    assert!(workflow::stage_remote_fixture_with(&state, &mut broker).is_err());
    assert!(!state.join("latest/draft-receipt-v1.json").exists());
}

#[test]
fn publish_before_and_after_failure_settles_receipt_without_duplicate_publication() {
    for &(call, timing) in PUBLISH_RETRY_CASES {
        let (_temp, state) = staged(&format!("publish-retry-{timing:?}"));
        let mut broker = RecoveryBroker::default();
        let approval = stage_approve(&state, &mut broker);
        broker.fail = Some((call.to_owned(), timing));
        let mut latest = BytesLatest(catalog_bytes(&state));
        let first =
            workflow::publish_remote_fixture_with(&state, &approval, &mut broker, &mut latest);
        if timing == Failure::Before {
            assert!(first.is_err());
            assert!(!state.join("latest/publication-receipt-v1.json").exists());
        }
        workflow::publish_remote_fixture_with(&state, &approval, &mut broker, &mut latest).unwrap();
        assert_eq!(broker.publish_calls, 1, "{call}:{timing:?}");
        assert_eq!(broker.release.as_ref().unwrap().release_id, "7");
        assert!(!broker.release.as_ref().unwrap().draft);
        assert!(state.join("latest/publication-receipt-v1.json").exists());
    }
}

#[test]
fn transport_fixture_before_and_after_mutation_failures_resume_exact_prerelease() {
    for &(call, timing) in TRANSPORT_RETRY_CASES {
        let (_temp, state) = fresh_transport_state(&format!(
            "transport-{call}-{}",
            matches!(timing, Failure::After)
        ));
        let mut broker = RecoveryBroker {
            fail: Some((call.to_owned(), timing)),
            ..Default::default()
        };
        let _ = workflow::publish_transport_fixture_with(&state, &mut broker, COMMIT);
        assert_eq!(
            workflow::publish_transport_fixture_with(&state, &mut broker, COMMIT).unwrap(),
            workflow::RemoteWorkflowOutcome::TransportFixturePublished,
            "{call}"
        );
        let release = broker.release.as_ref().unwrap();
        assert_eq!(release.release_id, "7", "{call}");
        assert!(!release.draft, "{call}");
        assert!(release.prerelease, "{call}");
        assert_eq!(release.assets.len(), 1, "{call}");
        assert_eq!(
            release.assets[0].name, "github-release-asset-v1.txt",
            "{call}"
        );
    }
}

#[test]
fn exclusive_workflow_lock_serializes_publish_stage_and_transport_mutations() {
    run_publish_contention();
    run_stage_contention();
    run_transport_contention();
}

fn run_publish_contention() {
    let (_temp, state) = staged("concurrent-publish-lock");
    let mut prepared = RecoveryBroker::default();
    let approval = stage_approve(&state, &mut prepared);
    let catalog = catalog_bytes(&state);
    let inner = Arc::new(Mutex::new(prepared));
    let gate = Arc::new(IdentityGate::new());
    let shared = SharedRecoveryBroker {
        inner: Arc::clone(&inner),
        gate: Some(Arc::clone(&gate)),
    };
    let first_state = state.clone();
    let first_approval = approval.clone();
    let first_catalog = catalog.clone();
    let mut first_broker = shared.clone();
    let first = thread::spawn(move || {
        let mut latest = BytesLatest(first_catalog);
        workflow::publish_remote_fixture_with(
            &first_state,
            &first_approval,
            &mut first_broker,
            &mut latest,
        )
    });
    gate.entered.wait();
    let mut contender = shared.clone();
    let mut latest = BytesLatest(catalog.clone());
    assert!(
        workflow::publish_remote_fixture_with(&state, &approval, &mut contender, &mut latest,)
            .is_err()
    );
    assert_eq!(inner.lock().unwrap().publish_calls, 0);
    gate.resume.wait();
    first.join().unwrap().unwrap();

    let mut retry = SharedRecoveryBroker {
        inner: Arc::clone(&inner),
        gate: None,
    };
    let mut latest = BytesLatest(catalog);
    workflow::publish_remote_fixture_with(&state, &approval, &mut retry, &mut latest).unwrap();
    assert_eq!(inner.lock().unwrap().publish_calls, 1);
}

fn run_stage_contention() {
    let (_temp, state) = staged("concurrent-stage-lock");
    let inner = Arc::new(Mutex::new(RecoveryBroker::default()));
    let gate = Arc::new(IdentityGate::new());
    let shared = SharedRecoveryBroker {
        inner: Arc::clone(&inner),
        gate: Some(Arc::clone(&gate)),
    };
    let first_state = state.clone();
    let mut first_broker = shared.clone();
    let first =
        thread::spawn(move || workflow::stage_remote_fixture_with(&first_state, &mut first_broker));
    gate.entered.wait();
    let mut contender = shared.clone();
    assert!(workflow::stage_remote_fixture_with(&state, &mut contender).is_err());
    assert_eq!(inner.lock().unwrap().tag_mutations, 0);
    gate.resume.wait();
    first.join().unwrap().unwrap();

    let mut retry = SharedRecoveryBroker {
        inner: Arc::clone(&inner),
        gate: None,
    };
    workflow::stage_remote_fixture_with(&state, &mut retry).unwrap();
    let broker = inner.lock().unwrap();
    assert_eq!(broker.tag_mutations, 1);
    assert_eq!(broker.draft_mutations, 1);
    assert!(
        broker
            .upload_mutations
            .values()
            .all(|mutations| *mutations == 1)
    );
}

fn run_transport_contention() {
    let (_temp, state) = fresh_transport_state("concurrent-transport-lock");
    let inner = Arc::new(Mutex::new(RecoveryBroker::default()));
    let gate = Arc::new(IdentityGate::new());
    let shared = SharedRecoveryBroker {
        inner: Arc::clone(&inner),
        gate: Some(Arc::clone(&gate)),
    };
    let first_state = state.clone();
    let mut first_broker = shared.clone();
    let first = thread::spawn(move || {
        workflow::publish_transport_fixture_with(&first_state, &mut first_broker, COMMIT)
    });
    gate.entered.wait();
    let mut contender = shared.clone();
    assert!(workflow::publish_transport_fixture_with(&state, &mut contender, COMMIT).is_err());
    assert_eq!(inner.lock().unwrap().tag_mutations, 0);
    gate.resume.wait();
    first.join().unwrap().unwrap();

    let mut retry = SharedRecoveryBroker {
        inner: Arc::clone(&inner),
        gate: None,
    };
    workflow::publish_transport_fixture_with(&state, &mut retry, COMMIT).unwrap();
    let broker = inner.lock().unwrap();
    assert_eq!(broker.tag_mutations, 1);
    assert_eq!(broker.draft_mutations, 1);
    assert_eq!(broker.publish_calls, 1);
    assert_eq!(
        broker.upload_mutations.get("github-release-asset-v1.txt"),
        Some(&1)
    );
}

#[test]
fn transport_fixture_rejects_concurrent_release_id_drift_before_publication() {
    let (_temp, state) = fresh_transport_state("transport-release-drift");
    let mut broker = RecoveryBroker {
        drift_after_upload: true,
        ..Default::default()
    };
    assert!(workflow::publish_transport_fixture_with(&state, &mut broker, COMMIT).is_err());
    assert!(broker.release.as_ref().unwrap().draft);
    assert_eq!(broker.publish_calls, 0);
}

#[test]
fn latest_mismatch_keeps_publication_receipt_and_credential_free_retry_needs_no_broker() {
    let (_temp, state) = staged("latest-retry");
    let mut broker = RecoveryBroker::default();
    let approval = stage_approve(&state, &mut broker);
    let mut wrong = BytesLatest(b"not the catalog".to_vec());
    assert!(
        workflow::publish_remote_fixture_with(&state, &approval, &mut broker, &mut wrong).is_err()
    );
    assert!(state.join("latest/publication-receipt-v1.json").exists());
    assert!(!state.join("latest/latest-receipt-v1.json").exists());
    let publish_calls = broker.publish_calls;

    let mut exact = BytesLatest(catalog_bytes(&state));
    assert_eq!(
        workflow::verify_latest_fixture_with(&state, &mut exact).unwrap(),
        workflow::RemoteWorkflowOutcome::LatestVerified
    );
    assert_eq!(broker.publish_calls, publish_calls);
    assert!(state.join("latest/latest-receipt-v1.json").exists());
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
