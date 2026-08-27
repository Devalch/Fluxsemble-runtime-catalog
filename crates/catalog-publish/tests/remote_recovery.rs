#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
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

#[derive(Clone, Copy)]
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
        Ok(self.release.clone())
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
        self.publish_calls += 1;
        let after = self.boundary("publish_draft")?;
        let release = self
            .release
            .as_mut()
            .filter(|release| release.release_id == release_id)
            .ok_or(RemoteBoundaryError)?;
        release.draft = false;
        if after { self.fail_after() } else { Ok(()) }
    }
}

struct BytesLatest(Vec<u8>);

impl LatestTransport for BytesLatest {
    fn fetch_catalog(&mut self, _expected: &RemoteAsset) -> Result<Vec<u8>, RemoteBoundaryError> {
        Ok(self.0.clone())
    }
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
fn failures_before_and_after_each_remote_mutation_resume_only_exact_state() {
    for (call, timing) in [
        ("create_tag", Failure::Before),
        ("create_tag", Failure::After),
        ("create_draft", Failure::Before),
        ("create_draft", Failure::After),
        ("upload:checksums-sha256.txt", Failure::Before),
        ("upload:checksums-sha256.txt", Failure::After),
    ] {
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
fn publish_after_failure_never_creates_or_publishes_another_release() {
    let (_temp, state) = staged("publish-retry");
    let mut broker = RecoveryBroker::default();
    let approval = stage_approve(&state, &mut broker);
    broker.fail = Some(("publish_draft".to_owned(), Failure::After));
    let mut latest = BytesLatest(catalog_bytes(&state));
    let _ = workflow::publish_remote_fixture_with(&state, &approval, &mut broker, &mut latest);
    workflow::publish_remote_fixture_with(&state, &approval, &mut broker, &mut latest).unwrap();
    assert_eq!(broker.publish_calls, 1);
    assert_eq!(broker.release.as_ref().unwrap().release_id, "7");
    assert!(!broker.release.as_ref().unwrap().draft);
}

#[test]
fn transport_fixture_before_and_after_mutation_failures_resume_exact_prerelease() {
    for (call, timing) in [
        ("create_tag", Failure::Before),
        ("create_tag", Failure::After),
        ("create_draft", Failure::Before),
        ("create_draft", Failure::After),
        ("upload:github-release-asset-v1.txt", Failure::Before),
        ("upload:github-release-asset-v1.txt", Failure::After),
        ("publish_draft", Failure::Before),
        ("publish_draft", Failure::After),
    ] {
        let mut broker = RecoveryBroker {
            fail: Some((call.to_owned(), timing)),
            ..Default::default()
        };
        let _ = workflow::publish_transport_fixture_with(&mut broker, COMMIT);
        assert_eq!(
            workflow::publish_transport_fixture_with(&mut broker, COMMIT).unwrap(),
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
fn transport_fixture_rejects_concurrent_release_id_drift_before_publication() {
    let mut broker = RecoveryBroker {
        drift_after_upload: true,
        ..Default::default()
    };
    assert!(workflow::publish_transport_fixture_with(&mut broker, COMMIT).is_err());
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
