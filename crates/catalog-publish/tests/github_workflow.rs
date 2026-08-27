#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
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

const TRANSPORT_PROTOCOL_FAKE_C: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *commit = "0123456789abcdef0123456789abcdef01234567";
static const char *asset = "Fluxsemble runtime catalog GitHub release asset transport fixture v1.\n";
static const char *digest = "12238677d13a13b3e9a47a952b8a96d45e06f4cb38fcb51cd5ddc04e2c624d95";

static int marker(const char *root, const char *name, int create) {
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", root, name) >= (int)sizeof(path)) return -1;
    if (create) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) { close(fd); return 1; }
        if (errno != EEXIST) return -1;
    }
    return access(path, F_OK) == 0;
}

static int output_path(const char *request, char *path, size_t capacity) {
    const char *start = strstr(request, "\"output_path\":\"");
    if (start == NULL) return -1;
    start += strlen("\"output_path\":\"");
    const char *end = strchr(start, '\"');
    if (end == NULL || (size_t)(end - start) >= capacity) return -1;
    memcpy(path, start, (size_t)(end - start));
    path[end - start] = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 5 || strcmp(argv[1], "--config") != 0 ||
        strcmp(argv[3], "--expected-config-sha256") != 0) return 80;
    char root[PATH_MAX], request[65537];
    int config = open(argv[2], O_RDONLY);
    if (config < 0) return 81;
    ssize_t root_size = read(config, root, sizeof(root) - 1);
    close(config);
    if (root_size <= 0) return 82;
    root[root_size] = 0;
    size_t request_size = fread(request, 1, sizeof(request) - 1, stdin);
    if (ferror(stdin) || request_size == sizeof(request) - 1) return 83;
    request[request_size] = 0;

    if (strstr(request, "\"kind\":\"create_tag\"") != NULL) {
        if (marker(root, "tag", 1) < 0) return 84;
        printf("{\"commit_sha\":\"%s\",\"kind\":\"tag\",\"object_type\":\"commit\",\"schema_version\":1,\"tag\":\"transport-v1\"}", commit);
    } else if (strstr(request, "\"kind\":\"read_tag\"") != NULL) {
        if (marker(root, "tag", 0) != 1) return 85;
        printf("{\"commit_sha\":\"%s\",\"kind\":\"tag\",\"object_type\":\"commit\",\"schema_version\":1,\"tag\":\"transport-v1\"}", commit);
    } else if (strstr(request, "\"kind\":\"read_draft\"") != NULL) {
        int draft = marker(root, "draft", 0);
        int uploaded = marker(root, "asset", 0);
        int published = marker(root, "published", 0);
        if (draft < 0 || uploaded < 0 || published < 0) return 86;
        if (!draft) {
            fputs("{\"kind\":\"draft_missing\",\"schema_version\":1,\"tag\":\"transport-v1\"}", stdout);
        } else {
            printf("{\"assets\":%s,\"draft\":%s,\"kind\":\"draft\",\"notes\":\"Permanent credential-free GitHub release asset transport fixture.\",\"prerelease\":true,\"release_id\":\"7\",\"schema_version\":1,\"tag\":\"transport-v1\",\"target_commitish\":\"%s\",\"title\":\"Fluxsemble runtime catalog transport fixture v1\"}", uploaded ? "[{\"asset_id\":\"11\",\"name\":\"github-release-asset-v1.txt\",\"size\":70}]" : "[]", published ? "false" : "true", commit);
        }
    } else if (strstr(request, "\"kind\":\"create_draft\"") != NULL) {
        if (marker(root, "draft", 1) < 0) return 87;
        printf("{\"assets\":[],\"draft\":true,\"kind\":\"draft\",\"notes\":\"Permanent credential-free GitHub release asset transport fixture.\",\"prerelease\":true,\"release_id\":\"7\",\"schema_version\":1,\"tag\":\"transport-v1\",\"target_commitish\":\"%s\",\"title\":\"Fluxsemble runtime catalog transport fixture v1\"}", commit);
    } else if (strstr(request, "\"kind\":\"upload_asset\"") != NULL) {
        if (marker(root, "asset", 1) < 0) return 88;
        printf("{\"kind\":\"asset_uploaded\",\"name\":\"github-release-asset-v1.txt\",\"schema_version\":1,\"sha256\":\"%s\",\"size\":70,\"status\":\"asset_uploaded\"}", digest);
    } else if (strstr(request, "\"kind\":\"download_asset\"") != NULL) {
        char path[PATH_MAX];
        if (output_path(request, path, sizeof(path)) != 0) return 89;
        int output = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (output < 0 || write(output, asset, 70) != 70 || fsync(output) != 0 || fchmod(output, 0400) != 0 || fsync(output) != 0 || close(output) != 0) return 90;
        printf("{\"asset\":{\"asset_id\":\"11\",\"name\":\"github-release-asset-v1.txt\",\"sha256\":\"%s\",\"size\":70},\"kind\":\"asset\",\"schema_version\":1}", digest);
    } else if (strstr(request, "\"kind\":\"publish_draft\"") != NULL) {
        if (marker(root, "published", 1) < 0) return 91;
        fputs("{\"kind\":\"published\",\"release_id\":\"7\",\"schema_version\":1,\"status\":\"published\"}", stdout);
    } else {
        return 92;
    }
    return fflush(stdout) == 0 ? 0 : 93;
}
"#;

#[derive(Clone, Copy, PartialEq, Eq)]
enum FaultTiming {
    Before,
    After,
}

struct FakeBroker {
    tags: BTreeMap<String, RemoteTag>,
    releases: Vec<RemoteRelease>,
    bytes: BTreeMap<String, Vec<u8>>,
    calls: Vec<String>,
    next_release: u64,
    next_asset: u64,
    fault: Option<(String, FaultTiming)>,
    drift_after_upload: bool,
    operation_record: Option<PathBuf>,
}

impl Default for FakeBroker {
    fn default() -> Self {
        Self {
            tags: BTreeMap::new(),
            releases: Vec::new(),
            bytes: BTreeMap::new(),
            calls: Vec::new(),
            next_release: 7,
            next_asset: 11,
            fault: None,
            drift_after_upload: false,
            operation_record: None,
        }
    }
}

impl FakeBroker {
    fn record(&mut self, call: &str) -> Result<FaultTiming, RemoteBoundaryError> {
        self.calls.push(call.to_owned());
        let timing = self
            .fault
            .as_ref()
            .filter(|(name, _)| name == call)
            .map(|(_, timing)| *timing);
        if timing == Some(FaultTiming::Before) {
            self.fault = None;
            return Err(RemoteBoundaryError);
        }
        Ok(timing.unwrap_or(FaultTiming::Before))
    }

    fn release_mut(&mut self, tag: &str) -> Result<&mut RemoteRelease, RemoteBoundaryError> {
        let matches = self
            .releases
            .iter_mut()
            .filter(|release| release.tag == tag)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(RemoteBoundaryError);
        }
        Ok(matches.into_iter().next().unwrap())
    }

    fn release(&self, tag: &str) -> Option<&RemoteRelease> {
        self.releases.iter().find(|release| release.tag == tag)
    }
}

impl BrokerTransport for FakeBroker {
    fn identity_digests(&mut self) -> Result<BrokerIdentityDigests, RemoteBoundaryError> {
        self.record("identity_digests")?;
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
        if let Some(record) = &self.operation_record {
            assert!(
                record.exists(),
                "operation record must precede first mutation"
            );
        }
        let timing = self.record("create_tag")?;
        if self.tags.contains_key(tag) {
            return Err(RemoteBoundaryError);
        }
        self.tags.insert(
            tag.to_owned(),
            RemoteTag {
                tag: tag.to_owned(),
                commit_sha: commit.to_owned(),
                object_type: broker::BrokerTagObjectTypeV1::Commit,
            },
        );
        if timing == FaultTiming::After {
            self.fault = None;
            return Err(RemoteBoundaryError);
        }
        Ok(())
    }

    fn read_tag(&mut self, _repository: &str, tag: &str) -> Result<RemoteTag, RemoteBoundaryError> {
        self.record("read_tag")?;
        self.tags.get(tag).cloned().ok_or(RemoteBoundaryError)
    }

    fn read_draft(
        &mut self,
        _repository: &str,
        tag: &str,
    ) -> Result<Option<RemoteRelease>, RemoteBoundaryError> {
        self.record("read_draft")?;
        let matches = self
            .releases
            .iter()
            .filter(|release| release.tag == tag)
            .cloned()
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Ok(None),
            [release] => Ok(Some(release.clone())),
            _ => Err(RemoteBoundaryError),
        }
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
        let timing = self.record("create_draft")?;
        if self.releases.iter().any(|release| release.tag == tag) {
            return Err(RemoteBoundaryError);
        }
        let release_id = self.next_release.to_string();
        self.next_release += 1;
        self.releases.push(RemoteRelease {
            release_id,
            tag: tag.to_owned(),
            target_commitish: target_commitish.to_owned(),
            title: title.to_owned(),
            notes: notes.to_owned(),
            draft: true,
            prerelease,
            assets: Vec::new(),
        });
        if timing == FaultTiming::After {
            self.fault = None;
            return Err(RemoteBoundaryError);
        }
        Ok(())
    }

    fn upload_asset(
        &mut self,
        _repository: &str,
        tag: &str,
        source: &UploadSource<'_>,
    ) -> Result<(), RemoteBoundaryError> {
        let timing = self.record(&format!("upload:{}", source.name()))?;
        let bytes = source.read_exact().map_err(|_| RemoteBoundaryError)?;
        assert_eq!(bytes.len() as u64, source.size());
        assert_eq!(sha256(&bytes), source.sha256());
        let id = self.next_asset.to_string();
        self.next_asset += 1;
        let release = self.release_mut(tag)?;
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
            self.release_mut(tag)?.title.push_str(" drift");
        }
        if timing == FaultTiming::After {
            self.fault = None;
            return Err(RemoteBoundaryError);
        }
        Ok(())
    }

    fn download_asset(
        &mut self,
        _repository: &str,
        asset: &RemoteReleaseAsset,
    ) -> Result<DownloadedAsset, RemoteBoundaryError> {
        self.record(&format!("download:{}", asset.name))?;
        let bytes = self
            .bytes
            .get(&asset.asset_id)
            .cloned()
            .ok_or(RemoteBoundaryError)?;
        Ok(DownloadedAsset {
            asset_id: asset.asset_id.clone(),
            name: asset.name.clone(),
            bytes,
        })
    }

    fn publish_draft(
        &mut self,
        _repository: &str,
        release_id: &str,
    ) -> Result<(), RemoteBoundaryError> {
        let timing = self.record("publish_draft")?;
        let release = self
            .releases
            .iter_mut()
            .find(|release| release.release_id == release_id)
            .ok_or(RemoteBoundaryError)?;
        release.draft = false;
        if timing == FaultTiming::After {
            self.fault = None;
            return Err(RemoteBoundaryError);
        }
        Ok(())
    }
}

struct FakeLatest {
    bytes: Vec<u8>,
    state: Option<PathBuf>,
    calls: usize,
}

impl LatestTransport for FakeLatest {
    fn fetch_catalog(&mut self, expected: &RemoteAsset) -> Result<Vec<u8>, RemoteBoundaryError> {
        self.calls += 1;
        if let Some(state) = &self.state {
            assert!(
                state.join("latest/publication-receipt-v1.json").exists(),
                "publication outcome must be durable before latest verification"
            );
        }
        assert_eq!(expected.name, "catalog-v1.json");
        Ok(self.bytes.clone())
    }
}

fn staged_fixture(label: &str) -> (TempTree, PathBuf) {
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

fn transport_protocol_fake_config(temp: &TempTree) -> PathBuf {
    let source = temp.path("transport-protocol-fake.c");
    let executable = temp.path("transport-protocol-fake");
    fs::write(&source, TRANSPORT_PROTOCOL_FAKE_C).unwrap();
    let output = Command::new("cc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fake broker compile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).unwrap();

    let remote = temp.path("fake-remote");
    fs::DirBuilder::new().mode(0o700).create(&remote).unwrap();
    let publisher_config = temp.path("publisher-config");
    fs::write(&publisher_config, remote.as_os_str().as_encoded_bytes()).unwrap();
    fs::set_permissions(&publisher_config, fs::Permissions::from_mode(0o600)).unwrap();
    let client_config = temp.path("broker-client-config.json");
    fs::write(
        &client_config,
        serde_jcs::to_vec(&broker_client::PublisherBrokerClientConfigV1 {
            schema_version: 1,
            catalog_gh_broker_path: executable.to_str().unwrap().to_owned(),
            catalog_gh_broker_sha256: sha256(&fs::read(&executable).unwrap()),
            publisher_broker_config_path: publisher_config.to_str().unwrap().to_owned(),
            publisher_broker_config_sha256: sha256(&fs::read(&publisher_config).unwrap()),
        })
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&client_config, fs::Permissions::from_mode(0o600)).unwrap();
    client_config
}

fn production_catalog_bytes(state: &Path) -> Vec<u8> {
    let reference: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("latest/catalog-v1.ref")).unwrap()).unwrap();
    let digest = reference["operation"]["catalog_envelope"]["sha256"]
        .as_str()
        .unwrap();
    fs::read(state.join("objects").join(digest)).unwrap()
}

#[test]
fn production_scratch_directory_identity_rebind_rejects_parent_swap() {
    assert!(github::scratch_directory_swap_is_rejected_for_test());
}

#[test]
fn tag_precedes_exact_draft_support_uploads_pre_post_binding_and_catalog_last() {
    let (_temp, state) = staged_fixture("remote-stage");
    let mut fake = FakeBroker {
        operation_record: Some(state.join("latest/remote-operation-v1.json")),
        ..Default::default()
    };

    assert_eq!(
        workflow::stage_remote_fixture_with(&state, &mut fake).unwrap(),
        workflow::RemoteWorkflowOutcome::DraftStaged
    );

    assert_eq!(
        &fake.calls[..6],
        [
            "identity_digests",
            "create_tag",
            "read_tag",
            "read_draft",
            "create_draft",
            "read_draft"
        ]
    );
    let uploads = fake
        .calls
        .iter()
        .filter_map(|call| call.strip_prefix("upload:"))
        .collect::<Vec<_>>();
    assert_eq!(uploads.last(), Some(&"catalog-v1.json"));
    assert!(
        uploads[..uploads.len() - 1]
            .iter()
            .all(|name| *name != "catalog-v1.json")
    );
    for (index, call) in fake.calls.iter().enumerate() {
        if call.starts_with("upload:") {
            assert_eq!(fake.calls[index - 1], "read_draft");
            assert_eq!(fake.calls[index + 1], "read_draft");
        }
    }
    let receipt = state.join("latest/draft-receipt-v1.json");
    let bytes = fs::read(&receipt).unwrap();
    assert_eq!(
        fs::metadata(receipt).unwrap().permissions().mode() & 0o7777,
        0o400
    );
    assert_eq!(
        serde_jcs::to_vec(&serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()).unwrap(),
        bytes
    );
    let receipt_text = String::from_utf8(bytes).unwrap();
    assert!(receipt_text.contains("Devalch/Fluxsemble-runtime-catalog"));
    for binding in [
        "broker_client_config_sha256",
        "broker_executable_sha256",
        "publisher_broker_config_sha256",
    ] {
        assert!(receipt_text.contains(binding), "missing {binding}");
    }
    let operation_text = fs::read_to_string(state.join("latest/remote-operation-v1.json")).unwrap();
    for binding in [
        "broker_client_config_sha256",
        "broker_executable_sha256",
        "publisher_broker_config_sha256",
    ] {
        assert!(operation_text.contains(binding), "missing {binding}");
    }
}

#[test]
fn reserved_tag_and_partial_exact_assets_resume_without_replacement() {
    let (_temp, state) = staged_fixture("remote-resume");
    let mut fake = FakeBroker {
        fault: Some(("upload:checksums-sha256.txt".to_owned(), FaultTiming::After)),
        ..Default::default()
    };
    // Mandatory post-upload readback may resolve the injected after-mutation failure in the same
    // invocation; either way the exact remote asset is safely resumable.
    let _ = workflow::stage_remote_fixture_with(&state, &mut fake);
    assert!(
        !fake
            .release("catalog-v1-sequence-42")
            .unwrap()
            .assets
            .is_empty()
    );

    fake.calls.clear();
    workflow::stage_remote_fixture_with(&state, &mut fake).unwrap();
    let release = fake.release("catalog-v1-sequence-42").unwrap();
    let names = release
        .assets
        .iter()
        .map(|asset| &asset.name)
        .collect::<Vec<_>>();
    assert_eq!(
        names
            .iter()
            .filter(|name| name.as_str() == "checksums-sha256.txt")
            .count(),
        1
    );
    assert!(
        fake.calls
            .iter()
            .any(|call| call == "download:checksums-sha256.txt")
    );
}

#[test]
fn wrong_or_annotated_tag_and_every_draft_identity_drift_fail_closed() {
    for (label, object_type, commit) in [
        ("annotated", broker::BrokerTagObjectTypeV1::Tag, COMMIT),
        (
            "wrong-commit",
            broker::BrokerTagObjectTypeV1::Commit,
            "1111111111111111111111111111111111111111",
        ),
    ] {
        let (_temp, state) = staged_fixture(label);
        let mut fake = FakeBroker::default();
        fake.tags.insert(
            "catalog-v1-sequence-42".to_owned(),
            RemoteTag {
                tag: "catalog-v1-sequence-42".to_owned(),
                commit_sha: commit.to_owned(),
                object_type,
            },
        );
        assert!(
            workflow::stage_remote_fixture_with(&state, &mut fake).is_err(),
            "{label}"
        );
        assert!(fake.releases.is_empty());
    }

    for field in [
        "target",
        "title",
        "notes",
        "draft",
        "prerelease",
        "duplicate",
    ] {
        let (_temp, state) = staged_fixture(&format!("draft-{field}"));
        let mut fake = FakeBroker::default();
        fake.tags.insert(
            "catalog-v1-sequence-42".to_owned(),
            RemoteTag {
                tag: "catalog-v1-sequence-42".to_owned(),
                commit_sha: COMMIT.to_owned(),
                object_type: broker::BrokerTagObjectTypeV1::Commit,
            },
        );
        let mut release = RemoteRelease {
            release_id: "7".to_owned(),
            tag: "catalog-v1-sequence-42".to_owned(),
            target_commitish: COMMIT.to_owned(),
            title: "Pi 0.83.0".to_owned(),
            notes: "Approved managed Pi release.".to_owned(),
            draft: true,
            prerelease: false,
            assets: Vec::new(),
        };
        match field {
            "target" => {
                release.target_commitish = "1111111111111111111111111111111111111111".to_owned()
            }
            "title" => release.title.push('x'),
            "notes" => release.notes.push('x'),
            "draft" => release.draft = false,
            "prerelease" => release.prerelease = true,
            _ => {}
        }
        fake.releases.push(release.clone());
        if field == "duplicate" {
            release.release_id = "8".to_owned();
            fake.releases.push(release);
        }
        assert!(
            workflow::stage_remote_fixture_with(&state, &mut fake).is_err(),
            "{field}"
        );
    }
}

#[test]
fn approval_publish_and_latest_are_separate_exact_durable_transitions() {
    let (_temp, state) = staged_fixture("approval-publish");
    let mut fake = FakeBroker::default();
    workflow::stage_remote_fixture_with(&state, &mut fake).unwrap();
    let receipt = fs::read(state.join("latest/draft-receipt-v1.json")).unwrap();
    let receipt_sha256 = sha256(&receipt);

    assert!(workflow::approve_remote_fixture(&state, &"0".repeat(64)).is_err());
    assert!(!state.join("latest/release-approval-v1.json").exists());
    assert_eq!(
        workflow::approve_remote_fixture(&state, &receipt_sha256).unwrap(),
        workflow::RemoteWorkflowOutcome::Approved
    );
    let approval = state.join("latest/release-approval-v1.json");
    let catalog = production_catalog_bytes(&state);
    let mut latest = FakeLatest {
        bytes: catalog,
        state: Some(state.clone()),
        calls: 0,
    };
    assert_eq!(
        workflow::publish_remote_fixture_with(&state, &approval, &mut fake, &mut latest).unwrap(),
        workflow::RemoteWorkflowOutcome::PublishedAndLatestVerified
    );
    assert_eq!(latest.calls, 1);
    assert!(!fake.release("catalog-v1-sequence-42").unwrap().draft);
    assert!(state.join("latest/publication-receipt-v1.json").exists());
    assert!(state.join("latest/latest-receipt-v1.json").exists());
}

#[test]
fn public_cli_transport_path_bootstraps_empty_state_with_fake_protocol_only() {
    let (temp, state) = fresh_transport_state("transport-public-cli");
    let config = transport_protocol_fake_config(&temp);
    let output = Command::new(env!("CARGO_BIN_EXE_catalog-publish"))
        .args([
            "publish-transport-fixture",
            "--state",
            state.to_str().unwrap(),
            "--source-commit",
            COMMIT,
            "--broker-config",
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"transport fixture prerelease published\n");
    assert!(output.stderr.is_empty());
    assert!(state.join("latest/transport-operation-v1.json").is_file());
    assert!(state.join("latest/transport-receipt-v1.json").is_file());
    assert!(!state.join("latest/catalog-v1.ref").exists());
    assert_eq!(fs::read_dir(state.join("objects")).unwrap().count(), 0);
}

#[test]
fn dedicated_transport_state_is_no_catalog_and_publishes_exact_prerelease() {
    let (_temp, state) = fresh_transport_state("transport-fixture");
    let mut fake = FakeBroker {
        operation_record: Some(state.join("latest/transport-operation-v1.json")),
        ..Default::default()
    };
    assert_eq!(
        workflow::publish_transport_fixture_with(&state, &mut fake, COMMIT).unwrap(),
        workflow::RemoteWorkflowOutcome::TransportFixturePublished
    );
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    assert_eq!(fs::read_dir(state.join("objects")).unwrap().count(), 0);
    let latest_names = fs::read_dir(state.join("latest"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        latest_names,
        std::collections::BTreeSet::from([
            ".remote-workflow-v1.lock".to_owned(),
            "transport-operation-v1.json".to_owned(),
            "transport-receipt-v1.json".to_owned(),
        ])
    );
    let operation = fs::read_to_string(state.join("latest/transport-operation-v1.json")).unwrap();
    for binding in [
        "repository",
        "source_commit",
        "manifest_sha256",
        "broker_client_config_sha256",
        "broker_executable_sha256",
        "publisher_broker_config_sha256",
    ] {
        assert!(operation.contains(binding), "missing {binding}");
    }
    for production_only in [
        "local_operation_id",
        "signed_transfer_sha256",
        "catalog-v1.ref",
        "signature",
    ] {
        assert!(
            !operation.contains(production_only),
            "found {production_only}"
        );
    }

    let release = fake.release("transport-v1").unwrap();
    assert!(!release.draft);
    assert!(release.prerelease);
    assert_eq!(
        release.title,
        "Fluxsemble runtime catalog transport fixture v1"
    );
    assert_eq!(release.assets.len(), 1);
    assert_eq!(release.assets[0].name, "github-release-asset-v1.txt");
    assert!(
        !release
            .assets
            .iter()
            .any(|asset| asset.name == "catalog-v1.json")
    );
    let upload = fake
        .calls
        .iter()
        .position(|call| call.starts_with("upload:"))
        .unwrap();
    assert_eq!(fake.calls[upload - 1], "read_draft");
    assert_eq!(fake.calls[upload + 1], "read_draft");
}

#[test]
fn transport_wrong_tag_release_and_asset_bytes_fail_without_replacement() {
    let exact_tag = || RemoteTag {
        tag: "transport-v1".to_owned(),
        commit_sha: COMMIT.to_owned(),
        object_type: broker::BrokerTagObjectTypeV1::Commit,
    };
    let exact_release = || RemoteRelease {
        release_id: "7".to_owned(),
        tag: "transport-v1".to_owned(),
        target_commitish: COMMIT.to_owned(),
        title: "Fluxsemble runtime catalog transport fixture v1".to_owned(),
        notes: "Permanent credential-free GitHub release asset transport fixture.".to_owned(),
        draft: true,
        prerelease: true,
        assets: Vec::new(),
    };

    let (_temp, state) = fresh_transport_state("transport-wrong-tag");
    let mut wrong_tag = FakeBroker::default();
    wrong_tag.tags.insert(
        "transport-v1".to_owned(),
        RemoteTag {
            commit_sha: "1111111111111111111111111111111111111111".to_owned(),
            ..exact_tag()
        },
    );
    assert!(workflow::publish_transport_fixture_with(&state, &mut wrong_tag, COMMIT).is_err());
    assert!(wrong_tag.releases.is_empty());

    let (_temp, state) = fresh_transport_state("transport-wrong-release");
    let mut wrong_release = FakeBroker::default();
    wrong_release
        .tags
        .insert("transport-v1".to_owned(), exact_tag());
    wrong_release.releases.push(RemoteRelease {
        title: "wrong title".to_owned(),
        ..exact_release()
    });
    assert!(workflow::publish_transport_fixture_with(&state, &mut wrong_release, COMMIT).is_err());
    assert!(
        !wrong_release
            .calls
            .iter()
            .any(|call| call.starts_with("upload:"))
    );

    let (_temp, state) = fresh_transport_state("transport-wrong-asset");
    let mut wrong_asset = FakeBroker::default();
    wrong_asset
        .tags
        .insert("transport-v1".to_owned(), exact_tag());
    wrong_asset.releases.push(RemoteRelease {
        assets: vec![RemoteReleaseAsset {
            asset_id: "11".to_owned(),
            name: "github-release-asset-v1.txt".to_owned(),
            size: 70,
        }],
        ..exact_release()
    });
    wrong_asset.bytes.insert("11".to_owned(), vec![b'x'; 70]);
    assert!(workflow::publish_transport_fixture_with(&state, &mut wrong_asset, COMMIT).is_err());
    assert!(!wrong_asset.calls.iter().any(|call| call == "publish_draft"));
}

#[test]
fn transport_state_rejects_unknown_and_production_records_without_remote_authority() {
    for name in [
        "unknown-v1.json",
        "catalog-v1.ref",
        "remote-operation-v1.json",
        ".remote-operation-v1.tmp",
        "latest-receipt-v1.json",
    ] {
        let (_temp, state) = fresh_transport_state(&format!("transport-reject-{name}"));
        fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(state.join("objects"))
            .unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(state.join("latest"))
            .unwrap();
        fs::write(state.join("latest").join(name), b"production-or-unknown").unwrap();
        fs::set_permissions(
            state.join("latest").join(name),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        let mut fake = FakeBroker::default();
        assert!(
            workflow::publish_transport_fixture_with(&state, &mut fake, COMMIT).is_err(),
            "{name}"
        );
        assert!(fake.calls.is_empty(), "remote authority reached for {name}");
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
