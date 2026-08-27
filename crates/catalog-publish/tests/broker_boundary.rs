#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

#[allow(dead_code)]
#[path = "../src/broker.rs"]
mod broker;

use broker::{
    BrokerPublicationStatusV1, BrokerRequestV1, BrokerResponseV1, BrokerTagObjectTypeV1,
    BrokerTestCheckpoints, PublisherBrokerConfigV1,
};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const TAG: &str = "catalog-v1-sequence-1";
const REPOSITORY: &str = "owner/name";
const CONFIG_CANARY: &str = "synthetic-owner-private-config-token-canary";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "catalog-broker-{label}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = make_tree_writable(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn make_tree_writable(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if metadata.is_dir() { 0o700 } else { 0o600 }),
    )?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            make_tree_writable(&entry?.path())?;
        }
    }
    Ok(())
}

#[derive(Clone)]
enum FakeOutput {
    Success(Vec<u8>),
    Failure { stdout: Vec<u8>, stderr: Vec<u8> },
    FloodStdout,
    FloodStderr,
    Deadlock,
    Timeout,
    Signal,
    InvalidUtf8,
}

struct Fixture {
    root: TempTree,
    executable: PathBuf,
    config_dir: PathBuf,
    config: PathBuf,
    snapshot: PathBuf,
}

impl Fixture {
    fn new(label: &str, output: FakeOutput) -> Self {
        let root = TempTree::new(label);
        let config_dir = root.path("github-config");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&config_dir)
            .unwrap();
        fs::write(config_dir.join("canary"), CONFIG_CANARY).unwrap();
        fs::set_permissions(config_dir.join("canary"), fs::Permissions::from_mode(0o600)).unwrap();
        let executable = root.path("fake-gh");
        let snapshot = root.path("snapshot");
        let behavior = match output {
            FakeOutput::Success(bytes) => format!(
                "/usr/bin/printf '%s' '{}'\n",
                String::from_utf8(bytes).unwrap()
            ),
            FakeOutput::Failure { stdout, stderr } => format!(
                "/usr/bin/printf '%s' '{}'\n/usr/bin/printf '%s' '{}' >&2\nexit 7\n",
                String::from_utf8(stdout).unwrap(),
                String::from_utf8(stderr).unwrap()
            ),
            FakeOutput::FloodStdout => {
                "/usr/bin/head -c 262144 /dev/zero\n/bin/sleep 10\n".to_owned()
            }
            FakeOutput::FloodStderr => {
                "/usr/bin/head -c 262144 /dev/zero >&2\n/bin/sleep 10\n".to_owned()
            }
            FakeOutput::Deadlock => {
                "/usr/bin/head -c 262144 /dev/zero >&2 &\n/usr/bin/head -c 262144 /dev/zero\nwait\n/bin/sleep 10\n".to_owned()
            }
            FakeOutput::Timeout => "/bin/sleep 10\n".to_owned(),
            FakeOutput::Signal => "kill -TERM $$\n".to_owned(),
            FakeOutput::InvalidUtf8 => "/usr/bin/printf '\\377\\376'\n".to_owned(),
        };
        let script = format!(
            "#!/bin/sh\nset -eu\n{{\n  /usr/bin/printf '%s\\n' 'ARGS_BEGIN'\n  for argument in \"$@\"; do /usr/bin/printf '%s\\n' \"$argument\"; done\n  /usr/bin/printf '%s\\n' 'ARGS_END' 'ENV_BEGIN'\n  /usr/bin/env -u PWD -u SHLVL -u _\n  /usr/bin/printf '%s\\n' 'ENV_END' 'CONFIG_BEGIN'\n  /bin/cat \"$GH_CONFIG_DIR/canary\"\n  /usr/bin/printf '\\n%s\\n' 'CONFIG_END' 'BODY_BEGIN'\n  /bin/cat\n  /usr/bin/printf '\\n%s\\n' 'BODY_END' 'INPUT_BEGIN'\n  previous=''\n  for argument in \"$@\"; do\n    if [ \"$previous\" = '--input' ] && [ \"$argument\" != '-' ]; then /bin/cat \"$argument\"; fi\n    previous=\"$argument\"\n  done\n  /usr/bin/printf '\\n%s\\n' 'INPUT_END' 'FDS_BEGIN'\n  /bin/ls -l /proc/self/fd\n  /usr/bin/printf '%s\\n' 'FDS_END'\n}} > '{}'\n{}",
            snapshot.display(),
            behavior
        );
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).unwrap();
        let config = root.path("broker-config.json");
        write_config(
            &config,
            &PublisherBrokerConfigV1 {
                schema_version: 1,
                gh_path: executable.to_str().unwrap().to_owned(),
                gh_sha256: sha256(&fs::read(&executable).unwrap()),
                github_config_dir: config_dir.to_str().unwrap().to_owned(),
            },
        );
        Self {
            root,
            executable,
            config_dir,
            config,
            snapshot,
        }
    }

    fn snapshot_section(&self, start: &str, end: &str) -> String {
        let value = fs::read_to_string(&self.snapshot).unwrap();
        value
            .split_once(start)
            .unwrap()
            .1
            .split_once(end)
            .unwrap()
            .0
            .trim_matches('\n')
            .to_owned()
    }
}

fn write_config(path: &Path, value: &PublisherBrokerConfigV1) {
    fs::write(path, serde_jcs::to_vec(value).unwrap()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn tag_json() -> Vec<u8> {
    format!(
        "{{\"object\":{{\"secret\":\"child-token-canary\",\"sha\":\"{COMMIT}\",\"type\":\"commit\"}},\"ref\":\"refs/tags/{TAG}\",\"unexpected\":\"child-path-canary\"}}"
    )
    .into_bytes()
}

fn draft_json() -> Vec<u8> {
    format!(
        "{{\"assets\":[{{\"id\":8,\"name\":\"existing.bin\",\"secret\":\"child-token-canary\",\"size\":3}}],\"draft\":true,\"id\":7,\"prerelease\":false,\"tag_name\":\"{TAG}\",\"target_commitish\":\"{COMMIT}\",\"unexpected\":\"child-path-canary\"}}"
    )
    .into_bytes()
}

fn read_tag_request() -> BrokerRequestV1 {
    BrokerRequestV1::ReadTag {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        tag: TAG.to_owned(),
    }
}

fn execute(
    fixture: &Fixture,
    request: &BrokerRequestV1,
) -> Result<BrokerResponseV1, broker::BrokerError> {
    struct Noop;
    impl BrokerTestCheckpoints for Noop {}
    broker::execute_with_test_checkpoints(&fixture.config, request, &mut Noop)
}

#[test]
fn broker_requests_are_a_closed_command_family_and_protocol_is_strict() {
    assert_eq!(
        BrokerRequestV1::all_kinds(),
        &[
            "create_tag",
            "read_tag",
            "create_draft",
            "read_draft",
            "upload_asset",
            "download_asset",
            "publish_draft",
        ]
    );
    let canonical = read_tag_request().to_canonical_bytes().unwrap();
    assert_eq!(
        BrokerRequestV1::from_canonical_bytes(&canonical).unwrap(),
        read_tag_request()
    );

    let invalid = [
        br#"{"kind":"auth","repository":"owner/name","schema_version":1}"#.as_slice(),
        br#"{"kind":"read_tag","repository":"owner/name","schema_version":1,"tag":"catalog-v1-sequence-1","token":"denied"}"#,
        br#"{"kind":"read_tag","repository":"owner/name","schema_version":1,"schema_version":1,"tag":"catalog-v1-sequence-1"}"#,
        br#"{"kind":"read_tag","repository":"owner/name","schema_version":1,"tag":"catalog-v1-sequence-1"} "#,
        br#"{"kind":"read_tag","repository":"owner/name","schema_version":1,"tag":"refs/tags/main"}"#,
        br#"{"kind":"read_tag","repository":"owner//name","schema_version":1,"tag":"catalog-v1-sequence-1"}"#,
    ];
    for bytes in invalid {
        assert!(BrokerRequestV1::from_canonical_bytes(bytes).is_err());
    }
    let deep = format!(
        "{{\"kind\":\"read_tag\",\"repository\":\"owner/name\",\"schema_version\":1,\"tag\":{}}}",
        "[".repeat(18) + "0" + &"]".repeat(18)
    );
    assert!(BrokerRequestV1::from_canonical_bytes(deep.as_bytes()).is_err());
}

#[test]
fn exact_seven_gh_api_families_have_fixed_argv_body_environment_and_projection() {
    let cases = vec![
        (
            BrokerRequestV1::CreateTag {
                schema_version: 1,
                repository: REPOSITORY.to_owned(),
                tag: TAG.to_owned(),
                commit_sha: COMMIT.to_owned(),
            },
            FakeOutput::Success(tag_json()),
            vec![
                "api",
                "--method",
                "POST",
                "/repos/owner/name/git/refs",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                "X-GitHub-Api-Version: 2022-11-28",
                "--input",
                "-",
            ],
            format!("{{\"ref\":\"refs/tags/{TAG}\",\"sha\":\"{COMMIT}\"}}"),
        ),
        (
            read_tag_request(),
            FakeOutput::Success(tag_json()),
            vec![
                "api",
                "--method",
                "GET",
                "/repos/owner/name/git/ref/tags/catalog-v1-sequence-1",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                "X-GitHub-Api-Version: 2022-11-28",
            ],
            String::new(),
        ),
        (
            BrokerRequestV1::CreateDraft {
                schema_version: 1,
                repository: REPOSITORY.to_owned(),
                tag: TAG.to_owned(),
                target_commitish: COMMIT.to_owned(),
                title: "Runtime catalog sequence 1".to_owned(),
                notes: "Reviewed release notes".to_owned(),
                prerelease: false,
            },
            FakeOutput::Success(draft_json()),
            vec![
                "api",
                "--method",
                "POST",
                "/repos/owner/name/releases",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                "X-GitHub-Api-Version: 2022-11-28",
                "--input",
                "-",
            ],
            format!(
                "{{\"body\":\"Reviewed release notes\",\"draft\":true,\"name\":\"Runtime catalog sequence 1\",\"prerelease\":false,\"tag_name\":\"{TAG}\",\"target_commitish\":\"{COMMIT}\"}}"
            ),
        ),
        (
            BrokerRequestV1::ReadDraft {
                schema_version: 1,
                repository: REPOSITORY.to_owned(),
                tag: TAG.to_owned(),
            },
            FakeOutput::Success(draft_json()),
            vec![
                "api",
                "--method",
                "GET",
                "/repos/owner/name/releases/tags/catalog-v1-sequence-1",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                "X-GitHub-Api-Version: 2022-11-28",
            ],
            String::new(),
        ),
        (
            BrokerRequestV1::PublishDraft {
                schema_version: 1,
                repository: REPOSITORY.to_owned(),
                release_id: "7".to_owned(),
            },
            FakeOutput::Success(
                br#"{"draft":false,"id":7,"secret":"child-token-canary"}"#.to_vec(),
            ),
            vec![
                "api",
                "--method",
                "PATCH",
                "/repos/owner/name/releases/7",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                "X-GitHub-Api-Version: 2022-11-28",
                "--input",
                "-",
            ],
            "{\"draft\":false}".to_owned(),
        ),
    ];

    for (index, (request, output, expected_args, expected_body)) in cases.into_iter().enumerate() {
        let fixture = Fixture::new(&format!("matrix-{index}"), output);
        let response = execute(&fixture, &request).unwrap();
        let safe = String::from_utf8(response.to_canonical_bytes().unwrap()).unwrap();
        assert!(!safe.contains("child-token-canary"));
        assert!(!safe.contains("child-path-canary"));
        let arguments = fixture.snapshot_section("ARGS_BEGIN\n", "\nARGS_END");
        assert_eq!(arguments.lines().collect::<Vec<_>>(), expected_args);
        assert_eq!(
            fixture.snapshot_section("BODY_BEGIN\n", "\nBODY_END"),
            expected_body
        );
        assert_eq!(
            fixture.snapshot_section("CONFIG_BEGIN\n", "\nCONFIG_END"),
            CONFIG_CANARY
        );
        let environment = fixture.snapshot_section("ENV_BEGIN\n", "\nENV_END");
        let environment = environment
            .lines()
            .map(|line| line.split_once('=').unwrap())
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            environment.keys().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from(["GH_CONFIG_DIR", "HOME", "LANG", "LC_ALL", "TZ"])
        );
        assert_eq!(environment["LANG"], "C");
        assert_eq!(environment["LC_ALL"], "C");
        assert_eq!(environment["TZ"], "UTC");
        assert!(environment["GH_CONFIG_DIR"].starts_with("/proc/self/fd/"));
        assert!(environment["HOME"].starts_with("/tmp/catalog-gh-broker-home-"));
        assert!(!Path::new(environment["HOME"]).exists());
        let descriptors = fixture.snapshot_section("FDS_BEGIN\n", "\nFDS_END");
        assert!(descriptors.contains(fixture.config_dir.to_str().unwrap()));
        assert!(!descriptors.contains(fixture.config.to_str().unwrap()));
        assert!(!descriptors.contains(fixture.executable.to_str().unwrap()));
        assert!(!descriptors.contains("/.ssh/"));
        assert!(!descriptors.contains("/.config/gh"));
    }
}

#[test]
fn upload_and_download_use_retained_descriptors_no_clobber_and_computed_hashes() {
    let upload_fixture = Fixture::new(
        "upload",
        FakeOutput::Success(
            br#"{"id":9,"name":"support.bin","secret":"token","size":12}"#.to_vec(),
        ),
    );
    let input = upload_fixture.root.path("asset-object");
    fs::write(&input, b"asset-canary").unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o400)).unwrap();
    let upload = BrokerRequestV1::UploadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        release_id: "7".to_owned(),
        name: "support.bin".to_owned(),
        input_path: input.to_str().unwrap().to_owned(),
    };
    let response = execute(&upload_fixture, &upload).unwrap();
    assert_eq!(
        response,
        BrokerResponseV1::Asset {
            schema_version: 1,
            asset: broker::BrokerTransferredAssetV1 {
                asset_id: "9".to_owned(),
                name: "support.bin".to_owned(),
                size: 12,
                sha256: sha256(b"asset-canary"),
            },
        }
    );
    assert_eq!(
        upload_fixture.snapshot_section("INPUT_BEGIN\n", "\nINPUT_END"),
        "asset-canary"
    );
    let upload_args = upload_fixture.snapshot_section("ARGS_BEGIN\n", "\nARGS_END");
    assert!(upload_args.contains("/repos/owner/name/releases/7/assets?name=support.bin"));
    assert!(upload_args.contains("Content-Type: application/octet-stream"));
    assert!(
        upload_args
            .lines()
            .last()
            .unwrap()
            .starts_with("/proc/self/fd/")
    );

    let download_fixture = Fixture::new(
        "download",
        FakeOutput::Success(b"downloaded-asset".to_vec()),
    );
    let output = download_fixture.root.path("downloaded.bin");
    let download = BrokerRequestV1::DownloadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        asset_id: "9".to_owned(),
        name: "downloaded.bin".to_owned(),
        output_path: output.to_str().unwrap().to_owned(),
    };
    let response = execute(&download_fixture, &download).unwrap_or_else(|error| {
        panic!(
            "download failed: {error}; snapshot={:?}; output={:?}",
            fs::read_to_string(&download_fixture.snapshot),
            fs::read(&output)
        )
    });
    assert_eq!(fs::read(&output).unwrap(), b"downloaded-asset");
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o7777,
        0o400
    );
    assert_eq!(
        response,
        BrokerResponseV1::Asset {
            schema_version: 1,
            asset: broker::BrokerTransferredAssetV1 {
                asset_id: "9".to_owned(),
                name: "downloaded.bin".to_owned(),
                size: 16,
                sha256: sha256(b"downloaded-asset"),
            },
        }
    );
    let download_args = download_fixture.snapshot_section("ARGS_BEGIN\n", "\nARGS_END");
    assert_eq!(
        download_args.lines().collect::<Vec<_>>(),
        [
            "api",
            "--method",
            "GET",
            "/repos/owner/name/releases/assets/9",
            "--header",
            "Accept: application/octet-stream",
            "--header",
            "X-GitHub-Api-Version: 2022-11-28"
        ]
    );

    let no_clobber = Fixture::new("download-no-clobber", FakeOutput::Success(b"new".to_vec()));
    let existing = no_clobber.root.path("downloaded.bin");
    fs::write(&existing, b"prior").unwrap();
    let request = BrokerRequestV1::DownloadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        asset_id: "9".to_owned(),
        name: "downloaded.bin".to_owned(),
        output_path: existing.to_str().unwrap().to_owned(),
    };
    assert!(execute(&no_clobber, &request).is_err());
    assert_eq!(fs::read(existing).unwrap(), b"prior");

    let failed = Fixture::new(
        "download-failure",
        FakeOutput::Failure {
            stdout: b"credential-canary".to_vec(),
            stderr: b"path-canary".to_vec(),
        },
    );
    let failed_output = failed.root.path("failed.bin");
    let request = BrokerRequestV1::DownloadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        asset_id: "9".to_owned(),
        name: "failed.bin".to_owned(),
        output_path: failed_output.to_str().unwrap().to_owned(),
    };
    assert!(execute(&failed, &request).is_err());
    assert!(!failed_output.exists());
}

#[test]
fn asset_link_mode_and_immediate_pre_spawn_replacement_attacks_fail_closed() {
    let request_for = |path: &Path| BrokerRequestV1::UploadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        release_id: "7".to_owned(),
        name: "support.bin".to_owned(),
        input_path: path.to_str().unwrap().to_owned(),
    };

    let mode = Fixture::new(
        "upload-mode",
        FakeOutput::Success(br#"{"id":9,"name":"support.bin","size":5}"#.to_vec()),
    );
    let input = mode.root.path("input");
    fs::write(&input, b"asset").unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(execute(&mode, &request_for(&input)).is_err());

    let hardlink = Fixture::new(
        "upload-hardlink",
        FakeOutput::Success(br#"{"id":9,"name":"support.bin","size":5}"#.to_vec()),
    );
    let input = hardlink.root.path("input");
    fs::write(&input, b"asset").unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o400)).unwrap();
    fs::hard_link(&input, hardlink.root.path("second-link")).unwrap();
    assert!(execute(&hardlink, &request_for(&input)).is_err());

    struct ReplaceInput {
        path: PathBuf,
        replacement: PathBuf,
    }
    impl BrokerTestCheckpoints for ReplaceInput {
        fn before_spawn(&mut self) {
            fs::rename(&self.path, self.path.with_extension("retained")).unwrap();
            fs::rename(&self.replacement, &self.path).unwrap();
        }
    }
    let raced = Fixture::new(
        "upload-rebind",
        FakeOutput::Success(br#"{"id":9,"name":"support.bin","size":5}"#.to_vec()),
    );
    let input = raced.root.path("input");
    let replacement = raced.root.path("replacement");
    for path in [&input, &replacement] {
        fs::write(path, b"asset").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }
    let mut checkpoint = ReplaceInput {
        path: input.clone(),
        replacement,
    };
    assert!(
        broker::execute_with_test_checkpoints(&raced.config, &request_for(&input), &mut checkpoint)
            .is_err()
    );
    assert!(!raced.snapshot.exists());

    struct ReplaceOutput {
        path: PathBuf,
        replacement: PathBuf,
    }
    impl BrokerTestCheckpoints for ReplaceOutput {
        fn before_spawn(&mut self) {
            fs::rename(&self.path, self.path.with_extension("retained")).unwrap();
            fs::rename(&self.replacement, &self.path).unwrap();
        }
    }
    let raced = Fixture::new("download-rebind", FakeOutput::Success(b"asset".to_vec()));
    let output = raced.root.path("output.bin");
    let replacement = raced.root.path("replacement-output");
    fs::write(&replacement, b"").unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    let request = BrokerRequestV1::DownloadAsset {
        schema_version: 1,
        repository: REPOSITORY.to_owned(),
        asset_id: "9".to_owned(),
        name: "output.bin".to_owned(),
        output_path: output.to_str().unwrap().to_owned(),
    };
    let mut checkpoint = ReplaceOutput {
        path: output.clone(),
        replacement,
    };
    assert!(
        broker::execute_with_test_checkpoints(&raced.config, &request, &mut checkpoint).is_err()
    );
    assert!(output.exists(), "replacement evidence is never unlinked");
    assert!(!raced.snapshot.exists());
}

#[test]
fn config_executable_and_config_directory_identity_hash_mode_and_links_fail_closed() {
    let request = read_tag_request();

    let wrong_hash = Fixture::new("wrong-hash", FakeOutput::Success(tag_json()));
    let mut config: PublisherBrokerConfigV1 =
        serde_json::from_slice(&fs::read(&wrong_hash.config).unwrap()).unwrap();
    config.gh_sha256 = "00".repeat(32);
    write_config(&wrong_hash.config, &config);
    assert!(execute(&wrong_hash, &request).is_err());

    let config_mode = Fixture::new("config-mode", FakeOutput::Success(tag_json()));
    fs::set_permissions(&config_mode.config, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(execute(&config_mode, &request).is_err());

    let exec_mode = Fixture::new("exec-mode", FakeOutput::Success(tag_json()));
    fs::set_permissions(&exec_mode.executable, fs::Permissions::from_mode(0o520)).unwrap();
    assert!(execute(&exec_mode, &request).is_err());

    let dir_mode = Fixture::new("dir-mode", FakeOutput::Success(tag_json()));
    fs::set_permissions(&dir_mode.config_dir, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(execute(&dir_mode, &request).is_err());

    let linked_exec = Fixture::new("exec-hardlink", FakeOutput::Success(tag_json()));
    fs::hard_link(&linked_exec.executable, linked_exec.root.path("other-link")).unwrap();
    assert!(execute(&linked_exec, &request).is_err());

    let linked_config = Fixture::new("config-symlink", FakeOutput::Success(tag_json()));
    let link = linked_config.root.path("config-link");
    symlink(&linked_config.config, &link).unwrap();
    struct Noop;
    impl BrokerTestCheckpoints for Noop {}
    assert!(broker::execute_with_test_checkpoints(&link, &request, &mut Noop).is_err());
}

#[test]
fn executable_and_config_directory_replacement_at_both_race_checkpoints_is_rejected() {
    struct ReplaceAfterHash {
        path: PathBuf,
        replacement: PathBuf,
    }
    impl BrokerTestCheckpoints for ReplaceAfterHash {
        fn after_executable_hash(&mut self) {
            fs::rename(&self.path, self.path.with_extension("retained")).unwrap();
            fs::rename(&self.replacement, &self.path).unwrap();
        }
    }

    let fixture = Fixture::new("replace-after-hash", FakeOutput::Success(tag_json()));
    let replacement = fixture.root.path("replacement-gh");
    fs::copy(&fixture.executable, &replacement).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o500)).unwrap();
    let mut checkpoint = ReplaceAfterHash {
        path: fixture.executable.clone(),
        replacement,
    };
    assert!(
        broker::execute_with_test_checkpoints(
            &fixture.config,
            &read_tag_request(),
            &mut checkpoint
        )
        .is_err()
    );

    let fixture = Fixture::new("replace-config-after-hash", FakeOutput::Success(tag_json()));
    let replacement = fixture.root.path("replacement-config");
    fs::copy(&fixture.config, &replacement).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    let mut checkpoint = ReplaceAfterHash {
        path: fixture.config.clone(),
        replacement,
    };
    assert!(
        broker::execute_with_test_checkpoints(
            &fixture.config,
            &read_tag_request(),
            &mut checkpoint
        )
        .is_err()
    );

    struct ReplaceBeforeSpawn {
        path: PathBuf,
        replacement: PathBuf,
    }
    impl BrokerTestCheckpoints for ReplaceBeforeSpawn {
        fn before_spawn(&mut self) {
            fs::rename(&self.path, self.path.with_extension("retained")).unwrap();
            fs::rename(&self.replacement, &self.path).unwrap();
        }
    }
    let fixture = Fixture::new("replace-exec-before-spawn", FakeOutput::Success(tag_json()));
    let replacement = fixture.root.path("replacement-exec");
    fs::copy(&fixture.executable, &replacement).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o500)).unwrap();
    let mut checkpoint = ReplaceBeforeSpawn {
        path: fixture.executable.clone(),
        replacement,
    };
    assert!(
        broker::execute_with_test_checkpoints(
            &fixture.config,
            &read_tag_request(),
            &mut checkpoint
        )
        .is_err()
    );

    let fixture = Fixture::new("replace-before-spawn", FakeOutput::Success(tag_json()));
    let replacement = fixture.root.path("replacement-config-dir");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&replacement)
        .unwrap();
    let mut checkpoint = ReplaceBeforeSpawn {
        path: fixture.config_dir.clone(),
        replacement,
    };
    assert!(
        broker::execute_with_test_checkpoints(
            &fixture.config,
            &read_tag_request(),
            &mut checkpoint
        )
        .is_err()
    );
}

#[test]
fn child_failures_malformed_output_floods_timeout_and_signal_are_bounded_and_redacted() {
    let cases = [
        FakeOutput::Failure {
            stdout: b"raw-token-canary".to_vec(),
            stderr: b"raw-path-and-request-canary".to_vec(),
        },
        FakeOutput::Success(br#"{"object":{"sha":"raw-token-canary"}"#.to_vec()),
        FakeOutput::Success(format!(
            "{{\"object\":{{\"sha\":\"{COMMIT}\",\"sha\":\"{COMMIT}\",\"type\":\"commit\"}},\"ref\":\"refs/tags/{TAG}\"}}"
        ).into_bytes()),
        FakeOutput::InvalidUtf8,
        FakeOutput::FloodStdout,
        FakeOutput::FloodStderr,
        FakeOutput::Deadlock,
        FakeOutput::Timeout,
        FakeOutput::Signal,
    ];
    for (index, output) in cases.into_iter().enumerate() {
        let fixture = Fixture::new(&format!("bounded-{index}"), output);
        let start = Instant::now();
        let error = execute(&fixture, &read_tag_request()).unwrap_err();
        assert_eq!(error.to_string(), "github broker failed");
        assert!(start.elapsed() < Duration::from_secs(4));
    }
}

#[test]
fn invalid_requests_are_rejected_before_config_or_process_authority() {
    let fixture = Fixture::new("invalid-before-config", FakeOutput::Success(tag_json()));
    fs::remove_file(&fixture.config).unwrap();
    let invalid = BrokerRequestV1::ReadTag {
        schema_version: 1,
        repository: "owner/name;--hostname=evil".to_owned(),
        tag: TAG.to_owned(),
    };
    let error = execute(&fixture, &invalid).unwrap_err();
    assert_eq!(error.to_string(), "github broker failed");
    assert!(!fixture.snapshot.exists());

    for denied in [
        "auth",
        "graphql",
        "--jq",
        "--template",
        "--hostname",
        "http://evil",
        "Authorization: token",
    ] {
        let bytes =
            format!("{{\"kind\":\"{denied}\",\"repository\":\"owner/name\",\"schema_version\":1}}");
        assert!(BrokerRequestV1::from_canonical_bytes(bytes.as_bytes()).is_err());
    }
}

#[test]
fn repeated_and_concurrent_requests_receive_distinct_fresh_homes() {
    let workers = (0..4)
        .map(|index| {
            thread::spawn(move || {
                let fixture = Fixture::new(
                    &format!("concurrent-{index}"),
                    FakeOutput::Success(tag_json()),
                );
                execute(&fixture, &read_tag_request()).unwrap();
                fixture
                    .snapshot_section("ENV_BEGIN\n", "\nENV_END")
                    .lines()
                    .find_map(|line| line.strip_prefix("HOME="))
                    .unwrap()
                    .to_owned()
            })
        })
        .collect::<Vec<_>>();
    let homes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(homes.len(), 4);
    assert!(homes.iter().all(|home| !Path::new(home).exists()));
}

fn run_binary(config: &Path, request: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_catalog-gh-broker"))
        .args(["--config", config.to_str().unwrap()])
        .env("GH_TOKEN", "ambient-gh-token-canary")
        .env("GITHUB_TOKEN", "ambient-github-token-canary")
        .env("HTTPS_PROXY", "ambient-proxy-canary")
        .env("SSH_AUTH_SOCK", "ambient-agent-canary")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(request).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn binary_accepts_only_exact_config_cli_and_emits_canonical_response_or_fixed_error() {
    let fixture = Fixture::new("binary", FakeOutput::Success(tag_json()));
    let request = read_tag_request().to_canonical_bytes().unwrap();
    let output = run_binary(&fixture.config, &request);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let response = BrokerResponseV1::from_canonical_bytes(&output.stdout).unwrap();
    assert_eq!(
        response,
        BrokerResponseV1::Tag {
            schema_version: 1,
            tag: TAG.to_owned(),
            commit_sha: COMMIT.to_owned(),
            object_type: BrokerTagObjectTypeV1::Commit,
        }
    );
    let environment = fixture.snapshot_section("ENV_BEGIN\n", "\nENV_END");
    for denied in [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "HTTPS_PROXY",
        "SSH_AUTH_SOCK",
        "ambient-gh-token-canary",
        "ambient-github-token-canary",
        "ambient-proxy-canary",
        "ambient-agent-canary",
    ] {
        assert!(!environment.contains(denied));
    }

    let child_failure = Fixture::new(
        "binary-child-failure",
        FakeOutput::Failure {
            stdout: b"raw-token-canary".to_vec(),
            stderr: b"raw-path-request-canary".to_vec(),
        },
    );
    let output = run_binary(&child_failure.config, &request);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"github broker failed\n");

    let output = run_binary(
        &fixture.config,
        br#"{"kind":"read_tag","repository":"owner/name","schema_version":1,"tag":"catalog-v1-sequence-1","token":"raw-token-canary"}"#,
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"github broker failed\n");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("raw-token-canary"));

    let output = Command::new(env!("CARGO_BIN_EXE_catalog-gh-broker"))
        .args(["--config", fixture.config.to_str().unwrap(), "extra"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"github broker failed\n");

    assert_eq!(
        BrokerPublicationStatusV1::Published,
        BrokerPublicationStatusV1::Published
    );
}
