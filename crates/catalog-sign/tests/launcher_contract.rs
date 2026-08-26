use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsString},
    fs,
    os::{
        fd::RawFd,
        unix::fs::{DirBuilderExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use catalog_core::{
    CatalogPayloadV1, SignedReleaseBundleManifestV1, canonical_catalog_payload,
    release_bundle_signing_bytes, verify_signed_catalog, verify_signed_release_bundle_manifest,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[allow(dead_code)]
#[path = "../src/bin/catalog-sign-launcher.rs"]
mod launcher_under_test;

#[test]
fn launcher_cli_is_a_closed_ordered_ceremony() {
    let launcher = env!("CARGO_BIN_EXE_catalog-sign-launcher");
    for arguments in [
        vec![],
        vec!["assemble-intent"],
        vec![
            "assemble-intent",
            "--input",
            "/tmp/input",
            "--config",
            "/tmp/config",
            "--output",
            "/tmp/output",
        ],
        vec![
            "sign",
            "--config",
            "/tmp/config",
            "--input",
            "/tmp/input",
            "--output",
            "/tmp/output",
        ],
        vec![
            "finalize",
            "--config",
            "/tmp/config",
            "--input",
            "/tmp/input",
            "--key",
            "/tmp/key",
            "--output",
            "/tmp/output",
        ],
        vec![
            "shell",
            "--config",
            "/tmp/config",
            "--input",
            "/tmp/input",
            "--output",
            "/tmp/output",
        ],
    ] {
        let output = Command::new(launcher).args(arguments).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"catalog signing launcher failed\n");
    }
}

#[test]
fn real_launcher_authenticates_static_signer_and_transfer_before_isolated_failure() {
    let root = TempRoot::new();
    let input = root.path.join("input");
    write_transfer(&input);
    let static_source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-linux-musl/release/catalog-sign")
        .canonicalize()
        .expect("build the authorized musl signer before this integration test");
    let signer = root.path.join("catalog-sign-static");
    fs::copy(static_source, &signer).unwrap();
    fs::set_permissions(&signer, fs::Permissions::from_mode(0o500)).unwrap();
    let config = root.path.join("launcher-config-v1.json");
    write_config(&config, &signer, &sha256(&fs::read(&signer).unwrap()));
    let output = root.path.join("output");

    let result = Command::new(env!("CARGO_BIN_EXE_catalog-sign-launcher"))
        .args([
            "assemble-intent",
            "--config",
            config.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !result.status.success(),
        "synthetic intent must not gain production admission"
    );
    assert!(result.stdout.is_empty());
    assert_eq!(result.stderr, b"catalog signing launcher failed\n");
    assert!(
        output.is_dir(),
        "valid static/config/input checks did not reach the isolated ceremony: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read_dir(&output).unwrap().count(), 0);

    let fixture_key = root.path.join("nonproduction-fixture-key.pem");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/nonproduction-ed25519-pkcs8.pem"),
        &fixture_key,
    )
    .unwrap();
    fs::set_permissions(&fixture_key, fs::Permissions::from_mode(0o400)).unwrap();
    let sign_output = root.path.join("sign-output");
    let sign_result = Command::new(env!("CARGO_BIN_EXE_catalog-sign-launcher"))
        .args([
            "sign",
            "--config",
            config.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--key",
            fixture_key.to_str().unwrap(),
            "--output",
            sign_output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!sign_result.status.success());
    assert!(sign_result.stdout.is_empty());
    assert_eq!(sign_result.stderr, b"catalog signing launcher failed\n");
    assert!(
        sign_output.is_dir(),
        "sign-mode fixture plumbing did not reach isolation"
    );
    assert_eq!(fs::read_dir(&sign_output).unwrap().count(), 0);

    let dynamic = root.path.join("dynamic-signer");
    fs::copy(env!("CARGO_BIN_EXE_catalog-sign"), &dynamic).unwrap();
    fs::set_permissions(&dynamic, fs::Permissions::from_mode(0o500)).unwrap();
    let dynamic_config = root.path.join("dynamic-config-v1.json");
    write_config(
        &dynamic_config,
        &dynamic,
        &sha256(&fs::read(&dynamic).unwrap()),
    );
    let rejected_output = root.path.join("dynamic-output");
    let rejected = Command::new(env!("CARGO_BIN_EXE_catalog-sign-launcher"))
        .args([
            "assemble-intent",
            "--config",
            dynamic_config.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--output",
            rejected_output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        !rejected_output.exists(),
        "dynamic signer was admitted before output visibility"
    );

    let substituted = root.path.join("substituted-config-v1.json");
    write_config(&substituted, &signer, &"00".repeat(32));
    let substituted_output = root.path.join("substituted-output");
    let rejected = Command::new(env!("CARGO_BIN_EXE_catalog-sign-launcher"))
        .args([
            "finalize",
            "--config",
            substituted.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--output",
            substituted_output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(
        !substituted_output.exists(),
        "signer hash substitution reached output visibility"
    );
}

#[test]
fn fixture_authority_signs_through_real_launcher_and_reverse_transfer() {
    let root = TempRoot::new();
    let input = root.path.join("input");
    let fixture_object = b"fixture-authority-retained-object";
    write_transfer_with_object(&input, fixture_object);
    let signer_source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-linux-musl/release/catalog-sign-fixture")
        .canonicalize()
        .expect("build the static fixture signer before this integration test");
    let signer = root.path.join("catalog-sign-fixture-static");
    fs::copy(signer_source, &signer).unwrap();
    fs::set_permissions(&signer, fs::Permissions::from_mode(0o500)).unwrap();
    let config = root.path.join("fixture-launcher-config-v1.json");
    write_config(&config, &signer, &sha256(&fs::read(&signer).unwrap()));
    let key = root.path.join("nonproduction-fixture-key.pem");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/nonproduction-ed25519-pkcs8.pem"),
        &key,
    )
    .unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
    let output = root.path.join("fixture-output");

    let first = launch_sign(&config, &input, &key, &output);
    assert!(
        first.status.success(),
        "fixture journey failed: stdout={} stderr={} output_exists={} output_names={:?}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
        output.exists(),
        output.is_dir().then(|| fs::read_dir(&output)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>())
    );
    assert_eq!(first.stdout, b"catalog signer completed\n");
    assert!(first.stderr.is_empty());
    verify_fixture_reverse_transfer(&output, &input, fixture_object);

    let first_snapshot = snapshot_tree(&output);
    let second = launch_sign(&config, &input, &key, &output);
    assert!(
        !second.status.success(),
        "no-clobber retry unexpectedly succeeded"
    );
    assert_eq!(snapshot_tree(&output), first_snapshot);

    let recovery_key_witness = InotifyKeyOpenWitness::new(&key);
    let recovered = launch_recover(&config, &input, &output);
    assert!(
        recovered.status.success(),
        "exact completed recovery failed: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(!recovery_key_witness.observed_open());
    assert_eq!(snapshot_tree(&output), first_snapshot);

    let alternate_signer = root.path.join("alternate-fixture-signer");
    fs::copy(&signer, &alternate_signer).unwrap();
    fs::set_permissions(&alternate_signer, fs::Permissions::from_mode(0o500)).unwrap();
    let alternate_config = root.path.join("alternate-launcher-config-v1.json");
    write_config(
        &alternate_config,
        &alternate_signer,
        &sha256(&fs::read(&alternate_signer).unwrap()),
    );
    assert!(
        !launch_recover(&alternate_config, &input, &output)
            .status
            .success(),
        "recovery admitted a different launcher config/signer identity"
    );
    assert_eq!(snapshot_tree(&output), first_snapshot);
}

#[test]
fn synchronized_signer_substitution_uniquely_converts_fixture_success_to_failure() {
    let baseline = FixtureLaunchSetup::new("baseline");
    let mut noop = CheckpointReplacement::new(Checkpoint::Never, &baseline);
    launcher_under_test::launch_with_test_checkpoints(&baseline.arguments(), &mut noop).unwrap();
    verify_fixture_reverse_transfer(&baseline.output, &baseline.input, baseline.object);

    for checkpoint in [
        Checkpoint::BeforeOpen,
        Checkpoint::AfterOpen,
        Checkpoint::BeforeBind,
    ] {
        let setup = FixtureLaunchSetup::new(checkpoint.label());
        let key_witness = InotifyKeyOpenWitness::new(&setup.key);
        let mut replacement = CheckpointReplacement::new(checkpoint, &setup);
        assert!(
            launcher_under_test::launch_with_test_checkpoints(
                &setup.arguments(),
                &mut replacement,
            )
            .is_err(),
            "{} substitution did not convert the successful fixture ceremony to failure",
            checkpoint.label()
        );
        assert!(replacement.triggered);
        if matches!(checkpoint, Checkpoint::BeforeOpen | Checkpoint::AfterOpen) {
            assert!(
                !key_witness.observed_open(),
                "{} opened the key",
                checkpoint.label()
            );
            assert!(!setup.output.exists());
        } else {
            assert!(setup.output.is_dir());
            assert_eq!(fs::read_dir(&setup.output).unwrap().count(), 0);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Checkpoint {
    Never,
    BeforeOpen,
    AfterOpen,
    BeforeBind,
}

impl Checkpoint {
    const fn label(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::BeforeOpen => "before-open",
            Self::AfterOpen => "after-open",
            Self::BeforeBind => "before-bind",
        }
    }
}

struct CheckpointReplacement {
    checkpoint: Checkpoint,
    signer: PathBuf,
    retained: PathBuf,
    triggered: bool,
}

impl CheckpointReplacement {
    fn new(checkpoint: Checkpoint, setup: &FixtureLaunchSetup) -> Self {
        Self {
            checkpoint,
            signer: setup.signer.clone(),
            retained: setup
                .root
                .path
                .join(format!("retained-{}", checkpoint.label())),
            triggered: false,
        }
    }

    fn replace_if(&mut self, actual: Checkpoint) {
        if self.checkpoint != actual {
            return;
        }
        fs::rename(&self.signer, &self.retained).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_catalog-sign"), &self.signer).unwrap();
        fs::set_permissions(&self.signer, fs::Permissions::from_mode(0o500)).unwrap();
        self.triggered = true;
    }
}

impl launcher_under_test::LauncherTestCheckpoints for CheckpointReplacement {
    fn before_signer_open(&mut self) {
        self.replace_if(Checkpoint::BeforeOpen);
    }

    fn after_signer_open(&mut self) {
        self.replace_if(Checkpoint::AfterOpen);
    }

    fn before_bwrap_bind(&mut self) {
        self.replace_if(Checkpoint::BeforeBind);
    }
}

struct FixtureLaunchSetup {
    root: TempRoot,
    input: PathBuf,
    signer: PathBuf,
    config: PathBuf,
    key: PathBuf,
    output: PathBuf,
    object: &'static [u8],
}

impl FixtureLaunchSetup {
    fn new(label: &str) -> Self {
        const OBJECT: &[u8] = b"fixture-authority-retained-object";
        let root = TempRoot::new();
        let input = root.path.join(format!("{label}-input"));
        write_transfer_with_object(&input, OBJECT);
        let static_source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/x86_64-unknown-linux-musl/release/catalog-sign-fixture")
            .canonicalize()
            .expect("build the static fixture signer before substitution tests");
        let signer = root
            .path
            .join(format!("{label}-catalog-sign-fixture-static"));
        fs::copy(static_source, &signer).unwrap();
        fs::set_permissions(&signer, fs::Permissions::from_mode(0o500)).unwrap();
        let config = root.path.join(format!("{label}-launcher-config-v1.json"));
        write_config(&config, &signer, &sha256(&fs::read(&signer).unwrap()));
        let key = root.path.join(format!("{label}-fixture-key.pem"));
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/nonproduction-ed25519-pkcs8.pem"),
            &key,
        )
        .unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
        let output = root.path.join(format!("{label}-output"));
        Self {
            root,
            input,
            signer,
            config,
            key,
            output,
            object: OBJECT,
        }
    }

    fn arguments(&self) -> Vec<OsString> {
        [
            OsString::from("sign"),
            OsString::from("--config"),
            self.config.as_os_str().to_owned(),
            OsString::from("--input"),
            self.input.as_os_str().to_owned(),
            OsString::from("--key"),
            self.key.as_os_str().to_owned(),
            OsString::from("--output"),
            self.output.as_os_str().to_owned(),
        ]
        .into_iter()
        .collect()
    }
}

struct InotifyKeyOpenWitness {
    descriptor: RawFd,
}

impl InotifyKeyOpenWitness {
    fn new(path: &Path) -> Self {
        // SAFETY: inotify_init1 has no pointer arguments.
        let descriptor = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        assert!(descriptor >= 0);
        let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: descriptor and NUL-terminated path are valid.
        assert!(
            unsafe {
                libc::inotify_add_watch(descriptor, path.as_ptr(), libc::IN_OPEN | libc::IN_ACCESS)
            } >= 0
        );
        Self { descriptor }
    }

    fn observed_open(&self) -> bool {
        let mut buffer = [0_u8; 512];
        // SAFETY: descriptor and writable buffer are valid.
        let read = unsafe { libc::read(self.descriptor, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read >= 0 {
            return read > 0;
        }
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );
        false
    }
}

impl Drop for InotifyKeyOpenWitness {
    fn drop(&mut self) {
        // SAFETY: descriptor is uniquely owned.
        unsafe { libc::close(self.descriptor) };
    }
}

#[test]
fn launcher_source_has_the_fixed_bubblewrap_capability_only() {
    let source = include_str!("../src/bin/catalog-sign-launcher.rs");
    assert!(source.contains("std::process::Command::new"));
    assert!(source.contains("--unshare-all"));
    assert!(source.contains("--unshare-net"));
    assert!(source.contains("--clearenv"));
    assert!(source.contains("--seccomp"));
    assert!(source.contains("--ro-bind-fd"));
    assert!(source.contains("--bind-fd"));
    assert!(!source.contains("sh -c"));
    assert!(!source.contains("/bin/sh"));
}

fn launch_recover(config: &Path, input: &Path, output: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_catalog-sign-launcher"))
        .args([
            "recover-sign",
            "--config",
            config.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap()
}

fn launch_sign(config: &Path, input: &Path, key: &Path, output: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_catalog-sign-launcher"))
        .args([
            "sign",
            "--config",
            config.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap()
}

fn verify_fixture_reverse_transfer(output: &Path, input: &Path, fixture_object: &[u8]) {
    let reverse_bytes = fs::read(output.join("transfer-manifest-v1.json")).unwrap();
    let reverse: Value = serde_json::from_slice(&reverse_bytes).unwrap();
    assert_eq!(serde_jcs::to_vec(&reverse).unwrap(), reverse_bytes);
    assert_eq!(reverse["schema_version"], 1);
    assert_eq!(reverse["kind"], "signer_output");
    assert_eq!(
        reverse["input_transfer_sha256"],
        sha256(&fs::read(input.join("transfer-manifest-v1.json")).unwrap())
    );
    assert_eq!(reverse["isolation_attestation"]["mode"], "sign");
    let entries = reverse["entries"].as_array().unwrap();
    let expected_paths = entries
        .iter()
        .map(|entry| entry["relative_path"].as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    let actual_paths = collect_regular_paths(output);
    assert_eq!(
        actual_paths,
        expected_paths
            .iter()
            .cloned()
            .chain(["transfer-manifest-v1.json".to_owned()])
            .collect()
    );
    for entry in entries {
        let relative = entry["relative_path"].as_str().unwrap();
        assert!(!relative.starts_with('/') && !relative.split('/').any(|part| part == ".."));
        let path = output.join(relative);
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o400);
        assert_eq!(metadata.len(), entry["size"].as_u64().unwrap());
        assert_eq!(sha256(&fs::read(path).unwrap()), entry["sha256"]);
    }

    let bundle = output.join("signed-release-bundle");
    let catalog_bytes = fs::read(bundle.join("catalog-v1.json")).unwrap();
    let manifest_bytes = fs::read(bundle.join("signed-release-bundle-manifest-v1.json")).unwrap();
    assert!(verify_signed_catalog(&catalog_bytes).is_err());
    assert!(verify_signed_release_bundle_manifest(&manifest_bytes).is_err());
    verify_fixture_catalog(&catalog_bytes);
    verify_fixture_manifest(&manifest_bytes);
    let envelope: Value = serde_json::from_slice(&catalog_bytes).unwrap();
    let actual_payload =
        CatalogPayloadV1::from_json(&serde_json::to_vec(&envelope["payload"]).unwrap()).unwrap();
    let expected_payload = CatalogPayloadV1::from_json(include_bytes!(
        "../../../conformance/catalog-v1/valid-payload.json"
    ))
    .unwrap();
    assert_eq!(
        canonical_catalog_payload(&actual_payload).unwrap(),
        canonical_catalog_payload(&expected_payload).unwrap()
    );
    let asset = format!("fixture-asset-{}.bin", sha256(fixture_object));
    assert_eq!(fs::read(bundle.join(asset)).unwrap(), fixture_object);
}

fn verify_fixture_catalog(bytes: &[u8]) {
    let envelope: Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(envelope["key_id"], "catalog-test-key-v1");
    let payload =
        CatalogPayloadV1::from_json(&serde_json::to_vec(&envelope["payload"]).unwrap()).unwrap();
    fixture_public_key()
        .verify_strict(
            &canonical_catalog_payload(&payload).unwrap(),
            &Signature::from_bytes(&decode_signature(envelope["signature"].as_str().unwrap())),
        )
        .unwrap();
}

fn verify_fixture_manifest(bytes: &[u8]) {
    let manifest = SignedReleaseBundleManifestV1::from_json(bytes).unwrap();
    assert_eq!(
        manifest.signature().key_id().as_str(),
        "catalog-test-key-v1"
    );
    fixture_public_key()
        .verify_strict(
            &release_bundle_signing_bytes(&manifest).unwrap(),
            &Signature::from_bytes(&decode_signature(manifest.signature().signature().as_str())),
        )
        .unwrap();
}

fn fixture_public_key() -> VerifyingKey {
    VerifyingKey::from_bytes(&[
        0x1b, 0xd3, 0x6a, 0xfe, 0xe9, 0x32, 0x3f, 0x1e, 0x38, 0x13, 0xf6, 0x8c, 0x4d, 0x5f, 0x2f,
        0x2b, 0x1b, 0xae, 0x44, 0xc0, 0xef, 0x69, 0x17, 0x62, 0x8e, 0xd6, 0xaf, 0xe1, 0x6a, 0xae,
        0x44, 0xa9,
    ])
    .unwrap()
}

fn decode_signature(value: &str) -> [u8; 64] {
    let decode = |byte| match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => panic!("invalid fixture signature"),
    };
    let mut output = Vec::new();
    for chunk in value.as_bytes().chunks(4) {
        let a = decode(chunk[0]);
        let b = decode(chunk[1]);
        output.push((a << 2) | (b >> 4));
        if chunk.len() >= 3 {
            let c = decode(chunk[2]);
            output.push((b << 4) | (c >> 2));
            if chunk.len() == 4 {
                output.push((c << 6) | decode(chunk[3]));
            }
        }
    }
    output.try_into().unwrap()
}

fn collect_regular_paths(root: &Path) -> BTreeSet<String> {
    fn visit(root: &Path, relative: &Path, output: &mut BTreeSet<String>) {
        for entry in fs::read_dir(root.join(relative)).unwrap() {
            let entry = entry.unwrap();
            let child = relative.join(entry.file_name());
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
                visit(root, &child, output);
            } else {
                output.insert(child.to_string_lossy().into_owned());
            }
        }
    }
    let mut output = BTreeSet::new();
    visit(root, Path::new(""), &mut output);
    output
}

fn snapshot_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    collect_regular_paths(root)
        .into_iter()
        .map(|relative| {
            let bytes = fs::read(root.join(&relative)).unwrap();
            (relative, bytes)
        })
        .collect()
}

fn write_transfer(path: &Path) {
    write_transfer_with_object(path, b"object");
}

fn write_transfer_with_object(path: &Path, object: &[u8]) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    for directory in ["objects", "records"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.join(directory))
            .unwrap();
    }
    let object_digest = sha256(object);
    write_read_only(&path.join(format!("objects/{object_digest}")), object);
    let mut entries = vec![json!({
        "relative_path": format!("objects/{object_digest}"),
        "mode": "0400",
        "size": object.len() as u64,
        "sha256": object_digest,
    })];
    let mut records = Vec::new();
    for (role, bytes) in [
        ("catalog_source", b"fixture source".as_slice()),
        ("package_inputs", b"inputs".as_slice()),
        ("qualification", b"fixture qualification".as_slice()),
    ] {
        let digest = sha256(bytes);
        let relative = format!("records/{digest}");
        write_read_only(&path.join(&relative), bytes);
        entries.push(json!({"relative_path": relative, "mode": "0400", "size": bytes.len() as u64, "sha256": digest}));
        records.push(json!({"role": role, "relative_path": relative, "sha256": digest}));
    }
    let inventory = serde_jcs::to_vec(&json!({
        "schema_version": 1,
        "source_kind": "catalog_source",
        "source_sha256": "11".repeat(32),
        "compatibility_input_sha256": "22".repeat(32),
        "objects": [{
            "relative_path": format!("objects/{object_digest}"),
            "source_url": "https://registry.npmjs.org/object/-/object-1.0.0.tgz",
            "size": object.len() as u64,
            "sha256": object_digest,
        }],
    }))
    .unwrap();
    let inventory_digest = sha256(&inventory);
    write_read_only(&path.join("verified-input-bundle-v1.json"), &inventory);
    entries.push(json!({
        "relative_path": "verified-input-bundle-v1.json",
        "mode": "0400",
        "size": inventory.len() as u64,
        "sha256": inventory_digest,
    }));
    entries.sort_by(|left, right| {
        left["relative_path"]
            .as_str()
            .cmp(&right["relative_path"].as_str())
    });
    let manifest = serde_jcs::to_vec(&json!({
        "schema_version": 1,
        "kind": "verified_input",
        "source_commit": "55".repeat(20),
        "source_tree_sha256": "66".repeat(32),
        "records": records,
        "entries": entries,
    }))
    .unwrap();
    write_read_only(&path.join("transfer-manifest-v1.json"), &manifest);
}

fn write_config(path: &Path, signer: &Path, signer_sha256: &str) {
    let config = serde_jcs::to_vec(&json!({
        "schema_version": 1,
        "bwrap_path": "/usr/bin/bwrap",
        "bwrap_sha256": sha256(&fs::read("/usr/bin/bwrap").unwrap()),
        "signer_path": signer,
        "signer_sha256": signer_sha256,
    }))
    .unwrap();
    fs::write(path, config).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn write_read_only(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "catalog-launcher-contract-{}-{nonce}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
