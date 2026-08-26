use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use catalog_acquire::{
    BundleRecord, PublicBundleObject, VerifiedBundleWriteRequest, export_transfer_bundle,
    verify_transferred_bundle, write_verified_bundle,
};
use catalog_core::InputSourceKind;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn no_clobber_digest_addressed_bundle_is_reopened_before_success() {
    let root = TempRoot::new();
    let bundle = root.path.join("bundle");
    write_fixture_bundle(&bundle);
    let verified = verify_transferred_bundle(&bundle).unwrap();
    assert_eq!(verified.object_count(), 1);
    assert!(verified.total_bytes() > 6);
    assert_eq!(verified.bundle_sha256().len(), 64);
    assert_eq!(mode(&bundle), 0o700);
    let object = object_path(&bundle);
    assert_eq!(mode(&object), 0o400);
    assert_eq!(
        object.file_name().unwrap().to_str().unwrap(),
        sha256(b"object")
    );
    assert!(
        write_request(&bundle).is_err(),
        "nonempty output must not clobber"
    );

    let exported = root.path.join("exported");
    let exported_verified = export_transfer_bundle(&bundle, &exported).unwrap();
    assert_eq!(exported_verified.bundle_sha256(), verified.bundle_sha256());
}

#[test]
fn cli_is_bounded_and_emits_only_stable_safe_output() {
    assert_closed_cli_failure(&[]);
    for arguments in [
        vec!["unknown".to_owned()],
        vec!["verify-bundle".to_owned()],
        vec![
            "verify-bundle".to_owned(),
            "--output".to_owned(),
            "echo-me".to_owned(),
        ],
        vec![
            "verify-public-object".to_owned(),
            "--url".to_owned(),
            "http://example.com/object".to_owned(),
            "--size".to_owned(),
            "01".to_owned(),
            "--sha256".to_owned(),
            "AA".repeat(32),
        ],
        vec![
            "verify-bundle".to_owned(),
            "--bundle".to_owned(),
            "x".repeat(4097),
        ],
        vec!["x".repeat(16 * 1024 + 1)],
        (0..12).map(|index| format!("argument-{index}")).collect(),
    ] {
        assert_closed_cli_failure(&arguments);
    }

    for arguments in [
        vec![
            "discover-inputs",
            "--intent",
            "missing",
            "--output",
            "output",
        ],
        vec![
            "acquire-intent",
            "--intent",
            "missing",
            "--package-inputs",
            "missing",
            "--output",
            "output",
        ],
        vec![
            "acquire-source",
            "--source",
            "missing",
            "--package-inputs",
            "missing",
            "--source-commit",
            "0123456789abcdef0123456789abcdef01234567",
            "--source-tree-sha256",
            "11",
            "--output",
            "output",
        ],
    ] {
        assert_closed_cli_failure(&arguments.into_iter().map(str::to_owned).collect::<Vec<_>>());
    }

    let root = TempRoot::new();
    let bundle = root.path.join("bundle");
    write_fixture_bundle(&bundle);
    let verify = run_cli(&[
        "verify-bundle".to_owned(),
        "--bundle".to_owned(),
        bundle.to_str().unwrap().to_owned(),
    ]);
    assert_safe_success(&verify);

    let exported = root.path.join("exported");
    let export = run_cli(&[
        "export-transfer".to_owned(),
        "--bundle".to_owned(),
        bundle.to_str().unwrap().to_owned(),
        "--output".to_owned(),
        exported.to_str().unwrap().to_owned(),
    ]);
    assert_safe_success(&export);
    assert_eq!(
        verify_transferred_bundle(&bundle).unwrap().bundle_sha256(),
        verify_transferred_bundle(&exported)
            .unwrap()
            .bundle_sha256()
    );
}

#[test]
fn failed_bundle_write_cleans_a_fresh_output_without_clobbering_existing_roots() {
    let root = TempRoot::new();
    let fresh = root.path.join("failed");
    let object_path = root.path.join("source-object");
    fs::write(&object_path, b"object").unwrap();
    fs::set_permissions(&object_path, fs::Permissions::from_mode(0o400)).unwrap();
    let object = fs::File::open(&object_path).unwrap();
    let result = write_verified_bundle(
        VerifiedBundleWriteRequest {
            source_kind: InputSourceKind::ReleaseIntent,
            source_sha256: "11".repeat(32),
            compatibility_input_sha256: "22".repeat(32),
            source_commit: None,
            source_tree_sha256: None,
            records: vec![
                BundleRecord {
                    role: "duplicate".into(),
                    bytes: b"first".to_vec(),
                },
                BundleRecord {
                    role: "duplicate".into(),
                    bytes: b"second".to_vec(),
                },
            ],
            objects: vec![
                PublicBundleObject::verified_file(
                    object,
                    "https://registry.npmjs.org/object/-/object-1.0.0.tgz".into(),
                    6,
                    sha256(b"object"),
                )
                .unwrap(),
            ],
        },
        &fresh,
    );
    assert!(result.is_err());
    assert!(!fresh.exists(), "failed fresh output must be removed");

    let existing = root.path.join("existing");
    fs::DirBuilder::new().mode(0o700).create(&existing).unwrap();
    fs::write(existing.join("sentinel"), b"keep").unwrap();
    assert!(write_request(&existing).is_err());
    assert_eq!(fs::read(existing.join("sentinel")).unwrap(), b"keep");
}

#[test]
fn transfer_rejects_path_mode_owner_link_size_hash_missing_extra_and_replacement() {
    for mutation in [
        Mutation::Path,
        Mutation::ModeField,
        Mutation::FileMode,
        Mutation::Size,
        Mutation::Digest,
        Mutation::Missing,
        Mutation::Extra,
        Mutation::Symlink,
        Mutation::Hardlink,
        Mutation::DirectoryReplacement,
        Mutation::ManifestReplacement,
        Mutation::WritableByOthers,
    ] {
        let root = TempRoot::new();
        let bundle = root.path.join("bundle");
        write_fixture_bundle(&bundle);
        mutate(&bundle, mutation);
        assert!(
            verify_transferred_bundle(&bundle).is_err(),
            "mutation {mutation:?} was accepted"
        );
    }

    let root = TempRoot::new();
    let original = root.path.join("bundle");
    write_fixture_bundle(&original);
    let moved = root.path.join("moved");
    fs::rename(&original, &moved).unwrap();
    symlink(&moved, &original).unwrap();
    assert!(
        verify_transferred_bundle(&original).is_err(),
        "input-root symlink replacement"
    );
}

#[derive(Debug, Clone, Copy)]
enum Mutation {
    Path,
    ModeField,
    FileMode,
    Size,
    Digest,
    Missing,
    Extra,
    Symlink,
    Hardlink,
    DirectoryReplacement,
    ManifestReplacement,
    WritableByOthers,
}

fn write_fixture_bundle(path: &Path) {
    write_request(path).unwrap();
}

fn write_request(
    path: &Path,
) -> Result<catalog_core::VerifiedInputBundleV1, catalog_acquire::AcquireError> {
    let object_path = path.with_extension("source-object");
    if object_path.exists() {
        fs::set_permissions(&object_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(&object_path, b"object").unwrap();
    fs::set_permissions(&object_path, fs::Permissions::from_mode(0o400)).unwrap();
    let object = fs::OpenOptions::new()
        .read(true)
        .open(&object_path)
        .unwrap();
    write_verified_bundle(
        VerifiedBundleWriteRequest {
            source_kind: InputSourceKind::ReleaseIntent,
            source_sha256: "11".repeat(32),
            compatibility_input_sha256: "22".repeat(32),
            source_commit: None,
            source_tree_sha256: None,
            records: vec![
                BundleRecord {
                    role: "package_inputs".into(),
                    bytes: b"inputs".to_vec(),
                },
                BundleRecord {
                    role: "release_intent".into(),
                    bytes: b"intent".to_vec(),
                },
            ],
            objects: vec![PublicBundleObject::verified_file(
                object,
                "https://registry.npmjs.org/object/-/object-1.0.0.tgz".into(),
                6,
                sha256(b"object"),
            )?],
        },
        path,
    )
}

fn mutate(bundle: &Path, mutation: Mutation) {
    let object = object_path(bundle);
    match mutation {
        Mutation::Path => mutate_manifest(bundle, |manifest| {
            manifest["entries"][0]["relative_path"] = Value::String("../escape".into());
        }),
        Mutation::ModeField => mutate_manifest(bundle, |manifest| {
            manifest["entries"][0]["mode"] = Value::String("0600".into());
        }),
        Mutation::FileMode => {
            fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap()
        }
        Mutation::Size => mutate_manifest(bundle, |manifest| {
            let size = manifest["entries"][0]["size"].as_u64().unwrap();
            manifest["entries"][0]["size"] = Value::from(size + 1);
        }),
        Mutation::Digest => mutate_manifest(bundle, |manifest| {
            manifest["entries"][0]["sha256"] = Value::String("aa".repeat(32));
        }),
        Mutation::Missing => fs::remove_file(object).unwrap(),
        Mutation::Extra => {
            fs::write(bundle.join("extra"), b"extra").unwrap();
            fs::set_permissions(bundle.join("extra"), fs::Permissions::from_mode(0o400)).unwrap();
        }
        Mutation::Symlink => {
            fs::remove_file(&object).unwrap();
            symlink("../verified-input-bundle-v1.json", object).unwrap();
        }
        Mutation::Hardlink => {
            fs::hard_link(&object, bundle.with_extension("outside-hardlink")).unwrap();
        }
        Mutation::DirectoryReplacement => {
            fs::remove_file(&object).unwrap();
            fs::remove_dir(bundle.join("objects")).unwrap();
            fs::write(bundle.join("objects"), b"not a directory").unwrap();
        }
        Mutation::ManifestReplacement => {
            let manifest = bundle.join("transfer-manifest-v1.json");
            fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&manifest, b"{}").unwrap();
            fs::set_permissions(manifest, fs::Permissions::from_mode(0o400)).unwrap();
        }
        Mutation::WritableByOthers => {
            fs::set_permissions(object, fs::Permissions::from_mode(0o402)).unwrap()
        }
    }
}

fn mutate_manifest(bundle: &Path, mutation: impl FnOnce(&mut Value)) {
    let path = bundle.join("transfer-manifest-v1.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    mutation(&mut value);
    let bytes = serde_jcs::to_vec(&value).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
}

fn object_path(bundle: &Path) -> PathBuf {
    fs::read_dir(bundle.join("objects"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

fn run_cli(arguments: &[String]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_catalog-acquire"))
        .args(arguments)
        .output()
        .unwrap()
}

fn assert_closed_cli_failure(arguments: &[String]) {
    let output = run_cli(arguments);
    assert!(!output.status.success(), "arguments unexpectedly succeeded");
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"catalog acquisition failed\n");
}

fn assert_safe_success(output: &std::process::Output) {
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(stdout.starts_with("verified bundle_sha256="));
    assert!(stdout.contains(" objects=1 bytes="));
    assert_eq!(stdout.lines().count(), 1);
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct TempRoot {
    path: PathBuf,
}
impl TempRoot {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "catalog-bundle-test-{}-{nanos}",
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
