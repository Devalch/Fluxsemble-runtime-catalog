use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use catalog_core::{
    CatalogPayloadV1, SignedReleaseBundleManifestV1, canonical_catalog_payload,
    release_bundle_signing_bytes,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const FIXTURE_KEY_ID: &str = "catalog-test-key-v1";
const FIXTURE_PKCS8: &[u8] =
    include_bytes!("../../../catalog-sign/tests/fixtures/nonproduction-ed25519-pkcs8.pem");

pub struct TempTree(pub PathBuf);

impl TempTree {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "catalog-publish-{label}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("create private test root");
        Self(path)
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = make_tree_owner_writable(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn fixture_transfer(root: &Path, sequence: u64, support: &[u8]) {
    let bundle = root.join("signed-release-bundle");
    fs::DirBuilder::new().mode(0o700).create(root).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&bundle).unwrap();

    let signing_key = fixture_signing_key();
    let payload_source = include_bytes!("../../../../conformance/catalog-v1/valid-payload.json");
    let mut payload_value: Value = serde_json::from_slice(payload_source).unwrap();
    payload_value["sequence"] = json!(sequence.to_string());
    let payload =
        CatalogPayloadV1::from_json(&serde_json::to_vec(&payload_value).unwrap()).unwrap();
    let canonical_payload = canonical_catalog_payload(&payload).unwrap();
    let catalog_signature = signing_key.sign(&canonical_payload);
    let canonical_value: Value = serde_json::from_slice(&canonical_payload).unwrap();
    let catalog = serde_jcs::to_vec(&json!({
        "envelope_version": 1,
        "signature_algorithm": "ed25519",
        "key_id": FIXTURE_KEY_ID,
        "payload": canonical_value,
        "signature": base64url(&catalog_signature.to_bytes()),
    }))
    .unwrap();

    let qualification_sha256 = sha256(support);
    let support_name = format!("qualification-{qualification_sha256}.json");
    let unsigned_value = json!({
        "schema_version": 1,
        "source_commit": "0123456789abcdef0123456789abcdef01234567",
        "source_tree_sha256": "11".repeat(32),
        "qualification_sha256": qualification_sha256,
        "tag": format!("catalog-v1-sequence-{sequence}"),
        "catalog_envelope": {
            "name": "catalog-v1.json",
            "size": catalog.len() as u64,
            "sha256": sha256(&catalog),
        },
        "assets": [{
            "name": support_name,
            "size": support.len() as u64,
            "sha256": sha256(support),
        }],
        "signature": {"key_id": FIXTURE_KEY_ID, "signature": "A".repeat(86)},
    });
    let unsigned =
        SignedReleaseBundleManifestV1::from_json(&serde_jcs::to_vec(&unsigned_value).unwrap())
            .unwrap();
    let manifest_signature = signing_key.sign(&release_bundle_signing_bytes(&unsigned).unwrap());
    let mut signed_value = unsigned_value;
    signed_value["signature"]["signature"] = json!(base64url(&manifest_signature.to_bytes()));
    let manifest = serde_jcs::to_vec(&signed_value).unwrap();

    let mut files = BTreeMap::from([
        ("catalog-v1.json".to_owned(), catalog),
        (support_name, support.to_vec()),
        (
            "signed-release-bundle-manifest-v1.json".to_owned(),
            manifest,
        ),
    ]);
    let checksums = files
        .iter()
        .map(|(name, bytes)| format!("{}  {name}\n", sha256(bytes)))
        .collect::<String>()
        .into_bytes();
    files.insert("checksums-sha256.txt".to_owned(), checksums);

    let mut entries = Vec::new();
    for (name, bytes) in &files {
        let path = bundle.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        entries.push(json!({
            "relative_path": format!("signed-release-bundle/{name}"),
            "mode": "0400",
            "size": bytes.len() as u64,
            "sha256": sha256(bytes),
        }));
    }
    let input_digest = "33".repeat(32);
    let attestation = json!({
        "schema_version": 1,
        "mode": "sign",
        "original_operation_mode": "sign",
        "input_transfer_sha256": input_digest,
        "launcher_config_sha256": "44".repeat(32),
        "signer_sha256": "55".repeat(32),
        "no_new_privileges": true,
        "launcher_seccomp_filter": true,
        "launcher_prefilter_errno": {
            "connect": libc::EPERM,
            "execve": libc::ENOENT,
            "fork": libc::EPERM,
            "io_uring_enter": libc::EPERM,
            "io_uring_register": libc::EPERM,
            "io_uring_setup": libc::EPERM,
            "mount": libc::EPERM,
            "move_mount": libc::EPERM,
            "open_tree": libc::EPERM,
            "setns": libc::EPERM,
            "socket": libc::EPERM,
            "umount2": libc::EPERM,
            "unshare": libc::EPERM
        },
        "inner_seccomp_filter": true,
        "core_limit_soft": 0,
        "core_limit_hard": 0,
        "dumpable": false,
        "private_tmpfs_root": true,
        "pid_namespace": "pid:[100]",
        "user_namespace": "user:[101]",
        "mount_namespace": "mnt:[102]",
        "network_namespace": "net:[103]",
        "mount_points": [
            "/", "/bin/catalog-sign", "/dev", "/dev/full", "/dev/null", "/dev/pts",
            "/dev/random", "/dev/tty", "/dev/urandom", "/dev/zero", "/input",
            "/key/runtime-catalog-private.pem", "/output", "/proc", "/tmp"
        ],
        "environment_names": [
            "CATALOG_SIGN_CONFIG_SHA256", "CATALOG_SIGN_EGID", "CATALOG_SIGN_EUID",
            "CATALOG_SIGN_HOST_MOUNT_NS", "CATALOG_SIGN_HOST_NETWORK_NS",
            "CATALOG_SIGN_HOST_PID_NS", "CATALOG_SIGN_HOST_USER_NS",
            "CATALOG_SIGN_INPUT_SHA256", "CATALOG_SIGN_ISOLATION", "CATALOG_SIGN_MODE",
            "CATALOG_SIGN_SIGNER_SHA256", "HOME", "LANG", "LC_ALL", "PATH", "PWD", "TZ"
        ]
    });
    let transfer = serde_jcs::to_vec(&json!({
        "schema_version": 1,
        "kind": "signer_output",
        "input_transfer_sha256": "33".repeat(32),
        "isolation_attestation": attestation,
        "entries": entries,
    }))
    .unwrap();
    let path = root.join("transfer-manifest-v1.json");
    fs::write(&path, transfer).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
}

fn fixture_signing_key() -> SigningKey {
    const BEGIN: &[u8] = b"-----BEGIN PRIVATE KEY-----\n";
    const END: &[u8] = b"\n-----END PRIVATE KEY-----\n";
    const DER_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];

    let body = FIXTURE_PKCS8
        .strip_prefix(BEGIN)
        .and_then(|bytes| bytes.strip_suffix(END))
        .expect("canonical fixture PKCS#8 PEM");
    assert_eq!(body.len(), 64);
    let mut der = [0_u8; 48];
    for (input, output) in body.chunks_exact(4).zip(der.chunks_exact_mut(3)) {
        let a = standard_base64_value(input[0]);
        let b = standard_base64_value(input[1]);
        let c = standard_base64_value(input[2]);
        let d = standard_base64_value(input[3]);
        output[0] = (a << 2) | (b >> 4);
        output[1] = (b << 4) | (c >> 2);
        output[2] = (c << 6) | d;
    }
    assert_eq!(der[..DER_PREFIX.len()], DER_PREFIX);
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&der[DER_PREFIX.len()..]);
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    der.fill(0);
    key
}

fn standard_base64_value(byte: u8) -> u8 {
    match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => panic!("noncanonical fixture PKCS#8 PEM"),
    }
}

pub fn private_directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

pub fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(char::from(ALPHABET[((value >> 18) & 63) as usize]));
        output.push(char::from(ALPHABET[((value >> 12) & 63) as usize]));
        if chunk.len() > 1 {
            output.push(char::from(ALPHABET[((value >> 6) & 63) as usize]));
        }
        if chunk.len() > 2 {
            output.push(char::from(ALPHABET[(value & 63) as usize]));
        }
    }
    output
}

fn make_tree_owner_writable(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            make_tree_owner_writable(&child)?;
            fs::set_permissions(&child, fs::Permissions::from_mode(0o700))?;
        } else if metadata.is_file() {
            fs::set_permissions(&child, fs::Permissions::from_mode(0o600))?;
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}
