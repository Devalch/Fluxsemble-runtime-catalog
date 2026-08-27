use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use catalog_core::production_key_identity;
use serde::Serialize;
use sha2::{Digest, Sha256};

const FIXTURE_KEY_ID: &str = "catalog-test-key-v1";
const MAX_VECTOR_BYTES: u64 = 8 * 1024 * 1024 + 1_024;

#[derive(Serialize)]
struct ManifestV1 {
    schema_version: u16,
    catalog_contract_version: &'static str,
    fixture_key_id: &'static str,
    entries: Vec<ManifestEntry>,
}

#[derive(Serialize)]
struct ManifestEntry {
    path: String,
    size: u64,
    sha256: String,
}

fn main() {
    if run().is_err() {
        eprintln!("catalog fixture generation failed");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 || FIXTURE_KEY_ID == production_key_identity().key_id() {
        return Err(());
    }
    let root = Path::new(&arguments[0]);
    let metadata = fs::symlink_metadata(root).map_err(|_| ())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(());
    }

    for (payload_name, envelope_name) in [
        (
            "initial-exact-candidate-payload.json",
            "initial-exact-candidate-envelope.json",
        ),
        ("valid-payload.json", "valid-envelope.json"),
    ] {
        let payload = read_declared(root, payload_name)?;
        let envelope = catalog_sign::generate_fixture_envelope(&payload).map_err(|_| ())?;
        write_declared(root, envelope_name, &envelope)?;
    }

    let mut entries = [
        "initial-exact-candidate-envelope.json",
        "initial-exact-candidate-payload.json",
        "rejected-fields.json",
        "valid-envelope.json",
        "valid-payload.json",
    ]
    .into_iter()
    .map(|name| {
        let bytes = read_declared(root, name)?;
        Ok(ManifestEntry {
            path: name.to_owned(),
            size: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        })
    })
    .collect::<Result<Vec<_>, ()>>()?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = serde_jcs::to_vec(&ManifestV1 {
        schema_version: 1,
        catalog_contract_version: "catalog-v1",
        fixture_key_id: FIXTURE_KEY_ID,
        entries,
    })
    .map_err(|_| ())?;
    write_declared(root, "manifest-v1.json", &manifest)
}

fn read_declared(root: &Path, name: &str) -> Result<Vec<u8>, ()> {
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|_| ())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_VECTOR_BYTES
    {
        return Err(());
    }
    let bytes = fs::read(path).map_err(|_| ())?;
    if bytes.len() as u64 != metadata.len() {
        return Err(());
    }
    Ok(bytes)
}

fn write_declared(root: &Path, name: &str, bytes: &[u8]) -> Result<(), ()> {
    if !matches!(
        name,
        "initial-exact-candidate-envelope.json" | "valid-envelope.json" | "manifest-v1.json"
    ) || bytes.is_empty()
    {
        return Err(());
    }
    let path = root.join(name);
    if path.exists() {
        let metadata = fs::symlink_metadata(&path).map_err(|_| ())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|_| ())?;
    }
    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(&path).map_err(|_| ())?;
    file.write_all(bytes).map_err(|_| ())?;
    file.flush().map_err(|_| ())?;
    file.set_permissions(fs::Permissions::from_mode(0o444))
        .map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    Ok(())
}
