use std::{collections::BTreeSet, env, fs, path::PathBuf};

use chrono::NaiveDateTime;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const KEYRING_PATH: &str = "../../config/production-signing-keys-v1.json";
const KEY_ID_PREFIX: &str = "runtime-catalog-ed25519-";
const MAX_KEYRING_ENTRIES: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Keyring {
    schema_version: u16,
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    generation: u32,
    key_id: String,
    public_key: String,
    status: Status,
    activated_at: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    ActiveForSigning,
    VerificationOnly,
    Retired,
}

fn main() {
    println!("cargo:rerun-if-changed={KEYRING_PATH}");
    let bytes = fs::read(KEYRING_PATH).expect("read reviewed production signing keyring");
    let keyring: Keyring =
        serde_json::from_slice(&bytes).expect("parse reviewed production signing keyring");
    assert_eq!(
        serde_jcs::to_vec(&keyring_value(&keyring)).expect("canonicalize reviewed keyring"),
        bytes,
        "reviewed production signing keyring must be canonical JSON"
    );
    validate(&keyring);

    let digest = format!("{:x}", Sha256::digest(&bytes));
    let mut generated = format!(
        "pub(crate) const EMBEDDED_KEYRING_SHA256: &str = {digest:?};\n\
         pub(crate) static EMBEDDED_PRODUCTION_KEYS: &[ProductionKeyIdentity] = &[\n"
    );
    for entry in &keyring.entries {
        let public = decode_base64url_32(&entry.public_key).expect("validated public key");
        let status = match entry.status {
            Status::ActiveForSigning => "ProductionKeyStatus::ActiveForSigning",
            Status::VerificationOnly => "ProductionKeyStatus::VerificationOnly",
            Status::Retired => "ProductionKeyStatus::Retired",
        };
        generated.push_str(&format!(
            "ProductionKeyIdentity {{ generation: {}, key_id: {:?}, public_key_base64url: {:?}, public_key: {:?}, status: {}, activated_at: {:?} }},\n",
            entry.generation, entry.key_id, entry.public_key, public, status, entry.activated_at
        ));
    }
    generated.push_str("];\n");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"))
        .join("production_signing_keyring.rs");
    fs::write(output, generated).expect("write embedded production signing keyring");
}

fn validate(keyring: &Keyring) {
    assert_eq!(
        keyring.schema_version, 1,
        "keyring schema_version must be 1"
    );
    assert!(
        !keyring.entries.is_empty() && keyring.entries.len() <= MAX_KEYRING_ENTRIES,
        "reviewed keyring entry count is out of bounds"
    );
    let active = keyring
        .entries
        .iter()
        .filter(|entry| matches!(entry.status, Status::ActiveForSigning))
        .count();
    assert_eq!(
        active, 1,
        "reviewed keyring must contain exactly one active signing key"
    );

    let mut generations = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    for entry in &keyring.entries {
        assert!(entry.generation != 0, "key generation must be nonzero");
        assert!(
            generations.insert(entry.generation),
            "duplicate key generation"
        );
        assert!(ids.insert(entry.key_id.as_str()), "duplicate key ID");
        assert!(
            public_keys.insert(entry.public_key.as_str()),
            "duplicate public key"
        );
        assert!(valid_key_id(&entry.key_id), "malformed production key ID");
        assert!(
            valid_activation_time(&entry.activated_at),
            "malformed activation time"
        );
        let public = decode_base64url_32(&entry.public_key).expect("malformed Ed25519 public key");
        assert_eq!(
            derive_key_id(&public),
            entry.key_id,
            "key ID does not derive from public key"
        );
    }
}

fn keyring_value(keyring: &Keyring) -> serde_json::Value {
    serde_json::json!({
        "schema_version": keyring.schema_version,
        "entries": keyring.entries.iter().map(|entry| serde_json::json!({
            "generation": entry.generation,
            "key_id": entry.key_id,
            "public_key": entry.public_key,
            "status": match entry.status {
                Status::ActiveForSigning => "active_for_signing",
                Status::VerificationOnly => "verification_only",
                Status::Retired => "retired",
            },
            "activated_at": entry.activated_at,
        })).collect::<Vec<_>>()
    })
}

fn valid_key_id(value: &str) -> bool {
    value.len() == KEY_ID_PREFIX.len() + 16
        && value.starts_with(KEY_ID_PREFIX)
        && value[KEY_ID_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_activation_time(value: &str) -> bool {
    const FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";
    value.len() == 20
        && NaiveDateTime::parse_from_str(value, FORMAT)
            .is_ok_and(|timestamp| timestamp.format(FORMAT).to_string() == value)
}

fn derive_key_id(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    format!("{KEY_ID_PREFIX}{}", lower_hex(&digest[..8]))
}

fn decode_base64url_32(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 43 || value.contains('=') {
        return Err(());
    }
    let mut decoded = Vec::with_capacity(32);
    for chunk in value.as_bytes().chunks(4) {
        let a = base64url_value(chunk[0]).ok_or(())?;
        let b = base64url_value(chunk[1]).ok_or(())?;
        decoded.push((a << 2) | (b >> 4));
        if chunk.len() >= 3 {
            let c = base64url_value(chunk[2]).ok_or(())?;
            decoded.push((b << 4) | (c >> 2));
            if chunk.len() == 4 {
                let d = base64url_value(chunk[3]).ok_or(())?;
                decoded.push((c << 6) | d);
            } else if c & 0x03 != 0 {
                return Err(());
            }
        }
    }
    decoded.try_into().map_err(|_| ())
}

fn base64url_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
