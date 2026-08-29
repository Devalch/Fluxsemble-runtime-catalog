use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use catalog_core::{SignedReleaseBundleManifestV1, production_keyring};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    WizardError,
    prompt::{Prompter, require_phrase},
};

const RELEASE_MANIFEST_NAME: &str = "signed-release-bundle-manifest-v1.json";
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_INSPECTION_BYTES: usize = 512;
const MAX_KEYRING_ENTRIES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveSigningKey {
    pub key_id: String,
    pub public_key: String,
    pub generation: u32,
    pub fingerprint: String,
    pub keyring_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationReceipt {
    pub old_key_id: String,
    pub new_key_id: String,
    pub generation: u32,
    pub fingerprint: String,
    pub approved_at: String,
    pub reviewer: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectionOutput {
    key_id: String,
    public_key: String,
    fingerprint: String,
}

#[cfg(test)]
#[derive(Deserialize)]
struct ManifestKey {
    signature: ManifestSignature,
}

#[cfg(test)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestSignature {
    key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewedKeyringV1 {
    schema_version: u16,
    entries: Vec<ReviewedKeyEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewedKeyEntry {
    generation: u32,
    key_id: String,
    public_key: String,
    status: ReviewedKeyStatus,
    activated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReviewedKeyStatus {
    ActiveForSigning,
    VerificationOnly,
    Retired,
}

#[derive(Serialize)]
struct LocalSigningConfig<'a> {
    schema_version: u32,
    signing_key_generation: u32,
    private_key_path: &'a str,
}

pub fn inspect_key_with_isolated_signer(
    private_key_path: &Path,
    launcher_config: &Path,
) -> Result<ActiveSigningKey, WizardError> {
    require_absolute_path(private_key_path)?;
    require_absolute_path(launcher_config)?;
    let launcher = isolated_launcher_path()?;
    let output = Command::new(launcher)
        .args([
            "inspect-key",
            "--config",
            launcher_config.to_str().ok_or(WizardError::Config)?,
            "--key",
            private_key_path.to_str().ok_or(WizardError::Config)?,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| WizardError::ExternalCommand)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(WizardError::ExternalCommand);
    }
    let mut identity = parse_inspection_output(&output.stdout)?;
    identity.generation = production_keyring()
        .active_signing_identity()
        .generation()
        .checked_add(1)
        .ok_or(WizardError::Config)?;
    identity.keyring_sha256 = production_keyring().sha256().to_owned();
    Ok(identity)
}

pub fn verify_active_signing_key(
    private_key_path: &Path,
    launcher_config: &Path,
) -> Result<ActiveSigningKey, WizardError> {
    let inspected = inspect_key_with_isolated_signer(private_key_path, launcher_config)?;
    bind_active_signing_identity(inspected)
}

fn bind_active_signing_identity(
    mut inspected: ActiveSigningKey,
) -> Result<ActiveSigningKey, WizardError> {
    let active = catalog_core::active_production_key_identity();
    if inspected.key_id != active.key_id() || inspected.public_key != active.public_key_base64url()
    {
        return Err(WizardError::Config);
    }
    inspected.generation = active.generation();
    inspected.keyring_sha256 = production_keyring().sha256().to_owned();
    Ok(inspected)
}

pub fn verify_signed_bundle_key(
    bundle_dir: &Path,
    expected: &ActiveSigningKey,
) -> Result<(), WizardError> {
    let path = bundle_dir.join(RELEASE_MANIFEST_NAME);
    let metadata = fs::symlink_metadata(&path).map_err(|_| WizardError::Io)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err(WizardError::Config);
    }
    let bytes = fs::read(path).map_err(|_| WizardError::Io)?;
    let manifest =
        SignedReleaseBundleManifestV1::from_json(&bytes).map_err(|_| WizardError::Config)?;
    if manifest.signature().key_id().as_str() != expected.key_id {
        return Err(WizardError::Config);
    }
    Ok(())
}

pub fn rotate_key(
    prompter: &mut dyn Prompter,
    keyring_path: &Path,
    local_config_path: &Path,
) -> Result<ActiveSigningKey, WizardError> {
    let private_key = PathBuf::from(prompter.ask("New private signing key path: ")?);
    let launcher_config = PathBuf::from(prompter.ask("Isolated signer launcher config path: ")?);
    require_absolute_path(&private_key)?;
    require_absolute_path(&launcher_config)?;

    let mut inspected = inspect_key_with_isolated_signer(&private_key, &launcher_config)?;
    let current_bytes = fs::read(keyring_path).map_err(|_| WizardError::Config)?;
    if sha256(&current_bytes) != production_keyring().sha256() {
        return Err(WizardError::Config);
    }
    let mut keyring: ReviewedKeyringV1 =
        serde_json::from_slice(&current_bytes).map_err(|_| WizardError::Config)?;
    if serde_jcs::to_vec(&keyring).map_err(|_| WizardError::Config)? != current_bytes
        || keyring.schema_version != 1
        || keyring.entries.is_empty()
        || keyring.entries.len() >= MAX_KEYRING_ENTRIES
    {
        return Err(WizardError::Config);
    }
    let active_index = exactly_one_active(&keyring)?;
    let generation = keyring
        .entries
        .iter()
        .map(|entry| entry.generation)
        .max()
        .ok_or(WizardError::Config)?
        .checked_add(1)
        .ok_or(WizardError::Config)?;
    if keyring.entries.iter().any(|entry| {
        entry.key_id == inspected.key_id
            || entry.public_key == inspected.public_key
            || entry.generation == generation
    }) {
        return Err(WizardError::Config);
    }

    prompter.say(&format!(
        "Proposed active key: {} generation {} fingerprint {}",
        inspected.key_id, generation, inspected.fingerprint
    ))?;
    require_phrase(
        prompter,
        "Type ROTATE KEY to write the reviewed proposal and local config: ",
        "ROTATE KEY",
    )?;

    keyring.entries[active_index].status = ReviewedKeyStatus::VerificationOnly;
    keyring.entries.push(ReviewedKeyEntry {
        generation,
        key_id: inspected.key_id.clone(),
        public_key: inspected.public_key.clone(),
        status: ReviewedKeyStatus::ActiveForSigning,
        activated_at: current_timestamp()?,
    });
    keyring.entries.sort_by_key(|entry| entry.generation);
    let proposed_bytes = serde_jcs::to_vec(&keyring).map_err(|_| WizardError::Config)?;
    inspected.generation = generation;
    inspected.keyring_sha256 = sha256(&proposed_bytes);

    let private_path = private_key.to_str().ok_or(WizardError::Config)?;
    let local_bytes = serde_jcs::to_vec(&LocalSigningConfig {
        schema_version: 1,
        signing_key_generation: generation,
        private_key_path: private_path,
    })
    .map_err(|_| WizardError::Config)?;
    atomic_write(local_config_path, &local_bytes, 0o600)?;
    atomic_write(keyring_path, &proposed_bytes, 0o644)?;

    prompter.say(
        "This keyring is a proposal, not publishable authority. Commit and review it, rebuild the signer and verifier, and complete compatibility qualification against the same keyring digest before publishing.",
    )?;
    Ok(inspected)
}

#[cfg(test)]
fn manifest_key_matches(bytes: &[u8], expected: &ActiveSigningKey) -> Result<(), WizardError> {
    let manifest: ManifestKey = serde_json::from_slice(bytes).map_err(|_| WizardError::Config)?;
    if manifest.signature.key_id == expected.key_id {
        Ok(())
    } else {
        Err(WizardError::Config)
    }
}

fn parse_inspection_output(bytes: &[u8]) -> Result<ActiveSigningKey, WizardError> {
    let canonical = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if canonical.is_empty() || canonical.len() > MAX_INSPECTION_BYTES || canonical.contains(&b'\n')
    {
        return Err(WizardError::ExternalCommand);
    }
    let output: InspectionOutput =
        serde_json::from_slice(canonical).map_err(|_| WizardError::ExternalCommand)?;
    if serde_jcs::to_vec(&serde_json::json!({
        "key_id": output.key_id,
        "public_key": output.public_key,
        "fingerprint": output.fingerprint,
    }))
    .map_err(|_| WizardError::ExternalCommand)?
        != canonical
    {
        return Err(WizardError::ExternalCommand);
    }
    let public = decode_public_key(&output.public_key)?;
    let digest = Sha256::digest(public);
    if output.fingerprint != lower_hex(&digest)
        || output.key_id != format!("runtime-catalog-ed25519-{}", lower_hex(&digest[..8]))
    {
        return Err(WizardError::ExternalCommand);
    }
    Ok(ActiveSigningKey {
        key_id: output.key_id,
        public_key: output.public_key,
        generation: 0,
        fingerprint: output.fingerprint,
        keyring_sha256: String::new(),
    })
}

fn exactly_one_active(keyring: &ReviewedKeyringV1) -> Result<usize, WizardError> {
    let active = keyring
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.status == ReviewedKeyStatus::ActiveForSigning)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match active.as_slice() {
        [index] => Ok(*index),
        _ => Err(WizardError::Config),
    }
}

fn current_timestamp() -> Result<String, WizardError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| WizardError::Config)?
        .as_secs();
    let seconds = i64::try_from(seconds).map_err(|_| WizardError::Config)?;
    DateTime::<Utc>::from_timestamp(seconds, 0)
        .map(|time| time.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .ok_or(WizardError::Config)
}

fn isolated_launcher_path() -> Result<PathBuf, WizardError> {
    let current = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| WizardError::ExternalCommand)?;
    let launcher = current
        .parent()
        .ok_or(WizardError::ExternalCommand)?
        .join("catalog-sign-launcher");
    fs::canonicalize(launcher).map_err(|_| WizardError::ExternalCommand)
}

fn require_absolute_path(path: &Path) -> Result<(), WizardError> {
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().len() > 4_096 {
        return Err(WizardError::Config);
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), WizardError> {
    let parent = path.parent().ok_or(WizardError::Io)?;
    let parent_existed = parent.exists();
    fs::create_dir_all(parent).map_err(|_| WizardError::Io)?;
    if mode == 0o600 {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::symlink_metadata(parent).map_err(|_| WizardError::Io)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(WizardError::Io);
        }
        if parent_existed {
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(WizardError::Config);
            }
        } else {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|_| WizardError::Io)?;
        }
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(WizardError::Io)?;
    let temporary = parent.join(format!(".{name}.rotate-key.tmp"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut file = options.open(&temporary).map_err(|_| WizardError::Io)?;
    let result = (|| {
        file.write_all(bytes).map_err(|_| WizardError::Io)?;
        file.flush().map_err(|_| WizardError::Io)?;
        file.sync_all().map_err(|_| WizardError::Io)?;
        fs::rename(&temporary, path).map_err(|_| WizardError::Io)?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| WizardError::Io)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn decode_public_key(value: &str) -> Result<[u8; 32], WizardError> {
    if value.len() != 43 || value.contains('=') {
        return Err(WizardError::ExternalCommand);
    }
    let decode = |byte| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    };
    let mut output = Vec::with_capacity(32);
    for chunk in value.as_bytes().chunks(4) {
        let a = decode(chunk[0]).ok_or(WizardError::ExternalCommand)?;
        let b = decode(chunk[1]).ok_or(WizardError::ExternalCommand)?;
        output.push((a << 2) | (b >> 4));
        if chunk.len() >= 3 {
            let c = decode(chunk[2]).ok_or(WizardError::ExternalCommand)?;
            output.push((b << 4) | (c >> 2));
            if chunk.len() == 4 {
                let d = decode(chunk[3]).ok_or(WizardError::ExternalCommand)?;
                output.push((c << 6) | d);
            } else if c & 0x03 != 0 {
                return Err(WizardError::ExternalCommand);
            }
        }
    }
    output.try_into().map_err(|_| WizardError::ExternalCommand)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_signing_identity_must_match_the_compiled_active_key() {
        let active = catalog_core::active_production_key_identity();
        let matching = ActiveSigningKey {
            key_id: active.key_id().to_owned(),
            public_key: active.public_key_base64url().to_owned(),
            generation: 0,
            fingerprint: lower_hex(&Sha256::digest(active.public_key_bytes())),
            keyring_sha256: String::new(),
        };
        let bound = bind_active_signing_identity(matching).unwrap();
        assert_eq!(bound.generation, active.generation());
        assert_eq!(bound.keyring_sha256, production_keyring().sha256());

        let wrong = ActiveSigningKey {
            key_id: "runtime-catalog-ed25519-wrong".to_owned(),
            public_key: active.public_key_base64url().to_owned(),
            generation: 0,
            fingerprint: String::new(),
            keyring_sha256: String::new(),
        };
        assert!(bind_active_signing_identity(wrong).is_err());
    }

    #[test]
    fn signed_bundle_key_must_match_active_key() {
        let expected = ActiveSigningKey {
            key_id: "runtime-catalog-ed25519-new".to_owned(),
            public_key: "public-key-text".to_owned(),
            generation: 2,
            fingerprint: "abc123".to_owned(),
            keyring_sha256: "11".repeat(32),
        };
        let matching_manifest = br#"{"signature":{"key_id":"runtime-catalog-ed25519-new"}}"#;
        assert!(manifest_key_matches(matching_manifest, &expected).is_ok());

        let wrong_manifest = br#"{"signature":{"key_id":"runtime-catalog-ed25519-old"}}"#;
        assert!(manifest_key_matches(wrong_manifest, &expected).is_err());
    }

    #[test]
    fn isolated_inspection_output_is_canonical_public_identity_only() {
        let bytes = br#"{"fingerprint":"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925","key_id":"runtime-catalog-ed25519-66687aadf862bd77","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let identity = parse_inspection_output(bytes).unwrap();
        assert_eq!(identity.key_id, "runtime-catalog-ed25519-66687aadf862bd77");
        assert_eq!(identity.generation, 0);
        assert!(identity.keyring_sha256.is_empty());

        assert!(
            parse_inspection_output(
                br#"{"key_id":"x","public_key":"y","fingerprint":"z","signature":"forbidden"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn wizard_source_does_not_open_the_private_key() {
        let source = include_str!("key_rotation.rs");
        assert!(!source.contains(&["fs::read(", "private_key_path"].concat()));
        assert!(!source.contains(&["File::open(", "private_key_path"].concat()));
        assert!(source.contains("catalog-sign-launcher"));
        assert!(source.contains("inspect-key"));
    }
}
