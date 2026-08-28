use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use catalog_acquire::{
    DiscoverPiReleaseRequest, DiscoveredPiRelease, PackageInputManifestV1, discover_pi_release,
};
use catalog_core::InitialPiReleaseIntentV1;
use chrono::{DateTime, Duration, SecondsFormat, Timelike, Utc};
use sha2::{Digest, Sha256};

use crate::WizardError;

const DEFAULT_NOTES: &str = "Approved managed Pi release.";
const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateReleaseInputsRequest {
    pub repository_root: PathBuf,
    pub sequence: u64,
    pub pi_version: String,
    pub node_version: String,
    pub target: String,
    pub generated_at: DateTime<Utc>,
    pub validity_window: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedReleaseInputs {
    pub intent_path: PathBuf,
    pub package_inputs_path: PathBuf,
    pub intent_sha256: String,
    pub package_inputs_sha256: String,
}

pub fn generate_release_inputs(
    request: GenerateReleaseInputsRequest,
) -> Result<GeneratedReleaseInputs, WizardError> {
    generate_release_inputs_with(request, discover_pi_release)
}

fn generate_release_inputs_with(
    request: GenerateReleaseInputsRequest,
    discover: impl FnOnce(
        DiscoverPiReleaseRequest,
    ) -> Result<DiscoveredPiRelease, catalog_acquire::AcquireError>,
) -> Result<GeneratedReleaseInputs, WizardError> {
    if request.sequence == 0
        || request.validity_window <= Duration::zero()
        || request.validity_window > Duration::days(366)
        || request.validity_window != Duration::seconds(request.validity_window.num_seconds())
    {
        return Err(WizardError::Discovery);
    }
    let generated_at = request
        .generated_at
        .with_nanosecond(0)
        .ok_or(WizardError::Discovery)?;
    let expires_at = generated_at
        .checked_add_signed(request.validity_window)
        .ok_or(WizardError::Discovery)?;
    let generated_at = generated_at.to_rfc3339_opts(SecondsFormat::Secs, true);
    let expires_at = expires_at.to_rfc3339_opts(SecondsFormat::Secs, true);
    let discovered = discover(DiscoverPiReleaseRequest {
        sequence: request.sequence,
        generated_at: generated_at.clone(),
        expires_at: expires_at.clone(),
        title: format!("Pi {}", request.pi_version),
        notes: DEFAULT_NOTES.to_owned(),
        pi_version: request.pi_version.clone(),
        node_version: request.node_version.clone(),
        target: request.target.clone(),
    })
    .map_err(|_| WizardError::Discovery)?;
    if discovered.intent.sequence().get() != request.sequence
        || discovered.intent.release().pi_version().as_str() != request.pi_version
        || discovered.intent.release().node_version().as_str() != request.node_version
        || discovered.intent.release().target().as_str() != request.target
        || discovered.intent.generated_at().as_str() != generated_at
        || discovered.intent.expires_at().as_str() != expires_at
    {
        return Err(WizardError::Discovery);
    }
    discovered
        .package_inputs
        .validate_for_intent(&discovered.intent)
        .map_err(|_| WizardError::Discovery)?;

    let work_root = request.repository_root.join(".release-work");
    create_private_directory_if_absent(&work_root)?;
    let release_root = work_root.join(format!("sequence-{}", request.sequence));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&release_root)
        .map_err(|_| WizardError::Io)?;
    let intent_path = release_root.join("intent.json");
    let package_inputs_path = release_root.join("package-inputs.json");
    let intent_bytes = serde_jcs::to_vec(&discovered.intent).map_err(|_| WizardError::Discovery)?;
    let package_inputs_bytes = discovered
        .package_inputs
        .canonical_bytes()
        .map_err(|_| WizardError::Discovery)?;
    write_no_clobber(&intent_path, &intent_bytes)?;
    write_no_clobber(&package_inputs_path, &package_inputs_bytes)?;

    let reopened_intent_bytes = read_regular_no_follow(&intent_path)?;
    let reopened_package_bytes = read_regular_no_follow(&package_inputs_path)?;
    let reopened_intent = InitialPiReleaseIntentV1::from_json(&reopened_intent_bytes)
        .map_err(|_| WizardError::Discovery)?;
    let reopened_package = PackageInputManifestV1::from_json(&reopened_package_bytes)
        .map_err(|_| WizardError::Discovery)?;
    reopened_package
        .validate_for_intent(&reopened_intent)
        .map_err(|_| WizardError::Discovery)?;
    if reopened_intent != discovered.intent || reopened_package != discovered.package_inputs {
        return Err(WizardError::Discovery);
    }

    Ok(GeneratedReleaseInputs {
        intent_path,
        package_inputs_path,
        intent_sha256: sha256(&reopened_intent_bytes),
        package_inputs_sha256: sha256(&reopened_package_bytes),
    })
}

fn create_private_directory_if_absent(path: &Path) -> Result<(), WizardError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|_| WizardError::Io)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| WizardError::Io)?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(WizardError::Io)
    }
}

fn write_no_clobber(path: &Path, bytes: &[u8]) -> Result<(), WizardError> {
    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| WizardError::Io)?;
    file.write_all(bytes).map_err(|_| WizardError::Io)?;
    file.sync_all().map_err(|_| WizardError::Io)
}

fn read_regular_no_follow(path: &Path) -> Result<Vec<u8>, WizardError> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| WizardError::Io)?;
    let metadata = file.metadata().map_err(|_| WizardError::Io)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_INPUT_BYTES {
        return Err(WizardError::Io);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| WizardError::Io)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(WizardError::Io);
    }
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use chrono::TimeZone;

    use super::*;

    #[test]
    fn generator_writes_canonical_reopened_inputs_with_second_resolution_timestamps() {
        let root = temporary_directory();
        let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let request = GenerateReleaseInputsRequest {
            repository_root: root.clone(),
            sequence: 1,
            pi_version: "0.83.0".to_owned(),
            node_version: "22.19.0".to_owned(),
            target: "linux_x86_64".to_owned(),
            generated_at: Utc
                .with_ymd_and_hms(2026, 8, 26, 0, 0, 0)
                .unwrap()
                .with_nanosecond(987_000_000)
                .unwrap(),
            validity_window: Duration::days(31),
        };
        let generated = generate_release_inputs_with(request, |_| {
            let intent = InitialPiReleaseIntentV1::from_json(
                &fs::read(fixture_root.join("catalogs/intents/catalog-v1-sequence-1-intent.json"))
                    .unwrap(),
            )
            .unwrap();
            let package_inputs = PackageInputManifestV1::from_json(
                &fs::read(
                    fixture_root.join("catalogs/inputs/pi-0.83.0-linux-x86_64-packages-v1.json"),
                )
                .unwrap(),
            )
            .unwrap();
            Ok(DiscoveredPiRelease {
                intent,
                package_inputs,
            })
        })
        .unwrap();

        assert_eq!(
            fs::read(&generated.intent_path).unwrap(),
            serde_jcs::to_vec(
                &InitialPiReleaseIntentV1::from_json(&fs::read(&generated.intent_path).unwrap())
                    .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            generated.intent_sha256,
            sha256(&fs::read(&generated.intent_path).unwrap())
        );
        assert_eq!(
            generated.package_inputs_sha256,
            sha256(&fs::read(&generated.package_inputs_path).unwrap())
        );
        assert!(
            generate_release_inputs_with(
                GenerateReleaseInputsRequest {
                    repository_root: root.clone(),
                    sequence: 1,
                    pi_version: "0.83.0".to_owned(),
                    node_version: "22.19.0".to_owned(),
                    target: "linux_x86_64".to_owned(),
                    generated_at: Utc.with_ymd_and_hms(2026, 8, 26, 0, 0, 0).unwrap(),
                    validity_window: Duration::days(31),
                },
                |_| fixture_release(&fixture_root),
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn fixture_release(
        fixture_root: &Path,
    ) -> Result<DiscoveredPiRelease, catalog_acquire::AcquireError> {
        let intent = InitialPiReleaseIntentV1::from_json(
            &fs::read(fixture_root.join("catalogs/intents/catalog-v1-sequence-1-intent.json"))
                .unwrap(),
        )
        .unwrap();
        let package_inputs = PackageInputManifestV1::from_json(
            &fs::read(fixture_root.join("catalogs/inputs/pi-0.83.0-linux-x86_64-packages-v1.json"))
                .unwrap(),
        )
        .unwrap();
        Ok(DiscoveredPiRelease {
            intent,
            package_inputs,
        })
    }

    fn temporary_directory() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("catalog-wizard-intent-{unique}"));
        fs::create_dir(&path).unwrap();
        path
    }
}
