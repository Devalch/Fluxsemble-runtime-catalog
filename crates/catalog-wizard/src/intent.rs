use std::{
    ffi::CString,
    fs,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
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
        installer_policy: None,
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
    let work = WorkRoot::open(&request.repository_root)?;
    let release = work.open_or_create_release_directory(request.sequence)?;
    let release_root = work_root.join(format!("sequence-{}", request.sequence));
    let intent_path = release_root.join("intent.json");
    let package_inputs_path = release_root.join("package-inputs.json");
    let intent_bytes = serde_jcs::to_vec(&discovered.intent).map_err(|_| WizardError::Discovery)?;
    let package_inputs_bytes = discovered
        .package_inputs
        .canonical_bytes()
        .map_err(|_| WizardError::Discovery)?;
    release.write_no_clobber("intent.json", &intent_bytes)?;
    release.write_no_clobber("package-inputs.json", &package_inputs_bytes)?;

    let reopened_intent_bytes = release.read_regular("intent.json")?;
    let reopened_package_bytes = release.read_regular("package-inputs.json")?;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.permissions().mode() & 0o7777,
        }
    }
}

struct WorkRoot {
    repository: fs::File,
    directory: fs::File,
    identity: DirectoryIdentity,
}

impl WorkRoot {
    fn open(repository_path: &Path) -> Result<Self, WizardError> {
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let repository = options.open(repository_path).map_err(|_| WizardError::Io)?;
        let repository_metadata = repository.metadata().map_err(|_| WizardError::Io)?;
        if !repository_metadata.is_dir()
            || repository_metadata.uid() != current_euid()
            || repository_metadata.permissions().mode() & 0o022 != 0
        {
            return Err(WizardError::Io);
        }
        let name = CString::new(".release-work").expect("fixed work-root name");
        // SAFETY: the retained directory, fixed name, and mode are valid.
        if unsafe { libc::mkdirat(repository.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(WizardError::Io);
            }
        }
        let directory = openat_directory(repository.as_raw_fd(), &name)?;
        let metadata = directory.metadata().map_err(|_| WizardError::Io)?;
        if !private_directory(&metadata) {
            return Err(WizardError::Io);
        }
        let result = Self {
            repository,
            directory,
            identity: DirectoryIdentity::from_metadata(&metadata),
        };
        result.revalidate()?;
        Ok(result)
    }

    fn revalidate(&self) -> Result<(), WizardError> {
        let retained = self.directory.metadata().map_err(|_| WizardError::Io)?;
        let name = CString::new(".release-work").expect("fixed work-root name");
        let named = openat_directory(self.repository.as_raw_fd(), &name)?;
        let named = named.metadata().map_err(|_| WizardError::Io)?;
        if private_directory(&retained)
            && private_directory(&named)
            && DirectoryIdentity::from_metadata(&retained) == self.identity
            && DirectoryIdentity::from_metadata(&named) == self.identity
        {
            Ok(())
        } else {
            Err(WizardError::Io)
        }
    }

    fn open_or_create_release_directory(
        self,
        sequence: u64,
    ) -> Result<ReleaseDirectory, WizardError> {
        self.revalidate()?;
        let name = CString::new(format!("sequence-{sequence}")).map_err(|_| WizardError::Io)?;
        // SAFETY: the retained work root, validated component, and private mode are valid.
        if unsafe { libc::mkdirat(self.directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(WizardError::Io);
            }
        }
        let directory = openat_directory(self.directory.as_raw_fd(), &name)?;
        let metadata = directory.metadata().map_err(|_| WizardError::Io)?;
        if !private_directory(&metadata) {
            return Err(WizardError::Io);
        }
        let release = ReleaseDirectory {
            work: self,
            directory,
            name,
            identity: DirectoryIdentity::from_metadata(&metadata),
        };
        release.revalidate()?;
        Ok(release)
    }
}

struct ReleaseDirectory {
    work: WorkRoot,
    directory: fs::File,
    name: CString,
    identity: DirectoryIdentity,
}

impl ReleaseDirectory {
    fn revalidate(&self) -> Result<(), WizardError> {
        self.work.revalidate()?;
        let retained = self.directory.metadata().map_err(|_| WizardError::Io)?;
        let named = openat_directory(self.work.directory.as_raw_fd(), &self.name)?;
        let named = named.metadata().map_err(|_| WizardError::Io)?;
        if private_directory(&retained)
            && private_directory(&named)
            && DirectoryIdentity::from_metadata(&retained) == self.identity
            && DirectoryIdentity::from_metadata(&named) == self.identity
        {
            Ok(())
        } else {
            Err(WizardError::Io)
        }
    }

    fn write_no_clobber(&self, name: &str, bytes: &[u8]) -> Result<(), WizardError> {
        self.revalidate()?;
        let name = CString::new(name).map_err(|_| WizardError::Io)?;
        // SAFETY: the retained private directory, fixed safe name, flags, and mode are valid.
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(WizardError::Io);
        }
        // SAFETY: successful openat returns one owned descriptor.
        let mut file = unsafe { fs::File::from_raw_fd(descriptor) };
        file.write_all(bytes).map_err(|_| WizardError::Io)?;
        file.sync_all().map_err(|_| WizardError::Io)?;
        let metadata = file.metadata().map_err(|_| WizardError::Io)?;
        if !metadata.is_file()
            || metadata.uid() != current_euid()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err(WizardError::Io);
        }
        self.revalidate()
    }

    fn read_regular(&self, name: &str) -> Result<Vec<u8>, WizardError> {
        self.revalidate()?;
        let name = CString::new(name).map_err(|_| WizardError::Io)?;
        // SAFETY: the retained private directory, fixed safe name, and flags are valid.
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(WizardError::Io);
        }
        // SAFETY: successful openat returns one owned descriptor.
        let mut file = unsafe { fs::File::from_raw_fd(descriptor) };
        let metadata = file.metadata().map_err(|_| WizardError::Io)?;
        if !metadata.is_file()
            || metadata.uid() != current_euid()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.len() == 0
            || metadata.len() > MAX_INPUT_BYTES
        {
            return Err(WizardError::Io);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&mut file)
            .take(MAX_INPUT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| WizardError::Io)?;
        let after = file.metadata().map_err(|_| WizardError::Io)?;
        if bytes.len() as u64 != metadata.len()
            || metadata.dev() != after.dev()
            || metadata.ino() != after.ino()
            || metadata.len() != after.len()
        {
            return Err(WizardError::Io);
        }
        self.revalidate()?;
        Ok(bytes)
    }
}

fn openat_directory(parent: i32, name: &CString) -> Result<fs::File, WizardError> {
    // SAFETY: the retained parent, validated name, and flags are valid.
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(WizardError::Io);
    }
    // SAFETY: successful openat returns one owned descriptor.
    Ok(unsafe { fs::File::from_raw_fd(descriptor) })
}

fn private_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir()
        && metadata.uid() == current_euid()
        && metadata.permissions().mode() & 0o7777 == 0o700
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions or side effects.
    unsafe { libc::geteuid() }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
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

    #[test]
    fn generator_rejects_an_existing_permissive_work_root() {
        let root = temporary_directory();
        let work_root = root.join(".release-work");
        fs::create_dir(&work_root).unwrap();
        fs::set_permissions(&work_root, fs::Permissions::from_mode(0o777)).unwrap();
        let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");

        assert_eq!(
            generate_release_inputs_with(generator_request(&root), |_| fixture_release(
                &fixture_root
            )),
            Err(WizardError::Io)
        );
        assert!(!work_root.join("sequence-1").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retained_work_root_rejects_named_replacement_and_symlink_redirection() {
        let root = temporary_directory();
        let work = WorkRoot::open(&root).unwrap();
        let original = root.join("original-work-root");
        fs::rename(root.join(".release-work"), &original).unwrap();
        let outside = root.join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, root.join(".release-work")).unwrap();

        assert!(work.open_or_create_release_directory(1).is_err());
        assert!(fs::read_dir(&outside).unwrap().next().is_none());
        fs::remove_file(root.join(".release-work")).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    fn generator_request(root: &Path) -> GenerateReleaseInputsRequest {
        GenerateReleaseInputsRequest {
            repository_root: root.to_owned(),
            sequence: 1,
            pi_version: "0.83.0".to_owned(),
            node_version: "22.19.0".to_owned(),
            target: "linux_x86_64".to_owned(),
            generated_at: Utc.with_ymd_and_hms(2026, 8, 26, 0, 0, 0).unwrap(),
            validity_window: Duration::days(31),
        }
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

/// Explicit public consumer policy data, independently imported into this repository.
pub fn load_pi_discovery_policy() -> Result<catalog_acquire::PiInstallerDiscoveryPolicy, WizardError>
{
    parse_pi_discovery_policy(
        include_bytes!("../../../resources/pi/consumer-policy-v1.json"),
        include_bytes!("../../../resources/pi/supported-contracts-v1.json"),
    )
}
fn parse_pi_discovery_policy(
    policy_bytes: &[u8],
    manifest_bytes: &[u8],
) -> Result<catalog_acquire::PiInstallerDiscoveryPolicy, WizardError> {
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct Policy {
        schema_version: u16,
        consumer_requirement: String,
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct Manifest {
        schema_version: u16,
        profile_id: String,
        required_contracts: serde_json::Value,
    }
    if policy_bytes.len() > 64 * 1024 || manifest_bytes.len() > 64 * 1024 {
        return Err(WizardError::Discovery);
    }
    let policy: Policy =
        serde_json::from_slice(policy_bytes).map_err(|_| WizardError::Discovery)?;
    let manifest: Manifest =
        serde_json::from_slice(manifest_bytes).map_err(|_| WizardError::Discovery)?;
    let mut canonical = serde_jcs::to_vec(&policy).map_err(|_| WizardError::Discovery)?;
    canonical.push(b'\n');
    let mut manifest_canonical =
        serde_jcs::to_vec(&manifest).map_err(|_| WizardError::Discovery)?;
    manifest_canonical.push(b'\n');
    if policy.schema_version != 1
        || manifest.schema_version != 1
        || manifest.profile_id != "builtin-pi-installer-lock-contracts-v1"
        || canonical != policy_bytes
        || manifest_canonical != manifest_bytes
    {
        return Err(WizardError::Discovery);
    }
    policy
        .consumer_requirement
        .parse::<catalog_core::CompatibilityRange>()
        .map_err(|_| WizardError::Discovery)?;
    let contracts = catalog_core::PiRequiredContractsV1::from_json(
        &serde_json::to_vec(&manifest.required_contracts).map_err(|_| WizardError::Discovery)?,
    )
    .map_err(|_| WizardError::Discovery)?;
    if catalog_core::pi_required_contracts_profile_sha256(&contracts)
        .map_err(|_| WizardError::Discovery)?
        != <[u8; 32]>::from(Sha256::digest(manifest_bytes))
    {
        return Err(WizardError::Discovery);
    }
    Ok(catalog_acquire::PiInstallerDiscoveryPolicy {
        consumer_requirement: policy.consumer_requirement,
        required_contracts: contracts,
    })
}

pub fn generate_installer_release_inputs(
    request: GenerateReleaseInputsRequest,
    policy: catalog_acquire::PiInstallerDiscoveryPolicy,
) -> Result<GeneratedReleaseInputs, WizardError> {
    generate_installer_release_inputs_with(
        request,
        policy,
        catalog_acquire::discover_pi_installer_release,
    )
}
fn generate_installer_release_inputs_with(
    request: GenerateReleaseInputsRequest,
    policy: catalog_acquire::PiInstallerDiscoveryPolicy,
    discover: impl FnOnce(
        DiscoverPiReleaseRequest,
    ) -> Result<
        catalog_acquire::PiInstallerCandidateV1,
        catalog_acquire::AcquireError,
    >,
) -> Result<GeneratedReleaseInputs, WizardError> {
    if request.sequence == 0
        || request.validity_window <= Duration::zero()
        || request.validity_window > Duration::days(366)
        || request.validity_window != Duration::seconds(request.validity_window.num_seconds())
    {
        return Err(WizardError::Discovery);
    }
    if let Some(existing) = reopen_installer_release_inputs(&request)? {
        return Ok(existing);
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
        pi_version: request.pi_version.clone(),
        node_version: request.node_version.clone(),
        title: format!("Pi {}", request.pi_version),
        notes: DEFAULT_NOTES.into(),
        target: request.target.clone(),
        installer_policy: Some(policy.clone()),
    })
    .map_err(|_| WizardError::Discovery)?;
    let profile = &discovered.profile;
    if profile.pi_package().version().as_str() != request.pi_version
        || profile.node_version().as_str() != request.node_version
        || profile.target().as_str() != request.target
        || profile.consumer_requirement().as_str() != policy.consumer_requirement
        || profile.required_contracts() != &policy.required_contracts
    {
        return Err(WizardError::Discovery);
    }
    discovered
        .inputs
        .validate_for_profile(profile)
        .map_err(|_| WizardError::Discovery)?;
    let intent_value = serde_json::json!({
        "schema_version": 2,
        "sequence": request.sequence.to_string(),
        "tag": format!("catalog-v1-sequence-{}", request.sequence),
        "generated_at": generated_at,
        "expires_at": expires_at,
        "title": format!("Pi {}", request.pi_version),
        "notes": DEFAULT_NOTES,
        "profile": profile,
    });
    let intent = catalog_core::PiReleaseIntentV2::from_json(
        &serde_jcs::to_vec(&intent_value).map_err(|_| WizardError::Discovery)?,
    )
    .map_err(|_| WizardError::Discovery)?;
    let work = WorkRoot::open(&request.repository_root)?;
    let release = work.open_or_create_release_directory(request.sequence)?;
    let intent_bytes = serde_jcs::to_vec(&intent).map_err(|_| WizardError::Discovery)?;
    let input_bytes = discovered
        .inputs
        .canonical_bytes()
        .map_err(|_| WizardError::Discovery)?;
    release.write_no_clobber("intent.json", &intent_bytes)?;
    release.write_no_clobber("package-inputs.json", &input_bytes)?;
    let reopened_intent = release.read_regular("intent.json")?;
    let reopened_inputs = release.read_regular("package-inputs.json")?;
    if reopened_intent != intent_bytes || reopened_inputs != input_bytes {
        return Err(WizardError::Discovery);
    }
    let root = request
        .repository_root
        .join(".release-work")
        .join(format!("sequence-{}", request.sequence));
    Ok(GeneratedReleaseInputs {
        intent_path: root.join("intent.json"),
        package_inputs_path: root.join("package-inputs.json"),
        intent_sha256: sha256(&reopened_intent),
        package_inputs_sha256: sha256(&reopened_inputs),
    })
}

#[cfg(test)]
mod installer_generation_tests {
    use super::*;
    use serde_json::{Value, json};
    use std::os::unix::fs::PermissionsExt;
    fn candidate(
        policy: &catalog_acquire::PiInstallerDiscoveryPolicy,
    ) -> catalog_acquire::PiInstallerCandidateV1 {
        let mut p: Value = serde_json::from_slice(include_bytes!(
            "../../catalog-core/tests/fixtures/catalog/pi-installer-v1/valid-wrapper-root.json"
        ))
        .unwrap();
        p["required_contracts"] = serde_json::to_value(&policy.required_contracts).unwrap();
        p["consumer_requirement"] = json!(policy.consumer_requirement);
        let url = "https://registry.npmjs.org/@earendil-works/pi-coding-agent/-/pi-coding-agent-1.2.0.tgz";
        p["components"][1]["artifacts"][0]["url"] = json!(url);
        p["locked_packages"][0]["resolved_url"] = json!(url);
        for role in ["installer_manifest", "installer_lock", "pi_manifest"] {
            p[role]["url"] = json!(format!(
                "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/catalog-v1-sequence-2/{role}-{}.json",
                p[role]["sha256"].as_str().unwrap()
            ));
        }
        let profile =
            catalog_core::PiReleaseProfileV1::from_json(&serde_jcs::to_vec(&p).unwrap()).unwrap();
        let subject = catalog_core::pi_release_subject_sha256(&profile)
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let package = &p["locked_packages"][0];
        let input = json!({"schema_version":2,"release_subject_sha256":subject,"installer_manifest_source":{"url":"https://github.com/earendil-works/pi/releases/download/v1.2.0/pi-coding-agent-install-package.json","size_bytes":p["installer_manifest"]["size_bytes"],"sha256":p["installer_manifest"]["sha256"]},"installer_lock_source":{"url":"https://github.com/earendil-works/pi/releases/download/v1.2.0/pi-coding-agent-install-package-lock.json","size_bytes":p["installer_lock"]["size_bytes"],"sha256":p["installer_lock"]["sha256"]},"locked_packages":[{"locator":package["locator"],"name":package["name"],"version":package["version"],"resolved_url":package["resolved_url"],"registry_integrity":package["registry_integrity"],"archive_size":1,"archive_sha256":package["archive_sha256"],"declaration_size":1,"declaration_sha256":p["pi_manifest"]["sha256"],"archive_member_count":2,"pruned_reasons":[]}],"pre_prune_package_count":2,"applicable_package_count":1});
        catalog_acquire::PiInstallerCandidateV1 {
            profile,
            inputs: catalog_acquire::PackageInputManifestV2::from_json(
                &serde_jcs::to_vec(&input).unwrap(),
            )
            .unwrap(),
        }
    }
    #[test]
    fn installer_generation_preserves_selected_public_policy_on_resume() {
        let root = std::env::temp_dir().join(format!(
            "wizard-generate-v2-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let policy = load_pi_discovery_policy().unwrap();
        let observed = candidate(&policy);
        let request = GenerateReleaseInputsRequest {
            repository_root: root.clone(),
            sequence: 2,
            pi_version: "1.2.0".into(),
            node_version: "22.19.0".into(),
            target: "linux_x86_64".into(),
            generated_at: DateTime::<Utc>::from(std::time::SystemTime::now()),
            validity_window: Duration::days(31),
        };
        let result = generate_installer_release_inputs_with(request.clone(), policy.clone(), |r| {
            assert_eq!(r.installer_policy, Some(policy.clone()));
            Ok(observed)
        })
        .unwrap();
        let selected = fs::read(&result.intent_path).unwrap();
        let mut changed = policy;
        changed.consumer_requirement = ">=0.2.0".into();
        let resumed = generate_installer_release_inputs_with(request, changed, |_| {
            panic!("resumed intent must not rediscover using current policy")
        })
        .unwrap();
        assert_eq!(selected, fs::read(resumed.intent_path).unwrap());
    }
    #[test]
    fn imported_policy_rejects_unknown_duplicate_and_malformed_contract_manifest() {
        let p = include_bytes!("../../../resources/pi/consumer-policy-v1.json");
        let m = include_bytes!("../../../resources/pi/supported-contracts-v1.json");
        parse_pi_discovery_policy(p, m).unwrap();
        for bytes in [
            b"{\"schema_version\":1,\"schema_version\":1,\"consumer_requirement\":\">=0.1.0\"}\n"
                .as_slice(),
            b"{\"schema_version\":1,\"consumer_requirement\":\"latest\"}\n",
            b"{\"schema_version\":1,\"consumer_requirement\":\">=0.1.0\",\"extra\":1}\n",
        ] {
            assert!(parse_pi_discovery_policy(bytes, m).is_err());
        }
        let mut manifest: Value = serde_json::from_slice(m).unwrap();
        manifest["profile_id"] = json!("other");
        let mut bytes = serde_jcs::to_vec(&manifest).unwrap();
        bytes.push(b'\n');
        assert!(parse_pi_discovery_policy(p, &bytes).is_err());
    }
}

fn reopen_installer_release_inputs(
    request: &GenerateReleaseInputsRequest,
) -> Result<Option<GeneratedReleaseInputs>, WizardError> {
    let root = request
        .repository_root
        .join(".release-work")
        .join(format!("sequence-{}", request.sequence));
    let intent_path = root.join("intent.json");
    let package_inputs_path = root.join("package-inputs.json");
    let exists = |path: &Path| match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(WizardError::Io),
    };
    if !exists(&intent_path)? && !exists(&package_inputs_path)? {
        return Ok(None);
    }
    let work = WorkRoot::open(&request.repository_root)?;
    let release = work.open_or_create_release_directory(request.sequence)?;
    let intent_bytes = release.read_regular("intent.json")?;
    let input_bytes = release.read_regular("package-inputs.json")?;
    let intent = catalog_core::PiReleaseIntentV2::from_json(&intent_bytes)
        .map_err(|_| WizardError::Discovery)?;
    let inputs = catalog_acquire::PackageInputManifestV2::from_json(&input_bytes)
        .map_err(|_| WizardError::Discovery)?;
    inputs
        .validate_for_profile(intent.profile())
        .map_err(|_| WizardError::Discovery)?;
    if intent.sequence() != request.sequence
        || intent.profile().pi_package().version().as_str() != request.pi_version
        || intent.profile().node_version().as_str() != request.node_version
        || intent.profile().target().as_str() != request.target
        || serde_jcs::to_vec(&intent).map_err(|_| WizardError::Discovery)? != intent_bytes
        || inputs
            .canonical_bytes()
            .map_err(|_| WizardError::Discovery)?
            != input_bytes
    {
        return Err(WizardError::Discovery);
    }
    Ok(Some(GeneratedReleaseInputs {
        intent_path,
        package_inputs_path,
        intent_sha256: sha256(&intent_bytes),
        package_inputs_sha256: sha256(&input_bytes),
    }))
}
