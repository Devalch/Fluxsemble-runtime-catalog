//! Inert, strictly decoded installer release and qualification records.
//! Parsing does not grant installation, execution, or catalog trust authority.
use super::*;
use sha2::{Digest, Sha256};

pub const MAX_PI_RELEASE_PROFILE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PI_QUALIFICATION_BYTES: usize = 64 * 1024;
pub const PI_INSTALLER_CONTRACT_PROFILE_ID: &str = "builtin-pi-installer-lock-contracts-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PiRequiredContractsV1 {
    installer_policy: u16,
    lockfile_version: u16,
    pi_rpc: u16,
    pi_session: u16,
    execution_payload: u16,
    tool_wire: u16,
    channel_layout: u16,
    native_auth: u16,
    resource_policy_sha256: Sha256Digest,
    tool_policy_sha256: Sha256Digest,
    execution_policy_sha256: Sha256Digest,
}

impl PiRequiredContractsV1 {
    /// Strict inert public contract input; this does not grant compatibility admission.
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require(bytes.len() <= MAX_PI_QUALIFICATION_BYTES)?;
        Self::from_wire(serde_json::from_slice(bytes).map_err(|_| invalid())?)
    }

    fn from_wire(w: PiRequiredContractsWire) -> Result<Self, CoreError> {
        require(
            (
                w.installer_policy,
                w.lockfile_version,
                w.pi_rpc,
                w.pi_session,
                w.execution_payload,
                w.tool_wire,
                w.channel_layout,
                w.native_auth,
            ) == (1, 3, 1, 1, 3, 1, 2, 1),
        )?;
        Ok(Self {
            installer_policy: w.installer_policy,
            lockfile_version: w.lockfile_version,
            pi_rpc: w.pi_rpc,
            pi_session: w.pi_session,
            execution_payload: w.execution_payload,
            tool_wire: w.tool_wire,
            channel_layout: w.channel_layout,
            native_auth: w.native_auth,
            resource_policy_sha256: Sha256Digest::parse(w.resource_policy_sha256)?,
            tool_policy_sha256: Sha256Digest::parse(w.tool_policy_sha256)?,
            execution_policy_sha256: Sha256Digest::parse(w.execution_policy_sha256)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PiReleaseProfileV1 {
    schema_version: u16,
    pi_package: ExactPackageIdentity,
    node_version: ExactVersion,
    target: CatalogTarget,
    consumer_requirement: CompatibilityRange,
    required_contracts: PiRequiredContractsV1,
    installer_root: ExactPackageIdentity,
    pi_package_locator: InventoryPath,
    cli_entrypoint: InventoryPath,
    installer_manifest: ImmutableFileDescriptor,
    installer_lock: ImmutableFileDescriptor,
    pi_manifest: ImmutableFileDescriptor,
    components: Vec<CatalogComponentRecord>,
    pi_component_id: CatalogId,
    pi_artifact_id: CatalogId,
    node_component_id: CatalogId,
    node_artifact_id: CatalogId,
    registry_integrity: RegistryIntegrity,
    locked_packages: Vec<LockedPackageRecord>,
}

impl PiReleaseProfileV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require(bytes.len() <= MAX_PI_RELEASE_PROFILE_BYTES)?;
        let w: PiReleaseProfileWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        let origins = w.origins()?;
        Self::from_wire(w, &origins)
    }

    fn from_wire(w: PiReleaseProfileWire, origins: &[AllowedOrigin]) -> Result<Self, CoreError> {
        require(w.schema_version == 1)?;
        require_bounded_nonempty(&w.components, MAX_COMPONENTS_PER_RELEASE)?;
        require_bounded_nonempty(&w.locked_packages, MAX_LOCKED_PACKAGES)?;
        let result = Self {
            schema_version: w.schema_version,
            pi_package: ExactPackageIdentity::try_from_wire(w.pi_package)?,
            node_version: ExactVersion::parse(w.node_version)?,
            target: CatalogTarget::parse(&w.target)?,
            consumer_requirement: CompatibilityRange::parse(w.consumer_requirement)?,
            required_contracts: PiRequiredContractsV1::from_wire(w.required_contracts)?,
            installer_root: ExactPackageIdentity::try_from_wire(w.installer_root)?,
            pi_package_locator: InventoryPath::parse(w.pi_package_locator)?,
            cli_entrypoint: InventoryPath::parse(w.cli_entrypoint)?,
            installer_manifest: ImmutableFileDescriptor::try_from_wire(
                w.installer_manifest,
                origins,
            )?,
            installer_lock: ImmutableFileDescriptor::try_from_wire(w.installer_lock, origins)?,
            pi_manifest: ImmutableFileDescriptor::try_from_wire(w.pi_manifest, origins)?,
            components: w
                .components
                .into_iter()
                .map(|c| CatalogComponentRecord::try_from_wire(c, origins))
                .collect::<Result<_, _>>()?,
            pi_component_id: CatalogId::parse(w.pi_component_id)?,
            pi_artifact_id: CatalogId::parse(w.pi_artifact_id)?,
            node_component_id: CatalogId::parse(w.node_component_id)?,
            node_artifact_id: CatalogId::parse(w.node_artifact_id)?,
            registry_integrity: RegistryIntegrity::parse(w.registry_integrity)?,
            locked_packages: w
                .locked_packages
                .into_iter()
                .map(|p| LockedPackageRecord::try_from_wire(p, origins))
                .collect::<Result<_, _>>()?,
        };
        result.validate()?;
        require(
            serde_jcs::to_vec(&result).map_err(|_| invalid())?.len()
                <= MAX_PI_RELEASE_PROFILE_BYTES,
        )?;
        Ok(result)
    }

    fn validate(&self) -> Result<(), CoreError> {
        require(self.pi_package.name.as_str() == PI_ROOT_PACKAGE_NAME)?;
        require(self.installer_root.name != self.pi_package.name)?;
        require(
            self.pi_package_locator.as_str()
                == format!("node_modules/{}", self.pi_package.name.as_str()),
        )?;
        require(self.pi_component_id != self.node_component_id)?;
        require_unique(self.components.iter().map(|c| &c.component_id))?;
        require_unique(
            self.components
                .iter()
                .flat_map(|c| &c.artifacts)
                .map(|a| &a.artifact_id),
        )?;
        require(
            self.components
                .windows(2)
                .all(|p| p[0].component_id.as_str() < p[1].component_id.as_str()),
        )?;
        for c in &self.components {
            require(
                c.artifacts
                    .windows(2)
                    .all(|p| p[0].artifact_id.as_str() < p[1].artifact_id.as_str()),
            )?;
        }
        require(
            self.locked_packages
                .windows(2)
                .all(|p| p[0].locator.as_str() < p[1].locator.as_str()),
        )?;
        require_coherent_package_identities(&self.locked_packages)?;
        for package in &self.locked_packages {
            validate_locator(package.locator.as_str(), package.name.as_str())?;
            require(package.name != self.installer_root.name)?;
        }
        let package = self
            .locked_packages
            .iter()
            .find(|p| p.locator == self.pi_package_locator)
            .ok_or(CoreError::InvalidCatalog)?;
        require(
            package.name == self.pi_package.name && package.version == self.pi_package.version,
        )?;
        let pi = self
            .components
            .iter()
            .find(|c| c.component_id == self.pi_component_id)
            .ok_or(CoreError::InvalidCatalog)?;
        require(pi.version == self.pi_package.version)?;
        let archive = pi
            .artifacts
            .iter()
            .find(|a| a.artifact_id == self.pi_artifact_id)
            .ok_or(CoreError::InvalidCatalog)?;
        require(
            archive.sha256 == package.archive_sha256
                && archive.url == package.resolved_url
                && self.registry_integrity == package.registry_integrity,
        )?;
        require(
            archive
                .inventory
                .iter()
                .filter(|i| i.path == self.cli_entrypoint)
                .count()
                == 1,
        )?;
        let node = self
            .components
            .iter()
            .find(|c| c.component_id == self.node_component_id)
            .ok_or(CoreError::InvalidCatalog)?;
        require(node.version == self.node_version)?;
        require(
            node.artifacts
                .iter()
                .any(|a| a.artifact_id == self.node_artifact_id),
        )?;
        Ok(())
    }
}

fn validate_locator(locator: &str, name: &str) -> Result<(), CoreError> {
    let mut rest = locator;
    loop {
        let tail = rest
            .strip_prefix("node_modules/")
            .ok_or(CoreError::InvalidCatalog)?;
        if let Some((parent, next)) = tail.split_once("/node_modules/") {
            PackageName::parse(parent.to_owned())?;
            rest = &tail[parent.len() + 1..];
            require(!next.is_empty())?;
        } else {
            require(tail == name)?;
            return Ok(());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PiInstallerLockMetadataV1 {
    profile: PiReleaseProfileV1,
    qualification: ImmutableFileDescriptor,
}
impl PiInstallerLockMetadataV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require(bytes.len() <= MAX_PI_RELEASE_PROFILE_BYTES + MAX_PI_QUALIFICATION_BYTES)?;
        let w: PiInstallerLockWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        let mut origins = w.profile.origins()?;
        add_origin(&mut origins, &w.qualification.url)?;
        Self::from_wire(w, &origins)
    }
    pub(super) fn from_wire(
        w: PiInstallerLockWire,
        origins: &[AllowedOrigin],
    ) -> Result<Self, CoreError> {
        let profile = PiReleaseProfileV1::from_wire(w.profile, origins)?;
        let qualification = ImmutableFileDescriptor::try_from_wire(w.qualification, origins)?;
        require(qualification.size_bytes.get() <= MAX_PI_QUALIFICATION_BYTES as u64)?;
        Ok(Self {
            profile,
            qualification,
        })
    }
    pub(super) fn validate_release(
        &self,
        version: &ExactVersion,
        components: &[CatalogComponentRecord],
    ) -> Result<(), CoreError> {
        require(
            &self.profile.pi_package.version == version && self.profile.components == components,
        )
    }
}

/// Domain-separated, length-framed JCS of the profile only. The qualification descriptor
/// deliberately lives outside this object so qualification cannot hash itself.
pub fn pi_release_subject_sha256(profile: &PiReleaseProfileV1) -> Result<[u8; 32], CoreError> {
    let bytes = serde_jcs::to_vec(profile).map_err(|_| invalid())?;
    let mut hash = Sha256::new();
    hash.update(b"fluxsemble:pi-release-subject:v1\0");
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    Ok(hash.finalize().into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiQualificationResultV1 {
    Pass,
    Fail,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PiQualificationResultsV1 {
    installation: PiQualificationResultV1,
    sdk_auth: PiQualificationResultV1,
    session_resume: PiQualificationResultV1,
    streaming_tools: PiQualificationResultV1,
    lifecycle: PiQualificationResultV1,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PiVerificationBuildV1 {
    consumer_version: ExactVersion,
    implementation_commit: String,
    application_sha256: Sha256Digest,
    daemon_sha256: Sha256Digest,
    compatibility_profile_id: String,
    compatibility_profile_sha256: Sha256Digest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PiReleaseQualificationV1 {
    schema_version: u16,
    release_subject_sha256: Sha256Digest,
    required_contracts: PiRequiredContractsV1,
    consumer_requirement: CompatibilityRange,
    verification_build: PiVerificationBuildV1,
    results: PiQualificationResultsV1,
}
impl PiReleaseQualificationV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require(bytes.len() <= MAX_PI_QUALIFICATION_BYTES)?;
        let w: PiQualificationWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        require(w.schema_version == 1)?;
        let build = w.verification_build;
        require(
            build.implementation_commit.len() == 40
                && build
                    .implementation_commit
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        )?;
        require(build.compatibility_profile_id == PI_INSTALLER_CONTRACT_PROFILE_ID)?;
        Ok(Self {
            schema_version: w.schema_version,
            release_subject_sha256: Sha256Digest::parse(w.release_subject_sha256)?,
            required_contracts: PiRequiredContractsV1::from_wire(w.required_contracts)?,
            consumer_requirement: CompatibilityRange::parse(w.consumer_requirement)?,
            verification_build: PiVerificationBuildV1 {
                consumer_version: ExactVersion::parse(build.consumer_version)?,
                implementation_commit: build.implementation_commit,
                application_sha256: Sha256Digest::parse(build.application_sha256)?,
                daemon_sha256: Sha256Digest::parse(build.daemon_sha256)?,
                compatibility_profile_id: build.compatibility_profile_id,
                compatibility_profile_sha256: Sha256Digest::parse(
                    build.compatibility_profile_sha256,
                )?,
            },
            results: w.results,
        })
    }
    /// This is evidence inspection, never an executable admission capability.
    pub fn is_complete_pass(&self) -> bool {
        [
            &self.results.installation,
            &self.results.sdk_auth,
            &self.results.session_resume,
            &self.results.streaming_tools,
            &self.results.lifecycle,
        ]
        .iter()
        .all(|r| **r == PiQualificationResultV1::Pass)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PiRequiredContractsWire {
    installer_policy: u16,
    lockfile_version: u16,
    pi_rpc: u16,
    pi_session: u16,
    execution_payload: u16,
    tool_wire: u16,
    channel_layout: u16,
    native_auth: u16,
    resource_policy_sha256: String,
    tool_policy_sha256: String,
    execution_policy_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PiReleaseProfileWire {
    schema_version: u16,
    pi_package: ExactPackageIdentityWire,
    node_version: String,
    target: String,
    consumer_requirement: String,
    required_contracts: PiRequiredContractsWire,
    installer_root: ExactPackageIdentityWire,
    pi_package_locator: String,
    cli_entrypoint: String,
    installer_manifest: ImmutableFileDescriptorWire,
    installer_lock: ImmutableFileDescriptorWire,
    pi_manifest: ImmutableFileDescriptorWire,
    components: Vec<CatalogComponentWire>,
    pi_component_id: String,
    pi_artifact_id: String,
    node_component_id: String,
    node_artifact_id: String,
    registry_integrity: String,
    locked_packages: Vec<LockedPackageWire>,
}
impl PiReleaseProfileWire {
    fn origins(&self) -> Result<Vec<AllowedOrigin>, CoreError> {
        let mut origins = Vec::new();
        for url in [
            &self.installer_manifest.url,
            &self.installer_lock.url,
            &self.pi_manifest.url,
        ]
        .into_iter()
        .chain(
            self.components
                .iter()
                .flat_map(|c| &c.artifacts)
                .map(|a| &a.url),
        )
        .chain(self.locked_packages.iter().map(|p| &p.resolved_url))
        {
            add_origin(&mut origins, url)?;
        }
        Ok(origins)
    }
}
fn add_origin(origins: &mut Vec<AllowedOrigin>, value: &str) -> Result<(), CoreError> {
    let url = HttpsArtifactUrl::parse(value.to_owned())?;
    let parsed = Url::parse(url.as_str()).map_err(|_| invalid())?;
    let origin = AllowedOrigin::parse(parsed.origin().ascii_serialization())?;
    if !origins.contains(&origin) {
        origins.push(origin);
    }
    require(origins.len() <= MAX_ALLOWED_ORIGINS)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PiInstallerLockWire {
    profile: PiReleaseProfileWire,
    qualification: ImmutableFileDescriptorWire,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PiQualificationWire {
    schema_version: u16,
    release_subject_sha256: String,
    required_contracts: PiRequiredContractsWire,
    consumer_requirement: String,
    verification_build: PiVerificationBuildWire,
    results: PiQualificationResultsV1,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PiVerificationBuildWire {
    consumer_version: String,
    implementation_commit: String,
    application_sha256: String,
    daemon_sha256: String,
    compatibility_profile_id: String,
    compatibility_profile_sha256: String,
}

impl PiRequiredContractsV1 {
    #[must_use]
    pub fn installer_policy(&self) -> &u16 {
        &self.installer_policy
    }
    #[must_use]
    pub fn lockfile_version(&self) -> &u16 {
        &self.lockfile_version
    }
    #[must_use]
    pub fn pi_rpc(&self) -> &u16 {
        &self.pi_rpc
    }
    #[must_use]
    pub fn pi_session(&self) -> &u16 {
        &self.pi_session
    }
    #[must_use]
    pub fn execution_payload(&self) -> &u16 {
        &self.execution_payload
    }
    #[must_use]
    pub fn tool_wire(&self) -> &u16 {
        &self.tool_wire
    }
    #[must_use]
    pub fn channel_layout(&self) -> &u16 {
        &self.channel_layout
    }
    #[must_use]
    pub fn native_auth(&self) -> &u16 {
        &self.native_auth
    }
    #[must_use]
    pub fn resource_policy_sha256(&self) -> &Sha256Digest {
        &self.resource_policy_sha256
    }
    #[must_use]
    pub fn tool_policy_sha256(&self) -> &Sha256Digest {
        &self.tool_policy_sha256
    }
    #[must_use]
    pub fn execution_policy_sha256(&self) -> &Sha256Digest {
        &self.execution_policy_sha256
    }
}

impl PiReleaseProfileV1 {
    #[must_use]
    pub fn schema_version(&self) -> &u16 {
        &self.schema_version
    }
    #[must_use]
    pub fn pi_package(&self) -> &ExactPackageIdentity {
        &self.pi_package
    }
    #[must_use]
    pub fn node_version(&self) -> &ExactVersion {
        &self.node_version
    }
    #[must_use]
    pub fn target(&self) -> &CatalogTarget {
        &self.target
    }
    #[must_use]
    pub fn consumer_requirement(&self) -> &CompatibilityRange {
        &self.consumer_requirement
    }
    #[must_use]
    pub fn required_contracts(&self) -> &PiRequiredContractsV1 {
        &self.required_contracts
    }
    #[must_use]
    pub fn installer_root(&self) -> &ExactPackageIdentity {
        &self.installer_root
    }
    #[must_use]
    pub fn pi_package_locator(&self) -> &InventoryPath {
        &self.pi_package_locator
    }
    #[must_use]
    pub fn cli_entrypoint(&self) -> &InventoryPath {
        &self.cli_entrypoint
    }
    #[must_use]
    pub fn installer_manifest(&self) -> &ImmutableFileDescriptor {
        &self.installer_manifest
    }
    #[must_use]
    pub fn installer_lock(&self) -> &ImmutableFileDescriptor {
        &self.installer_lock
    }
    #[must_use]
    pub fn pi_manifest(&self) -> &ImmutableFileDescriptor {
        &self.pi_manifest
    }
    #[must_use]
    pub fn components(&self) -> &Vec<CatalogComponentRecord> {
        &self.components
    }
    #[must_use]
    pub fn pi_component_id(&self) -> &CatalogId {
        &self.pi_component_id
    }
    #[must_use]
    pub fn pi_artifact_id(&self) -> &CatalogId {
        &self.pi_artifact_id
    }
    #[must_use]
    pub fn node_component_id(&self) -> &CatalogId {
        &self.node_component_id
    }
    #[must_use]
    pub fn node_artifact_id(&self) -> &CatalogId {
        &self.node_artifact_id
    }
    #[must_use]
    pub fn registry_integrity(&self) -> &RegistryIntegrity {
        &self.registry_integrity
    }
    #[must_use]
    pub fn locked_packages(&self) -> &Vec<LockedPackageRecord> {
        &self.locked_packages
    }
}

impl PiInstallerLockMetadataV1 {
    #[must_use]
    pub fn profile(&self) -> &PiReleaseProfileV1 {
        &self.profile
    }
    #[must_use]
    pub fn qualification(&self) -> &ImmutableFileDescriptor {
        &self.qualification
    }
}

impl PiVerificationBuildV1 {
    #[must_use]
    pub fn consumer_version(&self) -> &ExactVersion {
        &self.consumer_version
    }
    #[must_use]
    pub fn implementation_commit(&self) -> &String {
        &self.implementation_commit
    }
    #[must_use]
    pub fn application_sha256(&self) -> &Sha256Digest {
        &self.application_sha256
    }
    #[must_use]
    pub fn daemon_sha256(&self) -> &Sha256Digest {
        &self.daemon_sha256
    }
    #[must_use]
    pub fn compatibility_profile_id(&self) -> &String {
        &self.compatibility_profile_id
    }
    #[must_use]
    pub fn compatibility_profile_sha256(&self) -> &Sha256Digest {
        &self.compatibility_profile_sha256
    }
}

impl PiReleaseQualificationV1 {
    #[must_use]
    pub fn schema_version(&self) -> &u16 {
        &self.schema_version
    }
    #[must_use]
    pub fn release_subject_sha256(&self) -> &Sha256Digest {
        &self.release_subject_sha256
    }
    #[must_use]
    pub fn required_contracts(&self) -> &PiRequiredContractsV1 {
        &self.required_contracts
    }
    #[must_use]
    pub fn consumer_requirement(&self) -> &CompatibilityRange {
        &self.consumer_requirement
    }
    #[must_use]
    pub fn verification_build(&self) -> &PiVerificationBuildV1 {
        &self.verification_build
    }
    #[must_use]
    pub fn results(&self) -> &PiQualificationResultsV1 {
        &self.results
    }
}

impl PiQualificationResultsV1 {
    #[must_use]
    pub fn installation(&self) -> &PiQualificationResultV1 {
        &self.installation
    }
    #[must_use]
    pub fn sdk_auth(&self) -> &PiQualificationResultV1 {
        &self.sdk_auth
    }
    #[must_use]
    pub fn session_resume(&self) -> &PiQualificationResultV1 {
        &self.session_resume
    }
    #[must_use]
    pub fn streaming_tools(&self) -> &PiQualificationResultV1 {
        &self.streaming_tools
    }
    #[must_use]
    pub fn lifecycle(&self) -> &PiQualificationResultV1 {
        &self.lifecycle
    }
}
