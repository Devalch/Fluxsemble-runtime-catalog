use std::{
    collections::{HashMap, HashSet},
    fmt,
    hash::Hash,
    num::NonZeroU64,
};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use url::Url;

use crate::CoreError;

pub const CATALOG_SCHEMA_VERSION: u16 = 1;
pub const MAX_CATALOG_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PROVIDERS: usize = 16;
pub const MAX_RELEASES_PER_PROVIDER: usize = 64;
pub const MAX_COMPONENTS_PER_RELEASE: usize = 16;
pub const MAX_ARTIFACTS_PER_COMPONENT: usize = 8;
pub const MAX_ARTIFACT_URL_BYTES: usize = 2_048;
pub const MAX_RELEASE_TITLE_BYTES: usize = 128;
pub const MAX_RELEASE_NOTES_BYTES: usize = 16_384;
pub const MAX_INVENTORY_ENTRIES_PER_ARTIFACT: usize = 32_768;
pub const MAX_COMPATIBILITY_RANGES: usize = 16;
pub const MAX_COMPATIBILITY_RANGE_BYTES: usize = 128;
pub const MAX_ALLOWED_ORIGINS: usize = 16;
pub const MAX_ALLOWED_ORIGIN_BYTES: usize = 256;
pub const MAX_LOCKED_PACKAGES: usize = 512;
pub const MAX_PACKAGE_NAME_BYTES: usize = 214;
pub const MAX_INVENTORY_PATH_BYTES: usize = 512;

const MAX_EXACT_VERSION_BYTES: usize = 256;
const MAX_JSON_OBJECT_KEY_BYTES: usize = 64;
const MIN_CATALOG_ID_BYTES: usize = 3;
const MAX_CATALOG_ID_BYTES: usize = 191;
const MIN_CATALOG_ID_SEGMENTS: usize = 2;
const MAX_CATALOG_ID_SEGMENTS: usize = 4;
const MAX_CATALOG_ID_SEGMENT_BYTES: usize = 64;
const PI_PROVIDER_ID: &str = "builtin:pi";
const PI_ROOT_PACKAGE_NAME: &str = "@earendil-works/pi-coding-agent";
const CATALOG_TIMESTAMP_BYTES: usize = 20;
const SHA256_HEX_BYTES: usize = 64;
const SHA512_INTEGRITY_BYTES: usize = 95;

/// Validated catalog-v1 payload. Construction is limited to strict JSON admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogPayloadV1 {
    schema_version: u16,
    #[serde(serialize_with = "serialize_nonzero_decimal")]
    sequence: NonZeroU64,
    generated_at: CatalogTimestamp,
    expires_at: CatalogTimestamp,
    compatibility_ranges: Vec<CompatibilityRange>,
    providers: Vec<CatalogProviderRecord>,
}

impl CatalogPayloadV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require(bytes.len() <= MAX_CATALOG_PAYLOAD_BYTES)?;
        reject_duplicate_json(bytes)?;
        let wire: CatalogPayloadWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        Self::try_from_wire(wire)
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn sequence(&self) -> NonZeroU64 {
        self.sequence
    }

    #[must_use]
    pub fn generated_at(&self) -> &CatalogTimestamp {
        &self.generated_at
    }

    #[must_use]
    pub fn expires_at(&self) -> &CatalogTimestamp {
        &self.expires_at
    }

    #[must_use]
    pub fn compatibility_ranges(&self) -> &[CompatibilityRange] {
        &self.compatibility_ranges
    }

    #[must_use]
    pub fn providers(&self) -> &[CatalogProviderRecord] {
        &self.providers
    }

    fn try_from_wire(wire: CatalogPayloadWire) -> Result<Self, CoreError> {
        require(wire.schema_version == CATALOG_SCHEMA_VERSION)?;
        let sequence = parse_nonzero_decimal(&wire.sequence)?;
        let generated_at = CatalogTimestamp::parse(wire.generated_at)?;
        let expires_at = CatalogTimestamp::parse(wire.expires_at)?;
        let compatibility_ranges = parse_ranges(wire.compatibility_ranges)?;
        require_bounded_nonempty(&wire.providers, MAX_PROVIDERS)?;
        let providers = wire
            .providers
            .into_iter()
            .map(CatalogProviderRecord::try_from_wire)
            .collect::<Result<Vec<_>, _>>()?;
        require_strictly_sorted_by(&providers, |left, right| {
            left.provider_id < right.provider_id
        })?;
        Ok(Self {
            schema_version: wire.schema_version,
            sequence,
            generated_at,
            expires_at,
            compatibility_ranges,
            providers,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogProviderRecord {
    provider_id: CatalogId,
    allowed_origins: Vec<AllowedOrigin>,
    releases: Vec<CatalogReleaseRecord>,
}

impl CatalogProviderRecord {
    #[must_use]
    pub fn provider_id(&self) -> &str {
        self.provider_id.as_str()
    }

    #[must_use]
    pub fn allowed_origins(&self) -> &[AllowedOrigin] {
        &self.allowed_origins
    }

    #[must_use]
    pub fn releases(&self) -> &[CatalogReleaseRecord] {
        &self.releases
    }

    fn try_from_wire(wire: CatalogProviderWire) -> Result<Self, CoreError> {
        let provider_id = CatalogId::parse_harness(wire.provider_id)?;
        require_bounded_nonempty(&wire.allowed_origins, MAX_ALLOWED_ORIGINS)?;
        let allowed_origins = wire
            .allowed_origins
            .into_iter()
            .map(AllowedOrigin::parse)
            .collect::<Result<Vec<_>, _>>()?;
        require_unique(allowed_origins.iter())?;
        require_bounded_nonempty(&wire.releases, MAX_RELEASES_PER_PROVIDER)?;
        let releases = wire
            .releases
            .into_iter()
            .map(|release| {
                CatalogReleaseRecord::try_from_wire(release, provider_id.as_str(), &allowed_origins)
            })
            .collect::<Result<Vec<_>, _>>()?;
        require_unique(
            releases
                .iter()
                .map(|release| (&release.version, release.target)),
        )?;
        Ok(Self {
            provider_id,
            allowed_origins,
            releases,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogReleaseRecord {
    version: ExactVersion,
    target: CatalogTarget,
    compatibility_ranges: Vec<CompatibilityRange>,
    release_metadata: PlainTextReleaseMetadata,
    components: Vec<CatalogComponentRecord>,
    provider_extension: ProviderExtensionV1,
}

impl CatalogReleaseRecord {
    #[must_use]
    pub fn version(&self) -> &ExactVersion {
        &self.version
    }

    #[must_use]
    pub const fn target(&self) -> CatalogTarget {
        self.target
    }

    #[must_use]
    pub fn compatibility_ranges(&self) -> &[CompatibilityRange] {
        &self.compatibility_ranges
    }

    #[must_use]
    pub fn release_metadata(&self) -> &PlainTextReleaseMetadata {
        &self.release_metadata
    }

    #[must_use]
    pub fn components(&self) -> &[CatalogComponentRecord] {
        &self.components
    }

    #[must_use]
    pub fn provider_extension(&self) -> &ProviderExtensionV1 {
        &self.provider_extension
    }

    fn try_from_wire(
        wire: CatalogReleaseWire,
        provider_id: &str,
        allowed_origins: &[AllowedOrigin],
    ) -> Result<Self, CoreError> {
        let version = ExactVersion::parse(wire.version)?;
        let target = CatalogTarget::parse(&wire.target)?;
        let compatibility_ranges = parse_ranges(wire.compatibility_ranges)?;
        let release_metadata = PlainTextReleaseMetadata::try_from_wire(wire.release_metadata)?;
        require_bounded_nonempty(&wire.components, MAX_COMPONENTS_PER_RELEASE)?;
        let components = wire
            .components
            .into_iter()
            .map(|component| CatalogComponentRecord::try_from_wire(component, allowed_origins))
            .collect::<Result<Vec<_>, _>>()?;
        require_strictly_sorted_by(&components, |left, right| {
            left.component_id < right.component_id
        })?;
        require_unique(
            components
                .iter()
                .flat_map(|component| component.artifacts.iter())
                .map(|artifact| artifact.artifact_id.as_str()),
        )?;
        let provider_extension = ProviderExtensionV1::try_from_wire(
            wire.provider_extension,
            provider_id,
            &version,
            &components,
            allowed_origins,
        )?;
        Ok(Self {
            version,
            target,
            compatibility_ranges,
            release_metadata,
            components,
            provider_extension,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogComponentRecord {
    component_id: CatalogId,
    version: ExactVersion,
    artifacts: Vec<ArtifactDescriptor>,
}

impl CatalogComponentRecord {
    #[must_use]
    pub fn component_id(&self) -> &CatalogId {
        &self.component_id
    }

    #[must_use]
    pub fn version(&self) -> &ExactVersion {
        &self.version
    }

    #[must_use]
    pub fn artifacts(&self) -> &[ArtifactDescriptor] {
        &self.artifacts
    }

    fn try_from_wire(
        wire: CatalogComponentWire,
        allowed_origins: &[AllowedOrigin],
    ) -> Result<Self, CoreError> {
        let component_id = CatalogId::parse(wire.component_id)?;
        let version = ExactVersion::parse(wire.version)?;
        require_bounded_nonempty(&wire.artifacts, MAX_ARTIFACTS_PER_COMPONENT)?;
        let artifacts = wire
            .artifacts
            .into_iter()
            .map(|artifact| ArtifactDescriptor::try_from_wire(artifact, allowed_origins))
            .collect::<Result<Vec<_>, _>>()?;
        require_strictly_sorted_by(&artifacts, |left, right| {
            left.artifact_id < right.artifact_id
        })?;
        Ok(Self {
            component_id,
            version,
            artifacts,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactDescriptor {
    artifact_id: CatalogId,
    url: HttpsArtifactUrl,
    size_bytes: ByteSize,
    sha256: Sha256Digest,
    inventory: Vec<ArtifactInventoryEntry>,
}

impl ArtifactDescriptor {
    #[must_use]
    pub fn artifact_id(&self) -> &CatalogId {
        &self.artifact_id
    }

    #[must_use]
    pub fn url(&self) -> &HttpsArtifactUrl {
        &self.url
    }

    #[must_use]
    pub const fn size_bytes(&self) -> ByteSize {
        self.size_bytes
    }

    #[must_use]
    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    #[must_use]
    pub fn inventory(&self) -> &[ArtifactInventoryEntry] {
        &self.inventory
    }

    fn try_from_wire(
        wire: ArtifactDescriptorWire,
        allowed_origins: &[AllowedOrigin],
    ) -> Result<Self, CoreError> {
        let artifact_id = CatalogId::parse(wire.artifact_id)?;
        let url = HttpsArtifactUrl::parse(wire.url)?;
        require(origin_allowed(&url, allowed_origins))?;
        let size_bytes = ByteSize::parse(wire.size_bytes)?;
        require(size_bytes.get() != 0)?;
        let sha256 = Sha256Digest::parse(wire.sha256)?;
        require(wire.inventory.len() <= MAX_INVENTORY_ENTRIES_PER_ARTIFACT)?;
        let inventory = wire
            .inventory
            .into_iter()
            .map(ArtifactInventoryEntry::try_from_wire)
            .collect::<Result<Vec<_>, _>>()?;
        require_unique(inventory.iter().map(|entry| &entry.path))?;
        Ok(Self {
            artifact_id,
            url,
            size_bytes,
            sha256,
            inventory,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactInventoryEntry {
    path: InventoryPath,
    size_bytes: ByteSize,
    sha256: Sha256Digest,
}

impl ArtifactInventoryEntry {
    #[must_use]
    pub fn path(&self) -> &InventoryPath {
        &self.path
    }

    #[must_use]
    pub const fn size_bytes(&self) -> ByteSize {
        self.size_bytes
    }

    #[must_use]
    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    fn try_from_wire(wire: ArtifactInventoryWire) -> Result<Self, CoreError> {
        Ok(Self {
            path: InventoryPath::parse(wire.path)?,
            size_bytes: ByteSize::parse(wire.size_bytes)?,
            sha256: Sha256Digest::parse(wire.sha256)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlainTextReleaseMetadata {
    title: BoundedReleaseTitle,
    notes: BoundedReleaseNotes,
}

impl PlainTextReleaseMetadata {
    #[must_use]
    pub fn title(&self) -> &BoundedReleaseTitle {
        &self.title
    }

    #[must_use]
    pub fn notes(&self) -> &BoundedReleaseNotes {
        &self.notes
    }

    fn try_from_wire(wire: ReleaseMetadataWire) -> Result<Self, CoreError> {
        Ok(Self {
            title: BoundedReleaseTitle::parse(wire.title)?,
            notes: BoundedReleaseNotes::parse(wire.notes)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "metadata", rename_all = "snake_case")]
pub enum ProviderExtensionV1 {
    None,
    Pi(Box<PiCatalogExtensionMetadata>),
}

impl ProviderExtensionV1 {
    fn try_from_wire(
        wire: ProviderExtensionWire,
        provider_id: &str,
        release_version: &ExactVersion,
        components: &[CatalogComponentRecord],
        allowed_origins: &[AllowedOrigin],
    ) -> Result<Self, CoreError> {
        match wire {
            ProviderExtensionWire::None => {
                require(provider_id != PI_PROVIDER_ID)?;
                Ok(Self::None)
            }
            ProviderExtensionWire::Pi(metadata) => {
                require(provider_id == PI_PROVIDER_ID)?;
                Ok(Self::Pi(Box::new(
                    PiCatalogExtensionMetadata::try_from_wire(
                        *metadata,
                        release_version,
                        components,
                        allowed_origins,
                    )?,
                )))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PiCatalogExtensionMetadata {
    approved_package: ExactPackageIdentity,
    expected_entrypoint: InventoryPath,
    component_id: CatalogId,
    package_artifact_id: CatalogId,
    registry_integrity: RegistryIntegrity,
    root_package_manifest: ImmutableFileDescriptor,
    shipped_shrinkwrap: ShippedShrinkwrapMetadata,
}

impl PiCatalogExtensionMetadata {
    #[must_use]
    pub fn approved_package(&self) -> &ExactPackageIdentity {
        &self.approved_package
    }

    #[must_use]
    pub fn expected_entrypoint(&self) -> &InventoryPath {
        &self.expected_entrypoint
    }

    #[must_use]
    pub fn component_id(&self) -> &CatalogId {
        &self.component_id
    }

    #[must_use]
    pub fn package_artifact_id(&self) -> &CatalogId {
        &self.package_artifact_id
    }

    #[must_use]
    pub fn registry_integrity(&self) -> &RegistryIntegrity {
        &self.registry_integrity
    }

    #[must_use]
    pub fn root_package_manifest(&self) -> &ImmutableFileDescriptor {
        &self.root_package_manifest
    }

    #[must_use]
    pub fn shipped_shrinkwrap(&self) -> &ShippedShrinkwrapMetadata {
        &self.shipped_shrinkwrap
    }

    fn try_from_wire(
        wire: PiCatalogExtensionWire,
        release_version: &ExactVersion,
        components: &[CatalogComponentRecord],
        allowed_origins: &[AllowedOrigin],
    ) -> Result<Self, CoreError> {
        let approved_package = ExactPackageIdentity::try_from_wire(wire.approved_package)?;
        require(approved_package.name.as_str() == PI_ROOT_PACKAGE_NAME)?;
        require(&approved_package.version == release_version)?;
        let expected_entrypoint = InventoryPath::parse(wire.expected_entrypoint)?;
        let component_id = CatalogId::parse(wire.component_id)?;
        let package_artifact_id = CatalogId::parse(wire.package_artifact_id)?;
        let registry_integrity = RegistryIntegrity::parse(wire.registry_integrity)?;
        let root_package_manifest =
            ImmutableFileDescriptor::try_from_wire(wire.root_package_manifest, allowed_origins)?;
        let shipped_shrinkwrap =
            ShippedShrinkwrapMetadata::try_from_wire(wire.shipped_shrinkwrap, allowed_origins)?;
        require(shipped_shrinkwrap.root_package == approved_package)?;
        let component = components
            .iter()
            .find(|component| component.component_id == component_id)
            .ok_or_else(invalid)?;
        require(component.version == approved_package.version)?;
        let artifact = component
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == package_artifact_id)
            .ok_or_else(invalid)?;
        require(
            artifact
                .inventory
                .iter()
                .filter(|entry| entry.path == expected_entrypoint)
                .count()
                == 1,
        )?;
        require(!shipped_shrinkwrap.locked_packages.iter().any(|package| {
            package.name == approved_package.name && package.version == approved_package.version
        }))?;
        Ok(Self {
            approved_package,
            expected_entrypoint,
            component_id,
            package_artifact_id,
            registry_integrity,
            root_package_manifest,
            shipped_shrinkwrap,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactPackageIdentity {
    name: PackageName,
    version: ExactVersion,
}

impl ExactPackageIdentity {
    #[must_use]
    pub fn name(&self) -> &PackageName {
        &self.name
    }

    #[must_use]
    pub fn version(&self) -> &ExactVersion {
        &self.version
    }

    fn try_from_wire(wire: ExactPackageIdentityWire) -> Result<Self, CoreError> {
        Ok(Self {
            name: PackageName::parse(wire.name)?,
            version: ExactVersion::parse(wire.version)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImmutableFileDescriptor {
    url: HttpsArtifactUrl,
    size_bytes: ByteSize,
    sha256: Sha256Digest,
}

impl ImmutableFileDescriptor {
    #[must_use]
    pub fn url(&self) -> &HttpsArtifactUrl {
        &self.url
    }

    #[must_use]
    pub const fn size_bytes(&self) -> ByteSize {
        self.size_bytes
    }

    #[must_use]
    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    fn try_from_wire(
        wire: ImmutableFileDescriptorWire,
        allowed_origins: &[AllowedOrigin],
    ) -> Result<Self, CoreError> {
        let url = HttpsArtifactUrl::parse(wire.url)?;
        require(origin_allowed(&url, allowed_origins))?;
        let size_bytes = ByteSize::parse(wire.size_bytes)?;
        require(size_bytes.get() != 0)?;
        Ok(Self {
            url,
            size_bytes,
            sha256: Sha256Digest::parse(wire.sha256)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShippedShrinkwrapMetadata {
    lockfile_version: u8,
    root_package: ExactPackageIdentity,
    artifact: ImmutableFileDescriptor,
    locked_packages: Vec<LockedPackageRecord>,
}

impl ShippedShrinkwrapMetadata {
    #[must_use]
    pub const fn lockfile_version(&self) -> u8 {
        self.lockfile_version
    }

    #[must_use]
    pub fn root_package(&self) -> &ExactPackageIdentity {
        &self.root_package
    }

    #[must_use]
    pub fn artifact(&self) -> &ImmutableFileDescriptor {
        &self.artifact
    }

    #[must_use]
    pub fn locked_packages(&self) -> &[LockedPackageRecord] {
        &self.locked_packages
    }

    fn try_from_wire(
        wire: ShippedShrinkwrapWire,
        allowed_origins: &[AllowedOrigin],
    ) -> Result<Self, CoreError> {
        require(wire.lockfile_version == 3)?;
        require(wire.locked_packages.len() <= MAX_LOCKED_PACKAGES)?;
        let root_package = ExactPackageIdentity::try_from_wire(wire.root_package)?;
        let artifact = ImmutableFileDescriptor::try_from_wire(wire.artifact, allowed_origins)?;
        let locked_packages = wire
            .locked_packages
            .into_iter()
            .map(|package| LockedPackageRecord::try_from_wire(package, allowed_origins))
            .collect::<Result<Vec<_>, _>>()?;
        require_strictly_sorted_by(&locked_packages, |left, right| left.locator < right.locator)?;
        require_coherent_package_identities(&locked_packages)?;
        Ok(Self {
            lockfile_version: wire.lockfile_version,
            root_package,
            artifact,
            locked_packages,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LockedPackageRecord {
    locator: InventoryPath,
    name: PackageName,
    version: ExactVersion,
    resolved_url: HttpsArtifactUrl,
    registry_integrity: RegistryIntegrity,
    archive_sha256: Sha256Digest,
}

impl LockedPackageRecord {
    #[must_use]
    pub fn locator(&self) -> &InventoryPath {
        &self.locator
    }

    #[must_use]
    pub fn name(&self) -> &PackageName {
        &self.name
    }

    #[must_use]
    pub fn version(&self) -> &ExactVersion {
        &self.version
    }

    #[must_use]
    pub fn resolved_url(&self) -> &HttpsArtifactUrl {
        &self.resolved_url
    }

    #[must_use]
    pub fn registry_integrity(&self) -> &RegistryIntegrity {
        &self.registry_integrity
    }

    #[must_use]
    pub fn archive_sha256(&self) -> &Sha256Digest {
        &self.archive_sha256
    }

    fn try_from_wire(
        wire: LockedPackageWire,
        allowed_origins: &[AllowedOrigin],
    ) -> Result<Self, CoreError> {
        require(wire.locator.starts_with("node_modules/"))?;
        let resolved_url = HttpsArtifactUrl::parse(wire.resolved_url)?;
        require(origin_allowed(&resolved_url, allowed_origins))?;
        Ok(Self {
            locator: InventoryPath::parse(wire.locator)?,
            name: PackageName::parse(wire.name)?,
            version: ExactVersion::parse(wire.version)?,
            resolved_url,
            registry_integrity: RegistryIntegrity::parse(wire.registry_integrity)?,
            archive_sha256: Sha256Digest::parse(wire.archive_sha256)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CatalogTimestamp(String);

impl CatalogTimestamp {
    pub(crate) fn parse(value: String) -> Result<Self, CoreError> {
        require(value.len() == CATALOG_TIMESTAMP_BYTES)?;
        let parsed = DateTime::parse_from_rfc3339(&value).map_err(|_| invalid())?;
        require(parsed.offset().local_minus_utc() == 0)?;
        let utc = parsed.with_timezone(&Utc);
        require(utc.to_rfc3339_opts(SecondsFormat::Secs, true) == value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! validated_string {
    ($name:ident, $parse:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            fn parse(value: String) -> Result<Self, CoreError> {
                require(($parse)(&value))?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

validated_string!(Sha256Digest, |value: &str| {
    value.len() == SHA256_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
});
validated_string!(RegistryIntegrity, |value: &str| {
    is_canonical_sha512_integrity(value)
});
validated_string!(CompatibilityRange, |value: &str| {
    !value.is_empty()
        && value.len() <= MAX_COMPATIBILITY_RANGE_BYTES
        && value.is_ascii()
        && semver::VersionReq::parse(value).is_ok()
});
validated_string!(BoundedReleaseTitle, |value: &str| {
    valid_plain_text(value, MAX_RELEASE_TITLE_BYTES, false)
});
validated_string!(BoundedReleaseNotes, |value: &str| {
    valid_plain_text(value, MAX_RELEASE_NOTES_BYTES, true)
});
validated_string!(PackageName, |value: &str| { valid_package_name(value) });
validated_string!(InventoryPath, |value: &str| { valid_inventory_path(value) });

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ExactVersion(String);

impl ExactVersion {
    pub(crate) fn parse(value: String) -> Result<Self, CoreError> {
        require(valid_exact_version(&value))?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ExactVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CatalogId(String);

impl CatalogId {
    fn parse(value: String) -> Result<Self, CoreError> {
        require(valid_catalog_id(&value))?;
        Ok(Self(value))
    }

    fn parse_harness(value: String) -> Result<Self, CoreError> {
        require(valid_catalog_id(&value))?;
        let mut segments = value.split(':');
        require(segments.next() == Some("builtin") && segments.count() == 1)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CatalogId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct AllowedOrigin(String);

impl AllowedOrigin {
    fn parse(value: String) -> Result<Self, CoreError> {
        require(value.len() <= MAX_ALLOWED_ORIGIN_BYTES)?;
        require_url_input(&value)?;
        let url = parse_https_url(&value)?;
        require(url.path() == "/" && url.query().is_none())?;
        Ok(Self(url.origin().ascii_serialization()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct HttpsArtifactUrl(String);

impl HttpsArtifactUrl {
    pub(crate) fn parse(value: String) -> Result<Self, CoreError> {
        require(value.len() <= MAX_ARTIFACT_URL_BYTES)?;
        require_url_input(&value)?;
        parse_https_url(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn origin(&self) -> Result<String, CoreError> {
        Ok(parse_https_url(&self.0)?.origin().ascii_serialization())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSize(u64);

impl ByteSize {
    fn parse(value: String) -> Result<Self, CoreError> {
        let parsed = value.parse::<u64>().map_err(|_| invalid())?;
        require(value == parsed.to_string())?;
        Ok(Self(parsed))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Serialize for ByteSize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogTarget {
    LinuxX86_64,
}

impl CatalogTarget {
    pub(crate) fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "linux_x86_64" => Ok(Self::LinuxX86_64),
            _ => Err(invalid()),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "linux_x86_64",
        }
    }
}

fn serialize_nonzero_decimal<S>(value: &NonZeroU64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn parse_nonzero_decimal(value: &str) -> Result<NonZeroU64, CoreError> {
    let parsed = value.parse::<u64>().map_err(|_| invalid())?;
    require(value == parsed.to_string())?;
    NonZeroU64::new(parsed).ok_or_else(invalid)
}

fn parse_ranges(values: Vec<String>) -> Result<Vec<CompatibilityRange>, CoreError> {
    require_bounded_nonempty(&values, MAX_COMPATIBILITY_RANGES)?;
    let ranges = values
        .into_iter()
        .map(CompatibilityRange::parse)
        .collect::<Result<Vec<_>, _>>()?;
    require_unique(ranges.iter())?;
    Ok(ranges)
}

fn require_coherent_package_identities(packages: &[LockedPackageRecord]) -> Result<(), CoreError> {
    let mut identities = HashMap::new();
    for package in packages {
        let identity = (package.name.as_str(), package.version.as_str());
        let immutable = (
            package.resolved_url.as_str(),
            package.registry_integrity.as_str(),
            package.archive_sha256.as_str(),
        );
        if let Some(previous) = identities.insert(identity, immutable) {
            require(previous == immutable)?;
        }
    }
    Ok(())
}

fn origin_allowed(url: &HttpsArtifactUrl, allowed_origins: &[AllowedOrigin]) -> bool {
    url.origin().is_ok_and(|origin| {
        allowed_origins
            .iter()
            .any(|allowed| allowed.as_str() == origin)
    })
}

fn parse_https_url(value: &str) -> Result<Url, CoreError> {
    let url = Url::parse(value).map_err(|_| invalid())?;
    require(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
    )?;
    Ok(url)
}

fn require_url_input(value: &str) -> Result<(), CoreError> {
    require(
        !value.contains('\\')
            && value
                .bytes()
                .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace()),
    )
}

fn valid_catalog_id(value: &str) -> bool {
    if !(MIN_CATALOG_ID_BYTES..=MAX_CATALOG_ID_BYTES).contains(&value.len()) || !value.is_ascii() {
        return false;
    }
    let segments = value.split(':').collect::<Vec<_>>();
    (MIN_CATALOG_ID_SEGMENTS..=MAX_CATALOG_ID_SEGMENTS).contains(&segments.len())
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment.len() <= MAX_CATALOG_ID_SEGMENT_BYTES
                && segment
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && segment
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                })
                && !segment.as_bytes().windows(2).any(|pair| {
                    matches!(pair[0], b'-' | b'_' | b'.') && matches!(pair[1], b'-' | b'_' | b'.')
                })
        })
}

fn valid_exact_version(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_EXACT_VERSION_BYTES || !value.is_ascii() {
        return false;
    }
    let (without_build, build) = value
        .split_once('+')
        .map_or((value, None), |(version, build)| (version, Some(build)));
    if build.is_some_and(|build| !valid_version_identifiers(build, false))
        || without_build.contains('+')
    {
        return false;
    }
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(core, prerelease)| {
            (core, Some(prerelease))
        });
    if prerelease.is_some_and(|value| !valid_version_identifiers(value, true)) {
        return false;
    }
    let mut components = core.split('.');
    (0..3).all(|_| components.next().is_some_and(valid_numeric_component))
        && components.next().is_none()
}

fn valid_numeric_component(component: &str) -> bool {
    !component.is_empty()
        && component.bytes().all(|byte| byte.is_ascii_digit())
        && (component == "0" || !component.starts_with('0'))
}

fn valid_version_identifiers(identifiers: &str, reject_numeric_leading_zero: bool) -> bool {
    !identifiers.is_empty()
        && identifiers.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!reject_numeric_leading_zero
                    || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || identifier == "0"
                    || !identifier.starts_with('0'))
        })
}

fn valid_plain_text(value: &str, maximum_bytes: usize, allow_lines: bool) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.chars().all(|character| {
            !character.is_control() || (allow_lines && matches!(character, '\n' | '\r' | '\t'))
        })
}

fn valid_package_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PACKAGE_NAME_BYTES
        && value.is_ascii()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        && if let Some(scoped) = value.strip_prefix('@') {
            let mut parts = scoped.split('/');
            matches!((parts.next(), parts.next(), parts.next()), (Some(scope), Some(name), None) if valid_package_segment(scope) && valid_package_segment(name))
        } else {
            !value.contains('/') && valid_package_segment(value)
        }
}

fn valid_package_segment(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
        && value != "."
        && value != ".."
}

fn valid_inventory_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_INVENTORY_PATH_BYTES
        || value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return false;
    }
    value
        .split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn is_canonical_sha512_integrity(value: &str) -> bool {
    let Some(payload) = value.strip_prefix("sha512-") else {
        return false;
    };
    let Some(decoded) = decode_sha512_base64(payload) else {
        return false;
    };
    encode_sha512_base64(&decoded) == payload
}

fn decode_sha512_base64(payload: &str) -> Option<[u8; 64]> {
    let bytes = payload.as_bytes();
    if bytes.len() != SHA512_INTEGRITY_BYTES - "sha512-".len()
        || bytes[86] != b'='
        || bytes[87] != b'='
    {
        return None;
    }
    let mut decoded = [0_u8; 64];
    let mut output = 0;
    for group in 0..21 {
        let offset = group * 4;
        let a = base64_value(bytes[offset])?;
        let b = base64_value(bytes[offset + 1])?;
        let c = base64_value(bytes[offset + 2])?;
        let d = base64_value(bytes[offset + 3])?;
        decoded[output] = (a << 2) | (b >> 4);
        decoded[output + 1] = (b << 4) | (c >> 2);
        decoded[output + 2] = (c << 6) | d;
        output += 3;
    }
    let a = base64_value(bytes[84])?;
    let b = base64_value(bytes[85])?;
    decoded[63] = (a << 2) | (b >> 4);
    Some(decoded)
}

fn encode_sha512_base64(bytes: &[u8; 64]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(88);
    for chunk in bytes[..63].chunks_exact(3) {
        encoded.push(char::from(ALPHABET[usize::from(chunk[0] >> 2)]));
        encoded.push(char::from(
            ALPHABET[usize::from(((chunk[0] & 0x03) << 4) | (chunk[1] >> 4))],
        ));
        encoded.push(char::from(
            ALPHABET[usize::from(((chunk[1] & 0x0f) << 2) | (chunk[2] >> 6))],
        ));
        encoded.push(char::from(ALPHABET[usize::from(chunk[2] & 0x3f)]));
    }
    encoded.push(char::from(ALPHABET[usize::from(bytes[63] >> 2)]));
    encoded.push(char::from(ALPHABET[usize::from((bytes[63] & 0x03) << 4)]));
    encoded.push('=');
    encoded.push('=');
    encoded
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn require(condition: bool) -> Result<(), CoreError> {
    condition.then_some(()).ok_or_else(invalid)
}

fn require_bounded_nonempty<T>(values: &[T], maximum: usize) -> Result<(), CoreError> {
    require(!values.is_empty() && values.len() <= maximum)
}

fn require_unique<T, I>(values: I) -> Result<(), CoreError>
where
    T: Eq + Hash,
    I: IntoIterator<Item = T>,
{
    let mut seen = HashSet::new();
    require(values.into_iter().all(|value| seen.insert(value)))
}

fn require_strictly_sorted_by<T, F>(values: &[T], less: F) -> Result<(), CoreError>
where
    F: Fn(&T, &T) -> bool,
{
    require(values.windows(2).all(|pair| less(&pair[0], &pair[1])))
}

const fn invalid() -> CoreError {
    CoreError::InvalidCatalog
}

pub(crate) fn reject_duplicate_json(bytes: &[u8]) -> Result<(), CoreError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    DuplicateChecked::deserialize(&mut deserializer).map_err(|_| invalid())?;
    deserializer.end().map_err(|_| invalid())
}

struct DuplicateChecked;

impl<'de> Deserialize<'de> for DuplicateChecked {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateVisitor)
    }
}

struct DuplicateVisitor;

impl<'de> de::Visitor<'de> for DuplicateVisitor {
    type Value = DuplicateChecked;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded duplicate-free JSON")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(DuplicateChecked)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(DuplicateChecked)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(DuplicateChecked)
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        value
            .is_finite()
            .then_some(DuplicateChecked)
            .ok_or_else(|| E::custom("invalid number"))
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(DuplicateChecked)
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(DuplicateChecked)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateChecked)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateChecked)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateChecked::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        while sequence.next_element::<DuplicateChecked>()?.is_some() {}
        Ok(DuplicateChecked)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > MAX_JSON_OBJECT_KEY_BYTES || !keys.insert(key) {
                return Err(de::Error::custom("invalid object key"));
            }
            map.next_value::<DuplicateChecked>()?;
        }
        Ok(DuplicateChecked)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogPayloadWire {
    schema_version: u16,
    sequence: String,
    generated_at: String,
    expires_at: String,
    compatibility_ranges: Vec<String>,
    providers: Vec<CatalogProviderWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogProviderWire {
    provider_id: String,
    allowed_origins: Vec<String>,
    releases: Vec<CatalogReleaseWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogReleaseWire {
    version: String,
    target: String,
    compatibility_ranges: Vec<String>,
    release_metadata: ReleaseMetadataWire,
    components: Vec<CatalogComponentWire>,
    provider_extension: ProviderExtensionWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseMetadataWire {
    title: String,
    notes: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogComponentWire {
    component_id: String,
    version: String,
    artifacts: Vec<ArtifactDescriptorWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactDescriptorWire {
    artifact_id: String,
    url: String,
    size_bytes: String,
    sha256: String,
    inventory: Vec<ArtifactInventoryWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactInventoryWire {
    path: String,
    size_bytes: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    content = "metadata",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ProviderExtensionWire {
    None,
    Pi(Box<PiCatalogExtensionWire>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PiCatalogExtensionWire {
    approved_package: ExactPackageIdentityWire,
    expected_entrypoint: String,
    component_id: String,
    package_artifact_id: String,
    registry_integrity: String,
    root_package_manifest: ImmutableFileDescriptorWire,
    shipped_shrinkwrap: ShippedShrinkwrapWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactPackageIdentityWire {
    name: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImmutableFileDescriptorWire {
    url: String,
    size_bytes: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShippedShrinkwrapWire {
    lockfile_version: u8,
    root_package: ExactPackageIdentityWire,
    artifact: ImmutableFileDescriptorWire,
    locked_packages: Vec<LockedPackageWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LockedPackageWire {
    locator: String,
    name: String,
    version: String,
    resolved_url: String,
    registry_integrity: String,
    archive_sha256: String,
}
