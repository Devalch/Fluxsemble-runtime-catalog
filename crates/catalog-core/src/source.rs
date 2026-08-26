use std::{fmt, num::NonZeroU64};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    CatalogPayloadV1, CatalogReleaseRecord, CatalogTarget, CatalogTimestamp, CoreError,
    ExactVersion, MAX_CATALOG_PAYLOAD_BYTES, wire::reject_duplicate_json,
};

const SOURCE_SCHEMA_VERSION: u16 = 1;
const EXACT_FLUXSEMBLE_REQUIREMENT: &str = "=0.1.0";
const PI_PROVIDER: &str = "builtin:pi";
const NODE_COMPONENT: &str = "component:node";
const PI_COMPONENT: &str = "component:pi";
const MAX_ID_BYTES: usize = 128;
const MAX_QUALIFICATION_PATH_BYTES: usize = 512;
const SHA256_BYTES: usize = 64;
const COMMIT_SHA_BYTES: usize = 40;

const COMPATIBILITY_INPUT_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-compatibility-input:v1\0";
const RELEASE_INTENT_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-release-intent:v1\0";
const BUILD_BINDING_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-build-binding:v1\0";
const CATALOG_SOURCE_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-source:v1\0";

/// Exact final Fluxsemble implementation, packaged binaries, and consumer profile.
///
/// ```compile_fail
/// use catalog_core::FluxsembleBuildBindingV1;
/// fn substitute(build: &mut FluxsembleBuildBindingV1) {
///     build.application_sha256 = build.daemon_sha256.clone();
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FluxsembleBuildBindingV1 {
    implementation_commit: CommitSha,
    application_sha256: Sha256Hex,
    daemon_sha256: Sha256Hex,
    compatibility_profile_id: BoundedId,
    compatibility_profile_sha256: Sha256Hex,
}

impl FluxsembleBuildBindingV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require_bounded_json(bytes)?;
        let wire: BuildBindingWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        Self::try_from(wire)
    }

    #[must_use]
    pub fn implementation_commit(&self) -> &CommitSha {
        &self.implementation_commit
    }

    #[must_use]
    pub fn application_sha256(&self) -> &Sha256Hex {
        &self.application_sha256
    }

    #[must_use]
    pub fn daemon_sha256(&self) -> &Sha256Hex {
        &self.daemon_sha256
    }

    #[must_use]
    pub fn compatibility_profile_id(&self) -> &BoundedId {
        &self.compatibility_profile_id
    }

    #[must_use]
    pub fn compatibility_profile_sha256(&self) -> &Sha256Hex {
        &self.compatibility_profile_sha256
    }

    fn try_from(wire: BuildBindingWire) -> Result<Self, CoreError> {
        Ok(Self {
            implementation_commit: CommitSha::parse(wire.implementation_commit)?,
            application_sha256: Sha256Hex::parse(wire.application_sha256)?,
            daemon_sha256: Sha256Hex::parse(wire.daemon_sha256)?,
            compatibility_profile_id: BoundedId::parse(wire.compatibility_profile_id)?,
            compatibility_profile_sha256: Sha256Hex::parse(wire.compatibility_profile_sha256)?,
        })
    }
}

/// Reviewed public release semantics before final build qualification exists.
///
/// This record deliberately has no production signing authority. Production signing consumes
/// [`CatalogSourceV1`], which adds immutable build and qualification bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InitialPiReleaseIntentV1 {
    #[serde(serialize_with = "serialize_nonzero_decimal")]
    sequence: NonZeroU64,
    tag: CatalogTag,
    generated_at: CatalogTimestamp,
    expires_at: CatalogTimestamp,
    fluxsemble_requirement: ExactVersionRequirement,
    release: InitialPiReleaseSemanticsV1,
}

impl InitialPiReleaseIntentV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require_bounded_json(bytes)?;
        let wire: ReleaseIntentWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        Self::try_from(wire)
    }

    #[must_use]
    pub const fn sequence(&self) -> NonZeroU64 {
        self.sequence
    }

    #[must_use]
    pub fn tag(&self) -> &CatalogTag {
        &self.tag
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
    pub fn fluxsemble_requirement(&self) -> &ExactVersionRequirement {
        &self.fluxsemble_requirement
    }

    #[must_use]
    pub fn release(&self) -> &InitialPiReleaseSemanticsV1 {
        &self.release
    }

    fn try_from(wire: ReleaseIntentWire) -> Result<Self, CoreError> {
        let sequence = parse_nonzero_decimal(&wire.sequence)?;
        let tag = CatalogTag::parse(wire.tag, sequence)?;
        let generated_at = CatalogTimestamp::parse(wire.generated_at.clone())?;
        let expires_at = CatalogTimestamp::parse(wire.expires_at.clone())?;
        require(generated_at < expires_at)?;
        let fluxsemble_requirement = ExactVersionRequirement::parse(wire.fluxsemble_requirement)?;
        let release = InitialPiReleaseSemanticsV1::try_from_wire(
            wire.release,
            sequence,
            &wire.generated_at,
            &wire.expires_at,
        )?;
        Ok(Self {
            sequence,
            tag,
            generated_at,
            expires_at,
            fluxsemble_requirement,
            release,
        })
    }
}

/// The single initial provider/target release tuple, validated through the catalog-v1 wire model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialPiReleaseSemanticsV1 {
    catalog: CatalogPayloadV1,
}

impl InitialPiReleaseSemanticsV1 {
    fn try_from_wire(
        wire: ReleaseSemanticsWire,
        sequence: NonZeroU64,
        generated_at: &str,
        expires_at: &str,
    ) -> Result<Self, CoreError> {
        require(wire.provider == PI_PROVIDER)?;
        let payload = json!({
            "schema_version": SOURCE_SCHEMA_VERSION,
            "sequence": sequence.to_string(),
            "generated_at": generated_at,
            "expires_at": expires_at,
            "compatibility_ranges": [EXACT_FLUXSEMBLE_REQUIREMENT],
            "providers": [{
                "provider_id": wire.provider,
                "allowed_origins": wire.allowed_origins,
                "releases": [wire.release]
            }]
        });
        let catalog =
            CatalogPayloadV1::from_json(&serde_json::to_vec(&payload).map_err(|_| invalid())?)?;
        let provider = catalog.providers().first().ok_or_else(invalid)?;
        require(catalog.providers().len() == 1 && provider.releases().len() == 1)?;
        let release = provider.releases().first().ok_or_else(invalid)?;
        require(release.target() == CatalogTarget::LinuxX86_64)?;
        require(
            release.compatibility_ranges().len() == 1
                && release.compatibility_ranges()[0].as_str() == EXACT_FLUXSEMBLE_REQUIREMENT,
        )?;
        require(release.components().len() == 2)?;
        let node = release
            .components()
            .iter()
            .find(|component| component.component_id().as_str() == NODE_COMPONENT)
            .ok_or_else(invalid)?;
        let pi = release
            .components()
            .iter()
            .find(|component| component.component_id().as_str() == PI_COMPONENT)
            .ok_or_else(invalid)?;
        require(pi.version() == release.version())?;
        require(node.component_id() != pi.component_id())?;
        Ok(Self { catalog })
    }

    #[must_use]
    pub fn provider(&self) -> &str {
        self.provider_record().provider_id()
    }

    #[must_use]
    pub fn allowed_origins(&self) -> &[crate::AllowedOrigin] {
        self.provider_record().allowed_origins()
    }

    #[must_use]
    pub fn catalog_release(&self) -> &CatalogReleaseRecord {
        &self.provider_record().releases()[0]
    }

    #[must_use]
    pub fn target(&self) -> CatalogTarget {
        self.catalog_release().target()
    }

    #[must_use]
    pub fn pi_version(&self) -> &ExactVersion {
        self.catalog_release().version()
    }

    #[must_use]
    pub fn node_version(&self) -> &ExactVersion {
        self.catalog_release()
            .components()
            .iter()
            .find(|component| component.component_id().as_str() == NODE_COMPONENT)
            .map(|component| component.version())
            .expect("validated initial semantics contain Node")
    }

    fn provider_record(&self) -> &crate::CatalogProviderRecord {
        &self.catalog.providers()[0]
    }
}

impl Serialize for InitialPiReleaseSemanticsV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("InitialPiReleaseSemanticsV1", 3)?;
        state.serialize_field("provider", self.provider())?;
        state.serialize_field("allowed_origins", self.allowed_origins())?;
        state.serialize_field("release", self.catalog_release())?;
        state.end()
    }
}

/// Final and only production-signable source record.
///
/// ```compile_fail
/// use catalog_core::CatalogSourceV1;
/// fn replace_intent(source: &mut CatalogSourceV1) {
///     source.intent = source.intent.clone();
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogSourceV1 {
    intent: InitialPiReleaseIntentV1,
    build: FluxsembleBuildBindingV1,
    qualification: QualifiedRecordRefV1,
}

impl CatalogSourceV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require_bounded_json(bytes)?;
        let wire: CatalogSourceWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        Ok(Self {
            intent: InitialPiReleaseIntentV1::try_from(wire.intent)?,
            build: FluxsembleBuildBindingV1::try_from(wire.build)?,
            qualification: QualifiedRecordRefV1::try_from(wire.qualification)?,
        })
    }

    #[must_use]
    pub fn intent(&self) -> &InitialPiReleaseIntentV1 {
        &self.intent
    }

    #[must_use]
    pub fn build(&self) -> &FluxsembleBuildBindingV1 {
        &self.build
    }

    #[must_use]
    pub fn qualification(&self) -> &QualifiedRecordRefV1 {
        &self.qualification
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QualifiedRecordRefV1 {
    relative_path: QualificationRecordPath,
    sha256: Sha256Hex,
}

impl QualifiedRecordRefV1 {
    #[must_use]
    pub fn relative_path(&self) -> &QualificationRecordPath {
        &self.relative_path
    }

    #[must_use]
    pub fn sha256(&self) -> &Sha256Hex {
        &self.sha256
    }

    fn try_from(wire: QualifiedRecordRefWire) -> Result<Self, CoreError> {
        let relative_path = QualificationRecordPath::parse(wire.relative_path)?;
        require(relative_path.as_str().starts_with("qualifications/"))?;
        require(relative_path.as_str().ends_with(".json"))?;
        Ok(Self {
            relative_path,
            sha256: Sha256Hex::parse(wire.sha256)?,
        })
    }
}

macro_rules! validated_string {
    ($name:ident, $validator:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub(crate) fn parse(value: String) -> Result<Self, CoreError> {
                require(($validator)(&value))?;
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

validated_string!(CommitSha, |value: &str| {
    value.len() == COMMIT_SHA_BYTES && is_lower_hex(value)
});
validated_string!(Sha256Hex, |value: &str| {
    value.len() == SHA256_BYTES && is_lower_hex(value)
});
validated_string!(BoundedId, |value: &str| {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
});
validated_string!(QualificationRecordPath, |value: &str| {
    valid_relative_path(value, MAX_QUALIFICATION_PATH_BYTES)
});

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ExactVersionRequirement(String);

impl ExactVersionRequirement {
    fn parse(value: String) -> Result<Self, CoreError> {
        require(value == EXACT_FLUXSEMBLE_REQUIREMENT)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CatalogTag(String);

impl CatalogTag {
    pub(crate) fn parse(value: String, sequence: NonZeroU64) -> Result<Self, CoreError> {
        require(value == format!("catalog-v1-sequence-{sequence}"))?;
        Ok(Self(value))
    }

    pub(crate) fn parse_without_sequence(value: String) -> Result<Self, CoreError> {
        let sequence = value
            .strip_prefix("catalog-v1-sequence-")
            .ok_or_else(invalid)
            .and_then(parse_nonzero_decimal)?;
        Self::parse(value, sequence)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Domain-separated compatibility digest over runtime semantics and exact final build/profile only.
pub fn compatibility_input_digest(
    intent: &InitialPiReleaseIntentV1,
    build: &FluxsembleBuildBindingV1,
) -> Result<[u8; 32], CoreError> {
    let mut release = serde_json::to_value(&intent.release).map_err(|_| invalid())?;
    release
        .pointer_mut("/release")
        .and_then(Value::as_object_mut)
        .ok_or_else(invalid)?
        .remove("release_metadata")
        .ok_or_else(invalid)?;
    #[derive(Serialize)]
    struct CompatibilityInput<'a> {
        catalog_schema_version: u16,
        fluxsemble_requirement: &'a ExactVersionRequirement,
        release: Value,
        build: &'a FluxsembleBuildBindingV1,
    }
    domain_digest(
        COMPATIBILITY_INPUT_DOMAIN,
        &CompatibilityInput {
            catalog_schema_version: SOURCE_SCHEMA_VERSION,
            fluxsemble_requirement: &intent.fluxsemble_requirement,
            release,
            build,
        },
    )
}

pub fn initial_release_intent_digest(
    intent: &InitialPiReleaseIntentV1,
) -> Result<[u8; 32], CoreError> {
    domain_digest(RELEASE_INTENT_DOMAIN, intent)
}

pub fn fluxsemble_build_binding_digest(
    build: &FluxsembleBuildBindingV1,
) -> Result<[u8; 32], CoreError> {
    domain_digest(BUILD_BINDING_DOMAIN, build)
}

pub fn catalog_source_digest(source: &CatalogSourceV1) -> Result<[u8; 32], CoreError> {
    domain_digest(CATALOG_SOURCE_DOMAIN, source)
}

pub(crate) fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], CoreError> {
    let canonical = serde_jcs::to_vec(value).map_err(|_| invalid())?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Ok(hasher.finalize().into())
}

pub(crate) fn require_bounded_json(bytes: &[u8]) -> Result<(), CoreError> {
    require(bytes.len() <= MAX_CATALOG_PAYLOAD_BYTES)?;
    reject_duplicate_json(bytes)
}

pub(crate) fn require(condition: bool) -> Result<(), CoreError> {
    condition.then_some(()).ok_or_else(invalid)
}

pub(crate) const fn invalid() -> CoreError {
    CoreError::InvalidCatalog
}

fn parse_nonzero_decimal(value: &str) -> Result<NonZeroU64, CoreError> {
    let parsed = value.parse::<u64>().map_err(|_| invalid())?;
    require(value == parsed.to_string())?;
    NonZeroU64::new(parsed).ok_or_else(invalid)
}

fn serialize_nonzero_decimal<S>(value: &NonZeroU64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_relative_path(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildBindingWire {
    implementation_commit: String,
    application_sha256: String,
    daemon_sha256: String,
    compatibility_profile_id: String,
    compatibility_profile_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseIntentWire {
    sequence: String,
    tag: String,
    generated_at: String,
    expires_at: String,
    fluxsemble_requirement: String,
    release: ReleaseSemanticsWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseSemanticsWire {
    provider: String,
    allowed_origins: Vec<String>,
    release: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogSourceWire {
    intent: ReleaseIntentWire,
    build: BuildBindingWire,
    qualification: QualifiedRecordRefWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QualifiedRecordRefWire {
    relative_path: String,
    sha256: String,
}
