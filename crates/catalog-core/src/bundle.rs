use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    BoundedId, CatalogTag, CommitSha, CoreError, HttpsArtifactUrl, Sha256Hex,
    source::{domain_digest, invalid, require, require_bounded_json},
};

pub const BUNDLE_SCHEMA_VERSION: u16 = 1;
pub const MAX_BUNDLE_ENTRIES: usize = 32_768;
pub const MAX_BUNDLE_PATH_BYTES: usize = 512;
pub const MAX_BUNDLE_ASSET_NAME_BYTES: usize = 255;
pub const MAX_BUNDLE_OBJECT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_BUNDLE_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;

const VERIFIED_INPUT_RECORD_NAME: &str = "verified-input-bundle-v1.json";
const CATALOG_ENVELOPE_NAME: &str = "catalog-v1.json";
const RELEASE_CHECKSUMS_NAME: &str = "checksums-sha256.txt";
const RELEASE_MANIFEST_NAME: &str = "signed-release-bundle-manifest-v1.json";

const INVENTORY_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-bundle-inventory:v1\0";
const VERIFIED_INPUT_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-verified-input:v1\0";
pub const RELEASE_BUNDLE_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-release-bundle:v1\0";
const SIGNED_MANIFEST_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-signed-release-manifest:v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleEntryV1 {
    pub relative_path: BundlePath,
    pub mode: BundleMode,
    pub size: u64,
    pub sha256: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleInventoryV1 {
    pub schema_version: u16,
    pub kind: BundleKind,
    pub entries: Vec<BundleEntryV1>,
}

impl BundleInventoryV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require_bounded_json(bytes)?;
        let wire: BundleInventoryWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        require(wire.schema_version == BUNDLE_SCHEMA_VERSION)?;
        require(!wire.entries.is_empty() && wire.entries.len() <= MAX_BUNDLE_ENTRIES)?;
        let entries = wire
            .entries
            .into_iter()
            .map(BundleEntryV1::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        require_strictly_sorted_paths(&entries)?;
        require_bounded_total(entries.iter().map(|entry| entry.size))?;
        require_kind_objects(wire.kind, &entries)?;
        Ok(Self {
            schema_version: wire.schema_version,
            kind: wire.kind,
            entries,
        })
    }
}

impl BundleEntryV1 {
    fn try_from(wire: BundleEntryWire) -> Result<Self, CoreError> {
        require(wire.size != 0 && wire.size <= MAX_BUNDLE_OBJECT_BYTES)?;
        Ok(Self {
            relative_path: BundlePath::parse(wire.relative_path)?,
            mode: wire.mode,
            size: wire.size,
            sha256: Sha256Hex::parse(wire.sha256)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleKind {
    VerifiedInput,
    SignedRelease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BundleMode {
    #[serde(rename = "0400")]
    OwnerReadOnlyRegularFile,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct BundlePath(String);

impl BundlePath {
    fn parse(value: String) -> Result<Self, CoreError> {
        require(valid_relative_path(&value, MAX_BUNDLE_PATH_BYTES))?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BundlePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Public, inert acquisition result. Object names are digest-addressed and contain no local paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedInputBundleV1 {
    pub schema_version: u16,
    pub source_kind: InputSourceKind,
    pub source_sha256: Sha256Hex,
    pub compatibility_input_sha256: Sha256Hex,
    pub objects: Vec<VerifiedInputObjectV1>,
}

impl VerifiedInputBundleV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require_bounded_json(bytes)?;
        let wire: VerifiedInputBundleWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        require(wire.schema_version == BUNDLE_SCHEMA_VERSION)?;
        require(!wire.objects.is_empty() && wire.objects.len() <= MAX_BUNDLE_ENTRIES)?;
        let objects = wire
            .objects
            .into_iter()
            .map(VerifiedInputObjectV1::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        require(
            objects
                .windows(2)
                .all(|pair| pair[0].relative_path.as_str() < pair[1].relative_path.as_str()),
        )?;
        require_bounded_total(objects.iter().map(|object| object.size))?;
        Ok(Self {
            schema_version: wire.schema_version,
            source_kind: wire.source_kind,
            source_sha256: Sha256Hex::parse(wire.source_sha256)?,
            compatibility_input_sha256: Sha256Hex::parse(wire.compatibility_input_sha256)?,
            objects,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputSourceKind {
    ReleaseIntent,
    CatalogSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedInputObjectV1 {
    pub relative_path: BundlePath,
    pub source_url: HttpsArtifactUrl,
    pub size: u64,
    pub sha256: Sha256Hex,
}

impl VerifiedInputObjectV1 {
    fn try_from(wire: VerifiedInputObjectWire) -> Result<Self, CoreError> {
        require(wire.size != 0 && wire.size <= MAX_BUNDLE_OBJECT_BYTES)?;
        let relative_path = BundlePath::parse(wire.relative_path)?;
        let sha256 = Sha256Hex::parse(wire.sha256)?;
        require(relative_path.as_str() == format!("objects/{sha256}"))?;
        Ok(Self {
            relative_path,
            source_url: HttpsArtifactUrl::parse(wire.source_url)?,
            size: wire.size,
            sha256,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignedReleaseBundleManifestV1 {
    pub schema_version: u16,
    pub source_commit: CommitSha,
    pub source_tree_sha256: Sha256Hex,
    pub qualification_sha256: Sha256Hex,
    pub tag: CatalogTag,
    pub catalog_envelope: ReleaseAssetV1,
    pub assets: Vec<ReleaseAssetV1>,
    pub signature: ReleaseBundleSignatureV1,
}

impl SignedReleaseBundleManifestV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require_bounded_json(bytes)?;
        let wire: SignedReleaseBundleManifestWire =
            serde_json::from_slice(bytes).map_err(|_| invalid())?;
        require(wire.schema_version == BUNDLE_SCHEMA_VERSION)?;
        require(!wire.assets.is_empty() && wire.assets.len() <= MAX_BUNDLE_ENTRIES)?;
        let catalog_envelope = ReleaseAssetV1::try_from(wire.catalog_envelope)?;
        require(catalog_envelope.name.as_str() == CATALOG_ENVELOPE_NAME)?;
        let assets = wire
            .assets
            .into_iter()
            .map(ReleaseAssetV1::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        require(
            assets
                .windows(2)
                .all(|pair| pair[0].name.as_str() < pair[1].name.as_str()),
        )?;
        require(!assets.iter().any(|asset| {
            matches!(
                asset.name.as_str(),
                CATALOG_ENVELOPE_NAME | RELEASE_CHECKSUMS_NAME | RELEASE_MANIFEST_NAME
            )
        }))?;
        require_bounded_total(
            std::iter::once(catalog_envelope.size).chain(assets.iter().map(|asset| asset.size)),
        )?;
        Ok(Self {
            schema_version: wire.schema_version,
            source_commit: CommitSha::parse(wire.source_commit)?,
            source_tree_sha256: Sha256Hex::parse(wire.source_tree_sha256)?,
            qualification_sha256: Sha256Hex::parse(wire.qualification_sha256)?,
            tag: CatalogTag::parse_without_sequence(wire.tag)?,
            catalog_envelope,
            assets,
            signature: ReleaseBundleSignatureV1::try_from(wire.signature)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseAssetV1 {
    pub name: ReleaseAssetName,
    pub size: u64,
    pub sha256: Sha256Hex,
}

impl ReleaseAssetV1 {
    fn try_from(wire: ReleaseAssetWire) -> Result<Self, CoreError> {
        require(wire.size != 0 && wire.size <= MAX_BUNDLE_OBJECT_BYTES)?;
        Ok(Self {
            name: ReleaseAssetName::parse(wire.name)?,
            size: wire.size,
            sha256: Sha256Hex::parse(wire.sha256)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ReleaseAssetName(String);

impl ReleaseAssetName {
    fn parse(value: String) -> Result<Self, CoreError> {
        require(
            !value.is_empty()
                && value.len() <= MAX_BUNDLE_ASSET_NAME_BYTES
                && value != "."
                && value != ".."
                && value.is_ascii()
                && !value.contains(['/', '\\'])
                && !value
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()),
        )?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseBundleSignatureV1 {
    pub key_id: BoundedId,
    pub signature: BoundedSignatureText,
}

impl ReleaseBundleSignatureV1 {
    fn try_from(wire: ReleaseBundleSignatureWire) -> Result<Self, CoreError> {
        Ok(Self {
            key_id: BoundedId::parse(wire.key_id)?,
            signature: BoundedSignatureText::parse(wire.signature)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct BoundedSignatureText(String);

impl BoundedSignatureText {
    fn parse(value: String) -> Result<Self, CoreError> {
        require(
            !value.is_empty()
                && value.len() <= 256
                && value.is_ascii()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b'\\'),
        )?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn bundle_inventory_digest(inventory: &BundleInventoryV1) -> Result<[u8; 32], CoreError> {
    domain_digest(INVENTORY_DOMAIN, inventory)
}

pub fn verified_input_bundle_digest(bundle: &VerifiedInputBundleV1) -> Result<[u8; 32], CoreError> {
    domain_digest(VERIFIED_INPUT_DOMAIN, bundle)
}

/// Bytes signed by the release-bundle signature. The signature field is intentionally absent.
pub fn release_bundle_signing_bytes(
    manifest: &SignedReleaseBundleManifestV1,
) -> Result<Vec<u8>, CoreError> {
    #[derive(Serialize)]
    struct UnsignedManifest<'a> {
        schema_version: u16,
        source_commit: &'a CommitSha,
        source_tree_sha256: &'a Sha256Hex,
        qualification_sha256: &'a Sha256Hex,
        tag: &'a CatalogTag,
        catalog_envelope: &'a ReleaseAssetV1,
        assets: &'a [ReleaseAssetV1],
    }
    let unsigned = UnsignedManifest {
        schema_version: manifest.schema_version,
        source_commit: &manifest.source_commit,
        source_tree_sha256: &manifest.source_tree_sha256,
        qualification_sha256: &manifest.qualification_sha256,
        tag: &manifest.tag,
        catalog_envelope: &manifest.catalog_envelope,
        assets: &manifest.assets,
    };
    let canonical = serde_jcs::to_vec(&unsigned).map_err(|_| invalid())?;
    let mut bytes = Vec::with_capacity(RELEASE_BUNDLE_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(RELEASE_BUNDLE_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

pub fn release_bundle_domain_digest(
    manifest: &SignedReleaseBundleManifestV1,
) -> Result<[u8; 32], CoreError> {
    Ok(Sha256::digest(release_bundle_signing_bytes(manifest)?).into())
}

pub fn signed_release_bundle_manifest_digest(
    manifest: &SignedReleaseBundleManifestV1,
) -> Result<[u8; 32], CoreError> {
    domain_digest(SIGNED_MANIFEST_DOMAIN, manifest)
}

fn require_kind_objects(kind: BundleKind, entries: &[BundleEntryV1]) -> Result<(), CoreError> {
    let has = |name: &str| {
        entries
            .binary_search_by_key(&name, |entry| entry.relative_path.as_str())
            .is_ok()
    };
    match kind {
        BundleKind::VerifiedInput => require(has(VERIFIED_INPUT_RECORD_NAME)),
        BundleKind::SignedRelease => require(
            has(CATALOG_ENVELOPE_NAME) && has(RELEASE_CHECKSUMS_NAME) && has(RELEASE_MANIFEST_NAME),
        ),
    }
}

fn require_strictly_sorted_paths(entries: &[BundleEntryV1]) -> Result<(), CoreError> {
    require(
        entries
            .windows(2)
            .all(|pair| pair[0].relative_path.as_str() < pair[1].relative_path.as_str()),
    )
}

fn require_bounded_total(sizes: impl IntoIterator<Item = u64>) -> Result<(), CoreError> {
    let mut total = 0_u64;
    for size in sizes {
        total = total.checked_add(size).ok_or_else(invalid)?;
        require(total <= MAX_BUNDLE_TOTAL_BYTES)?;
    }
    Ok(())
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
struct BundleInventoryWire {
    schema_version: u16,
    kind: BundleKind,
    entries: Vec<BundleEntryWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleEntryWire {
    relative_path: String,
    mode: BundleMode,
    size: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedInputBundleWire {
    schema_version: u16,
    source_kind: InputSourceKind,
    source_sha256: String,
    compatibility_input_sha256: String,
    objects: Vec<VerifiedInputObjectWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedInputObjectWire {
    relative_path: String,
    source_url: String,
    size: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedReleaseBundleManifestWire {
    schema_version: u16,
    source_commit: String,
    source_tree_sha256: String,
    qualification_sha256: String,
    tag: String,
    catalog_envelope: ReleaseAssetWire,
    assets: Vec<ReleaseAssetWire>,
    signature: ReleaseBundleSignatureWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseAssetWire {
    name: String,
    size: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseBundleSignatureWire {
    key_id: String,
    signature: String,
}
