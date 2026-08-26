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
    relative_path: BundlePath,
    mode: BundleMode,
    size: u64,
    sha256: Sha256Hex,
}

impl BundleEntryV1 {
    #[must_use]
    pub fn relative_path(&self) -> &BundlePath {
        &self.relative_path
    }

    #[must_use]
    pub const fn mode(&self) -> BundleMode {
        self.mode
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub fn sha256(&self) -> &Sha256Hex {
        &self.sha256
    }
}

/// A validated transfer inventory whose order and entries cannot be mutated after admission.
///
/// ```compile_fail
/// use catalog_core::BundleInventoryV1;
/// fn reorder(inventory: &mut BundleInventoryV1) {
///     inventory.entries.reverse();
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleInventoryV1 {
    schema_version: u16,
    kind: BundleKind,
    entries: Vec<BundleEntryV1>,
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

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn kind(&self) -> BundleKind {
        self.kind
    }

    #[must_use]
    pub fn entries(&self) -> &[BundleEntryV1] {
        &self.entries
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
    schema_version: u16,
    source_kind: InputSourceKind,
    source_sha256: Sha256Hex,
    compatibility_input_sha256: Sha256Hex,
    objects: Vec<VerifiedInputObjectV1>,
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

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn source_kind(&self) -> InputSourceKind {
        self.source_kind
    }

    #[must_use]
    pub fn source_sha256(&self) -> &Sha256Hex {
        &self.source_sha256
    }

    #[must_use]
    pub fn compatibility_input_sha256(&self) -> &Sha256Hex {
        &self.compatibility_input_sha256
    }

    #[must_use]
    pub fn objects(&self) -> &[VerifiedInputObjectV1] {
        &self.objects
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
    relative_path: BundlePath,
    source_url: HttpsArtifactUrl,
    size: u64,
    sha256: Sha256Hex,
}

impl VerifiedInputObjectV1 {
    #[must_use]
    pub fn relative_path(&self) -> &BundlePath {
        &self.relative_path
    }

    #[must_use]
    pub fn source_url(&self) -> &HttpsArtifactUrl {
        &self.source_url
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub fn sha256(&self) -> &Sha256Hex {
        &self.sha256
    }

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

/// Validated release manifest fields cannot be substituted after admission.
///
/// ```compile_fail
/// use catalog_core::SignedReleaseBundleManifestV1;
/// fn substitute_assets(manifest: &mut SignedReleaseBundleManifestV1) {
///     manifest.assets.clear();
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignedReleaseBundleManifestV1 {
    schema_version: u16,
    source_commit: CommitSha,
    source_tree_sha256: Sha256Hex,
    qualification_sha256: Sha256Hex,
    tag: CatalogTag,
    catalog_envelope: ReleaseAssetV1,
    assets: Vec<ReleaseAssetV1>,
    signature: ReleaseBundleSignatureV1,
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
                VERIFIED_INPUT_RECORD_NAME
                    | CATALOG_ENVELOPE_NAME
                    | RELEASE_CHECKSUMS_NAME
                    | RELEASE_MANIFEST_NAME
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

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub fn source_commit(&self) -> &CommitSha {
        &self.source_commit
    }

    #[must_use]
    pub fn source_tree_sha256(&self) -> &Sha256Hex {
        &self.source_tree_sha256
    }

    #[must_use]
    pub fn qualification_sha256(&self) -> &Sha256Hex {
        &self.qualification_sha256
    }

    #[must_use]
    pub fn tag(&self) -> &CatalogTag {
        &self.tag
    }

    #[must_use]
    pub fn catalog_envelope(&self) -> &ReleaseAssetV1 {
        &self.catalog_envelope
    }

    #[must_use]
    pub fn assets(&self) -> &[ReleaseAssetV1] {
        &self.assets
    }

    #[must_use]
    pub fn signature(&self) -> &ReleaseBundleSignatureV1 {
        &self.signature
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseAssetV1 {
    name: ReleaseAssetName,
    size: u64,
    sha256: Sha256Hex,
}

impl ReleaseAssetV1 {
    #[must_use]
    pub fn name(&self) -> &ReleaseAssetName {
        &self.name
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub fn sha256(&self) -> &Sha256Hex {
        &self.sha256
    }

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
        require(valid_release_asset_name(&value))?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseBundleSignatureV1 {
    key_id: BoundedId,
    signature: BoundedSignatureText,
}

impl ReleaseBundleSignatureV1 {
    #[must_use]
    pub fn key_id(&self) -> &BoundedId {
        &self.key_id
    }

    #[must_use]
    pub fn signature(&self) -> &BoundedSignatureText {
        &self.signature
    }

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

/// Requires the signed inventory's non-circular asset entries to exactly match the manifest.
///
/// The checksum and signed-manifest entries are reserved outputs and cannot bind their own bytes.
/// Every other entry, including the catalog envelope, is matched by name, size, and digest.
pub fn verify_signed_release_inventory(
    inventory: &BundleInventoryV1,
    manifest: &SignedReleaseBundleManifestV1,
) -> Result<(), CoreError> {
    require(inventory.kind == BundleKind::SignedRelease)?;
    require(inventory.schema_version == BUNDLE_SCHEMA_VERSION)?;
    require(inventory.entries.len() == manifest.assets.len() + 3)?;

    let catalog = find_entry(&inventory.entries, CATALOG_ENVELOPE_NAME)?;
    require(catalog.size == manifest.catalog_envelope.size)?;
    require(catalog.sha256 == manifest.catalog_envelope.sha256)?;
    for asset in &manifest.assets {
        let entry = find_entry(&inventory.entries, asset.name.as_str())?;
        require(entry.size == asset.size)?;
        require(entry.sha256 == asset.sha256)?;
    }
    Ok(())
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
    let has = |name: &str| find_entry(entries, name).is_ok();
    match kind {
        BundleKind::VerifiedInput => require(
            has(VERIFIED_INPUT_RECORD_NAME)
                && entries.iter().all(|entry| {
                    entry.relative_path.as_str() == VERIFIED_INPUT_RECORD_NAME
                        || entry
                            .relative_path
                            .as_str()
                            .strip_prefix("objects/")
                            .is_some_and(|digest| digest == entry.sha256.as_str())
                }),
        ),
        BundleKind::SignedRelease => require(
            has(CATALOG_ENVELOPE_NAME)
                && has(RELEASE_CHECKSUMS_NAME)
                && has(RELEASE_MANIFEST_NAME)
                && entries.iter().all(|entry| {
                    let path = entry.relative_path.as_str();
                    path != VERIFIED_INPUT_RECORD_NAME && valid_release_asset_name(path)
                }),
        ),
    }
}

fn find_entry<'a>(
    entries: &'a [BundleEntryV1],
    name: &str,
) -> Result<&'a BundleEntryV1, CoreError> {
    entries
        .binary_search_by_key(&name, |entry| entry.relative_path.as_str())
        .map(|index| &entries[index])
        .map_err(|_| invalid())
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

fn valid_release_asset_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_BUNDLE_ASSET_NAME_BYTES
        && value != "."
        && value != ".."
        && value.is_ascii()
        && !value.contains(['/', '\\'])
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
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
