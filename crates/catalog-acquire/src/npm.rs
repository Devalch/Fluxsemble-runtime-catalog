use std::collections::{BTreeSet, HashSet};

use catalog_core::{
    ArtifactDescriptor, InitialPiReleaseIntentV1, LockedPackageRecord, PiCatalogExtensionMetadata,
    ProviderExtensionV1,
};
use serde::{Deserialize, Serialize, de};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    AcquireError,
    archive::{
        NpmArchiveInspection, VerifiedArchive, inspect_node_archive, inspect_npm_archive,
        require_pinned_node_identity,
    },
};

const ROOT_NAME: &str = "@earendil-works/pi-coding-agent";
const ROOT_VERSION: &str = "0.83.0";
const NODE_VERSION: &str = "22.19.0";
const ENTRYPOINT: &str = "dist/cli.js";
const LOCKED_COUNT: usize = 139;
const APPLICABLE_COUNT: usize = 130;
const PRE_PRUNE_COUNT: usize = 131;
const MAX_PACKAGE_INPUT_BYTES: usize = 8 * 1024 * 1024;

const MISSING_LOCK_INTEGRITY: [&str; 3] = [
    "node_modules/@earendil-works/pi-agent-core",
    "node_modules/@earendil-works/pi-ai",
    "node_modules/@earendil-works/pi-tui",
];

const PRUNED: [(&str, &[&str]); 9] = [
    (
        "node_modules/@mariozechner/clipboard-darwin-arm64",
        &["declaration.cpu", "declaration.os", "lock.cpu", "lock.os"],
    ),
    (
        "node_modules/@mariozechner/clipboard-darwin-universal",
        &["declaration.os", "lock.os"],
    ),
    (
        "node_modules/@mariozechner/clipboard-darwin-x64",
        &["declaration.os", "lock.os"],
    ),
    (
        "node_modules/@mariozechner/clipboard-linux-arm64-gnu",
        &["declaration.cpu", "lock.cpu"],
    ),
    (
        "node_modules/@mariozechner/clipboard-linux-arm64-musl",
        &["declaration.cpu", "declaration.libc", "lock.cpu"],
    ),
    (
        "node_modules/@mariozechner/clipboard-linux-riscv64-gnu",
        &["declaration.cpu", "lock.cpu"],
    ),
    (
        "node_modules/@mariozechner/clipboard-linux-x64-musl",
        &["declaration.libc"],
    ),
    (
        "node_modules/@mariozechner/clipboard-win32-arm64-msvc",
        &["declaration.cpu", "declaration.os", "lock.cpu", "lock.os"],
    ),
    (
        "node_modules/@mariozechner/clipboard-win32-x64-msvc",
        &["declaration.os", "lock.os"],
    ),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageInputManifestV1 {
    schema_version: u16,
    target_os: String,
    target_cpu: String,
    target_libc: String,
    root: ObservedRootInput,
    locked_packages: Vec<ObservedLockedInput>,
    pre_prune_package_count: u16,
    applicable_package_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedRootInput {
    name: String,
    version: String,
    archive_size: u64,
    archive_sha256: String,
    manifest_size: u64,
    manifest_sha256: String,
    shrinkwrap_size: u64,
    shrinkwrap_sha256: String,
    archive_member_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedLockedInput {
    locator: String,
    name: String,
    version: String,
    resolved_url: String,
    registry_integrity: String,
    archive_size: u64,
    archive_sha256: String,
    declaration_sha256: String,
    archive_member_count: u32,
    applicability: LinuxApplicability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum LinuxApplicability {
    Applicable,
    Pruned { reasons: Vec<String> },
}

impl PackageInputManifestV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, AcquireError> {
        if bytes.len() > MAX_PACKAGE_INPUT_BYTES {
            return Err(AcquireError::Graph);
        }
        reject_duplicate_json(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|_| AcquireError::Graph)?;
        value.validate()?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AcquireError> {
        serde_jcs::to_vec(self).map_err(|_| AcquireError::Graph)
    }

    #[must_use]
    pub fn locked_package_count(&self) -> usize {
        self.locked_packages.len()
    }

    pub(crate) fn archive_size_for(&self, locator: &str) -> Option<u64> {
        self.locked_packages
            .iter()
            .find(|record| record.locator == locator)
            .map(|record| record.archive_size)
    }

    fn validate(&self) -> Result<(), AcquireError> {
        if self.schema_version != 1
            || self.target_os != "linux"
            || self.target_cpu != "x64"
            || self.target_libc != "glibc"
            || self.root.name != ROOT_NAME
            || self.root.version != ROOT_VERSION
            || self.locked_packages.len() != LOCKED_COUNT
            || self.pre_prune_package_count != PRE_PRUNE_COUNT as u16
            || self.applicable_package_count != APPLICABLE_COUNT as u16
            || self
                .locked_packages
                .windows(2)
                .any(|pair| pair[0].locator.as_bytes() >= pair[1].locator.as_bytes())
            || self
                .locked_packages
                .iter()
                .filter(|record| matches!(record.applicability, LinuxApplicability::Applicable))
                .count()
                != APPLICABLE_COUNT
        {
            return Err(AcquireError::Graph);
        }
        let actual_pruned = self
            .locked_packages
            .iter()
            .filter_map(|record| match &record.applicability {
                LinuxApplicability::Applicable => None,
                LinuxApplicability::Pruned { reasons } => {
                    Some((record.locator.as_str(), reasons.as_slice()))
                }
            })
            .collect::<Vec<_>>();
        if actual_pruned.len() != PRUNED.len()
            || actual_pruned.iter().zip(PRUNED).any(|(actual, expected)| {
                actual.0 != expected.0
                    || actual.1.iter().map(String::as_str).collect::<Vec<_>>() != expected.1
            })
        {
            return Err(AcquireError::Graph);
        }
        Ok(())
    }
}

/// Exact descriptor graph presented to the corpus verifier.
pub struct NpmGraphRequest {
    pub intent: InitialPiReleaseIntentV1,
    pub node_archive: VerifiedArchive,
    pub root_archive: VerifiedArchive,
    pub locked_archives: Vec<VerifiedArchive>,
    pub package_inputs: PackageInputManifestV1,
}

/// Verified first-tuple graph retaining descriptor authority for bundle emission.
pub struct VerifiedNpmGraph {
    intent: InitialPiReleaseIntentV1,
    node_archive: VerifiedArchive,
    root_archive: VerifiedArchive,
    locked_archives: Vec<VerifiedArchive>,
    package_inputs: PackageInputManifestV1,
    root_manifest: Vec<u8>,
    shrinkwrap: Vec<u8>,
}

impl VerifiedNpmGraph {
    #[must_use]
    pub const fn root_package_count(&self) -> usize {
        1
    }

    #[must_use]
    pub fn locked_package_count(&self) -> usize {
        self.locked_archives.len()
    }

    #[must_use]
    pub fn total_archive_count(&self) -> usize {
        1 + self.locked_archives.len()
    }

    #[must_use]
    pub fn root_manifest(&self) -> &[u8] {
        &self.root_manifest
    }

    #[must_use]
    pub fn shrinkwrap(&self) -> &[u8] {
        &self.shrinkwrap
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        InitialPiReleaseIntentV1,
        VerifiedArchive,
        VerifiedArchive,
        Vec<VerifiedArchive>,
        PackageInputManifestV1,
        Vec<u8>,
        Vec<u8>,
    ) {
        (
            self.intent,
            self.node_archive,
            self.root_archive,
            self.locked_archives,
            self.package_inputs,
            self.root_manifest,
            self.shrinkwrap,
        )
    }
}

pub fn discover_package_inputs(
    intent: &InitialPiReleaseIntentV1,
    root_archive: &mut VerifiedArchive,
    locked_archives: &mut [VerifiedArchive],
) -> Result<PackageInputManifestV1, AcquireError> {
    let metadata = pi_metadata(intent)?;
    require_exact_intent(intent, metadata)?;
    let root_artifact = pi_artifact(intent, metadata)?;
    require_archive(
        root_archive,
        root_artifact,
        Some(metadata.registry_integrity().as_str()),
    )?;
    if locked_archives.len() != LOCKED_COUNT {
        return Err(AcquireError::Graph);
    }
    let root = inspect_npm_archive(root_archive, true)?;
    let declaration = parse_json_object(&root.declaration, 64 * 1024)?;
    let shrinkwrap_bytes = root.shrinkwrap.as_ref().ok_or(AcquireError::Graph)?;
    let shrinkwrap = parse_json_object(shrinkwrap_bytes, 1024 * 1024)?;
    verify_root_documents(intent, metadata, &declaration, &shrinkwrap, &root)?;
    let package_records = lock_package_records(&shrinkwrap)?;
    verify_lock_records(metadata, &package_records)?;
    verify_complete_closure(&package_records)?;

    let mut observed = Vec::with_capacity(LOCKED_COUNT);
    for ((record, archive), (locator, lock)) in metadata
        .shipped_shrinkwrap()
        .locked_packages()
        .iter()
        .zip(locked_archives.iter_mut())
        .zip(
            package_records
                .iter()
                .filter(|(locator, _)| !locator.is_empty()),
        )
    {
        if locator != record.locator().as_str() {
            return Err(AcquireError::Graph);
        }
        require_locked_archive(archive, record)?;
        let inspection = inspect_npm_archive(archive, false)?;
        let package = parse_json_object(&inspection.declaration, 64 * 1024)?;
        require_string(&package, "name", record.name().as_str())?;
        require_string(&package, "version", record.version().as_str())?;
        let reasons = applicability_reasons(&package, lock)?;
        let applicability = if reasons.is_empty() {
            LinuxApplicability::Applicable
        } else {
            if lock.get("optional").and_then(Value::as_bool) != Some(true) {
                return Err(AcquireError::Graph);
            }
            LinuxApplicability::Pruned { reasons }
        };
        observed.push(ObservedLockedInput {
            locator: locator.clone(),
            name: record.name().as_str().to_owned(),
            version: record.version().as_str().to_owned(),
            resolved_url: record.resolved_url().as_str().to_owned(),
            registry_integrity: record.registry_integrity().as_str().to_owned(),
            archive_size: archive.size(),
            archive_sha256: archive.sha256().to_owned(),
            declaration_sha256: sha256(&inspection.declaration),
            archive_member_count: u32::try_from(inspection.member_count)
                .map_err(|_| AcquireError::Graph)?,
            applicability,
        });
    }
    let manifest = PackageInputManifestV1 {
        schema_version: 1,
        target_os: "linux".to_owned(),
        target_cpu: "x64".to_owned(),
        target_libc: "glibc".to_owned(),
        root: ObservedRootInput {
            name: ROOT_NAME.to_owned(),
            version: ROOT_VERSION.to_owned(),
            archive_size: root_archive.size(),
            archive_sha256: root_archive.sha256().to_owned(),
            manifest_size: root.declaration.len() as u64,
            manifest_sha256: sha256(&root.declaration),
            shrinkwrap_size: shrinkwrap_bytes.len() as u64,
            shrinkwrap_sha256: sha256(shrinkwrap_bytes),
            archive_member_count: u32::try_from(root.member_count)
                .map_err(|_| AcquireError::Graph)?,
        },
        locked_packages: observed,
        pre_prune_package_count: PRE_PRUNE_COUNT as u16,
        applicable_package_count: APPLICABLE_COUNT as u16,
    };
    manifest.validate()?;
    Ok(manifest)
}

pub fn verify_npm_graph(mut request: NpmGraphRequest) -> Result<VerifiedNpmGraph, AcquireError> {
    let metadata = pi_metadata(&request.intent)?;
    require_exact_intent(&request.intent, metadata)?;
    let node = node_artifact(&request.intent)?;
    require_pinned_node_identity(
        node.url().as_str(),
        node.size_bytes().get(),
        node.sha256().as_str(),
    )?;
    require_archive(&request.node_archive, node, None)?;
    let node_inspection = inspect_node_archive(&mut request.node_archive)?;
    if node_inspection.member_count != 5_780 {
        return Err(AcquireError::Graph);
    }
    verify_npm_graph_after_node_admission(request)
}

fn verify_npm_graph_after_node_admission(
    mut request: NpmGraphRequest,
) -> Result<VerifiedNpmGraph, AcquireError> {
    let observed = discover_package_inputs(
        &request.intent,
        &mut request.root_archive,
        &mut request.locked_archives,
    )?;
    if observed != request.package_inputs {
        return Err(AcquireError::Graph);
    }
    let root = inspect_npm_archive(&mut request.root_archive, true)?;
    Ok(VerifiedNpmGraph {
        intent: request.intent,
        node_archive: request.node_archive,
        root_archive: request.root_archive,
        locked_archives: request.locked_archives,
        package_inputs: request.package_inputs,
        root_manifest: root.declaration,
        shrinkwrap: root.shrinkwrap.ok_or(AcquireError::Graph)?,
    })
}

#[cfg(test)]
fn verify_npm_graph_after_exact_node_for_test(
    request: NpmGraphRequest,
) -> Result<VerifiedNpmGraph, AcquireError> {
    verify_npm_graph_after_node_admission(request)
}

fn pi_metadata(
    intent: &InitialPiReleaseIntentV1,
) -> Result<&PiCatalogExtensionMetadata, AcquireError> {
    match intent.release().catalog_release().provider_extension() {
        ProviderExtensionV1::Pi(metadata) => Ok(metadata),
        ProviderExtensionV1::None => Err(AcquireError::Graph),
    }
}

fn require_exact_intent(
    intent: &InitialPiReleaseIntentV1,
    metadata: &PiCatalogExtensionMetadata,
) -> Result<(), AcquireError> {
    if intent.release().provider() != "builtin:pi"
        || intent.release().target().as_str() != "linux_x86_64"
        || intent.release().pi_version().as_str() != ROOT_VERSION
        || intent.release().node_version().as_str() != NODE_VERSION
        || metadata.approved_package().name().as_str() != ROOT_NAME
        || metadata.approved_package().version().as_str() != ROOT_VERSION
        || metadata.expected_entrypoint().as_str() != ENTRYPOINT
        || metadata.shipped_shrinkwrap().lockfile_version() != 3
        || metadata.shipped_shrinkwrap().locked_packages().len() != LOCKED_COUNT
    {
        return Err(AcquireError::Graph);
    }
    Ok(())
}

fn pi_artifact<'a>(
    intent: &'a InitialPiReleaseIntentV1,
    metadata: &PiCatalogExtensionMetadata,
) -> Result<&'a ArtifactDescriptor, AcquireError> {
    intent
        .release()
        .catalog_release()
        .components()
        .iter()
        .find(|component| component.component_id() == metadata.component_id())
        .and_then(|component| {
            component
                .artifacts()
                .iter()
                .find(|artifact| artifact.artifact_id() == metadata.package_artifact_id())
        })
        .ok_or(AcquireError::Graph)
}

fn node_artifact(intent: &InitialPiReleaseIntentV1) -> Result<&ArtifactDescriptor, AcquireError> {
    let component = intent
        .release()
        .catalog_release()
        .components()
        .iter()
        .find(|component| component.component_id().as_str() == "component:node")
        .ok_or(AcquireError::Graph)?;
    if component.version().as_str() != NODE_VERSION || component.artifacts().len() != 1 {
        return Err(AcquireError::Graph);
    }
    component.artifacts().first().ok_or(AcquireError::Graph)
}

fn require_archive(
    archive: &VerifiedArchive,
    descriptor: &ArtifactDescriptor,
    sri: Option<&str>,
) -> Result<(), AcquireError> {
    if archive.source_url() != descriptor.url().as_str()
        || archive.size() != descriptor.size_bytes().get()
        || archive.sha256() != descriptor.sha256().as_str()
        || archive.sri() != sri
    {
        return Err(AcquireError::Graph);
    }
    Ok(())
}

fn require_locked_archive(
    archive: &VerifiedArchive,
    record: &LockedPackageRecord,
) -> Result<(), AcquireError> {
    if archive.source_url() != record.resolved_url().as_str()
        || archive.sha256() != record.archive_sha256().as_str()
        || archive.sri() != Some(record.registry_integrity().as_str())
    {
        return Err(AcquireError::Graph);
    }
    Ok(())
}

fn verify_root_documents(
    intent: &InitialPiReleaseIntentV1,
    metadata: &PiCatalogExtensionMetadata,
    declaration: &Map<String, Value>,
    shrinkwrap: &Map<String, Value>,
    inspection: &NpmArchiveInspection,
) -> Result<(), AcquireError> {
    let shrinkwrap_bytes = inspection.shrinkwrap.as_ref().ok_or(AcquireError::Graph)?;
    if sha256(&inspection.declaration) != metadata.root_package_manifest().sha256().as_str()
        || inspection.declaration.len() as u64
            != metadata.root_package_manifest().size_bytes().get()
        || sha256(shrinkwrap_bytes) != metadata.shipped_shrinkwrap().artifact().sha256().as_str()
        || shrinkwrap_bytes.len() as u64
            != metadata.shipped_shrinkwrap().artifact().size_bytes().get()
    {
        return Err(AcquireError::Graph);
    }
    require_string(declaration, "name", ROOT_NAME)?;
    require_string(declaration, "version", ROOT_VERSION)?;
    let bin = declaration
        .get("bin")
        .and_then(Value::as_object)
        .ok_or(AcquireError::Graph)?;
    require_string(bin, "pi", ENTRYPOINT)?;
    require_string(shrinkwrap, "name", ROOT_NAME)?;
    require_string(shrinkwrap, "version", ROOT_VERSION)?;
    if shrinkwrap.get("lockfileVersion").and_then(Value::as_u64) != Some(3)
        || shrinkwrap.get("requires").and_then(Value::as_bool) != Some(true)
        || intent.release().catalog_release().version().as_str() != ROOT_VERSION
    {
        return Err(AcquireError::Graph);
    }
    Ok(())
}

type LockPackageRecord = (String, Map<String, Value>);

fn lock_package_records(
    shrinkwrap: &Map<String, Value>,
) -> Result<Vec<LockPackageRecord>, AcquireError> {
    let packages = shrinkwrap
        .get("packages")
        .and_then(Value::as_object)
        .ok_or(AcquireError::Graph)?;
    if packages.len() != LOCKED_COUNT + 1 || !packages.contains_key("") {
        return Err(AcquireError::Graph);
    }
    let mut records = packages
        .iter()
        .map(|(locator, value)| {
            value
                .as_object()
                .cloned()
                .map(|record| (locator.clone(), record))
                .ok_or(AcquireError::Graph)
        })
        .collect::<Result<Vec<_>, _>>()?;
    records.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    Ok(records)
}

fn verify_lock_records(
    metadata: &PiCatalogExtensionMetadata,
    packages: &[LockPackageRecord],
) -> Result<(), AcquireError> {
    let locked = packages.iter().filter(|(locator, _)| !locator.is_empty());
    for ((locator, package), expected) in
        locked.zip(metadata.shipped_shrinkwrap().locked_packages())
    {
        if locator != expected.locator().as_str() {
            return Err(AcquireError::Graph);
        }
        if package.get("name").is_some() {
            require_string(package, "name", expected.name().as_str())?;
        }
        require_string(package, "version", expected.version().as_str())?;
        require_string(package, "resolved", expected.resolved_url().as_str())?;
        match package.get("integrity").and_then(Value::as_str) {
            Some(value) if value == expected.registry_integrity().as_str() => {}
            None if MISSING_LOCK_INTEGRITY.contains(&locator.as_str()) => {}
            _ => return Err(AcquireError::Graph),
        }
    }
    Ok(())
}

fn verify_complete_closure(packages: &[(String, Map<String, Value>)]) -> Result<(), AcquireError> {
    let locators = packages
        .iter()
        .map(|(locator, _)| locator.as_str())
        .collect::<BTreeSet<_>>();
    for (locator, package) in packages {
        for field in ["dependencies", "optionalDependencies"] {
            let Some(dependencies) = package.get(field) else {
                continue;
            };
            let dependencies = dependencies.as_object().ok_or(AcquireError::Graph)?;
            for name in dependencies.keys() {
                if !dependency_resolves(locator, name, &locators) {
                    return Err(AcquireError::Graph);
                }
            }
        }
    }
    Ok(())
}

fn dependency_resolves(locator: &str, name: &str, locators: &BTreeSet<&str>) -> bool {
    let mut base = locator.to_owned();
    loop {
        let candidate = if base.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{base}/node_modules/{name}")
        };
        if locators.contains(candidate.as_str()) {
            return true;
        }
        let Some(index) = base.rfind("/node_modules/") else {
            break;
        };
        base.truncate(index);
    }
    locators.contains(format!("node_modules/{name}").as_str())
}

fn applicability_reasons(
    declaration: &Map<String, Value>,
    lock: &Map<String, Value>,
) -> Result<Vec<String>, AcquireError> {
    let mut reasons = Vec::new();
    for (source, object) in [("declaration", declaration), ("lock", lock)] {
        for (field, target) in [("os", "linux"), ("cpu", "x64"), ("libc", "glibc")] {
            if let Some(value) = object.get(field)
                && !selector_allows(value, target)?
            {
                reasons.push(format!("{source}.{field}"));
            }
        }
    }
    reasons.sort();
    reasons.dedup();
    Ok(reasons)
}

fn selector_allows(value: &Value, target: &str) -> Result<bool, AcquireError> {
    let values = match value {
        Value::String(value) => vec![value.as_str()],
        Value::Array(values) if !values.is_empty() => values
            .iter()
            .map(|value| value.as_str().ok_or(AcquireError::Graph))
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(AcquireError::Graph),
    };
    if values.iter().any(|value| *value == format!("!{target}")) {
        return Ok(false);
    }
    let positives = values
        .iter()
        .filter(|value| !value.starts_with('!'))
        .collect::<Vec<_>>();
    Ok(positives.is_empty() || positives.iter().any(|value| **value == target))
}

fn parse_json_object(bytes: &[u8], maximum: usize) -> Result<Map<String, Value>, AcquireError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(AcquireError::Graph);
    }
    reject_duplicate_json(bytes)?;
    serde_json::from_slice::<Value>(bytes)
        .map_err(|_| AcquireError::Graph)?
        .as_object()
        .cloned()
        .ok_or(AcquireError::Graph)
}

fn require_string(
    object: &Map<String, Value>,
    field: &str,
    expected: &str,
) -> Result<(), AcquireError> {
    if object.get(field).and_then(Value::as_str) == Some(expected) {
        Ok(())
    } else {
        Err(AcquireError::Graph)
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn reject_duplicate_json(bytes: &[u8]) -> Result<(), AcquireError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    NoDuplicates::deserialize(&mut deserializer).map_err(|_| AcquireError::Graph)?;
    deserializer.end().map_err(|_| AcquireError::Graph)
}

struct NoDuplicates;

impl<'de> Deserialize<'de> for NoDuplicates {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateVisitor)
    }
}

struct NoDuplicateVisitor;

impl<'de> de::Visitor<'de> for NoDuplicateVisitor {
    type Value = NoDuplicates;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("duplicate-free JSON")
    }
    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }
    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        value
            .is_finite()
            .then_some(NoDuplicates)
            .ok_or_else(|| E::custom("number"))
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }
    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }
    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        NoDuplicates::deserialize(deserializer)
    }
    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        while sequence.next_element::<NoDuplicates>()?.is_some() {}
        Ok(NoDuplicates)
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 256 || !keys.insert(key) {
                return Err(de::Error::custom("duplicate key"));
            }
            map.next_value::<NoDuplicates>()?;
        }
        Ok(NoDuplicates)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        io::Write,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use base64::Engine as _;
    use flate2::{Compression, write::GzEncoder};
    use serde_json::{Map, Value, json};
    use sha2::{Digest, Sha256, Sha512};

    use super::{
        AcquireError, MISSING_LOCK_INTEGRITY, NpmGraphRequest, PRUNED, PackageInputManifestV1,
        VerifiedArchive, discover_package_inputs, verify_npm_graph_after_exact_node_for_test,
    };

    #[test]
    fn post_exact_node_graph_accepts_root_plus_139_locked_archives() {
        let graph = verify_npm_graph_after_exact_node_for_test(GraphFixture::new().request())
            .expect("the admitted exact-Node production graph body");
        assert_eq!(graph.root_package_count(), 1);
        assert_eq!(graph.locked_package_count(), 139);
        assert_eq!(graph.total_archive_count(), 140);
    }

    #[test]
    fn post_exact_node_graph_reaches_named_mutation_checks() {
        let mut archive_substitution = GraphFixture::new();
        archive_substitution.locked.swap(0, 1);
        assert_graph_rejected(archive_substitution.request(), "archive substitution");

        let fixture = GraphFixture::new();
        let mut manifest: Value =
            serde_json::from_slice(&fixture.inputs.canonical_bytes().unwrap()).unwrap();
        manifest["root"]["archive_member_count"] = Value::from(999_u64);
        let manifest =
            PackageInputManifestV1::from_json(&serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert_graph_rejected(fixture.request_with_inputs(manifest), "manifest binding");

        let baseline_inputs = GraphFixture::new().inputs;
        for (mutation, label) in [
            (GraphMutation::LockSwap, "lock swap"),
            (GraphMutation::MissingClosure, "complete closure"),
            (
                GraphMutation::InapplicableRequiredPackage,
                "platform applicability",
            ),
        ] {
            assert_graph_rejected(
                GraphFixture::mutated(mutation, baseline_inputs.clone()).request(),
                label,
            );
        }
    }

    fn assert_graph_rejected(request: NpmGraphRequest, label: &str) {
        assert!(
            matches!(
                verify_npm_graph_after_exact_node_for_test(request),
                Err(AcquireError::Graph)
            ),
            "{label} did not reach its post-Node graph rejection"
        );
    }

    #[derive(Clone, Copy)]
    enum GraphMutation {
        LockSwap,
        MissingClosure,
        InapplicableRequiredPackage,
    }

    struct GraphFixture {
        intent: catalog_core::InitialPiReleaseIntentV1,
        node: VerifiedArchive,
        root: VerifiedArchive,
        locked: Vec<VerifiedArchive>,
        inputs: PackageInputManifestV1,
    }

    impl GraphFixture {
        fn new() -> Self {
            Self::build(None, None)
        }

        fn mutated(mutation: GraphMutation, inputs: PackageInputManifestV1) -> Self {
            Self::build(Some(mutation), Some(inputs))
        }

        fn build(
            mutation: Option<GraphMutation>,
            supplied_inputs: Option<PackageInputManifestV1>,
        ) -> Self {
            let mut locators = BTreeSet::new();
            locators.extend(PRUNED.iter().map(|(locator, _)| (*locator).to_owned()));
            locators.extend(
                MISSING_LOCK_INTEGRITY
                    .iter()
                    .map(|locator| (*locator).to_owned()),
            );
            let mut index = 0;
            while locators.len() < 139 {
                locators.insert(format!("node_modules/package-{index:03}"));
                index += 1;
            }

            let mut locked = Vec::new();
            let mut locked_records = Vec::new();
            let mut lock_packages = Map::new();
            lock_packages.insert(
                "".into(),
                json!({"name":"@earendil-works/pi-coding-agent","version":"0.83.0"}),
            );
            for locator in locators {
                let name = locator.rsplit("node_modules/").next().unwrap().to_owned();
                let mut declaration = Map::from_iter([
                    ("name".into(), Value::String(name.clone())),
                    ("version".into(), Value::String("1.0.0".into())),
                ]);
                declaration.extend(selectors(&locator, "declaration"));
                if matches!(mutation, Some(GraphMutation::InapplicableRequiredPackage))
                    && locator == "node_modules/package-000"
                {
                    declaration.insert("os".into(), Value::String("darwin".into()));
                }
                let declaration = serde_json::to_vec(&Value::Object(declaration)).unwrap();
                let bytes = gzip(&tar(&[TarEntry::file(
                    "package/package.json",
                    &declaration,
                )]));
                let digest = sha256(&bytes);
                let integrity = sri(&bytes);
                let encoded_name = name.replace('@', "").replace('/', "-");
                let url =
                    format!("https://registry.npmjs.org/{encoded_name}/-/{encoded_name}-1.0.0.tgz");
                let mut lock = Map::from_iter([
                    ("version".into(), Value::String("1.0.0".into())),
                    ("resolved".into(), Value::String(url.clone())),
                ]);
                if !MISSING_LOCK_INTEGRITY.contains(&locator.as_str()) {
                    lock.insert("integrity".into(), Value::String(integrity.clone()));
                }
                lock.extend(selectors(&locator, "lock"));
                if PRUNED.iter().any(|(expected, _)| *expected == locator) {
                    lock.insert("optional".into(), Value::Bool(true));
                }
                lock_packages.insert(locator.clone(), Value::Object(lock));
                locked_records.push(json!({
                    "locator": locator,
                    "name": name,
                    "version": "1.0.0",
                    "resolved_url": url,
                    "registry_integrity": integrity,
                    "archive_sha256": digest,
                }));
                locked.push(verified(bytes, &url, Some(&integrity)));
            }

            if matches!(mutation, Some(GraphMutation::LockSwap)) {
                lock_packages["node_modules/package-000"]["resolved"] = Value::String(
                    "https://registry.npmjs.org/package-001/-/package-001-1.0.0.tgz".into(),
                );
            }
            if matches!(mutation, Some(GraphMutation::MissingClosure)) {
                lock_packages[""]["dependencies"] = json!({"not-in-the-lock":"1.0.0"});
            }

            let root_manifest = serde_json::to_vec(&json!({
                "name":"@earendil-works/pi-coding-agent",
                "version":"0.83.0",
                "bin":{"pi":"dist/cli.js"}
            }))
            .unwrap();
            let shrinkwrap = serde_json::to_vec(&json!({
                "name":"@earendil-works/pi-coding-agent",
                "version":"0.83.0",
                "lockfileVersion":3,
                "requires":true,
                "packages":lock_packages
            }))
            .unwrap();
            let root_bytes = gzip(&tar(&[
                TarEntry::file("package/package.json", &root_manifest),
                TarEntry::file("package/npm-shrinkwrap.json", &shrinkwrap),
                TarEntry::file("package/dist/cli.js", b"entry"),
            ]));
            let root_digest = sha256(&root_bytes);
            let root_integrity = sri(&root_bytes);
            let node_bytes = b"test-only exact-Node admission marker".to_vec();
            let node_digest = sha256(&node_bytes);
            let intent_json = json!({
                "sequence":"1",
                "tag":"catalog-v1-sequence-1",
                "generated_at":"2026-08-26T00:00:00Z",
                "expires_at":"2026-09-26T00:00:00Z",
                "fluxsemble_requirement":"=0.1.0",
                "release":{
                    "provider":"builtin:pi",
                    "allowed_origins":["https://nodejs.org","https://registry.npmjs.org"],
                    "release":{
                        "version":"0.83.0",
                        "target":"linux_x86_64",
                        "compatibility_ranges":["=0.1.0"],
                        "release_metadata":{"title":"Pi","notes":"fixture"},
                        "components":[
                            {
                                "component_id":"component:node",
                                "version":"22.19.0",
                                "artifacts":[{
                                    "artifact_id":"artifact:node",
                                    "url":"https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.xz",
                                    "size_bytes":node_bytes.len().to_string(),
                                    "sha256":node_digest,
                                    "inventory":[]
                                }]
                            },
                            {
                                "component_id":"component:pi",
                                "version":"0.83.0",
                                "artifacts":[{
                                    "artifact_id":"artifact:pi",
                                    "url":"https://registry.npmjs.org/pi/-/pi-0.83.0.tgz",
                                    "size_bytes":root_bytes.len().to_string(),
                                    "sha256":root_digest,
                                    "inventory":[{
                                        "path":"dist/cli.js",
                                        "size_bytes":"5",
                                        "sha256":sha256(b"entry")
                                    }]
                                }]
                            }
                        ],
                        "provider_extension":{
                            "kind":"pi",
                            "metadata":{
                                "approved_package":{
                                    "name":"@earendil-works/pi-coding-agent",
                                    "version":"0.83.0"
                                },
                                "expected_entrypoint":"dist/cli.js",
                                "component_id":"component:pi",
                                "package_artifact_id":"artifact:pi",
                                "registry_integrity":root_integrity,
                                "root_package_manifest":{
                                    "url":"https://registry.npmjs.org/support/package.json",
                                    "size_bytes":root_manifest.len().to_string(),
                                    "sha256":sha256(&root_manifest)
                                },
                                "shipped_shrinkwrap":{
                                    "lockfile_version":3,
                                    "root_package":{
                                        "name":"@earendil-works/pi-coding-agent",
                                        "version":"0.83.0"
                                    },
                                    "artifact":{
                                        "url":"https://registry.npmjs.org/support/npm-shrinkwrap.json",
                                        "size_bytes":shrinkwrap.len().to_string(),
                                        "sha256":sha256(&shrinkwrap)
                                    },
                                    "locked_packages":locked_records
                                }
                            }
                        }
                    }
                }
            });
            let intent = catalog_core::InitialPiReleaseIntentV1::from_json(
                &serde_json::to_vec(&intent_json).unwrap(),
            )
            .unwrap();
            let mut root = verified(
                root_bytes,
                "https://registry.npmjs.org/pi/-/pi-0.83.0.tgz",
                Some(&root_integrity),
            );
            let mut locked_for_graph = locked;
            let inputs = match supplied_inputs {
                Some(inputs) => inputs,
                None => discover_package_inputs(&intent, &mut root, &mut locked_for_graph).unwrap(),
            };
            Self {
                intent,
                node: verified(
                    node_bytes,
                    "https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.xz",
                    None,
                ),
                root,
                locked: locked_for_graph,
                inputs,
            }
        }

        fn request(self) -> NpmGraphRequest {
            let inputs = self.inputs.clone();
            self.request_with_inputs(inputs)
        }

        fn request_with_inputs(self, package_inputs: PackageInputManifestV1) -> NpmGraphRequest {
            NpmGraphRequest {
                intent: self.intent,
                node_archive: self.node,
                root_archive: self.root,
                locked_archives: self.locked,
                package_inputs,
            }
        }
    }

    fn selectors(locator: &str, source: &str) -> Map<String, Value> {
        let mut result = Map::new();
        let Some((_, reasons)) = PRUNED.iter().find(|(expected, _)| *expected == locator) else {
            return result;
        };
        for reason in *reasons {
            let Some(field) = reason.strip_prefix(&format!("{source}.")) else {
                continue;
            };
            let value = match field {
                "os" => "darwin",
                "cpu" => "arm64",
                "libc" => "musl",
                _ => unreachable!(),
            };
            result.insert(field.into(), Value::String(value.into()));
        }
        result
    }

    struct TarEntry {
        path: String,
        data: Vec<u8>,
    }

    impl TarEntry {
        fn file(path: &str, data: &[u8]) -> Self {
            Self {
                path: path.into(),
                data: data.into(),
            }
        }
    }

    fn tar(entries: &[TarEntry]) -> Vec<u8> {
        let mut output = Vec::new();
        for entry in entries {
            let mut header = [0_u8; 512];
            let bytes = entry.path.as_bytes();
            header[..bytes.len()].copy_from_slice(bytes);
            write_octal(&mut header[100..108], 0o644);
            write_octal(&mut header[108..116], 0);
            write_octal(&mut header[116..124], 0);
            write_octal(&mut header[124..136], entry.data.len() as u64);
            write_octal(&mut header[136..148], 0);
            header[148..156].fill(b' ');
            header[156] = b'0';
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
            header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
            output.extend_from_slice(&header);
            output.extend_from_slice(&entry.data);
            output.resize(output.len().div_ceil(512) * 512, 0);
        }
        output.resize(output.len() + 1024, 0);
        output
    }

    fn write_octal(field: &mut [u8], value: u64) {
        let width = field.len() - 1;
        field.fill(0);
        let text = format!("{value:0width$o}");
        field[..width].copy_from_slice(text.as_bytes());
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut output = GzEncoder::new(Vec::new(), Compression::default());
        output.write_all(bytes).unwrap();
        output.finish().unwrap()
    }

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn sri(bytes: &[u8]) -> String {
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
        )
    }

    fn verified(bytes: Vec<u8>, url: &str, sri_value: Option<&str>) -> VerifiedArchive {
        let path = temp_file();
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let file = fs::File::open(&path).unwrap();
        let archive = VerifiedArchive::verify(
            file,
            url.into(),
            bytes.len() as u64,
            sha256(&bytes),
            sri_value.map(str::to_owned),
        )
        .unwrap();
        fs::remove_file(path).unwrap();
        archive
    }

    fn temp_file() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        std::env::temp_dir().join(format!(
            "catalog-npm-graph-unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }
}
