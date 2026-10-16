//! External installer input discovery. Candidates are inert and never authorize publication.
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    str::FromStr,
};

use catalog_core::{PiReleaseProfileV1, PiRequiredContractsV1, pi_release_subject_sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::archive::VerifiedArchive;
use crate::archive::{inspect_node_archive, inspect_npm_archive};
use crate::policy::{
    applicability_reasons, lock_package_records, npm_metadata_url, parse_json_object,
    parse_node_checksum, parse_npm_metadata, reject_duplicate_json, require_registry_url,
    require_string, sha256, valid_sha256, valid_sri, validate_discovery_request,
};
use crate::{AcquireError, DiscoverPiReleaseRequest};
use std::io::Cursor;

/// Byte/claim supplier. Implementations confer no verification authority.
pub trait InstallerInputs {
    fn read(&self, url: &str, maximum: usize) -> Result<Vec<u8>, AcquireError>;
}
fn verified_bytes(
    bytes: Vec<u8>,
    url: &str,
    sri: Option<&str>,
) -> Result<VerifiedArchive<Cursor<Vec<u8>>>, AcquireError> {
    let size = bytes.len() as u64;
    let digest = sha256(&bytes);
    VerifiedArchive::verify(
        Cursor::new(bytes),
        url.into(),
        size,
        digest,
        sri.map(str::to_owned),
    )
}

const PI: &str = "@earendil-works/pi-coding-agent";
const ROOT: &str = "@earendil-works/pi-coding-agent-install";
const PI_LOCATOR: &str = "node_modules/@earendil-works/pi-coding-agent";
const UPSTREAM: &str = "https://github.com/earendil-works/pi/releases/download/v";
const MANIFEST_ASSET: &str = "pi-coding-agent-install-package.json";
const LOCK_ASSET: &str = "pi-coding-agent-install-package-lock.json";
const MAX_PACKAGES: usize = 512;
const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: usize = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiInstallerDiscoveryPolicy {
    pub consumer_requirement: String,
    pub required_contracts: PiRequiredContractsV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiInstallerCandidateV1 {
    pub profile: PiReleaseProfileV1,
    pub inputs: PackageInputManifestV2,
}
impl PiInstallerCandidateV1 {
    pub fn release_subject_sha256(&self) -> Result<[u8; 32], AcquireError> {
        pi_release_subject_sha256(&self.profile).map_err(|_| AcquireError::Graph)
    }
}

/// Bounded immutable exact-archive graph, including pruned optional packages.
/// Parsing proves structure only; discovery validates the actual archive and lock bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageInputManifestV2 {
    schema_version: u16,
    release_subject_sha256: String,
    installer_manifest_source: InstallerInputSourceV1,
    installer_lock_source: InstallerInputSourceV1,
    auxiliary_inputs: Vec<InstallerInputSourceV1>,
    locked_packages: Vec<PackageArchiveInput>,
    pre_prune_package_count: u16,
    applicable_package_count: u16,
}
/// Exact public upstream support bytes to reacquire before publishing the planned descriptors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallerInputSourceV1 {
    url: String,
    #[serde(serialize_with = "serialize_source_size")]
    size_bytes: u64,
    sha256: String,
}
fn serialize_source_size<S: serde::Serializer>(
    size: &u64,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&size.to_string())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallerInputSourceWire {
    url: String,
    size_bytes: String,
    sha256: String,
}
impl InstallerInputSourceWire {
    fn into_source(self) -> Result<InstallerInputSourceV1, AcquireError> {
        let size = self
            .size_bytes
            .parse::<u64>()
            .map_err(|_| AcquireError::Graph)?;
        if size == 0 || size.to_string() != self.size_bytes {
            return Err(AcquireError::Graph);
        }
        Ok(InstallerInputSourceV1 {
            url: self.url,
            size_bytes: size,
            sha256: self.sha256,
        })
    }
}
impl InstallerInputSourceV1 {
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    fn matches_descriptor(&self, descriptor: &catalog_core::ImmutableFileDescriptor) -> bool {
        self.size_bytes == descriptor.size_bytes().get()
            && self.sha256 == descriptor.sha256().as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageArchiveInput {
    locator: String,
    name: String,
    version: String,
    resolved_url: String,
    registry_integrity: String,
    archive_size: u64,
    archive_sha256: String,
    declaration_size: u64,
    declaration_sha256: String,
    archive_member_count: u32,
    pruned_reasons: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputWire {
    schema_version: u16,
    release_subject_sha256: String,
    installer_manifest_source: InstallerInputSourceWire,
    installer_lock_source: InstallerInputSourceWire,
    auxiliary_inputs: Vec<InstallerInputSourceWire>,
    locked_packages: Vec<PackageArchiveInput>,
    pre_prune_package_count: u16,
    applicable_package_count: u16,
}
impl PackageInputManifestV2 {
    pub fn auxiliary_inputs(&self) -> &[InstallerInputSourceV1] {
        &self.auxiliary_inputs
    }
    pub fn archive_size_for(&self, locator: &str) -> Option<u64> {
        self.locked_packages
            .iter()
            .find(|p| p.locator == locator)
            .map(|p| p.archive_size)
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self, AcquireError> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(AcquireError::Graph);
        }
        reject_duplicate_json(bytes)?;
        let w: InputWire = serde_json::from_slice(bytes).map_err(|_| AcquireError::Graph)?;
        let result = Self {
            schema_version: w.schema_version,
            release_subject_sha256: w.release_subject_sha256,
            installer_manifest_source: w.installer_manifest_source.into_source()?,
            installer_lock_source: w.installer_lock_source.into_source()?,
            auxiliary_inputs: w
                .auxiliary_inputs
                .into_iter()
                .map(InstallerInputSourceWire::into_source)
                .collect::<Result<_, _>>()?,
            locked_packages: w.locked_packages,
            pre_prune_package_count: w.pre_prune_package_count,
            applicable_package_count: w.applicable_package_count,
        };
        result.validate()?;
        Ok(result)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AcquireError> {
        self.validate()?;
        let bytes = serde_jcs::to_vec(self).map_err(|_| AcquireError::Graph)?;
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(AcquireError::Graph);
        }
        Ok(bytes)
    }
    #[must_use]
    pub fn locked_package_count(&self) -> usize {
        self.locked_packages.len()
    }
    #[must_use]
    pub fn pre_prune_package_count(&self) -> usize {
        usize::from(self.pre_prune_package_count)
    }
    #[must_use]
    pub fn installer_manifest_source(&self) -> &InstallerInputSourceV1 {
        &self.installer_manifest_source
    }
    #[must_use]
    pub fn installer_lock_source(&self) -> &InstallerInputSourceV1 {
        &self.installer_lock_source
    }
    /// Bind inert decoded archive facts and original acquisition descriptors to the release profile.
    /// This does not authorize acquisition, publication, or installation.
    pub fn validate_for_profile(&self, profile: &PiReleaseProfileV1) -> Result<(), AcquireError> {
        self.validate()?;
        let subject = pi_release_subject_sha256(profile).map_err(|_| AcquireError::Graph)?;
        let expected: String = subject.iter().map(|b| format!("{b:02x}")).collect();
        if expected != self.release_subject_sha256
            || !self
                .installer_manifest_source
                .matches_descriptor(profile.installer_manifest())
            || !self
                .installer_lock_source
                .matches_descriptor(profile.installer_lock())
            || self.locked_packages.len() != profile.locked_packages().len()
        {
            return Err(AcquireError::Graph);
        }
        for (input, locked) in self.locked_packages.iter().zip(profile.locked_packages()) {
            if input.locator != locked.locator().as_str()
                || input.name != locked.name().as_str()
                || input.version != locked.version().as_str()
                || input.resolved_url != locked.resolved_url().as_str()
                || input.registry_integrity != locked.registry_integrity().as_str()
                || input.archive_sha256 != locked.archive_sha256().as_str()
            {
                return Err(AcquireError::Graph);
            }
        }
        let pi = self
            .locked_packages
            .iter()
            .find(|p| p.locator == PI_LOCATOR)
            .ok_or(AcquireError::Graph)?;
        if pi.declaration_size != profile.pi_manifest().size_bytes().get()
            || pi.declaration_sha256 != profile.pi_manifest().sha256().as_str()
        {
            return Err(AcquireError::Graph);
        }
        let artifact = profile
            .components()
            .iter()
            .flat_map(|c| c.artifacts())
            .find(|a| a.artifact_id() == profile.pi_artifact_id())
            .ok_or(AcquireError::Graph)?;
        if pi.archive_size != artifact.size_bytes().get() {
            return Err(AcquireError::Graph);
        }
        Ok(())
    }
    fn validate(&self) -> Result<(), AcquireError> {
        let applicable = self
            .locked_packages
            .iter()
            .filter(|p| p.pruned_reasons.is_empty())
            .count();
        if self.schema_version != 2
            || self.locked_packages.is_empty()
            || self.locked_packages.len() > MAX_PACKAGES
            || self.pre_prune_package_count() != self.locked_packages.len() + 1
            || usize::from(self.applicable_package_count) != applicable
            || self.installer_manifest_source.size_bytes == 0
            || self.installer_manifest_source.size_bytes > 64 * 1024
            || self.installer_lock_source.size_bytes == 0
            || self.installer_lock_source.size_bytes > 1024 * 1024
            || !valid_sha256(&self.installer_manifest_source.sha256)
            || !valid_sha256(&self.installer_lock_source.sha256)
            || !valid_sha256(&self.release_subject_sha256)
            || self
                .locked_packages
                .windows(2)
                .any(|p| p[0].locator >= p[1].locator)
        {
            return Err(AcquireError::Graph);
        }
        let pi = self
            .locked_packages
            .iter()
            .find(|p| p.locator == PI_LOCATOR && p.name == PI)
            .ok_or(AcquireError::Graph)?;
        if self.installer_manifest_source.url
            != format!("{UPSTREAM}{}/{MANIFEST_ASSET}", pi.version)
            || self.installer_lock_source.url != format!("{UPSTREAM}{}/{LOCK_ASSET}", pi.version)
        {
            return Err(AcquireError::Graph);
        }
        if self.auxiliary_inputs.is_empty()
            || self.auxiliary_inputs.len() > MAX_PACKAGES + 1
            || self
                .auxiliary_inputs
                .windows(2)
                .any(|p| p[0].url >= p[1].url)
            || self.auxiliary_inputs.iter().any(|p| {
                p.size_bytes == 0
                    || p.size_bytes > MAX_METADATA_BYTES as u64
                    || !valid_sha256(&p.sha256)
                    || p.url.len() > 4096
                    || !p.url.starts_with("https://")
                    || p.url.contains(['?', '#', '\\'])
            })
        {
            return Err(AcquireError::Graph);
        }
        let mut total = self
            .auxiliary_inputs
            .iter()
            .map(|p| p.size_bytes)
            .sum::<u64>();
        let mut identities = BTreeMap::new();
        for p in &self.locked_packages {
            validate_locator(&p.locator, &p.name)?;
            exact_version(&p.version)?;
            require_registry_url(&p.resolved_url)?;
            total = total
                .checked_add(p.archive_size)
                .ok_or(AcquireError::Graph)?;
            if total > MAX_TOTAL_BYTES as u64
                || p.archive_size == 0
                || p.archive_size > MAX_ARCHIVE_BYTES as u64
                || p.declaration_size == 0
                || p.declaration_size > 64 * 1024
                || p.archive_member_count == 0
                || p.archive_member_count > 32768
                || !valid_sha256(&p.archive_sha256)
                || !valid_sha256(&p.declaration_sha256)
                || !valid_sri(&p.registry_integrity)
                || p.pruned_reasons.windows(2).any(|p| p[0] >= p[1])
                || p.pruned_reasons.iter().any(|p| {
                    !matches!(
                        p.as_str(),
                        "declaration.cpu"
                            | "declaration.libc"
                            | "declaration.os"
                            | "lock.cpu"
                            | "lock.libc"
                            | "lock.os"
                    )
                })
            {
                return Err(AcquireError::Graph);
            }
            let facts = (&p.resolved_url, &p.registry_integrity, &p.archive_sha256);
            if identities
                .insert((&p.name, &p.version), facts)
                .is_some_and(|old| old != facts)
            {
                return Err(AcquireError::Graph);
            }
        }
        Ok(())
    }
}

pub fn derive_installer_release(
    request: DiscoverPiReleaseRequest,
    transport: &dyn InstallerInputs,
) -> Result<PiInstallerCandidateV1, AcquireError> {
    validate_discovery_request(&request)?;
    let policy = request
        .installer_policy
        .as_ref()
        .ok_or(AcquireError::Input)?;
    catalog_core::CompatibilityRange::from_str(&policy.consumer_requirement)
        .map_err(|_| AcquireError::Input)?;
    if request.node_version != "22.19.0" {
        return Err(AcquireError::Input);
    }
    let manifest_url = format!("{UPSTREAM}{}/{MANIFEST_ASSET}", request.pi_version);
    let lock_url = format!("{UPSTREAM}{}/{LOCK_ASSET}", request.pi_version);
    let mut budget = MAX_TOTAL_BYTES;
    let mut auxiliary_inputs = Vec::new();
    let manifest_bytes = fetch_bounded(transport, &manifest_url, 64 * 1024, &mut budget)?;
    let lock_bytes = fetch_bounded(transport, &lock_url, 1024 * 1024, &mut budget)?;
    let manifest = parse_json_object(&manifest_bytes, 64 * 1024)?;
    let lock = parse_json_object(&lock_bytes, 1024 * 1024)?;
    require_string(&manifest, "name", ROOT)?;
    let wrapper_version = string(&manifest, "version")?;
    exact_version(wrapper_version)?;
    require_string(&lock, "name", ROOT)?;
    require_string(&lock, "version", wrapper_version)?;
    if lock.get("lockfileVersion").and_then(Value::as_u64) != Some(3)
        || lock.get("requires").and_then(Value::as_bool) != Some(true)
    {
        return Err(AcquireError::Graph);
    }
    check_engine(&manifest, &request.node_version)?;
    let packages = lock_package_records(&lock)?;
    if packages.len() > MAX_PACKAGES + 1 {
        return Err(AcquireError::Graph);
    }
    let records: BTreeMap<_, _> = packages.iter().map(|(p, v)| (p.as_str(), v)).collect();
    let root = records.get("").ok_or(AcquireError::Graph)?;
    require_string(root, "name", ROOT)?;
    require_string(root, "version", wrapper_version)?;
    compare_dependencies(&manifest, root)?;
    for field in ["dependencies", "engines"] {
        if manifest.get(field) != root.get(field) {
            return Err(AcquireError::Graph);
        }
    }
    let deps = manifest
        .get("dependencies")
        .and_then(Value::as_object)
        .ok_or(AcquireError::Graph)?;
    require_string(deps, PI, &request.pi_version)?;
    verify_closure(&records)?;
    verify_root_overrides(&manifest, &lock, root, &records)?;

    let mut admitted_declarations = BTreeMap::from([(String::new(), manifest.clone())]);
    let mut pruned = BTreeSet::new();
    let mut descriptors = Vec::new();
    let mut observed = Vec::new();
    let mut pi_facts = None;
    for (locator, record) in packages.iter().filter(|(p, _)| !p.is_empty()) {
        let name = locator
            .rsplit("node_modules/")
            .next()
            .ok_or(AcquireError::Graph)?;
        validate_locator(locator, name)?;
        if record.contains_key("link")
            || record.get("dev").and_then(Value::as_bool) == Some(true)
            || record.get("inBundle").and_then(Value::as_bool) == Some(true)
        {
            return Err(AcquireError::Graph);
        }
        if record.contains_key("name") {
            require_string(record, "name", name)?;
        }
        let version = string(record, "version")?;
        exact_version(version)?;
        let resolved = string(record, "resolved")?;
        require_registry_url(resolved)?;
        let integrity = match record.get("integrity") {
            Some(Value::String(sri)) if valid_sri(sri) => sri.clone(),
            Some(_) => return Err(AcquireError::Graph),
            None => {
                let url = npm_metadata_url(name, version)?.replace('@', "%40");
                let bytes = fetch_bounded(transport, &url, MAX_METADATA_BYTES, &mut budget)?;
                auxiliary_inputs.push(InstallerInputSourceV1 {
                    url,
                    size_bytes: bytes.len() as u64,
                    sha256: sha256(&bytes),
                });
                parse_npm_metadata(&bytes, name, version, Some(resolved))?.1
            }
        };
        let bytes = fetch_bounded(transport, resolved, MAX_ARCHIVE_BYTES, &mut budget)?;
        let mut archive = verified_bytes(bytes, resolved, Some(&integrity))?;
        let inspection = inspect_npm_archive(&mut archive, false)?;
        let declaration = parse_json_object(&inspection.declaration, 64 * 1024)?;
        require_string(&declaration, "name", name)?;
        require_string(&declaration, "version", version)?;
        compare_dependencies(&declaration, record)?;
        let pruned_reasons = applicability_reasons(&declaration, record)?;
        if !pruned_reasons.is_empty() {
            pruned.insert(locator.as_str());
        }
        check_engine(&declaration, &request.node_version)?;
        check_engine(record, &request.node_version)?;
        let descriptor = json!({"locator":locator,"name":name,"version":version,"resolved_url":resolved,"registry_integrity":integrity,"archive_sha256":archive.sha256()});
        if locator == PI_LOCATOR {
            if version != request.pi_version {
                return Err(AcquireError::Graph);
            }
            let cli = declaration
                .get("bin")
                .and_then(Value::as_object)
                .and_then(|b| b.get("pi"))
                .and_then(Value::as_str)
                .ok_or(AcquireError::Graph)?;
            catalog_core::InventoryPath::from_str(cli).map_err(|_| AcquireError::Graph)?;
            let (size, digest) = inspection
                .package_regular_fact(cli)
                .ok_or(AcquireError::Archive)?;
            if !pruned_reasons.is_empty() {
                return Err(AcquireError::Graph);
            }
            pi_facts = Some((
                cli.to_owned(),
                size,
                digest,
                inspection.declaration.clone(),
                archive.size(),
                descriptor.clone(),
            ));
        }
        admitted_declarations.insert(locator.clone(), declaration);
        descriptors.push(descriptor);
        observed.push(PackageArchiveInput {
            locator: locator.clone(),
            name: name.into(),
            version: version.into(),
            resolved_url: resolved.into(),
            registry_integrity: integrity,
            archive_size: archive.size(),
            archive_sha256: archive.sha256().into(),
            declaration_size: inspection.declaration.len() as u64,
            declaration_sha256: sha256(&inspection.declaration),
            archive_member_count: inspection.member_count as u32,
            pruned_reasons,
        });
    }
    let admitted_records = admitted_declarations
        .iter()
        .map(|(locator, declaration)| (locator.as_str(), declaration))
        .collect();
    verify_applicable_closure(&admitted_records, &records, &pruned)?;
    let (cli, cli_size, cli_sha256, pi_manifest, pi_size, pi) =
        pi_facts.ok_or(AcquireError::Graph)?;
    let node_name = format!("node-v{}-linux-x64.tar.xz", request.node_version);
    let node_url = format!(
        "https://nodejs.org/dist/v{}/{node_name}",
        request.node_version
    );
    let checksums = fetch_bounded(
        transport,
        &format!(
            "https://nodejs.org/dist/v{}/SHASUMS256.txt",
            request.node_version
        ),
        1024 * 1024,
        &mut budget,
    )?;
    auxiliary_inputs.push(InstallerInputSourceV1 {
        url: format!(
            "https://nodejs.org/dist/v{}/SHASUMS256.txt",
            request.node_version
        ),
        size_bytes: checksums.len() as u64,
        sha256: sha256(&checksums),
    });
    auxiliary_inputs.sort_by(|a, b| a.url.cmp(&b.url));
    // Several locators may legitimately share one package identity/metadata response.
    // Only byte-identical descriptors collapse; a changing response at one URL still rejects.
    auxiliary_inputs.dedup();
    let node_sha256 = parse_node_checksum(&checksums, &node_name)?;
    let node_bytes = fetch_bounded(transport, &node_url, MAX_ARCHIVE_BYTES, &mut budget)?;
    let mut node_archive = verified_bytes(node_bytes, &node_url, None)?;
    if node_archive.sha256() != node_sha256 {
        return Err(AcquireError::DigestMismatch);
    }
    let node = inspect_node_archive(&mut node_archive)?;
    let support_prefix = format!(
        "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/catalog-v1-sequence-{}",
        request.sequence
    );
    // All profile descriptors are final planned sequence URLs before subject calculation.
    let manifest_descriptor =
        support_descriptor(&support_prefix, "pi-installer-package", &manifest_bytes);
    let lock_descriptor = support_descriptor(&support_prefix, "pi-installer-lock", &lock_bytes);
    let pi_descriptor = support_descriptor(&support_prefix, "pi-package", &pi_manifest);
    let profile = PiReleaseProfileV1::from_json(&serde_json::to_vec(&json!({
        "schema_version":1,"pi_package":{"name":PI,"version":request.pi_version},"node_version":request.node_version,"target":request.target,
        "consumer_requirement":policy.consumer_requirement,"required_contracts":policy.required_contracts,
        "installer_root":{"name":ROOT,"version":wrapper_version},"pi_package_locator":PI_LOCATOR,"cli_entrypoint":cli,
        "installer_manifest":manifest_descriptor,"installer_lock":lock_descriptor,"pi_manifest":pi_descriptor,
        "components":[{"component_id":"component:node","version":request.node_version,"artifacts":[{"artifact_id":"artifact:node-linux-x86_64","url":node_url,"size_bytes":node_archive.size().to_string(),"sha256":node_sha256,"inventory":[{"path":"bin/node","size_bytes":node.node_size.to_string(),"sha256":node.node_sha256}]}]},
        {"component_id":"component:pi","version":request.pi_version,"artifacts":[{"artifact_id":"artifact:pi-coding-agent","url":pi["resolved_url"],"size_bytes":pi_size.to_string(),"sha256":pi["archive_sha256"],"inventory":[{"path":cli,"size_bytes":cli_size.to_string(),"sha256":cli_sha256}]}]}],
        "pi_component_id":"component:pi","pi_artifact_id":"artifact:pi-coding-agent","node_component_id":"component:node","node_artifact_id":"artifact:node-linux-x86_64","registry_integrity":pi["registry_integrity"],"locked_packages":descriptors
    })).map_err(|_| AcquireError::Graph)?).map_err(|_| AcquireError::Graph)?;
    let subject = pi_release_subject_sha256(&profile).map_err(|_| AcquireError::Graph)?;
    let applicable_package_count = observed
        .iter()
        .filter(|p| p.pruned_reasons.is_empty())
        .count() as u16;
    let inputs = PackageInputManifestV2 {
        schema_version: 2,
        release_subject_sha256: subject.iter().map(|b| format!("{b:02x}")).collect(),
        installer_manifest_source: InstallerInputSourceV1 {
            url: manifest_url,
            size_bytes: manifest_bytes.len() as u64,
            sha256: sha256(&manifest_bytes),
        },
        installer_lock_source: InstallerInputSourceV1 {
            url: lock_url,
            size_bytes: lock_bytes.len() as u64,
            sha256: sha256(&lock_bytes),
        },
        auxiliary_inputs,
        pre_prune_package_count: (observed.len() + 1) as u16,
        applicable_package_count,
        locked_packages: observed,
    };
    inputs.validate_for_profile(&profile)?;
    Ok(PiInstallerCandidateV1 { profile, inputs })
}

pub fn is_installer_asset_url(url: &str) -> bool {
    let Some((version, asset)) = url.strip_prefix(UPSTREAM).and_then(|s| s.split_once('/')) else {
        return false;
    };
    exact_version(version).is_ok() && matches!(asset, MANIFEST_ASSET | LOCK_ASSET)
}
fn support_descriptor(prefix: &str, role: &str, bytes: &[u8]) -> Value {
    let digest = sha256(bytes);
    json!({"url":format!("{prefix}/{role}-{digest}.json"),"size_bytes":bytes.len().to_string(),"sha256":digest})
}
fn fetch_bounded(
    transport: &dyn InstallerInputs,
    url: &str,
    max: usize,
    budget: &mut usize,
) -> Result<Vec<u8>, AcquireError> {
    let bytes = transport.read(url, max.min(*budget))?;
    if bytes.is_empty() || bytes.len() > max || bytes.len() > *budget {
        return Err(AcquireError::SizeLimitExceeded);
    }
    *budget -= bytes.len();
    Ok(bytes)
}
fn string<'a>(o: &'a Map<String, Value>, key: &str) -> Result<&'a str, AcquireError> {
    o.get(key)
        .and_then(Value::as_str)
        .ok_or(AcquireError::Graph)
}
fn exact_version(s: &str) -> Result<(), AcquireError> {
    catalog_core::ExactVersion::from_str(s)
        .map(|_| ())
        .map_err(|_| AcquireError::Graph)
}
fn validate_locator(locator: &str, name: &str) -> Result<(), AcquireError> {
    catalog_core::InventoryPath::from_str(locator).map_err(|_| AcquireError::Graph)?;
    let parts: Vec<_> = locator.split("node_modules/").collect();
    if parts.first() != Some(&"") || parts.len() < 2 {
        return Err(AcquireError::Graph);
    }
    for (i, p) in parts[1..].iter().enumerate() {
        let p = if i + 2 == parts.len() {
            *p
        } else {
            p.strip_suffix('/').ok_or(AcquireError::Graph)?
        };
        catalog_core::PackageName::from_str(p).map_err(|_| AcquireError::Graph)?;
        if i + 2 == parts.len() && p != name {
            return Err(AcquireError::Graph);
        }
    }
    Ok(())
}
fn compare_dependencies(
    declaration: &Map<String, Value>,
    record: &Map<String, Value>,
) -> Result<(), AcquireError> {
    for field in [
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "peerDependenciesMeta",
    ] {
        // npm omits empty maps in package-lock entries; null and nonobjects are invalid.
        if dependency_map(declaration, field)? != dependency_map(record, field)? {
            return Err(AcquireError::Graph);
        }
    }
    Ok(())
}
fn dependency_map<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a Map<String, Value>>, AcquireError> {
    match object.get(field) {
        None => Ok(None),
        Some(value) => {
            let map = value.as_object().ok_or(AcquireError::Graph)?;
            Ok((!map.is_empty()).then_some(map))
        }
    }
}
fn resolve<'a>(
    locator: &str,
    name: &str,
    records: &BTreeMap<&'a str, &Map<String, Value>>,
) -> Option<&'a str> {
    let mut base = locator;
    loop {
        let candidate = if base.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{base}/node_modules/{name}")
        };
        if let Some((key, _)) = records.get_key_value(candidate.as_str()) {
            return Some(*key);
        }
        if base.is_empty() {
            return None;
        }
        base = base
            .rsplit_once("/node_modules/")
            .map_or("", |(parent, _)| parent);
    }
}
/// Initial installer_policy 1 supports only flat exact overrides that agree with the
/// entire reachable lock graph and do not relax the original dependency ranges.
fn override_map(object: &Map<String, Value>) -> Result<BTreeMap<String, String>, AcquireError> {
    let Some(value) = object.get("overrides") else {
        return Ok(BTreeMap::new());
    };
    let map = value.as_object().ok_or(AcquireError::Graph)?;
    if map.len() > MAX_PACKAGES {
        return Err(AcquireError::Graph);
    }
    map.iter()
        .map(|(name, value)| {
            catalog_core::PackageName::from_str(name).map_err(|_| AcquireError::Graph)?;
            let version = value.as_str().ok_or(AcquireError::Graph)?;
            exact_version(version)?;
            Ok((name.clone(), version.to_owned()))
        })
        .collect()
}
fn verify_root_overrides(
    manifest: &Map<String, Value>,
    lock: &Map<String, Value>,
    lock_root: &Map<String, Value>,
    records: &BTreeMap<&str, &Map<String, Value>>,
) -> Result<(), AcquireError> {
    let overrides = override_map(manifest)?;
    for document in [lock, lock_root] {
        if document.contains_key("overrides") && override_map(document)? != overrides {
            return Err(AcquireError::Graph);
        }
    }
    for (name, expected) in overrides {
        let mut matched = false;
        for (locator, record) in records {
            if locator.rsplit("node_modules/").next() == Some(name.as_str()) {
                matched = true;
                if string(record, "version")? != expected {
                    return Err(AcquireError::Graph);
                }
            }
        }
        if !matched {
            return Err(AcquireError::Graph);
        }
    }
    Ok(())
}

/// Required edges are derived from admitted declarations, never from lock optional flags.
fn dependency_edges<'a>(
    locator: &str,
    record: &Map<String, Value>,
    records: &BTreeMap<&'a str, &Map<String, Value>>,
) -> Result<Vec<(&'a str, bool)>, AcquireError> {
    let mut edges = Vec::new();
    let optional = dependency_map(record, "optionalDependencies")?;
    for field in ["dependencies", "optionalDependencies", "peerDependencies"] {
        let Some(deps) = dependency_map(record, field)? else {
            continue;
        };
        for (name, requirement) in deps {
            catalog_core::PackageName::from_str(name).map_err(|_| AcquireError::Graph)?;
            // npm optionalDependencies overrides the same name in dependencies.
            if field == "dependencies" && optional.is_some_and(|map| map.contains_key(name)) {
                continue;
            }
            let optional_peer = field == "peerDependencies"
                && record
                    .get("peerDependenciesMeta")
                    .and_then(|m| m.get(name))
                    .and_then(|m| m.get("optional"))
                    .and_then(Value::as_bool)
                    == Some(true);
            let Some(resolved) = resolve(locator, name, records) else {
                if optional_peer {
                    continue;
                }
                return Err(AcquireError::Graph);
            };
            let version = string(records[resolved], "version")?;
            if !npm_range_matches(requirement.as_str().ok_or(AcquireError::Graph)?, version)? {
                return Err(AcquireError::Graph);
            }
            edges.push((resolved, field != "optionalDependencies" && !optional_peer));
        }
    }
    Ok(edges)
}
fn verify_closure<'a>(
    records: &BTreeMap<&'a str, &Map<String, Value>>,
) -> Result<BTreeSet<&'a str>, AcquireError> {
    let mut reachability = BTreeMap::from([("", true)]);
    let mut pending = VecDeque::from([("", true)]);
    while let Some((locator, required_path)) = pending.pop_front() {
        let record = records.get(locator).ok_or(AcquireError::Graph)?;
        for (resolved, required_edge) in dependency_edges(locator, record, records)? {
            let required = required_path && required_edge;
            match reachability.get(resolved).copied() {
                None => {
                    reachability.insert(resolved, required);
                    pending.push_back((resolved, required));
                }
                Some(false) if required => {
                    reachability.insert(resolved, true);
                    pending.push_back((resolved, true));
                }
                _ => {}
            }
        }
    }
    if reachability.len() != records.len() {
        return Err(AcquireError::Graph);
    }
    Ok(reachability
        .into_iter()
        .filter_map(|(locator, required)| required.then_some(locator))
        .collect())
}
fn verify_applicable_closure(
    declarations: &BTreeMap<&str, &Map<String, Value>>,
    locks: &BTreeMap<&str, &Map<String, Value>>,
    pruned: &BTreeSet<&str>,
) -> Result<(), AcquireError> {
    let required = verify_closure(declarations)?;
    for (locator, declaration) in declarations {
        if locator.is_empty() {
            continue;
        }
        let optional_flag = match locks
            .get(locator)
            .ok_or(AcquireError::Graph)?
            .get("optional")
        {
            None => false,
            Some(Value::Bool(flag)) => *flag,
            _ => return Err(AcquireError::Graph),
        };
        let expected_optional = !required.contains(locator);
        if optional_flag != expected_optional || (!expected_optional && pruned.contains(locator)) {
            return Err(AcquireError::Graph);
        }
        if !pruned.contains(locator) {
            for (target, required_edge) in dependency_edges(locator, declaration, declarations)? {
                if required_edge && pruned.contains(target) {
                    return Err(AcquireError::Graph);
                }
            }
        }
    }
    Ok(())
}
fn check_engine(o: &Map<String, Value>, node: &str) -> Result<(), AcquireError> {
    let Some(engines) = o.get("engines") else {
        return Ok(());
    };
    let engines = engines.as_object().ok_or(AcquireError::Graph)?;
    if let Some(range) = engines.get("node") {
        if !npm_range_matches(range.as_str().ok_or(AcquireError::Graph)?, node)? {
            return Err(AcquireError::Graph);
        }
    }
    Ok(())
}
/// A bounded supported npm range subset; unsupported forms fail closed.
fn npm_range_matches(range: &str, version: &str) -> Result<bool, AcquireError> {
    if range.len() > 512 || range.is_empty() {
        return Err(AcquireError::Graph);
    }
    let version = semver::Version::parse(version).map_err(|_| AcquireError::Graph)?;
    let mut matched = false;
    for alternative in range.split("||") {
        let terms = alternative.split_whitespace().collect::<Vec<_>>();
        if terms.is_empty() {
            return Err(AcquireError::Graph);
        }
        let mut comparators = Vec::new();
        if terms.len() == 3 && terms[1] == "-" {
            comparators.extend(npm_comparators(&format!(">={}", terms[0]))?);
            comparators.extend(npm_comparators(&format!("<={}", terms[2]))?);
        } else {
            let mut terms = terms.into_iter();
            while let Some(term) = terms.next() {
                let term = if matches!(term, ">" | ">=" | "<" | "<=" | "=" | "~" | "^") {
                    format!("{term}{}", terms.next().ok_or(AcquireError::Graph)?)
                } else {
                    term.to_owned()
                };
                comparators.extend(npm_comparators(&term)?);
            }
        }
        let normalized = if comparators.is_empty() {
            "*".to_owned()
        } else {
            comparators.join(",")
        };
        let req = semver::VersionReq::parse(&normalized).map_err(|_| AcquireError::Graph)?;
        matched |= req.matches(&version);
    }
    Ok(matched)
}

// Expand npm's partial/x/caret/tilde intervals before semver's prerelease
// admission rule sees the whole comparator set. Rust's partial equality and
// caret defaults are different from npm, especially with explicit prereleases.
fn npm_comparators(term: &str) -> Result<Vec<String>, AcquireError> {
    use semver::Op;
    let normalized = if term.starts_with(|c: char| c.is_ascii_digit()) {
        format!("={term}")
    } else {
        term.to_owned()
    };
    let wildcard = normalized.trim_start_matches(['>', '<', '=', '^', '~']);
    if matches!(wildcard, "*" | "x" | "X") {
        return Ok(
            if normalized.starts_with('>') && !normalized.starts_with(">=")
                || normalized.starts_with('<') && !normalized.starts_with("<=")
            {
                vec!["<0.0.0-0".to_owned()]
            } else {
                Vec::new()
            },
        );
    }
    let c = semver::Comparator::parse(&normalized).map_err(|_| AcquireError::Graph)?;
    let low = format!(
        "{}.{}.{}{}",
        c.major,
        c.minor.unwrap_or(0),
        c.patch.unwrap_or(0),
        if c.pre.is_empty() {
            String::new()
        } else {
            format!("-{}", c.pre)
        }
    );
    let upper = |position: usize| -> Result<String, AcquireError> {
        let mut parts = [c.major, c.minor.unwrap_or(0), c.patch.unwrap_or(0)];
        parts[position] = parts[position].checked_add(1).ok_or(AcquireError::Graph)?;
        for value in parts.iter_mut().skip(position + 1) {
            *value = 0;
        }
        Ok(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
    };
    let partial = if c.minor.is_none() {
        Some(0)
    } else if c.patch.is_none() {
        Some(1)
    } else {
        None
    };
    Ok(match c.op {
        Op::Caret => {
            let position = if c.major != 0 || c.minor.is_none() {
                0
            } else if c.minor != Some(0) || c.patch.is_none() {
                1
            } else {
                2
            };
            vec![format!(">={low}"), format!("<{}-0", upper(position)?)]
        }
        Op::Tilde => vec![
            format!(">={low}"),
            format!("<{}-0", upper(if c.minor.is_none() { 0 } else { 1 })?),
        ],
        Op::Exact | Op::Wildcard if partial.is_some() => vec![
            format!(">={low}"),
            format!("<{}-0", upper(partial.unwrap())?),
        ],
        Op::Greater if partial.is_some() => vec![format!(">={}", upper(partial.unwrap())?)],
        Op::LessEq if partial.is_some() => vec![format!("<{}-0", upper(partial.unwrap())?)],
        Op::Less if partial.is_some() => vec![format!("<{low}-0")],
        Op::GreaterEq => vec![format!(">={low}")],
        Op::Greater => vec![format!(">{low}")],
        Op::Less => vec![format!("<{low}")],
        Op::LessEq => vec![format!("<={low}")],
        Op::Exact => vec![format!("={low}")],
        _ => return Err(AcquireError::Graph),
    })
}

#[cfg(test)]
mod range_tests {
    use super::*;
    #[test]
    fn immutable_npm_range_vectors_match_the_public_oracle() {
        let bytes = include_bytes!("../../../conformance/npm-range-v1/vectors.json");
        assert_eq!(
            sha256(bytes),
            "28575090e39101ce453f330ac240e9a221fdc58b38f5dddbde993edbcdedd546"
        );
        let data: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let vectors = data["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 61);
        for vector in vectors {
            assert_eq!(
                npm_range_matches(
                    vector["range"].as_str().unwrap(),
                    vector["version"].as_str().unwrap()
                )
                .unwrap_or(false),
                vector["accepts"].as_bool().unwrap(),
                "{vector}"
            );
        }
    }

    #[test]
    fn npm_bare_versions_and_partial_versions_are_not_caret_ranges() {
        assert!(!npm_range_matches("22.0.0", "22.19.0").unwrap());
        assert!(!npm_range_matches("22.18", "22.19.0").unwrap());
        assert!(npm_range_matches("22", "22.19.0").unwrap());
        assert!(npm_range_matches("22.19", "22.19.0").unwrap());
    }
}

#[cfg(test)]
mod spaced_range_tests {
    use super::*;
    #[test]
    fn npm_comparator_operator_whitespace_preserves_version_bounds() {
        assert!(npm_range_matches(">= 14.0.0", "22.19.0").unwrap());
        assert!(!npm_range_matches(">= 23.0.0", "22.19.0").unwrap());
        assert!(npm_range_matches(">= 14.0.0 <= 22", "22.19.0").unwrap());
        for malformed in [">=", ">= || <=22", ">=14.0.0 ||", ">= <22"] {
            assert!(npm_range_matches(malformed, "22.19.0").is_err());
        }
    }
}

#[cfg(test)]
mod override_tests {
    use super::*;
    #[test]
    fn override_map_has_its_own_bounded_entry_limit() {
        let overrides: Map<String, Value> = (0..MAX_PACKAGES)
            .map(|i| (format!("package{i}"), json!("1.0.0")))
            .collect();
        let mut root = Map::from_iter([("overrides".into(), Value::Object(overrides))]);
        assert_eq!(override_map(&root).unwrap().len(), MAX_PACKAGES);
        root.get_mut("overrides")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!("1.0.0"));
        assert!(override_map(&root).is_err());
    }
}

/// Replays the same bounded archive/graph policy from transferred bytes alone.
/// The caller supplies exact descriptor-backed bytes; no prior observation is a proof.
pub fn verify_installer_release(
    intent: &catalog_core::PiReleaseIntentV2,
    inputs: &PackageInputManifestV2,
    read: impl Fn(&str, usize) -> Result<Vec<u8>, AcquireError>,
) -> Result<(), AcquireError> {
    inputs.validate_for_profile(intent.profile())?;
    struct RetainedInputs<'a, F> {
        intent: &'a catalog_core::PiReleaseIntentV2,
        inputs: &'a PackageInputManifestV2,
        read: F,
    }
    impl<F: Fn(&str, usize) -> Result<Vec<u8>, AcquireError>> InstallerInputs
        for RetainedInputs<'_, F>
    {
        fn read(&self, url: &str, maximum: usize) -> Result<Vec<u8>, AcquireError> {
            let p = self.intent.profile();
            let (actual_url, size, digest) = if url == self.inputs.installer_manifest_source.url() {
                (
                    p.installer_manifest().url().as_str(),
                    p.installer_manifest().size_bytes().get(),
                    p.installer_manifest().sha256().as_str(),
                )
            } else if url == self.inputs.installer_lock_source.url() {
                (
                    p.installer_lock().url().as_str(),
                    p.installer_lock().size_bytes().get(),
                    p.installer_lock().sha256().as_str(),
                )
            } else if let Some(source) = self.inputs.auxiliary_inputs.iter().find(|s| s.url == url)
            {
                (source.url(), source.size_bytes(), source.sha256())
            } else if let Some(archive) = self
                .inputs
                .locked_packages
                .iter()
                .find(|s| s.resolved_url == url)
            {
                (url, archive.archive_size, archive.archive_sha256.as_str())
            } else if let Some(artifact) = p
                .components()
                .iter()
                .flat_map(|c| c.artifacts())
                .find(|a| a.url().as_str() == url)
            {
                (url, artifact.size_bytes().get(), artifact.sha256().as_str())
            } else {
                return Err(AcquireError::Graph);
            };
            if size > maximum as u64 {
                return Err(AcquireError::SizeLimitExceeded);
            }
            let bytes = (self.read)(actual_url, maximum)?;
            if bytes.len() as u64 != size || sha256(&bytes) != digest {
                return Err(AcquireError::DigestMismatch);
            }
            Ok(bytes)
        }
    }
    let derived = derive_installer_release(
        DiscoverPiReleaseRequest {
            sequence: intent.sequence(),
            generated_at: intent.generated_at().as_str().into(),
            expires_at: intent.expires_at().as_str().into(),
            title: intent.title().into(),
            notes: intent.notes().into(),
            pi_version: intent.profile().pi_package().version().as_str().into(),
            node_version: intent.profile().node_version().as_str().into(),
            target: intent.profile().target().as_str().into(),
            installer_policy: Some(PiInstallerDiscoveryPolicy {
                consumer_requirement: intent.profile().consumer_requirement().as_str().into(),
                required_contracts: intent.profile().required_contracts().clone(),
            }),
        },
        &RetainedInputs {
            intent,
            inputs,
            read,
        },
    )?;
    if derived.profile != *intent.profile() || derived.inputs != *inputs {
        return Err(AcquireError::Graph);
    }
    Ok(())
}
