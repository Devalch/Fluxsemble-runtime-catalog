use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    BoundedId, CatalogSourceV1, CatalogTarget, CatalogTimestamp, CoreError, ExactVersion,
    FluxsembleBuildBindingV1, Sha256Hex, compatibility_input_digest_with_keyring,
    source::{domain_digest, invalid, require, require_bounded_json},
};

pub const QUALIFICATION_SCHEMA_VERSION: u16 = 1;
pub const MAX_RESIDUAL_RISKS: usize = 32;
pub const MAX_QUALIFICATION_TEXT_BYTES: usize = 1_024;

const QUALIFICATION_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-qualification:v1\0";

/// Public evidence record bound to one exact runtime semantic input and final build/profile.
///
/// ```compile_fail
/// use catalog_core::CompatibilityQualificationV1;
/// fn clear_risks(record: &mut CompatibilityQualificationV1) {
///     record.residual_risks.clear();
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompatibilityQualificationV1 {
    schema_version: u16,
    compatibility_input_sha256: Sha256Hex,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_sha256: Option<Sha256Hex>,
    trusted_signing_keyring_sha256: Sha256Hex,
    fluxsemble: FluxsembleBuildBindingV1,
    provider: BoundedId,
    target: CatalogTarget,
    pi_version: ExactVersion,
    node_version: ExactVersion,
    checks: QualificationChecksV1,
    reviewer: BoundedPlainText,
    release_owner_approved_at: CatalogTimestamp,
    residual_risks: Vec<BoundedPlainText>,
}

impl CompatibilityQualificationV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require_bounded_json(bytes)?;
        let wire: QualificationWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        require(wire.schema_version == QUALIFICATION_SCHEMA_VERSION)?;
        require(wire.residual_risks.len() <= MAX_RESIDUAL_RISKS)?;
        let fluxsemble = FluxsembleBuildBindingV1::from_json(
            &serde_json::to_vec(&wire.fluxsemble).map_err(|_| invalid())?,
        )?;
        let provider = BoundedId::parse(wire.provider)?;
        Ok(Self {
            schema_version: wire.schema_version,
            compatibility_input_sha256: Sha256Hex::parse(wire.compatibility_input_sha256)?,
            candidate_sha256: wire.candidate_sha256.map(Sha256Hex::parse).transpose()?,
            trusted_signing_keyring_sha256: Sha256Hex::parse(wire.trusted_signing_keyring_sha256)?,
            fluxsemble,
            provider,
            target: CatalogTarget::parse(&wire.target)?,
            pi_version: ExactVersion::parse(wire.pi_version)?,
            node_version: ExactVersion::parse(wire.node_version)?,
            checks: wire.checks,
            reviewer: BoundedPlainText::parse(wire.reviewer)?,
            release_owner_approved_at: CatalogTimestamp::parse(wire.release_owner_approved_at)?,
            residual_risks: wire
                .residual_risks
                .into_iter()
                .map(BoundedPlainText::parse)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub fn compatibility_input_sha256(&self) -> &Sha256Hex {
        &self.compatibility_input_sha256
    }

    /// Digest of the exact catalog candidate supplied in a guided qualification request.
    /// Legacy sequence-1 evidence predates the guided handoff and therefore omits it.
    #[must_use]
    pub fn candidate_sha256(&self) -> Option<&Sha256Hex> {
        self.candidate_sha256.as_ref()
    }

    #[must_use]
    pub fn trusted_signing_keyring_sha256(&self) -> &Sha256Hex {
        &self.trusted_signing_keyring_sha256
    }

    #[must_use]
    pub fn fluxsemble(&self) -> &FluxsembleBuildBindingV1 {
        &self.fluxsemble
    }

    #[must_use]
    pub fn provider(&self) -> &BoundedId {
        &self.provider
    }

    #[must_use]
    pub const fn target(&self) -> CatalogTarget {
        self.target
    }

    #[must_use]
    pub fn pi_version(&self) -> &ExactVersion {
        &self.pi_version
    }

    #[must_use]
    pub fn node_version(&self) -> &ExactVersion {
        &self.node_version
    }

    #[must_use]
    pub fn checks(&self) -> &QualificationChecksV1 {
        &self.checks
    }

    #[must_use]
    pub fn reviewer(&self) -> &BoundedPlainText {
        &self.reviewer
    }

    #[must_use]
    pub fn release_owner_approved_at(&self) -> &CatalogTimestamp {
        &self.release_owner_approved_at
    }

    #[must_use]
    pub fn residual_risks(&self) -> &[BoundedPlainText] {
        &self.residual_risks
    }
}

/// Closed list of pre-publication checks required for compatibility qualification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationChecksV1 {
    catalog_v1_conformance: QualificationOutcome,
    managed_installation: QualificationOutcome,
    node_probe: QualificationOutcome,
    pi_probe: QualificationOutcome,
    pi_rpc_readiness: QualificationOutcome,
    activation: QualificationOutcome,
    managed_resolution: QualificationOutcome,
    required_failure: QualificationOutcome,
    cancellation: QualificationOutcome,
}

impl QualificationChecksV1 {
    #[must_use]
    pub const fn catalog_v1_conformance(&self) -> QualificationOutcome {
        self.catalog_v1_conformance
    }

    #[must_use]
    pub const fn managed_installation(&self) -> QualificationOutcome {
        self.managed_installation
    }

    #[must_use]
    pub const fn node_probe(&self) -> QualificationOutcome {
        self.node_probe
    }

    #[must_use]
    pub const fn pi_probe(&self) -> QualificationOutcome {
        self.pi_probe
    }

    #[must_use]
    pub const fn pi_rpc_readiness(&self) -> QualificationOutcome {
        self.pi_rpc_readiness
    }

    #[must_use]
    pub const fn activation(&self) -> QualificationOutcome {
        self.activation
    }

    #[must_use]
    pub const fn managed_resolution(&self) -> QualificationOutcome {
        self.managed_resolution
    }

    #[must_use]
    pub const fn required_failure(&self) -> QualificationOutcome {
        self.required_failure
    }

    #[must_use]
    pub const fn cancellation(&self) -> QualificationOutcome {
        self.cancellation
    }

    pub fn all_passed(&self) -> bool {
        [
            self.catalog_v1_conformance,
            self.managed_installation,
            self.node_probe,
            self.pi_probe,
            self.pi_rpc_readiness,
            self.activation,
            self.managed_resolution,
            self.required_failure,
            self.cancellation,
        ]
        .into_iter()
        .all(|outcome| outcome == QualificationOutcome::Passed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationOutcome {
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct BoundedPlainText(String);

impl BoundedPlainText {
    fn parse(value: String) -> Result<Self, CoreError> {
        require(
            !value.is_empty()
                && value.len() <= MAX_QUALIFICATION_TEXT_BYTES
                && value.chars().all(|character| {
                    !character.is_control() || matches!(character, '\n' | '\r' | '\t')
                }),
        )?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BoundedPlainText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub fn qualification_record_digest(
    record: &CompatibilityQualificationV1,
) -> Result<[u8; 32], CoreError> {
    domain_digest(QUALIFICATION_DOMAIN, record)
}

/// Verifies exact, non-circular qualification binding for the final source.
pub fn verify_qualification(
    source: &CatalogSourceV1,
    record: &CompatibilityQualificationV1,
) -> Result<(), CoreError> {
    require(record.schema_version == QUALIFICATION_SCHEMA_VERSION)?;
    require(record.checks.all_passed())?;
    require(record.fluxsemble == *source.build())?;
    require(record.provider.as_str() == source.intent().release().provider())?;
    require(record.target == source.intent().release().target())?;
    require(record.pi_version == *source.intent().release().pi_version())?;
    require(record.node_version == *source.intent().release().node_version())?;

    require(
        record.trusted_signing_keyring_sha256.as_str() == crate::production_keyring().sha256(),
    )?;
    let expected_input = compatibility_input_digest_with_keyring(
        source.intent(),
        source.build(),
        record.trusted_signing_keyring_sha256.as_str(),
    )?;
    require(record.compatibility_input_sha256.as_str() == encode_hex(&expected_input))?;
    let expected_record = qualification_record_digest(record)?;
    require(source.qualification().sha256().as_str() == encode_hex(&expected_record))
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationWire {
    schema_version: u16,
    compatibility_input_sha256: String,
    #[serde(default)]
    candidate_sha256: Option<String>,
    trusted_signing_keyring_sha256: String,
    fluxsemble: serde_json::Value,
    provider: String,
    target: String,
    pi_version: String,
    node_version: String,
    checks: QualificationChecksV1,
    reviewer: String,
    release_owner_approved_at: String,
    residual_risks: Vec<String>,
}

/// Bind inert current-format evidence to the exact release subject and tested consumer.
/// This performs data consistency checks only; acquisition, signing and consumer admission
/// retain their own authority and must verify the original inputs independently.
pub fn verify_pi_release_qualification(
    profile: &crate::PiReleaseProfileV1,
    qualification: &crate::PiReleaseQualificationV1,
) -> Result<(), CoreError> {
    let subject = crate::pi_release_subject_sha256(profile)?;
    let subject_hex: String = subject.iter().map(|byte| format!("{byte:02x}")).collect();
    require(qualification.release_subject_sha256().as_str() == subject_hex)?;
    require(qualification.required_contracts() == profile.required_contracts())?;
    require(qualification.consumer_requirement() == profile.consumer_requirement())?;
    require(qualification.is_complete_pass())?;
    let profile_digest = pi_required_contracts_profile_sha256(profile.required_contracts())?;
    let profile_hex: String = profile_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    require(
        qualification
            .verification_build()
            .compatibility_profile_id()
            == "builtin-pi-installer-lock-contracts-v1",
    )?;
    require(
        qualification
            .verification_build()
            .compatibility_profile_sha256()
            .as_str()
            == profile_hex,
    )?;
    let requirement = semver::VersionReq::parse(profile.consumer_requirement().as_str())
        .map_err(|_| invalid())?;
    let tested_version = semver::Version::parse(
        qualification
            .verification_build()
            .consumer_version()
            .as_str(),
    )
    .map_err(|_| invalid())?;
    require(requirement.matches(&tested_version))
}

/// SHA-256 of the public behavioral manifest: JCS object followed by one LF.
/// This projection depends only on behavioral contracts, never a Pi archive or build binary.
pub fn pi_required_contracts_profile_sha256(
    contracts: &crate::PiRequiredContractsV1,
) -> Result<[u8; 32], CoreError> {
    use sha2::{Digest, Sha256};
    let manifest = serde_json::json!({
        "schema_version": 1,
        "profile_id": "builtin-pi-installer-lock-contracts-v1",
        "required_contracts": contracts,
    });
    let mut bytes = serde_jcs::to_vec(&manifest).map_err(|_| invalid())?;
    bytes.push(b'\n');
    Ok(Sha256::digest(&bytes).into())
}
