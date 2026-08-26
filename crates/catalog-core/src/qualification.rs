use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    BoundedId, CatalogSourceV1, CatalogTarget, CatalogTimestamp, CoreError, ExactVersion,
    FluxsembleBuildBindingV1, Sha256Hex, compatibility_input_digest,
    source::{domain_digest, invalid, require, require_bounded_json},
};

pub const QUALIFICATION_SCHEMA_VERSION: u16 = 1;
pub const MAX_RESIDUAL_RISKS: usize = 32;
pub const MAX_QUALIFICATION_TEXT_BYTES: usize = 1_024;

const QUALIFICATION_DOMAIN: &[u8] = b"fluxsemble:runtime-catalog-qualification:v1\0";

/// Public evidence record bound to one exact runtime semantic input and final build/profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompatibilityQualificationV1 {
    pub schema_version: u16,
    pub compatibility_input_sha256: Sha256Hex,
    pub fluxsemble: FluxsembleBuildBindingV1,
    pub provider: BoundedId,
    pub target: CatalogTarget,
    pub pi_version: ExactVersion,
    pub node_version: ExactVersion,
    pub checks: QualificationChecksV1,
    pub reviewer: BoundedPlainText,
    pub release_owner_approved_at: CatalogTimestamp,
    pub residual_risks: Vec<BoundedPlainText>,
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
}

/// Closed list of pre-publication checks required for compatibility qualification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationChecksV1 {
    pub catalog_v1_conformance: QualificationOutcome,
    pub managed_installation: QualificationOutcome,
    pub node_probe: QualificationOutcome,
    pub pi_probe: QualificationOutcome,
    pub pi_rpc_readiness: QualificationOutcome,
    pub activation: QualificationOutcome,
    pub managed_resolution: QualificationOutcome,
    pub required_failure: QualificationOutcome,
    pub cancellation: QualificationOutcome,
}

impl QualificationChecksV1 {
    fn all_passed(&self) -> bool {
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
    require(record.fluxsemble == source.build)?;
    require(record.provider.as_str() == source.intent.release.provider())?;
    require(record.target == source.intent.release.target())?;
    require(record.pi_version == *source.intent.release.pi_version())?;
    require(record.node_version == *source.intent.release.node_version())?;

    let expected_input = compatibility_input_digest(&source.intent, &source.build)?;
    require(record.compatibility_input_sha256.as_str() == encode_hex(&expected_input))?;
    let expected_record = qualification_record_digest(record)?;
    require(source.qualification.sha256.as_str() == encode_hex(&expected_record))
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
