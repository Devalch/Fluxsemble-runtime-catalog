//! Versioned, inert producer records. Parsing never grants acquisition or signing authority.
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    CatalogTag, CatalogTimestamp, CoreError, FluxsembleBuildBindingV1, MAX_RELEASE_NOTES_BYTES,
    MAX_RELEASE_TITLE_BYTES, PiReleaseProfileV2, PiReleaseQualificationV1,
    source::{domain_digest, invalid, require, require_bounded_json},
    wire::valid_plain_text,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PiReleaseIntentV2 {
    schema_version: u16,
    sequence: String,
    tag: CatalogTag,
    generated_at: CatalogTimestamp,
    expires_at: CatalogTimestamp,
    title: String,
    notes: String,
    profile: PiReleaseProfileV2,
}

impl PiReleaseIntentV2 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require_bounded_json(bytes)?;
        let w: IntentWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        require(w.schema_version == 2)?;
        let sequence = w.sequence.parse::<u64>().map_err(|_| invalid())?;
        require(w.sequence == sequence.to_string())?;
        let sequence = NonZeroU64::new(sequence).ok_or_else(invalid)?;
        let intent = Self {
            schema_version: 2,
            sequence: w.sequence,
            tag: CatalogTag::parse(w.tag, sequence)?,
            generated_at: CatalogTimestamp::parse(w.generated_at)?,
            expires_at: CatalogTimestamp::parse(w.expires_at)?,
            title: w.title,
            notes: w.notes,
            profile: PiReleaseProfileV2::from_json(
                &serde_json::to_vec(&w.profile).map_err(|_| invalid())?,
            )?,
        };
        require(intent.generated_at < intent.expires_at)?;
        require(intent.profile.node_version().as_str() == "22.19.0")?;
        for (descriptor, role) in [
            (intent.profile.installer_manifest(), "pi-installer-package"),
            (intent.profile.installer_lock(), "pi-installer-lock"),
            (intent.profile.pi_manifest(), "pi-package"),
        ] {
            let name = pi_support_asset_name(
                descriptor.url().as_str(),
                descriptor.sha256().as_str(),
                intent.tag.as_str(),
            )?;
            require(name == format!("{role}-{}.json", descriptor.sha256().as_str()))?;
        }
        require(valid_plain_text(
            &intent.title,
            MAX_RELEASE_TITLE_BYTES,
            false,
        ))?;
        require(valid_plain_text(
            &intent.notes,
            MAX_RELEASE_NOTES_BYTES,
            true,
        ))?;
        Ok(intent)
    }
    pub fn sequence(&self) -> u64 {
        self.sequence.parse().expect("validated sequence")
    }
    pub fn tag(&self) -> &CatalogTag {
        &self.tag
    }
    pub fn generated_at(&self) -> &CatalogTimestamp {
        &self.generated_at
    }
    pub fn expires_at(&self) -> &CatalogTimestamp {
        &self.expires_at
    }
    pub fn title(&self) -> &str {
        &self.title
    }
    pub fn notes(&self) -> &str {
        &self.notes
    }
    pub fn profile(&self) -> &PiReleaseProfileV2 {
        &self.profile
    }
    pub fn support_prefix(&self) -> String {
        format!(
            "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/{}",
            self.tag.as_str()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogSourceV2 {
    schema_version: u16,
    intent: PiReleaseIntentV2,
}

impl CatalogSourceV2 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require_bounded_json(bytes)?;
        let wire: SourceWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        require(wire.schema_version == 2)?;
        Ok(Self {
            schema_version: 2,
            intent: PiReleaseIntentV2::from_json(
                &serde_json::to_vec(&wire.intent).map_err(|_| invalid())?,
            )?,
        })
    }
    pub fn intent(&self) -> &PiReleaseIntentV2 {
        &self.intent
    }
    /// Construct producer facts without consumer build or qualification assertions.
    pub fn finalize(&self) -> Result<PiReleaseIntentV2, CoreError> {
        Ok(self.intent.clone())
    }
}

pub fn verify_pi_verification_build(
    build: &FluxsembleBuildBindingV1,
    qualification: &PiReleaseQualificationV1,
) -> Result<(), CoreError> {
    let verified = qualification.verification_build();
    require(build.implementation_commit().as_str() == verified.implementation_commit())?;
    require(build.application_sha256().as_str() == verified.application_sha256().as_str())?;
    require(build.daemon_sha256().as_str() == verified.daemon_sha256().as_str())?;
    require(build.compatibility_profile_id().as_str() == verified.compatibility_profile_id())?;
    require(
        build.compatibility_profile_sha256().as_str()
            == verified.compatibility_profile_sha256().as_str(),
    )
}

pub fn pi_release_intent_v2_digest(intent: &PiReleaseIntentV2) -> Result<[u8; 32], CoreError> {
    domain_digest(b"fluxsemble:runtime-catalog-producer-intent:v2\0", intent)
}

/// Signature bytes for a producer-only V2 catalog.
pub fn catalog_signing_bytes_v2(intent: &PiReleaseIntentV2) -> Result<Vec<u8>, CoreError> {
    let canonical = serde_jcs::to_vec(intent).map_err(|_| invalid())?;
    let mut result = b"fluxsemble:runtime-catalog:v2\0".to_vec();
    result.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    result.extend_from_slice(&canonical);
    Ok(result)
}
pub fn catalog_source_v2_digest(source: &CatalogSourceV2) -> Result<[u8; 32], CoreError> {
    domain_digest(b"fluxsemble:runtime-catalog-producer-source:v2\0", source)
}

/// Resolve an exact publisher support URL to its bounded digest-bearing release asset name.
pub fn pi_support_asset_name(url: &str, digest: &str, tag: &str) -> Result<String, CoreError> {
    let prefix =
        format!("https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/{tag}/");
    let name = url.strip_prefix(&prefix).ok_or_else(invalid)?;
    require(
        !name.is_empty()
            && name.len() <= 255
            && name.contains(digest)
            && name.is_ascii()
            && !name.contains(['/', '\\'])
            && !name
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace()),
    )?;
    Ok(name.into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentWire {
    schema_version: u16,
    sequence: String,
    tag: String,
    generated_at: String,
    expires_at: String,
    title: String,
    notes: String,
    profile: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceWire {
    schema_version: u16,
    intent: Value,
}
