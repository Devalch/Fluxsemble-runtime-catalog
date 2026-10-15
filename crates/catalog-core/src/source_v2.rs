//! Versioned, inert producer records. Parsing never grants acquisition or signing authority.
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    CatalogPayloadV1, CatalogTag, CatalogTimestamp, CoreError, FluxsembleBuildBindingV1,
    PiReleaseProfileV1, PiReleaseQualificationV1, QualificationRecordPath, Sha256Hex,
    source::{domain_digest, invalid, require, require_bounded_json},
    verify_pi_release_qualification,
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
    profile: PiReleaseProfileV1,
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
            profile: PiReleaseProfileV1::from_json(
                &serde_json::to_vec(&w.profile).map_err(|_| invalid())?,
            )?,
        };
        require(intent.generated_at < intent.expires_at)?;
        require(intent.profile.node_version().as_str() == "22.19.0")?;
        for descriptor in [
            intent.profile.installer_manifest(),
            intent.profile.installer_lock(),
            intent.profile.pi_manifest(),
        ] {
            pi_support_asset_name(
                descriptor.url().as_str(),
                descriptor.sha256().as_str(),
                intent.tag.as_str(),
            )?;
        }
        // Validate publication metadata through its original catalog parser. This placeholder is
        // structural only and never leaves the constructor or enters a subject projection.
        intent.payload(&json!({
            "url": format!("{}/qualification-{}.json", intent.support_prefix(), "0".repeat(64)),
            "size_bytes": "1",
            "sha256": "0".repeat(64),
        }))?;
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
    pub fn profile(&self) -> &PiReleaseProfileV1 {
        &self.profile
    }
    pub fn support_prefix(&self) -> String {
        format!(
            "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/{}",
            self.tag.as_str()
        )
    }
    fn payload(&self, qualification: &Value) -> Result<CatalogPayloadV1, CoreError> {
        let mut origins = std::collections::BTreeSet::new();
        let mut add = |value: &str| -> Result<(), CoreError> {
            let url = url::Url::parse(value).map_err(|_| invalid())?;
            origins.insert(url.origin().ascii_serialization());
            Ok(())
        };
        for descriptor in [
            self.profile.installer_manifest(),
            self.profile.installer_lock(),
            self.profile.pi_manifest(),
        ] {
            add(descriptor.url().as_str())?;
        }
        add(qualification["url"].as_str().ok_or_else(invalid)?)?;
        for component in self.profile.components() {
            for artifact in component.artifacts() {
                add(artifact.url().as_str())?;
            }
        }
        for package in self.profile.locked_packages() {
            add(package.resolved_url().as_str())?;
        }
        let value = json!({
            "schema_version": 1,
            "sequence": self.sequence,
            "generated_at": self.generated_at,
            "expires_at": self.expires_at,
            "compatibility_ranges": [self.profile.consumer_requirement()],
            "providers": [{
                "provider_id": "builtin:pi",
                "allowed_origins": origins,
                "releases": [{
                    "version": self.profile.pi_package().version(),
                    "target": self.profile.target(),
                    "compatibility_ranges": [self.profile.consumer_requirement()],
                    "release_metadata": {"title": self.title, "notes": self.notes},
                    "components": self.profile.components(),
                    "provider_extension": {
                        "kind": "pi_installer_lock_v1",
                        "metadata": {"profile": self.profile, "qualification": qualification},
                    },
                }],
            }],
        });
        CatalogPayloadV1::from_json(&serde_json::to_vec(&value).map_err(|_| invalid())?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogSourceV2 {
    schema_version: u16,
    intent: PiReleaseIntentV2,
    build: FluxsembleBuildBindingV1,
    qualification: QualificationRefV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QualificationRefV2 {
    relative_path: QualificationRecordPath,
    sha256: Sha256Hex,
}
impl QualificationRefV2 {
    pub fn relative_path(&self) -> &QualificationRecordPath {
        &self.relative_path
    }
    pub fn sha256(&self) -> &Sha256Hex {
        &self.sha256
    }
}

impl CatalogSourceV2 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        require_bounded_json(bytes)?;
        let w: SourceWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        require(w.schema_version == 2)?;
        let relative_path = QualificationRecordPath::parse(w.qualification.relative_path)?;
        require(
            relative_path.as_str().starts_with("qualifications/")
                && relative_path.as_str().ends_with(".json"),
        )?;
        Ok(Self {
            schema_version: 2,
            intent: PiReleaseIntentV2::from_json(
                &serde_json::to_vec(&w.intent).map_err(|_| invalid())?,
            )?,
            build: FluxsembleBuildBindingV1::from_json(
                &serde_json::to_vec(&w.build).map_err(|_| invalid())?,
            )?,
            qualification: QualificationRefV2 {
                relative_path,
                sha256: Sha256Hex::parse(w.qualification.sha256)?,
            },
        })
    }
    pub fn intent(&self) -> &PiReleaseIntentV2 {
        &self.intent
    }
    pub fn build(&self) -> &FluxsembleBuildBindingV1 {
        &self.build
    }
    pub fn qualification(&self) -> &QualificationRefV2 {
        &self.qualification
    }

    /// Final catalog assembly binds the exact canonical record bytes; never rewrite after hashing.
    pub fn finalize(&self, qualification_bytes: &[u8]) -> Result<CatalogPayloadV1, CoreError> {
        let q = PiReleaseQualificationV1::from_json(qualification_bytes)?;
        require(serde_jcs::to_vec(&q).map_err(|_| invalid())? == qualification_bytes)?;
        require(
            format!("{:x}", Sha256::digest(qualification_bytes))
                == self.qualification.sha256.as_str(),
        )?;
        verify_pi_release_qualification(self.intent.profile(), &q)?;
        verify_pi_verification_build(&self.build, &q)?;
        self.intent.payload(&json!({
            "url":format!("{}/qualification-{}.json", self.intent.support_prefix(), self.qualification.sha256),
            "size_bytes":qualification_bytes.len().to_string(),"sha256":self.qualification.sha256,
        }))
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
    domain_digest(b"fluxsemble:runtime-catalog-release-intent:v2\0", intent)
}
pub fn catalog_source_v2_digest(source: &CatalogSourceV2) -> Result<[u8; 32], CoreError> {
    domain_digest(b"fluxsemble:runtime-catalog-source:v2\0", source)
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
    build: Value,
    qualification: QualificationRefWire,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationRefWire {
    relative_path: String,
    sha256: String,
}
