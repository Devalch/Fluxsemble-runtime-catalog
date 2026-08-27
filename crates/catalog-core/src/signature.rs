use std::{error::Error, fmt, ops::Range};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use crate::{
    CatalogPayloadV1, CoreError, MAX_CATALOG_PAYLOAD_BYTES, SignedReleaseBundleManifestV1,
    canonical_catalog_payload, catalog_payload_sha256, release_bundle_signing_bytes,
    wire::reject_duplicate_json,
};

pub const MAX_SIGNED_CATALOG_ENVELOPE_BYTES: usize = MAX_CATALOG_PAYLOAD_BYTES + 1_024;

const MAX_NON_PAYLOAD_ENVELOPE_BYTES: usize = 1_024;
const MAX_TOP_LEVEL_KEY_BYTES: usize = 32;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_SIGNATURE_ALGORITHM_BYTES: usize = 16;
const ED25519_SIGNATURE_TEXT_BYTES: usize = 86;
const MAX_JSON_NESTING_DEPTH: usize = 128;
const SIGNED_CATALOG_ENVELOPE_VERSION: u16 = 1;
const SIGNATURE_ALGORITHM: &str = "ed25519";
const PRODUCTION_KEY_ID_PREFIX: &str = "runtime-catalog-ed25519-";
const PRODUCTION_KEY_ID: &str = "runtime-catalog-ed25519-d1a64e2d55c8e5d8";
const PRODUCTION_PUBLIC_KEY_BASE64URL: &str = "t9wPqaH5olhFkcPEcH6QPHX9AsCcrwxiKdzQo8xjW2o";
const PRODUCTION_PUBLIC_KEY: [u8; 32] = [
    0xb7, 0xdc, 0x0f, 0xa9, 0xa1, 0xf9, 0xa2, 0x58, 0x45, 0x91, 0xc3, 0xc4, 0x70, 0x7e, 0x90, 0x3c,
    0x75, 0xfd, 0x02, 0xc0, 0x9c, 0xaf, 0x0c, 0x62, 0x29, 0xdc, 0xd0, 0xa3, 0xcc, 0x63, 0x5b, 0x6a,
];

#[cfg(feature = "fixture-tools")]
const FIXTURE_KEY_ID: &str = "catalog-test-key-v1";
#[cfg(feature = "fixture-tools")]
const FIXTURE_PUBLIC_KEY: [u8; 32] = [
    0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99,
    0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8,
];

/// The one repository-compiled production verification identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionKeyIdentity {
    key_id: &'static str,
    public_key_base64url: &'static str,
    public_key: [u8; 32],
}

impl ProductionKeyIdentity {
    #[must_use]
    pub const fn key_id(&self) -> &'static str {
        self.key_id
    }

    #[must_use]
    pub const fn public_key_base64url(&self) -> &'static str {
        self.public_key_base64url
    }

    #[must_use]
    pub const fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }
}

static PRODUCTION_IDENTITY: ProductionKeyIdentity = ProductionKeyIdentity {
    key_id: PRODUCTION_KEY_ID,
    public_key_base64url: PRODUCTION_PUBLIC_KEY_BASE64URL,
    public_key: PRODUCTION_PUBLIC_KEY,
};

#[must_use]
pub fn production_key_identity() -> &'static ProductionKeyIdentity {
    &PRODUCTION_IDENTITY
}

#[must_use]
pub fn derive_runtime_catalog_key_id(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    format!(
        "{PRODUCTION_KEY_ID_PREFIX}{}",
        encode_lower_hex(&digest[..8])
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogSignatureError {
    InvalidSignedCatalog,
    InvalidSignedReleaseBundle,
}

impl fmt::Display for CatalogSignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSignedCatalog => "invalid signed catalog",
            Self::InvalidSignedReleaseBundle => "invalid signed release bundle",
        })
    }
}

impl Error for CatalogSignatureError {}

#[derive(Debug, Clone)]
pub struct VerifiedCatalogV1 {
    payload: CatalogPayloadV1,
    canonical_payload: Vec<u8>,
    payload_sha256: [u8; 32],
    key_id: String,
}

impl VerifiedCatalogV1 {
    #[must_use]
    pub fn payload(&self) -> &CatalogPayloadV1 {
        &self.payload
    }

    #[must_use]
    pub fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }

    #[must_use]
    pub const fn payload_sha256(&self) -> &[u8; 32] {
        &self.payload_sha256
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedReleaseBundleManifestV1 {
    manifest: SignedReleaseBundleManifestV1,
}

impl VerifiedReleaseBundleManifestV1 {
    #[must_use]
    pub fn manifest(&self) -> &SignedReleaseBundleManifestV1 {
        &self.manifest
    }
}

/// Verifies an envelope using only the repository-compiled production identity.
pub fn verify_signed_catalog(bytes: &[u8]) -> Result<VerifiedCatalogV1, CatalogSignatureError> {
    verify_signed_catalog_with_identity(bytes, production_identity())
}

/// Verifies a release-bundle manifest using only the compiled production identity.
pub fn verify_signed_release_bundle_manifest(
    bytes: &[u8],
) -> Result<VerifiedReleaseBundleManifestV1, CatalogSignatureError> {
    let manifest =
        SignedReleaseBundleManifestV1::from_json(bytes).map_err(|_| invalid_release_bundle())?;
    verify_release_manifest_with_identity(&manifest, production_identity())?;
    Ok(VerifiedReleaseBundleManifestV1 { manifest })
}

/// Fixture verification exists only in builds of the separately gated fixture example.
#[cfg(feature = "fixture-tools")]
pub fn verify_fixture_signed_catalog(
    bytes: &[u8],
) -> Result<VerifiedCatalogV1, CatalogSignatureError> {
    verify_signed_catalog_with_identity(bytes, fixture_identity())
}

/// Fixture release verification exists only in separately gated fixture-tool builds.
#[cfg(feature = "fixture-tools")]
pub fn verify_fixture_signed_release_bundle_manifest(
    bytes: &[u8],
) -> Result<VerifiedReleaseBundleManifestV1, CatalogSignatureError> {
    let manifest =
        SignedReleaseBundleManifestV1::from_json(bytes).map_err(|_| invalid_release_bundle())?;
    verify_release_manifest_with_identity(&manifest, fixture_identity())?;
    Ok(VerifiedReleaseBundleManifestV1 { manifest })
}

#[cfg(feature = "fixture-tools")]
const fn fixture_identity() -> VerificationIdentity {
    VerificationIdentity {
        key_id: FIXTURE_KEY_ID,
        public_key: FIXTURE_PUBLIC_KEY,
    }
}

#[derive(Clone, Copy)]
struct VerificationIdentity {
    key_id: &'static str,
    public_key: [u8; 32],
}

const fn production_identity() -> VerificationIdentity {
    VerificationIdentity {
        key_id: PRODUCTION_KEY_ID,
        public_key: PRODUCTION_PUBLIC_KEY,
    }
}

fn verify_signed_catalog_with_identity(
    bytes: &[u8],
    identity: VerificationIdentity,
) -> Result<VerifiedCatalogV1, CatalogSignatureError> {
    let spans = scan_signed_envelope(bytes)?;
    reject_duplicate_json(bytes).map_err(|_| invalid_catalog())?;

    let envelope_version: u16 = parse_scalar(bytes, &spans.envelope_version)?;
    let signature_algorithm: String = parse_scalar(bytes, &spans.signature_algorithm)?;
    let key_id: String = parse_scalar(bytes, &spans.key_id)?;
    let signature_text: String = parse_scalar(bytes, &spans.signature)?;
    if envelope_version != SIGNED_CATALOG_ENVELOPE_VERSION
        || signature_algorithm != SIGNATURE_ALGORITHM
        || key_id != identity.key_id
        || key_id.len() > MAX_KEY_ID_BYTES
        || signature_text.len() != ED25519_SIGNATURE_TEXT_BYTES
    {
        return Err(invalid_catalog());
    }

    let payload = CatalogPayloadV1::from_json(&bytes[spans.payload.clone()])
        .map_err(|_| invalid_catalog())?;
    let canonical_payload = canonical_catalog_payload(&payload).map_err(|_| invalid_catalog())?;
    if canonical_payload.as_slice() != &bytes[spans.payload] {
        return Err(invalid_catalog());
    }
    verify_signature(&identity.public_key, &canonical_payload, &signature_text)
        .map_err(|_| invalid_catalog())?;
    let payload_sha256 = catalog_payload_sha256(&payload).map_err(|_| invalid_catalog())?;
    Ok(VerifiedCatalogV1 {
        payload,
        canonical_payload,
        payload_sha256,
        key_id,
    })
}

fn verify_release_manifest_with_identity(
    manifest: &SignedReleaseBundleManifestV1,
    identity: VerificationIdentity,
) -> Result<(), CatalogSignatureError> {
    if manifest.signature().key_id().as_str() != identity.key_id {
        return Err(invalid_release_bundle());
    }
    let signing_bytes =
        release_bundle_signing_bytes(manifest).map_err(|_| invalid_release_bundle())?;
    verify_signature(
        &identity.public_key,
        &signing_bytes,
        manifest.signature().signature().as_str(),
    )
    .map_err(|_| invalid_release_bundle())
}

fn verify_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature_text: &str,
) -> Result<(), CoreError> {
    let signature_bytes = decode_base64url_no_pad::<64>(signature_text)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| CoreError::InvalidCatalog)?;
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| CoreError::InvalidCatalog)
}

#[derive(Debug)]
struct SignedEnvelopeSpans {
    envelope_version: Range<usize>,
    signature_algorithm: Range<usize>,
    key_id: Range<usize>,
    payload: Range<usize>,
    signature: Range<usize>,
}

#[derive(Clone, Copy)]
enum EnvelopeField {
    EnvelopeVersion,
    SignatureAlgorithm,
    KeyId,
    Payload,
    Signature,
}

fn scan_signed_envelope(bytes: &[u8]) -> Result<SignedEnvelopeSpans, CatalogSignatureError> {
    if bytes.len() > MAX_SIGNED_CATALOG_ENVELOPE_BYTES {
        return Err(invalid_catalog());
    }
    let mut index = skip_json_whitespace(bytes, 0);
    if bytes.get(index) != Some(&b'{') {
        return Err(invalid_catalog());
    }
    index += 1;
    let mut fields: [Option<Range<usize>>; 5] = std::array::from_fn(|_| None);

    loop {
        index = skip_json_whitespace(bytes, index);
        if bytes.get(index) == Some(&b'}') {
            index += 1;
            break;
        }
        let key_start = index;
        let key_end = scan_bounded_json_string(bytes, index, MAX_TOP_LEVEL_KEY_BYTES)?;
        let field = match &bytes[key_start..key_end] {
            b"\"envelope_version\"" => EnvelopeField::EnvelopeVersion,
            b"\"signature_algorithm\"" => EnvelopeField::SignatureAlgorithm,
            b"\"key_id\"" => EnvelopeField::KeyId,
            b"\"payload\"" => EnvelopeField::Payload,
            b"\"signature\"" => EnvelopeField::Signature,
            _ => return Err(invalid_catalog()),
        };
        let slot = match field {
            EnvelopeField::EnvelopeVersion => 0,
            EnvelopeField::SignatureAlgorithm => 1,
            EnvelopeField::KeyId => 2,
            EnvelopeField::Payload => 3,
            EnvelopeField::Signature => 4,
        };
        if fields[slot].is_some() {
            return Err(invalid_catalog());
        }

        index = skip_json_whitespace(bytes, key_end);
        if bytes.get(index) != Some(&b':') {
            return Err(invalid_catalog());
        }
        index = skip_json_whitespace(bytes, index + 1);
        let value_start = index;
        index = scan_json_value(bytes, index)?;
        let span = value_start..index;
        let maximum = match field {
            EnvelopeField::EnvelopeVersion => 5,
            EnvelopeField::SignatureAlgorithm => MAX_SIGNATURE_ALGORITHM_BYTES + 2,
            EnvelopeField::KeyId => MAX_KEY_ID_BYTES + 2,
            EnvelopeField::Payload => MAX_CATALOG_PAYLOAD_BYTES,
            EnvelopeField::Signature => ED25519_SIGNATURE_TEXT_BYTES + 2,
        };
        if span.len() > maximum {
            return Err(invalid_catalog());
        }
        fields[slot] = Some(span);

        index = skip_json_whitespace(bytes, index);
        match bytes.get(index) {
            Some(b',') => {
                index = skip_json_whitespace(bytes, index + 1);
                if bytes.get(index) == Some(&b'}') {
                    return Err(invalid_catalog());
                }
            }
            Some(b'}') => {
                index += 1;
                break;
            }
            _ => return Err(invalid_catalog()),
        }
    }
    if skip_json_whitespace(bytes, index) != bytes.len() {
        return Err(invalid_catalog());
    }
    let [
        envelope_version,
        signature_algorithm,
        key_id,
        payload,
        signature,
    ] = fields;
    let spans = SignedEnvelopeSpans {
        envelope_version: envelope_version.ok_or_else(invalid_catalog)?,
        signature_algorithm: signature_algorithm.ok_or_else(invalid_catalog)?,
        key_id: key_id.ok_or_else(invalid_catalog)?,
        payload: payload.ok_or_else(invalid_catalog)?,
        signature: signature.ok_or_else(invalid_catalog)?,
    };
    if bytes.len() - spans.payload.len() > MAX_NON_PAYLOAD_ENVELOPE_BYTES {
        return Err(invalid_catalog());
    }
    Ok(spans)
}

fn scan_json_value(bytes: &[u8], index: usize) -> Result<usize, CatalogSignatureError> {
    match bytes.get(index) {
        Some(b'\"') => scan_json_string(bytes, index),
        Some(b'{') | Some(b'[') => scan_json_compound(bytes, index),
        Some(_) => {
            let end = bytes[index..]
                .iter()
                .position(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b',' | b'}'))
                .map_or(bytes.len(), |offset| index + offset);
            (end > index).then_some(end).ok_or_else(invalid_catalog)
        }
        None => Err(invalid_catalog()),
    }
}

fn scan_json_compound(bytes: &[u8], index: usize) -> Result<usize, CatalogSignatureError> {
    let first_closer = match bytes[index] {
        b'{' => b'}',
        b'[' => b']',
        _ => return Err(invalid_catalog()),
    };
    let mut closers = Vec::with_capacity(16);
    closers.push(first_closer);
    let mut cursor = index + 1;
    while let Some(byte) = bytes.get(cursor).copied() {
        match byte {
            b'\"' => cursor = scan_json_string(bytes, cursor)?,
            b'{' | b'[' => {
                if closers.len() == MAX_JSON_NESTING_DEPTH {
                    return Err(invalid_catalog());
                }
                closers.push(if byte == b'{' { b'}' } else { b']' });
                cursor += 1;
            }
            b'}' | b']' => {
                if closers.pop() != Some(byte) {
                    return Err(invalid_catalog());
                }
                cursor += 1;
                if closers.is_empty() {
                    return Ok(cursor);
                }
            }
            _ => cursor += 1,
        }
    }
    Err(invalid_catalog())
}

fn scan_bounded_json_string(
    bytes: &[u8],
    index: usize,
    maximum_content_bytes: usize,
) -> Result<usize, CatalogSignatureError> {
    let end = scan_json_string(bytes, index)?;
    if end - index - 2 > maximum_content_bytes {
        return Err(invalid_catalog());
    }
    Ok(end)
}

fn scan_json_string(bytes: &[u8], index: usize) -> Result<usize, CatalogSignatureError> {
    if bytes.get(index) != Some(&b'\"') {
        return Err(invalid_catalog());
    }
    let mut cursor = index + 1;
    while let Some(byte) = bytes.get(cursor).copied() {
        match byte {
            b'\"' => return Ok(cursor + 1),
            b'\\' => match bytes.get(cursor + 1).copied() {
                Some(b'\"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                    cursor += 2;
                }
                Some(b'u') => {
                    let hex_end = cursor.checked_add(6).ok_or_else(invalid_catalog)?;
                    let digits = bytes
                        .get(cursor + 2..hex_end)
                        .filter(|digits| digits.len() == 4)
                        .ok_or_else(invalid_catalog)?;
                    if !digits.iter().all(u8::is_ascii_hexdigit) {
                        return Err(invalid_catalog());
                    }
                    cursor = hex_end;
                }
                _ => return Err(invalid_catalog()),
            },
            0x00..=0x1f => return Err(invalid_catalog()),
            _ => cursor += 1,
        }
    }
    Err(invalid_catalog())
}

fn skip_json_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while bytes
        .get(index)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        index += 1;
    }
    index
}

fn parse_scalar<T: DeserializeOwned>(
    bytes: &[u8],
    span: &Range<usize>,
) -> Result<T, CatalogSignatureError> {
    serde_json::from_slice(&bytes[span.clone()]).map_err(|_| invalid_catalog())
}

pub(crate) fn encode_base64url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        encoded.push(char::from(ALPHABET[usize::from(chunk[0] >> 2)]));
        encoded.push(char::from(
            ALPHABET
                [usize::from(((chunk[0] & 3) << 4) | (chunk.get(1).copied().unwrap_or(0) >> 4))],
        ));
        if let Some(second) = chunk.get(1) {
            encoded.push(char::from(
                ALPHABET
                    [usize::from(((second & 15) << 2) | (chunk.get(2).copied().unwrap_or(0) >> 6))],
            ));
        }
        if let Some(third) = chunk.get(2) {
            encoded.push(char::from(ALPHABET[usize::from(third & 63)]));
        }
    }
    encoded
}

fn decode_base64url_no_pad<const N: usize>(value: &str) -> Result<[u8; N], CoreError> {
    if value.contains('=') || value.len() != (N * 8).div_ceil(6) {
        return Err(CoreError::InvalidCatalog);
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(N);
    for chunk in bytes.chunks(4) {
        let a = base64url_value(chunk[0]).ok_or(CoreError::InvalidCatalog)?;
        let b = base64url_value(chunk[1]).ok_or(CoreError::InvalidCatalog)?;
        decoded.push((a << 2) | (b >> 4));
        if chunk.len() >= 3 {
            let c = base64url_value(chunk[2]).ok_or(CoreError::InvalidCatalog)?;
            decoded.push((b << 4) | (c >> 2));
            if chunk.len() == 4 {
                let d = base64url_value(chunk[3]).ok_or(CoreError::InvalidCatalog)?;
                decoded.push((c << 6) | d);
            }
        }
    }
    let decoded: [u8; N] = decoded.try_into().map_err(|_| CoreError::InvalidCatalog)?;
    if encode_base64url_no_pad(&decoded) != value {
        return Err(CoreError::InvalidCatalog);
    }
    Ok(decoded)
}

fn base64url_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

const fn invalid_catalog() -> CatalogSignatureError {
    CatalogSignatureError::InvalidSignedCatalog
}

const fn invalid_release_bundle() -> CatalogSignatureError {
    CatalogSignatureError::InvalidSignedReleaseBundle
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};

    use super::*;

    const TEST_SEED: [u8; 32] = [7; 32];
    const TEST_ID: &str = "catalog-unit-test-key-core-v1";

    fn test_identity() -> VerificationIdentity {
        VerificationIdentity {
            key_id: TEST_ID,
            public_key: SigningKey::from_bytes(&TEST_SEED)
                .verifying_key()
                .to_bytes(),
        }
    }

    fn envelope() -> Vec<u8> {
        let payload = CatalogPayloadV1::from_json(include_bytes!(
            "../../../conformance/catalog-v1/valid-payload.json"
        ))
        .unwrap();
        let canonical = canonical_catalog_payload(&payload).unwrap();
        let signature = SigningKey::from_bytes(&TEST_SEED).sign(&canonical);
        let payload: Value = serde_json::from_slice(&canonical).unwrap();
        serde_jcs::to_vec(&json!({
            "envelope_version": 1,
            "signature_algorithm": "ed25519",
            "key_id": TEST_ID,
            "payload": payload,
            "signature": encode_base64url_no_pad(&signature.to_bytes())
        }))
        .unwrap()
    }

    fn manifest(signature: &str) -> SignedReleaseBundleManifestV1 {
        SignedReleaseBundleManifestV1::from_json(
            &serde_jcs::to_vec(&json!({
                "schema_version": 1,
                "source_commit": "0123456789abcdef0123456789abcdef01234567",
                "source_tree_sha256": "11".repeat(32),
                "qualification_sha256": "22".repeat(32),
                "tag": "catalog-v1-sequence-42",
                "catalog_envelope": {
                    "name": "catalog-v1.json", "size": 10, "sha256": "33".repeat(32)
                },
                "assets": [{
                    "name": "package-json-44.json", "size": 5, "sha256": "44".repeat(32)
                }],
                "signature": { "key_id": TEST_ID, "signature": signature }
            }))
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn valid_signature_verifies_only_in_its_own_domain() {
        let catalog = envelope();
        let verified = verify_signed_catalog_with_identity(&catalog, test_identity()).unwrap();
        let catalog_signature: Value = serde_json::from_slice(&catalog).unwrap();
        let catalog_signature = catalog_signature["signature"].as_str().unwrap();

        let unsigned_manifest = manifest(&"A".repeat(86));
        let release_bytes = release_bundle_signing_bytes(&unsigned_manifest).unwrap();
        let release_signature = SigningKey::from_bytes(&TEST_SEED).sign(&release_bytes);
        let release = manifest(&encode_base64url_no_pad(&release_signature.to_bytes()));
        verify_release_manifest_with_identity(&release, test_identity()).unwrap();

        assert!(
            verify_signature(
                &test_identity().public_key,
                &release_bytes,
                catalog_signature
            )
            .is_err()
        );
        assert!(
            verify_signature(
                &test_identity().public_key,
                verified.canonical_payload(),
                release.signature().signature().as_str()
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_payload_spelling_is_part_of_envelope_admission() {
        let canonical_envelope = envelope();
        let value: Value = serde_json::from_slice(&canonical_envelope).unwrap();
        let noncanonical_payload = serde_json::to_string_pretty(&value["payload"]).unwrap();
        let altered = format!(
            "{{\"envelope_version\":1,\"signature_algorithm\":\"ed25519\",\"key_id\":\"{TEST_ID}\",\"payload\":{noncanonical_payload},\"signature\":{}}}",
            serde_json::to_string(value["signature"].as_str().unwrap()).unwrap()
        );
        assert!(verify_signed_catalog_with_identity(altered.as_bytes(), test_identity()).is_err());
    }

    #[test]
    fn scanner_and_signature_decoder_reject_adversarial_spellings() {
        let signed = envelope();
        let signed_value: Value = serde_json::from_slice(&signed).unwrap();
        let signature = signed_value["signature"].as_str().unwrap();

        let padded = String::from_utf8(signed.clone())
            .unwrap()
            .replace(signature, &format!("{signature}="));
        assert!(verify_signed_catalog_with_identity(padded.as_bytes(), test_identity()).is_err());

        let mut noncanonical_signature = signature.as_bytes().to_vec();
        let final_index = noncanonical_signature.len() - 1;
        noncanonical_signature[final_index] = match noncanonical_signature[final_index] {
            b'A' => b'B',
            b'Q' => b'R',
            b'g' => b'h',
            b'w' => b'x',
            _ => panic!("canonical 64-byte base64url has an unexpected final character"),
        };
        let noncanonical_signature = String::from_utf8(noncanonical_signature).unwrap();
        let noncanonical = String::from_utf8(signed.clone())
            .unwrap()
            .replace(signature, &noncanonical_signature);
        assert!(
            verify_signed_catalog_with_identity(noncanonical.as_bytes(), test_identity()).is_err()
        );

        let mut flipped_signature = signature.as_bytes().to_vec();
        flipped_signature[0] = if flipped_signature[0] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let flipped = String::from_utf8(signed)
            .unwrap()
            .replace(signature, &String::from_utf8(flipped_signature).unwrap());
        assert!(verify_signed_catalog_with_identity(flipped.as_bytes(), test_identity()).is_err());

        for malformed in [
            br#"{"pay\qload":0}"#.as_slice(),
            br#"{"pay\u12x4load":0}"#.as_slice(),
            br#"{"payload":"unterminated\"}"#.as_slice(),
        ] {
            assert!(scan_signed_envelope(malformed).is_err());
        }

        let nested = format!(
            "{{\"envelope_version\":1,\"signature_algorithm\":\"ed25519\",\"key_id\":\"{TEST_ID}\",\"payload\":{}0{},\"signature\":\"{}\"}}",
            "[".repeat(MAX_JSON_NESTING_DEPTH + 1),
            "]".repeat(MAX_JSON_NESTING_DEPTH + 1),
            "A".repeat(ED25519_SIGNATURE_TEXT_BYTES),
        );
        assert!(scan_signed_envelope(nested.as_bytes()).is_err());
    }

    #[test]
    fn production_identity_is_exact_and_canonical() {
        assert_eq!(
            encode_base64url_no_pad(PRODUCTION_IDENTITY.public_key_bytes()),
            PRODUCTION_PUBLIC_KEY_BASE64URL
        );
        assert_eq!(
            derive_runtime_catalog_key_id(PRODUCTION_IDENTITY.public_key_bytes()),
            PRODUCTION_KEY_ID
        );
    }
}
