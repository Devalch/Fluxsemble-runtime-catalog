use sha2::{Digest, Sha256};

use crate::{CatalogPayloadV1, CoreError};

/// Serializes an already validated payload using RFC 8785 JSON Canonicalization Scheme.
pub fn canonical_catalog_payload(payload: &CatalogPayloadV1) -> Result<Vec<u8>, CoreError> {
    serde_jcs::to_vec(payload).map_err(|_| CoreError::InvalidCatalog)
}

/// Computes SHA-256 over the RFC 8785 canonical payload bytes.
pub fn catalog_payload_sha256(payload: &CatalogPayloadV1) -> Result<[u8; 32], CoreError> {
    Ok(Sha256::digest(canonical_catalog_payload(payload)?).into())
}
