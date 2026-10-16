//! Shared pure parsing and platform policy, also used by legacy acquisition adapters.
use crate::{AcquireError, DiscoverPiReleaseRequest};
use base64::Engine as _;
use serde::{Deserialize, de};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: usize = 1024 * 1024;
const MAX_LOCKED_COUNT: usize = 4096;
const NPM_ORIGIN: &str = "https://registry.npmjs.org";
type LockPackageRecord = (String, Map<String, Value>);
pub fn validate_discovery_request(request: &DiscoverPiReleaseRequest) -> Result<(), AcquireError> {
    if request.sequence == 0
        || request.target != "linux_x86_64"
        || !valid_version(&request.pi_version)
        || !valid_version(&request.node_version)
    {
        return Err(AcquireError::Input);
    }
    Ok(())
}

pub fn npm_metadata_url(name: &str, version: &str) -> Result<String, AcquireError> {
    if name.is_empty() || !valid_version(version) {
        return Err(AcquireError::Input);
    }
    let encoded = name.replace('/', "%2F");
    Ok(format!("{NPM_ORIGIN}/{encoded}/{version}"))
}

pub fn parse_npm_metadata(
    bytes: &[u8],
    expected_name: &str,
    expected_version: &str,
    expected_tarball: Option<&str>,
) -> Result<(String, String), AcquireError> {
    if bytes.is_empty() || bytes.len() > MAX_METADATA_BYTES {
        return Err(AcquireError::Input);
    }
    reject_duplicate_json(bytes)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| AcquireError::Input)?;
    let object = value.as_object().ok_or(AcquireError::Input)?;
    require_string(object, "name", expected_name)?;
    require_string(object, "version", expected_version)?;
    let dist = object
        .get("dist")
        .and_then(Value::as_object)
        .ok_or(AcquireError::Input)?;
    let tarball = dist
        .get("tarball")
        .and_then(Value::as_str)
        .ok_or(AcquireError::Input)?;
    let integrity = dist
        .get("integrity")
        .and_then(Value::as_str)
        .ok_or(AcquireError::Input)?;
    require_registry_url(tarball)?;
    if expected_tarball.is_some_and(|expected| expected != tarball) || !valid_sri(integrity) {
        return Err(AcquireError::Input);
    }
    Ok((tarball.to_owned(), integrity.to_owned()))
}

pub fn parse_node_checksum(bytes: &[u8], expected_name: &str) -> Result<String, AcquireError> {
    if bytes.is_empty() || bytes.len() > MAX_CHECKSUM_BYTES {
        return Err(AcquireError::Input);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| AcquireError::Input)?;
    let mut found = None;
    for line in text.lines() {
        let Some((digest, name)) = line.split_once("  ") else {
            return Err(AcquireError::Input);
        };
        if name == expected_name {
            if found.is_some() || !valid_sha256(digest) {
                return Err(AcquireError::Input);
            }
            found = Some(digest.to_owned());
        }
    }
    found.ok_or(AcquireError::Input)
}

pub fn require_registry_url(url: &str) -> Result<(), AcquireError> {
    if url.starts_with(&format!("{NPM_ORIGIN}/"))
        && !url.contains(['?', '#', '\\'])
        && url.len() <= 4096
    {
        Ok(())
    } else {
        Err(AcquireError::InvalidPolicy)
    }
}

pub fn safe_locator(value: &str) -> bool {
    value.len() <= 1024
        && value.starts_with("node_modules/")
        && !value.contains('\\')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

pub fn valid_version(value: &str) -> bool {
    let mut parts = value.split('.');
    parts.clone().count() == 3
        && parts.all(|part| {
            !part.is_empty()
                && (part == "0" || !part.starts_with('0'))
                && part.bytes().all(|byte| byte.is_ascii_digit())
        })
}

pub fn lock_package_records(
    shrinkwrap: &Map<String, Value>,
) -> Result<Vec<LockPackageRecord>, AcquireError> {
    let packages = shrinkwrap
        .get("packages")
        .and_then(Value::as_object)
        .ok_or(AcquireError::Graph)?;
    if packages.len() < 2 || packages.len() > MAX_LOCKED_COUNT + 1 || !packages.contains_key("") {
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

pub fn applicability_reasons(
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
    Ok(positives.is_empty()
        || positives
            .iter()
            .any(|value| **value == target || **value == "any"))
}

pub fn parse_json_object(bytes: &[u8], maximum: usize) -> Result<Map<String, Value>, AcquireError> {
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

pub fn require_string(
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

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub fn valid_sri(value: &str) -> bool {
    value.len() == 95
        && value.starts_with("sha512-")
        && base64::engine::general_purpose::STANDARD
            .decode(&value[7..])
            .is_ok_and(|bytes| bytes.len() == 64)
}

pub fn reject_duplicate_json(bytes: &[u8]) -> Result<(), AcquireError> {
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
mod selector_tests {
    use super::*;
    #[test]
    fn npm_any_selector_preserves_explicit_exclusion() {
        for target in ["linux", "x64", "glibc"] {
            assert!(selector_allows(&serde_json::json!(["any"]), target).unwrap());
            assert!(
                !selector_allows(&serde_json::json!(["any", format!("!{target}")]), target)
                    .unwrap()
            );
            assert!(!selector_allows(&serde_json::json!(["other"]), target).unwrap());
        }
    }
}
