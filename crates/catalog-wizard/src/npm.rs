use crate::WizardError;
use reqwest::{StatusCode, blocking::Client, header::CONTENT_LENGTH, redirect::Policy};
use semver::Version;
use serde_json::Value;
use std::{io::Read, time::Duration};

const PI_METADATA_URL: &str = "https://registry.npmjs.org/@earendil-works%2Fpi-coding-agent";
const NODE_INDEX_URL: &str = "https://nodejs.org/dist/index.json";
const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A credential-free source of versions published for the approved Pi package.
pub trait PiVersionSource {
    fn available_pi_versions(&self) -> Result<Vec<String>, WizardError>;
}

/// A credential-free source of versions published in the Node distribution index.
pub trait NodeVersionSource {
    fn available_node_versions(&self) -> Result<Vec<String>, WizardError>;
}

/// Fetches Pi versions from the only npm package metadata endpoint admitted by the wizard.
#[derive(Debug, Default, Clone, Copy)]
pub struct NpmPiVersionSource;

impl PiVersionSource for NpmPiVersionSource {
    fn available_pi_versions(&self) -> Result<Vec<String>, WizardError> {
        let metadata = fetch_metadata(PI_METADATA_URL)?;
        let versions = metadata
            .get("versions")
            .and_then(Value::as_object)
            .ok_or(WizardError::Discovery)?;
        normalize_versions(versions.keys().map(String::as_str), false)
    }
}

/// Fetches Node versions from the only Node distribution index admitted by the wizard.
#[derive(Debug, Default, Clone, Copy)]
pub struct NodeDistributionVersionSource;

impl NodeVersionSource for NodeDistributionVersionSource {
    fn available_node_versions(&self) -> Result<Vec<String>, WizardError> {
        let metadata = fetch_metadata(NODE_INDEX_URL)?;
        let entries = metadata.as_array().ok_or(WizardError::Discovery)?;
        let versions = entries
            .iter()
            .map(|entry| {
                entry
                    .get("version")
                    .and_then(Value::as_str)
                    .ok_or(WizardError::Discovery)
            })
            .collect::<Result<Vec<_>, _>>()?;
        normalize_versions(versions, true)
    }
}

/// Selects a requested Pi version only if the discovered source explicitly listed it.
pub fn choose_pi_version(
    available: &[String],
    preselected: Option<&str>,
) -> Result<String, WizardError> {
    validate_discovered_versions(available)?;
    match preselected {
        Some(version) if available.iter().any(|available| available == version) => {
            Ok(version.to_owned())
        }
        Some(_) => Err(WizardError::Discovery),
        None => available.first().cloned().ok_or(WizardError::Discovery),
    }
}

/// Suggests the greatest stable release in the configured major channel.
///
/// The caller must obtain user confirmation before using the suggestion.
pub fn suggest_node_version(available: &[String], channel: &str) -> Result<String, WizardError> {
    let major = channel.parse::<u64>().map_err(|_| WizardError::Discovery)?;
    let versions = parsed_stable_versions(available.iter().map(String::as_str), false)?;

    versions
        .into_iter()
        .filter(|version| version.major == major)
        .max()
        .map(|version| version.to_string())
        .ok_or(WizardError::Discovery)
}

fn fetch_metadata(endpoint: &str) -> Result<Value, WizardError> {
    let client = credential_free_client()?;
    let response = client
        .get(endpoint)
        .send()
        .map_err(|_| WizardError::Discovery)?;
    if response.status() != StatusCode::OK {
        return Err(WizardError::Discovery);
    }
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAX_METADATA_BYTES)
    {
        return Err(WizardError::Discovery);
    }

    let mut bytes = Vec::new();
    response
        .take((MAX_METADATA_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| WizardError::Discovery)?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(WizardError::Discovery);
    }
    serde_json::from_slice(&bytes).map_err(|_| WizardError::Discovery)
}

fn credential_free_client() -> Result<Client, WizardError> {
    Client::builder()
        .https_only(true)
        .use_rustls_tls()
        .no_proxy()
        .referer(false)
        .redirect(Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|_| WizardError::Discovery)
}

fn normalize_versions<'a>(
    versions: impl IntoIterator<Item = &'a str>,
    strip_node_prefix: bool,
) -> Result<Vec<String>, WizardError> {
    let parsed = parsed_stable_versions(versions, strip_node_prefix)?;
    if parsed.is_empty() {
        return Err(WizardError::Discovery);
    }
    Ok(parsed
        .into_iter()
        .map(|version| version.to_string())
        .collect())
}

fn validate_discovered_versions(available: &[String]) -> Result<(), WizardError> {
    if available.is_empty() {
        return Err(WizardError::Discovery);
    }
    for value in available {
        let version = Version::parse(value).map_err(|_| WizardError::Discovery)?;
        if !version.pre.is_empty() {
            return Err(WizardError::Discovery);
        }
    }
    Ok(())
}

fn parsed_stable_versions<'a>(
    versions: impl IntoIterator<Item = &'a str>,
    strip_node_prefix: bool,
) -> Result<Vec<Version>, WizardError> {
    let mut parsed = Vec::new();
    for value in versions {
        let value = if strip_node_prefix {
            value.strip_prefix('v').ok_or(WizardError::Discovery)?
        } else {
            value
        };
        let version = Version::parse(value).map_err(|_| WizardError::Discovery)?;
        if version.pre.is_empty() {
            parsed.push(version);
        }
    }
    parsed.sort_unstable_by(|left, right| right.cmp(left));
    parsed.dedup();
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preselected_pi_must_exist_in_available_versions() {
        let available = vec!["0.84.0".to_owned(), "0.83.1".to_owned()];
        assert_eq!(
            choose_pi_version(&available, Some("0.84.0")).unwrap(),
            "0.84.0"
        );
        assert!(choose_pi_version(&available, Some("0.82.0")).is_err());
        assert!(choose_pi_version(&["0.84.0-rc.1".to_owned()], Some("0.84.0-rc.1")).is_err());
        assert!(
            choose_pi_version(
                &["0.84.0".to_owned(), "0.85.0-rc.1".to_owned()],
                Some("0.84.0"),
            )
            .is_err()
        );
    }

    #[test]
    fn node_suggestion_uses_latest_stable_in_configured_major_channel() {
        let available = vec![
            "22.19.0".to_owned(),
            "22.20.0".to_owned(),
            "23.1.0".to_owned(),
        ];
        assert_eq!(suggest_node_version(&available, "22").unwrap(), "22.20.0");
    }

    #[test]
    fn metadata_parsing_rejects_malformed_or_only_prerelease_versions() {
        assert!(normalize_versions(["0.84"], false).is_err());
        assert!(normalize_versions(["0.84.0-rc.1"], false).is_err());
    }

    #[test]
    fn metadata_parsing_normalizes_node_versions_and_sorts_descending() {
        assert_eq!(
            normalize_versions(["v22.19.0", "v22.20.0", "v23.1.0-rc.1"], true).unwrap(),
            vec!["22.20.0", "22.19.0"],
        );
    }
}
