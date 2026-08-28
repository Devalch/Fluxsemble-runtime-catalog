use crate::WizardError;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

const V1_FLUXSEMBLE_REQUIREMENT: &str = "=0.1.0";
const V1_TARGET: &str = "linux_x86_64";
const PRIVATE_SIGNING_CONFIG_SCHEMA_VERSION: u32 = 1;
const MAX_PRIVATE_KEY_PATH_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WizardConfig {
    pub repository: String,
    pub fluxsemble_requirement: String,
    pub target: String,
    pub state_root: String,
    pub default_node_channel: String,
}

impl WizardConfig {
    pub fn default_for_repo() -> Self {
        Self {
            repository: "Devalch/Fluxsemble-runtime-catalog".to_owned(),
            fluxsemble_requirement: V1_FLUXSEMBLE_REQUIREMENT.to_owned(),
            target: V1_TARGET.to_owned(),
            state_root: ".release-work".to_owned(),
            default_node_channel: "22".to_owned(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, WizardError> {
        let contents = fs::read_to_string(path).map_err(|_| WizardError::Config)?;
        let config: Self = toml::from_str(&contents).map_err(|_| WizardError::Config)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), WizardError> {
        if self.target != V1_TARGET || self.fluxsemble_requirement != V1_FLUXSEMBLE_REQUIREMENT {
            return Err(WizardError::Config);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivateSigningConfig {
    pub schema_version: u32,
    pub signing_key_generation: u32,
    pub private_key_path: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateSigningConfigFile {
    schema_version: u32,
    signing_key_generation: u32,
    private_key_path: String,
}

impl PrivateSigningConfig {
    pub fn load(path: &Path) -> Result<Self, WizardError> {
        validate_private_config_file(path)?;
        let contents = fs::read_to_string(path).map_err(|_| WizardError::Config)?;
        let config: PrivateSigningConfigFile =
            serde_json::from_str(&contents).map_err(|_| WizardError::Config)?;
        validate_private_key_path(&config.private_key_path)?;

        if config.schema_version != PRIVATE_SIGNING_CONFIG_SCHEMA_VERSION
            || config.signing_key_generation == 0
        {
            return Err(WizardError::Config);
        }

        Ok(Self {
            schema_version: config.schema_version,
            signing_key_generation: config.signing_key_generation,
            private_key_path: PathBuf::from(config.private_key_path),
        })
    }
}

fn validate_private_key_path(path: &str) -> Result<(), WizardError> {
    if path.len() > MAX_PRIVATE_KEY_PATH_BYTES
        || !path.starts_with('/')
        || path
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(WizardError::Config);
    }
    Ok(())
}

fn validate_private_config_file(path: &Path) -> Result<(), WizardError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| WizardError::Config)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(WizardError::Config);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(WizardError::Config);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn default_config_has_fixed_v1_values() {
        let config = WizardConfig::default_for_repo();
        assert_eq!(config.repository, "Devalch/Fluxsemble-runtime-catalog");
        assert_eq!(config.fluxsemble_requirement, "=0.1.0");
        assert_eq!(config.target, "linux_x86_64");
        assert_eq!(config.state_root, ".release-work");
    }

    #[test]
    fn config_load_rejects_non_v1_target() {
        let path = temporary_path("invalid-target.toml");
        fs::write(
            &path,
            r#"repository = "Devalch/Fluxsemble-runtime-catalog"
fluxsemble_requirement = "=0.1.0"
target = "darwin_aarch64"
state_root = ".release-work"
default_node_channel = "22"
"#,
        )
        .unwrap();

        assert!(WizardConfig::load(&path).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn private_signing_config_rejects_relative_key_path() {
        let path = temporary_path("private-signing.json");
        fs::write(
            &path,
            r#"{"schema_version":1,"signing_key_generation":2,"private_key_path":"keys/release.key"}"#,
        )
        .unwrap();
        set_private_permissions(&path);

        assert!(PrivateSigningConfig::load(&path).is_err());
        fs::remove_file(path).unwrap();
    }

    fn temporary_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("catalog-wizard-{unique}-{name}"))
    }

    #[cfg(unix)]
    fn set_private_permissions(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_private_permissions(_: &std::path::Path) {}
}
