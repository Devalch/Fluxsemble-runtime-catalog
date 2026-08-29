use crate::{WizardError, cli::RunMode};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleasePhase {
    Planned,
    InputsDiscovered,
    Acquired,
    CandidateAssembled,
    AwaitingQualification,
    QualificationImported,
    Qualified,
    Signed,
    LocalStaged,
    RemoteDraftStaged,
    Approved,
    Published,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WizardState {
    pub schema_version: u32,
    pub sequence: u64,
    pub pi_version: String,
    pub node_version: String,
    pub target: String,
    pub mode: RunMode,
    pub phase: ReleasePhase,
    pub signing_key_generation: u32,
    pub catalog_source_commit: String,
    pub catalog_source_tree_sha256: String,
    pub work_dir: PathBuf,
}

impl WizardState {
    pub fn load(path: &Path) -> Result<Option<Self>, WizardError> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(WizardError::State),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| WizardError::State)
    }

    pub fn save(&self, path: &Path) -> Result<(), WizardError> {
        let parent = path.parent().ok_or(WizardError::State)?;
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|_| WizardError::State)?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| WizardError::State)?;
        fs::write(path, bytes).map_err(|_| WizardError::State)
    }
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
    fn state_round_trip_preserves_release_identity() {
        let state = WizardState {
            schema_version: 1,
            sequence: 2,
            pi_version: "0.84.0".to_owned(),
            node_version: "22.20.0".to_owned(),
            target: "linux_x86_64".to_owned(),
            mode: RunMode::PublishCapable,
            phase: ReleasePhase::Qualified,
            signing_key_generation: 2,
            catalog_source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            catalog_source_tree_sha256: "11".repeat(32),
            work_dir: PathBuf::from(".release-work/sequence-2"),
        };
        let bytes = serde_json::to_vec(&state).unwrap();
        assert!(
            std::str::from_utf8(&bytes)
                .unwrap()
                .contains("\"phase\":\"qualified\"")
        );
        let decoded: WizardState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, state);
    }

    #[test]
    fn save_creates_parent_directory_and_load_restores_state() {
        let directory = temporary_directory();
        let path = directory.join("nested/wizard-state.json");
        let state = WizardState {
            schema_version: 1,
            sequence: 2,
            pi_version: "0.84.0".to_owned(),
            node_version: "22.20.0".to_owned(),
            target: "linux_x86_64".to_owned(),
            mode: RunMode::DryRun,
            phase: ReleasePhase::Planned,
            signing_key_generation: 1,
            catalog_source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            catalog_source_tree_sha256: "11".repeat(32),
            work_dir: directory.clone(),
        };

        state.save(&path).unwrap();
        assert_eq!(WizardState::load(&path).unwrap(), Some(state));
        fs::remove_dir_all(directory).unwrap();
    }

    fn temporary_directory() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("catalog-wizard-state-{unique}"))
    }
}
