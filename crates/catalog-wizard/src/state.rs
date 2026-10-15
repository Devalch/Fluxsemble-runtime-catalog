use crate::{WizardError, cli::RunMode};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const MAX_STATE_BYTES: u64 = 64 * 1024;
const RECOVERY_SUFFIX: &str = ".next";

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
#[serde(deny_unknown_fields)]
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
        let recovery = recovery_path(path)?;
        let primary = read_state_file(path)?;
        let pending = match read_state_file(&recovery) {
            Ok(pending) => pending,
            Err(_) if primary.is_some() => {
                remove_recovery(&recovery)?;
                return Ok(primary);
            }
            Err(error) => return Err(error),
        };
        match (primary, pending) {
            (None, None) => Ok(None),
            (Some(state), None) => Ok(Some(state)),
            (None, Some(state)) => {
                install_recovery(&recovery, path)?;
                Ok(Some(state))
            }
            (Some(primary), Some(pending)) => {
                if same_release(&primary, &pending)
                    && phase_rank(pending.phase) >= phase_rank(primary.phase)
                {
                    install_recovery(&recovery, path)?;
                    Ok(Some(pending))
                } else {
                    remove_recovery(&recovery)?;
                    Ok(Some(primary))
                }
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), WizardError> {
        validate_state(self)?;
        let parent = path.parent().ok_or(WizardError::State)?;
        ensure_private_directory(parent)?;
        let bytes = serde_jcs::to_vec(self).map_err(|_| WizardError::State)?;
        let recovery = recovery_path(path)?;

        if recovery.exists() {
            match read_state_file(&recovery) {
                Ok(Some(pending)) if pending == *self => {
                    return install_recovery(&recovery, path);
                }
                Ok(Some(_)) | Err(_) => remove_recovery(&recovery)?,
                Ok(None) => {}
            }
        }

        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options.open(&recovery).map_err(|_| WizardError::State)?;
        let result = (|| {
            file.write_all(&bytes).map_err(|_| WizardError::State)?;
            file.sync_all().map_err(|_| WizardError::State)?;
            verify_open_state_file(&mut file, &bytes)?;
            install_recovery(&recovery, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&recovery);
        }
        result
    }
}

fn read_state_file(path: &Path) -> Result<Option<WizardState>, WizardError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(WizardError::State),
    };
    let before = file.metadata().map_err(|_| WizardError::State)?;
    if !before.is_file()
        || before.uid() != current_euid()
        || before.nlink() != 1
        || before.permissions().mode() & 0o7777 != 0o600
        || before.len() == 0
        || before.len() > MAX_STATE_BYTES
    {
        return Err(WizardError::State);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| WizardError::State)?;
    let after = file.metadata().map_err(|_| WizardError::State)?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || after.nlink() != 1
    {
        return Err(WizardError::State);
    }
    let state: WizardState = serde_json::from_slice(&bytes).map_err(|_| WizardError::State)?;
    validate_state(&state)?;
    if serde_jcs::to_vec(&state).map_err(|_| WizardError::State)? != bytes {
        return Err(WizardError::State);
    }
    Ok(Some(state))
}

fn verify_open_state_file(file: &mut fs::File, expected: &[u8]) -> Result<(), WizardError> {
    let metadata = file.metadata().map_err(|_| WizardError::State)?;
    if !metadata.is_file()
        || metadata.uid() != current_euid()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.len() != expected.len() as u64
    {
        return Err(WizardError::State);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| WizardError::State)?;
    let mut actual = Vec::with_capacity(expected.len());
    file.read_to_end(&mut actual)
        .map_err(|_| WizardError::State)?;
    if actual == expected {
        Ok(())
    } else {
        Err(WizardError::State)
    }
}

fn install_recovery(recovery: &Path, path: &Path) -> Result<(), WizardError> {
    fs::rename(recovery, path).map_err(|_| WizardError::State)?;
    sync_directory(path.parent().ok_or(WizardError::State)?)
}

fn remove_recovery(recovery: &Path) -> Result<(), WizardError> {
    match fs::remove_file(recovery) {
        Ok(()) => sync_directory(recovery.parent().ok_or(WizardError::State)?),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(WizardError::State),
    }
}

fn recovery_path(path: &Path) -> Result<PathBuf, WizardError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(WizardError::State)?;
    Ok(path.with_file_name(format!("{name}{RECOVERY_SUFFIX}")))
}

fn ensure_private_directory(path: &Path) -> Result<(), WizardError> {
    if !path.exists() {
        let mut missing = Vec::new();
        let mut cursor = path;
        while !cursor.exists() {
            missing.push(cursor.to_owned());
            cursor = cursor.parent().ok_or(WizardError::State)?;
        }
        for directory in missing.iter().rev() {
            fs::create_dir(directory).map_err(|_| WizardError::State)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| WizardError::State)?;
            sync_directory(directory.parent().ok_or(WizardError::State)?)?;
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| WizardError::State)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_euid()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(WizardError::State);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), WizardError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| WizardError::State)
}

fn same_release(left: &WizardState, right: &WizardState) -> bool {
    left.schema_version == right.schema_version
        && left.sequence == right.sequence
        && left.pi_version == right.pi_version
        && left.node_version == right.node_version
        && left.target == right.target
        && left.mode == right.mode
        && left.signing_key_generation == right.signing_key_generation
        && left.catalog_source_commit == right.catalog_source_commit
        && left.catalog_source_tree_sha256 == right.catalog_source_tree_sha256
        && left.work_dir == right.work_dir
}

const fn phase_rank(phase: ReleasePhase) -> u8 {
    match phase {
        ReleasePhase::Planned => 0,
        ReleasePhase::InputsDiscovered => 1,
        ReleasePhase::Acquired => 2,
        ReleasePhase::CandidateAssembled => 3,
        ReleasePhase::AwaitingQualification => 4,
        ReleasePhase::QualificationImported => 5,
        ReleasePhase::Qualified => 6,
        ReleasePhase::Signed => 7,
        ReleasePhase::LocalStaged => 8,
        ReleasePhase::RemoteDraftStaged => 9,
        ReleasePhase::Approved => 10,
        ReleasePhase::Published => 11,
    }
}

fn validate_state(state: &WizardState) -> Result<(), WizardError> {
    if !matches!(state.schema_version, 1 | 2)
        || state.sequence == 0
        || state.pi_version.is_empty()
        || state.node_version.is_empty()
        || state.target != "linux_x86_64"
        || state.signing_key_generation == 0
        || state.catalog_source_commit.len() != 40
        || !state
            .catalog_source_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || state.catalog_source_tree_sha256.len() != 64
        || !state
            .catalog_source_tree_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !state.work_dir.is_absolute()
    {
        return Err(WizardError::State);
    }
    Ok(())
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions or side effects.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture(directory: &Path) -> WizardState {
        WizardState {
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
            work_dir: directory.to_owned(),
        }
    }

    #[test]
    fn state_round_trip_preserves_release_identity() {
        let directory = temporary_directory().join("sequence-2");
        let state = fixture(&directory);
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
    fn save_creates_private_parent_and_load_restores_state() {
        let root = temporary_directory();
        fs::create_dir(&root).unwrap();
        let directory = root.join("nested");
        let path = directory.join("wizard-state.json");
        let mut state = fixture(&directory);
        state.mode = RunMode::DryRun;
        state.phase = ReleasePhase::Planned;

        state.save(&path).unwrap();
        assert_eq!(WizardState::load(&path).unwrap(), Some(state));
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn load_recovers_a_fsynced_phase_replacement() {
        let root = temporary_directory();
        fs::create_dir(&root).unwrap();
        let directory = root.join("sequence-2");
        let path = directory.join("wizard-state.json");
        let mut planned = fixture(&directory);
        planned.phase = ReleasePhase::Planned;
        planned.save(&path).unwrap();

        let mut advanced = planned.clone();
        advanced.phase = ReleasePhase::InputsDiscovered;
        let recovery = recovery_path(&path).unwrap();
        fs::write(&recovery, serde_jcs::to_vec(&advanced).unwrap()).unwrap();
        fs::set_permissions(&recovery, fs::Permissions::from_mode(0o600)).unwrap();
        fs::File::open(&recovery).unwrap().sync_all().unwrap();

        assert_eq!(WizardState::load(&path).unwrap(), Some(advanced));
        assert!(!recovery.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_replacement_leaves_the_last_durable_state_visible() {
        let root = temporary_directory();
        fs::create_dir(&root).unwrap();
        let directory = root.join("sequence-2");
        let path = directory.join("wizard-state.json");
        let state = fixture(&directory);
        state.save(&path).unwrap();

        let recovery = recovery_path(&path).unwrap();
        fs::write(&recovery, b"truncated").unwrap();
        fs::set_permissions(&recovery, fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(WizardState::load(&path).unwrap(), Some(state));
        assert!(!recovery.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_older_recovery_cannot_roll_state_back() {
        let root = temporary_directory();
        fs::create_dir(&root).unwrap();
        let directory = root.join("sequence-2");
        let path = directory.join("wizard-state.json");
        let published = fixture(&directory);
        published.save(&path).unwrap();

        let mut stale = published.clone();
        stale.phase = ReleasePhase::Planned;
        let recovery = recovery_path(&path).unwrap();
        fs::write(&recovery, serde_jcs::to_vec(&stale).unwrap()).unwrap();
        fs::set_permissions(&recovery, fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(WizardState::load(&path).unwrap(), Some(published));
        assert!(!recovery.exists());
        fs::remove_dir_all(root).unwrap();
    }

    fn temporary_directory() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("catalog-wizard-state-{unique}"))
    }
}
