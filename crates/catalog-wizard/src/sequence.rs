use crate::WizardError;
use std::{fs, io::ErrorKind, path::Path};

const CATALOG_PREFIX: &str = "catalog-v1-sequence-";
const CATALOG_SUFFIX: &str = "-source.json";

/// A read-only source for the latest sequence recorded by GitHub.
pub trait GithubSequenceSource {
    fn latest_sequence(&self) -> Result<Option<u64>, WizardError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequenceMismatch {
    Disagreement {
        local: Option<u64>,
        github: Option<u64>,
    },
    NextSequenceOverflow {
        sequence: u64,
    },
}

/// Finds the greatest positive sequence encoded by a committed catalog filename.
pub fn local_latest_sequence(repo: &Path) -> Result<Option<u64>, WizardError> {
    let directory = repo.join("catalogs");
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(WizardError::Io),
    };

    let mut latest = None;
    for entry in entries {
        let entry = entry.map_err(|_| WizardError::Io)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(sequence) = name
            .strip_prefix(CATALOG_PREFIX)
            .and_then(|value| value.strip_suffix(CATALOG_SUFFIX))
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|sequence| *sequence > 0)
        else {
            continue;
        };
        latest = Some(latest.map_or(sequence, |current: u64| current.max(sequence)));
    }

    Ok(latest)
}

/// Returns the next sequence only when local and GitHub observations agree.
pub fn compare_sequences(local: Option<u64>, github: Option<u64>) -> Result<u64, SequenceMismatch> {
    if local != github {
        return Err(SequenceMismatch::Disagreement { local, github });
    }

    local
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(SequenceMismatch::NextSequenceOverflow { sequence: u64::MAX })
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
    fn matching_sequences_return_next_sequence() {
        assert_eq!(compare_sequences(Some(1), Some(1)).unwrap(), 2);
    }

    #[test]
    fn missing_both_sequences_starts_at_one() {
        assert_eq!(compare_sequences(None, None).unwrap(), 1);
    }

    #[test]
    fn disagreement_is_a_stop() {
        assert!(compare_sequences(Some(2), Some(1)).is_err());
    }

    #[test]
    fn local_scan_uses_highest_valid_positive_sequence_filename() {
        let repo = temporary_directory();
        let catalogs = repo.join("catalogs");
        fs::create_dir_all(&catalogs).unwrap();
        for name in [
            "catalog-v1-sequence-1-source.json",
            "catalog-v1-sequence-12-source.json",
            "catalog-v1-sequence-0-source.json",
            "catalog-v1-sequence-nope-source.json",
            "catalog-v1-sequence-13-source.json.bak",
        ] {
            fs::write(catalogs.join(name), "{}").unwrap();
        }

        assert_eq!(local_latest_sequence(&repo).unwrap(), Some(12));
        fs::remove_dir_all(repo).unwrap();
    }

    fn temporary_directory() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("catalog-wizard-sequence-{unique}"))
    }
}
