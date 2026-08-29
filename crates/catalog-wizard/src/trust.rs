use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use catalog_core::active_production_key_identity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    WizardError,
    key_rotation::inspect_key_with_isolated_signer,
    prompt::{Prompter, confirm_yes_no},
};

const PROFILE_SCHEMA_VERSION: u32 = 1;
const MAX_FIELD_BYTES: usize = 4_096;
const MAX_PROFILE_BYTES: u64 = 64 * 1024;
const MAX_PROFILE_FILES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineRole {
    Preparer,
    Signer,
    Publisher,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineFacts {
    pub machine_id: String,
    pub user: String,
    pub hostname: String,
    pub repo_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedMachineProfile {
    pub schema_version: u32,
    pub label: String,
    pub facts: MachineFacts,
    pub roles: Vec<MachineRole>,
    pub approved_by: String,
    pub approved_at: String,
    pub expires_at: Option<String>,
    pub signing_private_key_path: PathBuf,
    pub signing_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicMachineApprovalReceipt {
    pub receipt_type: String,
    pub label: String,
    pub roles: Vec<MachineRole>,
    pub approved_by: String,
    pub approved_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub profile_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    InvalidProfile,
    FactsDoNotMatch,
    MissingRole(MachineRole),
    Expired,
}

pub fn current_machine_facts(repo: &Path) -> Result<MachineFacts, WizardError> {
    let repo_root = fs::canonicalize(repo).map_err(|_| WizardError::Config)?;
    if !repo_root.is_dir() {
        return Err(WizardError::Config);
    }
    let machine_id = read_fact("/etc/machine-id")?;
    let hostname = read_fact("/etc/hostname")?;
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .map_err(|_| WizardError::Config)?;
    if user.is_empty() || user.len() > MAX_FIELD_BYTES {
        return Err(WizardError::Config);
    }
    Ok(MachineFacts {
        machine_id,
        user,
        hostname,
        repo_root,
    })
}

pub fn profile_matches(
    profile: &TrustedMachineProfile,
    facts: &MachineFacts,
    required: &[MachineRole],
) -> Result<(), TrustError> {
    validate_profile(profile)?;
    if &profile.facts != facts {
        return Err(TrustError::FactsDoNotMatch);
    }
    if let Some(expires_at) = &profile.expires_at {
        let expiry =
            DateTime::parse_from_rfc3339(expires_at).map_err(|_| TrustError::InvalidProfile)?;
        if expiry <= current_time().map_err(|_| TrustError::InvalidProfile)? {
            return Err(TrustError::Expired);
        }
    }
    for role in required {
        if !profile.roles.contains(role) {
            return Err(TrustError::MissingRole(*role));
        }
    }
    Ok(())
}

pub fn load_matching_profile(
    directory: &Path,
    facts: &MachineFacts,
    required: &[MachineRole],
) -> Result<TrustedMachineProfile, WizardError> {
    let directory_metadata = fs::symlink_metadata(directory).map_err(|_| WizardError::Config)?;
    if !directory_metadata.is_dir()
        || directory_metadata.file_type().is_symlink()
        || directory_metadata.uid() != current_euid()
        || directory_metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(WizardError::Config);
    }

    let mut matching = Vec::new();
    for (index, entry) in fs::read_dir(directory)
        .map_err(|_| WizardError::Config)?
        .enumerate()
    {
        if index >= MAX_PROFILE_FILES {
            return Err(WizardError::Config);
        }
        let entry = entry.map_err(|_| WizardError::Config)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| WizardError::Config)?;
        let label = name.strip_suffix(".json").ok_or(WizardError::Config)?;
        validate_label(label).map_err(|_| WizardError::Config)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| WizardError::Config)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != current_euid()
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > MAX_PROFILE_BYTES
        {
            return Err(WizardError::Config);
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options
            .open(entry.path())
            .map_err(|_| WizardError::Config)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&mut file)
            .take(MAX_PROFILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| WizardError::Config)?;
        let after = file.metadata().map_err(|_| WizardError::Config)?;
        if bytes.len() as u64 != metadata.len()
            || metadata.dev() != after.dev()
            || metadata.ino() != after.ino()
            || metadata.len() != after.len()
            || after.nlink() != 1
        {
            return Err(WizardError::Config);
        }
        let profile: TrustedMachineProfile =
            serde_json::from_slice(&bytes).map_err(|_| WizardError::Config)?;
        if profile.label != label
            || serde_jcs::to_vec(&profile).map_err(|_| WizardError::Config)? != bytes
        {
            return Err(WizardError::Config);
        }
        match profile_matches(&profile, facts, required) {
            Ok(()) => matching.push(profile),
            Err(TrustError::FactsDoNotMatch | TrustError::MissingRole(_) | TrustError::Expired) => {
            }
            Err(TrustError::InvalidProfile) => return Err(WizardError::Config),
        }
    }
    match matching.as_slice() {
        [profile] => Ok(profile.clone()),
        _ => Err(WizardError::Config),
    }
}

impl PublicMachineApprovalReceipt {
    #[must_use]
    pub fn from_profile(profile: &TrustedMachineProfile, approved_by: &str) -> Self {
        Self {
            receipt_type: "trusted_machine_approval".to_owned(),
            label: public_label(&profile.label),
            roles: profile.roles.clone(),
            approved_by: public_approval_owner(approved_by),
            approved_at: public_timestamp(&profile.approved_at),
            expires_at: profile.expires_at.as_deref().and_then(public_expiry),
            profile_sha256: profile_digest(profile),
        }
    }
}

pub fn trust_machine(
    prompter: &mut dyn Prompter,
    repo: &Path,
    local_profiles_dir: &Path,
) -> Result<TrustedMachineProfile, WizardError> {
    let label = prompter.ask("Trusted machine label: ")?;
    validate_label(&label).map_err(|_| WizardError::Config)?;
    if !confirm_yes_no(
        prompter,
        "Approve this machine for preparer, signer, and publisher roles? [yes/no]: ",
        false,
    )? {
        return Err(WizardError::UserDeclined);
    }
    let approved_by = prompter.ask("Approval owner: ")?;
    if !is_safe_public_owner(&approved_by) {
        return Err(WizardError::Config);
    }
    let expires_at =
        optional_expiry(&prompter.ask("Optional approval expiry (RFC 3339, blank for none): ")?)?;
    if expires_at.is_none() {
        prompter.say("Warning: this approval has no expiry.")?;
    }

    let private_key_path = PathBuf::from(prompter.ask("Existing private signing key path: ")?);
    let launcher_config = local_launcher_config_path(local_profiles_dir)?;
    let inspected = inspect_key_with_isolated_signer(&private_key_path, &launcher_config)?;
    let active = active_production_key_identity();
    if inspected.key_id != active.key_id() || inspected.public_key != active.public_key_base64url()
    {
        return Err(WizardError::Config);
    }

    let profile = TrustedMachineProfile {
        schema_version: PROFILE_SCHEMA_VERSION,
        label: label.clone(),
        facts: current_machine_facts(repo)?,
        roles: vec![
            MachineRole::Preparer,
            MachineRole::Signer,
            MachineRole::Publisher,
        ],
        approved_by: approved_by.clone(),
        approved_at: current_timestamp()?,
        expires_at,
        signing_private_key_path: private_key_path,
        signing_key_id: inspected.key_id,
    };
    validate_profile(&profile).map_err(|_| WizardError::Config)?;
    save_profile(&profile, local_profiles_dir)?;

    if confirm_yes_no(
        prompter,
        "Create a public approval receipt? [yes/no]: ",
        false,
    )? {
        save_public_receipt(
            &PublicMachineApprovalReceipt::from_profile(&profile, &approved_by),
            &repo.join("docs/trust"),
            &label,
        )?;
    }
    prompter.say(
        "A profile match means this matches a previously approved profile; it does not prove this machine is secure.",
    )?;
    Ok(profile)
}

fn validate_profile(profile: &TrustedMachineProfile) -> Result<(), TrustError> {
    if profile.schema_version != PROFILE_SCHEMA_VERSION
        || validate_label(&profile.label).is_err()
        || profile.approved_by.is_empty()
        || profile.approved_by.len() > MAX_FIELD_BYTES
        || profile.signing_key_id.is_empty()
        || profile.signing_private_key_path.as_os_str().is_empty()
        || !profile.signing_private_key_path.is_absolute()
        || !valid_facts(&profile.facts)
    {
        return Err(TrustError::InvalidProfile);
    }
    let roles = profile.roles.iter().copied().collect::<BTreeSet<_>>();
    if roles.len() != profile.roles.len() || roles.is_empty() {
        return Err(TrustError::InvalidProfile);
    }
    if let Some(expires_at) = &profile.expires_at {
        DateTime::parse_from_rfc3339(expires_at).map_err(|_| TrustError::InvalidProfile)?;
    }
    Ok(())
}

fn valid_facts(facts: &MachineFacts) -> bool {
    !facts.machine_id.is_empty()
        && !facts.hostname.is_empty()
        && !facts.user.is_empty()
        && facts.machine_id.len() <= MAX_FIELD_BYTES
        && facts.hostname.len() <= MAX_FIELD_BYTES
        && facts.user.len() <= MAX_FIELD_BYTES
        && facts.repo_root.is_absolute()
}

fn local_launcher_config_path(local_profiles_dir: &Path) -> Result<PathBuf, WizardError> {
    let config_dir = local_profiles_dir.parent().ok_or(WizardError::Config)?;
    if !local_profiles_dir.is_absolute()
        || local_profiles_dir
            .file_name()
            .and_then(|name| name.to_str())
            != Some("trusted-machines")
        || config_dir.file_name().and_then(|name| name.to_str())
            != Some("fluxsemble-runtime-catalog")
    {
        return Err(WizardError::Config);
    }
    Ok(config_dir.join("launcher-config-v1.json"))
}

fn optional_expiry(value: &str) -> Result<Option<String>, WizardError> {
    if value.is_empty() {
        return Ok(None);
    }
    let expiry = DateTime::parse_from_rfc3339(value).map_err(|_| WizardError::Config)?;
    if expiry <= current_time()? {
        return Err(WizardError::Config);
    }
    Ok(Some(
        expiry.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    ))
}

fn read_fact(path: &str) -> Result<String, WizardError> {
    let value = fs::read_to_string(path).map_err(|_| WizardError::Config)?;
    let value = value.trim().to_owned();
    if value.is_empty() || value.len() > MAX_FIELD_BYTES {
        return Err(WizardError::Config);
    }
    Ok(value)
}

fn current_timestamp() -> Result<String, WizardError> {
    Ok(current_time()?.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions or side effects.
    unsafe { libc::geteuid() }
}

fn current_time() -> Result<DateTime<Utc>, WizardError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| WizardError::Config)?
        .as_secs();
    let seconds = i64::try_from(seconds).map_err(|_| WizardError::Config)?;
    DateTime::<Utc>::from_timestamp(seconds, 0).ok_or(WizardError::Config)
}

fn profile_digest(profile: &TrustedMachineProfile) -> String {
    let bytes = serde_jcs::to_vec(profile).expect("trusted machine profile must serialize");
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_label(label: &str) -> Result<(), ()> {
    if label.is_empty()
        || label.len() > 80
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(());
    }
    Ok(())
}

fn is_safe_public_owner(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'@'))
}

fn public_label(label: &str) -> String {
    if validate_label(label).is_ok() {
        label.to_owned()
    } else {
        "invalid-label".to_owned()
    }
}

fn public_approval_owner(owner: &str) -> String {
    if is_safe_public_owner(owner) {
        owner.to_owned()
    } else {
        "invalid-approval-owner".to_owned()
    }
}

fn public_timestamp(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|_| "invalid-timestamp".to_owned())
}

fn public_expiry(value: &str) -> Option<String> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

fn save_profile(profile: &TrustedMachineProfile, directory: &Path) -> Result<(), WizardError> {
    let bytes = serde_jcs::to_vec(profile).map_err(|_| WizardError::Config)?;
    atomic_write(
        &directory.join(format!("{}.json", profile.label)),
        &bytes,
        0o600,
        "trust-machine",
    )
}

fn save_public_receipt(
    receipt: &PublicMachineApprovalReceipt,
    directory: &Path,
    label: &str,
) -> Result<(), WizardError> {
    let bytes = serde_jcs::to_vec(receipt).map_err(|_| WizardError::Config)?;
    atomic_write(
        &directory.join(format!("trusted-machine-approval-{label}.json")),
        &bytes,
        0o644,
        "trust-receipt",
    )
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32, suffix: &str) -> Result<(), WizardError> {
    let parent = path.parent().ok_or(WizardError::Io)?;
    if parent.exists() {
        let metadata = fs::symlink_metadata(parent).map_err(|_| WizardError::Io)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(WizardError::Config);
        }
        #[cfg(unix)]
        if mode == 0o600 {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(WizardError::Config);
            }
        }
    } else {
        fs::create_dir_all(parent).map_err(|_| WizardError::Io)?;
        #[cfg(unix)]
        if mode == 0o600 {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|_| WizardError::Io)?;
        }
    }
    let name = path.file_name().ok_or(WizardError::Io)?.to_string_lossy();
    let temporary = parent.join(format!(".{name}.{suffix}.tmp"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut file = options.open(&temporary).map_err(|_| WizardError::Io)?;
    let result = (|| {
        file.write_all(bytes).map_err(|_| WizardError::Io)?;
        file.sync_all().map_err(|_| WizardError::Io)?;
        fs::rename(&temporary, path).map_err(|_| WizardError::Io)?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| WizardError::Io)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
impl MachineFacts {
    fn fixture_matching() -> Self {
        Self {
            machine_id: "machine-1".to_owned(),
            user: "local-user".to_owned(),
            hostname: "trusted-host".to_owned(),
            repo_root: PathBuf::from("/repo"),
        }
    }
}

#[cfg(test)]
impl TrustedMachineProfile {
    fn fixture_with_roles(roles: Vec<MachineRole>) -> Self {
        Self {
            schema_version: PROFILE_SCHEMA_VERSION,
            label: "trusted-release-machine".to_owned(),
            facts: MachineFacts::fixture_matching(),
            roles,
            approved_by: "release-owner".to_owned(),
            approved_at: "2026-08-28T00:00:00Z".to_owned(),
            expires_at: None,
            signing_private_key_path: PathBuf::from("/private/signing.key"),
            signing_key_id: "runtime-catalog-ed25519-test".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn profile_requires_requested_roles() {
        let profile = TrustedMachineProfile::fixture_with_roles(vec![MachineRole::Preparer]);
        let facts = MachineFacts::fixture_matching();
        assert!(profile_matches(&profile, &facts, &[MachineRole::Preparer]).is_ok());
        assert!(profile_matches(&profile, &facts, &[MachineRole::Signer]).is_err());
    }

    #[test]
    fn matching_profile_loader_rejects_missing_roles_and_returns_exact_match() {
        let directory = std::env::temp_dir().join(format!(
            "catalog-wizard-trust-load-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let profile = TrustedMachineProfile::fixture_with_roles(vec![MachineRole::Preparer]);
        let path = directory.join("trusted-release-machine.json");
        fs::write(&path, serde_jcs::to_vec(&profile).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            load_matching_profile(
                &directory,
                &MachineFacts::fixture_matching(),
                &[MachineRole::Signer]
            ),
            Err(WizardError::Config)
        );
        assert_eq!(
            load_matching_profile(
                &directory,
                &MachineFacts::fixture_matching(),
                &[MachineRole::Preparer]
            )
            .unwrap(),
            profile
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn public_receipt_does_not_include_private_paths() {
        let profile = TrustedMachineProfile::fixture_with_roles(vec![
            MachineRole::Preparer,
            MachineRole::Signer,
            MachineRole::Publisher,
        ]);
        let receipt = PublicMachineApprovalReceipt::from_profile(&profile, "release-owner");
        let text = serde_json::to_string(&receipt).unwrap();
        assert!(!text.contains("/home/"));
        assert!(!text.contains("private"));
        assert!(text.contains("trusted_machine_approval"));
    }

    #[test]
    fn profile_requires_all_approved_machine_facts() {
        let profile = TrustedMachineProfile::fixture_with_roles(vec![MachineRole::Preparer]);
        let mut facts = MachineFacts::fixture_matching();
        facts.hostname = "different-host".to_owned();
        assert_eq!(
            profile_matches(&profile, &facts, &[MachineRole::Preparer]),
            Err(TrustError::FactsDoNotMatch)
        );
    }

    #[test]
    fn inspection_uses_fixed_local_launcher_config_without_prompt() {
        let profiles =
            PathBuf::from("/home/release/.config/fluxsemble-runtime-catalog/trusted-machines");
        assert_eq!(
            local_launcher_config_path(&profiles).unwrap(),
            PathBuf::from(
                "/home/release/.config/fluxsemble-runtime-catalog/launcher-config-v1.json"
            )
        );

        let mut prompter = crate::prompt::ScriptedPrompter::new([
            "release-machine",
            "yes",
            "release-owner",
            "",
            "/missing/signing.key",
        ]);
        assert_eq!(
            trust_machine(&mut prompter, Path::new("/"), &profiles),
            Err(WizardError::ExternalCommand)
        );
    }
}
