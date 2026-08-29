use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime},
};

use catalog_core::{
    CatalogPayloadV1, CatalogSourceV1, InitialPiReleaseIntentV1, active_production_key_identity,
    production_keyring, qualification_record_digest,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::{StatusCode, blocking::Client, header::USER_AGENT, redirect::Policy};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    WizardError,
    cli::{ReleaseOptions, RunMode},
    commands::{
        CommandPlan, build_acquire_intent, build_acquire_source, build_assemble_intent,
        build_finalize_candidate,
    },
    config::WizardConfig,
    intent::{GenerateReleaseInputsRequest, generate_release_inputs},
    npm::{
        NodeDistributionVersionSource, NodeVersionSource, NpmPiVersionSource, PiVersionSource,
        choose_pi_version, suggest_node_version,
    },
    prompt::{Prompter, confirm_yes_no},
    qualification,
    sequence::{compare_sequences, local_latest_sequence},
    state::{ReleasePhase, WizardState},
};

const TARGET: &str = "linux_x86_64";
const STATE_ROOT: &str = ".release-work";
const MAX_GITHUB_RESPONSE_BYTES: u64 = 1024 * 1024;
const GITHUB_LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/Devalch/Fluxsemble-runtime-catalog/releases/latest";

pub fn run_release(
    options: ReleaseOptions,
    prompter: &mut dyn Prompter,
) -> Result<(), WizardError> {
    let repo = std::env::current_dir().map_err(|_| WizardError::Config)?;
    let config = load_config(&repo, options.config.as_deref())?;
    if config.repository != "Devalch/Fluxsemble-runtime-catalog"
        || config.target != TARGET
        || config.state_root != STATE_ROOT
    {
        return Err(WizardError::Config);
    }
    require_clean_head(&repo)?;

    let local = local_latest_sequence(&repo)?;
    let github = github_latest_sequence()?;
    let sequence = compare_sequences(local, github).map_err(|_| WizardError::Discovery)?;
    let pi_versions = NpmPiVersionSource.available_pi_versions()?;
    let entered_pi;
    let requested_pi = match options.pi.as_deref() {
        Some(version) => Some(version),
        None => {
            entered_pi = prompter.ask("Pi version: ")?;
            Some(entered_pi.as_str())
        }
    };
    let pi_version = choose_pi_version(&pi_versions, requested_pi)?;

    let node_versions = NodeDistributionVersionSource.available_node_versions()?;
    let node_version = match options.node {
        Some(version) if node_versions.iter().any(|available| available == &version) => version,
        Some(_) => return Err(WizardError::Discovery),
        None => {
            let suggested = suggest_node_version(&node_versions, &config.default_node_channel)?;
            if !confirm_yes_no(
                prompter,
                &format!("Use suggested Node {suggested}? [Y/n]: "),
                true,
            )? {
                return Err(WizardError::UserDeclined);
            }
            suggested
        }
    };
    let mode = match options.mode {
        Some(mode) => mode,
        None => match prompter.ask("Release mode (dry-run/publish): ")?.as_str() {
            "dry-run" => RunMode::DryRun,
            "publish" => RunMode::PublishCapable,
            _ => return Err(WizardError::UserDeclined),
        },
    };
    if !confirm_yes_no(
        prompter,
        &format!(
            "Prepare sequence {sequence} with Pi {pi_version}, Node {node_version}, target {TARGET}, key generation {}, mode {:?}? [yes/no]: ",
            active_production_key_identity().generation(),
            mode
        ),
        false,
    )? {
        return Err(WizardError::UserDeclined);
    }

    let (commit, tree_sha256) = source_identity(&repo)?;
    let work_dir = repo.join(STATE_ROOT).join(format!("sequence-{sequence}"));
    if work_dir.exists() {
        return Err(WizardError::State);
    }
    let state = WizardState {
        schema_version: 1,
        sequence,
        pi_version,
        node_version,
        target: TARGET.to_owned(),
        mode,
        phase: ReleasePhase::Planned,
        signing_key_generation: active_production_key_identity().generation(),
        catalog_source_commit: commit,
        catalog_source_tree_sha256: tree_sha256,
        work_dir,
    };
    let launcher_config = private_config_root()?.join("launcher-config-v1.json");
    let mut release = ProductionRelease::new(state, repo, launcher_config, false, None, prompter);
    drive_release(&mut release)
}

pub fn resume_release(prompter: &mut dyn Prompter) -> Result<(), WizardError> {
    resume_release_with_qualification(None, prompter)
}

pub fn resume_release_with_qualification(
    qualification_path: Option<&Path>,
    prompter: &mut dyn Prompter,
) -> Result<(), WizardError> {
    let repo = std::env::current_dir().map_err(|_| WizardError::Config)?;
    let state = select_resumable_state(&repo, prompter)?;
    validate_resumed_state(&repo, &state)?;
    let launcher_config = private_config_root()?.join("launcher-config-v1.json");
    let mut release = ProductionRelease::new(
        state,
        repo,
        launcher_config,
        true,
        qualification_path.map(Path::to_owned),
        prompter,
    );
    drive_release(&mut release)
}

trait ReleaseMachine {
    fn phase(&self) -> ReleasePhase;
    fn mode(&self) -> RunMode;
    fn save_phase(&mut self, phase: ReleasePhase) -> Result<(), WizardError>;
    fn generate_inputs(&mut self) -> Result<(), WizardError>;
    fn acquire_intent(&mut self) -> Result<(), WizardError>;
    fn assemble_intent(&mut self) -> Result<(), WizardError>;
    fn export_qualification(&mut self) -> Result<(), WizardError>;
    fn qualification_available(&self) -> bool;
    fn import_qualification(&mut self) -> Result<(), WizardError>;
    fn finalize_qualified_candidate(&mut self) -> Result<(), WizardError>;
    fn say(&mut self, message: &str) -> Result<(), WizardError>;
}

fn drive_release(release: &mut dyn ReleaseMachine) -> Result<(), WizardError> {
    loop {
        match release.phase() {
            ReleasePhase::Planned => {
                release.generate_inputs()?;
                release.save_phase(ReleasePhase::InputsDiscovered)?;
            }
            ReleasePhase::InputsDiscovered => {
                release.acquire_intent()?;
                release.save_phase(ReleasePhase::Acquired)?;
            }
            ReleasePhase::Acquired => {
                release.assemble_intent()?;
                release.save_phase(ReleasePhase::CandidateAssembled)?;
            }
            ReleasePhase::CandidateAssembled => {
                release.export_qualification()?;
                release.save_phase(ReleasePhase::AwaitingQualification)?;
            }
            ReleasePhase::AwaitingQualification => {
                if !release.qualification_available() {
                    release.say("Fluxsemble qualification is required. Send this directory to the Fluxsemble maintainer, then run catalog-wizard resume.")?;
                    return Ok(());
                }
                release.import_qualification()?;
                release.save_phase(ReleasePhase::QualificationImported)?;
            }
            ReleasePhase::QualificationImported => {
                release.finalize_qualified_candidate()?;
                release.save_phase(ReleasePhase::Qualified)?;
            }
            ReleasePhase::Qualified => {
                if release.mode() == RunMode::DryRun {
                    release.say("Dry run complete; no signing or publishing was performed.")?;
                } else {
                    release.say("Qualified candidate is ready; no signing or publishing was performed without approval.")?;
                }
                return Ok(());
            }
            _ => return Err(WizardError::State),
        }
    }
}

struct ProductionRelease<'a> {
    state: WizardState,
    repo: PathBuf,
    launcher_config: PathBuf,
    qualification_available: bool,
    qualification_path: Option<PathBuf>,
    prompter: &'a mut dyn Prompter,
}

impl<'a> ProductionRelease<'a> {
    fn new(
        state: WizardState,
        repo: PathBuf,
        launcher_config: PathBuf,
        qualification_available: bool,
        qualification_path: Option<PathBuf>,
        prompter: &'a mut dyn Prompter,
    ) -> Self {
        Self {
            state,
            repo,
            launcher_config,
            qualification_available,
            qualification_path,
            prompter,
        }
    }

    fn state_path(&self) -> PathBuf {
        self.state.work_dir.join("wizard-state.json")
    }

    fn execute(&self, plan: &CommandPlan) -> Result<(), WizardError> {
        let status = Command::new(&plan.program)
            .args(&plan.args)
            .current_dir(&self.repo)
            .status()
            .map_err(|_| WizardError::ExternalCommand)?;
        if status.success() {
            Ok(())
        } else {
            Err(WizardError::ExternalCommand)
        }
    }
}

impl ReleaseMachine for ProductionRelease<'_> {
    fn phase(&self) -> ReleasePhase {
        self.state.phase
    }
    fn mode(&self) -> RunMode {
        self.state.mode
    }

    fn save_phase(&mut self, phase: ReleasePhase) -> Result<(), WizardError> {
        self.state.phase = phase;
        self.state.save(&self.state_path())
    }

    fn generate_inputs(&mut self) -> Result<(), WizardError> {
        let generated = generate_release_inputs(GenerateReleaseInputsRequest {
            repository_root: self.repo.clone(),
            sequence: self.state.sequence,
            pi_version: self.state.pi_version.clone(),
            node_version: self.state.node_version.clone(),
            target: self.state.target.clone(),
            generated_at: DateTime::<Utc>::from(SystemTime::now()),
            validity_window: ChronoDuration::days(31),
        })?;
        if generated.intent_path != self.state.work_dir.join("intent.json")
            || generated.package_inputs_path != self.state.work_dir.join("package-inputs.json")
        {
            return Err(WizardError::State);
        }
        Ok(())
    }

    fn acquire_intent(&mut self) -> Result<(), WizardError> {
        let output = self.state.work_dir.join("acquired-transfer");
        if output.exists() {
            catalog_acquire::verify_transferred_bundle(&output)
                .map(|_| ())
                .map_err(|_| WizardError::ExternalCommand)
        } else {
            self.execute(&build_acquire_intent(
                &self.state.work_dir.join("intent.json"),
                &self.state.work_dir.join("package-inputs.json"),
                &output,
            ))
        }
    }

    fn assemble_intent(&mut self) -> Result<(), WizardError> {
        let output = self.state.work_dir.join("unsigned-candidate");
        if output.exists() {
            read_canonical_candidate(&output).map(|_| ())
        } else {
            self.execute(&build_assemble_intent(
                &self.launcher_config,
                &self.state.work_dir.join("acquired-transfer"),
                &output,
            ))?;
            read_canonical_candidate(&output).map(|_| ())
        }
    }

    fn export_qualification(&mut self) -> Result<(), WizardError> {
        qualification::export_request(
            &self.state,
            &self.state.work_dir.join("acquired-transfer"),
            &self.state.work_dir.join("qualification-request"),
        )?;
        Ok(())
    }

    fn qualification_available(&self) -> bool {
        self.qualification_available
    }

    fn import_qualification(&mut self) -> Result<(), WizardError> {
        qualification::resume_qualification(
            &self.state,
            self.qualification_path.as_deref(),
            production_keyring().sha256(),
            self.prompter,
        )?;
        Ok(())
    }

    fn finalize_qualified_candidate(&mut self) -> Result<(), WizardError> {
        let source = build_catalog_source(&self.state)?;
        let transfer = self.state.work_dir.join("final-acquired-transfer");
        if transfer.exists() {
            catalog_acquire::verify_transferred_bundle(&transfer)
                .map_err(|_| WizardError::ExternalCommand)?;
        } else {
            self.execute(&build_acquire_source(
                &source,
                &self.state.work_dir.join("package-inputs.json"),
                &self.state.catalog_source_commit,
                &self.state.catalog_source_tree_sha256,
                &transfer,
            ))?;
        }
        let final_candidate = self.state.work_dir.join("final-unsigned-candidate");
        if !final_candidate.exists() {
            self.execute(&build_finalize_candidate(
                &self.launcher_config,
                &transfer,
                &final_candidate,
            ))?;
        }
        let initial = read_canonical_candidate(&self.state.work_dir.join("unsigned-candidate"))?;
        let final_bytes = read_canonical_candidate(&final_candidate)?;
        if initial != final_bytes {
            return Err(WizardError::Qualification);
        }
        Ok(())
    }

    fn say(&mut self, message: &str) -> Result<(), WizardError> {
        self.prompter.say(message)
    }
}

fn build_catalog_source(state: &WizardState) -> Result<PathBuf, WizardError> {
    let intent_bytes = read_bounded_regular(&state.work_dir.join("intent.json"), 8 * 1024 * 1024)?;
    let intent = InitialPiReleaseIntentV1::from_json(&intent_bytes)
        .map_err(|_| WizardError::Qualification)?;
    if intent.sequence().get() != state.sequence
        || intent.release().pi_version().as_str() != state.pi_version
        || intent.release().node_version().as_str() != state.node_version
        || intent.release().target().as_str() != state.target
    {
        return Err(WizardError::Qualification);
    }
    let imported = state.work_dir.join("imported-qualification");
    let build_bytes =
        read_bounded_regular(&imported.join("build-binding-v1.json"), 8 * 1024 * 1024)?;
    let qualification_bytes =
        read_bounded_regular(&imported.join("qualification-v1.json"), 8 * 1024 * 1024)?;
    let build: serde_json::Value =
        serde_json::from_slice(&build_bytes).map_err(|_| WizardError::Qualification)?;
    let qualification_value: serde_json::Value =
        serde_json::from_slice(&qualification_bytes).map_err(|_| WizardError::Qualification)?;
    if serde_jcs::to_vec(&build).map_err(|_| WizardError::Qualification)? != build_bytes
        || serde_jcs::to_vec(&qualification_value).map_err(|_| WizardError::Qualification)?
            != qualification_bytes
    {
        return Err(WizardError::Qualification);
    }
    let qualification = catalog_core::CompatibilityQualificationV1::from_json(&qualification_bytes)
        .map_err(|_| WizardError::Qualification)?;
    let qualification_sha256 = encode_sha256(
        &qualification_record_digest(&qualification).map_err(|_| WizardError::Qualification)?,
    );
    let relative = format!(
        "qualifications/compatibility-pi-{}-node-{}-fluxsemble-0.1.0-v1.json",
        state.pi_version, state.node_version
    );
    let qualification_path = state.work_dir.join(&relative);
    write_exact_or_verify(&qualification_path, &qualification_bytes)?;
    let source_value = json!({
        "intent": serde_json::to_value(&intent).map_err(|_| WizardError::Qualification)?,
        "build": build,
        "qualification": { "relative_path": relative, "sha256": qualification_sha256 },
    });
    let source_bytes = serde_jcs::to_vec(&source_value).map_err(|_| WizardError::Qualification)?;
    let source =
        CatalogSourceV1::from_json(&source_bytes).map_err(|_| WizardError::Qualification)?;
    if source.intent() != &intent || source.build() != qualification.fluxsemble() {
        return Err(WizardError::Qualification);
    }
    let source_path = state.work_dir.join(format!(
        "catalog-v1-sequence-{}-source.json",
        state.sequence
    ));
    write_exact_or_verify(&source_path, &source_bytes)?;
    Ok(source_path)
}

fn read_canonical_candidate(path: &Path) -> Result<Vec<u8>, WizardError> {
    let bytes = read_bounded_regular(path, 8 * 1024 * 1024)?;
    let payload = CatalogPayloadV1::from_json(&bytes).map_err(|_| WizardError::Qualification)?;
    if serde_jcs::to_vec(&payload).map_err(|_| WizardError::Qualification)? != bytes {
        return Err(WizardError::Qualification);
    }
    Ok(bytes)
}

fn write_exact_or_verify(path: &Path, bytes: &[u8]) -> Result<(), WizardError> {
    if path.exists() {
        return if read_bounded_regular(path, 8 * 1024 * 1024)? == bytes {
            Ok(())
        } else {
            Err(WizardError::Qualification)
        };
    }
    let parent = path.parent().ok_or(WizardError::Io)?;
    fs::create_dir_all(parent).map_err(|_| WizardError::Io)?;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| WizardError::Io)?;
    file.write_all(bytes).map_err(|_| WizardError::Io)?;
    file.sync_all().map_err(|_| WizardError::Io)
}

fn read_bounded_regular(path: &Path, maximum: u64) -> Result<Vec<u8>, WizardError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| WizardError::Io)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
        || metadata.nlink() != 1
    {
        return Err(WizardError::Io);
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| WizardError::Io)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| WizardError::Io)?;
    let after = file.metadata().map_err(|_| WizardError::Io)?;
    if bytes.len() as u64 != metadata.len()
        || metadata.dev() != after.dev()
        || metadata.ino() != after.ino()
        || metadata.len() != after.len()
        || after.nlink() != 1
    {
        return Err(WizardError::Io);
    }
    Ok(bytes)
}

fn select_resumable_state(
    repo: &Path,
    prompter: &mut dyn Prompter,
) -> Result<WizardState, WizardError> {
    let root = repo.join(STATE_ROOT);
    let root_metadata = fs::symlink_metadata(&root).map_err(|_| WizardError::State)?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(WizardError::State);
    }
    let mut states = Vec::new();
    for entry in fs::read_dir(&root).map_err(|_| WizardError::State)? {
        let entry = entry.map_err(|_| WizardError::State)?;
        if states.len() >= 64 {
            return Err(WizardError::State);
        }
        let metadata = entry.file_type().map_err(|_| WizardError::State)?;
        if !metadata.is_dir() || metadata.is_symlink() {
            continue;
        }
        let state_path = entry.path().join("wizard-state.json");
        let state_metadata = match fs::symlink_metadata(&state_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(WizardError::State),
        };
        if !state_metadata.is_file() || state_metadata.file_type().is_symlink() {
            return Err(WizardError::State);
        }
        if let Some(state) = WizardState::load(&state_path)? {
            if !matches!(state.phase, ReleasePhase::Published) {
                states.push(state);
            }
        }
    }
    states.sort_by_key(|state| state.sequence);
    match states.len() {
        0 => Err(WizardError::State),
        1 => Ok(states.remove(0)),
        _ => {
            let sequence = prompter
                .ask("Release sequence to resume: ")?
                .parse::<u64>()
                .map_err(|_| WizardError::State)?;
            states
                .into_iter()
                .find(|state| state.sequence == sequence)
                .ok_or(WizardError::State)
        }
    }
}

fn validate_resumed_state(repo: &Path, state: &WizardState) -> Result<(), WizardError> {
    let expected = repo
        .join(STATE_ROOT)
        .join(format!("sequence-{}", state.sequence));
    if state.schema_version != 1
        || state.sequence == 0
        || state.target != TARGET
        || state.work_dir != expected
        || state.signing_key_generation == 0
        || state.catalog_source_commit.len() != 40
        || !lower_hex(&state.catalog_source_commit)
        || state.catalog_source_tree_sha256.len() != 64
        || !lower_hex(&state.catalog_source_tree_sha256)
    {
        return Err(WizardError::State);
    }
    Ok(())
}

fn load_config(repo: &Path, configured: Option<&str>) -> Result<WizardConfig, WizardError> {
    let path = configured.map_or_else(|| repo.join("catalog-wizard.toml"), PathBuf::from);
    WizardConfig::load(&path)
}

fn private_config_root() -> Result<PathBuf, WizardError> {
    let home = PathBuf::from(std::env::var_os("HOME").ok_or(WizardError::Config)?);
    if !home.is_absolute() {
        return Err(WizardError::Config);
    }
    Ok(home.join(".config/fluxsemble-runtime-catalog"))
}

fn require_clean_head(repo: &Path) -> Result<(), WizardError> {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(repo)
        .output()
        .map_err(|_| WizardError::Config)?;
    if !output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty() {
        return Err(WizardError::Config);
    }
    Ok(())
}

fn source_identity(repo: &Path) -> Result<(String, String), WizardError> {
    let commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
        .map_err(|_| WizardError::Config)?;
    if !commit.status.success() || !commit.stderr.is_empty() {
        return Err(WizardError::Config);
    }
    let commit = String::from_utf8(commit.stdout).map_err(|_| WizardError::Config)?;
    let commit = commit.trim_end_matches(['\r', '\n']).to_owned();
    if commit.len() != 40 || !lower_hex(&commit) {
        return Err(WizardError::Config);
    }
    let tree = Command::new("git")
        .args(["ls-tree", "-r", "--full-tree", "-z", "HEAD"])
        .current_dir(repo)
        .output()
        .map_err(|_| WizardError::Config)?;
    if !tree.status.success() || !tree.stderr.is_empty() || tree.stdout.is_empty() {
        return Err(WizardError::Config);
    }
    Ok((commit, format!("{:x}", Sha256::digest(&tree.stdout))))
}

fn github_latest_sequence() -> Result<Option<u64>, WizardError> {
    let client = Client::builder()
        .https_only(true)
        .use_rustls_tls()
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| WizardError::Discovery)?;
    let response = client
        .get(GITHUB_LATEST_RELEASE_URL)
        .header(USER_AGENT, "catalog-wizard/0.1.0")
        .send()
        .map_err(|_| WizardError::Discovery)?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if response.status() != StatusCode::OK {
        return Err(WizardError::Discovery);
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_GITHUB_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| WizardError::Discovery)?;
    if bytes.len() as u64 > MAX_GITHUB_RESPONSE_BYTES {
        return Err(WizardError::Discovery);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| WizardError::Discovery)?;
    let tag = value
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .ok_or(WizardError::Discovery)?;
    let sequence = tag
        .strip_prefix("catalog-v1-sequence-")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or(WizardError::Discovery)?;
    Ok(Some(sequence))
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn encode_sha256(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ReleaseHarness {
        phase: ReleasePhase,
        mode: RunMode,
        qualification_available: bool,
        executed: Vec<String>,
        saved_phases: Vec<ReleasePhase>,
        messages: Vec<String>,
        parity_verified: bool,
    }

    impl ReleaseHarness {
        fn dry_run_fixture() -> Self {
            Self {
                phase: ReleasePhase::Planned,
                mode: RunMode::DryRun,
                qualification_available: false,
                executed: Vec::new(),
                saved_phases: Vec::new(),
                messages: Vec::new(),
                parity_verified: false,
            }
        }
    }

    impl ReleaseMachine for ReleaseHarness {
        fn phase(&self) -> ReleasePhase {
            self.phase
        }
        fn mode(&self) -> RunMode {
            self.mode
        }
        fn save_phase(&mut self, phase: ReleasePhase) -> Result<(), WizardError> {
            self.phase = phase;
            self.saved_phases.push(phase);
            Ok(())
        }
        fn generate_inputs(&mut self) -> Result<(), WizardError> {
            self.executed.push("generate-release-inputs".to_owned());
            Ok(())
        }
        fn acquire_intent(&mut self) -> Result<(), WizardError> {
            self.executed
                .push("catalog-acquire acquire-intent --intent intent.json".to_owned());
            Ok(())
        }
        fn assemble_intent(&mut self) -> Result<(), WizardError> {
            self.executed
                .push("catalog-sign-launcher assemble-intent --input transfer".to_owned());
            Ok(())
        }
        fn export_qualification(&mut self) -> Result<(), WizardError> {
            self.executed.push("export-qualification".to_owned());
            Ok(())
        }
        fn qualification_available(&self) -> bool {
            self.qualification_available
        }
        fn import_qualification(&mut self) -> Result<(), WizardError> {
            self.executed.push("import-qualification".to_owned());
            Ok(())
        }
        fn finalize_qualified_candidate(&mut self) -> Result<(), WizardError> {
            self.executed
                .push("catalog-acquire acquire-source --source source.json".to_owned());
            self.executed
                .push("catalog-sign-launcher finalize --input final-transfer".to_owned());
            self.parity_verified = true;
            Ok(())
        }
        fn say(&mut self, message: &str) -> Result<(), WizardError> {
            self.messages.push(message.to_owned());
            Ok(())
        }
    }

    fn run_release_with_harness(harness: &mut ReleaseHarness) -> Result<(), WizardError> {
        drive_release(harness)
    }

    #[test]
    fn dry_run_stops_before_signing_and_remote_mutations() {
        let mut harness = ReleaseHarness::dry_run_fixture();
        run_release_with_harness(&mut harness).unwrap();
        assert!(
            harness
                .executed
                .iter()
                .any(|command| command.contains("acquire-intent"))
        );
        assert!(
            !harness
                .executed
                .iter()
                .any(|command| command.contains(" sign "))
        );
        assert!(
            !harness
                .executed
                .iter()
                .any(|command| command.contains("stage-remote"))
        );
    }

    #[test]
    fn each_completed_release_phase_is_persisted_and_resume_reaches_verified_dry_run() {
        let mut harness = ReleaseHarness::dry_run_fixture();
        run_release_with_harness(&mut harness).unwrap();
        assert_eq!(
            harness.saved_phases,
            vec![
                ReleasePhase::InputsDiscovered,
                ReleasePhase::Acquired,
                ReleasePhase::CandidateAssembled,
                ReleasePhase::AwaitingQualification,
            ]
        );

        harness.qualification_available = true;
        run_release_with_harness(&mut harness).unwrap();
        assert_eq!(harness.saved_phases.last(), Some(&ReleasePhase::Qualified));
        assert!(harness.parity_verified);
        assert_eq!(
            harness.messages.last().map(String::as_str),
            Some("Dry run complete; no signing or publishing was performed.")
        );
    }
}
