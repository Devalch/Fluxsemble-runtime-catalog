use std::{
    collections::BTreeSet,
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
use reqwest::{
    StatusCode,
    blocking::Client,
    header::{LINK, USER_AGENT},
    redirect::Policy,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    WizardError,
    cli::{ReleaseOptions, ResumeOptions, RunMode},
    commands::{
        CommandPlan, build_acquire_intent, build_acquire_source, build_assemble_intent,
        build_finalize_candidate, build_publish, build_publish_approve, build_publish_stage_local,
        build_publish_stage_remote, build_sign,
    },
    config::{PrivateSigningConfig, WizardConfig},
    intent::{GenerateReleaseInputsRequest, generate_release_inputs},
    key_rotation::{verify_active_signing_key, verify_signed_bundle_key},
    npm::{
        NodeDistributionVersionSource, NodeVersionSource, NpmPiVersionSource, PiVersionSource,
        choose_pi_version, suggest_node_version,
    },
    prompt::{Prompter, confirm_yes_no, require_phrase},
    qualification::{self, verify_consumer_keyring_readiness},
    sequence::{compare_sequences, local_latest_sequence},
    state::{ReleasePhase, WizardState},
    trust::{self, MachineRole},
};

const TARGET: &str = "linux_x86_64";
const STATE_ROOT: &str = ".release-work";
const MAX_GITHUB_RESPONSE_BYTES: u64 = 1024 * 1024;
const GITHUB_TAGS_URL: &str = "https://api.github.com/repos/Devalch/Fluxsemble-runtime-catalog/git/matching-refs/tags/catalog-v1-sequence-?per_page=100";
const GITHUB_RELEASES_URL: &str =
    "https://api.github.com/repos/Devalch/Fluxsemble-runtime-catalog/releases?per_page=100";
const REPOSITORY: &str = "Devalch/Fluxsemble-runtime-catalog";

pub fn run_release(
    options: ReleaseOptions,
    prompter: &mut dyn Prompter,
) -> Result<(), WizardError> {
    let repo = std::env::current_dir().map_err(|_| WizardError::Config)?;
    let config_path = resume_config_path(&repo, options.config.as_deref());
    let config = WizardConfig::load(&config_path)?;
    validate_release_config(&config)?;
    require_clean_head(&repo)?;
    require_trusted_machine(&repo, &[MachineRole::Preparer])?;

    loop {
        let unfinished = resumable_states(&repo)?;
        if unfinished.is_empty() {
            break;
        }
        match UnfinishedChoice::parse(
            &prompter.ask("An unfinished release exists. Enter resume, start new, or exit: ")?,
        )? {
            UnfinishedChoice::Resume => {
                return resume_in_repo(&repo, &config, None, prompter);
            }
            UnfinishedChoice::StartNew => {
                let state = choose_resumable_state(unfinished, prompter)?;
                archive_unfinished_state(&repo, &state)?;
            }
            UnfinishedChoice::Exit => return Err(WizardError::UserDeclined),
        }
    }

    let local = local_latest_sequence(&repo)?;
    let observation = github_sequence_observation(local, &publisher_broker_config()?)?;
    let sequence = reconcile_github_state(local, &observation)?;
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
    require_trusted_machine(&repo, required_roles(mode))?;
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
    resume_release_with_options(
        ResumeOptions {
            qualification: None,
            config: None,
        },
        prompter,
    )
}

pub fn resume_release_with_qualification(
    qualification_path: Option<&Path>,
    prompter: &mut dyn Prompter,
) -> Result<(), WizardError> {
    let qualification = qualification_path
        .map(|path| path.to_str().map(str::to_owned).ok_or(WizardError::Config))
        .transpose()?;
    resume_release_with_options(
        ResumeOptions {
            qualification,
            config: None,
        },
        prompter,
    )
}

pub fn resume_release_with_options(
    options: ResumeOptions,
    prompter: &mut dyn Prompter,
) -> Result<(), WizardError> {
    let repo = std::env::current_dir().map_err(|_| WizardError::Config)?;
    let config = WizardConfig::load(&resume_config_path(&repo, options.config.as_deref()))?;
    validate_release_config(&config)?;
    resume_in_repo(
        &repo,
        &config,
        options.qualification.as_deref().map(Path::new),
        prompter,
    )
}

fn resume_in_repo(
    repo: &Path,
    _config: &WizardConfig,
    qualification_path: Option<&Path>,
    prompter: &mut dyn Prompter,
) -> Result<(), WizardError> {
    require_clean_head(repo)?;
    let state = select_resumable_state(repo, prompter)?;
    validate_resumed_state(repo, &state)?;
    verify_resumed_source_identity(&state, &source_identity(repo)?)?;
    require_trusted_machine(repo, required_roles(state.mode))?;
    let local = local_latest_sequence(repo)?;
    let observation = github_sequence_observation(local, &publisher_broker_config()?)?;
    if reconcile_github_state(local, &observation)? != state.sequence {
        return Err(WizardError::Discovery);
    }
    let launcher_config = private_config_root()?.join("launcher-config-v1.json");
    let mut release = ProductionRelease::new(
        state,
        repo.to_owned(),
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
    fn prepare_signing(&mut self) -> Result<(), WizardError>;
    fn require_exact_phrase(&mut self, phrase: &str) -> Result<(), WizardError>;
    fn sign(&mut self) -> Result<(), WizardError>;
    fn verify_signed_bundle(&mut self) -> Result<(), WizardError>;
    fn stage_local(&mut self) -> Result<(), WizardError>;
    fn stage_remote(&mut self) -> Result<(), WizardError>;
    fn approve_draft(&mut self) -> Result<(), WizardError>;
    fn publish(&mut self) -> Result<(), WizardError>;
    fn update_docs_and_evidence(&mut self) -> Result<(), WizardError>;
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
                    return Ok(());
                }
                release.prepare_signing()?;
                release.require_exact_phrase("SIGN")?;
                release.sign()?;
                release.verify_signed_bundle()?;
                release.save_phase(ReleasePhase::Signed)?;
            }
            ReleasePhase::Signed => {
                release.verify_signed_bundle()?;
                release.stage_local()?;
                release.save_phase(ReleasePhase::LocalStaged)?;
            }
            ReleasePhase::LocalStaged => {
                release.require_exact_phrase("CREATE TAG")?;
                release.require_exact_phrase("CREATE DRAFT")?;
                release.require_exact_phrase("UPLOAD ASSETS")?;
                release.stage_remote()?;
                release.save_phase(ReleasePhase::RemoteDraftStaged)?;
            }
            ReleasePhase::RemoteDraftStaged => {
                release.approve_draft()?;
                release.save_phase(ReleasePhase::Approved)?;
            }
            ReleasePhase::Approved => {
                release.require_exact_phrase("PUBLISH")?;
                release.publish()?;
                release.save_phase(ReleasePhase::Published)?;
            }
            ReleasePhase::Published => {
                release.update_docs_and_evidence()?;
                return Ok(());
            }
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
        let candidate = self.state.work_dir.join("acquired-transfer");
        let output = self.state.work_dir.join("qualification-request");
        if output.exists() {
            qualification::verify_existing_request(&self.state, &candidate, &output)
        } else {
            qualification::export_request(&self.state, &candidate, &output).map(|_| ())
        }
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

    fn prepare_signing(&mut self) -> Result<(), WizardError> {
        match verified_signing_context(&self.state, &self.launcher_config) {
            Ok(_) => Ok(()),
            Err(error) => {
                self.prompter.say(
                    "Signing stopped: the approved qualification or active signing key does not match this release.",
                )?;
                Err(error)
            }
        }
    }

    fn require_exact_phrase(&mut self, phrase: &str) -> Result<(), WizardError> {
        require_phrase(
            self.prompter,
            &format!("Type {phrase} to continue: "),
            phrase,
        )
    }

    fn sign(&mut self) -> Result<(), WizardError> {
        let config = match verified_signing_context(&self.state, &self.launcher_config) {
            Ok((config, _)) => config,
            Err(error) => {
                self.prompter.say(
                    "Signing stopped: the approved qualification or active signing key does not match this release.",
                )?;
                return Err(error);
            }
        };
        let output = self.state.work_dir.join("signed-release-bundle");
        if output.exists() {
            return self.verify_signed_bundle();
        }
        self.execute(&build_sign(
            &self.launcher_config,
            &self.state.work_dir.join("final-acquired-transfer"),
            &config.private_key_path,
            &output,
        ))
    }

    fn verify_signed_bundle(&mut self) -> Result<(), WizardError> {
        let result =
            verified_signing_context(&self.state, &self.launcher_config).and_then(|(_, active)| {
                verify_signed_bundle_key(
                    &self.state.work_dir.join("signed-release-bundle"),
                    &active,
                )
            });
        if let Err(error) = result {
            self.prompter.say(
                "Publishing stopped: the signed bundle does not use the approved active signing key.",
            )?;
            return Err(error);
        }
        Ok(())
    }

    fn stage_local(&mut self) -> Result<(), WizardError> {
        self.execute(&build_publish_stage_local(
            &self.state.work_dir.join("signed-release-bundle"),
            &self.state.work_dir.join("publish-state"),
        ))
    }

    fn stage_remote(&mut self) -> Result<(), WizardError> {
        self.execute(&build_publish_stage_remote(
            &self.state.work_dir.join("publish-state"),
            &publisher_broker_config()?,
        ))
    }

    fn approve_draft(&mut self) -> Result<(), WizardError> {
        let publish_state = self.state.work_dir.join("publish-state");
        let receipt = read_bounded_regular(
            &publish_state.join("latest/draft-receipt-v1.json"),
            8 * 1024 * 1024,
        )?;
        let digest = format!("{:x}", Sha256::digest(receipt));
        self.execute(&build_publish_approve(&publish_state, &digest))
    }

    fn publish(&mut self) -> Result<(), WizardError> {
        let publish_state = self.state.work_dir.join("publish-state");
        self.execute(&build_publish(
            &publish_state,
            &publish_state.join("latest/release-approval-v1.json"),
            &publisher_broker_config()?,
        ))
    }

    fn update_docs_and_evidence(&mut self) -> Result<(), WizardError> {
        let receipt_paths = generate_public_receipts(&self.repo, &self.state)?;
        let answer = self
            .prompter
            .ask("Update docs and evidence files now? [Y/n]")?;
        if matches!(answer.as_str(), "" | "y" | "Y" | "yes" | "YES") {
            commit_public_evidence(&self.repo, &self.state, &receipt_paths)
        } else if matches!(answer.as_str(), "n" | "N" | "no" | "NO") {
            for path in receipt_paths {
                self.prompter
                    .say(&format!("Generated receipt: {}", path.display()))?;
            }
            Ok(())
        } else {
            Err(WizardError::UserDeclined)
        }
    }

    fn say(&mut self, message: &str) -> Result<(), WizardError> {
        self.prompter.say(message)
    }
}

fn verified_signing_context(
    state: &WizardState,
    launcher_config: &Path,
) -> Result<(PrivateSigningConfig, crate::key_rotation::ActiveSigningKey), WizardError> {
    let qualification_bytes = read_bounded_regular(
        &state
            .work_dir
            .join("imported-qualification/qualification-v1.json"),
        8 * 1024 * 1024,
    )?;
    let approved = catalog_core::CompatibilityQualificationV1::from_json(&qualification_bytes)
        .map_err(|_| WizardError::Qualification)?;
    verify_consumer_keyring_readiness(&approved, production_keyring().sha256())?;

    let config = PrivateSigningConfig::load(&private_config_root()?.join("signing-key.json"))?;
    let active = verify_active_signing_key(&config.private_key_path, launcher_config)?;
    if config.signing_key_generation != state.signing_key_generation
        || active.generation != state.signing_key_generation
        || active.keyring_sha256 != production_keyring().sha256()
    {
        return Err(WizardError::Config);
    }
    Ok((config, active))
}

fn generate_public_receipts(
    _repo: &Path,
    state: &WizardState,
) -> Result<Vec<PathBuf>, WizardError> {
    let source_root = state.work_dir.join("publish-state/latest");
    let receipt_root = state.work_dir.join("receipts");
    let mut generated = Vec::new();
    for name in ["publication-receipt-v1.json", "latest-receipt-v1.json"] {
        let bytes = read_bounded_regular(&source_root.join(name), 8 * 1024 * 1024)?;
        let destination = receipt_root.join(name);
        write_exact_or_verify(&destination, &bytes)?;
        generated.push(destination);
    }
    Ok(generated)
}

fn commit_public_evidence(
    repo: &Path,
    state: &WizardState,
    receipt_paths: &[PathBuf],
) -> Result<(), WizardError> {
    if receipt_paths.len() != 2 {
        return Err(WizardError::State);
    }
    let destinations = [
        repo.join(format!(
            "qualifications/publication-receipt-sequence-{}.json",
            state.sequence
        )),
        repo.join(format!(
            "qualifications/latest-receipt-sequence-{}.json",
            state.sequence
        )),
    ];
    let receipt_bytes = receipt_paths
        .iter()
        .map(|source| read_bounded_regular(source, 8 * 1024 * 1024))
        .collect::<Result<Vec<_>, _>>()?;
    let document = format!(
        "# Runtime catalog release sequence {}\n\nPublic release evidence:\n\n- `qualifications/publication-receipt-sequence-{}.json`\n- `qualifications/latest-receipt-sequence-{}.json`\n",
        state.sequence, state.sequence, state.sequence
    );
    let document_path = repo.join(format!("docs/release-sequence-{}.md", state.sequence));

    for (destination, bytes) in destinations.iter().zip(receipt_bytes.iter()) {
        require_absent_or_exact(destination, bytes)?;
    }
    require_absent_or_exact(&document_path, document.as_bytes())?;
    for (destination, bytes) in destinations.iter().zip(receipt_bytes.iter()) {
        write_exact_or_verify(destination, bytes)?;
    }
    write_exact_or_verify(&document_path, document.as_bytes())
}

fn require_absent_or_exact(path: &Path, bytes: &[u8]) -> Result<(), WizardError> {
    match fs::symlink_metadata(path) {
        Ok(_) if read_bounded_regular(path, 8 * 1024 * 1024)? == bytes => Ok(()),
        Ok(_) => Err(WizardError::State),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(WizardError::Io),
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
    choose_resumable_state(resumable_states(repo)?, prompter)
}

fn choose_resumable_state(
    mut states: Vec<WizardState>,
    prompter: &mut dyn Prompter,
) -> Result<WizardState, WizardError> {
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

fn resumable_states(repo: &Path) -> Result<Vec<WizardState>, WizardError> {
    let root = repo.join(STATE_ROOT);
    let root_metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(WizardError::State),
    };
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(WizardError::State);
    }
    let mut states = Vec::new();
    for (index, entry) in fs::read_dir(&root)
        .map_err(|_| WizardError::State)?
        .enumerate()
    {
        if index >= 256 {
            return Err(WizardError::State);
        }
        let entry = entry.map_err(|_| WizardError::State)?;
        if states.len() >= 64 {
            return Err(WizardError::State);
        }
        let metadata = entry.file_type().map_err(|_| WizardError::State)?;
        if !metadata.is_dir() || metadata.is_symlink() {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| WizardError::State)?;
        let Some(sequence) = name
            .strip_prefix("sequence-")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|sequence| *sequence > 0)
        else {
            continue;
        };
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
            if state.sequence != sequence {
                return Err(WizardError::State);
            }
            if !matches!(state.phase, ReleasePhase::Published) {
                states.push(state);
            }
        }
    }
    states.sort_by_key(|state| state.sequence);
    Ok(states)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnfinishedChoice {
    Resume,
    StartNew,
    Exit,
}

impl UnfinishedChoice {
    fn parse(value: &str) -> Result<Self, WizardError> {
        match value {
            "resume" => Ok(Self::Resume),
            "start new" => Ok(Self::StartNew),
            "exit" => Ok(Self::Exit),
            _ => Err(WizardError::UserDeclined),
        }
    }
}

fn archive_unfinished_state(repo: &Path, state: &WizardState) -> Result<(), WizardError> {
    if !matches!(
        state.phase,
        ReleasePhase::Planned
            | ReleasePhase::InputsDiscovered
            | ReleasePhase::Acquired
            | ReleasePhase::CandidateAssembled
            | ReleasePhase::AwaitingQualification
            | ReleasePhase::QualificationImported
            | ReleasePhase::Qualified
    ) {
        return Err(WizardError::State);
    }
    validate_resumed_state(repo, state)?;
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| WizardError::State)?
        .as_nanos();
    let destination = repo
        .join(STATE_ROOT)
        .join(format!("abandoned-sequence-{}-{nonce}", state.sequence));
    if destination.exists() {
        return Err(WizardError::State);
    }
    fs::rename(&state.work_dir, &destination).map_err(|_| WizardError::State)?;
    fs::File::open(repo.join(STATE_ROOT))
        .and_then(|directory| directory.sync_all())
        .map_err(|_| WizardError::State)
}

fn verify_resumed_source_identity(
    state: &WizardState,
    current: &(String, String),
) -> Result<(), WizardError> {
    if current.0 == state.catalog_source_commit && current.1 == state.catalog_source_tree_sha256 {
        Ok(())
    } else {
        Err(WizardError::State)
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

fn resume_config_path(repo: &Path, configured: Option<&str>) -> PathBuf {
    configured.map_or_else(|| repo.join("catalog-wizard.toml"), PathBuf::from)
}

fn validate_release_config(config: &WizardConfig) -> Result<(), WizardError> {
    if config.repository != REPOSITORY || config.target != TARGET || config.state_root != STATE_ROOT
    {
        Err(WizardError::Config)
    } else {
        Ok(())
    }
}

fn private_config_root() -> Result<PathBuf, WizardError> {
    let home = PathBuf::from(std::env::var_os("HOME").ok_or(WizardError::Config)?);
    if !home.is_absolute() {
        return Err(WizardError::Config);
    }
    Ok(home.join(".config/fluxsemble-runtime-catalog"))
}

fn publisher_broker_config() -> Result<PathBuf, WizardError> {
    Ok(private_config_root()?.join("publisher-broker-client-v1.json"))
}

fn required_roles(mode: RunMode) -> &'static [MachineRole] {
    match mode {
        RunMode::DryRun => &[MachineRole::Preparer],
        RunMode::PublishCapable => &[
            MachineRole::Preparer,
            MachineRole::Signer,
            MachineRole::Publisher,
        ],
    }
}

fn require_trusted_machine(repo: &Path, roles: &[MachineRole]) -> Result<(), WizardError> {
    let facts = trust::current_machine_facts(repo)?;
    trust::load_matching_profile(
        &private_config_root()?.join("trusted-machines"),
        &facts,
        roles,
    )?;
    Ok(())
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct GithubSequenceObservation {
    published: Option<u64>,
    tags: BTreeSet<u64>,
    next_draft_exists: bool,
}

fn reconcile_github_state(
    local: Option<u64>,
    observation: &GithubSequenceObservation,
) -> Result<u64, WizardError> {
    let next =
        compare_sequences(local, observation.published).map_err(|_| WizardError::Discovery)?;
    if observation
        .published
        .is_some_and(|published| !observation.tags.contains(&published))
        || observation
            .tags
            .iter()
            .any(|sequence| Some(*sequence) > local)
        || observation.next_draft_exists
    {
        return Err(WizardError::Discovery);
    }
    Ok(next)
}

fn github_sequence_observation(
    local: Option<u64>,
    broker_config: &Path,
) -> Result<GithubSequenceObservation, WizardError> {
    let tags_page = fetch_fixed_github_json(GITHUB_TAGS_URL)?;
    let releases_page = fetch_fixed_github_json(GITHUB_RELEASES_URL)?;
    let tags = parse_catalog_tag_sequences(&tags_page.value, tags_page.pagination_link_present)?;
    let published =
        parse_published_sequence(&releases_page.value, releases_page.pagination_link_present)?;
    let next = compare_sequences(local, published).map_err(|_| WizardError::Discovery)?;
    let next_draft_exists = catalog_publish::catalog_draft_exists(broker_config, next)
        .map_err(|_| WizardError::Discovery)?;
    Ok(GithubSequenceObservation {
        published,
        tags,
        next_draft_exists,
    })
}

struct GithubJsonPage {
    value: serde_json::Value,
    pagination_link_present: bool,
}

fn fetch_fixed_github_json(url: &'static str) -> Result<GithubJsonPage, WizardError> {
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
        .get(url)
        .header(USER_AGENT, "catalog-wizard/0.1.0")
        .send()
        .map_err(|_| WizardError::Discovery)?;
    if response.status() != StatusCode::OK {
        return Err(WizardError::Discovery);
    }
    let pagination_link_present = response.headers().contains_key(LINK);
    let mut bytes = Vec::new();
    response
        .take(MAX_GITHUB_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| WizardError::Discovery)?;
    if bytes.len() as u64 > MAX_GITHUB_RESPONSE_BYTES {
        return Err(WizardError::Discovery);
    }
    let value = serde_json::from_slice(&bytes).map_err(|_| WizardError::Discovery)?;
    Ok(GithubJsonPage {
        value,
        pagination_link_present,
    })
}

fn parse_catalog_tag_sequences(
    value: &serde_json::Value,
    pagination_link_present: bool,
) -> Result<BTreeSet<u64>, WizardError> {
    let values = value.as_array().ok_or(WizardError::Discovery)?;
    if pagination_link_present || values.len() >= 100 {
        return Err(WizardError::Discovery);
    }
    values
        .iter()
        .map(|value| {
            value
                .get("ref")
                .and_then(serde_json::Value::as_str)
                .and_then(|reference| reference.strip_prefix("refs/tags/catalog-v1-sequence-"))
                .and_then(|sequence| sequence.parse::<u64>().ok())
                .filter(|sequence| *sequence > 0)
                .ok_or(WizardError::Discovery)
        })
        .collect()
}

fn parse_published_sequence(
    value: &serde_json::Value,
    pagination_link_present: bool,
) -> Result<Option<u64>, WizardError> {
    let values = value.as_array().ok_or(WizardError::Discovery)?;
    if pagination_link_present || values.len() >= 100 {
        return Err(WizardError::Discovery);
    }
    let mut published = None;
    for value in values {
        if value
            .get("draft")
            .and_then(serde_json::Value::as_bool)
            .ok_or(WizardError::Discovery)?
        {
            continue;
        }
        let Some(tag) = value.get("tag_name").and_then(serde_json::Value::as_str) else {
            return Err(WizardError::Discovery);
        };
        let Some(sequence) = tag
            .strip_prefix("catalog-v1-sequence-")
            .map(|value| value.parse::<u64>())
            .transpose()
            .map_err(|_| WizardError::Discovery)?
            .filter(|sequence| *sequence > 0)
        else {
            continue;
        };
        published = Some(published.map_or(sequence, |current: u64| current.max(sequence)));
    }
    Ok(published)
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
        answers: std::collections::VecDeque<String>,
        required_phrases: Vec<String>,
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
                answers: std::collections::VecDeque::new(),
                required_phrases: Vec::new(),
            }
        }

        fn publish_fixture_with_answers<I, S>(answers: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            Self {
                phase: ReleasePhase::Qualified,
                mode: RunMode::PublishCapable,
                qualification_available: true,
                executed: Vec::new(),
                saved_phases: Vec::new(),
                messages: Vec::new(),
                parity_verified: true,
                answers: answers.into_iter().map(Into::into).collect(),
                required_phrases: Vec::new(),
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
        fn prepare_signing(&mut self) -> Result<(), WizardError> {
            self.executed.push("verify-signing-readiness".to_owned());
            Ok(())
        }
        fn require_exact_phrase(&mut self, phrase: &str) -> Result<(), WizardError> {
            self.required_phrases.push(phrase.to_owned());
            if self.answers.pop_front().as_deref() == Some(phrase) {
                Ok(())
            } else {
                Err(WizardError::UserDeclined)
            }
        }
        fn sign(&mut self) -> Result<(), WizardError> {
            self.executed
                .push("catalog-sign-launcher sign --input final-transfer".to_owned());
            Ok(())
        }
        fn verify_signed_bundle(&mut self) -> Result<(), WizardError> {
            self.executed.push("verify-signed-bundle-key".to_owned());
            Ok(())
        }
        fn stage_local(&mut self) -> Result<(), WizardError> {
            self.executed.push("catalog-publish stage-local".to_owned());
            Ok(())
        }
        fn stage_remote(&mut self) -> Result<(), WizardError> {
            self.executed
                .push("catalog-publish stage-remote".to_owned());
            Ok(())
        }
        fn approve_draft(&mut self) -> Result<(), WizardError> {
            self.executed.push("catalog-publish approve".to_owned());
            Ok(())
        }
        fn publish(&mut self) -> Result<(), WizardError> {
            self.executed.push("catalog-publish publish".to_owned());
            Ok(())
        }
        fn update_docs_and_evidence(&mut self) -> Result<(), WizardError> {
            match self.answers.pop_front().as_deref() {
                Some("" | "y" | "Y" | "yes" | "YES" | "n" | "N" | "no" | "NO") => Ok(()),
                _ => Err(WizardError::UserDeclined),
            }
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
    fn github_tag_observation_requests_maximum_page_and_rejects_pagination() {
        assert!(GITHUB_TAGS_URL.ends_with("?per_page=100"));
        let partial = json!([{"ref": "refs/tags/catalog-v1-sequence-4"}]);
        assert!(parse_catalog_tag_sequences(&partial, true).is_err());
        assert_eq!(
            parse_catalog_tag_sequences(&partial, false).unwrap(),
            BTreeSet::from([4])
        );
        let maximum_page = serde_json::Value::Array(
            (1..=100)
                .map(|sequence| json!({"ref": format!("refs/tags/catalog-v1-sequence-{sequence}")}))
                .collect(),
        );
        assert!(parse_catalog_tag_sequences(&maximum_page, false).is_err());
    }

    #[test]
    fn tag_only_and_draft_only_remote_state_stop_sequence_allocation() {
        let local = Some(4);
        assert!(
            reconcile_github_state(
                local,
                &GithubSequenceObservation {
                    published: Some(4),
                    tags: std::collections::BTreeSet::from([4, 5]),
                    next_draft_exists: false,
                }
            )
            .is_err()
        );
        assert!(
            reconcile_github_state(
                local,
                &GithubSequenceObservation {
                    published: Some(4),
                    tags: std::collections::BTreeSet::from([4]),
                    next_draft_exists: true,
                }
            )
            .is_err()
        );
        assert_eq!(
            reconcile_github_state(
                local,
                &GithubSequenceObservation {
                    published: Some(4),
                    tags: std::collections::BTreeSet::from([4]),
                    next_draft_exists: false,
                }
            )
            .unwrap(),
            5
        );
    }

    #[test]
    fn unfinished_release_choice_supports_resume_start_new_and_exit_exactly() {
        assert_eq!(
            UnfinishedChoice::parse("resume"),
            Ok(UnfinishedChoice::Resume)
        );
        assert_eq!(
            UnfinishedChoice::parse("start new"),
            Ok(UnfinishedChoice::StartNew)
        );
        assert_eq!(UnfinishedChoice::parse("exit"), Ok(UnfinishedChoice::Exit));
        assert!(UnfinishedChoice::parse("delete it").is_err());
    }

    #[test]
    fn start_new_archives_only_the_selected_safe_unfinished_state() {
        let repo = std::env::temp_dir().join(format!(
            "catalog-wizard-unfinished-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let work_dir = repo.join(".release-work/sequence-2");
        let state = WizardState {
            schema_version: 1,
            sequence: 2,
            pi_version: "0.84.0".to_owned(),
            node_version: "22.20.0".to_owned(),
            target: TARGET.to_owned(),
            mode: RunMode::DryRun,
            phase: ReleasePhase::AwaitingQualification,
            signing_key_generation: 1,
            catalog_source_commit: "11".repeat(20),
            catalog_source_tree_sha256: "22".repeat(32),
            work_dir: work_dir.clone(),
        };
        state.save(&work_dir.join("wizard-state.json")).unwrap();

        archive_unfinished_state(&repo, &state).unwrap();
        assert!(!work_dir.exists());
        assert!(resumable_states(&repo).unwrap().is_empty());
        assert!(
            fs::read_dir(repo.join(STATE_ROOT))
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("abandoned-sequence-2-"))
        );
        fs::remove_dir_all(repo).unwrap();
    }

    #[test]
    fn resume_rejects_changed_commit_or_tree_identity() {
        let state = WizardState {
            schema_version: 1,
            sequence: 2,
            pi_version: "0.84.0".to_owned(),
            node_version: "22.20.0".to_owned(),
            target: TARGET.to_owned(),
            mode: RunMode::DryRun,
            phase: ReleasePhase::AwaitingQualification,
            signing_key_generation: 1,
            catalog_source_commit: "11".repeat(20),
            catalog_source_tree_sha256: "22".repeat(32),
            work_dir: PathBuf::from("/repo/.release-work/sequence-2"),
        };
        assert!(
            verify_resumed_source_identity(
                &state,
                &("33".repeat(20), state.catalog_source_tree_sha256.clone())
            )
            .is_err()
        );
        assert!(
            verify_resumed_source_identity(
                &state,
                &(state.catalog_source_commit.clone(), "44".repeat(32))
            )
            .is_err()
        );
        verify_resumed_source_identity(
            &state,
            &(
                state.catalog_source_commit.clone(),
                state.catalog_source_tree_sha256.clone(),
            ),
        )
        .unwrap();
    }

    #[test]
    fn resume_config_option_is_not_discarded() {
        let repo = Path::new("/repo");
        assert_eq!(
            resume_config_path(repo, Some("/private/custom.toml")),
            PathBuf::from("/private/custom.toml")
        );
        assert_eq!(
            resume_config_path(repo, None),
            PathBuf::from("/repo/catalog-wizard.toml")
        );
    }

    #[test]
    fn publish_capable_run_requires_all_exact_phrases_in_order() {
        let mut harness = ReleaseHarness::publish_fixture_with_answers([
            "SIGN",
            "CREATE TAG",
            "CREATE DRAFT",
            "UPLOAD ASSETS",
            "PUBLISH",
            "n",
        ]);
        run_release_with_harness(&mut harness).unwrap();
        assert_eq!(
            harness.required_phrases,
            vec![
                "SIGN",
                "CREATE TAG",
                "CREATE DRAFT",
                "UPLOAD ASSETS",
                "PUBLISH",
            ]
        );
        assert_eq!(harness.phase, ReleasePhase::Published);
        assert_eq!(
            harness.executed,
            vec![
                "verify-signing-readiness",
                "catalog-sign-launcher sign --input final-transfer",
                "verify-signed-bundle-key",
                "verify-signed-bundle-key",
                "catalog-publish stage-local",
                "catalog-publish stage-remote",
                "catalog-publish approve",
                "catalog-publish publish",
            ]
        );
    }

    #[test]
    fn declined_remote_approval_stops_before_any_remote_mutation() {
        let mut harness =
            ReleaseHarness::publish_fixture_with_answers(["SIGN", "wrong tag approval"]);
        assert_eq!(
            run_release_with_harness(&mut harness),
            Err(WizardError::UserDeclined)
        );
        assert!(
            !harness
                .executed
                .iter()
                .any(|command| command == "catalog-publish stage-remote")
        );
        assert!(
            !harness
                .executed
                .iter()
                .any(|command| command == "catalog-publish publish")
        );
    }

    #[test]
    fn generated_receipts_and_committed_evidence_are_deterministic() {
        let repo = std::env::temp_dir().join(format!(
            "catalog-wizard-evidence-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let work_dir = repo.join(".release-work/sequence-2");
        let latest = work_dir.join("publish-state/latest");
        fs::create_dir_all(&latest).unwrap();
        fs::write(
            latest.join("publication-receipt-v1.json"),
            b"{\"publication\":true}",
        )
        .unwrap();
        fs::write(latest.join("latest-receipt-v1.json"), b"{\"latest\":true}").unwrap();
        let state = WizardState {
            schema_version: 1,
            sequence: 2,
            pi_version: "0.84.0".to_owned(),
            node_version: "22.20.0".to_owned(),
            target: TARGET.to_owned(),
            mode: RunMode::PublishCapable,
            phase: ReleasePhase::Published,
            signing_key_generation: 1,
            catalog_source_commit: "11".repeat(20),
            catalog_source_tree_sha256: "22".repeat(32),
            work_dir,
        };

        let receipts = generate_public_receipts(&repo, &state).unwrap();
        commit_public_evidence(&repo, &state, &receipts).unwrap();
        generate_public_receipts(&repo, &state).unwrap();
        commit_public_evidence(&repo, &state, &receipts).unwrap();

        assert_eq!(
            fs::read(repo.join("qualifications/publication-receipt-sequence-2.json")).unwrap(),
            b"{\"publication\":true}"
        );
        assert_eq!(
            fs::read(repo.join("qualifications/latest-receipt-sequence-2.json")).unwrap(),
            b"{\"latest\":true}"
        );
        assert_eq!(
            fs::read_to_string(repo.join("docs/release-sequence-2.md")).unwrap(),
            "# Runtime catalog release sequence 2\n\nPublic release evidence:\n\n- `qualifications/publication-receipt-sequence-2.json`\n- `qualifications/latest-receipt-sequence-2.json`\n"
        );
        fs::remove_dir_all(repo).unwrap();
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
