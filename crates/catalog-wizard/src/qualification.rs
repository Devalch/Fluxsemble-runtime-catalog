use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{self, DirBuilder, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use catalog_core::{
    CompatibilityQualificationV1, FluxsembleBuildBindingV1, InitialPiReleaseIntentV1,
    compatibility_input_digest_with_keyring, production_keyring,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    WizardError,
    prompt::Prompter,
    state::{ReleasePhase, WizardState},
};

const MAX_HANDOFF_FILE_BYTES: u64 = 8 * 1024 * 1024;
const REQUEST_MANIFEST_NAME: &str = "manifest-v1.json";
const BUILD_BINDING_NAME: &str = "build-binding-v1.json";
const QUALIFICATION_NAME: &str = "qualification-v1.json";
const IMPORT_RECEIPT_NAME: &str = "receipt-v1.json";
const README: &str = "Fluxsemble qualification request\n\nUpdate Fluxsemble's exact compatibility profile for the Pi, Node, and target tuple in manifest-v1.json.\nCapture the clean Fluxsemble build binding, run the fixed candidate qualification, and bind qualification-v1.json candidate_sha256 to the exact candidate_sha256 in manifest-v1.json.\nReturn a directory containing exactly build-binding-v1.json and qualification-v1.json.\n\nThis directory contains public, inert qualification inputs only. It grants no signing, publishing, credential, or remote-mutation authority.\n";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyQualificationRequest {
    schema_version: u16,
    sequence: u64,
    pi_version: String,
    node_version: String,
    target: String,
    candidate_sha256: String,
    compatibility_input_sha256: String,
    catalog_source_commit: String,
    catalog_source_tree_sha256: String,
    trusted_signing_keyring_sha256: String,
}

impl LegacyQualificationRequest {
    #[must_use]
    pub fn candidate_sha256(&self) -> &str {
        &self.candidate_sha256
    }

    #[must_use]
    pub fn trusted_signing_keyring_sha256(&self) -> &str {
        &self.trusted_signing_keyring_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedQualification {
    build: FluxsembleBuildBindingV1,
    qualification: QualificationEvidence,
}

impl ImportedQualification {
    #[must_use]
    pub fn pi_version(&self) -> &str {
        match &self.qualification {
            QualificationEvidence::Legacy(q) => q.pi_version().as_str(),
            QualificationEvidence::Installer { profile, .. } => {
                profile.pi_package().version().as_str()
            }
        }
    }

    #[must_use]
    pub fn node_version(&self) -> &str {
        match &self.qualification {
            QualificationEvidence::Legacy(q) => q.node_version().as_str(),
            QualificationEvidence::Installer { profile, .. } => profile.node_version().as_str(),
        }
    }

    #[must_use]
    pub fn build(&self) -> &FluxsembleBuildBindingV1 {
        &self.build
    }

    #[must_use]
    pub fn qualification(&self) -> &QualificationEvidence {
        &self.qualification
    }
}

#[derive(Serialize)]
struct ImportReceipt<'a> {
    schema_version: u16,
    sequence: u64,
    provider: &'a str,
    target: &'a str,
    pi_version: &'a str,
    node_version: &'a str,
    candidate_sha256: &'a str,
    compatibility_input_sha256: &'a str,
    trusted_signing_keyring_sha256: &'a str,
    implementation_commit: &'a str,
    build_binding_sha256: String,
    qualification_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateTransferManifest {
    schema_version: u16,
    kind: String,
    source_commit: Option<String>,
    source_tree_sha256: Option<String>,
    records: Vec<CandidateRecordRef>,
    entries: Vec<serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateRecordRef {
    role: String,
    relative_path: String,
    sha256: String,
}

pub fn export_request(
    state: &WizardState,
    candidate_dir: &Path,
    output: &Path,
) -> Result<QualificationRequest, WizardError> {
    if state.schema_version == 2 {
        return export_installer_request(state, candidate_dir, output);
    }
    validate_state_identity(state)?;
    let candidate = catalog_acquire::verify_transferred_bundle(candidate_dir)
        .map_err(|_| WizardError::Qualification)?;
    candidate_intent_for_state(state, candidate_dir)?;
    let keyring_sha256 = production_keyring().sha256();
    let request = LegacyQualificationRequest {
        schema_version: 1,
        sequence: state.sequence,
        pi_version: state.pi_version.clone(),
        node_version: state.node_version.clone(),
        target: state.target.clone(),
        candidate_sha256: candidate.bundle_sha256().to_owned(),
        compatibility_input_sha256: candidate
            .verified_input()
            .compatibility_input_sha256()
            .as_str()
            .to_owned(),
        catalog_source_commit: state.catalog_source_commit.clone(),
        catalog_source_tree_sha256: state.catalog_source_tree_sha256.clone(),
        trusted_signing_keyring_sha256: keyring_sha256.to_owned(),
    };
    let manifest = serde_jcs::to_vec(&request).map_err(|_| WizardError::Qualification)?;
    let stage = create_stage(output, "qualification-request")?;
    let result = (|| {
        let export_root = stage.join("candidate-export");
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&export_root).map_err(|_| WizardError::Io)?;
        catalog_acquire::export_transfer_bundle(candidate_dir, &export_root.join("candidate"))
            .map_err(|_| WizardError::Qualification)?;
        fs::rename(export_root.join("candidate"), stage.join("candidate"))
            .map_err(|_| WizardError::Io)?;
        let evidence = stage.parent().ok_or(WizardError::Io)?.join(format!(
            ".qualification-acquire-evidence.{}.{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| WizardError::Io)?
                .as_nanos()
        ));
        rename_no_replace(&export_root, &evidence)?;
        write_immutable(&stage.join(REQUEST_MANIFEST_NAME), &manifest)?;
        write_immutable(&stage.join("README.txt"), README.as_bytes())?;
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o500))
            .map_err(|_| WizardError::Io)?;
        rename_no_replace(&stage, output)
    })();
    if result.is_err() {
        let _ = make_tree_writable(&stage);
        let _ = fs::remove_dir_all(&stage);
    }
    result?;
    Ok(QualificationRequest::Legacy(request))
}

pub fn verify_existing_request(
    state: &WizardState,
    candidate_dir: &Path,
    output: &Path,
) -> Result<(), WizardError> {
    if state.schema_version == 2 {
        return verify_installer_request(state, candidate_dir, output);
    }
    validate_state_identity(state)?;
    let metadata = fs::symlink_metadata(output).map_err(|_| WizardError::Qualification)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_euid()
        || metadata.permissions().mode() & 0o7777 != 0o500
        || exact_directory_names(output, 3)?
            != BTreeSet::from([
                REQUEST_MANIFEST_NAME.to_owned(),
                "README.txt".to_owned(),
                "candidate".to_owned(),
            ])
        || read_immutable_regular(&output.join("README.txt"))? != README.as_bytes()
    {
        return Err(WizardError::Qualification);
    }
    let request_bytes = read_immutable_regular(&output.join(REQUEST_MANIFEST_NAME))?;
    let request: LegacyQualificationRequest = parse_canonical(&request_bytes)?;
    let keyring_sha256 = production_keyring().sha256();
    validate_request(state, &request, keyring_sha256)?;
    let source_candidate = catalog_acquire::verify_transferred_bundle(candidate_dir)
        .map_err(|_| WizardError::Qualification)?;
    let exported_candidate = catalog_acquire::verify_transferred_bundle(&output.join("candidate"))
        .map_err(|_| WizardError::Qualification)?;
    candidate_intent_for_state(state, candidate_dir)?;
    candidate_intent_for_state(state, &output.join("candidate"))?;
    if source_candidate.bundle_sha256() != request.candidate_sha256
        || exported_candidate.bundle_sha256() != request.candidate_sha256
        || source_candidate
            .verified_input()
            .compatibility_input_sha256()
            != exported_candidate
                .verified_input()
                .compatibility_input_sha256()
    {
        return Err(WizardError::Qualification);
    }
    Ok(())
}

pub fn import_handoff(
    state: &WizardState,
    handoff_dir: &Path,
    keyring_sha256: &str,
) -> Result<ImportedQualification, WizardError> {
    if state.schema_version == 2 {
        return import_installer_handoff(state, handoff_dir, keyring_sha256);
    }
    if state.phase != ReleasePhase::AwaitingQualification {
        return Err(WizardError::Qualification);
    }
    validate_state_identity(state)?;
    validate_sha256(keyring_sha256)?;
    let request_path = state
        .work_dir
        .join("qualification-request")
        .join(REQUEST_MANIFEST_NAME);
    let request_bytes = read_bounded_regular(&request_path, true)?;
    let request: LegacyQualificationRequest = parse_canonical(&request_bytes)?;
    validate_request(state, &request, keyring_sha256)?;
    let candidate = catalog_acquire::verify_transferred_bundle(
        &state.work_dir.join("qualification-request/candidate"),
    )
    .map_err(|_| WizardError::Qualification)?;
    if candidate.bundle_sha256() != request.candidate_sha256
        || candidate
            .verified_input()
            .compatibility_input_sha256()
            .as_str()
            != request.compatibility_input_sha256
    {
        return Err(WizardError::Qualification);
    }

    let names = exact_directory_names(handoff_dir, 2)?;
    let expected = BTreeSet::from([BUILD_BINDING_NAME.to_owned(), QUALIFICATION_NAME.to_owned()]);
    if names != expected {
        return Err(WizardError::Qualification);
    }
    let build_bytes = read_bounded_regular(&handoff_dir.join(BUILD_BINDING_NAME), true)?;
    let qualification_bytes = read_bounded_regular(&handoff_dir.join(QUALIFICATION_NAME), true)?;
    let build = FluxsembleBuildBindingV1::from_json(&build_bytes)
        .map_err(|_| WizardError::Qualification)?;
    let qualification = CompatibilityQualificationV1::from_json(&qualification_bytes)
        .map_err(|_| WizardError::Qualification)?;
    if serde_jcs::to_vec(&build).map_err(|_| WizardError::Qualification)? != build_bytes
        || serde_jcs::to_vec(&qualification).map_err(|_| WizardError::Qualification)?
            != qualification_bytes
        || qualification.fluxsemble() != &build
        || qualification
            .candidate_sha256()
            .map(|digest| digest.as_str())
            != Some(request.candidate_sha256.as_str())
        || qualification.provider().as_str() != "builtin:pi"
        || qualification.target().as_str() != state.target
        || qualification.pi_version().as_str() != state.pi_version
        || qualification.node_version().as_str() != state.node_version
    {
        return Err(WizardError::Qualification);
    }
    let intent = candidate_intent_for_state(
        state,
        &state.work_dir.join("qualification-request/candidate"),
    )?;
    let expected_compatibility =
        compatibility_input_digest_with_keyring(&intent, &build, keyring_sha256)
            .map_err(|_| WizardError::Qualification)?;
    if qualification.compatibility_input_sha256().as_str() != encode_sha256(&expected_compatibility)
    {
        return Err(WizardError::Qualification);
    }
    verify_consumer_keyring_readiness(&qualification, keyring_sha256)?;

    let receipt = ImportReceipt {
        schema_version: 1,
        sequence: state.sequence,
        provider: qualification.provider().as_str(),
        target: qualification.target().as_str(),
        pi_version: qualification.pi_version().as_str(),
        node_version: qualification.node_version().as_str(),
        candidate_sha256: &request.candidate_sha256,
        compatibility_input_sha256: qualification.compatibility_input_sha256().as_str(),
        trusted_signing_keyring_sha256: keyring_sha256,
        implementation_commit: build.implementation_commit().as_str(),
        build_binding_sha256: sha256(&build_bytes),
        qualification_sha256: sha256(&qualification_bytes),
    };
    let receipt_bytes = serde_jcs::to_vec(&receipt).map_err(|_| WizardError::Qualification)?;
    let output = state.work_dir.join("imported-qualification");
    ensure_imported_output(&output, &build_bytes, &qualification_bytes, &receipt_bytes)?;

    let mut advanced = state.clone();
    advanced.phase = ReleasePhase::QualificationImported;
    advanced.save(&state.work_dir.join("wizard-state.json"))?;
    Ok(ImportedQualification {
        build,
        qualification: QualificationEvidence::Legacy(qualification),
    })
}

pub fn verify_consumer_keyring_readiness(
    qualification: &CompatibilityQualificationV1,
    expected_keyring_sha256: &str,
) -> Result<(), WizardError> {
    validate_sha256(expected_keyring_sha256)?;
    if qualification.trusted_signing_keyring_sha256().as_str() != expected_keyring_sha256
        || !qualification.checks().all_passed()
    {
        return Err(WizardError::Qualification);
    }
    Ok(())
}

pub fn resume_qualification(
    state: &WizardState,
    qualification_path: Option<&Path>,
    keyring_sha256: &str,
    prompter: &mut dyn Prompter,
) -> Result<ImportedQualification, WizardError> {
    let entered;
    let handoff = match qualification_path {
        Some(path) => path,
        None => {
            entered = prompter.ask("Qualification is ready. Enter the returned directory:")?;
            Path::new(&entered)
        }
    };
    match import_handoff(state, handoff, keyring_sha256) {
        Ok(imported) => Ok(imported),
        Err(WizardError::Qualification) => {
            prompter.say("The returned qualification does not match this release.")?;
            Err(WizardError::Qualification)
        }
        Err(error) => Err(error),
    }
}

fn candidate_intent_for_state(
    state: &WizardState,
    candidate_dir: &Path,
) -> Result<InitialPiReleaseIntentV1, WizardError> {
    let intent = read_candidate_intent(candidate_dir)?;
    if intent.sequence().get() != state.sequence
        || intent.release().provider() != "builtin:pi"
        || intent.release().target().as_str() != state.target
        || intent.release().pi_version().as_str() != state.pi_version
        || intent.release().node_version().as_str() != state.node_version
    {
        return Err(WizardError::Qualification);
    }
    Ok(intent)
}

fn read_candidate_intent(candidate_dir: &Path) -> Result<InitialPiReleaseIntentV1, WizardError> {
    let manifest_bytes =
        read_bounded_regular(&candidate_dir.join("transfer-manifest-v1.json"), true)?;
    let manifest: CandidateTransferManifest = parse_canonical(&manifest_bytes)?;
    if manifest.schema_version != 1 || manifest.kind != "verified_input" {
        return Err(WizardError::Qualification);
    }
    let matching = manifest
        .records
        .iter()
        .filter(|record| record.role == "release_intent")
        .collect::<Vec<_>>();
    let [record] = matching.as_slice() else {
        return Err(WizardError::Qualification);
    };
    if !record.relative_path.starts_with("records/")
        || record.relative_path.contains("..")
        || record.relative_path.contains('\\')
    {
        return Err(WizardError::Qualification);
    }
    validate_sha256(&record.sha256)?;
    let bytes = read_bounded_regular(&candidate_dir.join(&record.relative_path), true)?;
    if sha256(&bytes) != record.sha256 {
        return Err(WizardError::Qualification);
    }
    InitialPiReleaseIntentV1::from_json(&bytes).map_err(|_| WizardError::Qualification)
}

fn validate_request(
    state: &WizardState,
    request: &LegacyQualificationRequest,
    keyring_sha256: &str,
) -> Result<(), WizardError> {
    if request.schema_version != 1
        || request.sequence != state.sequence
        || request.pi_version != state.pi_version
        || request.node_version != state.node_version
        || request.target != state.target
        || request.catalog_source_commit != state.catalog_source_commit
        || request.catalog_source_tree_sha256 != state.catalog_source_tree_sha256
        || request.trusted_signing_keyring_sha256 != keyring_sha256
    {
        return Err(WizardError::Qualification);
    }
    validate_sha256(&request.candidate_sha256)?;
    validate_sha256(&request.compatibility_input_sha256)?;
    Ok(())
}

fn validate_state_identity(state: &WizardState) -> Result<(), WizardError> {
    if !matches!(state.schema_version, 1 | 2)
        || state.sequence == 0
        || state.pi_version.is_empty()
        || state.node_version.is_empty()
        || state.target != "linux_x86_64"
        || state.catalog_source_commit.len() != 40
        || !lower_hex(&state.catalog_source_commit)
    {
        return Err(WizardError::Qualification);
    }
    validate_sha256(&state.catalog_source_tree_sha256)
}

fn validate_sha256(value: &str) -> Result<(), WizardError> {
    if value.len() == 64 && lower_hex(value) {
        Ok(())
    } else {
        Err(WizardError::Qualification)
    }
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions or side effects.
    unsafe { libc::geteuid() }
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn parse_canonical<T>(bytes: &[u8]) -> Result<T, WizardError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let parsed = serde_json::from_slice(bytes).map_err(|_| WizardError::Qualification)?;
    if serde_jcs::to_vec(&parsed).map_err(|_| WizardError::Qualification)? == bytes {
        Ok(parsed)
    } else {
        Err(WizardError::Qualification)
    }
}

fn ensure_imported_output(
    output: &Path,
    build_bytes: &[u8],
    qualification_bytes: &[u8],
    receipt_bytes: &[u8],
) -> Result<(), WizardError> {
    match fs::symlink_metadata(output) {
        Ok(_) => {
            return validate_imported_output(
                output,
                build_bytes,
                qualification_bytes,
                receipt_bytes,
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(WizardError::Io),
    }

    let stage = create_stage(output, "imported-qualification")?;
    let publication = (|| {
        write_immutable(&stage.join(BUILD_BINDING_NAME), build_bytes)?;
        write_immutable(&stage.join(QUALIFICATION_NAME), qualification_bytes)?;
        write_immutable(&stage.join(IMPORT_RECEIPT_NAME), receipt_bytes)?;
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o500))
            .map_err(|_| WizardError::Io)?;
        rename_no_replace(&stage, output)
    })();
    if publication.is_err() {
        let _ = make_tree_writable(&stage);
        let _ = fs::remove_dir_all(&stage);
    }
    match publication {
        Ok(()) => validate_imported_output(output, build_bytes, qualification_bytes, receipt_bytes),
        Err(error) => match fs::symlink_metadata(output) {
            Ok(_) => {
                validate_imported_output(output, build_bytes, qualification_bytes, receipt_bytes)
            }
            Err(not_found) if not_found.kind() == std::io::ErrorKind::NotFound => Err(error),
            Err(_) => Err(WizardError::Io),
        },
    }
}

fn validate_imported_output(
    output: &Path,
    build_bytes: &[u8],
    qualification_bytes: &[u8],
    receipt_bytes: &[u8],
) -> Result<(), WizardError> {
    let metadata = fs::symlink_metadata(output).map_err(|_| WizardError::Qualification)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_euid()
        || metadata.permissions().mode() & 0o7777 != 0o500
    {
        return Err(WizardError::Qualification);
    }
    let expected_names = BTreeSet::from([
        BUILD_BINDING_NAME.to_owned(),
        IMPORT_RECEIPT_NAME.to_owned(),
        QUALIFICATION_NAME.to_owned(),
    ]);
    if exact_directory_names(output, 3)? != expected_names
        || read_immutable_regular(&output.join(BUILD_BINDING_NAME))? != build_bytes
        || read_immutable_regular(&output.join(QUALIFICATION_NAME))? != qualification_bytes
        || read_immutable_regular(&output.join(IMPORT_RECEIPT_NAME))? != receipt_bytes
    {
        return Err(WizardError::Qualification);
    }
    Ok(())
}

fn exact_directory_names(
    path: &Path,
    maximum_names: usize,
) -> Result<BTreeSet<String>, WizardError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| WizardError::Qualification)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(WizardError::Qualification);
    }
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(path).map_err(|_| WizardError::Qualification)? {
        let entry = entry.map_err(|_| WizardError::Qualification)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| WizardError::Qualification)?;
        if !names.insert(name) || names.len() > maximum_names {
            return Err(WizardError::Qualification);
        }
    }
    Ok(names)
}

fn read_immutable_regular(path: &Path) -> Result<Vec<u8>, WizardError> {
    read_bounded_regular_with_mode(path, true, Some(0o400))
}

fn read_bounded_regular(path: &Path, require_one_link: bool) -> Result<Vec<u8>, WizardError> {
    read_bounded_regular_with_mode(path, require_one_link, None)
}

fn read_bounded_regular_with_mode(
    path: &Path,
    require_one_link: bool,
    required_mode: Option<u32>,
) -> Result<Vec<u8>, WizardError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| WizardError::Qualification)?;
    let before = file.metadata().map_err(|_| WizardError::Qualification)?;
    if !before.is_file()
        || (require_one_link && before.nlink() != 1)
        || required_mode.is_some_and(|mode| before.permissions().mode() & 0o7777 != mode)
        || before.len() == 0
        || before.len() > MAX_HANDOFF_FILE_BYTES
    {
        return Err(WizardError::Qualification);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(MAX_HANDOFF_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| WizardError::Qualification)?;
    let after = file.metadata().map_err(|_| WizardError::Qualification)?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || (require_one_link && after.nlink() != 1)
        || required_mode.is_some_and(|mode| after.permissions().mode() & 0o7777 != mode)
    {
        return Err(WizardError::Qualification);
    }
    Ok(bytes)
}

fn create_stage(output: &Path, label: &str) -> Result<PathBuf, WizardError> {
    let parent = output.parent().ok_or(WizardError::Io)?;
    fs::create_dir_all(parent).map_err(|_| WizardError::Io)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| WizardError::Io)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || output.exists() {
        return Err(WizardError::Io);
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| WizardError::Io)?
        .as_nanos();
    for attempt in 0..16 {
        let stage = parent.join(format!(
            ".{label}.{}.{}.tmp",
            std::process::id(),
            nonce + attempt
        ));
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&stage) {
            Ok(()) => return Ok(stage),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(WizardError::Io),
        }
    }
    Err(WizardError::Io)
}

fn write_immutable(path: &Path, bytes: &[u8]) -> Result<(), WizardError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| WizardError::Io)?;
    file.write_all(bytes).map_err(|_| WizardError::Io)?;
    file.sync_all().map_err(|_| WizardError::Io)?;
    let metadata = file.metadata().map_err(|_| WizardError::Io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o400
    {
        return Err(WizardError::Io);
    }
    Ok(())
}

fn rename_no_replace(source: &Path, destination: &Path) -> Result<(), WizardError> {
    let source = CString::new(source.as_os_str().as_bytes()).map_err(|_| WizardError::Io)?;
    let destination =
        CString::new(destination.as_os_str().as_bytes()).map_err(|_| WizardError::Io)?;
    // SAFETY: both paths are valid NUL-terminated names and RENAME_NOREPLACE preserves no-clobber.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(WizardError::Io)
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn encode_sha256(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn make_tree_writable(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(path)? {
            make_tree_writable(&entry?.path())?;
        }
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use catalog_acquire::{
        BundleRecord, PublicBundleObject, VerifiedBundleWriteRequest, write_verified_bundle,
    };
    use catalog_core::{CompatibilityQualificationV1, InputSourceKind};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        cli::RunMode,
        state::{ReleasePhase, WizardState},
    };

    const KEYRING: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const COMPATIBILITY: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const TREE: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    #[derive(Default)]
    struct RecordingPrompter {
        answer: String,
        asked: Vec<String>,
        said: Vec<String>,
    }

    impl Prompter for RecordingPrompter {
        fn ask(&mut self, message: &str) -> Result<String, WizardError> {
            self.asked.push(message.to_owned());
            Ok(self.answer.clone())
        }

        fn say(&mut self, message: &str) -> Result<(), WizardError> {
            self.said.push(message.to_owned());
            Ok(())
        }
    }

    struct Fixture {
        root: PathBuf,
        state: WizardState,
        handoff: PathBuf,
    }

    impl Fixture {
        fn matching() -> Self {
            let root = temporary_directory();
            let request = root.join("qualification-request");
            let handoff = root.join("returned-handoff");
            fs::create_dir_all(&request).unwrap();
            fs::create_dir_all(&handoff).unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&request, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&handoff, fs::Permissions::from_mode(0o700)).unwrap();
            let (candidate_sha256, qualification_compatibility) =
                create_candidate(&request.join("candidate"), &root);
            write_canonical(
                request.join("manifest-v1.json"),
                &json!({
                    "schema_version": 1,
                    "sequence": 1,
                    "pi_version": "0.83.0",
                    "node_version": "22.19.0",
                    "target": "linux_x86_64",
                    "candidate_sha256": candidate_sha256,
                    "compatibility_input_sha256": COMPATIBILITY,
                    "catalog_source_commit": COMMIT,
                    "catalog_source_tree_sha256": TREE,
                    "trusted_signing_keyring_sha256": KEYRING
                }),
            );
            write_canonical(handoff.join("build-binding-v1.json"), &build_value());
            write_canonical(
                handoff.join("qualification-v1.json"),
                &qualification_value(
                    "22.19.0",
                    KEYRING,
                    &qualification_compatibility,
                    Some(&candidate_sha256),
                ),
            );
            let state = WizardState {
                schema_version: 1,
                sequence: 1,
                pi_version: "0.83.0".to_owned(),
                node_version: "22.19.0".to_owned(),
                target: "linux_x86_64".to_owned(),
                mode: RunMode::DryRun,
                phase: ReleasePhase::AwaitingQualification,
                signing_key_generation: 2,
                catalog_source_commit: COMMIT.to_owned(),
                catalog_source_tree_sha256: TREE.to_owned(),
                work_dir: root.clone(),
            };
            state.save(&root.join("wizard-state.json")).unwrap();
            Self {
                root,
                state,
                handoff,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = make_writable(&self.root);
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn qualification_request_is_no_clobber_and_copies_a_verified_candidate() {
        let fixture = Fixture::matching();
        let output = fixture.root.join("exported-request");
        let request = export_request(
            &fixture.state,
            &fixture.root.join("qualification-request/candidate"),
            &output,
        )
        .unwrap();
        assert!(output.join("manifest-v1.json").is_file());
        assert!(output.join("candidate/transfer-manifest-v1.json").is_file());
        assert!(
            fs::read_to_string(output.join("README.txt"))
                .unwrap()
                .contains(
                    "grants no signing, publishing, credential, or remote-mutation authority"
                )
        );
        assert_eq!(request.candidate_sha256().len(), 64);
        verify_existing_request(
            &fixture.state,
            &fixture.root.join("qualification-request/candidate"),
            &output,
        )
        .unwrap();
        assert!(
            export_request(
                &fixture.state,
                &fixture.root.join("qualification-request/candidate"),
                &output,
            )
            .is_err()
        );
    }

    #[test]
    fn completed_export_is_reusable_when_state_save_was_interrupted() {
        let mut fixture = Fixture::matching();
        fixture.state.phase = ReleasePhase::CandidateAssembled;
        let output = fixture.root.join("interrupted-export");
        export_request(
            &fixture.state,
            &fixture.root.join("qualification-request/candidate"),
            &output,
        )
        .unwrap();

        assert_eq!(fixture.state.phase, ReleasePhase::CandidateAssembled);
        verify_existing_request(
            &fixture.state,
            &fixture.root.join("qualification-request/candidate"),
            &output,
        )
        .unwrap();
    }

    #[test]
    fn export_rejects_state_tuple_that_does_not_match_candidate_without_output() {
        let fixture = Fixture::matching();
        let mut wrong_state = fixture.state.clone();
        wrong_state.pi_version = "0.84.0".to_owned();
        let output = fixture.root.join("mismatched-request");

        assert!(
            export_request(
                &wrong_state,
                &fixture.root.join("qualification-request/candidate"),
                &output,
            )
            .is_err()
        );
        assert!(!output.exists());
    }

    #[test]
    fn matching_handoff_is_imported_for_the_exact_release() {
        let fixture = Fixture::matching();
        let imported = import_handoff(&fixture.state, &fixture.handoff, KEYRING).unwrap();
        assert_eq!(imported.pi_version(), "0.83.0");
        assert_eq!(imported.node_version(), "22.19.0");
        assert!(
            fixture
                .root
                .join("imported-qualification/receipt-v1.json")
                .is_file()
        );
        assert_eq!(
            WizardState::load(&fixture.root.join("wizard-state.json"))
                .unwrap()
                .unwrap()
                .phase,
            ReleasePhase::QualificationImported
        );
    }

    #[test]
    fn wrong_tuple_or_keyring_digest_is_rejected_before_import() {
        let fixture = Fixture::matching();
        write_canonical(
            fixture.handoff.join("qualification-v1.json"),
            &qualification_value("22.21.0", KEYRING, &"55".repeat(32), Some(&"66".repeat(32))),
        );
        assert!(import_handoff(&fixture.state, &fixture.handoff, KEYRING).is_err());
        assert!(!fixture.root.join("imported-qualification").exists());
        assert_eq!(
            WizardState::load(&fixture.root.join("wizard-state.json"))
                .unwrap()
                .unwrap()
                .phase,
            ReleasePhase::AwaitingQualification
        );

        let fixture = Fixture::matching();
        assert!(import_handoff(&fixture.state, &fixture.handoff, &"55".repeat(32)).is_err());
        assert!(!fixture.root.join("imported-qualification").exists());
    }

    #[test]
    fn returned_candidate_binding_must_match_the_exported_request() {
        let fixture = Fixture::matching();
        let path = fixture.handoff.join("qualification-v1.json");
        let mut qualification: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        qualification["candidate_sha256"] = json!("55".repeat(32));
        write_canonical(path, &qualification);

        assert!(import_handoff(&fixture.state, &fixture.handoff, KEYRING).is_err());
        assert!(!fixture.root.join("imported-qualification").exists());
        assert_eq!(
            WizardState::load(&fixture.root.join("wizard-state.json"))
                .unwrap()
                .unwrap()
                .phase,
            ReleasePhase::AwaitingQualification
        );
    }

    #[test]
    fn handoff_layout_and_files_are_strict() {
        let fixture = Fixture::matching();
        fs::write(fixture.handoff.join("unexpected"), b"extra").unwrap();
        assert!(import_handoff(&fixture.state, &fixture.handoff, KEYRING).is_err());

        let fixture = Fixture::matching();
        let external = fixture.root.join("external.json");
        fs::write(&external, serde_jcs::to_vec(&build_value()).unwrap()).unwrap();
        fs::remove_file(fixture.handoff.join("build-binding-v1.json")).unwrap();
        std::os::unix::fs::symlink(&external, fixture.handoff.join("build-binding-v1.json"))
            .unwrap();
        assert!(import_handoff(&fixture.state, &fixture.handoff, KEYRING).is_err());

        let fixture = Fixture::matching();
        let external = fixture.root.join("hardlinked.json");
        fs::rename(fixture.handoff.join("build-binding-v1.json"), &external).unwrap();
        fs::hard_link(&external, fixture.handoff.join("build-binding-v1.json")).unwrap();
        assert!(import_handoff(&fixture.state, &fixture.handoff, KEYRING).is_err());
    }

    #[test]
    fn interactive_resume_uses_only_the_fixed_handoff_prompt_and_mismatch_message() {
        let fixture = Fixture::matching();
        let mut prompter = RecordingPrompter {
            answer: fixture.handoff.to_string_lossy().into_owned(),
            ..RecordingPrompter::default()
        };
        resume_qualification(&fixture.state, None, KEYRING, &mut prompter).unwrap();
        assert_eq!(
            prompter.asked,
            ["Qualification is ready. Enter the returned directory:"]
        );
        assert!(prompter.said.is_empty());

        let fixture = Fixture::matching();
        fs::write(fixture.handoff.join("unexpected"), b"extra").unwrap();
        let mut prompter = RecordingPrompter::default();
        assert!(
            resume_qualification(
                &fixture.state,
                Some(&fixture.handoff),
                KEYRING,
                &mut prompter,
            )
            .is_err()
        );
        assert!(prompter.asked.is_empty());
        assert_eq!(
            prompter.said,
            ["The returned qualification does not match this release."]
        );
    }

    #[test]
    fn state_save_failure_after_import_publication_is_retryable_and_not_a_mismatch() {
        let fixture = Fixture::matching();
        let state_path = fixture.root.join("wizard-state.json");
        fs::remove_file(&state_path).unwrap();
        fs::create_dir(&state_path).unwrap();
        let mut prompter = RecordingPrompter::default();

        assert!(matches!(
            resume_qualification(
                &fixture.state,
                Some(&fixture.handoff),
                KEYRING,
                &mut prompter,
            ),
            Err(WizardError::State)
        ));
        assert!(prompter.said.is_empty());
        assert!(fixture.root.join("imported-qualification").is_dir());

        fs::remove_dir(&state_path).unwrap();
        import_handoff(&fixture.state, &fixture.handoff, KEYRING).unwrap();
        assert_eq!(
            WizardState::load(&state_path).unwrap().unwrap().phase,
            ReleasePhase::QualificationImported
        );
    }

    #[test]
    fn consumer_keyring_readiness_requires_exact_digest_and_passed_checks() {
        let bytes = serde_jcs::to_vec(&qualification_value(
            "22.19.0",
            KEYRING,
            COMPATIBILITY,
            None,
        ))
        .unwrap();
        let qualification = CompatibilityQualificationV1::from_json(&bytes).unwrap();
        verify_consumer_keyring_readiness(&qualification, KEYRING).unwrap();
        assert!(verify_consumer_keyring_readiness(&qualification, &"55".repeat(32)).is_err());

        let mut failed = qualification_value("22.19.0", KEYRING, COMPATIBILITY, None);
        failed["checks"]["activation"] = json!("failed");
        let qualification =
            CompatibilityQualificationV1::from_json(&serde_jcs::to_vec(&failed).unwrap()).unwrap();
        assert!(verify_consumer_keyring_readiness(&qualification, KEYRING).is_err());
    }

    fn build_value() -> serde_json::Value {
        json!({
            "implementation_commit": COMMIT,
            "application_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "daemon_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "compatibility_profile_id": "runtime-catalog-compatibility-v1",
            "compatibility_profile_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        })
    }

    fn qualification_value(
        node_version: &str,
        keyring: &str,
        compatibility: &str,
        candidate: Option<&str>,
    ) -> serde_json::Value {
        let mut value = json!({
            "schema_version": 1,
            "compatibility_input_sha256": compatibility,
            "trusted_signing_keyring_sha256": keyring,
            "fluxsemble": build_value(),
            "provider": "builtin:pi",
            "target": "linux_x86_64",
            "pi_version": "0.83.0",
            "node_version": node_version,
            "checks": {
                "catalog_v1_conformance": "passed",
                "managed_installation": "passed",
                "node_probe": "passed",
                "pi_probe": "passed",
                "pi_rpc_readiness": "passed",
                "activation": "passed",
                "managed_resolution": "passed",
                "required_failure": "passed",
                "cancellation": "passed"
            },
            "reviewer": "release-reviewer",
            "release_owner_approved_at": "2026-08-01T12:00:00Z",
            "residual_risks": ["Fixture-only qualification."]
        });
        if let Some(candidate) = candidate {
            value["candidate_sha256"] = json!(candidate);
        }
        value
    }

    fn create_candidate(output: &std::path::Path, root: &std::path::Path) -> (String, String) {
        use std::os::unix::fs::PermissionsExt;
        let bytes = b"verified candidate object";
        let digest = format!("{:x}", Sha256::digest(bytes));
        let object_path = root.join("candidate-object");
        fs::write(&object_path, bytes).unwrap();
        fs::set_permissions(&object_path, fs::Permissions::from_mode(0o400)).unwrap();
        let object = PublicBundleObject::verified_file(
            fs::File::open(&object_path).unwrap(),
            "https://registry.npmjs.org/package/-/package.tgz".to_owned(),
            bytes.len() as u64,
            digest,
        )
        .unwrap();
        let intent_bytes = fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../catalogs/intents/catalog-v1-sequence-1-intent.json"),
        )
        .unwrap();
        let intent = InitialPiReleaseIntentV1::from_json(&intent_bytes).unwrap();
        let build =
            FluxsembleBuildBindingV1::from_json(&serde_jcs::to_vec(&build_value()).unwrap())
                .unwrap();
        let qualification_compatibility = encode_sha256(
            &compatibility_input_digest_with_keyring(&intent, &build, KEYRING).unwrap(),
        );
        write_verified_bundle(
            VerifiedBundleWriteRequest {
                source_kind: InputSourceKind::ReleaseIntent,
                source_sha256: "66".repeat(32),
                compatibility_input_sha256: COMPATIBILITY.to_owned(),
                source_commit: None,
                source_tree_sha256: None,
                records: vec![
                    BundleRecord {
                        role: "package_inputs".to_owned(),
                        bytes: b"fixture package inputs".to_vec(),
                    },
                    BundleRecord {
                        role: "release_intent".to_owned(),
                        bytes: intent_bytes,
                    },
                ],
                objects: vec![object],
            },
            output,
        )
        .unwrap();
        let candidate_sha256 = catalog_acquire::verify_transferred_bundle(output)
            .unwrap()
            .bundle_sha256()
            .to_owned();
        (candidate_sha256, qualification_compatibility)
    }

    fn write_canonical(path: PathBuf, value: &serde_json::Value) {
        fs::write(path, serde_jcs::to_vec(value).unwrap()).unwrap();
    }

    fn temporary_directory() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("catalog-wizard-qualification-{unique}"));
        fs::create_dir(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn make_writable(path: &std::path::Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if path.is_dir() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            for entry in fs::read_dir(path)? {
                make_writable(&entry?.path())?;
            }
        } else {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod installer_qualification_tests {
    use super::*;
    use catalog_acquire::{
        BundleRecord, PublicBundleObject, VerifiedBundleWriteRequest, write_verified_bundle,
    };
    use serde_json::{Value, json};
    #[test]
    fn qualification_imports_existing_build_after_subject_request_without_profile_recompilation() {
        for version in ["1.2.0", "1.3.0"] {
            let root = std::env::temp_dir().join(format!(
                "wizard-pi-v2-{version}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let mut p: Value = serde_json::from_slice(include_bytes!(
                "../../catalog-core/tests/fixtures/catalog/pi-installer-v1/valid-wrapper-root.json"
            ))
            .unwrap();
            for pointer in [
                "/pi_package/version",
                "/components/1/version",
                "/locked_packages/0/version",
            ] {
                *p.pointer_mut(pointer).unwrap() = json!(version);
            }
            for key in ["installer_manifest", "installer_lock", "pi_manifest"] {
                p[key]["url"] = json!(format!(
                    "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/catalog-v1-sequence-2/{key}-{}.json",
                    p[key]["sha256"].as_str().unwrap()
                ));
            }
            let intent=catalog_core::PiReleaseIntentV2::from_json(&serde_jcs::to_vec(&json!({"schema_version":2,"sequence":"2","tag":"catalog-v1-sequence-2","generated_at":"2026-10-15T00:00:00Z","expires_at":"2026-11-15T00:00:00Z","title":"Candidate","notes":"Fixture","profile":p})).unwrap()).unwrap();
            let subject =
                encode_sha256(&catalog_core::pi_release_subject_sha256(intent.profile()).unwrap());
            let bytes = b"fixture-object";
            let file = root.join("input");
            fs::write(&file, bytes).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
            write_verified_bundle(
                VerifiedBundleWriteRequest {
                    source_kind: catalog_core::InputSourceKind::ReleaseIntent,
                    source_sha256: encode_sha256(
                        &catalog_core::pi_release_intent_v2_digest(&intent).unwrap(),
                    ),
                    compatibility_input_sha256: subject.clone(),
                    source_commit: None,
                    source_tree_sha256: None,
                    records: vec![BundleRecord {
                        role: "release_intent".into(),
                        bytes: serde_jcs::to_vec(&intent).unwrap(),
                    }],
                    objects: vec![
                        PublicBundleObject::verified_file(
                            fs::File::open(&file).unwrap(),
                            "https://example.com/a".into(),
                            bytes.len() as u64,
                            sha256(bytes),
                        )
                        .unwrap(),
                    ],
                },
                &root.join("candidate"),
            )
            .unwrap();
            let state = WizardState {
                schema_version: 2,
                sequence: 2,
                pi_version: version.into(),
                node_version: "22.19.0".into(),
                target: "linux_x86_64".into(),
                mode: crate::cli::RunMode::DryRun,
                phase: ReleasePhase::AwaitingQualification,
                signing_key_generation: 2,
                catalog_source_commit: "1".repeat(40),
                catalog_source_tree_sha256: "2".repeat(64),
                work_dir: root.clone(),
            };
            export_request(
                &state,
                &root.join("candidate"),
                &root.join("qualification-request"),
            )
            .unwrap();
            verify_existing_request(
                &state,
                &root.join("candidate"),
                &root.join("qualification-request"),
            )
            .unwrap();
            let request: Value = serde_json::from_slice(
                &fs::read(root.join("qualification-request/manifest-v1.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(request["release_subject_sha256"], subject);
            assert!(request.get("candidate_sha256").is_none());
            let mut q: Value = serde_json::from_slice(include_bytes!(
                "../../catalog-core/tests/fixtures/catalog/pi-installer-v1/valid-qualification.json"
            ))
            .unwrap();
            q["release_subject_sha256"] = json!(subject);
            q["verification_build"]["compatibility_profile_sha256"] = json!(encode_sha256(
                &catalog_core::pi_required_contracts_profile_sha256(
                    intent.profile().required_contracts()
                )
                .unwrap()
            ));
            let mut build = q["verification_build"].clone();
            build.as_object_mut().unwrap().remove("consumer_version");
            let returned = root.join("returned");
            fs::create_dir(&returned).unwrap();
            fs::set_permissions(&returned, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(
                returned.join("build-binding-v1.json"),
                serde_jcs::to_vec(&build).unwrap(),
            )
            .unwrap();
            fs::write(
                returned.join("qualification-v1.json"),
                serde_jcs::to_vec(&q).unwrap(),
            )
            .unwrap();
            let imported =
                import_handoff(&state, &returned, production_keyring().sha256()).unwrap();
            assert_eq!(imported.pi_version(), version);
            build["application_sha256"] = json!("9".repeat(64));
            fs::write(
                returned.join("build-binding-v1.json"),
                serde_jcs::to_vec(&build).unwrap(),
            )
            .unwrap();
            assert!(import_handoff(&state, &returned, production_keyring().sha256()).is_err());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualificationEvidence {
    Legacy(CompatibilityQualificationV1),
    Installer {
        profile: catalog_core::PiReleaseProfileV1,
        qualification: catalog_core::PiReleaseQualificationV1,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum QualificationRequest {
    Legacy(LegacyQualificationRequest),
    Installer(InstallerQualificationRequest),
}
impl QualificationRequest {
    pub fn candidate_sha256(&self) -> &str {
        match self {
            Self::Legacy(r) => r.candidate_sha256(),
            Self::Installer(r) => &r.input_bundle_sha256,
        }
    }
    pub fn trusted_signing_keyring_sha256(&self) -> &str {
        match self {
            Self::Legacy(r) => r.trusted_signing_keyring_sha256(),
            Self::Installer(r) => &r.trusted_signing_keyring_sha256,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallerQualificationRequest {
    schema_version: u16,
    kind: String,
    sequence: u64,
    release_subject_sha256: String,
    input_bundle_sha256: String,
    intent: serde_json::Value,
    catalog_source_commit: String,
    catalog_source_tree_sha256: String,
    trusted_signing_keyring_sha256: String,
}
const INSTALLER_README: &str = "Fluxsemble Pi installer qualification request\n\nUse the existing supported consumer build and its unchanged behavioral contracts to test the exact release profile in manifest-v1.json. No release-specific profile recompilation is required. Bind qualification-v1.json to release_subject_sha256 and record every required passing check. Return canonical JCS files build-binding-v1.json and qualification-v1.json. The final catalog is assembled after qualification.\n\nThese public inputs confer no signing, publishing, credential or remote mutation authority.\n";

fn installer_intent_for_state(
    state: &WizardState,
    candidate: &Path,
) -> Result<catalog_core::PiReleaseIntentV2, WizardError> {
    let manifest: CandidateTransferManifest = parse_canonical(&read_bounded_regular(
        &candidate.join("transfer-manifest-v1.json"),
        true,
    )?)?;
    let matching = manifest
        .records
        .iter()
        .filter(|r| r.role == "release_intent")
        .collect::<Vec<_>>();
    let [record] = matching.as_slice() else {
        return Err(WizardError::Qualification);
    };
    validate_sha256(&record.sha256)?;
    if record.relative_path != format!("records/{}", record.sha256) {
        return Err(WizardError::Qualification);
    }
    let bytes = read_bounded_regular(&candidate.join(&record.relative_path), true)?;
    if sha256(&bytes) != record.sha256 {
        return Err(WizardError::Qualification);
    }
    let intent = catalog_core::PiReleaseIntentV2::from_json(&bytes)
        .map_err(|_| WizardError::Qualification)?;
    let verified = catalog_acquire::verify_transferred_bundle(candidate)
        .map_err(|_| WizardError::Qualification)?;
    let inventory = verified.verified_input();
    if manifest.schema_version != 1
        || manifest.kind != "verified_input"
        || manifest.source_commit.is_some()
        || manifest.source_tree_sha256.is_some()
        || serde_jcs::to_vec(&intent).map_err(|_| WizardError::Qualification)? != bytes
        || inventory.source_kind() != catalog_core::InputSourceKind::ReleaseIntent
        || inventory.source_sha256().as_str()
            != encode_sha256(
                &catalog_core::pi_release_intent_v2_digest(&intent)
                    .map_err(|_| WizardError::Qualification)?,
            )
        || inventory.compatibility_input_sha256().as_str()
            != encode_sha256(
                &catalog_core::pi_release_subject_sha256(intent.profile())
                    .map_err(|_| WizardError::Qualification)?,
            )
        || intent.sequence() != state.sequence
        || intent.profile().pi_package().version().as_str() != state.pi_version
        || intent.profile().node_version().as_str() != state.node_version
        || intent.profile().target().as_str() != state.target
    {
        return Err(WizardError::Qualification);
    }
    Ok(intent)
}
fn installer_request(
    state: &WizardState,
    candidate: &Path,
    keyring: &str,
) -> Result<InstallerQualificationRequest, WizardError> {
    validate_state_identity(state)?;
    validate_sha256(keyring)?;
    let intent = installer_intent_for_state(state, candidate)?;
    let bundle = catalog_acquire::verify_transferred_bundle(candidate)
        .map_err(|_| WizardError::Qualification)?;
    Ok(InstallerQualificationRequest {
        schema_version: 2,
        kind: "pi_installer_lock_v1".into(),
        sequence: state.sequence,
        release_subject_sha256: encode_sha256(
            &catalog_core::pi_release_subject_sha256(intent.profile())
                .map_err(|_| WizardError::Qualification)?,
        ),
        input_bundle_sha256: bundle.bundle_sha256().into(),
        intent: serde_json::to_value(intent).map_err(|_| WizardError::Qualification)?,
        catalog_source_commit: state.catalog_source_commit.clone(),
        catalog_source_tree_sha256: state.catalog_source_tree_sha256.clone(),
        trusted_signing_keyring_sha256: keyring.into(),
    })
}
fn export_installer_request(
    state: &WizardState,
    candidate: &Path,
    output: &Path,
) -> Result<QualificationRequest, WizardError> {
    let request = installer_request(state, candidate, production_keyring().sha256())?;
    let stage = create_stage(output, "qualification-request")?;
    let result = (|| {
        let export_root = stage.join("candidate-export");
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&export_root).map_err(|_| WizardError::Io)?;
        catalog_acquire::export_transfer_bundle(candidate, &export_root.join("candidate"))
            .map_err(|_| WizardError::Qualification)?;
        fs::rename(export_root.join("candidate"), stage.join("candidate"))
            .map_err(|_| WizardError::Io)?;
        let evidence = stage.parent().ok_or(WizardError::Io)?.join(format!(
            ".qualification-acquire-evidence.{}.{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| WizardError::Io)?
                .as_nanos()
        ));
        rename_no_replace(&export_root, &evidence)?;
        write_immutable(
            &stage.join(REQUEST_MANIFEST_NAME),
            &serde_jcs::to_vec(&request).map_err(|_| WizardError::Qualification)?,
        )?;
        write_immutable(&stage.join("README.txt"), INSTALLER_README.as_bytes())?;
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o500))
            .map_err(|_| WizardError::Io)?;
        rename_no_replace(&stage, output)
    })();
    if result.is_err() {
        let _ = make_tree_writable(&stage);
        let _ = fs::remove_dir_all(&stage);
    }
    result?;
    Ok(QualificationRequest::Installer(request))
}
fn verify_installer_request(
    state: &WizardState,
    candidate: &Path,
    output: &Path,
) -> Result<(), WizardError> {
    let meta = fs::symlink_metadata(output).map_err(|_| WizardError::Qualification)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != current_euid()
        || meta.permissions().mode() & 0o7777 != 0o500
        || exact_directory_names(output, 3)?
            != BTreeSet::from([
                REQUEST_MANIFEST_NAME.into(),
                "README.txt".into(),
                "candidate".into(),
            ])
        || read_immutable_regular(&output.join("README.txt"))? != INSTALLER_README.as_bytes()
    {
        return Err(WizardError::Qualification);
    }
    let actual: InstallerQualificationRequest = parse_canonical(&read_immutable_regular(
        &output.join(REQUEST_MANIFEST_NAME),
    )?)?;
    if actual != installer_request(state, candidate, production_keyring().sha256())?
        || actual
            != installer_request(
                state,
                &output.join("candidate"),
                production_keyring().sha256(),
            )?
    {
        return Err(WizardError::Qualification);
    }
    Ok(())
}
fn import_installer_handoff(
    state: &WizardState,
    handoff: &Path,
    keyring: &str,
) -> Result<ImportedQualification, WizardError> {
    if state.phase != ReleasePhase::AwaitingQualification {
        return Err(WizardError::Qualification);
    }
    let root = state.work_dir.join("qualification-request");
    let request: InstallerQualificationRequest = parse_canonical(&read_bounded_regular(
        &root.join(REQUEST_MANIFEST_NAME),
        true,
    )?)?;
    let expected = installer_request(state, &root.join("candidate"), keyring)?;
    if request != expected
        || exact_directory_names(handoff, 2)?
            != BTreeSet::from([BUILD_BINDING_NAME.into(), QUALIFICATION_NAME.into()])
    {
        return Err(WizardError::Qualification);
    }
    let build_bytes = read_bounded_regular(&handoff.join(BUILD_BINDING_NAME), true)?;
    let bytes = read_bounded_regular(&handoff.join(QUALIFICATION_NAME), true)?;
    let build = FluxsembleBuildBindingV1::from_json(&build_bytes)
        .map_err(|_| WizardError::Qualification)?;
    let qualification = catalog_core::PiReleaseQualificationV1::from_json(&bytes)
        .map_err(|_| WizardError::Qualification)?;
    let intent = installer_intent_for_state(state, &root.join("candidate"))?;
    if serde_jcs::to_vec(&build).map_err(|_| WizardError::Qualification)? != build_bytes
        || serde_jcs::to_vec(&qualification).map_err(|_| WizardError::Qualification)? != bytes
    {
        return Err(WizardError::Qualification);
    }
    catalog_core::verify_pi_release_qualification(intent.profile(), &qualification)
        .map_err(|_| WizardError::Qualification)?;
    catalog_core::verify_pi_verification_build(&build, &qualification)
        .map_err(|_| WizardError::Qualification)?;
    let request_bytes = serde_jcs::to_vec(&request).map_err(|_| WizardError::Qualification)?;
    let receipt = serde_jcs::to_vec(&serde_json::json!({
        "schema_version": 2,
        "kind": "pi_installer_lock_v1",
        "sequence": state.sequence,
        "release_subject_sha256": request.release_subject_sha256,
        "request_sha256": sha256(&request_bytes),
        "build_binding_sha256": sha256(&build_bytes),
        "qualification_sha256": sha256(&bytes),
    }))
    .map_err(|_| WizardError::Qualification)?;
    ensure_imported_output(
        &state.work_dir.join("imported-qualification"),
        &build_bytes,
        &bytes,
        &receipt,
    )?;
    let mut advanced = state.clone();
    advanced.phase = ReleasePhase::QualificationImported;
    advanced.save(&state.work_dir.join("wizard-state.json"))?;
    Ok(ImportedQualification {
        build,
        qualification: QualificationEvidence::Installer {
            profile: intent.profile().clone(),
            qualification,
        },
    })
}
