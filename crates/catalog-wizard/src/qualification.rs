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
const README: &str = "Fluxsemble qualification request\n\nUpdate Fluxsemble's exact compatibility profile for the Pi, Node, and target tuple in manifest-v1.json.\nCapture the clean Fluxsemble build binding, run the fixed candidate qualification, and return a directory containing exactly build-binding-v1.json and qualification-v1.json.\n\nThis directory contains public, inert qualification inputs only. It grants no signing, publishing, credential, or remote-mutation authority.\n";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationRequest {
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

impl QualificationRequest {
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
    qualification: CompatibilityQualificationV1,
}

impl ImportedQualification {
    #[must_use]
    pub fn pi_version(&self) -> &str {
        self.qualification.pi_version().as_str()
    }

    #[must_use]
    pub fn node_version(&self) -> &str {
        self.qualification.node_version().as_str()
    }

    #[must_use]
    pub fn build(&self) -> &FluxsembleBuildBindingV1 {
        &self.build
    }

    #[must_use]
    pub fn qualification(&self) -> &CompatibilityQualificationV1 {
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
    validate_state_identity(state)?;
    let candidate = catalog_acquire::verify_transferred_bundle(candidate_dir)
        .map_err(|_| WizardError::Qualification)?;
    candidate_intent_for_state(state, candidate_dir)?;
    let keyring_sha256 = production_keyring().sha256();
    let request = QualificationRequest {
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
        catalog_acquire::export_transfer_bundle(candidate_dir, &stage.join("candidate"))
            .map_err(|_| WizardError::Qualification)?;
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
    Ok(request)
}

pub fn import_handoff(
    state: &WizardState,
    handoff_dir: &Path,
    keyring_sha256: &str,
) -> Result<ImportedQualification, WizardError> {
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
    let request: QualificationRequest = parse_canonical(&request_bytes)?;
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
        qualification,
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
    request: &QualificationRequest,
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
    if state.schema_version != 1
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
                &qualification_value("22.19.0", KEYRING, &qualification_compatibility),
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
            &qualification_value("22.21.0", KEYRING, &"55".repeat(32)),
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
        let bytes =
            serde_jcs::to_vec(&qualification_value("22.19.0", KEYRING, COMPATIBILITY)).unwrap();
        let qualification = CompatibilityQualificationV1::from_json(&bytes).unwrap();
        verify_consumer_keyring_readiness(&qualification, KEYRING).unwrap();
        assert!(verify_consumer_keyring_readiness(&qualification, &"55".repeat(32)).is_err());

        let mut failed = qualification_value("22.19.0", KEYRING, COMPATIBILITY);
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
    ) -> serde_json::Value {
        json!({
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
        })
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
