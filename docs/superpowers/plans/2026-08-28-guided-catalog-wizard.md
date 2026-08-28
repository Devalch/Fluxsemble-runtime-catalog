# Guided Catalog Wizard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `catalog-wizard`, a single guided CLI that lets a release owner update Pi/Node catalog metadata, create a new catalog sequence, sign it with the active private key, and publish through safe prompts.

**Architecture:** Add a new Rust workspace crate `crates/catalog-wizard` that owns CLI parsing, prompts, local/private config, release state, qualification handoff validation, and orchestration. Existing acquire/sign/publish boundaries remain authoritative; Fluxsemble changes stay manual and cross the boundary through one exact qualification request and one returned two-file handoff.

**Tech Stack:** Rust 2024, existing workspace crates, `serde`, `serde_json`, `sha2`, manual CLI parsing, standard-library process execution for existing binaries.

**Spec:** `docs/superpowers/specs/2026-08-28-guided-catalog-wizard-design.md`

## Global Constraints

- First-version workflow is single-machine release-owner flow.
- Target is exactly `linux_x86_64`.
- Fluxsemble compatibility requirement is exactly `=0.1.0`.
- The wizard must support `-h` and `--help` at root and subcommand level.
- If local catalog sequence and GitHub sequence disagree, the release stops.
- If neither `--dry-run` nor `--publish` is passed, the wizard asks the user which mode to use.
- Publish-capable runs must pause before signing, tag creation, draft creation, asset upload, and publication.
- Private keys, tokens, private config paths, credential contents, and redirect queries must never be written to committed files.
- The wizard process must never open private-key bytes; it passes the configured path only to the audited isolated signer launcher.
- Signing key rotation in v1 uses a private signing key file on the trusted release machine.
- Runtime configuration must not inject arbitrary production trust roots; production verifier identities come from the reviewed repository keyring embedded at build time.
- A new signing key cannot become active until the target Fluxsemble build is qualified against the same public keyring digest.
- The old key remains verification-only during the initial transition and may be retired only in a later separately reviewed change.
- This repository must not modify Fluxsemble; a new tuple pauses at `awaiting_qualification` until a matching manual Fluxsemble handoff is imported.

---

## File Structure

Create:

- `crates/catalog-wizard/Cargo.toml` — crate manifest.
- `crates/catalog-wizard/src/main.rs` — binary entrypoint and exit-code mapping.
- `crates/catalog-wizard/src/lib.rs` — module exports and shared `WizardError`.
- `crates/catalog-wizard/src/cli.rs` — manual argument parser and help text.
- `crates/catalog-wizard/src/config.rs` — committed wizard config and private signing config models.
- `crates/catalog-wizard/src/state.rs` — per-release resumable `wizard-state.json` model.
- `crates/catalog-wizard/src/prompt.rs` — prompt abstraction, exact phrase confirmations, test prompt implementation.
- `crates/catalog-wizard/src/sequence.rs` — local/GitHub sequence detection and comparison.
- `crates/catalog-wizard/src/npm.rs` — Pi and Node version discovery.
- `crates/catalog-wizard/src/intent.rs` — version-driven intent/package-input generation.
- `crates/catalog-wizard/src/qualification.rs` — manual Fluxsemble request export and returned handoff validation.
- `crates/catalog-wizard/src/trust.rs` — trusted-machine profile and optional public approval receipt.
- `crates/catalog-wizard/src/key_rotation.rs` — active signing key and rotation workflow.
- `crates/catalog-core/build.rs` — validate the reviewed keyring and generate embedded Rust constants.
- `config/production-signing-keys-v1.json` — reviewed public production keyring; never contains private material.
- `crates/catalog-wizard/src/release.rs` — guided release and resume state machine.
- `crates/catalog-wizard/src/commands.rs` — exact low-level command builders.
- `catalog-wizard.toml` — safe committed defaults.
- `docs/guided-release.md` — short user guide.

Modify:

- `Cargo.toml` — add `crates/catalog-wizard` to workspace members.
- `.gitignore` — ensure `.release-work/` remains ignored and add any wizard local artifacts if needed.

---

### Task 1: Workspace crate and CLI help

**Files:**
- Create: `crates/catalog-wizard/Cargo.toml`
- Create: `crates/catalog-wizard/src/main.rs`
- Create: `crates/catalog-wizard/src/lib.rs`
- Create: `crates/catalog-wizard/src/cli.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Produces: `cli::parse_args(args: &[String]) -> Result<Command, CliError>`
- Produces: `cli::root_help() -> &'static str`
- Produces: `cli::command_help(command: &str) -> Option<&'static str>`
- Produces: `enum Command { Release(ReleaseOptions), Resume(ResumeOptions), RotateKey, TrustMachine, Check, Help(HelpTopic) }`
- Produces: `struct ReleaseOptions { pi: Option<String>, node: Option<String>, mode: Option<RunMode>, config: Option<String> }`
- Produces: `struct ResumeOptions { qualification: Option<String>, config: Option<String> }`
- Produces: `enum RunMode { DryRun, PublishCapable }`

- [ ] **Step 1: Add failing parser/help tests in `cli.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn root_help_accepts_short_and_long_flags() {
        assert!(matches!(parse_args(&args(&["-h"])), Ok(Command::Help(HelpTopic::Root))));
        assert!(matches!(parse_args(&args(&["--help"])), Ok(Command::Help(HelpTopic::Root))));
        assert!(root_help().contains("catalog-wizard <command>"));
        assert!(root_help().contains("release"));
    }

    #[test]
    fn release_help_accepts_short_and_long_flags() {
        assert!(matches!(parse_args(&args(&["release", "-h"])), Ok(Command::Help(HelpTopic::Command(name))) if name == "release"));
        assert!(matches!(parse_args(&args(&["release", "--help"])), Ok(Command::Help(HelpTopic::Command(name))) if name == "release"));
        assert!(command_help("release").unwrap().contains("--pi <version>"));
        assert!(command_help("release").unwrap().contains("--node <version>"));
    }

    #[test]
    fn release_parses_versions_and_mode() {
        let parsed = parse_args(&args(&["release", "--pi", "0.84.0", "--node", "22.20.0", "--publish"])).unwrap();
        match parsed {
            Command::Release(options) => {
                assert_eq!(options.pi.as_deref(), Some("0.84.0"));
                assert_eq!(options.node.as_deref(), Some("22.20.0"));
                assert_eq!(options.mode, Some(RunMode::PublishCapable));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn release_rejects_dry_run_and_publish_together() {
        assert!(matches!(parse_args(&args(&["release", "--dry-run", "--publish"])), Err(CliError::ConflictingMode)));
    }
}
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `cargo test -p catalog-wizard cli::tests`

Expected: cargo reports that package `catalog-wizard` or module symbols do not exist.

- [ ] **Step 3: Add crate manifest and workspace member**

`Cargo.toml` workspace member addition:

```toml
  "crates/catalog-wizard",
```

`crates/catalog-wizard/Cargo.toml`:

```toml
[package]
name = "catalog-wizard"
version = "0.1.0"
edition = "2024"
license = "MIT"
rust-version = "1.85"

[dependencies]
chrono = { workspace = true }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
semver = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
sha2 = { workspace = true }
tokio = { version = "1", features = ["rt", "time"] }
toml = "0.8"
```

- [ ] **Step 4: Implement minimal CLI parser and help text**

`src/lib.rs`:

```rust
pub mod cli;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WizardError {
    Cli(cli::CliError),
    Io,
    Config,
    State,
    ExternalCommand,
    UserDeclined,
}
```

`src/main.rs`:

```rust
use catalog_wizard::cli::{self, Command, HelpTopic};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match cli::parse_args(&args) {
        Ok(Command::Help(HelpTopic::Root)) => println!("{}", cli::root_help()),
        Ok(Command::Help(HelpTopic::Command(command))) => {
            println!("{}", cli::command_help(command).unwrap_or(cli::root_help()))
        }
        Ok(command) => {
            eprintln!("Command requires the guided workflow modules: {command:?}");
            std::process::exit(2);
        }
        Err(_) => {
            eprintln!("Invalid command. Run `catalog-wizard --help`.");
            std::process::exit(2);
        }
    }
}
```

- [ ] **Step 5: Run tests and commit**

Run: `cargo test -p catalog-wizard cli::tests`

Expected: PASS.

Commit:

```bash
git add Cargo.toml crates/catalog-wizard
git commit -m "feat: add catalog wizard cli shell"
```

---

### Task 2: Configuration, private signing config, and release state

**Files:**
- Create: `crates/catalog-wizard/src/config.rs`
- Create: `crates/catalog-wizard/src/state.rs`
- Modify: `crates/catalog-wizard/src/lib.rs`
- Create: `catalog-wizard.toml`

**Interfaces:**
- Produces: `config::WizardConfig::load(path: &Path) -> Result<WizardConfig, WizardError>`
- Produces: `config::PrivateSigningConfig::load(path: &Path) -> Result<PrivateSigningConfig, WizardError>`
- Produces: `state::WizardState::load(path: &Path) -> Result<Option<WizardState>, WizardError>`
- Produces: `state::WizardState::save(&self, path: &Path) -> Result<(), WizardError>`
- Produces: `enum ReleasePhase { Planned, InputsDiscovered, Acquired, CandidateAssembled, Qualified, Signed, LocalStaged, RemoteDraftStaged, Approved, Published }`

- [ ] **Step 1: Write failing tests for config defaults and state round-trip**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn default_config_has_fixed_v1_values() {
        let config = WizardConfig::default_for_repo();
        assert_eq!(config.repository, "Devalch/Fluxsemble-runtime-catalog");
        assert_eq!(config.fluxsemble_requirement, "=0.1.0");
        assert_eq!(config.target, "linux_x86_64");
        assert_eq!(config.state_root, ".release-work");
    }

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
        };
        let bytes = serde_json::to_vec(&state).unwrap();
        let decoded: WizardState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, state);
    }
}
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `cargo test -p catalog-wizard config state`

Expected: FAIL because modules/types are missing.

- [ ] **Step 3: Implement serializable config and state types**

Use `serde::{Serialize, Deserialize}`. Reject config values that do not exactly match first-version constraints for `target` and `fluxsemble_requirement`.

Parse `catalog-wizard.toml` with `toml`, deserialize with `deny_unknown_fields`, and then enforce the fixed v1 values. The committed file is:

```toml
repository = "Devalch/Fluxsemble-runtime-catalog"
fluxsemble_requirement = "=0.1.0"
target = "linux_x86_64"
state_root = ".release-work"
default_node_channel = "22"
```

- [ ] **Step 4: Add module exports**

`src/lib.rs`:

```rust
pub mod cli;
pub mod config;
pub mod state;
```

- [ ] **Step 5: Run tests and commit**

Run: `cargo test -p catalog-wizard config state`

Expected: PASS.

Commit:

```bash
git add catalog-wizard.toml crates/catalog-wizard/src/config.rs crates/catalog-wizard/src/state.rs crates/catalog-wizard/src/lib.rs
git commit -m "feat: add catalog wizard config and state"
```

---

### Task 3: Prompt abstraction and exact confirmations

**Files:**
- Create: `crates/catalog-wizard/src/prompt.rs`
- Modify: `crates/catalog-wizard/src/lib.rs`

**Interfaces:**
- Produces: `trait Prompter { fn ask(&mut self, message: &str) -> Result<String, WizardError>; fn say(&mut self, message: &str) -> Result<(), WizardError>; }`
- Produces: `prompt::confirm_yes_no(prompter: &mut dyn Prompter, message: &str, default: bool) -> Result<bool, WizardError>`
- Produces: `prompt::require_phrase(prompter: &mut dyn Prompter, message: &str, phrase: &str) -> Result<(), WizardError>`
- Produces: `prompt::ScriptedPrompter` for tests.

- [ ] **Step 1: Write failing prompt tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yes_no_uses_default_on_empty_answer() {
        let mut prompt = ScriptedPrompter::new([""]);
        assert!(confirm_yes_no(&mut prompt, "Continue?", true).unwrap());
    }

    #[test]
    fn exact_phrase_accepts_only_exact_text() {
        let mut bad = ScriptedPrompter::new(["sign"]);
        assert!(matches!(require_phrase(&mut bad, "Type SIGN", "SIGN"), Err(WizardError::UserDeclined)));

        let mut good = ScriptedPrompter::new(["SIGN"]);
        assert!(require_phrase(&mut good, "Type SIGN", "SIGN").is_ok());
    }
}
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `cargo test -p catalog-wizard prompt::tests`

Expected: FAIL because `prompt` module is missing.

- [ ] **Step 3: Implement prompt module**

Implement `StdioPrompter` with `stdin`/`stdout` and `ScriptedPrompter` with a `VecDeque<String>`. `require_phrase` returns `WizardError::UserDeclined` on mismatch.

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p catalog-wizard prompt::tests`

Expected: PASS.

Commit:

```bash
git add crates/catalog-wizard/src/prompt.rs crates/catalog-wizard/src/lib.rs
git commit -m "feat: add catalog wizard prompts"
```

---

### Task 4: Sequence and version discovery boundaries

**Files:**
- Create: `crates/catalog-wizard/src/sequence.rs`
- Create: `crates/catalog-wizard/src/npm.rs`
- Modify: `crates/catalog-wizard/src/lib.rs`

**Interfaces:**
- Produces: `sequence::local_latest_sequence(repo: &Path) -> Result<Option<u64>, WizardError>`
- Produces: `sequence::compare_sequences(local: Option<u64>, github: Option<u64>) -> Result<u64, SequenceMismatch>` returning next sequence on match.
- Produces: `trait GithubSequenceSource { fn latest_sequence(&self) -> Result<Option<u64>, WizardError>; }`
- Produces: `trait PiVersionSource { fn available_pi_versions(&self) -> Result<Vec<String>, WizardError>; }`
- Produces: `trait NodeVersionSource { fn available_node_versions(&self) -> Result<Vec<String>, WizardError>; }`
- Produces: narrow credential-free implementations using only fixed npm and nodejs.org metadata endpoints.
- Produces: `npm::choose_pi_version(available: &[String], preselected: Option<&str>) -> Result<String, WizardError>`
- Produces: `npm::suggest_node_version(available: &[String], channel: &str) -> Result<String, WizardError>`

- [ ] **Step 1: Write failing sequence tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

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
}
```

- [ ] **Step 2: Write failing version tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preselected_pi_must_exist_in_available_versions() {
        let available = vec!["0.84.0".to_owned(), "0.83.1".to_owned()];
        assert_eq!(choose_pi_version(&available, Some("0.84.0")).unwrap(), "0.84.0");
        assert!(choose_pi_version(&available, Some("0.82.0")).is_err());
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
}
```

- [ ] **Step 3: Run tests and confirm failure**

Run: `cargo test -p catalog-wizard sequence npm`

Expected: FAIL because modules/types are missing.

- [ ] **Step 4: Implement local sequence scan and pure comparison**

Local sequence scan reads filenames matching `catalogs/catalog-v1-sequence-<N>-source.json` and returns the highest valid `N`. GitHub implementation can be a later concrete source; this task defines trait and pure comparison.

- [ ] **Step 5: Implement bounded credential-free version discovery and helpers**

Fetch only fixed query-free HTTPS metadata endpoints for the approved npm package and Node distribution index. Configure Rustls, `no_proxy`, bounded response sizes/timeouts/redirects, no caller-supplied URL or headers, and no credential input. Parse stable SemVer values, sort descending, and reject malformed or empty results. `choose_pi_version` validates preselected versions against discovered versions; `suggest_node_version` returns the highest stable version in the configured major channel and the wizard requires user confirmation.

- [ ] **Step 6: Run tests and commit**

Run: `cargo test -p catalog-wizard sequence npm`

Expected: PASS.

Commit:

```bash
git add crates/catalog-wizard/src/sequence.rs crates/catalog-wizard/src/npm.rs crates/catalog-wizard/src/lib.rs
git commit -m "feat: add wizard sequence and version discovery"
```

---

### Task 5: Version-driven intent and package-manifest generation

**Files:**
- Modify: `crates/catalog-acquire/src/lib.rs`
- Modify: `crates/catalog-acquire/src/npm.rs`
- Modify: `crates/catalog-acquire/src/archive.rs`
- Modify: `crates/catalog-acquire/src/main.rs`
- Create: `crates/catalog-acquire/tests/release_discovery.rs`
- Create: `crates/catalog-wizard/src/intent.rs`
- Modify: `crates/catalog-wizard/src/lib.rs`

**Interfaces:**
- Produces: `catalog_acquire::DiscoverPiReleaseRequest { sequence, generated_at, expires_at, pi_version, node_version, title, notes, target }`.
- Produces: `catalog_acquire::discover_pi_release(request) -> Result<DiscoveredPiRelease, AcquireError>`.
- Produces: `DiscoveredPiRelease { intent: InitialPiReleaseIntentV1, package_inputs: PackageInputManifestV1 }`.
- Produces: version-independent package-manifest validation; current `ROOT_VERSION`, package-count, and prune-result constants become derived authenticated values rather than locks to sequence 1.
- Produces: `intent::generate_release_inputs(...) -> Result<GeneratedReleaseInputs, WizardError>`.

- [ ] **Step 1: Write a failing authenticated discovery test**

```rust
#[test]
fn discovery_builds_a_coherent_intent_and_package_manifest() {
    let fixture = PublicReleaseFixture::pi_and_node("0.84.0", "22.20.0");
    let discovered = fixture.discover(DiscoverPiReleaseRequest {
        sequence: 2,
        generated_at: "2026-09-01T00:00:00Z".to_owned(),
        expires_at: "2026-10-01T00:00:00Z".to_owned(),
        pi_version: "0.84.0".to_owned(),
        node_version: "22.20.0".to_owned(),
        title: "Pi 0.84.0".to_owned(),
        notes: "Approved managed Pi release.".to_owned(),
        target: "linux_x86_64".to_owned(),
    }).unwrap();
    assert_eq!(discovered.intent.sequence().get(), 2);
    assert_eq!(discovered.intent.release().pi_version().as_str(), "0.84.0");
    assert_eq!(discovered.package_inputs.root_version(), "0.84.0");
}
```

- [ ] **Step 2: Run the focused test and confirm failure**

Run: `cargo test -p catalog-acquire --test release_discovery`

Expected: FAIL because `DiscoverPiReleaseRequest` and `discover_pi_release` do not exist.

- [ ] **Step 3: Implement narrow authenticated discovery**

Use fixed credential-free npm and nodejs.org origins. Resolve the exact selected Pi package and Node archive, verify npm integrity and Node checksums, inspect bounded archives, derive inventories, root manifest, shipped shrinkwrap, and locked package records, and construct both typed outputs. Refactor sequence-1 constants such as root version, package counts, and exact pruned locator set into bounds plus values derived from the authenticated shrinkwrap/platform declarations; retain explicit upper bounds and deterministic sorting. Reuse existing archive, npm, canonicalization, URL, digest, and package-graph validation rather than duplicating them. Accept no caller-supplied URL, origin, credential, command, or target other than `linux_x86_64`.

- [ ] **Step 4: Add rejection tests**

Add cases for a missing package version, mismatched npm integrity, wrong Node checksum, unsafe archive path, shrinkwrap/root mismatch, unsupported target, and an intent/package-manifest semantic mismatch. Each must return the existing closed acquisition error without echoing fetched content or URLs containing redirect queries.

- [ ] **Step 5: Add the wizard input generator**

`generate_release_inputs` sets canonical second-resolution UTC timestamps using the configured validity window, defaults title to `Pi <version>` and notes to `Approved managed Pi release.`, calls `discover_pi_release`, writes canonical no-clobber intent/package-input files under `.release-work/sequence-N/`, reopens them through existing parsers, and returns their SHA-256 digests.

- [ ] **Step 6: Run tests and commit**

Run:

```bash
cargo test -p catalog-acquire --test release_discovery
cargo test -p catalog-acquire
cargo test -p catalog-wizard intent
```

Expected: PASS.

Commit:

```bash
git add crates/catalog-acquire crates/catalog-wizard/src/intent.rs crates/catalog-wizard/src/lib.rs
git commit -m "feat: discover versioned catalog release inputs"
```

---

### Task 6: Reviewed keyring, signing key rotation, and active key verification

**Files:**
- Create: `config/production-signing-keys-v1.json`
- Create: `crates/catalog-core/build.rs`
- Create: `crates/catalog-wizard/src/key_rotation.rs`
- Modify: `crates/catalog-core/Cargo.toml`
- Modify: `crates/catalog-core/src/signature.rs`
- Modify: `crates/catalog-core/src/qualification.rs`
- Modify: `crates/catalog-core/tests/signature_contract.rs`
- Modify: `crates/catalog-core/tests/qualification_contract.rs`
- Modify: `crates/catalog-sign/src/key.rs`
- Modify: `crates/catalog-sign/src/signing.rs`
- Modify: `crates/catalog-sign/src/isolation.rs`
- Modify: `crates/catalog-sign/src/bin/catalog-sign-launcher.rs`
- Modify: `crates/catalog-sign/tests/key_boundary.rs`
- Modify: `crates/catalog-sign/tests/isolation_contract.rs`
- Modify: `crates/catalog-wizard/src/lib.rs`

**Interfaces:**
- Produces: `catalog_core::ProductionKeyringV1` embedded from the reviewed public keyring at build time.
- Produces: `catalog_core::active_production_key_identity() -> &'static ProductionKeyIdentity`.
- Produces: production verification that accepts `active_for_signing` and bounded `verification_only` key entries, while signer key access accepts only `active_for_signing`.
- Produces: `key_rotation::ActiveSigningKey { key_id: String, public_key: String, generation: u32, fingerprint: String, keyring_sha256: String }`
- Produces: `key_rotation::RotationReceipt`
- Produces: `key_rotation::inspect_key_with_isolated_signer(private_key_path: &Path, launcher_config: &Path) -> Result<ActiveSigningKey, WizardError>`; the wizard never opens the key.
- Produces: `key_rotation::verify_signed_bundle_key(bundle_dir: &Path, expected: &ActiveSigningKey) -> Result<(), WizardError>`
- Produces: `key_rotation::rotate_key(prompter: &mut dyn Prompter, keyring_path: &Path, local_config_path: &Path) -> Result<ActiveSigningKey, WizardError>`

- [ ] **Step 1: Write failing keyring contract tests**

```rust
#[test]
fn reviewed_keyring_has_exactly_one_active_signing_key() {
    let keyring = production_keyring();
    assert_eq!(
        keyring.entries().iter().filter(|entry| entry.is_active_for_signing()).count(),
        1
    );
}

#[test]
fn verification_only_key_can_verify_but_cannot_sign() {
    let keyring = two_generation_transition_fixture();
    assert!(keyring.verification_identity("runtime-catalog-ed25519-old").is_some());
    assert_ne!(
        keyring.active_signing_identity().key_id(),
        "runtime-catalog-ed25519-old"
    );
}
```

- [ ] **Step 2: Run keyring tests and confirm failure**

Run: `cargo test -p catalog-core --test signature_contract`

Expected: FAIL because keyring APIs do not exist and production identity is still a singleton.

- [ ] **Step 3: Add the reviewed public keyring and embed it into production verification**

Create `config/production-signing-keys-v1.json` with the existing production key as generation 1 and `active_for_signing`. Add `crates/catalog-core/build.rs` to validate it and generate immutable Rust constants into `OUT_DIR`; add `cargo:rerun-if-changed=../../config/production-signing-keys-v1.json`. Reject duplicate generations/IDs/public keys, malformed key IDs, zero generations, more than one active key, unknown status, or a key ID that does not derive from its public key. Keep runtime APIs incapable of accepting a caller-provided production identity.

- [ ] **Step 4: Update signer boundaries**

Change private-key admission and signing to compare the derived private-key public identity only with `active_production_key_identity()`. Update production verification to select a matching trusted key by signed `key_id`, accepting only keyring entries with status `active_for_signing` or `verification_only`. Add an isolated launcher mode `inspect-key` that mounts the key under the existing signer isolation controls, emits only canonical key ID/public key/fingerprint, performs no signing, and accepts no output path or network capability. Add boundary tests proving the wizard does not open the key and the inspection mode cannot produce a signature.

- [ ] **Step 5: Run core and signer boundary tests**

Run:

```bash
cargo test -p catalog-core --test signature_contract
cargo test -p catalog-sign --test key_boundary
cargo test -p catalog-sign --test isolation_contract
```

Expected: PASS.

- [ ] **Step 6: Write failing wizard key verification tests using synthetic signed manifest JSON**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_bundle_key_must_match_active_key() {
        let expected = ActiveSigningKey {
            key_id: "runtime-catalog-ed25519-new".to_owned(),
            public_key: "public-key-text".to_owned(),
            generation: 2,
            fingerprint: "abc123".to_owned(),
            keyring_sha256: "11".repeat(32),
        };
        let matching_manifest = r#"{"signature":{"key_id":"runtime-catalog-ed25519-new"}}"#;
        assert!(manifest_key_matches(matching_manifest.as_bytes(), &expected).is_ok());

        let wrong_manifest = r#"{"signature":{"key_id":"runtime-catalog-ed25519-old"}}"#;
        assert!(manifest_key_matches(wrong_manifest.as_bytes(), &expected).is_err());
    }
}
```

- [ ] **Step 7: Run wizard tests and confirm failure**

Run: `cargo test -p catalog-wizard key_rotation::tests`

Expected: FAIL because the wizard key-rotation module/types are missing.

- [ ] **Step 8: Implement key model and manifest key check**

Parse `signed-release-bundle-manifest-v1.json` and compare `signature.key_id` to the active keyring entry. Cryptographic verification remains the existing core responsibility; the wizard additionally enforces release-operator expectation matching.

- [ ] **Step 9: Implement rotate-key prompt flow**

Prompt for the private key path, call only the isolated `inspect-key` launcher mode, display key ID/new generation/fingerprint, require exact phrase `ROTATE KEY`, and write a proposed public keyring update plus local private config. The command must explain that the proposal is not publishable until committed, rebuilt, reviewed, and matched by compatibility qualification. It must not mark the old key retired during the same transition.

- [ ] **Step 10: Run tests and commit**

Run:

```bash
cargo test -p catalog-core
cargo test -p catalog-sign
cargo test -p catalog-wizard key_rotation::tests
```

Expected: PASS.

Commit:

```bash
git add config/production-signing-keys-v1.json crates/catalog-core crates/catalog-sign crates/catalog-wizard/src/key_rotation.rs crates/catalog-wizard/src/lib.rs
git commit -m "feat: add reviewed signing key rotation"
```

---

### Task 7: Fluxsemble qualification request and handoff

**Files:**
- Create: `crates/catalog-wizard/src/qualification.rs`
- Modify: `crates/catalog-wizard/src/state.rs`
- Modify: `crates/catalog-wizard/src/cli.rs`
- Modify: `crates/catalog-wizard/src/lib.rs`
- Modify: `crates/catalog-core/src/qualification.rs`
- Modify: `crates/catalog-core/tests/qualification_contract.rs`

**Interfaces:**
- Produces: `qualification::export_request(state: &WizardState, candidate_dir: &Path, output: &Path) -> Result<QualificationRequest, WizardError>`.
- Produces: `qualification::import_handoff(state: &WizardState, handoff_dir: &Path, keyring_sha256: &str) -> Result<ImportedQualification, WizardError>`.
- Produces: `qualification::verify_consumer_keyring_readiness(qualification: &CompatibilityQualificationV1, expected_keyring_sha256: &str) -> Result<(), WizardError>`.
- Adds: `ReleasePhase::AwaitingQualification` and `ReleasePhase::QualificationImported`.
- Adds: `resume --qualification <path>`.

- [ ] **Step 1: Write failing qualification handoff tests**

```rust
#[test]
fn matching_handoff_is_imported_for_the_exact_release() {
    let fixture = QualificationHandoffFixture::matching(
        2,
        "0.84.0",
        "22.20.0",
        "linux_x86_64",
        "11".repeat(32),
    );
    let imported = import_handoff(
        fixture.state(),
        fixture.handoff_dir(),
        &"11".repeat(32),
    ).unwrap();
    assert_eq!(imported.pi_version(), "0.84.0");
    assert_eq!(imported.node_version(), "22.20.0");
}

#[test]
fn wrong_tuple_or_keyring_digest_is_rejected_before_signing() {
    let fixture = QualificationHandoffFixture::with_wrong_node_version();
    assert!(import_handoff(fixture.state(), fixture.handoff_dir(), &"11".repeat(32)).is_err());
    let fixture = QualificationHandoffFixture::with_wrong_keyring_digest();
    assert!(import_handoff(fixture.state(), fixture.handoff_dir(), &"11".repeat(32)).is_err());
}
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `cargo test -p catalog-wizard qualification::tests`

Expected: FAIL because the qualification handoff module and state phases do not exist.

- [ ] **Step 3: Extend qualification binding for key rotation readiness**

Add required `trusted_signing_keyring_sha256` to `CompatibilityQualificationV1` and its compatibility-input digest domain. Update catalog-core qualification tests and sequence-1 fixture construction using the digest of the generation-1 reviewed keyring. Reject missing, unknown, malformed, or mismatched values.

- [ ] **Step 4: Implement qualification request export**

Write a no-clobber `qualification-request/manifest-v1.json` that binds sequence, Pi/Node/target, candidate digest, catalog source commit/tree, and keyring digest. Copy the unsigned candidate through verified immutable objects and write `README.txt` with the manual boundary: update Fluxsemble's exact compatibility profile, capture its clean build binding, run its fixed candidate qualification, and return a directory containing exactly `build-binding-v1.json` and `qualification-v1.json`. The text must contain no credentials, private paths, or executable authority.

- [ ] **Step 5: Implement strict handoff import**

Open a directory containing exactly the two expected non-symlink, one-link, bounded regular files. Parse them with existing core types, compare tuple/candidate/compatibility/keyring bindings, require all mandatory checks to be `passed`, copy them no-clobber into `imported-qualification/`, and write an immutable receipt containing only safe IDs and SHA-256 values.

- [ ] **Step 6: Add CLI and resume behavior**

Parse `resume --qualification <path>`. Interactive resume asks only: `Qualification is ready. Enter the returned directory:`. Successful import advances to `QualificationImported`; failure remains `AwaitingQualification` and prints `The returned qualification does not match this release.`

- [ ] **Step 7: Run tests and commit**

Run:

```bash
cargo test -p catalog-core --test qualification_contract
cargo test -p catalog-wizard qualification
```

Expected: PASS.

Commit:

```bash
git add crates/catalog-core/src/qualification.rs crates/catalog-core/tests/qualification_contract.rs crates/catalog-wizard/src/qualification.rs crates/catalog-wizard/src/state.rs crates/catalog-wizard/src/cli.rs crates/catalog-wizard/src/lib.rs
git commit -m "feat: add Fluxsemble qualification handoff"
```

---

### Task 8: Trusted machine profiles

**Files:**
- Create: `crates/catalog-wizard/src/trust.rs`
- Modify: `crates/catalog-wizard/src/lib.rs`

**Interfaces:**
- Produces: `trust::MachineRole::{Preparer, Signer, Publisher}`
- Produces: `trust::TrustedMachineProfile`
- Produces: `trust::PublicMachineApprovalReceipt`
- Produces: `trust::current_machine_facts(repo: &Path) -> Result<MachineFacts, WizardError>`
- Produces: `trust::profile_matches(profile: &TrustedMachineProfile, facts: &MachineFacts, required: &[MachineRole]) -> Result<(), TrustError>`

- [ ] **Step 1: Write failing trust tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_requires_requested_roles() {
        let profile = TrustedMachineProfile::fixture_with_roles(vec![MachineRole::Preparer]);
        let facts = MachineFacts::fixture_matching();
        assert!(profile_matches(&profile, &facts, &[MachineRole::Preparer]).is_ok());
        assert!(profile_matches(&profile, &facts, &[MachineRole::Signer]).is_err());
    }

    #[test]
    fn public_receipt_does_not_include_private_paths() {
        let profile = TrustedMachineProfile::fixture_with_roles(vec![MachineRole::Preparer, MachineRole::Signer, MachineRole::Publisher]);
        let receipt = PublicMachineApprovalReceipt::from_profile(&profile, "release-owner");
        let text = serde_json::to_string(&receipt).unwrap();
        assert!(!text.contains("/home/"));
        assert!(!text.contains("private"));
        assert!(text.contains("trusted_machine_approval"));
    }
}
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `cargo test -p catalog-wizard trust::tests`

Expected: FAIL because trust module is missing.

- [ ] **Step 3: Implement profile matching and public receipt redaction**

Represent roles as strings in JSON: `preparer`, `signer`, `publisher`. Public receipt contains label, roles, approved_by, approved_at, optional expires_at, and profile digest. It does not contain user, hostname, repo path, private key path, broker path, or config path.

- [ ] **Step 4: Implement the `trust-machine` guided command**

Prompt for label, confirm the combined preparer/signer/publisher roles, ask for optional expiry, and ask whether to create a public receipt. Because the profile includes signer role, prompt for the existing private key path and call the isolated key-inspection boundary added in Task 6. Save the private profile and key path only in mode-`0600` local config after the returned public identity matches the reviewed active key. Do not let the wizard open the key, and do not print or copy its path into the public receipt.

- [ ] **Step 5: Run tests and commit**

Run: `cargo test -p catalog-wizard trust::tests`

Expected: PASS.

Commit:

```bash
git add crates/catalog-wizard/src/trust.rs crates/catalog-wizard/src/lib.rs crates/catalog-wizard/src/main.rs
git commit -m "feat: add trusted machine profiles"
```

---

### Task 9: Low-level command builders and dry-run-safe release state machine

**Files:**
- Create: `crates/catalog-wizard/src/commands.rs`
- Create: `crates/catalog-wizard/src/release.rs`
- Modify: `crates/catalog-wizard/src/lib.rs`
- Modify: `crates/catalog-wizard/src/main.rs`

**Interfaces:**
- Produces: `commands::CommandPlan`
- Produces: `commands::build_acquire_intent(...) -> CommandPlan`
- Produces: `commands::build_assemble_intent(...) -> CommandPlan`
- Produces: `commands::build_acquire_source(...) -> CommandPlan`
- Produces: `commands::build_finalize_candidate(...) -> CommandPlan`
- Produces: `commands::build_sign(...) -> CommandPlan`
- Produces: `commands::build_publish_stage_local(...) -> CommandPlan`
- Produces: `release::run_release(options: ReleaseOptions, prompter: &mut dyn Prompter) -> Result<(), WizardError>`
- Produces: `release::resume_release(prompter: &mut dyn Prompter) -> Result<(), WizardError>`

- [ ] **Step 1: Write failing command-builder tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn acquire_intent_command_uses_exact_flags() {
        let plan = build_acquire_intent(
            Path::new("intent.json"),
            Path::new("package-inputs.json"),
            Path::new("transfer"),
        );
        assert_eq!(plan.program, "catalog-acquire");
        assert_eq!(plan.args, vec![
            "acquire-intent",
            "--intent", "intent.json",
            "--package-inputs", "package-inputs.json",
            "--output", "transfer",
        ]);
    }
}
```

- [ ] **Step 2: Write failing release dry-run test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_stops_before_signing_and_remote_mutations() {
        let mut harness = ReleaseHarness::dry_run_fixture();
        run_release_with_harness(&mut harness).unwrap();
        assert!(harness.executed.iter().any(|command| command.contains("acquire-intent")));
        assert!(!harness.executed.iter().any(|command| command.contains(" sign ")));
        assert!(!harness.executed.iter().any(|command| command.contains("stage-remote")));
    }
}
```

- [ ] **Step 3: Run tests and confirm failure**

Run: `cargo test -p catalog-wizard commands release`

Expected: FAIL because modules and harness are missing.

- [ ] **Step 4: Implement exact command builders**

`CommandPlan` must store `program: String` and `args: Vec<String>`. It must not shell-concatenate commands. Process execution uses `std::process::Command::new(&plan.program).args(&plan.args)`.

- [ ] **Step 5: Implement release phase progression**

Release phases update `wizard-state.json` after each successful phase. Generate authenticated release inputs, acquire them, assemble the intent candidate, and export the qualification request. If no handoff has been imported, stop at `AwaitingQualification` in either mode. After import, build canonical `CatalogSourceV1` from the unchanged intent plus returned build/qualification bindings, run `acquire-source`, finalize the exact candidate, and require semantic parity with the pre-qualification candidate. In dry-run mode, stop after this verified final candidate and print `Dry run complete; no signing or publishing was performed.`

- [ ] **Step 6: Wire `release` and `resume` in `main.rs`**

For interactive runs, instantiate `StdioPrompter` and call `release::run_release` or `release::resume_release`.

- [ ] **Step 7: Run tests and commit**

Run: `cargo test -p catalog-wizard commands release`

Expected: PASS.

Commit:

```bash
git add crates/catalog-wizard/src/commands.rs crates/catalog-wizard/src/release.rs crates/catalog-wizard/src/lib.rs crates/catalog-wizard/src/main.rs
git commit -m "feat: add guided dry-run release workflow"
```

---

### Task 10: Publish-capable approvals and docs/evidence prompt

**Files:**
- Modify: `crates/catalog-wizard/src/release.rs`
- Modify: `crates/catalog-wizard/src/key_rotation.rs`
- Modify: `crates/catalog-wizard/src/commands.rs`

**Interfaces:**
- Consumes: `prompt::require_phrase`
- Consumes: `key_rotation::verify_signed_bundle_key`
- Consumes: low-level command builders
- Produces: publish-capable release flow with required exact confirmation phrases.

- [ ] **Step 1: Write failing publish approval order test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(harness.required_phrases, vec![
            "SIGN",
            "CREATE TAG",
            "CREATE DRAFT",
            "UPLOAD ASSETS",
            "PUBLISH",
        ]);
    }
}
```

- [ ] **Step 2: Run test and confirm failure**

Run: `cargo test -p catalog-wizard release::tests::publish_capable_run_requires_all_exact_phrases_in_order`

Expected: FAIL because the harness does not yet record the required phrase sequence.

- [ ] **Step 3: Add publish-capable state transitions**

Before signing, call `require_phrase(..., "SIGN")`. Before remote staging phases, require `CREATE TAG`, `CREATE DRAFT`, and `UPLOAD ASSETS` before invoking the low-level command that can perform those authorized mutations. Before final publish, require `PUBLISH`.

- [ ] **Step 4: Verify signing key before publishing**

Before signing, call `verify_consumer_keyring_readiness` against the approved qualification record. After signing and before `stage-local`, call `verify_signed_bundle_key` with the active signing key. A readiness or bundle mismatch stops with a plain explanation and performs no remote mutation.

- [ ] **Step 5: Add post-success docs/evidence prompt**

After latest verification succeeds, ask `Update docs and evidence files now? [Y/n]`. If the user declines, print exact generated receipt paths under `.release-work/sequence-N/receipts/`. If accepted, copy safe public receipts into `qualifications/` and update `docs/first-release.md` or a new sequence-specific doc using a deterministic helper.

- [ ] **Step 6: Run tests and commit**

Run: `cargo test -p catalog-wizard release key_rotation commands`

Expected: PASS.

Commit:

```bash
git add crates/catalog-wizard/src/release.rs crates/catalog-wizard/src/key_rotation.rs crates/catalog-wizard/src/commands.rs
git commit -m "feat: add guided publishing approvals"
```

---

### Task 11: User documentation and full verification

**Files:**
- Create: `docs/guided-release.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: completed `catalog-wizard` CLI.
- Produces: user-facing docs that require only `catalog-wizard release` for the normal flow.

- [ ] **Step 1: Write `docs/guided-release.md`**

Use this content structure:

```markdown
# Guided runtime catalog release

For normal releases, run:

```bash
catalog-wizard release
```

The wizard will ask you to choose a Pi version, confirm a Node version, and choose dry-run or guided publish. It prepares a qualification request and pauses while a Fluxsemble maintainer updates and qualifies that version tuple. When the returned qualification directory is ready, continue with:

```bash
catalog-wizard resume
```

The wizard verifies the handoff and confirms before signing or publishing.

First-time setup:

```bash
catalog-wizard trust-machine
catalog-wizard check
```

Only when replacing the signing key:

```bash
catalog-wizard rotate-key
```

If a release is interrupted:

```bash
catalog-wizard resume
```

For help:

```bash
catalog-wizard -h
catalog-wizard release --help
```
```

- [ ] **Step 2: Add README pointer**

Add a short section to `README.md`:

```markdown
## Guided releases

Release owners should use the guided wizard for normal catalog updates:

```bash
catalog-wizard release
```

See `docs/guided-release.md`.
```

- [ ] **Step 3: Run focused verification**

Run:

```bash
cargo test -p catalog-wizard
cargo test -p catalog-core
cargo test -p catalog-acquire
cargo test -p catalog-sign
cargo test -p catalog-publish
```

Expected: all tests pass.

- [ ] **Step 4: Run repository gate**

Run:

```bash
scripts/check.sh
```

Expected: gate completes successfully.

- [ ] **Step 5: Commit docs and verification fixes**

Commit:

```bash
git add docs/guided-release.md README.md
git commit -m "docs: add guided catalog release workflow"
```

---

## Self-Review

- Spec coverage: The tasks cover CLI help, config, state, prompts, sequence comparison, public version discovery, version-independent intent generation, manual Fluxsemble qualification handoff, trusted machines, key rotation, release orchestration, publish approvals, docs, and verification.
- Placeholder scan: Every implementation step names concrete files, interfaces, commands, expected outcomes, and test assertions.
- Type consistency: Shared names used across tasks are defined before consumption: `RunMode`, `ReleaseOptions`, `Prompter`, `WizardState`, `MachineRole`, `ActiveSigningKey`, and `CommandPlan`.
