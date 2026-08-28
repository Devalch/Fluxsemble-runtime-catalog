# Guided Catalog Wizard Design

## Goal

Create a single guided CLI command for release owners to update the runtime catalog to new Pi and Node versions, create a new catalog sequence, sign it with the active private signing key, and publish it through guided GitHub approval stops without requiring knowledge of the internal acquire/sign/publish tools.

## Approved decisions

- First release workflow is a single-machine owner flow.
- The trusted release machine prepares, signs, and publishes.
- Target support is limited to `linux_x86_64` because catalog v1 currently admits only that target.
- The wizard queries npm for available `@earendil-works/pi-coding-agent` versions and lets the user choose.
- The wizard suggests a Node version and requires confirmation.
- The wizard compares local committed catalog sequence files and GitHub release/tag state; any disagreement stops the release with a plain explanation.
- Each run asks whether it is dry-run or publish-capable.
- Publishing is guided: the wizard runs existing publication tooling but pauses before irreversible GitHub mutations.
- Signing key rotation is supported through both reviewed config edits and a guided `rotate-key` command.
- First-version key rotation uses a private signing key file on the trusted single release machine. Public-key-only support is deferred to future split-machine workflows.
- Trusted machine data is local/private, with an optional committed public approval receipt that contains no secrets or private paths.
- Trusted machine approvals may omit expiry, but the wizard warns when no expiry is set.
- After a successful release, the wizard asks whether to update committed docs/evidence files.
- The wizard changes only the runtime-catalog repository. Fluxsemble compatibility-profile changes remain a separate manual workflow.
- The manual Fluxsemble boundary is presented as one qualification request directory and one returned qualification handoff directory; catalog operators do not need to understand its internal files.
- `-h` and `--help` must work for the root command and every subcommand.

## User workflow

### First-time trust setup

The user runs:

```bash
catalog-wizard trust-machine
```

The wizard asks for a friendly machine label, confirms that the machine is approved for prepare/sign/publish roles, warns if no expiry is configured, and optionally writes a safe public approval receipt. Because the machine has the signer role, first-time setup also asks for the existing private signing-key path. The wizard never opens the private key itself: a dedicated isolated signer inspection mode derives safe public identity output, which must match the reviewed active keyring entry. This binds local key access without rotating the key. The local private profile records enough local facts to detect accidental use from the wrong machine, but the wizard presents this only as a profile match, not as proof that the machine is secure.

### Normal release

The user runs:

```bash
catalog-wizard release
```

The wizard checks setup, detects/resolves unfinished release state, compares local and GitHub sequence state, asks the user to choose a Pi version, suggests and confirms Node version, asks whether to run dry-run or publish-capable, and shows one plain-language summary before doing work.

After preparing the exact unsigned candidate, the wizard writes one qualification request directory and pauses with a plain message: `Fluxsemble qualification is required. Send this directory to the Fluxsemble maintainer, then run catalog-wizard resume.` The Fluxsemble repository is updated and qualified manually. On resume, the catalog operator supplies one returned qualification handoff directory. The wizard verifies that it is bound to the selected Pi/Node/target, candidate digest, Fluxsemble build, and signing keyring digest before continuing.

During publish-capable runs, the wizard asks for exact confirmations before signing, tag creation, draft creation, asset upload, and publication. It verifies the signed bundle, staged draft, final publication, and latest catalog before reporting success.

### Interrupted release

If an unfinished release exists, `catalog-wizard release` asks whether to resume, start a new release, or exit. `catalog-wizard resume` skips directly to selecting resumable release state.

### Signing key rotation

The user runs:

```bash
catalog-wizard rotate-key
```

For first version, the wizard asks for the new private signing key file, derives/displays the key identity and public fingerprint, increments the signing key generation, and requires an exact confirmation phrase before updating active signing config. Future releases use the active key generation and verify the signed bundle matches it.

## CLI surface

Root usage:

```text
catalog-wizard <command> [options]
```

Commands:

- `release`: create and optionally publish a new runtime catalog.
- `resume`: continue an interrupted release.
- `rotate-key`: approve a new private signing key for future releases.
- `trust-machine`: approve the current machine for release operations and bind its existing private key to the reviewed active key.
- `check`: check local setup without signing or publishing.
- `help`: show help.

Common options:

- `-h`, `--help`: show short help.
- `--config <path>`: use a specific wizard config file.

Release options:

- `--pi <version>`: preselect the Pi version to publish.
- `--node <version>`: preselect the Node version to use.
- `--dry-run`: force non-mutating mode.
- `--publish`: allow guided publish-capable mode.
- `--qualification <path>`: supply a returned Fluxsemble qualification handoff when resuming non-interactively.

If neither `--dry-run` nor `--publish` is passed, the wizard asks interactively.

## Architecture

Add a new workspace crate `crates/catalog-wizard` that owns user prompts, configuration, resumable wizard state, qualification handoff validation, and orchestration. Add a narrow version-driven discovery API to `catalog-acquire` so the wizard can construct a complete reviewed intent and package manifest from authenticated public Pi/Node artifacts instead of editing the prior sequence by hand. Invoke existing binaries only through exact argument builders where a binary boundary is required.

The existing acquire, signer isolation, publisher broker, and publication workflow remain authoritative. The wizard does not weaken their validation, does not bypass approval stops, does not modify the Fluxsemble repository, and does not introduce credential-bearing catalog fields.

## Fluxsemble qualification handoff

A new Pi or Node tuple is not publishable until Fluxsemble has been manually updated and qualified for that exact tuple. The wizard exports:

```text
.release-work/sequence-N/qualification-request/
  manifest-v1.json
  candidate/
  README.txt
```

The manifest binds the release sequence, Pi/Node versions, target, candidate digest, source catalog commit/tree, and reviewed producer keyring digest. `README.txt` contains safe, copyable instructions for the Fluxsemble maintainer but no executable authority.

The returned directory is intentionally simple:

```text
fluxsemble-qualification-handoff-v1/
  build-binding-v1.json
  qualification-v1.json
```

The wizard admits only this exact bounded layout. It verifies canonical JSON, exact tuple, candidate/compatibility input digest, Fluxsemble implementation/build identities, qualification outcome, and trusted signing-keyring digest, then creates its own immutable import receipt. A mismatch leaves release state at `awaiting_qualification` and performs no signing or remote mutation.

## State and file layout

Committed configuration and optional public receipts:

```text
catalog-wizard.toml
docs/trust/trusted-machine-approval-<label>.json
```

Local/private configuration:

```text
~/.config/fluxsemble-runtime-catalog/trusted-machines/<label>.json
~/.config/fluxsemble-runtime-catalog/signing-key.json
```

Per-release ignored work directory:

```text
.release-work/sequence-N/
  wizard-state.json
  intent.json
  package-inputs.json
  acquired-transfer/
  unsigned-candidate/
  qualification-request/
  imported-qualification/
  signed-release-bundle/
  publish-state/
  receipts/
```

Generated committed files, when the user approves evidence/doc updates:

```text
catalogs/intents/catalog-v1-sequence-N-intent.json
catalogs/inputs/pi-<pi-version>-linux-x86_64-packages-v1.json
catalogs/catalog-v1-sequence-N-source.json
qualifications/compatibility-pi-<pi-version>-node-<node-version>-fluxsemble-0.1.0-v1.json
```

## Safety and approval model

The wizard must keep these stops:

- confirmation of selected Pi/Node/sequence/signing key before work starts;
- exact phrase before private-key signing;
- exact phrase before GitHub tag creation;
- exact phrase before draft release creation;
- exact phrase before release asset upload;
- explicit review and exact phrase before publication;
- post-release prompt before tracked docs/evidence changes.

All prompts must avoid secrets, private paths, tokens, credential contents, redirect queries, raw broker output, or key material. Private-key paths may be typed by the user during key setup, but they must not be written to committed files or displayed in public receipts.

## Signing key rotation

Key rotation is a trust-root transition, not merely a different private-key path. The repository must contain a reviewed public keyring whose entries include generation, key ID, public key, status, and activation metadata. Low-level production verification embeds that reviewed keyring at build time. Exactly one entry may be `active_for_signing`; an older key may remain `verification_only` during a bounded transition so existing published catalogs remain verifiable. Runtime config cannot inject an arbitrary production verification key.

The local active-key config references one keyring generation and stores its private key path outside the repository. Before signing, the wizard obtains the safe derived public identity from the isolated signer and requires an exact match with the keyring's `active_for_signing` entry. The signed release bundle must match that identity before staging or publishing.

`rotate-key` asks the dedicated isolated signer inspection mode to derive the new public identity, increments the generation, proposes a reviewed keyring update, and may write a safe committed receipt with old key ID, new key ID, generation, public fingerprint, approval time, and reviewer. The wizard process never reads private key bytes, and no command commits private key paths or private key bytes. Rotation does not become publishable merely because the file was generated: the wizard must require a clean reviewed source build and compatibility qualification proving that the target Fluxsemble build trusts the same keyring digest. This avoids publishing a catalog that deployed consumers cannot verify.

The first rotation release follows this order:

1. generate and review the new public keyring entry while the old key remains trusted;
2. update and qualify Fluxsemble against the resulting keyring digest;
3. build/review the producer signer and verifier from that committed keyring;
4. activate the new generation for signing;
5. publish a catalog signed by the new key only after the readiness checks pass;
6. retire the old verification key in a later separately reviewed transition, never in the same step that first activates the new key.

## Trusted machine profiles

A local profile may include machine ID, user, hostname, approved repo root, roles, executable hashes, approval metadata, and expiry. A committed approval receipt may include label, roles, approval metadata, expiry, and a digest of the local private profile. The wizard must warn that a profile match means “this matches a previously approved profile,” not “this machine is secure.”

## Error handling

Failures must be plain-language and action-oriented. Remote uncertainty, sequence mismatch, qualification mismatch, signing mismatch, trust-profile mismatch, dirty working tree, invalid config permissions, and interrupted release state must stop safely and explain the next command, usually `catalog-wizard resume` or `catalog-wizard check`.

## Testing requirements

Tests must cover CLI help, argument parsing, version selection, Node suggestion confirmation, local/GitHub sequence comparison, dry-run behavior, publish approval stops, wizard resume state, trusted-machine matching, key rotation, signed-bundle key verification, and safe receipt redaction.
