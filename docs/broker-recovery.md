# Recover an existing partial draft with a repaired broker

Use this path when an uncertain production operation must keep its exact tag,
draft release and already uploaded asset IDs while adopting a reviewed broker
repair. It does not resign, restage, recreate a draft, replace an asset, or grant
release approval/publication authority. The signed candidate and its source
commit remain unchanged; the repaired publication tools have their own reviewed
source commit and executable digests.

## 1. Prepare a public observation and offline plan

Retain the old state and tools. Independently inspect the exact draft and download
its existing assets by ID. Write a canonical owner-private mode-0400, one-link
observation file with exactly `release_id` and `assets`; each asset contains
`asset_id`, `name`, `size`, and `sha256`, in the signed upload order. The list must
be a nonempty proper prefix of the signed inventory and include at least the
old operation's recorded verified count. A fifth uploaded asset with recorded
count four is valid: observed and recorded progress are distinct.

Create a fresh canonical mode-0600 outer broker-client config pinning the repaired
one-link broker executable. Keep the inner credential-broker config and its hash
unchanged. Never copy credentials or include credential locators in commands,
plans, logs or receipts.

```text
catalog-publish plan-broker-recovery --state /ABSOLUTE/STATE --broker-config /ABSOLUTE/NEW_OUTER_CONFIG --retained-assets /ABSOLUTE/RETAINED_ASSETS
```

Stdout is the canonical public recovery plan, with no trailing newline. Capture
it using exclusive creation into a new mode-0400 file and compute its SHA-256
outside the tool. Planning validates the original signed/local state, retained
observation and new config/executable identities. It launches no authenticated
broker process, uploads nothing, and writes no recovery certificate/operation.
The existing descriptor-bound workflow lock is held during inspection.

The owner reviews the exact plan SHA-256, local-reference hash, complete original
operation/hash, successor operation/hash/ID, unchanged signed/source/release
bindings, observed asset IDs/hashes, and all old/new broker pins. The successor
changes only the outer-client/broker executable hashes, derived operation ID and
explicit required-proof marker. Original phase and verified count are preserved.
The plan's five-asset baseline does not fabricate a fifth prior verification.

## 2. Explicitly approved local broker recovery

Stop for approval of this exact transition and any necessary temporary directory
restrictions/restoration. This is separate from the release's later `approve`
command. Run only with the exact externally reviewed plan digest:

```text
catalog-publish recover-broker --state /ABSOLUTE/STATE --broker-config /ABSOLUTE/NEW_OUTER_CONFIG --plan /ABSOLUTE/REVIEWED_PLAN --plan-sha256 EXACT_SHA256
```

Expected summary: `broker recovery committed; no remote mutation`.

Before writing authority, the command verifies the digest, immutable original
state, new pins, exact existing lightweight tag, draft ID/metadata and complete
retained asset IDs/names/sizes/downloaded hashes. It rechecks tag and draft after
downloads. It has only authenticated read/download calls; it cannot call tag or
draft creation, upload, deletion or publication.

Under the retained lock it writes immutable `latest/broker-recovery-v1.json` as
exactly the approved plan, preserving the entire original operation and its
hash. It atomically changes the active operation to the exact successor using
the normal descriptor-bound temporary/rename/fsync machinery. The successor's
required-proof marker makes lost/malformed/pending proof fail closed in staging,
release approval, publication and latest verification. Old operations without a
recovery proof retain their existing semantics.

After a crash, preserve everything. Ordinary commands reject a pending
transition. Only a separately reviewed exact `recover-broker` retry may settle
the approved original/successor pair and exact temporary candidate. An exact
completed transition is idempotent before later staging advances; recovery
never overwrites newer staging progress. Unknown/mixed plans, temporaries or
substituted records fail closed. One broker-recovery transition is supported;
a second tool change requires a separately reviewed recovery design.

## 3. Finish only the missing suffix

Stop for approval of each exact remaining upload (one invocation may cover all
explicitly listed uploads). With a complete recovery proof:

```text
catalog-publish stage-remote --state /ABSOLUTE/STATE --broker-config /ABSOLUTE/NEW_OUTER_CONFIG
```

Recovered staging never calls `CreateTag` or `CreateDraft`. It rejects a missing
or changed original tag/draft/asset instead of falling back to creation/upload.
It preserves the immutable baseline through every draft read, checks the exact
signed prefix, and uploads only missing suffix assets, with catalog last.
New suffix IDs are durably checkpointed before downloading them; these
observations are separate from the verified count. Failed downloads and later
retries cannot accept replaced IDs or re-upload disappeared observed assets.

Successful staging still emits `remote draft staged; explicit approval required`.
It writes the normal canonical draft receipt with the actual new operation and
broker pins. Recovered receipt IDs must equal the full observed inventory and
immutable baseline. Independently verify all server IDs and downloaded bytes.
Then stop before the normal exact-digest local approval and publication steps in
[release-runbook.md](release-runbook.md). A recovery plan is neither a draft
receipt nor release approval.

## Response parsing bounds

GitHub API JSON uses an 8192-node budget, distinct from the unchanged 1024-node
canonical config/request/typed-response budget. API responses still have the
128-KiB byte cap, depth16, per-collection256, string32-KiB and duplicate-key
restrictions. This handles realistic metadata-heavy multi-release responses
without broadening credential/config/protocol admission. Oversized or malformed
responses remain failures; never repeatedly retry a deterministic bound violation.

## Verification

`cargo test --offline --locked -p catalog-publish` covers real broker process
responses with four/five/seven assets, parser limits and malformed inputs,
seven-asset preservation, wrong digests/bindings, missing/mixed proofs, all
workflow readers, suffix failures, changed server IDs, separate approval and
publication, and real SIGKILL at proof creation and operation pre-rename,
post-rename and final-readback checkpoints. Test transports use fixture state;
none accesses production keys, credentials or live release state.
