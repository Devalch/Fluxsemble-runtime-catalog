# Guided runtime catalog release

Run `catalog-wizard release` from a clean, committed checkout. The wizard selects the next sequence after verifying the latest published catalog and checking for conflicting tags and drafts. Choose a Pi version, confirm Node 22.19.0, and select dry-run or publish.

The producer discovers the exact upstream installer inputs, verifies their hashes and dependency graph, and independently replays those checks in the isolated signer. It does not require or assert a consumer build or compatibility qualification. A dry run stops before signing or publication. Consumer compatibility is checked separately by the consumer's owner.

The publish workflow shows the tag, draft and asset steps and verifies the published bytes through GitHub's latest endpoint. See [the V2 producer contract](pi-installer-lock-contract.md) and [release runbook](release-runbook.md) for artifact and release details.

Run `catalog-wizard trust-machine` and `catalog-wizard check` for first-time setup. Use `catalog-wizard resume` after an interruption. A historical schema-2 wizard state that awaited qualification must be preserved and archived before preparing a new producer-only release; it cannot be resumed as a new workflow.
