# Runtime catalog release runbook

This runbook describes the reviewed commands. It does **not** claim that the transport fixture, a production draft, or a production release exists.

## Non-negotiable stops

Automation and agents stop before:

1. any production signing-key access or signing ceremony;
2. the `transport-v1` tag mutation;
3. transport-fixture draft creation;
4. transport-fixture asset upload;
5. transport-fixture publication;
6. a production `catalog-v1-sequence-N` tag mutation;
7. production draft creation;
8. every production asset upload or resumed remote staging step;
9. the local approval transition;
10. publication of the exact approved release.

Only the release owner can authorize the next exact step. Authorization for one mutation does not authorize a later mutation. Never place a key, token, credential, header, SSH path, or GitHub configuration content in a command, receipt, issue, chat, or log.

On every stop the owner reviews:

- repository exactly `Devalch/Fluxsemble-runtime-catalog`;
- clean reviewed source commit and tree digest;
- sequence and canonical tag;
- broker executable identity and owner-private broker-config SHA-256;
- release ID, tag target, title, notes, `draft` and `prerelease` state;
- ordered asset names, public IDs, sizes, and SHA-256 values;
- local operation, draft, approval, publication, and latest receipt digests.

A failure is preserved. Do not delete, replace, clobber, retag, recreate, or administratively repair a tag, release, or asset with this tool. Escalate unexpected or ambiguous state to the release owner and GitHub repository administrator. Corrections use a higher production sequence.

## 1. Verify and stage the signed public transfer

The signing ceremony is separately authorized and isolated. Agents stop before key use. After the owner has transferred a signed public bundle out of the isolated signer:

```text
catalog-publish verify-bundle --bundle /ABSOLUTE/OWNER-PRIVATE/SIGNED_TRANSFER
catalog-publish stage-local --bundle /ABSOLUTE/OWNER-PRIVATE/SIGNED_TRANSFER --state /ABSOLUTE/OWNER-PRIVATE/STATE
```

Expected safe summaries contain only the sequence and signed-transfer SHA-256. Local state remains owner-private and contains immutable digest objects plus the exact latest reference. If local recovery is reported, do not stage another candidate:

```text
catalog-publish recover-local --state /ABSOLUTE/OWNER-PRIVATE/STATE
```

Expected safe output is exactly `recovery committed` or `recovery aborted`. Recovery accepts no candidate and performs no network or remote action.

Before any remote step, independently verify that local recovery is clear and review the canonical `latest/catalog-v1.ref` operation ID, source commit/tree, sequence/tag, catalog digest, signed inventory, checksums, and assets.

## 2. Harmless permanent transport prerelease

The committed manifest is exactly `conformance/transport/manifest-v1.json`. It fixes repository, tag `transport-v1`, title `Fluxsemble runtime catalog transport fixture v1`, `draft=true`, `prerelease=true`, and the single digest-bound `github-release-asset-v1.txt`. It contains no catalog, runtime archive, key, credential, private path, or production tag.

The owner first reviews the manifest and asset bytes/digest, broker executable/config digest, and exact reviewed 40-character source commit. Then stop separately before tag, draft, upload, and publication. Only after those exact mutations are authorized, run:

```text
catalog-publish publish-transport-fixture --source-commit FULL_REVIEWED_COMMIT_SHA --broker-config /ABSOLUTE/OWNER-PRIVATE/BROKER_CONFIG
```

Expected safe output after all exact readbacks is `transport fixture prerelease published`. The command creates no replacement and refuses any nonexact existing tag, release metadata, asset set, ID, size, or downloaded bytes. A failure may have left an exact tag, draft, or asset; preserve it and rerun only after owner review. Never infer that the fixture exists from this runbook.

## 3. Stage the production draft

The owner reviews and explicitly authorizes the exact production tag mutation, then draft mutation, then each ordered upload. `stage-remote` is resumable, but one invocation can reach several remote mutation stops; operational authorization must therefore cover each exact mutation listed in its already-reviewed operation record and asset inventory before invocation.

```text
catalog-publish stage-remote --state /ABSOLUTE/OWNER-PRIVATE/STATE --broker-config /ABSOLUTE/OWNER-PRIVATE/BROKER_CONFIG
```

Before its first mutation the tool writes owner-private canonical `latest/remote-operation-v1.json`, binding the local operation, broker-config digest, repository, source, sequence/tag, release metadata, and ordered inventory. It creates or exact-resumes the lightweight tag, verifies the commit object, exact-resumes or creates one draft non-prerelease release, uploads support assets first and `catalog-v1.json` last, and reads the same draft immediately before and after every tag-authorized upload. Every asset is downloaded and hash-verified.

Expected safe completion is:

```text
remote draft staged; explicit approval required
```

Completion writes no-clobber mode-`0400` `latest/draft-receipt-v1.json`. Stop. The release remains `draft=true`, `prerelease=false`. Independently inspect GitHub read-only state and compare repository, tag commit/object type, release ID/target/title/notes/state, every asset ID/name/size/digest, signed bundle/local operation digest, and broker-config digest to the receipt.

A remote failure reports uncertainty or recovery required and preserves the operation record plus remote tag/draft/assets. Do not delete or replace anything. Review the recorded phase and current remote readback before an exact retry.

## 4. Explicit local approval

The human computes SHA-256 over the exact canonical draft receipt outside the tool, compares it with the reviewed bytes, and explicitly authorizes the local approval transition. There is no interactive prompt and no broker/network input.

```text
catalog-publish approve --state /ABSOLUTE/OWNER-PRIVATE/STATE --draft-receipt-sha256 LOWERCASE_64_HEX
```

Expected output is `release approval recorded`. The tool writes no-clobber mode-`0400` `latest/release-approval-v1.json`, binding approved status, complete draft-receipt digest/body ID, repository, release ID, tag/source, local/remote operation IDs, and every asset. A mismatch creates no approval.

Stop again before publication. Review the approval digest and exact approval path:

```text
/ABSOLUTE/OWNER-PRIVATE/STATE/latest/release-approval-v1.json
```

## 5. Publish the exact approved draft

After explicit release-owner authorization for this release ID only:

```text
catalog-publish publish --state /ABSOLUTE/OWNER-PRIVATE/STATE --approval /ABSOLUTE/OWNER-PRIVATE/STATE/latest/release-approval-v1.json --broker-config /ABSOLUTE/OWNER-PRIVATE/BROKER_CONFIG
```

The command reopens and verifies local state, approval, receipt, config digest, tag, exact draft metadata, IDs, inventory, and downloaded bytes. It calls only `publish_draft` for the approved release ID. It then requires the same release with `draft=false`, `prerelease=false` and unchanged metadata/assets.

Before any public-latest request it durably writes `latest/publication-receipt-v1.json` with phase `published_latest_pending`. It then fetches only:

```text
https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/latest/download/catalog-v1.json
```

The fixed catalog-acquire transport is credential-free, no-proxy, redirect bounded, and content size/SHA bound. Expected safe completion is `release published and latest verified`; `latest/latest-receipt-v1.json` records the exact local immutable catalog object identity returned by latest.

If publication succeeded but latest verification failed, do not republish or mutate the release. Preserve the publication receipt and retry only fixed credential-free verification:

```text
catalog-publish verify-latest --state /ABSOLUTE/OWNER-PRIVATE/STATE
```

Expected output is `public latest verified`. This command accepts no broker config, credential, repository, URL, or network option.

## Escalation checklist

Escalate and stop on any annotated/wrong tag, commit mismatch, missing or duplicate release, release-ID change, target/title/notes/state drift, partial or extra asset, changed asset ID/name/size/bytes, download mismatch, broker-config digest mismatch, approval mismatch, publish uncertainty, latest mismatch, timeout, or local record/temp contradiction.

Retain owner-private state and all safe public receipts. Record only public IDs/digests and fixed error categories. Never include credentials, queries from release-asset redirects, raw child output, private paths, key material, or private configuration contents in escalation evidence.
