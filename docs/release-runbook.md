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
- owner-private broker-client config SHA-256, retained `catalog-gh-broker` executable SHA-256, and inner Task 9 broker-config SHA-256;
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

Every `--broker-config` below names the outer mode-`0600` canonical `PublisherBrokerClientConfigV1`, not the credential-bearing Task 9 config. It contains only the canonical absolute `catalog-gh-broker` path/digest and canonical absolute inner Task 9 config path/digest. In both client and broker traversal, a user-owned ancestor must be exact mode `0700` or `0755`; `0750`, `0751`, writable, and all other user-owned modes are rejected, while root-owned ancestor modes are unchanged. The configured GitHub CLI directory likewise permits exact owner mode `0700` or `0755`, but config and credential files remain exact `0600`. The publication process never opens the GitHub config directory; each typed request launches the retained broker executable as a separate process and the broker independently checks the supplied pinned inner digest before authenticated authority.

The committed manifest is exactly `conformance/transport/manifest-v1.json`. It fixes repository, tag `transport-v1`, title `Fluxsemble runtime catalog transport fixture v1`, `draft=true`, `prerelease=true`, and the single digest-bound `github-release-asset-v1.txt`. It contains no catalog, runtime archive, key, credential, private path, or production tag.

The owner first reviews the manifest and asset bytes/digest, all three broker client/executable/inner-config digests, and exact reviewed 40-character source commit. Then stop separately before tag, draft, upload, and publication. Only after those exact mutations are authorized, run:

```text
catalog-publish publish-transport-fixture --state /ABSOLUTE/OWNER-PRIVATE/STATE --source-commit FULL_REVIEWED_COMMIT_SHA --broker-config /ABSOLUTE/OWNER-PRIVATE/BROKER_CONFIG
```

Expected safe output after all exact readbacks is `transport fixture prerelease published`. This command alone atomically creates or reopens a dedicated owner-private mode-`0700` state at `--state`; it does not use or require the signed Task 8 production state. Its exact layout is empty `objects/` plus `latest/`, whose only admitted entries are the mode-`0600` `latest/.remote-workflow-v1.lock` and canonical mode-`0400` `transport-operation-v1.json` and `transport-receipt-v1.json`. State directories accept either their conventional exact link count or the filesystem-portable directory count `1`; exact bounded enumeration and child validation remain authoritative, and every regular file still requires its exact link count. The broker applies the same `1`-or-conventional rule only to its fresh empty mode-`0700` owner-private directories; upload staging and temporary HOME never admit `0755`. State-record creation prefers `O_TMPFILE` plus a no-clobber link. Only unsupported-filesystem `EOPNOTSUPP`/`ENOTSUP` or `EINVAL` permits a direct final-name `O_CREAT|O_EXCL|O_NOFOLLOW` fallback; existing names and all permission, I/O, corruption, or unexpected errors fail closed. The fallback writes mode `0600`, flushes, changes to `0400`, fsyncs file and parent, and reopens for exact inode/device, owner, one-link mode, size, and byte readback. It never overwrites, renames, deletes, or cleans up. A crash or short write leaves the partial final file and grants no remote authority. Preserve that state; after owner review use a fresh dedicated transport state for exact public settlement because transport operation identity is state-path-independent. The operation binds only repository, reviewed source commit, fixed manifest SHA-256, broker-client config SHA-256, broker executable SHA-256, and inner Task 9 config SHA-256. A catalog reference, signed transfer, production signature, package asset, latest receipt, production operation/receipt, temporary, or unknown entry fails closed.

The command holds the dedicated state's retained descriptor-bound lock across every remote decision, mutation, readback, and receipt. It creates no replacement and refuses any nonexact existing tag, release metadata, asset set, ID, size, or downloaded bytes. A failure may have left an exact tag, draft, or asset; preserve it and rerun only after owner review. Never infer that the fixture exists from this runbook. Production `stage-remote`, `approve`, `publish`, and `verify-latest` remain unchanged and still require the separately staged, production-signed Task 8 state.

## 3. Stage the production draft

The owner reviews and explicitly authorizes the exact production tag mutation, then draft mutation, then each ordered upload. `stage-remote` is resumable, but one invocation can reach several remote mutation stops; operational authorization must therefore cover each exact mutation listed in its already-reviewed operation record and asset inventory before invocation.

```text
catalog-publish stage-remote --state /ABSOLUTE/OWNER-PRIVATE/STATE --broker-config /ABSOLUTE/OWNER-PRIVATE/BROKER_CONFIG
```

Before its first mutation the tool acquires and rebinds the fixed mode-`0600`, one-link `latest/.remote-workflow-v1.lock`, then writes owner-private canonical `latest/remote-operation-v1.json`, binding the local operation, broker-client config digest, retained broker executable digest, inner Task 9 config digest, repository, source, sequence/tag, release metadata, and ordered inventory. Exact retries validate and settle only a canonical same-operation temporary record at its authorized next phase; malformed, replaced, skipped, backward, or conflicting temporaries are preserved as uncertain. It creates or exact-resumes the lightweight tag, verifies the commit object, exact-resumes or creates one draft non-prerelease release, uploads support assets first and `catalog-v1.json` last, and reads the same draft immediately before and after every tag-authorized upload. GitHub may return the same assets in a different vector order, so each readback must equal the duplicate-free locally authorized name/size set for that phase, preserve all prior name/ID/size tuples, and add only the one newly authorized asset; receipt order remains the signed local order. Every asset is downloaded by its name-bound remote ID and hash-verified.

Expected safe completion is:

```text
remote draft staged; explicit approval required
```

Completion writes no-clobber mode-`0400` `latest/draft-receipt-v1.json`. Stop. The release remains `draft=true`, `prerelease=false`. Independently inspect GitHub read-only state and compare repository, tag commit/object type, release ID/target/title/notes/state, every asset ID/name/size/digest, signed bundle/local operation digest, and all three operation-pinned broker digests to the receipt.

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

The dedicated async `catalog-latest-transport` capability is credential-free, no-proxy, Rustls-only, redirect bounded, content size/SHA bound, and has no URL/origin/method/header input or runtime creation. Expected safe completion is `release published and latest verified`; `latest/latest-receipt-v1.json` records the exact local immutable catalog object identity returned by latest.

If publication succeeded but latest verification failed, do not republish or mutate the release. Preserve the publication receipt and retry only fixed credential-free verification:

```text
catalog-publish verify-latest --state /ABSOLUTE/OWNER-PRIVATE/STATE
```

Expected output is `public latest verified`. This command accepts no broker config, credential, repository, URL, or network option.

## Escalation checklist

Escalate and stop on any annotated/wrong tag, commit mismatch, missing or duplicate release, release-ID change, target/title/notes/state drift, partial or extra asset, changed asset ID/name/size/bytes, download mismatch, broker-config digest mismatch, approval mismatch, publish uncertainty, latest mismatch, timeout, or local record/temp contradiction.

Retain owner-private state and all safe public receipts. Record only public IDs/digests and fixed error categories. Never include credentials, queries from release-asset redirects, raw child output, private paths, key material, or private configuration contents in escalation evidence.
