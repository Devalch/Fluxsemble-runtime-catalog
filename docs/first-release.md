# First runtime catalog candidate

This document records public reproducibility evidence and the approved compatibility qualification for the unsigned sequence-1 candidate. It is not a production signature, publication, or remote-state receipt.

## Approved intent

- Sequence/tag: `1` / `catalog-v1-sequence-1`.
- Compatibility requirement: exactly `=0.1.0`.
- Provider/target: `builtin:pi` / `linux_x86_64`.
- Pi/Node: `0.83.0` / `22.19.0`.
- Release title/notes: `Pi 0.83.0` / `Approved managed Pi release.`
- Representative fixture freshness: `2026-08-26T00:00:00Z` through `2026-09-26T00:00:00Z`. These timestamps remain frozen Task 11 fixture inputs, not compatibility-reuse authority.
- Canonical intent: 55,798 bytes, raw SHA-256 `9d9d6023b95f1908edd51f7d08c04c85dc64e35a8c08866e45a2b2bdcfedd047`.
- Immutable semantic domain digest: `46116101d1ffa3b1184d14347f62478fbc3a2d609afc3ba0bf6b2505265e8441`.

## Authenticated public inputs

- Retained public corpus aggregate: SHA-256 `782b4b92d97b0573502424b3f966d3361313f62b69d31e3122e4938c3fd56ab2`.
- Package graph: one root plus exactly 139 sorted locked records; 131 pre-prune and 130 applicable locked packages.
- Canonical package-input manifest: 78,346 bytes, raw SHA-256 `d511e45be4fc28ec20c62c2450b61ab61e61fbbd12024a1e95698ab0b702a02d`, domain-separated SHA-256 `04ff8560de163983621e86598c8eb6b80fabb32cfced020602c14ed45818f9ef`.
- Root archive: 4,992,066 bytes, SHA-256 `7097fe4b38762dda7ec78001e7b90430c849fbaf717325bfe8109744e32255e6`.
- Root package manifest: 3,560 bytes, SHA-256 `e02deae1cec07035807436c1864c88342e2f7d49050d03b858a3719f0c7aedbf`.
- Shipped shrinkwrap: 61,540 bytes, SHA-256 `9a17a6b9ba0a57b37773644f7945b1bf0bc10aa8923b87233fee6f75af1e1772`.
- Node archive: 30,479,988 bytes, SHA-256 `c0649af18e6a24f6fe5535a3e86b341dd49a8e71117c8b68bde973ef834f16f2`.
- Node inventory `bin/node`: 121,674,800 bytes, SHA-256 `596b5144ff242737f1c1be6a5f0ccb3907dbba2482344143cb1a6898633402a9`.
- Pi inventory `dist/cli.js`: 681 bytes, SHA-256 `af302f231437eaf6f37691bce4b34234fcb626bcb5eb3910d4fc3f6519bf78ca`.

One-time comparison independently derived all 139 locator/name/version/URL/SRI/archive/declaration/applicability records from the authenticated corpus. Its canonical bytes equal both the committed input and credential-free public discovery byte-for-byte.

## Credential-free reacquisition and isolation

`catalog-acquire 0.1.0` reacquired every exact Node/npm object from the committed origins with no proxy or credential interface. Discovery returned 140 archives and the package-input SHA-256 above. Intent acquisition verified 143 digest-addressed public objects totaling 58,968,692 bytes. Both intent and final-source prepublication acquisition derive the two bootstrap support objects as bounded regular members of the already authenticated root archive, verify their catalog-declared size and SHA-256, and never fetch them from the not-yet-created sequence release. The complete transfer manifest SHA-256 is `902d26005b161dc18b0247d9eca100e73b9fded21cd4e11f7d7c4de710b5dcbf`; the verified-input record SHA-256 is `6daea1dde5e455f6bcfdd1f73721e47cdec45f2ed6e1b856ea41e5ad840ca79a`.

The production static `catalog-sign 0.1.0` executable used for keyless assembly had SHA-256 `8740b9ba8d4e3679d6a985543cf5ad796768918cc2d90919a232873a12601d3b`. The audited Bubblewrap executable had SHA-256 `139bf12775025adf5c8523d119c5ad2950281335573708fd839c60181a3886dc`. `assemble-intent` mounted no key and emitted one 55,797-byte mode-0400 candidate. Its reverse transfer manifest is bound to input digest `902d26005b161dc18b0247d9eca100e73b9fded21cd4e11f7d7c4de710b5dcbf` and assembly mode.

## Candidate and parity

- Canonical payload: 55,797 bytes, SHA-256 `7dba62c8b44883cbd7b3615fd9fe3b1a08a3aa2c75c7729704c14804d1cc2a2b`.
- Independent oracle, production isolated assembly, new `catalog-core 0.1.0`, and retained old producer all returned the same accepted sequence and payload digest.
- Retained old producer source: commit `5e021e8e4353a7993017dfaf0c0e9fa9e145b53f`; externally built `runtime-catalog` SHA-256 `7f62899a728ab1ebd751fa7f87a878da6c31bbf2e016ea7d1ccc8ed38644392f`.
- New producer predecessor: commit `fe038f59654fc6f11c7cbf8b2af357a3cde9bfc1`; the enclosing source commit contains the Task 11 inputs and vectors.
- Accept/reject matrix: the accepted candidate plus exact single-pointer schema, canonical-decimal, provider, target, version, closure-reference, artifact-size, and unknown-field failures; the canonical case/category/pointer/before/after/old/new matrix is 1,428 bytes with SHA-256 `2cd34eaba1a2e609719a69ddf1a628f7cadba9e76512132750e1559284ba18f8`.

## Fixture vectors and support assets

The exact candidate is also carried in a nonproduction fixture envelope whose key ID is exactly `catalog-test-key-v1`. Fixture verification accepts it; production verification rejects it.

- Fixture envelope: 55,994 bytes, SHA-256 `e5e239bf4b3c10841ffc3105f7788782b3376289be3e17b3ae82cef8081d972f`.
- Conformance manifest: 743 bytes, SHA-256 `fc9808c8228ed4cfeddbab96fb0f0327a8e1eb672c82df230ca021f14f840b7a`.
- Support asset `pi-package-e02deae1cec07035807436c1864c88342e2f7d49050d03b858a3719f0c7aedbf.json` uses its immutable sequence tag URL and exact 3,560-byte digest-bound bytes.
- Support asset `pi-shrinkwrap-9a17a6b9ba0a57b37773644f7945b1bf0bc10aa8923b87233fee6f75af1e1772.json` uses its immutable sequence tag URL and exact 61,540-byte digest-bound bytes.

## Final build qualification

The release owner approved the exact public qualification input and then the resulting domain-separated qualification digest. Qualification used Fluxsemble commit `6fade3f51846a112177d2c0d14206a504884c48c`, application SHA-256 `45a566b5b890ecd373c1b5e16c738a447a7fe34de32e02737859ce15da8eafdc`, daemon SHA-256 `f851c018703e46bc782cba34618a2e28d170ee3fbadd144bf33a9fe439e5fad9`, and compact profile SHA-256 `016f39ac96b41a78c5c394b67c5f2d058a59aa7e6891eed10322a061fc0921d5`.

- Compatibility-input SHA-256: `308d4ea3990f7b856b3ac025b4be2cc3ecf96b246721bbe99354c23fd7390057`.
- Qualification-record domain SHA-256: `27b5539f10ff306c56e1c0e38d284f6e47b52e38e567de4483099c7d6b645e2e`.
- Qualification record: 1,145 bytes, raw SHA-256 `5eddfb0e5f6fa2e51eb98e5eba1d3584ccbb7a051233bc0cebb0c8f64899f5cb`.
- Final source record: 56,421 bytes, raw SHA-256 `fd6912bb89356d5cdc9e3e8ec28919ee8c9e58ea05d7cec5f3a8fd7d1f380bc6`, domain-separated SHA-256 `2cf24067658991ee326ea5fe334568da09a8d3fdf8b5441ea70756ef2b774fb0`.
- Final source freshness: `2026-08-28T11:10:00Z` through `2026-09-28T11:10:00Z`; it begins after exact qualification-digest approval, and only these excluded freshness fields differ from the frozen representative intent.
- All required catalog conformance, managed installation, Node/Pi probe, Pi RPC readiness, activation, managed resolution, required-failure, and cancellation checks passed.
- Residual scope: only the initial Pi/Linux tuple is qualified, and rollback publication is not qualified for sequence 1.

No production key, credential, SSH state, remote mutation, production envelope, production tag, release, or publication was used or claimed.
