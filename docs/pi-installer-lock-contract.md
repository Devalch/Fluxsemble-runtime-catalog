# Pi installer-lock and qualification wire contract v1

This document owns the public `pi_installer_lock_v1` extension to catalog-v1.
The existing envelope, signatures, trusted origins, sequence and freshness rules
remain authoritative. The legacy `pi` / `shipped_shrinkwrap` extension retains
its original meaning: the Pi package itself is that legacy shrinkwrap's root.

The new parsers produce immutable, inert data. Successful parsing, a subject
hash, and even an all-pass qualification record do not authorize installation,
execution, publication, or display of an untrusted candidate. Consumer admission
must verify the original signed catalog, qualification descriptor bytes, subject,
required contracts, consumer version requirement, Node/target support, installed
inputs and probes through the respective owners. In the Task 1 implementation,
existing runtime/acquisition/signing paths explicitly reject the new extension;
Task 4 owns compatible consumer admission.

## Encoding and bounds

Every object has exactly the fields listed here. Duplicate keys, unknown fields,
unknown discriminants and noncanonical typed values are rejected at every nesting
level. Versions, package names, identifiers, decimal-string byte sizes, lowercase
64-hex SHA-256 digests, canonical SHA-512 registry integrity, credential-free and
query-free HTTPS URLs, and safe relative paths use the existing catalog-v1 types.
No field carries a command, environment, hook, credential or validation program.

Standalone profile input is at most 2 MiB (`MAX_PI_RELEASE_PROFILE_BYTES`);
qualification input is at most 64 KiB (`MAX_PI_QUALIFICATION_BYTES`). Standalone
metadata is at most their sum; each decoded profile's canonical encoding remains
at most 2 MiB, including when embedded in the existing bounded 8 MiB catalog.
Qualification descriptor size is positive and at most 64 KiB. Existing catalog
component/artifact/inventory/URL/name/path bounds apply. Locked packages are
nonempty and at most **512**, including the selected Pi package; the producer's
larger discovery ceiling never grants permission to publish a larger qualified
graph. Distinct origins are at most 16 for standalone metadata/profile parsing.

Standalone parsing checks URL syntax and consistency only. Parsing inside a
catalog additionally enforces the enclosing provider's signed `allowed_origins`
on every descriptor, artifact and resolved package URL. Parsing alone never
authorizes contacting any origin.

## Required contracts

`PiRequiredContractsV1` has these required fields:

| Key | Supported value/type |
| --- | --- |
| `installer_policy` | integer 1 |
| `lockfile_version` | integer 3 |
| `pi_rpc` | integer 1 |
| `pi_session` | integer 1 |
| `execution_payload` | integer 3 |
| `tool_wire` | integer 1 |
| `channel_layout` | integer 2 |
| `native_auth` | integer 1 |
| `resource_policy_sha256` | SHA-256 |
| `tool_policy_sha256` | SHA-256 |
| `execution_policy_sha256` | SHA-256 |

Unknown numeric contract versions fail structural parsing. Policy digests are
required, syntactically validated claims; matching them to supported policy is
an admission operation, not a parser operation. The behavioral profile ID is
`builtin-pi-installer-lock-contracts-v1`. The supported policy is independent of
the Pi release version, graph size, archive hashes and reference fixture pin.

Task 4 computes stable domain-separated canonical policy projections from their
actual Fluxsemble owners: tool policy from `crates/agent-tool-protocol`, generated
`wire-contract.json` tools/counting and bounds; execution policy from
`harness-pi/execution_protocol.rs::execution_wire_schemas` and generated
channel-layout/invocation/counting; resource policy from closed resource-loading
behavior and `PiInstructionProjection` (`crates/harness/src/launch.rs`) with the
generated execution.start InstructionsSchema/InstructionBlockSchema/
InstructionKindSchema definitions. Per-run execution-profile digests and
per-release first-party bundle hashes are not these behavioral policy digests.
The producer consumes the immutable public contract data, with no build/test/
runtime dependency on a Fluxsemble checkout.

## Release profile

`PiReleaseProfileV1` has exactly these required fields:

| Key | Type and meaning |
| --- | --- |
| `schema_version` | integer 1 |
| `pi_package` | `{name, version}` exact Pi package identity |
| `node_version` | exact Node version |
| `target` | catalog target; currently `linux_x86_64` |
| `consumer_requirement` | catalog semantic-version requirement string |
| `required_contracts` | object above |
| `installer_root` | `{name, version}` exact wrapper-root identity |
| `pi_package_locator` | exact top-level `node_modules/@earendil-works/pi-coding-agent` |
| `cli_entrypoint` | package-relative inventory path |
| `installer_manifest` | immutable descriptor `{url, size_bytes, sha256}` |
| `installer_lock` | immutable descriptor `{url, size_bytes, sha256}` |
| `pi_manifest` | immutable descriptor `{url, size_bytes, sha256}` |
| `components` | catalog-v1 component records `{component_id, version, artifacts}` |
| `pi_component_id`, `pi_artifact_id` | IDs selecting the Pi archive |
| `node_component_id`, `node_artifact_id` | IDs selecting the Node archive |
| `registry_integrity` | selected Pi archive's canonical SHA-512 integrity |
| `locked_packages` | exact package records described below |

Artifacts retain catalog-v1 fields `{artifact_id, url, size_bytes, sha256,
inventory}`; inventory records have `{path, size_bytes, sha256}`. Components sort
strictly by component ID, their artifacts sort strictly by artifact ID, and
artifact IDs are globally unique within the profile. Inventory paths are unique.
Node and Pi component IDs differ; their versions match `node_version` and
`pi_package.version`, respectively. Selected artifacts must exist. The Pi
entrypoint must occur exactly once in the Pi artifact inventory.

The package name is exactly `@earendil-works/pi-coding-agent`; its version is not
pinned by the parser. Initial supported Node is 22.19.0; exact-version parsing
alone does not imply that another Node version is executable. Node engine
compatibility and supported Node admission are subsequent verified operations.

The installer root has a distinct package name from Pi and is not a locked
package. The wrapper version is its own identity; it need not equal Pi's version.
Locked records have exactly `{locator, name, version, resolved_url,
registry_integrity, archive_sha256}`. They sort strictly by locator. Each locator
is a chain of `node_modules/<valid-package-name>` segments, ending in the record's
name, with no traversal or alias substitution. The selected Pi locator must
exist with the exact Pi identity; its URL, archive hash and registry integrity
match the selected Pi archive/profile. Repeated name/version identities at
other locators must have identical immutable URL/integrity/hash facts. Lockfile
bytes still require their own graph/input validation after acquisition; these
records alone are not proof that the lock selected that graph.

The enclosing release version equals the profile's Pi version and its components
equal the profile components exactly. The only decoded catalog target is the
same `linux_x86_64` as the profile. This prevents the outer catalog from binding
one archive while qualification binds another.

## Metadata and acyclic subject

The extension is `{ "kind": "pi_installer_lock_v1", "metadata": ... }`.
`PiInstallerLockMetadataV1` is exactly `{profile, qualification}`. `qualification`
is a required immutable file descriptor. It is deliberately absent from the
profile.

`pi_release_subject_sha256(profile)` computes:

```text
SHA256(UTF8("fluxsemble:pi-release-subject:v1") || 0x00 ||
       uint64_be(length(JCS(profile))) || JCS(profile))
```

JCS is RFC 8785. All typed profile fields, including every input descriptor,
required policy digest, version and locator, are included. No qualification
field is included. Thus a qualification record can bind the profile subject and
the final signed catalog can bind that qualification's descriptor without a
hash cycle. Existing legacy candidate-hash semantics are unchanged and remain
legacy-only.

## Qualification evidence

`PiReleaseQualificationV1` is exactly:

- `schema_version`: integer 1.
- `release_subject_sha256`: SHA-256 of the profile projection above.
- `required_contracts`: the required contracts object.
- `consumer_requirement`: catalog semantic-version requirement.
- `verification_build`: the object below.
- `results`: the five-result object below.

`verification_build` contains `consumer_version` (exact version),
`implementation_commit` (40 lowercase hex), `application_sha256`, `daemon_sha256`,
`compatibility_profile_id` (exactly `builtin-pi-installer-lock-contracts-v1`) and
`compatibility_profile_sha256`. The digest fields are SHA-256. These retain the
existing producer build-binding evidence fields while adding the tested consumer
version. They identify the tested build; they are not an equality requirement
against every installing application's executable, nor a requirement to rebuild
the consumer for each later compatible Pi release.

`results` contains exactly `installation`, `sdk_auth`, `session_resume`,
`streaming_tools` and `lifecycle`. Each is the finite string `pass` or `fail`.
Missing, extra, unknown and skipped results fail parsing. Failed evidence is
inertly parseable; `is_complete_pass()` is true only when every result passes.
Only later verified admission can bind complete passing evidence to trusted
inputs and support policy.

## Independent conformance data

Each repository admits its own immutable local copy of
`tests/fixtures/catalog/pi-installer-v1/`, consumed without access to the other
checkout. All fixtures are synthetic and do not qualify any actual runtime.
The local manifest records each vector's exact bytes and has a separate digest;
it excludes itself and its own digest to avoid a manifest cycle.

The admitted manifest SHA-256 is
`6664e33095f6e9b72b1d0931873b7b59be0ed00fae8e4c0f2bd25c1582835518`.

The `valid-wrapper-root` subject known answer is
`984bfc0dc24559f286cc12c248334318ce3ff50cc7fc5f01bb2aa15d88460133`.
Tests cover the positive wrapper, wrong Pi root, unsafe path, locator identity,
unknown contract, duplicate and nested unknown fields, missing qualification,
byte/count limits, outer release/origin bindings, qualification result closure,
a later Pi release, and subject changes while excluding the final qualification
descriptor. Subject expected bytes were calculated independently using sorted
compact JSON (the synthetic fixture contains only ASCII strings and small
integers, for which this equals JCS), uint64 big-endian length and SHA-256.
