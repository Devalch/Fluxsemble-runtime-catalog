# Catalog v1 wire contract

Status: normative producer contract for schema version 1.

Catalog v1 is signed data, not executable policy. An implementation MUST reject a payload that violates any rule below with a closed, non-echoing error. The checked-in `conformance/catalog-v1/valid-payload.json` file is an inert schema vector, not a production catalog or artifact source.

## Encoding, canonicalization, and signature input

The input is one UTF-8 JSON value no larger than 8 MiB. It MUST be an object, contain no trailing JSON, contain no duplicate object key at any depth, and contain no object key longer than 64 UTF-8 bytes. Unknown and missing fields are rejected. JSON strings must be valid Unicode. Values admitted by the typed model are JCS-safe: the only JSON numbers are the bounded integer constants `schema_version` and `lockfile_version`; sequence and byte counts are strings.

The signature input for a catalog payload is exactly the RFC 8785 JSON Canonicalization Scheme (JCS) serialization of the validated `CatalogPayloadV1`. The payload digest is SHA-256 over those same canonical bytes. Producers do not sign the source spelling, whitespace, or member order. A future signed envelope signs these payload bytes; an envelope is outside this payload contract.

## Root `CatalogPayloadV1`

The root admits exactly:

| Field | Type and rule |
|---|---|
| `schema_version` | JSON integer exactly `1`. |
| `sequence` | String containing canonical nonzero decimal `u64`: ASCII digits only, no sign or leading zero. Sequence values are monotonic publication generations. |
| `generated_at` | Canonical 20-byte UTC timestamp `YYYY-MM-DDTHH:MM:SSZ`; offsets and fractional seconds are rejected. |
| `expires_at` | Same canonical timestamp form as `generated_at`. Expiry-window and clock policy are applied by the consumer, not invented by this wire parser. |
| `compatibility_ranges` | 1–16 unique ASCII semantic-version requirements, each 1–128 bytes and accepted by the SemVer requirement grammar. |
| `providers` | 1–16 records, strictly sorted and unique by `provider_id`. |

The canonical release tag for a sequence is `catalog-v1-sequence-<sequence>`. Tags and sequences are no-replace; a correction uses a higher sequence. Tag construction and monotonic remote-state checks occur outside payload parsing.

## `CatalogProviderRecord`

Each provider record admits exactly:

| Field | Type and rule |
|---|---|
| `provider_id` | A `builtin:<id>` catalog ID. IDs are 3–191 ASCII bytes with 2–4 colon-separated segments; each segment is 1–64 bytes, begins and ends in lowercase ASCII alphanumeric, otherwise uses only lowercase alphanumeric, `-`, `_`, or `.`, and has no adjacent punctuation. Provider IDs have exactly two segments. |
| `allowed_origins` | 1–16 unique parsed HTTPS origins, each input at most 256 bytes. |
| `releases` | 1–64 records unique by (`version`, `target`). |

An allowed origin has HTTPS scheme, a host, no username/password, query, fragment, control, whitespace, or backslash, and path exactly `/`. It is normalized using URL origin serialization before duplicate checks and artifact authorization. Default ports and IDNA names therefore cannot create aliases.

## `CatalogReleaseRecord` and `PlainTextReleaseMetadata`

Each release admits exactly:

| Field | Type and rule |
|---|---|
| `version` | Exact SemVer string, 1–256 ASCII bytes, exactly three canonical decimal core components, optional valid prerelease and build identifiers, and no leading zero in numeric core or prerelease identifiers. |
| `target` | Exactly `linux_x86_64` in v1. |
| `compatibility_ranges` | Same 1–16 unique requirements as the root. |
| `release_metadata` | Object containing only `title` and `notes`. |
| `components` | 1–16 records strictly sorted and unique by `component_id`. Artifact IDs are additionally unique across the whole release. |
| `provider_extension` | Exactly one tagged extension described below. |

`release_metadata.title` is nonempty plain text no larger than 128 UTF-8 bytes and contains no control characters. `release_metadata.notes` is nonempty plain text no larger than 16,384 UTF-8 bytes; only tab, carriage return, and line feed are admitted control characters.

## `CatalogComponentRecord`, artifacts, and inventory

A component admits exactly:

| Field | Type and rule |
|---|---|
| `component_id` | Catalog ID using the grammar above. |
| `version` | Exact version using the grammar above. |
| `artifacts` | 1–8 descriptors strictly sorted and unique by `artifact_id`. |

An `ArtifactDescriptor` admits exactly:

| Field | Type and rule |
|---|---|
| `artifact_id` | Catalog ID using the grammar above. |
| `url` | Initial artifact URL under an `allowed_origins` entry, with rules below. |
| `size_bytes` | Canonical decimal `u64` string and nonzero. |
| `sha256` | Exactly 64 lowercase hexadecimal characters. |
| `inventory` | 0–32,768 entries unique by `path`. |

An `ArtifactInventoryEntry` admits exactly `path`, `size_bytes`, and `sha256`. Inventory `size_bytes` uses canonical decimal `u64` and may be zero. `sha256` uses the same lowercase digest form.

Every inventory `path` is 1–512 UTF-8 bytes, relative, slash-separated, contains no backslash or control character, and has no empty, `.` or `..` segment. This same path grammar is used for entrypoints and package locators.

Every initial artifact or metadata `url` is at most 2,048 bytes, has HTTPS scheme and a host, belongs to a declared parsed origin, and contains no username/password, query, fragment, control, ASCII whitespace, or backslash. Redirect policy is not represented in catalog v1. Query-bearing release-asset redirects, if separately authorized by a consumer transport profile, are never valid initial catalog URLs.

## `provider_extension`

The extension uses adjacent tagging with `kind` and, when required, `metadata`:

- `{ "kind": "none" }` is allowed only for a provider other than `builtin:pi`.
- `{ "kind": "pi", "metadata": { ... } }` is required for `builtin:pi`.

No other extension kind or metadata shape is admitted.

### `PiCatalogExtensionMetadata`

Pi `metadata` admits exactly:

| Field | Type and rule |
|---|---|
| `approved_package` | Exact package identity object with `name` and `version`. The name is exactly `@earendil-works/pi-coding-agent`; the version equals the release version. |
| `expected_entrypoint` | Safe inventory path present exactly once in the selected package artifact inventory. |
| `component_id` | Existing component ID whose component version equals the approved package version. |
| `package_artifact_id` | Existing artifact ID under that component. |
| `registry_integrity` | Canonical npm `sha512-` SRI for exactly 64 bytes, with canonical base64 and `==` padding (95 bytes total). |
| `root_package_manifest` | Immutable file descriptor. |
| `shipped_shrinkwrap` | Strict shipped shrinkwrap record. |

A package identity has only `name` and `version`. Package names are 1–214 ASCII bytes, contain no whitespace/control, and are either one valid lowercase package segment or `@scope/name`; segments use lowercase alphanumeric, `-`, `_`, or `.`, and are not `.` or `..`.

An `ImmutableFileDescriptor` admits exactly `url`, `size_bytes`, and `sha256`. Its initial URL follows the artifact URL/origin rules, its canonical decimal size is nonzero, and its digest is lowercase SHA-256.

### `ShippedShrinkwrapMetadata`

The shipped shrinkwrap admits exactly:

| Field | Type and rule |
|---|---|
| `lockfile_version` | JSON integer exactly `3`. |
| `root_package` | Package identity exactly equal to `approved_package`. |
| `artifact` | Immutable file descriptor for the shipped shrinkwrap bytes. |
| `locked_packages` | 0–512 records strictly sorted and unique by `locator`. |

A `LockedPackageRecord` admits exactly:

| Field | Type and rule |
|---|---|
| `locator` | Safe inventory path beginning `node_modules/`. |
| `name` | Valid package name. |
| `version` | Exact version. |
| `resolved_url` | Allowlisted query-free HTTPS initial URL. |
| `registry_integrity` | Canonical SHA-512 npm SRI. |
| `archive_sha256` | Lowercase SHA-256 digest. |

Repeated (`name`, `version`) identities at different locators must have identical `resolved_url`, `registry_integrity`, and `archive_sha256`. The approved root Pi package at the release version cannot appear as its own locked dependency.

## Rejection categories and authority boundary

Catalog v1 rejects malformed/trailing/duplicate JSON, oversized input, overlong keys, missing or unknown fields, wrong JSON types, unsupported versions/targets/extensions, noncanonical decimal/timestamp/version/digest/SRI forms, empty/over-limit collections, unsorted ID or package-locator records, duplicate records, invalid IDs/names/paths, incoherent Pi relationships, unallowlisted or unsafe URLs, and JCS-unsafe typed values.

The payload cannot admit executable or authority-bearing fields. In particular, `command`, `args`, `environment`, `cwd`, `destination`, `script`, `hook`, `provider_code`, `trust_key`, `sandbox_policy`, `executable_recipe`, `bridge_hash`, `helper_hash`, `executable_arguments`, `installer_behavior`, or `pi_dependency` are unknown fields and MUST be rejected wherever supplied. No command, environment, hook, destination, provider code, key, credential, installer recipe, or executable argument may cross this data boundary.
