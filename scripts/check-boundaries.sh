#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import json
import subprocess
import sys

metadata = json.loads(subprocess.check_output([
    "cargo", "metadata", "--no-deps", "--format-version", "1"
], text=True))

expected_names = [
    "catalog-acquire",
    "catalog-core",
    "catalog-publish",
    "catalog-sign",
]
packages = {pkg["name"]: pkg for pkg in metadata["packages"]}
actual_names = sorted(packages)
if actual_names != expected_names:
    print(f"unexpected package set: {actual_names}", file=sys.stderr)
    sys.exit(1)

workspace_names = set(expected_names)
expected_internal_deps = {
    "catalog-core": [],
    "catalog-acquire": [("catalog-core", "normal")],
    "catalog-sign": [("catalog-core", "normal")],
    "catalog-publish": [("catalog-core", "normal")],
}
expected_external_deps = {
    "catalog-core": [
        ("chrono", "normal"),
        ("ed25519-dalek", "normal"),
        ("hex", "dev"),
        ("semver", "normal"),
        ("serde", "normal"),
        ("serde_jcs", "normal"),
        ("serde_json", "normal"),
        ("sha2", "normal"),
        ("url", "normal"),
    ],
    "catalog-acquire": [
        ("base64", "normal"),
        ("flate2", "normal"),
        ("libc", "normal"),
        ("reqwest", "normal"),
        ("serde", "normal"),
        ("serde_jcs", "normal"),
        ("serde_json", "normal"),
        ("sha2", "normal"),
        ("tokio", "normal"),
        ("xz2", "normal"),
    ],
    "catalog-sign": [
        ("ed25519-dalek", "normal"),
        ("libc", "normal"),
        ("serde", "normal"),
        ("serde_jcs", "normal"),
        ("serde_json", "normal"),
        ("sha2", "normal"),
        ("subtle", "normal"),
        ("zeroize", "normal"),
    ],
    "catalog-publish": [],
}

def dependency_key(dependency):
    return (dependency["name"], dependency["kind"] or "normal")

for name in expected_names:
    dependencies = packages[name]["dependencies"]
    internal = sorted(
        dependency_key(dependency)
        for dependency in dependencies
        if dependency["name"] in workspace_names
    )
    external = sorted(
        dependency_key(dependency)
        for dependency in dependencies
        if dependency["name"] not in workspace_names
    )
    if internal != expected_internal_deps[name]:
        print(f"unexpected internal dependencies for {name}: {internal}", file=sys.stderr)
        sys.exit(1)
    if external != expected_external_deps[name]:
        print(f"unexpected external dependencies for {name}: {external}", file=sys.stderr)
        sys.exit(1)
PY

python3 - <<'PY'
from pathlib import Path
import re
import sys

acquire_root = Path("crates/catalog-acquire")
forbidden_literals = [
    "SigningKey",
    "DecodePrivateKey",
    "pkcs8",
    "private.pem",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "gh auth",
]
key_flag = re.compile(r"--(?:[a-z0-9]+-)*(?:private-|signing-)?key(?:[= ]|\b)", re.IGNORECASE)
direct_verifier = re.compile(r"(?:ed25519[_-]dalek|VerifyingKey)")

for path in sorted(acquire_root.rglob("*")):
    if not path.is_file():
        continue
    try:
        source = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    if any(value in source for value in forbidden_literals):
        print(f"forbidden signing or GitHub credential interface in {path}", file=sys.stderr)
        sys.exit(1)
    if key_flag.search(source):
        print(f"forbidden key-related CLI flag in {path}", file=sys.stderr)
        sys.exit(1)
    if direct_verifier.search(source):
        print(f"catalog-acquire must use catalog-core public verification in {path}", file=sys.stderr)
        sys.exit(1)
PY

python3 - <<'PY'
from pathlib import Path
import re
import sys

sign_manifest = Path("crates/catalog-sign/Cargo.toml").read_text(encoding="utf-8")
for forbidden in [
    "catalog-acquire",
    "catalog-publish",
    "reqwest",
    "tokio",
    "hyper",
    "ureq",
    "curl",
    "openssh",
]:
    if forbidden in sign_manifest:
        print(f"forbidden signer dependency/capability: {forbidden}", file=sys.stderr)
        sys.exit(1)

main_source = Path("crates/catalog-sign/src/main.rs").read_text(encoding="utf-8")
lib_source = Path("crates/catalog-sign/src/lib.rs").read_text(encoding="utf-8")
for forbidden in ["catalog-test-key-v1", "nonproduction-ed25519-pkcs8.pem"]:
    if forbidden in main_source or forbidden in lib_source:
        print(f"fixture authority in production signer surface: {forbidden}", file=sys.stderr)
        sys.exit(1)
if "fixture-tools" in main_source:
    print("fixture CLI feature in production signer", file=sys.stderr)
    sys.exit(1)

capability_patterns = [
    re.compile(pattern)
    for pattern in [
        r"\bstd::net\b",
        r"\btokio::net\b",
        r"\b(?:TcpStream|TcpListener|UdpSocket)\b",
        r"\bstd::process::Command\b",
        r"\bCommand::new\s*\(",
        r"\blibc::(?:socket|connect|bind|listen|accept|fork|exec[a-z]*|posix_spawn|system|popen)\b",
    ]
]

def signer_boundary_errors(sources):
    errors = []
    for name, source in sources.items():
        for pattern in capability_patterns:
            if pattern.search(source):
                errors.append(f"network/process-launch capability in {name}: {pattern.pattern}")
    key_source = sources["crates/catalog-sign/src/key.rs"]
    required_zeroizing = [
        "let mut pem = Zeroizing::new(Vec::with_capacity(",
        "let mut encoded = Zeroizing::new(Vec::with_capacity(128))",
        "fn decode_standard_base64(encoded: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignError>",
        "fn encode_standard_base64(bytes: &[u8]) -> Zeroizing<String>",
        "let mut seed = Zeroizing::new([0_u8; 32])",
    ]
    for required in required_zeroizing:
        if required not in key_source:
            errors.append(f"missing private-derived zeroizing boundary: {required}")
    forbidden_private_sinks = [
        re.compile(r"fn encode_standard_base64\(bytes: &\[u8\]\) -> String"),
        re.compile(r"let\s+(?:mut\s+)?(?:pem|der|seed|encoded)\s*=\s*(?:Vec|String)::"),
        re.compile(r"let\s+(?:mut\s+)?der\s*=.*\.to_vec\(\)"),
    ]
    for pattern in forbidden_private_sinks:
        if pattern.search(key_source):
            errors.append(f"non-zeroizing private-derived sink: {pattern.pattern}")
    return errors

sign_sources = {
    str(path): path.read_text(encoding="utf-8")
    for path in sorted(Path("crates/catalog-sign/src").glob("*.rs"))
}
errors = signer_boundary_errors(sign_sources)
if errors:
    print(errors[0], file=sys.stderr)
    sys.exit(1)

# Mutation-style assertions prove both new structural boundaries fail closed.
key_name = "crates/catalog-sign/src/key.rs"
zeroizing_mutation = dict(sign_sources)
zeroizing_mutation[key_name] = zeroizing_mutation[key_name].replace(
    "fn encode_standard_base64(bytes: &[u8]) -> Zeroizing<String>",
    "fn encode_standard_base64(bytes: &[u8]) -> String",
    1,
)
if not signer_boundary_errors(zeroizing_mutation):
    print("zeroizing boundary scanner accepted an ordinary String mutation", file=sys.stderr)
    sys.exit(1)

capability_mutation = dict(sign_sources)
capability_mutation["crates/catalog-sign/src/lib.rs"] += (
    "\nfn forbidden_mutation() { let _ = std::process::Command::new(\"true\"); }\n"
)
if not signer_boundary_errors(capability_mutation):
    print("signer capability scanner accepted a process-launch mutation", file=sys.stderr)
    sys.exit(1)

core_source = Path("crates/catalog-core/src/signature.rs").read_text(encoding="utf-8")
for forbidden in ["PRIVATE KEY", "DecodePrivateKey", "from_pkcs8", "read_signing_key"]:
    if forbidden in core_source:
        print(f"private-key parser in catalog-core: {forbidden}", file=sys.stderr)
        sys.exit(1)

generator_source = Path("scripts/generate-approved-release-evidence.py").read_text(
    encoding="utf-8"
)
signing_source = sign_sources["crates/catalog-sign/src/signing.rs"]
key_source = sign_sources["crates/catalog-sign/src/key.rs"]
retained_tar_call = 'tarfile.open(fileobj=expanded, mode="r:") as opened:'

# Each entry names one exact enforcement expression at its authority seam. The
# self-mutations below remove that expression and require the scanner to reject
# the result, rather than searching for a broad token that may remain elsewhere.
python_reader_policies = [
    (
        "file expected-owner comparison",
        "and stat.S_ISREG(metadata.st_mode)\n        and metadata.st_uid == expected_owner",
        1,
    ),
    (
        "file production current effective owner",
        "metadata, expected_size, maximum_size, os.geteuid()",
        1,
    ),
    (
        "directory expected-owner comparison",
        "stat.S_ISDIR(metadata.st_mode)\n        and metadata.st_uid == expected_owner",
        1,
    ),
    (
        "directory exact safe mode set",
        "SAFE_PUBLIC_DIRECTORY_MODES = frozenset((0o700, 0o755))",
        1,
    ),
    (
        "directory production current effective owner",
        "_public_directory_policy_matches(metadata, os.geteuid())",
        1,
    ),
    (
        "authenticated-root directory policy invocation",
        "_require_public_directory(os.fstat(descriptor), str(path))",
        1,
    ),
    (
        "per-relative-component directory policy invocation",
        "_require_public_directory(\n                    os.fstat(parent), f\"{self._label}/{component}\"\n                )",
        1,
    ),
    (
        "absolute-root component-wise retained traversal",
        "next_descriptor = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)",
        1,
    ),
    ("single link", "and metadata.st_nlink == 1", 1),
    (
        "exact safe mode",
        "and stat.S_IMODE(metadata.st_mode) in SAFE_PUBLIC_FILE_MODES",
        1,
    ),
    ("declared maximum size", "0 < expected_size <= maximum_size", 1),
    ("exact pre-read size", "and metadata.st_size == expected_size", 1),
    ("digest verification", "if sha256(data) != expected_sha256:", 1),
    (
        "pre/post descriptor identity",
        "if _metadata_snapshot(before) != _metadata_snapshot(after):",
        1,
    ),
    (
        "retained final-name identity",
        "if _metadata_snapshot(before) != retained_name_snapshot:",
        1,
    ),
    (
        "full-relative-path identity",
        "if _metadata_snapshot(before) != full_path_snapshot:",
        1,
    ),
    (
        "directory no-follow capability",
        "_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC",
        1,
    ),
    (
        "file no-follow nonblocking capability",
        "_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK",
        1,
    ),
    (
        "component-wise beneath traversal",
        "child = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)",
        1,
    ),
    (
        "bounded read",
        "chunk = os.read(file_descriptor, min(64 * 1024, remaining))",
        1,
    ),
    ("one-byte excess probe", "probe = os.read(file_descriptor, 1)", 2),
    (
        "JSON depth and node bounds",
        "if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:",
        1,
    ),
    (
        "JSON collection bounds",
        "if len(current) > MAX_COLLECTION_MEMBERS:",
        2,
    ),
    ("JSON structural-bound invocation", "validate_collection_bounds(value)", 1),
    (
        "cumulative decompression bound",
        "if expanded_size > maximum_expanded_bytes:",
        1,
    ),
    (
        "cumulative decompression accounting",
        "expanded_size = _write_expanded_chunk(",
        2,
    ),
    (
        "bounded decompressor output",
        "maximum_expanded_bytes - expanded_size + 1,",
        2,
    ),
    (
        "anonymous expanded archive descriptor",
        'output = tempfile.TemporaryFile(mode="w+b")',
        1,
    ),
    (
        "bounded decompression invocation",
        "expanded, expanded_size = _decompress_archive_to_temporary(",
        1,
    ),
    (
        "exact gzip support",
        'if archive_bytes.startswith(b"\\x1f\\x8b"):',
        1,
    ),
    (
        "exact XZ support",
        'elif archive_bytes.startswith(b"\\xfd7zXZ\\x00"):',
        1,
    ),
    (
        "compressed exact-size authentication",
        "len(archive_bytes) != expected_archive_size",
        1,
    ),
    (
        "compressed digest authentication",
        "sha256(archive_bytes) != expected_archive_sha256",
        1,
    ),
    (
        "raw all-member validation invocation",
        "with expanded:\n        _validate_raw_tar_placement(",
        1,
    ),
    (
        "raw all-member size bound",
        "if size > maximum_member_bytes:",
        1,
    ),
    (
        "raw all-member offset validation",
        "if offset % tarfile.BLOCKSIZE != 0 or offset + tarfile.BLOCKSIZE > expanded_size:",
        1,
    ),
    (
        "raw type-related size semantics",
        "if size != 0:",
        1,
    ),
    (
        "raw padded-end placement",
        "or padded_end > expanded_size\n            or padded_end > maximum_expanded_bytes",
        1,
    ),
    (
        "yielded all-member size and offset validation",
        "or member.offset_data < member.offset + tarfile.BLOCKSIZE",
        1,
    ),
    (
        "yielded type-related size semantics",
        "if not member.isfile() and member.size != 0:",
        1,
    ),
    (
        "all-member validation before target matching",
        "previous_padded_end = _validate_yielded_member(",
        1,
    ),
    ("raw and yielded member-count bounds", "if member_count > maximum_members:", 2),
    ("target regular-file requirement", "not matched.isfile()", 1),
    ("target exact-size requirement", "or matched.size != expected_member_size", 1),
    ("bounded target extraction", "data = extracted.read(expected_member_size)", 1),
    ("target one-byte excess probe", "probe = extracted.read(1)", 1),
    ("target digest verification", "or sha256(data) != expected_member_sha256", 1),
]

rust_reader_policies = [
    (
        "file production current effective owner",
        "secure_public_corpus_file_for_owner(metadata, current_euid())",
        1,
    ),
    (
        "directory production current effective owner",
        "secure_public_corpus_directory_for_owner(metadata, current_euid())",
        1,
    ),
    (
        "file expected-owner comparison",
        "metadata.is_file()\n            && !metadata.file_type().is_symlink()\n            && metadata.uid() == expected_owner",
        1,
    ),
    (
        "directory expected-owner comparison",
        "metadata.is_dir()\n            && !metadata.file_type().is_symlink()\n            && metadata.uid() == expected_owner",
        1,
    ),
    ("directory exact safe modes", "0o700 | 0o755", 1),
    (
        "root admission directory-policy invocation",
        "let metadata = root.metadata().map_err(|_| bundle_rejected())?;\n            if !secure_public_corpus_directory(&metadata)",
        1,
    ),
    (
        "retained-root directory-policy revalidation",
        "let metadata = self.root.metadata().map_err(|_| bundle_rejected())?;\n            if !secure_public_corpus_directory(&metadata)",
        1,
    ),
    (
        "retained root revalidation before traversal",
        "let mut parent = self.validated_root()?;",
        1,
    ),
    (
        "component-wise retained-directory open",
        "let child = openat2(\n                        parent.as_raw_fd(),\n                        &component,\n                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,",
        1,
    ),
    (
        "retained-directory close-on-exec flags",
        "libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,",
        1,
    ),
    (
        "component directory no-magic-link/no-symlink/beneath resolution",
        "libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,\n                        // RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH.\n                        0x02 | 0x04 | 0x08,",
        1,
    ),
    (
        "per-component directory-policy invocation",
        "let metadata = child.metadata().map_err(|_| bundle_rejected())?;\n                    if !secure_public_corpus_directory(&metadata)",
        1,
    ),
    ("single link", "&& metadata.nlink() == 1", 1),
    (
        "exact safe mode",
        "0o400 | 0o444 | 0o600 | 0o644",
        1,
    ),
    (
        "maximum size before read",
        "|| expected_size > MAX_AUTHENTIC_CORPUS_OBJECT_BYTES",
        1,
    ),
    (
        "exact size before read",
        "if !secure_public_corpus_file(&before) || before.len() != expected_size",
        1,
    ),
    ("digest verification", "|| sha256(&bytes) != expected_sha256", 1),
    (
        "pre/post descriptor identity",
        "|| PublicCorpusMetadata::from_metadata(&after) != before",
        1,
    ),
    (
        "retained final-name identity",
        "|| PublicCorpusMetadata::from_metadata(&retained_name) != before",
        1,
    ),
    (
        "full-relative-path identity",
        "|| PublicCorpusMetadata::from_metadata(&full_path) != before",
        1,
    ),
    (
        "nonblocking no-follow object opens",
        "libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,",
        2,
    ),
    (
        "beneath no-symlink resolution for components and objects",
        "0x02 | 0x04 | 0x08,",
        3,
    ),
    ("bounded read and one-byte excess", ".take(expected_size + 1)", 1),
    (
        "retained parent descriptor",
        "parent.as_raw_fd(),\n                &final_name,",
        2,
    ),
    (
        "initial and full-relative-path validated traversal",
        "self.open_relative_with_parent(relative)?;",
        2,
    ),
    (
        "full-relative-path object open uses validated traversal",
        "let OpenedCorpusObject { file, .. } = self.open_relative_with_parent(relative)?;",
        1,
    ),
]

key_instrumentation_policies = [
    (
        "thread-local key-open instrumentation",
        "std::thread_local! {\n    static KEY_OPEN_COUNT: std::cell::Cell<usize>",
        1,
    ),
    (
        "thread-local key-open increment",
        "KEY_OPEN_COUNT.set(KEY_OPEN_COUNT.get() + 1);",
        1,
    ),
    ("thread-local key-open reset", "KEY_OPEN_COUNT.set(0);", 1),
]


def require_exact_policies(errors, source, owner, policies):
    for label, snippet, expected_count in policies:
        actual_count = source.count(snippet)
        if actual_count != expected_count:
            errors.append(
                f"missing exact {owner} policy {label}: expected {expected_count}, got {actual_count}"
            )


def authenticated_corpus_reader(signing):
    start = signing.find("    struct AuthenticatedCorpus {")
    end = signing.find("    type FixtureObjects", start)
    if start < 0 or end < 0:
        return None
    return signing[start:end]


def evidence_reader_errors(generator, signing, key):
    errors = []
    if re.search(r"\.read_bytes\s*\(", generator):
        errors.append("pathname read_bytes in approved-release evidence generator")
    tar_calls = re.findall(r"tarfile\.open\([^\n]*", generator)
    if tar_calls != [retained_tar_call]:
        errors.append("archive parsing is not exclusively from the bounded retained descriptor")
    require_exact_policies(errors, generator, "Python evidence reader", python_reader_policies)

    corpus_reader = authenticated_corpus_reader(signing)
    if corpus_reader is None:
        errors.append("authenticated corpus capability boundary is missing")
    else:
        if re.search(r"\bfs::read\s*\(", corpus_reader):
            errors.append("pathname fs::read in authenticated corpus reader")
        require_exact_policies(errors, corpus_reader, "Rust corpus reader", rust_reader_policies)
    require_exact_policies(errors, key, "key instrumentation", key_instrumentation_policies)
    return errors


errors = evidence_reader_errors(generator_source, signing_source, key_source)
if errors:
    print(errors[0], file=sys.stderr)
    sys.exit(1)

read_mutation = generator_source + '\nPath("mutation").read_bytes()\n'
if not evidence_reader_errors(read_mutation, signing_source, key_source):
    print("evidence scanner accepted a Path.read_bytes mutation", file=sys.stderr)
    sys.exit(1)

tar_mutation = generator_source.replace(
    retained_tar_call,
    'tarfile.open(archive_label, mode="r:*") as opened:',
    1,
)
if not evidence_reader_errors(tar_mutation, signing_source, key_source):
    print("evidence scanner accepted a pathname tar reopen mutation", file=sys.stderr)
    sys.exit(1)

rust_mutation = signing_source.replace(
    "            let OpenedCorpusObject {",
    "            let bytes = fs::read(relative)?;\n            let OpenedCorpusObject {",
    1,
)
if not evidence_reader_errors(generator_source, rust_mutation, key_source):
    print("evidence scanner accepted an fs::read mutation", file=sys.stderr)
    sys.exit(1)

for label, snippet, _expected_count in python_reader_policies:
    mutation = generator_source.replace(snippet, f"REMOVED_PYTHON_POLICY_{label}", 1)
    if mutation == generator_source:
        print(f"Python policy mutation could not be applied: {label}", file=sys.stderr)
        sys.exit(1)
    if not evidence_reader_errors(mutation, signing_source, key_source):
        print(f"evidence scanner accepted removed Python policy: {label}", file=sys.stderr)
        sys.exit(1)

corpus_reader_source = authenticated_corpus_reader(signing_source)
if corpus_reader_source is None:
    print("Rust corpus policy mutations have no reader region", file=sys.stderr)
    sys.exit(1)
for label, snippet, _expected_count in rust_reader_policies:
    mutated_reader = corpus_reader_source.replace(
        snippet, f"REMOVED_RUST_POLICY_{label}", 1
    )
    if mutated_reader == corpus_reader_source:
        print(f"Rust policy mutation could not be applied: {label}", file=sys.stderr)
        sys.exit(1)
    mutation = signing_source.replace(corpus_reader_source, mutated_reader, 1)
    if not evidence_reader_errors(generator_source, mutation, key_source):
        print(f"evidence scanner accepted removed Rust policy: {label}", file=sys.stderr)
        sys.exit(1)

for label, snippet, _expected_count in key_instrumentation_policies:
    mutation = key_source.replace(snippet, f"REMOVED_KEY_POLICY_{label}", 1)
    if mutation == key_source:
        print(f"key policy mutation could not be applied: {label}", file=sys.stderr)
        sys.exit(1)
    if not evidence_reader_errors(generator_source, signing_source, mutation):
        print(f"evidence scanner accepted removed key policy: {label}", file=sys.stderr)
        sys.exit(1)
PY
