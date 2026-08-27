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
    "catalog-publish": [("catalog-core", "dev"), ("catalog-core", "normal")],
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
    "catalog-publish": [
        ("ed25519-dalek", "dev"),
        ("libc", "normal"),
        ("serde", "normal"),
        ("serde_jcs", "normal"),
        ("serde_json", "normal"),
        ("sha2", "normal"),
    ],
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
        "complete directory mode predicate use",
        "and stat.S_IMODE(metadata.st_mode) in SAFE_PUBLIC_DIRECTORY_MODES",
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
        "complete metadata-bound directory mode predicate",
        "&& matches!(metadata.permissions().mode() & 0o7777, 0o700 | 0o755)",
        1,
    ),
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

python3 - <<'PY'
from pathlib import Path
import sys

paths = [
    "crates/catalog-sign/src/main.rs",
    "crates/catalog-sign/src/isolation.rs",
    "crates/catalog-sign/src/signing.rs",
    "crates/catalog-sign/src/bin/catalog-sign-launcher.rs",
    "crates/catalog-sign/src/lib.rs",
    "crates/catalog-sign/tests/isolation_contract.rs",
]
sources = tuple(Path(path).read_text(encoding="utf-8") for path in paths)


def section(source, start, end):
    if start not in source or end not in source.split(start, 1)[1]:
        return ""
    return source.split(start, 1)[1].split(end, 1)[0]


def isolation_boundary_errors(sources):
    main, inner, signing, launcher, lib, isolation_test = sources
    errors = []
    main_body = main.split("fn main() {", 1)[-1]
    first = next((line.strip() for line in main_body.splitlines() if line.strip()), "")
    if first != "let isolation = match catalog_sign::enter_signer_isolation() {":
        errors.append("inner isolation is not the first operation in main")
    isolation_call = main.find("catalog_sign::enter_signer_isolation()")
    for later in ["production_key_identity()", "std::env::args()"]:
        if isolation_call < 0 or main.find(later, isolation_call) < isolation_call:
            errors.append(f"inner isolation does not precede {later}")
    if main.count("catalog_sign::enter_signer_isolation()") != 1:
        errors.append("inner main isolation entry count changed")
    if main.count("catalog_sign::emit_reverse_transfer_manifest(&isolation)") != 2:
        errors.append("reverse transfer completion is not mandatory after success and uncertainty")

    inner_sources = main + inner + signing + lib
    for forbidden in ["std::process::Command", "Command::new(", "std::net::", "TcpStream", "UdpSocket"]:
        if forbidden in inner_sources:
            errors.append(f"inner signer gained network/process capability: {forbidden}")
    if launcher.count("std::process::Command::new(&bwrap_exec)") != 1:
        errors.append("launcher is not the sole exact process launch capability")
    for forbidden in ["/bin/sh", "sh -c", "Command::new(&request", "command.args(&request"]:
        if forbidden in launcher:
            errors.append(f"launcher gained shell/arbitrary argv capability: {forbidden}")

    inner_policy = section(inner, "fn inner_denied_syscalls()", "fn seccomp_filter(")
    launcher_policy = section(launcher, "fn create_launcher_seccomp()", "fn seccomp_filter(")
    prefilter = section(inner, "fn verify_launcher_prefilter()", "fn expect_prefilter_errno(")
    environment_policy = section(inner, "fn exact_environment()", "fn value<'a>(")
    mount_policy = section(inner, "fn verify_mounts(", "fn decode_mount_field(")
    reverse_emitter = section(inner, "pub fn emit_reverse_transfer_manifest(", "fn settle_recovery_binding(")
    reverse_existing = section(inner, "fn verify_existing_reverse_manifest(", "fn collect_output_paths(")
    elf_policy = section(launcher, "fn is_static_x86_64_elf(", "fn u16_le(")
    inner_probe = section(inner, "pub(crate) fn run_isolation_probe", "#[derive(Debug, Serialize)]\nstruct ReverseTransferManifestV1")
    for syscall in [
        "socket", "connect", "fork", "vfork", "clone", "clone3", "ptrace", "execve",
        "execveat", "unshare", "setns", "mount", "umount2",
    ]:
        if f"libc::SYS_{syscall}" not in inner_policy:
            errors.append(f"missing inner seccomp denial: {syscall}")
    for syscall in ["io_uring_setup", "io_uring_enter", "io_uring_register"]:
        token = f"libc::SYS_{syscall}"
        if token not in inner_policy:
            errors.append(f"missing inner io_uring denial: {syscall}")
        if token not in launcher_policy:
            errors.append(f"missing launcher io_uring denial: {syscall}")
        if token not in prefilter or f'"{syscall}"' not in prefilter:
            errors.append(f"missing pre-inner launcher io_uring result: {syscall}")
        if token not in inner_probe or f'"{syscall}"' not in inner_probe:
            errors.append(f"missing post-inner io_uring result: {syscall}")
    for required in [
        "AUDIT_ARCH_X86_64", "X32_SYSCALL_BIT",
        "SECCOMP_RET_ERRNO | libc::EPERM as u32", "verify_open_descriptors()?;",
    ]:
        if required not in inner:
            errors.append(f"missing inner isolation/seccomp enforcement: {required}")
    for required in [
        "fn create_launcher_seccomp()", "libc::SYS_socket", "libc::SYS_connect",
        "libc::SYS_fork", "libc::SYS_clone3", "libc::SYS_ptrace", "libc::SYS_unshare",
        "libc::SYS_mount", "0xc000_003e", "0x4000_0000",
        "0x0005_0000 | libc::EPERM as u32",
    ]:
        if required not in launcher:
            errors.append(f"missing launcher seccomp enforcement: {required}")

    for required in [
        '"--unshare-all"', '"--unshare-net"', '"--die-with-parent"',
        '"--new-session"', '"--clearenv"', '"--cap-drop"', '"--seccomp"',
        '"--ro-bind-fd"', '"--bind-fd"', '"/home/signer"', '"/input"',
        '"/output"', '"/key/runtime-catalog-private.pem"', '"0555"',
    ]:
        if required not in launcher:
            errors.append(f"missing fixed Bubblewrap boundary: {required}")
    for required in [
        '"CATALOG_SIGN_ISOLATION"', '"CATALOG_SIGN_INPUT_SHA256"',
        '"CATALOG_SIGN_HOST_PID_NS"', '"CATALOG_SIGN_HOST_USER_NS"',
        '"CATALOG_SIGN_HOST_MOUNT_NS"', '"CATALOG_SIGN_HOST_NETWORK_NS"',
        '"HTTP_PROXY"', '"GITHUB_TOKEN"', '"SSH_AUTH_SOCK"',
    ]:
        if required not in inner + launcher + isolation_test:
            errors.append(f"missing exact environment boundary evidence: {required}")
    for required in [
        'collect::<BTreeSet<_>>()\n        != expected',
        '.any(|name| sensitive_environment_name(name))',
    ]:
        if required not in environment_policy:
            errors.append(f"missing actual exact/no-extra environment predicate: {required.splitlines()[0]}")
    for required in [
        'root.root != "/newroot"', 'root.filesystem != "tmpfs"',
        'root.source != "tmpfs"', "root.options != expected_root_options",
        "!root.optional_fields.is_empty()", "!root.super_options.contains(&expected_uid)",
        "!root.super_options.contains(&expected_gid)",
        "metadata.permissions().mode() & 0o7777 != 0o555",
        "mount.parent_id != expected_parent", "mounts.keys()",
    ]:
        if required not in inner:
            errors.append(f"missing private root/topology enforcement: {required}")
    for required in [
        'mounts.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected',
        'if !mount_is_read_only(&mounts, path)',
        'mount_is_read_only(&mounts, "/output")',
        'mount.filesystem != "proc"',
        'mount.filesystem != "tmpfs"',
        'mount.filesystem != "devpts"',
    ]:
        if required not in mount_policy:
            errors.append(f"missing actual complete mount predicate: {required}")
    if mount_policy.count('mount.filesystem != "tmpfs"') != 2:
        errors.append("both dev and tmp exact tmpfs predicates are not enforced")
    for required in [
        'verify_empty_directory(Path::new("/home/signer"))?;',
        'verify_empty_directory(Path::new("/tmp"))?;',
    ]:
        if required not in inner:
            errors.append(f"missing empty private directory enforcement: {required}")

    for required in [
        "verify_transferred_bundle(&input_path)?", "verified_input.isolated_launch_capability()?",
        "hash_descriptor(&file, metadata.len())? != config.signer_sha256",
        "hash_descriptor(&file, metadata.len())? != config.bwrap_sha256",
        "matches!(kind, 2 | 3)", "set_close_on_exec(descriptor, false)?",
        'format!("/proc/self/fd/{}", bwrap.file.as_raw_fd())',
    ]:
        if required not in launcher:
            errors.append(f"missing descriptor/hash/static signer boundary: {required}")
    for required in [
        '&bytes[..4] != b"\\x7fELF"', 'bytes[4] != 2', 'bytes[5] != 1',
        'u16_le(&bytes, 18)? != 62', '!matches!(u16_le(&bytes, 16)?, 2 | 3)',
        'u16_le(&bytes, 54)? != 56', 'u64_le(&bytes, 32)?', 'count == 0',
        'count > 128', '.checked_add(count * 56)', 'end > bytes.len()',
        'matches!(kind, 2 | 3)', 'load |= kind == 1', 'Ok(load)',
    ]:
        if required not in elf_policy:
            errors.append(f"missing actual static ELF predicate: {required}")
    if launcher.count("rebind_executable(&signer, FilePolicy::Signer)?;") != 4:
        errors.append("signer replacement checkpoints are not exact")
    if launcher.count("rebind_executable(&bwrap, FilePolicy::Bwrap)?;") != 3:
        errors.append("bwrap replacement checkpoints are not exact")
    if "if (request.ceremony == Ceremony::Sign) != key.is_some()" not in launcher:
        errors.append("key mount ceremony matrix is not enforced")
    if "let output = OutputPreflight::new(request.output)?;\n    let signing_key = read_production_signing_key(request.key_path)?;" not in signing:
        errors.append("output preflight ordering before key open changed")

    launcher_core = section(launcher, "fn disable_core_dumps()", "fn create_launcher_seccomp()")
    for required in [
        "rlim_cur: 0", "rlim_max: 0", "libc::setrlimit(libc::RLIMIT_CORE, &limits)",
        "libc::getrlimit(libc::RLIMIT_CORE, verified.as_mut_ptr())",
        "verified.rlim_cur != 0", "verified.rlim_max != 0",
    ]:
        if required not in launcher_core:
            errors.append(f"missing launcher no-core enforcement: {required}")
    if launcher.find("disable_core_dumps()?;") > launcher.find("open_key_capability(path)"):
        errors.append("launcher no-core enforcement occurs after key open")
    isolation_entry = section(inner, "pub fn enter_signer_isolation()", "fn exact_environment()")
    for required in [
        "libc::PR_SET_DUMPABLE", "libc::PR_GET_DUMPABLE", "if dumpable_status != 0",
        "core_limit_soft != 0", "core_limit_hard != 0",
    ]:
        if required not in isolation_entry:
            errors.append(f"missing inner nondumpability enforcement: {required}")
    if isolation_entry.find("libc::PR_SET_DUMPABLE") > isolation_entry.find("exact_environment()?"):
        errors.append("dumpability is not disabled before input/environment processing")

    attestation_decl = section(inner, "pub struct IsolationAttestationV1", "impl IsolationAttestationV1")
    capability_decl = section(inner, "pub struct SignerIsolation", "impl SignerIsolation")
    if "Deserialize" in inner.split("pub struct IsolationAttestationV1", 1)[0].rsplit("#[derive", 1)[-1]:
        errors.append("isolation attestation remains deserializable")
    if "attestation: IsolationAttestationV1" not in capability_decl or "verified_transfer: VerifiedTransferredBundle" not in capability_decl:
        errors.append("non-constructible isolation capability lost its private authority")
    if "pub fn run_cli(" in lib or "pub fn sign_release(" in signing or "pub fn sign_release_from_path(" in signing:
        errors.append("raw CLI/signing authority is publicly exported")
    for required in [
        "pub fn run_isolated_cli(isolation: &SignerIsolation", "signing::run_isolated_cli(isolation.verified_transfer(), args)",
    ]:
        if required not in lib:
            errors.append(f"production CLI lost isolation capability requirement: {required}")
    if "struct SignReleaseRequest" not in signing or "pub struct SignReleaseRequest" in signing:
        errors.append("raw signing request became publicly constructible")

    for required in [
        'verify_transferred_bundle(Path::new("/input"))?',
        "verified_transfer.transfer_manifest_sha256().to_owned()",
        "if input_transfer_sha256 != expected_input_digest",
        "verified_transfer,",
    ]:
        if required not in isolation_entry:
            errors.append(f"attested transfer binding is missing: {required}")
    isolated_cli = section(signing, "pub(crate) fn run_isolated_cli", "fn exact_flags(")
    if "bundle: &VerifiedTransferredBundle" not in isolated_cli:
        errors.append("isolated CLI does not consume retained transfer")
    if "verify_transferred_bundle(" in isolated_cli or "_from_path(" in isolated_cli:
        errors.append("isolated CLI reopens the attested transfer by path")

    expected_prefilter_results = [
        'expect_prefilter_errno("socket", socket, libc::EPERM',
        'expect_prefilter_errno("connect", connect, libc::EPERM',
        'expect_prefilter_errno("fork", fork, libc::EPERM',
        'expect_prefilter_errno("execve", execve, libc::ENOENT',
        'expect_prefilter_errno("unshare", unshare, libc::EPERM',
        'expect_prefilter_errno("setns", setns, libc::EPERM',
        'expect_prefilter_errno("mount", mount, libc::EPERM',
        'expect_prefilter_errno("umount2", umount, libc::EPERM',
        'expect_prefilter_errno("open_tree", open_tree, libc::EPERM',
        'expect_prefilter_errno("move_mount", move_mount, libc::EPERM',
        'expect_prefilter_errno("io_uring_setup", setup, libc::EPERM',
        'expect_prefilter_errno("io_uring_enter", enter, libc::EPERM',
        '"io_uring_register",\n        register,\n        libc::EPERM',
    ]
    for required in expected_prefilter_results:
        if required not in prefilter:
            errors.append(f"missing exact launcher prefilter result: {required.splitlines()[0]}")
    if "libc::waitpid(fork as libc::pid_t" not in prefilter:
        errors.append("unexpected prefilter fork child is not cleaned up")

    assertion_sections = isolation_test.split("for syscall in [")
    first_assertions = assertion_sections[1].split("] {", 1)[0] if len(assertion_sections) > 1 else ""
    second_assertions = assertion_sections[2].split("] {", 1)[0] if len(assertion_sections) > 2 else ""
    for syscall in ["io_uring_setup", "io_uring_enter", "io_uring_register"]:
        if f'"{syscall}"' not in first_assertions or f'"{syscall}"' not in second_assertions:
            errors.append(f"real launcher probe lacks exact io_uring assertion: {syscall}")
    for syscall in [
        "socket", "connect", "fork", "unshare", "setns", "mount", "umount2",
        "open_tree", "move_mount", "io_uring_setup", "io_uring_enter", "io_uring_register",
    ]:
        if f'"{syscall}"' not in second_assertions:
            errors.append(f"real launcher probe lacks exact prefilter assertion: {syscall}")
    if 'probe["launcher_prefilter_errno"]["execve"], libc::ENOENT' not in isolation_test:
        errors.append("real launcher probe lacks exact prefilter exec assertion")
    marker_test = section(
        isolation_test,
        "fn direct_and_exact_marker_only_sign_fail_before_key_open_or_output()",
        "#[test]\nfn real_launcher_prefilter_and_inner_filter_emit_kernel_attestation()",
    )
    for required in [
        "for (name, value) in complete_marker_environment()",
        "InotifyKeyOpenWitness::new(&key)", "!witness.observed_open()",
        "assert!(!output.exists())", '"sign",\n            "--input"',
    ]:
        if required not in marker_test:
            errors.append(f"exact marker-only sign boundary missing: {required}")
    for required in [
        '"CATALOG_SIGN_ISOLATION", "launcher-v1"',
        '("CATALOG_SIGN_MODE", "sign".to_owned())',
        '"sign",\n            "--input"',
        "complete_marker_environment()", "InotifyKeyOpenWitness::new(&key)",
        "!witness.observed_open()", "assert!(!output.exists())",
        "libc::setrlimit(libc::RLIMIT_CORE, &limit)",
        'Command::new(env!("CARGO_BIN_EXE_catalog-sign-launcher"))',
    ]:
        if required not in isolation_test:
            errors.append(f"marker-only/key-open witness evidence missing: {required}")
    for forbidden in ["write_launcher_seccomp", "libc::sock_filter", 'Command::new("/usr/bin/bwrap")']:
        if forbidden in isolation_test:
            errors.append(f"isolation test duplicates/bypasses launcher policy: {forbidden}")

    for required in [
        "pub fn emit_reverse_transfer_manifest(", 'kind: "signer_output"',
        "input_transfer_sha256: attestation.input_transfer_sha256()",
        "isolation_attestation: attestation", 'mode: "0400".to_owned()',
        "write_fresh_public_file(Path::new(OUTPUT_MANIFEST), &bytes)?",
    ]:
        if required not in inner:
            errors.append(f"missing reverse authenticated transfer boundary: {required}")
    for required in [
        'names != expected_names', 'collect_output_paths(output, Path::new(expected_top), &mut paths)?',
        'paths.is_empty() || paths.len() > MAX_OUTPUT_ENTRIES', '!metadata.is_file()',
        'metadata.permissions().mode() & 0o7777 != 0o400', 'metadata.len() == 0',
        'metadata.len() > MAX_OUTPUT_BYTES', 'sha256: hash_descriptor(&file, metadata.len())?',
    ]:
        if required not in reverse_emitter:
            errors.append(f"missing actual reverse inventory predicate: {required}")
    for required in [
        'serde_jcs::to_vec(&value).map_err(|_| rejected())? != bytes',
        'value["input_transfer_sha256"] != current.input_transfer_sha256()',
        'value["entries"] != serde_json::to_value(expected_entries).map_err(|_| rejected())?',
        'authorized_recovery_mode_combination(historical_original, historical_mode)',
    ]:
        if required not in reverse_existing:
            errors.append(f"missing actual reverse manifest predicate: {required}")
    if "catalog-test-key-v1" in main + inner + launcher:
        errors.append("fixture authority crossed into signer isolation/launcher")
    return errors


errors = isolation_boundary_errors(sources)
if errors:
    print(errors[0], file=sys.stderr)
    sys.exit(1)

# One-at-a-time removals target the actual enforcement expressions rather than documentation tokens.
mutations = [
    (0, "catalog_sign::enter_signer_isolation()", "catalog_sign::enter_signer_isolation_removed()", "first-operation isolation", 1),
    (0, "catalog_sign::emit_reverse_transfer_manifest(&isolation)", "catalog_sign::removed_reverse_transfer_manifest(&isolation)", "successful reverse transfer emission", 1),
    (0, "catalog_sign::emit_reverse_transfer_manifest(&isolation)", "catalog_sign::removed_reverse_transfer_manifest(&isolation)", "uncertain reverse transfer completion", 2),
    (1, 'verify_empty_directory(Path::new("/home/signer"))?;', "", "empty private home", 1),
    (1, "verify_open_descriptors()?;", "", "ambient descriptor rejection", 1),
    # Exact environment set/no-extra predicates.
    (1, 'collect::<BTreeSet<_>>()\n        != expected', 'collect::<BTreeSet<_>>()\n        == expected', "exact environment set equality", 1),
    (1, '.any(|name| sensitive_environment_name(name))', '.all(|_| false)', "sensitive/no-extra environment rejection", 1),
    # Complete mount names, options, writable-output polarity, and filesystem types.
    (1, 'mounts.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected', 'false', "complete mount point/no-extra equality", 1),
    (1, 'if !mount_is_read_only(&mounts, path)', 'if false', "exact read-only mount options", 1),
    (1, 'mount_is_read_only(&mounts, "/output")', 'false', "writable output mount option", 1),
    (1, 'mount.filesystem != "proc"', 'false', "proc mount filesystem", 1),
    (1, 'mount.filesystem != "tmpfs"', 'false', "dev/tmp mount filesystem", 1),
    (1, 'mount.filesystem != "devpts"', 'false', "devpts mount filesystem", 1),
    (3, "hash_descriptor(&file, metadata.len())? != config.signer_sha256", "false", "signer descriptor hash", 1),
    # Every actual static ELF admission predicate.
    (3, '&bytes[..4] != b"\\x7fELF"', 'false', "static ELF magic", 1),
    (3, 'bytes[4] != 2', 'false', "static ELF class", 1),
    (3, 'bytes[5] != 1', 'false', "static ELF endian", 1),
    (3, 'u16_le(&bytes, 18)? != 62', 'false', "static ELF machine", 1),
    (3, '!matches!(u16_le(&bytes, 16)?, 2 | 3)', 'false', "static ELF type", 1),
    (3, 'u16_le(&bytes, 54)? != 56', 'false', "static ELF program header entry size", 1),
    (3, 'let offset = usize::try_from(u64_le(&bytes, 32)?).map_err(|_| rejected())?;', 'let offset = 0;', "static ELF program header offset", 1),
    (3, 'count == 0', 'false', "static ELF nonzero program header count", 1),
    (3, 'count > 128', 'false', "static ELF bounded program header count", 1),
    (3, '.checked_add(count * 56)', '.checked_add(0)', "static ELF program header extent", 1),
    (3, 'end > bytes.len()', 'false', "static ELF program header file bound", 1),
    (3, "matches!(kind, 2 | 3)", "false", "static ELF dynamic/interpreter rejection", 1),
    (3, 'load |= kind == 1;', 'load |= false;', "static ELF PT_LOAD requirement", 1),
    (3, "rebind_executable(&signer, FilePolicy::Signer)?;", "", "first signer replacement checkpoint", 1),
    (3, "if (request.ceremony == Ceremony::Sign) != key.is_some()", "if false", "key ceremony matrix", 1),
    (3, "std::process::Command::new(&bwrap_exec)", 'std::process::Command::new("/bin/sh")', "retained exact bwrap execution", 1),
    # Each io_uring syscall in each real policy.
    (1, "        libc::SYS_io_uring_setup,", "", "inner io_uring_setup policy", 1),
    (1, "        libc::SYS_io_uring_enter,", "", "inner io_uring_enter policy", 1),
    (1, "        libc::SYS_io_uring_register,", "", "inner io_uring_register policy", 1),
    (3, "        libc::SYS_io_uring_setup,", "", "launcher io_uring_setup policy", 1),
    (3, "        libc::SYS_io_uring_enter,", "", "launcher io_uring_enter policy", 1),
    (3, "        libc::SYS_io_uring_register,", "", "launcher io_uring_register policy", 1),
    # Both post-inner and actual-launcher probe assertions.
    (5, '        "io_uring_setup",', "", "post-inner io_uring_setup assertion", 1),
    (5, '        "io_uring_enter",', "", "post-inner io_uring_enter assertion", 1),
    (5, '        "io_uring_register",', "", "post-inner io_uring_register assertion", 1),
    (5, '        "io_uring_setup",', "", "prefilter io_uring_setup assertion", 2),
    (5, '        "io_uring_enter",', "", "prefilter io_uring_enter assertion", 2),
    (5, '        "io_uring_register",', "", "prefilter io_uring_register assertion", 2),
    (5, '        "socket",', "", "prefilter socket assertion", 2),
    (5, '        "connect",', "", "prefilter connect assertion", 2),
    (5, '        "fork",', "", "prefilter fork assertion", 2),
    (5, '        "unshare",', "", "prefilter unshare assertion", 2),
    (5, '        "setns",', "", "prefilter setns assertion", 2),
    (5, '        "mount",', "", "prefilter mount assertion", 2),
    (5, '        "umount2",', "", "prefilter umount assertion", 2),
    (5, '        "open_tree",', "", "prefilter open_tree assertion", 1),
    (5, '        "move_mount",', "", "prefilter move_mount assertion", 1),
    (5, 'probe["launcher_prefilter_errno"]["execve"], libc::ENOENT', 'probe["launcher_prefilter_errno"]["execve"], libc::EPERM', "prefilter exec assertion", 1),
    # Both core-limit values and verification, plus dumpable set/get.
    (3, "        rlim_cur: 0,", "        rlim_cur: 1,", "launcher soft core limit", 1),
    (3, "        rlim_max: 0,", "        rlim_max: 1,", "launcher hard core limit", 1),
    (3, "verified.rlim_cur != 0", "false", "launcher soft core verification", 1),
    (3, "verified.rlim_max != 0", "false", "launcher hard core verification", 1),
    (1, "libc::PR_SET_DUMPABLE", "libc::REMOVED_PR_SET_DUMPABLE", "inner dumpable set", 1),
    (1, "libc::PR_GET_DUMPABLE", "libc::REMOVED_PR_GET_DUMPABLE", "inner dumpable get", 1),
    (1, "if dumpable_status != 0", "if false", "inner dumpable verification", 1),
    (1, "core_limit_soft != 0", "false", "inner soft core verification", 1),
    (1, "core_limit_hard != 0", "false", "inner hard core verification", 1),
    # Unforgeable capability, signature requirement, and retained transfer binding.
    (1, "pub struct SignerIsolation", "pub struct RemovedSignerIsolation", "isolation capability", 1),
    (1, "#[derive(Debug, Clone, PartialEq, Eq, Serialize)]", "#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]", "non-deserializable attestation", 1),
    (2, "fn sign_release(request: SignReleaseRequest", "pub fn sign_release(request: SignReleaseRequest", "private raw signing seam", 1),
    (4, "pub fn run_isolated_cli(isolation: &SignerIsolation", "pub fn run_isolated_cli(isolation: &IsolationAttestationV1", "CLI capability signature", 1),
    (4, "signing::run_isolated_cli(isolation.verified_transfer(), args)", "signing::run_isolated_cli_removed(args)", "retained CLI consumption", 1),
    (1, 'verify_transferred_bundle(Path::new("/input"))?', 'verify_transferred_bundle(Path::new("/other"))?', "exact isolated transfer verification", 1),
    (1, "if input_transfer_sha256 != expected_input_digest", "if false", "attested digest comparison", 1),
    (1, "verified_transfer,", "", "retained transfer capability", 1),
    # Private root type/options/topology.
    (1, 'root.root != "/newroot"', "false", "private root origin", 1),
    (1, 'root.filesystem != "tmpfs"', "false", "private root filesystem", 1),
    (1, 'root.source != "tmpfs"', "false", "private root source", 1),
    (1, "root.options != expected_root_options", "false", "private root options", 1),
    (1, "!root.optional_fields.is_empty()", "false", "private root propagation", 1),
    (1, "!root.super_options.contains(&expected_uid)", "false", "private root owner uid", 1),
    (1, "!root.super_options.contains(&expected_gid)", "false", "private root owner gid", 1),
    (1, "metadata.permissions().mode() & 0o7777 != 0o555", "false", "private root mode", 1),
    (1, "mount.parent_id != expected_parent", "false", "private mount topology", 1),
    # Reverse inventory enumeration/type/mode/size/hash/canonical/input/mode predicates.
    (1, 'names != expected_names', 'false', "reverse top-level complete enumeration/no-extra", 1),
    (1, 'collect_output_paths(output, Path::new(expected_top), &mut paths)?;', '', "reverse recursive complete enumeration", 1),
    (1, 'paths.is_empty() || paths.len() > MAX_OUTPUT_ENTRIES', 'false', "reverse output count bounds", 1),
    (1, '!metadata.is_file()', 'false', "reverse regular file type", 1),
    (1, 'metadata.permissions().mode() & 0o7777 != 0o400', 'false', "reverse exact file mode", 1),
    (1, 'metadata.len() == 0', 'false', "reverse nonempty size", 1),
    (1, 'metadata.len() > MAX_OUTPUT_BYTES', 'false', "reverse individual size bound", 1),
    (1, 'sha256: hash_descriptor(&file, metadata.len())?', 'sha256: String::new()', "reverse SHA-256", 1),
    (1, 'serde_jcs::to_vec(&value).map_err(|_| rejected())? != bytes', 'false', "reverse canonical bytes", 2),
    (1, 'value["input_transfer_sha256"] != current.input_transfer_sha256()', 'false', "reverse input digest", 1),
    (1, 'value["entries"] != serde_json::to_value(expected_entries).map_err(|_| rejected())?', 'false', "reverse exact entries", 1),
    (1, 'authorized_recovery_mode_combination(historical_original, historical_mode)', 'true', "reverse attestation mode combination", 1),
    # Every exact inherited-prefilter result and unexpected-child cleanup.
    (1, 'expect_prefilter_errno("socket", socket, libc::EPERM', 'expect_prefilter_errno("socket", socket, libc::ENOENT', "prefilter socket result", 1),
    (1, 'expect_prefilter_errno("connect", connect, libc::EPERM', 'expect_prefilter_errno("connect", connect, libc::ENOENT', "prefilter connect result", 1),
    (1, 'expect_prefilter_errno("fork", fork, libc::EPERM', 'expect_prefilter_errno("fork", fork, libc::ENOENT', "prefilter fork result", 1),
    (1, 'expect_prefilter_errno("execve", execve, libc::ENOENT', 'expect_prefilter_errno("execve", execve, libc::EPERM', "prefilter exec result", 1),
    (1, 'expect_prefilter_errno("unshare", unshare, libc::EPERM', 'expect_prefilter_errno("unshare", unshare, libc::ENOENT', "prefilter unshare result", 1),
    (1, 'expect_prefilter_errno("setns", setns, libc::EPERM', 'expect_prefilter_errno("setns", setns, libc::ENOENT', "prefilter setns result", 1),
    (1, 'expect_prefilter_errno("mount", mount, libc::EPERM', 'expect_prefilter_errno("mount", mount, libc::ENOENT', "prefilter mount result", 1),
    (1, 'expect_prefilter_errno("umount2", umount, libc::EPERM', 'expect_prefilter_errno("umount2", umount, libc::ENOENT', "prefilter umount result", 1),
    (1, 'expect_prefilter_errno("open_tree", open_tree, libc::EPERM', 'expect_prefilter_errno("open_tree", open_tree, libc::ENOENT', "prefilter open_tree result", 1),
    (1, 'expect_prefilter_errno("move_mount", move_mount, libc::EPERM', 'expect_prefilter_errno("move_mount", move_mount, libc::ENOENT', "prefilter move_mount result", 1),
    (1, 'expect_prefilter_errno("io_uring_setup", setup, libc::EPERM', 'expect_prefilter_errno("io_uring_setup", setup, libc::ENOENT', "prefilter io_uring_setup result", 1),
    (1, 'expect_prefilter_errno("io_uring_enter", enter, libc::EPERM', 'expect_prefilter_errno("io_uring_enter", enter, libc::ENOENT', "prefilter io_uring_enter result", 1),
    (1, '"io_uring_register",\n        register,\n        libc::EPERM', '"io_uring_register",\n        register,\n        libc::ENOENT', "prefilter io_uring_register result", 1),
    (1, "libc::waitpid(fork as libc::pid_t", "libc::waitpid_removed(fork as libc::pid_t", "unexpected fork cleanup", 1),
    # Exact marker-only sign setup and cross-process no-key-open witness.
    (5, "for (name, value) in complete_marker_environment()", "for (name, value) in removed_marker_environment()", "complete marker-only environment", 1),
    (5, '("CATALOG_SIGN_ISOLATION", "launcher-v1".to_owned())', '("CATALOG_SIGN_ISOLATION", "wrong".to_owned())', "exact accepted marker", 1),
    (5, '("CATALOG_SIGN_MODE", "sign".to_owned())', '("CATALOG_SIGN_MODE", "assemble-intent".to_owned())', "marker-only sign mode", 1),
    (5, "InotifyKeyOpenWitness::new(&key)", "RemovedKeyOpenWitness::new(&key)", "key-open witness", 1),
    (5, "!witness.observed_open()", "true", "no key-open assertion", 1),
    (5, "assert!(!output.exists())", "", "no output assertion", 1),
]


def replace_nth(source, old, new, occurrence):
    start = 0
    for _ in range(occurrence):
        index = source.find(old, start)
        if index < 0:
            return source
        start = index + len(old)
    index = source.find(old, 0 if occurrence == 1 else 0)
    if occurrence > 1:
        start = 0
        for _ in range(occurrence):
            index = source.find(old, start)
            if index < 0:
                return source
            start = index + len(old)
    return source[:index] + new + source[index + len(old):]


for index, old, new, label, occurrence in mutations:
    mutated = list(sources)
    mutated[index] = replace_nth(mutated[index], old, new, occurrence)
    if mutated[index] == sources[index]:
        print(f"isolation policy mutation could not be applied: {label}", file=sys.stderr)
        sys.exit(1)
    if not isolation_boundary_errors(tuple(mutated)):
        print(f"isolation boundary scanner accepted removed enforcement: {label}", file=sys.stderr)
        sys.exit(1)
PY

python3 - <<'PY'
from pathlib import Path
import sys

paths = {
    "manifest": "crates/catalog-sign/Cargo.toml",
    "production_main": "crates/catalog-sign/src/main.rs",
    "fixture_main": "crates/catalog-sign/src/bin/catalog-sign-fixture.rs",
    "launcher": "crates/catalog-sign/src/bin/catalog-sign-launcher.rs",
    "inner": "crates/catalog-sign/src/isolation.rs",
    "key": "crates/catalog-sign/src/key.rs",
    "signing": "crates/catalog-sign/src/signing.rs",
    "launcher_test": "crates/catalog-sign/tests/launcher_contract.rs",
}
sources = {name: Path(path).read_text(encoding="utf-8") for name, path in paths.items()}


def round2_errors(source):
    errors = []
    required = {
        "manifest": [
            'name = "catalog-sign-fixture"',
        ],
        "fixture_main": [
            "run_fixture_isolated_cli(&isolation, &arguments)",
            "recover_fixture_isolated_output(&isolation)",
            "emit_reverse_transfer_manifest(&isolation)",
        ],
        "key": [
            "read_fixture_signing_key(",
            "FIXTURE_RUNTIME_KEY_ID",
        ],
        "launcher": [
            "#[cfg(test)]\npub(crate) trait LauncherTestCheckpoints",
            "checkpoints.before_signer_open();",
            "checkpoints.after_signer_open();",
            "checkpoints.before_bwrap_bind();",
            "rebind_executable(&signer, FilePolicy::Signer)?;",
            "Ceremony::RecoverSign",
            "open_existing_output(&request.output)?",
            '"CATALOG_SIGN_CONFIG_SHA256"',
            '"CATALOG_SIGN_SIGNER_SHA256"',
            '"original_operation_mode": "sign"',
            "authorized_recovery_mode_combination(",
            "valid_bound_staging(&value[\"staging\"])",
            '"recover-sign",\n                "--input"',
        ],
        "signing": [
            "PublicationDurability::Uncertain",
            "self.published = true;",
            "container_metadata.nlink() != 2",
            "SignError::OutputDurabilityUncertain",
            "fn recover_signed_output(",
            "settle_bound_empty_staging(parent_path)?;",
            "read_recovery_stage_binding(&parent)?",
            "FileIdentity::from_metadata(&metadata) != binding.identity",
            "metadata.permissions().mode() & 0o7777 != binding.mode",
            "!enumerate_names(&directory)",
            "verify_signed_bytes(&signed, verification_policy)?;",
            "PublishCheckpoint::RenameVisibility",
            "PublishCheckpoint::FirstParentFsync",
            "PublishCheckpoint::EmptyContainerUnlink",
            "PublishCheckpoint::FinalParentFsync",
            "PublishCheckpoint::FinalReopen",
        ],
        "inner": [
            "verify_existing_reverse_manifest(attestation, &entries)?;",
            "settle_recovery_binding(attestation)?;",
            "original_operation_mode: IsolationMode",
            "authorized_recovery_mode_combination(historical_original, historical_mode)",
            "launcher_config_sha256: String",
            "signer_sha256: String",
            "current.launcher_config_sha256",
            "current.signer_sha256",
            "libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC",
            "libc::AT_EMPTY_PATH",
            "Some(libc::EEXIST)",
            "verify_exact_public_file(&existing, bytes, 1)",
            "ReverseManifestCheckpoint::Link",
            "ReverseManifestCheckpoint::ParentFsync",
            "ReverseManifestCheckpoint::Reopen",
        ],
        "production_main": [
            "Err(catalog_sign::SignError::OutputDurabilityUncertain)",
            "recover_production_isolated_output(&isolation)",
        ],
        "launcher_test": [
            "fixture_authority_signs_through_real_launcher_and_reverse_transfer",
            "synchronized_signer_substitution_uniquely_converts_fixture_success_to_failure",
            "verify_fixture_catalog(&catalog_bytes)",
            "verify_fixture_manifest(&manifest_bytes)",
            "verify_signed_catalog(&catalog_bytes).is_err()",
            "Checkpoint::BeforeOpen",
            "Checkpoint::AfterOpen",
            "Checkpoint::BeforeBind",
            "!key_witness.observed_open()",
            "launch_recover(&config, &input, &output)",
            "!recovery_key_witness.observed_open()",
            'recovered_value["isolation_attestation"]["mode"],\n        "recover-sign"',
            'recovered_value["isolation_attestation"]["original_operation_mode"]',
            "completed recovered-manifest retry failed",
            "recovery admitted a different launcher config/signer identity",
        ],
    }
    for name, tokens in required.items():
        for token in tokens:
            if token not in source[name]:
                errors.append(f"missing round-2 enforcement in {name}: {token.splitlines()[0]}")
    fixture_bin = source["manifest"].split('name = "catalog-sign-fixture"', 1)[-1].split("[[example]]", 1)[0]
    if 'required-features = ["fixture-tools"]' not in fixture_bin:
        errors.append("fixture signer binary lost its nondefault feature gate")
    fixture_key_reader = source["key"].split("pub(crate) fn read_fixture_signing_key", 1)[-1].split("pub(crate) fn fixture_signing_key", 1)[0]
    if "public_key: &FIXTURE_PUBLIC" not in fixture_key_reader:
        errors.append("fixture signer key reader lost its fixture-only public identity")
    production_surface = source["production_main"] + source["launcher"]
    for forbidden in ["catalog-test-key-v1", "FIXTURE_PUBLIC", "read_fixture_signing_key"]:
        if forbidden in production_surface:
            errors.append(f"fixture authority crossed into production surface: {forbidden}")
    if source["launcher"].count("write_recovery_binding(") != 2:
        errors.append("fresh sign does not invoke exactly one persisted recovery binding writer")
    if source["launcher"].count("verify_recovery_binding(") != 2:
        errors.append("recovery does not invoke exactly one config/signer binding verifier")
    if source["launcher"].split("#[cfg(test)]\nmod tests", 1)[0].count("authorized_recovery_mode_combination(") != 2:
        errors.append("launcher recovery mode predicate call/definition count changed")
    if source["inner"].split("#[cfg(test)]\nmod tests", 1)[0].count("authorized_recovery_mode_combination(") != 2:
        errors.append("inner recovery mode predicate call/definition count changed")
    if source["signing"].count("self.parent.sync_all().is_err()") != 2:
        errors.append("both signed-output parent fsync uncertainty checks are not enforced")
    absent_binding_before_stage_bind = """let Some(mut file) = open_recovery_binding(parent, true)? else {
        return Err(output_rejected());
    };"""
    absent_binding_before_stage_cleanup = """let Some(file) = open_recovery_binding(parent, false)? else {
        return Err(output_rejected());
    };"""
    if source["signing"].count(absent_binding_before_stage_bind) != 1:
        errors.append("absent recovery binding before stage bind is not rejected")
    if source["signing"].count(absent_binding_before_stage_cleanup) != 1:
        errors.append("absent recovery binding before stage cleanup is not rejected")
    recover_region = source["signing"].split("fn recover_signed_output(", 1)[-1].split("fn catalog_payload_for_intent(", 1)[0]
    if recover_region.find("verify_signed_bytes(&signed, verification_policy)?;") > recover_region.find("settle_bound_empty_staging(parent_path)?;"):
        errors.append("recovery cleanup occurs before complete public output verification")
    if source["signing"].count("FileIdentity::from_metadata(&metadata) != binding.identity") != 2:
        errors.append("both recovery and in-process bound stage identity checks are not enforced")
    if source["signing"].count("metadata.permissions().mode() & 0o7777 != binding.mode") != 2:
        errors.append("both recovery and in-process bound stage mode checks are not enforced")
    publish_region = source["signing"].split("fn publish(&mut self)", 1)[-1].split("fn create_staging_container", 1)[0]
    if "enumerate_names(&self.container)" not in publish_region:
        errors.append("published staging cleanup no longer rejects nonempty retained evidence")
    checkpoint_region = source["launcher"].split("fn launch_impl(", 1)[-1].split("#[derive(Clone, Copy)]", 1)[0]
    if checkpoint_region.count("#[cfg(test)]\n    checkpoints.") != 3:
        errors.append("test checkpoints are not exactly cfg(test)-confined")
    if "CATALOG_SIGN_TEST" in source["launcher"] or "test-checkpoint" in source["launcher"]:
        errors.append("launcher gained an ambient production checkpoint hook")
    if source["launcher_test"].count("assert_eq!(snapshot_tree(&output), first_snapshot)") != 3:
        errors.append("no-clobber, recovery, and recovery rejection do not preserve exact first output bytes")
    return errors

errors = round2_errors(sources)
if errors:
    print(errors[0], file=sys.stderr)
    sys.exit(1)

mutations = [
    ("manifest", 'required-features = ["fixture-tools"]', 'required-features = []', "fixture feature gate"),
    ("fixture_main", "run_fixture_isolated_cli(&isolation, &arguments)", "run_isolated_cli(&isolation, &arguments)", "fixture/production signer separation"),
    ("key", "public_key: &FIXTURE_PUBLIC", "public_key: production_key_identity().public_key_bytes()", "fixture public identity"),
    ("launcher", "checkpoints.before_signer_open();", "", "before-open checkpoint"),
    ("launcher", "checkpoints.after_signer_open();", "", "after-open checkpoint"),
    ("launcher", "checkpoints.before_bwrap_bind();", "", "before-bind checkpoint"),
    ("launcher", "open_existing_output(&request.output)?", "create_fresh_output(&request.output)?", "closed recovery output"),
    ("launcher", "write_recovery_binding(", "removed_binding_write(", "persisted recovery binding"),
    ("launcher", "verify_recovery_binding(", "removed_binding_verify(", "recovery config/signer binding"),
    ("signing", "self.published = true;", "", "payload visibility state"),
    ("signing", "self.parent.sync_all().is_err()", "false", "first/final fsync uncertainty"),
    ("signing", "container_metadata.nlink() != 2", "false", "exact empty cleanup identity"),
    ("signing", "if !secure_directory(&container_metadata)\n            || container_metadata.nlink() != 2\n            || !enumerate_names(&self.container)", "if !secure_directory(&container_metadata)\n            || container_metadata.nlink() != 2\n            || !removed_container_enumeration()", "nonempty cleanup rejection"),
    ("signing", """let Some(mut file) = open_recovery_binding(parent, true)? else {
        return Err(output_rejected());
    };""", """let Some(mut file) = open_recovery_binding(parent, true)? else {
        return Ok(());
    };""", "absent binding before stage bind rejection"),
    ("signing", """let Some(file) = open_recovery_binding(parent, false)? else {
        return Err(output_rejected());
    };""", """let Some(file) = open_recovery_binding(parent, false)? else {
        return Ok(());
    };""", "absent binding before stage cleanup rejection"),
    ("signing", "fn recover_signed_output(", "fn removed_public_recovery(", "exact public recovery"),
    ("signing", "verify_signed_bytes(&signed, verification_policy)?;", "", "recovery public verification"),
    ("signing", "settle_bound_empty_staging(parent_path)?;", "", "output-before-bound-stage cleanup"),
    ("signing", "read_recovery_stage_binding(&parent)?", "None", "persisted stage binding"),
    ("signing", "FileIdentity::from_metadata(&metadata) != binding.identity", "false", "exact bound stage identity"),
    ("signing", "metadata.permissions().mode() & 0o7777 != binding.mode", "false", "bound stage owner mode"),
    ("signing", "!enumerate_names(&directory)", "!BTreeSet::new()", "bound stage nonempty rejection"),
    ("launcher", "valid_bound_staging(&value[\"staging\"])", "true", "launcher exact stage binding"),
    ("launcher", "authorized_recovery_mode_combination(", "removed_recovery_mode_combination(", "launcher recovery mode combination"),
    ("inner", "authorized_recovery_mode_combination(historical_original, historical_mode)", "true", "inner recovery mode combination"),
    ("inner", "verify_existing_reverse_manifest(attestation, &entries)?;", "", "idempotent reverse completion"),
    ("inner", "settle_recovery_binding(attestation)?;", "", "recovery binding settlement"),
    ("inner", "current.launcher_config_sha256", "removed_config_identity", "historical config identity"),
    ("inner", "current.signer_sha256", "removed_signer_identity", "historical signer identity"),
    ("inner", "libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC", "libc::O_RDWR | libc::O_CREAT", "partial reverse visibility"),
    ("inner", "verify_exact_public_file(&existing, bytes, 1)", "Ok(())", "conflicting reverse rejection"),
    ("production_main", "recover_production_isolated_output(&isolation)", "Ok(())", "post-visibility completion"),
    ("launcher_test", "!key_witness.observed_open()", "true", "substitution zero-key-open witness"),
    ("launcher_test", "assert_eq!(snapshot_tree(&output), first_snapshot)", "", "no-clobber byte preservation"),
    ("launcher_test", "verify_signed_catalog(&catalog_bytes).is_err()", "true", "fixture cannot production-verify"),
]
for name, old, new, label in mutations:
    mutated = dict(sources)
    mutated[name] = mutated[name].replace(old, new, 1)
    if mutated[name] == sources[name]:
        print(f"round-2 mutation could not be applied: {label}", file=sys.stderr)
        sys.exit(1)
    if not round2_errors(mutated):
        print(f"round-2 scanner accepted removed enforcement: {label}", file=sys.stderr)
        sys.exit(1)
PY

python3 - <<'PY'
from pathlib import Path
import sys

sources = {
    "oracle": Path("scripts/authentic-candidate-oracle.py").read_text(encoding="utf-8"),
    "test": Path("scripts/test_authentic_candidate_oracle.py").read_text(encoding="utf-8"),
    "journey": Path("scripts/run-authentic-signing-journey.sh").read_text(encoding="utf-8"),
}


def oracle_errors(source):
    errors = []
    required = {
        "oracle": [
            'EXPECTED_CANDIDATE_SHA256 = "7dba62c8b44883cbd7b3615fd9fe3b1a08a3aa2c75c7729704c14804d1cc2a2b"',
            '"compatibility_ranges": [intent["fluxsemble_requirement"]]',
            '"provider_id": release["provider"]',
            '"releases": [release["release"]]',
            'for record in verify_transfer(root):',
            'if digest != EXPECTED_CANDIDATE_SHA256:',
            'object_pairs_hook=reject_duplicates',
            'if actual != expected | {"transfer-manifest-v1.json"}:',
        ],
        "test": [
            "test_projection_is_independently_fixed_byte_for_byte",
            "self.assertEqual(candidate, expected)",
            "test_wrong_projection_or_approved_tuple_cannot_fall_back_to_peer_comparison",
            '"7dba62c8b44883cbd7b3615fd9fe3b1a08a3aa2c75c7729704c14804d1cc2a2b"',
            "duplicate_members_floats_and_bounds_fail_closed",
        ],
        "journey": [
            "scripts/authentic-candidate-oracle.py",
            'cmp --silent "$root/oracle-intent-candidate.json" "$root/oracle-final-candidate.json"',
            'assert assemble == oracle, "production assemble differs from independent oracle"',
            'assert finalized == oracle, "production finalize differs from independent oracle"',
            "expected_candidate_sha256=7dba62c8b44883cbd7b3615fd9fe3b1a08a3aa2c75c7729704c14804d1cc2a2b",
            'assert digest_bytes(oracle) == expected_candidate_sha256',
        ],
    }
    for name, tokens in required.items():
        for token in tokens:
            if token not in source[name]:
                errors.append(f"missing independent candidate oracle enforcement in {name}: {token}")
    if source["journey"].count("scripts/authentic-candidate-oracle.py") != 2:
        errors.append("authentic journey does not independently project both inputs")
    if "catalog_sign" in source["oracle"] or "subprocess" in source["oracle"]:
        errors.append("independent oracle gained producer implementation/process dependency")
    return errors


errors = oracle_errors(sources)
if errors:
    print(errors[0], file=sys.stderr)
    sys.exit(1)

mutations = [
    ("oracle", '"compatibility_ranges": [intent["fluxsemble_requirement"]]', '"compatibility_ranges": []', "independent expected projection"),
    ("oracle", 'if digest != EXPECTED_CANDIDATE_SHA256:', 'if False:', "frozen independent digest"),
    ("oracle", 'for record in verify_transfer(root):', 'for record in []:', "authenticated public transfer input"),
    ("oracle", 'object_pairs_hook=reject_duplicates', 'object_pairs_hook=dict', "duplicate-free oracle JSON"),
    ("journey", 'assert assemble == oracle, "production assemble differs from independent oracle"', 'assert assemble == finalized', "assemble-to-oracle comparison"),
    ("journey", 'assert finalized == oracle, "production finalize differs from independent oracle"', 'assert finalized == assemble', "finalize-to-oracle comparison"),
    ("journey", 'assert digest_bytes(oracle) == expected_candidate_sha256', 'assert assemble == finalized', "oracle digest assertion"),
]
for name, old, new, label in mutations:
    mutated = dict(sources)
    mutated[name] = mutated[name].replace(old, new, 1)
    if mutated[name] == sources[name]:
        print(f"oracle mutation could not be applied: {label}", file=sys.stderr)
        sys.exit(1)
    if not oracle_errors(mutated):
        print(f"oracle scanner accepted removed enforcement: {label}", file=sys.stderr)
        sys.exit(1)
PY

python3 - <<'PY'
from pathlib import Path
import re
import subprocess
import sys

subprocess.run(
    ["cargo", "build", "--locked", "-p", "catalog-publish", "--bin", "catalog-publish"],
    check=True,
    stdout=subprocess.DEVNULL,
)
production_binary = Path("target/debug/catalog-publish").read_bytes()
fixture_public_key = bytes([
    0x1B, 0xD3, 0x6A, 0xFE, 0xE9, 0x32, 0x3F, 0x1E,
    0x38, 0x13, 0xF6, 0x8C, 0x4D, 0x5F, 0x2F, 0x2B,
    0x1B, 0xAE, 0x44, 0xC0, 0xEF, 0x69, 0x17, 0x62,
    0x8E, 0xD6, 0xAF, 0xE1, 0x6A, 0xAE, 0x44, 0xA9,
])
for forbidden in [
    b"catalog-test-key-v1",
    b"verify_transferred_fixture_signed_bundle",
    fixture_public_key,
]:
    if forbidden in production_binary:
        print("fixture authority compiled into production catalog-publish", file=sys.stderr)
        sys.exit(1)
production_symbols = subprocess.check_output(
    ["nm", "-C", "target/debug/catalog-publish"], stderr=subprocess.DEVNULL
)
if b"verify_transferred_fixture_signed_bundle" in production_symbols:
    print("fixture verifier symbol compiled into production catalog-publish", file=sys.stderr)
    sys.exit(1)

local = Path("crates/catalog-publish/src/local.rs").read_text(encoding="utf-8")
lib = Path("crates/catalog-publish/src/lib.rs").read_text(encoding="utf-8")
main = Path("crates/catalog-publish/src/main.rs").read_text(encoding="utf-8")
manifest = Path("crates/catalog-publish/Cargo.toml").read_text(encoding="utf-8")
tests = "\n".join(
    path.read_text(encoding="utf-8")
    for path in sorted(Path("crates/catalog-publish/tests").rglob("*.rs"))
)

policies = [
    ("reverse canonical bytes", "serde_jcs::to_vec(&manifest).map_err(|_| rejected())? != transfer_bytes", 1),
    ("reverse exact kind", 'manifest.kind != "signer_output"', 1),
    ("reverse input digest", "attestation.input_transfer_sha256 != input_transfer_sha256", 1),
    ("reverse strict sorted paths", "pair[0].relative_path >= pair[1].relative_path", 1),
    ("reverse exact file mode", 'entry.mode != "0400"', 2),
    ("reverse exact entry count/no-extra", "expected_names != bundle_names || expected_names.len() != manifest.entries.len()", 1),
    ("reverse individual size bound", "entry.size > MAX_ENTRY_BYTES", 1),
    ("reverse total size bound", "if total > MAX_TRANSFER_BYTES", 1),
    ("reverse SHA-256", "hash_descriptor(&file, entry.size)? != entry.sha256", 1),
    ("current owner file", "metadata.uid() == current_euid()", 2),
    ("single-link file", "metadata.nlink() == links", 1),
    ("owner-only file mode", "metadata.permissions().mode() & 0o7777 == 0o400", 1),
    ("owner-only directory mode", "metadata.permissions().mode() & 0o7777 == 0o700", 1),
    ("component no-symlink resolution", "0x02 | 0x04 | 0x08,", 2),
    ("retained root identity", "FileIdentity::from_metadata(&root_metadata) != self.root_identity", 1),
    ("canonical state root rebind", "FileIdentity::from_metadata(&rebound_root_metadata) != self.root_identity", 1),
    ("canonical state objects rebind", "FileIdentity::from_metadata(&rebound_objects_metadata) != self.objects_identity", 1),
    ("canonical state latest rebind", "FileIdentity::from_metadata(&rebound_latest_metadata) != self.latest_identity", 1),
    ("retained bundle identity", "FileIdentity::from_metadata(&bundle_metadata) != self.bundle_identity", 1),
    ("retained named file identity", "FileIdentity::from_metadata(&rebound_metadata) != retained.identity", 1),
    ("retained all-file revalidation", "bundle.reverify_all().map_err(|_| prior_preserved())?;", 2),
    ("production catalog signature", "VerificationPolicy::Production => verify_signed_catalog(bytes).map_err(|_| rejected())", 1),
    ("production release signature", "verify_signed_release_bundle_manifest(bytes).map_err(|_| rejected())", 1),
    ("signed release inventory", "verify_signed_release_inventory(&inventory, &release_manifest)", 1),
    ("exact release file set", "files.keys().cloned().collect::<BTreeSet<_>>() != expected_names", 1),
    ("catalog envelope binding", "manifest.catalog_envelope().sha256().as_str() != catalog.sha256", 1),
    ("support asset binding", "asset.sha256().as_str() != file.sha256", 1),
    ("checksum inventory", "if checksums != expected_checksums", 1),
    ("tag/sequence binding", 'release_manifest.tag().as_str() != format!("catalog-v1-sequence-{sequence}")', 1),
    ("immutable unnamed object", "libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC", 1),
    ("immutable no-clobber link", "libc::AT_EMPTY_PATH,", 1),
    ("immutable source descriptor copy", "let mut input = source.file.try_clone().map_err(|_| rejected())?;", 1),
    ("immutable object readback", "hash_descriptor(&rebound, source.size)? != source.sha256", 1),
    ("immutable object fsync", "objects.sync_all().map_err(|_| rejected())?;", 2),
    ("persistent bounded streaming", "stream_names_bounded(&self.objects, object_enumeration_limits", 1),
    ("persistent object count bound", "entries = bounded_add(entries, 1, limits.maximum_entries)?;", 1),
    ("persistent cumulative byte bound", "self.limits.maximum_cumulative_bytes,\n            )?;", 1),
    ("persistent per-object byte bound", "metadata.len() > self.limits.maximum_object_bytes", 1),
    ("persistent object name bound", "name_bytes > limits.maximum_name_bytes", 1),
    ("persistent enumeration work bound", "work = bounded_add(work, 1, limits.maximum_work)?;", 1),
    ("persistent checked arithmetic", "current.checked_add(amount).ok_or_else(rejected)?", 1),
    ("persistent arithmetic maximum", "if next > maximum", 1),
    ("bounded intended inventory", "validate_staging_inventory(bundle, state.limits)", 1),
    ("bounded recovery inventory", "validate_recovery_inventory(&record.operation, state.limits)", 1),
    ("existing root validation before children", "let existing_names = validate_existing_state_layout(&root)?;", 1),
    ("record before latest", "let transaction = install_recovery_record(&state, &record_bytes)", 1),
    ("exact gated prior", "if gated != prior_bytes", 1),
    ("atomic latest rename", "libc::SYS_renameat2,", 1),
    ("no-replace absent latest", "libc::RENAME_NOREPLACE", 1),
    ("latest exact readback", "readback.as_deref() != Some(intended_bytes.as_slice())", 1),
    ("latest parent fsync", "state.latest.sync_all().map_err(|_| uncertain())?;", 3),
    ("recovery relation before cleanup", "verify_recovery_relation(&state, &record, &intended_bytes, bundle.policy)", 1),
    ("transaction lock", "libc::LOCK_EX | libc::LOCK_NB", 1),
    ("exact recovery commit", "current.as_deref() == Some(intended_bytes.as_slice())", 2),
    ("exact recovery abort", "current == prior_bytes", 1),
    ("staged before-success revalidation", "revalidate_before_staged_success(&state)", 2),
    ("recovered before-success revalidation", "revalidate_before_recovered_success(&state)", 3),
    ("uncertain no guessing", "return Err(uncertain());", 14),
    ("previsibility prior preserved", "return Err(prior_preserved());", 6),
    ("record visibility recovery required", "return Err(recovery_required());", 14),
    ("uncertainty record retention", "FaultPoint::AfterLatestDirectorySync", 1),
    ("latest temp unnamed preparation", "let latest_temporary = open_latest_temporary(&state)", 1),
    ("latest temp durable link and readback", "link_latest_temporary(&state, &latest_temporary, &intended_bytes)", 1),
    ("latest temp durability checkpoint", "if fault_at(&plan, Checkpoint::AfterLatestTempDurable)", 1),
    ("external SIGKILL blocking seam", "crash_pause_after_latest_temp(&plan)?;", 1),
    ("latest temp current-owner one-link mode", "if !secure_file(&metadata)\n        || FileIdentity::from_metadata(&metadata) != operation.latest_temporary_identity", 1),
    ("latest temp exact intended bytes", "read_descriptor(&file, metadata.len())? != intended_bytes", 1),
    ("latest temp exact intended hash", "hash_descriptor(&file, metadata.len())? != sha256(intended_bytes)", 1),
    ("latest temp descriptor/name rebound", "FileIdentity::from_metadata(&rebound_metadata) != operation.latest_temporary_identity\n        || FileIdentity::from_metadata(&rebound_metadata) != FileIdentity::from_metadata(&metadata)", 1),
    ("latest temp exact bound unlink", "unlink_bound_latest_temporary(", 2),
    ("exact prior before and after temp cleanup", "verify_exact_prior(&state, &record, &prior_bytes, policy)?;", 3),
    ("exact current prior relation", "current != *prior_bytes", 1),
    ("unexpected temp alongside intended", "if current.as_deref() == Some(intended_bytes.as_slice()) {\n            return Err(recovery_required());", 1),
    ("complete operation canonical digest", "let canonical = serde_jcs::to_vec(operation).map_err(|_| rejected())?;", 1),
    ("complete operation domain separation", "hasher.update(OPERATION_DOMAIN);", 1),
    ("complete operation digest recomputation on read", "operation_id(&record.operation).map_err(|_| uncertain())? != record.operation_id", 1),
    ("record/intended complete operation equality", "record.operation != record.intended_reference.operation", 1),
    ("exact prior reference digest binding", "record.operation.prior_reference_sha256 != prior_bytes.as_deref().map(sha256)", 1),
    ("complete exact object inventory", "if expected_objects != operation.objects", 1),
    ("recovery retained all referenced objects", "let mut retained = verify_record_objects(state, operation)?;", 1),
    ("recovery reverse manifest object digest", "sha256(&reverse_bytes) != operation.reverse_transfer_manifest.sha256", 1),
    ("recovery reverse input binding", "manifest.input_transfer_sha256 != operation.input_transfer_sha256", 1),
    ("recovery isolation original binding", "manifest.isolation_attestation.original_operation_mode\n            != operation.isolation_original_mode", 1),
    ("recovery isolation completion binding", "manifest.isolation_attestation.mode != operation.isolation_completion_mode", 1),
    ("recovery reverse no-extra inventory", "manifest.entries.len() != retained.len()", 1),
    ("recovery release inventory", "verify_signed_release_inventory(&inventory, release_manifest)", 1),
    ("recovery signed checksums and assets", "verify_release_bindings(&retained, release_manifest, &checksums_bytes)?;", 1),
    ("recovery catalog payload digest", "encode_hex(catalog.payload_sha256()) != operation.catalog_payload_sha256", 1),
    ("recovery catalog sequence", "catalog.payload().sequence().get() != operation.catalog_sequence", 1),
    ("recovery catalog provider target release", "catalog_release_bindings(catalog.payload())? != operation.catalog_releases", 1),
    ("recovery release tag", "release_manifest.tag().as_str() != operation.release_tag", 1),
    ("recovery source commit", "release_manifest.source_commit().as_str() != operation.source_commit", 1),
    ("recovery source tree", "release_manifest.source_tree_sha256().as_str() != operation.source_tree_sha256", 1),
    ("recovery qualification", "release_manifest.qualification_sha256().as_str() != operation.qualification_sha256", 1),
    ("recovery exact support assets", "actual_support_assets != operation.support_assets", 1),
    ("recovery retained object identity", "FileIdentity::from_metadata(&rebound_metadata) != file.identity", 1),
    ("completed reference named identity", "FileIdentity::from_metadata(&metadata) != reference.operation.latest_temporary_identity", 1),
    ("completed reference exact bytes", "read_descriptor(&file, metadata.len())? != expected", 1),
    ("completed no-marker signed verification", "verify_local_reference(state, &reference, policy).map_err(|_| uncertain())?;", 1),
]


def publisher_errors(local_source, lib_source, main_source, manifest_source, test_source):
    errors = []
    for label, snippet, count in policies:
        actual = local_source.count(snippet)
        if actual != count:
            errors.append(f"missing exact publisher policy {label}: expected {count}, got {actual}")
    prepare_state = local_source.split("fn prepare_state(", 1)[-1].split("fn open_existing_state(", 1)[0]
    validation = prepare_state.find("let existing_names = validate_existing_state_layout(&root)?;")
    first_child_mkdir = prepare_state.find('ensure_state_child(&root, "objects")?;')
    if validation < 0 or first_child_mkdir < 0 or validation > first_child_mkdir:
        errors.append("pre-existing state validation no longer precedes fixed-child mkdir")
    stage_region = local_source.split("fn stage_local_inner(", 1)[-1].split("fn revalidate_before_staged_success", 1)[0]
    stage_order = [
        "install_recovery_record(&state, &record_bytes)",
        "link_latest_temporary(&state, &latest_temporary, &intended_bytes)",
        "Checkpoint::AfterLatestTempDurable",
        "crash_pause_after_latest_temp(&plan)?;",
        "rename_latest_temporary(&state, &latest_temporary, &intended_bytes, prior.is_some())",
        "readback.as_deref() != Some(intended_bytes.as_slice())",
        "state.latest.sync_all().map_err(|_| uncertain())?;",
        "verify_recovery_relation(&state, &record, &intended_bytes, bundle.policy)",
        "cleanup_recovery_record(&state, &transaction)",
    ]
    stage_positions = [stage_region.find(item) for item in stage_order]
    if any(position < 0 for position in stage_positions) or stage_positions != sorted(stage_positions):
        errors.append("latest temp checkpoint/rename/readback/fsync/cleanup order changed")
    recovery_region = local_source.split("fn recover_local_inner(", 1)[-1].split("fn revalidate_before_recovered_success", 1)[0]
    temp_abort_region = recovery_region.split("if latest_temporary_exists {", 1)[-1].split("let outcome = if", 1)[0]
    temp_abort_order = [
        "verify_operation(&state, &record.operation, policy)",
        "verify_exact_prior(&state, &record, &prior_bytes, policy)?;",
        "unlink_bound_latest_temporary(",
        "state.latest.sync_all().map_err(|_| uncertain())?;",
        "verify_exact_prior(&state, &record, &prior_bytes, policy)?;",
        "cleanup_recovery_record(&state, &transaction)",
    ]
    cursor = -1
    for item in temp_abort_order:
        cursor = temp_abort_region.find(item, cursor + 1)
        if cursor < 0:
            errors.append("temp abort verification/unlink/fsync/readback/record cleanup order changed")
            break
    mismatch = temp_abort_region.find("if current != prior_bytes")
    first_destructive = temp_abort_region.find("unlink_bound_latest_temporary(")
    if mismatch < 0 or first_destructive < 0 or mismatch > first_destructive:
        errors.append("latest-temp mismatch can reach destructive cleanup")
    cleanup_region = local_source.split("fn cleanup_recovery_record(", 1)[-1].split("fn parse_reference(", 1)[0]
    cleanup_order = [
        "unlink_name(&state.latest, RECOVERY_TEMP)?;",
        "state.latest.sync_all().map_err(|_| rejected())?;",
        "let marker = open_regular_at(&state.latest, RECOVERY_RECORD)?;",
        "metadata.nlink() != 1",
        "unlink_name(&state.latest, RECOVERY_RECORD)?;",
        "state.latest.sync_all().map_err(|_| rejected())",
    ]
    cursor = -1
    for item in cleanup_order:
        cursor = cleanup_region.find(item, cursor + 1)
        if cursor < 0:
            errors.append("recovery temporary/record unlink, fsync, and readback order changed")
            break
    if "impl Drop for LatestTemporary" in local_source or "impl Drop for TransactionGuard" in local_source:
        errors.append("transaction state gained destructive Drop cleanup")
    for required in [
        "stage_local_with_sigkill_checkpoint(",
        "libc::kill(child.id() as i32, libc::SIGKILL)",
        "status.signal(), Some(libc::SIGKILL)",
        "run_sigkill_latest_temp_case(true)",
        "run_sigkill_latest_temp_case(false)",
        "exact durable pre-rename state",
    ]:
        if required not in test_source:
            errors.append(f"external SIGKILL latest-temp test lost seam: {required}")
    production_sources = lib_source + "\n" + main_source + "\n" + local_source
    for forbidden in [
        "SigningKey", "DecodePrivateKey", "from_pkcs8", "PRIVATE KEY",
        "GH_TOKEN", "GITHUB_TOKEN", "gh auth", "std::process::Command", "Command::new(",
        "std::net::", "reqwest::", "tokio::net", "TcpStream", "UdpSocket",
    ]:
        if forbidden in production_sources:
            errors.append(f"publisher gained forbidden key/network/process authority: {forbidden}")
    if re.search(r"std::env::(?:var|vars|var_os)\s*\(", production_sources):
        errors.append("publisher gained ambient environment lookup")
    if re.search(r"--(?:private-|signing-)?key(?:[= ]|\\b)", main_source, re.IGNORECASE):
        errors.append("publisher gained a key CLI flag")
    for forbidden in ["catalog-sign", "reqwest", "tokio", "hyper", "ureq", "curl", "openssh"]:
        if forbidden in manifest_source:
            errors.append(f"publisher gained forbidden dependency: {forbidden}")
    if '#[allow(dead_code)]\n#[cfg(test)]\npub fn verify_transferred_fixture_signed_bundle(' not in local_source:
        errors.append("fixture verifier is not compile-time test-only")
    if '#[cfg(test)]\n        VerificationPolicy::Fixture => {' not in local_source:
        errors.append("fixture verification match arm is not compile-time test-only")
    if "fixture" in main_source.lower() or "fixture" in lib_source.lower():
        errors.append("fixture authority reached production CLI/library exports")
    if test_source.count('#[path = "../src/local.rs"]') != 2:
        errors.append("filesystem fixture tests do not compile the exact production local implementation")
    if 'command == "recover-local"' not in main_source or main_source.count('command == "recover-local"') != 1:
        errors.append("recover-only command family changed")
    recover_arm = main_source.split('if command == "recover-local"', 1)[-1].split("_ =>", 1)[0]
    if "--bundle" in recover_arm or "verify_transferred_signed_bundle" in recover_arm or "stage_local" in recover_arm:
        errors.append("recover-local accepts or stages a candidate")
    for required in [
        '[command, bundle_flag, bundle] if command == "verify-bundle"',
        '[command, bundle_flag, bundle, state_flag, state] if command == "stage-local"',
        '[command, state_flag, state] if command == "recover-local"',
    ]:
        if required not in main_source:
            errors.append(f"publisher CLI lost exact ordered form: {required}")
    return errors

errors = publisher_errors(local, lib, main, manifest, tests)
if errors:
    print(errors[0], file=sys.stderr)
    sys.exit(1)

# Each mutation removes one actual enforcement expression while retaining its neighbors.
for label, snippet, _count in policies:
    mutation = local.replace(snippet, f"REMOVED_PUBLISHER_POLICY_{label}", 1)
    if mutation == local:
        print(f"publisher mutation could not be applied: {label}", file=sys.stderr)
        sys.exit(1)
    if not publisher_errors(mutation, lib, main, manifest, tests):
        print(f"publisher scanner accepted removed enforcement: {label}", file=sys.stderr)
        sys.exit(1)

# These false-predicate mutations bypass the executable comparison while retaining all
# neighboring identifiers/operators in a deliberately re-spaced comment. This prevents a broad
# token search from satisfying the mutation and gives each recovery authority seam a diagnostic.
semantic_mutations = [
    ("latest temp exact bytes", "read_descriptor(&file, metadata.len())? != intended_bytes"),
    ("latest temp exact hash", "hash_descriptor(&file, metadata.len())? != sha256(intended_bytes)"),
    ("exact prior before cleanup", "current != *prior_bytes"),
    ("unexpected temp alongside intended", "current.as_deref() == Some(intended_bytes.as_slice())"),
    ("operation body digest recomputation", "operation_id(&record.operation).map_err(|_| uncertain())? != record.operation_id"),
    ("complete immutable inventory", "expected_objects != operation.objects"),
    ("reverse manifest digest", "sha256(&reverse_bytes) != operation.reverse_transfer_manifest.sha256"),
    ("reverse input transfer", "manifest.input_transfer_sha256 != operation.input_transfer_sha256"),
    ("isolation original mode", "manifest.isolation_attestation.original_operation_mode\n            != operation.isolation_original_mode"),
    ("isolation completion mode", "manifest.isolation_attestation.mode != operation.isolation_completion_mode"),
    ("catalog payload digest", "encode_hex(catalog.payload_sha256()) != operation.catalog_payload_sha256"),
    ("catalog sequence", "catalog.payload().sequence().get() != operation.catalog_sequence"),
    ("catalog provider target release", "catalog_release_bindings(catalog.payload())? != operation.catalog_releases"),
    ("release tag", "release_manifest.tag().as_str() != operation.release_tag"),
    ("source commit", "release_manifest.source_commit().as_str() != operation.source_commit"),
    ("source tree", "release_manifest.source_tree_sha256().as_str() != operation.source_tree_sha256"),
    ("qualification", "release_manifest.qualification_sha256().as_str() != operation.qualification_sha256"),
    ("support assets", "actual_support_assets != operation.support_assets"),
    ("completed reference identity", "FileIdentity::from_metadata(&metadata) != reference.operation.latest_temporary_identity"),
    ("completed reference bytes", "read_descriptor(&file, metadata.len())? != expected"),
]
for label, predicate in semantic_mutations:
    retained_tokens = predicate.replace(" ", "  ").replace("\n", " ")
    mutation = local.replace(predicate, f"false /* {retained_tokens} */", 1)
    if mutation == local:
        print(f"publisher semantic mutation could not be applied: {label}", file=sys.stderr)
        sys.exit(1)
    if not publisher_errors(mutation, lib, main, manifest, tests):
        print(f"publisher scanner accepted bypassed comparison: {label}", file=sys.stderr)
        sys.exit(1)

initialization_order_mutation = local.replace(
    "    if existed {\n        let existing_names = validate_existing_state_layout(&root)?;",
    '    ensure_state_child(&root, "objects")?;\n    if existed {\n        let existing_names = validate_existing_state_layout(&root)?;',
    1,
)
if initialization_order_mutation == local:
    print("publisher initialization-order mutation could not be applied", file=sys.stderr)
    sys.exit(1)
if not publisher_errors(initialization_order_mutation, lib, main, manifest, tests):
    print("publisher scanner accepted child mkdir before existing-root validation", file=sys.stderr)
    sys.exit(1)

key_mutation = local + "\nfn forbidden_key_mutation(_: SigningKey) {}\n"
if not publisher_errors(key_mutation, lib, main, manifest, tests):
    print("publisher scanner accepted a signing-key mutation", file=sys.stderr)
    sys.exit(1)

fixture_mutation = local.replace(
    '#[allow(dead_code)]\n#[cfg(test)]\npub fn verify_transferred_fixture_signed_bundle(',
    '#[allow(dead_code)]\npub fn verify_transferred_fixture_signed_bundle(',
    1,
)
if not publisher_errors(fixture_mutation, lib, main, manifest, tests):
    print("publisher scanner accepted production fixture verification", file=sys.stderr)
    sys.exit(1)

recover_mutation = main.replace(
    '[command, state_flag, state] if command == "recover-local"',
    '[command, state_flag, state, bundle_flag, bundle] if command == "recover-local"',
    1,
)
if not publisher_errors(local, lib, recover_mutation, manifest, tests):
    print("publisher scanner accepted a recover candidate argument", file=sys.stderr)
    sys.exit(1)
PY

python3 - <<'PY'
from pathlib import Path
import re
import sys

broker = Path("crates/catalog-publish/src/broker.rs").read_text(encoding="utf-8")
binary = Path("crates/catalog-publish/src/bin/catalog-gh-broker.rs").read_text(encoding="utf-8")
lib = Path("crates/catalog-publish/src/lib.rs").read_text(encoding="utf-8")
local = Path("crates/catalog-publish/src/local.rs").read_text(encoding="utf-8")
main = Path("crates/catalog-publish/src/main.rs").read_text(encoding="utf-8")
tests = Path("crates/catalog-publish/tests/broker_boundary.rs").read_text(encoding="utf-8")

# These strings name the executable predicates at the broker authority seam. Exact counts make
# one-at-a-time removals fail even when neighboring identifiers and explanatory text remain.
policies = [
    ("exact seven request kinds", '"create_tag",\n            "read_tag",\n            "create_draft",\n            "read_draft",\n            "upload_asset",\n            "download_asset",\n            "publish_draft",', 1),
    ("request validation before config authority", "request.validate()?;\n    let config = read_config", 1),
    ("canonical request/config bytes", "serde_jcs::to_vec(&strict.0).map_err(|_| rejected())? != bytes", 1),
    ("duplicate JSON member rejection", "if values.contains_key(&key)", 1),
    ("JSON depth and node bounds", "if depth > MAX_JSON_DEPTH || *nodes > MAX_JSON_NODES", 1),
    ("JSON collection bounds", "if values.len() > MAX_COLLECTION_MEMBERS", 2),
    ("strict config schema", '#[serde(deny_unknown_fields)]\npub struct PublisherBrokerConfigV1', 1),
    ("config exact owner-private mode", "metadata.permissions().mode() & 0o7777 == 0o600", 1),
    ("root/current executable owner", "metadata.uid() == 0 || metadata.uid() == current_euid()", 1),
    ("executable nonwritable policy", "mode & 0o022 == 0", 1),
    ("executable execute policy", "mode & 0o111 != 0", 1),
    ("executable full SHA-256 recheck", "hash_descriptor(&executable.file, executable.identity.size)? != executable.sha256", 1),
    ("immediate executable rebind", "rebind_executable(&config.executable)?;", 1),
    ("ELF-only executable admission", "validate_elf_executable(&executable_file, executable_identity.size)?;", 1),
    ("ELF64 little-endian identity", '|| header[4] != 2\n        || header[5] != 1', 1),
    ("ELF x86-64 machine", 'u16::from_le_bytes([header[18], header[19]]) != 62', 1),
    ("ELF program-header bound", "program_count > MAX_ELF_PROGRAM_HEADERS", 1),
    ("ELF load segment required", "if !has_load || !has_executable_load", 1),
    ("config directory exact mode", "metadata.permissions().mode() & 0o7777 == 0o700", 1),
    ("immediate config directory rebind", "rebind_directory(&config.config_directory)?;", 1),
    ("clear child environment", "command.env_clear();", 1),
    ("single hard child deadline", "let deadline = Instant::now() + CHILD_TIMEOUT;", 1),
    ("all child pipes are broker pipes", "command.stdout(Stdio::piped());", 1),
    ("child pipes nonblocking", "flags | libc::O_NONBLOCK", 1),
    ("single poll IO state machine", "fn supervise_io(", 1),
    ("bounded concurrent stdin write", "write_nonblocking_stdin(", 2),
    ("bounded stdout ceiling", "MAX_RESPONSE_BYTES)?", 1),
    ("bounded stderr ceiling", "MAX_CHILD_STDERR_BYTES", 2),
    ("one-byte overflow probe", "let requested = if remaining == 0 {", 2),
    ("descendant-held pipe deadline", "!stdin_open && !stdout_open && !stderr_open", 1),
    ("child process-group kill", "libc::kill(-pid, libc::SIGKILL)", 1),
    ("nonreaping child status observation", "libc::WEXITED | libc::WNOHANG | libc::WNOWAIT", 1),
    ("nonblocking child reap", "child.try_wait()", 1),
    ("successful-return containment", "let contained = terminate_and_reap(child, deadline);", 1),
    ("exceptional detached child reap", 'name("catalog-gh-exceptional-reaper".to_owned())', 1),
    ("pre-exec containment filter", "let mut containment_filter = process_containment_filter();", 1),
    ("containment installation", "install_process_containment(&mut containment_filter)", 1),
    ("containment no-new-privileges", "libc::PR_SET_NO_NEW_PRIVS", 1),
    ("containment seccomp mode", "libc::PR_SET_SECCOMP", 1),
    ("containment architecture constant", "AUDIT_ARCH_X86_64", 2),
    ("containment architecture fail-closed", "jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0)", 1),
    ("containment x32 constant", "X32_SYSCALL_BIT", 2),
    ("containment x32 fail-closed", "jump(BPF_JMP_JGE_K, X32_SYSCALL_BIT, 0, 1)", 1),
    ("required Go thread clone flags", "const GO_RUNTIME_THREAD_CLONE_REQUIRED: u32 = (libc::CLONE_VM\n        | libc::CLONE_FS\n        | libc::CLONE_FILES\n        | libc::CLONE_SIGHAND\n        | libc::CLONE_SYSVSEM\n        | libc::CLONE_THREAD) as u32;", 1),
    ("allowed Go thread clone metadata", "const GO_RUNTIME_THREAD_CLONE_ALLOWED: u32 = GO_RUNTIME_THREAD_CLONE_REQUIRED\n        | libc::CLONE_SETTLS as u32\n        | libc::CLONE_PARENT_SETTID as u32\n        | libc::CLONE_CHILD_SETTID as u32\n        | libc::CLONE_CHILD_CLEARTID as u32;", 1),
    ("required-mask Go thread clone predicate", "statement(BPF_ALU_AND_K, GO_RUNTIME_THREAD_CLONE_REQUIRED),\n        jump(BPF_JMP_JEQ_K, GO_RUNTIME_THREAD_CLONE_REQUIRED, 0, 3)", 1),
    ("allowed-mask Go thread clone predicate", "statement(BPF_ALU_AND_K, !GO_RUNTIME_THREAD_CLONE_ALLOWED),\n        jump(BPF_JMP_JEQ_K, 0, 1, 0)", 1),
    ("deny fork", "libc::SYS_fork,", 1),
    ("deny vfork", "libc::SYS_vfork,", 1),
    ("deny clone3", "libc::SYS_clone3,", 1),
    ("deny setsid", "libc::SYS_setsid,", 1),
    ("deny setpgid", "libc::SYS_setpgid,", 1),
    ("deny unshare", "libc::SYS_unshare,", 1),
    ("deny setns", "libc::SYS_setns,", 1),
    ("deny mount mutation", "libc::SYS_mount,", 1),
    ("deny new mount mutation", "libc::SYS_mount_setattr,", 1),
    ("deny ptrace escape", "libc::SYS_ptrace,", 1),
    ("deny process-memory escape", "libc::SYS_process_vm_writev,", 1),
    ("deny pidfd descriptor escape", "libc::SYS_pidfd_getfd,", 1),
    ("single exact launch call", "let mut command = Command::new(executable_path);", 1),
    ("retained executable proc capability", 'format!(\n        "/proc/self/fd/{}",\n        config.executable.file.as_raw_fd()', 1),
    ("child-only executable and config inheritance", "for descriptor in [executable_descriptor, config_directory_descriptor]", 1),
    ("private exact upload directory", 'create_private_directory(b"/tmp/catalog-gh-broker-upload-XXXXXX\\0")?', 1),
    ("private upload no-clobber create", "libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW", 2),
    ("upload exact read-only mode", "metadata.permissions().mode() & 0o7777 == 0o400", 1),
    ("private upload source rebind", "rebind_upload_source(&source)?;", 3),
    ("private upload final rebind", "rebind_upload(&capability)?;", 1),
    ("upload descriptor and named hash readback", "hash_descriptor(&rebound, capability.size)? != capability.sha256", 1),
    ("download anonymous memfd spool", "libc::SYS_memfd_create", 1),
    ("download spool is sealed", "seal_download_spool(spool)?;", 1),
    ("download streamed only to spool", "spool\n                    .file\n                    .write_all(&buffer[..read])", 1),
    ("download incremental ceiling", "MAX_ASSET_BYTES.saturating_sub(accumulator.size)", 1),
    ("download incremental hash", "accumulator.hasher.update(&buffer[..read]);", 1),
    ("settlement helper process", "settlement_helper_main(", 2),
    ("settlement separate deadline", "Instant::now() + DOWNLOAD_SETTLEMENT_TIMEOUT", 1),
    ("settlement helper fsync", "libc::fsync(output)", 2),
    ("settlement helper exact mode", "libc::fchmod(output, 0o400)", 1),
    ("all incremental descriptor hashes", "hasher.update(&buffer[..read]);", 4),
    ("settlement helper readback hash", "hasher.update(&first[..requested]);", 1),
    ("settlement expected hash equality", "        || digest != expected_digest\n", 1),
    ("settlement helper readback", "verify_settled_readback(", 2),
    ("post-settlement canonical verification", "verify_download_after_settlement(", 2),
    ("post-settlement canonical parent reopen", "let canonical_parent = open_absolute_no_links(\n        &capability.parent_path,\n        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,\n    )?;", 1),
    ("post-settlement exact parent identity", "exact_download_parent_identity(", 3),
    ("post-settlement canonical leaf reopen", "let canonical_leaf = openat_regular(&canonical_parent, &capability.name, libc::O_RDONLY)?;", 1),
    ("post-settlement exact canonical leaf identity", "Identity::from_metadata(&canonical_leaf_metadata) != final_identity", 1),
    ("post-settlement canonical leaf hash", "hash_descriptor(&canonical_leaf, final_identity.size)? != expected_sha256", 1),
    ("post-settlement canonical leaf readback", "!descriptor_readback_matches(&spool.file, &canonical_leaf, final_identity.size)?", 1),
    ("settlement nonblocking wait", "libc::waitpid(pid, &mut status, libc::WNOHANG)", 1),
    ("settlement helper kill", "unsafe { libc::kill(pid, libc::SIGKILL) };", 1),
    ("bounded exact-inode cleanup helper", "supervise_download_cleanup(self, Instant::now() + DOWNLOAD_CLEANUP_TIMEOUT)", 1),
    ("cleanup descriptor/name identity", "value.st_dev == identity.device && value.st_ino == identity.inode", 1),
    ("cleanup exact retained name", "libc::unlinkat(parent, name, 0)", 1),
    ("upload tag-only request", "UploadAsset {\n        schema_version: u16,\n        repository: String,\n        tag: String,\n        name: String,\n        input_path: String,\n    }", 1),
    ("upload no-ID response", "BrokerResponseV1::AssetUploaded {", 1),
    ("fixed failure output", 'const FAILURE_LINE: &[u8] = b"github broker failed\\n";', 1),
    ("explicit child response projection", "project_child_response(request, &supervised.stdout, upload.as_ref())?", 1),
]

validator_calls = [
    ("schema-version validation", "valid_schema(*schema_version)?;", 11),
    ("repository validation", "valid_repository(repository)?;", 6),
    ("tag validation", "valid_tag(tag)?;", 5),
    ("commit validation", "valid_sha1(commit_sha)", 2),
    ("target commit validation", "valid_sha1(target_commitish)?;", 2),
    ("title validation", "valid_title(title)?;", 1),
    ("notes validation", "valid_notes(notes)", 1),
    ("release ID validation", "valid_decimal_id(release_id)?;", 1),
    ("asset ID validation", "valid_decimal_id(asset_id)?;", 1),
    ("asset name validation", "valid_asset_name(name)?;", 3),
    ("upload path validation", "valid_path_text(input_path)", 1),
    ("download path validation", "valid_path_text(output_path)", 1),
]

test_policies = [
    ("upload request release-ID mismatch", '"release_id":"7","repository":"owner/name","schema_version":1,"tag":"catalog-v1-sequence-1"', 1),
    ("upload response release-ID mismatch", '"name":"support.bin","release_id":"7","schema_version":1', 1),
    ("setsid fake probe", "SYS_setsid", 1),
    ("setpgid fake probe", "SYS_setpgid", 1),
    ("fork fake probe", "SYS_fork", 1),
    ("vfork fake probe", "SYS_vfork", 1),
    ("clone3 fake probe", "SYS_clone3", 1),
    ("thread-only clone fake probe", "CLONE_THREAD", 2),
    ("SETTLS compatibility fake probe", "int settls_errno = controlled_thread_clone_errno(", 1),
    ("post-settlement parent-swap checkpoint", "fn after_download_settlement_helper(&mut self)", 1),
    ("post-exec persistence fake probe", "--post-exec-containment-probe", 2),
    ("config-retention survivor marker", "escaped-config-marker", 2),
    ("blocked settlement writer fault", "block_download_settlement_after_first_write", 1),
    ("stubborn post-deadline fake", "stubborn-closed-stdio", 1),
]

validator_predicates = [
    ("repository one-slash grammar", "repository.matches('/').count() != 1", 1),
    ("owner bounded grammar", "owner.len() > 39", 1),
    ("repository-name bounded grammar", "name.len() > 100", 1),
    ("production tag prefix", '.strip_prefix("catalog-v1-sequence-")', 1),
    ("transport tag", 'tag == "transport-v1"', 1),
    ("full lowercase SHA-1", "value.len() != 40", 1),
    ("bounded canonical decimal ID", "value.len() > 19", 1),
    ("safe asset component grammar", "value.contains(\"..\")", 1),
    ("bounded title", "value.len() > 256", 1),
    ("bounded notes", "value.len() > 16 * 1024", 1),
    ("absolute lexical asset path", "if !path.is_absolute()", 1),
]


def broker_errors(source, binary_source=binary, lib_source=lib, local_source=local, main_source=main, test_source=tests):
    errors = []
    for label, snippet, expected in policies + validator_calls + validator_predicates:
        actual = source.count(snippet)
        if actual != expected:
            errors.append(f"missing exact broker policy {label}: expected {expected}, got {actual}")
    for label, snippet, expected in test_policies:
        actual = test_source.count(snippet)
        if actual != expected:
            errors.append(f"missing exact broker fake probe {label}: expected {expected}, got {actual}")

    request_enum = source.split("pub enum BrokerRequestV1 {", 1)[-1].split("impl BrokerRequestV1", 1)[0]
    variants = re.findall(r"^    ([A-Z][A-Za-z]+) \{", request_enum, re.MULTILINE)
    if variants != [
        "CreateTag", "ReadTag", "CreateDraft", "ReadDraft", "UploadAsset",
        "DownloadAsset", "PublishDraft",
    ]:
        errors.append(f"broker request variants changed: {variants}")
    for forbidden in [
        "method:", "endpoint:", "host:", "headers:", "gh_args:", "query:",
        "template:", "jq:", "graphql:", "token:", "environment:", "git_command:",
    ]:
        if forbidden in request_enum:
            errors.append(f"broker request gained arbitrary authority field: {forbidden}")
    upload_decl = request_enum.split("UploadAsset {", 1)[-1].split("},", 1)[0]
    upload_fields = re.findall(r"^        ([a-z0-9_]+):", upload_decl, re.MULTILINE)
    if upload_fields != ["schema_version", "repository", "tag", "name", "input_path"]:
        errors.append(f"upload authority is not exact tag-only schema: {upload_fields}")
    response_enum = source.split("pub enum BrokerResponseV1 {", 1)[-1].split("impl BrokerResponseV1", 1)[0]
    upload_response = response_enum.split("AssetUploaded {", 1)[-1].split("},", 1)[0]
    response_fields = re.findall(r"^        ([a-z0-9_]+):", upload_response, re.MULTILINE)
    if response_fields != ["schema_version", "status", "name", "size", "sha256"]:
        errors.append(f"upload response gained remote-ID authority: {response_fields}")

    terminate = source.split("fn terminate_and_reap(", 1)[-1].split("fn handoff_exceptional_child_reap", 1)[0]
    if ".wait(" in terminate or "waitpid(" in terminate:
        errors.append("terminate_and_reap gained a blocking post-deadline wait")
    transport_drain = source.split("fn drain_download_stdout(", 1)[-1].split("fn terminate_and_reap(", 1)[0]
    if "DownloadCapability" in transport_drain or "capability.file" in transport_drain:
        errors.append("download transport can write the final output instead of its anonymous spool")

    config_decl = source.split("pub struct PublisherBrokerConfigV1", 1)[-1].split("}", 1)[0]
    config_fields = re.findall(r"pub ([a-z0-9_]+):", config_decl)
    if config_fields != ["schema_version", "gh_path", "gh_sha256", "github_config_dir"]:
        errors.append(f"broker config fields changed: {config_fields}")
    for forbidden in ["token", "credential", "header", "host_override", "home"]:
        if forbidden in config_decl.lower():
            errors.append(f"broker config gained secret/discovery field: {forbidden}")

    environment_names = re.findall(r'command\.env\(\s*"([A-Z_]+)"', source)
    if environment_names != ["HOME", "GH_CONFIG_DIR", "LANG", "LC_ALL", "TZ"]:
        errors.append(f"broker environment allowlist changed: {environment_names}")
    command_sources = {
        "crates/catalog-publish/src/broker.rs": source,
        "crates/catalog-publish/src/bin/catalog-gh-broker.rs": binary_source,
        "crates/catalog-publish/src/lib.rs": lib_source,
        "crates/catalog-publish/src/local.rs": local_source,
        "crates/catalog-publish/src/main.rs": main_source,
    }
    for name, candidate in command_sources.items():
        count = candidate.count("Command::new(")
        if name == "crates/catalog-publish/src/broker.rs":
            if count != 1:
                errors.append(f"broker launch call count changed: {count}")
        elif count:
            errors.append(f"process launch escaped broker implementation: {name}")
    for forbidden in [
        "/bin/sh", "sh -c", "gh auth", "auth token", "api graphql", "--jq",
        "--template", "--hostname", "--clobber", "reqwest::", "ureq::", "curl::",
        "std::net::", "TcpStream", "UdpSocket", "println!(child", "eprintln!(child",
        "spawn_bounded_reader", "thread::spawn", "Stdio::from(",
        "config.executable.path.as_os_str().to_owned()",
    ]:
        if forbidden in source:
            errors.append(f"broker gained forbidden command/network/raw-output seam: {forbidden}")
    command_matrix = [
        ("create_tag method/route", '"POST",\n            format!("/repos/{repository}/git/refs")'),
        ("create_tag body", '"ref": format!("refs/tags/{tag}"),\n                "sha": commit_sha'),
        ("read_tag method/route", '"GET",\n            format!("/repos/{repository}/git/ref/tags/{tag}")'),
        ("create_draft method/route", '"POST",\n            format!("/repos/{repository}/releases")'),
        ("create_draft body", '"draft": true,\n                "name": title,\n                "prerelease": prerelease,\n                "tag_name": tag,\n                "target_commitish": target_commitish'),
        ("read_draft method/route", '"GET",\n            format!("/repos/{repository}/releases/tags/{tag}")'),
        ("upload fixed release family", 'OsString::from("release"),\n                    OsString::from("upload"),\n                    OsString::from(tag),\n                    capability.path.as_os_str().to_owned(),\n                    OsString::from("--repo"),\n                    OsString::from(repository)'),
        ("download method/route/accept", '"GET",\n            format!("/repos/{repository}/releases/assets/{asset_id}"),\n            "Accept: application/octet-stream"'),
        ("publish method/route/body", '"PATCH",\n            format!("/repos/{repository}/releases/{release_id}"),\n            "Accept: application/vnd.github+json",\n            Some(canonical_value(&serde_json::json!({"draft": false}))?)'),
        ("fixed API version", 'OsString::from("X-GitHub-Api-Version: 2022-11-28")'),
    ]
    for label, required in command_matrix:
        if source.count(required) != 1:
            errors.append(f"fixed command matrix lost {label}")
    required_tests = [
        "ambient-gh-token-canary", "ambient-github-token-canary", "ambient-proxy-canary",
        "ambient-agent-canary", "raw-token-canary", "CONFIG_CANARY", "FloodStdout",
        "FloodStderr", "Deadlock", "Timeout", "Signal", "InvalidUtf8", "download-no-clobber",
        "delayed-stdin", "non-reading-stdin", "stubborn-closed-stdio",
        "leader-exits-after-denied-closed-stdio-fork", "denied-descendant-cannot-flood-retained-pipes",
        "denied-descendant-cannot-retain-config", "containment-syscall-probe",
        "containment-persists-across-later-exec", "--post-exec-containment-probe", "process_clone",
        "thread_clone", "SYS_setsid", "SYS_setpgid", "SYS_fork", "SYS_vfork", "SYS_clone3",
        "CLONE_THREAD", '"release_id":"7","repository":"owner/name","schema_version":1,"tag":"catalog-v1-sequence-1"',
        '"name":"support.bin","release_id":"7","schema_version":1', "escaped-config-marker",
        "block_download_settlement_after_first_write", "download-overflow", "download-descendant",
        "download-blocked-settlement-writer", "download-post-settlement-parent-swap",
        "settls_clone", "missing_thread", "extra_newnet", "high_word",
        "script-rejected", "after-final-rebind", "replace-before-spawn",
        "repeated_and_concurrent_requests",
        "release_upload_materializes_private_exact_file_and_returns_no_fabricated_id",
    ]
    for required in required_tests:
        if required not in test_source:
            errors.append(f"broker adversarial evidence missing: {required}")
    return errors


errors = broker_errors(broker)
if errors:
    print(errors[0], file=sys.stderr)
    sys.exit(1)

# Remove every occurrence independently where a policy has multiple enforcement call sites.
for label, snippet, expected in policies + validator_calls + validator_predicates:
    for occurrence in range(expected):
        start = -1
        for _ in range(occurrence + 1):
            start = broker.find(snippet, start + 1)
        if start < 0:
            print(f"broker mutation could not be applied: {label} occurrence {occurrence}", file=sys.stderr)
            sys.exit(1)
        mutation = broker[:start] + f"REMOVED_BROKER_POLICY_{label}" + broker[start + len(snippet):]
        if not broker_errors(mutation):
            print(f"broker scanner accepted removed enforcement: {label} occurrence {occurrence}", file=sys.stderr)
            sys.exit(1)

# Remove the adversarial fake probes one at a time too; production-policy tokens without the
# compiled ELF behavior and exact protocol mismatch evidence are not an accepted boundary.
for label, snippet, expected in test_policies:
    for occurrence in range(expected):
        start = -1
        for _ in range(occurrence + 1):
            start = tests.find(snippet, start + 1)
        if start < 0:
            print(f"broker fake mutation could not be applied: {label} occurrence {occurrence}", file=sys.stderr)
            sys.exit(1)
        mutation = tests[:start] + f"REMOVED_BROKER_TEST_{label}" + tests[start + len(snippet):]
        if not broker_errors(broker, test_source=mutation):
            print(f"broker scanner accepted removed fake probe: {label} occurrence {occurrence}", file=sys.stderr)
            sys.exit(1)

# Semantic one-at-a-time bypasses retain neighboring method/route/body tokens so the scanner
# freezes enforcement rather than merely noticing that the operation name still exists.
for label, old, new in [
    ("create_tag method", '"POST",\n            format!("/repos/{repository}/git/refs")', '"GET",\n            format!("/repos/{repository}/git/refs")'),
    ("create_tag route", 'format!("/repos/{repository}/git/refs")', 'format!("/repos/{repository}/git/ref")'),
    ("create_tag body", '"sha": commit_sha', '"target": commit_sha'),
    ("read_tag method", '"GET",\n            format!("/repos/{repository}/git/ref/tags/{tag}")', '"POST",\n            format!("/repos/{repository}/git/ref/tags/{tag}")'),
    ("read_tag route", 'format!("/repos/{repository}/git/ref/tags/{tag}")', 'format!("/repos/{repository}/git/refs/tags/{tag}")'),
    ("create_draft method", '"POST",\n            format!("/repos/{repository}/releases")', '"GET",\n            format!("/repos/{repository}/releases")'),
    ("create_draft route", 'format!("/repos/{repository}/releases")', 'format!("/repos/{repository}/release")'),
    ("create_draft body", '"draft": true', '"draft": false'),
    ("read_draft method", '"GET",\n            format!("/repos/{repository}/releases/tags/{tag}")', '"POST",\n            format!("/repos/{repository}/releases/tags/{tag}")'),
    ("read_draft route", 'format!("/repos/{repository}/releases/tags/{tag}")', 'format!("/repos/{repository}/releases/tag/{tag}")'),
    ("upload family", 'OsString::from("release"),\n                    OsString::from("upload")', 'OsString::from("api"),\n                    OsString::from("upload")'),
    ("upload exact tag", 'OsString::from(tag),\n                    capability.path.as_os_str().to_owned()', 'OsString::from(repository),\n                    capability.path.as_os_str().to_owned()'),
    ("upload repository binding", 'OsString::from("--repo"),\n                    OsString::from(repository)', 'OsString::from("--repo"),\n                    OsString::from(tag)'),
    ("upload no-clobber", 'OsString::from("--repo"),', 'OsString::from("--clobber"),\n                    OsString::from("--repo"),'),
    ("download method", '"GET",\n            format!("/repos/{repository}/releases/assets/{asset_id}")', '"POST",\n            format!("/repos/{repository}/releases/assets/{asset_id}")'),
    ("download route", 'format!("/repos/{repository}/releases/assets/{asset_id}")', 'format!("/repos/{repository}/releases/{asset_id}")'),
    ("download accept", '"Accept: application/octet-stream",\n            None,', '"Accept: application/vnd.github+json",\n            None,'),
    ("publish method", '"PATCH",\n            format!("/repos/{repository}/releases/{release_id}")', '"POST",\n            format!("/repos/{repository}/releases/{release_id}")'),
    ("publish route", 'format!("/repos/{repository}/releases/{release_id}")', 'format!("/repos/{repository}/release/{release_id}")'),
    ("publish body", 'serde_json::json!({"draft": false})', 'serde_json::json!({"draft": true})'),
    ("upload ignored release ID reintroduction", "repository: String,\n        tag: String,\n        name: String,", "repository: String,\n        release_id: String,\n        tag: String,\n        name: String,"),
    ("upload response ID fabrication", "status: BrokerAssetUploadStatusV1,\n        name: String,", "status: BrokerAssetUploadStatusV1,\n        release_id: String,\n        name: String,"),
    ("executable hash bypass", "hash_descriptor(&executable.file, executable.identity.size)? != executable.sha256", "false /* hash_descriptor executable sha256 */"),
    ("settlement hash bypass", "digest != expected_digest", "false /* digest != expected_digest */"),
    ("request authority ordering", "request.validate()?;\n    let config = read_config", "let config = read_config /* request.validate moved after authority */"),
    ("seccomp installation bypass", "install_process_containment(&mut containment_filter)", "Ok(()) /* install_process_containment bypass */"),
    ("seccomp architecture bypass", "jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0)", "jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 0, 1)"),
    ("seccomp x32 bypass", "jump(BPF_JMP_JGE_K, X32_SYSCALL_BIT, 0, 1)", "jump(BPF_JMP_JGE_K, X32_SYSCALL_BIT, 1, 0)"),
    ("clone required-mask comparison bypass", "jump(BPF_JMP_JEQ_K, GO_RUNTIME_THREAD_CLONE_REQUIRED, 0, 3)", "jump(BPF_JMP_JEQ_K, GO_RUNTIME_THREAD_CLONE_REQUIRED, 3, 0) /* required-mask bypass */"),
    ("clone allowed-mask comparison bypass", "jump(BPF_JMP_JEQ_K, 0, 1, 0)", "jump(BPF_JMP_JEQ_K, 0, 0, 1) /* allowed-mask bypass */"),
    ("post-settlement parent identity bypass", ") || !exact_download_parent_identity(\n        Identity::from_metadata(&canonical_parent_metadata),\n        capability.parent_identity,\n    ) ||", ") || false /* exact_download_parent_identity canonical parent bypass */ ||"),
    ("post-settlement leaf identity bypass", "Identity::from_metadata(&canonical_leaf_metadata) != final_identity", "false /* Identity::from_metadata canonical_leaf_metadata final_identity bypass */"),
    ("successful-return containment bypass", "let contained = terminate_and_reap(child, deadline);", "let contained = Ok(()) /* terminate_and_reap only on error */;"),
    ("status reaps before group kill", "libc::WEXITED | libc::WNOHANG | libc::WNOWAIT", "libc::WEXITED | libc::WNOHANG /* WNOWAIT */"),
    ("blocking post-deadline wait", "match child.try_wait()", "match child.wait() /* try_wait */"),
    ("child environment clear", "command.env_clear();", "/* command env_clear removed */"),
    ("child pipe nonblocking", "flags | libc::O_NONBLOCK", "flags /* O_NONBLOCK retained token */"),
    ("stdin supervision", "write_nonblocking_stdin(", "bypassed_nonblocking_stdin("),
    ("descendant pipe completion", "!stdin_open && !stdout_open && !stderr_open", "leader_status.is_some()"),
    ("download streaming ceiling", "MAX_ASSET_BYTES.saturating_sub(accumulator.size)", "u64::MAX.saturating_sub(accumulator.size) /* MAX_ASSET_BYTES */"),
    ("download spool/final separation", "spool\n                    .file\n                    .write_all(&buffer[..read])", "final_output /* spool */\n                    .file\n                    .write_all(&buffer[..read])"),
    ("settlement deadline bypass", "Instant::now() + DOWNLOAD_SETTLEMENT_TIMEOUT", "Instant::now() + Duration::MAX /* DOWNLOAD_SETTLEMENT_TIMEOUT */"),
    ("settlement kill bypass", "libc::kill(pid, libc::SIGKILL)", "0 /* libc::kill(pid, libc::SIGKILL) */"),
    ("settlement cleanup bypass", "supervise_download_cleanup(self, Instant::now() + DOWNLOAD_CLEANUP_TIMEOUT)", "Ok(()) /* supervise_download_cleanup DOWNLOAD_CLEANUP_TIMEOUT */"),
    ("ELF-only admission", "validate_elf_executable(&executable_file, executable_identity.size)?;", "/* validate_elf_executable retained but bypassed */"),
    ("named execution fallback", "let executable_path = OsString::from(format!(", "let executable_path = config.executable.path.as_os_str().to_owned(); let _retained = OsString::from(format!("),
    ("fresh output no-clobber", "libc::O_EXCL", "0 /* O_EXCL */"),
]:
    mutation = broker.replace(old, new, 1)
    if mutation == broker or not broker_errors(mutation):
        print(f"broker scanner accepted semantic bypass: {label}", file=sys.stderr)
        sys.exit(1)
PY
