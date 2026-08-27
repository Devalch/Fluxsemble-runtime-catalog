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
