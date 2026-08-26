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
retained_tar_call = (
    'tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as opened:'
)

def evidence_reader_errors(generator, signing):
    errors = []
    if re.search(r"\.read_bytes\s*\(", generator):
        errors.append("pathname read_bytes in approved-release evidence generator")
    tar_calls = re.findall(r"tarfile\.open\([^\n]*", generator)
    if tar_calls != [retained_tar_call]:
        errors.append("archive parsing is not exclusively retained-byte BytesIO parsing")
    start = signing.find("    struct AuthenticatedCorpus {")
    end = signing.find("    type FixtureObjects", start)
    if start < 0 or end < 0:
        errors.append("authenticated corpus capability boundary is missing")
    else:
        corpus_reader = signing[start:end]
        if re.search(r"\bfs::read\s*\(", corpus_reader):
            errors.append("pathname fs::read in authenticated corpus reader")
        for required in [
            "libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK",
            "0x02 | 0x04 | 0x08",
            ".take(expected_size + 1)",
            "PublicCorpusMetadata::from_metadata(&rebound) != before",
        ]:
            if required not in corpus_reader:
                errors.append(f"missing retained corpus reader boundary: {required}")
    return errors

errors = evidence_reader_errors(generator_source, signing_source)
if errors:
    print(errors[0], file=sys.stderr)
    sys.exit(1)

read_mutation = generator_source + '\nPath("mutation").read_bytes()\n'
if not evidence_reader_errors(read_mutation, signing_source):
    print("evidence scanner accepted a Path.read_bytes mutation", file=sys.stderr)
    sys.exit(1)

tar_mutation = generator_source.replace(
    retained_tar_call,
    'tarfile.open(archive_label, mode="r:*") as opened:',
    1,
)
if not evidence_reader_errors(tar_mutation, signing_source):
    print("evidence scanner accepted a pathname tar reopen mutation", file=sys.stderr)
    sys.exit(1)

rust_mutation = signing_source.replace(
    "            let mut file = self.open_relative(relative)?;",
    "            let bytes = fs::read(relative)?;\n            let mut file = self.open_relative(relative)?;",
    1,
)
if not evidence_reader_errors(generator_source, rust_mutation):
    print("evidence scanner accepted an fs::read mutation", file=sys.stderr)
    sys.exit(1)
PY
