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
    "catalog-sign": [],
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
