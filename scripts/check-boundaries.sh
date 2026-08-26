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

expected_members = sorted(expected_names)
member_names = sorted(packages[name]["name"] for name in actual_names)
if member_names != expected_members:
    print(f"unexpected workspace member set: {member_names}", file=sys.stderr)
    sys.exit(1)

expected_deps = {
    "catalog-core": [],
    "catalog-acquire": ["catalog-core"],
    "catalog-sign": ["catalog-core"],
    "catalog-publish": ["catalog-core"],
}
for name, deps in expected_deps.items():
    actual = sorted(dep["name"] for dep in packages[name]["dependencies"])
    if actual != deps:
        print(f"unexpected dependencies for {name}: {actual}", file=sys.stderr)
        sys.exit(1)
PY
