#!/usr/bin/env python3
"""Generate standalone Task 6 approved-release evidence from authenticated public inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from pathlib import Path
from typing import Any

MATRIX_SHA256 = "6f389eb3b8b040acda99e63b8dfb0be710dc666182438b7b1c5881e430076d53"
APPROVAL_REPORT_SHA256 = "c4864c7bdccaf5ee9fa2e607ecf46a1657c8026fa6af0f492e021cf4724c4996"
PACKAGE_PROVENANCE_SHA256 = "3bb528f91e7cb6e8124d831bac6e06cc36a962691c72b4eec58b86b34d197c57"
CORPUS_SHA256_FILE_SHA256 = "9a7076a06bb66fbcbd6cdf430c55f21fdd16f42a0eeed93c39fdb7ac0941979c"
SOURCE_COMMIT = "2d5d104cec3c68b51469ca8ffa34642558fdfd67"

PACKAGE_INPUT_DOMAIN = b"fluxsemble:runtime-catalog-approved-package-input-manifest:v1\0"
RELEASE_SEMANTIC_DOMAIN = b"fluxsemble:runtime-catalog-approved-release-semantics:v1\0"
PACKAGE_INPUT_RAW_SHA256 = "d511e45be4fc28ec20c62c2450b61ab61e61fbbd12024a1e95698ab0b702a02d"
PACKAGE_INPUT_DOMAIN_SHA256 = "04ff8560de163983621e86598c8eb6b80fabb32cfced020602c14ed45818f9ef"
RELEASE_SEMANTIC_SHA256 = "46116101d1ffa3b1184d14347f62478fbc3a2d609afc3ba0bf6b2505265e8441"

ROOT_NAME = "@earendil-works/pi-coding-agent"
ROOT_VERSION = "0.83.0"
ROOT_ARCHIVE_SHA256 = "7097fe4b38762dda7ec78001e7b90430c849fbaf717325bfe8109744e32255e6"
ROOT_ARCHIVE_SIZE = 4_992_066
ROOT_ARCHIVE_URL = (
    "https://registry.npmjs.org/@earendil-works/pi-coding-agent/-/"
    "pi-coding-agent-0.83.0.tgz"
)
ROOT_REGISTRY_INTEGRITY = (
    "sha512-uYhF+FsZxogoSX/AxBcUdiY+ZklubwaXyAoEGA2eQwsHcyEAhUYIKh/"
    "WLXe/a8+k8eTCmxb+ZN2Zo9mzQtzbWw=="
)
ROOT_MANIFEST_SHA256 = "e02deae1cec07035807436c1864c88342e2f7d49050d03b858a3719f0c7aedbf"
ROOT_MANIFEST_SIZE = 3_560
SHRINKWRAP_SHA256 = "9a17a6b9ba0a57b37773644f7945b1bf0bc10aa8923b87233fee6f75af1e1772"
SHRINKWRAP_SIZE = 61_540

NODE_VERSION = "22.19.0"
NODE_ARCHIVE_SHA256 = "c0649af18e6a24f6fe5535a3e86b341dd49a8e71117c8b68bde973ef834f16f2"
NODE_ARCHIVE_SIZE = 30_479_988
NODE_ARCHIVE_URL = "https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.xz"
NODE_MEMBER = "node-v22.19.0-linux-x64/bin/node"
NODE_INVENTORY_PATH = "bin/node"
NODE_INVENTORY_SIZE = 121_674_800
NODE_INVENTORY_SHA256 = "596b5144ff242737f1c1be6a5f0ccb3907dbba2482344143cb1a6898633402a9"
PI_MEMBER = "package/dist/cli.js"
PI_INVENTORY_PATH = "dist/cli.js"
PI_INVENTORY_SIZE = 681
PI_INVENTORY_SHA256 = "af302f231437eaf6f37691bce4b34234fcb626bcb5eb3910d4fc3f6519bf78ca"

TAG = "catalog-v1-sequence-1"
GENERATED_AT = "2026-08-26T00:00:00Z"
EXPIRES_AT = "2026-09-26T00:00:00Z"
RELEASE_METADATA = {
    "title": "Pi 0.83.0",
    "notes": "Approved managed Pi release.",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    # The generated schemas contain no JSON numbers outside small integers and no floats.
    # Rust tests independently parse and RFC 8785-reserialize these bytes.
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def load_unique(path: Path, expected_sha256: str) -> tuple[dict[str, Any], bytes]:
    data = path.read_bytes()
    if sha256(data) != expected_sha256:
        raise ValueError(f"authenticated input digest mismatch: {path}")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON member in {path}: {key}")
            result[key] = value
        return result

    value = json.loads(data, object_pairs_hook=unique_pairs)
    if not isinstance(value, dict):
        raise ValueError(f"authenticated input is not an object: {path}")
    return value, data


def require_regular_member(
    archive: Path,
    expected_archive_size: int,
    expected_archive_sha256: str,
    member_name: str,
    expected_member_size: int,
    expected_member_sha256: str,
) -> bytes:
    archive_bytes = archive.read_bytes()
    if len(archive_bytes) != expected_archive_size or sha256(archive_bytes) != expected_archive_sha256:
        raise ValueError(f"authenticated archive mismatch: {archive}")
    with tarfile.open(archive, "r:*") as opened:
        matches = [member for member in opened.getmembers() if member.name == member_name]
        if len(matches) != 1:
            raise ValueError(f"required archive member is not unique: {member_name}")
        member = matches[0]
        if not member.isfile() or member.issym() or member.islnk():
            raise ValueError(f"required archive member is not regular: {member_name}")
        extracted = opened.extractfile(member)
        if extracted is None:
            raise ValueError(f"required archive member cannot be read: {member_name}")
        data = extracted.read(expected_member_size + 1)
    if len(data) != expected_member_size or sha256(data) != expected_member_sha256:
        raise ValueError(f"required archive member bytes mismatch: {member_name}")
    return data


def validate_approval_pair(matrix: dict[str, Any], approval: dict[str, Any]) -> None:
    if approval.get("runtime_matrix_sha256") != MATRIX_SHA256:
        raise ValueError("approval report does not bind the authenticated runtime matrix")
    report_matrix = approval.get("runtime_matrix")
    if not isinstance(report_matrix, dict):
        raise ValueError("approval report has no runtime matrix projection")
    exact = {
        "fluxsemble_version": matrix.get("fluxsemble_version"),
        "node_version": matrix.get("node", {}).get("version"),
        "node_target": matrix.get("node", {}).get("target"),
        "node_url": matrix.get("node", {}).get("url"),
        "node_sha256": matrix.get("node", {}).get("sha256"),
        "pi_package": matrix.get("pi", {}).get("package"),
        "pi_version": matrix.get("pi", {}).get("version"),
        "pi_target": matrix.get("pi", {}).get("target"),
        "pi_archive_count": matrix.get("pi", {}).get("archive_count"),
        "pi_corpus_file_count": matrix.get("pi", {}).get("corpus_file_count"),
        "pi_allowed_origins": matrix.get("pi", {}).get("allowed_origins"),
    }
    for key, expected in exact.items():
        if report_matrix.get(key) != expected:
            raise ValueError(f"approved input pair conflicts at runtime_matrix.{key}")
    if (
        exact["fluxsemble_version"] != "0.1.0"
        or exact["node_version"] != NODE_VERSION
        or exact["node_target"] != "linux-x86_64"
        or exact["node_url"] != NODE_ARCHIVE_URL
        or exact["node_sha256"] != NODE_ARCHIVE_SHA256
        or exact["pi_package"] != ROOT_NAME
        or exact["pi_version"] != ROOT_VERSION
        or exact["pi_target"] != "linux-x86_64"
        or exact["pi_archive_count"] != 140
        or exact["pi_allowed_origins"] != ["https://registry.npmjs.org"]
        or approval.get("fluxsemble_version_requirement") != "=0.1.0"
    ):
        raise ValueError("approved input pair does not describe the initial runtime tuple")


def derive_package_input(corpus: Path, provenance: dict[str, Any]) -> dict[str, Any]:
    packages = provenance.get("packages")
    pruning = provenance.get("install_pruning")
    if not isinstance(packages, list) or len(packages) != 140 or not isinstance(pruning, dict):
        raise ValueError("authenticated package provenance has an unexpected closure")
    root = packages[0]
    if root.get("path") != "" or root.get("name") != ROOT_NAME or root.get("version") != ROOT_VERSION:
        raise ValueError("authenticated package provenance has an unexpected root")

    root_archive = corpus / str(root["archive_path"])
    root_manifest = require_regular_member(
        root_archive,
        ROOT_ARCHIVE_SIZE,
        ROOT_ARCHIVE_SHA256,
        "package/package.json",
        ROOT_MANIFEST_SIZE,
        ROOT_MANIFEST_SHA256,
    )
    shrinkwrap_bytes = require_regular_member(
        root_archive,
        ROOT_ARCHIVE_SIZE,
        ROOT_ARCHIVE_SHA256,
        "package/npm-shrinkwrap.json",
        SHRINKWRAP_SIZE,
        SHRINKWRAP_SHA256,
    )
    shrinkwrap = json.loads(shrinkwrap_bytes)
    lock_packages = shrinkwrap.get("packages")
    if not isinstance(lock_packages, dict) or len(lock_packages) != 140:
        raise ValueError("authenticated shrinkwrap has an unexpected closure")

    decisions = pruning.get("decisions")
    if not isinstance(decisions, list) or len(decisions) != 9:
        raise ValueError("authenticated applicability evidence is incomplete")
    pruned = {
        decision["lock_path"]: decision["selector_sources"]
        for decision in decisions
    }

    locked: list[dict[str, Any]] = []
    for package in packages[1:]:
        locator = package["path"]
        lock = lock_packages.get(locator)
        if not isinstance(lock, dict):
            raise ValueError(f"authenticated shrinkwrap is missing {locator}")
        archive_path = corpus / str(package["archive_path"])
        archive_bytes = archive_path.read_bytes()
        if sha256(archive_bytes) != package["archive_sha256"]:
            raise ValueError(f"authenticated package archive mismatch: {locator}")
        declaration = corpus / str(package["declaration"]["path"])
        declaration_bytes = declaration.read_bytes()
        if sha256(declaration_bytes) != package["declaration"]["sha256"]:
            raise ValueError(f"authenticated package declaration mismatch: {locator}")
        applicability: dict[str, Any]
        if locator in pruned:
            applicability = {"kind": "pruned", "reasons": pruned[locator]}
        else:
            applicability = {"kind": "applicable"}
        locked.append(
            {
                "locator": locator,
                "name": package["name"],
                "version": package["version"],
                "resolved_url": lock["resolved"],
                "registry_integrity": package["integrity"],
                "archive_size": len(archive_bytes),
                "archive_sha256": package["archive_sha256"],
                "declaration_sha256": package["declaration"]["sha256"],
                "archive_member_count": package["archive_stats"]["logical_members"],
                "applicability": applicability,
            }
        )
    if [record["locator"] for record in locked] != sorted(record["locator"] for record in locked):
        raise ValueError("authenticated package records are not canonical by locator")

    return {
        "schema_version": 1,
        "target_os": "linux",
        "target_cpu": "x64",
        "target_libc": "glibc",
        "root": {
            "name": ROOT_NAME,
            "version": ROOT_VERSION,
            "archive_size": ROOT_ARCHIVE_SIZE,
            "archive_sha256": ROOT_ARCHIVE_SHA256,
            "manifest_size": len(root_manifest),
            "manifest_sha256": ROOT_MANIFEST_SHA256,
            "shrinkwrap_size": len(shrinkwrap_bytes),
            "shrinkwrap_sha256": SHRINKWRAP_SHA256,
            "archive_member_count": root["archive_stats"]["logical_members"],
        },
        "locked_packages": locked,
        "pre_prune_package_count": pruning["pre_prune_installed_count"],
        "applicable_package_count": sum(
            record["applicability"]["kind"] == "applicable" for record in locked
        ),
    }


def derive_intent(package_input: dict[str, Any]) -> dict[str, Any]:
    locked = [
        {
            key: record[key]
            for key in (
                "locator",
                "name",
                "version",
                "resolved_url",
                "registry_integrity",
                "archive_sha256",
            )
        }
        for record in package_input["locked_packages"]
    ]
    release_prefix = (
        "https://github.com/Devalch/Fluxsemble-runtime-catalog/releases/download/"
        f"{TAG}/"
    )
    return {
        "sequence": "1",
        "tag": TAG,
        "generated_at": GENERATED_AT,
        "expires_at": EXPIRES_AT,
        "fluxsemble_requirement": "=0.1.0",
        "release": {
            "provider": "builtin:pi",
            "allowed_origins": [
                "https://github.com",
                "https://nodejs.org",
                "https://registry.npmjs.org",
            ],
            "release": {
                "version": ROOT_VERSION,
                "target": "linux_x86_64",
                "compatibility_ranges": ["=0.1.0"],
                "release_metadata": RELEASE_METADATA,
                "components": [
                    {
                        "component_id": "component:node",
                        "version": NODE_VERSION,
                        "artifacts": [
                            {
                                "artifact_id": "artifact:node-linux-x86_64",
                                "url": NODE_ARCHIVE_URL,
                                "size_bytes": str(NODE_ARCHIVE_SIZE),
                                "sha256": NODE_ARCHIVE_SHA256,
                                "inventory": [
                                    {
                                        "path": NODE_INVENTORY_PATH,
                                        "size_bytes": str(NODE_INVENTORY_SIZE),
                                        "sha256": NODE_INVENTORY_SHA256,
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "component_id": "component:pi",
                        "version": ROOT_VERSION,
                        "artifacts": [
                            {
                                "artifact_id": "artifact:pi-coding-agent",
                                "url": ROOT_ARCHIVE_URL,
                                "size_bytes": str(ROOT_ARCHIVE_SIZE),
                                "sha256": ROOT_ARCHIVE_SHA256,
                                "inventory": [
                                    {
                                        "path": PI_INVENTORY_PATH,
                                        "size_bytes": str(PI_INVENTORY_SIZE),
                                        "sha256": PI_INVENTORY_SHA256,
                                    }
                                ],
                            }
                        ],
                    },
                ],
                "provider_extension": {
                    "kind": "pi",
                    "metadata": {
                        "approved_package": {"name": ROOT_NAME, "version": ROOT_VERSION},
                        "expected_entrypoint": PI_INVENTORY_PATH,
                        "component_id": "component:pi",
                        "package_artifact_id": "artifact:pi-coding-agent",
                        "registry_integrity": ROOT_REGISTRY_INTEGRITY,
                        "root_package_manifest": {
                            "url": f"{release_prefix}pi-package-{ROOT_MANIFEST_SHA256}.json",
                            "size_bytes": str(ROOT_MANIFEST_SIZE),
                            "sha256": ROOT_MANIFEST_SHA256,
                        },
                        "shipped_shrinkwrap": {
                            "lockfile_version": 3,
                            "root_package": {"name": ROOT_NAME, "version": ROOT_VERSION},
                            "artifact": {
                                "url": f"{release_prefix}pi-shrinkwrap-{SHRINKWRAP_SHA256}.json",
                                "size_bytes": str(SHRINKWRAP_SIZE),
                                "sha256": SHRINKWRAP_SHA256,
                            },
                            "locked_packages": locked,
                        },
                    },
                },
            },
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--approval-report", type=Path, required=True)
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    matrix, matrix_bytes = load_unique(args.matrix, MATRIX_SHA256)
    approval, approval_bytes = load_unique(args.approval_report, APPROVAL_REPORT_SHA256)
    validate_approval_pair(matrix, approval)

    provenance_path = args.corpus_root / "package-provenance.json"
    provenance, provenance_bytes = load_unique(provenance_path, PACKAGE_PROVENANCE_SHA256)
    corpus_sha_path = args.corpus_root / "CORPUS.SHA256"
    corpus_sha_bytes = corpus_sha_path.read_bytes()
    if sha256(corpus_sha_bytes) != CORPUS_SHA256_FILE_SHA256:
        raise ValueError("authenticated corpus digest evidence mismatch")

    node_archive = args.corpus_root / "toolchain/node/node-v22.19.0-linux-x64.tar.xz"
    node_bytes = require_regular_member(
        node_archive,
        NODE_ARCHIVE_SIZE,
        NODE_ARCHIVE_SHA256,
        NODE_MEMBER,
        NODE_INVENTORY_SIZE,
        NODE_INVENTORY_SHA256,
    )
    root_archive = args.corpus_root / f"packages/archives/{ROOT_ARCHIVE_SHA256}.tgz"
    pi_bytes = require_regular_member(
        root_archive,
        ROOT_ARCHIVE_SIZE,
        ROOT_ARCHIVE_SHA256,
        PI_MEMBER,
        PI_INVENTORY_SIZE,
        PI_INVENTORY_SHA256,
    )

    package_input = derive_package_input(args.corpus_root, provenance)
    package_input_bytes = canonical(package_input)
    if (
        len(package_input_bytes) != 78_346
        or sha256(package_input_bytes) != PACKAGE_INPUT_RAW_SHA256
        or sha256(PACKAGE_INPUT_DOMAIN + package_input_bytes) != PACKAGE_INPUT_DOMAIN_SHA256
    ):
        raise ValueError("derived Task 5 package-input evidence drifted")

    intent = derive_intent(package_input)
    intent_bytes = canonical(intent)
    semantic_projection = {
        "fluxsemble_requirement": intent["fluxsemble_requirement"],
        "release": intent["release"],
    }
    semantic_bytes = canonical(semantic_projection)
    if sha256(RELEASE_SEMANTIC_DOMAIN + semantic_bytes) != RELEASE_SEMANTIC_SHA256:
        raise ValueError("derived approved immutable release semantic drifted")

    fixture_files = [
        {
            "path": "initial-release-intent-v1.json",
            "size": len(intent_bytes),
            "sha256": sha256(intent_bytes),
        },
        {
            "path": "package-input-manifest-v1.json",
            "size": len(package_input_bytes),
            "sha256": sha256(package_input_bytes),
        },
    ]
    evidence = {
        "schema_version": 1,
        "kind": "approved_initial_release_evidence",
        "source": {
            "repository": "https://github.com/Devalch/Fluxsemble",
            "commit": SOURCE_COMMIT,
            "initial_runtime_matrix": {
                "path": "resources/runtime-release-inputs/initial-runtime-matrix-v1.json",
                "size": len(matrix_bytes),
                "sha256": MATRIX_SHA256,
            },
            "approval_report": {
                "path": "resources/runtime-release-inputs/approval-report-v1.json",
                "size": len(approval_bytes),
                "sha256": APPROVAL_REPORT_SHA256,
            },
            "package_provenance": {
                "path": "crates/harness-pi/tests/fixtures/pi-0.83.0/package-provenance.json",
                "size": len(provenance_bytes),
                "sha256": PACKAGE_PROVENANCE_SHA256,
            },
            "corpus_digest": {
                "path": "crates/harness-pi/tests/fixtures/pi-0.83.0/CORPUS.SHA256",
                "size": len(corpus_sha_bytes),
                "sha256": CORPUS_SHA256_FILE_SHA256,
            },
        },
        "task_6_initial_release_approval": {
            "sequence": "1",
            "tag": TAG,
            "release_metadata": RELEASE_METADATA,
            "representative_fixture_freshness": {
                "generated_at": GENERATED_AT,
                "expires_at": EXPIRES_AT,
                "compiled_production_authority": False,
            },
        },
        "archive_inventory_evidence": [
            {
                "artifact_id": "artifact:node-linux-x86_64",
                "archive_size": NODE_ARCHIVE_SIZE,
                "archive_sha256": NODE_ARCHIVE_SHA256,
                "archive_member": NODE_MEMBER,
                "archive_member_type": "regular_file",
                "catalog_path": NODE_INVENTORY_PATH,
                "size_bytes": len(node_bytes),
                "sha256": sha256(node_bytes),
            },
            {
                "artifact_id": "artifact:pi-coding-agent",
                "archive_size": ROOT_ARCHIVE_SIZE,
                "archive_sha256": ROOT_ARCHIVE_SHA256,
                "archive_member": PI_MEMBER,
                "archive_member_type": "regular_file",
                "catalog_path": PI_INVENTORY_PATH,
                "size_bytes": len(pi_bytes),
                "sha256": sha256(pi_bytes),
            },
        ],
        "package_input_manifest": {
            "canonical_size": len(package_input_bytes),
            "raw_sha256": PACKAGE_INPUT_RAW_SHA256,
            "domain": PACKAGE_INPUT_DOMAIN.decode("utf-8"),
            "domain_separated_sha256": PACKAGE_INPUT_DOMAIN_SHA256,
        },
        "immutable_release_semantic": {
            "canonical_projection_size": len(semantic_bytes),
            "domain": RELEASE_SEMANTIC_DOMAIN.decode("utf-8"),
            "domain_separated_sha256": RELEASE_SEMANTIC_SHA256,
            "projection": "fluxsemble_requirement + complete intent.release",
            "excluded_freshness_fields": ["sequence", "tag", "generated_at", "expires_at"],
            "tag_dependent_support_urls_bound_to": TAG,
        },
        "fixture_files": fixture_files,
    }

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "package-input-manifest-v1.json").write_bytes(package_input_bytes)
    (args.output / "initial-release-intent-v1.json").write_bytes(intent_bytes)
    (args.output / "evidence-manifest-v1.json").write_bytes(canonical(evidence))


if __name__ == "__main__":
    main()
