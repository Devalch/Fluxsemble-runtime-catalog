#!/usr/bin/env python3
"""Independently construct the approved catalog-v1 candidate from authenticated public input.

This oracle deliberately does not invoke or import catalog-sign. It verifies the complete public
transfer inventory, selects the committed release intent (directly or through catalog-source), and
projects only the catalog-v1 fields approved by the release-intent schema. The frozen digest was
established from that independent projection for the pi 0.83.0 public ceremony.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import sys
from typing import Any

EXPECTED_CANDIDATE_SHA256 = "7dba62c8b44883cbd7b3615fd9fe3b1a08a3aa2c75c7729704c14804d1cc2a2b"
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_ENTRY_BYTES = 8 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
MAX_ENTRIES = 32_768
INTENT_KEYS = {
    "expires_at",
    "fluxsemble_requirement",
    "generated_at",
    "release",
    "sequence",
    "tag",
}


class OracleError(ValueError):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OracleError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_json(data: bytes, label: str) -> Any:
    if not data or len(data) > MAX_MANIFEST_BYTES:
        raise OracleError(f"{label}: JSON bounds rejected")
    try:
        value = json.loads(data, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OracleError(f"{label}: invalid JSON") from error
    if canonical(value) != data:
        raise OracleError(f"{label}: noncanonical JSON")
    return value


def canonical(value: Any) -> bytes:
    _validate_number_safe_ascii(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _validate_number_safe_ascii(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise OracleError("non-ASCII JSON member")
            _validate_number_safe_ascii(child)
    elif isinstance(value, list):
        for child in value:
            _validate_number_safe_ascii(child)
    elif isinstance(value, str):
        if not value.isascii():
            raise OracleError("non-ASCII JSON string")
    elif isinstance(value, float):
        raise OracleError("non-number-safe JSON value")
    elif value is not None and not isinstance(value, (bool, int)):
        raise OracleError("unsupported JSON value")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_relative(relative: str) -> bool:
    path = pathlib.PurePosixPath(relative)
    return (
        bool(relative)
        and not relative.startswith("/")
        and len(relative.encode()) <= 4096
        and all(part not in ("", ".", "..") for part in path.parts)
    )


def verify_transfer(root: pathlib.Path) -> list[pathlib.Path]:
    if not root.is_absolute():
        raise OracleError("input root must be absolute")
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise OracleError("input root must be a retained directory")
    manifest_path = root / "transfer-manifest-v1.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = load_json(manifest_bytes, "transfer manifest")
    entries = manifest.get("entries") if isinstance(manifest, dict) else None
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_ENTRIES:
        raise OracleError("transfer entry count rejected")
    expected: set[str] = set()
    records: list[pathlib.Path] = []
    total = 0
    previous = ""
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"mode", "relative_path", "sha256", "size"}:
            raise OracleError("transfer entry schema rejected")
        relative = entry["relative_path"]
        size = entry["size"]
        digest = entry["sha256"]
        if (
            not isinstance(relative, str)
            or not safe_relative(relative)
            or relative <= previous
            or relative in expected
            or entry["mode"] != "0400"
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 < size <= MAX_ENTRY_BYTES
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise OracleError("transfer entry value rejected")
        previous = relative
        expected.add(relative)
        total += size
        if total > MAX_TOTAL_BYTES:
            raise OracleError("transfer total bounds rejected")
        path = root.joinpath(*pathlib.PurePosixPath(relative).parts)
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
            or metadata.st_size != size
        ):
            raise OracleError(f"transfer object metadata rejected: {relative}")
        data = path.read_bytes()
        if len(data) != size or sha256(data) != digest:
            raise OracleError(f"transfer object digest rejected: {relative}")
        if relative.startswith("records/"):
            records.append(path)
    actual: set[str] = set()
    for path in root.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise OracleError("transfer symlink rejected")
        if stat.S_ISREG(metadata.st_mode):
            actual.add(path.relative_to(root).as_posix())
        elif not stat.S_ISDIR(metadata.st_mode):
            raise OracleError("transfer special object rejected")
    if actual != expected | {"transfer-manifest-v1.json"}:
        raise OracleError("transfer complete inventory rejected")
    return records


def project_intent(intent: Any) -> dict[str, Any]:
    if not isinstance(intent, dict) or set(intent) != INTENT_KEYS:
        raise OracleError("release intent schema rejected")
    release = intent["release"]
    if not isinstance(release, dict) or set(release) != {"allowed_origins", "provider", "release"}:
        raise OracleError("release projection schema rejected")
    if (
        intent["sequence"] != "1"
        or intent["fluxsemble_requirement"] != "=0.1.0"
        or intent["generated_at"] != "2026-08-26T00:00:00Z"
        or intent["expires_at"] != "2026-09-26T00:00:00Z"
        or release["provider"] != "builtin:pi"
        or not isinstance(release["allowed_origins"], list)
        or not release["allowed_origins"]
        or not isinstance(release["release"], dict)
    ):
        raise OracleError("release intent approved tuple rejected")
    candidate = {
        "schema_version": 1,
        "sequence": intent["sequence"],
        "generated_at": intent["generated_at"],
        "expires_at": intent["expires_at"],
        "compatibility_ranges": [intent["fluxsemble_requirement"]],
        "providers": [
            {
                "provider_id": release["provider"],
                "allowed_origins": release["allowed_origins"],
                "releases": [release["release"]],
            }
        ],
    }
    if len(canonical(candidate)) > MAX_MANIFEST_BYTES:
        raise OracleError("candidate bounds rejected")
    return candidate


def construct_candidate(root: pathlib.Path) -> bytes:
    intents: list[dict[str, Any]] = []
    for record in verify_transfer(root):
        value = load_json(record.read_bytes(), record.name)
        if isinstance(value, dict) and set(value) == INTENT_KEYS:
            intents.append(value)
        elif isinstance(value, dict) and set(value) == {"build", "intent", "qualification"}:
            if isinstance(value["intent"], dict) and set(value["intent"]) == INTENT_KEYS:
                intents.append(value["intent"])
    if len(intents) != 1:
        raise OracleError(f"expected one authenticated release intent, found {len(intents)}")
    candidate = canonical(project_intent(intents[0]))
    digest = sha256(candidate)
    if digest != EXPECTED_CANDIDATE_SHA256:
        raise OracleError(f"independent candidate digest drift: {digest}")
    return candidate


def main(arguments: list[str]) -> int:
    if len(arguments) != 2:
        print("usage: authentic-candidate-oracle.py INPUT_ROOT OUTPUT", file=sys.stderr)
        return 2
    try:
        root = pathlib.Path(arguments[0])
        output = pathlib.Path(arguments[1])
        candidate = construct_candidate(root)
        with output.open("xb") as file:
            file.write(candidate)
            file.flush()
            os.fsync(file.fileno())
        print(f"independent candidate sha256={sha256(candidate)} size={len(candidate)}")
        return 0
    except (OSError, OracleError) as error:
        print(f"authentic candidate oracle failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
