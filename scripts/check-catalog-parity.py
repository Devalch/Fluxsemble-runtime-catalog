#!/usr/bin/env python3
"""Run the bounded, single-pointer old/new catalog parity matrix.

The old producer and new catalog-core probe are supplied as runtime executable
paths. The probe interface is `PROBE CANDIDATE`; the old producer interface is
its committed `runtime-catalog validate`/`canonicalize` CLI.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any

EXPECTED_CANDIDATE_SIZE = 55_797
EXPECTED_CANDIDATE_SHA256 = "7dba62c8b44883cbd7b3615fd9fe3b1a08a3aa2c75c7729704c14804d1cc2a2b"
MAX_CANDIDATE_BYTES = 8 * 1024 * 1024
MAX_TOOL_BYTES = 128 * 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 4 * 1024
TOOL_TIMEOUT_SECONDS = 10
ABSENT = "<absent>"

# This is the authoritative case manifest. Each rejected case changes exactly
# this one JSON pointer from `before` to `after` in the exact accepted candidate.
CASE_MANIFEST = (
    {
        "case": "schema-version",
        "category": "schema",
        "pointer": "/schema_version",
        "before": 1,
        "after": 2,
    },
    {
        "case": "canonical-decimal",
        "category": "canonical",
        "pointer": "/sequence",
        "before": "1",
        "after": "01",
    },
    {
        "case": "provider-id",
        "category": "provider",
        "pointer": "/providers/0/provider_id",
        "before": "builtin:pi",
        "after": "Builtin:pi",
    },
    {
        "case": "target",
        "category": "target",
        "pointer": "/providers/0/releases/0/target",
        "before": "linux_x86_64",
        "after": "windows_x86_64",
    },
    {
        "case": "release-version",
        "category": "version",
        "pointer": "/providers/0/releases/0/version",
        "before": "0.83.0",
        "after": "00.83.0",
    },
    {
        "case": "closure-reference",
        "category": "closure",
        "pointer": "/providers/0/releases/0/provider_extension/metadata/package_artifact_id",
        "before": "artifact:pi-coding-agent",
        "after": "artifact:missing",
    },
    {
        "case": "artifact-size",
        "category": "artifact",
        "pointer": "/providers/0/releases/0/components/0/artifacts/0/size_bytes",
        "before": "30479988",
        "after": "0",
    },
    {
        "case": "unknown-field",
        "category": "unknown",
        "pointer": "/unknown_field",
        "before": "<absent>",
        "after": "forbidden",
    },
)


class ParityError(ValueError):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ParityError("duplicate JSON member")
        value[key] = child
    return value


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def load_candidate(path: Path) -> tuple[bytes, dict[str, Any]]:
    data = path.read_bytes()
    if not data or len(data) > MAX_CANDIDATE_BYTES:
        raise ParityError("candidate bounds rejected")
    try:
        value = json.loads(data, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ParityError("candidate JSON rejected") from error
    if not isinstance(value, dict) or canonical(value) != data:
        raise ParityError("candidate is not exact canonical JSON")
    if len(data) != EXPECTED_CANDIDATE_SIZE or sha256(data) != EXPECTED_CANDIDATE_SHA256:
        raise ParityError("candidate identity rejected")
    return data, value


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pointer_tokens(pointer: str) -> list[str]:
    if not pointer.startswith("/") or pointer == "/":
        raise ParityError("invalid case pointer")
    return [token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/")]


def pointer_value(value: Any, pointer: str) -> Any:
    current = value
    for token in pointer_tokens(pointer):
        if isinstance(current, list):
            current = current[int(token)]
        elif isinstance(current, dict) and token in current:
            current = current[token]
        else:
            return ABSENT
    return current


def set_pointer(value: dict[str, Any], case: dict[str, Any]) -> None:
    tokens = pointer_tokens(case["pointer"])
    parent: Any = value
    for token in tokens[:-1]:
        parent = parent[int(token)] if isinstance(parent, list) else parent[token]
    final = tokens[-1]
    actual = parent[int(final)] if isinstance(parent, list) else parent.get(final, ABSENT)
    if actual != case["before"]:
        raise ParityError(f"{case['case']}: before value drift")
    if isinstance(parent, list):
        parent[int(final)] = case["after"]
    else:
        parent[final] = case["after"]


def json_differences(before: Any, after: Any, pointer: str = "") -> list[tuple[str, Any, Any]]:
    differences: list[tuple[str, Any, Any]] = []
    if type(before) is not type(after):
        return [(pointer, before, after)]
    if isinstance(before, dict):
        for key in sorted(set(before) | set(after)):
            escaped = key.replace("~", "~0").replace("/", "~1")
            child_pointer = f"{pointer}/{escaped}"
            if key not in before:
                differences.append((child_pointer, ABSENT, after[key]))
            elif key not in after:
                differences.append((child_pointer, before[key], ABSENT))
            else:
                differences.extend(json_differences(before[key], after[key], child_pointer))
    elif isinstance(before, list):
        if len(before) != len(after):
            differences.append((f"{pointer}/length", len(before), len(after)))
        for index, (left, right) in enumerate(zip(before, after)):
            differences.extend(json_differences(left, right, f"{pointer}/{index}"))
    elif before != after:
        differences.append((pointer, before, after))
    return differences


def build_cases(candidate: dict[str, Any]) -> list[tuple[dict[str, Any], bytes]]:
    cases: list[tuple[dict[str, Any], bytes]] = []
    for manifest_case in CASE_MANIFEST:
        case = dict(manifest_case)
        mutated = copy.deepcopy(candidate)
        set_pointer(mutated, case)
        if pointer_value(mutated, case["pointer"]) != case["after"]:
            raise ParityError(f"{case['case']}: mutation was not applied once")
        expected_difference = [(case["pointer"], case["before"], case["after"])]
        if json_differences(candidate, mutated) != expected_difference:
            raise ParityError(f"{case['case']}: mutation changed another canonical value")
        mutated_bytes = canonical(mutated)
        reparsed = json.loads(mutated_bytes, object_pairs_hook=reject_duplicates)
        if json_differences(candidate, reparsed) != expected_difference:
            raise ParityError(f"{case['case']}: canonical mutation changed another value")
        cases.append((case, mutated_bytes))
    return cases


def require_tool(path: Path) -> Path:
    metadata = path.stat()
    if (
        not path.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or not 0 < metadata.st_size <= MAX_TOOL_BYTES
        or metadata.st_mode & 0o111 == 0
    ):
        raise ParityError("tool path rejected")
    return path


def run_tool(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    environment = {
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "RUST_BACKTRACE": "0",
        "TZ": "UTC",
    }
    try:
        result = subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ParityError("catalog tool execution rejected") from error
    if len(result.stdout) > MAX_TOOL_OUTPUT_BYTES or len(result.stderr) > MAX_TOOL_OUTPUT_BYTES:
        raise ParityError("catalog tool output bounds rejected")
    return result


def old_accepts(tool: Path, case_path: Path) -> bool:
    result = run_tool(
        [
            os.fspath(tool),
            "validate",
            "--input",
            os.fspath(case_path),
            "--now",
            "2026-09-01T00:00:00Z",
            "--app-version",
            "0.1.0",
        ]
    )
    if result.returncode == 0:
        expected = f"valid sequence=1 payload_sha256={EXPECTED_CANDIDATE_SHA256}\n".encode()
        if result.stdout != expected or result.stderr:
            raise ParityError("old accepted output drift")
        return True
    if result.returncode != 2 or result.stdout or result.stderr != b"runtime catalog command failed\n":
        raise ParityError("old rejected output drift")
    return False


def new_accepts(tool: Path, case_path: Path) -> bool:
    result = run_tool([os.fspath(tool), os.fspath(case_path)])
    if result.returncode == 0:
        expected = (
            f"valid sequence=1 payload_sha256={EXPECTED_CANDIDATE_SHA256} "
            f"size={EXPECTED_CANDIDATE_SIZE}\n"
        ).encode()
        if result.stdout != expected or result.stderr:
            raise ParityError("new accepted output drift")
        return True
    return False


def require_old_canonical(tool: Path, candidate_path: Path, directory: Path) -> None:
    output = directory / "old-canonical.json"
    result = run_tool(
        [
            os.fspath(tool),
            "canonicalize",
            "--input",
            os.fspath(candidate_path),
            "--output",
            os.fspath(output),
        ]
    )
    expected = f"canonical payload_sha256={EXPECTED_CANDIDATE_SHA256}\n".encode()
    if result.returncode != 0 or result.stdout != expected or result.stderr:
        raise ParityError("old canonicalization rejected")
    if output.read_bytes() != candidate_path.read_bytes():
        raise ParityError("old canonical bytes differ from exact candidate")


def run_matrix(candidate_path: Path, old_tool: Path, new_tool: Path) -> bytes:
    candidate_bytes, candidate = load_candidate(candidate_path)
    old_tool = require_tool(old_tool)
    new_tool = require_tool(new_tool)
    matrix: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="catalog-parity-") as temporary:
        root = Path(temporary)
        accepted_path = root / "accepted.json"
        accepted_path.write_bytes(candidate_bytes)
        accepted_path.chmod(0o400)
        old_accepted = old_accepts(old_tool, accepted_path)
        if accepted_path.read_bytes() != candidate_bytes:
            raise ParityError("old tool changed the exact accepted case bytes")
        new_accepted = new_accepts(new_tool, accepted_path)
        if accepted_path.read_bytes() != candidate_bytes:
            raise ParityError("new tool changed the exact accepted case bytes")
        if not old_accepted or not new_accepted:
            raise ParityError("exact candidate was not accepted by both tools")
        require_old_canonical(old_tool, accepted_path, root)
        matrix.append(
            {
                "case": "accepted",
                "category": "accepted",
                "pointer": "",
                "before": None,
                "after": None,
                "old": "accepted",
                "new": "accepted",
            }
        )
        for case, data in build_cases(candidate):
            case_path = root / f"{case['case']}.json"
            case_path.write_bytes(data)
            case_path.chmod(0o400)
            old = old_accepts(old_tool, case_path)
            if case_path.read_bytes() != data:
                raise ParityError(f"{case['case']}: old tool changed the exact case bytes")
            new = new_accepts(new_tool, case_path)
            if case_path.read_bytes() != data:
                raise ParityError(f"{case['case']}: new tool changed the exact case bytes")
            if old or new:
                raise ParityError(f"{case['case']}: rejected mutation was accepted")
            matrix.append(
                {
                    **case,
                    "old": "rejected",
                    "new": "rejected",
                }
            )
    return canonical(matrix)


def parse_arguments(arguments: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--old-tool", required=True, type=Path)
    parser.add_argument("--new-tool", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    options = parse_arguments(arguments)
    try:
        matrix = run_matrix(options.candidate, options.old_tool, options.new_tool)
        with options.output.open("xb") as output:
            output.write(matrix)
            output.flush()
            os.fsync(output.fileno())
        print(f"parity matrix sha256={sha256(matrix)} size={len(matrix)} cases={len(CASE_MANIFEST) + 1}")
        return 0
    except (OSError, ParityError) as error:
        print(f"catalog parity failed: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
