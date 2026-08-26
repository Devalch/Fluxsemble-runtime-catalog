#!/usr/bin/env python3
"""Focused adversarial tests for approved-release authenticated input handling."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("generate-approved-release-evidence.py")
SPEC = importlib.util.spec_from_file_location("generate_approved_release_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_public_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o644)


class AuthenticatedInputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root_path = Path(self.temporary.name) / "corpus"
        self.root_path.mkdir(mode=0o700)
        self.root = GENERATOR.AuthenticatedInputRoot.open(self.root_path)

    def tearDown(self) -> None:
        self.root.close()
        self.temporary.cleanup()

    def read(self, relative: str, data: bytes, **kwargs: object) -> bytes:
        return self.root.read_file(
            relative,
            expected_size=len(data),
            expected_sha256=digest(data),
            maximum_size=GENERATOR.MAX_SMALL_INPUT_BYTES,
            **kwargs,
        )

    def test_regular_exact_current_owner_file_is_read_from_retained_descriptor(self) -> None:
        data = b"authenticated evidence"
        write_public_file(self.root_path / "nested/input.json", data)
        self.assertEqual(self.read("nested/input.json", data), data)

    def test_final_and_intermediate_symlinks_are_rejected(self) -> None:
        data = b"authenticated evidence"
        write_public_file(self.root_path / "outside.json", data)
        os.symlink("outside.json", self.root_path / "final-link.json")
        with self.assertRaises(ValueError):
            self.read("final-link.json", data)

        (self.root_path / "real").mkdir()
        write_public_file(self.root_path / "real/input.json", data)
        os.symlink("real", self.root_path / "linked-directory")
        with self.assertRaises(ValueError):
            self.read("linked-directory/input.json", data)

    def test_fifo_is_rejected_without_blocking(self) -> None:
        fifo = self.root_path / "input.fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError):
            self.root.read_file(
                "input.fifo",
                expected_size=1,
                expected_sha256=digest(b"x"),
                maximum_size=GENERATOR.MAX_SMALL_INPUT_BYTES,
            )
        self.assertTrue(stat.S_ISFIFO(fifo.lstat().st_mode))

    def test_wrong_exact_size_and_explicit_oversize_are_rejected_before_read(self) -> None:
        data = b"two bytes"
        write_public_file(self.root_path / "wrong-size.json", data)
        with self.assertRaises(ValueError):
            self.root.read_file(
                "wrong-size.json",
                expected_size=len(data) - 1,
                expected_sha256=digest(data),
                maximum_size=GENERATOR.MAX_SMALL_INPUT_BYTES,
            )

        oversized = self.root_path / "oversized.bin"
        write_public_file(oversized, b"")
        with oversized.open("r+b") as opened:
            opened.truncate(GENERATOR.MAX_SMALL_INPUT_BYTES + 1)
        with self.assertRaises(ValueError):
            self.root.read_file(
                "oversized.bin",
                expected_size=GENERATOR.MAX_SMALL_INPUT_BYTES + 1,
                expected_sha256=digest(b""),
                maximum_size=GENERATOR.MAX_SMALL_INPUT_BYTES,
            )

    def test_wrong_owner_link_count_and_mode_policies_are_rejected(self) -> None:
        data = b"authenticated evidence"
        original = self.root_path / "original.json"
        write_public_file(original, data)
        os.link(original, self.root_path / "hard-link.json")
        with self.assertRaises(ValueError):
            self.read("original.json", data)
        os.unlink(self.root_path / "hard-link.json")

        original.chmod(0o666)
        with self.assertRaises(ValueError):
            self.read("original.json", data)

    def test_pathname_replacement_after_read_is_rejected_by_named_identity_binding(self) -> None:
        data = b"same authenticated bytes"
        path = self.root_path / "replace.json"
        displaced = self.root_path / "displaced.json"
        write_public_file(path, data)

        def replace_name() -> None:
            path.rename(displaced)
            write_public_file(path, data)

        with self.assertRaises(ValueError):
            self.read("replace.json", data, checkpoint=replace_name)

    def test_absolute_reader_rejects_a_linked_path_component(self) -> None:
        data = b"authenticated evidence"
        real = Path(self.temporary.name) / "real"
        real.mkdir(mode=0o700)
        write_public_file(real / "input.json", data)
        linked = Path(self.temporary.name) / "linked"
        os.symlink(real, linked)
        with self.assertRaises(ValueError):
            GENERATOR.read_authenticated_absolute(
                linked / "input.json",
                expected_size=len(data),
                expected_sha256=digest(data),
                maximum_size=GENERATOR.MAX_SMALL_INPUT_BYTES,
            )


if __name__ == "__main__":
    unittest.main()
