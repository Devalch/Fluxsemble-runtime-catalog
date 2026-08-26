#!/usr/bin/env python3
"""Focused adversarial tests for approved-release authenticated input handling."""

from __future__ import annotations

import bz2
import gzip
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

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


def tar_bytes(entries: list[tuple[str, bytes]], *, compression: str = "gz") -> bytes:
    expanded = io.BytesIO()
    with tarfile.open(fileobj=expanded, mode="w") as archive:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(data))
    if compression == "gz":
        return gzip.compress(expanded.getvalue(), mtime=0)
    if compression == "xz":
        import lzma

        return lzma.compress(expanded.getvalue(), format=lzma.FORMAT_XZ)
    if compression == "bz2":
        return bz2.compress(expanded.getvalue())
    if compression == "plain":
        return expanded.getvalue()
    raise AssertionError(f"unsupported test compression: {compression}")


def rewrite_first_tar_header(
    archive: bytes, *, declared_size: int | None = None, typeflag: bytes | None = None
) -> bytes:
    expanded = bytearray(gzip.decompress(archive))
    if declared_size is not None:
        expanded[124:136] = f"{declared_size:011o}\0".encode("ascii")
    if typeflag is not None:
        expanded[156:157] = typeflag
    expanded[148:156] = b"        "
    checksum = sum(expanded[:512])
    expanded[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    return gzip.compress(bytes(expanded), mtime=0)


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

    def test_current_owner_single_link_and_exact_safe_mode_are_enforced(self) -> None:
        data = b"authenticated evidence"
        original = self.root_path / "original.json"
        write_public_file(original, data)
        metadata = original.stat()
        self.assertFalse(
            GENERATOR._public_file_policy_matches(
                metadata,
                len(data),
                GENERATOR.MAX_SMALL_INPUT_BYTES,
                os.geteuid() + 1,
            ),
            "a deterministic synthetic foreign owner satisfied the file policy",
        )

        os.link(original, self.root_path / "hard-link.json")
        with self.assertRaises(ValueError):
            self.read("original.json", data)
        os.unlink(self.root_path / "hard-link.json")

        for mode in (0o000, 0o440, 0o666, 0o700, 0o1000, 0o2644):
            original.chmod(mode)
            with self.assertRaises(ValueError, msg=f"accepted mode {mode:o}"):
                self.read("original.json", data)
        original.chmod(0o644)
        self.assertEqual(self.read("original.json", data), data)

    def test_digest_and_pre_post_descriptor_identity_are_enforced(self) -> None:
        data = b"authenticated evidence"
        path = self.root_path / "identity.json"
        write_public_file(path, data)
        with self.assertRaises(ValueError):
            self.root.read_file(
                "identity.json",
                expected_size=len(data),
                expected_sha256=digest(b"different authenticated evidence"),
                maximum_size=GENERATOR.MAX_SMALL_INPUT_BYTES,
            )

        original_read = os.read
        changed = False

        def read_then_change_metadata(descriptor: int, count: int) -> bytes:
            nonlocal changed
            chunk = original_read(descriptor, count)
            if chunk and not changed:
                changed = True
                path.chmod(0o600)
                path.chmod(0o644)
            return chunk

        with mock.patch.object(GENERATOR.os, "read", side_effect=read_then_change_metadata):
            with self.assertRaises(ValueError):
                self.read("identity.json", data)

    def test_bounded_read_one_byte_excess_probe_rejects_growth(self) -> None:
        data = b"authenticated evidence"
        path = self.root_path / "growth.json"
        write_public_file(path, data)
        original_read = os.read
        grown = False

        def grow_before_read(descriptor: int, count: int) -> bytes:
            nonlocal grown
            if not grown:
                grown = True
                with path.open("ab") as opened:
                    opened.write(b"!")
            return original_read(descriptor, count)

        with mock.patch.object(GENERATOR.os, "read", side_effect=grow_before_read):
            with self.assertRaises(ValueError):
                self.read("growth.json", data)

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

    def test_intermediate_replacement_is_rejected_by_full_relative_path_binding(self) -> None:
        data = b"same authenticated bytes"
        directory = self.root_path / "nested"
        displaced = self.root_path / "displaced"
        write_public_file(directory / "replace.json", data)

        def replace_directory() -> None:
            directory.rename(displaced)
            write_public_file(directory / "replace.json", data)

        with self.assertRaises(ValueError):
            self.read("nested/replace.json", data, checkpoint=replace_directory)

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


class ResourceBoundTests(unittest.TestCase):
    def test_json_depth_node_and_collection_bounds_use_small_overrides(self) -> None:
        with mock.patch.object(GENERATOR, "MAX_JSON_DEPTH", 2):
            with self.assertRaises(ValueError):
                GENERATOR.validate_collection_bounds({"a": {"b": {"c": 1}}})
        with mock.patch.object(GENERATOR, "MAX_JSON_NODES", 3):
            with self.assertRaises(ValueError):
                GENERATOR.validate_collection_bounds([1, 2, 3])
        with mock.patch.object(GENERATOR, "MAX_COLLECTION_MEMBERS", 2):
            with self.assertRaises(ValueError):
                GENERATOR.validate_collection_bounds([1, 2, 3])

    def test_gzip_and_xz_target_members_are_accepted_but_other_formats_fail_closed(self) -> None:
        target = b"target bytes"
        for compression in ("gz", "xz"):
            archive = tar_bytes([("target", target)], compression=compression)
            self.assertEqual(
                GENERATOR.require_regular_member(
                    archive,
                    compression,
                    len(archive),
                    digest(archive),
                    "target",
                    len(target),
                    digest(target),
                    maximum_expanded_bytes=32 * 1024,
                ),
                target,
            )
        for compression in ("plain", "bz2"):
            archive = tar_bytes([("target", target)], compression=compression)
            with self.assertRaises(ValueError, msg=f"accepted {compression}"):
                GENERATOR.require_regular_member(
                    archive,
                    compression,
                    len(archive),
                    digest(archive),
                    "target",
                    len(target),
                    digest(target),
                    maximum_expanded_bytes=32 * 1024,
                )

    def test_highly_compressible_cumulative_expansion_bomb_is_rejected(self) -> None:
        target = b"target bytes"
        archive = tar_bytes(
            [("target", target), ("bomb", b"\0" * (64 * 1024))],
            compression="gz",
        )
        self.assertLess(len(archive), 1024)
        with self.assertRaises(ValueError):
            GENERATOR.require_regular_member(
                archive,
                "compressible-bomb",
                len(archive),
                digest(archive),
                "target",
                len(target),
                digest(target),
                maximum_expanded_bytes=8 * 1024,
            )

    def test_invalid_oversized_non_target_member_placement_is_rejected(self) -> None:
        target = b"target bytes"
        archive = tar_bytes([("non-target", b"x"), ("target", target)])
        archive = rewrite_first_tar_header(archive, declared_size=64 * 1024)
        with self.assertRaises(ValueError):
            GENERATOR.require_regular_member(
                archive,
                "invalid-non-target-offset",
                len(archive),
                digest(archive),
                "target",
                len(target),
                digest(target),
                maximum_expanded_bytes=32 * 1024,
                maximum_member_bytes=4 * 1024,
            )

    def test_non_data_member_size_and_member_count_bounds_are_enforced(self) -> None:
        target = b"target bytes"
        non_data = tar_bytes([("non-target", b"x"), ("target", target)])
        non_data = rewrite_first_tar_header(non_data, typeflag=tarfile.SYMTYPE)
        with self.assertRaises(ValueError):
            GENERATOR.require_regular_member(
                non_data,
                "invalid-link-size",
                len(non_data),
                digest(non_data),
                "target",
                len(target),
                digest(target),
                maximum_expanded_bytes=32 * 1024,
            )

        archive = tar_bytes([("one", b"1"), ("target", target)])
        with self.assertRaises(ValueError):
            GENERATOR.require_regular_member(
                archive,
                "too-many-members",
                len(archive),
                digest(archive),
                "target",
                len(target),
                digest(target),
                maximum_expanded_bytes=32 * 1024,
                maximum_members=1,
            )


if __name__ == "__main__":
    unittest.main()
