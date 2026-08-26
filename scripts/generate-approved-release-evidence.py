#!/usr/bin/env python3
"""Generate standalone Task 6 approved-release evidence from authenticated public inputs."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import os
import stat
import tarfile
import tempfile
import zlib
from pathlib import Path
from typing import Any, Callable

from approved_release_input_sizes import PACKAGE_FILE_SIZES

MATRIX_SHA256 = "6f389eb3b8b040acda99e63b8dfb0be710dc666182438b7b1c5881e430076d53"
MATRIX_SIZE = 2_782
APPROVAL_REPORT_SHA256 = "c4864c7bdccaf5ee9fa2e607ecf46a1657c8026fa6af0f492e021cf4724c4996"
APPROVAL_REPORT_SIZE = 21_461
PACKAGE_PROVENANCE_SHA256 = "3bb528f91e7cb6e8124d831bac6e06cc36a962691c72b4eec58b86b34d197c57"
PACKAGE_PROVENANCE_SIZE = 187_087
CORPUS_SHA256_FILE_SHA256 = "9a7076a06bb66fbcbd6cdf430c55f21fdd16f42a0eeed93c39fdb7ac0941979c"
CORPUS_SHA256_FILE_SIZE = 65
SOURCE_COMMIT = "2d5d104cec3c68b51469ca8ffa34642558fdfd67"

MAX_SMALL_INPUT_BYTES = 1024 * 1024
MAX_ARCHIVE_INPUT_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 32_768
DECOMPRESSION_CHUNK_BYTES = 64 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000
MAX_COLLECTION_MEMBERS = 10_000
SAFE_PUBLIC_FILE_MODES = frozenset((0o400, 0o444, 0o600, 0o644))
SAFE_PUBLIC_DIRECTORY_MODES = frozenset((0o700, 0o755))

if len(PACKAGE_FILE_SIZES) != 140:
    raise RuntimeError("compiled package file-size authority is incomplete")
PACKAGE_ARCHIVE_SIZES = {record[0]: record[1] for record in PACKAGE_FILE_SIZES}
PACKAGE_DECLARATION_SIZES = {record[2]: record[3] for record in PACKAGE_FILE_SIZES}
if len(PACKAGE_ARCHIVE_SIZES) != 140 or len(PACKAGE_DECLARATION_SIZES) != 140:
    raise RuntimeError("compiled package file-size authority contains duplicate digests")

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

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def _safe_relative_components(relative: str) -> list[str]:
    if (
        not isinstance(relative, str)
        or not relative
        or len(os.fsencode(relative)) > 4096
        or relative.startswith("/")
        or "\\" in relative
    ):
        raise ValueError("authenticated input path is not a bounded relative path")
    components = relative.split("/")
    if any(
        not component
        or component in (".", "..")
        or len(os.fsencode(component)) > 255
        or "\x00" in component
        or any(ord(character) < 32 or ord(character) == 127 for character in component)
        for component in components
    ):
        raise ValueError("authenticated input path has an unsafe component")
    return components


def _metadata_snapshot(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_uid,
        metadata.st_nlink,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_public_directory(metadata: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) not in SAFE_PUBLIC_DIRECTORY_MODES
    ):
        raise ValueError(f"authenticated input directory policy mismatch: {label}")


def _public_file_policy_matches(
    metadata: os.stat_result,
    expected_size: int,
    maximum_size: int,
    expected_owner: int,
) -> bool:
    return (
        0 < expected_size <= maximum_size
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == expected_owner
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) in SAFE_PUBLIC_FILE_MODES
        and metadata.st_size == expected_size
    )


def _require_public_file(
    metadata: os.stat_result,
    expected_size: int,
    maximum_size: int,
    label: str,
) -> None:
    if not _public_file_policy_matches(
        metadata, expected_size, maximum_size, os.geteuid()
    ):
        raise ValueError(f"authenticated input file policy mismatch: {label}")


class AuthenticatedInputRoot:
    """Retained directory capability for bounded no-link authenticated reads."""

    def __init__(self, descriptor: int, label: str) -> None:
        self._descriptor = descriptor
        self._label = label

    @classmethod
    def open(cls, path: Path) -> "AuthenticatedInputRoot":
        if not path.is_absolute() or len(os.fsencode(path)) > 4096:
            raise ValueError("authenticated input root must be a bounded absolute path")
        descriptor = os.open("/", _DIRECTORY_FLAGS)
        try:
            for component in path.parts[1:]:
                if component in ("", ".", "..") or len(os.fsencode(component)) > 255:
                    raise ValueError("authenticated input root has an unsafe component")
                next_descriptor = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            _require_public_directory(os.fstat(descriptor), str(path))
            return cls(descriptor, str(path))
        except (OSError, ValueError) as error:
            os.close(descriptor)
            if isinstance(error, ValueError):
                raise
            raise ValueError(f"authenticated input root cannot be opened: {path}") from error

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1

    def __enter__(self) -> "AuthenticatedInputRoot":
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        self.close()

    def _open_relative(self, relative: str) -> tuple[int, int, str]:
        components = _safe_relative_components(relative)
        parent = os.dup(self._descriptor)
        try:
            for component in components[:-1]:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)
                os.close(parent)
                parent = child
                _require_public_directory(
                    os.fstat(parent), f"{self._label}/{component}"
                )
            file_descriptor = os.open(components[-1], _FILE_FLAGS, dir_fd=parent)
            return file_descriptor, parent, components[-1]
        except (OSError, ValueError) as error:
            os.close(parent)
            if isinstance(error, ValueError):
                raise
            raise ValueError(
                f"authenticated input cannot be opened: {self._label}/{relative}"
            ) from error

    def read_file(
        self,
        relative: str,
        *,
        expected_size: int,
        expected_sha256: str,
        maximum_size: int,
        checkpoint: Callable[[], None] | None = None,
    ) -> bytes:
        if (
            not isinstance(expected_size, int)
            or not isinstance(maximum_size, int)
            or expected_size <= 0
            or expected_size > maximum_size
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_sha256)
        ):
            raise ValueError("authenticated input expectation is invalid")
        file_descriptor, parent, final_name = self._open_relative(relative)
        try:
            before = os.fstat(file_descriptor)
            _require_public_file(before, expected_size, maximum_size, relative)
            remaining = expected_size
            chunks: list[bytes] = []
            while remaining:
                try:
                    chunk = os.read(file_descriptor, min(64 * 1024, remaining))
                except InterruptedError:
                    continue
                if not chunk:
                    raise ValueError(f"authenticated input ended early: {relative}")
                chunks.append(chunk)
                remaining -= len(chunk)
            try:
                probe = os.read(file_descriptor, 1)
            except InterruptedError:
                probe = os.read(file_descriptor, 1)
            if probe:
                raise ValueError(f"authenticated input exceeded exact size: {relative}")
            data = b"".join(chunks)
            after = os.fstat(file_descriptor)
            if _metadata_snapshot(before) != _metadata_snapshot(after):
                raise ValueError(f"authenticated input changed while reading: {relative}")
            if sha256(data) != expected_sha256:
                raise ValueError(f"authenticated input digest mismatch: {relative}")
            if checkpoint is not None:
                checkpoint()

            rebound = os.open(final_name, _FILE_FLAGS, dir_fd=parent)
            try:
                rebound_metadata = os.fstat(rebound)
                _require_public_file(
                    rebound_metadata, expected_size, maximum_size, relative
                )
                retained_name_snapshot = _metadata_snapshot(rebound_metadata)
                if _metadata_snapshot(before) != retained_name_snapshot:
                    raise ValueError(
                        f"authenticated input name changed while reading: {relative}"
                    )
            finally:
                os.close(rebound)

            rebound_file, rebound_parent, _ = self._open_relative(relative)
            try:
                rebound_metadata = os.fstat(rebound_file)
                _require_public_file(
                    rebound_metadata, expected_size, maximum_size, relative
                )
                full_path_snapshot = _metadata_snapshot(rebound_metadata)
                if _metadata_snapshot(before) != full_path_snapshot:
                    raise ValueError(
                        f"authenticated input path changed while reading: {relative}"
                    )
            finally:
                os.close(rebound_file)
                os.close(rebound_parent)
            return data
        except OSError as error:
            raise ValueError(f"authenticated input read failed: {relative}") from error
        finally:
            os.close(file_descriptor)
            os.close(parent)


def read_authenticated_absolute(
    path: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    maximum_size: int,
    checkpoint: Callable[[], None] | None = None,
) -> bytes:
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise ValueError("authenticated input must be an absolute file path")
    with AuthenticatedInputRoot.open(path.parent) as parent:
        return parent.read_file(
            path.name,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            maximum_size=maximum_size,
            checkpoint=checkpoint,
        )


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


def validate_collection_bounds(value: Any) -> None:
    pending = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ValueError("authenticated JSON exceeds structural bounds")
        if isinstance(current, dict):
            if len(current) > MAX_COLLECTION_MEMBERS:
                raise ValueError("authenticated JSON object exceeds member bound")
            pending.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            if len(current) > MAX_COLLECTION_MEMBERS:
                raise ValueError("authenticated JSON array exceeds member bound")
            pending.extend((child, depth + 1) for child in current)


def parse_unique_object(data: bytes, label: str) -> dict[str, Any]:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len(pairs) > MAX_COLLECTION_MEMBERS:
            raise ValueError(f"JSON object exceeds member bound in {label}")
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON member in {label}: {key}")
            result[key] = value
        return result

    value = json.loads(data, object_pairs_hook=unique_pairs)
    validate_collection_bounds(value)
    if not isinstance(value, dict):
        raise ValueError(f"authenticated input is not an object: {label}")
    return value


def load_unique_absolute(
    path: Path,
    expected_size: int,
    expected_sha256: str,
) -> tuple[dict[str, Any], bytes]:
    data = read_authenticated_absolute(
        path,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
        maximum_size=MAX_SMALL_INPUT_BYTES,
    )
    return parse_unique_object(data, str(path)), data


def load_unique_relative(
    root: AuthenticatedInputRoot,
    relative: str,
    expected_size: int,
    expected_sha256: str,
) -> tuple[dict[str, Any], bytes]:
    data = root.read_file(
        relative,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
        maximum_size=MAX_SMALL_INPUT_BYTES,
    )
    return parse_unique_object(data, relative), data


def _write_expanded_chunk(
    output: io.BufferedRandom,
    chunk: bytes,
    expanded_size: int,
    maximum_expanded_bytes: int,
    archive_label: str,
) -> int:
    expanded_size += len(chunk)
    if expanded_size > maximum_expanded_bytes:
        raise ValueError(f"archive expanded-byte bound exceeded: {archive_label}")
    output.write(chunk)
    return expanded_size


def _decompress_gzip(
    archive_bytes: bytes,
    output: io.BufferedRandom,
    maximum_expanded_bytes: int,
    archive_label: str,
) -> int:
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    compressed_offset = 0
    pending = b""
    expanded_size = 0
    while not decompressor.eof:
        if pending:
            compressed = pending
        elif compressed_offset < len(archive_bytes):
            compressed = archive_bytes[
                compressed_offset : compressed_offset + DECOMPRESSION_CHUNK_BYTES
            ]
            compressed_offset += len(compressed)
        else:
            compressed = b""
        maximum_output = min(
            DECOMPRESSION_CHUNK_BYTES,
            maximum_expanded_bytes - expanded_size + 1,
        )
        chunk = decompressor.decompress(compressed, maximum_output)
        pending = decompressor.unconsumed_tail
        expanded_size = _write_expanded_chunk(
            output, chunk, expanded_size, maximum_expanded_bytes, archive_label
        )
        if not compressed and not pending and not chunk and not decompressor.eof:
            raise ValueError(f"authenticated gzip archive is truncated: {archive_label}")
    if decompressor.unused_data or pending or compressed_offset != len(archive_bytes):
        raise ValueError(f"authenticated gzip archive has trailing data: {archive_label}")
    return expanded_size


def _decompress_xz(
    archive_bytes: bytes,
    output: io.BufferedRandom,
    maximum_expanded_bytes: int,
    archive_label: str,
) -> int:
    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    compressed_offset = 0
    expanded_size = 0
    while not decompressor.eof:
        if decompressor.needs_input:
            if compressed_offset >= len(archive_bytes):
                raise ValueError(f"authenticated XZ archive is truncated: {archive_label}")
            compressed = archive_bytes[
                compressed_offset : compressed_offset + DECOMPRESSION_CHUNK_BYTES
            ]
            compressed_offset += len(compressed)
        else:
            compressed = b""
        maximum_output = min(
            DECOMPRESSION_CHUNK_BYTES,
            maximum_expanded_bytes - expanded_size + 1,
        )
        chunk = decompressor.decompress(compressed, max_length=maximum_output)
        expanded_size = _write_expanded_chunk(
            output, chunk, expanded_size, maximum_expanded_bytes, archive_label
        )
    if decompressor.unused_data or compressed_offset != len(archive_bytes):
        raise ValueError(f"authenticated XZ archive has trailing data: {archive_label}")
    return expanded_size


def _decompress_archive_to_temporary(
    archive_bytes: bytes,
    archive_label: str,
    maximum_expanded_bytes: int,
) -> tuple[io.BufferedRandom, int]:
    if not 0 < maximum_expanded_bytes <= MAX_ARCHIVE_EXPANDED_BYTES:
        raise ValueError(f"archive expanded-byte bound is invalid: {archive_label}")
    output = tempfile.TemporaryFile(mode="w+b")
    try:
        os.fchmod(output.fileno(), 0o600)
        if archive_bytes.startswith(b"\x1f\x8b"):
            expanded_size = _decompress_gzip(
                archive_bytes, output, maximum_expanded_bytes, archive_label
            )
        elif archive_bytes.startswith(b"\xfd7zXZ\x00"):
            expanded_size = _decompress_xz(
                archive_bytes, output, maximum_expanded_bytes, archive_label
            )
        else:
            raise ValueError(f"authenticated archive compression is unsupported: {archive_label}")
        if expanded_size <= 0:
            raise ValueError(f"authenticated archive is empty: {archive_label}")
        output.flush()
        output.seek(0)
        return output, expanded_size
    except Exception:
        output.close()
        raise


def _tar_header_size(header: bytes, archive_label: str) -> int:
    try:
        size = tarfile.nti(header[124:136])
    except (tarfile.InvalidHeaderError, ValueError) as error:
        raise ValueError(f"archive member size is invalid: {archive_label}") from error
    if not isinstance(size, int) or size < 0:
        raise ValueError(f"archive member size is invalid: {archive_label}")
    return size


def _validate_raw_tar_placement(
    expanded: io.BufferedRandom,
    expanded_size: int,
    maximum_expanded_bytes: int,
    maximum_member_bytes: int,
    maximum_members: int,
    archive_label: str,
) -> None:
    offset = 0
    member_count = 0
    data_types = frozenset(
        (
            tarfile.REGTYPE,
            tarfile.AREGTYPE,
            tarfile.CONTTYPE,
            tarfile.XHDTYPE,
            tarfile.XGLTYPE,
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
        )
    )
    no_data_types = frozenset(
        (
            tarfile.LNKTYPE,
            tarfile.SYMTYPE,
            tarfile.CHRTYPE,
            tarfile.BLKTYPE,
            tarfile.DIRTYPE,
            tarfile.FIFOTYPE,
        )
    )
    while offset < expanded_size:
        if offset % tarfile.BLOCKSIZE != 0 or offset + tarfile.BLOCKSIZE > expanded_size:
            raise ValueError(f"archive member offset is invalid: {archive_label}")
        expanded.seek(offset)
        header = expanded.read(tarfile.BLOCKSIZE)
        if len(header) != tarfile.BLOCKSIZE:
            raise ValueError(f"archive member header is truncated: {archive_label}")
        if header == tarfile.NUL * tarfile.BLOCKSIZE:
            while True:
                trailing = expanded.read(DECOMPRESSION_CHUNK_BYTES)
                if not trailing:
                    return
                if trailing.strip(tarfile.NUL):
                    raise ValueError(f"archive has data after its end marker: {archive_label}")
        member_count += 1
        if member_count > maximum_members:
            raise ValueError(f"archive member bound exceeded: {archive_label}")
        size = _tar_header_size(header, archive_label)
        if size > maximum_member_bytes:
            raise ValueError(f"archive member size bound exceeded: {archive_label}")
        typeflag = header[156:157]
        if typeflag in no_data_types:
            if size != 0:
                raise ValueError(f"archive member type has invalid size: {archive_label}")
        elif typeflag not in data_types:
            raise ValueError(f"archive member type is unsupported: {archive_label}")
        data_offset = offset + tarfile.BLOCKSIZE
        padded_size = (size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE * tarfile.BLOCKSIZE
        padded_end = data_offset + padded_size
        if (
            data_offset > expanded_size
            or padded_end > expanded_size
            or padded_end > maximum_expanded_bytes
        ):
            raise ValueError(f"archive member placement exceeds bound: {archive_label}")
        offset = padded_end


def _validate_yielded_member(
    member: tarfile.TarInfo,
    previous_padded_end: int,
    expanded_size: int,
    maximum_expanded_bytes: int,
    maximum_member_bytes: int,
    archive_label: str,
) -> int:
    if (
        type(member.size) is not int
        or type(member.offset) is not int
        or type(member.offset_data) is not int
        or member.size < 0
        or member.size > maximum_member_bytes
        or member.offset < previous_padded_end
        or member.offset % tarfile.BLOCKSIZE != 0
        or member.offset_data < member.offset + tarfile.BLOCKSIZE
        or member.offset_data % tarfile.BLOCKSIZE != 0
    ):
        raise ValueError(f"archive yielded member metadata is invalid: {archive_label}")
    if not (
        member.isfile()
        or member.isdir()
        or member.issym()
        or member.islnk()
        or member.ischr()
        or member.isblk()
        or member.isfifo()
    ):
        raise ValueError(f"archive yielded member type is unsupported: {archive_label}")
    if not member.isfile() and member.size != 0:
        raise ValueError(f"archive yielded member type has invalid size: {archive_label}")
    padded_size = (
        (member.size + tarfile.BLOCKSIZE - 1)
        // tarfile.BLOCKSIZE
        * tarfile.BLOCKSIZE
    )
    padded_end = member.offset_data + padded_size
    if padded_end > expanded_size or padded_end > maximum_expanded_bytes:
        raise ValueError(f"archive yielded member placement exceeds bound: {archive_label}")
    return padded_end


def require_regular_member(
    archive_bytes: bytes,
    archive_label: str,
    expected_archive_size: int,
    expected_archive_sha256: str,
    member_name: str,
    expected_member_size: int,
    expected_member_sha256: str,
    *,
    maximum_expanded_bytes: int = MAX_ARCHIVE_EXPANDED_BYTES,
    maximum_member_bytes: int = MAX_ARCHIVE_MEMBER_BYTES,
    maximum_members: int = MAX_ARCHIVE_MEMBERS,
) -> bytes:
    if (
        expected_archive_size <= 0
        or expected_archive_size > MAX_ARCHIVE_INPUT_BYTES
        or len(archive_bytes) != expected_archive_size
        or sha256(archive_bytes) != expected_archive_sha256
        or expected_member_size <= 0
        or expected_member_size > maximum_member_bytes
        or not 0 < maximum_member_bytes <= MAX_ARCHIVE_MEMBER_BYTES
        or not 0 < maximum_members <= MAX_ARCHIVE_MEMBERS
    ):
        raise ValueError(f"authenticated archive mismatch: {archive_label}")
    expanded, expanded_size = _decompress_archive_to_temporary(
        archive_bytes, archive_label, maximum_expanded_bytes
    )
    with expanded:
        _validate_raw_tar_placement(
            expanded,
            expanded_size,
            maximum_expanded_bytes,
            maximum_member_bytes,
            maximum_members,
            archive_label,
        )
        expanded.seek(0)
        with tarfile.open(fileobj=expanded, mode="r:") as opened:
            matched = None
            member_count = 0
            previous_padded_end = 0
            for member in opened:
                member_count += 1
                if member_count > maximum_members:
                    raise ValueError(f"archive member bound exceeded: {archive_label}")
                previous_padded_end = _validate_yielded_member(
                    member,
                    previous_padded_end,
                    expanded_size,
                    maximum_expanded_bytes,
                    maximum_member_bytes,
                    archive_label,
                )
                if member.name == member_name:
                    if matched is not None:
                        raise ValueError(f"required archive member is not unique: {member_name}")
                    matched = member
            if matched is None:
                raise ValueError(f"required archive member is not unique: {member_name}")
            if (
                not matched.isfile()
                or matched.issym()
                or matched.islnk()
                or matched.size != expected_member_size
            ):
                raise ValueError(f"required archive member is not regular: {member_name}")
            extracted = opened.extractfile(matched)
            if extracted is None:
                raise ValueError(f"required archive member cannot be read: {member_name}")
            data = extracted.read(expected_member_size)
            probe = extracted.read(1)
    if (
        len(data) != expected_member_size
        or probe
        or sha256(data) != expected_member_sha256
    ):
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


def derive_package_input(
    corpus: AuthenticatedInputRoot,
    provenance: dict[str, Any],
    root_archive_bytes: bytes,
) -> dict[str, Any]:
    packages = provenance.get("packages")
    pruning = provenance.get("install_pruning")
    if not isinstance(packages, list) or len(packages) != 140 or not isinstance(pruning, dict):
        raise ValueError("authenticated package provenance has an unexpected closure")
    archive_digests = {package.get("archive_sha256") for package in packages if isinstance(package, dict)}
    declaration_digests = {
        package.get("declaration", {}).get("sha256")
        for package in packages
        if isinstance(package, dict) and isinstance(package.get("declaration"), dict)
    }
    if (
        archive_digests != set(PACKAGE_ARCHIVE_SIZES)
        or declaration_digests != set(PACKAGE_DECLARATION_SIZES)
    ):
        raise ValueError("authenticated provenance conflicts with compiled exact file sizes")
    root = packages[0]
    if root.get("path") != "" or root.get("name") != ROOT_NAME or root.get("version") != ROOT_VERSION:
        raise ValueError("authenticated package provenance has an unexpected root")

    root_manifest = require_regular_member(
        root_archive_bytes,
        str(root["archive_path"]),
        ROOT_ARCHIVE_SIZE,
        ROOT_ARCHIVE_SHA256,
        "package/package.json",
        ROOT_MANIFEST_SIZE,
        ROOT_MANIFEST_SHA256,
    )
    shrinkwrap_bytes = require_regular_member(
        root_archive_bytes,
        str(root["archive_path"]),
        ROOT_ARCHIVE_SIZE,
        ROOT_ARCHIVE_SHA256,
        "package/npm-shrinkwrap.json",
        SHRINKWRAP_SIZE,
        SHRINKWRAP_SHA256,
    )
    shrinkwrap = parse_unique_object(shrinkwrap_bytes, "root npm-shrinkwrap.json")
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
    if len(pruned) != len(decisions):
        raise ValueError("authenticated applicability evidence has duplicate lock paths")

    locked: list[dict[str, Any]] = []
    for package in packages[1:]:
        locator = package["path"]
        lock = lock_packages.get(locator)
        if not isinstance(lock, dict):
            raise ValueError(f"authenticated shrinkwrap is missing {locator}")
        archive_sha256 = package["archive_sha256"]
        archive_size = PACKAGE_ARCHIVE_SIZES.get(archive_sha256)
        if archive_size is None:
            raise ValueError(f"package archive has no exact size authority: {locator}")
        archive_bytes = corpus.read_file(
            str(package["archive_path"]),
            expected_size=archive_size,
            expected_sha256=archive_sha256,
            maximum_size=MAX_ARCHIVE_INPUT_BYTES,
        )
        declaration_sha256 = package["declaration"]["sha256"]
        declaration_size = PACKAGE_DECLARATION_SIZES.get(declaration_sha256)
        if declaration_size is None:
            raise ValueError(f"package declaration has no exact size authority: {locator}")
        declaration_bytes = corpus.read_file(
            str(package["declaration"]["path"]),
            expected_size=declaration_size,
            expected_sha256=declaration_sha256,
            maximum_size=MAX_SMALL_INPUT_BYTES,
        )
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
                "archive_size": archive_size,
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

    matrix, matrix_bytes = load_unique_absolute(
        args.matrix, MATRIX_SIZE, MATRIX_SHA256
    )
    approval, approval_bytes = load_unique_absolute(
        args.approval_report, APPROVAL_REPORT_SIZE, APPROVAL_REPORT_SHA256
    )
    validate_approval_pair(matrix, approval)

    with AuthenticatedInputRoot.open(args.corpus_root) as corpus:
        provenance, provenance_bytes = load_unique_relative(
            corpus,
            "package-provenance.json",
            PACKAGE_PROVENANCE_SIZE,
            PACKAGE_PROVENANCE_SHA256,
        )
        corpus_sha_bytes = corpus.read_file(
            "CORPUS.SHA256",
            expected_size=CORPUS_SHA256_FILE_SIZE,
            expected_sha256=CORPUS_SHA256_FILE_SHA256,
            maximum_size=MAX_SMALL_INPUT_BYTES,
        )

        node_archive_relative = "toolchain/node/node-v22.19.0-linux-x64.tar.xz"
        node_archive_bytes = corpus.read_file(
            node_archive_relative,
            expected_size=NODE_ARCHIVE_SIZE,
            expected_sha256=NODE_ARCHIVE_SHA256,
            maximum_size=MAX_ARCHIVE_INPUT_BYTES,
        )
        node_bytes = require_regular_member(
            node_archive_bytes,
            node_archive_relative,
            NODE_ARCHIVE_SIZE,
            NODE_ARCHIVE_SHA256,
            NODE_MEMBER,
            NODE_INVENTORY_SIZE,
            NODE_INVENTORY_SHA256,
        )
        root_archive_relative = f"packages/archives/{ROOT_ARCHIVE_SHA256}.tgz"
        root_archive_bytes = corpus.read_file(
            root_archive_relative,
            expected_size=ROOT_ARCHIVE_SIZE,
            expected_sha256=ROOT_ARCHIVE_SHA256,
            maximum_size=MAX_ARCHIVE_INPUT_BYTES,
        )
        pi_bytes = require_regular_member(
            root_archive_bytes,
            root_archive_relative,
            ROOT_ARCHIVE_SIZE,
            ROOT_ARCHIVE_SHA256,
            PI_MEMBER,
            PI_INVENTORY_SIZE,
            PI_INVENTORY_SHA256,
        )

        package_input = derive_package_input(corpus, provenance, root_archive_bytes)
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
