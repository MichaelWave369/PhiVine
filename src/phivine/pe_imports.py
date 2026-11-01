"""Bounded, read-only PE import-DLL observations; NEVER compatibility approval.

PE/COFF specification (Microsoft): section table, optional header data
directory 1, IMAGE_IMPORT_DESCRIPTOR 20-byte entries, ASCII DLL name RVAs.
This module does not load DLLs, execute PE bytes, use Wine, or issue grants.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import struct
from typing import BinaryIO

SCHEMA = "phivine.pe_imports.v0.1"
MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_PE_OFFSET = 1024 * 1024
MAX_SECTIONS = 96
MAX_IMPORT_DIRECTORY_BYTES = 16384
MAX_IMPORT_DESCRIPTORS = 128
MAX_DLL_NAME_BYTES = 128
_SUPPORTED = {0x014C: ("x86", 0x10B), 0x8664: ("x86_64", 0x20B)}
_DLL_NAME = re.compile(rb"[A-Za-z0-9_.+-]{1,128}\Z")


class _BadPE(ValueError):
    """Malformed, unsupported or out-of-bounds static PE structure."""


def _read(handle: BinaryIO, offset: int, count: int, file_size: int) -> bytes:
    if offset < 0 or count < 0 or offset + count > file_size:
        raise _BadPE("out-of-bounds PE offset")
    handle.seek(offset)
    data = handle.read(count)
    if len(data) != count:
        raise _BadPE("short read in PE structure")
    return data


def _number(data: bytes, offset: int, length: int) -> int:
    if offset < 0 or offset + length > len(data):
        raise _BadPE("truncated PE field")
    return int.from_bytes(data[offset:offset + length], "little")


def _sections(handle: BinaryIO, section_offset: int, count: int, size: int) -> list[tuple[int, int, int]]:
    if count < 1 or count > MAX_SECTIONS:
        raise _BadPE("too many or absent PE sections")
    raw = _read(handle, section_offset, count * 40, size)
    sections: list[tuple[int, int, int]] = []
    for index in range(count):
        entry = raw[index * 40:(index + 1) * 40]
        virtual_size = _number(entry, 8, 4)
        virtual_address = _number(entry, 12, 4)
        raw_size = _number(entry, 16, 4)
        raw_start = _number(entry, 20, 4)
        if raw_size == 0:
            continue
        if raw_start + raw_size > size or raw_start == 0:
            raise _BadPE("section exceeds file bounds")
        # Only raw-file-backed bytes are inspectable; virtual-only bytes
        # cannot legitimately contain an import descriptor or DLL name.
        span = max(virtual_size, raw_size)
        if virtual_address + span > 0x100000000:
            raise _BadPE("section virtual address overflow")
        sections.append((virtual_address, raw_size, raw_start))
    return sections


def _rva_to_offset(rva: int, count: int, sections: list[tuple[int, int, int]],
                   size: int) -> int:
    offsets = []
    for va, raw_size, raw_start in sections:
        if va <= rva and rva - va + count <= raw_size:
            pos = raw_start + rva - va
            if pos + count <= size:
                offsets.append(pos)
    if len(offsets) != 1:
        raise _BadPE("unmapped or ambiguous import RVA")
    return offsets[0]


def _name(handle: BinaryIO, rva: int, sections: list[tuple[int, int, int]],
          size: int) -> str:
    # Read one byte at a time to allow a name ending at a section boundary,
    # but never read beyond the reviewed 128-byte DLL name limit.
    result = bytearray()
    for i in range(MAX_DLL_NAME_BYTES + 1):
        pos = _rva_to_offset(rva + i, 1, sections, size)
        char = _read(handle, pos, 1, size)[0]
        if char == 0:
            if not _DLL_NAME.fullmatch(bytes(result)):
                raise _BadPE("unsafe or empty DLL import name")
            return result.decode("ascii").lower()
        if i == MAX_DLL_NAME_BYTES:
            break
        result.append(char)
    raise _BadPE("unterminated or overlong DLL name")


def _inspect(handle: BinaryIO, size: int) -> tuple[str, str, list[str]]:
    dos = _read(handle, 0, 64, size)
    if dos[:2] != b"MZ":
        raise _BadPE("missing DOS MZ signature")
    pe_offset = _number(dos, 0x3C, 4)
    if not 64 <= pe_offset <= MAX_PE_OFFSET:
        raise _BadPE("PE header location outside safe bounds")
    nt = _read(handle, pe_offset, 24, size)
    if nt[:4] != b"PE\x00\x00":
        raise _BadPE("missing PE signature")
    machine, section_count = struct.unpack_from("<HH", nt, 4)
    optional_size = _number(nt, 20, 2)
    supported = _SUPPORTED.get(machine)
    if supported is None:
        raise _BadPE("unsupported PE architecture")
    architecture, expected_magic = supported
    opt_offset = pe_offset + 24
    if optional_size < 2 or optional_size > 4096:
        raise _BadPE("missing or oversized optional header")
    optional = _read(handle, opt_offset, optional_size, size)
    magic = _number(optional, 0, 2)
    if magic != expected_magic:
        raise _BadPE("architecture and optional header disagree")
    # Data directory 1 is the import directory. Check NumberOfRvaAndSizes
    # before dereferencing, and bound reads to SizeOfOptionalHeader.
    count_offset = 92 if magic == 0x10B else 108
    data_offset = 96 if magic == 0x10B else 112
    if len(optional) < data_offset:
        raise _BadPE("truncated optional header")
    directories = _number(optional, count_offset, 4)
    section_offset = opt_offset + optional_size
    sections = _sections(handle, section_offset, section_count, size)
    if directories < 2:
        return architecture, "HELD_NO_IMPORT_TABLE_OBSERVED", []
    if len(optional) < data_offset + 16:
        raise _BadPE("truncated import data directory")
    import_rva = _number(optional, data_offset + 8, 4)
    import_size = _number(optional, data_offset + 12, 4)
    if import_rva == 0 and import_size == 0:
        return architecture, "HELD_NO_IMPORT_TABLE_OBSERVED", []
    if (not import_rva or import_size < 20
            or import_size > MAX_IMPORT_DIRECTORY_BYTES):
        raise _BadPE("invalid or oversized import directory")
    descriptors = min(import_size // 20, MAX_IMPORT_DESCRIPTORS + 1)
    names: list[str] = []
    terminated = False
    for index in range(descriptors):
        desc_rva = import_rva + index * 20
        pos = _rva_to_offset(desc_rva, 20, sections, size)
        descriptor = _read(handle, pos, 20, size)
        if descriptor == bytes(20):
            terminated = True
            break
        if index >= MAX_IMPORT_DESCRIPTORS:
            raise _BadPE("too many imported DLL descriptors")
        name_rva = _number(descriptor, 12, 4)
        if not name_rva:
            raise _BadPE("import descriptor without DLL name")
        dll = _name(handle, name_rva, sections, size)
        if dll not in names:
            names.append(dll)
    if not terminated:
        raise _BadPE("import directory missing terminal descriptor")
    return architecture, "OBSERVED_IMPORT_NAMES_REVIEW_ONLY", names


def inspect_pe_imports(path: str | Path) -> dict:
    """Observe a bounded PE import table using one open read-only file handle.

    The digest is observational, not a signature or immutable pin. Windows
    import resolution also includes delay imports, dynamic LoadLibrary calls,
    API-set redirects, SxS manifests, and other mechanisms NOT covered here.
    """
    source = Path(path).expanduser()
    if source.suffix.lower() != ".exe" or source.is_symlink():
        raise ValueError("PE imports require a local regular .exe, not a symlink")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(source, flags)
    except OSError as exc:
        raise ValueError("Cannot open regular local PE file") from exc
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= MAX_INPUT_BYTES:
            raise ValueError("PE file is not regular or exceeds static-inspection bounds")
        size = info.st_size
        # Stream the same open descriptor that the parser reads. This avoids
        # a filename reopen, but does not pretend a mutable file is pinned.
        digest = hashlib.sha256()
        handle.seek(0)
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
        try:
            architecture, status, dlls = _inspect(handle, size)
        except _BadPE:
            architecture, status, dlls = None, "HELD_MALFORMED_OR_UNSUPPORTED_PE", []
    return {
        "schema": SCHEMA,
        "name": source.name,
        "sha256_observed": digest.hexdigest(),
        "size_bytes_observed": size,
        "architecture_observed": architecture,
        "status": status,
        "import_dlls_observed": dlls,
        "import_dll_count": len(dlls),
        "import_scan_scope": "DIRECT_IMPORT_DIRECTORY_ONLY",
        "origin_attested": False,
        "source_immutable": False,
        "compatibility_verified": False,
        "sandbox_verified": False,
        "execution_authorized": False,
        "windows_execution_attempted": False,
        "wine_executed": False,
    }
