"""Synthetic PE32/PE32+ fixtures for the Rung 9 no-execution import reader."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from phivine.cli import main
from phivine.pe_imports import inspect_pe_imports


def build_pe(*, pe64: bool, names: tuple[bytes, ...] = (b"KERNEL32.dll",)) -> bytes:
    """Tiny header/table fixture, NOT a functional Windows executable."""
    if len(names) > 2:
        raise ValueError("synthetic fixture supports two imports")
    raw = bytearray(0x400)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, 0x80)
    raw[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", raw, 0x84, 0x8664 if pe64 else 0x014C)
    struct.pack_into("<H", raw, 0x86, 1)
    optional_size = 0xF0 if pe64 else 0xE0
    struct.pack_into("<H", raw, 0x94, optional_size)
    opt = 0x98
    struct.pack_into("<H", raw, opt, 0x20B if pe64 else 0x10B)
    struct.pack_into("<I", raw, opt + (108 if pe64 else 92), 16)
    data_offset = opt + (112 if pe64 else 96)
    if names:
        struct.pack_into("<II", raw, data_offset + 8, 0x1000, (len(names) + 1) * 20)
    section = opt + optional_size
    raw[section:section + 6] = b".idata"
    struct.pack_into("<IIII", raw, section + 8, 0x200, 0x1000, 0x200, 0x200)
    for i, name in enumerate(names):
        name_rva = 0x1060 + i * 0x40
        struct.pack_into("<I", raw, 0x200 + i * 20 + 12, name_rva)
        start = 0x260 + i * 0x40
        raw[start:start + len(name) + 1] = name + b"\x00"
    return bytes(raw)


class PEImportEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def file(self, contents: bytes, name: str = "synthetic.exe") -> Path:
        result = self.root / name
        result.write_bytes(contents)
        return result

    def test_pe32_and_pe32plus_imports_without_authority(self) -> None:
        for pe64, arch in ((False, "x86"), (True, "x86_64")):
            with self.subTest(arch=arch):
                raw = build_pe(pe64=pe64, names=(b"KERNEL32.dll", b"USER32.dll"))
                record = inspect_pe_imports(self.file(raw))
                self.assertEqual(record["schema"], "phivine.pe_imports.v0.1")
                self.assertEqual(record["status"], "OBSERVED_IMPORT_NAMES_REVIEW_ONLY")
                self.assertEqual(record["architecture_observed"], arch)
                self.assertEqual(record["import_dlls_observed"],
                                 ["kernel32.dll", "user32.dll"])
                self.assertEqual(record["import_dll_count"], 2)
                self.assertEqual(record["sha256_observed"], hashlib.sha256(raw).hexdigest())
                self.assertEqual(record["import_scan_scope"], "DIRECT_IMPORT_DIRECTORY_ONLY")
                for key in ("origin_attested", "source_immutable", "compatibility_verified",
                            "sandbox_verified", "execution_authorized",
                            "windows_execution_attempted", "wine_executed"):
                    self.assertIs(record[key], False, key)

    def test_no_import_directory_is_not_compatibility(self) -> None:
        record = inspect_pe_imports(self.file(build_pe(pe64=True, names=())))
        self.assertEqual(record["status"], "HELD_NO_IMPORT_TABLE_OBSERVED")
        self.assertEqual(record["import_dlls_observed"], [])
        self.assertIs(record["compatibility_verified"], False)

    def test_bad_signature_and_short_dos_are_held(self) -> None:
        for raw in (b"hello world", b"MZ", bytes(256)):
            with self.subTest(raw=raw[:10]):
                result = inspect_pe_imports(self.file(raw))
                self.assertEqual(result["status"], "HELD_MALFORMED_OR_UNSUPPORTED_PE")

    def test_bad_optional_header_and_section_out_of_bounds(self) -> None:
        raw = bytearray(build_pe(pe64=True))
        struct.pack_into("<H", raw, 0x98, 0x10B)
        self.assertEqual(
            inspect_pe_imports(self.file(raw))["status"],
            "HELD_MALFORMED_OR_UNSUPPORTED_PE"
        )
        raw = bytearray(build_pe(pe64=True))
        section = 0x98 + 0xF0
        struct.pack_into("<I", raw, section + 20, 0x500)
        self.assertEqual(
            inspect_pe_imports(self.file(raw))["status"],
            "HELD_MALFORMED_OR_UNSUPPORTED_PE"
        )

    def test_unknown_architecture_not_reclassified(self) -> None:
        raw = bytearray(build_pe(pe64=True))
        struct.pack_into("<H", raw, 0x84, 0xAA64)
        self.assertEqual(
            inspect_pe_imports(self.file(raw))["status"],
            "HELD_MALFORMED_OR_UNSUPPORTED_PE",
        )

    def test_unsafe_dll_basename_is_not_exposed(self) -> None:
        raw = build_pe(pe64=True, names=(b"../evil.dll",))
        record = inspect_pe_imports(self.file(raw))
        self.assertEqual(record["status"], "HELD_MALFORMED_OR_UNSUPPORTED_PE")
        self.assertEqual(record["import_dlls_observed"], [])

    def test_unterminated_descriptor_is_held(self) -> None:
        raw = bytearray(build_pe(pe64=True))
        struct.pack_into("<I", raw, 0x98 + 112 + 12, 20)
        record = inspect_pe_imports(self.file(raw))
        self.assertEqual(record["status"], "HELD_MALFORMED_OR_UNSUPPORTED_PE")

    def test_overlong_dll_name_is_held(self) -> None:
        raw = bytearray(build_pe(pe64=True))
        raw[0x260:0x260 + 140] = b"a" * 140
        self.assertEqual(
            inspect_pe_imports(self.file(raw))["status"],
            "HELD_MALFORMED_OR_UNSUPPORTED_PE",
        )

    def test_ambiguous_section_address_rejected(self) -> None:
        raw = bytearray(build_pe(pe64=True))
        struct.pack_into("<H", raw, 0x86, 2)
        old = 0x98 + 0xF0
        raw[old + 40:old + 80] = raw[old:old + 40]
        self.assertEqual(
            inspect_pe_imports(self.file(raw))["status"],
            "HELD_MALFORMED_OR_UNSUPPORTED_PE",
        )

    def test_no_symlink_or_unsupported_extension(self) -> None:
        target = self.file(build_pe(pe64=True))
        alias = self.root / "alias.exe"
        try:
            alias.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(ValueError):
            inspect_pe_imports(alias)
        with self.assertRaises(ValueError):
            inspect_pe_imports(self.file(build_pe(pe64=True), "not-an-exe.dll"))

    def test_cli_exit_three_always_and_never_runs_windows_or_wine(self) -> None:
        source = self.file(build_pe(pe64=False))
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("subprocess.run", side_effect=AssertionError("would spawn")), \
             patch("subprocess.Popen", side_effect=AssertionError("would spawn")), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["inspect-imports", str(source)])
        self.assertEqual(code, 3)
        self.assertEqual(stderr.getvalue(), "")
        record = json.loads(stdout.getvalue())
        self.assertEqual(record["import_dlls_observed"], ["kernel32.dll"])
        self.assertIs(record["execution_authorized"], False)


if __name__ == "__main__":
    unittest.main()
