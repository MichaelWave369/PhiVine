"""Rung 10: conservative static import review hints, no compatibility claims."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from phivine.cli import main
from phivine.import_triage import review_import_evidence, review_pe_imports
from phivine.pe_imports import inspect_pe_imports
from test_pe_imports import build_pe


class ImportTriageTests(unittest.TestCase):
    def setUp(self) -> None:
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)

    def file(self, contents: bytes) -> Path:
        path = self.root / "synthetic.exe"
        path.write_bytes(contents)
        return path

    def test_direct_graphics_and_network_signals_only(self) -> None:
        path = self.file(build_pe(
            pe64=True, names=(b"D3D11.dll", b"WS2_32.dll")
        ))
        result = review_pe_imports(path)
        self.assertEqual(result["schema"], "phivine.import_triage.v0.1")
        self.assertEqual(result["status"], "HELD_STATIC_IMPORT_TRIAGE_REVIEW_ONLY")
        self.assertEqual(result["architecture_observed"], "x86_64")
        self.assertEqual(result["direct_import_dll_count"], 2)
        self.assertEqual([x["area"] for x in result["review_areas"]],
                         ["graphics_apis", "network_apis"])
        self.assertEqual(result["review_areas"][0]["dll_names_observed"], ["d3d11.dll"])
        self.assertEqual(result["review_areas"][1]["dll_names_observed"], ["ws2_32.dll"])
        self.assertEqual(result["unclassified_direct_imports"], [])
        for key in ("dependency_availability_verified", "wine_compatibility_verified",
                    "origin_attested", "source_immutable", "sandbox_verified",
                    "operator_approval_granted", "effect_lease_issued",
                    "execution_authorized", "windows_execution_attempted", "wine_executed"):
            self.assertIs(result[key], False, key)

    def test_unrecognized_dll_not_treated_as_missing(self) -> None:
        result = review_pe_imports(
            self.file(build_pe(pe64=False, names=(b"MYGAME.DLL",)))
        )
        self.assertEqual(result["review_areas"], [])
        self.assertEqual(result["unclassified_direct_imports"], ["mygame.dll"])
        self.assertEqual(result["architecture_observed"], "x86")
        self.assertNotIn("unsupported", str(result).lower())
        self.assertIs(result["wine_compatibility_verified"], False)

    def test_empty_imports_make_no_compatibility_claim(self) -> None:
        result = review_pe_imports(self.file(build_pe(pe64=True, names=())))
        self.assertEqual(result["status"], "HELD_STATIC_INPUT_INSUFFICIENT")
        self.assertEqual(result["review_areas"], [])
        self.assertEqual(result["unclassified_direct_imports"], [])
        self.assertIn("dynamic_library_loading", result["other_dependencies_not_scanned"])

    def test_malformed_pe_never_promotes_partial_imports(self) -> None:
        result = review_pe_imports(self.file(b"MZ"))
        self.assertEqual(result["status"], "HELD_STATIC_INPUT_INSUFFICIENT")
        self.assertEqual(result["direct_import_dll_count"], 0)
        self.assertEqual(result["review_areas"], [])
        self.assertFalse(result["execution_authorized"])

    def test_refuse_forged_permissions_or_scope(self) -> None:
        source = inspect_pe_imports(
            self.file(build_pe(pe64=True, names=(b"D3D11.dll",)))
        )
        for key in ("compatibility_verified", "sandbox_verified", "execution_authorized"):
            fake = dict(source, **{key: True})
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "authority"):
                review_import_evidence(fake)
        with self.assertRaisesRegex(ValueError, "scan scope"):
            review_import_evidence(dict(source, import_scan_scope="ALL_DYNAMIC_IMPORTS"))

    def test_refuse_fake_names_counts_and_partial_held_result(self) -> None:
        source = inspect_pe_imports(
            self.file(build_pe(pe64=True, names=(b"D3D11.dll",)))
        )
        bad = [
            dict(source, import_dlls_observed=["../d3d11.dll"]),
            dict(source, import_dlls_observed=["D3D11.dll"]),
            dict(source, import_dlls_observed=["d3d11.dll", "d3d11.dll"],
                 import_dll_count=2),
            dict(source, import_dll_count=0),
            dict(source, status="HELD_MALFORMED_OR_UNSUPPORTED_PE"),
            dict(source, import_dlls_observed=["valid.dll"] * 129,
                 import_dll_count=129),
        ]
        for fake in bad:
            with self.subTest(fake=fake), self.assertRaises(ValueError):
                review_import_evidence(fake)

    def test_cli_always_held_and_no_process_invocation(self) -> None:
        path = self.file(build_pe(pe64=True, names=(b"D3D11.dll",)))
        out, err = io.StringIO(), io.StringIO()
        with patch("subprocess.Popen", side_effect=AssertionError("spawn")), \
             patch("subprocess.run", side_effect=AssertionError("spawn")), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["triage-imports", str(path)])
        self.assertEqual(code, 3)
        self.assertEqual(err.getvalue(), "")
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["status"], "HELD_STATIC_IMPORT_TRIAGE_REVIEW_ONLY")
        self.assertIs(payload["execution_authorized"], False)

    def test_bad_filename_remains_cli_error_not_permission(self) -> None:
        path = self.root / "bad.dll"
        path.write_bytes(build_pe(pe64=True))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["triage-imports", str(path)])
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(json.loads(err.getvalue())["schema"], "phivine.error.v0.1")


if __name__ == "__main__":
    unittest.main()
