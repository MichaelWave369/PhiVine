#!/usr/bin/env python3
"""Current PhiVine Rung 10 producer -> pinned PhiOS Rung 11 static triage.

Only nonfunctional synthetic PE fixtures and JSON are read. Windows binaries,
Wine and DLLs are never executed; held reviews are not permission grants.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from typing import Any

PHIOS_REVIEWED_SHA = "34553a6214b05e5bb6c42665d89621d13f1f0516"
PHIVINE_TRIAGE_SCHEMA = "phivine.import_triage.v0.1"
PHIOS_REVIEW_SCHEMA = "phios.phivine_import_triage_review.v0.1"
NO_AUTHORITY = (
    "source_immutability_verified",
    "binary_file_read_by_phios",
    "source_repo_profiler_called",
    "wine_compatibility_verified",
    "network_granted",
    "app_registry_read_or_modified",
    "phios_install_or_launch_called",
    "operator_approval_minted",
    "effect_lease_issued",
    "execution_authorized",
    "windows_binary_executed",
)


def invoke(module: str, arguments: list[str], *, pythonpath: Path,
           cwd: Path, expected_exit: int) -> dict[str, Any]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(pythonpath.resolve())
    proc = subprocess.run(
        [sys.executable, "-m", module, *arguments],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=30,
        check=False,
    )
    if proc.returncode != expected_exit:
        raise AssertionError(
            f"{module} exit={proc.returncode} expected={expected_exit}; "
            f"stderr_tail={proc.stderr[-500:]}"
        )
    output = json.loads(proc.stdout)
    if not isinstance(output, dict):
        raise AssertionError(f"{module} did not emit a JSON object")
    return output


def create_pe(path: Path, *, pe64: bool, dlls: tuple[bytes, ...]) -> bytes:
    """Generate an inert header with section-backed import descriptors.

    Not a valid runnable program: no entry point, imported functions, or code.
    The test names are not paths and are not opened as host libraries.
    """
    if len(dlls) > 3:
        raise ValueError("Synthetic fixture only supports three DLL names")
    result = bytearray(0x600)
    result[:2] = b"MZ"
    struct.pack_into("<I", result, 0x3C, 0x80)
    result[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", result, 0x84, 0x8664 if pe64 else 0x014C)
    struct.pack_into("<H", result, 0x86, 1)
    struct.pack_into("<H", result, 0x94, 0xF0 if pe64 else 0xE0)
    optional = 0x98
    struct.pack_into("<H", result, optional, 0x20B if pe64 else 0x10B)
    struct.pack_into("<I", result, optional + (108 if pe64 else 92), 16)
    if dlls:
        directory = optional + (112 if pe64 else 96)
        struct.pack_into("<II", result, directory + 8, 0x1000, (len(dlls) + 1) * 20)
    section = optional + (0xF0 if pe64 else 0xE0)
    result[section:section + 6] = b".idata"
    struct.pack_into("<IIII", result, section + 8, 0x400, 0x1000, 0x400, 0x200)
    for index, dll in enumerate(dlls):
        if not (1 <= len(dll) <= 28):
            raise ValueError("Fixture name outside local 28-byte budget")
        struct.pack_into("<I", result, 0x200 + index * 20 + 12, 0x1060 + index * 0x40)
        offset = 0x260 + index * 0x40
        result[offset:offset + len(dll) + 1] = dll + b"\x00"
    payload = bytes(result)
    path.write_bytes(payload)
    return payload


def accept(review: dict[str, Any], *, expected_status: str, visible: bool) -> None:
    if review.get("schema") != PHIOS_REVIEW_SCHEMA or review.get("status") != expected_status:
        raise AssertionError(f"Unexpected review contract: {review.get('status')}")
    for key in NO_AUTHORITY:
        if review.get(key) is not False:
            raise AssertionError(f"PhiOS incorrectly granted or claimed {key}")
    if visible:
        if not isinstance(review.get("review_groups"), list):
            raise AssertionError("Verified observational groups absent")
    elif (review.get("artifact_name_observed") is not None
          or review.get("review_groups")
          or review.get("unclassified_direct_imports")):
        raise AssertionError("Untrusted malformed data became visible")


def read_review(candidate: Any, *, phi_os: Path, cwd: Path,
                expected_status: str, visible: bool,
                raw_bytes: bytes | None = None) -> dict[str, Any]:
    handoff = cwd / "triage.json"
    handoff.write_bytes(
        raw_bytes if raw_bytes is not None else json.dumps(candidate).encode("utf-8")
    )
    result = invoke(
        "phios.apps.cli", ["review-phivine-triage", str(handoff)],
        pythonpath=phi_os, cwd=cwd, expected_exit=3,
    )
    accept(result, expected_status=expected_status, visible=visible)
    return result


def run(phi_os: Path, receipt: Path) -> None:
    pinned_sha = subprocess.check_output(
        ["git", "-C", str(phi_os), "rev-parse", "HEAD"], text=True, timeout=10,
    ).strip()
    if pinned_sha != PHIOS_REVIEWED_SHA:
        raise AssertionError("PhiOS triage reader is not the reviewed #364 commit")

    producer = Path(__file__).resolve().parents[1]
    producer_sha = subprocess.check_output(
        ["git", "-C", str(producer), "rev-parse", "HEAD"], text=True, timeout=10,
    ).strip()
    workflow_sha = os.environ.get("GITHUB_SHA")
    if workflow_sha and producer_sha != workflow_sha:
        raise AssertionError("PhiVine under test differs from GitHub workflow head")

    with tempfile.TemporaryDirectory(prefix="phivine-phios-static-peer-") as dir_name:
        root = Path(dir_name)
        source = root / "synthetic.exe"
        content = create_pe(
            source, pe64=True,
            dlls=(b"D3D11.dll", b"WS2_32.dll", b"MYGAME.dll"),
        )
        observed = invoke(
            "phivine", ["triage-imports", str(source)],
            pythonpath=producer / "src", cwd=root, expected_exit=3,
        )
        if (observed.get("schema") != PHIVINE_TRIAGE_SCHEMA
                or observed.get("status") != "HELD_STATIC_IMPORT_TRIAGE_REVIEW_ONLY"
                or observed.get("source_sha256_observed") != hashlib.sha256(content).hexdigest()
                or observed.get("direct_import_dll_count") != 3):
            raise AssertionError("PhiVine static triage source or structure drift")
        good = read_review(
            observed, phi_os=phi_os, cwd=root,
            expected_status="HELD_STATIC_DLL_REVIEW_UNTRUSTED",
            visible=True,
        )
        if [entry["area"] for entry in good["review_groups"]] != [
            "graphics_apis", "network_apis",
        ]:
            raise AssertionError("PhiOS recognized areas changed unexpectedly")
        if good["unclassified_direct_imports"] != ["mygame.dll"]:
            raise AssertionError("PhiOS concealed unknown DLL or invented support")
        if good["artifact_sha256_observed"] != observed["source_sha256_observed"]:
            raise AssertionError("PhiOS changed the observed, unauthenticated digest")

        # PE32 with no direct imports is not accepted as "self-contained".
        create_pe(source, pe64=False, dlls=())
        empty = invoke(
            "phivine", ["triage-imports", str(source)],
            pythonpath=producer / "src", cwd=root, expected_exit=3,
        )
        if empty["status"] != "HELD_STATIC_INPUT_INSUFFICIENT":
            raise AssertionError("Empty PE imports were promoted as compatibility")
        empty_review = read_review(
            empty, phi_os=phi_os, cwd=root,
            expected_status="HELD_STATIC_DLL_REVIEW_UNTRUSTED",
            visible=True,
        )
        if empty_review["review_groups"] or empty_review["unclassified_direct_imports"]:
            raise AssertionError("Empty import table gained invented dependencies")

        # A corrupt PE never returns partial import names.
        source.write_bytes(b"MZ")
        malformed = invoke(
            "phivine", ["triage-imports", str(source)],
            pythonpath=producer / "src", cwd=root, expected_exit=3,
        )
        if malformed["status"] != "HELD_STATIC_INPUT_INSUFFICIENT":
            raise AssertionError("Malformed PE was not held")
        read_review(
            malformed, phi_os=phi_os, cwd=root,
            expected_status="HELD_STATIC_DLL_REVIEW_UNTRUSTED", visible=True,
        )

        forbidden = "HELD_INVALID_OR_UNTRUSTED_STATIC_TRIAGE"
        forged = json.loads(json.dumps(observed))
        forged["execution_authorized"] = True
        denied = read_review(
            forged, phi_os=phi_os, cwd=root,
            expected_status=forbidden, visible=False,
        )
        invented = json.loads(json.dumps(observed))
        invented["review_areas"][0]["area"] = "network_apis"
        read_review(
            invented, phi_os=phi_os, cwd=root,
            expected_status=forbidden, visible=False,
        )
        concealed = json.loads(json.dumps(observed))
        concealed["unclassified_direct_imports"] = ["d3d11.dll"]
        read_review(
            concealed, phi_os=phi_os, cwd=root,
            expected_status=forbidden, visible=False,
        )
        expanded = json.loads(json.dumps(observed))
        expanded["import_scope"] = "ALL_DYNAMIC_IMPORTS"
        read_review(
            expanded, phi_os=phi_os, cwd=root,
            expected_status=forbidden, visible=False,
        )
        read_review(
            None, phi_os=phi_os, cwd=root,
            expected_status=forbidden, visible=False,
            raw_bytes=b'{"status":"HELD","status":"COMPATIBLE"}',
        )

        # Detect future accidental parser changes that allow >64 KiB.
        read_review(
            None, phi_os=phi_os, cwd=root,
            expected_status=forbidden, visible=False,
            raw_bytes=b" " * 65537,
        )

    record = {
        "schema": "phivine.phios_triage_reciprocal.v0.1",
        "producer_sha": producer_sha,
        "consumer_sha": pinned_sha,
        "producer_exit": 3,
        "consumer_exit": 3,
        "recognized_areas": ["graphics_apis", "network_apis"],
        "unknown_imports_preserved": True,
        "valid_status": good["status"],
        "no_imports_status": empty_review["status"],
        "forged_authority_status": denied["status"],
        "invalid_category_status": forbidden,
        "duplicate_keys_blocked": True,
        "oversized_json_blocked": True,
        "wine_executed": False,
        "windows_binary_executed": False,
        "dependencies_available_verified": False,
        "sandbox_qualified": False,
        "permissions_granted": False,
        "phi_os_application_installed": False,
        "release_authorized": False,
    }
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("PHIVINE_PHIOS_TRIAGE_RECIPROCAL_HELD_PASS")
    print(json.dumps(record, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phios", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    arguments = parser.parse_args()
    run(arguments.phios.resolve(strict=True), arguments.receipt)


if __name__ == "__main__":
    main()
