"""Pure, non-authorizing manual-review hints for static PE import observations.

The heuristics match *names only*. They are not DLL resolution, a Wine
compatibility database, a malware assessment, or an execution plan.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .pe_imports import inspect_pe_imports

SCHEMA = "phivine.import_triage.v0.1"
SOURCE_SCHEMA = "phivine.pe_imports.v0.1"
_VALID_NAME = re.compile(r"[a-z0-9_.+-]{1,128}\Z")
_HEX64 = re.compile(r"[a-f0-9]{64}\Z")

# Small, intentionally conservative name-pattern catalog. An absent name
# never proves an API is unused; a present name never proves runtime support.
_AREAS = (
    (
        "graphics_apis",
        frozenset({
            "d3d8.dll", "d3d9.dll", "d3d10.dll", "d3d10_1.dll",
            "d3d11.dll", "d3d12.dll", "dxgi.dll", "ddraw.dll",
            "opengl32.dll", "vulkan-1.dll",
        }),
        "Review graphics API translation and driver capabilities independently.",
    ),
    (
        "network_apis",
        frozenset({
            "wsock32.dll", "ws2_32.dll", "winhttp.dll", "wininet.dll",
            "dnsapi.dll",
        }),
        "Review requested network effects; importing networking APIs does not authorize network access.",
    ),
    (
        "managed_runtime_bootstrap",
        frozenset({"mscoree.dll", "coreclr.dll", "hostfxr.dll"}),
        "Review managed-runtime requirements and deployment separately; no runtime was detected or installed.",
    ),
    (
        "visual_cpp_runtime",
        frozenset({
            "msvcrt.dll", "ucrtbase.dll", "msvcr100.dll", "msvcr110.dll",
            "msvcr120.dll", "msvcp100.dll", "msvcp110.dll", "msvcp120.dll",
            "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll",
            "vcruntime140.dll", "vcruntime140_1.dll",
        }),
        "Review compiler runtime dependencies and redistribution licenses, not installation status.",
    ),
    (
        "com_and_automation",
        frozenset({"ole32.dll", "oleaut32.dll", "combase.dll"}),
        "Review COM or automation behavior independently; importing a library does not prove a component is registered.",
    ),
    (
        "windows_ui",
        frozenset({"user32.dll", "gdi32.dll", "comctl32.dll", "shell32.dll"}),
        "Review desktop/UI integration requirements; no display session has been tested.",
    ),
)

_FALSE_FIELDS = (
    "origin_attested", "source_immutable", "compatibility_verified",
    "sandbox_verified", "execution_authorized", "windows_execution_attempted",
    "wine_executed",
)
_MAX_DIRECT_IMPORTS = 128


def _refuse(source: Any) -> None:
    if not isinstance(source, dict) or source.get("schema") != SOURCE_SCHEMA:
        raise ValueError("Expected bounded PE import evidence v0.1")
    # This accepts observations from our static parser, NOT arbitrary
    # caller-supplied capability/permission claims.
    if any(source.get(key) is not False for key in _FALSE_FIELDS):
        raise ValueError("PE evidence attempted to claim trust or authority")
    if source.get("import_scan_scope") != "DIRECT_IMPORT_DIRECTORY_ONLY":
        raise ValueError("Unknown or expanded PE scan scope")
    digest = source.get("sha256_observed")
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise ValueError("Malformed observed content digest")
    if type(source.get("size_bytes_observed")) is not int or not 1 <= source["size_bytes_observed"] <= 512 * 1024 * 1024:
        raise ValueError("Unbounded observed file size")
    names = source.get("import_dlls_observed")
    if not isinstance(names, list) or len(names) > _MAX_DIRECT_IMPORTS:
        raise ValueError("Invalid or oversized direct import list")
    if any(type(name) is not str or not _VALID_NAME.fullmatch(name) or name != name.lower()
           for name in names):
        raise ValueError("Unsafe, uppercase or non-basename DLL observation")
    if len(set(names)) != len(names) or source.get("import_dll_count") != len(names):
        raise ValueError("Duplicate or inconsistent direct DLL observations")
    status = source.get("status")
    if status == "OBSERVED_IMPORT_NAMES_REVIEW_ONLY":
        if not names or source.get("architecture_observed") not in ("x86", "x86_64"):
            raise ValueError("Observed imports require nonempty list and supported PE")
    elif status in ("HELD_NO_IMPORT_TABLE_OBSERVED", "HELD_MALFORMED_OR_UNSUPPORTED_PE"):
        if names or source.get("import_dll_count") != 0:
            raise ValueError("Held static parsing cannot return partial import names")
    else:
        raise ValueError("Unknown static PE evidence status")


def review_import_evidence(source: dict[str, Any]) -> dict[str, Any]:
    """Derive human review categories from exact direct-DLL observations only.

    This function never infers dependency availability or Windows compatibility.
    """
    _refuse(source)
    names = source["import_dlls_observed"]
    review_areas = []
    classified: set[str] = set()
    if source["status"] == "OBSERVED_IMPORT_NAMES_REVIEW_ONLY":
        for area, known, guidance in _AREAS:
            matched = sorted(name for name in names if name in known)
            if matched:
                review_areas.append({
                    "area": area,
                    "dll_names_observed": matched,
                    "review_prompt": guidance,
                    "capability_or_dependency_availability_verified": False,
                })
                classified.update(matched)
    status = (
        "HELD_STATIC_IMPORT_TRIAGE_REVIEW_ONLY"
        if source["status"] == "OBSERVED_IMPORT_NAMES_REVIEW_ONLY"
        else "HELD_STATIC_INPUT_INSUFFICIENT"
    )
    return {
        "schema": SCHEMA,
        "source_schema": SOURCE_SCHEMA,
        "status": status,
        "name": source["name"],
        "source_sha256_observed": source["sha256_observed"],
        "source_size_bytes_observed": source["size_bytes_observed"],
        "architecture_observed": source["architecture_observed"],
        "static_parser_status": source["status"],
        "direct_import_dll_count": len(names),
        "review_areas": review_areas,
        "unclassified_direct_imports": sorted(set(names) - classified),
        "import_scope": "DIRECT_IMPORT_DIRECTORY_ONLY",
        "other_dependencies_not_scanned": [
            "delayed_imports", "dynamic_library_loading", "imported_symbols_and_ordinals",
            "manifests_and_side_by_side", "managed_assemblies", "external_installer_effects",
        ],
        "dependency_availability_verified": False,
        "wine_compatibility_verified": False,
        "origin_attested": False,
        "source_immutable": False,
        "sandbox_verified": False,
        "operator_approval_granted": False,
        "effect_lease_issued": False,
        "execution_authorized": False,
        "windows_execution_attempted": False,
        "wine_executed": False,
        "note": "Name-only manual-review hints; no compatibility verdict, runtime probes, or grants.",
    }


def review_pe_imports(path: str | Path) -> dict[str, Any]:
    """Read the file via the existing bounded PE parser; never open a DLL."""
    return review_import_evidence(inspect_pe_imports(path))
