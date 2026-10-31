"""Read-only, offline, bounded Windows-binary evidence inspection.

This module does not execute untrusted inputs, launch subprocesses, contact the
network, or implement sandbox enforcement. Its results never grant authority.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
from typing import Callable

SCHEMA = "phivine.inspection.v0.1"
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_PE_OFFSET = 1024 * 1024
CFB_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
MACHINES = {0x014C: "x86", 0x8664: "x86_64", 0xAA64: "arm64"}


class InspectionError(ValueError):
    """A local input could not be inspected under Rung 1 limits."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_file(
    input_path: str | Path,
    *,
    which: Callable[[str], str | None] | None = None,
) -> dict[str, object]:
    """Return deterministic evidence without executing or modifying the input.

    'which' is injectable so tests can simulate runtime discovery. Only 'wine'
    on PATH is observed; Proton installs and runtime behavior are not inferred.
    """
    path = Path(input_path).expanduser()
    if path.is_symlink():
        raise InspectionError("symbolic links are not accepted in Rung 1")
    if not path.is_file():
        raise InspectionError("input must be a regular local file")
    size = path.stat().st_size
    if size == 0 or size > MAX_FILE_BYTES:
        raise InspectionError("input must be between 1 byte and 512 MiB")

    fmt = "unknown"
    architecture: str | None = None
    problem: str | None = None
    with path.open("rb") as handle:
        header = handle.read(64)
        if header[:2] == b"MZ":
            fmt = "pe_candidate"
            if len(header) < 64:
                problem = "HELD_MALFORMED_PE"
            else:
                pe_offset = int.from_bytes(header[0x3C:0x40], "little")
                if not 64 <= pe_offset <= MAX_PE_OFFSET or pe_offset + 6 > size:
                    problem = "HELD_MALFORMED_PE"
                else:
                    handle.seek(pe_offset)
                    coff = handle.read(6)
                    if coff[:4] != b"PE\x00\x00" or len(coff) < 6:
                        problem = "HELD_MALFORMED_PE"
                    else:
                        fmt = "pe"
                        machine = int.from_bytes(coff[4:6], "little")
                        architecture = MACHINES.get(machine)
                        if architecture not in ("x86", "x86_64"):
                            problem = "HELD_UNSUPPORTED_ARCHITECTURE"
        elif header.startswith(CFB_MAGIC) and path.suffix.lower() == ".msi":
            fmt = "msi_cfb_candidate"
            problem = "HELD_MSI_REVIEW_REQUIRED"
        else:
            problem = "HELD_UNRECOGNIZED_FORMAT"

    if path.suffix.lower() not in (".exe", ".msi"):
        problem = "HELD_UNSUPPORTED_EXTENSION"
    elif fmt == "pe" and path.suffix.lower() != ".exe":
        problem = "HELD_UNSUPPORTED_EXTENSION"

    find_runner = which if which is not None else shutil.which
    wine_path = find_runner("wine")
    runners = ["wine"] if wine_path else []

    if problem is None:
        status = "REVIEW_REQUIRED" if runners else "HELD_RUNTIME_MISSING"
    else:
        status = problem

    return {
        "schema": SCHEMA,
        "name": path.name,
        "size_bytes": size,
        "sha256": _sha256(path),
        "observed_format": fmt,
        "architecture": architecture,
        "observed_runners": runners,
        "status": status,
        "execution_authorized": False,
        "execution_attempted": False,
        "network_probed": False,
        "sandbox_verified": False,
        "note": "Advisory evidence only: neither a safety assessment nor a compatibility guarantee.",
    }
