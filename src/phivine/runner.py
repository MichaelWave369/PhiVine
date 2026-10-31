"""Read-only candidate Wine runner fingerprinting, not trust attestation.

No --version calls, shell invocation, Wine execution or subprocesses.
A SHA-256 identifies observed bytes at one moment; it cannot certify origin,
signatures, dynamic dependencies or executable behavior.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from .revalidate import CHUNK, _open_without_symlinks

SCHEMA = "phivine.runner_observation.v0.1"
MAX_RUNNER_BYTES = 128 * 1024 * 1024


def _result(status: str, path: str, *, digest: str | None = None,
            size: int | None = None, kind: str | None = None) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "status": status,
        "runner_path_observed": path,
        "sha256_observed": digest,
        "size_bytes_observed": size,
        "file_kind_observed": kind,
        "binary_identity_observed": status == "RUNNER_ELF_BYTES_OBSERVED_NOT_ATTESTED",
        "binary_identity_attested": False,
        "version_verified": False,
        "signature_verified": False,
        "dependencies_verified": False,
        "execution_authorized": False,
        "effect_lease_present": False,
        "runner_executed": False,
        "note": "One untrusted local file fingerprint; no runtime qualification or launch permission.",
    }


def observe_runner(path: str | Path) -> dict[str, object]:
    observed = os.fspath(path)
    if (not isinstance(observed, str) or not observed.startswith("/")
            or "\x00" in observed or len(observed) > 4096
            or any(part in ("", ".", "..") for part in observed.split("/")[1:])):
        return _result("HELD_INVALID_RUNNER_PATH", str(observed))
    try:
        fd = _open_without_symlinks(observed)
    except OSError:
        return _result("HELD_RUNNER_PATH_UNAVAILABLE_OR_UNSAFE", observed)
    try:
        with os.fdopen(fd, "rb", closefd=True) as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                return _result("HELD_RUNNER_NOT_REGULAR_FILE", observed)
            if not (before.st_mode & 0o111):
                return _result("HELD_RUNNER_NOT_EXECUTABLE", observed)
            if not 0 < before.st_size <= MAX_RUNNER_BYTES:
                return _result("HELD_RUNNER_SIZE_LIMIT", observed)
            digest = hashlib.sha256()
            total = 0
            first = b""
            for block in iter(lambda: handle.read(CHUNK), b""):
                if not first:
                    first = block[:4]
                digest.update(block)
                total += len(block)
                if total > MAX_RUNNER_BYTES:
                    return _result("HELD_RUNNER_SIZE_LIMIT", observed)
            after = os.fstat(handle.fileno())
            if (before.st_dev != after.st_dev or before.st_ino != after.st_ino
                    or before.st_size != after.st_size or before.st_size != total
                    or before.st_mtime_ns != after.st_mtime_ns
                    or before.st_ctime_ns != after.st_ctime_ns):
                return _result("HELD_RUNNER_CHANGED_DURING_READ", observed)
            kind = "elf" if first == b"\x7fELF" else "script" if first.startswith(b"#!") else "unknown"
            if kind != "elf":
                return _result("HELD_RUNNER_NOT_ELF_BINARY", observed,
                               digest=digest.hexdigest(), size=total, kind=kind)
            return _result("RUNNER_ELF_BYTES_OBSERVED_NOT_ATTESTED", observed,
                           digest=digest.hexdigest(), size=total, kind=kind)
    except OSError:
        return _result("HELD_RUNNER_READ_ERROR", observed)
