"""Read-only staged-file verification, without immutable or execution claims.

The same-user owned snapshot can still change immediately afterward. A
verification report is not an artifact lease, trusted source, or authorization.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from .revalidate import CHUNK, _open_without_symlinks, _validated_fields
from .staging import _absolute_components

SCHEMA = "phivine.stage_verification.v0.1"


def _result(status: str, proposal_id: str | None = None,
            path: str | None = None, *, matched: bool = False) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "status": status,
        "proposal_id_observed": proposal_id,
        "staged_path_observed": path,
        "staged_bytes_match_observed": matched,
        "immutability_verified": False,
        "stable_handle_retained": False,
        "runner_attested": False,
        "sandbox_verified": False,
        "execution_authorized": False,
        "effect_lease_present": False,
        "windows_execution_attempted": False,
        "note": "Read-only snapshot check; owner-controlled files are mutable after observation.",
    }


def verify_stage(plan: Mapping[str, Any], store: str | Path) -> dict[str, object]:
    """Check one SHA-named staged snapshot against a held Rung 2 proposal.

    The selected store is not created, repaired, or modified. All observations
    are bound to one open descriptor that is closed before returning.
    """
    fields = _validated_fields(plan)
    if fields is None:
        return _result("HELD_INVALID_OR_TAMPERED_PROPOSAL")
    _, digest, expected_size, pid = fields
    destination = os.fspath(store)
    if not isinstance(destination, str) or not _absolute_components(destination):
        return _result("HELD_INVALID_STAGE_DIRECTORY", pid)

    target = destination + "/" + digest + ".exe"
    try:
        dirfd = _open_without_symlinks(destination)
    except OSError:
        return _result("HELD_STAGE_DIRECTORY_UNAVAILABLE", pid, target)
    try:
        dststat = os.fstat(dirfd)
        if (not stat.S_ISDIR(dststat.st_mode) or dststat.st_uid != os.geteuid()
                or dststat.st_mode & 0o077):
            return _result("HELD_STAGE_DIRECTORY_NOT_PRIVATE", pid, target)
        try:
            fd = os.open(
                digest + ".exe",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=dirfd,
            )
        except OSError:
            return _result("HELD_STAGE_FILE_UNAVAILABLE_OR_UNSAFE", pid, target)

        try:
            with os.fdopen(fd, "rb", closefd=True) as snapshot:
                before = os.fstat(snapshot.fileno())
                if not stat.S_ISREG(before.st_mode):
                    return _result("HELD_STAGE_NOT_REGULAR_FILE", pid, target)
                if (before.st_uid != os.geteuid() or before.st_mode & 0o277
                        or before.st_nlink != 1 or not before.st_mode & stat.S_IRUSR):
                    return _result("HELD_STAGE_FILE_PERMISSIONS_OR_LINKS", pid, target)
                if before.st_size != expected_size:
                    return _result("HELD_STAGE_SIZE_MISMATCH", pid, target)

                digest_state = hashlib.sha256()
                count = 0
                for data in iter(lambda: snapshot.read(CHUNK), b""):
                    count += len(data)
                    if count > expected_size:
                        return _result("HELD_STAGE_SIZE_MISMATCH", pid, target)
                    digest_state.update(data)
                after = os.fstat(snapshot.fileno())
                if (before.st_dev != after.st_dev or before.st_ino != after.st_ino
                        or before.st_size != after.st_size
                        or before.st_mtime_ns != after.st_mtime_ns
                        or before.st_ctime_ns != after.st_ctime_ns):
                    return _result("HELD_STAGE_CHANGED_DURING_READ", pid, target)
                if count != expected_size:
                    return _result("HELD_STAGE_SIZE_MISMATCH", pid, target)
                if not hmac.compare_digest(digest_state.hexdigest(), digest):
                    return _result("HELD_STAGE_HASH_MISMATCH", pid, target)
        except OSError:
            return _result("HELD_STAGE_READ_FAILED", pid, target)
        return _result("STAGE_MATCHED_NOT_IMMUTABLE_NOT_RUNNABLE", pid, target,
                       matched=True)
    finally:
        os.close(dirfd)
