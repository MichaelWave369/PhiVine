"""Operator-invoked, content-addressed *snapshot* staging, never execution.

Staging writes exactly one SHA-256-named file into an explicitly supplied,
already-existing private directory. It does not make bytes immutable against
the same OS user, qualify a sandbox, or grant launch authority.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat
from typing import Any, Mapping

from .inspector import MAX_FILE_BYTES
from .revalidate import CHUNK, _open_without_symlinks, _validated_fields

SCHEMA = "phivine.staging.v0.1"


def _report(status: str, proposal_id: str | None = None, *,
            digest: str | None = None, staged: str | None = None) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "proposal_id_observed": proposal_id,
        "status": status,
        "artifact_sha256": digest,
        "staged_path": staged,
        "content_snapshot_created_or_reused": status == "SNAPSHOT_STAGED_NOT_RUNNABLE",
        "immutable_storage_verified": False,
        "sandbox_verified": False,
        "runner_attested": False,
        "execution_authorized": False,
        "effect_lease_present": False,
        "windows_execution_attempted": False,
        "note": "Operator-requested local copy only; owner can still mutate the snapshot.",
    }


def _absolute_components(value: str) -> bool:
    return (value.startswith("/") and value != "/" and "\x00" not in value
            and len(value) <= 4096
            and all(part not in ("", ".", "..") for part in value.split("/")[1:]))


def _snapshot_matches(dirfd: int, name: str, digest: str, size: int) -> bool:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=dirfd)
        with os.fdopen(fd, "rb") as file:
            st = os.fstat(file.fileno())
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                    or st.st_mode & 0o222 or st.st_mode & 0o077 or st.st_size != size):
                return False
            hashed = hashlib.sha256()
            count = 0
            for block in iter(lambda: file.read(CHUNK), b""):
                hashed.update(block)
                count += len(block)
                if count > size:
                    return False
            return count == size and hmac.compare_digest(hashed.hexdigest(), digest)
    except OSError:
        return False


def stage_plan(plan: Mapping[str, Any], store: str | Path) -> dict[str, object]:
    """Explicitly copy a validated input to a private, already-present store.

    No file is executed or returned as an open descriptor. A future trusted
    broker must revalidate a pinned exact blob before any action.
    """
    fields = _validated_fields(plan)
    if fields is None:
        return _report("HELD_INVALID_OR_TAMPERED_PROPOSAL")
    source, digest, size, proposal_id = fields
    destination = os.fspath(store)
    if not isinstance(destination, str) or not _absolute_components(destination):
        return _report("HELD_INVALID_STAGE_DIRECTORY", proposal_id)

    try:
        dirfd = _open_without_symlinks(destination)
    except OSError:
        return _report("HELD_STAGE_DIRECTORY_UNAVAILABLE", proposal_id)

    try:
        dststat = os.fstat(dirfd)
        if (not stat.S_ISDIR(dststat.st_mode) or dststat.st_uid != os.geteuid()
                or dststat.st_mode & 0o077):
            return _report("HELD_STAGE_DIRECTORY_NOT_PRIVATE", proposal_id)
        try:
            srcfd = _open_without_symlinks(source)
        except OSError:
            return _report("HELD_SOURCE_PATH_UNAVAILABLE_OR_UNSAFE", proposal_id)
        try:
            with os.fdopen(srcfd, "rb", closefd=True) as src:
                before = os.fstat(src.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size != size:
                    return _report("HELD_SOURCE_SIZE_OR_TYPE_MISMATCH", proposal_id)
                if not 0 < size <= MAX_FILE_BYTES:
                    return _report("HELD_SOURCE_SIZE_LIMIT", proposal_id)

                name = digest + ".exe"
                # Re-use an existing valid private snapshot. Never replace it.
                try:
                    os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    if not _snapshot_matches(dirfd, name, digest, size):
                        return _report("HELD_EXISTING_STAGE_CONFLICT", proposal_id)
                    # Even on re-use, ensure the current source still matches
                    # the proposal. Reuse does not silently bypass revalidation.
                    current = hashlib.sha256()
                    total = 0
                    for block in iter(lambda: src.read(CHUNK), b""):
                        total += len(block)
                        if total > size:
                            return _report("HELD_SOURCE_SIZE_MISMATCH", proposal_id)
                        current.update(block)
                    after = os.fstat(src.fileno())
                    if (before.st_dev != after.st_dev or before.st_ino != after.st_ino
                            or before.st_size != after.st_size or before.st_size != total
                            or before.st_mtime_ns != after.st_mtime_ns
                            or before.st_ctime_ns != after.st_ctime_ns):
                        return _report("HELD_SOURCE_CHANGED_DURING_COPY", proposal_id)
                    if not hmac.compare_digest(current.hexdigest(), digest):
                        return _report("HELD_SOURCE_DIGEST_MISMATCH", proposal_id)
                    return _report("SNAPSHOT_STAGED_NOT_RUNNABLE", proposal_id, digest=digest,
                                   staged=destination + "/" + name)

                tmpname = ".incoming-" + secrets.token_hex(16)
                tmpfd = os.open(
                    tmpname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    | os.O_CLOEXEC, 0o600, dir_fd=dirfd,
                )
                try:
                    with os.fdopen(tmpfd, "wb", closefd=True) as tmp:
                        hashed = hashlib.sha256()
                        total = 0
                        for block in iter(lambda: src.read(CHUNK), b""):
                            total += len(block)
                            if total > size:
                                return _report("HELD_SOURCE_SIZE_MISMATCH", proposal_id)
                            hashed.update(block)
                            tmp.write(block)
                        after = os.fstat(src.fileno())
                        stable = (before.st_dev == after.st_dev and before.st_ino == after.st_ino
                                  and before.st_size == after.st_size == total
                                  and before.st_mtime_ns == after.st_mtime_ns
                                  and before.st_ctime_ns == after.st_ctime_ns)
                        if not stable:
                            return _report("HELD_SOURCE_CHANGED_DURING_COPY", proposal_id)
                        if total != size or not hmac.compare_digest(hashed.hexdigest(), digest):
                            return _report("HELD_SOURCE_DIGEST_MISMATCH", proposal_id)
                        # Read-only to discourage accidental changes, but NOT
                        # immutable: owner can chmod, unlink, or overwrite.
                        os.fchmod(tmp.fileno(), 0o400)
                        tmp.flush()
                        os.fsync(tmp.fileno())

                    try:
                        # Hard link is atomic within the store and does not
                        # overwrite an existing digest-named destination.
                        os.link(tmpname, name, src_dir_fd=dirfd, dst_dir_fd=dirfd,
                                follow_symlinks=False)
                    except FileExistsError:
                        if not _snapshot_matches(dirfd, name, digest, size):
                            return _report("HELD_EXISTING_STAGE_CONFLICT", proposal_id)
                    os.fsync(dirfd)
                    return _report("SNAPSHOT_STAGED_NOT_RUNNABLE", proposal_id, digest=digest,
                                   staged=destination + "/" + name)
                finally:
                    try:
                        os.unlink(tmpname, dir_fd=dirfd)
                    except FileNotFoundError:
                        pass
        except OSError:
            return _report("HELD_SOURCE_OR_COPY_IO_ERROR", proposal_id)
    except OSError:
        return _report("HELD_STAGE_IO_ERROR", proposal_id)
    finally:
        os.close(dirfd)
