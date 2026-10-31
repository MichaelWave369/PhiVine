"""Read-only exact-artifact revalidation before any future execution adapter.

A matching result only establishes that a separately opened regular file had
the proposed SHA-256 at read time. No descriptor is retained, no sandbox is
attested, and no execution or operator permission can be inferred.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from .inspector import MAX_FILE_BYTES
from .planner import PLAN_SCHEMA, REQUIRED_GATES

SCHEMA = "phivine.artifact_revalidation.v0.1"
MAX_PLAN_BYTES = 65536
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
CHUNK = 1024 * 1024


def _receipt(status: str, proposal_id: str | None = None, *, matched: bool = False) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "proposal_id_observed": proposal_id,
        "status": status,
        "artifact_match_observed": matched,
        "descriptor_retained_for_execution": False,
        "sandbox_verified": False,
        "runner_attested": False,
        "execution_authorized": False,
        "effect_lease_present": False,
        "windows_execution_attempted": False,
        "note": "One read-only observation, NOT a signature, sandbox attestation, or launch authorization.",
    }


def _validated_fields(plan: Mapping[str, Any]) -> tuple[str, str, int, str] | None:
    """Validate an untrusted proposal's shape and self-consistency.

    The proposal ID is an integrity checksum, not authentication: an attacker
    could recompute it. Never use this function to grant privileges.
    """
    if not isinstance(plan, dict) or len(plan) > 20:
        return None
    pid = plan.get("proposal_id")
    if not isinstance(pid, str) or not re.fullmatch(r"pv-[0-9a-f]{24}", pid):
        return None
    if plan.get("schema") != PLAN_SCHEMA:
        return None
    try:
        base = {k: v for k, v in plan.items() if k != "proposal_id"}
        canonical = json.dumps(base, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        if len(canonical.encode("utf-8")) > MAX_PLAN_BYTES:
            return None
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        return None
    expected_id = "pv-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
    if not hmac.compare_digest(pid, expected_id):
        return None
    a, effect, decision, runner = (
        plan.get("artifact"), plan.get("proposed_effects"),
        plan.get("decision"), plan.get("runner")
    )
    if not all(isinstance(x, dict) for x in (a, effect, decision, runner)):
        return None
    path = a.get("path_observed")
    digest = a.get("sha256_observed")
    size = a.get("size_bytes_observed")
    if not isinstance(path, str) or not path or "\x00" in path or len(path) > 4096:
        return None
    # Reject ambiguous spelling and directory traversal, including any parent
    # symlink while opening. This is deliberately Linux/POSIX-only.
    pieces = path.split("/")
    if not path.startswith("/") or any(x in ("", ".", "..") for x in pieces[1:]):
        return None
    if not path.lower().endswith(".exe") or Path(path).name != a.get("name"):
        return None
    if not isinstance(digest, str) or not DIGEST_PATTERN.fullmatch(digest):
        return None
    if type(size) is not int or size < 1 or size > MAX_FILE_BYTES:
        return None
    if effect.get("input_file_read") != path:
        return None
    if effect.get("network") not in ("deny_requested", "operator_review_requested"):
        return None
    if effect.get("network_enforcement_verified") is not False:
        return None
    if effect.get("extra_host_filesystem_access") != "not_requested":
        return None
    prefix = effect.get("isolated_prefix_write")
    if not isinstance(prefix, str) or Path(prefix).name != digest:
        return None
    if runner.get("family_requested") != "wine":
        return None
    if runner.get("version_verified") is not False or runner.get("binary_identity_verified") is not False:
        return None
    if decision.get("plan_only") is not True or not str(decision.get("status", "")).startswith("HELD_"):
        return None
    for key in ("execution_authorized", "execution_attempted", "installation_attempted",
                "sandbox_verified", "human_approved", "effect_lease_present",
                "eligible_for_direct_execution"):
        if decision.get(key) is not False:
            return None
    if plan.get("required_before_execution") != list(REQUIRED_GATES):
        return None
    return path, digest, size, pid


def _open_without_symlinks(path: str) -> int:
    """Traverse absolute paths with directory FDs and O_NOFOLLOW on POSIX.

    Prevent following symlinks even in parents. This protects the snapshot
    opening only; it does not secure a future executor or stop in-place writes.
    """
    if os.name != "posix" or not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK")):
        raise OSError("unsupported platform")
    parts = path.split("/")[1:]
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            nextfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nextfd
        resultfd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    finally:
        os.close(fd)
    return resultfd


def revalidate_plan(plan: Mapping[str, Any]) -> dict[str, object]:
    fields = _validated_fields(plan)
    if fields is None:
        return _receipt("HELD_INVALID_OR_TAMPERED_PROPOSAL")
    path, expected_sha, expected_size, proposal_id = fields
    try:
        fd = _open_without_symlinks(path)
    except OSError:
        return _receipt("HELD_PATH_UNAVAILABLE_OR_UNSAFE", proposal_id)
    try:
        with os.fdopen(fd, "rb", closefd=True) as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                return _receipt("HELD_NOT_REGULAR_FILE", proposal_id)
            if before.st_size != expected_size:
                return _receipt("HELD_SIZE_MISMATCH", proposal_id)
            if before.st_size > MAX_FILE_BYTES:
                return _receipt("HELD_SIZE_LIMIT", proposal_id)
            hashed = hashlib.sha256()
            total = 0
            while True:
                block = handle.read(CHUNK)
                if not block:
                    break
                total += len(block)
                if total > MAX_FILE_BYTES:
                    return _receipt("HELD_SIZE_LIMIT", proposal_id)
                hashed.update(block)
            after = os.fstat(handle.fileno())
            stable = (
                before.st_dev == after.st_dev
                and before.st_ino == after.st_ino
                and before.st_size == after.st_size == total
                and before.st_mtime_ns == after.st_mtime_ns
                and before.st_ctime_ns == after.st_ctime_ns
            )
            if not stable:
                return _receipt("HELD_FILE_CHANGED_DURING_READ", proposal_id)
            if total != expected_size:
                return _receipt("HELD_SIZE_MISMATCH", proposal_id)
            if not hmac.compare_digest(hashed.hexdigest(), expected_sha):
                return _receipt("HELD_HASH_MISMATCH", proposal_id)
    except OSError:
        return _receipt("HELD_READ_FAILED", proposal_id)
    # Intentionally close the only FD before returning: execution remains
    # impossible via this API and another open would require revalidation.
    return _receipt("ARTIFACT_MATCHED_STILL_NOT_RUNNABLE", proposal_id, matched=True)


def read_plan_json(path: str | Path) -> dict[str, Any]:
    """Read bounded local JSON; no network and no external process."""
    target = Path(path).expanduser()
    if target.is_symlink() or not target.is_file():
        raise ValueError("plan must be a local regular JSON file, not a symlink")
    if target.stat().st_size > MAX_PLAN_BYTES:
        raise ValueError("plan JSON exceeds 64 KiB")
    with target.open("rb") as handle:
        data = handle.read(MAX_PLAN_BYTES + 1)
    if len(data) > MAX_PLAN_BYTES:
        raise ValueError("plan JSON exceeds 64 KiB")
    try:
        parsed = json.loads(data)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError("invalid JSON plan") from exc
    if not isinstance(parsed, dict):
        raise ValueError("plan must be a JSON object")
    return parsed
