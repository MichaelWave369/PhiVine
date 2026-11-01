"""Bounded, read-only resolution of local runner symlink chains.

This discovers a path and fingerprints observed bytes, never runs Wine, scripts,
or --version. A resolved path is NOT a safe or authenticated launch target.
"""

from __future__ import annotations

import os
import posixpath
import stat

from .runner import observe_runner
from .staging import _absolute_components

SCHEMA = "phivine.runner_resolution.v0.1"
MAX_LINKS = 12


def _report(status: str, original: str, resolved: str | None = None, *,
            links: list[dict[str, str]] | None = None,
            observed: dict[str, object] | None = None) -> dict[str, object]:
    evidence = observed or {}
    return {
        "schema": SCHEMA,
        "status": status,
        "requested_path": original,
        "resolved_path_observed": resolved,
        "symlink_chain_observed": links or [],
        "resolved_elf_observed": status == "RUNNER_RESOLVED_ELF_OBSERVED_NOT_ATTESTED",
        "runner_observation_status": evidence.get("status"),
        "sha256_observed": evidence.get("sha256_observed"),
        "file_kind_observed": evidence.get("file_kind_observed"),
        "binary_identity_attested": False,
        "version_verified": False,
        "signature_verified": False,
        "dependencies_verified": False,
        "runner_executed": False,
        "execution_authorized": False,
        "effect_lease_present": False,
        "note": "Symlink traversal is observational and raceable. No wrapper/script is executed.",
    }


def _first_symlink(path: str) -> str | None:
    """Find the first symlink in an absolute lexical path, without following parents."""
    prefix = ""
    for component in path.split("/")[1:]:
        prefix += "/" + component
        mode = os.lstat(prefix).st_mode
        if stat.S_ISLNK(mode):
            return prefix
        if prefix != path and not stat.S_ISDIR(mode):
            raise OSError("non-directory component")
    return None


def resolve_runner(path: str) -> dict[str, object]:
    """Observe up to 12 symlink hops, then fingerprint a non-symlink candidate.

    Real Wine installations may expose a symlink to an ELF binary or script.
    Scripts are explicitly HELD for human review, rather than interpreted.
    """
    if not isinstance(path, str) or not _absolute_components(path):
        return _report("HELD_INVALID_RUNNER_PATH", str(path))
    origin = path
    current = path
    seen: set[str] = set()
    trace: list[dict[str, str]] = []
    for _ in range(MAX_LINKS + 1):
        if current in seen:
            return _report("HELD_SYMLINK_CYCLE", origin, current, links=trace)
        seen.add(current)
        try:
            link = _first_symlink(current)
        except OSError:
            return _report("HELD_RUNNER_PATH_UNAVAILABLE", origin, current, links=trace)
        if link is None:
            # Observe the fully lexical, no-follow path *again* through
            # descriptor-relative opens. This does not establish TOCTOU safety.
            candidate = observe_runner(current)
            if candidate["status"] == "RUNNER_ELF_BYTES_OBSERVED_NOT_ATTESTED":
                status = "RUNNER_RESOLVED_ELF_OBSERVED_NOT_ATTESTED"
            elif candidate["file_kind_observed"] == "script":
                status = "HELD_SCRIPT_WRAPPER_REVIEW_REQUIRED"
            else:
                status = "HELD_RUNNER_OBSERVATION_" + str(candidate["status"])
            return _report(status, origin, current, links=trace, observed=candidate)
        if len(trace) >= MAX_LINKS:
            return _report("HELD_SYMLINK_DEPTH_EXCEEDED", origin, current, links=trace)
        try:
            raw_target = os.readlink(link)
        except OSError:
            return _report("HELD_SYMLINK_READ_FAILED", origin, current, links=trace)
        suffix = current[len(link):]
        candidate_path = (
            raw_target if raw_target.startswith("/")
            else posixpath.join(posixpath.dirname(link), raw_target)
        )
        next_path = posixpath.normpath(candidate_path + suffix)
        if not _absolute_components(next_path):
            return _report("HELD_INVALID_LINK_TARGET", origin, current, links=trace)
        trace.append({"link": link, "target_observed": raw_target})
        current = next_path
    return _report("HELD_SYMLINK_DEPTH_EXCEEDED", origin, current, links=trace)
