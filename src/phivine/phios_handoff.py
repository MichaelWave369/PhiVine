"""Non-authoritative, read-only PhiVine -> PhiOS advisory handoff.

IMPORTANT: This is NOT a PhiOS API client, install record, compatibility
approval, effect lease or launch authorization. It performs local checks only,
and exports a small path-redacted record for *future* native binary intake.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .planner import REQUIRED_GATES
from .revalidate import _validated_fields, revalidate_plan
from .runner_resolve import resolve_runner
from .stage_verify import verify_stage

SCHEMA = "phivine.phios_advisory.v0.1"
PHIOS_BOUNDARY = "HELD_PHIOS_BINARY_INTAKE_NOT_IMPLEMENTED"
MISSING_GATE = "PHIOS_NATIVE_WINDOWS_BINARY_INTAKE_REVIEW_REQUIRED"


def _sha256_id(record: dict[str, object]) -> str:
    canonical = json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    )
    return "pha-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def build_phios_handoff(
    plan: Mapping[str, Any],
    *,
    stage_store: str | Path | None = None,
    runner_path: str | None = None,
) -> dict[str, object]:
    """Build a read-only, path-redacted evidence handoff.

    The optional stage and runner checks are performed live, rather than
    accepting old caller-supplied receipts. Neither a successful observation
    nor a forged proposal ID is a credential for a PhiOS effect.
    """
    fields = _validated_fields(plan)
    if fields is None:
        record: dict[str, object] = {
            "schema": SCHEMA,
            "producer": "phivine",
            "target": "phios",
            "handoff_type": "local_windows_binary_advisory",
            "status": "HELD_INVALID_OR_TAMPERED_PROPOSAL",
            "proposal_id_observed": None,
            "artifact": None,
            "requested_effects": None,
            "observations": {
                "source_status": "NOT_CHECKED_INVALID_PLAN",
                "stage_status": "NOT_CHECKED_INVALID_PLAN",
                "runner_status": "NOT_CHECKED_INVALID_PLAN",
                "source_bytes_match_observed": False,
                "stage_bytes_match_observed": False,
                "runner_elf_observed": False,
            },
            "authority": {
                "phios_native_binary_intake_exists": False,
                "phios_api_called": False,
                "phios_app_registered": False,
                "trusted_origin_attested": False,
                "runtime_attested": False,
                "sandbox_verified": False,
                "install_authorized": False,
                "execution_authorized": False,
                "effect_lease_present": False,
                "windows_execution_attempted": False,
            },
            "required_before_execution": list(REQUIRED_GATES) + [MISSING_GATE],
            "limitations": [
                "This is an unsigned advisory record and cannot grant PhiOS authority.",
                "No Windows executable, Wine runner or shell wrapper is launched.",
                "No source repository intake, installation or trusted broker is invoked.",
            ],
        }
        record["handoff_id"] = _sha256_id(record)
        return record

    _source, digest, size, proposal_id = fields
    artifact = plan["artifact"]
    effects = plan["proposed_effects"]

    source = revalidate_plan(plan)
    stage = (
        verify_stage(plan, stage_store)
        if stage_store is not None
        else {"status": "NOT_REQUESTED", "staged_bytes_match_observed": False}
    )
    runner = (
        resolve_runner(runner_path)
        if runner_path is not None
        else {"status": "NOT_REQUESTED", "resolved_elf_observed": False}
    )
    record = {
        "schema": SCHEMA,
        "producer": "phivine",
        "target": "phios",
        "handoff_type": "local_windows_binary_advisory",
        "status": PHIOS_BOUNDARY,
        "proposal_id_observed": proposal_id,
        "artifact": {
            "name": artifact["name"],
            "sha256_observed": digest,
            "size_bytes_observed": size,
            "format_observed": artifact.get("format_observed"),
            "architecture_observed": artifact.get("architecture_observed"),
        },
        "requested_effects": {
            "runner_family_requested": "wine",
            "network": effects["network"],
            "extra_host_filesystem_access": "not_requested",
        },
        "observations": {
            "source_status": source["status"],
            "stage_status": stage["status"],
            "runner_status": runner["status"],
            "source_bytes_match_observed": source["artifact_match_observed"] is True,
            "stage_bytes_match_observed": stage["staged_bytes_match_observed"] is True,
            "runner_elf_observed": runner["resolved_elf_observed"] is True,
        },
        "authority": {
            "phios_native_binary_intake_exists": False,
            "phios_api_called": False,
            "phios_app_registered": False,
            "trusted_origin_attested": False,
            "runtime_attested": False,
            "sandbox_verified": False,
            "install_authorized": False,
            "execution_authorized": False,
            "effect_lease_present": False,
            "windows_execution_attempted": False,
        },
        "required_before_execution": list(REQUIRED_GATES) + [MISSING_GATE],
        "limitations": [
            "This is an unsigned advisory record and cannot grant PhiOS authority.",
            "Matching source or staged bytes are momentary observations, not immutable pins.",
            "ELF fingerprints and symlink traces do not attest a Wine runtime or its dependencies.",
            "No Windows executable, Wine runner or shell wrapper is launched.",
            "No source repository intake, installation or trusted broker is invoked.",
            "Absolute local paths are intentionally excluded from this handoff.",
        ],
    }
    record["handoff_id"] = _sha256_id(record)
    return record
