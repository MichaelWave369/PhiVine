"""Deterministic, advisory-only launch proposals for future PhiOS integration.

No execution, installation, prefix creation, runtime invocation, or sandboxing
is performed. A plan is *not* an approval, permission token, or launch command.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable

from .inspector import inspect_file

PLAN_SCHEMA = "phivine.launch_plan.v0.1"
REQUIRED_GATES = (
    "EXACT_ARTIFACT_HASH_REVALIDATION",
    "RUNNER_BINARY_IDENTITY_AND_VERSION_ATTESTATION",
    "VERIFIED_LINUX_SANDBOX_AND_IDENTITY_BOUNDARY",
    "FILESYSTEM_AND_NETWORK_EFFECT_ENFORCEMENT",
    "EXPLICIT_HUMAN_OPERATOR_AUTHORIZATION",
    "SINGLE_USE_EFFECT_BOUND_LAUNCH_LEASE",
    "PROCESS_LIFECYCLE_AND_TERMINATION_CONTROLS",
    "INDEPENDENT_POST_EFFECT_VERIFICATION_AND_RECEIPTS",
)


def plan_launch(
    input_path: str | Path,
    *,
    request_network: bool = False,
    which: Callable[[str], str | None] | None = None,
    home: str | Path | None = None,
) -> dict[str, object]:
    """Describe a *potential* Wine launch without performing any effect.

    The evidence snapshot is bound to SHA-256, but the file is not held open
    and a future executor MUST independently revalidate the exact bytes.
    'home' and 'which' are injectable for deterministic tests.
    """
    if type(request_network) is not bool:
        raise ValueError("request_network must be a boolean")
    inspected = inspect_file(input_path, which=which)
    source_path = Path(input_path).expanduser().absolute()
    home_path = Path(home).expanduser().absolute() if home is not None else Path.home().absolute()
    prefix_path = home_path / ".local" / "share" / "phivine" / "prefixes" / str(inspected["sha256"])

    inspection_status = str(inspected["status"])
    runner_detected = "wine" in inspected["observed_runners"]
    primary_blocker = (
        "HELD_NO_VERIFIED_EXECUTION_BOUNDARY"
        if inspection_status == "REVIEW_REQUIRED"
        else f"HELD_INSPECTION_{inspection_status}"
    )
    base: dict[str, object] = {
        "schema": PLAN_SCHEMA,
        "inspection_schema": inspected["schema"],
        "inspection_status": inspection_status,
        "artifact": {
            "path_observed": str(source_path),
            "name": inspected["name"],
            "sha256_observed": inspected["sha256"],
            "size_bytes_observed": inspected["size_bytes"],
            "format_observed": inspected["observed_format"],
            "architecture_observed": inspected["architecture"],
        },
        "runner": {
            "family_requested": "wine",
            "command_observed_on_path": runner_detected,
            "version_verified": False,
            "binary_identity_verified": False,
        },
        "proposed_effects": {
            "input_file_read": str(source_path),
            "isolated_prefix_write": str(prefix_path),
            "extra_host_filesystem_access": "not_requested",
            "network": "operator_review_requested" if request_network else "deny_requested",
            "network_enforcement_verified": False,
        },
        "decision": {
            "status": primary_blocker,
            "plan_only": True,
            "execution_authorized": False,
            "execution_attempted": False,
            "installation_attempted": False,
            "sandbox_verified": False,
            "human_approved": False,
            "effect_lease_present": False,
            "eligible_for_direct_execution": False,
        },
        "required_before_execution": list(REQUIRED_GATES),
        "limitations": [
            "No executable is run or checked for trustworthiness or malware.",
            "A discovered runner does not mean that runner works or is safe.",
            "Requested access is not granted, enforced, or sandboxed.",
            "Proposed paths are not reserved or protected from symlink/race attacks.",
            "The file may change after inspection; an executor must rehash pinned bytes.",
            "No integration with PhiOS permission or app execution APIs exists yet.",
        ],
    }
    canonical = json.dumps(base, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    base["proposal_id"] = "pv-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
    return base
