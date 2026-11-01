#!/usr/bin/env python3
"""Cross-repository PhiVine producer -> immutable PhiOS consumer contract test.

Only a synthetic 256-byte PE header and inert fake runner bytes are used.
This never executes Wine, the synthetic PE, or an arbitrary input executable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

PHIOS_PIN = "8ce70d2425b1c3b1de08f8e80cc9df65f03f525f"
AUTHORITY_FLAGS = (
    "app_registry_read_or_modified",
    "phios_install_or_launch_called",
    "operator_approval_minted",
    "effect_lease_issued",
    "execution_authorized",
    "windows_binary_executed",
)


def invoke(module: str, arguments: list[str], *, source: Path, cwd: Path,
           expected_exit: int) -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(source.resolve())
    result = subprocess.run(
        [sys.executable, "-m", module, *arguments],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode != expected_exit:
        raise AssertionError(
            f"{module} returned {result.returncode} (expected {expected_exit}), "
            f"stderr excerpt: {result.stderr[-400:]}"
        )
    parsed = json.loads(result.stdout)
    if not isinstance(parsed, dict):
        raise AssertionError("CLI must output a JSON object")
    return parsed


def synthetic_pe() -> bytes:
    header = bytearray(256)
    header[:2] = b"MZ"
    header[0x3C:0x40] = (128).to_bytes(4, "little")
    header[128:132] = b"PE\x00\x00"
    header[132:134] = (0x8664).to_bytes(2, "little")
    return bytes(header)


def review(handoff: dict, *, cwd: Path, phi_os: Path,
           expected_status: str, artifact_present: bool) -> dict:
    path = cwd / "handoff.json"
    path.write_text(json.dumps(handoff), encoding="utf-8")
    consumer = invoke(
        "phios.apps.cli", ["review-phivine", str(path)],
        source=phi_os, cwd=cwd, expected_exit=3,
    )
    if consumer.get("schema") != "phios.phivine_advisory_review.v0.1":
        raise AssertionError("PhiOS reader schema drift")
    if consumer.get("status") != expected_status:
        raise AssertionError(f"Consumer decision drift: {consumer.get('status')}")
    if any(consumer.get(flag) is not False for flag in AUTHORITY_FLAGS):
        raise AssertionError("Consumer issued a prohibited authority flag")
    if len(consumer.get("unmet_execution_gates", [])) != 9:
        raise AssertionError("Consumer dropped an execution gate")
    if artifact_present:
        if consumer.get("artifact", {}).get("name") != "synthetic.exe":
            raise AssertionError("Valid synthetic candidate was not displayed")
    elif consumer.get("artifact") is not None:
        raise AssertionError("Invalid candidate was promoted to visible evidence")
    return consumer


def run(phi_os: Path, receipt: Path) -> None:
    actual_peer_sha = subprocess.check_output(
        ["git", "-C", str(phi_os), "rev-parse", "HEAD"], text=True, timeout=10,
    ).strip()
    if actual_peer_sha != PHIOS_PIN:
        raise AssertionError("PhiOS reader checkout differs from reviewed immutable pin")
    producer = Path(__file__).resolve().parents[1]
    producer_sha = subprocess.check_output(
        ["git", "-C", str(producer), "rev-parse", "HEAD"], text=True, timeout=10,
    ).strip()
    expected_current_sha = os.environ.get("GITHUB_SHA")
    if expected_current_sha and producer_sha != expected_current_sha:
        raise AssertionError("PhiVine producer differs from GitHub Actions checkout SHA")

    with tempfile.TemporaryDirectory(prefix="phivine-peer-test-") as workdir:
        root = Path(workdir)
        source = root / "synthetic.exe"
        source.write_bytes(synthetic_pe())
        if source.stat().st_size != 256:
            raise AssertionError("Synthetic fixture length changed")
        plan = invoke("phivine", ["plan", str(source)],
                      source=producer / "src", cwd=root, expected_exit=0)
        if plan.get("schema") != "phivine.launch_plan.v0.1":
            raise AssertionError("Producer plan schema drift")
        if plan.get("decision", {}).get("execution_authorized") is not False:
            raise AssertionError("Producer wrongly authorized execution")
        proposal = root / "proposal.json"
        proposal.write_text(json.dumps(plan), encoding="utf-8")

        # Mode 1: no stage, no observed runner.
        basic = invoke(
            "phivine", ["phios-handoff", str(proposal)],
            source=producer / "src", cwd=root, expected_exit=3,
        )
        if basic.get("status") != "HELD_PHIOS_BINARY_INTAKE_NOT_IMPLEMENTED":
            raise AssertionError("Producer no longer refuses unimplemented PhiOS intake")
        if basic.get("observations", {}).get("stage_status") != "NOT_REQUESTED":
            raise AssertionError("Unexpected stage execution/observation")
        review(
            basic, cwd=root, phi_os=phi_os,
            expected_status="HELD_NATIVE_WINDOWS_BINARY_INTAKE_UNAVAILABLE",
            artifact_present=True,
        )

        # Mode 2: staged bytes and inert runner ELF-header observation ONLY.
        store = root / "stage"
        store.mkdir(mode=0o700)
        stage = invoke(
            "phivine", ["stage-plan", str(proposal), "--store", str(store)],
            source=producer / "src", cwd=root, expected_exit=0,
        )
        if stage.get("status") != "SNAPSHOT_STAGED_NOT_RUNNABLE":
            raise AssertionError("Producer stage contract drift")
        fake_runner = root / "fake-wine-elf"
        fake_runner.write_bytes(b"\x7fELF" + b"inert-fixture")
        fake_runner.chmod(0o700)
        complete = invoke(
            "phivine",
            ["phios-handoff", str(proposal), "--store", str(store),
             "--runner", str(fake_runner)],
            source=producer / "src", cwd=root, expected_exit=3,
        )
        if complete.get("observations", {}).get("stage_bytes_match_observed") is not True:
            raise AssertionError("Staged synthetic data was not observed")
        if complete.get("observations", {}).get("runner_elf_observed") is not True:
            raise AssertionError("Inert runner header observation did not occur")
        if any(value is not False for value in complete.get("authority", {}).values()):
            raise AssertionError("Producer emitted an authority value")
        validated = review(
            complete, cwd=root, phi_os=phi_os,
            expected_status="HELD_NATIVE_WINDOWS_BINARY_INTAKE_UNAVAILABLE",
            artifact_present=True,
        )

        # An attacker can recalculate an unkeyed ID but NOT create authority.
        forged = json.loads(json.dumps(complete))
        forged["authority"]["execution_authorized"] = True
        body = json.dumps(
            {k: v for k, v in forged.items() if k != "handoff_id"},
            ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        forged["handoff_id"] = "pha-" + hashlib.sha256(body.encode()).hexdigest()[:24]
        denied = review(
            forged, cwd=root, phi_os=phi_os,
            expected_status="HELD_INVALID_OR_UNTRUSTED_PHIVINE_ADVISORY",
            artifact_present=False,
        )
        if validated.get("app_registry_read_or_modified") is not False:
            raise AssertionError("Registry accessed in valid held review")

    report = {
        "schema": "phivine.phios_peer_compatibility.v0.1",
        "current_producer_source_sha": producer_sha,
        "pinned_consumer_source_sha": actual_peer_sha,
        "producer_handoff_exit": 3,
        "consumer_review_exit": 3,
        "basic_handoff_status": basic["status"],
        "full_observation_status": validated["status"],
        "forged_authority_status": denied["status"],
        "synthetic_windows_executable_launched": False,
        "wine_launched": False,
        "phios_install_or_launch_called": False,
        "permission_or_lease_granted": False,
        "sandbox_qualified": False,
        "production_ready": False,
    }
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("PHIVINE_PHIOS_PINNED_PEER_CONTRACT_HELD_PASS")
    print(json.dumps(report, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phios", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    options = parser.parse_args()
    run(options.phios.resolve(strict=True), options.receipt)


if __name__ == "__main__":
    main()
