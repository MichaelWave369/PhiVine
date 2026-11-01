"""PhiOS handoff tests: evidence may improve, authorization never does."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from phivine.phios_handoff import build_phios_handoff, PHIOS_BOUNDARY, SCHEMA
from phivine.planner import REQUIRED_GATES, plan_launch
from phivine.staging import stage_plan


def pe():
    payload = bytearray(256)
    payload[:2] = b"MZ"
    payload[0x3c:0x40] = (128).to_bytes(4, "little")
    payload[128:132] = b"PE\x00\x00"
    payload[132:134] = (0x8664).to_bytes(2, "little")
    return bytes(payload)


class PhiOSHandoffTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.exe = self.root / "old-app.exe"
        self.exe.write_bytes(pe())
        self.plan = plan_launch(self.exe, home=self.root, which=lambda _: "/usr/bin/wine")
        self.store = self.root / "private"
        self.store.mkdir(mode=0o700)
        r = stage_plan(self.plan, self.store)
        self.assertEqual(r["status"], "SNAPSHOT_STAGED_NOT_RUNNABLE")
        self.snapshot = Path(r["staged_path"])
        self.elf = self.root / "wine-real"
        self.elf.write_bytes(b"\x7fELF" + b"mock")
        self.elf.chmod(0o700)
        self.runner = self.root / "wine"
        self.runner.symlink_to("wine-real")

    def handoff(self, **changes):
        args = {"stage_store": self.store, "runner_path": str(self.runner)}
        args.update(changes)
        return build_phios_handoff(self.plan, **args)

    def test_full_evidence_remains_held(self):
        h = self.handoff()
        self.assertEqual(h["schema"], SCHEMA)
        self.assertEqual(h["status"], PHIOS_BOUNDARY)
        self.assertTrue(h["observations"]["source_bytes_match_observed"])
        self.assertTrue(h["observations"]["stage_bytes_match_observed"])
        self.assertTrue(h["observations"]["runner_elf_observed"])
        self.assertEqual(h["artifact"]["sha256_observed"],
                         self.plan["artifact"]["sha256_observed"])
        self.assertEqual(h["proposal_id_observed"], self.plan["proposal_id"])
        self.assertEqual(h["requested_effects"]["runner_family_requested"], "wine")
        self.assertEqual(h["requested_effects"]["network"], "deny_requested")
        self.assertEqual(h["required_before_execution"][:len(REQUIRED_GATES)],
                         list(REQUIRED_GATES))
        for k, value in h["authority"].items():
            self.assertIs(value, False, k)

    def test_handoff_is_path_redacted(self):
        text = json.dumps(self.handoff())
        self.assertNotIn(str(self.root), text)
        self.assertNotIn(str(self.exe), text)
        self.assertNotIn(str(self.store), text)
        self.assertNotIn(str(self.runner), text)

    def test_deterministic_with_same_evidence(self):
        self.assertEqual(self.handoff(), self.handoff())
        self.assertRegex(self.handoff()["handoff_id"], r"^pha-[0-9a-f]{24}$")

    def test_no_optional_evidence_stays_held(self):
        h = build_phios_handoff(self.plan)
        self.assertEqual(h["observations"]["stage_status"], "NOT_REQUESTED")
        self.assertEqual(h["observations"]["runner_status"], "NOT_REQUESTED")
        self.assertFalse(h["observations"]["stage_bytes_match_observed"])
        self.assertFalse(h["observations"]["runner_elf_observed"])
        self.assertEqual(h["status"], PHIOS_BOUNDARY)

    def test_changed_original_stays_held(self):
        self.exe.write_bytes(pe() + b"x")
        h = self.handoff()
        self.assertFalse(h["observations"]["source_bytes_match_observed"])
        self.assertTrue(h["observations"]["stage_bytes_match_observed"])
        self.assertEqual(h["status"], PHIOS_BOUNDARY)
        self.assertFalse(h["authority"]["execution_authorized"])

    def test_original_missing_stage_still_observed(self):
        self.exe.unlink()
        h = self.handoff()
        self.assertFalse(h["observations"]["source_bytes_match_observed"])
        self.assertTrue(h["observations"]["stage_bytes_match_observed"])
        self.assertEqual(h["status"], PHIOS_BOUNDARY)

    def test_mutated_stage_detected(self):
        self.snapshot.chmod(0o600)
        self.snapshot.write_bytes(b"changed")
        self.snapshot.chmod(0o400)
        h = self.handoff()
        self.assertFalse(h["observations"]["stage_bytes_match_observed"])
        self.assertEqual(h["observations"]["stage_status"], "HELD_STAGE_SIZE_MISMATCH")

    def test_script_wrapper_is_held(self):
        script = self.root / "wine-wrapper"
        script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        script.chmod(0o700)
        h = self.handoff(runner_path=str(script))
        self.assertEqual(h["observations"]["runner_status"], "HELD_SCRIPT_WRAPPER_REVIEW_REQUIRED")
        self.assertFalse(h["observations"]["runner_elf_observed"])

    def test_missing_runner_is_held(self):
        h = self.handoff(runner_path=str(self.root / "missing"))
        self.assertFalse(h["observations"]["runner_elf_observed"])
        self.assertTrue(h["observations"]["runner_status"].startswith("HELD_"))

    def test_invalid_proposal_is_held_without_reading_sources(self):
        h = build_phios_handoff({"schema": "phivine.launch_plan.v0.1"}, stage_store=self.store,
                                runner_path=str(self.elf))
        self.assertEqual(h["status"], "HELD_INVALID_OR_TAMPERED_PROPOSAL")
        self.assertIsNone(h["artifact"])
        for value in h["authority"].values():
            self.assertFalse(value)

    def test_forged_execution_permission_is_rejected(self):
        altered = copy.deepcopy(self.plan)
        altered["decision"]["execution_authorized"] = True
        h = build_phios_handoff(altered, stage_store=self.store,
                                runner_path=str(self.runner))
        self.assertEqual(h["status"], "HELD_INVALID_OR_TAMPERED_PROPOSAL")

    def test_forged_network_request_not_accepted(self):
        altered = copy.deepcopy(self.plan)
        altered["proposed_effects"]["network"] = "allow"
        h = build_phios_handoff(altered)
        self.assertEqual(h["status"], "HELD_INVALID_OR_TAMPERED_PROPOSAL")

    def test_no_subprocess_and_no_store_writes(self):
        before = self.snapshot.stat().st_mtime_ns
        with patch("subprocess.run", side_effect=AssertionError("subprocess")), \
             patch("subprocess.Popen", side_effect=AssertionError("subprocess")):
            h = self.handoff()
        self.assertEqual(h["status"], PHIOS_BOUNDARY)
        self.assertEqual(self.snapshot.stat().st_mtime_ns, before)

    def test_missing_stage_store_does_not_create_it(self):
        missing = self.root / "absent"
        h = self.handoff(stage_store=missing)
        self.assertEqual(h["observations"]["stage_status"], "HELD_STAGE_DIRECTORY_UNAVAILABLE")
        self.assertFalse(missing.exists())

    def test_recomputing_a_checksum_cannot_authenticate_proposal(self):
        altered = copy.deepcopy(self.plan)
        altered["decision"]["human_approved"] = True
        base = {k: v for k, v in altered.items() if k != "proposal_id"}
        import hashlib
        altered["proposal_id"] = ("pv-" + hashlib.sha256(json.dumps(
            base, sort_keys=True, ensure_ascii=True, separators=(",", ":")
        ).encode()).hexdigest()[:24])
        h = build_phios_handoff(altered)
        self.assertEqual(h["status"], "HELD_INVALID_OR_TAMPERED_PROPOSAL")
        self.assertFalse(h["authority"]["execution_authorized"])


if __name__ == "__main__":
    unittest.main()
