"""Exact-file Rung 4 preflight tests: observation never becomes launch."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from phivine.planner import plan_launch
from phivine.revalidate import (
    MAX_PLAN_BYTES, read_plan_json, revalidate_plan, SCHEMA,
)


def example_pe():
    data = bytearray(256)
    data[:2] = b"MZ"
    data[0x3c:0x40] = (128).to_bytes(4, "little")
    data[128:132] = b"PE\x00\x00"
    data[132:134] = (0x8664).to_bytes(2, "little")
    return bytes(data)


class ExactArtifactTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.exe = self.root / "legacy.exe"
        self.exe.write_bytes(example_pe())
        self.plan = plan_launch(self.exe, home=self.root, which=lambda _: "/usr/bin/wine")

    @staticmethod
    def rehash_proposal(plan):
        """Attacker can recalculate a non-authenticating proposal ID."""
        body = {k: v for k, v in plan.items() if k != "proposal_id"}
        canonical = json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        plan["proposal_id"] = "pv-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
        return plan

    def test_matching_artifact_is_still_unlaunchable(self):
        report = revalidate_plan(self.plan)
        self.assertEqual(report["schema"], SCHEMA)
        self.assertEqual(report["status"], "ARTIFACT_MATCHED_STILL_NOT_RUNNABLE")
        self.assertTrue(report["artifact_match_observed"])
        self.assertEqual(report["proposal_id_observed"], self.plan["proposal_id"])
        for key in ("descriptor_retained_for_execution", "sandbox_verified",
                    "runner_attested", "execution_authorized",
                    "effect_lease_present", "windows_execution_attempted"):
            self.assertFalse(report[key], key)

    def test_changed_content_same_size_is_rejected(self):
        data = bytearray(example_pe())
        data[-1] = 11
        self.exe.write_bytes(data)
        report = revalidate_plan(self.plan)
        self.assertEqual(report["status"], "HELD_HASH_MISMATCH")
        self.assertFalse(report["artifact_match_observed"])

    def test_changed_size_is_rejected(self):
        self.exe.write_bytes(example_pe() + b"x")
        self.assertEqual(revalidate_plan(self.plan)["status"], "HELD_SIZE_MISMATCH")

    def test_missing_file_is_held(self):
        self.exe.unlink()
        self.assertEqual(revalidate_plan(self.plan)["status"], "HELD_PATH_UNAVAILABLE_OR_UNSAFE")

    def test_final_symlink_is_held_even_if_digest_would_match(self):
        real = self.root / "real.exe"
        real.write_bytes(example_pe())
        self.exe.unlink()
        self.exe.symlink_to(real)
        self.assertEqual(revalidate_plan(self.plan)["status"], "HELD_PATH_UNAVAILABLE_OR_UNSAFE")

    def test_parent_symlink_is_held(self):
        realdir = self.root / "real"
        realdir.mkdir()
        actual = realdir / "legacy.exe"
        actual.write_bytes(example_pe())
        linkdir = self.root / "alias"
        linkdir.symlink_to(realdir, target_is_directory=True)
        replacement = json.loads(json.dumps(self.plan))
        replacement["artifact"]["path_observed"] = str(linkdir / "legacy.exe")
        replacement["proposed_effects"]["input_file_read"] = str(linkdir / "legacy.exe")
        self.rehash_proposal(replacement)
        self.assertEqual(revalidate_plan(replacement)["status"], "HELD_PATH_UNAVAILABLE_OR_UNSAFE")

    def test_tampered_proposal_is_held(self):
        changed = json.loads(json.dumps(self.plan))
        changed["proposed_effects"]["network"] = "operator_review_requested"
        self.assertEqual(revalidate_plan(changed)["status"], "HELD_INVALID_OR_TAMPERED_PROPOSAL")

    def test_recomputed_checksum_cannot_grant_authority(self):
        changed = json.loads(json.dumps(self.plan))
        changed["decision"]["execution_authorized"] = True
        self.rehash_proposal(changed)
        self.assertEqual(revalidate_plan(changed)["status"], "HELD_INVALID_OR_TAMPERED_PROPOSAL")

    def test_recomputed_checksum_cannot_request_host_filesystem(self):
        changed = json.loads(json.dumps(self.plan))
        changed["proposed_effects"]["extra_host_filesystem_access"] = "all"
        self.rehash_proposal(changed)
        self.assertEqual(revalidate_plan(changed)["status"], "HELD_INVALID_OR_TAMPERED_PROPOSAL")

    def test_recomputed_checksum_cannot_rewrite_effect_input(self):
        changed = json.loads(json.dumps(self.plan))
        changed["proposed_effects"]["input_file_read"] = "/etc/passwd"
        self.rehash_proposal(changed)
        self.assertEqual(revalidate_plan(changed)["status"], "HELD_INVALID_OR_TAMPERED_PROPOSAL")

    def test_traversal_is_rejected_before_file_open(self):
        changed = json.loads(json.dumps(self.plan))
        changed["artifact"]["path_observed"] = str(self.root) + "/../" + self.root.name + "/legacy.exe"
        changed["proposed_effects"]["input_file_read"] = changed["artifact"]["path_observed"]
        self.rehash_proposal(changed)
        self.assertEqual(revalidate_plan(changed)["status"], "HELD_INVALID_OR_TAMPERED_PROPOSAL")

    def test_invalid_json_structures_are_held(self):
        self.assertEqual(revalidate_plan({})["status"], "HELD_INVALID_OR_TAMPERED_PROPOSAL")
        changed = json.loads(json.dumps(self.plan))
        changed["artifact"]["size_bytes_observed"] = True
        self.rehash_proposal(changed)
        self.assertEqual(revalidate_plan(changed)["status"], "HELD_INVALID_OR_TAMPERED_PROPOSAL")

    def test_no_subprocess_or_writes_during_revalidation(self):
        with patch("subprocess.run", side_effect=AssertionError("subprocess called")), \
             patch("subprocess.Popen", side_effect=AssertionError("subprocess called")):
            self.assertTrue(revalidate_plan(self.plan)["artifact_match_observed"])
        self.assertFalse((self.root / ".local").exists())

    def test_bounded_json_reader(self):
        path = self.root / "plan.json"
        path.write_text(json.dumps(self.plan), encoding="utf-8")
        self.assertEqual(read_plan_json(path)["proposal_id"], self.plan["proposal_id"])
        path.write_bytes(b"x" * (MAX_PLAN_BYTES + 1))
        with self.assertRaises(ValueError):
            read_plan_json(path)

    def test_plan_symlink_is_not_accepted(self):
        real = self.root / "plan.json"
        real.write_text(json.dumps(self.plan), encoding="utf-8")
        alias = self.root / "link.json"
        alias.symlink_to(real)
        with self.assertRaises(ValueError):
            read_plan_json(alias)


if __name__ == "__main__":
    unittest.main()
