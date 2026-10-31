"""Contract tests for Rung 2's deliberately inert launch planner."""

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from phivine.inspector import InspectionError
from phivine.planner import REQUIRED_GATES, PLAN_SCHEMA, plan_launch


def pe(machine=0x8664):
    payload = bytearray(256)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (128).to_bytes(4, "little")
    payload[128:132] = b"PE\x00\x00"
    payload[132:134] = machine.to_bytes(2, "little")
    return bytes(payload)


class GovernedPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exe = self.root / "old-tool.exe"
        self.exe.write_bytes(pe())

    def build(self, *, available=True, request_network=False):
        return plan_launch(
            self.exe,
            which=lambda name: "/usr/bin/wine" if available and name == "wine" else None,
            home=self.root,
            request_network=request_network,
        )

    def test_plan_stays_held_even_if_wine_observed(self):
        p = self.build()
        self.assertEqual(p["schema"], PLAN_SCHEMA)
        self.assertEqual(p["decision"]["status"], "HELD_NO_VERIFIED_EXECUTION_BOUNDARY")
        self.assertEqual(p["inspection_status"], "REVIEW_REQUIRED")
        self.assertEqual(p["runner"]["family_requested"], "wine")
        self.assertTrue(p["runner"]["command_observed_on_path"])
        self.assertFalse(p["runner"]["version_verified"])
        self.assertFalse(p["runner"]["binary_identity_verified"])
        for field in ("execution_authorized", "execution_attempted", "installation_attempted",
                      "sandbox_verified", "human_approved", "effect_lease_present",
                      "eligible_for_direct_execution"):
            self.assertFalse(p["decision"][field], field)
        self.assertEqual(p["proposed_effects"]["network"], "deny_requested")
        self.assertEqual(p["artifact"]["sha256_observed"], hashlib.sha256(pe()).hexdigest())
        self.assertEqual(p["artifact"]["size_bytes_observed"], len(pe()))
        self.assertEqual(set(p["required_before_execution"]), set(REQUIRED_GATES))

    def test_network_request_is_not_permission(self):
        p = self.build(request_network=True)
        self.assertEqual(p["proposed_effects"]["network"], "operator_review_requested")
        self.assertFalse(p["proposed_effects"]["network_enforcement_verified"])
        self.assertFalse(p["decision"]["execution_authorized"])
        self.assertFalse(p["decision"]["eligible_for_direct_execution"])

    def test_missing_runner_retains_inspection_blocker(self):
        p = self.build(available=False)
        self.assertEqual(p["inspection_status"], "HELD_RUNTIME_MISSING")
        self.assertEqual(p["decision"]["status"], "HELD_INSPECTION_HELD_RUNTIME_MISSING")
        self.assertFalse(p["runner"]["command_observed_on_path"])

    def test_msi_candidate_cannot_become_launchable(self):
        pth = self.root / "installer.msi"
        pth.write_bytes(bytes.fromhex("D0CF11E0A1B11AE1") + b"stub")
        p = plan_launch(pth, which=lambda _: "/usr/bin/wine", home=self.root)
        self.assertEqual(p["inspection_status"], "HELD_MSI_REVIEW_REQUIRED")
        self.assertFalse(p["decision"]["eligible_for_direct_execution"])

    def test_unknown_extension_is_held(self):
        pth = self.root / "fake.dll"
        pth.write_bytes(pe())
        p = plan_launch(pth, which=lambda _: "/usr/bin/wine", home=self.root)
        self.assertEqual(p["inspection_status"], "HELD_UNSUPPORTED_EXTENSION")
        self.assertFalse(p["decision"]["eligible_for_direct_execution"])

    def test_proposal_id_is_deterministic_and_changes_when_artifact_changes(self):
        a = self.build()
        b = self.build()
        self.assertEqual(a, b)
        self.exe.write_bytes(pe(0x14c))
        c = self.build()
        self.assertNotEqual(a["proposal_id"], c["proposal_id"])
        self.assertNotEqual(a["artifact"]["sha256_observed"], c["artifact"]["sha256_observed"])
        self.assertEqual(c["artifact"]["architecture_observed"], "x86")

    def test_network_request_changes_proposal_id(self):
        self.assertNotEqual(self.build()["proposal_id"], self.build(request_network=True)["proposal_id"])

    def test_does_not_create_prefix_or_launch_subprocess(self):
        with patch("subprocess.Popen", side_effect=AssertionError("subprocess invoked")), \
             patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            p = self.build()
        self.assertFalse(Path(p["proposed_effects"]["isolated_prefix_write"]).exists())

    def test_symlink_rejected(self):
        symlink = self.root / "link.exe"
        symlink.symlink_to(self.exe)
        with self.assertRaises(InspectionError):
            plan_launch(symlink, which=lambda _: None, home=self.root)

    def test_boolean_network_flag_required(self):
        with self.assertRaises(ValueError):
            plan_launch(self.exe, request_network="yes", which=lambda _: None, home=self.root)


if __name__ == "__main__":
    unittest.main()
