"""Rung 6 staged snapshot validation: no mutable artifact is made trusted."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from phivine.planner import plan_launch
from phivine.staging import stage_plan
from phivine.stage_verify import verify_stage


def sample_pe():
    raw = bytearray(256)
    raw[:2] = b"MZ"
    raw[0x3c:0x40] = (128).to_bytes(4, "little")
    raw[128:132] = b"PE\x00\x00"
    raw[132:134] = (0x8664).to_bytes(2, "little")
    return bytes(raw)


class StageVerificationTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.exe = self.root / "legacy.exe"
        self.exe.write_bytes(sample_pe())
        self.store = self.root / "private"
        self.store.mkdir(mode=0o700)
        self.plan = plan_launch(self.exe, home=self.root, which=lambda _: "/usr/bin/wine")
        result = stage_plan(self.plan, str(self.store))
        self.assertEqual(result["status"], "SNAPSHOT_STAGED_NOT_RUNNABLE")
        self.snapshot = Path(result["staged_path"])

    def verify(self, *, plan=None, store=None):
        return verify_stage(self.plan if plan is None else plan,
                            str(self.store if store is None else store))

    def test_match_remains_unlaunchable_and_unattested(self):
        report = self.verify()
        self.assertEqual(report["schema"], "phivine.stage_verification.v0.1")
        self.assertEqual(report["status"], "STAGE_MATCHED_NOT_IMMUTABLE_NOT_RUNNABLE")
        self.assertTrue(report["staged_bytes_match_observed"])
        for field in ("immutability_verified", "stable_handle_retained",
                      "runner_attested", "sandbox_verified", "execution_authorized",
                      "effect_lease_present", "windows_execution_attempted"):
            self.assertFalse(report[field], field)

    def test_staged_copy_survives_original_removal(self):
        self.exe.unlink()
        self.assertTrue(self.verify()["staged_bytes_match_observed"])

    def test_same_size_tampering_detected(self):
        self.snapshot.chmod(0o600)
        altered = bytearray(sample_pe())
        altered[-1] ^= 1
        self.snapshot.write_bytes(altered)
        self.snapshot.chmod(0o400)
        self.assertEqual(self.verify()["status"], "HELD_STAGE_HASH_MISMATCH")

    def test_size_change_detected(self):
        self.snapshot.chmod(0o600)
        self.snapshot.write_bytes(sample_pe() + b"x")
        self.snapshot.chmod(0o400)
        self.assertEqual(self.verify()["status"], "HELD_STAGE_SIZE_MISMATCH")

    def test_unsafe_mode_detected(self):
        self.snapshot.chmod(0o600)
        self.assertEqual(self.verify()["status"], "HELD_STAGE_FILE_PERMISSIONS_OR_LINKS")

    def test_hardlink_alias_detected(self):
        alias = self.root / "alias.exe"
        alias.hardlink_to(self.snapshot)
        self.assertEqual(self.verify()["status"], "HELD_STAGE_FILE_PERMISSIONS_OR_LINKS")

    def test_nonprivate_directory_detected(self):
        self.store.chmod(0o755)
        self.assertEqual(self.verify()["status"], "HELD_STAGE_DIRECTORY_NOT_PRIVATE")

    def test_missing_store_detected(self):
        missing = self.root / "missing"
        self.assertEqual(self.verify(store=missing)["status"], "HELD_STAGE_DIRECTORY_UNAVAILABLE")
        self.assertFalse(missing.exists())

    def test_symlinked_stage_file_detected(self):
        original = self.root / "elsewhere.exe"
        self.snapshot.rename(original)
        self.snapshot.symlink_to(original)
        self.assertEqual(self.verify()["status"], "HELD_STAGE_FILE_UNAVAILABLE_OR_UNSAFE")

    def test_symlinked_parent_directory_detected(self):
        link = self.root / "linked"
        link.symlink_to(self.store, target_is_directory=True)
        self.assertEqual(self.verify(store=link)["status"], "HELD_STAGE_DIRECTORY_UNAVAILABLE")

    def test_invalid_stage_directory_detected(self):
        self.assertEqual(self.verify(store=str(self.root) + "/../private")["status"],
                         "HELD_INVALID_STAGE_DIRECTORY")

    def test_forged_permission_detected(self):
        changed = copy.deepcopy(self.plan)
        changed["decision"]["execution_authorized"] = True
        self.assertEqual(self.verify(plan=changed)["status"], "HELD_INVALID_OR_TAMPERED_PROPOSAL")

    def test_read_only_no_subprocess(self):
        before = self.snapshot.read_bytes()
        with patch("subprocess.run", side_effect=AssertionError("spawned subprocess")), \
             patch("subprocess.Popen", side_effect=AssertionError("spawned subprocess")):
            self.assertTrue(self.verify()["staged_bytes_match_observed"])
        self.assertEqual(before, self.snapshot.read_bytes())


if __name__ == "__main__":
    unittest.main()
