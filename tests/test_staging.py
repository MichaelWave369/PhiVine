"""Rung 5: content-addressed snapshots remain unlaunchable, never overwrite."""
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from phivine.planner import plan_launch
from phivine.staging import stage_plan


def synthetic_pe():
    b = bytearray(256)
    b[:2] = b"MZ"
    b[0x3c:0x40] = (128).to_bytes(4, "little")
    b[128:132] = b"PE\x00\x00"
    b[132:134] = (0x8664).to_bytes(2, "little")
    return bytes(b)


class StagingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source = self.root / "legacy.exe"
        self.source.write_bytes(synthetic_pe())
        self.store = self.root / "private"
        self.store.mkdir(mode=0o700)
        self.plan = plan_launch(self.source, which=lambda _: "/usr/bin/wine", home=self.root)

    def stage(self, store=None, plan=None):
        return stage_plan(self.plan if plan is None else plan,
                          str(self.store if store is None else store))

    def test_creates_sha_named_private_snapshot_without_execution(self):
        result = self.stage()
        self.assertEqual(result["status"], "SNAPSHOT_STAGED_NOT_RUNNABLE")
        self.assertTrue(result["content_snapshot_created_or_reused"])
        self.assertFalse(result["immutable_storage_verified"])
        self.assertFalse(result["sandbox_verified"])
        self.assertFalse(result["runner_attested"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["effect_lease_present"])
        self.assertFalse(result["windows_execution_attempted"])
        staged = Path(result["staged_path"])
        self.assertEqual(staged.name, self.plan["artifact"]["sha256_observed"] + ".exe")
        self.assertEqual(staged.read_bytes(), synthetic_pe())
        self.assertEqual(staged.stat().st_mode & 0o777, 0o400)
        self.assertFalse(list(self.store.glob(".incoming-*")))

    def test_idempotent_existing_snapshot_is_not_replaced(self):
        result = self.stage()
        staged = Path(result["staged_path"])
        ino = staged.stat().st_ino
        again = self.stage()
        self.assertEqual(again["status"], "SNAPSHOT_STAGED_NOT_RUNNABLE")
        self.assertEqual(staged.stat().st_ino, ino)

    def test_changed_source_same_size_is_held(self):
        modified = bytearray(synthetic_pe())
        modified[-1] ^= 1
        self.source.write_bytes(modified)
        result = self.stage()
        self.assertEqual(result["status"], "HELD_SOURCE_DIGEST_MISMATCH")
        self.assertFalse(list(self.store.glob("*.exe")))
        self.assertFalse(list(self.store.glob(".incoming-*")))

    def test_source_with_wrong_size_is_held(self):
        self.source.write_bytes(synthetic_pe() + b"X")
        self.assertEqual(self.stage()["status"], "HELD_SOURCE_SIZE_OR_TYPE_MISMATCH")

    def test_private_directory_required(self):
        self.store.chmod(0o755)
        self.assertEqual(self.stage()["status"], "HELD_STAGE_DIRECTORY_NOT_PRIVATE")

    def test_destination_symlink_is_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.store, target_is_directory=True)
        self.assertEqual(self.stage(store=alias)["status"], "HELD_STAGE_DIRECTORY_UNAVAILABLE")

    def test_source_symlink_is_rejected(self):
        actual = self.root / "real.exe"
        actual.write_bytes(synthetic_pe())
        self.source.unlink()
        self.source.symlink_to(actual)
        self.assertEqual(self.stage()["status"], "HELD_SOURCE_PATH_UNAVAILABLE_OR_UNSAFE")

    def test_existing_conflicting_snapshot_must_not_be_overwritten(self):
        collision = self.store / (self.plan["artifact"]["sha256_observed"] + ".exe")
        collision.write_bytes(b"attacker" + b"X" * 249)
        before = collision.read_bytes()
        self.assertEqual(self.stage()["status"], "HELD_EXISTING_STAGE_CONFLICT")
        self.assertEqual(collision.read_bytes(), before)

    def test_existing_symlink_is_not_followed(self):
        outside = self.root / "outside.exe"
        outside.write_bytes(synthetic_pe())
        collision = self.store / (self.plan["artifact"]["sha256_observed"] + ".exe")
        collision.symlink_to(outside)
        self.assertEqual(self.stage()["status"], "HELD_EXISTING_STAGE_CONFLICT")
        self.assertEqual(outside.read_bytes(), synthetic_pe())

    def test_forged_approval_is_held(self):
        altered = copy.deepcopy(self.plan)
        altered["decision"]["execution_authorized"] = True
        self.assertEqual(self.stage(plan=altered)["status"], "HELD_INVALID_OR_TAMPERED_PROPOSAL")

    def test_missing_store_is_held_without_auto_creation(self):
        absent = self.root / "does-not-exist"
        self.assertEqual(self.stage(store=absent)["status"], "HELD_STAGE_DIRECTORY_UNAVAILABLE")
        self.assertFalse(absent.exists())

    def test_store_with_traversal_is_held(self):
        self.assertEqual(
            self.stage(store=str(self.root) + "/./private")["status"],
            "HELD_INVALID_STAGE_DIRECTORY",
        )

    def test_staging_uses_no_subprocess(self):
        with patch("subprocess.Popen", side_effect=AssertionError("subprocess invoked")), \
             patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            self.assertEqual(self.stage()["status"], "SNAPSHOT_STAGED_NOT_RUNNABLE")


if __name__ == "__main__":
    unittest.main()
