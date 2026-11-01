"""Rung 6 CLI: exit semantics reflect observation, never execution rights."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from phivine.cli import main
from phivine.planner import plan_launch
from phivine.staging import stage_plan


def pe():
    body = bytearray(256)
    body[:2] = b"MZ"
    body[0x3c:0x40] = (128).to_bytes(4, "little")
    body[128:132] = b"PE\x00\x00"
    body[132:134] = (0x8664).to_bytes(2, "little")
    return bytes(body)


class Rung6CliTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        exe = self.root / "old.exe"
        exe.write_bytes(pe())
        self.store = self.root / "store"
        self.store.mkdir(mode=0o700)
        self.proposal = self.root / "plan.json"
        plan = plan_launch(exe, home=self.root, which=lambda _: "/bin/wine")
        self.proposal.write_text(json.dumps(plan), encoding="utf-8")
        staged = stage_plan(plan, str(self.store))
        self.assertEqual(staged["status"], "SNAPSHOT_STAGED_NOT_RUNNABLE")
        self.staged = Path(staged["staged_path"])
        self.elf = self.root / "wine-elf"
        self.elf.write_bytes(b"\x7fELF" + b"mock binary")
        self.elf.chmod(0o700)
        self.link = self.root / "wine"
        self.link.symlink_to(self.elf)

    def call(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(args)
        return code, json.loads(out.getvalue() if code in (0, 3) else err.getvalue())

    def test_verify_stage_matching_bytes_not_authorization(self):
        code, payload = self.call(["verify-stage", str(self.proposal), "--store", str(self.store)])
        self.assertEqual(code, 0)
        self.assertTrue(payload["staged_bytes_match_observed"])
        self.assertFalse(payload["immutability_verified"])
        self.assertFalse(payload["execution_authorized"])

    def test_verify_stage_tamper_held_exit_3(self):
        self.staged.chmod(0o600)
        self.staged.write_bytes(b"different!")
        code, payload = self.call(["verify-stage", str(self.proposal), "--store", str(self.store)])
        self.assertEqual(code, 3)
        self.assertTrue(payload["status"].startswith("HELD_"))

    def test_verify_stage_invalid_plan_exit_2(self):
        self.proposal.write_text("invalid JSON", encoding="utf-8")
        code, payload = self.call(["verify-stage", str(self.proposal), "--store", str(self.store)])
        self.assertEqual(code, 2)
        self.assertEqual(payload["schema"], "phivine.error.v0.1")

    def test_resolve_runner_symlink_observed(self):
        code, payload = self.call(["resolve-runner", str(self.link)])
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "RUNNER_RESOLVED_ELF_OBSERVED_NOT_ATTESTED")
        self.assertFalse(payload["runner_executed"])
        self.assertFalse(payload["execution_authorized"])

    def test_resolve_runner_script_held_exit_3(self):
        script = self.root / "wrapper"
        script.write_text("#!/bin/sh\necho abc\n", encoding="utf-8")
        script.chmod(0o700)
        code, payload = self.call(["resolve-runner", str(script)])
        self.assertEqual(code, 3)
        self.assertEqual(payload["status"], "HELD_SCRIPT_WRAPPER_REVIEW_REQUIRED")


if __name__ == "__main__":
    unittest.main()
