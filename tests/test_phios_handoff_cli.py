"""CLI exercises the output contract, never a PhiOS approval service."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from phivine.cli import main
from phivine.planner import plan_launch
from phivine.staging import stage_plan


def pe():
    d = bytearray(256)
    d[:2] = b"MZ"
    d[0x3c:0x40] = (128).to_bytes(4, "little")
    d[128:132] = b"PE\x00\x00"
    d[132:134] = (0x8664).to_bytes(2, "little")
    return bytes(d)


class PhiOSHandoffCliTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        exe = self.root / "old.exe"
        exe.write_bytes(pe())
        self.store = self.root / "store"
        self.store.mkdir(mode=0o700)
        self.proposal = self.root / "plan.json"
        plan = plan_launch(exe, home=self.root, which=lambda _: "/usr/bin/wine")
        self.proposal.write_text(json.dumps(plan), encoding="utf-8")
        self.assertEqual(stage_plan(plan, self.store)["status"], "SNAPSHOT_STAGED_NOT_RUNNABLE")
        self.elf = self.root / "wine-elf"
        self.elf.write_bytes(b"\x7fELF" + b"mock")
        self.elf.chmod(0o700)

    def invoke(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            exit_code = main(args)
        source = err.getvalue() if exit_code == 2 else out.getvalue()
        return exit_code, json.loads(source)

    def test_complete_evidence_still_exits_3(self):
        code, record = self.invoke([
            "phios-handoff", str(self.proposal), "--store", str(self.store),
            "--runner", str(self.elf),
        ])
        self.assertEqual(code, 3)
        self.assertEqual(record["status"], "HELD_PHIOS_BINARY_INTAKE_NOT_IMPLEMENTED")
        self.assertTrue(record["observations"]["stage_bytes_match_observed"])
        self.assertTrue(record["observations"]["runner_elf_observed"])
        self.assertFalse(record["authority"]["execution_authorized"])
        self.assertNotIn(str(self.root), json.dumps(record))

    def test_plan_only_exits_3(self):
        code, record = self.invoke(["phios-handoff", str(self.proposal)])
        self.assertEqual(code, 3)
        self.assertEqual(record["observations"]["stage_status"], "NOT_REQUESTED")

    def test_invalid_json_exits_2(self):
        self.proposal.write_text("{oops", encoding="utf-8")
        code, record = self.invoke(["phios-handoff", str(self.proposal)])
        self.assertEqual(code, 2)
        self.assertEqual(record["schema"], "phivine.error.v0.1")

    def test_no_subprocess_invocation(self):
        with patch("subprocess.run", side_effect=AssertionError("subprocess")), \
             patch("subprocess.Popen", side_effect=AssertionError("subprocess")):
            code, record = self.invoke([
                "phios-handoff", str(self.proposal), "--store", str(self.store),
                "--runner", str(self.elf),
            ])
        self.assertEqual(code, 3)
        self.assertFalse(record["authority"]["phios_api_called"])


if __name__ == "__main__":
    unittest.main()
