"""Rung 4 CLI: successful evidence is never an executable grant."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from phivine.cli import main
from phivine.planner import plan_launch


def pe():
    data = bytearray(256)
    data[:2] = b"MZ"
    data[0x3c:0x40] = (128).to_bytes(4, "little")
    data[128:132] = b"PE\x00\x00"
    data[132:134] = (0x8664).to_bytes(2, "little")
    return bytes(data)


class VerifyCliTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.exe = self.root / "legacy.exe"
        self.exe.write_bytes(pe())
        self.plan = self.root / "plan.json"
        self.plan.write_text(json.dumps(plan_launch(self.exe, which=lambda _: "/bin/wine", home=self.root)))

    def invoke(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["verify-plan", str(self.plan)])
        stream = stdout.getvalue() if code in (0, 3) else stderr.getvalue()
        return code, json.loads(stream)

    def test_match_observed_not_runnable(self):
        code, report = self.invoke()
        self.assertEqual(code, 0)
        self.assertTrue(report["artifact_match_observed"])
        self.assertFalse(report["execution_authorized"])

    def test_changed_file_exits_3(self):
        self.exe.write_bytes(pe() + b"x")
        code, report = self.invoke()
        self.assertEqual(code, 3)
        self.assertEqual(report["status"], "HELD_SIZE_MISMATCH")

    def test_malformed_plan_input_exits_2(self):
        self.plan.write_text("not json", encoding="utf-8")
        code, report = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(report["schema"], "phivine.error.v0.1")


if __name__ == "__main__":
    unittest.main()
