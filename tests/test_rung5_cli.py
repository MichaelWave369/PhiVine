"""CLI contracts for explicit, never-launching Rung 5 workflows."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from phivine.cli import main
from phivine.planner import plan_launch


def pe():
    b = bytearray(256)
    b[:2] = b"MZ"
    b[0x3c:0x40] = (128).to_bytes(4, "little")
    b[128:132] = b"PE\x00\x00"
    b[132:134] = (0x8664).to_bytes(2, "little")
    return bytes(b)


class StageCliTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.exe = self.root / "legacy.exe"
        self.exe.write_bytes(pe())
        self.store = self.root / "private"
        self.store.mkdir(mode=0o700)
        self.planpath = self.root / "proposal.json"
        self.planpath.write_text(json.dumps(plan_launch(self.exe, which=lambda _: "/usr/bin/wine",
                                                     home=self.root)), encoding="utf-8")

    def invoke(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(args)
        return code, json.loads(stdout.getvalue() if code in (0, 3) else stderr.getvalue())

    def test_stage_plan_explicit_directory_succeeds_but_is_not_authority(self):
        code, report = self.invoke(["stage-plan", str(self.planpath), "--store", str(self.store)])
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "SNAPSHOT_STAGED_NOT_RUNNABLE")
        self.assertFalse(report["immutable_storage_verified"])
        self.assertFalse(report["execution_authorized"])

    def test_stage_held_when_directory_not_private(self):
        self.store.chmod(0o755)
        code, report = self.invoke(["stage-plan", str(self.planpath), "--store", str(self.store)])
        self.assertEqual(code, 3)
        self.assertEqual(report["status"], "HELD_STAGE_DIRECTORY_NOT_PRIVATE")

    def test_stage_invalid_json_exits_2(self):
        self.planpath.write_text("{", encoding="utf-8")
        code, report = self.invoke(["stage-plan", str(self.planpath), "--store", str(self.store)])
        self.assertEqual(code, 2)
        self.assertEqual(report["schema"], "phivine.error.v0.1")

    def test_runner_observation_never_executes_binary(self):
        binary = self.root / "wine-elf"
        binary.write_bytes(b"\x7fELF" + b"x" * 100)
        binary.chmod(0o700)
        code, report = self.invoke(["observe-runner", str(binary)])
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "RUNNER_ELF_BYTES_OBSERVED_NOT_ATTESTED")
        self.assertFalse(report["runner_executed"])
        self.assertFalse(report["execution_authorized"])

    def test_script_runner_is_held(self):
        binary = self.root / "wine-script"
        binary.write_text("#!/bin/sh\necho test\n", encoding="utf-8")
        binary.chmod(0o700)
        code, report = self.invoke(["observe-runner", str(binary)])
        self.assertEqual(code, 3)
        self.assertEqual(report["status"], "HELD_RUNNER_NOT_ELF_BINARY")


if __name__ == "__main__":
    unittest.main()
