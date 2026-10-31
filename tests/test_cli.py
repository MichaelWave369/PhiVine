import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from phivine.cli import main


def pe():
    data = bytearray(256)
    data[:2] = b"MZ"
    data[0x3c:0x40] = (128).to_bytes(4, "little")
    data[128:132] = b"PE\x00\x00"
    data[132:134] = (0x8664).to_bytes(2, "little")
    return bytes(data)


class CliTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.file = Path(t.name) / "example.exe"
        self.file.write_bytes(pe())

    def invoke(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(argv)
        return code, json.loads(stdout.getvalue() if code == 0 else stderr.getvalue())

    def test_inspect_remains_supported(self):
        code, report = self.invoke(["inspect", str(self.file)])
        self.assertEqual(code, 0)
        self.assertEqual(report["schema"], "phivine.inspection.v0.1")
        self.assertFalse(report["execution_attempted"])

    def test_plan_held_without_network(self):
        code, report = self.invoke(["plan", str(self.file)])
        self.assertEqual(code, 0)
        self.assertEqual(report["schema"], "phivine.launch_plan.v0.1")
        self.assertEqual(report["proposed_effects"]["network"], "deny_requested")
        self.assertFalse(report["decision"]["eligible_for_direct_execution"])

    def test_network_flag_is_request_only(self):
        code, report = self.invoke(["plan", str(self.file), "--request-network"])
        self.assertEqual(code, 0)
        self.assertEqual(report["proposed_effects"]["network"], "operator_review_requested")
        self.assertFalse(report["decision"]["human_approved"])

    def test_error_is_structured(self):
        code, report = self.invoke(["plan", str(self.file) + ".missing"])
        self.assertEqual(code, 2)
        self.assertEqual(report["schema"], "phivine.error.v0.1")


if __name__ == "__main__":
    unittest.main()
