"""Ensure a sandbox-check HELD result never exits successfully."""

import contextlib
import io
import json
import unittest
from unittest.mock import patch

from phivine.cli import main


class SandboxCliTests(unittest.TestCase):
    def invoke(self, report):
        output = io.StringIO()
        with patch("phivine.cli.qualify_fixture_sandbox", return_value=report), contextlib.redirect_stdout(output):
            status = main(["sandbox-check"])
        return status, json.loads(output.getvalue())

    def test_held_exits_3(self):
        status, payload = self.invoke({"fixture_boundary_passed": False, "status": "HELD_BWRAP_NOT_FOUND"})
        self.assertEqual(status, 3)
        self.assertEqual(payload["status"], "HELD_BWRAP_NOT_FOUND")

    def test_fixture_pass_exits_zero_without_grant(self):
        status, payload = self.invoke({"fixture_boundary_passed": True, "windows_execution_authorized": False})
        self.assertEqual(status, 0)
        self.assertFalse(payload["windows_execution_authorized"])


if __name__ == "__main__":
    unittest.main()
