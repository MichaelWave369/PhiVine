"""Rung 3 qualification unit tests: no untrusted program may be executed."""

import json
import subprocess
import unittest
from unittest.mock import patch

from phivine.sandbox import qualify_fixture_sandbox, SCHEMA

DEFAULT = object()


class SandboxProbeTests(unittest.TestCase):
    def call(self, *, returncode=0, payload=DEFAULT, which=lambda x: "/usr/bin/bwrap"):
        calls = []
        if payload is DEFAULT:
            payload = {"host_canary_visible": False, "sandbox_tmp_writable": True,
                       "host_loopback_reachable": False}

        def fake_run(argv, **kw):
            calls.append((argv, kw))
            return subprocess.CompletedProcess(argv, returncode, stdout=json.dumps(payload), stderr="")

        with patch("phivine.sandbox.Path.is_file", return_value=True):
            result = qualify_fixture_sandbox(which=which, run=fake_run, system=lambda: "Linux")
        return result, calls

    def test_missing_bwrap_is_held(self):
        result = qualify_fixture_sandbox(which=lambda _: None, run=lambda *a, **k: self.fail("executed"), system=lambda: "Linux")
        self.assertEqual(result["status"], "HELD_BWRAP_NOT_FOUND")
        self.assertFalse(result["fixture_boundary_passed"])

    def test_non_linux_is_held(self):
        result = qualify_fixture_sandbox(which=lambda _: "/usr/bin/bwrap", run=lambda *a, **k: self.fail("executed"), system=lambda: "Windows")
        self.assertEqual(result["status"], "HELD_LINUX_REQUIRED")

    def test_fixed_command_and_no_windows_execution(self):
        result, calls = self.call()
        self.assertEqual(result["schema"], SCHEMA)
        self.assertEqual(result["status"], "FIXTURE_BOUNDARY_OBSERVED_NOT_APP_READY")
        self.assertTrue(result["fixture_boundary_passed"])
        self.assertFalse(result["phios_sandbox_attested"])
        self.assertFalse(result["windows_execution_authorized"])
        self.assertFalse(result["wine_invoked"])
        argv, options = calls[0]
        self.assertIn("--unshare-all", argv)
        self.assertIn("--clearenv", argv)
        self.assertIn("--tmpfs", argv)
        self.assertIn("--ro-bind", argv)
        self.assertIn("--die-with-parent", argv)
        self.assertIn("--new-session", argv)
        self.assertEqual(argv[argv.index("--") + 1:][:3], ["/usr/bin/python3", "-I", "-c"])
        self.assertNotIn("wine", argv)
        self.assertTrue(options["capture_output"])
        self.assertLessEqual(options["timeout"], 10)

    def test_no_canary_visibility_allowed(self):
        payload = {"host_canary_visible": True, "sandbox_tmp_writable": True,
                   "host_loopback_reachable": False}
        result, _ = self.call(payload=payload)
        self.assertEqual(result["status"], "HELD_FIXTURE_BOUNDARY_VIOLATION")
        self.assertFalse(result["fixture_boundary_passed"])

    def test_network_isolation_must_be_observed(self):
        payload = {"host_canary_visible": False, "sandbox_tmp_writable": True,
                   "host_loopback_reachable": True}
        result, _ = self.call(payload=payload)
        self.assertEqual(result["status"], "HELD_FIXTURE_BOUNDARY_VIOLATION")

    def test_tmp_must_be_writable_for_fixture(self):
        payload = {"host_canary_visible": False, "sandbox_tmp_writable": False,
                   "host_loopback_reachable": False}
        result, _ = self.call(payload=payload)
        self.assertEqual(result["status"], "HELD_FIXTURE_BOUNDARY_VIOLATION")

    def test_nonzero_bwrap_exit_holds(self):
        result, _ = self.call(returncode=1)
        self.assertEqual(result["status"], "HELD_BWRAP_FIXTURE_FAILED")

    def test_malformed_bwrap_receipt_holds(self):
        result, _ = self.call(payload={"fake": True})
        self.assertEqual(result["status"], "HELD_INVALID_FIXTURE_RECEIPT")

    def test_timeout_holds(self):
        def timeout(argv, **kw):
            raise subprocess.TimeoutExpired(argv, kw["timeout"])
        with patch("phivine.sandbox.Path.is_file", return_value=True):
            result = qualify_fixture_sandbox(which=lambda _: "/usr/bin/bwrap", run=timeout, system=lambda: "Linux")
        self.assertEqual(result["status"], "HELD_FIXTURE_TIMEOUT")

    def test_missing_python_holds(self):
        with patch("phivine.sandbox.Path.is_file", return_value=False):
            result = qualify_fixture_sandbox(which=lambda _: "/usr/bin/bwrap", run=lambda *a, **k: self.fail("executed"), system=lambda: "Linux")
        self.assertEqual(result["status"], "HELD_SYSTEM_PYTHON_NOT_FOUND")

    def test_numeric_or_string_receipt_is_rejected(self):
        for bad in ({"host_canary_visible": False, "sandbox_tmp_writable": 1, "host_loopback_reachable": False},
                    [False, True, False], None):
            result, _ = self.call(payload=bad)
            self.assertEqual(result["status"], "HELD_INVALID_FIXTURE_RECEIPT")


if __name__ == "__main__":
    unittest.main()
