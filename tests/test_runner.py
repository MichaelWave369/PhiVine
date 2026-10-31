"""Rung 5 runner fingerprints: local bytes only, never execution."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from phivine.runner import observe_runner


class RunnerObservationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.runner = self.root / "wine"
        self.runner.write_bytes(b"\x7fELF" + b"test runner fixture")
        self.runner.chmod(0o700)

    def test_elf_fingerprint_is_not_attestation(self):
        r = observe_runner(self.runner)
        self.assertEqual(r["status"], "RUNNER_ELF_BYTES_OBSERVED_NOT_ATTESTED")
        self.assertTrue(r["binary_identity_observed"])
        self.assertEqual(len(r["sha256_observed"]), 64)
        self.assertFalse(r["binary_identity_attested"])
        self.assertFalse(r["version_verified"])
        self.assertFalse(r["signature_verified"])
        self.assertFalse(r["dependencies_verified"])
        self.assertFalse(r["runner_executed"])
        self.assertFalse(r["execution_authorized"])
        self.assertFalse(r["effect_lease_present"])

    def test_script_wrapper_not_promoted_as_verified_binary(self):
        self.runner.write_text("#!/bin/sh\necho version\n", encoding="utf-8")
        self.assertEqual(observe_runner(self.runner)["status"], "HELD_RUNNER_NOT_ELF_BINARY")

    def test_non_executable_file_held(self):
        self.runner.chmod(0o600)
        self.assertEqual(observe_runner(self.runner)["status"], "HELD_RUNNER_NOT_EXECUTABLE")

    def test_symlink_runner_is_held(self):
        alias = self.root / "wine-link"
        alias.symlink_to(self.runner)
        self.assertEqual(observe_runner(alias)["status"], "HELD_RUNNER_PATH_UNAVAILABLE_OR_UNSAFE")

    def test_parent_symlink_runner_is_held(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(observe_runner(alias / "wine")["status"], "HELD_RUNNER_PATH_UNAVAILABLE_OR_UNSAFE")

    def test_nonexistent_runner_is_held(self):
        self.assertEqual(observe_runner(self.root / "missing")["status"], "HELD_RUNNER_PATH_UNAVAILABLE_OR_UNSAFE")

    def test_relative_path_is_held(self):
        self.assertEqual(observe_runner("wine")["status"], "HELD_INVALID_RUNNER_PATH")

    def test_observation_does_not_run_executable(self):
        with patch("subprocess.run", side_effect=AssertionError("run invoked")), \
             patch("subprocess.Popen", side_effect=AssertionError("Popen invoked")):
            self.assertTrue(observe_runner(self.runner)["binary_identity_observed"])


if __name__ == "__main__":
    unittest.main()
