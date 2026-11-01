"""Rung 6 Wine path resolution: trace, don't execute or grant authority."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from phivine.runner_resolve import MAX_LINKS, resolve_runner


class RunnerResolutionTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        self.elf = self.root / "wine64-real"
        self.elf.write_bytes(b"\x7fELF" + b"local ELF fixture")
        self.elf.chmod(0o700)

    def test_direct_elf_is_observed_not_attested(self):
        report = resolve_runner(str(self.elf))
        self.assertEqual(report["status"], "RUNNER_RESOLVED_ELF_OBSERVED_NOT_ATTESTED")
        self.assertTrue(report["resolved_elf_observed"])
        self.assertEqual(report["resolved_path_observed"], str(self.elf))
        self.assertEqual(report["symlink_chain_observed"], [])
        for key in ("binary_identity_attested", "version_verified", "signature_verified",
                    "dependencies_verified", "runner_executed", "execution_authorized",
                    "effect_lease_present"):
            self.assertFalse(report[key])

    def test_absolute_symlink_target(self):
        link = self.root / "wine"
        link.symlink_to(self.elf)
        report = resolve_runner(str(link))
        self.assertTrue(report["resolved_elf_observed"])
        self.assertEqual(report["resolved_path_observed"], str(self.elf))
        self.assertEqual(len(report["symlink_chain_observed"]), 1)

    def test_relative_symlink_target(self):
        link = self.root / "wine"
        link.symlink_to("wine64-real")
        report = resolve_runner(str(link))
        self.assertTrue(report["resolved_elf_observed"])
        self.assertEqual(report["resolved_path_observed"], str(self.elf))

    def test_parent_directory_symlink(self):
        real = self.root / "installed"
        real.mkdir()
        target = real / "wine"
        target.write_bytes(b"\x7fELF" + b"runner")
        target.chmod(0o700)
        link = self.root / "current"
        link.symlink_to(real, target_is_directory=True)
        report = resolve_runner(str(link / "wine"))
        self.assertEqual(report["status"], "RUNNER_RESOLVED_ELF_OBSERVED_NOT_ATTESTED")
        self.assertEqual(report["resolved_path_observed"], str(target))

    def test_two_hop_symlink_chain(self):
        middle = self.root / "wine2"
        middle.symlink_to(self.elf)
        first = self.root / "wine"
        first.symlink_to("wine2")
        report = resolve_runner(str(first))
        self.assertTrue(report["resolved_elf_observed"])
        self.assertEqual(len(report["symlink_chain_observed"]), 2)

    def test_shell_wrapper_is_held_but_identified(self):
        wrapper = self.root / "wine-wrapper"
        wrapper.write_text("#!/bin/sh\nexec wine64 \"$@\"\n", encoding="utf-8")
        wrapper.chmod(0o700)
        link = self.root / "wine"
        link.symlink_to(wrapper)
        report = resolve_runner(str(link))
        self.assertEqual(report["status"], "HELD_SCRIPT_WRAPPER_REVIEW_REQUIRED")
        self.assertEqual(report["file_kind_observed"], "script")
        self.assertFalse(report["resolved_elf_observed"])
        self.assertFalse(report["runner_executed"])

    def test_cycle_is_held(self):
        a = self.root / "wine"
        b = self.root / "wine2"
        a.symlink_to("wine2")
        b.symlink_to("wine")
        self.assertEqual(resolve_runner(str(a))["status"], "HELD_SYMLINK_CYCLE")

    def test_excess_hops_is_held(self):
        for i in range(MAX_LINKS + 1):
            link = self.root / f"link{i}"
            link.symlink_to(f"link{i+1}")
        (self.root / f"link{MAX_LINKS+1}").symlink_to(self.elf)
        report = resolve_runner(str(self.root / "link0"))
        self.assertEqual(report["status"], "HELD_SYMLINK_DEPTH_EXCEEDED")
        self.assertFalse(report["resolved_elf_observed"])

    def test_broken_link_is_held(self):
        link = self.root / "wine"
        link.symlink_to("missing")
        self.assertEqual(resolve_runner(str(link))["status"], "HELD_RUNNER_PATH_UNAVAILABLE")

    def test_relative_argument_is_held(self):
        self.assertEqual(resolve_runner("wine")["status"], "HELD_INVALID_RUNNER_PATH")

    def test_nonexecutable_elf_is_held(self):
        self.elf.chmod(0o600)
        self.assertTrue(resolve_runner(str(self.elf))["status"].startswith("HELD_"))

    def test_resolver_does_not_execute_anything(self):
        link = self.root / "wine"
        link.symlink_to(self.elf)
        with patch("subprocess.Popen", side_effect=AssertionError("subprocess")), \
             patch("subprocess.run", side_effect=AssertionError("subprocess")):
            self.assertTrue(resolve_runner(str(link))["resolved_elf_observed"])


if __name__ == "__main__":
    unittest.main()
