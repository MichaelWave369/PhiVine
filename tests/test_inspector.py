import hashlib
from pathlib import Path
import tempfile
import unittest

from phivine.inspector import InspectionError, inspect_file


def pe_bytes(machine=0x8664, *, valid=True):
    payload = bytearray(256)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (128).to_bytes(4, "little")
    payload[128:132] = b"PE\x00\x00" if valid else b"NOPE"
    payload[132:134] = machine.to_bytes(2, "little")
    return bytes(payload)


class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name, data):
        p = self.root / name
        p.write_bytes(data)
        return p

    def test_valid_pe_requires_review_and_never_grants_execution(self):
        payload = pe_bytes()
        path = self.write("demo.EXE", payload)
        result = inspect_file(path, which=lambda cmd: "/bin/wine" if cmd == "wine" else None)
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(result["architecture"], "x86_64")
        self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(result["observed_runners"], ["wine"])
        for flag in ("execution_authorized", "execution_attempted", "network_probed", "sandbox_verified"):
            self.assertFalse(result[flag])

    def test_missing_wine_holds(self):
        report = inspect_file(self.write("demo.exe", pe_bytes(0x014C)), which=lambda _: None)
        self.assertEqual(report["status"], "HELD_RUNTIME_MISSING")
        self.assertEqual(report["architecture"], "x86")

    def test_malformed_pe_holds_even_with_runner(self):
        report = inspect_file(self.write("bad.exe", pe_bytes(valid=False)), which=lambda _: "/bin/wine")
        self.assertEqual(report["status"], "HELD_MALFORMED_PE")

    def test_arm64_pe_not_claimed_supported(self):
        report = inspect_file(self.write("arm.exe", pe_bytes(0xAA64)), which=lambda _: "/bin/wine")
        self.assertEqual(report["status"], "HELD_UNSUPPORTED_ARCHITECTURE")

    def test_msi_compound_format_not_automatically_accepted(self):
        payload = bytes.fromhex("D0CF11E0A1B11AE1") + b"fake-msi"
        report = inspect_file(self.write("pkg.msi", payload), which=lambda _: "/bin/wine")
        self.assertEqual(report["status"], "HELD_MSI_REVIEW_REQUIRED")

    def test_random_exe_not_accepted_by_extension(self):
        report = inspect_file(self.write("spoof.exe", b"not an executable"), which=lambda _: "/bin/wine")
        self.assertEqual(report["status"], "HELD_UNRECOGNIZED_FORMAT")

    def test_extension_policy_holds(self):
        report = inspect_file(self.write("payload.dll", pe_bytes()), which=lambda _: "/bin/wine")
        self.assertEqual(report["status"], "HELD_UNSUPPORTED_EXTENSION")

    def test_invalid_files_rejected(self):
        with self.assertRaises(InspectionError):
            inspect_file(self.root, which=lambda _: None)
        with self.assertRaises(InspectionError):
            inspect_file(self.write("zero.exe", b""), which=lambda _: None)

    def test_symbolic_links_rejected(self):
        target = self.write("target.exe", pe_bytes())
        link = self.root / "linked.exe"
        link.symlink_to(target)
        with self.assertRaises(InspectionError):
            inspect_file(link, which=lambda _: None)


if __name__ == "__main__":
    unittest.main()
