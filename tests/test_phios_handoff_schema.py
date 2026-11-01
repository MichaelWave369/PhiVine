"""The published handoff schema itself forbids authoritative claims."""

import json
from pathlib import Path
import unittest


class HandoffSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.schema = json.loads(
            (root / "contracts/phivine.phios_advisory.v0.1.schema.json").read_text(
                encoding="utf-8"
            )
        )

    def test_current_version_is_explicit(self):
        self.assertEqual(
            self.schema["properties"]["schema"]["const"], "phivine.phios_advisory.v0.1"
        )
        self.assertFalse(self.schema["additionalProperties"])

    def test_authority_fields_are_required_and_constant_false(self):
        authority = self.schema["properties"]["authority"]
        self.assertFalse(authority["additionalProperties"])
        self.assertEqual(set(authority["required"]), set(authority["properties"]))
        self.assertIn("execution_authorized", authority["properties"])
        self.assertIn("phios_api_called", authority["properties"])
        for key, spec in authority["properties"].items():
            self.assertEqual(spec["type"], "boolean", key)
            self.assertIs(spec["const"], False, key)

    def test_no_approval_statuses_exist(self):
        statuses = self.schema["properties"]["status"]["enum"]
        self.assertEqual(set(statuses), {
            "HELD_PHIOS_BINARY_INTAKE_NOT_IMPLEMENTED",
            "HELD_INVALID_OR_TAMPERED_PROPOSAL",
        })
        self.assertTrue(all(s.startswith("HELD_") for s in statuses))


if __name__ == "__main__":
    unittest.main()
