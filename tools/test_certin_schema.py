#!/usr/bin/env python3
"""Tests for formats/certin-audit-metadata/certin-metadata-schema.json.

Asserts the schema is draft 2020-12, requires exactly the six top-level keys
(four array-typed), carries NO duplicated enum arrays (structure-only — vocab is
validated by the builder against enums.json), and that a real builder-produced
sample conforms.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SCHEMA = os.path.join(REPO, "formats", "certin-audit-metadata", "certin-metadata-schema.json")
ENUMS = os.path.join(REPO, "formats", "certin-audit-metadata", "enums.json")
BUILD = os.path.join(HERE, "certin_metadata_build.py")
TEMPLATE = os.path.join(REPO, "formats", "certin-audit-metadata", "Audit-Metadata-Format-2026.xlsx")

try:
    import jsonschema
    HAVE_JSONSCHEMA = True
except ImportError:
    HAVE_JSONSCHEMA = False


def find_enum_arrays(node):
    """Yield any 'enum' keyword anywhere in the schema (should be none)."""
    if isinstance(node, dict):
        if "enum" in node:
            yield node["enum"]
        for v in node.values():
            yield from find_enum_arrays(v)
    elif isinstance(node, list):
        for v in node:
            yield from find_enum_arrays(v)


class TestSchema(unittest.TestCase):
    def setUp(self):
        with open(SCHEMA) as f:
            self.schema = json.load(f)

    def test_draft_2020_12(self):
        self.assertEqual(self.schema.get("$schema"), "https://json-schema.org/draft/2020-12/schema")

    def test_top_level_keys(self):
        req = set(self.schema["required"])
        self.assertEqual(req, {"auditor_details", "audits_completed", "security_issues_technical",
                               "issues_compliance", "manpower", "meta"})
        props = self.schema["properties"]
        for arr in ("audits_completed", "security_issues_technical", "issues_compliance", "manpower"):
            self.assertEqual(props[arr]["type"], "array")

    def test_structure_only_no_enum_duplication(self):
        self.assertEqual(list(find_enum_arrays(self.schema)), [],
                         "schema must not duplicate enum vocabularies (enums.json is the single source of truth)")

    def test_enums_json_present_and_shaped(self):
        with open(ENUMS) as f:
            enums = json.load(f)
        for k in ("category", "audit_type", "reason", "state_ut", "attributing_factor", "severity",
                  "standards", "certifications", "first_final", "sector", "count_specials"):
            self.assertIn(k, enums)
        self.assertIsInstance(enums["sector"], dict)
        self.assertEqual(len(enums["sector"]), 12)
        self.assertEqual(enums["severity"], ["Critical", "High", "Medium", "Low", "Informational"])

    @unittest.skipUnless(HAVE_JSONSCHEMA and os.path.isfile(TEMPLATE), "jsonschema/template needed")
    def test_builder_sample_conforms(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = os.path.join(tmp, "260101_x")
            os.makedirs(os.path.join(eng, "reports"))
            os.makedirs(os.path.join(eng, "input"))
            with open(os.path.join(eng, "reports", "report_data.json"), "w") as f:
                json.dump({"engagement": {"target": "x"}, "findings": [
                    {"id": "F1", "title": "XSS", "severity": "Medium", "cwe": "CWE-79", "affected": ["a"]},
                    {"id": "C1", "title": "No MFA", "severity": "High", "control_id": "CL-1", "type": "compliance", "affected": ["b"]},
                ]}, f)
            # includes <FILL> placeholders (no certin.json) — must still conform
            p = subprocess.run([sys.executable, BUILD, "--engagement-dir", eng], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            sample = json.load(open(os.path.join(eng, "reports", "certin-audit-metadata.json")))
            jsonschema.validate(sample, self.schema)
            # both an empty-and-nonempty issue array shape validated (compliance non-empty here)
            self.assertEqual(len(sample["issues_compliance"]), 1)
            self.assertEqual(len(sample["security_issues_technical"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
