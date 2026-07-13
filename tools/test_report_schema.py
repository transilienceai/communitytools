#!/usr/bin/env python3
"""Schema + example checks for the source_ips appendix. Stdlib only.
Run: python3 tools/test_report_schema.py
"""
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = os.path.join(REPO, "skills", "transilience-report-style", "reference")
SCHEMA = os.path.join(REF, "report-data-schema.json")
EXAMPLE = os.path.join(REF, "example-report-data.json")


def test_schema_has_source_ips():
    props = json.load(open(SCHEMA))["properties"]
    si = props["source_ips"]
    assert si["type"] == "array"
    assert si["items"]["type"] == "array" and si["items"]["items"]["type"] == "string"
    assert props["source_ips_intro"]["type"] == "string"


def test_example_source_ips_and_count_style_tools():
    ex = json.load(open(EXAMPLE))
    sips = ex["source_ips"]
    assert sips, "example must have a non-empty source_ips"
    for row in sips:
        assert isinstance(row, list) and len(row) == 3 and all(isinstance(c, str) for c in row), row
    assert any(re.search(r"invoked \d+\s*[×xX]", r[2]) for r in ex["tools_used"] if len(r) > 2), \
        "example tools_used must be count-style (invoked N×)"


def test_schema_has_attack_pattern_coverage():
    props = json.load(open(SCHEMA))["properties"]
    assert "attack_pattern_coverage" in props, "schema must define attack_pattern_coverage"
    apc = props["attack_pattern_coverage"]
    assert apc["type"] == "object"
    for k in ("header", "rows", "widths", "note"):
        assert k in apc["properties"], f"attack_pattern_coverage.{k} missing from schema"


def test_example_has_attack_pattern_coverage():
    ex = json.load(open(EXAMPLE))
    apc = ex.get("attack_pattern_coverage")
    assert apc and apc["header"][0] == "Attack class", "example must carry an attack_pattern_coverage block"
    statuses = {r[-1] for r in apc["rows"]}
    assert statuses <= {"covered", "covered_negative", "pending"}, statuses


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"FAIL {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
