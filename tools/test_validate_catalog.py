#!/usr/bin/env python3
"""Tests for tools/validate_catalog.py — stdlib + subprocess, no pytest required.

Runs the validator as a subprocess against the real catalog (positive) and
against synthetic fixtures (negative + parse-robustness).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
VALIDATOR = os.path.join(HERE, "validate_catalog.py")
REAL_CATALOG = os.path.join(REPO, "skills", "coordination", "reference", "coverage-matrix.json")
REAL_MD = os.path.join(REPO, "skills", "coordination", "reference", "coverage-matrix.md")


def run(catalog=None, md=None):
    cmd = [sys.executable, VALIDATOR]
    if catalog:
        cmd += ["--catalog", catalog]
    if md:
        cmd += ["--md", md]
    p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def _load_real():
    with open(REAL_CATALOG) as f:
        return json.load(f)


def _write(tmp, name, obj):
    path = os.path.join(tmp, name)
    with open(path, "w") as f:
        json.dump(obj, f) if isinstance(obj, (dict, list)) else f.write(obj)
    return path


def _synthetic_md(class_ids, extra_noise=False):
    lines = [
        "# Attack-Class Coverage Matrix",
        "",
        "## Class catalog",
        "",
        "| class_id | Taxonomy | Class | Applicability trigger | Technique ref |",
        "|----------|----------|-------|-----------------------|---------------|",
    ]
    for cid in class_ids:
        lines.append(f"| `{cid}` | API'23 | desc | some trigger | `ref.md` |")
    if extra_noise:
        lines += [
            "",
            "Prose paragraph mentioning class_id in running text should be ignored.",
            "",
            "A flag-vocabulary table (lowercase first cell) must NOT count as a class:",
            "| `object_by_id` | agent flag | set on id-by-object endpoints |",
            "",
            "```json",
            '{ "class_id": "FAKE-JSON-CLASS", "status": "covered" }',
            "```",
        ]
    return "\n".join(lines) + "\n"


def test_positive():
    rc, out = run()
    assert rc == 0, f"real catalog should pass, got rc={rc}: {out}"
    assert "clean" in out


def test_missing_class_fails():
    cat = _load_real()
    cat["classes"] = cat["classes"][:-1]  # drop one -> 23
    with tempfile.TemporaryDirectory() as tmp:
        cpath = _write(tmp, "cat.json", cat)
        rc, out = run(catalog=cpath)
        assert rc == 1, f"23-class catalog must fail, rc={rc}: {out}"
        assert "expected 24 classes" in out


def test_parity_drift_fails():
    cat = _load_real()
    ids = [c["class_id"] for c in cat["classes"]]
    with tempfile.TemporaryDirectory() as tmp:
        # md missing the last class -> parity drift, catalog still 24
        mpath = _write(tmp, "cat.md", _synthetic_md(ids[:-1]))
        rc, out = run(md=mpath)
        assert rc == 1, f"parity drift must fail, rc={rc}: {out}"
        assert "not in md table" in out


def test_parse_robustness_ignores_noise():
    cat = _load_real()
    ids = [c["class_id"] for c in cat["classes"]]
    with tempfile.TemporaryDirectory() as tmp:
        # all 24 real class rows + prose/flag-table/fenced-json noise -> still clean
        mpath = _write(tmp, "cat.md", _synthetic_md(ids, extra_noise=True))
        rc, out = run(md=mpath)
        assert rc == 0, f"noise-laden md should still pass parity, rc={rc}: {out}"


def test_bad_scope_split_fails():
    cat = _load_real()
    # move a unit-scope class to host -> scope split becomes 11/7/6
    for c in cat["classes"]:
        if c["scope"] == "unit":
            c["scope"] = "host"
            c["key_by"] = "listener"
            break
    with tempfile.TemporaryDirectory() as tmp:
        cpath = _write(tmp, "cat.json", cat)
        rc, out = run(catalog=cpath)
        assert rc == 1, f"bad scope split must fail, rc={rc}: {out}"
        assert "scope split" in out


def test_unknown_flag_fails():
    cat = _load_real()
    cat["classes"][0]["applies_when"] = {"any_flag": ["not_a_real_flag"]}
    with tempfile.TemporaryDirectory() as tmp:
        cpath = _write(tmp, "cat.json", cat)
        rc, out = run(catalog=cpath)
        assert rc == 1, f"unknown flag must fail, rc={rc}: {out}"
        assert "unknown flag" in out or "applies_when" in out


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
