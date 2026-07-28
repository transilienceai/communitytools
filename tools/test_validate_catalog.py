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
sys.path.insert(0, HERE)
from coverage_catalog import CLASS_COUNT, PROOF_MODES  # noqa: E402
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
    cat["classes"] = cat["classes"][:-1]  # drop one
    with tempfile.TemporaryDirectory() as tmp:
        cpath = _write(tmp, "cat.json", cat)
        rc, out = run(catalog=cpath)
        assert rc == 1, f"short catalog must fail, rc={rc}: {out}"
        # derived from the pin, so this test never needs re-baselining again
        assert f"expected {CLASS_COUNT} classes" in out


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
    # move a unit-scope class to host without touching meta -> meta disagrees with
    # the recomputed split. (The split itself is no longer separately pinned.)
    for c in cat["classes"]:
        if c["scope"] == "unit":
            c["scope"] = "host"
            c["key_by"] = "listener"
            break
    with tempfile.TemporaryDirectory() as tmp:
        cpath = _write(tmp, "cat.json", cat)
        rc, out = run(catalog=cpath)
        assert rc == 1, f"bad scope split must fail, rc={rc}: {out}"
        assert "scope_split" in out


def test_meta_class_count_drift_fails():
    cat = _load_real()
    cat["meta"]["class_count"] = CLASS_COUNT + 1  # meta self-certifies a wrong size
    with tempfile.TemporaryDirectory() as tmp:
        cpath = _write(tmp, "cat.json", cat)
        rc, out = run(catalog=cpath)
        assert rc == 1, f"meta.class_count drift must fail, rc={rc}: {out}"
        assert "meta.class_count" in out


def test_meta_flag_vocab_drift_fails():
    cat = _load_real()
    cat["meta"]["agent_flags"] = [f for f in cat["meta"]["agent_flags"] if f != "webview"]
    with tempfile.TemporaryDirectory() as tmp:
        cpath = _write(tmp, "cat.json", cat)
        rc, out = run(catalog=cpath)
        assert rc == 1, f"meta flag-vocab drift must fail, rc={rc}: {out}"
        assert "meta.agent_flags" in out and "webview" in out


def test_dead_flag_fails():
    cat = _load_real()
    # drop the only other reference to static_js_or_repo -> it becomes dead vocabulary
    for c in cat["classes"]:
        if c["class_id"] == "XC-SECRET-EXPOSURE":
            c["applies_when"] = {"any_flag": ["serves_js"]}
            break
    with tempfile.TemporaryDirectory() as tmp:
        cpath = _write(tmp, "cat.json", cat)
        rc, out = run(catalog=cpath)
        assert rc == 1, f"dead flag must fail, rc={rc}: {out}"
        assert "dead" in out and "static_js_or_repo" in out


def test_broken_technique_ref_fails():
    cat = _load_real()
    cat["classes"][0]["technique_ref"] = "skills/nope/does-not-exist.md"
    with tempfile.TemporaryDirectory() as tmp:
        cpath = _write(tmp, "cat.json", cat)
        rc, out = run(catalog=cpath)
        assert rc == 1, f"unresolvable technique_ref must fail, rc={rc}: {out}"
        assert "technique_ref does not resolve" in out


def test_bad_proof_mode_fails():
    cat = _load_real()
    for c in cat["classes"]:
        if c["class_id"].startswith("MAS-"):
            c["proof_mode"] = "sometimes"
            break
    with tempfile.TemporaryDirectory() as tmp:
        cpath = _write(tmp, "cat.json", cat)
        rc, out = run(catalog=cpath)
        assert rc == 1, f"bad proof_mode must fail, rc={rc}: {out}"
        assert "proof_mode" in out


def test_proof_mode_on_web_class_fails():
    cat = _load_real()
    cat["classes"][0]["proof_mode"] = "static"  # a non-MAS class must not carry it
    with tempfile.TemporaryDirectory() as tmp:
        cpath = _write(tmp, "cat.json", cat)
        rc, out = run(catalog=cpath)
        assert rc == 1, f"proof_mode on a web class must fail, rc={rc}: {out}"
        assert "mobile-only field" in out


def test_mobile_classes_shaped():
    """The 15 MAS-* rows obey the mobile design invariants."""
    cat = _load_real()
    mas = [c for c in cat["classes"] if c["class_id"].startswith("MAS-")]
    assert len(mas) == 15, f"expected 15 MAS-* classes, found {len(mas)}"
    mobile_flags = {"local_store", "crypto_use", "exported_component", "webview", "mobile_app"}
    for c in mas:
        cid = c["class_id"]
        assert c["taxonomy"] == "MASVS-2023", f"{cid} taxonomy {c['taxonomy']!r}"
        # an app binary has no listener: a host-scope mobile class would be incoherent
        assert c["scope"] in ("unit", "asset"), f"{cid} scope {c['scope']!r} must be unit|asset"
        assert c["negative_kind"] == "active_probe", f"{cid} negative_kind {c['negative_kind']!r}"
        assert c["min_vantages"] == 0, f"{cid} min_vantages {c['min_vantages']!r}"
        assert c["proof_mode"] in PROOF_MODES, f"{cid} proof_mode missing/invalid"
        assert c["technique_ref"].startswith("skills/mobile-security/"), f"{cid} technique_ref"
        refd: set = set()
        for key in ("any_flag", "all_flags"):
            refd |= set(c["applies_when"].get(key) or [])
        assert refd & mobile_flags, f"{cid} applies_when references no mobile flag"
        # the disjointness guarantee: every MAS class requires the derived mobile_app flag
        assert "mobile_app" in refd, f"{cid} must require the mobile_app flag"


def test_unknown_flag_fails():
    cat = _load_real()
    cat["classes"][0]["applies_when"] = {"any_flag": ["not_a_real_flag"]}
    with tempfile.TemporaryDirectory() as tmp:
        cpath = _write(tmp, "cat.json", cat)
        rc, out = run(catalog=cpath)
        assert rc == 1, f"unknown flag must fail, rc={rc}: {out}"
        assert "unknown flag" in out or "applies_when" in out


def _owasp_case(mutate):
    """Run the validator over the real catalog with one OWASP-block mutation."""
    cat = _load_real()
    mutate(cat)
    with tempfile.TemporaryDirectory() as tmp:
        c = _write(tmp, "catalog.json", cat)
        md = _write(tmp, "matrix.md", _synthetic_md([r["class_id"] for r in cat["classes"]]))
        return run(catalog=c, md=md)


def test_owasp_uncovered_category_fails():
    """The point of the check: a category that is simply absent reads as covered."""
    def drop_all(cat):
        for r in cat["classes"]:
            r.pop("owasp_refs", None)
    rc, out = _owasp_case(drop_all)
    assert rc == 1, f"stripping every owasp_refs must fail, rc={rc}"
    assert "neither covered by a class nor explicitly excluded" in out, out


def test_owasp_removing_the_exclusion_fails():
    """A09 is not assessable black-box; deleting the record of that must not pass."""
    rc, out = _owasp_case(lambda c: c["meta"]["owasp_top10_2021"].update({"not_assessed": {}}))
    assert rc == 1, f"removing the A09 exclusion must fail, rc={rc}"
    assert "A09:2021" in out, out


def test_owasp_hand_wave_exclusion_reason_fails():
    """An exclusion is only honest if it says why; 'too hard' is not a reason."""
    rc, out = _owasp_case(
        lambda c: c["meta"]["owasp_top10_2021"]["not_assessed"].update({"A09:2021": "too hard"}))
    assert rc == 1, f"a thin exclusion reason must fail, rc={rc}"
    assert "substantive reason" in out, out


def test_owasp_unknown_category_fails():
    def bogus(cat):
        cat["classes"][0]["owasp_refs"] = ["A99:2021"]
    rc, out = _owasp_case(bogus)
    assert rc == 1, f"an unknown OWASP id must fail, rc={rc}"
    assert "unknown categor" in out, out


def test_owasp_covered_and_excluded_is_contradictory():
    rc, out = _owasp_case(
        lambda c: c["meta"]["owasp_top10_2021"]["not_assessed"].update({"A01:2021": "x" * 60}))
    assert rc == 1, f"claiming a category both tested and untestable must fail, rc={rc}"
    assert "both covered by a class and listed not_assessed" in out, out


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
