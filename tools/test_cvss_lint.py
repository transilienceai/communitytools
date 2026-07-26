#!/usr/bin/env python3
"""Tests for tools/cvss_lint.py — the authoring-time CVSS consistency linter.

Run: python3 tools/test_cvss_lint.py   (or via pytest)

Every recomputed score below is produced by tools/cvss_calc.py (the linter does
no CVSS math of its own); the anchors mirror the values certified in
test_cvss_calc.py. Findings use synthetic ids (F-001, ...) and no client data.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import cvss_lint as L  # noqa: E402

# Reference vectors (scores per test_cvss_calc.py anchors).
V4_10 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"  # 10.0 Critical
V31_98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"                    # 9.8 Critical
V31_75 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"                    # 7.5 High
V2_10 = "AV:N/AC:L/Au:N/C:C/I:C/A:C"                                       # 10.0 (v2: High)


def _kinds(result):
    return [i["kind"] for i in result["issues"]]


# --------------------------------------------------------------------------- #
# Consistent findings -> ok, no issues
# --------------------------------------------------------------------------- #
def test_consistent_v4_is_ok():
    r = L.lint_finding({"id": "F-001", "cvss_vector": V4_10,
                        "cvss_score": 10.0, "severity": "CRITICAL"})
    assert r["ok"] is True
    assert r["issues"] == []
    assert r["recomputed"] == {"score": 10.0, "severity": "Critical", "version": "4.0"}
    assert r["id"] == "F-001" and r["version"] == 1


def test_no_vector_no_cves_is_ok_and_recomputed_none():
    r = L.lint_finding({"id": "F-000", "severity": "HIGH"})
    assert r["ok"] is True and r["issues"] == [] and r["recomputed"] is None
    assert r["id"] == "F-000"


def test_info_label_folds_to_none_no_false_band_mismatch():
    # A 0.0 vector recomputes to band 'None'; 'Informational' must not mismatch.
    zero = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
    r = L.lint_finding({"id": "F-INF", "cvss_vector": zero, "severity": "Informational"})
    assert r["ok"] is True and r["issues"] == []


# --------------------------------------------------------------------------- #
# Score mismatch + the exact-0.1 boundary
# --------------------------------------------------------------------------- #
def test_score_mismatch_flagged():
    r = L.lint_finding({"id": "F-002", "cvss_vector": V31_98,
                        "cvss_score": 7.5, "severity": "CRITICAL"})
    assert r["ok"] is False
    assert _kinds(r) == ["score_mismatch"]
    issue = r["issues"][0]
    assert issue["scope"] == "finding" and issue["claimed"] == 7.5
    assert issue["recomputed"] == 9.8 and issue["delta"] == 2.3
    assert issue["vector"] == V31_98


def test_exact_0_1_delta_is_not_a_mismatch():
    # Vector recomputes to 9.8; a claimed 9.7 is exactly 0.1 off -> tolerated.
    r = L.lint_finding({"id": "F-003", "cvss_vector": V31_98, "cvss_score": 9.7})
    assert r["ok"] is True and r["issues"] == []


def test_just_over_0_1_delta_is_a_mismatch():
    # 9.8 vs 9.6 is 0.2 off -> flagged (guards the boundary from the other side).
    r = L.lint_finding({"id": "F-003b", "cvss_vector": V31_98, "cvss_score": 9.6})
    assert _kinds(r) == ["score_mismatch"] and r["issues"][0]["delta"] == 0.2


# --------------------------------------------------------------------------- #
# Band mismatch (finding level, incl. v2.0 having no Critical)
# --------------------------------------------------------------------------- #
def test_band_mismatch_medium_labeled_low():
    # A mid-range vector recomputes to Medium; labelled 'Low' -> mismatch.
    v = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"  # 5.4
    assert abs(L.C.base_score(v) - 5.4) < 1e-9  # anchor the vector's score
    r = L.lint_finding({"id": "F-004", "cvss_vector": v, "severity": "Low"})
    assert r["ok"] is False
    issue = next(i for i in r["issues"] if i["kind"] == "band_mismatch")
    assert issue["claimed"] == "Low" and issue["expected"] == "Medium"


def test_v2_no_critical_band_mismatch():
    # v2.0 tops out at High; a 10.0 v2 vector labelled 'Critical' -> mismatch.
    r = L.lint_finding({"id": "F-005", "cvss_vector": V2_10,
                        "cvss_score": 10.0, "severity": "Critical"})
    assert r["recomputed"]["version"] == "2.0"
    assert _kinds(r) == ["band_mismatch"]
    issue = r["issues"][0]
    assert issue["claimed"] == "Critical" and issue["expected"] == "High"


# --------------------------------------------------------------------------- #
# CVEs: vector-bearing + score+severity-only (assumed_version), and unparseable
# --------------------------------------------------------------------------- #
def test_cves_mixed_vector_and_score_only():
    finding = {
        "id": "F-006",
        "cves": [
            # vector-bearing, internally consistent -> no issue
            {"id": "CVE-2020-0001", "vector": V31_75, "score": 7.5, "severity": "High"},
            # score+severity only, no finding vector -> assumed v3.1, 5.3 != Low
            {"id": "CVE-2020-0002", "score": 5.3, "severity": "Low"},
        ],
    }
    r = L.lint_finding(finding)
    assert r["ok"] is False
    assert r["recomputed"] is None  # finding itself carries no vector
    band_issues = [i for i in r["issues"] if i["scope"] == "cve"]
    assert len(band_issues) == 1
    issue = band_issues[0]
    assert issue["cve"] == "CVE-2020-0002"
    assert issue["kind"] == "band_mismatch"
    assert issue["expected"] == "Medium" and issue["claimed"] == "Low"
    assert issue["assumed_version"] == "3.1"
    assert issue["score"] == 5.3


def test_cve_score_only_uses_finding_vector_version_not_assumed():
    # With a finding vector present, the CVE band-check inherits its version and
    # records NO assumed_version.
    finding = {
        "id": "F-007",
        "cvss_vector": V31_98, "cvss_score": 9.8, "severity": "Critical",
        "cves": [{"id": "CVE-2021-9999", "score": 5.3, "severity": "Low"}],
    }
    r = L.lint_finding(finding)
    cve_issues = [i for i in r["issues"] if i["scope"] == "cve"]
    assert len(cve_issues) == 1
    assert "assumed_version" not in cve_issues[0]
    assert cve_issues[0]["expected"] == "Medium"


def test_cve_vector_score_mismatch():
    finding = {"id": "F-008",
               "cves": [{"id": "CVE-2022-1", "vector": V31_98, "score": 4.0}]}
    r = L.lint_finding(finding)
    assert _kinds(r) == ["score_mismatch"]
    assert r["issues"][0]["scope"] == "cve" and r["issues"][0]["cve"] == "CVE-2022-1"


# --------------------------------------------------------------------------- #
# Unparseable vectors + lenient downgrade
# --------------------------------------------------------------------------- #
def test_unparseable_vector_blocks_by_default():
    r = L.lint_finding({"id": "F-009", "cvss_vector": "CVSS:9.9/AV:N/NONSENSE"})
    assert r["ok"] is False
    assert _kinds(r) == ["unparseable_vector"]
    assert r["recomputed"] is None
    assert "error" in r["issues"][0]


def test_unparseable_vector_lenient_does_not_block():
    r = L.lint_finding({"id": "F-009", "cvss_vector": "not a vector"}, lenient=True)
    assert r["ok"] is True  # still reported, but non-blocking under lenient
    assert _kinds(r) == ["unparseable_vector"]


def test_unparseable_cve_vector():
    r = L.lint_finding({"id": "F-010",
                        "cves": [{"id": "CVE-2023-1", "vector": "garbage/vector"}]})
    assert r["ok"] is False
    assert _kinds(r) == ["unparseable_vector"]
    assert r["issues"][0]["scope"] == "cve" and r["issues"][0]["cve"] == "CVE-2023-1"


# --------------------------------------------------------------------------- #
# Shape detection via lint_all
# --------------------------------------------------------------------------- #
def test_lint_all_report_data_shape():
    data = {"findings": [
        {"id": "F-A", "cvss_vector": V4_10, "cvss_score": 10.0, "severity": "Critical"},
        {"id": "F-B", "cvss_vector": V31_98, "cvss_score": 7.5},  # inconsistent
    ]}
    results, code = L.lint_all(data)
    assert code == 1 and len(results) == 2
    assert results[0]["ok"] is True and results[1]["ok"] is False


def test_lint_all_bare_list_and_single_and_custom_key():
    results, code = L.lint_all([{"id": "F-A", "cvss_vector": V4_10,
                                 "cvss_score": 10.0}])
    assert code == 0 and len(results) == 1
    results, code = L.lint_all({"id": "F-solo", "cvss_vector": V31_98,
                                "cvss_score": 7.5})  # single finding dict
    assert code == 1 and results[0]["id"] == "F-solo"
    results, code = L.lint_all({"vulns": [{"id": "F-A", "cvss_vector": V4_10,
                                           "cvss_score": 10.0}]},
                               findings_key="vulns")
    assert code == 0 and len(results) == 1


def test_lint_all_unrecognized_shape():
    results, code = L.lint_all("just a string")
    assert results is None and code == 2


# --------------------------------------------------------------------------- #
# CLI exit contract (direct main() + subprocess)
# --------------------------------------------------------------------------- #
def _write(obj):
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(obj, fh)
    fh.close()
    return fh.name


def test_cli_exit_clean():
    path = _write({"findings": [
        {"id": "F-A", "cvss_vector": V4_10, "cvss_score": 10.0, "severity": "Critical"}]})
    try:
        assert L.main([path]) == 0
    finally:
        os.unlink(path)


def test_cli_exit_inconsistent():
    path = _write({"findings": [
        {"id": "F-B", "cvss_vector": V31_98, "cvss_score": 3.0}]})
    try:
        assert L.main([path]) == 1
    finally:
        os.unlink(path)


def test_cli_exit_malformed_json():
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    fh.write("{ this is not : valid json ]")
    fh.close()
    try:
        assert L.main([fh.name]) == 2
    finally:
        os.unlink(fh.name)


def test_cli_exit_unreadable_path():
    assert L.main(["/nonexistent/definitely/missing.json"]) == 2


def test_cli_subprocess_exit_codes():
    clean = _write({"findings": [
        {"id": "F-A", "cvss_vector": V4_10, "cvss_score": 10.0, "severity": "Critical"}]})
    bad = _write({"findings": [{"id": "F-B", "cvss_vector": V31_98, "cvss_score": 3.0}]})
    script = os.path.join(HERE, "cvss_lint.py")
    try:
        assert subprocess.run([sys.executable, script, clean]).returncode == 0
        assert subprocess.run([sys.executable, script, bad]).returncode == 1
    finally:
        os.unlink(clean)
        os.unlink(bad)


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
