#!/usr/bin/env python3
"""Tests for tools/cvss_calc.py — the canonical CVSS calculator (v4.0-primary).

Run: python3 tools/test_cvss_calc.py   (or via pytest)

The v4.0 anchor scores below were CERTIFIED against the OFFICIAL FIRST.org
reference implementation (github.com/FIRSTdotorg/cvss-v4-calculator) — the port
matched it on all 104,976 base-metric combinations and 8,000 randomized full
(threat/environmental) vectors with zero deviation. v3.1/v3.0/v2.0 anchors match
the FIRST specifications and the RedHat `cvss` library exactly.

NOTE on the pip `cvss` library: it agrees with this module on v3.1/v3.0/v2.0,
but its CVSS v4.0 scoring drifts by up to 0.1 from the official FIRST reference
(both base-only and environmental vectors). This module follows the authoritative
FIRST reference, so the optional differential below is v3/v2 ONLY — never v4.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import cvss_calc as C  # noqa: E402

# --------------------------------------------------------------------------- #
# Anchors certified against the official FIRST reference / specifications.
# --------------------------------------------------------------------------- #
V4_ANCHORS = [
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
    ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:L", 1.0),
    ("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N", 2.4),
    ("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.4),
    # threat / environmental
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U", 9.1),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:H/IR:H/AR:H/E:A", 10.0),
    ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:H/SC:L/SI:N/SA:N/E:P/MSI:S/MSA:L/MVC:H/MVA:H", 9.0),
    # spread across the score range
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:L/SC:H/SI:L/SA:L", 7.0),
    ("CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N", 7.0),
    ("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:H/SC:L/SI:L/SA:H", 7.2),
    ("CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:L/SC:L/SI:N/SA:L", 6.9),
    ("CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:H/SA:N", 4.3),
    ("CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:H", 7.0),
    ("CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:L/VA:N/SC:H/SI:H/SA:L", 5.9),
    ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:L/VA:H/SC:H/SI:L/SA:N", 6.8),
    ("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:A/VC:L/VI:H/VA:L/SC:L/SI:H/SA:H", 6.0),
    ("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L", 1.0),
    ("CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:L/VI:N/VA:H/SC:L/SI:N/SA:N", 5.6),
    ("CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:P/VC:H/VI:L/VA:L/SC:N/SI:L/SA:H", 6.9),
    ("CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:L", 4.1),
    ("CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:L/VI:H/VA:L/SC:H/SI:H/SA:N", 5.9),
    ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:H/SI:N/SA:H", 2.1),
]

V31_ANCHORS = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L", 4.7),
    ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", 3.6),
    ("CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:H", 5.9),
    ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
]

# v3.0 vs v3.1 differ only in the Roundup function; these coincide as a smoke set.
V30_ANCHORS = [
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", 3.6),
]

V2_ANCHORS = [
    ("AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0),
    ("AV:N/AC:L/Au:N/C:P/I:N/A:N", 5.0),
    ("AV:N/AC:L/Au:N/C:C/I:N/A:N", 7.8),
    ("AV:L/AC:H/Au:M/C:N/I:N/A:N", 0.0),
    ("AV:L/AC:M/Au:M/C:P/I:N/A:N", 1.3),
    ("AV:L/AC:L/Au:M/C:C/I:N/A:N", 4.3),
    ("AV:A/AC:M/Au:S/C:P/I:N/A:N", 2.3),
    ("AV:A/AC:L/Au:S/C:C/I:N/A:N", 5.5),
    ("AV:N/AC:M/Au:N/C:P/I:N/A:N", 4.3),
]


def _assert_close(vector, expected):
    got = C.base_score(vector)
    assert abs(got - expected) < 1e-9, f"{vector}: expected {expected}, got {got}"


# --------------------------------------------------------------------------- #
# Base-score anchors
# --------------------------------------------------------------------------- #
def test_v4_anchors():
    for vec, exp in V4_ANCHORS:
        _assert_close(vec, exp)


def test_v31_anchors():
    for vec, exp in V31_ANCHORS:
        _assert_close(vec, exp)


def test_v30_anchors():
    for vec, exp in V30_ANCHORS:
        _assert_close(vec, exp)


def test_v2_anchors():
    for vec, exp in V2_ANCHORS:
        _assert_close(vec, exp)


def test_v4_no_impact_shortcut_is_zero():
    assert C.base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N") == 0.0


# --------------------------------------------------------------------------- #
# Version detection & parsing
# --------------------------------------------------------------------------- #
def test_detect_version():
    assert C.detect_version("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H") == "4.0"
    assert C.detect_version("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "3.1"
    assert C.detect_version("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "3.0"
    assert C.detect_version("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C") == "2.0"
    assert C.detect_version("AV:N/AC:L/Au:N/C:C/I:C/A:C") == "2.0"  # prefix-less v2


def test_detect_version_errors():
    for bad in ("", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:5.0/AV:N", "not a vector"):
        try:
            C.detect_version(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_validation_errors():
    # missing a mandatory base metric
    try:
        C.base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H")  # no SA
        raise AssertionError("expected ValueError for missing SA")
    except ValueError:
        pass
    # invalid value
    try:
        C.base_score("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        raise AssertionError("expected ValueError for AV:Z")
    except ValueError:
        pass


# --------------------------------------------------------------------------- #
# Severity bands
# --------------------------------------------------------------------------- #
def test_severity_bands_v3v4():
    for ver in ("4.0", "3.1", "3.0"):
        assert C.severity(0.0, ver) == "None"
        assert C.severity(0.1, ver) == "Low"
        assert C.severity(3.9, ver) == "Low"
        assert C.severity(4.0, ver) == "Medium"
        assert C.severity(6.9, ver) == "Medium"
        assert C.severity(7.0, ver) == "High"
        assert C.severity(8.9, ver) == "High"
        assert C.severity(9.0, ver) == "Critical"
        assert C.severity(10.0, ver) == "Critical"


def test_severity_bands_v2():
    assert C.severity(0.0, "2.0") == "Low"
    assert C.severity(3.9, "2.0") == "Low"
    assert C.severity(4.0, "2.0") == "Medium"
    assert C.severity(6.9, "2.0") == "Medium"
    assert C.severity(7.0, "2.0") == "High"
    assert C.severity(10.0, "2.0") == "High"  # v2 has no Critical


def test_score_vector_shape():
    r = C.score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
    assert r == {
        "version": "4.0", "base_score": 10.0, "severity": "Critical",
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    }


# --------------------------------------------------------------------------- #
# select_primary — the v4.0-first fallback ladder (the headline behavior)
# --------------------------------------------------------------------------- #
V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"       # 9.3
V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"                         # 9.8
V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"                         # 9.8
V2 = "AV:N/AC:L/Au:N/C:C/I:C/A:C"                                           # 10.0


def test_select_primary_prefers_v4_even_when_lower_score():
    # v4=9.3 is picked over v3.1=9.8 — primacy is by VERSION, not magnitude.
    r = C.select_primary([V31, V4, V2])
    assert r["version"] == "4.0" and r["base_score"] == 9.3


def test_select_primary_falls_back_to_highest_available():
    r = C.select_primary([V31, V30, V2])          # no v4 -> v3.1
    assert r["version"] == "3.1"
    r = C.select_primary([V30, V2])               # no v4/v3.1 -> v3.0
    assert r["version"] == "3.0"
    r = C.select_primary([V2])                    # only v2 -> the lowest, last resort
    assert r["version"] == "2.0" and r["base_score"] == 10.0


def test_select_primary_dict_with_nvd_labels():
    cand = {
        "CVSS v3.1": {"vector": V31, "score": 9.8, "severity": "CRITICAL", "source": "NVD"},
        "CVSS v4.0": {"vector": V4, "score": 9.3, "severity": "CRITICAL"},
        "CVSS v2.0": {"vector": V2},
    }
    r = C.select_primary(cand)
    assert r["version"] == "4.0" and r["base_score"] == 9.3 and r["vector"] == V4


def test_select_primary_uses_given_score_without_vector():
    # NVD sometimes gives a v4 score but the module still headlines it.
    cand = {"cvssMetricV40": {"score": 8.5}, "cvssMetricV31": {"vector": V31}}
    r = C.select_primary(cand)
    assert r["version"] == "4.0" and r["base_score"] == 8.5


def test_select_primary_skips_unusable_v4_and_falls_through():
    # v4 entry has neither a score nor a vector -> fall to v3.1.
    cand = {"CVSS v4.0": {}, "CVSS v3.1": {"vector": V31}}
    r = C.select_primary(cand)
    assert r["version"] == "3.1"


def test_select_primary_empty_is_none():
    assert C.select_primary([]) is None
    assert C.select_primary({}) is None


def test_fallback_order_constant():
    assert C.FALLBACK_ORDER == ("4.0", "3.1", "3.0", "2.0")


# --------------------------------------------------------------------------- #
# Optional differential vs the pip `cvss` library — v3.1/v3.0/v2.0 ONLY.
# (v4.0 is intentionally excluded: pip drifts from the FIRST reference there.)
# --------------------------------------------------------------------------- #
def test_v3_v2_differential_vs_pip_if_available():
    try:
        from cvss import CVSS3, CVSS2
    except Exception:
        print("  (skipped: pip `cvss` not installed)")
        return
    import itertools
    v3 = {"AV": ["N", "A", "L", "P"], "AC": ["L", "H"], "PR": ["N", "L", "H"],
          "UI": ["N", "R"], "S": ["U", "C"], "C": ["H", "L", "N"],
          "I": ["H", "L", "N"], "A": ["H", "L", "N"]}
    k3 = list(v3)
    for minor in ("1", "0"):
        for combo in itertools.product(*[v3[k] for k in k3]):
            d = dict(zip(k3, combo))
            vec = f"CVSS:3.{minor}/" + "/".join(f"{k}:{d[k]}" for k in k3)
            assert abs(C.base_score(vec) - float(CVSS3(vec).base_score)) < 1e-9, vec
    v2 = {"AV": ["L", "A", "N"], "AC": ["H", "M", "L"], "Au": ["M", "S", "N"],
          "C": ["N", "P", "C"], "I": ["N", "P", "C"], "A": ["N", "P", "C"]}
    k2 = list(v2)
    for combo in itertools.product(*[v2[k] for k in k2]):
        d = dict(zip(k2, combo))
        vec = "/".join(f"{k}:{d[k]}" for k in k2)
        assert abs(C.base_score(vec) - float(CVSS2(vec).base_score)) < 1e-9, vec


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
