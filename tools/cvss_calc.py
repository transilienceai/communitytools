#!/usr/bin/env python3
"""Canonical CVSS calculator — CVSS v4.0-primary, deterministic, dependency-free.

This is the ONE sanctioned place in this repo that computes a CVSS base score
from a vector string. Do not hand-roll CVSS math anywhere else and do not depend
on an environment-installed `cvss` package (its version varies per host) — call
this module's `base_score()` / `select_primary()` / `score_vector()`, or the CLI.

Supported versions and provenance of each algorithm:

  * CVSS v4.0 — a faithful port of the OFFICIAL FIRST.org reference
    implementation (github.com/FIRSTdotorg/cvss-v4-calculator, BSD-2-Clause):
    the MacroVector lookup table plus the equivalence-class (EQ1..EQ6) severity
    interpolation. The lookup / max-composed / max-severity tables below are
    generated verbatim from that repo's cvss_lookup.js / max_composed.js /
    max_severity.js. Copyright FIRST, Red Hat, and contributors.
  * CVSS v3.1 and v3.0 — the closed-form base-score equations from the FIRST
    CVSS v3.1 / v3.0 specifications (they differ only in the Roundup function).
  * CVSS v2.0 — the base-score equation from the FIRST CVSS v2.0 guide.

Version policy (see FALLBACK_ORDER): v4.0 is PRIMARY. When a v4.0 score/vector
is unavailable, degrade to the highest available lower version, terminating at
the lowest (v2.0) as the last resort: v4.0 -> v3.1 -> v3.0 -> v2.0.

CLI:
    python3 tools/cvss_calc.py "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    python3 tools/cvss_calc.py "<v4 vector>" "<v3.1 vector>" "AV:N/AC:L/Au:N/C:C/I:C/A:C"
        -> emits {"primary": {...v4-first pick...}, "all": [ per-vector {...} ]}
    python3 tools/cvss_calc.py --band 9.3            # score -> qualitative rating
    python3 tools/cvss_calc.py --select '<json>'     # {version: {vector,score?}} -> primary
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys

# Fallback ladder: v4.0 is primary; degrade to the highest available lower
# version, terminating at the lowest (v2.0) as last resort.
FALLBACK_ORDER = ("4.0", "3.1", "3.0", "2.0")

# --------------------------------------------------------------------------- #
# CVSS v4.0 official reference tables (generated verbatim from FIRST's
# cvss-v4-calculator: cvss_lookup.js, max_composed.js, max_severity.js).
# Copyright FIRST, Red Hat, and contributors. SPDX-License-Identifier: BSD-2-Clause
# --------------------------------------------------------------------------- #
_V4_LOOKUP = {
    "100000": 9.8,
    "100001": 9.5,
    "100010": 9.4,
    "100011": 8.7,
    "100020": 9.1,
    "100021": 8.1,
    "100100": 9.4,
    "100101": 8.9,
    "100110": 8.6,
    "100111": 7.4,
    "100120": 7.7,
    "100121": 6.4,
    "100200": 8.7,
    "100201": 7.5,
    "100210": 7.4,
    "100211": 6.3,
    "100220": 6.3,
    "100221": 4.9,
    "101000": 9.4,
    "101001": 8.9,
    "101010": 8.8,
    "101011": 7.7,
    "101020": 7.6,
    "101021": 6.7,
    "101100": 8.6,
    "101101": 7.6,
    "101110": 7.4,
    "101111": 5.8,
    "101120": 5.9,
    "101121": 5,
    "101200": 7.2,
    "101201": 5.7,
    "101210": 5.7,
    "101211": 5.2,
    "101220": 5.2,
    "101221": 2.5,
    "102001": 8.3,
    "102011": 7,
    "102021": 5.4,
    "102101": 6.5,
    "102111": 5.8,
    "102121": 2.6,
    "102201": 5.3,
    "102211": 2.1,
    "102221": 1.3,
    "110000": 9.5,
    "110001": 9,
    "110010": 8.8,
    "110011": 7.6,
    "110020": 7.6,
    "110021": 7,
    "110100": 9,
    "110101": 7.7,
    "110110": 7.5,
    "110111": 6.2,
    "110120": 6.1,
    "110121": 5.3,
    "110200": 7.7,
    "110201": 6.6,
    "110210": 6.8,
    "110211": 5.9,
    "110220": 5.2,
    "110221": 3,
    "111000": 8.9,
    "111001": 7.8,
    "111010": 7.6,
    "111011": 6.7,
    "111020": 6.2,
    "111021": 5.8,
    "111100": 7.4,
    "111101": 5.9,
    "111110": 5.7,
    "111111": 5.7,
    "111120": 4.7,
    "111121": 2.3,
    "111200": 6.1,
    "111201": 5.2,
    "111210": 5.7,
    "111211": 2.9,
    "111220": 2.4,
    "111221": 1.6,
    "112001": 7.1,
    "112011": 5.9,
    "112021": 3,
    "112101": 5.8,
    "112111": 2.6,
    "112121": 1.5,
    "112201": 2.3,
    "112211": 1.3,
    "112221": 0.6,
    "200000": 9.3,
    "200001": 8.7,
    "200010": 8.6,
    "200011": 7.2,
    "200020": 7.5,
    "200021": 5.8,
    "200100": 8.6,
    "200101": 7.4,
    "200110": 7.4,
    "200111": 6.1,
    "200120": 5.6,
    "200121": 3.4,
    "200200": 7,
    "200201": 5.4,
    "200210": 5.2,
    "200211": 4,
    "200220": 4,
    "200221": 2.2,
    "201000": 8.5,
    "201001": 7.5,
    "201010": 7.4,
    "201011": 5.5,
    "201020": 6.2,
    "201021": 5.1,
    "201100": 7.2,
    "201101": 5.7,
    "201110": 5.5,
    "201111": 4.1,
    "201120": 4.6,
    "201121": 1.9,
    "201200": 5.3,
    "201201": 3.6,
    "201210": 3.4,
    "201211": 1.9,
    "201220": 1.9,
    "201221": 0.8,
    "202001": 6.4,
    "202011": 5.1,
    "202021": 2,
    "202101": 4.7,
    "202111": 2.1,
    "202121": 1.1,
    "202201": 2.4,
    "202211": 0.9,
    "202221": 0.4,
    "210000": 8.8,
    "210001": 7.5,
    "210010": 7.3,
    "210011": 5.3,
    "210020": 6,
    "210021": 5,
    "210100": 7.3,
    "210101": 5.5,
    "210110": 5.9,
    "210111": 4,
    "210120": 4.1,
    "210121": 2,
    "210200": 5.4,
    "210201": 4.3,
    "210210": 4.5,
    "210211": 2.2,
    "210220": 2,
    "210221": 1.1,
    "211000": 7.5,
    "211001": 5.5,
    "211010": 5.8,
    "211011": 4.5,
    "211020": 4,
    "211021": 2.1,
    "211100": 6.1,
    "211101": 5.1,
    "211110": 4.8,
    "211111": 1.8,
    "211120": 2,
    "211121": 0.9,
    "211200": 4.6,
    "211201": 1.8,
    "211210": 1.7,
    "211211": 0.7,
    "211220": 0.8,
    "211221": 0.2,
    "212001": 5.3,
    "212011": 2.4,
    "212021": 1.4,
    "212101": 2.4,
    "212111": 1.2,
    "212121": 0.5,
    "212201": 1,
    "212211": 0.3,
    "212221": 0.1,
    "000000": 10,
    "000001": 9.9,
    "000010": 9.8,
    "000011": 9.5,
    "000020": 9.5,
    "000021": 9.2,
    "000100": 10,
    "000101": 9.6,
    "000110": 9.3,
    "000111": 8.7,
    "000120": 9.1,
    "000121": 8.1,
    "000200": 9.3,
    "000201": 9,
    "000210": 8.9,
    "000211": 8,
    "000220": 8.1,
    "000221": 6.8,
    "001000": 9.8,
    "001001": 9.5,
    "001010": 9.5,
    "001011": 9.2,
    "001020": 9,
    "001021": 8.4,
    "001100": 9.3,
    "001101": 9.2,
    "001110": 8.9,
    "001111": 8.1,
    "001120": 8.1,
    "001121": 6.5,
    "001200": 8.8,
    "001201": 8,
    "001210": 7.8,
    "001211": 7,
    "001220": 6.9,
    "001221": 4.8,
    "002001": 9.2,
    "002011": 8.2,
    "002021": 7.2,
    "002101": 7.9,
    "002111": 6.9,
    "002121": 5,
    "002201": 6.9,
    "002211": 5.5,
    "002221": 2.7,
    "010000": 9.9,
    "010001": 9.7,
    "010010": 9.5,
    "010011": 9.2,
    "010020": 9.2,
    "010021": 8.5,
    "010100": 9.5,
    "010101": 9.1,
    "010110": 9,
    "010111": 8.3,
    "010120": 8.4,
    "010121": 7.1,
    "010200": 9.2,
    "010201": 8.1,
    "010210": 8.2,
    "010211": 7.1,
    "010220": 7.2,
    "010221": 5.3,
    "011000": 9.5,
    "011001": 9.3,
    "011010": 9.2,
    "011011": 8.5,
    "011020": 8.5,
    "011021": 7.3,
    "011100": 9.2,
    "011101": 8.2,
    "011110": 8,
    "011111": 7.2,
    "011120": 7,
    "011121": 5.9,
    "011200": 8.4,
    "011201": 7,
    "011210": 7.1,
    "011211": 5.2,
    "011220": 5,
    "011221": 3,
    "012001": 8.6,
    "012011": 7.5,
    "012021": 5.2,
    "012101": 7.1,
    "012111": 5.2,
    "012121": 2.9,
    "012201": 6.3,
    "012211": 2.9,
    "012221": 1.7,
}

_V4_MAX_COMPOSED = {
    "eq1": {
        "0": [
            "AV:N/PR:N/UI:N/"
        ],
        "1": [
            "AV:A/PR:N/UI:N/",
            "AV:N/PR:L/UI:N/",
            "AV:N/PR:N/UI:P/"
        ],
        "2": [
            "AV:P/PR:N/UI:N/",
            "AV:A/PR:L/UI:P/"
        ]
    },
    "eq2": {
        "0": [
            "AC:L/AT:N/"
        ],
        "1": [
            "AC:H/AT:N/",
            "AC:L/AT:P/"
        ]
    },
    "eq3": {
        "0": {
            "0": [
                "VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"
            ],
            "1": [
                "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/",
                "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"
            ]
        },
        "1": {
            "0": [
                "VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/",
                "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"
            ],
            "1": [
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"
            ]
        },
        "2": {
            "1": [
                "VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"
            ]
        }
    },
    "eq4": {
        "0": [
            "SC:H/SI:S/SA:S/"
        ],
        "1": [
            "SC:H/SI:H/SA:H/"
        ],
        "2": [
            "SC:L/SI:L/SA:L/"
        ]
    },
    "eq5": {
        "0": [
            "E:A/"
        ],
        "1": [
            "E:P/"
        ],
        "2": [
            "E:U/"
        ]
    }
}

_V4_MAX_SEVERITY = {
    "eq1": {
        "0": 1,
        "1": 4,
        "2": 5
    },
    "eq2": {
        "0": 1,
        "1": 2
    },
    "eq3eq6": {
        "0": {
            "0": 7,
            "1": 6
        },
        "1": {
            "0": 8,
            "1": 8
        },
        "2": {
            "1": 10
        }
    },
    "eq4": {
        "0": 6,
        "1": 5,
        "2": 4
    },
    "eq5": {
        "0": 1,
        "1": 1,
        "2": 1
    }
}


# v4.0 metric-value -> ordinal "level" used for severity-distance math (lower is
# more severe). Ported from the reference cvss_score.js. Note E is only used for
# EQ5 (whose severity distance is defined as 0), so it never appears in the
# per-metric distance loop.
_V4_LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "E": {"U": 0.2, "P": 0.1, "A": 0.0},
}

# Mandatory (Base) metrics — every valid v4.0 vector must supply all 11.
_V4_BASE_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")

# Valid values per v4.0 metric (from metrics.js expectedMetricOrder).
_V4_VALID = {
    "AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "AT": {"N", "P"},
    "PR": {"N", "L", "H"}, "UI": {"N", "P", "A"},
    "VC": {"H", "L", "N"}, "VI": {"H", "L", "N"}, "VA": {"H", "L", "N"},
    "SC": {"H", "L", "N"}, "SI": {"H", "L", "N"}, "SA": {"H", "L", "N"},
    "E": {"X", "A", "P", "U"},
    "CR": {"X", "H", "M", "L"}, "IR": {"X", "H", "M", "L"}, "AR": {"X", "H", "M", "L"},
    "MAV": {"X", "N", "A", "L", "P"}, "MAC": {"X", "L", "H"}, "MAT": {"X", "N", "P"},
    "MPR": {"X", "N", "L", "H"}, "MUI": {"X", "N", "P", "A"},
    "MVC": {"X", "H", "L", "N"}, "MVI": {"X", "H", "L", "N"}, "MVA": {"X", "H", "L", "N"},
    "MSC": {"X", "H", "L", "N"}, "MSI": {"X", "S", "H", "L", "N"}, "MSA": {"X", "S", "H", "L", "N"},
    "S": {"X", "N", "P"}, "AU": {"X", "N", "Y"}, "R": {"X", "A", "U", "I"},
    "V": {"X", "D", "C"}, "RE": {"X", "L", "M", "H"},
    "U": {"X", "Clear", "Green", "Amber", "Red"},
}

# The 14 metrics that carry a severity distance in the v4.0 interpolation.
_V4_DIST_METRICS = ("AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA",
                    "SC", "SI", "SA", "CR", "IR", "AR")


# --------------------------------------------------------------------------- #
# CVSS v4.0 scoring (port of FIRST cvss_score.js + macroVector())
# --------------------------------------------------------------------------- #
def _v4_m(sel: dict, metric: str) -> str:
    """Effective metric value with v4.0 defaults (port of reference m())."""
    selected = sel.get(metric, "X")
    if metric == "E" and selected == "X":
        return "A"  # E:X defaults to the worst case (Attacked)
    if metric in ("CR", "IR", "AR") and selected == "X":
        return "H"  # CR/IR/AR:X default to High
    # A modified (environmental) metric overrides its base counterpart when set.
    mod = sel.get("M" + metric)
    if mod is not None and mod != "X":
        return mod
    return selected


def _v4_macrovector(sel: dict) -> str:
    m = _v4_m
    # EQ1
    if m(sel, "AV") == "N" and m(sel, "PR") == "N" and m(sel, "UI") == "N":
        eq1 = "0"
    elif ((m(sel, "AV") == "N" or m(sel, "PR") == "N" or m(sel, "UI") == "N")
          and not (m(sel, "AV") == "N" and m(sel, "PR") == "N" and m(sel, "UI") == "N")
          and m(sel, "AV") != "P"):
        eq1 = "1"
    else:
        eq1 = "2"
    # EQ2
    eq2 = "0" if (m(sel, "AC") == "L" and m(sel, "AT") == "N") else "1"
    # EQ3
    if m(sel, "VC") == "H" and m(sel, "VI") == "H":
        eq3 = "0"
    elif m(sel, "VC") == "H" or m(sel, "VI") == "H" or m(sel, "VA") == "H":
        eq3 = "1"
    else:
        eq3 = "2"
    # EQ4
    if m(sel, "MSI") == "S" or m(sel, "MSA") == "S":
        eq4 = "0"
    elif m(sel, "SC") == "H" or m(sel, "SI") == "H" or m(sel, "SA") == "H":
        eq4 = "1"
    else:
        eq4 = "2"
    # EQ5
    if m(sel, "E") == "A":
        eq5 = "0"
    elif m(sel, "E") == "P":
        eq5 = "1"
    else:
        eq5 = "2"
    # EQ6
    if ((m(sel, "CR") == "H" and m(sel, "VC") == "H")
            or (m(sel, "IR") == "H" and m(sel, "VI") == "H")
            or (m(sel, "AR") == "H" and m(sel, "VA") == "H")):
        eq6 = "0"
    else:
        eq6 = "1"
    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6


def _v4_extract(metric: str, composed: str) -> str:
    """Read a metric's value out of a composed max-vector string (extractValueMetric)."""
    i = composed.index(metric)
    rest = composed[i + len(metric) + 1:]
    j = rest.find("/")
    return rest[:j] if j > 0 else rest


def _gt(a, b) -> bool:
    """JS `a > b` semantics: any comparison involving an absent value is False."""
    return a is not None and b is not None and a > b


def _v4_score(sel: dict) -> float:
    m = _v4_m
    lvl = _V4_LEVELS

    # Shortcut: no impact on any system => 0.0
    if all(m(sel, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    macro = _v4_macrovector(sel)
    value = _V4_LOOKUP[macro]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in macro)

    # Next-lower MacroVectors (None when they do not exist in the lookup).
    eq1_next = f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}"
    eq2_next = f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}"

    left = right = None
    eq3eq6_next = None
    if eq3 == 1 and eq6 == 1:
        eq3eq6_next = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
    elif eq3 == 0 and eq6 == 1:
        eq3eq6_next = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
    elif eq3 == 1 and eq6 == 0:
        eq3eq6_next = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"
    elif eq3 == 0 and eq6 == 0:
        left = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"
        right = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
    else:
        eq3eq6_next = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}"

    eq4_next = f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}"
    eq5_next = f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}"

    s_eq1 = _V4_LOOKUP.get(eq1_next)
    s_eq2 = _V4_LOOKUP.get(eq2_next)
    if eq3 == 0 and eq6 == 0:
        s_left = _V4_LOOKUP.get(left)
        s_right = _V4_LOOKUP.get(right)
        s_eq3eq6 = s_left if _gt(s_left, s_right) else s_right
    else:
        s_eq3eq6 = _V4_LOOKUP.get(eq3eq6_next)
    s_eq4 = _V4_LOOKUP.get(eq4_next)
    s_eq5 = _V4_LOOKUP.get(eq5_next)

    # Highest-severity ("max") vectors composed for this MacroVector.
    eq1_maxes = _V4_MAX_COMPOSED["eq1"][macro[0]]
    eq2_maxes = _V4_MAX_COMPOSED["eq2"][macro[1]]
    eq3eq6_maxes = _V4_MAX_COMPOSED["eq3"][macro[2]][macro[5]]
    eq4_maxes = _V4_MAX_COMPOSED["eq4"][macro[3]]
    eq5_maxes = _V4_MAX_COMPOSED["eq5"][macro[4]]

    max_vectors = []
    for a in eq1_maxes:
        for b in eq2_maxes:
            for c in eq3eq6_maxes:
                for d in eq4_maxes:
                    for e in eq5_maxes:
                        max_vectors.append(a + b + c + d + e)

    # Find the max vector whose severity is >= the to-be-scored vector on every
    # metric; its per-metric distances feed the interpolation.
    sev = {}
    for mv in max_vectors:
        sev = {met: lvl[met][m(sel, met)] - lvl[met][_v4_extract(met, mv)]
               for met in _V4_DIST_METRICS}
        if all(d >= 0 for d in sev.values()):
            break

    cur_eq1 = sev["AV"] + sev["PR"] + sev["UI"]
    cur_eq2 = sev["AC"] + sev["AT"]
    cur_eq3eq6 = sev["VC"] + sev["VI"] + sev["VA"] + sev["CR"] + sev["IR"] + sev["AR"]
    cur_eq4 = sev["SC"] + sev["SI"] + sev["SA"]

    step = 0.1
    avail_eq1 = (value - s_eq1) if s_eq1 is not None else None
    avail_eq2 = (value - s_eq2) if s_eq2 is not None else None
    avail_eq3eq6 = (value - s_eq3eq6) if s_eq3eq6 is not None else None
    avail_eq4 = (value - s_eq4) if s_eq4 is not None else None
    avail_eq5 = (value - s_eq5) if s_eq5 is not None else None

    max_sev_eq1 = _V4_MAX_SEVERITY["eq1"][macro[0]] * step
    max_sev_eq2 = _V4_MAX_SEVERITY["eq2"][macro[1]] * step
    max_sev_eq3eq6 = _V4_MAX_SEVERITY["eq3eq6"][macro[2]][macro[5]] * step
    max_sev_eq4 = _V4_MAX_SEVERITY["eq4"][macro[3]] * step

    n = 0
    norm1 = norm2 = norm3 = norm4 = norm5 = 0.0
    if avail_eq1 is not None:
        n += 1
        norm1 = avail_eq1 * (cur_eq1 / max_sev_eq1)
    if avail_eq2 is not None:
        n += 1
        norm2 = avail_eq2 * (cur_eq2 / max_sev_eq2)
    if avail_eq3eq6 is not None:
        n += 1
        norm3 = avail_eq3eq6 * (cur_eq3eq6 / max_sev_eq3eq6)
    if avail_eq4 is not None:
        n += 1
        norm4 = avail_eq4 * (cur_eq4 / max_sev_eq4)
    if avail_eq5 is not None:
        n += 1
        norm5 = 0.0  # EQ5 percentage is always 0

    mean = 0.0 if n == 0 else (norm1 + norm2 + norm3 + norm4 + norm5) / n
    value -= mean
    value = max(0.0, min(10.0, value))
    return math.floor(value * 10 + 0.5) / 10  # JS Math.round(value*10)/10


# --------------------------------------------------------------------------- #
# CVSS v3.1 / v3.0 base score (FIRST v3.1 / v3.0 specifications)
# --------------------------------------------------------------------------- #
_V3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_V3_AC = {"L": 0.77, "H": 0.44}
_V3_UI = {"N": 0.85, "R": 0.62}
_V3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope Unchanged
_V3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}   # Scope Changed
_V3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_V3_BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_V3_VALID = {
    "AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "PR": {"N", "L", "H"},
    "UI": {"N", "R"}, "S": {"U", "C"},
    "C": {"H", "L", "N"}, "I": {"H", "L", "N"}, "A": {"H", "L", "N"},
}


def _roundup31(x: float) -> float:
    """CVSS v3.1 Roundup (integer arithmetic — avoids binary float edge cases)."""
    i = int(math.floor(x * 100000 + 0.5))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def _roundup30(x: float) -> float:
    """CVSS v3.0 Roundup: smallest 1-dp number >= x."""
    return math.ceil(round(x, 5) * 10) / 10.0


def _v3_base(metrics: dict, minor: str) -> float:
    scope = metrics["S"]
    c = _V3_CIA[metrics["C"]]
    i = _V3_CIA[metrics["I"]]
    a = _V3_CIA[metrics["A"]]
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
        pr = _V3_PR_U[metrics["PR"]]
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        pr = _V3_PR_C[metrics["PR"]]
    expl = 8.22 * _V3_AV[metrics["AV"]] * _V3_AC[metrics["AC"]] * pr * _V3_UI[metrics["UI"]]
    if impact <= 0:
        return 0.0
    roundup = _roundup31 if minor == "1" else _roundup30
    raw = (impact + expl) if scope == "U" else 1.08 * (impact + expl)
    return roundup(min(raw, 10))


# --------------------------------------------------------------------------- #
# CVSS v2.0 base score (FIRST v2.0 guide)
# --------------------------------------------------------------------------- #
_V2_AV = {"L": 0.395, "A": 0.646, "N": 1.0}
_V2_AC = {"H": 0.35, "M": 0.61, "L": 0.71}
_V2_AU = {"M": 0.45, "S": 0.56, "N": 0.704}
_V2_CIA = {"N": 0.0, "P": 0.275, "C": 0.660}
_V2_BASE_METRICS = ("AV", "AC", "Au", "C", "I", "A")
_V2_VALID = {
    "AV": {"L", "A", "N"}, "AC": {"H", "M", "L"}, "Au": {"M", "S", "N"},
    "C": {"N", "P", "C"}, "I": {"N", "P", "C"}, "A": {"N", "P", "C"},
}


def _v2_base(metrics: dict) -> float:
    c = _V2_CIA[metrics["C"]]
    i = _V2_CIA[metrics["I"]]
    a = _V2_CIA[metrics["A"]]
    impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
    expl = 20 * _V2_AV[metrics["AV"]] * _V2_AC[metrics["AC"]] * _V2_AU[metrics["Au"]]
    f = 0.0 if impact == 0 else 1.176
    base = ((0.6 * impact) + (0.4 * expl) - 1.5) * f
    return math.floor(base * 10 + 0.5) / 10


# --------------------------------------------------------------------------- #
# Parsing, versioning, public API
# --------------------------------------------------------------------------- #
_PREFIX_RE = re.compile(r"(?i)^CVSS:(\d\.\d)/")


def detect_version(vector: str) -> str:
    """Return '4.0' | '3.1' | '3.0' | '2.0' for a vector string, else raise."""
    v = vector.strip()
    m = _PREFIX_RE.match(v)
    if m:
        ver = m.group(1)
        if ver in ("4.0", "3.1", "3.0", "2.0"):
            return ver
        raise ValueError(f"unsupported CVSS prefix version: {ver}")
    up = v.upper()
    if up.startswith("CVSS:"):
        raise ValueError(f"unrecognized CVSS prefix in vector: {v[:16]!r}")
    # No prefix: only CVSS v2.0 is emitted prefix-less (its hallmark is the Au: metric).
    if re.search(r"(?i)\bAu:", v):
        return "2.0"
    raise ValueError("cannot detect CVSS version (missing CVSS:x.y/ prefix)")


def parse_vector(vector: str):
    """Return (version, {metric: value}). Does not validate metric completeness."""
    version = detect_version(vector)
    body = _PREFIX_RE.sub("", vector.strip())
    metrics = {}
    for part in body.split("/"):
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"malformed metric segment: {part!r}")
        key, val = part.split(":", 1)
        metrics[key] = val
    return version, metrics


def _validate(version: str, metrics: dict) -> None:
    if version == "4.0":
        missing = [k for k in _V4_BASE_METRICS if k not in metrics]
        if missing:
            raise ValueError(f"CVSS v4.0 vector missing base metrics: {missing}")
        for k, val in metrics.items():
            if k in _V4_VALID and val not in _V4_VALID[k]:
                raise ValueError(f"invalid v4.0 value {k}:{val}")
    elif version in ("3.1", "3.0"):
        missing = [k for k in _V3_BASE_METRICS if k not in metrics]
        if missing:
            raise ValueError(f"CVSS v{version} vector missing base metrics: {missing}")
        for k in _V3_BASE_METRICS:
            if metrics[k] not in _V3_VALID[k]:
                raise ValueError(f"invalid v{version} value {k}:{metrics[k]}")
    elif version == "2.0":
        missing = [k for k in _V2_BASE_METRICS if k not in metrics]
        if missing:
            raise ValueError(f"CVSS v2.0 vector missing base metrics: {missing}")
        for k in _V2_BASE_METRICS:
            if metrics[k] not in _V2_VALID[k]:
                raise ValueError(f"invalid v2.0 value {k}:{metrics[k]}")


def base_score(vector: str) -> float:
    """Compute the CVSS base score for a vector of any supported version."""
    version, metrics = parse_vector(vector)
    _validate(version, metrics)
    if version == "4.0":
        return _v4_score(metrics)
    if version in ("3.1", "3.0"):
        return _v3_base(metrics, version.split(".")[1])
    return _v2_base(metrics)


def severity(score, version: str = "3.1") -> str:
    """Qualitative rating for a base score. v3.x/v4.0 share bands (None/Low/
    Medium/High/Critical); v2.0 has no Critical (Low/Medium/High)."""
    if score is None:
        return "None"
    s = float(score)
    if version == "2.0":
        if s >= 7.0:
            return "High"
        if s >= 4.0:
            return "Medium"
        return "Low"
    if s == 0:
        return "None"
    if s < 4.0:
        return "Low"
    if s < 7.0:
        return "Medium"
    if s < 9.0:
        return "High"
    return "Critical"


def score_vector(vector: str) -> dict:
    """Full result for one vector: {version, base_score, severity, vector}."""
    version, _ = parse_vector(vector)
    score = base_score(vector)
    return {
        "version": version,
        "base_score": score,
        "severity": severity(score, version),
        "vector": vector.strip(),
    }


def _canon_version(label) -> str | None:
    """Map a version-ish label (e.g. 'CVSS v4.0', 'cvssMetricV31', 'v3.1', 4.0)
    onto one of FALLBACK_ORDER, else None."""
    s = str(label).lower()
    if "4.0" in s or "v40" in s or s in ("4", "v4"):
        return "4.0"
    if "3.1" in s or "v31" in s:
        return "3.1"
    if "3.0" in s or "v30" in s:
        return "3.0"
    if "2.0" in s or s in ("2", "v2") or "metricv2" in s:
        return "2.0"
    return None


def select_primary(candidates):
    """Pick the authoritative score across versions using the v4.0-first ladder.

    `candidates` may be:
      * a dict {version_label: {"vector": str, "score"?: float, "severity"?: str,
        "source"?: str}}  (score is recomputed from the vector when absent), or
      * an iterable of vector strings.

    Returns {version, base_score, severity, vector, source} for the winning
    version per FALLBACK_ORDER, or None when nothing usable is present.
    """
    norm: dict[str, dict] = {}
    if isinstance(candidates, dict):
        for label, info in candidates.items():
            ver = _canon_version(label)
            if not ver:
                continue
            norm.setdefault(ver, info if isinstance(info, dict) else {"vector": info})
    else:
        for vec in candidates:
            try:
                ver, _ = parse_vector(vec)
            except ValueError:
                continue
            norm.setdefault(ver, {"vector": vec})

    for ver in FALLBACK_ORDER:
        if ver not in norm:
            continue
        info = norm[ver]
        vec = info.get("vector")
        score = info.get("score")
        if score is None and vec:
            try:
                score = base_score(vec)
            except ValueError:
                score = None
        if score is None:
            continue
        return {
            "version": ver,
            "base_score": score,
            "severity": info.get("severity") or severity(score, ver),
            "vector": vec,
            "source": info.get("source"),
        }
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("vectors", nargs="*", metavar="VECTOR",
                    help="one or more CVSS vector strings (any supported version)")
    ap.add_argument("--band", type=float, metavar="SCORE",
                    help="print the qualitative rating for a base score and exit")
    ap.add_argument("--band-version", default="3.1",
                    help="version whose bands --band uses (default 3.1; use 2.0 for v2 bands)")
    ap.add_argument("--select", metavar="JSON",
                    help='pick the primary from a JSON {version: {vector, score?}} map')
    args = ap.parse_args(argv)

    if args.band is not None:
        print(severity(args.band, args.band_version))
        return 0

    if args.select:
        try:
            cand = json.loads(args.select)
        except json.JSONDecodeError as exc:
            print(f"ERROR: --select is not valid JSON: {exc}", file=sys.stderr)
            return 2
        primary = select_primary(cand)
        print(json.dumps({"primary": primary}, indent=2))
        return 0 if primary else 1

    if not args.vectors:
        ap.print_help()
        return 2

    results = []
    for vec in args.vectors:
        try:
            results.append(score_vector(vec))
        except ValueError as exc:
            results.append({"vector": vec, "error": str(exc)})

    if len(results) == 1:
        print(json.dumps(results[0], indent=2))
        return 0 if "error" not in results[0] else 1

    primary = select_primary([r["vector"] for r in results if "error" not in r])
    print(json.dumps({"primary": primary, "all": results}, indent=2))
    return 0 if primary else 1


if __name__ == "__main__":
    raise SystemExit(main())
