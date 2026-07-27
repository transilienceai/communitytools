#!/usr/bin/env python3
"""Tests for scripts/skill_linter.py --json.

The JSON payload is what makes a deterministic skill-update workflow possible:
without it the workflow would need an agent to parse human prose into structured
violations — an LLM judgement call in the middle of the determinism chain.

So the properties that matter are contract properties: the payload is stable
across runs (the workflow gates on the DELTA between two of them, and unstable
output would read as new violations), every violation resolves to a real file,
and human mode is untouched so CI behaviour does not change.

Run: python3 scripts/test_skill_linter.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINTER = os.path.join(REPO, "scripts", "skill_linter.py")


def run(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, LINTER, *args],
                          capture_output=True, text=True, cwd=REPO)


def payload() -> dict:
    r = run("--json")
    assert r.returncode == 0, f"--json must exit 0, got {r.returncode}: {r.stderr[:400]}"
    return json.loads(r.stdout)


def test_json_always_exits_zero():
    """The JSON *is* the result. A relay agent must not have to reason about exit
    codes to know whether it can trust stdout."""
    r = run("--json")
    assert r.returncode == 0, r.returncode
    assert json.loads(r.stdout)["exit_code_equivalent"] in (0, 1)


def test_human_mode_still_fails_on_violations():
    """CI runs the human mode. Adding --json must not change its behaviour."""
    r = run()
    assert r.returncode == 1, "the tree has known violations; human mode must exit 1"
    assert "skill_linter:" in r.stdout


def test_output_is_byte_identical_across_runs():
    """The workflow gates on the delta between a before and after run. Any
    instability — filesystem iteration order, unsorted dicts — would surface as a
    phantom new violation and block every write."""
    a, b = run("--json").stdout, run("--json").stdout
    assert a == b, "non-deterministic --json output"


def test_every_violation_resolves_to_a_real_file():
    """`file` must be a path, not a prose fragment. CAP's message continues with
    ` = N lines`, which a naive ': ' split folds into the filename."""
    bad = [v for v in payload()["violations"] if not os.path.exists(os.path.join(REPO, v["file"]))]
    assert not bad, f"unresolvable paths: {bad[:3]}"


def test_violation_records_are_well_formed():
    for v in payload()["violations"]:
        assert v["code"].isupper() and v["code"], v
        assert v["file"] and not v["file"].endswith(":"), v
        assert v["line"] is None or isinstance(v["line"], int), v


def test_violations_are_sorted():
    v = payload()["violations"]
    key = [(x["code"], x["file"], x["line"] or 0, x["detail"]) for x in v]
    assert key == sorted(key), "violations must be sorted for a stable delta"


def test_caps_are_published():
    """The workflow enforces caps before writing; it must read them from here
    rather than carry a second copy that can drift."""
    caps = payload()["caps"]
    assert caps["SKILL.md"] == 150 and caps["reference"] == 200
    assert caps["scenario"] == 400 and caps["README.md"] == 100


def test_file_inventory_is_the_oracle():
    """Line counts, caps and frontmatter come from the payload, so the workflow
    never needs an agent to read a file just to count its lines."""
    files = {f["path"]: f for f in payload()["files"]}
    su = files["skills/skill-update/SKILL.md"]
    assert su["cap"] == 150 and su["kind"] == "SKILL.md"
    assert su["lines"] == len(open(os.path.join(REPO, su["path"]), encoding="utf-8")
                              .read().splitlines())
    assert su["has_anti_patterns"] is True
    assert su["frontmatter"]["name"] == "skill-update"
    assert su["frontmatter"]["description_len"] > 0


def test_inventory_covers_every_skill_markdown():
    listed = {f["path"] for f in payload()["files"]}
    on_disk = set()
    for root, _, names in os.walk(os.path.join(REPO, "skills")):
        for n in names:
            if n.endswith(".md"):
                on_disk.add(os.path.relpath(os.path.join(root, n), REPO))
    assert listed == on_disk, f"missing: {sorted(on_disk - listed)[:3]}"


def test_json_includes_orphans():
    """--json implies --check-orphans: the workflow gates on the delta, so
    pre-existing orphans never block while a NEWLY orphaned file does."""
    assert "ORPHAN" in payload()["counts"]["by_code"]


def test_counts_match_the_arrays():
    d = payload()
    assert d["counts"]["violations"] == len(d["violations"])
    assert d["counts"]["files"] == len(d["files"])
    assert sum(d["counts"]["by_code"].values()) == len(d["violations"])


def main() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
