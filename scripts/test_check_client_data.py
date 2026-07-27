#!/usr/bin/env python3
"""Tests for scripts/check_client_data.py — the public-repo content guard.

Two halves, and the second matters as much as the first:

  * TRUE POSITIVES  — every rule fires on a synthetic leak. All fixtures are
    invented (Zorbix, Quellhaven, Nemora Bank) and use RFC 5737 addresses, so
    this file never becomes the leak it tests for.
  * FALSE POSITIVES — a corpus of things that must NEVER fire, measured against
    the real tree. A guard that cries wolf gets bypassed, and a bypassed guard
    protects nothing, so the noise floor is a hard assertion rather than a hope.

Run: python3 scripts/test_check_client_data.py
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD = os.path.join(REPO, "scripts", "check_client_data.py")

_spec = importlib.util.spec_from_file_location("ccd", GUARD)
ccd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ccd)


def engagement_hits(line: str) -> list[tuple[str, str]]:
    """Mirror of the engagement lane in main(), including its suppressors."""
    out = []
    for label, rx in ccd.ENGAGEMENT_PATTERNS:
        for m in rx.finditer(line):
            hit = m.group(0)
            if ccd.PLACEHOLDER_SLUG.search(hit) or "projects/ctf/" in line:
                continue
            out.append((label, hit))
    return out


# --------------------------------------------------------------------------
# Engagement identifiers — true positives
# --------------------------------------------------------------------------

def test_engagement_path_8digit():
    hits = engagement_hits("see projects/pentest/20260709_zorbix_ext_vapt/report.pdf")
    assert hits and hits[0][0] == "engagement-path", hits


def test_engagement_path_legacy_6digit():
    assert engagement_hits("outputs/260602_quellhaven/findings"), "legacy YYMMDD_ must match"


def test_engagement_path_every_tree():
    for tree in ("pentest", "compliance", "offsec", "webinars",
                 "attacks-validation", "attack-path-prioritisation"):
        line = f"projects/{tree}/20260101_nemora_bank/scope.md"
        assert engagement_hits(line), f"{tree} not covered"


def test_finding_id_engagement_local_script():
    hits = engagement_hits("ported from f09_zmtp_probe.py into the skill")
    assert hits and hits[0][0] == "finding-id", hits


def test_finding_id_sweep():
    assert engagement_hits("finding F-SWEEP-0042 was confirmed"), "F-SWEEP-* must match"


# --------------------------------------------------------------------------
# Engagement identifiers — false positives that must stay silent
# --------------------------------------------------------------------------

def test_placeholder_slug_after_underscore_is_suppressed():
    """Regression: \\bacme\\b never fires inside `260101_acme` because `_` is a word
    character. The suppressor uses letter-boundary lookarounds for exactly this."""
    assert not engagement_hits("projects/pentest/260101_acme is the documented format")


def test_placeholder_slugs_generally():
    for slug in ("acme", "example", "demo", "test", "yourco", "customer"):
        line = f"projects/pentest/260101_{slug}/scope.md"
        assert not engagement_hits(line), f"placeholder {slug} must be suppressed"


def test_ctf_tree_is_not_an_engagement():
    """projects/ctf/ holds public challenge platforms, cited on purpose."""
    line = ("see `projects/ctf/260516_art_of_capture/emulation/qiling_emul.py`")
    assert not engagement_hits(line)


def test_bare_sequence_finding_ids_never_match():
    """A bare F-12 is a sequence number carrying no customer information, and the
    tree uses those ids as synthetic fixtures 80+ times. Matching them would be
    pure noise. This asserts the decision, so it cannot be silently reversed."""
    for fid in ("F-1", "F-01", "F-03", "F-12", "F-200", "F-404", "F-100"):
        assert not engagement_hits(f"the fixture uses {fid} as its id"), fid


# --------------------------------------------------------------------------
# Symlink lane
# --------------------------------------------------------------------------

def test_symlink_absolute_target_blocks():
    leaks = ccd.symlink_leaks({"a/b": "/Users/someone/dev/other-repo/x"})
    assert len(leaks) == 1 and "absolute-target" in leaks[0]


def test_symlink_absolute_target_is_not_echoed():
    """The target string IS the leak; printing it would republish it into CI logs."""
    leaks = ccd.symlink_leaks({"a/b": "/Users/someone/dev/private-repo/x"})
    assert "someone" not in leaks[0] and "private-repo" not in leaks[0], leaks


def test_symlink_windows_absolute_target_blocks():
    assert ccd.symlink_leaks({"a/b": r"C:\Users\someone\x"}), "drive-letter path must block"


def test_symlink_escaping_repo_blocks():
    leaks = ccd.symlink_leaks({"a/b": "../../../outside"})
    assert len(leaks) == 1 and "escapes-repo" in leaks[0]


def test_symlink_relative_in_repo_is_clean():
    assert ccd.symlink_leaks({".claude/skills": "../skills"}) == []


def test_symlink_lane_reads_the_real_tree():
    """Targets come from the git blob, so a link to a DIRECTORY is still seen --
    os.path.isfile() gating is what made this class invisible."""
    targets = ccd.symlink_targets(False)
    assert len(targets) > 50, f"expected the tree's symlinks, saw {len(targets)}"
    assert targets.get(".claude/skills") == "../skills", targets.get(".claude/skills")


def test_symlinks_excluded_from_the_text_scan():
    """open()ing a symlink follows it: it re-reads the destination and never
    examines the target string."""
    targets = ccd.symlink_targets(False)
    scanned = set(ccd.files_to_scan(False, frozenset(targets)))
    assert not (set(targets) & scanned), sorted(set(targets) & scanned)[:5]


def test_tree_has_no_absolute_symlinks():
    """The live invariant. 66 absolute targets were once published this way."""
    assert ccd.symlink_leaks(ccd.symlink_targets(False)) == []


# --------------------------------------------------------------------------
# Noise floor — the anti-rot assertion
# --------------------------------------------------------------------------

def test_current_tree_noise_floor():
    """The guard must be CLEAN on the real tree. If a new rule lands with false
    positives, this fails and the rule gets fixed or dropped -- rather than the
    whole guard getting bypassed."""
    r = subprocess.run([sys.executable, GUARD], capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, f"guard is not clean on the tracked tree:\n{r.stderr[:3000]}"


def test_guard_still_catches_a_planted_leak():
    """A clean tree must not mean a dead guard: prove it still fails on input."""
    line = "artifacts live in projects/pentest/20260709_zorbix_ext_vapt/"
    assert engagement_hits(line), "guard no longer detects a planted engagement path"


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
