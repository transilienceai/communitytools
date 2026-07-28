#!/usr/bin/env python3
"""Every asset a tool, test or doc depends on must actually be in the repository.

WHY THIS TEST EXISTS
--------------------
The blanket `*.json` rule in .gitignore has now hidden four separate source files:
coverage-matrix.json (the whole coverage catalogue), report-data-schema.json (the
render contract), example-report-data.json (linked twice from a SKILL.md and read by
a test), and the OCI posture catalogue. Each was present on an author's disk and
absent from a fresh checkout, so the tests passed locally and failed only in CI —
or, worse, passed in CI while silently assessing nothing.

The failure is invisible by construction: a validator that globs for catalogues finds
zero and reports success. So the guard cannot be "remember to allowlist it"; it has to
be a test that fails on the untracked file itself.

Run: python3 tools/test_tracked_assets.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))

# Globs whose matches are load-bearing source data, not engagement output. A file
# matching one of these must be tracked by git.
REQUIRED_TRACKED = (
    "skills/**/catalog/*.json",
    "skills/**/reference/catalog/*.json",
    "skills/coordination/reference/coverage-matrix.json",
    "skills/transilience-report-style/reference/report-data-schema.json",
    "skills/transilience-report-style/reference/example-report-data.json",
)

# Intentionally untracked: documented as intermediate build input or a third-party
# document we may not redistribute. Listed explicitly so an exemption is a decision.
KNOWN_UNTRACKED = (
    "skills/pci-secure-software/reference/catalog/parts/",   # intermediate; merged file is tracked
    "formats/certin-audit-metadata/",                        # third-party workbook, TLP:AMBER
)


def _ignored(rels: list) -> set:
    """Which of these paths git would refuse to track.

    The defect is being IGNORED, not being uncommitted: a correctly-allowlisted file
    that simply has not been committed yet is fine, whereas an ignored one can never
    reach a checkout no matter how many times it is added. `git ls-files` cannot tell
    those apart, so ask check-ignore instead.
    """
    if not rels:
        return set()
    p = subprocess.run(["git", "-C", REPO, "check-ignore", "--stdin"],
                       input="\n".join(rels), capture_output=True, text=True)
    return {line.strip() for line in p.stdout.splitlines() if line.strip()}


def _exempt(rel: str) -> bool:
    return any(rel.startswith(p) for p in KNOWN_UNTRACKED)


class TestLoadBearingAssetsAreTracked(unittest.TestCase):
    def test_required_globs_are_trackable(self):
        import glob
        cands = []
        for pattern in REQUIRED_TRACKED:
            for path in glob.glob(os.path.join(REPO, pattern), recursive=True):
                rel = os.path.relpath(path, REPO)
                if not _exempt(rel):
                    cands.append(rel)
        missing = sorted(_ignored(cands))
        self.assertEqual(
            missing, [],
            "on disk but NOT tracked by git — these vanish from a fresh checkout, so any tool "
            "that globs for them finds nothing and reports success:\n  "
            + "\n  ".join(sorted(missing))
            + "\nAdd a `!` allowlist line to .gitignore (the blanket *.json rule is what hides them).")

    def test_no_posture_catalog_is_invisible_to_ci(self):
        """The specific regression: a catalogue one directory deeper than the
        original allowlist pattern, which matched `reference/catalog/` only."""
        import glob
        found = glob.glob(os.path.join(
            REPO, "skills/cloud-containers/reference/posture/catalog/*.json"))
        self.assertTrue(found, "no posture catalogue on disk — did the path move?")
        rels = [os.path.relpath(p, REPO) for p in found]
        self.assertEqual(sorted(_ignored(rels)), [],
                         "gitignored; CI would validate zero catalogues and report success")


class TestReferencedFilesExist(unittest.TestCase):
    """A doc or tool citing a path that no checkout has is the same bug wearing a hat."""

    def test_skill_md_relative_links_resolve(self):
        import glob
        import re
        bad = []
        link = re.compile(r"\[[^\]]+\]\((?!https?://|#)([^)]+)\)")
        for md in glob.glob(os.path.join(REPO, "skills/*/SKILL.md")):
            base = os.path.dirname(md)
            with open(md, encoding="utf-8") as fh:
                for m in link.finditer(fh.read()):
                    target = m.group(1).split("#", 1)[0]
                    if not target or "..." in target:
                        continue    # prose ellipsis such as `reference/...`, not a link
                    if not os.path.exists(os.path.normpath(os.path.join(base, target))):
                        bad.append(f"{os.path.relpath(md, REPO)} -> {target}")
        self.assertEqual(sorted(bad), [], "SKILL.md links that do not resolve:\n  " + "\n  ".join(sorted(bad)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
