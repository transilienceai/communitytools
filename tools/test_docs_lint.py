#!/usr/bin/env python3
"""Docs-lint: the normative docs describe the NEW interleaved per-finding
validate -> cure/drop model, and no longer describe the retired one-shot
P5 / "Assurance & Gaps" model.

Stdlib only. Run: python3 tools/test_docs_lint.py

Two kinds of assertion:
  * ABSENT  — the retired string "Assurance & Gaps" must not appear in any
              doc we migrated NOR in tools/report_data_build.py (the report
              assembler no longer emits a gaps section).
  * PRESENT — each new-model phrase must appear in the doc that owns it
              (interleaved per-finding validation, coverage-by-VALID, the
              `dropped/` terminal state, the honest "100% only on replay"
              determinism statement, and the cure lane).

Substrings are the exact text placed in the docs, so this test is true.
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The retired framing that must be gone everywhere we touched.
FORBIDDEN = "Assurance & Gaps"

# Docs migrated to the new model (+ the report assembler) — none may mention
# the retired gaps section.
ABSENT_FILES = [
    "skills/coordination/reference/VALIDATION.md",
    "skills/coordination/reference/output-discipline.md",
    "skills/coordination/reference/role-matrix.md",
    "skills/coordination/reference/validator-role.md",
    "skills/coordination/reference/coverage-matrix.md",
    "skills/coordination/SKILL.md",
    "skills/pentest-engagement/SKILL.md",
    "skills/coordination/reference/coordinator.md",
    "skills/coordination/reference/spawning-recipes.md",
    "skills/hackerone/SKILL.md",
    "tools/report_data_build.py",
]

# New-model phrases that MUST be present, keyed by the doc that owns each.
PRESENT = [
    # Interleaved, strict per-finding validation is the headline.
    ("skills/coordination/reference/VALIDATION.md", "interleaved, strict per-finding"),
    ("skills/coordination/reference/VALIDATION.md", "Drop-entirely policy"),
    ("skills/coordination/reference/VALIDATION.md", "dropped/"),
    ("skills/coordination/reference/validator-role.md", "interleaved, strict per-finding"),
    ("skills/coordination/reference/validator-role.md", "cure lane"),
    ("skills/coordination/reference/role-matrix.md", "Interleaved — the instant INTEGRATE"),
    ("skills/coordination/reference/role-matrix.md", "Executor — cure"),
    ("skills/coordination/reference/coordinator.md", "interleaved"),
    ("skills/coordination/reference/spawning-recipes.md", "Executor — cure"),
    ("skills/coordination/SKILL.md", "interleaved"),
    # Coverage-by-VALID + the genuine-negative distinction.
    ("skills/coordination/reference/coverage-matrix.md", "coverage-by-VALID"),
    ("skills/coordination/reference/coverage-matrix.md", "covered_negative"),
    ("skills/coordination/SKILL.md", "coverage-by-VALID"),
    # New OUTPUT_DIR tree entries.
    ("skills/coordination/reference/output-discipline.md", "dropped/"),
    ("skills/coordination/reference/output-discipline.md", "nvd-cache/"),
    ("skills/coordination/reference/output-discipline.md", "kev-snapshot.json"),
    ("skills/coordination/reference/output-discipline.md", "validation-cache/"),
    # Single-stage Assess + honest determinism model.
    ("skills/pentest-engagement/SKILL.md", "drop-entirely"),
    ("skills/pentest-engagement/SKILL.md", "100% only on replay"),
    # hackerone reconciled (no retired inline-P5 phrasing).
    ("skills/hackerone/SKILL.md", "interleaved per-finding"),
    # Activity & source-IP logging (deterministic audit artifacts).
    ("skills/coordination/reference/output-discipline.md", "tool-invocations.jsonl"),
    ("skills/coordination/reference/output-discipline.md", "source-ips.jsonl"),
    ("skills/coordination/reference/principles.md", "source-ips.jsonl"),
    ("skills/coordination/reference/principles.md", "register every egress vantage"),
    ("skills/coordination/reference/preflight-checklist.md", "Source vantage recorded"),
    ("skills/coordination/reference/executor-role.md", "provision_vantage.sh"),
    ("skills/coordination/reference/executor-role.md", "hook"),
    ("formats/logs.md", "tool-invocations.jsonl"),
    ("formats/logs.md", "source-ips.jsonl"),
    ("CLAUDE.md", "Activity & source-IP logging"),
]


def _read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
        return fh.read()


def main():
    failures = []

    for rel in ABSENT_FILES:
        try:
            text = _read(rel)
        except FileNotFoundError:
            failures.append(f"ABSENT-check target missing: {rel}")
            continue
        if FORBIDDEN in text:
            failures.append(f"{rel}: retired string {FORBIDDEN!r} still present")

    for rel, needle in PRESENT:
        try:
            text = _read(rel)
        except FileNotFoundError:
            failures.append(f"PRESENT-check target missing: {rel}")
            continue
        if needle not in text:
            failures.append(f"{rel}: expected new-model string {needle!r} not found")

    total = len(ABSENT_FILES) + len(PRESENT)
    if failures:
        print(f"FAIL ({len(failures)}/{total} assertions failed):", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"OK: docs-lint passed "
          f"({len(ABSENT_FILES)} absent-checks + {len(PRESENT)} present-checks).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
