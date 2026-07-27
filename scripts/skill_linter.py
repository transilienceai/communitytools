#!/usr/bin/env python3
"""Skill linter.

Enforces the structural rules for skills/. Run in CI on every PR.

Checks:
  1. Every SKILL.md ≤ 150 lines.
  2. Every reference/*.md ≤ 200 lines (scenarios/*.md ≤ 400 lines).
  3. Every SKILL.md has YAML frontmatter with `name` + `description`.
  4. Single-owner: brute-force / output-discipline / env-reader / skill-update rules each
     appear in at most one canonical file (allowlist).
  5. No DO NOT / MUST NOT / NEVER outside an `## Anti-Patterns` section. Configurable
     allowlist for hard-contract files (validator/role-matrix/git-conventions/etc).
  6. Every [link](path) in a markdown file resolves (relative or absolute under repo).
  7. De-specialization: no challenge identifiers (HackTheBox/HTB/Vulnlab/XBEN/lab-IPs/
     preserved flags) outside `skills/hackthebox/` or `skills/INDEX.md`.
  8. Orphans: every reference file is linked from at least one other file in skills/.

Exit 0 if clean. Exit 1 with a list of violations otherwise.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKILLS = REPO / "skills"

# Caps
SKILL_MD_CAP = 150
REFERENCE_CAP = 200
SCENARIO_CAP = 400
README_CAP = 100
PRINCIPLES_CAP = 150

# Single-owner allowlist — each rule lives in exactly these files.
SINGLE_OWNER = {
    "brute-force-rule": [
        SKILLS / "coordination" / "SKILL.md",
        SKILLS / "coordination" / "reference" / "principles.md",
    ],
    "env-reader-rule": [
        SKILLS / "coordination" / "reference" / "credential-loading.md",
    ],
    "output-dir-rule": [
        SKILLS / "coordination" / "reference" / "output-discipline.md",
    ],
    "skill-update-procedure": [
        SKILLS / "skill-update" / "SKILL.md",
    ],
}

# Files where DO NOT / MUST NOT / NEVER are legitimate hard-contract statements.
# Outside this set, negative rules must live inside an `## Anti-Patterns` section.
NEGATIVE_RULE_ALLOWLIST = {
    SKILLS / "coordination" / "SKILL.md",  # Rule 1 forbids AskUserQuestion
    SKILLS / "coordination" / "reference" / "role-matrix.md",
    SKILLS / "coordination" / "reference" / "context-injection.md",
    SKILLS / "coordination" / "reference" / "credential-loading.md",
    SKILLS / "coordination" / "reference" / "GIT_CONVENTIONS.md",
    SKILLS / "coordination" / "reference" / "validator-role.md",
    SKILLS / "coordination" / "reference" / "VALIDATION.md",
    SKILLS / "coordination" / "reference" / "skeptic-role.md",
    SKILLS / "coordination" / "reference" / "coordinator.md",
    SKILLS / "coordination" / "reference" / "orchestrator.md",
    SKILLS / "coordination" / "reference" / "spawning-recipes.md",
    SKILLS / "coordination" / "reference" / "preflight-checklist.md",
    SKILLS / "skill-update" / "SKILL.md",  # rules describe themselves
    SKILLS / "skill-prune" / "SKILL.md",
    SKILLS / "firewall-review",  # whole subtree — agent contracts are hard-contract by design
    SKILLS / "pci-secure-software",  # whole subtree — compliance agent/anti-hallucination contracts are hard-contract by design
    SKILLS / "github-workflow" / "SKILL.md",  # git-policy hard rules
}

# Files allowed to mention platform names cross-skill (orchestrator/coordinator dispatch).
DESPEC_FILE_ALLOWLIST = {
    SKILLS / "INDEX.md",
    SKILLS / "coordination" / "reference" / "orchestrator.md",
    SKILLS / "coordination" / "reference" / "coordinator.md",
    SKILLS / "coordination" / "reference" / "ATTACK_INDEX.md",
}

# Forbidden tokens repo-wide except in the platform skill that owns each.
DESPEC_PATTERNS = [
    (re.compile(r"\b(HackTheBox|hackthebox)\b"), "platform name", SKILLS / "hackthebox"),
    (re.compile(r"\bHTB\b"), "platform name", SKILLS / "hackthebox"),
    (re.compile(r"\bVulnlab\b"), "lab platform", None),
    (re.compile(r"\bXBEN-\d+-\d+\b"), "challenge id", None),
    (re.compile(r"\b10\.(?:10|129)\.\d+\.\d+\b"), "lab IP", SKILLS / "hackthebox"),
]

NEG_RE = re.compile(r"\b(DO NOT|MUST NOT|NEVER)\b")
LINK_RE = re.compile(r"\[(?P<text>[^\]]+)\]\((?P<url>[^)]+)\)")


def is_under(path: Path, prefix: Path | None) -> bool:
    if prefix is None:
        return False
    try:
        path.relative_to(prefix)
        return True
    except ValueError:
        return False


def in_negative_allowlist(path: Path) -> bool:
    for allowed in NEGATIVE_RULE_ALLOWLIST:
        if path == allowed or is_under(path, allowed):
            return True
    return False


def check_caps(violations: list[str]) -> None:
    for md in SKILLS.rglob("*.md"):
        lines = sum(1 for _ in md.open())
        rel = md.relative_to(REPO)
        if md.name == "SKILL.md" and lines > SKILL_MD_CAP:
            violations.append(f"CAP: {rel} = {lines} lines (> {SKILL_MD_CAP} for SKILL.md)")
        elif "/scenarios/" in str(md) and lines > SCENARIO_CAP:
            violations.append(f"CAP: {rel} = {lines} lines (> {SCENARIO_CAP} for scenarios)")
        elif "/reference/" in str(md) and "/scenarios/" not in str(md) and lines > REFERENCE_CAP:
            violations.append(f"CAP: {rel} = {lines} lines (> {REFERENCE_CAP} for reference/)")


def check_frontmatter(violations: list[str]) -> None:
    for skill in SKILLS.rglob("SKILL.md"):
        text = skill.read_text()
        if not text.startswith("---\n"):
            violations.append(f"FRONTMATTER: {skill.relative_to(REPO)} missing YAML frontmatter")
            continue
        end = text.find("\n---", 4)
        if end < 0:
            violations.append(f"FRONTMATTER: {skill.relative_to(REPO)} unterminated frontmatter")
            continue
        block = text[4:end]
        if "name:" not in block:
            violations.append(f"FRONTMATTER: {skill.relative_to(REPO)} missing `name`")
        if "description:" not in block:
            violations.append(f"FRONTMATTER: {skill.relative_to(REPO)} missing `description`")


def check_negatives(violations: list[str]) -> None:
    for md in SKILLS.rglob("*.md"):
        if in_negative_allowlist(md):
            continue
        in_anti = False
        in_code = False
        for n, line in enumerate(md.read_text().splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("```"):
                in_code = not in_code
                continue
            if in_code:
                continue
            if stripped.startswith("## ") or stripped.startswith("### "):
                in_anti = "Anti-Pattern" in stripped or "anti-pattern" in stripped.lower()
            if not in_anti and NEG_RE.search(line):
                rel = md.relative_to(REPO)
                violations.append(f"NEGATIVE: {rel}:{n}: {line.strip()[:120]}")


def check_despecialization(violations: list[str]) -> None:
    for md in SKILLS.rglob("*.md"):
        if md in DESPEC_FILE_ALLOWLIST:
            continue
        for line_no, line in enumerate(md.read_text().splitlines(), 1):
            for pattern, label, allowed_root in DESPEC_PATTERNS:
                if pattern.search(line):
                    if allowed_root and is_under(md, allowed_root):
                        continue
                    rel = md.relative_to(REPO)
                    violations.append(f"DESPEC: {rel}:{line_no} [{label}]: {line.strip()[:120]}")
                    break


def check_single_owner(violations: list[str]) -> None:
    # Heuristic: search for canonical *prohibition prose* — not technique-name uses of "brute-force".
    # The single-owner rule applies only to cross-cutting *prohibitions* that should live in one place.
    triggers = {
        "brute-force-rule": re.compile(
            r"\bno (?:online )?brute[- ]force\b|brute[- ]force is (?:always )?(?:wrong|forbidden|prohibited)",
            re.IGNORECASE,
        ),
        "env-reader-rule": re.compile(
            r"(?:always|MUST) use (?:`?python3 )?(?:tools/)?env-reader\.py",
            re.IGNORECASE,
        ),
        "output-dir-rule": re.compile(
            r"NEVER write any file to (?:the )?(?:project|repo) root",
            re.IGNORECASE,
        ),
    }
    for owner, pat in triggers.items():
        allowed = SINGLE_OWNER[owner]
        for md in SKILLS.rglob("*.md"):
            if any(md == a for a in allowed):
                continue
            for line_no, line in enumerate(md.read_text().splitlines(), 1):
                if pat.search(line):
                    rel = md.relative_to(REPO)
                    violations.append(f"SINGLE_OWNER ({owner}): {rel}:{line_no} → move to {allowed[0].relative_to(REPO)}")
                    break


def check_links(violations: list[str]) -> None:
    for md in SKILLS.rglob("*.md"):
        in_code = False
        for line in md.read_text().splitlines():
            stripped = line.lstrip()
            if stripped.startswith("```"):
                in_code = not in_code
                continue
            if in_code:
                continue
            for match in LINK_RE.finditer(line):
                url = match.group("url").split("#", 1)[0].strip()
                if not url or url.startswith(("http://", "https://", "mailto:", "javascript:", "data:")):
                    continue
                # Skip link targets that are obviously not file paths (e.g. `[1]`, `[2]`, footnote refs).
                if url.isdigit() or len(url) <= 2:
                    continue
                # Skip URLs containing characters that can't appear in real file paths
                if any(c in url for c in ("`", "{", " ", "<", ">")):
                    continue
                if url.startswith("/"):
                    target = REPO / url.lstrip("/")
                else:
                    target = (md.parent / url).resolve()
                if not target.exists():
                    rel = md.relative_to(REPO)
                    violations.append(f"LINK: {rel} → {url} (not found)")


def check_orphans(violations: list[str]) -> None:
    """Every reference file should be linked by at least one other file in skills/."""
    referenced: set[Path] = set()
    for md in SKILLS.rglob("*.md"):
        for match in LINK_RE.finditer(md.read_text()):
            url = match.group("url").split("#", 1)[0].strip()
            if not url or url.startswith(("http://", "https://", "mailto:")):
                continue
            if url.startswith("/"):
                target = (REPO / url.lstrip("/")).resolve()
            else:
                target = (md.parent / url).resolve()
            referenced.add(target)
    for md in SKILLS.rglob("*/reference/**/*.md"):
        if md.resolve() not in referenced:
            rel = md.relative_to(REPO)
            violations.append(f"ORPHAN: {rel} not linked from any other file")


VIOLATION_RE = re.compile(r"^(?P<code>[A-Z_]+)(?: \([^)]*\))?: (?P<rest>.*)$")


def parse_violation(v: str) -> dict:
    """Split a human violation line into {code, file, line, detail}.

    The workflow gates on the DELTA between two runs, so every field here must be
    stable across runs: an unstable detail string would read as a new violation.
    """
    m = VIOLATION_RE.match(v)
    code, rest = (m.group("code"), m.group("rest")) if m else ("UNKNOWN", v)
    # Every emitter puts the path first, optionally as `path:line`, then a space.
    # CAP alone continues with ` = N lines`, so split on whitespace rather than
    # on ": " — otherwise CAP's whole message lands in `file`.
    token, _, detail = rest.partition(" ")
    token = token.rstrip(":")
    head, sep, tail = token.rpartition(":")
    if sep and tail.isdigit():
        path, lineno = head, int(tail)
    else:
        path, lineno = token, None
    return {"code": code, "file": path.strip(), "line": lineno,
            "detail": detail.strip() or rest.strip()}


def _arg_value(flag: str) -> str | None:
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return None


def violation_key(v: dict) -> str:
    """Stable identity of a violation across two runs. Mirrors violationKey() in
    .claude/workflows/lib/wf-helpers.mjs — same fields, same order, same truncation."""
    return "|".join([v["code"], v["file"], str(v["line"] or 0), (v["detail"] or "")[:60]])


def emit_delta(violations: list[str], baseline_path: str) -> int:
    """Emit ONLY what this run introduced, relative to a stored baseline.

    The full payload is ~280 KB — 571 violations across 808 files. Relaying that
    through an agent is slow and, worse, lossy: a model asked to echo a quarter of
    a megabyte of JSON verbatim will truncate or paraphrase, silently corrupting
    the very baseline the gate depends on. So the DELTA is computed here, in the
    tool, and the agent relays a payload that is normally empty.
    """
    parsed = sorted((parse_violation(v) for v in violations),
                    key=lambda d: (d["code"], d["file"], d["line"] or 0, d["detail"]))
    try:
        with open(baseline_path, encoding="utf-8") as fh:
            base = json.load(fh)
        before = set(base.get("keys", []))
        ok = True
    except (OSError, ValueError):
        before, ok = set(), False

    now = {violation_key(v): v for v in parsed}
    introduced = [v for k, v in now.items() if k not in before]
    resolved = sorted(before - set(now))
    print(json.dumps({
        "tool": "skill_linter", "schema": 1, "mode": "delta",
        "baseline_ok": ok, "baseline_path": baseline_path,
        "baseline_count": len(before), "after_count": len(now),
        "introduced": introduced,
        "introduced_count": len(introduced), "resolved_count": len(resolved),
        "regressed": len(introduced) > 0,
    }, indent=2))
    return 0


def write_baseline(violations: list[str], path: str) -> int:
    """Store the violation KEY SET for a later --delta run. Keys only: the workflow
    needs identity to compute a delta, never the prose."""
    parsed = [parse_violation(v) for v in violations]
    keys = sorted(violation_key(v) for v in parsed)
    directory = Path(path).parent
    directory.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"tool": "skill_linter", "schema": 1, "keys": keys}, fh, indent=2)
    caps = {"SKILL.md": SKILL_MD_CAP, "reference": REFERENCE_CAP, "scenario": SCENARIO_CAP,
            "README.md": README_CAP, "principles": PRINCIPLES_CAP}
    print(json.dumps({"tool": "skill_linter", "schema": 1, "mode": "baseline",
                      "baseline_path": path, "count": len(keys), "caps": caps}, indent=2))
    return 0


def emit_json(violations: list[str]) -> int:
    """Machine-readable payload for `.claude/workflows/skill-update.js`.

    Always exits 0: the JSON *is* the result, and the relay agent must not have to
    reason about exit codes. The human mode keeps exit 1 so CI is unaffected.
    Sorted throughout, so an unchanged tree produces byte-identical output.
    """
    files = []
    for md in sorted(SKILLS.rglob("*.md")):
        rel = str(md.relative_to(REPO))
        text = md.read_text()
        lines = text.splitlines()
        if md.name == "SKILL.md":
            cap = SKILL_MD_CAP
        elif "/scenarios/" in str(md):
            cap = SCENARIO_CAP
        elif "/reference/" in str(md):
            cap = REFERENCE_CAP
        else:
            cap = None
        entry = {"path": rel, "lines": len(lines), "cap": cap,
                 "kind": md.name if md.name in ("SKILL.md", "README.md") else "reference",
                 "has_anti_patterns": any(
                     l.startswith(("## ", "### ")) and "anti-pattern" in l.lower() for l in lines)}
        if md.name == "SKILL.md" and text.startswith("---\n"):
            end = text.find("\n---", 4)
            if end > 0:
                fm = {}
                for fl in text[4:end].splitlines():
                    k, s, v = fl.partition(":")
                    if s and not k.startswith(" "):
                        fm[k.strip()] = v.strip()
                entry["frontmatter"] = {
                    "name": fm.get("name", ""), "description": fm.get("description", ""),
                    "name_len": len(fm.get("name", "")),
                    "description_len": len(fm.get("description", ""))}
        files.append(entry)

    parsed = sorted((parse_violation(v) for v in violations),
                    key=lambda d: (d["code"], d["file"], d["line"] or 0, d["detail"]))
    by_code: dict[str, int] = {}
    for p in parsed:
        by_code[p["code"]] = by_code.get(p["code"], 0) + 1

    print(json.dumps({
        "tool": "skill_linter", "schema": 1, "root": "skills",
        "exit_code_equivalent": 1 if violations else 0,
        "caps": {"SKILL.md": SKILL_MD_CAP, "reference": REFERENCE_CAP,
                 "scenario": SCENARIO_CAP, "README.md": README_CAP,
                 "principles": PRINCIPLES_CAP},
        "counts": {"files": len(files), "violations": len(parsed),
                   "by_code": dict(sorted(by_code.items()))},
        "violations": parsed,
        "files": files,
    }, indent=2))
    return 0


def main() -> int:
    violations: list[str] = []
    check_caps(violations)
    check_frontmatter(violations)
    check_negatives(violations)
    check_despecialization(violations)
    check_single_owner(violations)
    check_links(violations)
    # Orphan check disabled by default — existing reference files predate the linter
    # and many resource lists are intentionally standalone. Enable when ready:
    #   --check-orphans
    # --json always includes it: the workflow gates on the delta, so pre-existing
    # orphans never block, while a NEWLY orphaned file does.
    if "--check-orphans" in sys.argv or "--json" in sys.argv \
            or "--write-baseline" in sys.argv or "--delta" in sys.argv:
        check_orphans(violations)

    baseline_out = _arg_value("--write-baseline")
    if baseline_out:
        return write_baseline(violations, baseline_out)
    delta_in = _arg_value("--delta")
    if delta_in:
        return emit_delta(violations, delta_in)
    if "--json" in sys.argv:
        return emit_json(violations)

    if violations:
        print(f"skill_linter: {len(violations)} violation(s)")
        for v in violations[:200]:
            print(f"  {v}")
        if len(violations) > 200:
            print(f"  ... and {len(violations) - 200} more")
        return 1
    print("skill_linter: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
