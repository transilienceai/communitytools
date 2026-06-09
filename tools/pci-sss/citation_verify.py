#!/usr/bin/env python3
"""Deterministic citation verifier — the anti-hallucination backstop.

For every RequirementVerdict in an engagement's artifacts/validated/ tree it:
  (a) resolves control_ref (framework == PCI_SSS_v2.0, version == 2.0,
      test_requirement_id present in the pinned catalog),
  (b) enforces the status/evidence invariants from schema.md §3,
  (c) greps every Evidence quote at its cited file:line (+/-5 lines,
      whitespace-normalized) and checks the file's sha256.

Any failure QUARANTINES the verdict: its status is rewritten to
REQUIRES_MANUAL_REVIEW, citation_verified=false, and the original is
appended to quarantined.json. A MET/NOT_MET cannot survive an
unverifiable citation. Deterministic, no LLM, no retries, fails closed.

Hard rules (for any operator/agent invoking this): never re-word a quote
to make it match, never adjust a framework version, never edit a
test_requirement_id to resolve it, never remove a verdict from quarantine.

Usage:
  python3 tools/pci-sss/citation_verify.py --output-dir DIR [--catalog PATH] [--source-root DIR]

Exit 0 if nothing was quarantined, 1 if one or more verdicts were quarantined.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _common import load_catalog, normalize_ws, sha256_file

WINDOW = 5  # lines of slack around the cited line


def _resolve_source(source_file: str, source_root: Path | None) -> Path | None:
    p = Path(source_file)
    if p.is_file():
        return p
    if source_root is not None:
        cand = source_root / source_file
        if cand.is_file():
            return cand
    return None


def verify_evidence(ev: dict, source_root: Path | None) -> list[str]:
    reasons: list[str] = []
    src = _resolve_source(ev.get("source_file", ""), source_root)
    if src is None:
        return [f"source_file missing: {ev.get('source_file')!r}"]
    declared_sha = ev.get("sha256")
    if declared_sha:
        try:
            if sha256_file(src) != declared_sha:
                reasons.append(f"sha256 mismatch for {src}")
        except OSError as e:
            reasons.append(f"cannot hash {src}: {e}")
    needle = normalize_ws(ev.get("quoted_text", ""))
    if not needle:
        return reasons + ["empty quoted_text"]
    try:
        lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return reasons + [f"cannot read {src}: {e}"]
    lineno = ev.get("source_lineno")
    if isinstance(lineno, int) and lineno > 0:
        lo = max(0, lineno - 1 - WINDOW)
        hi = min(len(lines), lineno - 1 + WINDOW + 1)
        window = normalize_ws(" ".join(lines[lo:hi]))
    else:
        window = normalize_ws(" ".join(lines))  # whole-file evidence (lineno null)
    if needle not in window:
        reasons.append(f"quoted_text not found at {ev.get('source_file')}:{lineno} +/-{WINDOW}")
    return reasons


AFFIRMATIVE = ("MET", "NOT_MET", "PARTIALLY_MET")


def verify_verdict(v: dict, catalog_by_id: dict, source_root: Path | None) -> list[str]:
    """Return a list of quarantine reasons (empty == passes).

    Beyond grepping cited quotes, this re-enforces the kill rules DETERMINISTICALLY
    from the recorded numbers + the pinned catalog — it does NOT trust the writer
    agent's status. So a fabricated affirmative verdict (dynamic MET with no run,
    or one that survived majority refutation) is quarantined here even if the
    writer recorded MET.
    """
    reasons: list[str] = []
    cr = v.get("control_ref") or {}
    if cr.get("framework") != "PCI_SSS_v2.0" or cr.get("version") != "2.0":
        reasons.append("control_ref framework/version != PCI_SSS_v2.0/2.0")
    trid = v.get("test_requirement_id") or cr.get("test_requirement_id")
    cat = catalog_by_id.get(trid)
    if cat is None:
        reasons.append(f"test_requirement_id {trid!r} not in pinned catalog")

    status = v.get("status")
    evidence = v.get("evidence") or []
    appl_ev = v.get("applicability_evidence") or []

    # (1) evidence-presence invariant for EVERY affirmative status (incl. PARTIALLY_MET)
    if status in AFFIRMATIVE and len(evidence) < 1:
        reasons.append(f"{status} with zero evidence")
    if status == "NOT_APPLICABLE" and len(appl_ev) < 1:
        reasons.append("NOT_APPLICABLE without applicability_evidence")

    # (2) deterministic kill-rule re-enforcement (independent of the writer's status)
    if status in AFFIRMATIVE:
        votes = v.get("votes")
        refuted = v.get("refuted_count")
        if isinstance(votes, int) and isinstance(refuted, int) and votes > 0 and refuted >= (votes // 2 + 1):
            reasons.append(f"{status} survived majority refutation (refuted {refuted} of {votes})")
        if status == "MET" and cat and cat.get("analysis_type") == "dynamic":
            kinds = {(e or {}).get("evidence_type") for e in evidence}
            if "dynamic_observation" not in kinds:
                reasons.append("MET on a dynamic requirement without a dynamic_observation evidence item")
        if status == "MET" and v.get("dynamic_blocked") is True:
            reasons.append("MET on a dynamic_blocked requirement (no running instance was in scope)")

    # REQUIRES_MANUAL_REVIEW may carry zero evidence; still grep any it does cite.
    for ev in evidence + appl_ev:
        reasons.extend(verify_evidence(ev, source_root))
    return reasons


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", required=True, help="engagement OUTPUT_DIR")
    ap.add_argument("--catalog", default=None)
    ap.add_argument("--source-root", default=None,
                    help="root to resolve relative evidence source_file paths against")
    args = ap.parse_args()

    out = Path(args.output_dir)
    validated_dir = out / "artifacts" / "validated"
    if not validated_dir.is_dir():
        print(f"citation_verify: no {validated_dir}; nothing to verify", file=sys.stderr)
        return 0
    catalog = load_catalog(args.catalog) if args.catalog else load_catalog()
    catalog_by_id = {r["id"]: r for r in catalog["test_requirements"]}
    source_root = Path(args.source_root) if args.source_root else None

    quarantined: list[dict] = []
    n_passed = 0
    for jf in sorted(validated_dir.glob("*.json")):
        try:
            v = json.loads(jf.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            quarantined.append({"file": str(jf), "reasons": [f"unparseable verdict: {e}"]})
            continue
        reasons = verify_verdict(v, catalog_by_id, source_root)
        v.setdefault("verification", {})
        if reasons:
            original_status = v.get("status")
            v["verification"]["citation_verifier"] = "failed"
            v["citation_verified"] = False
            v["downgraded_from"] = v.get("downgraded_from") or original_status
            v["status"] = "REQUIRES_MANUAL_REVIEW"
            v["why"] = (v.get("why", "") + f" [citation_verify quarantine: {'; '.join(reasons)}]").strip()
            jf.write_text(json.dumps(v, ensure_ascii=False, indent=2), encoding="utf-8")
            quarantined.append({"test_requirement_id": v.get("test_requirement_id"),
                                "file": str(jf), "reasons": reasons,
                                "downgraded_from": v["downgraded_from"]})
        else:
            v["verification"]["citation_verifier"] = "passed"
            v["citation_verified"] = True
            jf.write_text(json.dumps(v, ensure_ascii=False, indent=2), encoding="utf-8")
            n_passed += 1

    qpath = out / "artifacts" / "quarantined.json"
    qpath.parent.mkdir(parents=True, exist_ok=True)
    qpath.write_text(json.dumps(quarantined, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"citation_verify: {n_passed} passed, {len(quarantined)} quarantined -> {qpath}")
    return 1 if quarantined else 0


if __name__ == "__main__":
    sys.exit(main())
