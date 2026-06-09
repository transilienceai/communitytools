#!/usr/bin/env python3
"""Shared helpers for the pci-sss compliance tools.

Loaded by validate_catalog.py, applicability.py, citation_verify.py,
aggregate.py, and coverage_gate.py. Pure stdlib, deterministic.

The data contracts these helpers operate on are defined in
skills/pci-secure-software/reference/core/schema.md.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

# Repo root = three levels up from tools/pci-sss/_common.py
REPO = Path(__file__).resolve().parent.parent.parent

# Canonical locations
DEFAULT_CATALOG = REPO / "skills" / "pci-secure-software" / "reference" / "catalog" / "pci-sss-v2.0.json"
SOURCE_PDF = REPO / "PCI-Secure-Software-Standard-v2.0.pdf"

# Atomic Test Requirement id, e.g. 1-3.c, 4-1.7.6.c, C2-1.d, A1-1.a
ID_RE = re.compile(r"^([0-9]{1,2}|[A-D][0-9])-[0-9]+(\.[0-9]+){0,2}\.[a-z]$")

# Closed enums (mirror schema.md §9)
MODULES = {"core", "A", "B", "C", "D"}
TEST_METHODS = {"Examine", "Interview", "Observe", "Perform", "Test", "Verify"}
ANALYSIS_TYPES = {"documentation-only", "static", "dynamic", "static-and-or-dynamic", "research"}
POLARITIES = {"positive", "negative"}
EVIDENCE_TYPES = {"source_code", "documentation", "build_artifact", "dynamic_observation"}
VERDICT_STATUSES = {"MET", "NOT_MET", "PARTIALLY_MET", "NOT_APPLICABLE", "REQUIRES_MANUAL_REVIEW"}

# The closed AppContext vocabulary (mirror schema.md §2)
APP_CONTEXT_KEYS = {
    "account_data",
    "sensitive_mode",
    "random_for_sensitive_assets",
    "pts_poi_device",
    "public_network_interface",
    "is_sdk",
    "sred_approved",
}

# Negative-polarity detector. PCI SSS negative testing is phrased "Testing should
# include ... attempting to <do the forbidden/abusive thing>" (violate, bypass,
# circumvent, misuse, exceed, recover-after-deletion, etc.) — so any "attempt(ing) to"
# in a test requirement marks a negative test.
NEGATIVE_RE = re.compile(r"\battempt(?:ing|s)? to\b", re.IGNORECASE)


def load_catalog(path: Path | str = DEFAULT_CATALOG) -> dict:
    """Load the catalog JSON. Returns {'meta': {...}, 'test_requirements': [...]}."""
    p = Path(path)
    with p.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if "test_requirements" not in data or "meta" not in data:
        raise ValueError(f"{p}: catalog must have top-level 'meta' and 'test_requirements'")
    return data


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(path: Path | str) -> str:
    return sha256_bytes(Path(path).read_bytes())


def normalize_ws(s: str) -> str:
    """Collapse all runs of whitespace to a single space and lowercase.

    Used by the citation-verifier so that quoting drift (re-indentation,
    CRLF vs LF, case) does not cause false misses — while still requiring
    the substantive characters to be present at the cited location.
    """
    return re.sub(r"\s+", " ", (s or "")).strip().lower()


class AppContextError(ValueError):
    pass


def eval_applicability(node, ctx: dict) -> bool:
    """Evaluate an applicability AST against an AppContext (the 7 booleans).

    Grammar (closed): {"always": true} | {"ctx": k, "eq": bool}
                      | {"all": [...]} | {"any": [...]} | {"not": node}
    Raises AppContextError on any unknown ctx key or malformed node so the
    catalog validator can fail closed rather than silently mis-scoping.
    """
    if not isinstance(node, dict):
        raise AppContextError(f"applicability node must be an object, got {type(node).__name__}")
    if "always" in node:
        return bool(node["always"])
    if "ctx" in node:
        key = node["ctx"]
        if key not in APP_CONTEXT_KEYS:
            raise AppContextError(f"unknown AppContext key: {key!r}")
        if "eq" not in node:
            raise AppContextError(f"leaf for {key!r} missing 'eq'")
        return bool(ctx.get(key, False)) == bool(node["eq"])
    if "all" in node:
        return all(eval_applicability(c, ctx) for c in node["all"])
    if "any" in node:
        return any(eval_applicability(c, ctx) for c in node["any"])
    if "not" in node:
        return not eval_applicability(node["not"], ctx)
    raise AppContextError(f"malformed applicability node: {json.dumps(node)[:80]}")


def collect_ctx_keys(node, out: set) -> None:
    """Collect every ctx key referenced by an AST (for validation)."""
    if not isinstance(node, dict):
        return
    if "ctx" in node:
        out.add(node["ctx"])
    for k in ("all", "any"):
        if k in node:
            for c in node[k]:
                collect_ctx_keys(c, out)
    if "not" in node:
        collect_ctx_keys(node["not"], out)
