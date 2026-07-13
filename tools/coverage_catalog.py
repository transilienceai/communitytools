#!/usr/bin/env python3
"""Shared helpers for the attack-class coverage tools.

Loaded by validate_catalog.py, enumerate_cells.py, coverage_gate.py, and
network_coverage_map.py. Pure stdlib, deterministic.

The catalog (skills/coordination/reference/coverage-matrix.json) is the machine
source of truth; the markdown companion (coverage-matrix.md) is human-facing and
kept in class_id-parity by validate_catalog.py.

Applicability predicate DSL (closed grammar), evaluated against a *set of flags*
present on a surface unit / listener / asset:

    {"always": true}
    {"any_flag":  ["a", "b"]}     # the flag set intersects the list
    {"all_flags": ["a", "b"]}     # the flag set is a superset of the list
    {"not": <node>}

Every leaf flag must be one of the 20 vocabulary flags (14 agent-set + 6
code-derived); eval/collect raise CatalogError on an unknown flag or malformed
node so the validator fails closed rather than silently mis-scoping.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# Repo root = two levels up from tools/coverage_catalog.py
REPO = Path(__file__).resolve().parent.parent

DEFAULT_CATALOG = REPO / "skills" / "coordination" / "reference" / "coverage-matrix.json"
DEFAULT_MD = REPO / "skills" / "coordination" / "reference" / "coverage-matrix.md"

# 14 agent-set flags (recon-justifiable; an agent may set these on a unit)
AGENT_FLAGS = {
    "object_by_id",
    "json_body",
    "role_verb_gated",
    "sensitive_flow",
    "server_fetched_url",
    "input_sink",
    "workflow",
    "deser_or_ci",
    "inbound_webhook",
    "id_keyed_unauth",
    "stored_field",
    "auth_surface",
    "consumes_upstream",
    "static_js_or_repo",
}
# 6 code-derived flags (computed by enumerate_cells.py; agent-unfabricatable)
DERIVED_FLAGS = {
    "http_listener",
    "tls_listener",
    "version_fingerprinted",
    "has_api",
    "is_apex",
    "serves_js",
}
ALL_FLAGS = AGENT_FLAGS | DERIVED_FLAGS

SCOPES = {"unit", "host", "asset"}
NEGATIVE_KINDS = {"active_probe", "reachability", "none"}
KEY_BY_FOR_SCOPE = {"unit": "unit_id", "host": "listener", "asset": "asset_tag"}

# Table-scoped class_id extractor for coverage-matrix.md: only a backtick-wrapped
# FIRST cell of a markdown table row, e.g. "| `API1-BOLA` | API'23 | ...". This
# deliberately ignores class_id mentions in prose or the fenced-JSON example.
_MD_ROW_RE = re.compile(r"^\|\s*`([A-Z0-9][A-Z0-9-]*)`\s*\|")


class CatalogError(ValueError):
    pass


def load_catalog(path: Path | str = DEFAULT_CATALOG) -> dict:
    """Load the catalog JSON. Returns {'meta': {...}, 'classes': [...]}."""
    p = Path(path)
    with p.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if "classes" not in data or "meta" not in data:
        raise CatalogError(f"{p}: catalog must have top-level 'meta' and 'classes'")
    return data


def catalog_by_id(catalog: dict) -> dict:
    return {c["class_id"]: c for c in catalog.get("classes", []) if c.get("class_id")}


def eval_applies(node, flags) -> bool:
    """Evaluate an applicability predicate against a set/collection of flags."""
    fset = flags if isinstance(flags, (set, frozenset)) else set(flags or ())
    if not isinstance(node, dict):
        raise CatalogError(f"applies_when node must be an object, got {type(node).__name__}")
    if "always" in node:
        return bool(node["always"])
    if "any_flag" in node:
        leaves = node["any_flag"]
        _check_leaves(leaves)
        return any(f in fset for f in leaves)
    if "all_flags" in node:
        leaves = node["all_flags"]
        _check_leaves(leaves)
        return all(f in fset for f in leaves)
    if "not" in node:
        return not eval_applies(node["not"], fset)
    raise CatalogError(f"malformed applies_when node: {json.dumps(node)[:80]}")


def _check_leaves(leaves) -> None:
    if not isinstance(leaves, list) or not leaves:
        raise CatalogError(f"flag list must be a non-empty array, got {leaves!r}")
    for f in leaves:
        if f not in ALL_FLAGS:
            raise CatalogError(f"unknown flag {f!r} (not in the 20-flag vocabulary)")


def collect_flags(node, out: set) -> None:
    """Collect every leaf flag referenced by a predicate (for validation)."""
    if not isinstance(node, dict):
        return
    for k in ("any_flag", "all_flags"):
        if k in node:
            for f in node[k]:
                out.add(f)
    if "not" in node:
        collect_flags(node["not"], out)


def md_class_ids(md_path: Path | str = DEFAULT_MD) -> set:
    """Extract class_ids from the coverage-matrix.md 'Class catalog' table only."""
    ids: set = set()
    for line in Path(md_path).read_text(encoding="utf-8").splitlines():
        m = _MD_ROW_RE.match(line)
        if m:
            ids.add(m.group(1))
    return ids
