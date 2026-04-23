"""Bountybench CWE → pentest skill filter.

Each bounty's `CWE` field looks like `"CWE-639: Authorization Bypass …"`. We
extract the numeric ID and map to a skill subset. Baseline skills are always
included — source-code-scanning is part of the baseline because every bounty
ships its vulnerable source tree for review.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Set


BASELINE_SKILLS: List[str] = [
    "coordination",
    "essential-tools",
    "script-generator",
    "source-code-scanning",
]


CWE_SKILLS: dict[str, List[str]] = {
    # Input validation / misc
    "CWE-20":   ["server-side", "injection"],
    "CWE-200":  ["reconnaissance", "api-security"],

    # Authentication & authorization
    "CWE-287":  ["authentication", "api-security"],
    "CWE-288":  ["authentication"],
    "CWE-306":  ["authentication", "api-security"],
    "CWE-285":  ["authentication", "web-app-logic"],
    "CWE-639":  ["authentication", "web-app-logic", "api-security"],
    "CWE-862":  ["authentication", "web-app-logic"],
    "CWE-863":  ["authentication", "web-app-logic"],

    # Injection
    "CWE-74":   ["injection"],
    "CWE-77":   ["injection"],
    "CWE-78":   ["injection"],
    "CWE-89":   ["injection"],
    "CWE-94":   ["injection"],
    "CWE-95":   ["injection"],
    "CWE-917":  ["injection"],
    "CWE-1336": ["injection"],

    # Path / file handling
    "CWE-22":   ["server-side"],
    "CWE-23":   ["server-side"],
    "CWE-73":   ["server-side"],
    "CWE-434":  ["server-side"],
    "CWE-552":  ["server-side"],

    # Deserialization / RCE
    "CWE-502":  ["server-side", "api-security"],

    # SSRF / XXE / external entities
    "CWE-918":  ["server-side", "api-security"],
    "CWE-611":  ["injection", "server-side"],

    # Web client
    "CWE-79":   ["client-side"],
    "CWE-352":  ["client-side", "web-app-logic"],

    # Credential / crypto
    "CWE-522":  ["authentication"],
    "CWE-327":  [],      # baseline covers SAST for crypto
    "CWE-798":  ["authentication"],

    # AI / ML specific (mlflow, vllm, langchain ...)
    "CWE-1426": ["ai-threat-testing"],
    "CWE-1427": ["ai-threat-testing"],

    # Race conditions / logic
    "CWE-362":  ["web-app-logic"],
    "CWE-367":  ["web-app-logic"],
    "CWE-841":  ["web-app-logic"],
}


_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def extract_cwe_id(cwe_field: str) -> str:
    """Return canonical `CWE-N` id from a raw `CWE` metadata string, or `""`."""
    if not cwe_field:
        return ""
    m = _CWE_RE.search(cwe_field)
    return f"CWE-{m.group(1)}" if m else ""


def skills_for_cwe(cwe_field: str) -> List[str]:
    """Deduped skill list for a bounty's CWE field. Unknown CWE → baseline only."""
    selected: Set[str] = set(BASELINE_SKILLS)
    cwe_id = extract_cwe_id(cwe_field)
    if cwe_id:
        selected.update(CWE_SKILLS.get(cwe_id, []))
    return sorted(selected)


def skills_for_cwes(cwe_fields: Iterable[str]) -> List[str]:
    """Union of skills across multiple CWE fields."""
    selected: Set[str] = set(BASELINE_SKILLS)
    for field in cwe_fields:
        cwe_id = extract_cwe_id(field)
        if cwe_id:
            selected.update(CWE_SKILLS.get(cwe_id, []))
    return sorted(selected)
