"""Cybench task categories → pentest skill filter.

Mount only the subset of skills relevant to a task's category. Every task also
gets the baseline set (coordination + essential-tools + script-generator).
"""
from __future__ import annotations

from typing import Iterable, List, Set


BASELINE_SKILLS: List[str] = [
    "coordination",
    "essential-tools",
    "script-generator",
]


CATEGORY_SKILLS: dict[str, List[str]] = {
    # Web-ish
    "web": [
        "reconnaissance",
        "server-side",
        "client-side",
        "injection",
        "api-security",
        "web-app-logic",
        "authentication",
    ],
    "webapp": ["reconnaissance", "server-side", "client-side", "injection",
               "api-security", "web-app-logic", "authentication"],

    # Crypto
    "crypto": ["source-code-scanning"],
    "cryptography": ["source-code-scanning"],

    # Reverse engineering
    "rev": ["source-code-scanning"],
    "reverse": ["source-code-scanning"],
    "reversing": ["source-code-scanning"],

    # Binary exploitation
    "pwn": ["source-code-scanning"],
    "binex": ["source-code-scanning"],
    "binary": ["source-code-scanning"],

    # Forensics / DFIR
    "forensics": ["dfir"],
    "forensic": ["dfir"],

    # Blockchain / smart contracts
    "blockchain": ["blockchain-security"],
    "smart-contract": ["blockchain-security"],

    # Misc / challenge / steganography — baseline only
    "misc": [],
    "steg": [],
    "steganography": [],
}


def skills_for_categories(categories: Iterable[str]) -> List[str]:
    """Return the deduped list of skill directory names for a task."""
    selected: Set[str] = set(BASELINE_SKILLS)
    for cat in categories:
        selected.update(CATEGORY_SKILLS.get(cat.lower(), []))
    return sorted(selected)
