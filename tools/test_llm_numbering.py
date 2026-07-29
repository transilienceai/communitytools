#!/usr/bin/env python3
"""Pin the OWASP LLM Top 10 edition the ai-threat-testing skill claims.

WHY THIS TEST EXISTS
--------------------
The skill carried two incompatible numbering schemes simultaneously. `reference/`
used LLM06=Excessive Agency, LLM07=Model Extraction, LLM08=Vector Poisoning,
LLM10=Insufficient Logging; `reference/scenarios/llm/` used the OWASP 2023 order
(LLM06=Sensitive Information Disclosure, LLM07=Insecure Plugin Design,
LLM08=Excessive Agency). So a report citing "OWASP LLM Top 10" contradicted itself
depending on which file the agent had read, and "Insufficient Logging & Monitoring"
was presented as LLM10 despite never being an OWASP LLM category in any edition.

Filenames were left as they are — the content is right, only the label was wrong,
and renaming would break inbound links. The catalogue is the source of truth, and
this test is what stops the two drifting apart again.

Run: python3 tools/test_llm_numbering.py
"""
from __future__ import annotations

import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
SKILL = os.path.join(REPO, "skills", "ai-threat-testing")
CATALOG = os.path.join(SKILL, "reference", "catalog", "llm-top10-2025.json")

# The OWASP Top 10 for LLM Applications, 2025 edition. Pinned here so that a
# catalogue edit cannot quietly redefine what the framework says.
OWASP_2025 = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}


def _catalog():
    with open(CATALOG, encoding="utf-8") as fh:
        return json.load(fh)


class TestCatalogPinsOneEdition(unittest.TestCase):
    def test_edition_is_declared_and_pinned(self):
        meta = _catalog()["meta"]
        self.assertEqual(meta["framework_version"], "2025")
        self.assertIn("owasp.org", meta["source_url"])

    def test_all_ten_categories_present_with_official_titles(self):
        cats = {c["id"]: c["title"] for c in _catalog()["categories"]}
        self.assertEqual(set(cats), set(OWASP_2025),
                         "the catalogue must carry exactly the ten 2025 categories")
        for cid, title in OWASP_2025.items():
            self.assertEqual(cats[cid], title, f"{cid} title drifted from the pinned edition")

    def test_every_category_is_covered_or_declares_a_gap(self):
        """Silence reads as coverage — an uncovered category must say so."""
        for c in _catalog()["categories"]:
            if not c.get("covered_by"):
                self.assertTrue(str(c.get("gap", "")).strip(),
                                f"{c['id']} has no files and no gap statement")

    def test_referenced_files_exist(self):
        cat = _catalog()
        missing = []
        for group in ("categories", "local_classes"):
            for c in cat[group]:
                for rel in c.get("covered_by", []):
                    if not os.path.isfile(os.path.join(SKILL, rel)):
                        missing.append(f"{c['id']} -> {rel}")
        self.assertEqual(missing, [], "catalogue cites files that do not exist")


class TestNoInventedOwaspIds(unittest.TestCase):
    """The defect that made the conformance claim false."""

    def test_local_classes_never_use_an_llm_number(self):
        for c in _catalog()["local_classes"]:
            self.assertTrue(c["id"].startswith("TX-"),
                            f"{c['id']} must use the TX- local namespace")
            self.assertNotRegex(c["id"], r"LLM\d",
                                "a non-OWASP class must never be given an LLMnn id — "
                                "that is exactly how 'LLM10 Insufficient Logging' came about")

    def test_logging_evasion_is_local_not_owasp(self):
        """Named explicitly: it was presented as LLM10 and is in no edition."""
        local = {c["id"] for c in _catalog()["local_classes"]}
        self.assertIn("TX-LLM-LOG-EVASION", local)
        titles = {c["title"].lower() for c in _catalog()["categories"]}
        self.assertFalse(any("logging" in t or "monitoring" in t for t in titles),
                         "logging/monitoring is not an OWASP LLM category")

    def test_model_theft_is_filed_under_unbounded_consumption(self):
        """A named client deliverable; it was filed under an invented LLM07."""
        by_id = {c["id"]: c for c in _catalog()["categories"]}
        files = by_id["LLM10:2025"]["covered_by"]
        self.assertTrue(any("model-extraction" in f for f in files),
                        "model extraction/theft belongs to LLM10:2025 Unbounded Consumption")
        self.assertNotIn("reference/llm07-model-extraction.md",
                         by_id["LLM07:2025"].get("covered_by", []),
                         "LLM07:2025 is System Prompt Leakage, not Model Theft")

    def test_no_file_is_claimed_by_two_categories(self):
        seen, dupes = {}, []
        cat = _catalog()
        for group in ("categories", "local_classes"):
            for c in cat[group]:
                for rel in c.get("covered_by", []):
                    if rel in seen:
                        dupes.append(f"{rel}: {seen[rel]} and {c['id']}")
                    seen[rel] = c["id"]
        self.assertEqual(dupes, [], "a file addressing two categories makes coverage ambiguous")


class TestEachFileDeclaresItsOwnCategory(unittest.TestCase):
    """The part a catalogue alone does not fix.

    Executors are handed a reference-file path, not SKILL.md — that is the repo's
    stated convention. So a file whose own heading says "LLM07 Model Extraction"
    still teaches the wrong id to every agent that reads it, however correct the
    catalogue is. Each catalogued file must therefore name its category itself.
    """

    def _files(self):
        cat = _catalog()
        for group in ("categories", "local_classes"):
            for c in cat[group]:
                for rel in c.get("covered_by", []):
                    yield rel, c["id"]

    def test_no_heading_asserts_a_bare_llm_number(self):
        offenders = []
        for rel, _ in self._files():
            with open(os.path.join(SKILL, rel), encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("#"):
                        if re.search(r"LLM\d{2}(?!:)", line):
                            offenders.append(f"{rel}: {line.strip()}")
                        break
        self.assertEqual(offenders, [],
                         "a heading carrying an unqualified LLMnn re-teaches the old scheme")

    def test_every_catalogued_file_states_its_category(self):
        missing = []
        for rel, cid in self._files():
            with open(os.path.join(SKILL, rel), encoding="utf-8") as fh:
                head = "".join(fh.readlines()[:6])
            if cid not in head:
                missing.append(f"{rel} does not name {cid} in its first 6 lines")
        self.assertEqual(missing, [], "\n  ".join([""] + missing))

    def test_the_three_that_were_actively_wrong(self):
        """Named individually because these were the false claims."""
        def head(rel):
            with open(os.path.join(SKILL, rel), encoding="utf-8") as fh:
                return "".join(fh.readlines()[:6])
        self.assertIn("LLM10:2025", head("reference/llm07-model-extraction.md"),
                      "model theft is Unbounded Consumption in 2025, not LLM07")
        self.assertIn("TX-LLM-LOG-EVASION", head("reference/llm10-logging-bypass.md"),
                      "monitoring evasion is not an OWASP category and must not claim LLM10")
        self.assertIn("LLM02:2025", head("reference/scenarios/llm/llm06-sensitive-info-disclosure.md"),
                      "sensitive information disclosure is LLM02 in 2025, not LLM06")


class TestSkillDoesNotAssertTheOldScheme(unittest.TestCase):
    """SKILL.md is what an agent reads first; it propagated the wrong ids."""

    def test_skill_md_carries_no_bare_llm_numbering_claim(self):
        with open(os.path.join(SKILL, "SKILL.md"), encoding="utf-8") as fh:
            body = fh.read()
        # A bare "(LLM07)" with no edition is the ambiguity that started this.
        bare = re.findall(r"\(LLM\d{2}\)(?!:)", body)
        self.assertEqual(bare, [], "SKILL.md must qualify every id with its edition, e.g. LLM07:2025")

    def test_skill_md_points_at_the_catalogue(self):
        with open(os.path.join(SKILL, "SKILL.md"), encoding="utf-8") as fh:
            body = fh.read()
        self.assertIn("llm-top10-2025.json", body,
                      "SKILL.md must route through the pinned catalogue, not a hand-written list")


if __name__ == "__main__":
    unittest.main(verbosity=2)
