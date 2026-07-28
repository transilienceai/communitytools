#!/usr/bin/env python3
"""Tests for tools/posture/catalog_validate.py.

The licence checks are the ones that matter most: a catalogue derived from a
restricted benchmark is a legal exposure if source prose leaks into it, and no
other tooling in this repo looks at catalogue JSON at all.
"""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import catalog_validate as CV  # noqa: E402

GOOD_CONTROL = {
    "control_id": "1.7",
    "section": "1",
    "level": 1,
    "assessment": "Automated",
    "service": "iam",
    "title": "Console sign-in requires a second factor for every local user",
    "objective": "A stolen or guessed console password alone must not grant tenancy access.",
    "procedure": "List local users in each identity domain and read the MFA activation state; "
                 "a tenancy-wide Advanced Resource Query avoids walking compartments.",
    "api": ["oci iam user list --compartment-id <tenancy-ocid> --all"],
    "evidence": "Per user OCID, the is_mfa_activated field of the user record.",
    "verdict_rule": "PASS when every user holding a console password has MFA active.",
    "remediation": "Enable multi-factor authentication for the listed users in their identity domain.",
}

GOOD_META = {
    "catalog_id": "cis-oci-foundations",
    "framework": "CIS Oracle Cloud Infrastructure Foundations Benchmark",
    "framework_version": "3.1.1",
    "provider": "oci",
    "control_count": 1,
    "source_url": "https://www.cisecurity.org/benchmark/oracle_cloud",
    "licence_note": ("Control numbers, levels and assessment statuses are identifiers; all "
                     "titles and procedures are our own. No benchmark text is reproduced."),
    "sections": {"1": "Identity and Access Management"},
}


def _cat(**overrides):
    c = {"meta": copy.deepcopy(GOOD_META), "controls": [copy.deepcopy(GOOD_CONTROL)]}
    c.update(overrides)
    return c


class TestPositive(unittest.TestCase):
    def test_a_well_formed_catalog_is_clean(self):
        self.assertEqual(CV.validate(_cat()), [])


class TestStructure(unittest.TestCase):
    def test_pinned_count_drift_fails(self):
        c = _cat()
        c["meta"]["control_count"] = 54
        self.assertTrue(any("control_count" in e for e in CV.validate(c)))

    def test_missing_required_control_field_fails(self):
        for field in ("verdict_rule", "evidence", "api", "remediation"):
            c = _cat()
            del c["controls"][0][field]
            self.assertTrue(any(field in e for e in CV.validate(c)), field)

    def test_duplicate_control_id_fails(self):
        c = _cat()
        c["controls"].append(copy.deepcopy(GOOD_CONTROL))
        c["meta"]["control_count"] = 2
        self.assertTrue(any("duplicate" in e for e in CV.validate(c)))

    def test_section_must_match_control_id_prefix(self):
        c = _cat()
        c["controls"][0]["section"] = "4"
        c["meta"]["sections"]["4"] = "Logging and Monitoring"
        self.assertTrue(any("inconsistent with control_id" in e for e in CV.validate(c)))

    def test_undeclared_section_fails(self):
        c = _cat()
        c["controls"][0]["control_id"] = "9.1"
        c["controls"][0]["section"] = "9"
        self.assertTrue(any("not declared in meta.sections" in e for e in CV.validate(c)))

    def test_bad_level_and_assessment_fail(self):
        c = _cat()
        c["controls"][0]["level"] = 3
        c["controls"][0]["assessment"] = "Semi"
        errs = CV.validate(c)
        self.assertTrue(any("level" in e for e in errs))
        self.assertTrue(any("assessment" in e for e in errs))

    def test_split_drift_fails(self):
        c = _cat()
        c["meta"]["level_split"] = {"1": 5}
        self.assertTrue(any("level_split" in e for e in CV.validate(c)))

    def test_manual_control_must_declare_what_a_human_judges(self):
        """Manual without a caveat silently reads as fully automated."""
        c = _cat()
        c["controls"][0]["assessment"] = "Manual"
        self.assertTrue(any("caveat" in e for e in CV.validate(c)))
        c["controls"][0]["caveat"] = "Requires reading the policy intent against business need."
        self.assertEqual(CV.validate(c), [])


class TestLicence(unittest.TestCase):
    """The expensive failure mode: restricted source prose reaching a public repo."""

    def test_authoring_aid_field_must_not_ship(self):
        c = _cat()
        c["controls"][0]["cis_title_hint"] = "Ensure MFA is enabled for all users"
        self.assertTrue(any("cis_title_hint" in e for e in CV.validate(c)))

    def test_transcribed_document_phrasing_is_caught(self):
        for field, text in (
            ("procedure", "From Console: 1. Login into the OCI Console and click the search bar"),
            ("procedure", "From CLI: execute the following command"),
            ("objective", "Profile Applicability: Level 1"),
            ("remediation", "Remediation Procedure: open the console"),
        ):
            c = _cat()
            c["controls"][0][field] = text
            self.assertTrue(any(field in e for e in CV.validate(c)), (field, text))

    def test_source_house_style_title_is_flagged(self):
        c = _cat()
        c["controls"][0]["title"] = "Ensure MFA is enabled for all users with a console password"
        errs = CV.validate(c)
        self.assertTrue(any("own voice" in e for e in errs))

    def test_licence_check_can_be_disabled_but_structure_still_validates(self):
        c = _cat()
        c["controls"][0]["title"] = "Ensure MFA is enabled for all users with a console password"
        self.assertEqual(CV.validate(c, strict_licence=False), [])

    def test_meta_must_carry_a_substantive_licence_note(self):
        c = _cat()
        c["meta"]["licence_note"] = "see CIS"
        self.assertTrue(any("licence_note" in e for e in CV.validate(c)))


class TestCli(unittest.TestCase):
    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "good.json")
            bad = os.path.join(d, "bad.json")
            with open(good, "w", encoding="utf-8") as fh:
                json.dump(_cat(), fh)
            broken = _cat()
            broken["meta"]["control_count"] = 99
            with open(bad, "w", encoding="utf-8") as fh:
                json.dump(broken, fh)
            self.assertEqual(CV.main([good]), CV.EXIT_OK)
            self.assertEqual(CV.main([bad]), CV.EXIT_INVALID)
            self.assertEqual(CV.main([]), CV.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
