#!/usr/bin/env python3
"""Tests for tools/dns_email_posture.py — the DNS/email posture rubric.

No live DNS/HTTPS: the module-level seams (_txt/_mx/_cname/_caa/_has_dnssec/
_https_get) are replaced with fakes backed by in-memory record maps.
"""
import unittest

import dns_email_posture as m


def _strong(apex="example.org"):
    """A fully-hardened apex: every posture control present and correct."""
    return dict(
        txt={
            apex: ["v=spf1 include:_spf.example.net -all"],
            f"_dmarc.{apex}": [f"v=DMARC1; p=reject; sp=reject; rua=mailto:d@{apex}"],
            f"default._domainkey.{apex}": ["v=DKIM1; k=rsa; p=MIGfMA0GCSq"],
            f"_mta-sts.{apex}": ["v=STSv1; id=20260101T000000"],
            f"_smtp._tls.{apex}": [f"v=TLSRPTv1; rua=mailto:tls@{apex}"],
            f"default._bimi.{apex}": [f"v=BIMI1; l=https://{apex}/logo.svg"],
        },
        mx={apex: [f"mail.{apex}"]},
        cname={},
        caa={apex: ['0 issue "letsencrypt.org"']},
        dnssec={apex},
        https={
            f"https://mta-sts.{apex}/.well-known/mta-sts.txt": (200, "version: STSv1\nmode: enforce\nmx: mail." + apex),
            f"https://{apex}/.well-known/security.txt": (200, f"Contact: mailto:security@{apex}\n"),
        },
    )


class PostureTest(unittest.TestCase):
    def setUp(self):
        # Snapshot the real seams and restore them after each test.
        self._orig = {n: getattr(m, n) for n in
                      ("_txt", "_mx", "_cname", "_caa", "_has_dnssec", "_https_get")}
        self.addCleanup(lambda: [setattr(m, n, fn) for n, fn in self._orig.items()])

    def install(self, txt=None, mx=None, cname=None, caa=None, dnssec=None, https=None):
        txt, mx, cname, caa = txt or {}, mx or {}, cname or {}, caa or {}
        dnssec, https = dnssec or set(), https or {}
        m._txt = lambda name: list(txt.get(name, []))
        m._mx = lambda name: list(mx.get(name, []))
        m._cname = lambda name: cname.get(name)
        m._caa = lambda name: list(caa.get(name, []))
        m._has_dnssec = lambda name: name in dnssec
        m._https_get = lambda url, timeout=8: https.get(url, (0, ""))

    def _by_check(self, apex, findings):
        """Map the trailing check-slug of each finding id -> finding."""
        prefix = f"DNSMAIL-{apex}-"
        return {f["id"][len(prefix):]: f for f in findings}

    # --- negative control: a hardened apex must be clean ---------------------
    def test_strong_apex_emits_no_findings(self):
        self.install(**_strong("example.org"))
        self.assertEqual(m.analyze("example.org"), [])

    # --- positive control: a weak apex trips the rubric ----------------------
    def test_weak_apex_emits_expected_findings(self):
        # No DMARC, SPF +all, no CAA, unsigned, nothing else configured.
        self.install(txt={"example.test": ["v=spf1 +all"]})
        by = self._by_check("example.test", m.analyze("example.test"))
        expected = {
            "spf-weak-all": "Medium",
            "dmarc-missing": "Medium",
            "dkim-none-found": "Info",
            "mta-sts-missing": "Low",
            "tlsrpt-missing": "Info",
            "bimi-missing": "Info",
            "caa-missing": "Low",
            "dnssec-unsigned": "Low",
            "mx-missing": "Info",
            "securitytxt-missing": "Info",
        }
        for check, sev in expected.items():
            self.assertIn(check, by, f"missing finding {check}")
            self.assertEqual(by[check]["severity"], sev, f"{check} severity")
        # affected is exactly the apex; every finding carries the required fields.
        for f in by.values():
            self.assertEqual(f["affected"], ["example.test"])
            for field in ("id", "title", "severity", "description", "impact", "recommendation"):
                self.assertTrue(f.get(field), f"{f['id']} missing {field}")
            self.assertIn(f["severity"], ("Critical", "High", "Medium", "Low", "Info"))

    def test_spf_missing_is_medium(self):
        # SPF absent entirely (a DMARC record is present so SPF is the only SPF finding).
        self.install(txt={"_dmarc.example.test": ["v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.test"]})
        by = self._by_check("example.test", m.analyze("example.test"))
        self.assertIn("spf-missing", by)
        self.assertEqual(by["spf-missing"]["severity"], "Medium")
        self.assertNotIn("spf-weak-all", by)

    def test_multiple_spf_is_low(self):
        self.install(txt={"example.test": ["v=spf1 include:a -all", "v=spf1 include:b -all"]})
        by = self._by_check("example.test", m.analyze("example.test"))
        self.assertIn("spf-multiple", by)
        self.assertEqual(by["spf-multiple"]["severity"], "Low")
        self.assertNotIn("spf-missing", by)  # records exist -> not "missing"

    def test_dmarc_p_none_is_low(self):
        self.install(txt={
            "example.test": ["v=spf1 -all"],
            "_dmarc.example.test": ["v=DMARC1; p=none; rua=mailto:d@example.test"],
        })
        by = self._by_check("example.test", m.analyze("example.test"))
        self.assertIn("dmarc-p-none", by)
        self.assertEqual(by["dmarc-p-none"]["severity"], "Low")
        self.assertNotIn("dmarc-missing", by)

    def test_mta_sts_present_but_policy_unreachable_is_low(self):
        # Start from a strong apex, then make ONLY the MTA-STS policy unreachable.
        cfg = _strong("example.org")
        cfg["https"]["https://mta-sts.example.org/.well-known/mta-sts.txt"] = (404, "")
        self.install(**cfg)
        findings = m.analyze("example.org")
        by = self._by_check("example.org", findings)
        self.assertEqual(list(by.keys()), ["mta-sts-policy-unreachable"])
        self.assertEqual(by["mta-sts-policy-unreachable"]["severity"], "Low")

    def test_dkim_present_via_cname_suppresses_advisory(self):
        # No DKIM TXT, but a selector is delegated by CNAME -> DKIM counts as present.
        cfg = _strong("example.org")
        del cfg["txt"]["default._domainkey.example.org"]
        cfg["cname"]["google._domainkey.example.org"] = "google._domainkey.example.com"
        self.install(**cfg)
        by = self._by_check("example.org", m.analyze("example.org"))
        self.assertNotIn("dkim-none-found", by)
        self.assertEqual(by, {})  # still fully hardened overall

    def test_run_wraps_result_document(self):
        self.install(**_strong("example.org"))
        doc = m.run(["example.org"])
        self.assertEqual(doc["version"], 1)
        self.assertEqual(doc["apexes"], ["example.org"])
        self.assertEqual(doc["findings"], [])

    def test_run_multi_apex_scopes_findings_per_apex(self):
        self.install(txt={"example.test": ["v=spf1 +all"]}, **{
            k: v for k, v in _strong("example.org").items() if k != "txt"})
        # merge the two txt maps
        strong_txt = _strong("example.org")["txt"]
        weak_txt = {"example.test": ["v=spf1 +all"]}
        merged = dict(strong_txt)
        merged.update(weak_txt)
        m._txt = lambda name: list(merged.get(name, []))
        doc = m.run(["example.org", "example.test"])
        self.assertEqual(sorted(doc["apexes"]), ["example.org", "example.test"])
        affected = {a for f in doc["findings"] for a in f["affected"]}
        self.assertNotIn("example.org", affected)  # hardened apex contributes nothing
        self.assertIn("example.test", affected)

    def test_ids_are_stable_and_prefixed(self):
        self.install(txt={"example.test": ["v=spf1 +all"]})
        ids = [f["id"] for f in m.analyze("example.test")]
        self.assertTrue(all(i.startswith("DNSMAIL-example.test-") for i in ids))
        self.assertEqual(len(ids), len(set(ids)))  # no duplicate ids


if __name__ == "__main__":
    unittest.main(verbosity=2)
