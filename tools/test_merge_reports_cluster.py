#!/usr/bin/env python3
"""Tests for tools/merge_reports_cluster.py (deterministic dup-candidate clusterer)."""
import unittest

from merge_reports_cluster import (
    candidate_pairs, cluster, jaccard, norm_assets, norm_cves, norm_cwe,
    norm_host_ports, norm_hosts, norm_urlpath, title_tokens,
)


def _ids(clusters):
    """Set of frozensets of member-uids, for order-independent comparison."""
    return {frozenset(c["members"]) for c in clusters}


class NormalizeTest(unittest.TestCase):
    def test_cves_from_list_and_dicts_and_text(self):
        f = {"cves": ["cve-2024-1234", {"id": "CVE-2023-9999"}], "title": "leaks CVE-2022-1111"}
        self.assertEqual(norm_cves(f), {"CVE-2024-1234", "CVE-2023-9999", "CVE-2022-1111"})

    def test_cwe_canonical(self):
        self.assertEqual(norm_cwe({"cwe": "CWE-79"}), "CWE-79")
        self.assertEqual(norm_cwe({"cwe": "cwe_089"}), "CWE-89")
        self.assertEqual(norm_cwe({"cwe": 89}), "CWE-89")
        self.assertEqual(norm_cwe({}), "")

    def test_assets_host_extraction(self):
        f = {"affected": ["https://App.ACME.com:8443/login"], "url": "http://app.acme.com/x"}
        self.assertEqual(norm_assets(f), {"app.acme.com"})

    def test_norm_assets_is_norm_hosts(self):
        # Backwards-compat: the historical name resolves to bare-host extraction.
        self.assertIs(norm_assets, norm_hosts)

    def test_host_port_parsing_messy_formats(self):
        # https URL with an explicit port
        f = {"affected": ["https://h.example:8443/x"]}
        self.assertEqual(norm_hosts(f), {"h.example"})
        self.assertEqual(norm_host_ports(f), {"h.example:8443"})
        # bare ip:port with a /tcp service suffix (nmap-style)
        f = {"asset": "198.51.100.7:64780/tcp"}
        self.assertEqual(norm_hosts(f), {"198.51.100.7"})
        self.assertEqual(norm_host_ports(f), {"198.51.100.7:64780"})
        # host:port with no scheme and no path
        f = {"asset": "h.example:443"}
        self.assertEqual(norm_hosts(f), {"h.example"})
        self.assertEqual(norm_host_ports(f), {"h.example:443"})
        # free text where the number after the colon is prose, NOT a port
        f = {"asset": "198.51.100.7: 145 open ports"}
        self.assertEqual(norm_hosts(f), {"198.51.100.7"})
        self.assertEqual(norm_host_ports(f), set())

    def test_urlpath(self):
        self.assertEqual(norm_urlpath({"url": "https://a.com/search/?q=1"}), ("a.com", "/search"))
        self.assertIsNone(norm_urlpath({}))

    def test_title_tokens_drop_stopwords(self):
        self.assertEqual(title_tokens({"title": "XSS in the search"}), {"xss", "search"})

    def test_jaccard(self):
        self.assertAlmostEqual(jaccard({"a", "b"}, {"a", "b"}), 1.0)
        self.assertAlmostEqual(jaccard({"a", "b"}, {"a"}), 0.5)
        self.assertEqual(jaccard(set(), {"a"}), 0.0)


class ClusterTest(unittest.TestCase):
    def test_requires_unique_uid(self):
        with self.assertRaises(ValueError):
            cluster([{"uid": "x"}, {"uid": "x"}])
        with self.assertRaises(ValueError):
            cluster([{"title": "no uid"}])

    def test_same_cve_different_names_merges(self):
        # Different sources, different ids/titles, same CVE -> one cluster.
        f = [
            {"uid": "src1::F1", "title": "Outdated nginx", "cves": ["CVE-2024-1234"]},
            {"uid": "src2::A9", "title": "nginx RCE", "cves": [{"id": "CVE-2024-1234"}]},
        ]
        c = cluster(f)
        self.assertEqual(len(c), 1)
        self.assertEqual(_ids(c), {frozenset({"src1::F1", "src2::A9"})})
        self.assertIn("cve", c[0]["signals"])

    def test_same_asset_and_cwe_merges(self):
        f = [
            {"uid": "a::1", "title": "SQL injection on login", "asset": "app.x.com", "cwe": "CWE-89"},
            {"uid": "b::2", "title": "Database injection flaw", "affected": ["https://app.x.com/login"], "cwe": "CWE-89"},
        ]
        c = cluster(f)
        self.assertEqual(_ids(c), {frozenset({"a::1", "b::2"})})

    def test_same_asset_different_cwe_stays_split(self):
        f = [
            {"uid": "a::1", "title": "SQLi", "asset": "app.x.com", "cwe": "CWE-89"},
            {"uid": "b::2", "title": "XSS", "asset": "app.x.com", "cwe": "CWE-79"},
        ]
        c = cluster(f)
        self.assertEqual(len(c), 2)

    def test_host_overlap_candidate_pair_across_differing_cwes(self):
        # The free-text-asset failure: free-text asset + divergent CWEs meant asset+cwe never
        # fired. Union still splits them, but a host-overlap candidate pair surfaces
        # them for LLM adjudication.
        f = [
            {"uid": "a::1", "title": "SQLi", "asset": "app.example.com", "cwe": "CWE-89"},
            {"uid": "b::2", "title": "XSS", "asset": "app.example.com", "cwe": "CWE-79"},
        ]
        self.assertEqual(len(cluster(f)), 2)  # NOT force-merged into one cluster
        cp = candidate_pairs(f)
        self.assertEqual(len(cp), 1)
        self.assertEqual(cp[0]["pair"], ["a::1", "b::2"])
        self.assertEqual(cp[0]["signal"], "host-overlap")
        self.assertIn("app.example.com", cp[0]["hosts"])

    def test_same_host_different_port_not_auto_merged(self):
        # The same-host-different-port over-cluster: same host, DIFFERENT explicit ports, different
        # issues. No union edge fires, and the host-overlap signal is suppressed.
        f = [
            {"uid": "a::1", "title": "Weak TLS on service", "asset": "198.51.100.9:64680", "cwe": "CWE-326"},
            {"uid": "b::2", "title": "Info leak on service", "asset": "198.51.100.9:64780", "cwe": "CWE-200"},
        ]
        self.assertEqual(len(cluster(f)), 2)
        self.assertEqual(candidate_pairs(f), [])

    def test_divergent_cited_port_warning(self):
        # Same host + same CWE ⇒ union-merged, but the members cite ports 100 apart.
        # The cluster must carry a divergent-cited-port warning, never a silent merge.
        f = [
            {"uid": "a::1", "title": "Weak TLS on mgmt", "asset": "203.0.113.5:64680", "cwe": "CWE-326"},
            {"uid": "b::2", "title": "Weak TLS management", "asset": "203.0.113.5:64780", "cwe": "CWE-326"},
        ]
        c = cluster(f)
        self.assertEqual(len(c), 1)
        self.assertIn("warnings", c[0])
        self.assertEqual(c[0]["warnings"], ["divergent cited port for 203.0.113.5: {64680, 64780}"])

    def test_no_warning_when_ports_agree(self):
        # Same host, same cited port -> merged, and NO divergent-port warning.
        f = [
            {"uid": "a::1", "title": "Weak TLS on mgmt", "asset": "203.0.113.6:8443", "cwe": "CWE-326"},
            {"uid": "b::2", "title": "Weak TLS management", "asset": "203.0.113.6:8443", "cwe": "CWE-326"},
        ]
        c = cluster(f)
        self.assertEqual(len(c), 1)
        self.assertNotIn("warnings", c[0])

    def test_url_param_merges(self):
        f = [
            {"uid": "a::1", "title": "Reflected input", "url": "https://x.com/s", "param": "q"},
            {"uid": "b::2", "title": "Echoed value", "url": "http://x.com/s?q=2", "param": "Q"},
        ]
        c = cluster(f)
        self.assertEqual(_ids(c), {frozenset({"a::1", "b::2"})})

    def test_title_jaccard_within_asset(self):
        f = [
            {"uid": "a::1", "title": "Reflected XSS in search parameter", "asset": "x.com"},
            {"uid": "b::2", "title": "Reflected XSS in the search parameter", "asset": "x.com"},
        ]
        c = cluster(f)  # tokens overlap 4/5 = 0.8 >= 0.6
        self.assertEqual(_ids(c), {frozenset({"a::1", "b::2"})})

    def test_title_jaccard_requires_same_asset(self):
        f = [
            {"uid": "a::1", "title": "Reflected XSS in search parameter", "asset": "x.com"},
            {"uid": "b::2", "title": "Reflected XSS in search parameter", "asset": "y.com"},
        ]
        c = cluster(f)  # identical titles but different assets -> NOT merged
        self.assertEqual(len(c), 2)

    def test_transitive_chain(self):
        # 1-2 by cve, 2-3 by asset+cwe -> all three in one cluster (distinct signals).
        f = [
            {"uid": "s::1", "title": "A", "cves": ["CVE-2024-5555"], "asset": "y.com"},
            {"uid": "s::2", "title": "B", "cves": ["CVE-2024-5555"], "asset": "x.com", "cwe": "CWE-22"},
            {"uid": "s::3", "title": "C", "asset": "x.com", "cwe": "CWE-22"},
        ]
        c = cluster(f)
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0]["size"], 3)
        # both signal types must have fired for this to be a genuine transitive chain
        self.assertIn("cve", c[0]["signals"])
        self.assertIn("asset+cwe", c[0]["signals"])

    def test_singletons_each_their_own_cluster(self):
        f = [
            {"uid": "s::1", "title": "Alpha", "asset": "a.com", "cwe": "CWE-1"},
            {"uid": "s::2", "title": "Beta", "asset": "b.com", "cwe": "CWE-2"},
            {"uid": "s::3", "title": "Gamma", "asset": "c.com", "cwe": "CWE-3"},
        ]
        c = cluster(f)
        self.assertEqual(len(c), 3)
        self.assertTrue(all(x["size"] == 1 for x in c))

    def test_deterministic_ids_and_order(self):
        f = [
            {"uid": "z::9", "title": "Same", "cves": ["CVE-2024-5555"]},
            {"uid": "a::1", "title": "Same", "cves": ["CVE-2024-5555"]},
            {"uid": "m::5", "title": "Lonely", "asset": "q.com", "cwe": "CWE-1"},
        ]
        c1 = cluster(f)
        c2 = cluster(list(reversed(f)))
        self.assertEqual(_ids(c1), _ids(c2))
        # the two shared-CVE findings actually merge into one multi-member cluster,
        # rooted at (and ordered by) the min member uid.
        self.assertEqual(c1[0]["cluster_id"], "C001")
        self.assertEqual(c1[0]["size"], 2)
        self.assertEqual(_ids(c1), {frozenset({"a::1", "z::9"}), frozenset({"m::5"})})
        self.assertEqual(c1[0]["members"][0], "a::1")

    def test_every_finding_appears_once(self):
        f = [{"uid": "s::%d" % i, "title": "t%d" % i, "asset": "a%d.com" % (i % 3), "cwe": "CWE-%d" % i} for i in range(10)]
        c = cluster(f)
        seen = [m for cl in c for m in cl["members"]]
        self.assertEqual(sorted(seen), sorted(x["uid"] for x in f))
        self.assertEqual(len(seen), len(set(seen)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
