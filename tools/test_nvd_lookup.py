#!/usr/bin/env python3
"""Tests for tools/nvd-lookup.py deterministic cache + F-3 path safety.

Stdlib only; NO network — the fetch seam is monkeypatched. Any real fetch on a
cache HIT is made to raise, so "zero network on replay" is enforced, not assumed.
Run: python3 tools/test_nvd_lookup.py
"""
import contextlib
import importlib.util
import io
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# A realistic NVD-API-shaped success dict — round-trips through json for the
# cache HIT re-render, so out(MISS) and out(HIT) must be byte-identical.
CANNED = {
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2024-0001",
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-02-01T00:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Test description."}],
            "metrics": {"cvssMetricV31": [{
                "type": "Primary",
                "cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH",
                             "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
                "exploitabilityScore": 2.8, "impactScore": 5.2,
            }]},
            "weaknesses": [{"descriptions": [{"lang": "en", "value": "CWE-79"}]}],
        }
    }]
}


def load_module():
    path = os.path.join(HERE, "nvd-lookup.py")
    spec = importlib.util.spec_from_file_location("nvd_lookup_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_main(mod, argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            mod.main(argv)
        except SystemExit:
            pass
    return buf.getvalue()


def _boom_fetch(*a, **k):
    raise AssertionError("network fetch attempted when it should not have been")


def test_cache_hit_is_byte_identical_and_zero_network():
    mod = load_module()
    with tempfile.TemporaryDirectory() as d:
        cache = os.path.join(d, "nvd-cache")
        calls = {"n": 0}

        def stub(cve_id, api_key=None):
            calls["n"] += 1
            return dict(CANNED)

        mod.fetch_cve = stub
        out1 = run_main(mod, ["--cache-dir", cache, "CVE-2024-0001"])
        assert calls["n"] == 1, "a MISS must fetch exactly once"
        assert os.path.isfile(os.path.join(cache, "CVE-2024-0001.json")), "MISS must persist the dict"

        # Any fetch on the second run fails the test — it must be a pure cache HIT.
        mod.fetch_cve = _boom_fetch
        out2 = run_main(mod, ["--cache-dir", cache, "CVE-2024-0001"])
        assert out1 == out2, "cache HIT stdout must be byte-identical to the MISS render"


def test_miss_falls_through_to_fetch():
    mod = load_module()
    with tempfile.TemporaryDirectory() as d:
        cache = os.path.join(d, "nvd-cache")
        calls = {"n": 0}

        def stub(cve_id, api_key=None):
            calls["n"] += 1
            return dict(CANNED)

        mod.fetch_cve = stub
        run_main(mod, ["--cache-dir", cache, "CVE-2024-0001"])
        assert calls["n"] == 1, "an empty cache must fall through to a live fetch"


def test_errors_are_not_cached():
    mod = load_module()
    with tempfile.TemporaryDirectory() as d:
        cache = os.path.join(d, "nvd-cache")
        mod.fetch_cve = lambda cid, ak=None: {"error": "boom"}
        out = run_main(mod, ["--cache-dir", cache, "CVE-2024-0002"])
        assert "ERROR: boom" in out
        assert not os.path.exists(os.path.join(cache, "CVE-2024-0002.json"))
        assert os.listdir(cache) == [], "a failed lookup must never be cached"


def test_no_cache_dir_still_works():
    mod = load_module()
    mod.fetch_cve = lambda cid, ak=None: dict(CANNED)
    out = run_main(mod, ["CVE-2024-0001"])
    assert "CVE-2024-0001" in out and "8.1" in out


def test_f3_cache_path_containment_helper():
    mod = load_module()
    with tempfile.TemporaryDirectory() as d:
        good = mod.cache_path_for(d, "CVE-2024-0001")
        assert good == os.path.join(os.path.realpath(d), "CVE-2024-0001.json"), good
        for bad in ["../evil", "CVE-2024-0001/../../etc/passwd", "CVE-XX",
                    "/etc/passwd", "CVE-2024", "CVE-2024-0001.json", "..", ""]:
            assert mod.cache_path_for(d, bad) is None, f"must reject id {bad!r}"


def test_f3_traversal_id_writes_nothing_outside_cache():
    mod = load_module()
    with tempfile.TemporaryDirectory() as d:
        cache = os.path.join(d, "cache")
        mod.fetch_cve = lambda cid, ak=None: dict(CANNED)
        # Passes the .upper()/startswith("CVE-") gate but fails the strict regex.
        run_main(mod, ["--cache-dir", cache, "CVE-../../evil"])
        assert os.listdir(cache) == [], "an unsafe id must not be cached"
        for root, _dirs, files in os.walk(d):
            assert not files or root == cache, f"stray file(s) under {root}: {files}"


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"FAIL {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
