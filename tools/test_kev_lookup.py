#!/usr/bin/env python3
"""Tests for tools/kev-lookup.py deterministic snapshot + F-3 path safety.

Stdlib only; NO network — the catalog fetch seam is monkeypatched, and a HIT that
touches the network is made to raise. Run: python3 tools/test_kev_lookup.py
"""
import contextlib
import importlib.util
import io
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

CANNED_KEV = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2024.01.01",
    "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
         "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
         "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2023-1234", "vendorProject": "X", "product": "Y",
         "vulnerabilityName": "Z bug", "dateAdded": "2023-05-01"},
    ],
}


def load_module():
    path = os.path.join(HERE, "kev-lookup.py")
    spec = importlib.util.spec_from_file_location("kev_lookup_under_test", path)
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


def _boom():
    raise AssertionError("network fetch attempted when it should not have been")


def test_snapshot_hit_is_byte_identical_and_zero_network():
    mod = load_module()
    with tempfile.TemporaryDirectory() as d:
        cache = os.path.join(d, "kev")
        calls = {"n": 0}

        def stub():
            calls["n"] += 1
            return dict(CANNED_KEV)

        mod.fetch_kev_catalog = stub
        out1 = run_main(mod, ["--cache-dir", cache, "CVE-2021-44228"])
        assert calls["n"] == 1, "a MISS must fetch the catalog once"
        assert os.path.isfile(os.path.join(cache, "kev-snapshot.json")), "MISS must persist the snapshot"
        assert "ON KEV" in out1 and "2021-12-10" in out1

        mod.fetch_kev_catalog = _boom  # any fetch on replay fails the test
        out2 = run_main(mod, ["--cache-dir", cache, "CVE-2021-44228"])
        assert out1 == out2, "snapshot HIT stdout must be byte-identical + zero network"


def test_not_on_kev_verdict():
    mod = load_module()
    with tempfile.TemporaryDirectory() as d:
        mod.fetch_kev_catalog = lambda: dict(CANNED_KEV)
        out = run_main(mod, ["--cache-dir", os.path.join(d, "kev"), "CVE-2020-9999"])
        assert "NOT on KEV" in out
        assert '"on_kev": false' in out


def test_miss_falls_through_and_errors_not_cached():
    mod = load_module()
    with tempfile.TemporaryDirectory() as d:
        cache = os.path.join(d, "kev")
        mod.fetch_kev_catalog = lambda: {"error": "boom"}
        out = run_main(mod, ["--cache-dir", cache, "CVE-2021-44228"])
        assert "ERROR: boom" in out
        assert not os.path.exists(os.path.join(cache, "kev-snapshot.json")), "error must not be snapshotted"


def test_single_fetch_shared_across_ids():
    mod = load_module()
    calls = {"n": 0}

    def stub():
        calls["n"] += 1
        return dict(CANNED_KEV)

    mod.fetch_kev_catalog = stub
    out = run_main(mod, ["CVE-2021-44228", "CVE-2023-1234"])  # no cache-dir
    assert calls["n"] == 1, "the catalog must be fetched once and shared across ids"
    assert out.count("ON KEV") == 2


def test_f3_snapshot_path_containment_helper():
    mod = load_module()
    with tempfile.TemporaryDirectory() as d:
        p = mod.snapshot_path(d)
        assert p == os.path.join(os.path.realpath(d), "kev-snapshot.json"), p


def test_f3_bad_cve_rejected_no_file():
    mod = load_module()
    with tempfile.TemporaryDirectory() as d:
        cache = os.path.join(d, "kev")
        mod.fetch_kev_catalog = lambda: dict(CANNED_KEV)
        out = run_main(mod, ["--cache-dir", cache, "CVE-../../evil"])
        assert "doesn't look like a CVE" in out
        assert os.listdir(cache) == [], "a malformed id must never trigger a write"
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
