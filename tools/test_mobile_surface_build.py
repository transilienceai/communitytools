#!/usr/bin/env python3
"""Tests for tools/mobile_surface_build.py — stdlib + subprocess, no pytest."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TOOL = os.path.join(HERE, "mobile_surface_build.py")
ENUM = os.path.join(HERE, "enumerate_cells.py")


def run(app_dir, eng_dir, allow=(), platform="android", omit_allow=False):
    cmd = [sys.executable, TOOL, "--app-dir", app_dir, "--engagement-dir", eng_dir,
           "--platform", platform]
    if not omit_allow:
        cmd += ["--allow", *allow]
    p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    summary = None
    lines = [l for l in p.stdout.splitlines() if l.strip()]
    if lines:
        try:
            summary = json.loads(lines[-1])
        except json.JSONDecodeError:
            pass
    return p.returncode, summary, p.stdout + p.stderr


def wjson(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f)


def fixture(tmp, tag="fieldapp-app", endpoints=None, units=None, components=None):
    app = os.path.join(tmp, tag)
    wjson(os.path.join(app, "recon", "manifest-facts.json"), {
        "platform": "android", "package": "com.example.fieldapp", "version_name": "2.4.1",
        "artifact_sha256": "deadbeef", "framework": "react-native-hermes",
        "components": components if components is not None else [
            {"name": "com.example.fieldapp.MainActivity", "type": "activity", "exported": True},
            {"name": "com.example.fieldapp.Internal", "type": "activity", "exported": False},
        ],
        "deeplinks": [{"pattern": "fieldapp://ticket/{id}", "component": "MainActivity"}],
    })
    wjson(os.path.join(app, "recon", "inventory", "app-units.json"), {
        "schema": "app-units/v1",
        "units": units if units is not None else [
            {"unit_id": "wv:Help", "type": "webview", "address": "HelpWebView#onCreate",
             "flags": ["webview"]},
            {"unit_id": "st:prefs", "type": "storage",
             "address": "/data/data/com.example.fieldapp/shared_prefs/session.xml", "flags": []},
            {"unit_id": "cy:Envelope", "type": "crypto-use",
             "address": "com/example/fieldapp/net/Envelope;->encrypt", "flags": ["crypto_use"]},
        ]})
    wjson(os.path.join(app, "recon", "inventory", "endpoints.json"),
          endpoints if endpoints is not None else [
              {"origin": "https://gw.example.test", "method": "GET",
               "path_template": "/api/v1/tickets/{id}", "flags": ["object_by_id", "json_body"],
               "source_file": "decompiled.js:1"},
              {"origin": "https://gw.example.test", "method": "POST",
               "path_template": "/api/v1/login", "flags": ["auth_surface", "json_body"]},
              {"origin": "https://cdn.evil-not-in-scope.test", "method": "GET",
               "path_template": "/x", "flags": []},
          ])
    return app


def test_emits_both_surfaces_in_separate_dirs():
    with tempfile.TemporaryDirectory() as tmp:
        app = fixture(tmp)
        rc, s, out = run(app, tmp, allow=["example.test"])
        assert rc == 0, out
        mob = json.load(open(os.path.join(app, "recon", "inventory", "mobile-surface.json")))
        assert mob["schema"] == "mobile-surface/v1"
        # asset_tag MUST equal the dir basename — the gate resolves the ledger by dir
        assert mob["asset_tag"] == os.path.basename(app)
        assert s["api_assets"] == 1
        api = s["api_surfaces"][0]
        assert api["tag"] == "example-test-api" and api["apex"] == "example.test"
        # the two assets are siblings, never the same directory
        assert os.path.abspath(api["output_dir"]) != os.path.abspath(app)
        surf = json.load(open(api["surface_path"]))
        assert surf["schema"] == "surface/v2" and surf["asset_tag"] == api["tag"]
        assert surf["recovered_from"] == os.path.basename(app)


def test_allow_gate_is_required_and_enforced():
    with tempfile.TemporaryDirectory() as tmp:
        app = fixture(tmp)
        rc, s, out = run(app, tmp, omit_allow=True)
        assert rc == 2 and "--allow is required" in out, out
        # an out-of-scope bundle string must never become an active-testing target
        rc, s, out = run(app, tmp, allow=["example.test"])
        assert rc == 0
        assert "cdn.evil-not-in-scope.test" in s["skipped_out_of_scope"], s
        assert all(a["apex"] == "example.test" for a in s["api_surfaces"])
        assert not os.path.isdir(os.path.join(tmp, "evil-not-in-scope-test-api"))


def test_flag_filters_are_per_surface():
    """A single shared 14-flag filter would strip every mobile flag."""
    with tempfile.TemporaryDirectory() as tmp:
        app = fixture(tmp, endpoints=[
            # a mobile flag on a web unit must be dropped (it would raise CatalogError)
            {"origin": "https://gw.example.test", "method": "GET", "path_template": "/a",
             "flags": ["object_by_id", "webview", "not_a_flag"]},
        ])
        rc, s, out = run(app, tmp, allow=["example.test"])
        assert rc == 0, out
        mob = json.load(open(os.path.join(app, "recon", "inventory", "mobile-surface.json")))
        by_id = {u["unit_id"]: u for u in mob["units"]}
        assert "webview" in by_id["wv:Help"]["flags"], by_id["wv:Help"]
        # type implies its flag even when the agent omitted it
        assert "local_store" in by_id["st:prefs"]["flags"], by_id["st:prefs"]
        surf = json.load(open(s["api_surfaces"][0]["surface_path"]))
        assert surf["units"][0]["flags"] == ["object_by_id"], surf["units"][0]


def test_control_wiring_gaps_are_surfaced():
    """Regression: the gaps live under controls.wiring_gaps as OBJECTS.

    Reading the top level (or expecting strings) yields [] and silently drops the
    one signal an agent cannot fabricate — a control shipped but inert. Fixture is
    the real apk_control_wiring.py schema.
    """
    with tempfile.TemporaryDirectory() as tmp:
        app = fixture(tmp)
        wjson(os.path.join(app, "recon", "control_wiring.json"), {
            "tool": "apk_control_wiring", "version": 1,
            "native_library_wiring": {"bundled": ["libtoolChecker.so"], "loaded": [],
                                      "orphaned": ["libtoolChecker.so"]},
            "root_integrity": {"rootbeer": {"present": True, "references": 0, "wired": False,
                                            "shipped_but_unwired": True}},
            "ssl_pinning": {"pinner_built": True, "attached": False, "pinning_present_but_inert": True},
            "hardcoded_keys": [{"literal_prefix": "d01f7706…", "length": 32, "invoke_sites": 1}],
            "controls": {"wiring_gaps": [
                {"control": "native_lib", "name": "libtoolChecker.so", "gap": "orphaned",
                 "detail": "bundled but never loaded"},
                {"control": "ssl_pinning", "name": "CertificatePinner", "gap": "inert",
                 "detail": "built but never attached"}]},
        })
        rc, s, out = run(app, tmp, allow=["example.test"])
        assert rc == 0, out
        mob = json.load(open(os.path.join(app, "recon", "inventory", "mobile-surface.json")))
        gaps = mob["control_wiring_gaps"]
        assert "native_lib:libtoolChecker.so:orphaned" in gaps, gaps
        assert "ssl_pinning:CertificatePinner:inert" in gaps, gaps
        assert "root_integrity:rootbeer:shipped_but_unwired" in gaps, gaps
        assert "hardcoded_keys:count:1" in gaps, gaps
        assert all(isinstance(g, str) for g in gaps)


def test_absent_control_wiring_is_not_a_crash():
    with tempfile.TemporaryDirectory() as tmp:
        app = fixture(tmp)  # no control_wiring.json at all (e.g. an iOS artifact)
        rc, s, out = run(app, tmp, allow=["example.test"])
        assert rc == 0, out
        mob = json.load(open(os.path.join(app, "recon", "inventory", "mobile-surface.json")))
        assert mob["control_wiring_gaps"] == []


def test_agent_cannot_declare_a_derived_flag():
    with tempfile.TemporaryDirectory() as tmp:
        app = fixture(tmp)
        facts = json.load(open(os.path.join(app, "recon", "manifest-facts.json")))
        facts["flags"] = ["mobile_app", "http_listener", "is_apex", "static_js_or_repo"]
        wjson(os.path.join(app, "recon", "manifest-facts.json"), facts)
        rc, s, out = run(app, tmp, allow=["example.test"])
        assert rc == 0, out
        mob = json.load(open(os.path.join(app, "recon", "inventory", "mobile-surface.json")))
        assert mob["flags"] == ["static_js_or_repo"], mob["flags"]


def test_only_exported_components_become_units():
    with tempfile.TemporaryDirectory() as tmp:
        app = fixture(tmp)
        rc, s, out = run(app, tmp, allow=["example.test"])
        mob = json.load(open(os.path.join(app, "recon", "inventory", "mobile-surface.json")))
        addrs = {u["address"] for u in mob["units"]}
        assert "com.example.fieldapp.MainActivity" in addrs
        assert "com.example.fieldapp.Internal" not in addrs, "a non-exported component owes no IPC cell"


def test_equiv_group_is_never_invented():
    """The gate CREDITS siblings from equiv_group, so an invented group erases cells."""
    with tempfile.TemporaryDirectory() as tmp:
        app = fixture(tmp, endpoints=[
            {"origin": "https://gw.example.test", "method": "GET", "path_template": "/a/{id}", "flags": []},
            {"origin": "https://gw.example.test", "method": "GET", "path_template": "/a/{id}/sub", "flags": []},
            {"origin": "https://gw.example.test", "method": "GET", "path_template": "/b",
             "flags": [], "equiv_group": "explicit-family"},
        ])
        rc, s, out = run(app, tmp, allow=["example.test"])
        surf = json.load(open(s["api_surfaces"][0]["surface_path"]))
        groups = {u["address"]: u["equiv_group"] for u in surf["units"]}
        assert sum(1 for g in groups.values() if g is None) == 2, groups
        assert "explicit-family" in groups.values(), groups


def test_rerun_merges_and_does_not_clobber():
    with tempfile.TemporaryDirectory() as tmp:
        app = fixture(tmp)
        run(app, tmp, allow=["example.test"])
        spath = os.path.join(app, "recon", "inventory", "mobile-surface.json")
        mob = json.load(open(spath))
        mob["units"].append({"unit_id": "st:runtime-only", "type": "storage",
                             "address": "/data/.../found-at-runtime.db",
                             "flags": ["local_store"], "equiv_group": None})
        wjson(spath, mob)
        run(app, tmp, allow=["example.test"])  # a second pass must not drop it
        again = json.load(open(spath))
        assert "st:runtime-only" in {u["unit_id"] for u in again["units"]}


def test_surfaces_enumerate_disjoint_classes():
    """End-to-end: the emitted pair feeds enumerate_cells with no cross-contamination."""
    with tempfile.TemporaryDirectory() as tmp:
        app = fixture(tmp)
        rc, s, out = run(app, tmp, allow=["example.test"])
        p = subprocess.run([sys.executable, ENUM, "--engagement-dir", tmp],
                           cwd=REPO, capture_output=True, text=True)
        assert p.returncode == 0, p.stdout + p.stderr
        doc = json.load(open(os.path.join(tmp, "applicability", "cells.json")))
        kinds = {t: m["kind"] for t, m in doc["assets"].items()}
        assert kinds[os.path.basename(app)] == "mobile"
        assert kinds["example-test-api"] == "web"
        app_ids = {c["class_id"] for c in doc["cells"] if c["asset_tag"] == os.path.basename(app)}
        api_ids = {c["class_id"] for c in doc["cells"] if c["asset_tag"] == "example-test-api"}
        assert all(c.startswith("MAS-") or c == "API8-MISCONFIG" for c in app_ids), app_ids
        assert not any(c.startswith("MAS-") for c in api_ids), api_ids
        # the backend is the half that gets systematically under-tested — assert it
        # actually carries a real work-list
        assert len(api_ids) >= 6, api_ids


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
