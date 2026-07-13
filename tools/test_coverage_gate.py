#!/usr/bin/env python3
"""Tests for enumerate_cells.py + coverage_gate.py — stdlib + subprocess.

Fixtures are built in temp dirs; the tools run as subprocesses. Evidence is
constructed catalog-aware (reads each class's negative_kind) so the tests stay
valid if catalog negative-kinds are later tuned.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ENUM = os.path.join(HERE, "enumerate_cells.py")
GATE = os.path.join(HERE, "coverage_gate.py")
CATALOG = json.load(open(os.path.join(REPO, "skills", "coordination", "reference", "coverage-matrix.json")))
CLS = {c["class_id"]: c for c in CATALOG["classes"]}


# --- subprocess helpers ------------------------------------------------------
def _run(script, root, single, emit_open=False):
    flag = "--asset-dir" if single else "--engagement-dir"
    cmd = [sys.executable, script, flag, root]
    if emit_open:
        cmd.append("--emit-open")
    p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def enum(root, single=False):
    return _run(ENUM, root, single)


def gate(root, single=False, emit_open=False):
    rc, out = _run(GATE, root, single, emit_open)
    matrix = None
    mpath = os.path.join(root, "reports", "coverage-matrix.json")
    if os.path.isfile(mpath):
        matrix = json.load(open(mpath))
    return rc, out, matrix


# --- fixture writers ---------------------------------------------------------
def wjson(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f)


def web_asset(base, tag, units, apex="demo.test", subdomains=None):
    d = os.path.join(base, tag)
    wjson(os.path.join(d, "recon", "inventory", "surface.json"),
          {"schema": "surface/v2", "asset_tag": tag, "apex": apex, "units": units})
    if subdomains is not None:
        wjson(os.path.join(d, "recon", "inventory", "subdomains.json"), subdomains)
    return d


def net_host(base, ip, ports, live=True):
    d = os.path.join(base, "hosts", ip)
    body = {"ip": ip, "live": live}
    if live:
        body["ports"] = ports
    else:
        body["no_surface_from"] = ["primary"]
    wjson(os.path.join(d, "host.json"), body)
    return d


def append_experiment(asset_dir, e_id, note="probe"):
    path = os.path.join(asset_dir, "experiments.md")
    new = not os.path.isfile(path)
    os.makedirs(asset_dir, exist_ok=True)
    with open(path, "a") as f:
        if new:
            f.write("# Experiments\n| # | Batch | Technique | Target | Parameters | Result | Notes |\n|---|---|---|---|---|---|---|\n")
        f.write(f"| {e_id} | B1 | probe | t | p | done | {note} |\n")


def write_tool_md(asset_dir, e_id, n=1):
    path = os.path.join(asset_dir, "tools", f"{n:03d}_probe.md")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(f"# probe\nExperiment: {e_id}\n\n## Input\nnmap ...\n\n## Output\nclean\n")


def register_region(asset_dir, region, verified=True):
    path = os.path.join(asset_dir, "logs", "activity", "source-ips.jsonl")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps({"ip": "1.2.3.4", "role": "attack-vm", "region": region, "verified": verified}) + "\n")


def write_validated(asset_dir, finding_id, class_id, unit_refs, asset_tag, verdict="VALID"):
    wjson(os.path.join(asset_dir, "artifacts", "validated", f"{finding_id}.json"),
          {"finding_id": finding_id, "verdict": verdict, "class_id": class_id,
           "unit_refs": unit_refs, "asset_tag": asset_tag, "severity": "Medium"})


def close_negative(asset_dir, cell, e_id, region_pool, n=1):
    """Return a units_tested entry closing `cell` as a genuine negative, and write
    the matching evidence per the class's negative_kind."""
    nk = CLS[cell["class_id"]]["negative_kind"]
    entry = {"key": cell["scope_key"], "status": "covered_negative", "e_id": e_id, "negative_kind": nk}
    append_experiment(asset_dir, e_id)
    if nk == "active_probe":
        write_tool_md(asset_dir, e_id, n)
    elif nk == "reachability":
        mv = CLS[cell["class_id"]]["min_vantages"]
        entry["vantages"] = region_pool[:mv]
        for r in region_pool[:mv]:
            register_region(asset_dir, r)
    return entry


def write_coverage(asset_dir, entries_by_class, extra_rows=None):
    rows = [{"class_id": cid, "applicability": "applicable", "status": "pending", "units_tested": ents}
            for cid, ents in entries_by_class.items()]
    rows += (extra_rows or [])
    wjson(os.path.join(asset_dir, "coverage.json"), rows)


def load_cells(root, host_dir):
    enum(host_dir, single=True)
    return json.load(open(os.path.join(host_dir, "applicability", "cells.json")))["cells"]


def close_all(host_dir, cells, region_pool=("eu-west", "us-east")):
    by_class = {}
    for i, c in enumerate(cells, 1):
        e = close_negative(host_dir, c, f"E-{i:03d}", list(region_pool), n=i)
        by_class.setdefault(c["class_id"], []).append(e)
    write_coverage(host_dir, by_class)


# --- tests -------------------------------------------------------------------
def test_net_enumerate_and_zero_units():
    with tempfile.TemporaryDirectory() as tmp:
        net_host(tmp, "10.0.0.5", [{"port": 443, "state": "open", "service": "https", "product": "nginx", "version": "1.28.0"},
                                   {"port": 22, "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.9"}])
        net_host(tmp, "10.0.0.9", [], live=False)
        rc, out = enum(tmp)
        cells = json.load(open(os.path.join(tmp, "applicability", "cells.json")))["cells"]
        tags = {c["asset_tag"] for c in cells}
        assert "10.0.0.9" not in tags, "dead host must yield zero cells"
        h443 = {c["class_id"] for c in cells if c["scope_key"] == "10.0.0.5:443"}
        assert "XC-TLS-POSTURE" in h443 and "WEB-A06-COMPONENTS" in h443 and "XC-CORS" in h443
        h22 = {c["class_id"] for c in cells if c["scope_key"] == "10.0.0.5:22"}
        assert h22 == {"WEB-A06-COMPONENTS"}, f"ssh port should only get components, got {h22}"


def test_covered_pass_and_conjunct_flips():
    # host with only ssh:22 -> cells: COMPONENTS@ip:22 (active_probe), API8@ip (none)
    def fresh():
        tmp = tempfile.mkdtemp()
        hd = net_host(tmp, "10.0.0.7", [{"port": 22, "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.9"}])
        cells = load_cells(tmp, hd)
        comp = next(c for c in cells if c["class_id"] == "WEB-A06-COMPONENTS")
        return tmp, hd, cells, comp

    # baseline: COMPONENTS covered by a real finding; API8 closed as none-negative
    tmp, hd, cells, comp = fresh()
    append_experiment(hd, "E-001")
    write_validated(hd, "F-1", "WEB-A06-COMPONENTS", [comp["scope_key"]], "10.0.0.7")
    api8 = next(c for c in cells if c["class_id"] == "API8-MISCONFIG")
    entries = {"WEB-A06-COMPONENTS": [{"key": comp["scope_key"], "status": "covered", "e_id": "E-001", "finding_id": "F-1"}],
               "API8-MISCONFIG": [close_negative(hd, api8, "E-002", [])]}
    write_coverage(hd, entries)
    rc, out, m = gate(hd, single=True)
    assert rc == 0 and m["coverage_ratio"] == 1.0, f"baseline should pass: {out}"

    checks = [
        ("no_finding", lambda: os.remove(os.path.join(hd2, "artifacts", "validated", "F-1.json")), "no_matching_finding"),
        ("class_mismatch", None, "class_mismatch"),
        ("wrong_unit", None, "no_matching_finding"),
        ("demoted", None, "no_matching_finding"),
        ("dangling", None, "dangling_e_id"),
    ]
    for name, _, expect_reason in checks:
        tmp2, hd2, cells2, comp2 = fresh()
        api8b = next(c for c in cells2 if c["class_id"] == "API8-MISCONFIG")
        entries2 = {"WEB-A06-COMPONENTS": [{"key": comp2["scope_key"], "status": "covered", "e_id": "E-001", "finding_id": "F-1"}],
                    "API8-MISCONFIG": [close_negative(hd2, api8b, "E-002", [])]}
        append_experiment(hd2, "E-001")
        if name == "no_finding":
            write_validated(hd2, "F-1", "WEB-A06-COMPONENTS", [comp2["scope_key"]], "10.0.0.7")
            os.remove(os.path.join(hd2, "artifacts", "validated", "F-1.json"))
        elif name == "class_mismatch":
            write_validated(hd2, "F-1", "API1-BOLA", [comp2["scope_key"]], "10.0.0.7")
        elif name == "wrong_unit":
            write_validated(hd2, "F-1", "WEB-A06-COMPONENTS", ["some-other-key"], "10.0.0.7")
        elif name == "demoted":
            write_validated(hd2, "F-1", "WEB-A06-COMPONENTS", [comp2["scope_key"]], "10.0.0.7", verdict="DEMOTED")
        elif name == "dangling":
            write_validated(hd2, "F-1", "WEB-A06-COMPONENTS", [comp2["scope_key"]], "10.0.0.7")
            entries2["WEB-A06-COMPONENTS"][0]["e_id"] = "E-999"  # not in experiments
        write_coverage(hd2, entries2)
        rc2, out2, m2 = gate(hd2, single=True)
        reasons = {r["reason"] for r in m2["missing_cells"]}
        assert rc2 == 1 and expect_reason in reasons, f"{name}: expected {expect_reason}, got {reasons} ({out2})"


def test_reachability_negative():
    # XC-SUBDOMAIN-ORIGIN (asset scope) is the sole reachability class (min_vantages 2).
    RC = "XC-SUBDOMAIN-ORIGIN"
    assert CLS[RC]["negative_kind"] == "reachability" and CLS[RC]["min_vantages"] == 2

    def build(regions, verified_flags):
        tmp = tempfile.mkdtemp()
        d = web_asset(tmp, "webA", units=[{"unit_id": "u1", "type": "endpoint",
                      "address": "https://api.demo.test/x", "flags": ["input_sink"]}], apex="demo.test")
        cells = load_cells(tmp, d)
        sub = next(c for c in cells if c["class_id"] == RC)
        for r, v in zip(regions, verified_flags):
            register_region(d, r, verified=v)
        append_experiment(d, "E-001")
        entry = {"key": sub["scope_key"], "status": "covered_negative", "e_id": "E-001",
                 "negative_kind": "reachability", "vantages": regions}
        write_coverage(d, {RC: [entry]})
        return d

    # 2 verified regions -> the cell passes
    d = build(["eu-west", "us-east"], [True, True])
    _, _, m = gate(d, single=True)
    assert not [r for r in m["missing_cells"] if r["class_id"] == RC], f"2 verified regions should close {RC}"

    # single region -> insufficient
    d = build(["eu-west"], [True])
    _, _, m = gate(d, single=True)
    reasons = {r["reason"] for r in m["missing_cells"] if r["class_id"] == RC}
    assert "insufficient_vantages" in reasons, f"1 region should be insufficient: {reasons}"

    # 2 regions but one verified:false -> insufficient
    d = build(["eu-west", "us-east"], [True, False])
    _, _, m = gate(d, single=True)
    reasons = {r["reason"] for r in m["missing_cells"] if r["class_id"] == RC}
    assert "insufficient_vantages" in reasons, f"verified:false must be excluded: {reasons}"


def test_active_probe_negative_needs_corroborator():
    # SECURITY-HEADERS is active_probe (host scope). Build a 443 host, close the
    # headers cell as covered_negative WITHOUT a tool-log -> uncorroborated; then add one.
    def build():
        tmp = tempfile.mkdtemp()
        hd = net_host(tmp, "10.0.0.11", [{"port": 443, "state": "open", "service": "https", "product": "nginx", "version": "1.28.0"}])
        cells = load_cells(tmp, hd)
        hdr = next(c for c in cells if c["class_id"] == "XC-SECURITY-HEADERS")
        append_experiment(hd, "E-050")
        return tmp, hd, hdr

    tmp, hd, hdr = build()
    write_coverage(hd, {"XC-SECURITY-HEADERS": [{"key": hdr["scope_key"], "status": "covered_negative", "e_id": "E-050", "negative_kind": "active_probe"}]})
    _, _, m = gate(hd, single=True)
    reasons = {r["reason"] for r in m["missing_cells"] if r["class_id"] == "XC-SECURITY-HEADERS"}
    assert "uncorroborated_negative" in reasons, f"no tool-log -> uncorroborated: {reasons}"

    tmp, hd, hdr = build()
    write_tool_md(hd, "E-050")  # non-agent corroborator
    write_coverage(hd, {"XC-SECURITY-HEADERS": [{"key": hdr["scope_key"], "status": "covered_negative", "e_id": "E-050", "negative_kind": "active_probe"}]})
    _, _, m = gate(hd, single=True)
    hdr_fail = [r for r in m["missing_cells"] if r["class_id"] == "XC-SECURITY-HEADERS"]
    assert not hdr_fail, f"tool-log corroborator should close it: {hdr_fail}"


def test_na_fabrication_and_extra_and_false_na():
    tmp = tempfile.mkdtemp()
    hd = net_host(tmp, "10.0.0.12", [{"port": 22, "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.9"}])
    cells = load_cells(tmp, hd)
    comp = next(c for c in cells if c["class_id"] == "WEB-A06-COMPONENTS")
    append_experiment(hd, "E-1")
    rows = [
        # na_fabrication: NA on an applicable cell
        {"class_id": "WEB-A06-COMPONENTS", "applicability": "applicable", "status": "pending",
         "units_tested": [{"key": comp["scope_key"], "status": "NA", "e_id": "E-1"}]},
        # extra_cell: claim for a non-applicable key
        {"class_id": "API8-MISCONFIG", "applicability": "applicable", "status": "pending",
         "units_tested": [{"key": "phantom-key", "status": "covered", "e_id": "E-1"}]},
        # false_NA: class marked NA at class level though it has applicable cells (API8 always-applies)
        {"class_id": "API1-BOLA", "applicability": "not_applicable", "status": "NA", "units_tested": []},
    ]
    wjson(os.path.join(hd, "coverage.json"), rows)
    _, out, m = gate(hd, single=True)
    reasons = {r["reason"] for r in m["missing_cells"]}
    assert "na_fabrication" in reasons, f"expected na_fabrication: {reasons}"
    assert any(e["scope_key"] == "phantom-key" for e in m["extra_cells"]), f"expected extra_cell: {m['extra_cells']}"
    # API1-BOLA has no applicable cell on this ssh host, so its NA is NOT false_NA — sanity:
    assert not any(x["class_id"] == "API1-BOLA" for x in m["false_NA"]), "API1-BOLA not applicable here"


def test_false_na_when_applicable():
    tmp = tempfile.mkdtemp()
    hd = net_host(tmp, "10.0.0.13", [{"port": 22, "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.9"}])
    load_cells(tmp, hd)
    # API8-MISCONFIG always applies -> marking it not_applicable is a false_NA
    wjson(os.path.join(hd, "coverage.json"),
          [{"class_id": "API8-MISCONFIG", "applicability": "not_applicable", "status": "NA", "units_tested": []}])
    _, _, m = gate(hd, single=True)
    assert any(x["class_id"] == "API8-MISCONFIG" for x in m["false_NA"]), f"API8 NA must be false_NA: {m['false_NA']}"


def test_surface_undercount():
    tmp = tempfile.mkdtemp()
    # surface has only api.demo.test; subdomains.json also lists admin.demo.test -> undercount
    web_asset(tmp, "web1",
              units=[{"unit_id": "u1", "type": "endpoint", "address": "https://api.demo.test/v1/x", "flags": ["input_sink"]}],
              subdomains=["api.demo.test", "admin.demo.test"])
    _, _, m = gate(tmp)  # engagement-dir mode
    uc = m["surface_undercount"]
    assert uc and "admin.demo.test" in uc[0]["missing_hosts"], f"expected undercount for admin.demo.test: {uc}"


def test_exit_contract_and_emit_open():
    tmp = tempfile.mkdtemp()
    hd = net_host(tmp, "10.0.0.20", [{"port": 22, "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.9"}])
    cells = load_cells(tmp, hd)
    close_all(hd, cells)
    rc, out, m = gate(hd, single=True)
    assert rc == 0 and m["complete"] and m["coverage_ratio"] == 1.0, f"fully-closed host must exit 0: {out}"
    # emit-open on a complete asset
    rc_o, out_o = _run(GATE, hd, True, emit_open=True)
    assert "none" in out_o.lower(), f"emit-open should report none: {out_o}"
    # remove one evidence file -> exit 1
    os.remove(os.path.join(hd, "coverage.json"))
    rc2, _, m2 = gate(hd, single=True)
    assert rc2 == 1 and not m2["complete"], "missing ledger must fail"


def test_empty_engagement_is_graceful():
    tmp = tempfile.mkdtemp()
    os.makedirs(tmp, exist_ok=True)
    rc, out, m = gate(tmp)
    assert rc == 0 and m["applicable"] == 0 and m["coverage_ratio"] == 1.0, f"empty engagement -> graceful COMPLETE: {out}"


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
