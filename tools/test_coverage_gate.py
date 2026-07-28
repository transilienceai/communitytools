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
def _run(script, root, single, emit_open=False, accept_deferrals=False):
    flag = "--asset-dir" if single else "--engagement-dir"
    cmd = [sys.executable, script, flag, root]
    if emit_open:
        cmd.append("--emit-open")
    if accept_deferrals:
        cmd.append("--accept-deferrals")
    p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def enum(root, single=False):
    return _run(ENUM, root, single)


def gate(root, single=False, emit_open=False, accept_deferrals=False):
    rc, out = _run(GATE, root, single, emit_open, accept_deferrals)
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


_REGION_IPS = {}


def register_region(asset_dir, region, verified=True, ip=None, evidence=True,
                    role="attack-vm"):
    """Write one source-ips row for `region`.

    Defaults mirror a REAL verified vantage: a distinct egress IP per region plus
    an on-disk probe-evidence file containing that IP. Both are required by
    coverage_gate.load_verified_regions — a row without evidence, or a second
    region sharing an already-seen IP, must NOT count.
    """
    if ip is None:  # one distinct egress per region, as reality produces
        ip = _REGION_IPS.setdefault(region, f"203.0.113.{len(_REGION_IPS) + 10}")
    row = {"ip": ip, "role": role, "region": region, "verified": verified,
           "probe_evidence": ""}
    if evidence:
        rel = os.path.join("logs", "activity", "vantage-probes", f"{ip}.txt")
        p = os.path.join(asset_dir, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(ip + "\n")
        row["probe_evidence"] = rel
    path = os.path.join(asset_dir, "logs", "activity", "source-ips.jsonl")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(row) + "\n")


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


def write_cir(asset_dir, rel="reports/client-input-requests/CIR-001.md"):
    p = os.path.join(asset_dir, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write("# Client Input Request\nNeeds OTP seed / test account for <realm>.\n")
    return rel


def close_all_but_defer(host_dir, cells, defer_cells, substantiated=True, cir=True,
                        region_pool=("eu-west", "us-east")):
    """Close every cell as a negative EXCEPT those in defer_cells, which get a
    status:deferred entry. When substantiated+cir, an on-disk CIR is written and
    referenced so the deferral is legitimate; otherwise it should be a hard miss."""
    defer_keys = {(c["class_id"], c["scope_key"]) for c in defer_cells}
    cir_rel = write_cir(host_dir) if (substantiated and cir) else None
    by_class = {}
    for i, c in enumerate(cells, 1):
        if (c["class_id"], c["scope_key"]) in defer_keys:
            entry = {"key": c["scope_key"], "status": "deferred"}
            if substantiated:
                entry["deferral_reason"] = "post-auth probe needs MFA/OTP session; no client OTP seed"
                entry["blocked_on"] = "otp"
                if cir_rel:
                    entry["client_input_request"] = cir_rel
        else:
            entry = close_negative(host_dir, c, f"E-{i:03d}", list(region_pool), n=i)
        by_class.setdefault(c["class_id"], []).append(entry)
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

    def build(regions, verified_flags, **kw):
        tmp = tempfile.mkdtemp()
        d = web_asset(tmp, "webA", units=[{"unit_id": "u1", "type": "endpoint",
                      "address": "https://api.demo.test/x", "flags": ["input_sink"]}], apex="demo.test")
        cells = load_cells(tmp, d)
        sub = next(c for c in cells if c["class_id"] == RC)
        for r, v in zip(regions, verified_flags):
            register_region(d, r, verified=v, **kw)
        append_experiment(d, "E-001")
        entry = {"key": sub["scope_key"], "status": "covered_negative", "e_id": "E-001",
                 "negative_kind": "reachability", "vantages": regions}
        write_coverage(d, {RC: [entry]})
        return d

    def insufficient(d):
        _, _, m = gate(d, single=True)
        return {r["reason"] for r in m["missing_cells"] if r["class_id"] == RC}

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
    reasons = insufficient(d)
    assert "insufficient_vantages" in reasons, f"verified:false must be excluded: {reasons}"

    # --- the fabrication holes these rules exist to close ---------------------

    # verified:true but NO probe evidence on disk -> insufficient.
    # This is the old hole: register_source_ip.py used to write verified:true
    # unconditionally (even under --dry-run), so two registrations with different
    # --region values closed this cell having sent zero packets.
    d = build(["eu-west", "us-east"], [True, True], evidence=False)
    reasons = insufficient(d)
    assert "insufficient_vantages" in reasons, \
        f"verified:true without probe evidence must not count: {reasons}"

    # evidence file exists but does not contain the row's own IP -> insufficient.
    tmp = tempfile.mkdtemp()
    d = web_asset(tmp, "webA", units=[{"unit_id": "u1", "type": "endpoint",
                  "address": "https://api.demo.test/x", "flags": ["input_sink"]}], apex="demo.test")
    sub = next(c for c in load_cells(tmp, d) if c["class_id"] == RC)
    for r, ip in (("eu-west", "203.0.113.201"), ("us-east", "203.0.113.202")):
        register_region(d, r, ip=ip)
        rel = os.path.join("logs", "activity", "vantage-probes", f"{ip}.txt")
        with open(os.path.join(d, rel), "w") as f:
            f.write("curl: (7) Failed to connect\n")  # a real echo would print the IP
    append_experiment(d, "E-001")
    write_coverage(d, {RC: [{"key": sub["scope_key"], "status": "covered_negative",
                             "e_id": "E-001", "negative_kind": "reachability",
                             "vantages": ["eu-west", "us-east"]}]})
    reasons = insufficient(d)
    assert "insufficient_vantages" in reasons, \
        f"evidence not naming the row's IP must not count: {reasons}"

    # one egress re-registered under two region spellings -> ONE vantage.
    d = build(["us-east", "us-east-2"], [True, True], ip="203.0.113.77")
    reasons = insufficient(d)
    assert "insufficient_vantages" in reasons, \
        f"same IP under two region names must dedupe to one vantage: {reasons}"

    # a verified proxy is not a geography -> does not count toward min_vantages.
    d = build(["eu-west", "us-east"], [True, True], role="proxy")
    reasons = insufficient(d)
    assert "insufficient_vantages" in reasons, \
        f"role=proxy must not count as an attacking vantage: {reasons}"


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


def test_equiv_class_credit_and_controls():
    # E2 equivalence-class validation: a sibling in the same equiv_group rides a
    # DIRECT validated finding on ONE representative; controls (different group,
    # no group, host/asset) must NEVER take the fallback.
    INJ = "WEB-A03-INJECTION"  # unit-scope class, applies on the `input_sink` flag
    tmp = tempfile.mkdtemp()
    units = [
        {"unit_id": "u1", "type": "endpoint", "address": "https://api.demo.test/a", "flags": ["input_sink"], "equiv_group": "g1"},
        {"unit_id": "u2", "type": "endpoint", "address": "https://api.demo.test/b", "flags": ["input_sink"], "equiv_group": "g1"},
        {"unit_id": "u3", "type": "endpoint", "address": "https://api.demo.test/c", "flags": ["input_sink"], "equiv_group": "g2"},
        {"unit_id": "u4", "type": "endpoint", "address": "https://api.demo.test/d", "flags": ["input_sink"]},  # no equiv_group
    ]
    d = web_asset(tmp, "webB", units=units)
    load_cells(tmp, d)
    append_experiment(d, "E-001")
    write_validated(d, "F-1", INJ, ["u1"], "webB")  # sole direct finding, on u1
    inj_entries = [
        {"key": "u1", "status": "covered", "e_id": "E-001", "finding_id": "F-1"},
        {"key": "u2", "status": "covered", "e_id": "E-001", "representative": "u1"},
        {"key": "u3", "status": "covered", "e_id": "E-001"},
        {"key": "u4", "status": "covered", "e_id": "E-001"},
    ]
    write_coverage(d, {INJ: inj_entries})
    _, out, m = gate(d, single=True)

    inj_missing = {r["scope_key"]: r["reason"] for r in m["missing_cells"] if r["class_id"] == INJ}
    ce = {r["scope_key"]: r for r in m["covered_equiv"] if r["class_id"] == INJ}
    # u1 passes directly, u2 rides u1 via equivalence -> BOTH pass
    assert "u1" not in inj_missing, f"u1 (direct finding) should pass: {inj_missing}"
    assert "u2" not in inj_missing, f"u2 should ride u1 via equiv: {inj_missing}"
    assert "u2" in ce and ce["u2"]["representative"] == "u1" and ce["u2"]["reason"] == "covered_equiv", \
        f"u2 must be covered_equiv w/ representative u1: {m['covered_equiv']}"
    assert "u1" not in ce, "the representative itself must not be marked covered_equiv"
    # control: u3 in a DIFFERENT group (g2) with no rep -> still missing no_matching_finding
    assert inj_missing.get("u3") == "no_matching_finding", f"u3 (g2, no rep) must fail: {inj_missing}"
    # control: u4 has equiv_group None -> never takes the fallback
    assert inj_missing.get("u4") == "no_matching_finding", f"u4 (no group) must fail: {inj_missing}"
    # host/asset cells (equiv_group None) never take the fallback
    host_asset_missing = [r for r in m["missing_cells"] if r["scope"] in ("host", "asset")]
    assert host_asset_missing, "sanity: open host/asset cells present"
    assert all(r.get("equiv_group") is None for r in host_asset_missing), "host/asset cells carry no equiv_group"
    assert not any(r["scope"] in ("host", "asset") for r in m["covered_equiv"]), "host/asset must never be equiv-credited"
    # emit-open annotates open unit cells with their equiv group
    _, out_o = _run(GATE, d, True, emit_open=True)
    assert "[equiv:g2]" in out_o, f"emit-open should tag u3 with its equiv group: {out_o}"


def test_equiv_group_bound():
    # A single representative may only collapse EQUIV_GROUP_MAX siblings; the excess
    # stay in missing_cells (bounds "one rep covers an unbounded group").
    sys.path.insert(0, HERE)
    from coverage_gate import EQUIV_GROUP_MAX
    INJ = "WEB-A03-INJECTION"
    n_sib = EQUIV_GROUP_MAX + 2  # more siblings than one rep can cover
    tmp = tempfile.mkdtemp()
    units = [{"unit_id": "u0", "type": "endpoint", "address": "https://api.demo.test/rep",
              "flags": ["input_sink"], "equiv_group": "gbig"}]
    for i in range(1, n_sib + 1):
        units.append({"unit_id": f"s{i:02d}", "type": "endpoint",
                      "address": f"https://api.demo.test/s{i}", "flags": ["input_sink"], "equiv_group": "gbig"})
    d = web_asset(tmp, "webC", units=units)
    load_cells(tmp, d)
    append_experiment(d, "E-001")
    write_validated(d, "F-1", INJ, ["u0"], "webC")  # rep u0 has the sole direct finding
    entries = [{"key": "u0", "status": "covered", "e_id": "E-001", "finding_id": "F-1"}]
    for i in range(1, n_sib + 1):
        entries.append({"key": f"s{i:02d}", "status": "covered", "e_id": "E-001"})
    write_coverage(d, {INJ: entries})
    _, out, m = gate(d, single=True)

    credited = [r for r in m["covered_equiv"] if r["class_id"] == INJ]
    inj_missing = [r for r in m["missing_cells"] if r["class_id"] == INJ]
    assert len(credited) == EQUIV_GROUP_MAX, f"exactly {EQUIV_GROUP_MAX} siblings credited, got {len(credited)}: {credited}"
    assert all(r["representative"] == "u0" for r in credited), f"all credited siblings ride u0: {credited}"
    assert len(inj_missing) == n_sib - EQUIV_GROUP_MAX, f"excess siblings must remain missing: {inj_missing}"
    assert all(r["reason"] == "no_matching_finding" for r in inj_missing), f"excess reason: {inj_missing}"


def test_deferred_substantiated_is_not_missing_and_holds_complete():
    # A substantiated deferred cell (reason + on-disk CIR) is pulled out of missing_cells
    # into deferred_cells; ratio is over RESOLVABLE cells (==1.0 here) but complete stays
    # False until acknowledged.
    tmp = tempfile.mkdtemp()
    hd = net_host(tmp, "10.0.0.30", [{"port": 443, "state": "open", "service": "https", "product": "nginx", "version": "1.28.0"},
                                     {"port": 22, "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.9"}])
    cells = load_cells(tmp, hd)
    defer = next(c for c in cells if c["class_id"] == "XC-SECURITY-HEADERS")  # host-scope active_probe cell
    close_all_but_defer(hd, cells, [defer])
    rc, out, m = gate(hd, single=True)
    assert m["coverage_ratio"] == 1.0, f"all resolvable cells covered -> ratio 1.0: {out}"
    assert m["deferred"] == 1 and not m["complete"] and rc == 1, f"deferred holds complete False: {out}"
    dk = {(r["class_id"], r["scope_key"]) for r in m["deferred_cells"]}
    assert (defer["class_id"], defer["scope_key"]) in dk, f"deferred cell must be bucketed: {m['deferred_cells']}"
    d = m["deferred_cells"][0]
    assert d.get("deferral_reason") and d.get("client_input_request"), f"deferral metadata carried: {d}"
    mk = {(r["class_id"], r["scope_key"]) for r in m["missing_cells"]}
    assert (defer["class_id"], defer["scope_key"]) not in mk, "deferred cell must NOT be in missing_cells"


def test_deferred_acknowledged_completes():
    tmp = tempfile.mkdtemp()
    hd = net_host(tmp, "10.0.0.31", [{"port": 443, "state": "open", "service": "https", "product": "nginx", "version": "1.28.0"},
                                     {"port": 22, "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.9"}])
    cells = load_cells(tmp, hd)
    defer = next(c for c in cells if c["class_id"] == "XC-SECURITY-HEADERS")
    close_all_but_defer(hd, cells, [defer])
    rc, out, m = gate(hd, single=True, accept_deferrals=True)
    assert rc == 0 and m["complete"] and m["deferred_acknowledged"], f"--accept-deferrals completes: {out}"
    assert m["deferred"] == 1 and m["deferred_cells"], "deferred cells stay disclosed even when acknowledged"


def test_deferred_unsubstantiated_is_hard_miss():
    # status:deferred WITHOUT reason/CIR (or with a CIR that does not resolve on disk)
    # can never dodge the gate — it is a hard miss.
    for substantiated, cir in ((False, False), (True, False)):
        tmp = tempfile.mkdtemp()
        hd = net_host(tmp, "10.0.0.32", [{"port": 443, "state": "open", "service": "https", "product": "nginx", "version": "1.28.0"}])
        cells = load_cells(tmp, hd)
        defer = next(c for c in cells if c["class_id"] == "XC-SECURITY-HEADERS")
        # substantiated=True + cir=False => reason present but client_input_request path missing on disk
        if substantiated and not cir:
            close_all_but_defer(hd, cells, [defer], substantiated=True, cir=True)
            # point the CIR at a non-existent file
            rows = json.load(open(os.path.join(hd, "coverage.json")))
            for row in rows:
                for e in row.get("units_tested", []):
                    if e.get("status") == "deferred":
                        e["client_input_request"] = "reports/client-input-requests/DOES-NOT-EXIST.md"
            wjson(os.path.join(hd, "coverage.json"), rows)
        else:
            close_all_but_defer(hd, cells, [defer], substantiated=False)
        rc, out, m = gate(hd, single=True)
        reasons = {r["reason"] for r in m["missing_cells"]}
        assert "deferred_unsubstantiated" in reasons, f"(sub={substantiated},cir={cir}) must be a hard miss: {reasons}"
        assert m["deferred"] == 0 and rc == 1 and not m["complete"], f"unsubstantiated is not a deferral: {out}"


def test_all_deferred_never_completes():
    # A scope where EVERY cell is deferred can never complete (ratio 0.0), even with
    # --accept-deferrals — no resolvable cell was actually tested.
    tmp = tempfile.mkdtemp()
    hd = net_host(tmp, "10.0.0.33", [{"port": 22, "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.9"}])
    cells = load_cells(tmp, hd)
    close_all_but_defer(hd, cells, cells)  # defer ALL cells
    rc, out, m = gate(hd, single=True, accept_deferrals=True)
    assert m["coverage_ratio"] == 0.0 and not m["complete"] and rc == 1, f"all-deferred must hard-block: {out}"


# --- mobile (MASVS) ----------------------------------------------------------
MOBILE_CLASSES = {c["class_id"] for c in CATALOG["classes"] if c["taxonomy"] == "MASVS-2023"}
# the six classes that gate solely on http_listener / tls_listener — a mobile asset
# must never enumerate any of them
WEB_LISTENER_CLASSES = {"XC-CORS", "XC-TRANSPORT-DOWNGRADE", "XC-VERBOSE-ERRORS",
                        "XC-SECURITY-HEADERS", "XC-TLS-POSTURE", "WEB-A06-COMPONENTS"}
# the worked example from masvs-class-map.md / the plan
RN_UNITS = [
    {"unit_id": "cmp:MainActivity", "type": "component",
     "address": "com.example.fieldapp/.MainActivity", "flags": ["exported_component"]},
    {"unit_id": "cmp:DevSettings", "type": "component",
     "address": "com.facebook.react.devsupport.DevSettingsActivity",
     "flags": ["exported_component"], "equiv_group": "rn-devsupport"},
    {"unit_id": "cmp:DevLoading", "type": "component",
     "address": "com.facebook.react.devsupport.DevLoadingView",
     "flags": ["exported_component"], "equiv_group": "rn-devsupport"},
    {"unit_id": "dl:ticket", "type": "deeplink", "address": "fieldapp://ticket/{id}", "flags": []},
    {"unit_id": "wv:Help", "type": "webview",
     "address": "com.example.fieldapp.ui.HelpWebView#onCreate", "flags": ["webview"]},
    {"unit_id": "st:prefs", "type": "storage",
     "address": "/data/data/com.example.fieldapp/shared_prefs/session.xml", "flags": ["local_store"]},
    {"unit_id": "st:rkstorage", "type": "storage",
     "address": "/data/data/com.example.fieldapp/databases/RKStorage", "flags": ["local_store"]},
    {"unit_id": "cy:Envelope", "type": "crypto-use",
     "address": "com/example/fieldapp/net/Envelope;->encrypt", "flags": ["crypto_use"]},
]


def mobile_app(base, tag, units, platform="android", dirname=None, flags=None):
    d = os.path.join(base, dirname or tag)
    wjson(os.path.join(d, "recon", "inventory", "mobile-surface.json"),
          {"schema": "mobile-surface/v1", "asset_tag": tag, "platform": platform,
           "package": "com.example.fieldapp", "version": "2.4.1",
           "artifact_sha256": "deadbeef", "flags": flags or [], "units": units})
    return d


def test_mobile_never_acquires_http_listener():
    """Trap 1: a mobile unit must never be routed through web_unit_flags/parse_listener.

    web_unit_flags stamps http_listener on EVERY unit unconditionally, and
    parse_listener defaults any colon-less address to '<addr>:443'. If a mobile unit
    ever reached them, `com.example.fieldapp/.MainActivity` would mint the listener
    `com.example.fieldapp:443` and the app would enumerate the four http_listener
    classes. Belt-and-braces so this still fires if a host-scope mobile class is
    ever added.
    """
    import re
    tmp = tempfile.mkdtemp()
    d = mobile_app(tmp, "fieldapp-app", RN_UNITS)
    cells = load_cells(tmp, d)
    raw = open(os.path.join(d, "applicability", "cells.json")).read()
    doc = json.loads(raw)

    assert not [c for c in cells if c["scope"] == "host"], "mobile must yield ZERO host-scope cells"
    got = {c["class_id"] for c in cells}
    assert not (got & WEB_LISTENER_CLASSES), f"listener classes enumerated for an app: {got & WEB_LISTENER_CLASSES}"
    assert not [c for c in cells if re.search(r":\d+$", str(c["scope_key"]))], \
        "no host:port scope_key may be minted from a mobile address"
    assert ":443" not in raw, "parse_listener's :443 default must never touch a mobile asset"
    assert doc["assets"]["fieldapp-app"]["open_listeners"] == []

    sys.path.insert(0, HERE)
    import enumerate_cells as ec
    a = ec.load_mobile_app(d)
    assert a["listener_flags"] == {} and a["kind"] == "mobile"
    assert "http_listener" not in a["asset_flags"] and "tls_listener" not in a["asset_flags"]
    assert all("http_listener" not in u["flags"] for u in a["units"])


def test_mobile_loader_shape():
    """Unit flags must NOT roll up to the asset, or every app double-counts its work-list."""
    sys.path.insert(0, HERE)
    import enumerate_cells as ec
    tmp = tempfile.mkdtemp()
    d = mobile_app(tmp, "fieldapp-app", RN_UNITS)
    a = ec.load_mobile_app(d)
    assert a["asset_flags"] == {"mobile_app"}, f"asset_flags rolled up unit flags: {a['asset_flags']}"
    # an asset-level agent declaration IS honoured
    d2 = mobile_app(tmp, "other-app", RN_UNITS, dirname="other", flags=["static_js_or_repo"])
    a2 = ec.load_mobile_app(d2)
    assert a2["asset_flags"] == {"mobile_app", "static_js_or_repo"}
    # a derived flag can never be injected by the agent
    d3 = mobile_app(tmp, "evil-app", RN_UNITS, dirname="evil", flags=["http_listener", "is_apex"])
    a3 = ec.load_mobile_app(d3)
    assert a3["asset_flags"] == {"mobile_app"}, "an agent must not be able to declare a DERIVED flag"


def test_mobile_per_class_enumeration():
    tmp = tempfile.mkdtemp()
    d = mobile_app(tmp, "fieldapp-app", RN_UNITS)
    cells = load_cells(tmp, d)
    unit_cells = [c for c in cells if c["scope"] == "unit"]
    asset_cells = [c for c in cells if c["scope"] == "asset"]
    by_class = {}
    for c in unit_cells:
        by_class.setdefault(c["class_id"], []).append(c["scope_key"])
    assert len(by_class["MAS-PLATFORM-IPC"]) == 4, by_class.get("MAS-PLATFORM-IPC")
    assert len(by_class["MAS-PLATFORM-WEBVIEW"]) == 1
    assert len(by_class["MAS-STORAGE-LOCAL"]) == 2
    assert len(by_class["MAS-CRYPTO-WEAK"]) == 1
    assert len(unit_cells) == 8, f"expected 8 unit cells, got {len(unit_cells)}"
    # 11 MASVS asset classes + the unconditional API8-MISCONFIG
    assert len(asset_cells) == 12, f"expected 12 asset cells, got {len(asset_cells)}"
    assert all(c["scope_key"] == "fieldapp-app" for c in asset_cells)


def test_mobile_shares_only_api8():
    """The sharpest statement of disjointness: mobile and web classes never cross."""
    tmp = tempfile.mkdtemp()
    d = mobile_app(tmp, "fieldapp-app", RN_UNITS)
    got = {c["class_id"] for c in load_cells(tmp, d)}
    assert got - MOBILE_CLASSES == {"API8-MISCONFIG"}, f"unexpected web classes on an app: {got - MOBILE_CLASSES}"


def test_web_asset_gets_no_mobile_cells():
    tmp = tempfile.mkdtemp()
    d = web_asset(tmp, "api-demo", [{"unit_id": "u-1", "type": "endpoint",
                                     "address": "https://api.demo.test/v1/x/{id}",
                                     "flags": ["object_by_id", "json_body"]}])
    got = {c["class_id"] for c in load_cells(tmp, d)}
    assert not (got & MOBILE_CLASSES), f"mobile classes leaked onto a web asset: {got & MOBILE_CLASSES}"


def test_mobile_type_implies_flag():
    """A declared type adds its flag even when the agent omitted it (monotone)."""
    tmp = tempfile.mkdtemp()
    d = mobile_app(tmp, "fieldapp-app", [
        {"unit_id": "wv:bare", "type": "webview", "address": "X#onCreate", "flags": []},
    ])
    got = {c["class_id"] for c in load_cells(tmp, d) if c["scope"] == "unit"}
    assert got == {"MAS-PLATFORM-WEBVIEW"}, got


def test_mobile_zero_units_still_owes_asset_cells():
    """A units-less app is a recon FAILURE, not an absent asset (unlike a dead host)."""
    tmp = tempfile.mkdtemp()
    d = mobile_app(tmp, "fieldapp-app", [])
    cells = load_cells(tmp, d)
    assert len(cells) == 12, f"expected the 12 asset cells, got {len(cells)}"
    rc, out, m = gate(d, single=True)
    assert rc == 1 and not m["complete"], "an unenumerated app must block, not pass vacuously"


def test_mobile_active_probe_needs_corroborator():
    tmp = tempfile.mkdtemp()
    d = mobile_app(tmp, "fieldapp-app", RN_UNITS)
    cells = load_cells(tmp, d)
    target = next(c for c in cells if c["class_id"] == "MAS-RESILIENCE-ROOT")
    append_experiment(d, "E-001")
    write_coverage(d, {"MAS-RESILIENCE-ROOT": [
        {"key": target["scope_key"], "status": "covered_negative", "e_id": "E-001"}]})
    rc, out, m = gate(d, single=True)
    bad = [r for r in m["missing_cells"] if r["class_id"] == "MAS-RESILIENCE-ROOT"]
    assert bad and bad[0]["reason"] == "uncorroborated_negative", bad
    write_tool_md(d, "E-001")
    rc, out, m = gate(d, single=True)
    assert not [r for r in m["missing_cells"] if r["class_id"] == "MAS-RESILIENCE-ROOT"], \
        "a corroborated negative must close the cell"


def test_only_runtime_cells_are_device_deferrable():
    """A device excuse is valid ONLY for a cell that genuinely needs a device.

    static  -> provable from the artifact; a missing device is no excuse.
    either  -> the static route stays open when no device is available; likewise.
    runtime -> genuinely blocked, so a substantiated device deferral is legitimate.
    """
    tmp = tempfile.mkdtemp()
    d = mobile_app(tmp, "fieldapp-app", RN_UNITS)
    cells = load_cells(tmp, d)
    pick = lambda cid: next(c for c in cells if c["class_id"] == cid)
    static_cell, either_cell = pick("MAS-NETWORK-CLEARTEXT"), pick("MAS-CRYPTO-KEYMGMT")
    runtime_cell, web_cell = pick("MAS-NETWORK-PINNING"), pick("API8-MISCONFIG")
    assert static_cell["proof_mode"] == "static"
    assert either_cell["proof_mode"] == "either"
    assert runtime_cell["proof_mode"] == "runtime"
    assert web_cell["proof_mode"] == "either", "a class with no proof_mode defaults to either"
    cir = write_cir(d)
    defer = {"status": "deferred", "deferral_reason": "no rooted device available",
             "client_input_request": cir, "blocked_on": "device"}
    write_coverage(d, {c["class_id"]: [{"key": c["scope_key"], **defer}]
                       for c in (static_cell, either_cell, runtime_cell, web_cell)})
    rc, out, m = gate(d, single=True, accept_deferrals=True)
    rejected = {r["class_id"] for r in m["missing_cells"]
                if r["reason"] == "deferred_device_excuse_on_provable_cell"}
    deferred = {r["class_id"] for r in m["deferred_cells"]}
    assert rejected == {"MAS-NETWORK-CLEARTEXT", "MAS-CRYPTO-KEYMGMT", "API8-MISCONFIG"}, rejected
    assert deferred == {"MAS-NETWORK-PINNING"}, deferred
    assert not (rejected & deferred)


def test_non_device_deferral_still_works_for_any_cell():
    """Tightening the DEVICE excuse must not break deferrals for other blockers."""
    tmp = tempfile.mkdtemp()
    d = mobile_app(tmp, "fieldapp-app", RN_UNITS)
    cells = load_cells(tmp, d)
    static_cell = next(c for c in cells if c["class_id"] == "MAS-NETWORK-CLEARTEXT")
    cir = write_cir(d)
    write_coverage(d, {"MAS-NETWORK-CLEARTEXT": [{
        "key": static_cell["scope_key"], "status": "deferred",
        "deferral_reason": "client has not released the production build for analysis",
        "client_input_request": cir, "blocked_on": "artifact"}]})
    rc, out, m = gate(d, single=True, accept_deferrals=True)
    assert any(r["class_id"] == "MAS-NETWORK-CLEARTEXT" for r in m["deferred_cells"]), \
        "a non-device blocker must still be deferrable on a static cell"


def test_mobile_dast_deferral_lifecycle():
    tmp = tempfile.mkdtemp()
    d = mobile_app(tmp, "fieldapp-app", RN_UNITS)
    cells = load_cells(tmp, d)
    runtime_cells = [c for c in cells if c["proof_mode"] == "runtime"]
    assert runtime_cells, "the catalog must mark some mobile cells runtime-only"
    close_all_but_defer(d, cells, runtime_cells)
    rc, out, m = gate(d, single=True)
    assert not m["complete"], "deferrals must not silently complete without --accept-deferrals"
    rc, out, m = gate(d, single=True, accept_deferrals=True)
    deferred_ids = {c["class_id"] for c in m["deferred_cells"]}
    assert deferred_ids == {c["class_id"] for c in runtime_cells}, deferred_ids
    assert not m["missing_cells"], f"substantiated deferrals are not misses: {m['missing_cells']}"
    assert m["complete"], out


def test_mobile_unsubstantiated_deferral_is_hard_miss():
    tmp = tempfile.mkdtemp()
    d = mobile_app(tmp, "fieldapp-app", RN_UNITS)
    cells = load_cells(tmp, d)
    runtime_cells = [c for c in cells if c["proof_mode"] == "runtime"]
    close_all_but_defer(d, cells, runtime_cells, cir=False)  # CIR path does not resolve
    rc, out, m = gate(d, single=True, accept_deferrals=True)
    assert rc == 1 and not m["complete"]
    assert any(c["reason"] == "deferred_unsubstantiated" for c in m["missing_cells"]), m["missing_cells"]


def test_emit_open_marks_runtime_cells():
    tmp = tempfile.mkdtemp()
    d = mobile_app(tmp, "fieldapp-app", [])
    load_cells(tmp, d)
    rc, out, _ = gate(d, single=True, emit_open=True)
    assert "[runtime]" in out, f"open runtime cells must be annotated for THINK routing:\n{out}"
    assert "MAS-NETWORK-PINNING" in out


def test_mobile_equiv_group():
    """Near-identical exported components ride one real probe."""
    tmp = tempfile.mkdtemp()
    d = mobile_app(tmp, "fieldapp-app", RN_UNITS)
    cells = load_cells(tmp, d)
    ipc = [c for c in cells if c["class_id"] == "MAS-PLATFORM-IPC"]
    grouped = [c for c in ipc if c.get("equiv_group") == "rn-devsupport"]
    assert len(grouped) == 2, grouped
    rep, sibling = grouped[0], grouped[1]
    append_experiment(d, "E-010")
    write_validated(d, "F-01", "MAS-PLATFORM-IPC", [rep["scope_key"]], "fieldapp-app")
    write_coverage(d, {"MAS-PLATFORM-IPC": [
        {"key": rep["scope_key"], "status": "covered", "e_id": "E-010"},
        {"key": sibling["scope_key"], "status": "covered", "e_id": "E-010"},
    ]})
    rc, out, m = gate(d, single=True)
    sib = next((r for r in m["covered_equiv"] if r["scope_key"] == sibling["scope_key"]), None)
    assert sib is not None and sib.get("representative") == rep["scope_key"], m["covered_equiv"]
    assert not [r for r in m["missing_cells"] if r["scope_key"] == sibling["scope_key"]]


def test_mobile_and_web_in_separate_dirs():
    """The MAPT layout: app bundle and its recovered backend, each its own asset dir.

    They MUST NOT share a directory — coverage_gate loads the ledger per asset_dir,
    so a shared coverage.json makes each asset see the other's entries as extra_cells,
    mutually, and `complete` becomes unreachable.
    """
    tmp = tempfile.mkdtemp()
    app = mobile_app(tmp, "fieldapp-app", RN_UNITS)
    api = web_asset(tmp, "example-api", [{"unit_id": "u-1", "type": "endpoint",
                                          "address": "https://api.example.test/v1/t/{id}",
                                          "flags": ["object_by_id"]}], apex="example.test")
    assert os.path.dirname(app) == os.path.dirname(api) and app != api
    enum(tmp)
    doc = json.loads(open(os.path.join(tmp, "applicability", "cells.json")).read())
    assert set(doc["assets"]) == {"fieldapp-app", "example-api"}
    assert doc["assets"]["fieldapp-app"]["kind"] == "mobile"
    assert doc["assets"]["example-api"]["kind"] == "web"
    app_ids = {c["class_id"] for c in doc["cells"] if c["asset_tag"] == "fieldapp-app"}
    api_ids = {c["class_id"] for c in doc["cells"] if c["asset_tag"] == "example-api"}
    assert not (app_ids & WEB_LISTENER_CLASSES)
    assert not (api_ids & MOBILE_CLASSES)
    rc, out, m = gate(tmp)
    assert not m["extra_cells"], f"separate dirs must not cross-contaminate: {m['extra_cells']}"


def test_duplicate_asset_tag_fails_closed():
    tmp = tempfile.mkdtemp()
    mobile_app(tmp, "same-tag", RN_UNITS, dirname="a")
    web_asset(tmp, "same-tag", [{"unit_id": "u-1", "type": "endpoint",
                                 "address": "https://x.test/", "flags": []}])
    rc, out = enum(tmp)
    assert rc == 2, f"a duplicate asset_tag must fail closed (exit 2), got {rc}: {out}"
    assert "duplicate asset_tag" in out


def test_mobile_no_surface_undercount():
    """surface_undercount is web-only; a subdomains.json beside an app must not trip it."""
    tmp = tempfile.mkdtemp()
    d = mobile_app(tmp, "fieldapp-app", RN_UNITS)
    wjson(os.path.join(d, "recon", "inventory", "subdomains.json"),
          [{"host": "never-enumerated.example.test"}])
    cells = load_cells(tmp, d)
    close_all(d, cells)
    rc, out, m = gate(d, single=True)
    assert not m["surface_undercount"], m["surface_undercount"]


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
