#!/usr/bin/env python3
"""Tests for tools/verify_source_ip.py and the register->verify->gate contract.

The property under test is the one that closes the fabrication hole: a vantage
counts toward coverage_gate's min_vantages ONLY after an egress echo that names
the IP has been stored on disk. Registration alone, a dry run, a mismatched
echo, or a duplicate egress must all fail to produce a countable vantage.

No network. Run: python3 tools/test_verify_source_ip.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import coverage_gate  # noqa: E402


def run(args, stdin=None):
    return subprocess.run([sys.executable] + args, capture_output=True, text=True,
                          input=stdin, cwd=REPO)


def register(root, ip, role="attack-vm", region="asia-south1"):
    return run([os.path.join(HERE, "register_source_ip.py"), ip, "--role", role,
                "--region", region, "--engagement", root])


def verify(root, ip, evidence, role="attack-vm", region="asia-south1", extra=()):
    return run([os.path.join(HERE, "verify_source_ip.py"), "--ip", ip, "--role", role,
                "--region", region, "--evidence-file", "-", "--engagement", root,
                *extra], stdin=evidence)


def rows(root):
    p = os.path.join(root, "logs", "activity", "source-ips.jsonl")
    if not os.path.isfile(p):
        return []
    return [json.loads(x) for x in open(p) if x.strip()]


def regions(root):
    return coverage_gate.load_verified_regions([root])


FAILURES = []


def check(name, cond, detail=""):
    if cond:
        print(f"  PASS {name}")
    else:
        print(f"  FAIL {name}: {detail}")
        FAILURES.append(name)


def test_register_is_never_verified():
    with tempfile.TemporaryDirectory() as t:
        r = register(t, "203.0.113.10")
        check("register exits 0", r.returncode == 0, r.stderr)
        row = rows(t)[0]
        check("register writes verified:false", row["verified"] is False, row)
        check("register writes empty probe_evidence", row["probe_evidence"] == "", row)
        check("registration alone yields no countable vantage", regions(t) == set(), regions(t))


def test_verify_requires_matching_evidence():
    with tempfile.TemporaryDirectory() as t:
        register(t, "203.0.113.11")
        r = verify(t, "203.0.113.11", "curl: (7) Failed to connect\n")
        check("mismatched echo exits non-zero", r.returncode == 1, r.stdout + r.stderr)
        check("mismatched echo names the refusal", "refusing to mark verified" in r.stderr, r.stderr)
        check("mismatched echo appends nothing", len(rows(t)) == 1, rows(t))
        check("mismatched echo yields no vantage", regions(t) == set(), regions(t))


def test_verify_happy_path_counts():
    with tempfile.TemporaryDirectory() as t:
        register(t, "203.0.113.12")
        r = verify(t, "203.0.113.12", "203.0.113.12\n")
        check("verify exits 0", r.returncode == 0, r.stderr)
        row = rows(t)[-1]
        check("verify appends verified:true", row["verified"] is True, row)
        check("verify records probe_evidence", row["probe_evidence"].endswith(".txt"), row)
        check("evidence file exists and holds the ip",
              os.path.isfile(os.path.join(t, row["probe_evidence"])) and
              "203.0.113.12" in open(os.path.join(t, row["probe_evidence"])).read(), row)
        check("ledger stays append-only (2 rows, registration intact)",
              len(rows(t)) == 2 and rows(t)[0]["verified"] is False, rows(t))
        check("verified vantage counts", regions(t) == {"asia-south1"}, regions(t))


def test_dry_run_cannot_manufacture_a_vantage():
    with tempfile.TemporaryDirectory() as t:
        register(t, "203.0.113.13")
        r = verify(t, "203.0.113.13", "203.0.113.13\n", extra=("--dry-run",))
        check("dry-run exits 0", r.returncode == 0, r.stderr)
        check("dry-run appends nothing", len(rows(t)) == 1, rows(t))
        check("dry-run yields no vantage", regions(t) == set(), regions(t))


def test_two_regions_one_egress_is_one_vantage():
    with tempfile.TemporaryDirectory() as t:
        verify(t, "203.0.113.14", "203.0.113.14\n", region="us-east")
        verify(t, "203.0.113.14", "203.0.113.14\n", region="us-east-2")
        check("same egress under two region spellings dedupes to one vantage",
              len(regions(t)) == 1, regions(t))


def test_two_distinct_egresses_are_two_vantages():
    with tempfile.TemporaryDirectory() as t:
        verify(t, "203.0.113.15", "203.0.113.15\n", region="eu-west")
        verify(t, "203.0.113.16", "203.0.113.16\n", region="us-east")
        check("two proven egresses give two vantages",
              regions(t) == {"eu-west", "us-east"}, regions(t))


def test_proxy_role_is_not_a_geography():
    with tempfile.TemporaryDirectory() as t:
        verify(t, "203.0.113.17", "203.0.113.17\n", role="proxy", region="eu-west")
        verify(t, "203.0.113.18", "203.0.113.18\n", role="vpn", region="us-east")
        check("proxy excluded, vpn counted", regions(t) == {"us-east"}, regions(t))


def test_deleted_evidence_revokes_the_vantage():
    with tempfile.TemporaryDirectory() as t:
        verify(t, "203.0.113.19", "203.0.113.19\n", region="eu-west")
        check("counted while evidence present", regions(t) == {"eu-west"}, regions(t))
        os.remove(os.path.join(t, rows(t)[-1]["probe_evidence"]))
        check("evidence removed -> vantage no longer counts", regions(t) == set(), regions(t))


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        print(t.__name__)
        t()
    print(f"\n{len(tests) - len({f.split(':')[0] for f in FAILURES})}/{len(tests)} test groups clean"
          if FAILURES else f"\n{len(tests)}/{len(tests)} test groups clean")
    sys.exit(1 if FAILURES else 0)
