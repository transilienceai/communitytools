#!/usr/bin/env python3
"""Tests for tools/register_source_ip.py. Stdlib only.
Run: python3 tools/test_register_source_ip.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "register_source_ip.py")


def run(root, ip, *args):
    p = subprocess.run([sys.executable, SCRIPT, ip, "--engagement", root, *args],
                       capture_output=True, text=True)
    assert p.returncode == 0, f"exit {p.returncode}: {p.stderr}"
    return p


def read(root):
    path = os.path.join(root, "logs", "activity", "source-ips.jsonl")
    with open(path) as f:
        return [json.loads(x) for x in f if x.strip()]


def test_single_line_all_flags_and_selfcreate():
    with tempfile.TemporaryDirectory() as d:
        # logs/activity does not exist yet — the helper must create it.
        run(d, "203.0.113.5", "--role", "attack-vm", "--provider", "gcp",
            "--region", "asia-south1", "--note", "mumbai vantage")
        rows = read(d)
        assert len(rows) == 1
        r = rows[0]
        assert r["ip"] == "203.0.113.5" and r["role"] == "attack-vm"
        assert r["provider"] == "gcp" and r["region"] == "asia-south1"
        assert r["note"] == "mumbai vantage"
        assert r["source"] == "register_source_ip" and r["verified"] is True
        assert r["ts"], "ts must be present in the raw log"


def test_append_no_dedup():
    with tempfile.TemporaryDirectory() as d:
        run(d, "203.0.113.5", "--role", "primary-runner")
        run(d, "198.51.100.9", "--role", "attack-vm")
        run(d, "203.0.113.5", "--role", "primary-runner")  # duplicate -> still appends
        rows = read(d)
        assert len(rows) == 3, rows
        assert rows[0]["ip"] == "203.0.113.5" and rows[1]["ip"] == "198.51.100.9"
        # omitted optional flags serialize as empty strings, not null
        assert rows[0]["provider"] == "" and rows[0]["region"] == ""


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
