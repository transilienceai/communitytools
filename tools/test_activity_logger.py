#!/usr/bin/env python3
"""Tests for tools/activity-logger.py (the PostToolUse Bash hook).

Pure functions (parse_bins, redact, resolve_root, derive_asset, detect_ips,
append_jsonl) are imported directly; the stdin→file behaviour + exit-0 contract
is exercised via subprocess. Stdlib only.
Run: python3 tools/test_activity_logger.py
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "activity-logger.py")

_spec = importlib.util.spec_from_file_location("activity_logger", SCRIPT)
al = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(al)


def _touch(path, content="{}"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def run_hook(payload, cwd, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    p = subprocess.run([sys.executable, SCRIPT], input=json.dumps(payload),
                       capture_output=True, text=True, cwd=cwd, env=e)
    assert p.returncode == 0, f"exit {p.returncode}: {p.stderr}"
    return p


def read_inv(root):
    path = os.path.join(root, "logs", "activity", "tool-invocations.jsonl")
    with open(path) as f:
        return [json.loads(x) for x in f if x.strip()]


# --- parse_bins ---------------------------------------------------------------

def test_parse_bins():
    cases = {
        "env FOO=bar nmap -sV h": ["nmap"],
        "sudo -u www-data time nmap h": ["nmap"],
        "python3 exploit.py --x": ["exploit.py"],
        "perl a.pl": ["a.pl"], "ruby b.rb": ["b.rb"],
        "bash s.sh": ["s.sh"], "node c.js": ["c.js"],
        "python3 -c 'import x'": ["python3"],
        "python3 -m http.server": ["python3"],
        "bash -c 'id'": ["bash"],
        "nmap && nikto ; gobuster | grep x": ["nmap", "nikto", "gobuster", "grep"],
        "echo 'a; b' | grep x": ["grep"],           # quoted ; is not a split
        "cd /tmp && ls && cat f": [],               # all trivial
        "FOO=1 BAR=2 curl http://x": ["curl"],
    }
    for cmd, expected in cases.items():
        got = al.parse_bins(cmd)
        assert got == expected, f"{cmd!r}: got {got}, want {expected}"


# --- redact -------------------------------------------------------------------

def test_redact_masks_secrets():
    secret_cases = [
        ("curl -H 'Authorization: Bearer abc123XYZ' http://x", "abc123XYZ"),
        ("mysql --password=SuperSecret1 -h db", "SuperSecret1"),
        ("curl -u admin:hunter2 http://x", "hunter2"),
        ("curl -H 'Cookie: session=deadbeef' http://x", "deadbeef"),
        ("curl 'http://x/?api_key=KEY_9f8e' ", "KEY_9f8e"),
        ("curl 'http://x/?token=TOK_1234' ", "TOK_1234"),
        ("curl https://user:p4ss@host/path", "p4ss"),
    ]
    for cmd, secret in secret_cases:
        out = al.redact(cmd)
        assert secret not in out, f"secret {secret!r} leaked: {out!r}"


def test_redact_preserves_benign():
    for cmd in ("nmap -p80 host", "nmap -p- -sV 10.0.0.1", "nmap -sU -p1-100 h",
                "gobuster dir -u http://x -w list.txt"):
        assert al.redact(cmd) == cmd, f"benign command altered: {cmd!r}"


# --- resolve_root + derive_asset ---------------------------------------------

def test_root_meta_beats_nearer_stats():
    with tempfile.TemporaryDirectory() as T:
        _touch(os.path.join(T, "eng", "engagement-meta.json"))
        _touch(os.path.join(T, "eng", "hosts", "1.2.3.4", "stats.json"))
        root, asset, how = al.resolve_root(
            "nmap -oA eng/hosts/1.2.3.4/recon/scan h", cwd=T, repo_cwd=T)
        assert root == os.path.join(T, "eng"), (root, how)
        assert asset == "1.2.3.4", asset


def test_root_standalone_ctf_stats_only():
    with tempfile.TemporaryDirectory() as T:
        _touch(os.path.join(T, "ctf", "stats.json"))
        root, asset, how = al.resolve_root("nmap -oA ctf/recon/scan h", cwd=T, repo_cwd=T)
        assert root == os.path.join(T, "ctf"), (root, how)


def test_root_cwd_fallback_for_pathless():
    with tempfile.TemporaryDirectory() as T:
        eng = os.path.join(T, "eng")
        _touch(os.path.join(eng, "engagement-meta.json"))
        root, asset, how = al.resolve_root("whoami", cwd=eng, repo_cwd=T)
        assert root == eng and how == "meta-cwd", (root, how)


def test_root_pointer_and_stale_pointer():
    with tempfile.TemporaryDirectory() as T:
        eng = os.path.join(T, "eng")
        _touch(os.path.join(eng, "engagement-meta.json"))
        _touch(os.path.join(T, ".claude", "state", "active-engagement"), eng)
        root, _a, how = al.resolve_root("whoami", cwd=T, repo_cwd=T)
        assert root == eng and how == "pointer", (root, how)
        # stale pointer -> orphan (None root)
        _touch(os.path.join(T, ".claude", "state", "active-engagement"),
               os.path.join(T, "gone"))
        root2, _a2, how2 = al.resolve_root("whoami", cwd=T, repo_cwd=T)
        assert root2 is None and how2 == "orphan", (root2, how2)


# --- detect_ips ---------------------------------------------------------------

def test_detect_ips():
    prov = al.detect_ips("gcloud compute instances create vm --zone z",
                         "NAME ZONE EXTERNAL_IP STATUS\nvm z 203.0.113.55 RUNNING", ["gcloud"])
    assert ("attack-vm-detect", "203.0.113.55") in prov, prov
    aws = al.detect_ips("aws ec2 run-instances --image-id ami",
                        '{"PublicIpAddress": "198.51.100.7"}', ["aws"])
    assert ("attack-vm-detect", "198.51.100.7") in aws, aws
    echo = al.detect_ips("curl -s ifconfig.me", "203.0.113.9\n", ["curl"])
    assert ("egress-detect", "203.0.113.9") in echo, echo
    assert al.detect_ips("nmap -V", "Nmap version 7.94", ["nmap"]) == []
    # private IPs in provisioning output are ignored
    assert al.detect_ips("gcloud compute instances create vm --zone z",
                         "10.0.0.5 192.168.1.2", ["gcloud"]) == []


# --- append_jsonl (atomicity + oversized) ------------------------------------

def test_append_oversized_stays_valid_and_bounded():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "logs", "activity", "t.jsonl")
        al.append_jsonl(path, {"full_command": "A" * 6000, "bins": ["nmap"], "ts": "x"})
        with open(path, "rb") as f:
            raw = f.readline()
        assert len(raw) < al.MAX_LINE, len(raw)
        obj = json.loads(raw)
        assert "truncated" in obj["full_command"] and obj["bins"] == ["nmap"]


def test_append_concurrent_lines_intact():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "logs", "activity", "c.jsonl")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        N, K = 20, 25
        pids = []
        for i in range(N):
            pid = os.fork()
            if pid == 0:  # child
                try:
                    for j in range(K):
                        al.append_jsonl(path, {"full_command": f"c{i}-{j}", "n": i * 1000 + j})
                finally:
                    os._exit(0)
            pids.append(pid)
        for pid in pids:
            os.waitpid(pid, 0)
        with open(path) as f:
            lines = [x for x in f if x.strip()]
        assert len(lines) == N * K, f"{len(lines)} != {N*K}"
        for x in lines:
            json.loads(x)  # every line is intact JSON (no interleave)


# --- end-to-end via subprocess (main + exit-0 contract) ----------------------

def test_e2e_dual_shape_and_agent_id():
    with tempfile.TemporaryDirectory() as T:
        eng = os.path.join(T, "eng")
        _touch(os.path.join(eng, "engagement-meta.json"))
        # shape 1: tool_response dict
        run_hook({"tool_input": {"command": "nmap -oA eng/web1/recon/s h"},
                  "cwd": T, "agent_id": "sub-42", "agent_type": "executor",
                  "tool_response": {"exit_code": 0, "stdout": "80/tcp open"}}, cwd=T)
        # shape 2: tool_output list
        run_hook({"tool_input": {"command": "curl -sv eng/web1/x"},
                  "cwd": T, "agent_id": None, "agent_type": None,
                  "tool_output": [{"type": "stdout", "content": "ok"},
                                  {"type": "exit_code", "content": "0"}]}, cwd=T)
        rows = read_inv(eng)
        assert len(rows) == 2, rows
        r0 = rows[0]
        assert r0["bins"] == ["nmap"] and r0["agent_id"] == "sub-42"
        assert r0["agent_type"] == "executor" and r0["exit_code"] == 0
        assert r0["asset"] == "web1" and r0["cwd"] == T
        assert rows[1]["bins"] == ["curl"] and rows[1]["exit_code"] == 0


def test_e2e_redact_default_and_opt_out():
    with tempfile.TemporaryDirectory() as T:
        eng = os.path.join(T, "eng")
        _touch(os.path.join(eng, "engagement-meta.json"))
        cmd = "curl -H 'Authorization: Bearer SEKRET1' eng/x"
        run_hook({"tool_input": {"command": cmd}, "cwd": T}, cwd=T)
        assert "SEKRET1" not in read_inv(eng)[0]["full_command"]
        run_hook({"tool_input": {"command": cmd}, "cwd": T}, cwd=T,
                 env={"ACTIVITY_LOG_NO_REDACT": "1"})
        assert "SEKRET1" in read_inv(eng)[1]["full_command"]


def test_e2e_orphan_and_bad_input_exit0():
    with tempfile.TemporaryDirectory() as T:
        # path-less command, no marker anywhere -> orphan under <cwd>/.claude/state
        run_hook({"tool_input": {"command": "whoami"}, "cwd": T}, cwd=T)
        orphan = os.path.join(T, ".claude", "state", "activity-orphan.jsonl")
        assert os.path.isfile(orphan), "orphan log must catch unresolved commands"
        # garbage / empty stdin -> exit 0, no traceback
        for bad in ("", "not json", "{}", '{"tool_input":{"command":""}}'):
            p = subprocess.run([sys.executable, SCRIPT], input=bad,
                               capture_output=True, text=True, cwd=T)
            assert p.returncode == 0, (bad, p.stderr)
            assert "Traceback" not in p.stderr


def test_source_is_network_free():
    src = open(SCRIPT).read()
    for bad in ("import socket", "import urllib", "import requests",
                "http.client", "from urllib", "import ssl"):
        assert bad not in src, f"hook must be network-free; found {bad!r}"


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
