#!/usr/bin/env python3
"""Tests for tools/validation_cache.py — the deterministic replay-cache.

Stdlib only (tempfile + subprocess + json). Drives the tool through its CLI so
what is tested is exactly what the pipeline invokes. Run:
    python3 tools/test_validation_cache.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "validation_cache.py")


def run(args, expect=0):
    """Run the tool; assert exit code; return (parsed-stdout-json, proc)."""
    proc = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    assert proc.returncode == expect, \
        f"exit {proc.returncode} (want {expect}); args={args}; stderr={proc.stderr}; stdout={proc.stdout}"
    out = json.loads(proc.stdout) if proc.stdout.strip() else {}
    return out, proc


def make_finding(base, fid="F1", description="the finding\n", poc="print('poc')\n",
                 raw_source="secret-source\n"):
    """Create a finding dir with the hashed INPUT files under `base`."""
    d = os.path.join(base, "findings", "finding-1")
    os.makedirs(os.path.join(d, "evidence"), exist_ok=True)
    with open(os.path.join(d, "description.md"), "w") as f:
        f.write(description)
    with open(os.path.join(d, "poc.py"), "w") as f:
        f.write(poc)
    with open(os.path.join(d, "evidence", "raw-source.txt"), "w") as f:
        f.write(raw_source)
    return d


def add_validation_output(finding_dir, name="validation-summary.md", body="validator wrote this\n"):
    """Write a file under evidence/validation/ (the validator's own output)."""
    vdir = os.path.join(finding_dir, "evidence", "validation")
    os.makedirs(vdir, exist_ok=True)
    with open(os.path.join(vdir, name), "w") as f:
        f.write(body)


def interim(fid="F1", verdict="VALID", title="My Finding", proof_dir=None):
    return {
        "finding_id": fid,
        "verdict": verdict,
        "severity": "High",
        "report_fields": {"title": title, "description": "d"},
        "proof_dir": proof_dir,
    }


def write_interim(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # Match validate-findings.js: JSON.stringify(interim, null, 2), no trailing newline.
    with open(path, "w") as f:
        f.write(json.dumps(obj, indent=2))


# --------------------------------------------------------------------------- #
# (1) hash is stable, ignores evidence/validation/**, tracks the real inputs
# --------------------------------------------------------------------------- #
def test_hash_is_stable_and_ignores_validation_subtree():
    with tempfile.TemporaryDirectory() as base:
        d = make_finding(base)
        h1, _ = run(["hash", "--finding-dir", d])
        h2, _ = run(["hash", "--finding-dir", d])
        assert h1["hash"] == h2["hash"], "hash must be stable across calls"
        assert len(h1["hash"]) == 64, "sha256 hex"

        # Adding validator output under evidence/validation/ must NOT change it.
        add_validation_output(d)
        add_validation_output(d, name="poc-rerun-output.txt", body="rerun\n")
        h3, _ = run(["hash", "--finding-dir", d])
        assert h3["hash"] == h1["hash"], "evidence/validation/** must be excluded from the hash"


def test_hash_changes_when_real_inputs_change():
    with tempfile.TemporaryDirectory() as base:
        d = make_finding(base)
        h0, _ = run(["hash", "--finding-dir", d])
        # description.md
        with open(os.path.join(d, "description.md"), "w") as f:
            f.write("CHANGED\n")
        hd, _ = run(["hash", "--finding-dir", d])
        assert hd["hash"] != h0["hash"], "description.md change must move the hash"
        # poc.py
        with open(os.path.join(d, "poc.py"), "w") as f:
            f.write("print('changed')\n")
        hp, _ = run(["hash", "--finding-dir", d])
        assert hp["hash"] != hd["hash"], "poc.py change must move the hash"
        # evidence/raw-source.txt
        with open(os.path.join(d, "evidence", "raw-source.txt"), "w") as f:
            f.write("CHANGED-SOURCE\n")
        he, _ = run(["hash", "--finding-dir", d])
        assert he["hash"] != hp["hash"], "evidence/* change must move the hash"


# --------------------------------------------------------------------------- #
# (2) key = interim-<hash> and follows the sanitize rule
# --------------------------------------------------------------------------- #
def test_key_format_and_sanitize():
    out, _ = run(["key", "--prompt-id", "interim", "--hash", "abc123"])
    assert out["key"] == "interim-abc123", out["key"]
    # A weird char in the hash is replaced with '_' (both fields sanitized).
    out2, _ = run(["key", "--prompt-id", "inte/rim", "--hash", "ab/cd ef"])
    assert out2["key"] == "inte_rim-ab_cd_ef", out2["key"]


# --------------------------------------------------------------------------- #
# (3) store -> restore round-trip is byte-identical; verdict routes the subdir
# --------------------------------------------------------------------------- #
def _store(eng, cache, obj):
    """Create the finding UNDER the engagement dir `eng` (as the real pipeline
    does: findings/ live under OUTPUT_DIR), write the interim to
    <finding_dir>/evidence/validation/<id>.json, and store it."""
    d = make_finding(eng, fid=obj["finding_id"])
    obj = dict(obj)
    obj["proof_dir"] = os.path.join(d, "evidence", "validation")
    interim_path = os.path.join(obj["proof_dir"], obj["finding_id"] + ".json")
    write_interim(interim_path, obj)
    out, _ = run(["store", "--cache-dir", cache, "--interim-file", interim_path])
    return d, interim_path, out


def test_store_restore_roundtrip_byte_identical():
    # `eng` is the engagement/output dir: it holds findings/ AND receives the
    # restored artifacts/validated tree (finding_dir is contained within it).
    with tempfile.TemporaryDirectory() as eng, tempfile.TemporaryDirectory() as cache:
        d, interim_path, s = _store(eng, cache, interim("F1", "VALID"))
        assert s["stored"] is True, s
        original = open(interim_path, "rb").read()

        r, _ = run(["restore", "--finding-dir", d, "--cache-dir", cache, "--output-dir", eng])
        assert r["restored"] is True, r
        assert r["id"] == "F1" and r["verdict"] == "VALID" and r["title"] == "My Finding", r
        for rel in ("artifacts/validated/F1.json", "validated/F1.json"):
            got = open(os.path.join(eng, rel), "rb").read()
            assert got == original, f"{rel} must be byte-identical to the stored interim"


def test_verdict_routes_terminal_subdir():
    for verdict, sub in (("VALID", "validated"), ("REPAIRED", "validated"),
                         ("REJECTED", "false-positives"), ("DEMOTED", "dropped")):
        with tempfile.TemporaryDirectory() as eng, tempfile.TemporaryDirectory() as cache:
            fid = "F_" + verdict
            d, _, s = _store(eng, cache, interim(fid, verdict))
            assert s["stored"] is True, s
            r, _ = run(["restore", "--finding-dir", d, "--cache-dir", cache, "--output-dir", eng])
            assert r["restored"] is True and r["verdict"] == verdict, r
            assert os.path.isfile(os.path.join(eng, "artifacts", sub, fid + ".json")), \
                f"{verdict} must land in {sub}/"
            assert os.path.isfile(os.path.join(eng, sub, fid + ".json"))


# --------------------------------------------------------------------------- #
# (4) restore MISS writes nothing
# --------------------------------------------------------------------------- #
def test_restore_miss_writes_nothing():
    with tempfile.TemporaryDirectory() as eng, tempfile.TemporaryDirectory() as cache:
        d = make_finding(eng)
        r, _ = run(["restore", "--finding-dir", d, "--cache-dir", cache, "--output-dir", eng])
        assert r["restored"] is False and "hash" in r, r
        # No terminal/output tree may be created on a MISS.
        for sub in ("artifacts", "validated", "false-positives", "dropped"):
            assert not os.path.exists(os.path.join(eng, sub)), f"MISS must not create {sub}/"
        assert os.listdir(cache) == [], "restore must never write to the cache"


# --------------------------------------------------------------------------- #
# (5) store is write-once
# --------------------------------------------------------------------------- #
def test_store_is_write_once():
    with tempfile.TemporaryDirectory() as eng, tempfile.TemporaryDirectory() as cache:
        _, interim_path, s1 = _store(eng, cache, interim("F1", "VALID"))
        assert s1["stored"] is True
        # Second store of the SAME inputs => same key => refused.
        s2, _ = run(["store", "--cache-dir", cache, "--interim-file", interim_path])
        assert s2["stored"] is False and s2["reason"] == "exists", s2
        assert s2["key"] == s1["key"] and s2["hash"] == s1["hash"]


def test_malformed_interim_is_not_cached():
    with tempfile.TemporaryDirectory() as base, tempfile.TemporaryDirectory() as cache:
        d = make_finding(base)
        proof = os.path.join(d, "evidence", "validation")
        # Missing verdict.
        p1 = os.path.join(proof, "bad1.json")
        write_interim(p1, {"finding_id": "F1", "proof_dir": proof})
        out1, _ = run(["store", "--cache-dir", cache, "--interim-file", p1])
        assert out1["stored"] is False and out1["reason"] == "bad_verdict", out1
        # Verdict not in the 4-enum.
        p2 = os.path.join(proof, "bad2.json")
        write_interim(p2, {"finding_id": "F1", "verdict": "MAYBE", "proof_dir": proof})
        out2, _ = run(["store", "--cache-dir", cache, "--interim-file", p2])
        assert out2["stored"] is False and out2["reason"] == "bad_verdict", out2
        assert os.listdir(cache) == [], "malformed interims must never be cached"


# --------------------------------------------------------------------------- #
# (6) SECURITY: traversal in finding_id or an out-of-root finding_dir is rejected
# --------------------------------------------------------------------------- #
def test_security_bad_finding_id_rejected():
    with tempfile.TemporaryDirectory() as base, tempfile.TemporaryDirectory() as cache:
        d = make_finding(base, fid="F1")
        proof = os.path.join(d, "evidence", "validation")
        p = os.path.join(proof, "evil.json")
        write_interim(p, {"finding_id": "../../evil", "verdict": "VALID", "proof_dir": proof})
        out, proc = run(["store", "--cache-dir", cache, "--interim-file", p], expect=2)
        assert "error" in out, out
        assert os.listdir(cache) == [], "a traversal finding_id must never be cached"


def test_security_proof_dir_outside_root_rejected():
    with tempfile.TemporaryDirectory() as base, tempfile.TemporaryDirectory() as cache, \
            tempfile.TemporaryDirectory() as elsewhere:
        d = make_finding(base, fid="F1")
        proof = os.path.join(d, "evidence", "validation")
        # A proof_dir claiming the finding lives OUTSIDE --root.
        evil_proof = os.path.join(elsewhere, "steal", "evidence", "validation")
        p = os.path.join(proof, "F1.json")
        write_interim(p, {"finding_id": "F1", "verdict": "VALID", "proof_dir": evil_proof})
        out, _ = run(["store", "--cache-dir", cache, "--interim-file", p, "--root", base], expect=2)
        assert "error" in out, out
        assert os.listdir(cache) == [], "an out-of-root finding_dir must write nothing"


def test_security_nonexistent_proof_dir_rejected():
    with tempfile.TemporaryDirectory() as base, tempfile.TemporaryDirectory() as cache:
        d = make_finding(base, fid="F1")
        proof = os.path.join(d, "evidence", "validation")
        p = os.path.join(proof, "F1.json")
        # proof_dir points at a path that does not exist -> finding_dir not found.
        write_interim(p, {"finding_id": "F1", "verdict": "VALID",
                          "proof_dir": "/no/such/finding/evidence/validation"})
        out, _ = run(["store", "--cache-dir", cache, "--interim-file", p], expect=2)
        assert "error" in out, out
        assert os.listdir(cache) == []


def test_security_restore_finding_dir_outside_output_dir_rejected():
    with tempfile.TemporaryDirectory() as base, tempfile.TemporaryDirectory() as cache, \
            tempfile.TemporaryDirectory() as out, tempfile.TemporaryDirectory() as outside:
        d = make_finding(outside)  # finding_dir lives OUTSIDE output-dir
        res, _ = run(["restore", "--finding-dir", d, "--cache-dir", cache, "--output-dir", out],
                     expect=2)
        assert "error" in res, res
        assert os.listdir(out) == [], "restore must write nothing when finding_dir escapes output-dir"


# --------------------------------------------------------------------------- #
# (7) determinism end-to-end: store at round 0, restore after validation ran
# --------------------------------------------------------------------------- #
def test_determinism_replay_hits_after_validation_ran():
    with tempfile.TemporaryDirectory() as eng, tempfile.TemporaryDirectory() as cache:
        d, interim_path, s = _store(eng, cache, interim("F1", "VALID"))
        assert s["stored"] is True
        round0_hash = s["hash"]
        original = open(interim_path, "rb").read()

        # Simulate a later re-validation of the SAME inputs: the validator's own
        # output subtree now exists on disk. The input hash must be unchanged, so
        # the replay HITS and restores byte-identically.
        add_validation_output(d)
        add_validation_output(d, name="verification-script.py", body="print(1)\n")
        r, _ = run(["restore", "--finding-dir", d, "--cache-dir", cache, "--output-dir", eng])
        assert r["restored"] is True, "replay over the same inputs must HIT"
        assert r["hash"] == round0_hash, "the input hash must be identical round-over-round"
        got = open(os.path.join(eng, "artifacts", "validated", "F1.json"), "rb").read()
        assert got == original, "restored bytes must equal the round-0 interim"


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
