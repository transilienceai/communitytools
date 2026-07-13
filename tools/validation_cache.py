#!/usr/bin/env python3
"""Deterministic replay-cache for the pentest validation lane (C3).

Makes re-validating an UNCHANGED finding directory deterministic: record a
finding's final verdict JSON ("interim") keyed by a content-hash of its
INVESTIGATION INPUTS, and on a later run restore that exact interim to disk
instead of re-running the (non-deterministic) LLM validation lane. NO LLM and
NO JS live in the deterministic path — this Python tool owns hashing + the
read/write; JS only composes the cache key (single-sourced in
.claude/workflows/lib/wf-helpers.mjs `cacheKey`, which this file mirrors).

Content hash (determinism hinges on this): sha256 over a canonical serialization
of the finding's INPUT files — sorted by POSIX relative path, each contributing
`relpath + "\\0" + raw_bytes`. INCLUDE description.md, poc.py, poc_output.txt and
everything under evidence/ EXCEPT evidence/validation/** (the validator's OWN
output, written DURING validation — including it would make a same-directory
replay miss). Absent files are simply not included. Raw bytes + sorted POSIX
paths make the digest stable across runs / OSes / on-disk order.

Key format (mirrors JS `cacheKey` exactly): sanitize(prompt_id) + "-" +
sanitize(ev_hash), where sanitize replaces every char NOT in [A-Za-z0-9_.-]
with "_". Default prompt_id is "interim". Cache file: <cache-dir>/<key>.json.

Security (hard requirements):
  * realpath-contain EVERY read/write — the finding_dir, the cache file, and any
    restore-output file must resolve inside their root (cache-dir / output-dir).
    On any escape: print an error JSON and exit(2); never read/write outside.
  * finding_id used in output paths must match ^[A-Za-z0-9_.-]+$; reject else.
  * `store` is write-once: never overwrite an existing cache file.
  * only well-formed interims are cached (valid JSON + finding_id + a verdict in
    VALID|REPAIRED|DEMOTED|REJECTED).

CLI (every subcommand prints ONE json line to stdout):
  hash    --finding-dir DIR
  key     --prompt-id interim --hash HEX
  store   --cache-dir VC --interim-file PATH [--prompt-id interim]
          [--finding-dir DIR] [--root ROOT]
  restore --finding-dir DIR --cache-dir VC --output-dir OUT [--prompt-id interim]

Exit codes: 0 ok (incl. stored:false / restored:false); 2 security/usage escape.
"""
import argparse
import hashlib
import json
import os
import sys
import tempfile

# The four terminal verdicts an interim may carry (mirrors the JS enum).
VERDICTS = ("VALID", "REPAIRED", "DEMOTED", "REJECTED")

# Top-level investigation INPUT files that feed the content hash.
INPUT_TOP = ("description.md", "poc.py", "poc_output.txt")

# The validator's OWN output subtree — excluded from the input hash so that a
# replay over the SAME directory (now containing this subtree) still hits.
EXCLUDE_REL = "evidence/validation"


# --------------------------------------------------------------------------- #
# Pure helpers (parity-guarded against wf-helpers.mjs)
# --------------------------------------------------------------------------- #
def sanitize(s):
    """Replace every char NOT in [A-Za-z0-9_.-] with '_' (mirrors JS `safe`)."""
    s = "" if s is None else str(s)
    return "".join(c if ((c.isascii() and c.isalnum()) or c in "_.-") else "_" for c in s)


def cache_key(prompt_id, ev_hash):
    """sanitize(prompt_id) + '-' + sanitize(ev_hash) — identical to JS cacheKey."""
    return sanitize(prompt_id) + "-" + sanitize(ev_hash)


def terminal_subdir(verdict):
    """Which artifacts/<subdir> a terminal verdict is persisted to (mirrors JS)."""
    if verdict in ("VALID", "REPAIRED"):
        return "validated"
    if verdict == "REJECTED":
        return "false-positives"
    return "dropped"


def valid_finding_id(fid):
    """True iff fid is a non-empty ^[A-Za-z0-9_.-]+$ string (safe in a path)."""
    return bool(fid) and isinstance(fid, str) and all(
        (c.isascii() and c.isalnum()) or c in "_.-" for c in fid)


# --------------------------------------------------------------------------- #
# Path containment
# --------------------------------------------------------------------------- #
def _within(root_real, path_real):
    return path_real == root_real or path_real.startswith(root_real + os.sep)


def contain(root, *parts):
    """realpath(root/parts) if it resolves inside realpath(root), else None.
    Absolute `parts` (os.path.join semantics) are still re-contained against
    root, so an absolute escape resolves outside and returns None."""
    root_real = os.path.realpath(root)
    target = os.path.realpath(os.path.join(root, *parts))
    return target if _within(root_real, target) else None


# --------------------------------------------------------------------------- #
# Content hash
# --------------------------------------------------------------------------- #
def _collect_inputs(base):
    """Yield (posix_relpath, abspath) for every hashed INPUT file under `base`,
    excluding evidence/validation/** and any file whose realpath escapes `base`
    (symlink-out — never read). Deterministic set; caller sorts."""
    entries = []
    for name in INPUT_TOP:
        p = os.path.join(base, name)
        if os.path.isfile(p) and _within(base, os.path.realpath(p)):
            entries.append((name, p))

    ev = os.path.join(base, "evidence")
    # Guard a symlinked-out evidence/ dir before walking it.
    if os.path.isdir(ev) and _within(base, os.path.realpath(ev)):
        for root, dirs, files in os.walk(ev):  # followlinks=False (no dir-symlink descent)
            rel_root = os.path.relpath(root, base).replace(os.sep, "/")
            if rel_root == "evidence" and "validation" in dirs:
                dirs.remove("validation")          # prune evidence/validation/**
            for fn in files:
                fp = os.path.join(root, fn)
                rel = os.path.relpath(fp, base).replace(os.sep, "/")
                if rel == EXCLUDE_REL or rel.startswith(EXCLUDE_REL + "/"):
                    continue
                if not _within(base, os.path.realpath(fp)):
                    continue                       # symlink escaping base — skip
                entries.append((rel, fp))
    return entries


def hash_finding_dir(finding_dir):
    """sha256 over the canonical serialization of a finding's INPUT files.
    Each contributes  relpath + '\\0' + raw_bytes , sorted by POSIX relpath."""
    base = os.path.realpath(finding_dir)
    h = hashlib.sha256()
    for rel, path in sorted(_collect_inputs(base), key=lambda e: e[0]):
        with open(path, "rb") as f:
            data = f.read()
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(data)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# I/O helpers
# --------------------------------------------------------------------------- #
def emit(obj):
    """Print exactly one JSON line to stdout."""
    print(json.dumps(obj))


def die(message, code=2):
    """Print an error JSON and exit (security/usage escapes use code 2)."""
    emit({"error": message})
    sys.exit(code)


def _atomic_write_bytes(path, data):
    """Write bytes to `path` via a same-dir temp file + os.replace (atomic)."""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".vc-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def finding_dir_from_interim(interim, explicit):
    """Resolve the finding_dir to hash: explicit --finding-dir wins, else derive
    from the interim's proof_dir (<finding_dir>/evidence/validation)."""
    if explicit:
        return explicit
    proof_dir = interim.get("proof_dir")
    if not proof_dir or not isinstance(proof_dir, str):
        return None
    return os.path.dirname(os.path.dirname(proof_dir))


# --------------------------------------------------------------------------- #
# Subcommands
# --------------------------------------------------------------------------- #
def cmd_hash(args):
    emit({"hash": hash_finding_dir(args.finding_dir)})
    return 0


def cmd_key(args):
    emit({"key": cache_key(args.prompt_id, args.hash)})
    return 0


def cmd_store(args):
    # Read + parse the interim (raw bytes are what we persist, byte-for-byte).
    try:
        with open(args.interim_file, "rb") as f:
            raw = f.read()
        interim = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        emit({"stored": False, "reason": "invalid_json"})
        return 0
    if not isinstance(interim, dict):
        emit({"stored": False, "reason": "invalid_json"})
        return 0

    fid = interim.get("finding_id")
    if fid is None:
        emit({"stored": False, "reason": "missing_finding_id"})
        return 0
    # A finding_id that could escape a restore output path is a hard reject.
    if not valid_finding_id(fid):
        die("invalid finding_id: %r" % (fid,))
    if interim.get("verdict") not in VERDICTS:
        emit({"stored": False, "reason": "bad_verdict"})
        return 0

    finding_dir = finding_dir_from_interim(interim, args.finding_dir)
    if not finding_dir:
        die("no finding_dir: interim lacks proof_dir and --finding-dir not given")
    # Optional root containment; else the isdir gate below bounds a bad proof_dir.
    if args.root:
        contained = contain(args.root, finding_dir)
        if contained is None:
            die("finding_dir escapes --root: %s" % finding_dir)
        finding_dir = contained
    finding_dir = os.path.realpath(finding_dir)
    if not os.path.isdir(finding_dir):
        die("finding_dir not found: %s" % finding_dir)

    ev_hash = hash_finding_dir(finding_dir)
    key = cache_key(args.prompt_id, ev_hash)
    cache_path = contain(args.cache_dir, key + ".json")
    if cache_path is None:
        die("cache path escapes --cache-dir")

    # Write-once: never overwrite an existing entry.
    if os.path.exists(cache_path):
        emit({"stored": False, "key": key, "hash": ev_hash, "reason": "exists"})
        return 0

    _atomic_write_bytes(cache_path, raw)
    emit({"stored": True, "key": key, "hash": ev_hash})
    return 0


def cmd_restore(args):
    fd = contain(args.output_dir, args.finding_dir)
    if fd is None:
        die("finding_dir escapes --output-dir: %s" % args.finding_dir)

    ev_hash = hash_finding_dir(fd)
    key = cache_key(args.prompt_id, ev_hash)
    cache_path = contain(args.cache_dir, key + ".json")
    if cache_path is None:
        die("cache path escapes --cache-dir")

    # MISS: nothing on disk for these inputs — write nothing.
    if not os.path.isfile(cache_path):
        emit({"restored": False, "hash": ev_hash})
        return 0

    try:
        with open(cache_path, "rb") as f:
            raw = f.read()
        interim = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        die("corrupt cache entry: %s" % cache_path)
    if not isinstance(interim, dict):
        die("corrupt cache entry: %s" % cache_path)

    fid = interim.get("finding_id")
    if not valid_finding_id(fid):
        die("cached interim has invalid finding_id: %r" % (fid,))
    verdict = interim.get("verdict")
    sub = terminal_subdir(verdict)
    title = (interim.get("report_fields") or {}).get("title")

    # Restore the exact bytes to BOTH the namespaced artifacts/ tree and the
    # top-level terminal tree, each realpath-contained under output-dir.
    targets = [
        contain(args.output_dir, "artifacts", sub, fid + ".json"),
        contain(args.output_dir, sub, fid + ".json"),
    ]
    if any(t is None for t in targets):
        die("restore output path escapes --output-dir")
    for t in targets:
        _atomic_write_bytes(t, raw)

    emit({"restored": True, "hash": ev_hash, "id": fid, "verdict": verdict, "title": title})
    return 0


def build_parser():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("hash", help="content-hash a finding's investigation inputs")
    p.add_argument("--finding-dir", required=True)
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("key", help="compose the cache key from prompt_id + hash")
    p.add_argument("--prompt-id", default="interim")
    p.add_argument("--hash", required=True)
    p.set_defaults(func=cmd_key)

    p = sub.add_parser("store", help="record an interim keyed by its input hash (write-once)")
    p.add_argument("--cache-dir", required=True)
    p.add_argument("--interim-file", required=True)
    p.add_argument("--prompt-id", default="interim")
    p.add_argument("--finding-dir", help="override the proof_dir-derived finding_dir")
    p.add_argument("--root", help="optional containment root for the finding_dir")
    p.set_defaults(func=cmd_store)

    p = sub.add_parser("restore", help="restore a recorded interim for unchanged inputs")
    p.add_argument("--finding-dir", required=True)
    p.add_argument("--cache-dir", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--prompt-id", default="interim")
    p.set_defaults(func=cmd_restore)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
