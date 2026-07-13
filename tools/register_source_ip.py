#!/usr/bin/env python3
"""Register one source/egress-IP used during an engagement.

Appends ONE line to ``<engagement-root>/logs/activity/source-ips.jsonl``. The file
is append-only: there is deliberately NO dedup / read-modify-write here (dedup
happens once, single-threaded, at report-build time), so this helper is safe to
call concurrently from parallel executors and from a VM-provisioning wrapper. The
write is a single ``O_APPEND`` ``os.write`` of a ``<4000``-byte line, so lines from
concurrent writers never interleave.

Roles: ``primary-runner`` (the local workstation egress), ``attack-vm`` (an
ephemeral cloud VM spun up to attack), ``proxy`` / ``vpn`` / ``socks`` (a tunnel
egress), ``detected`` (best-effort auto-scrape — written by activity-logger.py, not
here). Every egress vantage MUST be registered — see
skills/coordination/reference/principles.md.

Usage:
    python3 tools/register_source_ip.py <ip> --role <role> \
        [--provider gcp|aws|az|...] [--region <r>] [--note <text>] \
        --engagement <engagement-root>

Exit codes: 0 ok; 1 write error; 2 bad args (argparse).
"""
import argparse
import datetime as _dt
import json
import os
import sys


def now_iso():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_jsonl(path, obj):
    """Atomic append of one JSON line. Creates the parent dir if needed.

    A single ``os.write`` of a sub-``PIPE_BUF`` (4096-byte) buffer to an O_APPEND fd
    is atomic on POSIX, so concurrent registrations never produce a torn line.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    buf = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, buf)
    finally:
        os.close(fd)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ip")
    ap.add_argument("--role", required=True)
    ap.add_argument("--provider", default="")
    ap.add_argument("--region", default="")
    ap.add_argument("--note", default="")
    ap.add_argument("--engagement", required=True, help="engagement root directory")
    args = ap.parse_args()

    root = args.engagement.rstrip("/")
    path = os.path.join(root, "logs", "activity", "source-ips.jsonl")
    obj = {
        "ts": now_iso(),
        "ip": args.ip,
        "role": args.role,
        "provider": args.provider,
        "region": args.region,
        "note": args.note,
        "source": "register_source_ip",
        "verified": True,
    }
    try:
        append_jsonl(path, obj)
    except Exception as e:  # never crash a Setup/provisioning step over a log write
        print(f"register_source_ip: could not write {path}: {e}", file=sys.stderr)
        return 1
    print(f"registered {args.role} {args.ip} -> {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
