#!/usr/bin/env python3
"""Verify one source/egress IP by storing the probe evidence that proves it.

This is the ONLY writer of ``verified: true`` into
``<engagement-root>/logs/activity/source-ips.jsonl``.
``tools/register_source_ip.py`` records intent (``verified: false``); this tool
records proof.

The proof is deliberately dumb and deterministic: an *egress echo* — the raw
output of an IP-reflector request made FROM the vantage being verified (e.g.
``gcloud compute ssh <vm> --command "curl -s ifconfig.me"``, or plain
``curl -s ifconfig.me`` when the caller already IS that vantage). The evidence
text must contain the IP being claimed. If it does not, nothing is written and
the exit code is non-zero. A provider API reporting "your VM has address X" is
NOT evidence: it proves allocation, not egress.

Evidence is copied to ``logs/activity/vantage-probes/<ip>.txt`` and referenced
from the ledger row by a path RELATIVE to the engagement root, so
``tools/coverage_gate.py`` can re-check it later without trusting this process —
the same corroborator-file pattern as ``_is_corroborated``.

The ledger stays append-only: verifying appends a second row for the IP rather
than mutating the registration.

Usage:
    # evidence from a file
    python3 tools/verify_source_ip.py --ip 203.0.113.9 --role vpn --region NL \
        --evidence-file /tmp/echo.txt --engagement <root>

    # evidence on stdin
    gcloud compute ssh vm --command "curl -s ifconfig.me" \
      | python3 tools/verify_source_ip.py --ip 203.0.113.9 --role attack-vm \
          --region asia-south1 --evidence-file - --engagement <root>

Exit codes: 0 verified; 1 evidence missing / unreadable / does not contain the
IP / write error; 2 bad args (argparse).
"""
import argparse
import os
import sys

# Reuse the one canonical append + timestamp implementation. Importing rather
# than re-copying keeps the atomic-append guarantee in a single place; the
# hyphen-free module name makes this importable (unlike env-reader.py).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from register_source_ip import append_jsonl, now_iso  # noqa: E402

# Only these roles can ever count as a distinct attacking vantage. A proxy is
# not a geography and the primary runner is the baseline, not a second vantage.
VANTAGE_ROLES = ("attack-vm", "vpn")

EVIDENCE_SUBDIR = os.path.join("logs", "activity", "vantage-probes")


def safe_name(ip: str) -> str:
    """Filesystem-safe stem for an IPv4/IPv6 literal."""
    return "".join(c if (c.isalnum() or c in "-.") else "_" for c in ip)[:64]


def read_evidence(spec: str) -> str:
    """Read evidence text from a path, or from stdin when spec is '-'."""
    if spec == "-":
        return sys.stdin.read()
    with open(spec, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ip", required=True, help="the egress IP the evidence must show")
    ap.add_argument("--role", default="attack-vm",
                    help=f"vantage role; only {'/'.join(VANTAGE_ROLES)} count toward min_vantages")
    ap.add_argument("--provider", default="")
    ap.add_argument("--region", default="")
    ap.add_argument("--note", default="")
    ap.add_argument("--evidence-file", required=True,
                    help="path to the egress-echo output, or '-' for stdin")
    ap.add_argument("--engagement", required=True, help="engagement root directory")
    ap.add_argument("--dry-run", action="store_true",
                    help="validate only; never append a verified row")
    args = ap.parse_args()

    root = args.engagement.rstrip("/")
    ip = args.ip.strip()

    try:
        text = read_evidence(args.evidence_file)
    except OSError as e:
        print(f"verify_source_ip: cannot read evidence: {e}", file=sys.stderr)
        return 1

    # THE check. An echo that does not name the IP proves nothing about egress.
    if ip not in text:
        print(
            f"verify_source_ip: evidence does not contain {ip} — refusing to mark verified.\n"
            f"  evidence ({len(text)} bytes) began: {text[:120]!r}",
            file=sys.stderr)
        return 1

    if args.dry_run:
        # A dry run must never be able to manufacture a vantage.
        print(f"DRY-RUN would verify {args.role} {ip} (evidence {len(text)} bytes); nothing written")
        return 0

    rel = os.path.join(EVIDENCE_SUBDIR, f"{safe_name(ip)}.txt")
    abs_evidence = os.path.join(root, rel)
    try:
        os.makedirs(os.path.dirname(abs_evidence), exist_ok=True)
        with open(abs_evidence, "w", encoding="utf-8") as fh:
            fh.write(text)
        append_jsonl(
            os.path.join(root, "logs", "activity", "source-ips.jsonl"),
            {
                "ts": now_iso(),
                "ip": ip,
                "role": args.role,
                "provider": args.provider,
                "region": args.region,
                "note": args.note or "egress echo verified",
                "source": "verify_source_ip",
                "verified": True,
                "probe_evidence": rel,
            },
        )
    except Exception as e:  # never crash a provisioning step over a log write
        print(f"verify_source_ip: could not write evidence/ledger: {e}", file=sys.stderr)
        return 1

    if args.role not in VANTAGE_ROLES:
        print(f"verify_source_ip: note — role '{args.role}' is verified but does NOT "
              f"count toward min_vantages (only {'/'.join(VANTAGE_ROLES)} do)", file=sys.stderr)
    print(f"verified {args.role} {ip} -> {rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
