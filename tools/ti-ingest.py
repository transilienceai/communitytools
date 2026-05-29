#!/usr/bin/env python3
"""Threat-intel signal ingest.

Reads a signal payload (JSON file or stdin), validates schema, enriches with
NVD risk scores, de-dupes against existing queue/validated/false-positives
rows, and writes one engagement-scope row per (asset, cve) pair to
{OUTPUT_DIR}/queue/.

Usage:
    python3 tools/ti-ingest.py --in signal.json --output-dir runs/org/
    cat signal.json | python3 tools/ti-ingest.py --output-dir runs/org/

Exit codes:
    0 — at least one row queued (or all valid duplicates)
    1 — schema error (no rows written)
    2 — runtime error (partial write — see stderr)
"""

import argparse
import csv
import glob
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
REQUIRED = ("signal_id", "cve", "assets", "claim")


def utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_payload(path: str | None) -> dict:
    if path and path != "-":
        with open(path) as f:
            return json.load(f)
    return json.loads(sys.stdin.read())


def validate(payload: dict) -> list[str]:
    errs = []
    for k in REQUIRED:
        if k not in payload:
            errs.append(f"missing required key: {k}")
    if "cve" in payload:
        cves = payload["cve"] if isinstance(payload["cve"], list) else [payload["cve"]]
        for c in cves:
            if not CVE_RE.match(c.strip().upper()):
                errs.append(f"invalid CVE id: {c}")
    if "assets" in payload:
        if not isinstance(payload["assets"], list) or not payload["assets"]:
            errs.append("assets must be a non-empty list")
        else:
            for i, a in enumerate(payload["assets"]):
                if not isinstance(a, dict) or "id" not in a:
                    errs.append(f"assets[{i}] missing 'id'")
                elif not SAFE_ID_RE.match(str(a["id"])):
                    errs.append(f"assets[{i}].id {a['id']!r} fails {SAFE_ID_RE.pattern} "
                                f"(rejected to prevent path traversal in scope/queue paths)")
    if "signal_id" in payload and not SAFE_ID_RE.match(str(payload["signal_id"])):
        errs.append(f"signal_id {payload['signal_id']!r} fails {SAFE_ID_RE.pattern}")
    return errs


def load_tier_map(output_dir: Path) -> dict[str, str]:
    repo_root = Path(__file__).resolve().parent.parent
    candidates = [
        output_dir / "business-tier-map.csv",
        repo_root / "cloud-agents" / "schemas" / "business-tier-map.csv",
    ]
    for p in candidates:
        if p.is_file():
            with p.open() as f:
                reader = csv.DictReader(f)
                return {row["asset_id"]: row["tier"] for row in reader if row.get("asset_id")}
    return {}


def nvd_enrich(cve: str) -> dict | None:
    repo_root = Path(__file__).resolve().parent.parent
    nvd_tool = repo_root / "tools" / "nvd-lookup.py"
    if not nvd_tool.is_file():
        return None
    try:
        out = subprocess.run(
            ["python3", str(nvd_tool), cve],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        return {"error": "nvd-lookup timeout"}
    for line in out.stdout.splitlines():
        if line.startswith("JSON_SUMMARY:"):
            return json.loads(line.split(":", 1)[1].strip())
    return {"error": out.stderr.strip()[:200] or "no JSON_SUMMARY in nvd-lookup output"}


def is_duplicate(output_dir: Path, asset_id: str, cve: str, incoming_confidence: str) -> bool:
    patterns = [
        f"queue/scope-*-{asset_id}-{cve}.json",
        f"validated/*{asset_id}*{cve}*.json",
        f"false-positives/*{asset_id}*{cve}*.json",
    ]
    matches = []
    for pat in patterns:
        matches.extend(glob.glob(str(output_dir / pat)))
    if not matches:
        return False

    rejected_only = True
    last_confidence = "low"
    for m in matches:
        try:
            with open(m) as f:
                row = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"WARN: cannot parse existing queue/verdict file {m}: {e} — "
                  f"treating as 'duplicate exists' (fail-closed)", file=sys.stderr)
            return True
        # Queue rows use 'status', validator output uses 'verdict' (task-03 contract).
        state = row.get("verdict") or row.get("status") or ""
        if state in ("queued", "VALID"):
            return True
        if state == "REJECTED":
            last_confidence = row.get("confidence", "low")
        else:
            rejected_only = False
    if rejected_only and incoming_confidence == "high" and last_confidence != "high":
        return False
    return True


def write_row(output_dir: Path, ts: str, signal: dict, asset: dict, cve: str,
              tier_map: dict[str, str]) -> Path:
    asset_id = asset["id"]
    fname = f"scope-{ts}-{asset_id}-{cve}.json"
    target = output_dir / "queue" / fname
    target.parent.mkdir(parents=True, exist_ok=True)

    nvd = nvd_enrich(cve)
    nvd_error = nvd.pop("error", None) if isinstance(nvd, dict) else None
    tier = tier_map.get(asset_id, "unknown")

    row = {
        "scope_id": f"scope-{ts}-{asset_id}-{cve}",
        "signal_id": signal["signal_id"],
        "asset": {**asset, "tier": tier},
        "cve": cve,
        "nvd": nvd if (nvd and "error" not in (nvd or {})) else None,
        "nvd_error": nvd_error,
        "claim": signal["claim"],
        "confidence": signal.get("confidence", "medium"),
        "source": signal.get("source"),
        "references": signal.get("references", []),
        "unknown_asset": tier == "unknown",
        "queued_at": utc_iso(),
        "status": "queued",
    }

    with open(target, "w") as f:
        json.dump(row, f, indent=2)
    return target


def copy_to_inbox(output_dir: Path, ts: str, payload: dict) -> Path:
    inbox = output_dir / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    target = inbox / f"signal-{ts}.json"
    with open(target, "w") as f:
        json.dump(payload, f, indent=2)
    return target


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="inp", default="-", help="payload JSON file or '-' for stdin")
    ap.add_argument("--output-dir", required=True, help="engagement OUTPUT_DIR")
    args = ap.parse_args()

    try:
        payload = load_payload(args.inp)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read payload: {e}", file=sys.stderr)
        return 1

    errs = validate(payload)
    if errs:
        for e in errs:
            print(f"SCHEMA: {e}", file=sys.stderr)
        return 1

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = utc_ts()
    copy_to_inbox(output_dir, ts, payload)

    tier_map = load_tier_map(output_dir)
    cves = payload["cve"] if isinstance(payload["cve"], list) else [payload["cve"]]
    cves = [c.strip().upper() for c in cves]

    written, skipped = [], []
    for asset in payload["assets"]:
        for cve in cves:
            if is_duplicate(output_dir, asset["id"], cve, payload.get("confidence", "medium")):
                skipped.append(f"{asset['id']}::{cve}")
                continue
            target = write_row(output_dir, ts, payload, asset, cve, tier_map)
            written.append(str(target))

    print(json.dumps({
        "signal_id": payload["signal_id"],
        "written": written,
        "skipped_duplicates": skipped,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
