#!/usr/bin/env python3
"""CISA KEV (Known Exploited Vulnerabilities) Lookup

Symmetric deterministic mirror of nvd-lookup.py: given a CVE ID, reports whether
it is on the CISA Known Exploited Vulnerabilities catalog.

Usage:
    python3 tools/kev-lookup.py CVE-2021-44228 [CVE-2023-99999 ...]
    python3 tools/kev-lookup.py --cache-dir <dir> CVE-2021-44228

With --cache-dir the catalog is frozen once to <dir>/kev-snapshot.json (write-once:
if present, it is read with ZERO network). "Is this CVE known-exploited?" is then
answerable deterministically from the frozen snapshot, which makes it unit-testable.

CVE ids are validated against ^CVE-\\d{4}-\\d{4,}$ and the snapshot path is
realpath-contained inside <dir> before any filesystem use (F-3).

Prints a one-line verdict per CVE plus a KEV_SUMMARY JSON line for programmatic use.
"""

import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.error

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SNAPSHOT_NAME = "kev-snapshot.json"

# Strict CVE id shape used to gate any filesystem path (F-3, HIGH).
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def fetch_kev_catalog() -> dict:
    """Fetch the full CISA KEV catalog JSON."""
    req = urllib.request.Request(KEV_URL)
    req.add_header("User-Agent", "communitytools-kev-lookup/1.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"KEV HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"error": f"KEV connection failed: {e.reason}"}
    except Exception as e:
        return {"error": f"KEV error: {e}"}


def snapshot_path(cache_dir):
    """Return the realpath-contained <cache_dir>/kev-snapshot.json path, or None if
    it would escape cache_dir. None means "do not touch the filesystem"."""
    root = os.path.realpath(cache_dir)
    path = os.path.realpath(os.path.join(root, SNAPSHOT_NAME))
    if path != root and path.startswith(root + os.sep):
        return path
    return None


def _is_success(catalog):
    """A cacheable KEV catalog: no error and a list of vulnerabilities."""
    return isinstance(catalog, dict) and "error" not in catalog and isinstance(
        catalog.get("vulnerabilities"), list)


def load_catalog(cache_dir):
    """Return the KEV catalog dict. With cache_dir: read the frozen snapshot if it
    exists (zero network), else fetch once and persist it (write-once, on success)."""
    path = snapshot_path(cache_dir) if cache_dir else None
    if path and os.path.isfile(path):
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            pass  # fall through to a live fetch on a corrupt snapshot
    catalog = fetch_kev_catalog()
    if path and _is_success(catalog):
        try:
            with open(path, "w") as f:
                json.dump(catalog, f)
        except OSError:
            pass
    return catalog


def kev_status(catalog: dict, cve_id: str) -> dict:
    """Look a CVE up in the catalog and return its KEV status record."""
    for v in catalog.get("vulnerabilities", []):
        if str(v.get("cveID", "")).upper() == cve_id:
            return {
                "cve_id": cve_id,
                "on_kev": True,
                "dateAdded": v.get("dateAdded"),
                "vendorProject": v.get("vendorProject"),
                "product": v.get("product"),
                "vulnerabilityName": v.get("vulnerabilityName"),
                "dueDate": v.get("dueDate"),
                "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse"),
            }
    return {"cve_id": cve_id, "on_kev": False, "dateAdded": None}


def format_status(status: dict) -> str:
    """One-line verdict + a KEV_SUMMARY JSON line."""
    cve_id = status["cve_id"]
    if status["on_kev"]:
        added = status.get("dateAdded") or "unknown"
        name = status.get("vulnerabilityName") or ""
        verdict = f"{cve_id}: ON KEV (added {added})" + (f" — {name}" if name else "")
    else:
        verdict = f"{cve_id}: NOT on KEV"
    return f"{verdict}\nKEV_SUMMARY: {json.dumps(status)}"


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, add_help=True)
    ap.add_argument("cve_ids", nargs="*", metavar="CVE-ID")
    ap.add_argument("--cache-dir", help="Freeze the KEV catalog to <dir>/kev-snapshot.json (zero network on hit)")
    args = ap.parse_args(argv)

    if not args.cve_ids:
        print("Usage: python3 tools/kev-lookup.py CVE-XXXX-XXXXX [...]")
        sys.exit(1)

    if args.cache_dir:
        os.makedirs(args.cache_dir, exist_ok=True)

    catalog = None  # loaded lazily and shared across ids (one fetch/snapshot read)
    for cve_id in args.cve_ids:
        cve_id = cve_id.strip().upper()
        if not CVE_ID_RE.match(cve_id):
            print(f"WARNING: '{cve_id}' doesn't look like a CVE ID, skipping.")
            continue

        if catalog is None:
            catalog = load_catalog(args.cache_dir)
        if "error" in catalog:
            print(f"ERROR: {catalog['error']}")
            continue

        print(format_status(kev_status(catalog, cve_id)))


if __name__ == "__main__":
    main()
