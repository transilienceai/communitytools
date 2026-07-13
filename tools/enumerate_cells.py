#!/usr/bin/env python3
"""Code-produce the (surface-unit x attack-class) work-list — the un-fabricatable
applicable-cell set that the coverage gate scores against.

This is the pentest analogue of pci-sss/applicability/work-list.json: because the
applicable set is computed HERE by code from code-owned inputs (a structured
surface inventory + network host.json), an agent cannot shrink it. The agent only
produces FACTS (surface units with agent-set flags); this tool applies the fixed
catalog predicates (with 6 code-derived flags the agent cannot set) to enumerate
every applicable cell.

cell = (asset_tag, scope_key, class_id), where scope_key is:
  unit-scope  -> unit_id      (one cell per matching surface unit)
  host-scope  -> host:port    (one cell per distinct open listener)
  asset-scope -> asset_tag    (one cell per asset)

Inputs:
  WEB asset:  <asset_dir>/recon/inventory/surface.json   (schema "surface/v2")
  NETWORK:    <engagement>/hosts/<ip>/host.json           (structured ports[])

Usage:
  python3 tools/enumerate_cells.py --asset-dir DIR        # one web asset OR one network host dir
  python3 tools/enumerate_cells.py --engagement-dir DIR   # all web assets + all network hosts

Writes <root>/applicability/cells.json. Exit 0 on success, 2 on unreadable catalog.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from collections import Counter
from urllib.parse import urlparse

from coverage_catalog import (
    AGENT_FLAGS,
    DEFAULT_CATALOG,
    CatalogError,
    catalog_by_id,
    eval_applies,
    load_catalog,
)

# --- network service/port -> code-derived-flag heuristics --------------------
HTTP_SERVICES = {"http", "https", "http-proxy", "http-alt", "https-alt", "ssl/http",
                 "http-mgmt", "sun-answerbook", "webcache", "http-rpc-epmap"}
TLS_SERVICES = {"https", "ssl", "tls", "ssl/http", "https-alt", "imaps", "pop3s", "smtps"}
HTTP_PRODUCTS_RE = re.compile(r"nginx|apache|httpd|iis|tomcat|lighttpd|caddy|jetty|gunicorn|"
                              r"kestrel|express|node|openresty|traefik|envoy", re.I)
HTTP_PORTS = {80, 280, 591, 593, 981, 1010, 2480, 3000, 4000, 4567, 5000, 5104, 5800,
              7000, 7001, 8000, 8008, 8042, 8080, 8081, 8082, 8088, 8888, 9000, 9080, 9200}
TLS_PORTS = {443, 993, 995, 8443, 8444, 9443, 10443, 4443}


def parse_listener(address: str) -> str | None:
    """Return a 'host:port' listener string for a URL / host:port / bare host."""
    if not address:
        return None
    a = address.strip()
    if "://" in a:
        u = urlparse(a)
        host = u.hostname
        if not host:
            return None
        port = u.port or (443 if u.scheme == "https" else 80)
        return f"{host}:{port}"
    # host:port (but not a path); take the first token before any '/'
    a = a.split("/")[0]
    if ":" in a and not a.startswith("["):
        host, _, port = a.rpartition(":")
        if host and port.isdigit():
            return f"{host}:{port}"
    return f"{a}:443" if a else None


def _has_version_token(*vals) -> bool:
    for v in vals:
        if isinstance(v, str) and re.search(r"\d", v):
            return True
        if isinstance(v, (list, tuple)) and any(isinstance(x, str) and re.search(r"\d", x) for x in v):
            return True
    return False


def web_unit_flags(unit: dict) -> set:
    """Agent flags (filtered to the vocabulary) plus code-derived unit flags."""
    flags = {f for f in (unit.get("flags") or []) if f in AGENT_FLAGS}
    addr = unit.get("address", "")
    scheme = urlparse(addr).scheme if "://" in addr else ""
    listener = parse_listener(addr) or ""
    port = int(listener.rsplit(":", 1)[1]) if listener.rsplit(":", 1)[-1].isdigit() else None
    # code-derived (agent-unfabricatable):
    flags.add("http_listener")  # a web surface unit is an HTTP endpoint by definition
    if scheme == "https" or (port in TLS_PORTS) or unit.get("tls"):
        flags.add("tls_listener")
    if _has_version_token(unit.get("server"), unit.get("tech"), unit.get("version")):
        flags.add("version_fingerprinted")
    return flags


def load_web_asset(asset_dir: str) -> dict | None:
    spath = os.path.join(asset_dir, "recon", "inventory", "surface.json")
    if not os.path.isfile(spath):
        return None
    try:
        surf = json.load(open(spath, encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    asset_tag = surf.get("asset_tag") or os.path.basename(asset_dir.rstrip("/"))
    units = surf.get("units") or []
    listener_flags: dict = {}
    asset_flags: set = set()
    unit_records = []
    surface_hosts: set = set()
    for u in units:
        uid = u.get("unit_id")
        if not uid:
            continue
        uf = web_unit_flags(u)
        listener = parse_listener(u.get("address", ""))
        if listener:
            listener_flags.setdefault(listener, set()).update(uf)
            surface_hosts.add(listener.rsplit(":", 1)[0])
        asset_flags |= uf
        unit_records.append({"unit_id": uid, "flags": uf, "equiv_group": u.get("equiv_group")})
    # asset-rollup derived flags
    types = {u.get("type") for u in units}
    if "endpoint" in types or "service" in types:
        asset_flags.add("has_api")
    if surf.get("apex"):
        asset_flags.add("is_apex")
    if "page" in types or any(str(u.get("address", "")).endswith(".js") for u in units):
        asset_flags.add("serves_js")
    recon_hosts = _recon_hosts(asset_dir)
    return {
        "asset_tag": asset_tag, "kind": "web", "dir": asset_dir,
        "units": unit_records, "listener_flags": listener_flags, "asset_flags": asset_flags,
        "open_listeners": sorted(listener_flags.keys()),
        "surface_hosts": sorted(surface_hosts), "recon_hosts": sorted(recon_hosts),
    }


def _recon_hosts(asset_dir: str) -> set:
    """Independently-discovered hosts (for the gate's surface_undercount check)."""
    hosts: set = set()
    sub = os.path.join(asset_dir, "recon", "inventory", "subdomains.json")
    if os.path.isfile(sub):
        try:
            data = json.load(open(sub, encoding="utf-8"))
        except json.JSONDecodeError:
            data = None
        rows = data if isinstance(data, list) else (data or {}).get("subdomains", []) if isinstance(data, dict) else []
        for r in rows:
            if isinstance(r, str):
                hosts.add(r)
            elif isinstance(r, dict):
                h = r.get("host") or r.get("hostname") or r.get("subdomain") or r.get("name")
                if h:
                    hosts.add(h)
    return hosts


def load_network_host(host_json_path: str) -> dict | None:
    try:
        host = json.load(open(host_json_path, encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    # Zero-units guard: a dead / no-surface host yields NO cells (not even misconfig).
    if not host.get("live") or not host.get("ports"):
        return None
    ip = host.get("ip") or os.path.basename(os.path.dirname(host_json_path))
    listener_flags: dict = {}
    asset_flags: set = set()
    open_listeners: list = []
    for p in host.get("ports") or []:
        if p.get("state") not in (None, "open"):
            continue
        try:
            port = int(p.get("port"))
        except (TypeError, ValueError):
            continue
        svc = (p.get("service") or "").lower()
        product = p.get("product") or ""
        version = p.get("version") or ""
        listener = f"{ip}:{port}"
        lf: set = set()
        if svc in HTTP_SERVICES or HTTP_PRODUCTS_RE.search(product) or port in HTTP_PORTS:
            lf.add("http_listener")
        if svc in TLS_SERVICES or "ssl" in svc or port in TLS_PORTS:
            lf.add("tls_listener")
        if product and version:
            lf.add("version_fingerprinted")
        listener_flags[listener] = lf
        open_listeners.append(listener)
        asset_flags |= lf
    if any("http_listener" in lf for lf in listener_flags.values()):
        asset_flags.add("has_api")
    return {
        "asset_tag": ip, "kind": "network", "dir": os.path.dirname(host_json_path),
        "units": [], "listener_flags": listener_flags, "asset_flags": asset_flags,
        "open_listeners": sorted(open_listeners),
        "surface_hosts": [ip], "recon_hosts": [],
    }


def cells_for_asset(catalog: dict, asset: dict) -> list:
    cells = []
    by_id = catalog_by_id(catalog)
    for cid, cls in by_id.items():
        scope = cls["scope"]
        base = {"class_id": cid, "taxonomy": cls["taxonomy"], "title": cls["title"],
                "scope": scope, "negative_kind": cls["negative_kind"], "min_vantages": cls["min_vantages"],
                "asset_tag": asset["asset_tag"]}
        if scope == "unit":
            for u in asset["units"]:
                if eval_applies(cls["applies_when"], u["flags"]):
                    cells.append({**base, "scope_key": u["unit_id"], "equiv_group": u.get("equiv_group")})
        elif scope == "host":
            for listener, lf in asset["listener_flags"].items():
                if eval_applies(cls["applies_when"], lf):
                    cells.append({**base, "scope_key": listener, "equiv_group": None})
        else:  # asset
            if eval_applies(cls["applies_when"], asset["asset_flags"]):
                cells.append({**base, "scope_key": asset["asset_tag"], "equiv_group": None})
    return cells


def discover_assets(engagement_dir: str) -> list:
    assets = []
    for sp in sorted(glob.glob(os.path.join(engagement_dir, "**", "recon", "inventory", "surface.json"), recursive=True)):
        a = load_web_asset(os.path.dirname(os.path.dirname(os.path.dirname(sp))))
        if a:
            assets.append(a)
    for hp in sorted(glob.glob(os.path.join(engagement_dir, "hosts", "*", "host.json"))):
        a = load_network_host(hp)
        if a:
            assets.append(a)
    return assets


def build(root: str, single_asset: bool) -> dict:
    catalog = load_catalog(DEFAULT_CATALOG)
    if single_asset:
        if os.path.isfile(os.path.join(root, "recon", "inventory", "surface.json")):
            assets = [a for a in [load_web_asset(root)] if a]
        elif os.path.isfile(os.path.join(root, "host.json")):
            assets = [a for a in [load_network_host(os.path.join(root, "host.json"))] if a]
        else:
            assets = []
    else:
        assets = discover_assets(root)

    all_cells = []
    asset_meta = {}
    for a in assets:
        all_cells.extend(cells_for_asset(catalog, a))
        asset_meta[a["asset_tag"]] = {
            "kind": a["kind"], "dir": os.path.relpath(a["dir"], root),
            "open_listeners": a["open_listeners"],
            "surface_hosts": a["surface_hosts"], "recon_hosts": a["recon_hosts"],
        }
    all_cells.sort(key=lambda c: (c["asset_tag"], c["class_id"], c["scope_key"]))
    return {
        "generated_by": "enumerate_cells.py",
        "catalog_version": catalog.get("meta", {}).get("version"),
        "assets": asset_meta,
        "cells": all_cells,
        "per_class_counts": dict(Counter(c["class_id"] for c in all_cells)),
        "total_cells": len(all_cells),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--asset-dir")
    g.add_argument("--engagement-dir")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()

    root = os.path.abspath(args.asset_dir or args.engagement_dir)
    single = bool(args.asset_dir)
    try:
        result = build(root, single)
    except CatalogError as e:
        print(f"enumerate_cells: {e}", file=sys.stderr)
        return 2
    out = args.out or os.path.join(root, "applicability", "cells.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"enumerate_cells: {result['total_cells']} cell(s) across {len(result['assets'])} asset(s) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
