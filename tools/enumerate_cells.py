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


_OPEN_SERVICE_RE = re.compile(r"^\s*(\d{1,5})\s*/\s*(.*)$")
# A version-looking token inside the free-text service label, e.g. "nginx 1.18.0",
# "IIS/10.0". Used only to decide version_fingerprinted, never to assert a CVE.
_VERSION_IN_TEXT_RE = re.compile(r"\d+\.\d+(?:\.\d+)*")


def normalize_ports(host: dict) -> list:
    """Return the host's open listeners as `ports[]` records, from either shape.

    The scan pipeline writes `open_services: ["443/IIS-ASP.NET", ...]`; the schema
    documented for this loader is `ports: [{port, service, product, version}]`.
    Every one of the 72 committed host.json files uses the first form and none use
    the second, so a loader that reads only `ports` returns None for every real
    host — enumerating zero cells, which the gate then reports as nothing to do.
    Accept both, and let a host that genuinely has neither fall through to None.
    """
    if host.get("ports"):
        return list(host["ports"])
    out = []
    for entry in host.get("open_services") or []:
        m = _OPEN_SERVICE_RE.match(str(entry))
        if not m:
            continue
        label = m.group(2).strip()
        out.append({
            "port": m.group(1),
            "state": "open",
            # The label is one free-text blob; it is the only evidence available, so
            # it serves as both service and product for flag matching. Splitting it
            # further would be invention.
            "service": label.lower(),
            "product": label,
            "version": m.group(0) if _VERSION_IN_TEXT_RE.search(label) else "",
        })
    return out


def load_network_host(host_json_path: str) -> dict | None:
    try:
        with open(host_json_path, encoding="utf-8") as fh:
            host = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None
    ports = normalize_ports(host)
    # Zero-units guard: a dead / no-surface host yields NO cells (not even misconfig).
    if not host.get("live") or not ports:
        return None
    host = dict(host, ports=ports)
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


# mobile: unit `type` -> the flag it implies. Monotone — a declared type can only
# ADD cells, never remove one, so a forgotten flag costs coverage but never hides it.
MOBILE_TYPE_FLAGS = {
    "component": "exported_component",
    "deeplink": "exported_component",
    "webview": "webview",
    "storage": "local_store",
    "crypto-use": "crypto_use",
}


def load_mobile_app(asset_dir: str) -> dict | None:
    """Mobile app-bundle asset (schema mobile-surface/v1).

    Deliberately does NOT call web_unit_flags() or parse_listener(). web_unit_flags
    stamps http_listener on every unit unconditionally ("a web surface unit is an
    HTTP endpoint by definition") and parse_listener coerces any colon-less address
    to "<addr>:443" — so routing a mobile unit through them would turn
    `com.example.app/.MainActivity` into the listener `com.example.app:443` and make
    the app eligible for XC-CORS / XC-TRANSPORT-DOWNGRADE / XC-VERBOSE-ERRORS /
    XC-SECURITY-HEADERS. listener_flags stays EMPTY, so the host-scope branch of
    cells_for_asset iterates zero times.

    The backend API this client talks to is a SEPARATE web asset with its own
    surface.json and the ordinary web/API classes — never modelled here.
    """
    spath = os.path.join(asset_dir, "recon", "inventory", "mobile-surface.json")
    if not os.path.isfile(spath):
        return None
    try:
        surf = json.load(open(spath, encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    base = os.path.basename(asset_dir.rstrip("/"))
    asset_tag = surf.get("asset_tag") or base

    # Asset flags are the derived mobile_app plus ASSET-level declarations only.
    # Unit flags deliberately do NOT roll up: rolling them up would make every app
    # enumerate the four unit classes at asset scope as well, double-counting the
    # work-list and breaking the "12 asset cells per app" invariant.
    asset_flags: set = {"mobile_app"}
    asset_flags |= {f for f in (surf.get("flags") or []) if f in AGENT_FLAGS}

    unit_records = []
    for u in surf.get("units") or []:
        uid = u.get("unit_id")
        if not uid:
            continue
        uf = {f for f in (u.get("flags") or []) if f in AGENT_FLAGS}
        implied = MOBILE_TYPE_FLAGS.get(u.get("type"))
        if implied:
            uf.add(implied)
        uf.add("mobile_app")
        unit_records.append({"unit_id": uid, "flags": uf, "equiv_group": u.get("equiv_group")})

    # NOTE: unlike load_network_host's zero-units guard, a units-less mobile app is
    # a RECON FAILURE, not an absent asset — it still owes its asset-scope cells so
    # the gate blocks rather than reporting a vacuous 1.0.
    return {
        "asset_tag": asset_tag, "kind": "mobile", "dir": asset_dir,
        "platform": (surf.get("platform") or "").lower() or None,
        "package": surf.get("package"), "version": surf.get("version"),
        "artifact_sha256": surf.get("artifact_sha256"),
        "units": unit_records,
        "listener_flags": {},          # an app binary has NO listener
        "asset_flags": asset_flags,
        "open_listeners": [],
        "surface_hosts": [], "recon_hosts": [],   # kind != "web" -> no surface_undercount
    }


def cells_for_asset(catalog: dict, asset: dict) -> list:
    cells = []
    by_id = catalog_by_id(catalog)
    for cid, cls in by_id.items():
        scope = cls["scope"]
        base = {"class_id": cid, "taxonomy": cls["taxonomy"], "title": cls["title"],
                "scope": scope, "negative_kind": cls["negative_kind"], "min_vantages": cls["min_vantages"],
                "proof_mode": cls.get("proof_mode", "either"),
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
    # NOTE: the surface.json glob does NOT match mobile-surface.json — basenames are
    # exact — so the two surface kinds never collide.
    for sp in sorted(glob.glob(os.path.join(engagement_dir, "**", "recon", "inventory", "surface.json"), recursive=True)):
        a = load_web_asset(os.path.dirname(os.path.dirname(os.path.dirname(sp))))
        if a:
            assets.append(a)
    for mp in sorted(glob.glob(os.path.join(engagement_dir, "**", "recon", "inventory", "mobile-surface.json"), recursive=True)):
        a = load_mobile_app(os.path.dirname(os.path.dirname(os.path.dirname(mp))))
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
        # Accumulate rather than first-match-wins: a dir carrying both surface kinds
        # must contribute both assets, never silently drop one.
        assets = [a for a in (load_web_asset(root), load_mobile_app(root)) if a]
        if not assets and os.path.isfile(os.path.join(root, "host.json")):
            n = load_network_host(os.path.join(root, "host.json"))
            if n:
                assets.append(n)
    else:
        assets = discover_assets(root)

    all_cells = []
    asset_meta = {}
    seen_tags: dict = {}
    for a in assets:
        # Fail closed on a duplicate tag. asset_meta is keyed by asset_tag and the
        # gate resolves each asset's ledger from meta["dir"], so a collision would
        # silently evaluate both assets' cells against ONE directory.
        if a["asset_tag"] in seen_tags:
            raise CatalogError(
                f"duplicate asset_tag {a['asset_tag']!r} in {seen_tags[a['asset_tag']]} "
                f"and {a['dir']} — asset_tag must be unique across the engagement")
        seen_tags[a["asset_tag"]] = a["dir"]
        all_cells.extend(cells_for_asset(catalog, a))
        asset_meta[a["asset_tag"]] = {
            "kind": a["kind"], "dir": os.path.relpath(a["dir"], root),
            "platform": a.get("platform"),
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
