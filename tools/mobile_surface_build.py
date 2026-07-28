#!/usr/bin/env python3
"""Emit the TWO gated surfaces of a mobile engagement from recovered facts.

A mobile app assessment owes coverage on two distinct surfaces, and this tool owns
the bytes of both so no agent can shrink either work-list:

  1. the app bundle  -> <app_dir>/recon/inventory/mobile-surface.json  (mobile-surface/v1)
     covered by the 15 MAS-* MASVS classes
  2. its backend(s)  -> <api_dir>/recon/inventory/surface.json         (surface/v2)
     covered by the ordinary web/API classes

(2) is the point. A mobile engagement that stops at the bundle has tested the
smaller half — the endpoints recovered from a decompiled bundle are not browser
reachable and are therefore systematically under-tested.

INPUTS (facts, not bytes — the agent authors these; this tool transforms them)
  <app_dir>/recon/manifest-facts.json     deterministic, from mobile_manifest_facts.py
  <app_dir>/recon/inventory/app-units.json   agent: code-level units only decompiled
                                             source review can find (webview/storage/
                                             crypto-use), schema app-units/v1
  <app_dir>/recon/inventory/endpoints.json   agent: the recovered server contract,
                                             schema endpoints/v1
  <app_dir>/recon/control_wiring.json      optional, from apk_control_wiring.py

SCOPE GATE
  --allow is REQUIRED. Only apexes on the allow-list become backend assets. A bundle
  string is attacker- or staleness-influenced input; without the gate a hostile or
  obsolete host in a decompiled blob would steer active testing out of scope, and
  passive_web_probe would inherit the same list.

Prints a one-line JSON summary on its last stdout line (house convention).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from coverage_catalog import AGENT_FLAGS, MOBILE_FLAGS, WEB_AGENT_FLAGS  # noqa: E402

# unit type -> the mobile flag it implies (mirrors enumerate_cells.MOBILE_TYPE_FLAGS)
MOBILE_TYPES = {"component": "exported_component", "deeplink": "exported_component",
                "webview": "webview", "storage": "local_store", "crypto-use": "crypto_use",
                "other": None}
_SLUG_RE = re.compile(r"[^a-z0-9]+")
# Multi-label public suffixes we actually meet. Not a full PSL — an over-long apex
# only ever splits one backend into two assets (more cells, never fewer), which is
# the safe direction to be wrong in.
_MULTI_SUFFIX = {"co.uk", "co.in", "com.au", "co.za", "com.br", "co.jp", "com.sg",
                 "co.nz", "com.mx", "co.kr", "ac.uk", "gov.uk", "org.uk", "com.tr"}


def slug(s: str) -> str:
    return _SLUG_RE.sub("-", (s or "").lower()).strip("-")


def registrable_apex(host: str) -> str:
    parts = (host or "").split(".")
    if len(parts) <= 2:
        return host or ""
    if ".".join(parts[-2:]) in _MULTI_SUFFIX and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def wiring_gaps(wiring: dict) -> list:
    """Flatten apk_control_wiring.py's gap findings to "control:name:gap" strings.

    The gaps live under `controls.wiring_gaps` as OBJECTS, not at the top level as
    strings — reading the wrong path yields [] and silently drops the one signal an
    agent cannot fabricate: a control that is SHIPPED BUT INERT (a CertificatePinner
    built and never attached, a root-check .so bundled and never loaded). Those are
    positives that may be raised from static evidence; the corresponding NEGATIVE
    ("pinning is enforced") still requires a runtime bypass attempt.
    """
    out = []
    for g in ((wiring.get("controls") or {}).get("wiring_gaps") or []):
        if isinstance(g, dict):
            out.append(":".join(str(g.get(k, "")) for k in ("control", "name", "gap")))
        elif g:
            out.append(str(g))
    if (wiring.get("ssl_pinning") or {}).get("pinning_present_but_inert"):
        out.append("ssl_pinning:CertificatePinner:inert")
    for name, r in (wiring.get("root_integrity") or {}).items():
        if isinstance(r, dict) and r.get("shipped_but_unwired"):
            out.append(f"root_integrity:{name}:shipped_but_unwired")
    if wiring.get("hardcoded_keys"):
        out.append(f"hardcoded_keys:count:{len(wiring['hardcoded_keys'])}")
    return sorted(set(out))


def merge_units(existing: list, fresh: list) -> list:
    """Merge, never clobber: a re-run must not drop units a previous pass recorded.

    Keyed by unit_id; the fresh record wins on conflict (it reflects the newer facts),
    but a unit only present in the existing file survives.
    """
    by_id = {u.get("unit_id"): u for u in (existing or []) if u.get("unit_id")}
    for u in fresh:
        by_id[u["unit_id"]] = u
    return sorted(by_id.values(), key=lambda u: str(u.get("unit_id")))


# --- (1) the app bundle surface ----------------------------------------------
def build_mobile_surface(app_dir: str, platform: str) -> dict:
    facts = read_json(os.path.join(app_dir, "recon", "manifest-facts.json"), {}) or {}
    code = read_json(os.path.join(app_dir, "recon", "inventory", "app-units.json"), {}) or {}
    wiring = read_json(os.path.join(app_dir, "recon", "control_wiring.json"), {}) or {}

    units: list = []

    # manifest-derived units (deterministic)
    for c in facts.get("components") or []:
        if not c.get("exported") or not c.get("name"):
            continue
        units.append({"unit_id": f"cmp:{c['name'].rsplit('.', 1)[-1]}", "type": "component",
                      "address": c["name"], "flags": ["exported_component"],
                      "equiv_group": c.get("equiv_group"), "evidence_ref": ["manifest-facts"]})
    for i, d in enumerate(facts.get("deeplinks") or [], 1):
        addr = d if isinstance(d, str) else d.get("pattern") or json.dumps(d, sort_keys=True)
        units.append({"unit_id": f"dl:{slug(addr)[:40] or i}", "type": "deeplink",
                      "address": addr, "flags": ["exported_component"],
                      "equiv_group": (d or {}).get("equiv_group") if isinstance(d, dict) else None,
                      "evidence_ref": ["manifest-facts"]})

    # code-level units (agent facts): only decompiled-source review finds these
    for u in code.get("units") or []:
        uid, utype = u.get("unit_id"), u.get("type")
        if not uid or utype not in MOBILE_TYPES:
            continue
        flags = [f for f in (u.get("flags") or []) if f in MOBILE_FLAGS]
        implied = MOBILE_TYPES.get(utype)
        if implied and implied not in flags:
            flags.append(implied)
        units.append({"unit_id": uid, "type": utype, "address": u.get("address") or uid,
                      "flags": sorted(flags), "equiv_group": u.get("equiv_group"),
                      "evidence_ref": u.get("evidence_ref") or []})

    spath = os.path.join(app_dir, "recon", "inventory", "mobile-surface.json")
    prior = read_json(spath, {}) or {}
    doc = {
        "schema": "mobile-surface/v1",
        # asset_tag MUST equal the directory basename: coverage_gate resolves each
        # asset's ledger from its dir, and a tag/dir mismatch silently mis-joins.
        "asset_tag": os.path.basename(app_dir.rstrip("/")),
        "platform": platform or facts.get("platform") or "",
        "package": facts.get("package") or prior.get("package"),
        "version": facts.get("version_name") or prior.get("version"),
        "artifact": facts.get("artifact") or prior.get("artifact"),
        "artifact_sha256": facts.get("artifact_sha256") or prior.get("artifact_sha256"),
        "framework": facts.get("framework") or prior.get("framework") or "unknown",
        # asset-level agent flags only; a DERIVED flag (mobile_app) is stamped by
        # enumerate_cells.load_mobile_app and can never be declared here.
        "flags": sorted({f for f in (facts.get("flags") or []) if f in AGENT_FLAGS}),
        "control_wiring_gaps": wiring_gaps(wiring),
        "units": merge_units(prior.get("units"), units),
    }
    os.makedirs(os.path.dirname(spath), exist_ok=True)
    with open(spath, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
    return doc


# --- (2) the recovered backend surfaces --------------------------------------
def build_api_surfaces(app_dir: str, engagement_dir: str, allow: set) -> tuple[list, list]:
    eps = read_json(os.path.join(app_dir, "recon", "inventory", "endpoints.json"), []) or []
    if isinstance(eps, dict):
        eps = eps.get("endpoints") or []

    by_apex: dict = {}
    skipped: list = []
    for e in eps:
        origin = e.get("origin") or ""
        host = urlsplit(origin).hostname or origin
        if not host:
            continue
        apex = registrable_apex(host)
        if not (host in allow or apex in allow):
            skipped.append(host)
            continue
        by_apex.setdefault(apex, []).append((host, e))

    out = []
    for apex, rows in sorted(by_apex.items()):
        tag = f"{slug(apex)}-api"
        adir = os.path.join(engagement_dir, tag)
        units = []
        for i, (host, e) in enumerate(rows, 1):
            tmpl = e.get("path_template") or e.get("path") or "/"
            methods = e.get("methods") or ([e["method"]] if e.get("method") else ["GET"])
            scheme = urlsplit(e.get("origin") or "").scheme or "https"
            units.append({
                "unit_id": e.get("unit_id") or f"{slug(host)[:24]}:{'-'.join(methods)}:{slug(tmpl)[:60] or i}",
                "type": "endpoint",
                "address": f"{scheme}://{host}{tmpl}",
                "methods": methods,
                # filtered to the WEB vocabulary specifically: mobile flags are also
                # AGENT_FLAGS, so filtering against that alone would let a stray
                # `webview` onto an HTTP endpoint
                "flags": sorted({f for f in (e.get("flags") or []) if f in WEB_AGENT_FLAGS}),
                # equiv_group is honoured ONLY when the agent set it explicitly. The
                # gate CREDITS siblings from it, so an invented over-broad group would
                # silently erase cells; when unsure the correct value is null.
                "equiv_group": e.get("equiv_group"),
                "evidence_ref": e.get("evidence_ref") or ([e["source_file"]] if e.get("source_file") else []),
            })
        spath = os.path.join(adir, "recon", "inventory", "surface.json")
        prior = read_json(spath, {}) or {}
        doc = {"schema": "surface/v2", "asset_tag": tag, "apex": apex,
               "recovered_from": os.path.basename(app_dir.rstrip("/")),
               "units": merge_units(prior.get("units"), units)}
        os.makedirs(os.path.dirname(spath), exist_ok=True)
        with open(spath, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
        out.append({"tag": tag, "apex": apex, "output_dir": adir,
                    "surface_path": spath, "units": len(doc["units"])})
    return out, sorted(set(skipped))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-dir", required=True, help="the app-bundle asset dir")
    ap.add_argument("--engagement-dir", required=True)
    ap.add_argument("--platform", default="", choices=["", "android", "ios"])
    ap.add_argument("--allow", nargs="*", default=None,
                    help="in-scope hosts/apexes for the recovered backend (REQUIRED, may be empty)")
    args = ap.parse_args()

    if args.allow is None:
        print("mobile_surface_build: --allow is required (pass an explicit in-scope host list; "
              "use --allow with no values only when the scope genuinely names no backend)",
              file=sys.stderr)
        return 2
    if not os.path.isdir(args.app_dir):
        print(f"mobile_surface_build: --app-dir not found: {args.app_dir}", file=sys.stderr)
        return 2

    mob = build_mobile_surface(args.app_dir, args.platform)
    apis, skipped = build_api_surfaces(args.app_dir, args.engagement_dir, set(args.allow))

    summary = {
        "ok": True,
        "app_dir": args.app_dir,
        "asset_tag": mob["asset_tag"],
        "platform": mob["platform"],
        "mobile_surface_path": os.path.join(args.app_dir, "recon", "inventory", "mobile-surface.json"),
        # relayed to the workflow's mobSurfaceOk gate — counted HERE, by code, so the
        # completion precondition never rests on an agent's self-report
        "mobile_units": len(mob["units"]),
        "api_surfaces": apis,
        "api_assets": len(apis),
        "endpoints_recovered": sum(a["units"] for a in apis),
        "skipped_out_of_scope": skipped,
    }
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
