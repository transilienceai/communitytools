#!/usr/bin/env python3
"""Deterministic AndroidManifest / Info.plist fact extractor.

Feeds mobile_surface_build.py. Exists so the app's exported-component and
transport-security facts are CODE-owned: an agent may not decide which components
are exported, because that decision sizes the MAS-PLATFORM-IPC work-list.

Reads a decoded artifact tree (apktool output for Android, the extracted .app for
iOS) and writes <app_dir>/recon/manifest-facts.json. Prints the same JSON on its
last stdout line.

Android input : <decoded>/AndroidManifest.xml (+ res/xml/*.xml for the NSC)
iOS input     : <extracted>/Payload/*.app/Info.plist  (plutil -convert json)
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
COMPONENT_TAGS = {"activity": "activity", "activity-alias": "activity",
                  "service": "service", "receiver": "receiver", "provider": "provider"}


def _attr(el, name, default=None):
    return el.attrib.get(f"{ANDROID_NS}{name}", default)


def _truthy(v) -> bool:
    return str(v).lower() == "true"


def _apktool_yml_version(decoded: str) -> tuple:
    """(versionName, versionCode) from apktool.yml.

    apktool MOVES versionCode/versionName out of AndroidManifest.xml into
    apktool.yml under `versionInfo:` — so on real apktool output (which is exactly
    what the workflow feeds this tool) the manifest carries neither. Parsed with a
    regex rather than a yaml dep: the block is two fixed scalar keys, and every
    other tool here is stdlib-only.
    """
    path = os.path.join(decoded, "apktool.yml")
    try:
        txt = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None, None
    blk = re.search(r"^versionInfo:\s*$((?:\n[ \t]+.*)*)", txt, re.M)
    if not blk:
        return None, None
    name = re.search(r"^\s+versionName:\s*['\"]?(.+?)['\"]?\s*$", blk.group(1), re.M)
    code = re.search(r"^\s+versionCode:\s*['\"]?(.+?)['\"]?\s*$", blk.group(1), re.M)
    val = lambda m: m.group(1).strip() if m and m.group(1).strip() not in ("", "null") else None
    return val(name), val(code)


def android_facts(decoded: str) -> dict:
    mpath = os.path.join(decoded, "AndroidManifest.xml")
    root = ET.parse(mpath).getroot()
    app = root.find("application")
    yml_name, yml_code = _apktool_yml_version(decoded)
    facts: dict = {
        "platform": "android",
        "package": root.attrib.get("package"),
        # manifest first (an aapt2-dumped or hand-decoded manifest keeps them),
        # then apktool.yml (where apktool actually puts them)
        "version_name": _attr(root, "versionName") or yml_name,
        "version_code": _attr(root, "versionCode") or yml_code,
        "components": [], "deeplinks": [], "permissions": [],
        "uses_cleartext_traffic": _truthy(_attr(app, "usesCleartextTraffic", "false")) if app is not None else False,
        "network_security_config": None,
        "allow_backup": _truthy(_attr(app, "allowBackup", "true")) if app is not None else True,
        "debuggable": _truthy(_attr(app, "debuggable", "false")) if app is not None else False,
    }
    for p in root.findall("uses-permission"):
        n = _attr(p, "name")
        if n:
            facts["permissions"].append(n)

    if app is not None:
        nsc = _attr(app, "networkSecurityConfig")
        if nsc:
            facts["network_security_config"] = nsc
            ref = nsc.split("/")[-1]
            for cand in glob.glob(os.path.join(decoded, "res", "xml*", f"{ref}.xml")):
                try:
                    txt = open(cand, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                facts["nsc_path"] = os.path.relpath(cand, decoded)
                facts["nsc_cleartext_permitted"] = "cleartextTrafficPermitted=\"true\"" in txt
                facts["nsc_user_ca_trusted"] = 'certificates src="user"' in txt
                break

        for tag, kind in COMPONENT_TAGS.items():
            for el in app.findall(tag):
                name = _attr(el, "name")
                if not name:
                    continue
                if name.startswith("."):
                    name = f"{facts['package']}{name}"
                intents = el.findall("intent-filter")
                # Android's own rule: exported defaults to TRUE when an intent-filter
                # is present and the attribute is absent. Getting this backwards would
                # silently shrink the IPC work-list, so it is code, not judgement.
                explicit = _attr(el, "exported")
                exported = _truthy(explicit) if explicit is not None else bool(intents)
                facts["components"].append({
                    "name": name, "type": kind, "exported": exported,
                    "permission": _attr(el, "permission"),
                    "explicit_exported": explicit is not None,
                })
                for f in intents:
                    for data in f.findall("data"):
                        scheme = _attr(data, "scheme")
                        if not scheme or scheme in ("http", "https") and not _attr(data, "host"):
                            continue
                        host = _attr(data, "host") or ""
                        path = (_attr(data, "path") or _attr(data, "pathPrefix")
                                or _attr(data, "pathPattern") or "")
                        facts["deeplinks"].append(
                            {"pattern": f"{scheme}://{host}{path}", "component": name})
    return facts


def ios_facts(extracted: str) -> dict:
    cands = glob.glob(os.path.join(extracted, "Payload", "*.app", "Info.plist")) \
        or glob.glob(os.path.join(extracted, "*.app", "Info.plist")) \
        or glob.glob(os.path.join(extracted, "Info.plist"))
    if not cands:
        raise FileNotFoundError(f"no Info.plist under {extracted}")
    path = cands[0]
    with open(path, "rb") as fh:
        pl = plistlib.load(fh)

    ats = pl.get("NSAppTransportSecurity") or {}
    exceptions = ats.get("NSExceptionDomains") or {}
    facts: dict = {
        "platform": "ios",
        "package": pl.get("CFBundleIdentifier"),
        "version_name": pl.get("CFBundleShortVersionString"),
        "version_code": pl.get("CFBundleVersion"),
        "components": [], "deeplinks": [], "permissions": [],
        "uses_cleartext_traffic": bool(ats.get("NSAllowsArbitraryLoads")),
        "ats_allows_arbitrary_loads": bool(ats.get("NSAllowsArbitraryLoads")),
        "ats_exception_domains": sorted(exceptions.keys()),
        "min_os": pl.get("MinimumOSVersion"),
        "info_plist": os.path.relpath(path, extracted),
    }
    # usage-description keys are the declared privacy surface
    for k, v in pl.items():
        if k.startswith("NS") and k.endswith("UsageDescription"):
            facts["permissions"].append(k)
    for entry in pl.get("CFBundleURLTypes") or []:
        for scheme in entry.get("CFBundleURLSchemes") or []:
            facts["deeplinks"].append({"pattern": f"{scheme}://", "component": entry.get("CFBundleURLName")})
    for dom in pl.get("com.apple.developer.associated-domains") or []:
        facts["deeplinks"].append({"pattern": str(dom), "component": "associated-domain"})
    # An app extension is third-party-reachable in the same sense an exported
    # Android component is, so it belongs in the IPC work-list.
    for ext in glob.glob(os.path.join(os.path.dirname(path), "PlugIns", "*.appex")):
        facts["components"].append({"name": os.path.basename(ext), "type": "app-extension",
                                    "exported": True, "permission": None,
                                    "explicit_exported": True})
    return facts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--platform", required=True, choices=["android", "ios"])
    ap.add_argument("--decoded", required=True,
                    help="apktool output dir (android) or extracted IPA dir (ios)")
    ap.add_argument("--app-dir", required=True, help="the app-bundle asset dir")
    ap.add_argument("--artifact", default=None)
    ap.add_argument("--artifact-sha256", default=None)
    ap.add_argument("--framework", default=None)
    args = ap.parse_args()

    if not os.path.isdir(args.decoded):
        print(f"mobile_manifest_facts: --decoded not found: {args.decoded}", file=sys.stderr)
        return 2
    try:
        facts = android_facts(args.decoded) if args.platform == "android" else ios_facts(args.decoded)
    except (FileNotFoundError, ET.ParseError, plistlib.InvalidFileException) as e:
        print(f"mobile_manifest_facts: cannot parse the manifest: {e}", file=sys.stderr)
        return 2

    for k, val in (("artifact", args.artifact), ("artifact_sha256", args.artifact_sha256),
                   ("framework", args.framework)):
        if val:
            facts[k] = val
    facts["exported_component_count"] = sum(1 for c in facts["components"] if c["exported"])

    out = os.path.join(args.app_dir, "recon", "manifest-facts.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(facts, fh, indent=1)
    print(json.dumps({"ok": True, "path": out, "platform": facts["platform"],
                      "package": facts["package"],
                      "components": len(facts["components"]),
                      "exported": facts["exported_component_count"],
                      "deeplinks": len(facts["deeplinks"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
