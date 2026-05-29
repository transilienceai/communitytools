#!/usr/bin/env python3
"""Attack-path stitcher — graph builder.

Reads validated findings + org surface, applies the 7 edge detectors documented
in skills/attack-path-stitcher/reference/edge-detectors.md, and writes:

    {OUTPUT_DIR}/artifacts/attack-paths.json
    {OUTPUT_DIR}/artifacts/attack-paths.dot
    {OUTPUT_DIR}/artifacts/attack-paths.md

Confirmed vs inferred:
    A path is "confirmed" only when every hop has a feasibility of 1.0 AND
    every edge cites at least one validated finding. Paths containing any
    inferred edge (trust-zone, supply-chain default, shared-secret) land in
    `inferred_paths`, never in `confirmed_paths`. Per RFP §3.3, only
    `confirmed_paths` are RFP-grade "confirmed attack paths".

Usage:
    python3 tools/chain-merger.py --output-dir runs/org/
    python3 tools/chain-merger.py --output-dir runs/org/ --max-depth 6

Exit codes:
    0 — graph written
    1 — missing required inputs (no validated findings or no org-surface.json)
    2 — runtime error
"""

import argparse
import glob
import json
import math
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

MAX_EDGES = 50_000
DEFAULT_MAX_DEPTH = 8
TOP_N_PATHS_PER_JEWEL = 10
MAX_IMPLICIT_TRUST_FANOUT = 20  # per zone — caps O(n²) inferred-edge explosion

# Path-safe identifier regex. Asset / finding ids that fail this are rejected
# to prevent attacker-controlled IDs from writing or reading outside OUTPUT_DIR.
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# Credential keyword anchors. The generic user:pass pattern is only accepted
# when one of these tokens appears within CREDKEYWORD_WINDOW chars before the
# candidate match. Standalone `pass` / `auth` are deliberately excluded — they
# match common English in evidence files ("Did not pass authentication") and
# trigger FPs whenever a Header:Value line is nearby. Only specific, unambiguous
# credential tokens are accepted.
CRED_KEYWORDS = re.compile(
    r"\b(password|passwd|pwd|credential[s]?|authoriz(?:ation|e)|"
    r"secret|api[_-]?key|access[_-]?key|bearer)\b",
    re.IGNORECASE,
)
CREDKEYWORD_WINDOW = 80

# High-confidence credential shapes — accepted without keyword anchor.
HC_CRED_PATTERNS = [
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "jwt"),
    (re.compile(r"\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b"), "ntlm"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "openai-key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws-access"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "github-pat"),
    (re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "github-oauth"),
    (re.compile(r"\bxox[abps]-[A-Za-z0-9-]{10,}\b"), "slack-token"),
]
# Generic user:pass — requires CRED_KEYWORD within window.
USERPASS = re.compile(r"\b([A-Za-z_][A-Za-z0-9_.-]{2,32}):([!-~]{6,64})\b")
USERPASS_USERNAME_DENY = re.compile(
    r"^(http|https|ftp|sftp|ssh|host|server|user-agent|content|accept|referer|origin|"
    r"version|build|release|ubuntu|debian|alpine|centos|nginx|apache|httpd|tcp|udp|tls|"
    r"x-[a-z-]+|cache-control|last-modified|etag|location|date|content-type|set-cookie)$",
    re.IGNORECASE,
)

# Token shapes that look high-entropy but are NOT secrets (audit critical #5).
TOKEN_DENY_PREFIX = (
    "sha256-", "sha384-", "sha512-", "sri-", "blake2b-", "blake2s-",
    "data:", "blob:", "MII",  # PEM/DER base64 prefix
)
TOKEN_HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")
KNOWN_HEX_LENGTHS = {32, 40, 56, 64, 96, 128}  # md5/sha1/sha224/sha256/sha384/sha512

AD_SIGNALS = re.compile(
    r"(secretsdump\.py|ticketer\.py|getST\.py|msDS-AllowedToActOnBehalfOfOtherIdentity|"
    r"\bESC(?:1[0-5]|[1-9])\b|kerberoast|AS-?REPRoast)",
    re.IGNORECASE,
)
IAM_SIGNALS = re.compile(r"\bsts:AssumeRole\b|\biam:PassRole\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://([a-zA-Z0-9.-]+)(?::\d+)?(?:/|\b)")
TOKEN_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9_/+=-]{20,}\b")


def utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_finding_row(row: dict, path: str) -> bool:
    """Drop rows that can't safely participate in stitching. Logs every drop.

    Enforces the contract documented in cloud-agents/task-03-validation-run.md.
    """
    missing = [k for k in ("finding_id", "asset", "verdict") if not row.get(k)]
    if missing:
        print(f"WARN: dropping {path} — missing required field(s): {missing}", file=sys.stderr)
        return False
    if row["verdict"] != "VALID":
        print(f"WARN: dropping {path} — verdict={row['verdict']!r}, only VALID rows stitched", file=sys.stderr)
        return False
    fid = str(row["finding_id"])
    asset = str(row["asset"])
    if not SAFE_ID_RE.match(fid):
        print(f"WARN: dropping {path} — finding_id {fid!r} fails {SAFE_ID_RE.pattern} "
              f"(rejected to prevent path traversal in findings/ resolution)", file=sys.stderr)
        return False
    if not SAFE_ID_RE.match(asset):
        print(f"WARN: dropping {path} — asset {asset!r} fails {SAFE_ID_RE.pattern}",
              file=sys.stderr)
        return False
    if not row.get("vuln_class"):
        print(f"WARN: {path} missing vuln_class — ssrf/ad/iam detectors will skip this row",
              file=sys.stderr)
    return True


def load_validated(output_dir: Path) -> list[dict]:
    out = []
    for path in sorted(glob.glob(str(output_dir / "validated" / "*.json"))):
        try:
            with open(path) as f:
                row = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"WARN: cannot read {path}: {e}", file=sys.stderr)
            continue
        if not _validate_finding_row(row, path):
            continue
        row["_validated_path"] = path
        out.append(row)
    return out


def load_surface(output_dir: Path) -> dict:
    surface_path = output_dir / "artifacts" / "org-surface.json"
    if not surface_path.is_file():
        print(f"ERROR: missing {surface_path}", file=sys.stderr)
        return {}
    try:
        with open(surface_path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: {surface_path} is not valid JSON: {e}", file=sys.stderr)
        return {}


def read_finding_evidence(output_dir: Path, finding_id: str) -> str:
    parts = []
    base = output_dir / "findings" / finding_id
    for fname in ("description.md", "poc.py", "evidence/raw-source.txt"):
        p = base / fname
        if not p.is_file():
            continue
        try:
            parts.append(p.read_text(errors="replace"))
        except OSError as e:
            print(f"WARN: cannot read {p}: {e}", file=sys.stderr)
    return "\n".join(parts)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def safe_cvss(row: dict) -> float:
    """Extract CVSS as float, tolerant of validator schema drift.

    Accepts: {nvd: {score: 9.8}}, {nvd: {score: "9.8"}}, {cvss: 9.8}, {cvss: "9.8"}.
    Returns 0.0 on any malformed shape; the caller treats 0.0 as 'unscored'.
    """
    nvd = row.get("nvd")
    score = None
    if isinstance(nvd, dict):
        score = nvd.get("score")
    if score is None:
        score = row.get("cvss")
    if score is None:
        return 0.0
    try:
        return float(score)
    except (TypeError, ValueError):
        return 0.0


def _near_credential_keyword(text: str, match_start: int) -> bool:
    window_start = max(0, match_start - CREDKEYWORD_WINDOW)
    return bool(CRED_KEYWORDS.search(text[window_start:match_start]))


def extract_credentials(text: str) -> set[tuple[str, str]]:
    """Return set of (label, normalized_token) for credentials in text.

    High-confidence shapes (JWT, NTLM, vendor key prefixes) are accepted
    unconditionally. Generic user:pass is accepted only when a credential
    keyword precedes it within CREDKEYWORD_WINDOW chars — eliminates the
    huge FP rate from Server/Host/version-string false matches.
    """
    found: set[tuple[str, str]] = set()
    for pat, label in HC_CRED_PATTERNS:
        for m in pat.finditer(text):
            found.add((label, m.group(0)))
    for m in USERPASS.finditer(text):
        user, password = m.group(1), m.group(2)
        if USERPASS_USERNAME_DENY.match(user):
            continue
        if shannon_entropy(password) < 2.5 and not re.search(r"[!@#$%^&*()_+=\[\]{};:,.<>?/\\|`~-]", password):
            continue
        if not _near_credential_keyword(text, m.start()):
            continue
        found.add(("userpass", m.group(0)))
    return found


def _token_is_likely_digest(tok: str) -> bool:
    for prefix in TOKEN_DENY_PREFIX:
        if tok.startswith(prefix):
            return True
    if TOKEN_HEX_RE.match(tok) and len(tok) in KNOWN_HEX_LENGTHS:
        return True
    return False


def _proximity_has_secret_keyword(text: str, pos: int) -> bool:
    window_start = max(0, pos - 200)
    window_end = min(len(text), pos + 200)
    return bool(CRED_KEYWORDS.search(text[window_start:window_end]))


def detect_credential_reuse(
    findings: list[dict],
    evidence_by_finding: dict[str, str],
    findings_by_id: dict[str, dict],
) -> list[dict]:
    cred_locations: dict[tuple[str, str], list[str]] = defaultdict(list)
    for f in findings:
        fid = f.get("finding_id")
        creds = extract_credentials(evidence_by_finding.get(fid, ""))
        for c in creds:
            cred_locations[c].append(fid)

    edges = []
    for cred, fids in cred_locations.items():
        assets_for_fids = {findings_by_id[fid].get("asset") for fid in fids if fid in findings_by_id}
        assets_for_fids.discard(None)
        if len(assets_for_fids) < 2:
            continue
        assets = sorted(assets_for_fids)
        for src in assets:
            for dst in assets:
                if src == dst:
                    continue
                src_fids = [fid for fid in fids if findings_by_id.get(fid, {}).get("asset") == src]
                dst_fids = [fid for fid in fids if findings_by_id.get(fid, {}).get("asset") == dst]
                if not src_fids or not dst_fids:
                    continue
                edges.append({
                    "src": src, "dst": dst, "detector": "credential-reuse",
                    "via_findings": sorted(set(src_fids + dst_fids)),
                    "evidence": f"credential ({cred[0]}) present in evidence of {src} (findings {src_fids}) and {dst} (findings {dst_fids})",
                    "feasibility": 1.0,
                })
    return edges


def detect_shared_secret(findings: list[dict], evidence_by_finding: dict[str, str]) -> list[dict]:
    """High-entropy token shared across two assets — credential-adjacent but unproven.

    Requires the token to appear near (within 200 chars of) a credential keyword
    on AT LEAST ONE side. Otherwise base64 page hashes, sourcemap names, and
    container digests would generate noise edges (audit critical #5).
    """
    asset_token_context: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for f in findings:
        asset = f.get("asset")
        if not asset:
            continue
        text = evidence_by_finding.get(f.get("finding_id"), "")
        for m in TOKEN_CANDIDATE_RE.finditer(text):
            tok = m.group(0)
            if _token_is_likely_digest(tok):
                continue
            if shannon_entropy(tok) < 3.5:
                continue
            if not _proximity_has_secret_keyword(text, m.start()):
                continue
            asset_token_context[asset][tok].append(f.get("finding_id"))

    edges = []
    assets = list(asset_token_context)
    for i, src in enumerate(assets):
        for dst in assets[i + 1:]:
            shared = set(asset_token_context[src]) & set(asset_token_context[dst])
            if not shared:
                continue
            via = sorted({fid for tok in shared for fid in asset_token_context[src][tok] + asset_token_context[dst][tok] if fid})
            edges.append({
                "src": src, "dst": dst, "detector": "shared-secret",
                "via_findings": via,
                "evidence": f"{len(shared)} high-entropy credential-adjacent token(s) shared between {src} and {dst}",
                "feasibility": 0.5,
            })
    return edges


def detect_trust_zone(surface: dict) -> list[dict]:
    edges = []
    zones = surface.get("network_zones", {})
    trust_edges = surface.get("trust_edges", [])

    # Implicit same-zone fan-out: capped to prevent O(n²) edge explosion on
    # flat zones with 100+ assets. For larger zones, declare an explicit
    # trust_edge instead — or rely on credential-reuse / ssrf-reach to detect
    # the actual pivot during validation.
    for zone, assets_in_zone in zones.items():
        if len(assets_in_zone) > MAX_IMPLICIT_TRUST_FANOUT:
            print(f"WARN: zone {zone!r} has {len(assets_in_zone)} assets — skipping implicit "
                  f"same-zone fan-out (cap: {MAX_IMPLICIT_TRUST_FANOUT}). Declare explicit "
                  f"trust_edges if needed.", file=sys.stderr)
            continue
        for src in assets_in_zone:
            for dst in assets_in_zone:
                if src == dst:
                    continue
                edges.append({
                    "src": src, "dst": dst, "detector": "trust-zone",
                    "via_findings": [],
                    "evidence": f"both in zone {zone}",
                    "feasibility": 0.5,
                })
    for te in trust_edges:
        src_zone, dst_zone = te.get("src_zone"), te.get("dst_zone")
        for src in zones.get(src_zone, []):
            for dst in zones.get(dst_zone, []):
                edges.append({
                    "src": src, "dst": dst, "detector": "trust-zone",
                    "via_findings": [],
                    "evidence": f"zone trust: {src_zone} → {dst_zone} via {te.get('via','unknown')}",
                    "feasibility": 0.5,
                })
    return edges


def detect_ad_path(findings: list[dict], evidence_by_finding: dict[str, str], surface: dict) -> list[dict]:
    edges = []
    ad_principals = surface.get("ad_principals", {})
    for f in findings:
        text = evidence_by_finding.get(f.get("finding_id"), "")
        if not AD_SIGNALS.search(text):
            continue
        src = f.get("asset")
        for principal, owner_asset in ad_principals.items():
            if principal and principal.lower() in text.lower() and owner_asset != src:
                edges.append({
                    "src": src, "dst": owner_asset, "detector": "ad-path",
                    "via_findings": [f.get("finding_id")],
                    "evidence": f"AD pivot to principal '{principal}' via {f.get('finding_id')}",
                    "feasibility": 1.0,
                })
    return edges


def detect_iam_chain(findings: list[dict], evidence_by_finding: dict[str, str], surface: dict) -> list[dict]:
    edges = []
    iam_roles = surface.get("iam_roles", {})
    for f in findings:
        text = evidence_by_finding.get(f.get("finding_id"), "")
        if not IAM_SIGNALS.search(text):
            continue
        src = f.get("asset")
        for role_name, owner_asset in iam_roles.items():
            if role_name in text and owner_asset != src:
                edges.append({
                    "src": src, "dst": owner_asset, "detector": "iam-chain",
                    "via_findings": [f.get("finding_id")],
                    "evidence": f"cloud role assumption: {role_name}",
                    "feasibility": 1.0,
                })
    return edges


def detect_ssrf_reach(findings: list[dict], evidence_by_finding: dict[str, str], surface: dict) -> list[dict]:
    edges = []
    endpoint_to_asset: dict[str, str] = {}
    for node in surface.get("nodes", []):
        for ep in node.get("internal_endpoints", []):
            endpoint_to_asset[ep] = node["id"]

    for f in findings:
        vclass = (f.get("vuln_class") or f.get("class") or "").lower()
        if "ssrf" not in vclass:
            continue
        text = evidence_by_finding.get(f.get("finding_id"), "")
        src = f.get("asset")
        for m in URL_RE.finditer(text):
            host = m.group(1)
            if host in endpoint_to_asset:
                dst = endpoint_to_asset[host]
                if dst != src:
                    edges.append({
                        "src": src, "dst": dst, "detector": "ssrf-reach",
                        "via_findings": [f.get("finding_id")],
                        "evidence": f"SSRF reached internal host {host}",
                        "feasibility": 1.0,
                    })
    return edges


def detect_supply_chain(surface: dict, findings: list[dict]) -> list[dict]:
    edges = []
    sbom = surface.get("sbom", {})
    findings_by_asset: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        findings_by_asset[f.get("asset")].append(f)

    for dependent, providers in sbom.items():
        for provider in providers:
            if provider == dependent:
                continue
            provider_findings = findings_by_asset.get(provider, [])
            has_rce = any("rce" in (pf.get("vuln_class") or "").lower() for pf in provider_findings)
            edges.append({
                "src": provider, "dst": dependent, "detector": "supply-chain",
                "via_findings": [pf["finding_id"] for pf in provider_findings if pf.get("finding_id")],
                "evidence": f"{dependent} consumes artifacts from {provider}",
                "feasibility": 0.5 if has_rce else 0.25,
            })
    return edges


def dedupe(edges: list[dict]) -> list[dict]:
    cleaned = []
    for e in edges:
        if not e.get("src") or not e.get("dst"):
            print(f"WARN: dropping edge with missing src/dst: {e}", file=sys.stderr)
            continue
        cleaned.append(e)

    by_key: dict[tuple[str, str, str], dict] = {}
    for e in cleaned:
        key = (e["src"], e["dst"], e["detector"])
        if key in by_key:
            existing = by_key[key]
            existing["via_findings"] = sorted(set(existing["via_findings"]) | set(e["via_findings"]))
            existing["feasibility"] = max(existing["feasibility"], e["feasibility"])
        else:
            by_key[key] = dict(e)
    return list(by_key.values())


def build_nodes(surface: dict, findings: list[dict]) -> list[dict]:
    findings_by_asset: dict[str, list[str]] = defaultdict(list)
    max_cvss_by_asset: dict[str, float] = defaultdict(float)
    for f in findings:
        a = f.get("asset")
        if not a:
            continue
        if f.get("finding_id"):
            findings_by_asset[a].append(f["finding_id"])
        max_cvss_by_asset[a] = max(max_cvss_by_asset[a], safe_cvss(f))

    nodes = []
    for node in surface.get("nodes", []):
        aid = node["id"]
        nodes.append({
            "id": aid,
            "tier": node.get("tier", "unknown"),
            "services": node.get("services", []),
            "zone": node.get("zone"),
            "external": bool(node.get("external")),
            "findings": findings_by_asset.get(aid, []),
            "max_cvss": max_cvss_by_asset.get(aid, 0.0),
        })
    return nodes


def _classify_path(edges_in_path: list[dict]) -> str:
    """Return 'confirmed' iff every edge has via_findings AND feasibility == 1.0;
    'plausible' iff every edge has via_findings (some <1.0); 'inferred' otherwise."""
    if not edges_in_path:
        return "inferred"
    if all(e["feasibility"] >= 1.0 and e["via_findings"] for e in edges_in_path):
        return "confirmed"
    if all(e["via_findings"] for e in edges_in_path):
        return "plausible"
    return "inferred"


def find_paths_to_jewels(nodes: list[dict], edges: list[dict], max_depth: int) -> dict:
    jewels = [n["id"] for n in nodes if n.get("tier") == "crown_jewel"]
    by_id = {n["id"]: n for n in nodes}
    incoming_by_dst: dict[str, list[dict]] = defaultdict(list)
    for e in edges:
        incoming_by_dst[e["dst"]].append(e)

    entry_points: set[str] = set()
    confirmed_paths_per_jewel: list[dict] = []
    inferred_paths_per_jewel: list[dict] = []
    depth_truncated_count = 0
    topn_dropped_count = 0

    for jewel in jewels:
        raw_paths: list[dict] = []
        seen: set[tuple[str, ...]] = set()

        def dfs(current: str, path: list[str], used_edges: list[dict],
                feas: float, max_cvss: float, depth: int):
            nonlocal depth_truncated_count
            if depth > max_depth:
                depth_truncated_count += 1
                return
            incoming = [e for e in incoming_by_dst[current] if e["src"] not in path]
            if not incoming and len(path) > 1:
                start = path[-1]
                if by_id.get(start, {}).get("external"):
                    entry_points.add(start)
                    raw_paths.append({
                        "hops": list(reversed(path)),
                        "edges": [{"src": e["src"], "dst": e["dst"], "detector": e["detector"],
                                   "feasibility": e["feasibility"],
                                   "via_findings": e["via_findings"]} for e in reversed(used_edges)],
                        "feasibility": feas,
                        "max_cvss": max_cvss,
                        "path_class": _classify_path(used_edges),
                    })
                return
            for e in incoming:
                key = tuple(path + [e["src"]])
                if key in seen:
                    continue
                seen.add(key)
                new_max = max(max_cvss, by_id.get(e["src"], {}).get("max_cvss", 0.0))
                dfs(e["src"], path + [e["src"]], used_edges + [e],
                    feas * e["feasibility"], new_max, depth + 1)

        dfs(jewel, [jewel], [], 1.0, by_id.get(jewel, {}).get("max_cvss", 0.0), 0)

        confirmed = [p for p in raw_paths if p["path_class"] == "confirmed"]
        non_confirmed = [p for p in raw_paths if p["path_class"] != "confirmed"]

        def rank_key(p):
            return (p["feasibility"] * p["max_cvss"]) / max(1, len(p["hops"]))

        confirmed.sort(key=rank_key, reverse=True)
        non_confirmed.sort(key=rank_key, reverse=True)

        topn_dropped_count += max(0, len(confirmed) - TOP_N_PATHS_PER_JEWEL)
        topn_dropped_count += max(0, len(non_confirmed) - TOP_N_PATHS_PER_JEWEL)

        confirmed_paths_per_jewel.append({"jewel": jewel, "paths": confirmed[:TOP_N_PATHS_PER_JEWEL]})
        inferred_paths_per_jewel.append({"jewel": jewel, "paths": non_confirmed[:TOP_N_PATHS_PER_JEWEL]})

    return {
        "entry_points": sorted(entry_points),
        "confirmed_paths": confirmed_paths_per_jewel,
        "inferred_paths": inferred_paths_per_jewel,
        "depth_truncated_count": depth_truncated_count,
        "topn_dropped_count": topn_dropped_count,
    }


def write_dot(nodes: list[dict], edges: list[dict], path: Path) -> None:
    lines = ["digraph attack_paths {", '  rankdir=LR;', '  node [shape=box, style=rounded];']
    tier_color = {"crown_jewel": "#d62728", "revenue": "#ff7f0e", "support": "#1f77b4", "dev": "#7f7f7f"}
    for n in nodes:
        color = tier_color.get(n.get("tier"), "#cccccc")
        lines.append(f'  "{n["id"]}" [label="{n["id"]}\\n{n.get("tier")}", color="{color}"];')
    for e in edges:
        style = "solid" if e["feasibility"] >= 1.0 and e["via_findings"] else "dashed"
        lines.append(f'  "{e["src"]}" -> "{e["dst"]}" [label="{e["detector"]}", style={style}];')
    lines.append("}")
    path.write_text("\n".join(lines))


def write_markdown(confirmed: list[dict], inferred: list[dict],
                   nodes: list[dict], edges: list[dict], path: Path) -> None:
    lines = [f"# Attack Paths — {utc_iso()}", "",
             f"- Nodes: {len(nodes)}", f"- Edges: {len(edges)}", ""]
    lines.append("## Confirmed crown-jewel paths (RFP-grade)")
    lines.append("")
    for jewel in confirmed:
        lines.append(f"### {jewel['jewel']}")
        if not jewel["paths"]:
            lines.append("_No confirmed path._")
            lines.append("")
            continue
        for i, p in enumerate(jewel["paths"], 1):
            hops = " → ".join(p["hops"])
            lines.append(f"{i}. **{hops}** — feasibility {p['feasibility']:.2f}, max CVSS {p['max_cvss']:.1f}, "
                         f"{len(p['hops'])-1} hop(s)")
        lines.append("")
    lines.append("## Inferred paths (topology / supply-chain — NOT RFP-grade confirmed)")
    lines.append("")
    for jewel in inferred:
        if not jewel["paths"]:
            continue
        lines.append(f"### {jewel['jewel']}")
        for i, p in enumerate(jewel["paths"], 1):
            hops = " → ".join(p["hops"])
            lines.append(f"{i}. **{hops}** — class={p['path_class']}, feasibility {p['feasibility']:.2f}, "
                         f"max CVSS {p['max_cvss']:.1f}")
        lines.append("")
    path.write_text("\n".join(lines))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH,
                    help=f"max path length to search (default {DEFAULT_MAX_DEPTH})")
    args = ap.parse_args()

    output_dir = Path(args.output_dir).resolve()
    validated = load_validated(output_dir)
    if not validated:
        print("ERROR: no validated findings under", output_dir / "validated", file=sys.stderr)
        return 1

    surface = load_surface(output_dir)
    if not surface:
        return 1

    findings_by_id = {f["finding_id"]: f for f in validated}

    evidence_by_finding: dict[str, str] = {}
    for f in validated:
        fid = f["finding_id"]
        evidence_by_finding[fid] = read_finding_evidence(output_dir, fid)

    edges: list[dict] = []
    edges.extend(detect_credential_reuse(validated, evidence_by_finding, findings_by_id))
    edges.extend(detect_shared_secret(validated, evidence_by_finding))
    edges.extend(detect_trust_zone(surface))
    edges.extend(detect_ad_path(validated, evidence_by_finding, surface))
    edges.extend(detect_iam_chain(validated, evidence_by_finding, surface))
    edges.extend(detect_ssrf_reach(validated, evidence_by_finding, surface))
    edges.extend(detect_supply_chain(surface, validated))

    edges = dedupe(edges)
    edge_cap_truncated = False
    if len(edges) > MAX_EDGES:
        edges = edges[:MAX_EDGES]
        edge_cap_truncated = True

    nodes = build_nodes(surface, validated)
    paths = find_paths_to_jewels(nodes, edges, args.max_depth)

    artifacts = output_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)

    graph = {
        "generated_at": utc_iso(),
        "nodes": nodes,
        "edges": edges,
        "entry_points": paths["entry_points"],
        "confirmed_paths": paths["confirmed_paths"],
        "inferred_paths": paths["inferred_paths"],
        "truncation": {
            "edge_cap_hit": edge_cap_truncated,
            "depth_truncated_count": paths["depth_truncated_count"],
            "topn_dropped_count": paths["topn_dropped_count"],
            "max_depth": args.max_depth,
            "edge_cap": MAX_EDGES,
        },
    }
    (artifacts / "attack-paths.json").write_text(json.dumps(graph, indent=2))
    write_dot(nodes, edges, artifacts / "attack-paths.dot")
    write_markdown(paths["confirmed_paths"], paths["inferred_paths"],
                   nodes, edges, artifacts / "attack-paths.md")

    print(json.dumps({
        "nodes": len(nodes),
        "edges": len(edges),
        "entry_points": len(paths["entry_points"]),
        "confirmed_paths": sum(len(j["paths"]) for j in paths["confirmed_paths"]),
        "inferred_paths": sum(len(j["paths"]) for j in paths["inferred_paths"]),
        "truncation": graph["truncation"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
