#!/usr/bin/env python3
"""Deterministic report_data.json assembler.

Reads the namespaced interim per-finding verdict JSONs an engagement produced and
the engagement-meta.json, and writes ONE canonical report_data.json matching
skills/transilience-report-style/reference/report-data-schema.json — with NO LLM
in the loop. This is the concrete realization of the "coordinator is the sole
owner of the final JSON" guarantee: workers only ever wrote their own interim
file; this tool merges them.

Drop-entirely policy: only VALID/REPAIRED interims become findings[]. Any other
verdict found under validated/ (DEMOTED, unknown, null) is hard-dropped — excluded
from the report, listed in the printed summary's `hard_dropped`, and logged to
stderr (never into the payload, so idempotency/clocklessness are preserved).

Contract for an interim validated finding JSON (written by validate-findings to
<asset>/artifacts/validated/<id>.json — REJECTED ones live under false-positives/
and DEMOTED under dropped/; neither is read here):

    {
      "finding_id": "F1",
      "verdict": "VALID" | "REPAIRED",
      "severity": "High",                       # optional; derived from cvss if absent
      # cvss_vector should be the PRIMARY per the v4.0-first ladder (v4.0 -> v3.1
      # -> v3.0 -> v2.0); its prefix records which version the score came from.
      "cvss_score": 9.3, "cvss_vector": "CVSS:4.0/...",
      "cwe": "CWE-89", "owasp": "A03:2021",
      "cves": [{"id": "CVE-2024-1234", "score": 8.1, "severity": "High"}],
      "on_kev": false,
      "risk": {"risk_score": 0.56, "risk_bucket": "short_term"},
      "report_fields": {
        "title": "...", "affected": ["..."], "description": "...",
        "impact": "...", "recommendation": "..."
      },
      "poc": [                                    # ordered PoC steps (merges evidence/poc_request/screenshot)
        {"description": "...", "command": "...", "image_url": "..."}
      ]
    }

engagement-meta.json supplies the `engagement` block (title/version/etc.) plus any
optional passthrough sections (executive_summary, sections, tools_used, roadmap,
disclaimer, coverage_table, ruled_out).

Usage:
    python3 tools/report_data_build.py --engagement-dir <dir> \
        [--meta <dir>/engagement-meta.json] [-o <dir>/reports/report_data.json]

Exit codes: 0 ok; 1 missing inputs; 2 runtime/JSON error.
Prints a JSON summary (counts + sha256 of the written file) on the last line.
"""
import argparse
import glob
import hashlib
import json
import os
import sys

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def severity_band(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "Info"
    if not s > 0:
        return "Info"            # schema enum has no "None"
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    return "Low"


def load_json(path):
    with open(path) as f:
        return json.load(f)


def normalize_poc(poc):
    """The reproducible PoC as an ordered list of {description, command, image_url}
    step dicts (only-if-present keys). Returns [] for anything else."""
    out = []
    if not isinstance(poc, list):
        return out
    for s in poc:
        if not isinstance(s, dict):
            continue
        step = {k: s[k] for k in ("description", "command", "image_url") if s.get(k) not in (None, "")}
        if step:
            out.append(step)
    return out


def finding_from_verdict(v):
    """Map an interim verdict JSON -> a report_data findings[] entry."""
    rf = v.get("report_fields") or {}
    sev = v.get("severity") or severity_band(v.get("cvss_score"))
    if sev not in SEVERITY_ORDER:
        sev = severity_band(v.get("cvss_score"))
    out = {
        "id": v.get("finding_id") or v.get("id"),
        "title": rf.get("title") or v.get("title") or (v.get("finding_id") or "Finding"),
        "severity": sev,
    }
    # Optional, only-if-present so we never emit nulls the generator would render blank.
    for k_src, k_dst in (("cvss_score", "cvss_score"), ("cvss_vector", "cvss_vector"),
                         ("cwe", "cwe"), ("owasp", "owasp")):
        if v.get(k_src) is not None:
            out[k_dst] = v[k_src]
    for k in ("affected", "description", "impact", "recommendation",
              "calibration", "ease_of_exploitation", "references"):
        if rf.get(k) is not None:
            out[k] = rf[k]
    if v.get("cves"):
        out["cves"] = v["cves"]
    # Reproducible PoC — an ordered list of {description, command, image_url} steps
    # (merges the former evidence / poc_request / screenshot fields). The validated
    # recipe from the verdict is the canonical one rendered by the PDF generator.
    poc = normalize_poc(v.get("poc"))
    if poc:
        out["poc"] = poc
    return out


def build_cve_register(findings):
    """One row per distinct CVE; headline score = max computed score seen."""
    reg = {}
    for f in findings:
        for cve in f.get("cves") or []:
            cid = cve.get("id")
            if not cid:
                continue
            score = cve.get("score")
            cur = reg.get(cid)
            if cur is None or (score is not None and (cur.get("score") is None or score > cur["score"])):
                reg[cid] = {
                    "cve": cid,
                    "component": cve.get("component") or f.get("title", ""),
                    "score": score,
                    "severity": cve.get("severity") or severity_band(score),
                    "summary": cve.get("summary", ""),
                }
    return [reg[k] for k in sorted(reg)]


def build_attack_coverage(eng_dir):
    """Derive the Attack Pattern Coverage section from the deterministic gate output
    (reports/coverage-matrix.json, written by tools/coverage_gate.py). Returns a
    {header,rows,widths,note} table, or None if the gate has not run. Mirrors the
    derived cve_register — no LLM authoring, one input file."""
    path = os.path.join(eng_dir, "reports", "coverage-matrix.json")
    if not os.path.isfile(path):
        return None
    try:
        m = load_json(path)
    except json.JSONDecodeError:
        return None
    per_class = m.get("per_class") or {}
    if not per_class:
        return None
    tax_order = {"API-2023": 0, "Web-2021": 1, "Cross-cut": 2, "MASVS-2023": 3}
    items = sorted(per_class.items(),
                   key=lambda kv: (tax_order.get((kv[1] or {}).get("taxonomy"), 9), kv[0]))
    rows = [[cid, pc.get("taxonomy", ""), (pc.get("title") or "")[:52],
             f"{pc.get('passed', 0)}/{pc.get('applicable', 0)}", pc.get("status", "")]
            for cid, pc in items]
    ratio = m.get("coverage_ratio", 0) or 0
    untested = len(m.get("missing_cells") or [])
    note = (f"Deterministic (surface-unit × attack-class) coverage: {ratio:.0%} of applicable cells "
            f"covered — {untested} cell(s) untested. Every applicable cell is enumerated by code from the "
            f"discovered surface and requires cross-checked on-disk evidence; the engagement cannot be marked "
            f"COMPLETE while any applicable cell is untested.")
    deferred = m.get("deferred", 0) or len(m.get("deferred_cells") or [])
    if deferred:
        note += (f" {deferred} cell(s) are deferred pending client input (MFA/OTP session or test account); "
                 f"each is traceable to a filed client-input request and is disclosed here rather than "
                 f"silently omitted.")
    return {
        "header": ["Attack class", "Taxonomy", "Description", "Cells", "Status"],
        "rows": rows,
        "widths": [0.20, 0.12, 0.40, 0.12, 0.16],
        "note": note,
    }


def sort_findings(findings):
    # Critical -> Info, then risk_score desc (carried aside), then id — fully stable.
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9),
                                           -(f.pop("_risk", 0) or 0), str(f.get("id"))))


# --- activity-log folding (tool-usage + source-IP appendices) ----------------
# Deterministic capture writes two append-only JSONL logs under the engagement
# root; here they are folded into CLOCKLESS appendix rows (raw timestamps stay
# only in the JSONL, which ships in the deliverable's logs/). No-op when absent.

TOOL_PURPOSE = {
    "nmap": "Port & service enumeration", "masscan": "Fast port sweep",
    "nuclei": "Templated vulnerability scanning", "ffuf": "Content/parameter fuzzing",
    "gobuster": "Content/DNS brute enumeration", "feroxbuster": "Recursive content discovery",
    "sqlmap": "SQL injection testing", "nikto": "Web server misconfig scanning",
    "curl": "Manual HTTP probing", "wget": "HTTP retrieval",
    "httpx": "HTTP probing & fingerprinting", "subfinder": "Passive subdomain enumeration",
    "amass": "Attack-surface / subdomain mapping", "dnsx": "DNS resolution & probing",
    "dig": "DNS lookups", "sslscan": "TLS posture assessment", "sslyze": "TLS posture assessment",
    "openssl": "TLS/crypto inspection", "whatweb": "Web technology fingerprinting",
    "wpscan": "WordPress assessment", "hydra": "Authenticated service testing",
    "smbclient": "SMB share access", "crackmapexec": "AD/SMB assessment",
    "netexec": "AD/SMB assessment", "certipy": "AD CS assessment",
    "bloodhound": "AD attack-path mapping", "gcloud": "Cloud vantage provisioning",
    "aws": "Cloud vantage provisioning", "az": "Cloud vantage provisioning",
    "ssh": "Remote access / pivot", "proxychains": "Proxied egress",
}

# Harness / report / self plumbing — never attack tooling; kept out of the appendix
# so "Tools & Techniques Used" stays security-relevant (formats/logs.md:71).
TOOL_DENYLIST = {
    "report_data_build.py", "generate_report.py", "kev-lookup.py", "nvd-lookup.py",
    "env-reader.py", "slack-send.py", "register_source_ip.py", "provision_vantage.sh",
    "activity-logger.py", "stats-updater.py", "session-start.py", "block-coordinator-ask.py",
    "risk-prioritise.py", "chain-merger.py", "ti-ingest.py",
    "zip", "unzip", "shasum", "sha256sum", "getconf", "jq", "date", "git",
}

EGRESS_PATTERNS = [
    "gcloud compute instances create", "ec2 run-instances", "vm create",
    "ssh -d", "sshuttle", "proxychains", "openvpn", "wg-quick up", "wg set", "sslocal",
]
NONPRIMARY_ROLES = {"attack-vm", "proxy", "vpn", "socks"}


def read_jsonl_lines(path):
    """Parse a JSONL file, skipping malformed lines. Returns (rows, skipped_count).
    Never raises on a bad line — append-only logs under a parallel fan-out may end
    in a partial trailing line."""
    rows, skipped = [], 0
    if not os.path.isfile(path):
        return rows, skipped
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    skipped += 1
    except OSError:
        pass
    return rows, skipped


def _merge_tools_used(meta_rows, counts):
    """Merge meta-authored [tool,purpose,mode] rows with log bin counts (count is
    authoritative for the third column). Sorted by tool name → stable sha."""
    out = {}
    for r in (meta_rows or []):
        if isinstance(r, list) and r:
            name = str(r[0])
            out[name] = [name, r[1] if len(r) > 1 else TOOL_PURPOSE.get(name, ""),
                         r[2] if len(r) > 2 else ""]
    for name, count in counts.items():
        if name in out:
            out[name][2] = f"invoked {count}×"
        else:
            out[name] = [name, TOOL_PURPOSE.get(name, ""), f"invoked {count}×"]
    return [out[k] for k in sorted(out)]


def _merge_source_ips(meta_rows, log_rows):
    """Rows are [ip, role, provider/region]. Dedup by (ip,role), sort by (ip,role)."""
    out = {}
    for r in (meta_rows or []):
        if isinstance(r, list) and len(r) >= 2:
            out.setdefault((str(r[0]), str(r[1])),
                           [str(r[0]), str(r[1]), str(r[2]) if len(r) > 2 else ""])
    for ip, role, pr in log_rows:
        out.setdefault((ip, role), [ip, role, pr])
    return [out[k] for k in sorted(out)]


def fold_activity_logs(eng_dir, report):
    """Fold logs/activity/{tool-invocations,source-ips}.jsonl into clockless
    tools_used + source_ips appendix rows (mutates report). Returns the counts +
    reconciliation gaps for the printed summary."""
    act = os.path.join(eng_dir, "logs", "activity")
    inv_rows, _s1 = read_jsonl_lines(os.path.join(act, "tool-invocations.jsonl"))
    sip_rows, _s2 = read_jsonl_lines(os.path.join(act, "source-ips.jsonl"))

    counts, egress_hits = {}, set()
    for r in inv_rows:
        cmd = (r.get("full_command") or "").lower()
        for pat in EGRESS_PATTERNS:
            if pat in cmd:
                egress_hits.add(pat)
        for b in (r.get("bins") or []):
            if b and b not in TOOL_DENYLIST:
                counts[b] = counts.get(b, 0) + 1
    if counts:  # else leave any meta-authored tools_used passthrough verbatim
        report["tools_used"] = _merge_tools_used(report.get("tools_used"), counts)

    ip_rows = []
    for r in sip_rows:
        ip = r.get("ip")
        if not ip:
            continue
        pr = "/".join([x for x in (r.get("provider") or "", r.get("region") or "") if x])
        ip_rows.append((str(ip), str(r.get("role") or ""), pr))
    if ip_rows:  # else leave any meta-authored source_ips passthrough verbatim
        report["source_ips"] = _merge_source_ips(report.get("source_ips"), ip_rows)

    gaps = []
    roles = {row[1] for row in report.get("source_ips", [])}
    if egress_hits and not (roles & NONPRIMARY_ROLES):
        gaps = [f"egress command '{pat}' ran with no registered attack-vm/proxy/vpn source IP"
                for pat in sorted(egress_hits)]
        note = "⚠ Egress-reconciliation gaps: " + "; ".join(gaps) + "."
        intro = report.get("source_ips_intro")
        report["source_ips_intro"] = (intro + "\n" + note) if intro else note

    return {
        "tools_used_count": len(report.get("tools_used") or []),
        "source_ips_count": len(report.get("source_ips") or []),
        "reconciliation_gaps": gaps,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engagement-dir", required=True)
    ap.add_argument("--meta")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()

    eng_dir = os.path.abspath(args.engagement_dir)
    if not os.path.isdir(eng_dir):
        print(f"ERROR: not a directory: {eng_dir}", file=sys.stderr)
        return 1
    meta_path = args.meta or os.path.join(eng_dir, "engagement-meta.json")
    out_path = args.out or os.path.join(eng_dir, "reports", "report_data.json")

    meta = {}
    if os.path.isfile(meta_path):
        try:
            meta = load_json(meta_path)
        except json.JSONDecodeError as e:
            print(f"ERROR: {meta_path} invalid JSON: {e}", file=sys.stderr)
            return 2

    # Deterministic file order: sorted recursive glob. Both WEB (<asset>/artifacts/
    # validated) and NETWORK (hosts/<ip>/artifacts/validated) layouts are covered.
    paths = sorted(glob.glob(os.path.join(eng_dir, "**", "artifacts", "validated", "*.json"), recursive=True))
    validated, hard_dropped, skipped = [], [], []
    for p in paths:
        rel = os.path.relpath(p, eng_dir)
        try:
            v = load_json(p)
        except json.JSONDecodeError:
            skipped.append(rel)
            continue
        verdict = v.get("verdict")
        # Drop-entirely: only VALID/REPAIRED reach findings[]. Everything else
        # (DEMOTED, unknown, null) is hard-dropped — never in the report, logged to
        # stderr and surfaced in the summary, but NOT in the payload (idempotency).
        if verdict in ("VALID", "REPAIRED"):
            f = finding_from_verdict(v)
            f["_risk"] = (v.get("risk") or {}).get("risk_score", 0)
            validated.append(f)
        else:
            fid = v.get("finding_id") or v.get("id")
            hard_dropped.append({"path": rel, "finding_id": fid, "verdict": verdict})
            print(f"HARD-DROP: {rel} finding_id={fid} verdict={verdict!r} "
                  f"(not VALID/REPAIRED — excluded from report)", file=sys.stderr)

    validated = sort_findings(validated)

    report = {
        "engagement": meta.get("engagement", {}),
        "findings": validated,
    }
    # Passthrough optional sections from meta if present.
    for k in ("executive_summary", "metrics", "sections", "coverage_table",
              "ruled_out", "tools_used", "tools_intro", "source_ips", "source_ips_intro",
              "roadmap", "conclusion", "disclaimer"):
        if meta.get(k) is not None:
            report[k] = meta[k]

    # Fold the deterministic activity logs into clockless appendix rows (no-op if absent).
    activity = fold_activity_logs(eng_dir, report)

    cve_register = build_cve_register(validated)
    if cve_register:
        report["cve_register"] = cve_register

    attack_coverage = build_attack_coverage(eng_dir)
    if attack_coverage:
        report["attack_pattern_coverage"] = attack_coverage

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    payload = json.dumps(report, indent=2, sort_keys=True)
    with open(out_path, "w") as f:
        f.write(payload)
    sha = hashlib.sha256(payload.encode()).hexdigest()

    sev_counts = {}
    for f in validated:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    print(json.dumps({
        "out": out_path,
        "sha256": sha,
        "bytes": len(payload),
        "findings": len(validated),
        "cve_register": len(cve_register),
        "severity_counts": sev_counts,
        "skipped_malformed": skipped,
        "hard_dropped": hard_dropped,
        "finding_ids": [f["id"] for f in validated],
        "tools_used_count": activity["tools_used_count"],
        "source_ips_count": activity["source_ips_count"],
        "reconciliation_gaps": activity["reconciliation_gaps"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
