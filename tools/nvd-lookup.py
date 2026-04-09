#!/usr/bin/env python3
"""
NVD CVE Risk Score Lookup

Queries the NVD API v2.0 for a CVE ID and prints a structured summary
including CVSS scores, severity, CWE, and description.

Usage:
    python3 tools/nvd-lookup.py CVE-2024-12345 [CVE-2023-99999 ...]

No API key required (rate-limited to ~5 req/30s without key).
Set NVD_API_KEY env var for higher rate limits.
"""

import html as html_module
import json
import re
import sys
import time
import urllib.request
import urllib.error
import urllib.parse

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_WEB_URL = "https://nvd.nist.gov/vuln/detail"


def fetch_cve_api(cve_id: str, api_key: str | None = None) -> dict:
    """Fetch CVE data from NVD API v2.0."""
    url = f"{NVD_API_URL}?cveId={urllib.parse.quote(cve_id)}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "communitytools-nvd-lookup/1.0")
    if api_key:
        req.add_header("apiKey", api_key)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"API HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"error": f"API connection failed: {e.reason}"}
    except Exception as e:
        return {"error": f"API error: {e}"}


def _parse_nvd_html(html: str) -> dict:
    """Extract CVE data from NVD website HTML using regex patterns."""
    result = {
        "description": "",
        "cvss3_score": None,
        "cvss3_severity": None,
        "cvss3_vector": None,
        "cvss2_score": None,
        "cwes": [],
        "published": "",
        "modified": "",
    }

    # Description
    m = re.search(r'data-testid="vuln-description"[^>]*>([^<]+)', html)
    if m:
        result["description"] = html_module.unescape(m.group(1).strip())

    # CVSS v3 score — matches both nist and cna panel-score elements
    m = re.search(r'data-testid="vuln-cvss3-\w+-panel-score"[^>]*>([^<]+)', html)
    if m:
        text = m.group(1).strip()
        score_match = re.search(r"(\d+\.?\d*)", text)
        if score_match:
            result["cvss3_score"] = float(score_match.group(1))
            upper = text.upper()
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev in upper:
                    result["cvss3_severity"] = sev
                    break

    # CVSS v3 vector from calculator link
    m = re.search(r'v3-calculator\?[^"]*vector=([^&"]+)', html)
    if m:
        vector = urllib.parse.unquote(m.group(1))
        result["cvss3_vector"] = f"CVSS:3.1/{vector}" if not vector.startswith("CVSS:") else vector

    # CVSS v4 score
    m = re.search(r'data-testid="vuln-cvss4-\w+-panel-score"[^>]*>([^<]+)', html)
    if m:
        score_match = re.search(r"(\d+\.?\d*)", m.group(1).strip())
        if score_match:
            result["cvss4_score"] = float(score_match.group(1))

    # CVSS v2 score
    m = re.search(r'data-testid="vuln-cvss2-\w+-panel-score"[^>]*>([^<]+)', html)
    if m:
        score_match = re.search(r"(\d+\.?\d*)", m.group(1).strip())
        if score_match:
            result["cvss2_score"] = float(score_match.group(1))

    # CWEs
    for m in re.finditer(r'data-testid="vuln-CWEs-link-\d+"[^>]*>([^<]+)', html):
        val = m.group(1).strip()
        if val.startswith("CWE-"):
            result["cwes"].append(val)

    # Published / Modified dates
    m = re.search(r'data-testid="vuln-published-on"[^>]*>([^<]+)', html)
    if m:
        result["published"] = m.group(1).strip()
    m = re.search(r'data-testid="vuln-last-modified-on"[^>]*>([^<]+)', html)
    if m:
        result["modified"] = m.group(1).strip()

    return result


def fetch_cve_web(cve_id: str) -> dict:
    """Fallback: scrape the NVD website for CVE data."""
    url = f"{NVD_WEB_URL}/{urllib.parse.quote(cve_id)}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0 (compatible; communitytools-nvd-lookup/1.0)")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return {"error": f"Website HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"error": f"Website connection failed: {e.reason}"}
    except Exception as e:
        return {"error": f"Website error: {e}"}

    parsed = _parse_nvd_html(html)

    severity = parsed["cvss3_severity"]
    if severity is None and parsed["cvss3_score"] is not None:
        severity = severity_label(parsed["cvss3_score"])

    metrics = {}
    if parsed["cvss3_score"] is not None:
        metrics["cvssMetricV31"] = [{
            "type": "Primary",
            "cvssData": {
                "baseScore": parsed["cvss3_score"],
                "baseSeverity": severity or "UNKNOWN",
                "vectorString": parsed["cvss3_vector"] or "N/A",
            },
            "exploitabilityScore": None,
            "impactScore": None,
        }]
    if parsed.get("cvss4_score") is not None:
        metrics["cvssMetricV40"] = [{
            "cvssData": {
                "baseScore": parsed["cvss4_score"],
                "baseSeverity": severity_label(parsed["cvss4_score"]),
                "vectorString": "N/A",
            },
        }]
    if parsed["cvss2_score"] is not None:
        metrics["cvssMetricV2"] = [{
            "type": "Primary",
            "cvssData": {
                "baseScore": parsed["cvss2_score"],
                "baseSeverity": severity_label(parsed["cvss2_score"]),
                "vectorString": "N/A",
            },
            "exploitabilityScore": None,
            "impactScore": None,
        }]

    weaknesses = []
    if parsed["cwes"]:
        weaknesses = [{"descriptions": [{"lang": "en", "value": c} for c in parsed["cwes"]]}]

    return {
        "_source": "website",
        "vulnerabilities": [{
            "cve": {
                "id": cve_id,
                "vulnStatus": "N/A (scraped from website)",
                "published": parsed["published"] or "N/A",
                "lastModified": parsed["modified"] or "N/A",
                "descriptions": [{"lang": "en", "value": parsed["description"] or "No description available."}],
                "metrics": metrics,
                "weaknesses": weaknesses,
            }
        }]
    }


def fetch_cve(cve_id: str, api_key: str | None = None) -> dict:
    """Fetch CVE data from NVD API, falling back to website scraping."""
    data = fetch_cve_api(cve_id, api_key)

    if "error" not in data and data.get("vulnerabilities"):
        return data

    api_error = data.get("error", "unknown API error")
    print(f"NOTE: API failed ({api_error}), falling back to NVD website...", file=sys.stderr)

    web_data = fetch_cve_web(cve_id)
    if "error" in web_data:
        return {"error": f"{api_error}; website fallback also failed: {web_data['error']}"}

    return web_data


def extract_cvss(metrics: dict) -> dict:
    """Extract the best available CVSS score from NVD metrics."""
    result = {}

    # Prefer CVSS v3.1, then v3.0, then v2.0
    for version_key, label in [
        ("cvssMetricV31", "CVSS v3.1"),
        ("cvssMetricV30", "CVSS v3.0"),
        ("cvssMetricV2", "CVSS v2.0"),
    ]:
        entries = metrics.get(version_key, [])
        if not entries:
            continue
        # Prefer primary (NVD) source
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss = entry.get("cvssData", {})
        result[label] = {
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity", entry.get("baseSeverity", "UNKNOWN")),
            "vector": cvss.get("vectorString"),
            "exploitability_score": entry.get("exploitabilityScore"),
            "impact_score": entry.get("impactScore"),
        }

    # Also check CVSS v4.0
    for entry in metrics.get("cvssMetricV40", []):
        cvss = entry.get("cvssData", {})
        result["CVSS v4.0"] = {
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity", "UNKNOWN"),
            "vector": cvss.get("vectorString"),
        }

    return result


def extract_cwes(weaknesses: list) -> list[str]:
    """Extract CWE IDs from weakness data."""
    cwes = []
    for w in weaknesses:
        for desc in w.get("descriptions", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") or val == "NVD-CWE-noinfo":
                cwes.append(val)
    return list(dict.fromkeys(cwes))  # dedupe, preserve order


def severity_label(score: float | None) -> str:
    """Map CVSS score to severity label."""
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def format_cve(data: dict) -> str:
    """Format NVD response into readable output."""
    if "error" in data:
        return f"ERROR: {data['error']}"

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return "CVE not found in NVD."

    cve = vulns[0].get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")
    published = cve.get("published", "N/A")
    modified = cve.get("lastModified", "N/A")
    status = cve.get("vulnStatus", "N/A")

    # Description (English preferred)
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description available.")

    # CVSS scores
    metrics = cve.get("metrics", {})
    cvss_data = extract_cvss(metrics)

    # CWEs
    cwes = extract_cwes(cve.get("weaknesses", []))

    source = "NVD Website" if data.get("_source") == "website" else "NVD API"

    # Build output
    lines = [
        f"{'=' * 70}",
        f"CVE ID:      {cve_id}",
        f"Source:      {source}",
        f"Status:      {status}",
        f"Published:   {published[:10]}",
        f"Modified:    {modified[:10]}",
        f"{'=' * 70}",
    ]

    if cvss_data:
        lines.append("")
        lines.append("RISK SCORES:")
        for label, info in cvss_data.items():
            score = info.get("score")
            sev = info.get("severity", severity_label(score))
            vector = info.get("vector", "N/A")
            lines.append(f"  {label}: {score} ({sev})")
            lines.append(f"    Vector: {vector}")
            if info.get("exploitability_score") is not None:
                lines.append(f"    Exploitability: {info['exploitability_score']}")
            if info.get("impact_score") is not None:
                lines.append(f"    Impact: {info['impact_score']}")
    else:
        lines.append("")
        lines.append("RISK SCORES: Not yet scored by NVD")

    if cwes:
        lines.append("")
        lines.append(f"CWE(s):      {', '.join(cwes)}")

    lines.append("")
    lines.append(f"DESCRIPTION: {desc}")
    lines.append(f"{'=' * 70}")

    # JSON summary for programmatic use
    best_score = None
    best_severity = "UNKNOWN"
    for info in cvss_data.values():
        s = info.get("score")
        if s is not None and (best_score is None or s > best_score):
            best_score = s
            best_severity = info.get("severity", severity_label(s))

    summary = {
        "cve_id": cve_id,
        "score": best_score,
        "severity": best_severity,
        "cwes": cwes,
        "status": status,
    }
    lines.append("")
    lines.append(f"JSON_SUMMARY: {json.dumps(summary)}")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 tools/nvd-lookup.py CVE-XXXX-XXXXX [...]")
        sys.exit(1)

    # Check for API key
    api_key = None
    try:
        from pathlib import Path
        env_file = Path(__file__).resolve().parent.parent / ".env"
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line.startswith("NVD_API_KEY=") and not line.startswith("#"):
                    api_key = line.split("=", 1)[1].strip()
                    break
    except Exception:
        pass

    cve_ids = sys.argv[1:]
    for i, cve_id in enumerate(cve_ids):
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith("CVE-"):
            print(f"WARNING: '{cve_id}' doesn't look like a CVE ID, skipping.")
            continue

        data = fetch_cve(cve_id, api_key)
        print(format_cve(data))

        # Rate limiting: NVD allows ~5 requests per 30s without API key
        if i < len(cve_ids) - 1:
            time.sleep(6 if not api_key else 0.6)


if __name__ == "__main__":
    main()
