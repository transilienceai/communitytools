---
name: techstack-identification
description: OSINT-based technology stack identification. Discovers company tech stacks using passive reconnaissance across 17 intelligence domains. Given a company name (and optional domain hint), infers frontend, backend, infrastructure, and security technologies using publicly available signals.
---

# Tech Stack Identification

Passive OSINT reconnaissance to identify a target's technology stack. No credentials, no active scanning — only publicly available signals.

## Quick Start

```
1. Provide company name (+ optional domain hint)
2. 5 coordinating agents run 26 sub-skills across 17 intelligence domains
3. Signals correlated, confidence scored, conflicts resolved
4. Final report: JSON + Markdown with evidence for every inference
```

## Coordination (5 Agents → 26 Sub-Skills)

**Phase 1: Asset Discovery** (`asset_discovery_agent`)
- domain_discovery, subdomain_enumeration, certificate_transparency, ip_attribution, api_portal_discovery

**Phase 2: Data Collection** (`data_collection_agent`)
- http_fingerprinting, dns_intelligence, tls_certificate_analysis, javascript_dom_analysis, html_content_analysis, code_repository_intel, job_posting_analysis, web_archive_analysis

**Phase 3: Tech Inference** (`tech_inference_agent`)
- frontend_inferencer, backend_inferencer, cloud_infra_detector, cdn_waf_fingerprinter, security_posture_analyzer, devops_detector, third_party_detector

**Phase 4: Correlation** (`correlation_agent`)
- signal_correlator, confidence_scorer, conflict_resolver

**Phase 5: Report** (`report_generation_agent`)
- See `formats/techstack-json-report.md`, `formats/techstack-evidence-formatter.md`, `formats/techstack-report-exporter.md`

Phases run sequentially. Sub-skills within each phase run in parallel.

## Confidence Levels

- **High**: Multiple independent sources + explicit identifier (headers, meta tags, cookies)
- **Medium**: Single strong source OR indirect signals (URL patterns, error messages, job postings)
- **Low**: Speculative from indirect signals, conflicting data, or outdated evidence

## Output: TechStackReport

```json
{
  "report_id": "uuid",
  "company": "string",
  "primary_domain": "string",
  "discovered_assets": { "domains", "subdomains", "ip_addresses", "certificates", "api_portals" },
  "technologies": {
    "frontend": [{ "name", "version?", "confidence": "High|Medium|Low", "evidence": [...] }],
    "backend": [...],
    "infrastructure": [...],
    "security": [...],
    "devops": [...],
    "third_party": [...]
  },
  "confidence_summary": { "high_confidence", "medium_confidence", "low_confidence", "overall_score" }
}
```

## Rate Limits

| Service | Limit |
|---------|-------|
| crt.sh | 10 req/min |
| GitHub API (unauth) | 60 req/hr |
| General HTTP | 30 req/min |
| DNS queries | 30 req/min |

## Integration

Called by pentest coordinator as a recon step, by CVE testing to map technologies to CVEs, or standalone for due diligence and competitive analysis.
