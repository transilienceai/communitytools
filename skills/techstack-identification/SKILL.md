---
name: techstack-identification
description: OSINT-based technology stack identification. Routes to 6 domain sub-skills (frontend, backend, infra, security, osint, correlation) to discover a target's stack from publicly available signals.
---

# Tech Stack Identification

Passive OSINT reconnaissance to identify a target's technology stack. No credentials, no active scanning — only publicly available signals.

## Quick Start

```
1. Provide company name (+ optional domain hint)
2. Run infra first (asset inventory) → frontend / backend / security / osint in parallel
3. Pass all signals into correlation → final report (JSON + Markdown)
```

## Domain Sub-Skills

| Sub-skill | Identifies | Read |
|-----------|-----------|------|
| **frontend** | JS frameworks, meta-frameworks, CSS libraries, build tools, CMS via DOM/HTML/JS | [frontend/SKILL.md](frontend/SKILL.md) |
| **backend** | Web servers, runtimes, languages, frameworks, DB, APIs, CMS | [backend/SKILL.md](backend/SKILL.md) |
| **infra** | Cloud, CDN/WAF, DNS, TLS/CT, DevOps, asset discovery (domains/subdomains/IPs) | [infra/SKILL.md](infra/SKILL.md) |
| **security** | Security headers, CSP, email auth, security.txt, third-party SaaS | [security/SKILL.md](security/SKILL.md) |
| **osint** | Public repos (GitHub/GitLab), job postings/ATS, Wayback Machine | [osint/SKILL.md](osint/SKILL.md) |
| **correlation** | Cross-validation, confidence scoring, conflict resolution | [correlation/SKILL.md](correlation/SKILL.md) |

## Routing by Objective

| Objective | Mount |
|-----------|-------|
| Full stack discovery | infra → (frontend, backend, security, osint) → correlation |
| CDN/WAF identification only | infra |
| API surface mapping | backend |
| Supply-chain / SaaS exposure | security + osint |
| CVE matching by version | backend + frontend (then correlation) |
| Migration / historical context | osint (web archive) + correlation |
| CMS fingerprint | frontend (HTML generators) + backend (CMS paths/cookies) |
| Asset inventory only | infra (domain discovery, subdomain enum, IP attribution, CT) |

## Confidence Levels

- **High**: 3+ independent sources OR explicit identifier (header/meta/global) + supporting evidence + version known
- **Medium**: Single strong source OR multiple indirect signals (URL patterns, cookies, DOM attrs, job postings)
- **Low**: Speculative — single weak signal, conflicting data, or archive-only evidence

Computed in `correlation/`. Target distribution: 50-70% High, 20-35% Medium, <15% Low.

## Final Report Schema

```json
{ "report_id": "uuid", "company": "string", "primary_domain": "string",
  "discovered_assets": {"domains", "subdomains", "ip_addresses", "certificates", "api_portals"},
  "technologies": {
    "frontend": [{"name", "version?", "confidence", "evidence": []}],
    "backend": [...], "infrastructure": [...], "security": [...],
    "devops": [...], "third_party": [...] },
  "confidence_summary": {"high_confidence", "medium_confidence", "low_confidence", "overall_score"} }
```

## Rate Limits

crt.sh 10/min · GitHub (unauth) 60/h · HTTP 30/min/domain · DNS 30/min · Wayback CDX 15/min · WHOIS 5/min.

## Ethics

Passive only. No active scanning, credentialed access, zone transfers, or brute force. Public sources only. Log every external request for audit.
