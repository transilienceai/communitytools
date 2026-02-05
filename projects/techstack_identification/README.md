# Tech Stack Identification Agent

OSINT-based technology stack discovery using passive reconnaissance across 17 intelligence domains.

## Overview

This agent discovers an organization's technology stack using only publicly available information and passive external reconnaissance techniques. Given a company name (and optional domain hint), it infers technologies through a 5-phase pipeline orchestrated by specialized agents.

| | |
|---|---|
| **Project Type** | Security Reconnaissance |
| **Version** | 1.0.0 |
| **Intelligence Domains** | 17 |
| **Approach** | Passive OSINT only |

## 5-Phase Pipeline

The agent executes a sequential pipeline where each phase builds on the previous phase's output:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Phase 1: Asset Discovery                                           │
│  Map company's public internet footprint                            │
│  Output: Asset Inventory JSON                                       │
└─────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────┐
│  Phase 2: Data Collection                                           │
│  Gather technical signals from discovered assets                    │
│  Output: Raw Signals JSON                                           │
└─────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────┐
│  Phase 3: Tech Inference                                            │
│  Infer technologies across all stack layers                         │
│  Output: Inferred Technologies JSON                                 │
└─────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────┐
│  Phase 4: Correlation                                               │
│  Cross-validate signals and calculate confidence                    │
│  Output: Correlated Technologies JSON                               │
└─────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────┐
│  Phase 5: Report Generation                                         │
│  Generate final structured report with evidence                     │
│  Output: TechStackReport (JSON/MD/HTML)                             │
└─────────────────────────────────────────────────────────────────────┘
```

## Agents & Skills

### Phase 1: Asset Discovery Agent

Maps the company's public internet footprint through passive reconnaissance.

| Skill | Description | Execution |
|-------|-------------|-----------|
| `domain_discovery` | Find official domain via web search, WHOIS, TLD patterns | Parallel |
| `subdomain_enumeration` | Query CT logs, passive DNS, search dorks | Parallel |
| `certificate_transparency` | Extract SANs from crt.sh, discover naming conventions | Parallel |
| `ip_attribution` | Map IPs to cloud providers, ASNs, organizations | Parallel |
| `api_portal_discovery` | Find developer portals, OpenAPI/Swagger endpoints | Parallel |

**Output**: Asset Inventory (domains, subdomains, IPs, certificates, API portals)

---

### Phase 2: Data Collection Agent

Gathers technical signals from all discovered assets through passive data collection.

| Skill | Description | Execution |
|-------|-------------|-----------|
| `http_fingerprinting` | Collect headers, cookies, error pages, status codes | Parallel |
| `dns_intelligence` | Query MX, TXT, NS, CNAME, SRV records | Parallel |
| `tls_certificate_analysis` | Extract certificate metadata, JARM fingerprints | Parallel |
| `javascript_dom_analysis` | Detect framework globals, bundle patterns | Parallel |
| `html_content_analysis` | Parse meta tags, comments, script URLs | Parallel |
| `code_repository_intel` | Scan GitHub/GitLab for public repos, dependencies | Parallel |
| `job_posting_analysis` | Extract tech requirements from career pages | Parallel |
| `web_archive_analysis` | Query Wayback Machine for historical snapshots | Parallel |

**Output**: Raw Signals (HTTP, DNS, TLS, JavaScript, HTML, repository, job, archive signals)

---

### Phase 3: Tech Inference Agent

Infers technologies across all stack layers by analyzing collected signals.

| Skill | Description | Execution |
|-------|-------------|-----------|
| `frontend_inferencer` | Detect React, Angular, Vue, jQuery, Bootstrap, etc. | Parallel |
| `backend_inferencer` | Detect servers, languages, frameworks, databases, CMS | Parallel |
| `cloud_infra_detector` | Detect AWS, Azure, GCP, PaaS platforms | Parallel |
| `cdn_waf_fingerprinter` | Detect Cloudflare, Akamai, Fastly, CloudFront | Parallel |
| `security_posture_analyzer` | Analyze CSP, HSTS, WAF presence, security.txt | Parallel |
| `devops_detector` | Detect CI/CD tools, Docker, Kubernetes signals | Parallel |
| `third_party_detector` | Detect payments, analytics, auth, CRM services | Parallel |

**Output**: Inferred Technologies (categorized by frontend, backend, infrastructure, security, devops, third-party)

---

### Phase 4: Correlation Agent

Cross-validates signals and calculates confidence levels for each detected technology.

| Skill | Description | Execution |
|-------|-------------|-----------|
| `signal_correlator` | Group signals by technology, identify overlaps, flag conflicts | Sequential |
| `confidence_scorer` | Calculate base scores, apply diversity bonuses, assign levels | Sequential |
| `conflict_resolver` | Analyze conflicts, apply resolution strategies, document reasoning | Sequential |

**Output**: Correlated Technologies with confidence scores (High/Medium/Low)

---

### Phase 5: Report Generation Agent

Generates the final structured TechStackReport with evidence and citations.

| Skill | Description | Execution |
|-------|-------------|-----------|
| `json_report_generator` | Generate structured TechStackReport JSON | Sequential |
| `evidence_formatter` | Format evidence with proper citations | Sequential |
| `report_exporter` | Export to JSON, Markdown, HTML formats | Sequential |

**Output**: Final report in `outputs/techstack_reports/`

---

## Skills Summary

| Phase | Agent | Skills | Execution Mode |
|-------|-------|--------|----------------|
| 1 | asset_discovery_agent | 5 | Parallel |
| 2 | data_collection_agent | 8 | Parallel |
| 3 | tech_inference_agent | 7 | Parallel |
| 4 | correlation_agent | 3 | Sequential |
| 5 | report_generation_agent | 3 | Sequential |
| **Total** | **5 agents** | **26 skills** | |

## Execution Configuration

From `agents/config.json`:

- **Phases execute sequentially** (Phase N+1 waits for Phase N to complete)
- **Skills within phases 1-3 execute in parallel**
- **Skills within phases 4-5 execute sequentially**
- **Failures don't halt the pipeline** - partial results are returned
- **Max retries**: 3 per skill

## Confidence Levels

| Level | Score | Criteria |
|-------|-------|----------|
| **High** | 80-100% | 3+ independent signals, no conflicts, explicit identifiers |
| **Medium** | 50-79% | 2 signals or 1 strong signal, minimal conflicts |
| **Low** | 20-49% | Single weak signal, conflicting evidence |

## Output Structure

```
outputs/techstack_reports/<company>_<timestamp>/
├── report.json           # Structured TechStackReport
├── report.md             # Markdown summary
├── report.html           # Styled HTML report
├── evidence/             # Raw evidence files
└── logs/
    └── execution.log
```

## Project Structure

```
techstack_identification/
├── .claude/
│   ├── agents/           # 5 agent definitions
│   │   ├── asset_discovery_agent.md
│   │   ├── data_collection_agent.md
│   │   ├── tech_inference_agent.md
│   │   ├── correlation_agent.md
│   │   ├── report_generation_agent.md
│   │   └── config.json
│   ├── hooks/            # Pre/post execution hooks
│   │   └── skills/
│   ├── rules/            # Operational rules
│   │   └── general_rules.md
│   ├── skills/           # 26 skill implementations
│   ├── CLAUDE.md         # Agent instructions
│   ├── project.json      # Project configuration
│   └── settings.json     # Runtime settings
├── outputs/              # Generated reports
└── README.md
```

## Core Principles

### Passive Reconnaissance Only
- No internal access or authenticated scanning
- No exploitation or aggressive techniques
- No intrusive vulnerability scans
- All findings are probabilistic hypotheses
- Every inference includes evidence and confidence level

### Ethical Boundaries
- Obtain authorization before analyzing any organization
- Respect robots.txt directives
- Honor rate limits for all external services
- Maintain audit logs for all activities
- Comply with applicable laws

## Rate Limits

| Service | Limit |
|---------|-------|
| crt.sh | 10 requests/minute |
| GitHub API | 60 requests/hour |
| General HTTP | 30 requests/minute |
| DNS queries | 30 requests/minute |

## Timeouts

| Operation | Timeout |
|-----------|---------|
| HTTP request | 30 seconds |
| DNS query | 10 seconds |
| Browser automation | 60 seconds |
| Overall analysis | 600 seconds |

---

**Note**: This tool produces best-effort hypotheses, not definitive facts. All findings should be validated when critical decisions depend on accuracy.
