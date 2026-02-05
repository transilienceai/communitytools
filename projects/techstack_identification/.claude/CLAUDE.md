# Tech Stack Identification Agent

## Project Overview

This project implements an **OSINT-based Technology Stack Identification Agent** that discovers company tech stacks using passive reconnaissance across **17 intelligence domains**. Given only a company name (and optional domain hint), the agent infers the company's technology stack using open-source intelligence and passive external reconnaissance techniques.

**Project Type**: Security Reconnaissance
**Version**: 1.0.0
**Intelligence Domains**: 17
**Approach**: Passive OSINT only - no internal access or credentials required

## Core Principles

### Passive Reconnaissance Only
- **NO internal access or authenticated scanning**
- **NO exploitation or aggressive techniques**
- **NO intrusive vulnerability scans**
- All findings are **probabilistic hypotheses**, not certainties
- Every technology inference includes **evidence and confidence level**

### Allowed Techniques
- Passive OSINT (DNS records, certificates, public websites)
- Public data analysis (HTTP headers, HTML content, job postings)
- Non-intrusive enumeration (public APIs, databases)
- JavaScript and DOM analysis
- Certificate transparency log queries

## Architecture

### 17 Intelligence Domains

**Phase 1: Asset Discovery (5 domains)**
1. **Domain Discovery** - Official domain identification via web search, WHOIS, TLD patterns
2. **Subdomain Enumeration** - CT logs, passive DNS, search dorks
3. **Certificate Transparency** - crt.sh queries, SAN extraction
4. **IP Attribution** - Cloud provider mapping, ASN lookups, WHOIS
5. **API Portal Discovery** - Developer docs, OpenAPI/Swagger endpoints

**Phase 2: Data Collection (8 domains)**
6. **HTTP Fingerprinting** - Headers, cookies, error pages, status codes
7. **DNS Intelligence** - MX, TXT, NS, CNAME, SRV records
8. **TLS Certificate Analysis** - Issuer, SANs, JARM fingerprints
9. **JavaScript/DOM Analysis** - Framework detection via global variables, DOM attributes
10. **HTML Content Analysis** - Meta tags, generator comments, script paths
11. **Code Repository Intel** - GitHub/GitLab scanning for dependencies, CI configs
12. **Job Posting Analysis** - Career page tech requirements extraction
13. **Web Archive Analysis** - Wayback Machine for technology migrations

**Phase 3: Technology Inference (4 domains)**
14. **Frontend Technologies** - React, Angular, Vue, jQuery, Bootstrap, etc.
15. **Backend Technologies** - Servers, languages, frameworks, databases, CMS
16. **Cloud Infrastructure** - AWS, Azure, GCP detection, CDN/WAF identification
17. **Security/DevOps/Third-Party** - Security headers, CI/CD tools, SaaS integrations

### Agent Orchestration

```
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 1: Asset Discovery                  │
│  agent: asset_discovery_agent                                │
├─────────────────────────────────────────────────────────────┤
│  ├─ domain_discovery           (parallel)                    │
│  ├─ subdomain_enumeration      (parallel)                    │
│  ├─ certificate_transparency   (parallel)                    │
│  ├─ ip_attribution             (parallel)                    │
│  └─ api_portal_discovery       (parallel)                    │
│         ↓ Output: Asset Inventory JSON                       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                  PHASE 2: Data Collection                    │
│  agent: data_collection_agent                                │
├─────────────────────────────────────────────────────────────┤
│  ├─ http_fingerprinting        (parallel)                    │
│  ├─ dns_intelligence           (parallel)                    │
│  ├─ tls_certificate_analysis   (parallel)                    │
│  ├─ javascript_dom_analysis    (parallel)                    │
│  ├─ html_content_analysis      (parallel)                    │
│  ├─ code_repository_intel      (parallel)                    │
│  ├─ job_posting_analysis       (parallel)                    │
│  └─ web_archive_analysis       (parallel)                    │
│         ↓ Output: Raw Signals JSON                           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                 PHASE 3: Tech Inference                      │
│  agent: tech_inference_agent                                 │
├─────────────────────────────────────────────────────────────┤
│  ├─ frontend_inferencer         (parallel)                   │
│  ├─ backend_inferencer          (parallel)                   │
│  ├─ cloud_infra_detector        (parallel)                   │
│  ├─ cdn_waf_fingerprinter       (parallel)                   │
│  ├─ security_posture_analyzer   (parallel)                   │
│  ├─ devops_detector             (parallel)                   │
│  └─ third_party_detector        (parallel)                   │
│         ↓ Output: Inferred Technologies JSON                 │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   PHASE 4: Correlation                       │
│  agent: correlation_agent                                    │
├─────────────────────────────────────────────────────────────┤
│  ├─ signal_correlator          (parallel)                    │
│  ├─ confidence_scorer          (parallel)                    │
│  └─ conflict_resolver          (parallel)                    │
│         ↓ Output: Correlated Technologies JSON               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│               PHASE 5: Report Generation                     │
│  agent: report_generation_agent                              │
├─────────────────────────────────────────────────────────────┤
│  ├─ json_report_generator      (sequential)                  │
│  ├─ evidence_formatter         (sequential)                  │
│  └─ report_exporter            (sequential)                  │
│         ↓ Output: Final TechStackReport (JSON/MD/HTML)       │
└─────────────────────────────────────────────────────────────┘
```

## Configuration Files

- **project.json** - Entity definitions, workflow phases, metadata
- **agents/config.json** - Sequential phase strategy, execution config, data passing
- **settings.json** - Model selection, timeouts, rate limits, feature flags

## Output Schema

### TechStackReport Structure

```json
{
  "report_id": "uuid",
  "company": "string",
  "primary_domain": "string",
  "generated_at": "ISO-8601",
  "analysis_depth": "quick|standard|deep",
  "discovered_assets": {
    "domains": ["array of verified domains"],
    "subdomains": ["array of subdomains"],
    "ip_addresses": [{
      "ip": "string",
      "domain": "string",
      "provider": "string",
      "asn": "string",
      "region": "string"
    }],
    "certificates": [{
      "common_name": "string",
      "issuer": "string",
      "sans": ["array"],
      "valid_until": "date"
    }],
    "api_portals": ["array of URLs"]
  },
  "technologies": {
    "frontend": [{
      "name": "string",
      "version": "string (optional)",
      "category": "string",
      "confidence": "High|Medium|Low",
      "evidence": [{
        "source": "skill_name",
        "signal": "description",
        "url": "string (optional)"
      }]
    }],
    "backend": [...],
    "infrastructure": [...],
    "security": [...],
    "devops": [...],
    "third_party": [...]
  },
  "confidence_summary": {
    "high_confidence": "integer",
    "medium_confidence": "integer",
    "low_confidence": "integer",
    "overall_score": "float (0-1)"
  },
  "metadata": {
    "intelligence_domains_queried": 17,
    "total_signals_collected": "integer",
    "execution_time_seconds": "integer"
  }
}
```

## Confidence Levels

### High Confidence
- Multiple independent evidence points align
- Explicit identifiers found (headers, meta tags, cookies)
- Job postings + technical signals corroborate
- Direct API or service detection

### Medium Confidence
- Single strong evidence point
- Indirect signals (URL patterns, error messages)
- Job posting mentions without technical confirmation
- Historical evidence from web archives

### Low Confidence
- Speculation based on generic behavior
- Single weak hint without corroboration
- Conflicting signals requiring resolution
- Outdated information

## Rate Limits & Timeouts

### Rate Limits (from settings.json)
- **crt.sh**: 10 requests/minute
- **GitHub API**: 60 requests/hour (unauthenticated)
- **General HTTP**: 30 requests/minute
- **DNS queries**: 30 requests/minute

### Timeouts (from settings.json)
- **HTTP request**: 30 seconds
- **DNS query**: 10 seconds
- **Browser automation**: 60 seconds
- **Overall analysis**: 600 seconds (10 minutes)

## Security & Ethics

### Authorized Use Cases
- Security due diligence and risk assessment
- Competitive technical analysis
- Red teaming and threat modeling preparation
- Educational security research
- Bug bounty reconnaissance (with authorization)

### Prohibited Activities
- Exploiting discovered vulnerabilities without permission
- Aggressive scanning or DoS attacks
- Bypassing authentication or access controls
- Collecting personally identifiable information (PII)
- Any activity violating computer fraud laws

### Compliance
- Respects robots.txt directives
- Honors rate limits for all external services
- Maintains audit logs for all reconnaissance activities
- Only uses publicly available OSINT sources
- No credential usage or authenticated access

## Error Handling

| Error Scenario | Agent Behavior |
|---------------|----------------|
| Domain not found | Prompt for domain hint |
| Rate limit hit | Automatic retry with exponential backoff (max 3 retries) |
| Partial skill failure | Continue with available data, log failure, mark confidence as reduced |
| Network timeout | Retry skill execution up to 3 times per `agents/config.json` |
| No technologies detected | Review asset discovery results, may indicate heavy obfuscation |
| Conflicting signals | List both possibilities with context, mark as medium/low confidence |

## Integration with Other Agents

This agent is designed to be called by other security agents as a reconnaissance step:

```markdown
### In pentest workflow:
Phase 1: reconnaissance
  ├─ Run techstack identification pipeline
  └─ Use output to tailor penetration testing approach

### In CVE testing workflow:
Step 1: Identify target technologies
  ├─ Run techstack identification pipeline
  └─ Map detected technologies to CVE databases

### In domain assessment workflow:
Asset discovery enhancement
  ├─ Leverage subdomain_enumeration skill
  └─ Feed discovered domains to techstack analysis
```

## Development & Extension

### Creating New Skills
1. Create `SKILL.md` in `.claude/skills/<skill_name>/`
2. Define operations, inputs, outputs, detection patterns
3. Assign skill to appropriate agent
4. Update agent orchestration if needed

### Modifying Agent Logic
1. Edit agent `.md` file in `.claude/agents/`
2. Adjust skill execution order and parallelization
3. Update `agents/config.json` for phase-level changes
4. Test full workflow end-to-end with known targets

## Troubleshooting

### Low Quality Results
- **Check domain discovery** - Ensure correct primary domain identified
- **Review rate limits** - May have hit API limits reducing data collection
- **Verify network access** - Hooks check connectivity before execution

### High False Positive Rate
- **Focus on high-confidence findings** - Filter low-confidence results
- **Cross-validate manually** - Check evidence URLs and sources
- **Report issues** - Help improve detection accuracy

### Performance Issues
- **Check network latency** - Slow responses affect overall timing
- **Review timeout settings** - Adjust in `settings.json` if needed
- **Monitor rate limits** - Excessive throttling impacts performance

## Support & Resources

- **Skill Documentation**: See `.claude/skills/<skill_name>/SKILL.md`
- **Agent Specifications**: See `.claude/agents/<agent_name>.md`
- **Configuration**: See `.claude/*.json`

---

**Remember**: This tool performs **authorized passive reconnaissance only**. Always obtain proper authorization before analyzing any organization's infrastructure. The agent produces **best-effort hypotheses**, not guaranteed facts. All findings should be validated through additional verification when critical decisions depend on accuracy.
