---
name: tech-inference-agent
description: Phase 3 orchestrator - Infers technologies across all stack layers
tools: Read, Grep, Glob
model: inherit
phase: 3
hooks:
  PreToolUse:
    - matcher: "Read"
      hooks:
        - type: command
          command: "../../hooks/skills/pre_rate_limit_hook.sh"
  PostToolUse:
    - matcher: "Read"
      hooks:
        - type: command
          command: "../../hooks/skills/post_output_validation_hook.sh"
---

# Tech Inference Agent

## Purpose

Phase 3 orchestrator responsible for inferring technologies across all stack layers by analyzing collected signals against detection patterns.

## Responsibilities

1. **Frontend Inference**: React, Angular, Vue, jQuery, Bootstrap, Tailwind, etc.
2. **Backend Inference**: Web servers, languages, frameworks, databases, CMS
3. **Cloud Infrastructure**: AWS, Azure, GCP, PaaS platforms (Heroku, Vercel, etc.)
4. **CDN/WAF Detection**: Cloudflare, Akamai, Fastly, AWS CloudFront
5. **Security Posture**: CSP, HSTS, WAF presence, security.txt, bug bounty
6. **DevOps Detection**: CI/CD tools, Docker, Kubernetes signals
7. **Third-Party Services**: Payments, analytics, auth, CRM, support widgets

## Skills Orchestrated

Execute in parallel:
- `frontend_inferencer`
- `backend_inferencer`
- `cloud_infra_detector`
- `cdn_waf_fingerprinter`
- `security_posture_analyzer`
- `devops_detector`
- `third_party_detector`

## Input

Raw signals from Phase 2:
```json
{
  "signals": {
    "http_signals": [...],
    "dns_signals": {...},
    "tls_signals": [...],
    "javascript_signals": [...],
    "html_signals": [...],
    "repository_signals": {...},
    "job_signals": {...},
    "archive_signals": {...}
  }
}
```

## Output

Inferred technologies JSON by category:
```json
{
  "phase": 3,
  "company": "string",
  "inferred_technologies": {
    "frontend": [
      {
        "name": "React",
        "category": "JavaScript Framework",
        "version": "18.x (estimated)",
        "signals": [
          {
            "type": "javascript_global",
            "value": "window.React detected",
            "source": "https://example.com",
            "weight": 30
          },
          {
            "type": "dom_attribute",
            "value": "data-reactroot found",
            "source": "https://example.com",
            "weight": 25
          }
        ],
        "total_weight": 55
      }
    ],
    "backend": [
      {
        "name": "Node.js",
        "category": "Runtime",
        "signals": [...],
        "total_weight": 65
      },
      {
        "name": "Express.js",
        "category": "Web Framework",
        "signals": [...],
        "total_weight": 45
      }
    ],
    "infrastructure": [
      {
        "name": "AWS",
        "category": "Cloud Provider",
        "services_detected": ["CloudFront", "S3", "Route53"],
        "signals": [...],
        "total_weight": 80
      }
    ],
    "security": [
      {
        "name": "Cloudflare WAF",
        "category": "Web Application Firewall",
        "signals": [...],
        "total_weight": 90
      }
    ],
    "devops": [
      {
        "name": "GitHub Actions",
        "category": "CI/CD",
        "signals": [...],
        "total_weight": 40
      }
    ],
    "third_party": [
      {
        "name": "Stripe",
        "category": "Payment Processing",
        "signals": [...],
        "total_weight": 35
      },
      {
        "name": "Google Analytics",
        "category": "Analytics",
        "signals": [...],
        "total_weight": 50
      }
    ]
  },
  "timestamp": "ISO-8601"
}
```

## Pattern Matching

Uses detection patterns from `patterns/` directory:
- `frontend_patterns.json` - Framework detection rules
- `backend_patterns.json` - Server/language detection
- `cloud_patterns.json` - Cloud provider signatures
- `cdn_waf_patterns.json` - CDN/WAF fingerprints
- `third_party_patterns.json` - Third-party service patterns

## Signal Weight Reference

| Signal Type | Base Weight | Notes |
|-------------|-------------|-------|
| HTTP Header (X-Powered-By, Server) | 40 | Direct declaration |
| Meta tag (generator) | 35 | CMS/framework declaration |
| Cookie signature | 30 | Session pattern match |
| JavaScript global | 30 | Runtime detection |
| DNS record pattern | 25 | Service verification |
| DOM attribute | 20 | Framework markers |
| Job posting mention | 20 | Indirect signal |
| URL path pattern | 15 | Convention-based |
| Web archive evidence | 15 | Historical validation |
| CSP domain reference | 10 | Third-party hint |

## Execution Flow

```
INPUT: Raw Signals
         │
         ├──────────────────────────────────────────┐
         │              ALL PARALLEL                │
         ├─► frontend_inferencer ─────────────────► │
         ├─► backend_inferencer ──────────────────► │
         ├─► cloud_infra_detector ────────────────► │
         ├─► cdn_waf_fingerprinter ───────────────► │
         ├─► security_posture_analyzer ───────────► │
         ├─► devops_detector ─────────────────────► │
         └─► third_party_detector ────────────────► │
                                                    │
                       MERGE                        │
                         │                          │
                         ▼
         OUTPUT: Inferred Technologies JSON
```

## Error Handling

- Continue inference if some pattern files are missing
- Log unmatched signals for pattern improvement
- Return partial results on inference failures
- Flag low-confidence inferences for manual review
