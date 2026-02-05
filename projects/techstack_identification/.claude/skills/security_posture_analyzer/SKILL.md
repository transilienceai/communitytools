---
name: security-posture-analyzer
description: Analyzes security headers, CSP, HSTS, WAF presence, and security.txt
tools: Read, Grep
model: inherit
hooks:
  PostToolUse:
    - matcher: "Read"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_output_validation_hook.sh"
---

# Security Posture Analyzer Skill

## Purpose

Analyze the organization's security posture by examining security headers, Content Security Policy, HSTS configuration, security.txt file, and other security indicators.

## Input

Raw signals from Phase 2:
- `http_signals` - Security headers, CSP, HSTS
- `dns_signals` - DMARC, SPF, DKIM records
- `html_signals` - Meta tags for security policies
- `repository_signals` - Security configurations

## Security Categories

### HTTP Security Headers

| Header | Purpose | Strength Indicator |
|--------|---------|-------------------|
| Strict-Transport-Security | HTTPS enforcement | max-age value, includeSubDomains |
| Content-Security-Policy | XSS prevention | Policy complexity |
| X-Frame-Options | Clickjacking prevention | DENY vs SAMEORIGIN |
| X-Content-Type-Options | MIME sniffing prevention | nosniff |
| X-XSS-Protection | XSS filter (legacy) | 1; mode=block |
| Referrer-Policy | Referrer leakage control | strict-origin-when-cross-origin |
| Permissions-Policy | Feature restrictions | Comprehensive vs minimal |
| Cross-Origin-Opener-Policy | Cross-origin isolation | same-origin |
| Cross-Origin-Embedder-Policy | Embedding restrictions | require-corp |
| Cross-Origin-Resource-Policy | Resource sharing control | same-origin |

### Content Security Policy Analysis

| Directive | Security Implication |
|-----------|---------------------|
| default-src 'self' | Restrictive baseline |
| script-src 'unsafe-inline' | XSS vulnerability |
| script-src 'unsafe-eval' | Code injection risk |
| upgrade-insecure-requests | Mixed content handling |
| report-uri / report-to | Active monitoring |

### Email Security (DNS)

| Record | Purpose |
|--------|---------|
| SPF (TXT) | Email sender validation |
| DKIM | Email signing |
| DMARC | Email authentication policy |
| MTA-STS | Email transport security |

### Security Discovery Files

| File | Purpose |
|------|---------|
| /.well-known/security.txt | Security contact info |
| /security.txt | Security contact info |
| /.well-known/change-password | Password change endpoint |
| /humans.txt | Team information |

## Analysis Logic

```python
def analyze_security_posture(signals):
    results = {
        "security_headers": [],
        "csp_analysis": None,
        "email_security": [],
        "security_files": [],
        "overall_score": 0,
        "technologies_detected": []
    }

    # Security Header Analysis
    for header in SECURITY_HEADERS:
        if header.name in signals.http_signals.headers:
            value = signals.http_signals.headers[header.name]
            score, analysis = analyze_header(header.name, value)
            results["security_headers"].append({
                "header": header.name,
                "value": value,
                "present": True,
                "score": score,
                "analysis": analysis
            })
            results["overall_score"] += score
        else:
            results["security_headers"].append({
                "header": header.name,
                "present": False,
                "recommendation": header.recommendation
            })

    # CSP Deep Analysis
    if 'Content-Security-Policy' in signals.http_signals.headers:
        csp = signals.http_signals.headers['Content-Security-Policy']
        results["csp_analysis"] = analyze_csp(csp)

        # Extract third-party domains from CSP
        third_parties = extract_csp_domains(csp)
        for domain in third_parties:
            results["technologies_detected"].append({
                "name": identify_service(domain),
                "source": "CSP allowed domain",
                "domain": domain
            })

    # Email Security Analysis
    for record_type in ['SPF', 'DMARC', 'DKIM']:
        for txt in signals.dns_signals.txt_records:
            if record_type.lower() in txt.lower() or is_record_type(txt, record_type):
                score, analysis = analyze_email_record(record_type, txt)
                results["email_security"].append({
                    "type": record_type,
                    "value": txt,
                    "score": score,
                    "analysis": analysis
                })

    # Security File Discovery
    security_files = [
        "/.well-known/security.txt",
        "/security.txt"
    ]
    for file_url in security_files:
        # Check if file exists in signals
        if file_exists_in_signals(signals, file_url):
            content = get_file_content(signals, file_url)
            results["security_files"].append({
                "path": file_url,
                "exists": True,
                "content_analysis": analyze_security_txt(content)
            })

    return results
```

## CSP Analysis Function

```python
def analyze_csp(csp_value):
    directives = parse_csp(csp_value)

    analysis = {
        "directives_count": len(directives),
        "security_level": "Unknown",
        "issues": [],
        "strengths": [],
        "third_party_domains": []
    }

    # Check for unsafe directives
    if "'unsafe-inline'" in csp_value:
        analysis["issues"].append({
            "severity": "High",
            "issue": "unsafe-inline allows inline scripts",
            "recommendation": "Use nonces or hashes instead"
        })

    if "'unsafe-eval'" in csp_value:
        analysis["issues"].append({
            "severity": "High",
            "issue": "unsafe-eval allows dynamic code execution",
            "recommendation": "Refactor to avoid eval()"
        })

    # Check for good practices
    if "upgrade-insecure-requests" in csp_value:
        analysis["strengths"].append("Upgrades HTTP to HTTPS")

    if "report-uri" in csp_value or "report-to" in csp_value:
        analysis["strengths"].append("CSP violation reporting enabled")

    if "default-src 'self'" in csp_value:
        analysis["strengths"].append("Restrictive default policy")

    # Extract allowed domains
    domains = re.findall(r'https?://([^\s;\'\"]+)', csp_value)
    analysis["third_party_domains"] = list(set(domains))

    # Calculate security level
    if len(analysis["issues"]) == 0 and len(analysis["strengths"]) >= 3:
        analysis["security_level"] = "Strong"
    elif len(analysis["issues"]) <= 1:
        analysis["security_level"] = "Moderate"
    else:
        analysis["security_level"] = "Weak"

    return analysis
```

## Output

```json
{
  "skill": "security_posture_analyzer",
  "results": {
    "security_headers": [
      {
        "header": "Strict-Transport-Security",
        "value": "max-age=31536000; includeSubDomains; preload",
        "present": true,
        "score": 10,
        "analysis": {
          "max_age": 31536000,
          "include_subdomains": true,
          "preload": true,
          "assessment": "Strong - HSTS preload eligible"
        }
      },
      {
        "header": "Content-Security-Policy",
        "value": "default-src 'self'; script-src 'self' https://cdn.example.com; ...",
        "present": true,
        "score": 8,
        "analysis": "See csp_analysis"
      },
      {
        "header": "X-Frame-Options",
        "present": false,
        "recommendation": "Add 'X-Frame-Options: DENY' to prevent clickjacking"
      }
    ],
    "csp_analysis": {
      "directives_count": 8,
      "security_level": "Moderate",
      "issues": [
        {
          "severity": "Medium",
          "issue": "Script sources include external CDN",
          "domain": "cdn.example.com"
        }
      ],
      "strengths": [
        "Restrictive default policy",
        "CSP violation reporting enabled"
      ],
      "third_party_domains": [
        "cdn.example.com",
        "analytics.example.com",
        "api.stripe.com"
      ]
    },
    "email_security": [
      {
        "type": "SPF",
        "value": "v=spf1 include:_spf.google.com ~all",
        "score": 7,
        "analysis": "Good - SPF configured with softfail"
      },
      {
        "type": "DMARC",
        "value": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        "score": 10,
        "analysis": "Strong - DMARC reject policy with reporting"
      }
    ],
    "security_files": [
      {
        "path": "/.well-known/security.txt",
        "exists": true,
        "content_analysis": {
          "contact": "security@example.com",
          "encryption_key": true,
          "bug_bounty": "https://example.com/bug-bounty",
          "expires": "2025-12-31"
        }
      }
    ],
    "overall_score": {
      "score": 72,
      "max_score": 100,
      "grade": "B",
      "assessment": "Good security posture with some improvements needed"
    },
    "technologies_detected": [
      {
        "name": "Google Workspace",
        "source": "SPF include",
        "confidence": 90
      },
      {
        "name": "Stripe",
        "source": "CSP allowed domain: api.stripe.com",
        "confidence": 95
      }
    ],
    "recommendations": [
      {
        "priority": "High",
        "item": "Add X-Frame-Options header",
        "current": "Missing",
        "recommended": "DENY"
      },
      {
        "priority": "Medium",
        "item": "Enable HSTS preload",
        "current": "Not preloaded",
        "recommended": "Submit to HSTS preload list"
      }
    ]
  }
}
```

## Third-Party Detection from Security Headers

| CSP Domain Pattern | Service |
|-------------------|---------|
| *.stripe.com | Stripe Payments |
| *.google-analytics.com | Google Analytics |
| *.googletagmanager.com | Google Tag Manager |
| *.facebook.com | Facebook SDK |
| *.intercom.io | Intercom |
| *.zendesk.com | Zendesk |
| *.sentry.io | Sentry Error Tracking |
| *.datadog*.com | Datadog |
| *.newrelic.com | New Relic |

## Error Handling

- Missing headers: Note as finding, provide recommendations
- Malformed CSP: Parse what's possible, flag errors
- DNS lookup failures: Continue with HTTP-based analysis
