---
name: cdn-waf-fingerprinter
description: Identifies CDNs (Cloudflare, Akamai, Fastly) and WAFs
tools: Read, Grep
model: inherit
hooks:
  PostToolUse:
    - matcher: "Read"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_output_validation_hook.sh"
---

# CDN/WAF Fingerprinter Skill

## Purpose

Identify Content Delivery Networks (CDNs), Web Application Firewalls (WAFs), and DDoS protection services from HTTP headers, DNS records, and TLS fingerprints.

## Input

Raw signals from Phase 2:
- `http_signals` - CDN/WAF-specific headers, cookies
- `dns_signals` - CDN CNAME delegations
- `ip_signals` - CDN IP ranges
- `tls_signals` - JARM fingerprints, certificate issuers

## Technology Categories

### Content Delivery Networks

| CDN | Detection Signals | Weight |
|-----|-------------------|--------|
| Cloudflare | CF-RAY header, cf-* cookies, cloudflare-nginx server | 45 |
| Akamai | X-Akamai-*, Akamai-* headers, akamaiedge.net CNAME | 45 |
| Fastly | X-Served-By: cache-*, Fastly headers | 45 |
| AWS CloudFront | X-Amz-Cf-Id, cloudfront.net CNAME | 45 |
| Azure CDN | X-Azure-Ref, azureedge.net CNAME | 40 |
| Google Cloud CDN | Via: google, X-GFE-* headers | 40 |
| Cloudinary | cloudinary.com URLs | 35 |
| imgix | imgix.net URLs | 35 |
| KeyCDN | X-Edge-IP, keycdn.com | 35 |
| StackPath | X-HW headers, stackpath.com | 35 |
| BunnyCDN | X-Bunny-* headers | 35 |

### Web Application Firewalls

| WAF | Detection Signals | Weight |
|-----|-------------------|--------|
| Cloudflare WAF | CF-RAY, cf_clearance cookie | 40 |
| AWS WAF | X-Amz-Cf-Id with WAF rules | 35 |
| Akamai Kona | Akamai-* WAF headers | 40 |
| Imperva/Incapsula | X-Iinfo, incap_ses_* cookies | 45 |
| Sucuri | X-Sucuri-ID, sucuri.net | 40 |
| ModSecurity | Server: Apache + ModSecurity patterns | 35 |
| F5 BIG-IP | BIGipServer cookie | 40 |
| Barracuda | barra_counter_session cookie | 35 |
| Fortinet FortiWeb | FORTIWAFSID cookie | 40 |

### DDoS Protection

| Service | Detection Signals | Weight |
|---------|-------------------|--------|
| Cloudflare | CF-RAY, __cf_bm cookie | 40 |
| AWS Shield | CloudFront + Shield indicators | 35 |
| Akamai Prolexic | Akamai headers | 35 |
| Arbor Networks | Specific patterns | 30 |
| Project Shield | Google infrastructure | 35 |

### Bot Management

| Service | Detection Signals | Weight |
|---------|-------------------|--------|
| Cloudflare Bot Management | __cf_bm cookie | 40 |
| PerimeterX | _px* cookies | 40 |
| DataDome | datadome cookie | 40 |
| Shape Security | Shape patterns | 35 |
| Kasada | Kasada patterns | 35 |
| Arkose Labs | Arkose patterns | 35 |

## Detection Patterns

### Cloudflare
```json
{
  "headers": {
    "CF-RAY": true,
    "CF-Cache-Status": true,
    "Server": "cloudflare"
  },
  "cookies": [
    "__cfduid",
    "cf_clearance",
    "__cf_bm"
  ],
  "cname_patterns": [
    "cdn.cloudflare.net"
  ],
  "ip_ranges": "103.21.244.0/22, 103.22.200.0/22, ...",
  "jarm_hash": "29d29d15d29d29d00042d42d000000cd19c7d2c21d91e77fcb9e7a8d6d1d8c"
}
```

### Akamai
```json
{
  "headers": {
    "X-Akamai-Transformed": true,
    "X-Akamai-Session-Info": true,
    "X-Akamai-Pragma-Client-IP": true,
    "Akamai-Origin-Hop": true
  },
  "cname_patterns": [
    "edgekey.net",
    "edgesuite.net",
    "akamaiedge.net",
    "akamaized.net"
  ]
}
```

### Fastly
```json
{
  "headers": {
    "X-Served-By": "cache-",
    "X-Cache": true,
    "X-Cache-Hits": true,
    "Fastly-Debug-Digest": true,
    "X-Timer": true
  },
  "cname_patterns": [
    "fastly.net",
    "fastlylb.net"
  ]
}
```

### AWS CloudFront
```json
{
  "headers": {
    "X-Amz-Cf-Id": true,
    "X-Amz-Cf-Pop": true,
    "Via": "CloudFront"
  },
  "cname_patterns": [
    "cloudfront.net"
  ]
}
```

### Imperva/Incapsula
```json
{
  "headers": {
    "X-Iinfo": true,
    "X-CDN": "Incapsula"
  },
  "cookies": [
    "incap_ses_*",
    "visid_incap_*",
    "nlbi_*"
  ]
}
```

## Inference Logic

```python
def fingerprint_cdn_waf(signals):
    results = []

    # Header-based Detection
    for cdn in CDN_PATTERNS:
        matches = 0
        evidence = []

        for header, expected in cdn.headers.items():
            if header in signals.http_signals.headers:
                if expected == True or expected in signals.http_signals.headers[header]:
                    matches += 1
                    evidence.append({
                        "type": "http_header",
                        "value": f"{header}: {signals.http_signals.headers[header]}"
                    })

        if matches > 0:
            results.append({
                "name": cdn.name,
                "category": cdn.category,
                "signals": evidence,
                "total_weight": cdn.base_weight + (matches * 5)
            })

    # Cookie-based Detection
    for waf in WAF_PATTERNS:
        for cookie in signals.http_signals.cookies:
            for waf_cookie in waf.cookies:
                if waf_cookie in cookie or fnmatch(cookie, waf_cookie):
                    results.append({
                        "name": waf.name,
                        "category": "WAF",
                        "signals": [{
                            "type": "cookie",
                            "value": f"Cookie pattern: {cookie}"
                        }],
                        "total_weight": waf.weight
                    })
                    break

    # CNAME-based Detection
    for cname in signals.dns_signals.cname_records:
        for cdn in CDN_PATTERNS:
            for pattern in cdn.cname_patterns:
                if pattern in cname.target:
                    add_if_not_exists(results, cdn.name, "CDN", {
                        "type": "dns_cname",
                        "value": f"CNAME → {cname.target}"
                    }, cdn.weight)

    # JARM Fingerprint Detection
    if signals.tls_signals.jarm_hash:
        for cdn in JARM_DATABASE:
            if signals.tls_signals.jarm_hash == cdn.jarm_hash:
                add_if_not_exists(results, cdn.name, cdn.category, {
                    "type": "jarm_fingerprint",
                    "value": f"JARM match: {signals.tls_signals.jarm_hash}"
                }, 40)

    return results
```

## Output

```json
{
  "skill": "cdn_waf_fingerprinter",
  "results": {
    "technologies": [
      {
        "name": "Cloudflare",
        "category": "CDN",
        "signals": [
          {
            "type": "http_header",
            "value": "CF-RAY: 7a1b2c3d4e5f6g7h-IAD",
            "weight": 40
          },
          {
            "type": "http_header",
            "value": "Server: cloudflare",
            "weight": 35
          },
          {
            "type": "cookie",
            "value": "__cf_bm cookie present",
            "weight": 30
          }
        ],
        "total_weight": 105,
        "additional_services": ["Bot Management", "DDoS Protection"]
      },
      {
        "name": "Cloudflare WAF",
        "category": "WAF",
        "signals": [
          {
            "type": "cookie",
            "value": "cf_clearance cookie present",
            "weight": 35
          }
        ],
        "total_weight": 35
      }
    ],
    "security_summary": {
      "cdn_provider": "Cloudflare",
      "waf_enabled": true,
      "waf_provider": "Cloudflare WAF",
      "ddos_protection": "Cloudflare",
      "bot_management": "Cloudflare Bot Management"
    },
    "cache_behavior": {
      "cache_status_header": "CF-Cache-Status",
      "observed_statuses": ["HIT", "MISS", "DYNAMIC"]
    }
  }
}
```

## Security Implications

### CDN Behind WAF
```
Cloudflare (CDN + WAF) → Origin Server
- All traffic passes through Cloudflare
- WAF rules applied at edge
- Origin IP potentially hidden
```

### Multiple CDN Layers
```
CDN1 (Cloudflare) → CDN2 (CloudFront) → Origin
- Possible for different purposes
- Content caching vs security
```

## Error Handling

- Multiple CDN signals: May indicate CDN chain or migration
- Conflicting WAF signals: Report all possibilities
- Missing JARM: Fall back to header/cookie detection
