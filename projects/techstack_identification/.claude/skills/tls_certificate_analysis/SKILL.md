---
name: tls-certificate-analysis
description: Analyzes TLS certificates for issuer, SAN, and JARM fingerprints
tools: Bash, WebFetch
model: inherit
hooks:
  PreToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: "../../../hooks/skills/pre_network_skill_hook.sh"
  PostToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_skill_logging_hook.sh"
---

# TLS Certificate Analysis Skill

## Purpose

Analyze TLS certificates to extract issuer information, Subject Alternative Names, protocol versions, and fingerprint data for technology identification.

## Operations

### 1. extract_certificate_metadata

Connect to server and extract certificate details.

**Command:**
```bash
echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null | openssl x509 -noout -text
```

**Fields to Extract:**
- Subject (CN, O, OU)
- Issuer (CN, O)
- Validity (Not Before, Not After)
- Subject Alternative Names
- Signature Algorithm
- Public Key Algorithm & Size

### 2. analyze_certificate_issuer

Identify certificate authority and infer hosting/security practices.

**Issuer Detection Patterns:**
```json
{
  "Let's Encrypt": {
    "pattern": "Let's Encrypt",
    "indicates": ["Automated cert management", "Cost-conscious"],
    "confidence": 90
  },
  "DigiCert": {
    "pattern": "DigiCert",
    "indicates": ["Enterprise security", "Compliance focus"],
    "confidence": 85
  },
  "Amazon": {
    "pattern": "Amazon|AWS",
    "indicates": ["AWS infrastructure", "ACM usage"],
    "confidence": 95,
    "tech": "AWS Certificate Manager"
  },
  "Cloudflare": {
    "pattern": "Cloudflare",
    "indicates": ["Cloudflare CDN/proxy"],
    "confidence": 95,
    "tech": "Cloudflare"
  },
  "Google Trust Services": {
    "pattern": "Google Trust Services|GTS",
    "indicates": ["GCP infrastructure"],
    "confidence": 90,
    "tech": "Google Cloud"
  },
  "Sectigo": {
    "pattern": "Sectigo|Comodo",
    "indicates": ["Commercial CA", "Traditional hosting"],
    "confidence": 80
  },
  "ZeroSSL": {
    "pattern": "ZeroSSL",
    "indicates": ["Free CA alternative", "Automated certs"],
    "confidence": 85
  }
}
```

### 3. extract_sans

Parse Subject Alternative Names from certificate.

**Command:**
```bash
echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null | \
  openssl x509 -noout -ext subjectAltName
```

**Process:**
1. Extract SAN extension
2. Parse DNS names
3. Filter for relevant domains
4. Identify wildcards

### 4. check_protocol_support

Test TLS protocol and cipher support.

**Command:**
```bash
# Check TLS versions
nmap --script ssl-enum-ciphers -p 443 {domain}
# Or simpler check:
openssl s_client -connect {domain}:443 -tls1_2
openssl s_client -connect {domain}:443 -tls1_3
```

**Protocol Analysis:**
```json
{
  "TLS 1.3 only": {"indicates": ["Modern security", "Recent deployment"]},
  "TLS 1.2 + 1.3": {"indicates": ["Standard modern config"]},
  "TLS 1.1 enabled": {"indicates": ["Legacy support", "Older infrastructure"]},
  "TLS 1.0 enabled": {"indicates": ["Legacy systems", "Security concern"]}
}
```

### 5. generate_jarm_fingerprint

Generate JARM fingerprint for server identification.

**JARM Concept:**
JARM is a TLS server fingerprinting tool that sends specific TLS ClientHello packets and fingerprints the server's responses.

**Known JARM Fingerprints:**
```json
{
  "29d29d15d29d29d00042d42d000000cd19c7d2c21d91e77fcb9e7a8d6d1d8c": "Cloudflare",
  "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c": "Cloudflare Alternative",
  "29d29d00029d29d00042d43d00041d44609a5a9a88e797f466e878a82e8365": "AWS CloudFront",
  "29d29d15d29d29d00029d29d29d29dcd19c7d2c21d91e77fcb9e7a8d6d1d8c": "Fastly",
  "2ad2ad0002ad2ad0002ad2ad2ad2adce7a321c3e485c38c0e28d4e78968ed7": "Akamai"
}
```

**Note:** JARM fingerprinting requires specialized tools. This operation may be marked as optional.

## Output

```json
{
  "skill": "tls_certificate_analysis",
  "domain": "string",
  "results": {
    "certificates": [
      {
        "domain": "string",
        "subject": {
          "common_name": "string",
          "organization": "string",
          "country": "string"
        },
        "issuer": {
          "common_name": "string",
          "organization": "string",
          "technology_indicated": "AWS Certificate Manager|Cloudflare|Let's Encrypt|Other"
        },
        "validity": {
          "not_before": "date",
          "not_after": "date",
          "days_remaining": "number"
        },
        "sans": ["array of DNS names"],
        "signature_algorithm": "string",
        "public_key": {
          "algorithm": "RSA|ECDSA",
          "size": "number"
        }
      }
    ],
    "protocol_support": {
      "tls_1_3": "boolean",
      "tls_1_2": "boolean",
      "tls_1_1": "boolean",
      "tls_1_0": "boolean"
    },
    "fingerprints": {
      "jarm": "string (optional)",
      "jarm_match": "string (if known)"
    },
    "security_analysis": {
      "cert_automation": "boolean (Let's Encrypt or similar)",
      "wildcard_usage": "boolean",
      "short_validity": "boolean (< 90 days)",
      "modern_protocols_only": "boolean"
    },
    "technologies_detected": [
      {
        "name": "string",
        "source": "certificate_issuer|jarm_fingerprint",
        "confidence": "number"
      }
    ]
  },
  "evidence": [
    {
      "type": "certificate",
      "domain": "string",
      "issuer": "string",
      "validity": "string",
      "timestamp": "ISO-8601"
    }
  ]
}
```

## Technology Signals from Certificates

| Signal | Indicates | Confidence |
|--------|-----------|------------|
| Amazon issuer | AWS infrastructure | 95% |
| Cloudflare issuer | Cloudflare proxy | 95% |
| GTS issuer | Google Cloud | 90% |
| Let's Encrypt + 90-day validity | Automated cert management | 85% |
| EV certificate | Enterprise/financial | 80% |
| Wildcard SAN | Dynamic subdomain usage | 70% |

## Rate Limiting

- TLS connections: 10/minute per domain
- JARM scanning: 5/minute (if enabled)

## Error Handling

- Connection refused: Server may not have HTTPS
- Certificate expired: Log but continue
- Self-signed certificate: Log as finding
- SNI required: Retry with server name

## Security Considerations

- Only passive TLS analysis
- No certificate validation bypass
- Do not store private key material
- Log all connections for audit
