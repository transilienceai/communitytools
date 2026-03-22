---
name: certificate-transparency
description: Queries CT logs for certificates and extracts SANs for subdomain discovery
tools: Bash, WebFetch
model: inherit
hooks:
  PreToolUse:
    - matcher: "WebFetch"
      hooks:
        - type: command
          command: "../../../hooks/skills/pre_rate_limit_hook.sh"
  PostToolUse:
    - matcher: "WebFetch"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_skill_logging_hook.sh"
---

# Certificate Transparency Skill

## Purpose

Query Certificate Transparency logs to discover certificates issued for a domain, extract Subject Alternative Names (SANs), and identify internal naming conventions.

## Operations

### 1. query_crt_sh_json

Query crt.sh for all certificates matching a domain.

**Endpoint:**
```
GET https://crt.sh/?q=%25.{domain}&output=json
```

**Request Headers:**
```
User-Agent: TechStackAgent/1.0
Accept: application/json
```

**Process:**
1. URL encode domain with wildcard prefix
2. Make HTTP GET request to crt.sh
3. Parse JSON response array
4. Extract certificate metadata

**Response Fields:**
```json
{
  "issuer_ca_id": 183267,
  "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
  "common_name": "example.com",
  "name_value": "example.com\nwww.example.com\napi.example.com",
  "id": 1234567890,
  "entry_timestamp": "2024-01-15T10:30:00.000",
  "not_before": "2024-01-15T09:00:00",
  "not_after": "2024-04-15T09:00:00",
  "serial_number": "abc123..."
}
```

### 2. extract_sans

Parse Subject Alternative Names from certificate data.

**Process:**
1. Split name_value field by newlines
2. Filter for domain matches
3. Deduplicate entries
4. Validate format (no wildcards in extracted names)

**Example:**
```
Input: "example.com\n*.example.com\napi.example.com\nwww.example.com"
Output: ["example.com", "api.example.com", "www.example.com"]
```

### 3. identify_naming_patterns

Analyze SANs to detect internal naming conventions.

**Pattern Detection:**
```python
patterns = {
    "environment_prefix": r"^(prod|staging|dev|test|qa|uat)-",
    "environment_suffix": r"-(prod|staging|dev|test|qa|uat)$",
    "numbered_instances": r"(\d+)$",
    "geo_prefix": r"^(us|eu|apac|asia|emea|latam)-",
    "service_pattern": r"^(api|app|web|cdn|static|assets)-"
}
```

**Example Output:**
```json
{
  "patterns": [
    {
      "type": "environment_prefix",
      "regex": "^(prod|staging|dev)-",
      "matches": ["prod-api", "staging-api", "dev-api"]
    },
    {
      "type": "geo_prefix",
      "regex": "^(us|eu)-",
      "matches": ["us-east-api", "eu-west-api"]
    }
  ]
}
```

### 4. find_wildcard_certs

Identify wildcard certificate usage.

**Process:**
1. Filter certificates where common_name starts with "*."
2. Note wildcard scope (*.domain.com vs *.subdomain.domain.com)
3. Flag potential security implications

**Wildcard Analysis:**
```json
{
  "wildcards": [
    {
      "pattern": "*.example.com",
      "scope": "root_domain",
      "certificates_count": 5,
      "latest_issue": "2024-01-15"
    },
    {
      "pattern": "*.api.example.com",
      "scope": "subdomain",
      "certificates_count": 2,
      "latest_issue": "2024-01-10"
    }
  ]
}
```

## Output

```json
{
  "skill": "certificate_transparency",
  "domain": "string",
  "results": {
    "certificates": [
      {
        "id": "number",
        "issuer": "string",
        "common_name": "string",
        "sans": ["array"],
        "not_before": "date",
        "not_after": "date",
        "is_wildcard": "boolean"
      }
    ],
    "unique_subdomains": ["array"],
    "naming_patterns": [
      {
        "type": "string",
        "pattern": "string",
        "examples": ["array"]
      }
    ],
    "wildcard_analysis": {
      "wildcards_found": "number",
      "patterns": ["array"]
    },
    "issuers": {
      "issuer_name": "count"
    }
  },
  "evidence": [
    {
      "type": "ct_certificate",
      "id": "number",
      "common_name": "string",
      "issuer": "string",
      "timestamp": "ISO-8601"
    }
  ],
  "metadata": {
    "total_certificates": "number",
    "unique_subdomains": "number",
    "query_timestamp": "ISO-8601"
  }
}
```

## Certificate Issuer Analysis

Track which CAs are used (reveals hosting/security practices):

| Issuer Pattern | Indicates |
|----------------|-----------|
| Let's Encrypt | Cost-conscious, automated cert management |
| DigiCert, Sectigo | Enterprise/compliance requirements |
| AWS Certificate Manager | AWS infrastructure |
| Cloudflare | Cloudflare CDN/proxy |
| Google Trust Services | GCP infrastructure |

## Rate Limiting

- crt.sh: Max 10 requests/minute
- Implement exponential backoff on 429 responses
- Cache results to avoid repeated queries

## Error Handling

- If crt.sh returns 503, wait 30s and retry
- If timeout, retry with longer timeout (60s)
- If JSON parse fails, log raw response
- Continue with partial results if some queries fail

## Security Considerations

- Only query public CT logs
- Do not attempt to access certificate private keys
- Log all queries for audit trail
- Respect crt.sh rate limits
