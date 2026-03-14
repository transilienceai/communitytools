---
name: subdomain-enumeration
description: Enumerates subdomains using CT logs, passive DNS, and search engine dorks
tools: Bash, WebFetch
model: inherit
hooks:
  PreToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: "../../../hooks/skills/pre_network_skill_hook.sh"
        - type: command
          command: "../../../hooks/skills/pre_rate_limit_hook.sh"
  PostToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_skill_logging_hook.sh"
---

# Subdomain Enumeration Skill

## Purpose

Enumerate all discoverable subdomains for a given domain using passive reconnaissance techniques including Certificate Transparency logs, passive DNS, and search engine dorks.

## Operations

### 1. query_crt_sh

Query Certificate Transparency logs via crt.sh API.

**Endpoint:**
```
GET https://crt.sh/?q=%25.{domain}&output=json
```

**Process:**
1. URL encode the wildcard query
2. Make HTTP GET request
3. Parse JSON response
4. Extract unique subdomains from name_value field
5. Deduplicate and sort results

**Example Response:**
```json
[
  {
    "issuer_ca_id": 183267,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "*.example.com",
    "name_value": "api.example.com\nwww.example.com"
  }
]
```

### 2. search_engine_dorks

Use search engine dorks to discover subdomains.

**Dork Queries:**
```
site:*.{domain} -www
site:{domain} inurl:subdomain
site:*.*.{domain}
```

**Process:**
1. Execute each dork query
2. Extract unique subdomains from results
3. Validate each subdomain resolves
4. Merge with CT log results

### 3. check_common_subdomains

Test a wordlist of common subdomains.

**Common Subdomain Wordlist:**
```
api, app, dev, staging, test, beta, www, mail, webmail,
admin, portal, dashboard, docs, status, support, help,
blog, news, cdn, static, assets, media, img, images,
auth, login, sso, id, account, my, secure, vpn,
git, gitlab, github, jenkins, ci, build, deploy,
k8s, kubernetes, docker, registry, grafana, prometheus,
shop, store, checkout, cart, payments, billing,
crm, erp, hr, internal, intranet, wiki, confluence,
slack, jira, trello, asana, notion, airtable,
aws, azure, gcp, cloud, s3, storage, backup,
mobile, ios, android, m, wap,
v1, v2, v3, api-v1, api-v2, rest, graphql, gql
```

**Process:**
1. For each subdomain in wordlist:
   - Construct FQDN: {subdomain}.{domain}
   - Attempt DNS resolution
   - Record if resolves
2. Return list of valid subdomains

### 4. passive_dns_lookup

Query passive DNS databases (if available).

**Data Sources:**
- VirusTotal (requires API key)
- SecurityTrails (requires API key)
- DNSDumpster (free, limited)

**Note:** This operation is optional and depends on available API access.

## Output

```json
{
  "skill": "subdomain_enumeration",
  "domain": "string",
  "results": {
    "total_subdomains": "number",
    "subdomains": [
      {
        "fqdn": "api.example.com",
        "source": "crt.sh",
        "resolves": true,
        "ip_addresses": ["array"]
      }
    ],
    "sources_queried": ["crt.sh", "search_dorks", "wordlist"],
    "naming_patterns_detected": [
      {
        "pattern": "{env}-{service}",
        "examples": ["prod-api", "staging-api", "dev-api"]
      }
    ]
  },
  "evidence": [
    {
      "type": "ct_log",
      "source": "crt.sh",
      "count": "number",
      "timestamp": "ISO-8601"
    }
  ]
}
```

## Naming Pattern Detection

Analyze discovered subdomains to detect naming conventions:

```
Pattern: {environment}-{service}
  Examples: prod-api, staging-web, dev-backend

Pattern: {service}.{environment}
  Examples: api.prod, web.staging, backend.dev

Pattern: {service}{number}
  Examples: api1, api2, web01, web02

Pattern: {geo}-{service}
  Examples: us-east-api, eu-west-cdn, apac-app
```

## Rate Limiting

| Source | Rate Limit |
|--------|------------|
| crt.sh | 10 requests/minute |
| Search engines | 10 requests/minute |
| DNS resolution | 30 requests/minute |

## Error Handling

- If crt.sh times out, retry with backoff
- If search engine blocks, wait and retry
- Continue with partial results if some sources fail
- Log all errors for debugging

## Security Considerations

- Only use passive techniques
- No active subdomain brute-forcing
- Respect rate limits to avoid blocking
- Log all queries for audit trail
