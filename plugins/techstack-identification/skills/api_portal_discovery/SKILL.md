---
name: api-portal-discovery
description: Discovers public API portals, developer docs, and OpenAPI/Swagger endpoints
tools: Bash, WebFetch
model: inherit
hooks:
  PreToolUse:
    - matcher: "WebFetch"
      hooks:
        - type: command
          command: "../../../hooks/skills/pre_network_skill_hook.sh"
        - type: command
          command: "../../../hooks/skills/pre_rate_limit_hook.sh"
  PostToolUse:
    - matcher: "WebFetch"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_skill_logging_hook.sh"
---

# API Portal Discovery Skill

## Purpose

Discover public API portals, developer documentation, and OpenAPI/Swagger specification endpoints for a given domain.

## Operations

### 1. check_api_subdomains

Test common API-related subdomains.

**Subdomain Wordlist:**
```
api, developer, developers, dev, docs, documentation,
api-docs, apidocs, api-portal, portal, integrate,
sandbox, public-api, open, openapi, swagger,
rest, graphql, gql, v1, v2, v3
```

**Process:**
1. For each subdomain, construct FQDN
2. Attempt HTTP HEAD request
3. Record status code and redirects
4. Flag successful responses for further analysis

**Example:**
```
Domain: example.com
Test: api.example.com, developers.example.com, docs.example.com, ...
```

### 2. find_openapi_spec

Check for OpenAPI/Swagger specification files.

**Common Paths:**
```
/openapi.json
/openapi.yaml
/swagger.json
/swagger.yaml
/api-docs
/api-docs.json
/v1/openapi.json
/v2/openapi.json
/v3/openapi.json
/docs/openapi.json
/api/openapi.json
/.well-known/openapi.json
/specification/openapi.json
```

**Process:**
1. For each API subdomain found:
2. Test each common path
3. Validate response is valid OpenAPI spec
4. Extract API metadata if found

**OpenAPI Validation:**
```json
{
  "openapi": "3.0.0",  // or "swagger": "2.0"
  "info": {
    "title": "string",
    "version": "string"
  },
  "paths": {...}
}
```

### 3. detect_graphql

Test for GraphQL endpoints.

**Common GraphQL Paths:**
```
/graphql
/gql
/api/graphql
/v1/graphql
/query
```

**Detection Method:**
1. Send POST request with introspection query
2. Check for GraphQL-specific response structure
3. Extract schema metadata if available

**Introspection Query:**
```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

### 4. scan_robots_txt

Extract API paths from robots.txt.

**Process:**
1. Fetch /robots.txt
2. Parse Disallow and Allow directives
3. Identify API-related paths
4. Note any sitemap references

**API Path Patterns in robots.txt:**
```
Disallow: /api/
Disallow: /v1/
Disallow: /internal/
Allow: /api/public/
Sitemap: https://example.com/api-sitemap.xml
```

### 5. analyze_developer_portal

Analyze discovered developer portals for tech signals.

**Signals to Extract:**
- Authentication methods (OAuth, API keys, JWT)
- SDK languages mentioned
- Rate limit documentation
- Webhook support
- API versioning strategy

## Output

```json
{
  "skill": "api_portal_discovery",
  "domain": "string",
  "results": {
    "api_subdomains": [
      {
        "subdomain": "api.example.com",
        "status_code": 200,
        "redirect_to": null,
        "has_openapi": true,
        "has_graphql": false
      }
    ],
    "openapi_specs": [
      {
        "url": "https://api.example.com/openapi.json",
        "version": "3.0.0",
        "title": "Example API",
        "api_version": "1.0.0",
        "endpoints_count": 45,
        "auth_methods": ["oauth2", "apiKey"]
      }
    ],
    "graphql_endpoints": [
      {
        "url": "https://api.example.com/graphql",
        "introspection_enabled": true,
        "types_count": 120
      }
    ],
    "developer_portals": [
      {
        "url": "https://developers.example.com",
        "title": "Example Developer Portal",
        "sdks_mentioned": ["JavaScript", "Python", "Ruby"],
        "auth_methods": ["OAuth 2.0", "API Key"]
      }
    ],
    "robots_txt_findings": {
      "api_paths_disallowed": ["/api/internal/"],
      "api_paths_allowed": ["/api/public/"],
      "sitemaps": ["https://example.com/sitemap.xml"]
    }
  },
  "evidence": [
    {
      "type": "api_endpoint",
      "url": "string",
      "response_code": "number",
      "timestamp": "ISO-8601"
    },
    {
      "type": "openapi_spec",
      "url": "string",
      "version": "string"
    }
  ]
}
```

## Technology Inference from APIs

| Signal | Technology Indication |
|--------|----------------------|
| /swagger-ui/ path | Swagger UI (Java common) |
| /redoc path | ReDoc documentation |
| GraphQL introspection | GraphQL server |
| x-api-key header | Custom auth system |
| OAuth 2.0 in spec | OAuth provider integration |
| /v1/, /v2/ versioning | REST API maturity |

## Rate Limiting

- HTTP requests: 30/minute per domain
- OpenAPI validation: No limit (local parsing)
- GraphQL introspection: 5/minute (can be expensive)

## Error Handling

- 401/403 responses indicate protected APIs (still valuable discovery)
- 404 responses indicate path doesn't exist
- Timeout responses indicate potential API (record for retry)
- Continue discovery even if some paths fail

## Security Considerations

- Only use safe HTTP methods (GET, HEAD, OPTIONS)
- Do not attempt authentication bypass
- Respect rate limits in API documentation
- Log all requests for audit trail
- Do not execute arbitrary code from API specs
