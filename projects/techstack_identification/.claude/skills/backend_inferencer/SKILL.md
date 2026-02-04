---
name: backend-inferencer
description: Infers backend technologies including servers, languages, frameworks, databases, and CMS
tools: Read, Grep
model: inherit
hooks:
  PostToolUse:
    - matcher: "Read"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_output_validation_hook.sh"
---

# Backend Inferencer Skill

## Purpose

Infer backend technologies by analyzing HTTP headers, cookies, error pages, DNS records, and repository data.

## Input

Raw signals from Phase 2:
- `http_signals` - Server headers, X-Powered-By, cookies
- `dns_signals` - Service verification TXT records
- `repository_signals` - Dependencies, Dockerfiles
- `html_signals` - Generator meta tags, CMS patterns

## Technology Categories

### Web Servers

| Technology | Detection Signals | Weight |
|------------|-------------------|--------|
| nginx | Server: nginx, nginx error pages | 35-40 |
| Apache | Server: Apache, Apache error pages | 35-40 |
| Microsoft IIS | Server: Microsoft-IIS | 40 |
| Caddy | Server: Caddy | 35 |
| LiteSpeed | Server: LiteSpeed | 35 |

### Programming Languages

| Technology | Detection Signals | Weight |
|------------|-------------------|--------|
| Node.js | X-Powered-By: Express, connect.sid cookie | 30-40 |
| Python | X-Powered-By: gunicorn/Werkzeug, django_session cookie | 30-40 |
| PHP | X-Powered-By: PHP, PHPSESSID cookie | 35-40 |
| Ruby | _rails_session cookie, X-Request-Id | 30-40 |
| Java | JSESSIONID cookie, X-Powered-By: Servlet | 35-40 |
| Go | Custom patterns, repo analysis | 25-35 |
| .NET | ASP.NET_SessionId cookie, X-AspNet-Version | 40 |

### Backend Frameworks

| Technology | Detection Signals | Implies | Weight |
|------------|-------------------|---------|--------|
| Express.js | X-Powered-By: Express | Node.js | 40 |
| NestJS | Nest patterns, repo analysis | Node.js, TypeScript | 35 |
| Fastify | Fastify patterns | Node.js | 35 |
| Django | csrftoken/django_session cookies | Python | 40 |
| Flask | Werkzeug server | Python | 35 |
| FastAPI | uvicorn patterns | Python | 35 |
| Rails | _rails_session cookie | Ruby | 40 |
| Laravel | laravel_session cookie, XSRF-TOKEN | PHP | 40 |
| Symfony | symfony cookie patterns | PHP | 35 |
| Spring | JSESSIONID, X-Application-Context | Java | 35 |
| ASP.NET | ASP.NET_SessionId | .NET | 40 |

### Content Management Systems

| Technology | Detection Signals | Weight |
|------------|-------------------|--------|
| WordPress | /wp-content/, /wp-admin/, generator meta | 45 |
| Drupal | X-Drupal-Cache, /sites/default/ | 45 |
| Joomla | generator meta, /components/ | 40 |
| Magento | /skin/frontend/, Mage patterns | 40 |
| Shopify | myshopify.com, Shopify patterns | 45 |
| Contentful | Contentful API patterns | 35 |
| Strapi | Strapi patterns | 35 |
| Ghost | Ghost generator meta | 40 |

### Databases (Indirect Signals)

| Technology | Detection Signals | Weight |
|------------|-------------------|--------|
| PostgreSQL | pg dependency, Heroku Postgres | 25-30 |
| MySQL | mysql dependency, common patterns | 25-30 |
| MongoDB | mongoose dependency, MongoDB Atlas TXT | 30 |
| Redis | redis dependency, session patterns | 25-30 |
| Elasticsearch | elasticsearch dependency | 25-30 |
| DynamoDB | AWS SDK patterns, boto3 | 25-30 |

### API Technologies

| Technology | Detection Signals | Weight |
|------------|-------------------|--------|
| GraphQL | /graphql endpoint, schema patterns | 35 |
| REST | /api/v1, OpenAPI spec | 25 |
| gRPC | grpc patterns in repos | 30 |
| tRPC | tRPC patterns | 30 |

## Inference Logic

```python
def infer_backend_technologies(signals):
    results = []

    # Web Server Detection
    server_header = signals.http_signals.get('Server', '')
    for server in SERVER_PATTERNS:
        if server.pattern.match(server_header):
            results.append({
                "name": server.name,
                "category": "Web Server",
                "version": extract_version(server_header, server.pattern),
                "signals": [{"type": "http_header", "value": f"Server: {server_header}"}],
                "total_weight": server.weight
            })

    # Language/Framework from X-Powered-By
    powered_by = signals.http_signals.get('X-Powered-By', '')
    for framework in POWERED_BY_PATTERNS:
        if framework.pattern in powered_by:
            results.append({
                "name": framework.name,
                "category": framework.category,
                "implies": framework.implies,
                "signals": [{"type": "http_header", "value": f"X-Powered-By: {powered_by}"}],
                "total_weight": framework.weight
            })

    # Cookie-based Detection
    for cookie in signals.http_signals.cookies:
        for pattern in COOKIE_PATTERNS:
            if pattern.name in cookie:
                results.append({
                    "name": pattern.tech,
                    "category": pattern.category,
                    "implies": pattern.implies,
                    "signals": [{"type": "cookie", "value": f"Cookie: {cookie}"}],
                    "total_weight": pattern.weight
                })

    # CMS Detection from HTML
    for cms in CMS_PATTERNS:
        score = 0
        evidence = []

        if cms.generator_pattern in signals.html_signals.generators:
            score += 40
            evidence.append("Generator meta tag")

        for url_pattern in cms.url_patterns:
            if url_pattern in signals.html_signals.script_urls:
                score += 20
                evidence.append(f"URL pattern: {url_pattern}")

        if score > 0:
            results.append({
                "name": cms.name,
                "category": "CMS",
                "signals": evidence,
                "total_weight": score
            })

    # Repository-based Detection
    if signals.repository_signals:
        for dep_file, deps in signals.repository_signals.dependencies.items():
            for dep in deps:
                if dep.name in DEPENDENCY_PATTERNS:
                    pattern = DEPENDENCY_PATTERNS[dep.name]
                    results.append({
                        "name": pattern.tech,
                        "category": pattern.category,
                        "version": dep.version,
                        "signals": [{"type": "dependency", "value": f"{dep.name}@{dep.version}"}],
                        "total_weight": pattern.weight
                    })

    return results
```

## Output

```json
{
  "skill": "backend_inferencer",
  "results": {
    "technologies": [
      {
        "name": "nginx",
        "category": "Web Server",
        "version": "1.18.0",
        "signals": [
          {
            "type": "http_header",
            "value": "Server: nginx/1.18.0",
            "source": "https://example.com",
            "weight": 40
          }
        ],
        "total_weight": 40
      },
      {
        "name": "Express.js",
        "category": "Backend Framework",
        "signals": [
          {
            "type": "http_header",
            "value": "X-Powered-By: Express",
            "source": "https://api.example.com",
            "weight": 40
          },
          {
            "type": "cookie",
            "value": "connect.sid session cookie",
            "source": "https://example.com",
            "weight": 30
          }
        ],
        "total_weight": 70,
        "implies": ["Node.js"]
      },
      {
        "name": "Node.js",
        "category": "Runtime",
        "signals": [
          {
            "type": "implied",
            "value": "Implied by Express.js detection",
            "weight": 0
          },
          {
            "type": "dependency",
            "value": "node version in package.json",
            "source": "github.com/example/repo",
            "weight": 35
          }
        ],
        "total_weight": 35
      },
      {
        "name": "PostgreSQL",
        "category": "Database",
        "signals": [
          {
            "type": "dependency",
            "value": "pg@8.11.0 in package.json",
            "source": "github.com/example/repo",
            "weight": 30
          }
        ],
        "total_weight": 30
      }
    ],
    "implied_technologies": [
      {
        "name": "Node.js",
        "implied_by": ["Express.js"],
        "confidence": "High"
      }
    ],
    "summary": {
      "web_server": "nginx",
      "runtime": "Node.js",
      "framework": "Express.js",
      "database": "PostgreSQL",
      "cms": null
    }
  }
}
```

## Version Detection

### From Headers
```
Server: nginx/1.18.0 → nginx 1.18.0
X-Powered-By: PHP/8.1.0 → PHP 8.1.0
X-AspNet-Version: 4.0.30319 → ASP.NET 4.x
```

### From Dependencies
```json
// package.json
"express": "^4.18.2" → Express.js 4.18.x

// requirements.txt
Django==4.2.1 → Django 4.2.1

// Gemfile
gem 'rails', '~> 7.0' → Rails 7.0.x
```

## Error Handling

- Missing headers: Continue with other signals
- Ambiguous cookies: Include all possibilities
- Conflicting signals: Report both, flag for correlation phase
