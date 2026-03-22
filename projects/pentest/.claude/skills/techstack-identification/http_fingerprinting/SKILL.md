---
name: http-fingerprinting
description: Analyzes HTTP responses for technology signatures in headers, cookies, and error pages
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
          command: "../../../hooks/skills/post_evidence_capture_hook.sh"
---

# HTTP Fingerprinting Skill

## Purpose

Analyze HTTP responses to identify technology signatures in headers, cookies, and error pages.

## Operations

### 1. collect_headers

Make HTTP requests and capture all response headers.

**Command:**
```bash
curl -sI -L --max-redirs 3 --connect-timeout 10 {url}
```

**Headers to Analyze:**
```
Server
X-Powered-By
X-AspNet-Version
X-AspNetMvc-Version
X-Generator
X-Drupal-Cache
X-Drupal-Dynamic-Cache
X-Varnish
X-Cache
X-Cache-Status
CF-RAY
X-Amz-Cf-Id
X-Vercel-Id
X-Netlify-
Via
```

### 2. analyze_server_header

Parse Server header for software and version.

**Detection Patterns:**
```json
{
  "nginx": {
    "pattern": "nginx(/[\\d.]+)?",
    "tech": "nginx",
    "extract_version": true
  },
  "Apache": {
    "pattern": "Apache(/[\\d.]+)?",
    "tech": "Apache HTTP Server",
    "extract_version": true
  },
  "Microsoft-IIS": {
    "pattern": "Microsoft-IIS/([\\d.]+)",
    "tech": "Microsoft IIS",
    "extract_version": true
  },
  "cloudflare": {
    "pattern": "cloudflare",
    "tech": "Cloudflare",
    "extract_version": false
  },
  "AmazonS3": {
    "pattern": "AmazonS3",
    "tech": "AWS S3",
    "extract_version": false
  },
  "gunicorn": {
    "pattern": "gunicorn(/[\\d.]+)?",
    "tech": "Gunicorn",
    "implies": ["Python"]
  },
  "Werkzeug": {
    "pattern": "Werkzeug(/[\\d.]+)?",
    "tech": "Flask",
    "implies": ["Python"]
  }
}
```

### 3. detect_powered_by

Check X-Powered-By and similar headers.

**Detection Patterns:**
```json
{
  "X-Powered-By": {
    "Express": {"tech": "Express.js", "implies": ["Node.js"], "confidence": 95},
    "PHP/": {"tech": "PHP", "extract_version": true, "confidence": 95},
    "ASP.NET": {"tech": "ASP.NET", "confidence": 95},
    "Servlet": {"tech": "Java Servlet", "implies": ["Java"], "confidence": 90},
    "Next.js": {"tech": "Next.js", "implies": ["React", "Node.js"], "confidence": 95},
    "Phusion Passenger": {"tech": "Passenger", "implies": ["Ruby"], "confidence": 85},
    "PleskLin": {"tech": "Plesk", "confidence": 90},
    "WP Engine": {"tech": "WP Engine", "implies": ["WordPress"], "confidence": 95}
  },
  "X-Generator": {
    "Drupal": {"tech": "Drupal", "confidence": 95},
    "WordPress": {"tech": "WordPress", "confidence": 95}
  }
}
```

### 4. fingerprint_cookies

Match cookie names to technology patterns.

**Cookie Detection Patterns:**
```json
{
  "PHPSESSID": {"tech": "PHP", "confidence": 85},
  "JSESSIONID": {"tech": "Java", "confidence": 85},
  "ASP.NET_SessionId": {"tech": "ASP.NET", "confidence": 90},
  "connect.sid": {"tech": "Express.js", "implies": ["Node.js"], "confidence": 80},
  "_rails_session": {"tech": "Ruby on Rails", "confidence": 90},
  "laravel_session": {"tech": "Laravel", "implies": ["PHP"], "confidence": 90},
  "XSRF-TOKEN": {"tech": "Laravel", "confidence": 70},
  "django_session": {"tech": "Django", "implies": ["Python"], "confidence": 90},
  "csrftoken": {"tech": "Django", "implies": ["Python"], "confidence": 85},
  "_session_id": {"tech": "Ruby", "confidence": 60},
  "rack.session": {"tech": "Rack", "implies": ["Ruby"], "confidence": 85},
  "cf_clearance": {"tech": "Cloudflare", "confidence": 95},
  "__cf_bm": {"tech": "Cloudflare Bot Management", "confidence": 95},
  "__cfduid": {"tech": "Cloudflare", "confidence": 90},
  "AWSALB": {"tech": "AWS ALB", "confidence": 95},
  "AWSALBCORS": {"tech": "AWS ALB", "confidence": 95},
  "_gh_sess": {"tech": "GitHub", "confidence": 95},
  "wp-settings-": {"tech": "WordPress", "confidence": 90},
  "wordpress_logged_in": {"tech": "WordPress", "confidence": 95}
}
```

### 5. analyze_error_pages

Request invalid paths and analyze error page content.

**Process:**
1. Request non-existent path: `/{random_uuid}`
2. Analyze 404 response body
3. Look for technology signatures in error HTML

**Error Page Signatures:**
```json
{
  "Apache": {
    "pattern": "Apache/[\\d.]+ \\(.*\\) Server at",
    "confidence": 90
  },
  "nginx": {
    "pattern": "<center>nginx</center>",
    "confidence": 90
  },
  "IIS": {
    "pattern": "Server Error in '/' Application",
    "confidence": 85
  },
  "Tomcat": {
    "pattern": "Apache Tomcat/[\\d.]+",
    "confidence": 90
  },
  "Express": {
    "pattern": "Cannot GET /",
    "confidence": 70
  },
  "Django": {
    "pattern": "Page not found \\(404\\)|Django",
    "confidence": 85
  },
  "Rails": {
    "pattern": "Action Controller: Exception",
    "confidence": 90
  },
  "Laravel": {
    "pattern": "Whoops, looks like something went wrong",
    "confidence": 80
  }
}
```

## Output

```json
{
  "skill": "http_fingerprinting",
  "domain": "string",
  "results": {
    "endpoints_analyzed": "number",
    "signals": [
      {
        "url": "https://example.com",
        "headers": {
          "Server": "nginx/1.18.0",
          "X-Powered-By": "Express"
        },
        "cookies": ["connect.sid", "csrf_token"],
        "status_code": 200,
        "technologies_detected": [
          {
            "name": "nginx",
            "version": "1.18.0",
            "source": "Server header",
            "confidence": 90
          },
          {
            "name": "Express.js",
            "source": "X-Powered-By header",
            "confidence": 95,
            "implies": ["Node.js"]
          }
        ]
      }
    ],
    "unique_technologies": [
      {
        "name": "string",
        "total_signals": "number",
        "sources": ["array"]
      }
    ]
  },
  "evidence": [
    {
      "type": "http_header",
      "url": "string",
      "header": "string",
      "value": "string",
      "timestamp": "ISO-8601"
    },
    {
      "type": "cookie",
      "url": "string",
      "cookie_name": "string",
      "timestamp": "ISO-8601"
    }
  ]
}
```

## Rate Limiting

- HTTP requests: 30/minute per domain
- 2 second delay between requests to same host
- Respect Retry-After headers

## Error Handling

- Timeout after 10 seconds per request
- Continue on connection failures
- Log all errors for debugging
- Never fail completely - return partial results

## Security Considerations

- Only use safe HTTP methods (GET, HEAD)
- Follow redirects (max 3)
- Do not send authentication
- Respect robots.txt rate limits
- Log all requests for audit
