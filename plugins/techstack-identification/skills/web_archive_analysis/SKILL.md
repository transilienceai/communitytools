---
name: web-archive-analysis
description: Uses Wayback Machine to detect technology migrations over time
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

# Web Archive Analysis Skill

## Purpose

Query the Wayback Machine to discover historical technology usage and detect technology migrations over time.

## Operations

### 1. query_cdx_api

Get historical snapshots from the Wayback Machine CDX API.

**Endpoint:**
```
GET http://web.archive.org/cdx/search/cdx
```

**Parameters:**
```
url: {domain}
output: json
filter: statuscode:200
collapse: timestamp:6  # Group by month (YYYYMM)
limit: 100
from: {start_year}
to: {end_year}
```

**Example Request:**
```bash
curl "http://web.archive.org/cdx/search/cdx?url=example.com&output=json&filter=statuscode:200&collapse=timestamp:6&limit=100"
```

**Response Format:**
```json
[
  ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
  ["com,example)/", "20240115120000", "https://example.com/", "text/html", "200", "ABC123...", "45678"]
]
```

### 2. select_snapshots

Choose representative snapshots for analysis.

**Selection Strategy:**
```python
def select_snapshots(all_snapshots):
    # Get snapshots at regular intervals
    intervals = [
        "6 months ago",
        "1 year ago",
        "2 years ago",
        "3 years ago",
        "5 years ago"
    ]

    selected = []
    for interval in intervals:
        target_date = calculate_date(interval)
        closest = find_closest_snapshot(all_snapshots, target_date)
        if closest:
            selected.append(closest)

    return selected
```

**Snapshot Priority:**
1. Recent (baseline for comparison)
2. 1 year ago (detect recent changes)
3. 2-3 years ago (medium-term evolution)
4. 5+ years ago (historical context)

### 3. fetch_archived_content

Retrieve archived pages for analysis.

**Wayback URL Format:**
```
https://web.archive.org/web/{timestamp}/{original_url}
```

**Example:**
```
https://web.archive.org/web/20230115120000/https://example.com/
```

**Headers to Request:**
```
Accept: text/html
User-Agent: TechStackAgent/1.0 (OSINT research)
```

### 4. compare_snapshots

Detect technology changes between snapshots.

**Comparison Points:**
```json
{
  "headers_to_compare": [
    "Server",
    "X-Powered-By",
    "Set-Cookie"
  ],
  "html_elements": [
    "meta[name=generator]",
    "script[src]",
    "link[href]"
  ],
  "patterns_to_track": [
    "/wp-content/",
    "/_next/",
    "/_nuxt/",
    "/static/js/"
  ]
}
```

**Change Detection:**
```python
def detect_changes(old_snapshot, new_snapshot):
    changes = []

    # Compare technologies
    old_tech = extract_technologies(old_snapshot)
    new_tech = extract_technologies(new_snapshot)

    added = new_tech - old_tech
    removed = old_tech - new_tech

    for tech in added:
        changes.append({
            "type": "technology_added",
            "technology": tech,
            "first_seen": new_snapshot.timestamp
        })

    for tech in removed:
        changes.append({
            "type": "technology_removed",
            "technology": tech,
            "last_seen": old_snapshot.timestamp
        })

    return changes
```

### 5. detect_migrations

Identify framework/platform migrations.

**Common Migration Patterns:**
```json
{
  "WordPress → Custom/React": {
    "indicators": [
      "/wp-content/ disappears",
      "React globals appear",
      "/_next/ or /static/js/ paths"
    ],
    "typical_timeline": "6-18 months"
  },
  "AngularJS → Angular": {
    "indicators": [
      "ng-app disappears",
      "ng-version appears",
      "Angular 2+ patterns"
    ],
    "typical_timeline": "12-24 months"
  },
  "jQuery → React/Vue": {
    "indicators": [
      "jQuery CDN removed",
      "Modern framework globals",
      "SPA patterns"
    ],
    "typical_timeline": "6-12 months"
  },
  "On-prem → Cloud": {
    "indicators": [
      "CloudFront/Cloudflare headers appear",
      "AWS/GCP/Azure signatures",
      "CDN usage"
    ],
    "typical_timeline": "3-12 months"
  }
}
```

### 6. extract_historical_tech

Parse archived HTML for technology signals.

**Process:**
1. Fetch archived page
2. Apply same analysis as html_content_analysis skill
3. Record technologies with timestamp
4. Build timeline of technology usage

## Output

```json
{
  "skill": "web_archive_analysis",
  "domain": "string",
  "results": {
    "archive_coverage": {
      "oldest_snapshot": "2015-03-15",
      "newest_snapshot": "2024-01-10",
      "total_snapshots": 450,
      "snapshots_analyzed": 5
    },
    "snapshots_analyzed": [
      {
        "timestamp": "2024-01-10",
        "url": "https://web.archive.org/web/20240110/...",
        "technologies_detected": ["Next.js", "React", "Vercel"]
      },
      {
        "timestamp": "2022-06-15",
        "url": "https://web.archive.org/web/20220615/...",
        "technologies_detected": ["React", "Create React App", "Heroku"]
      },
      {
        "timestamp": "2020-01-20",
        "url": "https://web.archive.org/web/20200120/...",
        "technologies_detected": ["WordPress", "PHP"]
      }
    ],
    "technology_timeline": [
      {
        "technology": "WordPress",
        "first_seen": "2015-03-15",
        "last_seen": "2020-06-01",
        "status": "removed"
      },
      {
        "technology": "React",
        "first_seen": "2020-03-01",
        "last_seen": "present",
        "status": "current"
      },
      {
        "technology": "Next.js",
        "first_seen": "2023-01-15",
        "last_seen": "present",
        "status": "current"
      }
    ],
    "migrations_detected": [
      {
        "type": "CMS → Modern Framework",
        "from": "WordPress",
        "to": "React/Next.js",
        "approximate_date": "2020-Q1 to 2020-Q2",
        "confidence": 85
      },
      {
        "type": "Hosting Migration",
        "from": "Heroku",
        "to": "Vercel",
        "approximate_date": "2023-Q1",
        "confidence": 80
      }
    ],
    "current_vs_historical": {
      "current_stack": ["Next.js", "React", "Vercel"],
      "historical_stack": ["WordPress", "PHP", "Heroku"],
      "major_changes": 2
    }
  },
  "evidence": [
    {
      "type": "archived_snapshot",
      "timestamp": "string",
      "archive_url": "string",
      "technologies": ["array"],
      "analysis_timestamp": "ISO-8601"
    }
  ]
}
```

## Rate Limiting

- Wayback CDX API: 15 requests/minute
- Archived page fetches: 10/minute
- Cache CDX results to avoid repeated queries

## Error Handling

- 404: Domain not archived
- 503: Wayback Machine overloaded - retry with backoff
- Timeout: Increase timeout for archived pages (can be slow)
- Continue with available snapshots on partial failures

## Security Considerations

- Only access public archives
- Respect Wayback Machine rate limits
- Do not store archived content beyond analysis
- Note that archived content may contain outdated security vulnerabilities
- Log all queries for audit

## Confidence Notes

Historical data provides **contextual signals**:
- Confirms technology transitions
- Validates current technology choices
- Lower weight than current direct evidence
- Base confidence: 60-75%
