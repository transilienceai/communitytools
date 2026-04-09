# Reconnaissance Output Format

Asset-specific reconnaissance for Phase 2. Stored in `data/reconnaissance/`.

## Directory Structure

```
data/reconnaissance/
├── domains.json
├── web-apps.json
├── apis.json
├── network.json
├── cloud.json
└── repositories.json

reports/
└── reconnaissance_report.md

processed/reconnaissance/
└── raw/              # Tool outputs (nmap, ffuf, ZAP)
```

## Schema: domains.json

```json
{
  "asset_type": "domain",
  "target": "example.com",
  "subdomains": [
    {"name": "api.example.com", "ip_addresses": ["192.0.2.1"], "status": "live",
     "tech_stack": ["nginx/1.21.0"], "discovery_method": "certificate_transparency"}
  ],
  "dns_records": {"mx": [], "txt": [], "ns": []},
  "stats": {"total_subdomains": 15, "live_subdomains": 12}
}
```

## Schema: web-apps.json

```json
{
  "asset_type": "web_application",
  "target": "https://app.example.com",
  "technology_stack": {"frontend": ["React 18.2.0"], "backend": ["Express.js 4.18.0"]},
  "endpoints": [{"path": "/api/v1/users", "method": "GET", "params": ["id"], "auth_required": true}],
  "forms": [{"location": "/profile", "inputs": ["name", "email"], "file_upload": true}],
  "javascript_files": [{"url": "/static/js/main.js", "endpoints_found": ["/api/v1/users"]}],
  "cookies": [{"name": "session_token", "secure": true, "httponly": true}],
  "stats": {"total_endpoints": 45, "input_fields": 127}
}
```

## Schema: apis.json

```json
{
  "asset_type": "api",
  "target": "https://api.example.com",
  "api_type": "REST",
  "documentation": {"swagger": "https://api.example.com/swagger.json"},
  "authentication": {"methods": ["Bearer Token"], "endpoints": {"login": "/api/v1/auth/login"}},
  "endpoints": [
    {"path": "/api/v1/users/{id}", "methods": ["GET", "PUT"],
     "params": {"path": ["id"], "query": ["fields"]}, "auth_required": true, "rate_limit": "100/minute"}
  ],
  "graphql": {"endpoint": "/graphql", "introspection_enabled": true, "mutations": ["createUser"]},
  "stats": {"total_endpoints": 67, "authenticated_endpoints": 55}
}
```

## Schema: network.json

```json
{
  "asset_type": "network_services",
  "target": "192.0.2.1",
  "hostname": "web01.example.com",
  "os_detection": {"name": "Linux", "version": "Ubuntu 22.04"},
  "open_ports": [
    {"port": 22, "service": "ssh", "version": "OpenSSH 8.9p1",
     "cve_candidates": ["CVE-2023-38408"], "risk_level": "medium"},
    {"port": 3306, "service": "mysql", "exposed_to_internet": true, "risk_level": "high"}
  ],
  "stats": {"open_ports": 8, "high_risk_services": 1}
}
```

## Schema: cloud.json

```json
{
  "asset_type": "cloud_infrastructure",
  "provider": "aws",
  "s3_buckets": [
    {"name": "example-backups", "public_access": true, "encryption": null, "risk_level": "critical"}
  ],
  "ec2_instances": [
    {"instance_id": "i-abc123", "ip_public": "192.0.2.10", "security_groups": ["sg-web"], "open_ports": [22, 443]}
  ],
  "stats": {"public_buckets": 1, "total_instances": 5}
}
```

## Schema: repositories.json

```json
{
  "asset_type": "repositories",
  "target_org": "example",
  "platforms": ["github", "gitlab"],
  "repositories": [
    {
      "name": "example/backend-api",
      "url": "https://github.com/example/backend-api",
      "language": "Python",
      "last_updated": "2024-11-01",
      "risk_level": "critical",
      "findings": [
        {
          "type": "secret",
          "description": "AWS Access Key ID in commit a1b2c3d",
          "file": "config/settings.py",
          "commit": "a1b2c3d",
          "detector": "trufflehog",
          "verified": true
        }
      ]
    }
  ],
  "employee_accounts": [
    {"platform": "github", "username": "jsmith-example", "repos_scanned": 12, "findings": []}
  ],
  "stats": {"total_repos": 34, "repos_with_findings": 5, "total_secrets_found": 8, "verified_secrets": 3}
}
```

## reconnaissance_report.md

Summary report structure:
- **Executive summary**: List of all discovered assets
- **Stats**: Asset count, high-risk items, coverage metrics (e.g., live vs. total subdomains)
- **Risk-prioritized findings**: Critical -> Low (ordered by severity)
- **Technology stack**: Summary with version information
- **External exposure map**: Internet-facing services
- **Authentication entry points**: Where authentication occurs
- **Data input vectors**: Forms, APIs, file uploads
- **Reconnaissance logs**: Tools/jobs grouped by asset

## Rules

- Generate one JSON file per discovered asset type
- Save raw tool outputs in `processed/reconnaissance/raw/` (named: `{asset}_{tool}.txt`)
- All JSON must be valid and include a `stats` summary object
