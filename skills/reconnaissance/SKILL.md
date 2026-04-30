---
name: reconnaissance
description: Domain assessment and web application mapping - subdomain discovery, port scanning, endpoint enumeration, API discovery, and attack surface analysis.
---

# Reconnaissance

Domain and web application reconnaissance. Discovers subdomains, open ports, endpoints, APIs, and JavaScript routes to build attack surface inventory.

## Phases

### Domain Assessment
1. **Subdomain Discovery** - Passive DNS, certificate transparency, DNS brute-forcing, zone transfers
2. **Port Scanning** - nmap/masscan (top 1000/10000/all), service detection, OS fingerprinting
3. **Service Enumeration** - Version detection, banner grabbing, protocol-specific enumeration

### Web Application Mapping
0. **Software Inventory** - Dependencies, frameworks, SBOM generation
1. **Active Scanning** - ffuf, gobuster, nikto, ZAP spider for directories/files
2. **API Discovery** - REST, GraphQL, SOAP, WebSocket, Swagger/OpenAPI docs
3. **JavaScript & SPA** - Client-side routes, dynamic scripts, browser storage
4. **Surface Analysis** - Categorize attack surfaces, prioritize by risk

## Output

```
inventory/  - JSON: subdomains, ports, endpoints, APIs, SBOM
analysis/   - MD: attack-surface, testing-checklist
raw/        - Tool outputs (nmap, ffuf, ZAP, subfinder)
```

## Tools

subfinder, amass, nmap, masscan, ffuf, gobuster, nikto, ZAP, Playwright MCP

## Related Skills

- `/osint` - Run alongside reconnaissance for repository enumeration, secret scanning, and git history analysis

## Rules

1. Passive discovery before active scanning
2. Always run `/osint` in parallel during Phase 2
3. Respect rate limits
4. Verify subdomains are live before port scanning
5. Save all raw tool outputs
6. **HTTP response header vhost leaks**: Always check response headers on the raw IP (`curl -sI http://IP/`). Headers like `X-Backend-Server`, `X-Forwarded-Host`, `X-Served-By`, `X-Upstream` often leak internal hostnames/vhosts not discoverable via DNS or brute-force. Add discovered hostnames to `/etc/hosts` immediately.
7. **Wildcard SSL certs** (`*.domain.tld` in SAN) = strong indicator of hidden vhosts. Always run vhost brute-force with `ffuf -u https://IP -k -H "Host: FUZZ.domain.tld" -w subdomains.txt -mc all -fs <default_size>` when wildcard SAN detected. Compare response size/status vs default vhost to identify valid subdomains.
8. **VHost enumeration without ffuf**: When ffuf/gobuster unavailable, use shell loop: `for sub in admin dev api portal dashboard staging git; do code=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" -H "Host: ${sub}.DOMAIN" http://IP); echo "$sub: $code"; done` — filter by response size difference from default page.
9. **Web management panels**: When discovering admin vhosts (admin.*, panel.*, manage.*), check for known management UIs: Nginx UI (`manifest.json` → "Nginx UI"), Cockpit, Webmin, phpMyAdmin. These often have unauthenticated API endpoints or known CVEs. Check `/api/backup`, `/api/settings`, `/api/install` for Nginx UI specifically.
