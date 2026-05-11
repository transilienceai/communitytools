# HTTP Host Header — Resources

## Standards

- RFC 7230 — HTTP/1.1 Message Syntax (Host required)
- RFC 9110 — HTTP Semantics
- RFC 9111 — HTTP Caching
- RFC 7239 — Forwarded HTTP Extension

## OWASP

- A01:2021 Broken Access Control
- A05:2021 Security Misconfiguration
- OWASP Web Security Testing Guide — Host header testing
- OWASP Cheat Sheet — Host Header Validation

## CWE

- CWE-20 — Improper Input Validation
- CWE-444 — Inconsistent Interpretation of HTTP Requests
- CWE-444 — HTTP Request Smuggling (related)
- CWE-444 — Cache Poisoning

## Foundational research

- "Practical Web Cache Poisoning" — James Kettle
- "Password Reset Poisoning" — multiple PortSwigger writeups
- PortSwigger Research blog — Host header attacks
- HackerOne disclosed reports tagged `host-header`

## Notable cases

- Multiple HackerOne disclosed reports on Twitter, Slack, GitHub, GitLab
- Drupal CVE-2018-7600 (Drupalgeddon — Host header indirectly involved)
- WordPress password reset (multiple CVEs)
- Django host validation bypasses
- Python Flask `host_url` issues
- Express trust-proxy misconfigurations

## Tools

### Burp extensions

- **Param Miner** — find unkeyed Host-like inputs
- **Collaborator Everywhere** — auto-injects Collaborator into Host
- **Turbo Intruder** — high-speed cache poisoning
- **Logger++** — track cache hit ratios
- **Host Header Injection Checker** (some BApps)

### Standalone

- **smuggler.py** — HTTP smuggling combined with Host header
- **race-the-web**
- Custom Python with `requests.get(url, headers={'Host': ...})`
- curl `-H "Host: ..."`

## Override headers (full list)

```
X-Forwarded-Host        X-Forwarded-Server      X-Forwarded-For
X-Forwarded-Scheme      X-Forwarded-Proto       X-Forwarded-SSL
X-HTTP-Host-Override    X-Original-Host         X-Host
X-Backend-Server        X-Original-URL          X-Rewrite-URL
X-Originating-IP        X-Remote-IP             X-Remote-Addr
X-Real-IP               X-ProxyUser-Ip          X-Cluster-Client-IP
True-Client-IP          CF-Connecting-IP        Forwarded
```

## Internal IP ranges

```
10.0.0.0/8       (10.0.0.0 - 10.255.255.255)
172.16.0.0/12    (172.16.0.0 - 172.31.255.255)
192.168.0.0/16   (192.168.0.0 - 192.168.255.255)
127.0.0.0/8      (127.0.0.1 - 127.255.255.255)
169.254.0.0/16   (Link-local, cloud metadata)
```

## Cloud metadata endpoints

```
# AWS
http://169.254.169.254/latest/meta-data/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true

# GCP
http://metadata.google.internal/computeMetadata/v1/
Header: Metadata-Flavor: Google

# DigitalOcean
http://169.254.169.254/metadata/v1/
```

## Localhost variations (IPv4 + IPv6 + encoding)

```
127.0.0.1   127.1   2130706433 (decimal)   0x7f000001 (hex)
017700000001 (octal)   [::1]   [0:0:0:0:0:0:0:1]
LocalHost   LOCALHOST   localhost.localdomain
127.0.0.1.nip.io
```

## Vulnerable patterns

- Password reset: `https://{HOST}/reset?token={token}` in email body
- Redirect: `Location: https://{HOST}/path`
- CORS: `Access-Control-Allow-Origin: https://{HOST}`
- Script injection: `<script src="//{HOST}/tracking.js">`
- Cache key omits Host (or X-Forwarded-Host)
- `Vary: Accept-Encoding` (no Host) signals cache-poisoning surface

## Connection state attack (Burp 2022.8.1+)

- Single TCP connection, two requests
- First validates legitimately, second exploits
- Right-click tab group → "Send in sequence (single connection)"

## Practice / labs

- Web Security Academy — Host header attacks — https://portswigger.net/web-security/host-header
- TryHackMe — Host Header rooms

## Detection / monitoring

- Splunk: `index=web_logs | search uri="/forgot-password" | stats values(http_x_forwarded_host)`
- ELK / Sentinel — track Host header diversity per endpoint
- WAF — block `Host: localhost`/`127.0.0.1`/`169.254.*` from external sources
- DataDog APM — request.host monitoring

## Frameworks reference

- **Django** — `ALLOWED_HOSTS` setting
- **Flask** — `SERVER_NAME`, `request.url_root`
- **Spring** — `server.tomcat.use-relative-redirects`
- **Express** — `app.set('trust proxy', ...)`, `req.hostname`
- **Rails** — `Rails.application.config.hosts`
- **ASP.NET** — `<allowedHosts>`

## Defensive references

- Whitelist Host header against config (not Host itself)
- Use absolute URLs from server config, never `request.host`
- Validate on every request (not connection)
- Reject ambiguous requests (duplicate Host, line wrapping)
- Disable unnecessary override headers at proxy layer
- Cache key includes Host
- HTTPS enforcement + HSTS preload

## Cheat-sheet companions in this repo

- `scenarios/host-header/password-reset-poisoning.md`
- `scenarios/host-header/auth-bypass-localhost.md`
- `scenarios/host-header/cache-poisoning-via-host.md`
- `scenarios/host-header/routing-ssrf-and-flawed-parsing.md`

## Bug bounty programs

- HackerOne — most SaaS programs accept Host-header issues
- Bugcrowd — Tesla, Netflix
- Self-hosted — Slack, GitLab, Twitter (X)
