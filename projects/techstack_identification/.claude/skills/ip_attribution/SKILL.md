---
name: ip-attribution
description: Maps IP addresses to cloud providers, ASNs, and organizations via WHOIS
tools: Bash, WebFetch
model: inherit
hooks:
  PreToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: "../../../hooks/skills/pre_network_skill_hook.sh"
  PostToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: "../../../hooks/skills/post_skill_logging_hook.sh"
---

# IP Attribution Skill

## Purpose

Map discovered IP addresses to cloud providers, Autonomous System Numbers (ASNs), and organizations through WHOIS lookups and cloud IP range matching.

## Operations

### 1. dns_resolve

Resolve domain names to IP addresses.

**Command:**
```bash
dig +short A {domain}
dig +short AAAA {domain}
```

**Process:**
1. Query A records for IPv4 addresses
2. Query AAAA records for IPv6 addresses
3. Handle CNAME chains (follow to final IP)
4. Record all resolved IPs

**Output:**
```json
{
  "domain": "example.com",
  "ipv4": ["93.184.216.34"],
  "ipv6": ["2606:2800:220:1:248:1893:25c8:1946"],
  "cname_chain": ["example.com", "cdn.example.net"]
}
```

### 2. whois_ip_lookup

Query WHOIS for IP ownership information.

**Command:**
```bash
whois {ip_address} | grep -iE "OrgName|Organization|NetName|Country|CIDR|ASN"
```

**Fields to Extract:**
- OrgName / Organization
- NetName
- Country
- CIDR Block
- ASN / OriginAS
- Abuse Contact

**Example Output:**
```json
{
  "ip": "93.184.216.34",
  "organization": "Edgecast Inc.",
  "net_name": "EDGECAST",
  "country": "US",
  "cidr": "93.184.216.0/24",
  "asn": "AS15133"
}
```

### 3. asn_lookup

Identify the Autonomous System Number for an IP.

**Command:**
```bash
dig +short {reversed_ip}.origin.asn.cymru.com TXT
```

**Process:**
1. Reverse IP octets (1.2.3.4 → 4.3.2.1)
2. Query Team Cymru ASN service
3. Parse ASN, country, registry info

**Response Format:**
```
"15133 | US | arin | 2007-03-01 | EDGECAST"
```

### 4. cloud_provider_match

Match IP against known cloud provider IP ranges.

**Cloud Provider IP Sources:**

**AWS:**
```
URL: https://ip-ranges.amazonaws.com/ip-ranges.json
Fields: ip_prefix, region, service
```

**GCP:**
```
URL: https://www.gstatic.com/ipranges/cloud.json
Fields: ipv4Prefix, ipv6Prefix, scope
```

**Azure:**
```
URL: https://www.microsoft.com/en-us/download/details.aspx?id=56519
Note: Weekly updated JSON files
```

**Cloudflare:**
```
URL: https://www.cloudflare.com/ips-v4
URL: https://www.cloudflare.com/ips-v6
```

**Matching Process:**
1. Download/cache cloud IP ranges
2. For each target IP, check membership in ranges
3. Return provider, region, service if matched

## Output

```json
{
  "skill": "ip_attribution",
  "domain": "string",
  "results": {
    "ip_mappings": [
      {
        "domain": "example.com",
        "ip": "93.184.216.34",
        "ip_version": "ipv4",
        "attribution": {
          "cloud_provider": "AWS|GCP|Azure|Cloudflare|Other",
          "cloud_region": "us-east-1",
          "cloud_service": "CloudFront",
          "organization": "Amazon.com, Inc.",
          "asn": "AS16509",
          "asn_name": "AMAZON-02",
          "country": "US",
          "cidr": "93.184.216.0/24"
        },
        "is_cloud": true,
        "is_cdn": true
      }
    ],
    "summary": {
      "unique_ips": "number",
      "cloud_hosted": "number",
      "cdn_fronted": "number",
      "providers_detected": ["array"]
    }
  },
  "evidence": [
    {
      "type": "dns_resolution",
      "domain": "string",
      "ip": "string",
      "timestamp": "ISO-8601"
    },
    {
      "type": "whois",
      "ip": "string",
      "organization": "string"
    },
    {
      "type": "cloud_ip_match",
      "ip": "string",
      "provider": "string",
      "range": "string"
    }
  ]
}
```

## Cloud Provider Detection Signals

| Provider | IP Range Pattern | ASN Pattern |
|----------|-----------------|-------------|
| AWS | From ip-ranges.json | AS16509, AS14618 |
| GCP | From cloud.json | AS15169, AS396982 |
| Azure | From ServiceTags | AS8075 |
| Cloudflare | 104.16.0.0/12, 172.64.0.0/13 | AS13335 |
| Fastly | 151.101.0.0/16 | AS54113 |
| Akamai | Various | AS20940, AS16625 |
| DigitalOcean | Various | AS14061 |
| Linode | Various | AS63949 |
| Vultr | Various | AS20473 |
| Heroku | AWS ranges | (Uses AWS) |
| Vercel | Various | AS209242 |
| Netlify | Various | AS205948 |

## Rate Limiting

- DNS queries: No hard limit (use local resolver)
- WHOIS queries: 5 requests/minute
- Cloud IP range downloads: Cache for 24 hours

## Error Handling

- If DNS fails, record as unresolvable
- If WHOIS fails, continue with ASN lookup
- If cloud matching fails, return "Unknown" provider
- Never block on single failure

## Security Considerations

- Only use public DNS and WHOIS services
- Cache cloud IP ranges to reduce external requests
- Log all queries for audit trail
- Respect rate limits
