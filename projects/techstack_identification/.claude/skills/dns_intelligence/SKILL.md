---
name: dns-intelligence
description: Extracts technology signals from DNS records (MX, TXT, NS, CNAME, SRV)
tools: Bash
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

# DNS Intelligence Skill

## Purpose

Extract technology signals from DNS records including MX, TXT, NS, CNAME, and SRV records.

## Operations

### 1. query_mx_records

Identify email provider from MX records.

**Command:**
```bash
dig +short MX {domain}
```

**MX Record Detection Patterns:**
```json
{
  "aspmx.l.google.com": {"service": "Google Workspace", "confidence": 95},
  "googlemail.com": {"service": "Google Workspace", "confidence": 95},
  "mail.protection.outlook.com": {"service": "Microsoft 365", "confidence": 95},
  "pphosted.com": {"service": "Proofpoint", "confidence": 95},
  "mimecast.com": {"service": "Mimecast", "confidence": 95},
  "mailgun.org": {"service": "Mailgun", "confidence": 95},
  "sendgrid.net": {"service": "SendGrid", "confidence": 95},
  "amazonses.com": {"service": "AWS SES", "confidence": 95},
  "mx.zoho.com": {"service": "Zoho Mail", "confidence": 95},
  "secureserver.net": {"service": "GoDaddy Email", "confidence": 90},
  "emailsrvr.com": {"service": "Rackspace Email", "confidence": 90},
  "messagelabs.com": {"service": "Symantec Email Security", "confidence": 90},
  "barracudanetworks.com": {"service": "Barracuda Email Security", "confidence": 90}
}
```

### 2. query_txt_records

Find service verification tokens in TXT records.

**Command:**
```bash
dig +short TXT {domain}
```

**TXT Record Detection Patterns:**
```json
{
  "google-site-verification=": {"service": "Google Search Console / Workspace", "confidence": 95},
  "MS=ms": {"service": "Microsoft 365", "confidence": 95},
  "facebook-domain-verification=": {"service": "Meta Business Suite", "confidence": 95},
  "atlassian-domain-verification=": {"service": "Jira/Confluence Cloud", "confidence": 95},
  "stripe-verification=": {"service": "Stripe", "confidence": 95},
  "docusign=": {"service": "DocuSign", "confidence": 95},
  "slack-domain-verification=": {"service": "Slack", "confidence": 95},
  "zendesk-domain-verification=": {"service": "Zendesk", "confidence": 95},
  "hubspot-developer-verification=": {"service": "HubSpot", "confidence": 95},
  "apple-domain-verification=": {"service": "Apple Business", "confidence": 95},
  "amazonses:": {"service": "AWS SES", "confidence": 95},
  "mailchimp": {"service": "Mailchimp", "confidence": 90},
  "pardot": {"service": "Salesforce Pardot", "confidence": 95},
  "v=spf1": {"service": "SPF Record", "confidence": 100},
  "v=DMARC1": {"service": "DMARC", "confidence": 100},
  "DKIM1": {"service": "DKIM", "confidence": 100},
  "have-i-been-pwned-verification=": {"service": "Have I Been Pwned", "confidence": 95},
  "status-page-domain-verification=": {"service": "Statuspage", "confidence": 95},
  "1password-site-verification=": {"service": "1Password", "confidence": 95}
}
```

### 3. query_ns_records

Identify DNS provider from NS records.

**Command:**
```bash
dig +short NS {domain}
```

**NS Record Detection Patterns:**
```json
{
  "cloudflare.com": {"service": "Cloudflare DNS", "confidence": 95},
  "awsdns": {"service": "AWS Route 53", "confidence": 95},
  "azure-dns.com": {"service": "Azure DNS", "confidence": 95},
  "googledomains.com": {"service": "Google Domains DNS", "confidence": 95},
  "dns.google": {"service": "Google Cloud DNS", "confidence": 95},
  "ns-cloud": {"service": "Google Cloud DNS", "confidence": 90},
  "digitalocean.com": {"service": "DigitalOcean DNS", "confidence": 95},
  "domaincontrol.com": {"service": "GoDaddy DNS", "confidence": 95},
  "name.com": {"service": "Name.com DNS", "confidence": 95},
  "namecheap.com": {"service": "Namecheap DNS", "confidence": 95},
  "dynect.net": {"service": "Oracle Dyn DNS", "confidence": 95},
  "nsone.net": {"service": "NS1 DNS", "confidence": 95},
  "ultradns.com": {"service": "UltraDNS", "confidence": 95},
  "constellix.com": {"service": "Constellix DNS", "confidence": 95}
}
```

### 4. query_cname_records

Detect CDN/hosting delegations from CNAME records.

**Command:**
```bash
dig +short CNAME {subdomain}.{domain}
```

**CNAME Detection Patterns:**
```json
{
  "cloudfront.net": {"tech": "AWS CloudFront", "type": "CDN", "confidence": 95},
  "azureedge.net": {"tech": "Azure CDN", "type": "CDN", "confidence": 95},
  "akamaiedge.net": {"tech": "Akamai", "type": "CDN", "confidence": 95},
  "fastly.net": {"tech": "Fastly", "type": "CDN", "confidence": 95},
  "cdn.cloudflare.net": {"tech": "Cloudflare CDN", "type": "CDN", "confidence": 95},
  "netlify.app": {"tech": "Netlify", "type": "Hosting", "confidence": 95},
  "vercel.app": {"tech": "Vercel", "type": "Hosting", "confidence": 95},
  "vercel-dns.com": {"tech": "Vercel", "type": "Hosting", "confidence": 95},
  "herokuapp.com": {"tech": "Heroku", "type": "PaaS", "confidence": 95},
  "pages.dev": {"tech": "Cloudflare Pages", "type": "Hosting", "confidence": 95},
  "firebaseapp.com": {"tech": "Firebase Hosting", "type": "Hosting", "confidence": 95},
  "web.app": {"tech": "Firebase Hosting", "type": "Hosting", "confidence": 95},
  "shopify.com": {"tech": "Shopify", "type": "E-commerce", "confidence": 95},
  "myshopify.com": {"tech": "Shopify", "type": "E-commerce", "confidence": 95},
  "squarespace.com": {"tech": "Squarespace", "type": "Website Builder", "confidence": 95},
  "wixsite.com": {"tech": "Wix", "type": "Website Builder", "confidence": 95},
  "ghost.io": {"tech": "Ghost", "type": "CMS", "confidence": 95},
  "webflow.io": {"tech": "Webflow", "type": "Website Builder", "confidence": 95},
  "zendesk.com": {"tech": "Zendesk", "type": "Support", "confidence": 95},
  "salesforce.com": {"tech": "Salesforce", "type": "CRM", "confidence": 95}
}
```

### 5. query_srv_records

Find enterprise services from SRV records.

**Command:**
```bash
dig +short SRV _sip._tcp.{domain}
dig +short SRV _sipfederationtls._tcp.{domain}
dig +short SRV _xmpp-server._tcp.{domain}
```

**SRV Record Detection Patterns:**
```json
{
  "_sip._tcp": {"service": "SIP/VoIP", "confidence": 80},
  "_sipfederationtls._tcp": {"service": "Microsoft Teams/Skype for Business", "confidence": 95},
  "_xmpp-server._tcp": {"service": "XMPP Server (Jabber)", "confidence": 90},
  "_caldav._tcp": {"service": "CalDAV Calendar", "confidence": 85},
  "_carddav._tcp": {"service": "CardDAV Contacts", "confidence": 85},
  "_ldap._tcp": {"service": "LDAP Directory", "confidence": 80}
}
```

## Output

```json
{
  "skill": "dns_intelligence",
  "domain": "string",
  "results": {
    "mx_records": [
      {
        "priority": "number",
        "exchange": "string",
        "service_detected": "Google Workspace",
        "confidence": 95
      }
    ],
    "txt_records": [
      {
        "value": "string",
        "service_detected": "string",
        "record_type": "verification|spf|dkim|dmarc|other",
        "confidence": "number"
      }
    ],
    "ns_records": [
      {
        "nameserver": "string",
        "service_detected": "string",
        "confidence": "number"
      }
    ],
    "cname_records": [
      {
        "subdomain": "string",
        "target": "string",
        "service_detected": "string",
        "service_type": "CDN|Hosting|PaaS|Other",
        "confidence": "number"
      }
    ],
    "srv_records": [
      {
        "service": "string",
        "protocol": "string",
        "target": "string",
        "service_detected": "string",
        "confidence": "number"
      }
    ],
    "services_summary": {
      "email_provider": "string",
      "dns_provider": "string",
      "cdn_provider": "string",
      "hosting_provider": "string",
      "third_party_services": ["array"]
    }
  },
  "evidence": [
    {
      "type": "dns_record",
      "record_type": "MX|TXT|NS|CNAME|SRV",
      "query": "string",
      "response": "string",
      "timestamp": "ISO-8601"
    }
  ]
}
```

## Rate Limiting

- DNS queries: No hard limit (local resolver)
- 2 second delay between batches of queries
- Respect DNS TTL values

## Error Handling

- NXDOMAIN: Record doesn't exist (not an error)
- SERVFAIL: DNS server error (retry once)
- Timeout: Retry with backup resolver
- Continue with partial results on failures

## Security Considerations

- Use public DNS resolvers only
- Do not attempt zone transfers
- Log all queries for audit trail
- Cache results respecting TTL
