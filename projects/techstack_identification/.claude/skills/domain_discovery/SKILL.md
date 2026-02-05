---
name: domain-discovery
description: Discovers official company domain via web search, WHOIS, and common TLD patterns
tools: Bash, WebSearch, WebFetch
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

# Domain Discovery Skill

## Purpose

Find and validate the official company domain using web search, WHOIS lookups, and common TLD pattern testing.

## Operations

### 1. search_official_domain

Search for the company's official website using web search engines.

**Input:**
```json
{
  "company_name": "string (required)"
}
```

**Process:**
1. Construct search query: "{company_name} official website"
2. Execute web search
3. Extract top domain results
4. Filter out social media, news sites, directories

**Search Query Templates:**
```
"{company_name}" official website
"{company_name}" homepage
site:{company_name}.com OR site:{company_name}.io
```

### 2. check_common_tlds

Test common TLD variations for the company name.

**TLD Priority Order:**
```
.com → .io → .co → .org → .net → .ai → .dev → .app
```

**Process:**
1. Normalize company name (lowercase, remove spaces/special chars)
2. Test each TLD in priority order
3. Verify domain resolves (DNS A record exists)
4. Check if homepage contains company name

**Example:**
```
Company: "Acme Corporation"
Test: acme.com, acmecorp.com, acme.io, acmecorp.io, ...
```

### 3. whois_lookup

Query WHOIS database for domains registered to the company.

**Command:**
```bash
whois {domain} | grep -i "Registrant\|Organization\|Admin"
```

**Fields to Extract:**
- Registrant Organization
- Registrant Name
- Admin Email Domain
- Creation Date
- Name Servers

### 4. validate_domain

Verify the discovered domain belongs to the target company.

**Validation Checks:**
1. Homepage title contains company name
2. Meta description mentions company
3. WHOIS registrant matches company name
4. Social media links point to expected profiles

## Output

```json
{
  "skill": "domain_discovery",
  "company": "string",
  "results": {
    "primary_domain": "string",
    "alternative_domains": ["array"],
    "validation": {
      "title_match": "boolean",
      "whois_match": "boolean",
      "confidence": "High|Medium|Low"
    },
    "whois_data": {
      "registrant": "string",
      "created": "date",
      "nameservers": ["array"]
    }
  },
  "evidence": [
    {
      "type": "search_result",
      "query": "string",
      "result": "string"
    },
    {
      "type": "whois",
      "field": "string",
      "value": "string"
    }
  ]
}
```

## Detection Patterns

### Company Name Normalization

```
"Acme Corporation" → acme, acmecorp, acme-corp
"The Widget Co." → widget, widgetco, thewidget
"ABC Technologies Inc" → abc, abctech, abctechnologies
```

### Domain Validation Signals

| Signal | Weight | Description |
|--------|--------|-------------|
| Title contains company name | +30 | Strong validation |
| WHOIS registrant matches | +40 | Definitive ownership |
| Meta description mentions | +20 | Supporting evidence |
| Social links present | +10 | Weak validation |

## Error Handling

- If no domain found via search, prompt for domain hint
- If WHOIS fails, continue with DNS-based validation
- If multiple candidates, return all with confidence scores
- Never assume - always validate ownership signals

## Rate Limiting

- Web search: 10 requests/minute
- WHOIS: 5 requests/minute
- DNS resolution: No hard limit

## Security Considerations

- Never attempt unauthorized access
- Only use public WHOIS data
- Respect robots.txt on discovered domains
- Log all queries for audit trail
