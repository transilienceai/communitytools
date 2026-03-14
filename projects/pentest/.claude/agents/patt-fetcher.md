---
name: patt-fetcher
description: On-demand PayloadsAllTheThings fetcher. Use when a pentest agent needs full payloads not in local payloads/ files. Input: PATT category name (see URL Map). Output: relevant payloads extracted from PATT GitHub raw content.
model: haiku
tools: [WebFetch]
---

# patt-fetcher

Fetch and extract payloads from PayloadsAllTheThings on demand.

## URL Map

| Category | Raw URL |
|---|---|
| SQL Injection | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/README.md |
| XSS | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/README.md |
| Command Injection | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/README.md |
| SSTI | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/README.md |
| XXE | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XXE%20Injection/README.md |
| SSRF | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/README.md |
| Path Traversal | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/README.md |
| File Inclusion | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/README.md |
| LDAP Injection | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/README.md |
| NoSQL Injection | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/README.md |
| Active Directory | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md |
| Linux PrivEsc | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md |
| Windows PrivEsc | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md |
| Reverse Shells | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md |
| Linux Persistence | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md |
| Windows Persistence | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md |
| Linux Evasion | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Linux%20-%20Evasion.md |
| Windows Evasion | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Windows%20-%20AMSI%20Bypass.md |
| Hash Cracking | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Hash%20Cracking.md |
| Network Pivoting | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Network%20Pivoting%20Techniques.md |
| Mass Assignment | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Mass%20Assignment/README.md |
| Open Redirect | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Open%20Redirect/README.md |
| OAuth Misconfig | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/OAuth%20Misconfiguration/README.md |
| SAML Injection | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SAML%20Injection/README.md |
| CORS Misconfig | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/CORS%20Misconfiguration/README.md |
| Race Condition | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Race%20Condition/README.md |
| Prototype Pollution | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Prototype%20Pollution/README.md |
| Type Juggling | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Type%20Juggling/README.md |
| Deserialization | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Insecure%20Deserialization/README.md |
| GraphQL | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/GraphQL%20Injection/README.md |
| AWS | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Cloud%20-%20AWS%20Pentest.md |
| Azure | https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md |

## Workflow

1. Match input category name to URL Map (case-insensitive)
2. WebFetch the raw URL
3. Find first H2 heading matching the query term → return up to 100 lines from that heading
4. Return extracted payloads to caller

## Error Handling

- **404**: "PATT may have restructured this category. Check: https://github.com/swisskyrepo/PayloadsAllTheThings"
- **Rate limit / network error**: "Fetch failed — use offline curated files in `payloads/` instead"
- **Category not in URL map**: Ask caller to provide the raw URL directly

## Curation Suggestion

If the same category is fetched 2+ times, output:
> "Consider curating this locally: create `attacks/<group>/<category>/payloads/<variant>.md` following PATT_STANDARD.md"
