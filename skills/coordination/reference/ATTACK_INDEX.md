# Attack Categories Index

53 attack types organized by category. Each has reference documentation in the corresponding skill's `reference/` directory.

## Injection (6 types) → `skills/injection/reference/`
- SQL Injection | NoSQL Injection | Command Injection
- SSTI | XXE | LDAP/XPath
**Agent**: `SQL Injection Discovery Agent`, `NoSQL Injection Discovery Agent`, `SSTI Discovery Agent`, `XXE Discovery Agent`

## Client-Side (6 types) → `skills/client-side/reference/`
- XSS (Reflected/Stored/DOM) | CSRF | Clickjacking
- CORS | Prototype Pollution | DOM-based
**Agent**: `XSS Discovery Agent`, `Prototype Pollution Agent`

## Server-Side (6 types) → `skills/server-side/reference/`
- SSRF | HTTP Smuggling | Path Traversal
- File Upload | Deserialization | Host Header Injection
**Agent**: `SSRF Discovery Agent`, `Path Traversal Discovery Agent`

## Authentication (4 types) → `skills/authentication/reference/`
- Bypass | JWT | OAuth | Password Attacks (2FA)
**Agent**: `JWT Attack Discovery Agent`, `/authentication` skill

## API Security (4 types) → `skills/api-security/reference/`
- GraphQL | REST API | WebSockets | Web LLM
**Agent**: `/ai-threat-testing` skill for LLM, specialized API agents

## Web Applications (6 types) → `skills/web-app-logic/reference/`
- Business Logic | Race Conditions | Access Control
- Cache Poisoning | Cache Deception | Info Disclosure

## Cloud & Containers (5 types) → `skills/cloud-containers/reference/`
- AWS | Azure | GCP | Docker | Kubernetes

## System (3 types) → `skills/system/reference/`
- Active Directory | Privilege Escalation | Exploit Development

## IP Infrastructure (8 types) → `skills/infrastructure/reference/`
- Port Scanning | DNS | MitM | Sniffing | SMB/NetBIOS | IPv6 | VLAN Hopping | DoS/DDoS

## OSINT & Repository Recon (4 types) → `skills/osint/reference/`
- Repository Enumeration | Secret Scanning | Git History Analysis | Code Intelligence
**Agent**: `/osint` skill — run during Phase 2 (Reconnaissance) for every engagement
**Reference**: `skills/osint/reference/repository-recon.md`

## Physical & Social (1 type) → `skills/social-engineering/reference/`
- Social Engineering

## Per-Attack Documentation Structure

Each skill's `reference/` directory contains:
- `*-quickstart.md` - Immediate test vectors
- `*-cheat-sheet.md` - Common payloads & bypass techniques
- `*-resources.md` - Tools, references, advanced techniques
