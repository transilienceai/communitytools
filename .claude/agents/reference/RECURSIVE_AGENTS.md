# Recursive Agent Spawning

Dynamically spawn agents based on discoveries.

## Exploit Chain Matrix

When vulnerability A found, automatically test for B:

| Primary Vuln | Spawn These Agents | Exploit Chain |
|--------------|-------------------|---------------|
| **SQL Injection** | Auth Bypass, Info Disclosure, Command Injection, File Upload | SQLi → Admin Access → RCE |
| **XSS** | CSRF, Clickjacking, Session Hijacking | XSS → CSRF → Account Takeover |
| **SSRF** | Cloud Metadata, IDOR, XXE | SSRF → AWS Creds → S3 Access |
| **Auth Bypass** | Access Control, Business Logic, IDOR | Auth Bypass → Admin → Full Compromise |
| **File Upload** | Path Traversal, RCE, XXE | File Upload → Webshell → Server Takeover |
| **Path Traversal** | Info Disclosure, Source Code Access | Path Traversal → Credentials → Escalation |
| **CSRF** | XSS, Clickjacking, Business Logic | CSRF → State Change → Account Takeover |
| **OAuth** | SSRF, Open Redirect, Account Linking | OAuth → Account Takeover |
| **JWT** | Auth Bypass, Privilege Escalation | JWT Forge → Admin Access |
| **GraphQL** | IDOR, Info Disclosure, Business Logic | GraphQL Introspection → IDOR |
| **WebSocket** | CSRF (CSWSH), XSS, Auth Bypass | WebSocket → Real-time Manipulation |
| **Deserialization** | RCE, Command Injection | Deserialization → RCE |
| **SSTI** | RCE, SSRF, File Read | SSTI → Server Takeover |
| **XXE** | SSRF, File Read, DoS | XXE → Internal Network Access |
| **NoSQL** | Auth Bypass, Data Extraction | NoSQL → Auth Bypass |
| **Cache Vuln** | Cache Poison → XSS, Cache Deception | Cache → Mass Compromise |

## Technology-Agent Mapping

When technology X detected, spawn agents Y:

| Technology | Spawn Agents |
|-----------|--------------|
| **GraphQL** | GraphQL, REST API, JWT, OAuth, CORS |
| **WebSocket** | WebSocket, CSRF, XSS, Authentication |
| **Node.js/Express** | Prototype Pollution, Command Injection, SSTI |
| **Django/Flask** | SSTI, SSRF, Path Traversal |
| **Java/Spring** | Deserialization, XXE, SSRF, SSTI |
| **PHP** | Command Injection, File Upload, Path Traversal |
| **.NET** | Deserialization, XXE, SSRF |
| **React/Vue/Angular** | DOM XSS, Prototype Pollution, CORS |
| **MongoDB/NoSQL** | NoSQL Injection, SSRF |
| **LLM/AI** | Web LLM, SSRF, Info Disclosure, Prompt Injection |
| **OAuth 2.0/OIDC** | OAuth, JWT, SSRF, Open Redirect |
| **JWT Auth** | JWT, Auth Bypass, CORS |
| **AWS/Cloud** | SSRF (metadata), Access Control, Info Disclosure |
| **Docker/K8s** | SSRF, Path Traversal, Info Disclosure |
| **CDN/Caching** | Cache Poisoning, Cache Deception, HTTP Smuggling |
| **XML Parser** | XXE, SSRF, DoS |
| **File Upload** | File Upload, Path Traversal, XSS, XXE |
| **LDAP/AD** | LDAP Injection, Auth Bypass |

## Asset Discovery Cascade

When new assets found, deploy full suite:

**Example: Admin Panel Discovered**
```
Path Traversal Agent finds /admin/
→ Spawn ALL 32 agents targeting /admin/*
Priority: Authentication, Access Control, Business Logic, CSRF
```

**Example: API Endpoints Enumerated**
```
REST API Agent discovers 50 endpoints via /api-docs
→ Spawn API Security Agents for each endpoint
→ Spawn Authentication Agents for each endpoint
→ Spawn Access Control Agent (test authorization)
```

**Example: New Subdomain Found**
```
Recon discovers internal.target.com
→ Treat as NEW ASSET
→ Spawn complete agent suite (all 32)
→ Check if internal has relaxed security
```

## Recursion Logic

```
Initial Deployment (32 agents)
    ↓
Discovery Event Monitoring
    ↓
Decision: Spawn Additional Agents?
    ├─ New vulnerability → Check exploit chain matrix
    ├─ New asset → Spawn full suite
    ├─ New technology → Spawn tech-specific agents
    └─ Pattern detected → Spawn pattern-testing agents
    ↓
Recursive Agent Spawning
    ↓
Monitor New Agents (recursive)
    ↓
Continue until no new discoveries for N iterations
```

## Recursion Limits

Safety constraints:
- **Max depth**: 5 levels
- **Max concurrent agents**: 200
- **Deduplication**: Don't re-test same vector
- **Scope validation**: All spawned agents inherit restrictions
- **Stop condition**: No new findings for 3 iterations

## Practical Example

```
E-commerce Application Test

Initial: Deploy 32 agents
    ↓
Finding #1: SQLi in /search?q=
    → Spawn: Auth Bypass, Info Disclosure, Command Injection
    → Result: Auth Bypass confirms SQLi login bypass
    → CRITICAL CHAIN: SQLi → Admin Access
    ↓
Finding #2: Admin panel at /admin/
    → Spawn: ALL 32 agents for /admin/*
    → Result: Business Logic flaw in admin order editing
    → CRITICAL CHAIN: SQLi → Admin → Price Manipulation
    ↓
Finding #3: GraphQL at /graphql
    → Spawn: GraphQL, JWT, Access Control, Business Logic
    → Result: IDOR in getUserOrders query
    → HIGH CHAIN: GraphQL → IDOR → Data Exposure
    ↓
Finding #4: WebSocket at wss://cart
    → Spawn: WebSocket, CSRF, XSS, Business Logic
    → Result: XSS in WebSocket messages
    → HIGH CHAIN: WebSocket XSS → Session Hijacking
    ↓
Finding #5: S3 URLs in images
    → Spawn: SSRF, Access Control, Path Traversal
    → Result: Public S3 bucket with customer PII
    → CRITICAL: Public S3 → Mass Data Exposure

Final Report: 5 Critical Exploit Chains
```

## Agent Communication

Agents report spawn recommendations:

```json
{
  "spawn_recommendations": [
    {
      "agent": "authentication-bypass-agent",
      "reason": "Test if SQLi can bypass authentication",
      "priority": "HIGH",
      "context": {"sqli_location": "/search?q=", "database": "MySQL"}
    }
  ]
}
```

Orchestrator acts on recommendations immediately.
