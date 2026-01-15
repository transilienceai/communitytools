# Specialized Security Testing Agents

Specialized agents for testing specific vulnerability types. These agents are orchestrated by higher-level agents like `pentester` or skill commands.

## Agent Categories

**Access Control:**
- `access-control-agent.md` - IDOR, BFLA, vertical/horizontal privilege escalation
- `authentication-bypass-agent.md` - Auth bypass techniques

**Injection Attacks:**
- `sql-injection-agent.md` - SQL injection (all databases)
- `nosql-injection-agent.md` - NoSQL injection (MongoDB, etc.)
- `command-injection-agent.md` - OS command injection
- `ssti-agent.md` - Server-side template injection
- `xxe-agent.md` - XML external entity injection
- `ldap-xpath-injection-agent.md` - LDAP/XPath injection

**Client-Side Attacks:**
- `xss-agent.md` - Cross-site scripting (reflected, stored, DOM)
- `csrf-agent.md` - Cross-site request forgery
- `cors-agent.md` - CORS misconfiguration
- `clickjacking-agent.md` - Clickjacking attacks
- `dom-based-agent.md` - DOM-based vulnerabilities
- `prototype-pollution-agent.md` - JavaScript prototype pollution

**Server-Side Attacks:**
- `ssrf-agent.md` - Server-side request forgery
- `http-smuggling-agent.md` - HTTP request smuggling
- `file-upload-agent.md` - Insecure file upload
- `path-traversal-agent.md` - Path traversal / directory disclosure
- `deserialization-agent.md` - Insecure deserialization
- `host-header-agent.md` - Host header injection

**API Security:**
- `graphql-agent.md` - GraphQL vulnerabilities
- `rest-api-agent.md` - REST API security testing
- `jwt-agent.md` - JWT vulnerabilities
- `oauth-agent.md` - OAuth/OAuth2 flaws
- `websocket-agent.md` - WebSocket security

**Application Logic:**
- `business-logic-agent.md` - Business logic flaws
- `race-condition-agent.md` - Race conditions/TOCTOU
- `password-attack-agent.md` - Password attacks
- `cache-poisoning-agent.md` - Web cache poisoning
- `cache-deception-agent.md` - Web cache deception
- `information-disclosure-agent.md` - Information disclosure

**Emerging Threats:**
- `web-llm-agent.md` - LLM/AI-related vulnerabilities

## Usage Pattern

These agents follow a systematic approach:
1. **Reconnaissance** - Identify potential attack surface
2. **Experimentation** - Try various payloads and techniques
3. **Testing** - Validate findings with proof-of-concept
4. **Retry** - Iterate with different approaches if needed

IMPORTANT: All testing MUST be authorized. These agents refuse destructive operations and require proper authorization context.
