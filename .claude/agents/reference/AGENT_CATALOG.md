# Agent Catalog

Complete list of specialized agents for web application testing.

## Injection Vulnerability Agents (6)

1. **sql-injection-agent.md** - SQL injection (MySQL, PostgreSQL, MSSQL, Oracle)
2. **nosql-injection-agent.md** - NoSQL injection (MongoDB, CouchDB, Cassandra)
3. **command-injection-agent.md** - OS command injection
4. **ssti-agent.md** - Server-side template injection (Jinja2, ERB, etc.)
5. **xxe-agent.md** - XML external entity injection
6. **ldap-xpath-injection-agent.md** - LDAP/XPath injection

## Client-Side Vulnerability Agents (6)

7. **xss-agent.md** - Cross-site scripting (reflected, stored, DOM)
8. **csrf-agent.md** - Cross-site request forgery
9. **cors-agent.md** - CORS misconfiguration
10. **clickjacking-agent.md** - UI redress attacks
11. **dom-based-agent.md** - DOM-based vulnerabilities
12. **prototype-pollution-agent.md** - JavaScript prototype pollution

## Server-Side Vulnerability Agents (6)

13. **ssrf-agent.md** - Server-side request forgery
14. **file-upload-agent.md** - Insecure file upload
15. **path-traversal-agent.md** - Directory traversal
16. **deserialization-agent.md** - Unsafe deserialization
17. **http-smuggling-agent.md** - HTTP request smuggling
18. **host-header-agent.md** - Host header injection

## Authentication & Authorization Agents (4)

19. **authentication-bypass-agent.md** - Authentication bypass
20. **oauth-agent.md** - OAuth/OIDC vulnerabilities
21. **jwt-agent.md** - JWT attacks
22. **password-attack-agent.md** - Password policy testing

## API Security Agents (4)

23. **graphql-agent.md** - GraphQL vulnerabilities
24. **rest-api-agent.md** - REST API security
25. **websocket-agent.md** - WebSocket security
26. **web-llm-agent.md** - LLM integration vulnerabilities

## Business Logic & Application Security Agents (6)

27. **business-logic-agent.md** - Business logic flaws
28. **race-condition-agent.md** - Race conditions/TOCTOU
29. **information-disclosure-agent.md** - Information leakage
30. **access-control-agent.md** - IDOR, BFLA, privilege escalation
31. **cache-poisoning-agent.md** - Web cache poisoning
32. **cache-deception-agent.md** - Web cache deception

## Agent Locations

All agents in: `.claude/agents/specialized/[agent-name].md`

## Agent Characteristics

All agents follow:
- 4-phase workflow (Reconnaissance → Experimentation → Testing → Retry)
- PoC verification requirements (see `POC_REQUIREMENTS.md`)
- Output standards (see `/.claude/OUTPUT_STANDARDS.md`)
- Ethical testing principles
