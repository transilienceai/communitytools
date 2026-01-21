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

## Report Generation Requirements (MANDATORY FOR ALL AGENTS)

**CRITICAL**: Every specialized agent MUST generate comprehensive testing reports in organized folders.

See `reference/REPORT_GENERATION.md` for complete guidelines. All agents generate:
- `TESTING_PROCESS.md` - Overview of testing phases
- `EXPERIMENTATION_LOG.md` - Detailed log of every test
- `HYPOTHESES_AND_RESULTS.md` - All hypotheses with results
- `METHODOLOGY.md` - Testing methodology applied
- `summary/findings-summary.md` - Executive summary
- `summary/statistics.md` - Testing statistics and metrics
- Individual `finding-NNN/` folders with complete documentation

**Quick navigation**:
- Start here: `reference/REPORTING_STANDARDS_SUMMARY.md`
- Complete guide: `reference/REPORT_GENERATION.md`
- Update template: `reference/AGENT_UPDATE_TEMPLATE.md`
- Real example: `reference/EXAMPLE_REPORT_OUTPUT.md`
- Implementation: `reference/IMPLEMENTATION_GUIDE.md`
- Index: `reference/REPORTING_INDEX.md`

## PoC Verification Requirements (MANDATORY FOR ALL AGENTS)

**CRITICAL**: Every specialized agent MUST follow PoC verification requirements.

See `POC_REQUIREMENTS.md` in this directory for complete guidelines.

### Key Requirements

**A vulnerability is NOT verified unless**:
1. Working PoC script exists (poc.py or poc.sh)
2. PoC was tested and succeeded
3. poc_output.txt proves successful exploitation
4. workflow.md documents manual steps
5. description.md explains the attack
6. report.md provides comprehensive analysis

**Folder Structure**: `findings/finding-NNN/`
```
finding-001/
├── poc.py              # Verified, tested exploit script
├── poc_output.txt      # Proof of successful execution
├── workflow.md         # Manual exploitation steps
├── description.md      # Attack technical details
└── report.md           # Complete vulnerability report
```

**Do NOT report vulnerabilities without**:
- ❌ Working, tested PoC script
- ❌ Proof of execution (poc_output.txt)
- ❌ Complete documentation

**PoC Development Process**:
1. Discover potential vulnerability
2. Develop PoC script using template
3. Test PoC - MUST succeed
4. Capture output with timestamp
5. Document workflow and description
6. Create complete report
7. Only then report to orchestrator

## Browser Automation (Playwright MCP)

**Available for client-side agents**: XSS, CSRF, DOM-based, Clickjacking, CORS, Prototype Pollution

**Use Playwright when**:
- Testing DOM-based vulnerabilities
- Testing Single Page Applications (SPAs)
- Automating multi-step exploits
- Capturing screenshot/video evidence
- Testing JavaScript-heavy applications
- Verifying client-side impact

**Key Capabilities**:
- Navigate pages: `playwright_navigate(url)`
- Fill forms: `playwright_fill(selector, value)`
- Click elements: `playwright_click(selector)`
- Execute JS: `playwright_evaluate(script)`
- Screenshots: `playwright_screenshot(path)`
- Network monitoring

**See**: `/pentest` skill → `attacks/essential-skills/playwright-automation.md` for complete guide
