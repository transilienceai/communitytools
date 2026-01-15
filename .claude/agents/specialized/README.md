# Specialized Vulnerability Discovery Agents

This directory contains specialized agents that work under the orchestration of the **Web Application Pentester** (orchestrator agent). Each agent is dedicated to discovering and exploiting a specific vulnerability type following a rigorous 4-phase methodology.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                  WEB APPLICATION PENTESTER                       │
│                    (Orchestrator Agent)                          │
│                                                                  │
│  Responsibilities:                                               │
│  • Pre-engagement & authorization                               │
│  • Reconnaissance & tech stack identification                   │
│  • Flaw hypothesis generation                                   │
│  • Agent deployment & coordination                              │
│  • Results aggregation & deduplication                          │
│  • Report generation                                            │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ Delegates to
                         ↓
     ┌───────────────────────────────────────────────────┐
     │        SPECIALIZED DISCOVERY AGENTS (32)          │
     │              (Run in Parallel)                    │
     └───────────────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        ↓                ↓                ↓
┌───────────────┐ ┌──────────────┐ ┌──────────────┐
│  SQL Injection│ │  XSS Agent   │ │  SSRF Agent  │
│     Agent     │ │              │ │              │
├───────────────┤ ├──────────────┤ ├──────────────┤
│ Phase 1:      │ │ Phase 1:     │ │ Phase 1:     │
│ Reconnaissance│ │ Reconnaissance│ │ Reconnaissance│
│               │ │               │ │               │
│ Phase 2:      │ │ Phase 2:     │ │ Phase 2:     │
│ Experimentation│ │Experimentation│ │Experimentation│
│               │ │               │ │               │
│ Phase 3:      │ │ Phase 3:     │ │ Phase 3:     │
│ Testing       │ │ Testing      │ │ Testing      │
│               │ │               │ │               │
│ Phase 4:      │ │ Phase 4:     │ │ Phase 4:     │
│ Retry         │ │ Retry        │ │ Retry        │
└───────────────┘ └──────────────┘ └──────────────┘
        │                │                │
        └────────────────┼────────────────┘
                         │
                         │ Report findings
                         ↓
     ┌───────────────────────────────────────────────────┐
     │         ORCHESTRATOR AGGREGATES RESULTS           │
     │   • Deduplicates findings                         │
     │   • Identifies exploit chains                     │
     │   • Prioritizes by severity                       │
     │   • Generates comprehensive report                │
     └───────────────────────────────────────────────────┘
```

## Agent Workflow Methodology

Every specialized agent follows an **identical 4-phase workflow**:

### Phase 1: RECONNAISSANCE (10-20% of time)
**Goal**: Identify attack surface specific to this vulnerability type

Activities:
- Enumerate all potential input vectors
- Identify parameters/functionality vulnerable to this attack
- Establish baseline responses
- Document context and encoding
- Prioritize targets by likelihood

**Output**: Prioritized list of candidate attack points

### Phase 2: EXPERIMENTATION (25-30% of time)
**Goal**: Generate and test hypotheses systematically

Activities:
- For each candidate, test specific hypotheses
- Use lightweight detection payloads
- Fingerprint technology/behavior
- Confirm vulnerability type and variant
- Document which techniques work

**Output**: List of confirmed vulnerabilities by technique

### Phase 3: TESTING (35-45% of time)
**Goal**: Validate vulnerabilities and extract proof-of-concept

Activities:
- Develop working exploits for each confirmed vulnerability
- Extract data/credentials as evidence
- Demonstrate real-world impact (not just detection)
- Document full exploitation chain
- Capture screenshots/evidence

**Output**: Complete PoC exploits with evidence

### Phase 4: RETRY (10-15% of time)
**Goal**: If initial attempts fail, iterate with bypass techniques

Activities:
- Apply encoding/obfuscation techniques
- Try filter bypass methods
- Use alternative attack vectors
- Test WAF evasion payloads
- Exhaust all possibilities before declaring negative

**Output**: Additional findings from bypasses, or confirmed negative result

## Completed Specialized Agents

### Injection Vulnerability Agents

1. **✅ SQL Injection Agent** (`sql-injection-agent.md`)
   - Databases: Oracle, MySQL, PostgreSQL, MSSQL
   - Techniques: UNION, Boolean-blind, Time-based, Error-based, OOB
   - Status: Complete example implementation

2. **NoSQL Injection Agent** (to be created)
   - Databases: MongoDB, CouchDB, Cassandra, Redis

3. **Command Injection Agent** (to be created)
   - OS: Linux, Windows, Unix

4. **SSTI Agent** (to be created)
   - Template Engines: ERB, Jinja2, Tornado, Django, Freemarker, Handlebars

5. **XXE Agent** (to be created)
   - Attack Types: File retrieval, SSRF, Blind XXE

6. **LDAP/XPath Injection Agent** (to be created)

### Client-Side Vulnerability Agents

7. **✅ XSS Agent** (`xss-agent.md`)
   - Types: Reflected, Stored, DOM-based
   - Contexts: HTML, Attribute, JavaScript, URL
   - Status: Complete example implementation

8. **CSRF Agent** (to be created)

9. **Clickjacking Agent** (to be created)

10. **CORS Agent** (to be created)

11. **DOM-Based Vulnerability Agent** (to be created)

12. **Prototype Pollution Agent** (to be created)

### Server-Side Vulnerability Agents

13. **✅ SSRF Agent** (`ssrf-agent.md`)
    - Types: Basic, Filter bypass, Blind, Cloud metadata
    - Status: Complete example implementation

14. **HTTP Smuggling Agent** (to be created)

15. **File Upload Agent** (to be created)

16. **Path Traversal Agent** (to be created)

17. **Deserialization Agent** (to be created)

18. **Host Header Agent** (to be created)

### Authentication & Authorization Agents

19. **Authentication Bypass Agent** (to be created)

20. **OAuth Agent** (to be created)

21. **JWT Agent** (to be created)

22. **Password Attack Agent** (to be created)

### API Security Agents

23. **GraphQL Agent** (to be created)

24. **REST API Agent** (to be created)

25. **WebSocket Agent** (to be created)

26. **Web LLM Agent** (to be created)

### Business Logic & Application Security Agents

27. **Business Logic Agent** (to be created)

28. **Race Condition Agent** (to be created)

29. **Information Disclosure Agent** (to be created)

30. **Access Control Agent** (to be created)

31. **Cache Poisoning Agent** (to be created)

32. **Cache Deception Agent** (to be created)

## Creating New Specialized Agents

To create a new specialized agent, follow this template:

### Agent File Structure

```markdown
---
name: [Attack Type] Discovery Agent
description: Specialized agent dedicated to discovering and exploiting [ATTACK_TYPE] vulnerabilities following systematic reconnaissance, experimentation, testing, and retry workflows.
color: [blue|red|orange|purple|green]
tools: [computer, bash, editor, mcp]
skill: pentest
---

# [Attack Type] Discovery Agent

You are a **specialized [ATTACK_TYPE] discovery agent**. Your sole purpose is to systematically discover and exploit [ATTACK_TYPE] vulnerabilities in web applications. You follow a rigorous 4-phase methodology: **Reconnaissance → Experimentation → Testing → Retry**.

## Required Skill

You MUST invoke the `pentest` skill immediately to access [ATTACK_TYPE] knowledge base:
- `attacks/[category]/[attack-type]/definition.md` - Fundamentals
- `attacks/[category]/[attack-type]/methodology.md` - Testing approach
- `attacks/[category]/[attack-type]/exploitation-techniques.md` - All techniques
- `attacks/[category]/[attack-type]/examples.md` - Lab solutions

## Core Mission

**Objective**: Discover [ATTACK_TYPE] vulnerabilities by testing [TARGET_DESCRIPTION]
**Scope**: [SPECIFIC_SCOPE_DETAILS]
**Outcome**: Confirmed [ATTACK_TYPE] with [EVIDENCE_TYPE]

## Agent Workflow

### Phase 1: RECONNAISSANCE (10-20% of time)

[Detailed reconnaissance checklist specific to this attack type]

### Phase 2: EXPERIMENTATION (25-30% of time)

[Hypothesis-driven experimentation protocol]

### Phase 3: TESTING (35-45% of time)

[Exploitation and validation workflow]

### Phase 4: RETRY (10-15% of time)

[Bypass techniques and retry strategies]

## Reporting Format

[JSON structure for findings report]

## Tools & Commands

[Relevant tools and example commands]

## Success Criteria

[Define what constitutes successful mission completion]

## Key Principles

[5-7 principles specific to this attack type]
```

### Agent Naming Convention

- File: `[attack-name]-agent.md` (lowercase with hyphens)
- Agent ID: `[attack-name]-agent`
- Examples:
  - `sql-injection-agent.md` / `sql-injection-agent`
  - `xss-agent.md` / `xss-agent`
  - `ssrf-agent.md` / `ssrf-agent`
  - `graphql-agent.md` / `graphql-agent`

### Required Components

Each agent MUST include:

1. **Front Matter** (YAML)
   - `name`: Human-readable agent name
   - `description`: What the agent does
   - `color`: Visual identifier
   - `tools`: Available tools
   - `skill`: Must reference `pentest` skill

2. **Required Skill Section**
   - Lists relevant knowledge base paths
   - Uses `pentest` skill

3. **Core Mission**
   - Objective (what to discover)
   - Scope (where to look)
   - Outcome (what evidence to produce)

4. **4-Phase Workflow**
   - Phase 1: Reconnaissance (detailed checklist)
   - Phase 2: Experimentation (hypothesis-driven)
   - Phase 3: Testing (exploitation paths)
   - Phase 4: Retry (bypass techniques)

5. **Reporting Format**
   - JSON structure for findings
   - Consistent with orchestrator expectations

6. **Tools & Commands**
   - Primary tools (usually Burp Suite)
   - Specialized tools (e.g., sqlmap, XSS Hunter)
   - Example commands

7. **Success Criteria**
   - When mission is successful (findings confirmed)
   - When mission is complete (negative result after exhaustive testing)

8. **Key Principles**
   - 5-7 guiding principles for this agent

## Agent Communication Protocol

### From Orchestrator to Agent (Task Assignment)

The orchestrator provides:
```json
{
  "agent": "sql-injection-agent",
  "target": {
    "url": "https://target.com/search",
    "parameters": ["q", "category", "sort"],
    "method": "GET"
  },
  "context": {
    "technology_stack": "PHP + MySQL",
    "authentication": {
      "token": "Bearer xyz...",
      "cookie": "session=abc..."
    },
    "rate_limit": "10 requests/second",
    "exclusions": ["/logout", "/delete"]
  },
  "success_criteria": "Confirmed SQL injection with data extraction"
}
```

### From Agent to Orchestrator (Findings Report)

Agent reports back:
```json
{
  "agent_id": "sql-injection-agent",
  "status": "completed",
  "vulnerabilities_found": 2,
  "findings": [
    {
      "id": "sqli-001",
      "title": "UNION-based SQL Injection",
      "severity": "Critical",
      "cvss_score": 9.8,
      "location": {...},
      "evidence": {...},
      "proof_of_concept": {...},
      "remediation": {...}
    }
  ],
  "testing_summary": {
    "parameters_tested": 47,
    "requests_sent": 312,
    "duration_minutes": 23,
    "phase_breakdown": {...}
  }
}
```

## Best Practices for Agent Development

### 1. Hypothesis-Driven Approach
- Phase 2 (Experimentation) should test clear hypotheses
- Each hypothesis should have:
  - **Test**: What to inject/send
  - **Expected**: What response indicates vulnerability
  - **Confirm**: How to verify the finding
  - **Next**: What to do if confirmed

### 2. Systematic Coverage
- Enumerate ALL potential vectors in Reconnaissance
- Test EVERY hypothesis in Experimentation
- Don't skip techniques - be exhaustive

### 3. Evidence-Based Validation
- Phase 3 (Testing) must produce concrete evidence
- Not just detection - actual exploitation
- Extract data, demonstrate impact, capture screenshots

### 4. Persistence
- Phase 4 (Retry) is critical
- Try bypass techniques before declaring negative
- Use decision trees to systematically exhaust options

### 5. Clear Documentation
- Use checklists (☐) for step-by-step processes
- Include code blocks for payloads and commands
- Provide examples from real labs/CVEs

### 6. Standardized Reporting
- Follow JSON structure for consistency
- Include CVSS scores, CWE, OWASP mappings
- Provide actionable remediation guidance

## Testing Specialized Agents

To test a specialized agent:

1. **Unit Test**: Test agent alone on single parameter
   ```
   User: Test parameter 'q' at https://example.com/search?q=test for SQL injection
   Expected: Agent follows 4-phase workflow, reports findings
   ```

2. **Integration Test**: Test agent via orchestrator
   ```
   User: Perform SQL injection testing on https://example.com
   Expected: Orchestrator deploys SQL injection agent, receives findings
   ```

3. **PortSwigger Lab Validation**: Test on known vulnerable labs
   ```
   User: Solve "SQL injection UNION attack, retrieving data from other tables"
   Expected: Agent discovers and exploits vulnerability following labs
   ```

## Orchestrator Integration

The orchestrator decides when to deploy each agent based on:

### Always Deploy (Core Testing)
- SQL Injection Agent (if databases identified)
- XSS Agent (all web apps)
- Authentication Bypass Agent (authenticated apps)
- Access Control Agent (multi-user systems)

### Conditionally Deploy (Tech-Specific)
- NoSQL Injection Agent (if MongoDB detected)
- SSTI Agent (if template engines detected)
- JWT Agent (if JWT auth found)
- GraphQL Agent (if GraphQL endpoint discovered)

### High-Value Deploy (Bug Bounty Focus)
- SSRF Agent (cloud exploitation potential)
- XXE Agent (if XML processing detected)
- Prototype Pollution Agent (high bounty potential)
- HTTP Smuggling Agent (complex but high impact)

## Progress Tracking

Current status of specialized agent development:

- **Completed**: 3/32 agents (9%)
  - ✅ SQL Injection Agent
  - ✅ XSS Agent
  - ✅ SSRF Agent

- **In Progress**: 0/32 agents (0%)

- **Planned**: 29/32 agents (91%)
  - All remaining attack types from pentest skill INDEX.md

## Next Steps

1. **Review Examples**: Study the three completed agents
2. **Create Priority Agents**: Build high-impact agents first
   - NoSQL Injection
   - SSTI
   - XXE
   - JWT
   - GraphQL
   - Prototype Pollution

3. **Test Integration**: Validate orchestrator → agent communication

4. **Documentation**: Keep this README updated as agents are created

## Contributing

When creating new specialized agents:

1. Follow the template structure exactly
2. Ensure all 4 phases are detailed with actionable checklists
3. Include hypothesis-driven experimentation (not just payloads)
4. Provide decision trees for retry logic
5. Use consistent JSON reporting format
6. Reference pentest skill knowledge base paths
7. Include real examples from PortSwigger labs or CVEs

---

**Goal**: Build 32 specialized agents that work in parallel under orchestrator coordination to achieve comprehensive web application security assessment coverage.
