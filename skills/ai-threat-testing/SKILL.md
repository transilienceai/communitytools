---
name: ai-threat-testing
description: Offensive AI security testing and exploitation framework. Systematically tests LLM applications for OWASP Top 10 vulnerabilities including prompt injection, model extraction, data poisoning, and supply chain attacks. Integrates with pentest workflows to discover and exploit AI-specific threats.
---

# AI Threat Testing

Test LLM applications for OWASP LLM Top 10 vulnerabilities using 10 specialized agents. Use for authorized AI security assessments.

## Quick Start

```
1. Specify target (LLM app URL, API endpoint, or local model)
2. Select scope: Full OWASP Top 10 | Specific vulnerability | Supply chain
3. Agents deploy, test, capture evidence
4. Professional report with PoCs generated
```

## Coverage — OWASP LLM Top 10, 2025 edition

**Which file addresses which category is decided by
[`reference/catalog/llm-top10-2025.json`](reference/catalog/llm-top10-2025.json), not by the
filename.** The `llmNN-` prefixes on disk predate the 2025 renumbering and no longer match; the
content is correct, the labels were not. Cite an id only with its edition (`LLM06:2025`), because a
bare `LLM06` means two different categories depending on which edition the reader assumes.

| Category | Attack surface |
|---|---|
| `LLM01:2025` Prompt Injection | Direct and indirect injection, instruction override, filter evasion |
| `LLM02:2025` Sensitive Information Disclosure | Training-data and cross-tenant RAG leakage, canary verification |
| `LLM03:2025` Supply Chain | Dependency CVEs, model provenance, malicious serialized models |
| `LLM04:2025` Data and Model Poisoning | Backdoor triggers, membership inference, behavioural anomalies |
| `LLM05:2025` Improper Output Handling | Code/XSS injection downstream, unsafe deserialization |
| `LLM06:2025` Excessive Agency | Tool/plugin abuse, privilege escalation, unauthorised actions — the category that matters for **agents** rather than chatbots |
| `LLM07:2025` System Prompt Leakage | **Gap — no playbook yet.** See the catalogue: what the prompt *contains* is a separate finding from whether it can be extracted |
| `LLM08:2025` Vector and Embedding Weaknesses | RAG injection, retrieval manipulation, embedding inversion |
| `LLM09:2025` Misinformation | Hallucination and confidence manipulation where output is relied upon |
| `LLM10:2025` Unbounded Consumption | Token flooding, cost impact, and **model extraction/theft** (2025 treats extraction-by-query as a consumption problem) |

Two classes are testable but are **not** OWASP categories, so they carry local `TX-` ids rather than
an invented `LLMnn`: monitoring evasion / forensic gaps, and adversarial perturbation of non-text
input. `tools/test_llm_numbering.py` enforces that separation.

## Workflows

**Full Assessment** (4-8 hours):
```
- [ ] Reconnaissance
- [ ] Deploy all 10 agents
- [ ] Execute exploits
- [ ] Capture evidence
- [ ] Generate report
```

**Focused Testing** (1-3 hours):
```
- [ ] Select a category from the catalogue (LLM01:2025 .. LLM10:2025, or a TX- local class)
- [ ] Deploy agent
- [ ] Execute techniques
- [ ] Document findings
```

**Supply Chain Audit** (2-4 hours):
```
- [ ] Inventory dependencies
- [ ] Scan CVEs
- [ ] Test plugins/APIs
- [ ] Verify model provenance
```

## Integration

Enhances `/pentest` with AI-specific testing:
- Traditional pentesting + AI threat testing = complete security assessment
- Chain vulnerabilities across traditional and AI vectors
- Unified reporting with CVSS scores

## Key Techniques

**Prompt Injection**: Instruction override, system prompt extraction, filter evasion
**Model Extraction**: Query sampling, token analysis, membership inference
**Data Poisoning**: Behavioral anomalies, backdoor triggers, bias analysis
**DoS**: Token flooding, recursive expansion, context exhaustion
**Supply Chain**: CVE scanning, plugin audit, model verification
**MCP Tool Abuse**: MCP server inspectors/debuggers often expose `/api/mcp/connect` or similar endpoints that accept `serverConfig` with arbitrary `command` parameters — unauthenticated RCE. Check for MCP Inspector, MCP Playground, or any MCP debugging UI on non-standard ports (6274, 3000, etc.).

## Evidence Capture

All agents collect: screenshots, network logs, API responses, errors, console output, execution metrics.

## Reporting

Automated reports include: executive summary, detailed findings (CVSS scores), PoC scripts, evidence, remediation guidance.

## Critical Rules

- Written authorization REQUIRED before testing
- Never exceed defined scope
- Test in isolated environments when possible
- Document all findings with reproducible PoCs
- Follow responsible disclosure practices

## Integration

- Integrates with `/pentest` skill for comprehensive security testing
- AI-specific vulnerability knowledge in `/AGENTS.md`
- Attack playbooks in `reference/llm0X-*.md`
