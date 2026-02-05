# AI Threat Testing & Exploitation

Offensive AI security testing framework for systematic penetration testing of LLM applications and AI systems. Discovers and exploits OWASP LLM Top 10 vulnerabilities with automated agents and professional reporting.

## Overview

Test LLM applications for:
- **Prompt injection** attacks (direct and indirect)
- **Output handling** vulnerabilities (code/XSS injection)
- **Training data poisoning** and backdoors
- **Model denial of service** (resource exhaustion)
- **Supply chain** vulnerabilities
- **Excessive agency** (privilege escalation)
- **Model theft** (extraction attacks)
- **Vector database** poisoning
- **Overreliance** vulnerabilities
- **Insufficient logging** gaps

## Quick Start

```bash
# Start AI threat testing
/ai-threat-testing

# Specify target (choose one):
- LLM application URL: https://example.com/ai-chat
- API endpoint: OpenAI, Anthropic, Azure, local model
- RAG system with vector database
- Integrated AI feature in web/mobile app

# Select scope:
- Full OWASP Top 10 assessment
- Specific vulnerability class
- Quick vulnerability scan
- Supply chain audit
```

## Key Features

### 10 Specialized Agents
Each agent focuses on one OWASP LLM vulnerability with:
- Automated exploitation techniques
- Evidence capture and documentation
- Custom payload support
- Bypass technique development
- Remediation guidance

### Complete Assessment Coverage
- **Reconnaissance**: Target fingerprinting and capability detection
- **Exploitation**: Systematic vulnerability testing
- **Evidence**: Professional PoC with reproducible steps
- **Reporting**: Executive summary with CVSS scores
- **Remediation**: Specific hardening guidance

### Integration with Pentest
Works alongside the pentest skill to provide:
- Traditional web/API vulnerability testing
- AI-specific threat assessment
- Multi-vector attack chains
- Combined findings report

## Agents Included

| Agent | OWASP # | Focus | Output |
|-------|---------|-------|--------|
| Prompt Injection | LLM01 | Direct/indirect injection, system prompt extraction | Injection payloads, bypass techniques |
| Output Handling | LLM02 | Code/XSS injection, unsafe deserialization | Injection exploits, filter bypasses |
| Data Poisoning | LLM03 | Membership inference, backdoor detection, bias analysis | Data exposure findings, trigger identification |
| Resource Exhaustion | LLM04 | Token flooding, context exhaustion, DoS | DoS techniques, cost impact analysis |
| Supply Chain | LLM05 | Dependency scanning, plugin security, model verification | Vulnerability inventory, risk scores |
| Agency Exploitation | LLM06 | Privilege escalation, unauthorized API calls, boundary testing | Escalation PoCs, permission bypasses |
| Model Extraction | LLM07 | Query-based extraction, membership inference, model property inference | Extracted model info, leakage assessment |
| Vector DB Poisoning | LLM08 | Malicious injection, retrieval manipulation, embedding attacks | Injection techniques, remediation guidance |
| Reliance Testing | LLM09 | Hallucination injection, confidence manipulation, verification gaps | Hallucination techniques, process improvements |
| Logging Bypass | LLM10 | Log evasion, monitoring bypass, detection gaps | Evasion techniques, monitoring recommendations |

## Usage Workflows

### Full Assessment
```
1. Target specification
2. Run all 10 agents
3. Chain findings for multi-vector attacks
4. Generate comprehensive report
5. Provide remediation roadmap

Duration: 4-8 hours
Output: Professional penetration test report
```

### Focused Testing
```
1. Select specific vulnerability
2. Deploy targeted agent
3. Execute exploitation
4. Document findings
5. Provide quick fix

Duration: 1-3 hours
Output: Focused vulnerability report with PoC
```

### Supply Chain Audit
```
1. Inventory dependencies
2. Scan vulnerabilities
3. Verify model provenance
4. Test plugin/API security
5. Rate vendor risk

Duration: 2-4 hours
Output: Supply chain risk assessment
```

### Continuous Monitoring Check
```
1. Attempt monitoring evasion
2. Test detection capabilities
3. Verify alert responsiveness
4. Identify logging gaps
5. Recommend improvements

Duration: 1-2 hours
Output: Monitoring assessment report
```

## Integration with Pentest Skill

Enhance penetration testing with AI threat assessment:

```
Traditional Pentest
    ↓
    + AI Threat Testing
    ↓
Complete Security Assessment
(traditional + AI vulnerabilities + combined attack vectors)
```

## Evidence Capture

Each agent automatically captures:
- Screenshots (before/after)
- Network logs and API responses
- Error messages and debug info
- Execution metrics
- Resource consumption
- Proof-of-concept scripts

## Professional Reporting

Automated reports include:
- Executive summary with risk scoring
- Detailed findings per vulnerability
- CVSS vulnerability scores
- Reproducible PoC steps
- Evidence screenshots and logs
- Specific remediation guidance
- Business impact assessment
- Priority and timeline recommendations

## Authorization & Legal

**IMPORTANT**: All testing must be properly authorized.

Before testing:
- ✅ Obtain written permission from system owner
- ✅ Define scope clearly
- ✅ Establish testing timeline
- ✅ Document authorization agreement
- ✅ Use isolated test environments when possible

## Techniques & Methods

### Prompt Injection
- Instruction override attacks
- System prompt extraction
- Indirect injection via RAG/documents
- Multi-turn context manipulation
- Session hijacking and token extraction

### Model Extraction
- Query-based behavior reconstruction
- Token probability analysis
- Membership inference
- Model property inference
- Training data reconstruction

### Supply Chain Testing
- Dependency vulnerability scanning
- Plugin capability auditing
- API security verification
- Model integrity checking
- Vendor risk assessment

### Advanced Exploitation
- Multi-vector attack chains
- Privilege escalation sequences
- Data exfiltration techniques
- Persistence mechanisms
- Detection and monitoring bypass

## Tools & Integration

**Integrates with**:
- Pentest skill (for combined testing)
- Existing penetration testing workflows
- Vulnerability management platforms
- CVSS scoring systems
- Report generation tools

**Supports**:
- OpenAI API
- Anthropic API
- Azure OpenAI
- Local LLM deployments (Ollama, LM Studio)
- Custom API endpoints
- RAG systems and vector databases

## Output Examples

**Quick Finding**:
```
Vulnerability: Prompt Injection (LLM01)
CVSS Score: 9.1 (Critical)
Description: Direct prompt injection possible via user input
Proof of Concept: [PoC script provided]
Remediation: Implement input validation and parametrized prompts
```

**Full Assessment Report**:
```
Executive Summary: 7 critical findings, 12 high, 8 medium
Findings by Vulnerability:
  - LLM01 Prompt Injection: CRITICAL (CVSS 9.1)
  - LLM02 Output Handling: HIGH (CVSS 7.8)
  - LLM05 Supply Chain: MEDIUM (CVSS 5.2)
  [... detailed findings for each agent ...]
Remediation Roadmap: 30-day priority fixes
Risk Assessment: Complete attack surface coverage
```

## Troubleshooting

**Issues and Solutions**:
- Agent won't deploy: Check authorization, verify API keys
- No vulnerabilities found: System may be hardened; try advanced techniques
- Need custom payloads: Agents support custom payload injection
- Want specific test: Specify vulnerability class or technique
- Legal concerns: Ensure written authorization before testing

## Learning Resources

**OWASP References**:
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Prompt Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)

**Standards**:
- NIST AI Risk Management Framework
- CVSS v3.1 Scoring
- CWE/CAPEC mappings

## Support & Updates

For updated techniques and emerging vulnerabilities:
- Check OWASP Gen AI Security Project
- Follow academic research (arXiv)
- Review latest CVEs and exploits
- Contribute findings to security community

