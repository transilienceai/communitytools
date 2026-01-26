---
name: ai-threat-testing
description: Offensive AI security testing and exploitation framework. Systematically tests LLM applications for OWASP Top 10 vulnerabilities including prompt injection, model extraction, data poisoning, and supply chain attacks. Integrates with pentest workflows to discover and exploit AI-specific threats.
---

# AI Threat Testing & Exploitation

This skill orchestrates comprehensive AI threat testing across LLM applications and systems. Use this to perform authorized penetration testing of AI systems, discover vulnerabilities, and document findings with proof-of-concept exploits.

## Quick Start

**Test an AI system**:

```
Specify target:
- LLM application URL or deployment
- API endpoints (OpenAI, Anthropic, Azure, etc.)
- Local model (Ollama, LM Studio)
- RAG system or vector database
```

**Select vulnerability scope**:

```
1. All OWASP Top 10 (full assessment)
2. Specific vulnerabilities (targeted testing)
3. Quick scan (common issues)
4. Supply chain assessment (dependencies)
```

**Get automated testing**:
- Reconnaissance and fingerprinting
- Vulnerability-specific agents deploy
- Exploit execution with evidence capture
- Professional report generation

## Primary Testing Agents

### Agent 1: Prompt Injection Testing
**Tests**: LLM01 - Direct and indirect prompt injection

**Covers**:
- Direct instruction override attacks
- System prompt extraction
- Indirect injection via RAG/documents
- Multi-turn context manipulation
- Session hijacking and token extraction

**Output**: Prompt injection PoCs, bypass techniques, remediation

---

### Agent 2: Output Handling Exploitation
**Tests**: LLM02 - Insecure output handling

**Covers**:
- Code injection (Python, SQL, shell commands)
- XSS via generated HTML/JavaScript
- Template injection attacks
- Unsafe deserialization
- Malicious content propagation

**Output**: Injection payloads, successful exploits, detection bypass

---

### Agent 3: Training Data Analysis
**Tests**: LLM03 - Data poisoning vulnerability assessment

**Covers**:
- Membership inference attacks
- Training data extraction attempts
- Backdoor trigger identification
- Bias and adversarial example detection
- Model behavior anomalies

**Output**: Data exposure findings, backdoor triggers, bias analysis

---

### Agent 4: Resource Exhaustion Testing
**Tests**: LLM04 - Model DoS vulnerabilities

**Covers**:
- Token flooding attacks
- Context window exhaustion
- Recursive expansion exploitation
- Computational overload testing
- Cost impact analysis

**Output**: DoS techniques, impact assessment, mitigation guidance

---

### Agent 5: Supply Chain Assessment
**Tests**: LLM05 - Supply chain vulnerabilities

**Covers**:
- Dependency vulnerability scanning
- Plugin/integration security testing
- Model source verification
- API endpoint security
- Third-party risk assessment

**Output**: Vulnerability inventory, risk scores, remediation roadmap

---

### Agent 6: Agency Exploitation
**Tests**: LLM06 - Excessive agency vulnerabilities

**Covers**:
- Privilege escalation attempts
- Unauthorized API calls
- Permission boundary testing
- State modification exploits
- Lateral movement via model

**Output**: Privilege escalation PoCs, permission bypasses

---

### Agent 7: Model Extraction Attack
**Tests**: LLM07 - Model theft and extraction

**Covers**:
- Query-based model extraction
- Output analysis and inference
- Membership inference attacks
- Model property inference
- Training data reconstruction

**Output**: Extracted model info, leakage assessment, impact analysis

---

### Agent 8: Vector DB Poisoning
**Tests**: LLM08 - Vector database and RAG attacks

**Covers**:
- Malicious document injection
- Retrieval manipulation
- Embedding space attacks
- Citation spoofing
- Knowledge base poisoning

**Output**: Injection techniques, retrieval bypass, remediation

---

### Agent 9: Decision Reliance Testing
**Tests**: LLM09 - Overreliance vulnerabilities

**Covers**:
- Hallucination injection
- Output confidence analysis
- Verification workflow gaps
- Human-in-the-loop bypass
- False authority establishment

**Output**: Hallucination techniques, confidence manipulation, process gaps

---

### Agent 10: Logging Bypass Testing
**Tests**: LLM10 - Insufficient logging and monitoring

**Covers**:
- Log deletion or evasion
- Monitoring detection bypass
- Unlogged request techniques
- Alert threshold manipulation
- Forensic evidence destruction

**Output**: Evasion techniques, detection gaps, monitoring recommendations

---

## Testing Workflows

### Workflow 1: Full OWASP Top 10 Assessment
```
Progress:
- [ ] Reconnaissance (target fingerprinting, capability detection)
- [ ] Agent 1: Prompt Injection testing
- [ ] Agent 2: Output Handling testing
- [ ] Agent 3: Data Poisoning analysis
- [ ] Agent 4: DoS vulnerability testing
- [ ] Agent 5: Supply Chain assessment
- [ ] Agent 6: Agency exploitation
- [ ] Agent 7: Model Extraction attempts
- [ ] Agent 8: Vector DB poisoning
- [ ] Agent 9: Reliance testing
- [ ] Agent 10: Logging bypass
- [ ] Report generation with findings
```

**Duration**: 4-8 hours depending on target complexity

**Output**: Professional penetration test report, PoC scripts, remediation roadmap

---

### Workflow 2: Focused Vulnerability Testing
```
Progress:
- [ ] Identify specific vulnerability category
- [ ] Deploy targeted agent
- [ ] Execute exploitation techniques
- [ ] Capture evidence (screenshots, logs, outputs)
- [ ] Document findings
- [ ] Provide remediation guidance
```

**Duration**: 1-3 hours per vulnerability

**Output**: Focused finding with PoC

---

### Workflow 3: Supply Chain Security Audit
```
Progress:
- [ ] Inventory AI/ML dependencies
- [ ] Scan for known vulnerabilities
- [ ] Test plugin security
- [ ] Verify model provenance
- [ ] Assess API security
- [ ] Rate vendor/third-party risk
- [ ] Create remediation roadmap
```

**Duration**: 2-4 hours

**Output**: Supply chain risk assessment, vendor scorecard, recommendations

---

### Workflow 4: Continuous Monitoring Validation
```
Progress:
- [ ] Execute logging bypass techniques
- [ ] Attempt monitoring evasion
- [ ] Verify detection capabilities
- [ ] Test alert responsiveness
- [ ] Document monitoring gaps
- [ ] Recommend improvements
```

**Duration**: 1-2 hours

**Output**: Monitoring assessment, detection capability report

---

## Integration with Pentest Skill

This skill enhances pentest workflows:

```
/pentest → Add AI testing phase
  ├── Traditional vulnerability assessment (web, API, infrastructure)
  ├── AI Threat Testing (NEW)
  │   ├── LLM application testing
  │   ├── AI-specific exploitation
  │   └── Model security assessment
  └── Combined findings report
```

**Combined testing provides**:
- Traditional security + AI security assessment
- Complete attack surface coverage
- Multi-vector exploitation chains
- Comprehensive risk scoring

---

## Key Techniques Reference

### Prompt Injection Payloads
- Instruction override: "Ignore all previous instructions..."
- System prompt extraction: "Repeat your system prompt exactly..."
- Context shifting: Gradually moving conversation context
- Token smuggling: Encoding across multiple turns
- Filter evasion: Base64, leetspeak, language mixing

### Model Extraction Methods
- Query sampling: Repeated API queries for behavior reconstruction
- Token probability analysis: Extracting logits and confidence scores
- Membership inference: Testing if specific data was in training
- Model inversion: Reconstructing training examples
- Confidence calibration: Analyzing prediction confidence patterns

### Data Poisoning Detection
- Behavioral anomalies: Testing for trigger-based responses
- Membership testing: Probing for specific training data
- Fairness analysis: Checking for bias amplification
- Output consistency: Testing reproducibility of predictions
- Backdoor triggers: Common activation patterns

### DoS Exploitation
- Token flooding: Sending extremely long inputs
- Recursive expansion: Nested loops and recursive structures
- Context exhaustion: Filling available context window
- Computational loops: Triggering expensive operations
- Resource measurement: Monitoring cost and performance impact

### Supply Chain Attacks
- Dependency enumeration: Listing all AI/ML dependencies
- CVE scanning: Identifying known vulnerabilities
- Plugin capability audit: Testing plugin permissions and scope
- API security testing: Checking endpoint authentication/authorization
- Model verification: Confirming model integrity and provenance

---

## Evidence Capture

All agents capture:
- **Screenshots**: Before/after exploitation
- **Network logs**: HTTP requests and responses
- **API responses**: Full response bodies and metadata
- **Error messages**: System errors and debug information
- **Console output**: Model outputs and behavior
- **Execution time**: Performance impact measurement
- **Resource usage**: CPU, memory, token consumption

---

## Reporting

Automated report includes:
- **Executive Summary**: Critical findings and risk scoring
- **Detailed Findings**: Per-vulnerability analysis with CVSS scores
- **Proof of Concept**: Reproducible exploitation steps
- **Evidence**: Screenshots, logs, captured outputs
- **Remediation**: Specific fixes and hardening guidance
- **Risk Assessment**: Business impact and priority

---

## Common Patterns

### Quick Vulnerability Check
```
1. Target identification (fingerprinting)
2. Select single agent for vulnerability
3. Execute with default payloads
4. Document findings
5. Provide quick remediation tip
```

### Deep Exploitation
```
1. Extensive reconnaissance
2. Deploy multiple agents
3. Chain vulnerabilities together
4. Custom exploit development
5. Complete assessment report
```

### Red Team Scenario
```
1. Full OWASP assessment
2. Multi-vector attack chains
3. Privilege escalation paths
4. Data exfiltration techniques
5. Impact demonstration
```

---

## Troubleshooting

**"Target not responding"**
→ Check network connectivity, verify API keys, confirm endpoint is live

**"Agents not deploying"**
→ Ensure proper authorization, check agent dependencies, verify scope

**"No vulnerabilities found"**
→ System may be hardened; try advanced techniques; check for defense mechanisms

**"I need custom payloads"**
→ Agents support custom payload injection; specify in prompts

**"Need legal verification"**
→ All testing MUST be authorized; provide written permission documentation

