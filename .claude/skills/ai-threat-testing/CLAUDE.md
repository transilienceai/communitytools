# AI Threat Testing Skill - Claude Context

Auto-loaded context when working with AI Threat Testing skill.

## Skill Purpose

Offensive AI security testing framework for systematically discovering and exploiting OWASP LLM Top 10 vulnerabilities. Integrates with pentest workflows to provide comprehensive AI-specific threat testing and professional vulnerability reporting.

## Key Files

### Core Documentation
- **SKILL.md** (389 lines) - Comprehensive testing workflows, agent descriptions, techniques reference
- **README.md** - User guide with features, quick start, integration with pentest skill
- **CLAUDE.md** - This file (auto-loaded context for working with agents)

### Agent Files (agents/ directory)
Each agent focuses on one OWASP LLM vulnerability:
- **llm01-prompt-injection.md** - Direct/indirect prompt injection, system prompt extraction
- **llm02-insecure-output.md** - Code/XSS injection, unsafe deserialization
- **llm03-training-poisoning.md** - Membership inference, backdoors, data extraction
- **llm04-resource-exhaustion.md** - Token flooding, DoS, cost impact
- **llm05-supply-chain.md** - Dependency scanning, plugin security, model verification
- **llm06-excessive-agency.md** - Privilege escalation, unauthorized actions, lateral movement
- **llm07-model-extraction.md** - Query-based extraction, model theft, data reconstruction
- **llm08-vector-poisoning.md** - RAG injection, retrieval manipulation, embedding attacks
- **llm09-overreliance.md** - Hallucination testing, confidence manipulation, verification bypass
- **llm10-logging-bypass.md** - Logging gaps, monitoring evasion, forensic analysis

## Core Workflows

### Workflow 1: Full OWASP Assessment
**When**: Complete penetration test required

**Steps**:
1. Target identification (fingerprinting)
2. Deploy all 10 agents sequentially
3. Execute exploitation techniques
4. Capture comprehensive evidence
5. Generate professional report

**Duration**: 4-8 hours

**Output**: Full penetration test report with CVSS scoring

---

### Workflow 2: Focused Vulnerability Testing
**When**: Specific vulnerability suspected or remediation verification

**Steps**:
1. Identify target vulnerability (LLM01-10)
2. Deploy specific agent
3. Execute exploitation
4. Document findings
5. Provide remediation

**Duration**: 1-3 hours

**Output**: Focused vulnerability finding with PoC

---

### Workflow 3: Supply Chain Audit
**When**: Dependencies and integrations need security assessment

**Steps**:
1. Run LLM05 Supply Chain agent
2. Scan all dependencies for CVEs
3. Test plugin security
4. Verify model provenance
5. Rate vendor/third-party risk

**Duration**: 2-4 hours

**Output**: Supply chain risk assessment with remediation

---

### Workflow 4: Monitoring & Detection Testing
**When**: Evaluating logging and monitoring effectiveness

**Steps**:
1. Run LLM10 Logging Bypass agent
2. Attempt evasion techniques
3. Test detection capabilities
4. Identify gaps
5. Recommend improvements

**Duration**: 1-2 hours

**Output**: Monitoring assessment with detection gaps identified

---

## Agent Deployment Pattern

Each agent follows this pattern:

```
Agent → Reconnaissance → Exploitation → Evidence Capture → Reporting

1. RECONNAISSANCE
   - Identify attack surface
   - Determine target capabilities
   - Assess defense mechanisms

2. EXPLOITATION
   - Deploy attack techniques specific to vulnerability
   - Attempt multiple payload variations
   - Document successful exploits

3. EVIDENCE CAPTURE
   - Screenshots before/after
   - Network/API logs
   - Proof-of-concept scripts
   - Execution metrics

4. REPORTING
   - CVSS vulnerability score
   - Detailed finding description
   - Reproducible exploitation steps
   - Remediation guidance
```

## Integration with Pentest Skill

This skill enhances `/pentest` with AI-specific testing:

```
Traditional Pentest
  ├── Web/API vulnerabilities
  ├── Infrastructure security
  └── Authentication/authorization

+ AI Threat Testing (NEW)
  ├── Prompt injection
  ├── Model extraction
  ├── Supply chain
  ├── Output handling
  └── ... (all OWASP Top 10)

= Comprehensive Security Assessment
```

**Combined Testing Benefits**:
- Complete attack surface coverage
- Multi-vector exploitation chains
- Both traditional + AI vulnerability classes
- Combined CVSS risk scoring
- Unified findings report

## Key Techniques by Agent

### LLM01: Prompt Injection
- Instruction override ("Ignore previous instructions...")
- System prompt extraction
- Indirect RAG/document injection
- Multi-turn context manipulation
- Session hijacking
- Encoding evasion (Base64, ROT13, leetspeak)

### LLM02: Output Handling
- Code injection (Python, SQL, shell)
- XSS via generated HTML/JavaScript
- Template injection
- Unsafe deserialization
- Command injection

### LLM03: Training Poisoning
- Membership inference
- Backdoor trigger detection
- Bias amplification analysis
- Training data extraction
- Model behavior anomaly detection

### LLM04: Resource Exhaustion
- Token flooding (millions of tokens)
- Recursive expansion attacks
- Context window exhaustion
- Computational overload
- Cost impact analysis

### LLM05: Supply Chain
- Dependency CVE scanning
- Plugin permission auditing
- Model integrity verification
- API security testing
- Vendor risk assessment

### LLM06: Excessive Agency
- Privilege escalation testing
- Unauthorized API calls
- Permission boundary fuzzing
- State modification exploitation
- Lateral movement vectors

### LLM07: Model Extraction
- Query-based model extraction
- Membership inference
- Token probability analysis
- Model property inference
- Training data reconstruction

### LLM08: Vector Poisoning
- Malicious document injection
- Retrieval manipulation
- Embedding space attacks
- Citation spoofing
- Knowledge base poisoning

### LLM09: Overreliance
- Hallucination injection
- Confidence manipulation
- Verification process bypass
- False authority establishment
- Decision impact quantification

### LLM10: Logging Bypass
- Unlogged endpoint discovery
- Evasion technique development
- Alert threshold avoidance
- Forensic gap identification
- Log integrity testing

## Evidence Quality Standards

All agents must capture:

**Technical Evidence**:
- Network logs (HTTP/API requests and responses)
- Exploit payloads (exact strings used)
- Model outputs (complete responses)
- Execution metrics (latency, resource usage)
- Error messages and debug info

**Visual Evidence**:
- Before/after screenshots
- Exploitation timeline screenshots
- Dashboard/monitoring screenshots
- Output comparison visuals

**Reproducibility**:
- Step-by-step exploitation instructions
- Exact payloads and parameters
- Timing and sequencing
- Environment requirements
- Success criteria

## Reporting Standards

All findings must include:

**Executive Summary**:
- Vulnerability title and OWASP classification
- CVSS v3.1 score
- Business impact assessment
- Executive-level explanation

**Technical Details**:
- Detailed vulnerability description
- Attack vector explanation
- Proof of concept with evidence
- Root cause analysis
- Affected components

**Remediation**:
- Specific technical fixes
- Implementation guidance
- Testing procedures
- Priority and timeline
- Long-term hardening recommendations

## Authorization & Legal

**CRITICAL CHECKLIST**:
- ✅ Written authorization from system owner
- ✅ Defined scope and boundaries
- ✅ Agreed testing timeline
- ✅ Signed authorization agreement
- ✅ Isolated test environment preferred
- ✅ No production data testing
- ✅ Incident contact established

## Common Questions

**"How do I start testing?"**
→ Run `/ai-threat-testing`, specify target, select scope (full/focused/supply-chain)

**"Which agent should I run first?"**
→ Start with LLM01 (Prompt Injection) - most common vulnerability, quick wins

**"Can I run agents in parallel?"**
→ Yes, agents are independent; parallelize to reduce testing time

**"What if target has defenses?"**
→ Agents include bypass techniques; document defensive measures as findings

**"How do I integrate with existing pentest?"**
→ Add AI testing phase after traditional assessment; combine findings

**"What evidence should I capture?"**
→ Screenshots, API logs, payloads, exploitation steps, metrics; see Evidence Quality Standards

**"How long does a full assessment take?"**
→ 4-8 hours depending on target complexity and defense mechanisms

**"Can I customize payloads?"**
→ Yes, agents support custom payload injection; specify in prompts

## Quick Reference

**Skill activation**: `/ai-threat-testing`

**Common commands**:
- Full OWASP assessment
- Test specific vulnerability (LLM01-10)
- Supply chain audit only
- Monitoring/detection testing
- Custom scope targeting

**Output location**: `outputs/` directory in skill

**Evidence checklist**: Screenshots, logs, PoC scripts, metrics

**Report formats**: Executive summary + detailed findings + remediation

## Maintenance & Updates

**Emerging techniques**:
- Monitor OWASP Gen AI Security Project
- Check arXiv for latest research
- Review new CVEs affecting AI systems
- Update agent techniques as new methods discovered

**Defenses evolution**:
- Document new defense mechanisms found
- Develop bypass techniques
- Share findings with security community
- Update agent playbooks

