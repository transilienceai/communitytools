# Specialized Agent Update Template

This template shows how to add the Report Generation section to EVERY specialized pentest agent.

## Required Addition to All Agent Files

Add this section to EVERY specialized agent markdown file (e.g., `xss-agent.md`, `sql-injection-agent.md`, etc.) in the appropriate location within the agent definition.

### Location in Agent File

Add this section **AFTER the workflow phases** and **BEFORE the tools section**, or as a separate "Reporting" section near the end of the agent definition.

### Template Section to Add

```markdown
## Report Generation & Documentation

### Comprehensive Testing Reports

This agent generates detailed, organized testing reports during execution:

#### Generated Reports

**Phase Overview Documents** (required for all executions):

1. **TESTING_PROCESS.md**
   - High-level overview of all testing phases
   - Summary of what was tested and when
   - Key achievements and statistics
   - Recommendations for remediation

2. **EXPERIMENTATION_LOG.md**
   - Detailed record of every test performed
   - Each experiment with hypothesis, payload, and result
   - Evidence references and analysis
   - Complete experiment statistics

3. **HYPOTHESES_AND_RESULTS.md**
   - All hypotheses tested during assessment
   - Pass/fail results for each hypothesis
   - Technical basis and testing approach
   - Impact analysis for each hypothesis

4. **METHODOLOGY.md**
   - Systematic testing approach applied
   - Testing phases and techniques used
   - Tools, payloads, and techniques
   - Compliance with security frameworks (PTES, OWASP, etc.)
   - Metrics and statistics

**Summary Reports**:

5. **summary/findings-summary.md**
   - Executive summary of all findings discovered
   - Risk heat map and severity distribution
   - Top findings with business impact
   - Complete findings index
   - Remediation priorities

6. **summary/statistics.md**
   - Detailed testing metrics and KPIs
   - Severity distribution graphs
   - Vulnerability type breakdown
   - OWASP Top 10 and CWE mappings
   - Coverage statistics by category
   - Time allocation across phases

#### Vulnerability Documentation (per finding)

For each discovered vulnerability, the agent creates a folder `findings/finding-NNN/` containing:

- **report.md** - Comprehensive vulnerability report with CVSS, CWE, OWASP mappings
- **poc.py** - Tested, working exploit script
- **poc_output.txt** - Proof of successful exploitation with timestamp
- **workflow.md** - Step-by-step manual exploitation guide
- **description.md** - Technical details of the attack

#### Evidence Organization

All evidence is organized in `findings/evidence/`:
- `screenshots/` - Visual evidence of exploitation
- `http-captures/` - HTTP request/response pairs
- `videos/` - Video recordings of exploits (if applicable)

### Directory Structure

```
findings/
├── TESTING_PROCESS.md           # Phase overview
├── EXPERIMENTATION_LOG.md       # Detailed test log
├── HYPOTHESES_AND_RESULTS.md    # Hypothesis testing results
├── METHODOLOGY.md               # Testing methodology
├── summary/
│   ├── findings-summary.md      # Executive summary
│   └── statistics.md             # Testing metrics
├── finding-001/
│   ├── report.md                # Vulnerability report
│   ├── poc.py                   # Exploit script
│   ├── poc_output.txt           # Proof of execution
│   ├── workflow.md              # Manual exploitation
│   └── description.md           # Technical details
├── finding-002/
│   └── [same structure as finding-001]
├── finding-NNN/
│   └── [same structure]
└── evidence/
    ├── screenshots/
    │   ├── finding-001-screenshot-1.png
    │   ├── finding-001-screenshot-2.png
    │   └── ...
    ├── http-captures/
    │   ├── finding-002-request.txt
    │   ├── finding-002-response.txt
    │   └── ...
    └── videos/
        └── [if applicable]
```

### Reporting Responsibilities

**During Execution**:
1. Initialize `findings/` directory structure at start
2. Log each experiment immediately after testing
3. Track all hypotheses tested with results
4. Save evidence files with clear naming
5. Create finding folders as vulnerabilities are verified

**Upon Completion**:
1. Generate `TESTING_PROCESS.md` - High-level overview
2. Generate `EXPERIMENTATION_LOG.md` - Complete test log
3. Generate `HYPOTHESES_AND_RESULTS.md` - Hypothesis analysis
4. Generate `METHODOLOGY.md` - Testing approach
5. Generate `summary/findings-summary.md` - Executive summary
6. Generate `summary/statistics.md` - Detailed metrics
7. Ensure all finding folders have complete documentation
8. Organize all evidence in appropriate subdirectories

### Quality Standards

All generated reports must meet these standards:

**Organization**:
- [ ] All files in structured `findings/` directory
- [ ] Clear, consistent file naming
- [ ] Proper folder hierarchy
- [ ] Complete evidence organization

**Documentation**:
- [ ] Clear, professional writing
- [ ] Complete technical details
- [ ] Actionable remediation guidance
- [ ] Accurate CVSS/CWE/OWASP mappings

**Completeness**:
- [ ] All required files present
- [ ] Every finding has verified PoC
- [ ] Every finding has working exploit script (poc.py)
- [ ] Every finding has proof of execution (poc_output.txt)
- [ ] Every finding has manual workflow
- [ ] Every finding has technical description

**Evidence**:
- [ ] Screenshots of exploitation
- [ ] HTTP request/response captures
- [ ] Network evidence (if applicable)
- [ ] Console/terminal output (if applicable)

### Integration with Reporting Standards

All reports follow the standards defined in:
- `.claude/OUTPUT_STANDARDS.md` - Overall output format
- `.claude/agents/specialized/POC_REQUIREMENTS.md` - PoC verification requirements
- `.claude/agents/specialized/reference/REPORT_GENERATION.md` - Detailed reporting guidelines

### References

For complete reporting guidelines and templates, see:
- `REPORT_GENERATION.md` - Complete reporting guide with templates
- `POC_REQUIREMENTS.md` - PoC development and verification
- `.claude/OUTPUT_STANDARDS.md` - Organization-wide standards
```

## How to Update Existing Agents

### Step 1: Add Section to Agent File

1. Open the agent markdown file (e.g., `.claude/agents/specialized/xss-agent.md`)
2. Locate a good insertion point (typically after workflows, before or instead of existing reporting mentions)
3. Add the template section above
4. Customize the content for the specific agent if needed

### Step 2: Update References

If the agent already has reporting sections:
- Replace vague references with specific section names
- Add cross-references to REPORT_GENERATION.md
- Ensure consistency with other agents

### Step 3: Verify

- [ ] Section is clear and complete
- [ ] All required files are documented
- [ ] Directory structure is clearly explained
- [ ] Quality standards are listed
- [ ] References to external docs are accurate

## Example: Minimal Update

For agents with minimal documentation, just add:

```markdown
## Reporting

This agent generates organized reports in `findings/`:
- TESTING_PROCESS.md, EXPERIMENTATION_LOG.md, HYPOTHESES_AND_RESULTS.md, METHODOLOGY.md
- summary/findings-summary.md, summary/statistics.md
- Individual finding-NNN/ folders with PoC scripts, workflows, and evidence

See REPORT_GENERATION.md for complete guidelines and templates.
```

## Example: Comprehensive Update

For agents with detailed documentation, expand the template section to include specific details about what this particular agent reports (e.g., "XSS Agent Reports" would document XSS-specific hypotheses, payloads, etc.).

---

## Summary

**What to do**:
1. Open each of the 30+ specialized agent files
2. Add (or update) the "Report Generation & Documentation" section
3. Ensure all agents reference REPORT_GENERATION.md
4. Verify the directory structure matches the template

**Result**:
- All agents now have clear expectations for report generation
- Users understand what reports will be produced
- Consistent, professional documentation across all agents
- Easy reference to templates and guidelines

---
