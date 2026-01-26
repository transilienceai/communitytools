# Quick Guide: Applying Template to Specialized Agents

Use this guide to quickly refactor the remaining 29+ specialized agents.

## Template Location

`.claude/agents/specialized/TEMPLATE.md`

## Refactoring Process (5-10 minutes per agent)

### Step 1: Copy Template
```bash
cp .claude/agents/specialized/TEMPLATE.md .claude/agents/specialized/NEW_AGENT.md
```

### Step 2: Update Frontmatter
```yaml
---
name: [Vulnerability] Discovery Agent
description: Specialized agent for [vulnerability] testing...
color: [red|orange|purple|green]
tools: [computer, bash, editor, mcp]
skill: pentest
---
```

### Step 3: Customize Core Mission
- Update objective (one line)
- Update scope (attack surface)
- Update outcome (what PoC demonstrates)

### Step 4: Customize Quick Start
Update 4-phase workflow with agent-specific actions:
- Phase 1: Reconnaissance (what to identify)
- Phase 2: Experimentation (what hypotheses to test)
- Phase 3: Testing (what to extract/demonstrate)
- Phase 4: Retry (what bypasses to apply)

### Step 5: Fill Phase Sections

**Phase 1: Reconnaissance**
- Attack surface discovery (3-5 bullet points)
- Context analysis (if applicable)
- Link to: `reference/[VULN]_RECON.md`

**Phase 2: Experimentation**
- Top 5 hypotheses with basic payloads
- Expected results for each
- Link to: `reference/[VULN]_PAYLOADS.md` for complete list

**Phase 3: Testing & Exploitation**
- 3-5 step exploitation workflow
- Impact demonstration examples
- Link to: `reference/[VULN]_EXPLOITATION.md`

**Phase 4: Retry & Bypass**
- Top 5 bypass categories
- Link to: `reference/[VULN]_BYPASSES.md`

### Step 6: Update PoC Example
```python
# Update with agent-specific PoC script
def exploit_[vuln](target, param):
    # Agent-specific exploitation
    pass
```

### Step 7: Update Tools & Commands
- Primary tool (Burp, sqlmap, etc.)
- Secondary tools
- Key commands
- Link to: `reference/[VULN]_TOOLS.md`

### Step 8: Update Reporting Format
- Update agent_id
- Update finding title/type
- Update severity range
- Update evidence fields

### Step 9: Update Spawn Recommendations
List 3-5 related agents to spawn when this vuln found.

### Step 10: Update Reference Links
```markdown
## Reference
- [reference/[VULN]_RECON.md] - Reconnaissance
- [reference/[VULN]_PAYLOADS.md] - Payloads
- [reference/[VULN]_EXPLOITATION.md] - Exploitation
- [reference/[VULN]_BYPASSES.md] - Bypasses
- [reference/[VULN]_TOOLS.md] - Tools
- [POC_REQUIREMENTS.md] - PoC standards
```

## Examples

**Completed examples to reference**:
- `.claude/agents/specialized/path-traversal-agent.md`
- `.claude/agents/specialized/sql-injection-agent.md`
- `.claude/agents/specialized/xss-agent.md`

## Target Size

- Main agent file: 250-450 lines
- Keep under 500 lines max
- Extract detailed content to reference/ files

## Validation Checklist

- [ ] Frontmatter valid YAML
- [ ] Under 500 lines
- [ ] Quick start present
- [ ] All 4 phases covered
- [ ] PoC section complete
- [ ] Reference links added
- [ ] Success criteria clear

## Batch Processing

To refactor all 29 remaining agents efficiently:

1. Create reference/ files first (shared resources)
2. Apply template to similar agents in batches
3. Injection agents (5 remaining)
4. Client-side agents (3 remaining)
5. Server-side agents (4 remaining)
6. Auth agents (3 remaining)
7. API agents (3 remaining)
8. Business logic agents (5 remaining)
9. Other specialized agents (6 remaining)

**Estimated time**: 3-4 hours for all 29 agents
