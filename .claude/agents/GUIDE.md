# Agent Refactoring Guide

Complete guide for the refactored agent structure.

## ✅ What Was Accomplished

### Refactored Agents (7 total - 55% average reduction)

| Agent | Before | After | Reduction | Type |
|-------|--------|-------|-----------|------|
| pentester.md | 1,214 | 274 | 77% | Orchestrator |
| hackerone-hunter.md | 434 | 276 | 36% | Orchestrator |
| git-issue-creator.md | 436 | 161 | 63% | Git Tool |
| path-traversal-agent.md | 910 | 368 | 60% | Specialized |
| sql-injection-agent.md | 625 | 399 | 36% | Specialized |
| xss-agent.md | 749 | 444 | 41% | Specialized |
| ssrf-agent.md | 628 → 885 → 307 | 307 | 51% (fixed) | Specialized |

**Total**: 4,996 lines → 2,229 lines (55% reduction)

### Key Improvements

1. **Progressive Disclosure** - Main files 200-450 lines, details in reference/
2. **Template-Based** - Shared TEMPLATE.md for all 32+ specialized agents
3. **Improved Clarity** - Quick start, 4-phase workflow, clean structure
4. **Validated** - Template proven with 4 different vulnerability types

## 📁 File Structure

```
.claude/agents/
├── README.md - Overview (read this first)
├── GUIDE.md - This file (complete guide)
├── APPLY_TEMPLATE_GUIDE.md - Template usage (for refactoring remaining agents)
│
├── pentester.md (274 lines) ✅
├── hackerone-hunter.md (276 lines) ✅
├── git-issue-creator.md (161 lines) ✅
├── skiller.md (needs refactoring)
├── git-pr-creator.md (needs refactoring)
├── git-branch-manager.md (needs refactoring)
│
├── reference/
│   ├── AGENT_CATALOG.md - All 32 specialized agents
│   ├── DELEGATION.md - Delegation patterns
│   ├── RECURSIVE_AGENTS.md - Discovery-based spawning
│   ├── REPORTING.md - Report generation
│   └── ENGAGEMENT_TYPES.md - Domain workflows
│
└── specialized/
    ├── TEMPLATE.md - Shared template ✅
    ├── path-traversal-agent.md (368 lines) ✅
    ├── sql-injection-agent.md (399 lines) ✅
    ├── xss-agent.md (444 lines) ✅
    ├── ssrf-agent.md (307 lines) ✅
    └── [28 agents] - Can be refactored on-demand using TEMPLATE.md
```

## 🚀 Using Refactored Agents

All refactored agents follow consistent structure:

1. **Quick Start** - 4-phase workflow overview
2. **Phase 1: Reconnaissance** - What to identify
3. **Phase 2: Experimentation** - Top 5 hypotheses
4. **Phase 3: Testing** - Exploitation workflow
5. **Phase 4: Retry** - Top 5 bypass techniques
6. **PoC Verification** - Mandatory requirements
7. **Reference Links** - Deep dive documentation

## 🔧 Refactoring Remaining Agents

To refactor any of the 28 remaining specialized agents:

1. **Read**: `APPLY_TEMPLATE_GUIDE.md`
2. **Copy**: `specialized/TEMPLATE.md` to new agent name
3. **Follow**: 10-step process in guide
4. **Validate**: Under 500 lines, all sections complete
5. **Time**: 5-10 minutes per agent

**Examples to reference**:
- path-traversal-agent.md
- sql-injection-agent.md
- xss-agent.md
- ssrf-agent.md

## 📊 Benefits Achieved

- **55% reduction** in file sizes = faster loading
- **Consistent structure** = easier navigation
- **Progressive disclosure** = better comprehension
- **Template-based** = easy maintenance
- **Proven approach** = validated with 7 agents

## 🎯 Next Steps

### If Refactoring More Agents

**Recommended Approach**: On-demand refactoring
- Template is ready and proven
- Refactor agents as you use them
- Takes 5-10 minutes per agent with template

**Batch Approach**: By category
1. Injection agents (NoSQL, Command, LDAP, SSTI, XXE)
2. Client-side (CSRF, CORS, Clickjacking, DOM, Prototype)
3. Server-side (Deserialization, File Upload, HTTP Smuggling, Host Header)
4. Authentication (Auth Bypass, OAuth, JWT, Password)
5. API (GraphQL, REST, WebSocket)
6. Business logic (Race Condition, Info Disclosure, Access Control, etc.)

**Estimated Time**: 28 agents × 10 min = ~5 hours

### Reference Files to Create (Optional)

When refactoring agents, optionally create:
- `specialized/reference/[VULN]_PAYLOADS.md`
- `specialized/reference/[VULN]_BYPASSES.md`
- `specialized/reference/[VULN]_EXPLOITATION.md`
- `specialized/reference/[VULN]_TOOLS.md`

These provide the "deep dive" content linked from main agent files.

## ✅ Validation Checklist

For each refactored agent:
- [ ] Under 500 lines
- [ ] Valid YAML frontmatter
- [ ] Quick start section present
- [ ] All 4 phases covered
- [ ] PoC verification section included
- [ ] Reference links added
- [ ] Spawn recommendations listed
- [ ] Success criteria defined

## 📚 Key Files

**Primary Documentation**:
- **README.md** - Start here for overview
- **THIS FILE** - Complete refactoring guide
- **APPLY_TEMPLATE_GUIDE.md** - Template application guide

**Core Template**:
- **specialized/TEMPLATE.md** - Base for all specialized agents

**Reference Documentation** (used by all agents):
- **reference/AGENT_CATALOG.md**
- **reference/DELEGATION.md**
- **reference/RECURSIVE_AGENTS.md**
- **reference/REPORTING.md**
- **reference/ENGAGEMENT_TYPES.md**

## 🎓 Lessons Learned

1. **Progressive disclosure works** - Main file + reference links
2. **Templates reduce duplication** - Shared structure = consistency
3. **Quality over speed** - 7 well-done agents > 36 rushed ones
4. **Quick start is critical** - Most important info first
5. **55% reduction validated** - Significant improvement proven

## 💡 Best Practices

**When refactoring**:
- Start with Quick Start section
- Keep main file under 500 lines
- Top 5 techniques inline, rest in reference/
- Include PoC example
- Link to external resources
- Follow template structure

**When using agents**:
- Read Quick Start first
- Follow 4-phase workflow
- Check reference links for deep dives
- Verify PoC requirements
- Generate complete reports

---

**Status**: Foundation complete, template validated, 7 agents refactored (4 specialized + 2 orchestrator + 1 git tool)
**Next**: Refactor remaining agents on-demand using template
**Time**: 5-10 minutes per agent with APPLY_TEMPLATE_GUIDE.md
