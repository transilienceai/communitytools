# Skill Directory Structure Reference

## Contents
- Required structure
- File details
- Naming conventions
- Progressive disclosure
- Domain-specific organization
- Validation checklist

## Required Structure

```
.claude/skills/[skill-name]/
├── SKILL.md              # YAML frontmatter + main instructions (REQUIRED)
├── README.md             # User-facing documentation (REQUIRED)
├── tools/__init__.py     # Python package marker (REQUIRED if tools/ exists)
└── outputs/.gitkeep      # Keep outputs/ in git (REQUIRED if outputs/ exists)
```

## Full Structure

```
.claude/skills/[skill-name]/
├── SKILL.md
├── README.md
├── CLAUDE.md             # (Optional) auto-loaded context for this dir
├── agents/               # Skill-specific agent role prompts
├── tools/                # Python utilities (with __init__.py)
├── templates/            # Templates and boilerplate (basic/, advanced/, examples/)
├── reference/            # Progressive-disclosure files (API.md, EXAMPLES.md, ...)
└── outputs/              # Test outputs and reports (with .gitkeep)
```

## File Details

### SKILL.md (required)

Main file Claude reads. Must start with valid YAML frontmatter (see [FRONTMATTER.md](FRONTMATTER.md)). Keep under 500 lines; use progressive disclosure to push details into `reference/`.

```markdown
---
name: skill-name
description: What it does and when to use it
---

# Skill Name
[content]
```

### README.md (required)

Human-facing GitHub doc: overview, quick start, install, usage examples, features, troubleshooting, requirements, contributing.

### CLAUDE.md (optional)

Auto-loaded when Claude works in the skill's directory. Contains: skill overview, common tasks → reference file map, key file locations, critical conventions.

### tools/

Python utilities. Required `__init__.py` (even if minimal):

```python
"""Tools for Skill Name"""
__version__ = "0.1.0"
```

Use when deterministic operations or strict validation matters. See [SCRIPTS.md](SCRIPTS.md).

### templates/

Reusable templates and boilerplate. Common layout: `basic/`, `advanced/`, `examples/`. Use for output formats, code skeletons, configuration examples, sample I/O.

### reference/

Progressive-disclosure files. Common: `API.md`, `EXAMPLES.md`, `ADVANCED.md`, `TROUBLESHOOTING.md`, `BEST-PRACTICES.md`. Organize by topic, by domain (multi-domain skills), or by feature.

### outputs/

Test outputs, reports, generated files. Keep with `.gitkeep` (`touch outputs/.gitkeep`).

## Naming Conventions

**Directories** (lowercase + hyphens, gerund preferred): `processing-pdfs`, `analyzing-data`, `managing-aws-cloudtrail`.

**Files**:
- UPPERCASE for special files: `README.md`, `SKILL.md`, `CLAUDE.md`
- UPPERCASE for reference docs: `API.md`, `EXAMPLES.md`
- lowercase-with-hyphens for agents: `data-analyzer.md`
- snake_case for Python: `data_processor.py`
- forward slashes only — even on Windows (`reference/API.md`)

## Progressive Disclosure Pattern

When SKILL.md exceeds ~400 lines, split details into `reference/` and link from SKILL.md.

Before (800-line SKILL.md): all sections inline.

After (150-line SKILL.md):
```markdown
# Processing PDFs

## Quick Start
[50 lines]

## API Reference
See [API.md](reference/API.md) for the complete API.

## Examples
[20-line basic example]
For more, see [EXAMPLES.md](reference/EXAMPLES.md).

## Advanced
See [ADVANCED.md](reference/ADVANCED.md) for batch ops, custom processors, perf.

## Troubleshooting
[20 lines of top issues]
For more, see [TROUBLESHOOTING.md](reference/TROUBLESHOOTING.md).
```

## Domain-Specific Organization

For multi-domain skills, split reference by domain so Claude only loads what's relevant.

```
bigquery-analytics/
├── SKILL.md             # Overview with per-domain links
└── reference/
    ├── finance.md
    ├── sales.md
    ├── product.md
    └── marketing.md
```

In SKILL.md:
```markdown
## Datasets
- Finance (Revenue, ARR) → [reference/finance.md](reference/finance.md)
- Sales (Pipeline, deals) → [reference/sales.md](reference/sales.md)
- Product (Usage, features) → [reference/product.md](reference/product.md)
- Marketing (Campaigns) → [reference/marketing.md](reference/marketing.md)
```

## Reference Depth

Keep references **one level deep** from SKILL.md. Nested references (`reference/advanced.md` → `reference/details/specific.md`) risk partial reads and incomplete information. If a sub-topic deserves its own file, give it a sibling at the same level (`reference/specific.md`).

## File Size Guidelines

- **SKILL.md**: target < 500 lines (hard limit). Split when approaching 400.
- **Reference files**: include contents list when > 100 lines; split when > 500.
- **README.md**: 100-300 lines, sectioned with clear headers.

## Anti-Patterns

Windows-style backslashes in paths; nested references (more than one hop from SKILL.md); `tools/` missing `__init__.py`; SKILL.md over 500 lines.

## Validation Checklist

- [ ] SKILL.md exists with valid YAML frontmatter, under 500 lines
- [ ] README.md exists
- [ ] `tools/__init__.py` exists (if `tools/` exists)
- [ ] `outputs/.gitkeep` exists (if `outputs/` exists)
- [ ] Forward slashes in all paths
- [ ] References one level deep
- [ ] Lowercase-with-hyphens directory names; file names follow conventions
- [ ] Progressive disclosure used; reference files organized; descriptive names

## Scaffold Script

```bash
SKILL_NAME="your-skill-name"
BASE=".claude/skills/$SKILL_NAME"

mkdir -p "$BASE"/{agents,tools,templates,reference,outputs}
touch "$BASE/SKILL.md" "$BASE/README.md" "$BASE/outputs/.gitkeep"

cat > "$BASE/tools/__init__.py" <<'EOF'
"""Tools for Your Skill Name"""
__version__ = "0.1.0"
EOF

echo "Structure created at $BASE"
```

## Reference

- [Progressive Disclosure](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices#progressive-disclosure-patterns)
- [Skill Structure Overview](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview#skill-structure)
