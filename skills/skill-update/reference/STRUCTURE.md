# Skill Directory Structure Reference

Complete guide to Claude skill directory organization and file requirements.

## Contents
- Required structure
- Optional directories
- File naming conventions
- Organization patterns
- Domain-specific organization

## Required Structure

Every skill MUST have this minimum structure:

```
.claude/skills/[skill-name]/
├── SKILL.md              # YAML frontmatter + main instructions (REQUIRED)
├── README.md             # User-facing documentation (REQUIRED)
├── tools/__init__.py     # Python package marker (REQUIRED if tools/ exists)
└── outputs/.gitkeep      # Keep outputs/ in git (REQUIRED if outputs/ exists)
```

## Complete Structure

A fully-featured skill may include:

```
.claude/skills/[skill-name]/
├── SKILL.md              # Main skill definition
├── README.md             # User documentation
├── CLAUDE.md             # (Optional) Auto-loaded context
├── agents/               # Skill-specific agent role prompts
│   └── example-agent.md
├── tools/                # Python utilities
│   ├── __init__.py
│   ├── helper.py
│   └── validator.py
├── templates/            # Templates and boilerplate
│   ├── basic/
│   ├── advanced/
│   └── examples/
├── reference/            # Progressive disclosure files
│   ├── API.md
│   ├── EXAMPLES.md
│   ├── ADVANCED.md
│   └── TROUBLESHOOTING.md
└── outputs/              # Test outputs and reports
    └── .gitkeep
```

## File Details

### SKILL.md (Required)

**Purpose**: Main skill instructions that Claude reads

**Format**:
```markdown
---
name: skill-name
description: What it does and when to use it
---

# Skill Name

[Content here]
```

**Requirements**:
- Must start with valid YAML frontmatter
- Keep under 500 lines
- Use progressive disclosure for details
- Include workflows with checklists
- Reference other files for depth

**See**: [FRONTMATTER.md](FRONTMATTER.md) for frontmatter rules

### README.md (Required)

**Purpose**: User-facing documentation

**Contents**:
- Overview and purpose
- Quick start guide
- Installation instructions
- Usage examples
- Feature list
- Troubleshooting
- Requirements
- Contributing guidelines

**Audience**: Humans reading on GitHub or in IDEs

### CLAUDE.md (Optional)

**Purpose**: Context automatically loaded by Claude when working in this directory

**When to create**:
- Skill needs special working context
- Common tasks need guidance
- File locations should be documented
- Critical rules exist

**Contents**:
- Skill overview
- Common tasks and approaches
- Quick reference to file locations
- Critical rules or conventions

**Example**:
```markdown
# Skill Name - Claude Context

Auto-loaded when Claude works in this directory.

## What You Need to Know

**Purpose:** Brief explanation

**Key files:**
- SKILL.md - Main instructions
- reference/API.md - API documentation

## Common Tasks

- Task 1 → Reference file A
- Task 2 → Reference file B

## Important Rules

- Rule 1
- Rule 2
```

### tools/ Directory

**Purpose**: Python utilities and helper functions

**Structure**:
```
tools/
├── __init__.py          # REQUIRED (even if empty)
├── generator.py         # Utility modules
├── validator.py
└── helpers.py
```

**__init__.py minimum**:
```python
"""
Tools for Skill Name
"""

__version__ = "0.1.0"
```

**When to create tools**:
- Deterministic operations needed
- Complex logic should be consistent
- Validation/error handling required
- Script execution preferred over generation

**See**: [SCRIPTS.md](SCRIPTS.md) for scripting patterns

### templates/ Directory

**Purpose**: Reusable templates and boilerplate

**Organization**:
```
templates/
├── basic/               # Simple templates
│   ├── minimal.md
│   └── starter.py
├── advanced/            # Complex templates
│   ├── full-featured.md
│   └── with-validation.py
└── examples/            # Example files
    ├── example-1.md
    └── example-2.py
```

**Use for**:
- Output format templates
- Code boilerplate
- Configuration examples
- Sample inputs/outputs

### reference/ Directory

**Purpose**: Progressive disclosure files for detailed information

**Key principle**: Keep SKILL.md under 500 lines by moving details here

**Common files**:
- `API.md` - API reference documentation
- `EXAMPLES.md` - Extended examples and use cases
- `ADVANCED.md` - Advanced features and patterns
- `TROUBLESHOOTING.md` - Common issues and solutions
- `BEST-PRACTICES.md` - Best practices guide

**Organization patterns**:

**Pattern 1: By topic**
```
reference/
├── API.md
├── CONFIGURATION.md
├── EXAMPLES.md
└── TROUBLESHOOTING.md
```

**Pattern 2: By domain** (for multi-domain skills)
```
reference/
├── finance.md           # Finance domain schemas
├── sales.md             # Sales domain schemas
├── product.md           # Product domain schemas
└── marketing.md         # Marketing domain schemas
```

**Pattern 3: By feature**
```
reference/
├── form-filling.md      # Form-related features
├── text-extraction.md   # Text features
└── image-processing.md  # Image features
```

**See**: [CONTENT.md](CONTENT.md) for writing guidelines

### outputs/ Directory

**Purpose**: Store test outputs, reports, and generated files

**Structure**:
```
outputs/
├── .gitkeep             # REQUIRED (keeps dir in git)
├── test-run-1/
├── test-run-2/
└── reports/
```

**Usage**:
- Store skill test outputs
- Save generated reports
- Keep example results
- Organize by test scenario

**.gitkeep requirement**:
```bash
# Create empty .gitkeep file
touch outputs/.gitkeep
```

## Naming Conventions

### Directory Names

**Skill directories**:
- Use lowercase with hyphens
- Prefer gerund form: `processing-pdfs`, `analyzing-data`
- Be specific: `managing-aws-cloudtrail` not `cloud-logs`

**Subdirectories**:
- Use lowercase with hyphens or underscores
- Be descriptive: `reference/`, `templates/`, `tools/`

### File Names

**Markdown files**:
- UPPERCASE for important files: `README.md`, `SKILL.md`, `CLAUDE.md`
- UPPERCASE for reference files: `API.md`, `EXAMPLES.md`
- lowercase-with-hyphens for agents: `data-analyzer.md`

**Python files**:
- lowercase_with_underscores: `data_processor.py`
- Follow PEP 8 conventions

**Always use forward slashes** (even on Windows):
- ✓ `reference/API.md`
- ✗ `reference\API.md`

## Progressive Disclosure Pattern

**Problem**: SKILL.md over 500 lines

**Solution**: Split content into reference files

**Before** (SKILL.md with 800 lines):
```markdown
---
name: processing-pdfs
description: ...
---

# Processing PDFs

## Quick Start
[50 lines]

## API Reference
[300 lines of API docs]

## Examples
[200 lines of examples]

## Advanced Features
[150 lines of advanced content]

## Troubleshooting
[100 lines]
```

**After** (SKILL.md with 150 lines):
```markdown
---
name: processing-pdfs
description: ...
---

# Processing PDFs

## Quick Start
[50 lines]

## API Reference

See [API.md](reference/API.md) for complete API documentation.

## Examples

Basic example:
[20 lines]

For more examples, see [EXAMPLES.md](reference/EXAMPLES.md).

## Advanced Features

See [ADVANCED.md](reference/ADVANCED.md) for:
- Custom processors
- Batch operations
- Performance optimization

## Troubleshooting

Common issues:
[20 lines]

For more help, see [TROUBLESHOOTING.md](reference/TROUBLESHOOTING.md).
```

**Result**:
- SKILL.md: 150 lines (under 500) ✓
- Details available when needed ✓
- Better organization ✓

## Domain-Specific Organization

For skills covering multiple domains, organize by domain to avoid loading irrelevant context.

**Example: BigQuery Analytics Skill**

```
bigquery-analytics/
├── SKILL.md             # Overview with domain nav
└── reference/
    ├── finance.md       # Finance tables/metrics
    ├── sales.md         # Sales tables/metrics
    ├── product.md       # Product tables/metrics
    └── marketing.md     # Marketing tables/metrics
```

**SKILL.md navigation**:
```markdown
## Available Datasets

**Finance**: Revenue, ARR → See [reference/finance.md](reference/finance.md)
**Sales**: Pipeline, deals → See [reference/sales.md](reference/sales.md)
**Product**: Usage, features → See [reference/product.md](reference/product.md)
**Marketing**: Campaigns, attribution → See [reference/marketing.md](reference/marketing.md)

## Quick Search

Find specific metrics:
```bash
grep -i "revenue" reference/finance.md
grep -i "pipeline" reference/sales.md
```
```

**Benefit**: Claude only loads relevant domain file, not all domains

## Reference Depth Rules

**CRITICAL**: Keep references ONE level deep from SKILL.md

**Good** (one level):
```
SKILL.md
├─> reference/API.md
├─> reference/EXAMPLES.md
└─> reference/ADVANCED.md
```

**Bad** (nested):
```
SKILL.md
└─> reference/ADVANCED.md
    └─> reference/details/SPECIFIC.md  # ✗ Too deep
```

**Why**: Claude may only partially read nested references, causing incomplete information.

## File Size Guidelines

**SKILL.md**: Target < 500 lines
- Hard limit: 500 lines
- If approaching 400, consider splitting

**Reference files**: No hard limit
- Include table of contents if > 100 lines
- Split into multiple files if > 500 lines

**README.md**: Keep reasonable
- Target: 100-300 lines
- Split into sections with clear headers

## Validation Checklist

Before finalizing structure:

### Required Files
- [ ] SKILL.md exists
- [ ] SKILL.md has valid YAML frontmatter
- [ ] README.md exists
- [ ] tools/__init__.py exists (if tools/ directory exists)
- [ ] outputs/.gitkeep exists (if outputs/ directory exists)

### Structure Quality
- [ ] SKILL.md under 500 lines
- [ ] No Windows-style paths (use forward slashes)
- [ ] References are one level deep
- [ ] Directory names use lowercase-with-hyphens
- [ ] File names follow conventions
- [ ] Progressive disclosure used appropriately

### Organization
- [ ] Clear separation of concerns
- [ ] Logical file grouping
- [ ] Descriptive directory names
- [ ] Reference files well-organized

## Directory Creation Script

```bash
# Create skill directory structure
SKILL_NAME="your-skill-name"
BASE=".claude/skills/$SKILL_NAME"

# Create directories
mkdir -p "$BASE"/{agents,tools,templates,reference,outputs}

# Create required files
touch "$BASE/SKILL.md"
touch "$BASE/README.md"
touch "$BASE/tools/__init__.py"
touch "$BASE/outputs/.gitkeep"

# Create __init__.py content
cat > "$BASE/tools/__init__.py" << 'EOF'
"""
Tools for Your Skill Name
"""

__version__ = "0.1.0"
EOF

echo "✓ Structure created at $BASE"
```

## Common Mistakes

### Mistake 1: Windows-Style Paths

```markdown
# ✗ Wrong
See [API.md](reference\API.md)

# ✓ Correct
See [API.md](reference/API.md)
```

### Mistake 2: Nested References

```markdown
# ✗ Wrong (in SKILL.md)
See [advanced.md](reference/advanced.md)

# (in reference/advanced.md)
See [details.md](details/specific.md)  # Too deep!

# ✓ Correct (in SKILL.md)
See [advanced.md](reference/advanced.md)
See [specific.md](reference/specific.md)  # Same level
```

### Mistake 3: Missing __init__.py

```
tools/
├── helper.py
└── validator.py  # ✗ Missing __init__.py
```

### Mistake 4: SKILL.md Too Long

```markdown
# ✗ Wrong: 800 lines in SKILL.md

# ✓ Correct: 150 lines in SKILL.md + reference files
```

## Examples

## Reference

- [Progressive Disclosure](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices#progressive-disclosure-patterns)
- [Skill Structure Overview](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview#skill-structure)
