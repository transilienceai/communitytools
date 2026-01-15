# Generating Skills

Create and update Claude Code skills following official Anthropic best practices.

## Overview

Generate well-structured Claude skills that follow best practices from [Claude Code Best Practices](https://www.anthropic.com/engineering/claude-code-best-practices) and [Agent Skills Best Practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices).

## Quick Start

### Create New Skill

```
Use the generating-skills skill to create "processing-pdfs"
```

Provide:
- Skill name (gerund form)
- Description (what AND when)
- Key features
- Whether it needs scripts

Generates:
- Complete directory structure
- SKILL.md with YAML frontmatter
- README.md
- Reference files
- Validation checks

### Update Existing Skill

```
Update the processing-pdfs skill to follow best practices
```

Reviews structure, identifies improvements, updates files, validates changes.

## Features

- **Structure generation**: Proper directory, all required files, progressive disclosure
- **Best practices**: Validates YAML, naming, description format, references
- **Workflows**: Step-by-step with checklists, validation loops
- **Testing**: Evaluation scenarios, multi-model testing, troubleshooting

## Structure

```
.claude/skills/skill-name/
├── SKILL.md              # Main instructions
├── README.md             # User docs
├── CLAUDE.md             # (Optional) Auto-loaded context
├── reference/            # Progressive disclosure
│   ├── STRUCTURE.md
│   ├── FRONTMATTER.md
│   └── CONTENT.md
└── outputs/.gitkeep      # Test outputs
```

## Key Principles

**Concise**: Challenge every token, assume Claude is smart

**Progressive disclosure**: SKILL.md < 500 lines, details in reference/

**Degrees of freedom**: Match specificity to task fragility

## Examples

### Example 1: Data Analysis Skill

```
User: Create skill for analyzing CSV data

Generates:
- analyzing-csv-data/
- SKILL.md with data loading workflow
- reference/PANDAS.md, VISUALIZATION.md
- Test scenarios
```

### Example 2: Update Existing

```
User: Update my pdf-processing skill

Fixes:
- Description missing "when to use"
- SKILL.md over 500 lines → splits into reference files
- Flattens nested references
```

## Requirements

- Claude Code (latest)
- Access to `.claude/skills/`
- Write permissions

## Best Practices Checklist

### Core
- [ ] Description includes WHAT and WHEN
- [ ] SKILL.md < 500 lines
- [ ] Progressive disclosure used
- [ ] References one level deep
- [ ] Workflows have checklists

### Structure
- [ ] Valid YAML frontmatter
- [ ] Gerund naming
- [ ] All required files
- [ ] Forward slashes (not backslashes)

### Testing
- [ ] 3+ scenarios
- [ ] Tested with models
- [ ] Skill activates correctly

## Reference

- [STRUCTURE.md](reference/STRUCTURE.md) - Directory requirements
- [FRONTMATTER.md](reference/FRONTMATTER.md) - YAML rules
- [CONTENT.md](reference/CONTENT.md) - Writing guidelines

## Troubleshooting

**Skill not activating**: Add specific triggers to description

**Claude ignoring files**: Make references prominent, descriptive names

**Context overflow**: Split SKILL.md into reference files

**Inconsistent behavior**: Add structure, provide defaults

## Contributing

See [CONTRIBUTING.md](../../../CONTRIBUTING.md) for guidelines.

## License

See repository root for license information.
