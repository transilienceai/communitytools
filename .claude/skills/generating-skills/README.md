# Generating Skills

Create and update Claude Code skills following official Anthropic best practices.

## Overview

This skill helps you generate well-structured Claude skills that follow best practices from:
- [Claude Code Best Practices](https://www.anthropic.com/engineering/claude-code-best-practices)
- [Agent Skills Best Practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)

## Quick Start

### Creating a New Skill

1. Invoke the skill:
   ```
   Use the generating-skills skill to create a new skill called "processing-pdfs"
   ```

2. Provide skill requirements when asked:
   - Skill name (gerund form): "Processing PDFs"
   - Description: What it does and when to use it
   - Key features
   - Whether it needs utility scripts

3. The skill will generate:
   - Complete directory structure in `.claude/skills/`
   - SKILL.md with proper YAML frontmatter
   - README.md with user documentation
   - Reference files for progressive disclosure
   - Utility scripts (if needed)
   - Validation checks

### Updating an Existing Skill

```
Help me update the processing-pdfs skill to follow best practices
```

The skill will:
- Review current structure
- Identify areas for improvement
- Update files to match best practices
- Validate changes

## Features

### Structure Generation
- Creates proper directory structure
- Generates all required files
- Sets up progressive disclosure pattern
- Creates reference files

### Best Practices Enforcement
- Validates YAML frontmatter
- Ensures gerund naming convention
- Checks description format (WHAT and WHEN)
- Keeps SKILL.md under 500 lines
- Verifies reference depth (one level only)

### Workflows with Checklists
- Provides step-by-step workflows
- Includes progress checklists
- Implements validation feedback loops
- Sets appropriate degrees of freedom

### Testing Support
- Creates evaluation scenarios
- Tests skill activation triggers
- Validates with multiple models
- Provides troubleshooting guidance

## Skill Structure

Generated skills follow this structure:

```
.claude/skills/[skill-name]/
├── SKILL.md              # Main instructions with YAML frontmatter
├── README.md             # User-facing documentation
├── CLAUDE.md             # (Optional) Auto-loaded context
├── agents/               # Skill-specific agents
├── tools/                # Python utilities
│   └── __init__.py
├── templates/            # Templates and examples
├── reference/            # Progressive disclosure files
│   ├── STRUCTURE.md
│   ├── FRONTMATTER.md
│   ├── CONTENT.md
│   └── SCRIPTS.md
└── outputs/              # Test outputs
    └── .gitkeep
```

## Key Principles

### Concise is Key
- Context window is a public good
- Challenge every token
- Only add what Claude doesn't know
- Keep SKILL.md under 500 lines

### Progressive Disclosure
- SKILL.md is overview
- Details go in reference/ files
- One level deep references only
- Load content as needed

### Appropriate Degrees of Freedom

**High freedom** (text instructions):
- Multiple valid approaches
- Context-dependent decisions
- Example: Code reviews, analysis

**Medium freedom** (templates/pseudocode):
- Preferred patterns exist
- Some variation acceptable
- Example: Report generation

**Low freedom** (exact scripts):
- Critical operations
- Consistency required
- Example: Database migrations

## Examples

### Example 1: Create Data Analysis Skill

```
User: Create a skill for analyzing CSV data

Skill Generator:
1. Validates name: "analyzing-csv-data"
2. Creates directory structure
3. Generates SKILL.md with:
   - Data loading workflow
   - Analysis patterns
   - Visualization examples
   - Error handling
4. Creates reference files:
   - PANDAS.md - Pandas operations
   - VISUALIZATION.md - Chart creation
   - EXAMPLES.md - Sample analyses
5. Validates structure
6. Creates test scenarios
```

### Example 2: Update Existing Skill

```
User: Update my pdf-processing skill to follow new best practices

Skill Generator:
1. Reads current SKILL.md
2. Identifies issues:
   - Description missing "when to use"
   - SKILL.md over 500 lines
   - No progressive disclosure
   - Nested references
3. Fixes issues:
   - Updates description
   - Splits content into reference files
   - Flattens reference structure
4. Validates changes
5. Tests skill activation
```

## Requirements

- Claude Code (latest version)
- Access to `.claude/skills/` directory
- Write permissions

## Common Tasks

### Validate an Existing Skill

```
Validate the structure of my analyzing-data skill
```

### Convert Legacy Skill

```
Convert my old custom_skills/pdf_processor to the new structure
```

### Generate Reference Files

```
Create reference files for my skill's advanced features
```

## Troubleshooting

### Skill Not Activating

**Issue**: Claude doesn't load the skill when expected

**Solutions**:
- Check description includes specific triggers and key terms
- Ensure description mentions "when to use"
- Add more specific keywords to description
- Test with example queries

### SKILL.md Too Long

**Issue**: SKILL.md exceeds 500 lines

**Solutions**:
- Split content into reference/ files
- Move examples to EXAMPLES.md
- Move API details to API.md
- Keep overview in SKILL.md, details in references

### References Not Followed

**Issue**: Claude doesn't read referenced files

**Solutions**:
- Make references more prominent in SKILL.md
- Use descriptive file names
- Keep references one level deep (not nested)
- Add context around references

### Inconsistent Behavior

**Issue**: Skill works differently each time

**Solutions**:
- Add more structure to workflows
- Provide default approaches
- Include validation steps
- Add feedback loops

## Best Practices Checklist

Before finalizing a skill, verify:

### Core Quality
- [ ] Description includes WHAT and WHEN
- [ ] Description has key terms and triggers
- [ ] SKILL.md under 500 lines
- [ ] Progressive disclosure used
- [ ] No time-sensitive information
- [ ] Consistent terminology
- [ ] Examples are concrete
- [ ] References one level deep
- [ ] Workflows have checklists

### Structure
- [ ] Valid YAML frontmatter
- [ ] Gerund naming (processing-pdfs)
- [ ] All required files present
- [ ] No Windows-style paths
- [ ] tools/__init__.py created
- [ ] outputs/.gitkeep present

### Testing
- [ ] 3+ evaluation scenarios
- [ ] Tested with target models
- [ ] Tested with real usage
- [ ] Skill activates correctly
- [ ] Workflows work as expected

## Reference Documentation

See the skill's reference files for detailed information:

- [STRUCTURE.md](reference/STRUCTURE.md) - Complete structure requirements
- [FRONTMATTER.md](reference/FRONTMATTER.md) - YAML frontmatter rules and examples
- [CONTENT.md](reference/CONTENT.md) - Content writing guidelines
- [SCRIPTS.md](reference/SCRIPTS.md) - Utility script patterns
- [TESTING.md](reference/TESTING.md) - Testing and evaluation approaches
- [BEST-PRACTICES.md](reference/BEST-PRACTICES.md) - Complete best practices guide

## Contributing

Contributions are welcome! Please see the main repository [CONTRIBUTING.md](../../../CONTRIBUTING.md) for guidelines.

## Support

For issues and questions:
- Create an issue: [GitHub Issues](https://github.com/anthropics/claude-code/issues)
- Discussions: [GitHub Discussions](https://github.com/anthropics/claude-code/discussions)

## License

See repository root for license information.
