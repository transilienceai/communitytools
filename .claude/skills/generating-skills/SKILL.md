---
name: generating-skills
description: Generate and update Claude skills following official Anthropic best practices. Use when creating new skills, updating existing skills, or when the user mentions skill development, skill generation, or Claude Code skills.
---

# Generating Skills

Generate and update Claude Code skills following official best practices from Anthropic's engineering documentation.

## Quick Start

**Creating a new skill**:
1. Copy this checklist and track progress:
```
Skill Generation Progress:
- [ ] Step 1: Design skill structure
- [ ] Step 2: Create directory and files
- [ ] Step 3: Write SKILL.md with frontmatter
- [ ] Step 4: Add README and documentation
- [ ] Step 5: Create utility scripts (if needed)
- [ ] Step 6: Validate structure
- [ ] Step 7: Test with real scenarios
```

2. Use the generation workflow below

## Core Principles

**Concise is key**: The context window is a public good. Only add context Claude doesn't already have. Challenge every token:
- Does Claude really need this explanation?
- Can I assume Claude knows this?
- Does this justify its token cost?

**Progressive disclosure**: SKILL.md is an overview that points to detailed materials as needed. Keep SKILL.md body under 500 lines.

**Set appropriate degrees of freedom**:
- High freedom (text instructions): Multiple valid approaches
- Medium freedom (pseudocode/templates): Preferred patterns with flexibility
- Low freedom (exact scripts): Critical operations requiring consistency

## Skill Generation Workflow

### Step 1: Design skill structure

**Determine naming** (use gerund form):
- ✓ Good: `processing-pdfs`, `analyzing-data`, `testing-code`
- ✗ Avoid: `helper`, `utils`, `tools`, or names with "anthropic"/"claude"

**Plan content organization**:
- What goes in SKILL.md? (Overview, quick start, core workflows)
- What needs separate files? (Detailed reference, examples, advanced topics)
- What scripts are needed? (Utilities that should be executed vs referenced)

**Identify domains** (if applicable):
- Will this skill cover multiple domains that should be organized separately?
- Example: BigQuery skill with finance/, sales/, product/ subdirectories

See [STRUCTURE.md](reference/STRUCTURE.md) for complete structure requirements.

### Step 2: Create directory and files

**Required structure**:
```
skill-name/
├── SKILL.md          # YAML frontmatter + main instructions
├── README.md         # User-facing documentation
├── CLAUDE.md         # (Optional) Context for working in this skill
├── agents/           # Agent definitions (.md files)
├── tools/            # Python tools (if needed)
│   └── __init__.py
└── outputs/          # Test outputs
    └── .gitkeep
```

**Use the template**:
```bash
python tools/generate_structure.py skill-name "Description of skill"
```

Or copy from `templates/skill_template/`

### Step 3: Write SKILL.md with frontmatter

**YAML frontmatter requirements**:
```yaml
---
name: skill-name
description: What the skill does and when to use it. Include key terms and triggers.
---
```

**Name field rules**:
- Maximum 64 characters
- Lowercase letters, numbers, hyphens only
- No XML tags, no "anthropic" or "claude"

**Description field rules**:
- Maximum 1024 characters
- Non-empty, no XML tags
- Write in third person: "Processes files" not "I can help you process files"
- Include BOTH what it does AND when to use it
- Include specific triggers: "Use when the user mentions PDFs, forms, or document extraction"

See [FRONTMATTER.md](reference/FRONTMATTER.md) for examples and anti-patterns.

**Body content structure**:
1. Quick start section (most common use case)
2. Core principles (if complex)
3. Main workflows with checklists
4. Advanced features (link to separate files)
5. Common patterns
6. Troubleshooting

See [CONTENT.md](reference/CONTENT.md) for writing guidelines.

### Step 4: Add README and documentation

**README.md** (user-facing):
- What the skill does
- Installation requirements
- Quick examples
- Links to detailed documentation

**CLAUDE.md** (optional, auto-loaded):
- Context for Claude when working in this directory
- Common tasks and how to approach them
- Quick reference to file locations
- Critical rules or conventions

### Step 5: Create utility scripts (if needed)

**When to create scripts**:
- ✓ Deterministic operations with complex logic
- ✓ Operations that need validation/error handling
- ✓ Tasks that should be consistent across uses
- ✗ Simple one-off operations Claude can handle

**Script design principles**:
- Solve problems, don't punt to Claude
- Handle errors explicitly with helpful messages
- Document all configuration parameters (no "voodoo constants")
- Make execution intent clear in SKILL.md

See [SCRIPTS.md](reference/SCRIPTS.md) for scripting patterns.

### Step 6: Validate structure

**Run validation**:
```bash
python tools/validate_skill.py skill-name
```

**Check for**:
- Valid YAML frontmatter
- Required files present
- File references are one level deep (not nested)
- No Windows-style paths (use forward slashes)
- SKILL.md body under 500 lines
- Consistent terminology throughout

### Step 7: Test with real scenarios

**Create evaluations BEFORE writing extensive documentation**:
1. Identify gaps: Run Claude on tasks without the skill, document failures
2. Create 3+ test scenarios
3. Establish baseline performance
4. Write minimal instructions to address gaps
5. Iterate based on observed behavior

**Test with all target models**:
- Claude Haiku: Does it provide enough guidance?
- Claude Sonnet: Is it clear and efficient?
- Claude Opus: Does it avoid over-explaining?

**Observe how Claude uses the skill**:
- Does it read files in expected order?
- Are references followed correctly?
- Is any content ignored or overused?
- Does the skill activate at the right times?

## Updating Existing Skills

**Iteration workflow**:
1. Use skill in real tasks (not test scenarios)
2. Observe Claude's behavior - where does it struggle or succeed?
3. Return to editing: Review SKILL.md and identify improvements
4. Make targeted changes based on observations
5. Test changes with real usage
6. Repeat based on continued usage

**Common improvements**:
- Reorganize to make critical information more prominent
- Use stronger language for rules ("MUST filter" vs "always filter")
- Add missing workflows or validation steps
- Split large files using progressive disclosure
- Improve description for better skill activation

## Common Patterns

### Template Pattern

**For strict requirements**:
````markdown
## Output Format

ALWAYS use this exact template structure:

```markdown
# [Title]

## Section 1
[Content]
```
````

**For flexible guidance**:
````markdown
## Output Format

Here is a sensible default format, but use your best judgment:

```markdown
# [Title]
[Adapt as needed]
```

Adjust sections based on specific context.
````

### Examples Pattern

Provide input/output pairs for quality-dependent tasks:

````markdown
## Commit Message Format

**Example 1:**
Input: Added user authentication
Output:
```
feat(auth): implement JWT authentication

Add login endpoint and token validation
```

Follow this style: type(scope): brief description
````

### Conditional Workflow Pattern

````markdown
## Document Processing Workflow

1. Determine document type:

   **Creating new?** → Follow creation workflow below
   **Editing existing?** → Follow editing workflow below

2. Creation workflow:
   - Step A
   - Step B

3. Editing workflow:
   - Step X
   - Step Y
````

### Feedback Loop Pattern

Greatly improves quality:

```markdown
## Validation Process

1. Create your output
2. **Validate immediately**: `python validate.py output.json`
3. If validation fails:
   - Review errors carefully
   - Fix issues
   - Run validation again
4. **Only proceed when validation passes**
5. Finalize and save
```

## Best Practices Checklist

Before finalizing a skill, verify:

### Core Quality
- [ ] Description is specific with key terms and triggers
- [ ] Description includes both what and when
- [ ] SKILL.md body under 500 lines
- [ ] Progressive disclosure used appropriately
- [ ] No time-sensitive information
- [ ] Consistent terminology throughout
- [ ] Examples are concrete
- [ ] File references are one level deep
- [ ] Workflows have clear steps and checklists

### Code and Scripts
- [ ] Scripts solve problems, don't punt to Claude
- [ ] Error handling is explicit and helpful
- [ ] No "voodoo constants" (all values justified)
- [ ] Required packages listed and verified
- [ ] No Windows-style paths (all forward slashes)
- [ ] Validation steps for critical operations
- [ ] Feedback loops for quality-critical tasks

### Testing
- [ ] At least 3 evaluations created
- [ ] Tested with target models (Haiku/Sonnet/Opus)
- [ ] Tested with real usage scenarios
- [ ] Team feedback incorporated

## Anti-Patterns to Avoid

**Too many options**: Provide a default with escape hatch, not multiple equal choices

**Punting to Claude**: Scripts should handle errors, not fail and expect Claude to figure it out

**Vague naming**: Use specific, action-oriented names, not "helper" or "utils"

**Nested references**: Keep all references one level from SKILL.md

**Over-explaining**: Don't explain what Claude already knows

**Time-sensitive content**: Use "old patterns" section for deprecated approaches

**Inconsistent terminology**: Choose one term and use it throughout

## Reference Documentation

**Detailed guides**:
- [STRUCTURE.md](reference/STRUCTURE.md) - Complete skill structure requirements
- [FRONTMATTER.md](reference/FRONTMATTER.md) - YAML frontmatter examples and validation
- [CONTENT.md](reference/CONTENT.md) - Content writing guidelines
- [SCRIPTS.md](reference/SCRIPTS.md) - Utility script patterns
- [TESTING.md](reference/TESTING.md) - Evaluation and testing approaches
- [BEST-PRACTICES.md](reference/BEST-PRACTICES.md) - Complete Anthropic best practices

**Templates**:
- [templates/basic/](templates/basic/) - Simple skill template
- [templates/with-scripts/](templates/with-scripts/) - Skill with utility scripts
- [templates/multi-domain/](templates/multi-domain/) - Multi-domain skill structure

## Troubleshooting

**Skill not activating**: Check description field - does it include specific triggers and key terms?

**Claude ignoring files**: Are references prominent enough in SKILL.md? Are file names descriptive?

**Context overflow**: Is SKILL.md over 500 lines? Split content into referenced files.

**Inconsistent behavior**: Are instructions too vague? Add more structure or provide default approaches.

**Scripts failing**: Do they handle errors explicitly? Are error messages helpful?

For more help, see [TROUBLESHOOTING.md](reference/TROUBLESHOOTING.md).
