# Content Writing Guidelines

How to write effective content for Claude skills.

## Core Principles

1. **Concise** — challenge every token. Skip explanations Claude already has (what PDFs are, what `pip` does, importing libraries). Spend tokens on domain knowledge, project conventions, file locations, custom workflows.

2. **Third person** — descriptions are injected into system prompts.
   - Good: "Processes Excel files and generates reports"
   - Bad: "I can help you process Excel files" / "You can use this to..."

3. **Consistent terminology** — pick one term per concept and stay with it (always "field", not a mix of "field/box/element/control").

4. **No time-sensitive content** — instead of "after August 2025 use new API", document the current method and put deprecated info in a `<details>` block.

## Content Structure

### Quick Start section

Get users productive fast: most-common use case + checklist + reference to main workflow.

````markdown
## Quick Start
1. Copy this checklist:
```
- [ ] Step 1: Analyze form
- [ ] Step 2: Extract fields
- [ ] Step 3: Validate mapping
- [ ] Step 4: Fill form
- [ ] Step 5: Verify output
```
2. Follow workflow below.
````

### Workflows always have checklists

Multi-step processes get an explicit checklist plus a per-step section that names the exact script or action.

````markdown
**Step 1: Analyze the form**
Run: `python scripts/analyze_form.py input.pdf`
Outputs `fields.json`.

**Step 2: Create field mapping**
Edit `fields.json` to add values for each field.

**Step 3: Validate**
Run: `python scripts/validate_fields.py fields.json` and fix errors before continuing.
````

### Match degrees of freedom to task fragility

- **High freedom** — text-only instructions for stable, judgment-driven work (code review, prose writing).
- **Medium freedom** — pseudocode / templates for tasks where shape matters but details vary.
- **Low freedom** — exact commands when correctness depends on the literal command. Example: `python scripts/migrate.py --verify --backup`.

## Patterns

### Template

For strict requirements, give the exact template. For flexible guidance, give a default and explicitly note "use your best judgment, adjust sections as needed".

### Examples (input/output pairs)

For quality-dependent tasks, show pairs:

````markdown
Input: Added user auth with JWT tokens
Output:
```
feat(auth): implement JWT-based authentication

Add login endpoint and token validation middleware
```
````

### Conditional workflow

Branch on a decision point with named workflows:

```markdown
Determine type:
  Creating new content?  → "Creation workflow"
  Editing existing?      → "Editing workflow"

Creation workflow: use docx-js, build from scratch, export to .docx.
Editing workflow:  unpack, modify XML, validate after each change, repack.
```

### Feedback loop

```markdown
1. Create output
2. Validate immediately: `python validate.py output.json`
3. If validation fails: review errors, fix, re-validate
4. Only proceed when validation passes
5. Finalize
```

## Progressive Disclosure

**Link to a reference file when**: content > 100 lines, detailed API docs, extended examples, advanced features, domain-specific deep-dives.

**Keep in SKILL.md when**: core workflow (< 50 lines), quick start, common patterns, overview.

**Linking patterns**:
- Brief overview + link to deeper file
- Section list with one link per section
- Contextual inline links (`For Excel see EXCEL.md, for JSON see JSON.md`)

For reference files > 100 lines, include a contents list at the top so partial reads still see scope:

```markdown
# API Reference

## Contents
- Authentication and setup
- Core methods (CRUD)
- Advanced features (batch, webhooks)
- Error handling
- Code examples
```

## Scripts

### Solve, don't punt

Handle errors so the script makes progress; don't fail silently and expect Claude to figure it out.

```python
def process_file(path):
    """Process file, creating if missing."""
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        print(f"File {path} not found, creating default")
        with open(path, 'w') as f:
            f.write('')
        return ''
    except PermissionError:
        print(f"Cannot access {path}, using default")
        return ''
```

### Document config (no magic numbers)

```python
# HTTP requests typically complete within 30s; longer covers slow links
REQUEST_TIMEOUT = 30
# Three retries balances reliability vs speed
MAX_RETRIES = 3
```

### Make execution intent clear

Distinguish "run this" from "read this for the algorithm":

```markdown
Run `analyze_form.py` to extract fields:
`python scripts/analyze_form.py input.pdf > fields.json`

(or: "See `analyze_form.py` for the field-extraction algorithm.")
```

## Anti-Patterns

- **Too many options** — pick one preferred tool/approach; mention alternatives only when context demands.
- **Explaining the obvious** — "Python is a programming language" wastes tokens.
- **Vague instructions** — "process the data appropriately" → "parse CSV rows, validate email format, drop invalid entries".
- **No "why"** — `git commit --amend --no-edit` should come with "to add changes to the previous commit without rewriting the message".

## Content Checklist

**Quality**: concise, assumes Claude is smart, third person, consistent terminology, no time-sensitive content, clear workflows with checklists, freedom matches task.

**Structure**: quick start present, workflows have checklists, examples concrete, progressive disclosure used, references one level deep, long files have contents list.

**Scripts/code**: scripts handle errors, config documented, intent clear, no magic numbers.

**Patterns**: templates where strictness matters, input/output examples for quality-critical work, conditional workflows for decision points, feedback loops for verifiable tasks.

## Reference

- [Concise is Key](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices#concise-is-key)
- [Degrees of Freedom](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices#set-appropriate-degrees-of-freedom)
- [Common Patterns](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices#common-patterns)
