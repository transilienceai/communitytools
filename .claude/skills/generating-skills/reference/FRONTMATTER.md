# YAML Frontmatter Reference

Complete guide to writing valid YAML frontmatter for Claude skills.

## Contents
- Frontmatter requirements
- Validation rules
- Good examples
- Bad examples (anti-patterns)
- Common mistakes

## Frontmatter Requirements

Every SKILL.md must start with YAML frontmatter enclosed in `---` markers:

```yaml
---
name: skill-name
description: What the skill does and when to use it
---
```

## Name Field Rules

**Maximum length**: 64 characters

**Allowed characters**:
- Lowercase letters (a-z)
- Numbers (0-9)
- Hyphens (-)

**Forbidden**:
- XML tags
- Reserved words: "anthropic", "claude"
- Uppercase letters
- Underscores
- Spaces

**Naming conventions**:
- Prefer gerund form (verb + -ing)
- Use hyphens for word separation
- Be specific and descriptive

### Good Name Examples

```yaml
name: processing-pdfs
name: analyzing-data
name: testing-code
name: managing-databases
name: writing-documentation
name: deploying-applications
```

### Bad Name Examples

```yaml
name: pdf_processor  # ✗ Underscores not allowed
name: ProcessingPDFs # ✗ Uppercase not allowed
name: PDF Processing # ✗ Spaces not allowed
name: helper         # ✗ Too vague
name: utils          # ✗ Too generic
name: anthropic-helper # ✗ Reserved word
name: claude-tools   # ✗ Reserved word
```

## Description Field Rules

**Maximum length**: 1024 characters

**Required**: Non-empty

**Forbidden**: XML tags

**Must include**:
1. **WHAT it does**: Clear explanation of functionality
2. **WHEN to use it**: Specific triggers and contexts
3. **Key terms**: Important keywords for discovery

**Point of view**: Third person (NOT first or second person)

### Good Description Examples

**Example 1 - PDF Processing:**
```yaml
description: Extract text and tables from PDF files, fill forms, merge documents. Use when working with PDF files or when the user mentions PDFs, forms, or document extraction.
```

Why it's good:
- ✓ Explains WHAT: extract, fill, merge
- ✓ Explains WHEN: working with PDFs, mentions forms
- ✓ Key terms: PDF, forms, documents, extract
- ✓ Third person

**Example 2 - Excel Analysis:**
```yaml
description: Analyze Excel spreadsheets, create pivot tables, generate charts. Use when analyzing Excel files, spreadsheets, tabular data, or .xlsx files.
```

Why it's good:
- ✓ Explains WHAT: analyze, create pivots, generate charts
- ✓ Explains WHEN: analyzing Excel, spreadsheets
- ✓ Key terms: Excel, spreadsheets, tabular data, xlsx
- ✓ Includes file extension for specificity

**Example 3 - Git Commits:**
```yaml
description: Generate descriptive commit messages by analyzing git diffs. Use when the user asks for help writing commit messages or reviewing staged changes.
```

Why it's good:
- ✓ Explains WHAT: generate commit messages from diffs
- ✓ Explains WHEN: writing commits, reviewing changes
- ✓ Key terms: commit, git, diffs, staged
- ✓ Specific user actions mentioned

**Example 4 - Code Testing:**
```yaml
description: Run unit tests, integration tests, and generate coverage reports. Use when testing code, debugging test failures, or when the user mentions tests, testing, or coverage.
```

Why it's good:
- ✓ Explains WHAT: run tests, generate reports
- ✓ Explains WHEN: testing, debugging, user mentions
- ✓ Key terms: tests, testing, coverage, debugging
- ✓ Multiple trigger phrases

### Bad Description Examples

**Example 1 - Too vague:**
```yaml
description: Helps with documents
```

Problems:
- ✗ Doesn't explain WHAT operations
- ✗ Doesn't explain WHEN to use
- ✗ No key terms for discovery
- ✗ What kind of documents?

**Example 2 - Wrong point of view:**
```yaml
description: I can help you process Excel files and create reports
```

Problems:
- ✗ First person ("I can help")
- Should be: "Processes Excel files and creates reports"

**Example 3 - No triggers:**
```yaml
description: Processes data files and generates output
```

Problems:
- ✗ Too generic (what kind of data?)
- ✗ No WHEN clause
- ✗ No specific triggers or keywords

**Example 4 - Missing key terms:**
```yaml
description: Handles form filling
```

Problems:
- ✗ Missing context (PDF forms? Web forms?)
- ✗ No WHEN clause
- ✗ No file types or specific terms

## Complete Frontmatter Examples

### Example: Data Analysis Skill

```yaml
---
name: analyzing-spreadsheets
description: Analyze CSV and Excel files with pandas, create visualizations, generate statistical summaries. Use when analyzing tabular data, spreadsheets, CSV files, or when the user mentions data analysis, charts, or statistics.
---
```

### Example: API Testing Skill

```yaml
---
name: testing-apis
description: Test REST APIs, validate responses, generate test reports. Use when testing APIs, debugging endpoints, or when the user mentions API testing, HTTP requests, or REST endpoints.
---
```

### Example: Database Management Skill

```yaml
---
name: managing-databases
description: Query databases, optimize schemas, backup and restore data. Use when working with databases, SQL queries, or when the user mentions database operations, schemas, or data migration.
---
```

## Validation Checklist

Before finalizing frontmatter:

### Name Field
- [ ] 64 characters or less
- [ ] Only lowercase letters, numbers, hyphens
- [ ] No XML tags
- [ ] Doesn't contain "anthropic" or "claude"
- [ ] Uses gerund form (processing, analyzing, testing)
- [ ] Specific and descriptive

### Description Field
- [ ] 1024 characters or less
- [ ] Non-empty
- [ ] No XML tags
- [ ] Includes WHAT it does
- [ ] Includes WHEN to use it
- [ ] Contains key terms and triggers
- [ ] Written in third person
- [ ] Specific, not vague

## Testing Your Frontmatter

**Test name validation:**
```bash
echo "name-to-test" | grep -qE '^[a-z0-9-]{1,64}$' && echo "Valid" || echo "Invalid"
```

**Test for gerund form:**
```bash
# Name should ideally end with -ing or contain a verb-ing form
echo "processing-pdfs" | grep -q "ing" && echo "Uses gerund" || echo "Check naming"
```

**Test description length:**
```bash
echo "your description here" | wc -c
# Should be <= 1024
```

## Common Mistakes

### Mistake 1: Using Underscores Instead of Hyphens

```yaml
# ✗ Wrong
name: pdf_processor

# ✓ Correct
name: processing-pdfs
```

### Mistake 2: Vague Names

```yaml
# ✗ Wrong
name: helper
name: utils
name: tools

# ✓ Correct
name: processing-documents
name: analyzing-logs
name: testing-endpoints
```

### Mistake 3: Description Without "When"

```yaml
# ✗ Wrong
description: Processes PDF files and extracts text

# ✓ Correct
description: Processes PDF files and extracts text. Use when working with PDFs or when the user mentions document extraction.
```

### Mistake 4: First/Second Person

```yaml
# ✗ Wrong
description: I can help you analyze data
description: You can use this to process files

# ✓ Correct
description: Analyzes data and generates reports
description: Processes files and transforms data
```

### Mistake 5: Missing Key Terms

```yaml
# ✗ Wrong
description: Works with spreadsheet files

# ✓ Correct
description: Analyzes Excel and CSV spreadsheets. Use when working with .xlsx, .csv, or tabular data.
```

## Tips for Writing Great Descriptions

1. **Be specific about file types**: Mention extensions (.xlsx, .pdf, .csv)
2. **Include action verbs**: extract, analyze, generate, process
3. **List key operations**: what specific things does it do?
4. **Name user intents**: "when the user wants to...", "when debugging..."
5. **Include domain terms**: technical keywords users might mention
6. **Think about discovery**: What would someone search for?

## Updating Frontmatter

When updating existing skills:

1. Read current frontmatter
2. Check against validation rules
3. Identify missing elements:
   - Is WHEN clause present?
   - Are key terms included?
   - Is it third person?
4. Update incrementally
5. Test skill activation
6. Iterate based on results

## Reference

- [Anthropic Skills Overview](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview#skill-structure)
- [Skills Best Practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)
