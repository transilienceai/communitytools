# YAML Frontmatter Reference

How to write valid YAML frontmatter for Claude skills.

## Contents
- Requirements
- Validation rules
- Examples (good and bad)
- Common mistakes

## Requirements

Every SKILL.md must start with YAML frontmatter:

```yaml
---
name: skill-name
description: What the skill does and when to use it
---
```

## Name field

- **Max 64 chars**
- **Allowed**: lowercase letters, digits, hyphens
- **Forbidden**: XML tags, reserved words ("anthropic", "claude"), uppercase, underscores, spaces
- **Convention**: gerund form (verb + -ing), specific and descriptive

**Good**:
```yaml
name: processing-pdfs
name: analyzing-data
name: testing-code
name: managing-databases
name: writing-documentation
name: deploying-applications
```

**Bad**:
```yaml
name: pdf_processor       # underscores
name: ProcessingPDFs      # uppercase
name: PDF Processing      # spaces
name: helper              # too vague
name: utils               # too generic
name: anthropic-helper    # reserved word
name: claude-tools        # reserved word
```

## Description field

- **Max 1024 chars**, non-empty, no XML tags
- **Must include**: WHAT it does, WHEN to use it, key terms (file extensions, technical keywords)
- **Point of view**: third person

**Good**:
```yaml
description: Extract text and tables from PDF files, fill forms, merge documents. Use when working with PDF files or when the user mentions PDFs, forms, or document extraction.
```
WHAT (extract/fill/merge) + WHEN (working with PDFs, mentions forms) + key terms (PDF, forms, documents, extract).

```yaml
description: Analyze Excel spreadsheets, create pivot tables, generate charts. Use when analyzing Excel files, spreadsheets, tabular data, or .xlsx files.
```
File extensions for specificity.

```yaml
description: Generate descriptive commit messages by analyzing git diffs. Use when the user asks for help writing commit messages or reviewing staged changes.
```
Specific user actions.

```yaml
description: Run unit tests, integration tests, and generate coverage reports. Use when testing code, debugging test failures, or when the user mentions tests, testing, or coverage.
```
Multiple trigger phrases.

**Bad — too vague**:
```yaml
description: Helps with documents
```

**Bad — wrong POV**:
```yaml
description: I can help you process Excel files and create reports
# → "Processes Excel files and creates reports"
```

**Bad — no triggers**:
```yaml
description: Processes data files and generates output
```

**Bad — missing context**:
```yaml
description: Handles form filling
# PDF forms? Web forms? When?
```

## Complete Examples

```yaml
---
name: analyzing-spreadsheets
description: Analyze CSV and Excel files with pandas, create visualizations, generate statistical summaries. Use when analyzing tabular data, spreadsheets, CSV files, or when the user mentions data analysis, charts, or statistics.
---
```

```yaml
---
name: testing-apis
description: Test REST APIs, validate responses, generate test reports. Use when testing APIs, debugging endpoints, or when the user mentions API testing, HTTP requests, or REST endpoints.
---
```

```yaml
---
name: managing-databases
description: Query databases, optimize schemas, backup and restore data. Use when working with databases, SQL queries, or when the user mentions database operations, schemas, or data migration.
---
```

## Validation Checklist

**Name**:
- [ ] ≤ 64 chars
- [ ] Only [a-z0-9-]
- [ ] No XML tags or reserved words
- [ ] Gerund form
- [ ] Specific and descriptive

**Description**:
- [ ] ≤ 1024 chars, non-empty, no XML tags
- [ ] Has WHAT and WHEN
- [ ] Key terms / triggers present
- [ ] Third person
- [ ] Specific, not vague

## Quick Validation

```bash
# Name regex
echo "name-to-test" | grep -qE '^[a-z0-9-]{1,64}$' && echo Valid || echo Invalid

# Description length
echo "your description here" | wc -c   # should be <= 1024
```

## Common Mistakes

**Underscores → use hyphens**:
```yaml
name: pdf_processor    # wrong
name: processing-pdfs  # right
```

**Vague names → be specific**:
```yaml
name: helper           # wrong
name: processing-documents  # right
```

**Description without "when"**:
```yaml
description: Processes PDF files and extracts text  # wrong
description: Processes PDF files and extracts text. Use when working with PDFs or when the user mentions document extraction.  # right
```

**First/second person → third**:
```yaml
description: I can help you analyze data       # wrong
description: You can use this to process files # wrong
description: Analyzes data and generates reports  # right
```

**Missing key terms**:
```yaml
description: Works with spreadsheet files  # wrong
description: Analyzes Excel and CSV spreadsheets. Use when working with .xlsx, .csv, or tabular data.  # right
```

## Tips for Great Descriptions

1. Specific file types (mention extensions: `.xlsx`, `.pdf`, `.csv`)
2. Action verbs (extract, analyze, generate, process)
3. List key operations
4. Name user intents ("when the user wants to...", "when debugging...")
5. Domain terms users might search for
6. Think discovery: what would someone search for?

## Updating Frontmatter

Read current frontmatter → check against rules → identify gaps (missing WHEN, key terms, third person) → update incrementally → test skill activation → iterate.

## Reference

- [Anthropic Skills Overview](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview#skill-structure)
- [Skills Best Practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)
