# Content Writing Guidelines

Complete guide to writing effective content for Claude skills following Anthropic best practices.

## Core Writing Principles

### 1. Concise is Key

**The context window is a public good.** Challenge every token you add:
- Does Claude really need this explanation?
- Can I assume Claude knows this?
- Does this paragraph justify its token cost?

**Good example** (50 tokens):
````markdown
## Extract PDF text

Use pdfplumber for text extraction:

```python
import pdfplumber

with pdfplumber.open("file.pdf") as pdf:
    text = pdf.pages[0].extract_text()
```
````

**Bad example** (150 tokens):
```markdown
## Extract PDF text

PDF (Portable Document Format) files are a common file format that contains
text, images, and other content. To extract text from a PDF, you'll need to
use a library. There are many libraries available for PDF processing, but we
recommend pdfplumber because it's easy to use and handles most cases well.
First, you'll need to install it using pip. Then you can use the code below...
```

**Why bad**: Over-explains what Claude already knows (PDFs, libraries, pip)

### 2. Default Assumption: Claude is Smart

Only add context Claude doesn't have:
- Domain-specific knowledge ✓
- Project-specific conventions ✓
- Specific file locations ✓
- Custom workflows ✓
- What PDFs are ✗
- How to import libraries ✗
- What pip does ✗

### 3. Write in Third Person

Skill descriptions are injected into system prompts. Use third person:

- ✓ **Good**: "Processes Excel files and generates reports"
- ✗ **Bad**: "I can help you process Excel files"
- ✗ **Bad**: "You can use this to process Excel files"

## Content Structure

### Quick Start Section

**Purpose**: Get users productive immediately

**Structure**:
1. Most common use case
2. Checklist for tracking progress
3. Reference to main workflow

**Example**:
````markdown
## Quick Start

**Most common use case**:
1. Copy this checklist:
```
Progress:
- [ ] Step 1: Analyze form structure
- [ ] Step 2: Extract field definitions
- [ ] Step 3: Validate field mappings
- [ ] Step 4: Fill form
- [ ] Step 5: Verify output
```

2. Follow workflow below
````

### Workflow Sections

**Always include checklists** for multi-step processes:

````markdown
## PDF Form Filling Workflow

Copy this checklist and track progress:

```
Task Progress:
- [ ] Step 1: Analyze the form
- [ ] Step 2: Create field mapping
- [ ] Step 3: Validate mapping
- [ ] Step 4: Fill the form
- [ ] Step 5: Verify output
```

**Step 1: Analyze the form**

Run: `python scripts/analyze_form.py input.pdf`

This extracts form fields and saves to `fields.json`.

**Step 2: Create field mapping**

Edit `fields.json` to add values for each field.

**Step 3: Validate mapping**

Run: `python scripts/validate_fields.py fields.json`

Fix any validation errors before continuing.

**Step 4: Fill the form**

Run: `python scripts/fill_form.py input.pdf fields.json output.pdf`

**Step 5: Verify output**

Run: `python scripts/verify_output.py output.pdf`

If verification fails, return to Step 2.
````

### Set Appropriate Degrees of Freedom

Match specificity to task fragility:

**High freedom** (text-based instructions):
```markdown
## Code Review Process

1. Analyze code structure and organization
2. Check for potential bugs or edge cases
3. Suggest improvements for readability
4. Verify adherence to project conventions
```

**Medium freedom** (pseudocode/templates):
````markdown
## Generate Report

Use this template and customize as needed:

```python
def generate_report(data, format="markdown", include_charts=True):
    # Process data
    # Generate output in specified format
    # Optionally include visualizations
```
````

**Low freedom** (exact scripts):
````markdown
## Database Migration

Run exactly this script:

```bash
python scripts/migrate.py --verify --backup
```

Do not modify the command or add additional flags.
````

## Common Content Patterns

### Template Pattern

**For strict requirements**:
````markdown
## Report Structure

ALWAYS use this exact template structure:

```markdown
# [Analysis Title]

## Executive Summary
[One-paragraph overview]

## Key Findings
- Finding 1 with data
- Finding 2 with data

## Recommendations
1. Specific recommendation
2. Specific recommendation
```
````

**For flexible guidance**:
````markdown
## Report Structure

Here is a sensible default format, but use your best judgment:

```markdown
# [Analysis Title]

## Executive Summary
[Overview]

## Key Findings
[Adapt based on what you discover]

## Recommendations
[Tailor to specific context]
```

Adjust sections as needed for the specific analysis type.
````

### Examples Pattern

Provide input/output pairs for quality-dependent tasks:

````markdown
## Commit Message Format

Generate commit messages following these examples:

**Example 1:**
Input: Added user authentication with JWT tokens
Output:
```
feat(auth): implement JWT-based authentication

Add login endpoint and token validation middleware
```

**Example 2:**
Input: Fixed bug where dates displayed incorrectly
Output:
```
fix(reports): correct date formatting in timezone conversion

Use UTC timestamps consistently across report generation
```

Follow this style: type(scope): brief description, then detailed explanation.
````

### Conditional Workflow Pattern

Guide Claude through decision points:

```markdown
## Document Processing Workflow

1. Determine document type:

   **Creating new content?** → Follow "Creation workflow" below
   **Editing existing content?** → Follow "Editing workflow" below

2. Creation workflow:
   - Use docx-js library
   - Build document from scratch
   - Export to .docx format

3. Editing workflow:
   - Unpack existing document
   - Modify XML directly
   - Validate after each change
   - Repack when complete
```

### Feedback Loop Pattern

Dramatically improves quality:

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

## Progressive Disclosure

### When to Link to Reference Files

**Link when**:
- Content > 100 lines
- Detailed API documentation
- Extended examples
- Advanced features
- Domain-specific information

**Keep in SKILL.md when**:
- Core workflow (< 50 lines)
- Quick start guide
- Common patterns
- Overview content

### How to Link Effectively

**Pattern 1: Brief overview + link**:
```markdown
## Form Filling

Basic usage:
[20 lines of quick start]

For advanced form filling features, see [FORMS.md](reference/FORMS.md).
```

**Pattern 2: Section list + links**:
```markdown
## Advanced Features

**Form filling**: See [FORMS.md](reference/FORMS.md) for complete guide
**API reference**: See [REFERENCE.md](reference/REFERENCE.md) for all methods
**Examples**: See [EXAMPLES.md](reference/EXAMPLES.md) for common patterns
```

**Pattern 3: Contextual links**:
```markdown
## Data Processing

Process CSV files:
[code example]

For Excel files, see [EXCEL.md](reference/EXCEL.md).
For JSON processing, see [JSON.md](reference/JSON.md).
```

### Reference File Table of Contents

For files > 100 lines, include TOC at top:

```markdown
# API Reference

## Contents
- Authentication and setup
- Core methods (create, read, update, delete)
- Advanced features (batch operations, webhooks)
- Error handling patterns
- Code examples

## Authentication and Setup
[content]

## Core Methods
[content]
```

**Why**: Ensures Claude sees full scope even with partial reads

## Avoid Time-Sensitive Content

**Bad example** (will become wrong):
```markdown
If you're doing this before August 2025, use the old API.
After August 2025, use the new API.
```

**Good example** (use "old patterns" section):
```markdown
## Current Method

Use the v2 API endpoint: `api.example.com/v2/messages`

## Old Patterns

<details>
<summary>Legacy v1 API (deprecated 2025-08)</summary>

The v1 API used: `api.example.com/v1/messages`

This endpoint is no longer supported.
</details>
```

## Consistent Terminology

**Choose one term** and use it throughout:

**Good - Consistent**:
- Always "API endpoint"
- Always "field"
- Always "extract"

**Bad - Inconsistent**:
- Mix "API endpoint", "URL", "API route", "path"
- Mix "field", "box", "element", "control"
- Mix "extract", "pull", "get", "retrieve"

## Writing for Scripts

### Solve, Don't Punt

**Good example** (handles errors):
```python
def process_file(path):
    """Process file, creating if it doesn't exist."""
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        # Create with default content instead of failing
        print(f"File {path} not found, creating default")
        with open(path, 'w') as f:
            f.write('')
        return ''
    except PermissionError:
        # Provide alternative instead of failing
        print(f"Cannot access {path}, using default")
        return ''
```

**Bad example** (punts to Claude):
```python
def process_file(path):
    # Just fail and let Claude figure it out
    return open(path).read()
```

### Document Configuration

Avoid "voodoo constants":

**Good example** (self-documenting):
```python
# HTTP requests typically complete within 30 seconds
# Longer timeout accounts for slow connections
REQUEST_TIMEOUT = 30

# Three retries balances reliability vs speed
# Most intermittent failures resolve by second retry
MAX_RETRIES = 3
```

**Bad example** (magic numbers):
```python
TIMEOUT = 47  # Why 47?
RETRIES = 5   # Why 5?
```

### Make Execution Intent Clear

**For scripts to execute**:
```markdown
Run `analyze_form.py` to extract fields:
```bash
python scripts/analyze_form.py input.pdf > fields.json
```

**For scripts as reference**:
```markdown
See `analyze_form.py` for the field extraction algorithm.
```

## Anti-Patterns to Avoid

### 1. Too Many Options

**Bad**:
"You can use pypdf, or pdfplumber, or PyMuPDF, or pdf2image, or..."

**Good**:
````markdown
Use pdfplumber for text extraction:
```python
import pdfplumber
```

For scanned PDFs requiring OCR, use pdf2image with pytesseract instead.
````

### 2. Explaining the Obvious

**Bad**:
"Python is a programming language. To use a library, you need to import it. The import statement loads the library into your program."

**Good**:
````markdown
```python
import pdfplumber
```
````

### 3. Vague Instructions

**Bad**:
"Process the data appropriately"

**Good**:
"Parse CSV rows, validate email format, filter invalid entries"

### 4. Missing Context for Why

**Bad**:
"Use this command: `git commit --amend --no-edit`"

**Good**:
"Add changes to the previous commit without modifying the message:
`git commit --amend --no-edit`"

## Content Checklist

Before finalizing content:

### Core Quality
- [ ] Concise (no unnecessary explanations)
- [ ] Assumes Claude is smart
- [ ] Third person for all descriptions
- [ ] Consistent terminology
- [ ] No time-sensitive information
- [ ] Clear workflows with checklists
- [ ] Appropriate degree of freedom

### Structure
- [ ] Quick start section present
- [ ] Workflows have checklists
- [ ] Examples are concrete
- [ ] Progressive disclosure used
- [ ] References one level deep
- [ ] Long files have table of contents

### Scripts and Code
- [ ] Scripts solve problems, don't punt
- [ ] Error handling is explicit
- [ ] Configuration is documented
- [ ] Execution intent is clear
- [ ] No magic numbers

### Patterns
- [ ] Templates provided where needed
- [ ] Examples show input/output
- [ ] Conditional workflows guide decisions
- [ ] Feedback loops for quality-critical tasks

## Examples

See [content-examples.md](content-examples.md) for complete examples of well-written skill content.

## Reference

- [Conciseness](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices#concise-is-key)
- [Degrees of Freedom](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices#set-appropriate-degrees-of-freedom)
- [Common Patterns](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices#common-patterns)
