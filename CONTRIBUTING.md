# Contributing to Transilience AI Community Tools

Thank you for your interest in contributing to the Transilience AI Community Tools! This repository thrives on community contributions, and we welcome developers, security researchers, and enthusiasts of all skill levels.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Contributing New Tools](#contributing-new-tools)
- [Contributing to Pentest Framework](#contributing-to-pentest-framework)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Community](#community)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming, inclusive, and harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Expected Behavior:**
- Be respectful and inclusive
- Welcome newcomers and help them learn
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy toward other community members

**Unacceptable Behavior:**
- Harassment, trolling, or discriminatory comments
- Publishing others' private information
- Personal or political attacks
- Any conduct inappropriate in a professional setting

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by opening an issue or contacting the project maintainers at [contact@transilience.ai](mailto:contact@transilience.ai).

---

## Ways to Contribute

There are many ways to contribute to this project:

### 1. Report Bugs and Issues
- Found a false positive in the pentest framework? Report it!
- Discovered a bug in existing tools? Let us know!
- Issues template available for structured reporting

### 2. Improve Documentation
- Fix typos or clarify instructions
- Add examples and use cases
- Create tutorials or blog posts
- Improve README files

### 3. Contribute Code
- Fix bugs in existing tools
- Add new security testing agents
- Improve detection accuracy
- Optimize performance
- Add new features

### 4. Add New Tools
- Contribute entirely new security tools
- Share your frameworks or utilities
- Extend existing tools with new capabilities

### 5. Testing and Validation
- Test tools against various targets
- Validate detection accuracy
- Report false positives/negatives
- Contribute test cases

### 6. Community Support
- Answer questions in GitHub Discussions
- Help other contributors
- Share your use cases and experience
- Provide feedback on proposed changes

---

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Git** installed ([download](https://git-scm.com/downloads))
- **GitHub account** ([sign up](https://github.com/join))
- **Claude Code** installed ([download](https://claude.ai/code))
- **Python 3.8+** for Python-based tools
- **GitHub CLI** (optional but recommended): `brew install gh` or [install guide](https://cli.github.com/)

### Fork and Clone

1. **Fork the repository** on GitHub by clicking the "Fork" button at the top right of the repository page

2. **Clone your fork locally:**

```bash
git clone https://github.com/YOUR_USERNAME/communitytools.git
cd communitytools
```

3. **Add the upstream repository:**

```bash
git remote add upstream https://github.com/transilienceai/communitytools.git
```

4. **Verify your remotes:**

```bash
git remote -v
# origin    https://github.com/YOUR_USERNAME/communitytools.git (fetch)
# origin    https://github.com/YOUR_USERNAME/communitytools.git (push)
# upstream  https://github.com/transilienceai/communitytools.git (fetch)
# upstream  https://github.com/transilienceai/communitytools.git (push)
```

### Install Dependencies

For the Pentest Framework:

```bash
cd pentest
pip install -r requirements.txt
```

For other tools, check their specific README files for dependencies.

---

## Development Workflow

We follow a standard GitHub workflow with feature branches and pull requests.

### Step 1: Create an Issue First

**Always create an issue before starting work** to:
- Discuss your proposed changes
- Get feedback from maintainers
- Avoid duplicate work
- Track progress

**Create an issue:**
```bash
gh issue create --title "Add XSS payload library" --body "Description of your proposal"
```

Or create one on the GitHub web interface: [Create Issue](https://github.com/transilienceai/communitytools/issues/new)

### Step 2: Create a Feature Branch

Create a branch from `main` using conventional naming:

**Branch Naming Convention:**
- `feature/description` - New features
- `bugfix/description` - Bug fixes
- `docs/description` - Documentation updates
- `enhancement/description` - Improvements to existing features

**Example:**
```bash
# Ensure main is up to date
git checkout main
git pull upstream main

# Create and switch to your feature branch
git checkout -b feature/xss-payload-library
```

### Step 3: Make Your Changes

- Write clean, readable code
- Follow existing code style and conventions
- Add comments where necessary
- Update documentation
- Add tests if applicable

### Step 4: Test Your Changes

Before committing:

```bash
# For Python tools, run tests
cd pentest
python -m pytest tests/

# Test your changes manually
# Verify nothing is broken
```

### Step 5: Commit Your Changes

Use **Conventional Commits** format:

**Commit Message Format:**
```
<type>(scope): <description> - Fixes #<issue_number>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```bash
git add .
git commit -m "feat(pentest): add advanced XSS payload library - Fixes #123"
git commit -m "fix(xss-tester): correct false positive detection - Fixes #124"
git commit -m "docs(readme): add installation troubleshooting section - Fixes #125"
```

### Step 6: Push to Your Fork

```bash
git push origin feature/xss-payload-library
```

### Step 7: Create a Pull Request

**Option A: Using GitHub CLI (Recommended)**

```bash
gh pr create --title "Add XSS payload library" --body "Closes #123

## Summary
- Added comprehensive XSS payload library
- Includes reflected, stored, and DOM-based payloads
- Added tests and documentation

## Testing
- Tested against DVWA and WebGoat
- All tests passing"
```

**Option B: Using GitHub Web Interface**

1. Go to your fork on GitHub
2. Click "Compare & pull request"
3. Fill in the PR template
4. Link to the issue using "Closes #123" or "Fixes #123"
5. Submit the PR

---

## Contributing New Tools

### Tool Structure Requirements

Every new tool should follow this structure:

```
tool-name/
├── README.md              # User-facing documentation
├── CLAUDE.md              # Claude Code integration context
├── LICENSE                # MIT License (or compatible)
├── requirements.txt       # Python dependencies
├── .claude/
│   ├── agents/           # Claude Code agents (if applicable)
│   │   └── agent-name.md
│   └── skills/           # Claude Code skills (if applicable)
│       └── skill-name/
│           └── SKILL.md
├── src/                  # Source code
├── tests/                # Test files
└── outputs/              # Output directory
    └── .gitkeep
```

### Required Documentation

**README.md must include:**
- Tool description and purpose
- Features and capabilities
- Installation instructions
- Usage examples
- Configuration options
- Output format
- License information
- Legal disclaimer (for security tools)

**CLAUDE.md should include:**
- Context for Claude Code
- Agent descriptions
- Skill capabilities
- Workflow instructions
- Best practices

### Adding a New Tool Checklist

- [ ] Create tool directory with proper structure
- [ ] Write comprehensive README.md
- [ ] Add CLAUDE.md for Claude Code integration
- [ ] Include requirements.txt with dependencies
- [ ] Add LICENSE file (MIT recommended)
- [ ] Write tests if applicable
- [ ] Create GitHub issue describing the tool
- [ ] Submit PR linking to the issue
- [ ] Update root README.md to list new tool

---

## Contributing to Pentest Framework

The pentest framework has specific contribution guidelines.

### Adding a New Security Testing Agent

**Agent File Structure:**
```markdown
---
name: agent-name
description: Brief description of what this agent does
---

# Agent Name

## Purpose
What vulnerability or security issue does this agent test for?

## Testing Methodology
How does this agent perform testing?

## Detection Criteria
What constitutes a positive finding?

## Output Format
What reports and evidence does this agent generate?

## Testing Instructions
Step-by-step instructions for Claude Code to execute
```

**Agent File Location:**
```
pentest/.claude/agents/agent-name.md
```

**Agent Naming Convention:**
- Use lowercase with hyphens: `sql-injection.md`, `xss-tester.md`
- Be descriptive and specific
- Match OWASP or CVE categories where applicable

**Required Elements:**
1. **Clear purpose** - What does this agent test?
2. **Testing methodology** - How does it work?
3. **Detection logic** - How to identify vulnerabilities accurately
4. **False positive prevention** - How to avoid false positives
5. **Evidence collection** - What proof should be gathered
6. **Report generation** - Output format requirements

### Improving Existing Agents

When improving detection accuracy:

1. **Document the issue** - What false positive or false negative occurred?
2. **Explain the fix** - How does your change improve detection?
3. **Test thoroughly** - Validate against multiple scenarios
4. **Update documentation** - Reflect changes in agent markdown

**Example PR Description:**
```markdown
## Problem
The SQL injection agent was producing false positives when the application
legitimately returns the word "MySQL" in help text.

## Solution
- Implemented baseline comparison methodology
- Changed detection from generic keywords to strict database-specific errors
- Added context-aware matching to differentiate application content from errors

## Testing
- Tested against DVWA, WebGoat, and production apps (authorized)
- Zero false positives in 50 test cases
- All true vulnerabilities still detected

Fixes #142
```

### Adding Test Payloads

Contribute new payloads to improve coverage:

**Location:** `pentest/payloads/<category>/`

**Format:**
```
payloads/
├── xss/
│   ├── reflected.txt
│   ├── stored.txt
│   └── dom-based.txt
├── sqli/
│   ├── error-based.txt
│   └── union-based.txt
└── README.md
```

---

## Coding Standards

### Python Code Style

Follow **PEP 8** style guide:

```python
# Good: Clear, readable, well-documented
def test_sql_injection(url: str, params: dict) -> bool:
    """
    Test for SQL injection vulnerability.

    Args:
        url: Target URL to test
        params: Query parameters to inject

    Returns:
        True if vulnerable, False otherwise
    """
    baseline = requests.get(url, params=params)
    # Test with SQL payload
    params['id'] = "1' OR '1'='1"
    response = requests.get(url, params=params)

    return is_vulnerable(response, baseline)
```

### Markdown Style

- Use ATX-style headers (`# Header` not `Header\n======`)
- Include blank lines between sections
- Use code fences with language identifiers
- Keep line length reasonable (80-120 characters)

### Shell Scripts

- Use `#!/bin/bash` shebang
- Quote variables: `"$var"` not `$var`
- Check exit codes: `|| exit 1`
- Add comments for complex logic

---

## Testing Guidelines

### Manual Testing

Before submitting a PR:

1. **Test against known vulnerable applications:**
   - DVWA (Damn Vulnerable Web Application)
   - WebGoat
   - Juice Shop
   - Your own test environments

2. **Verify false positive prevention:**
   - Test against production applications (authorized)
   - Ensure legitimate application behavior doesn't trigger false positives

3. **Document test results:**
   - Include test URLs (if public)
   - Screenshots of findings
   - Logs and evidence files

### Automated Testing

If adding Python code, include unit tests:

```python
# tests/test_sql_injection.py
import pytest
from agents.sql_injection import test_sql_injection

def test_detects_error_based_sqli():
    """Test that error-based SQLi is detected"""
    result = test_sql_injection(
        "http://testphp.vulnweb.com/artists.php?artist=1'",
        method="error"
    )
    assert result.vulnerable is True
    assert "SQL syntax error" in result.evidence

def test_no_false_positive_on_legitimate_content():
    """Test that legitimate content doesn't trigger false positives"""
    result = test_sql_injection(
        "http://example.com/help?query=MySQL",
        method="error"
    )
    assert result.vulnerable is False
```

Run tests:
```bash
cd pentest
python -m pytest tests/ -v
```

---

## Documentation

### Documentation Standards

- **Be clear and concise** - Write for beginners
- **Provide examples** - Show, don't just tell
- **Use proper formatting** - Headers, code blocks, lists
- **Keep it up to date** - Update docs when code changes
- **Include screenshots** - Visual aids help understanding

### Documentation to Update

When making changes, update:

1. **README.md** - User-facing documentation
2. **CLAUDE.md** - Claude Code context
3. **Code comments** - Inline documentation
4. **CHANGELOG.md** - Track changes (if applicable)
5. **Root README** - If adding new tools

---

## Pull Request Process

### Before Submitting

- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] Documentation is updated
- [ ] Commit messages follow conventions
- [ ] PR links to an issue

### PR Template

Your PR description should include:

```markdown
## Summary
Brief description of changes

## Related Issue
Fixes #123

## Changes Made
- Bullet list of specific changes
- What was added/modified/removed

## Testing
- How did you test this?
- What scenarios were covered?
- Any edge cases?

## Screenshots (if applicable)
Include visual evidence

## Checklist
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Tests passing
- [ ] No breaking changes (or documented)
```

### Review Process

1. **Automated checks run** - CI/CD validates your code
2. **Maintainer review** - We review within 2-5 business days
3. **Feedback addressed** - Make requested changes
4. **Approval and merge** - Once approved, we merge your PR

### After Your PR is Merged

- Your changes appear in the next release
- You're added to the contributors list
- Delete your feature branch:
  ```bash
  git checkout main
  git pull upstream main
  git branch -d feature/your-branch-name
  git push origin --delete feature/your-branch-name
  ```

---

## Issue Reporting

### Creating Quality Issues

**Good Issue:**
```markdown
**Title:** SQL Injection agent produces false positive on help page

**Description:**
When testing http://example.com/help, the SQL injection agent reports a
vulnerability because the page contains the word "database" in the help text.

**Steps to Reproduce:**
1. Run SQL injection agent against http://example.com/help
2. Agent reports vulnerability based on keyword "database"
3. Manual verification shows this is legitimate content, not an SQL error

**Expected Behavior:**
Agent should differentiate between application content and actual SQL errors

**Actual Behavior:**
False positive reported

**Environment:**
- Claude Code version: 1.0.0
- Python version: 3.9.5
- Target: http://example.com/help

**Screenshots:**
[Attach screenshots]

**Logs:**
[Attach relevant log files]
```

### Issue Templates

We provide templates for:
- **Bug Reports** - Something isn't working
- **Feature Requests** - New capabilities or improvements
- **False Positive Reports** - Detection accuracy issues
- **Documentation Issues** - Docs are unclear or wrong

---

## Community

### Getting Help

- **GitHub Discussions** - Ask questions, share ideas
- **GitHub Issues** - Report bugs or request features
- **Website** - [transilience.ai](https://transilience.ai)

### Recognition

Contributors are recognized in:
- GitHub Contributors list
- Release notes
- Project documentation

### Communication Guidelines

- Be patient and respectful
- Provide context and details
- Search before asking (issue might already exist)
- Follow up on your issues and PRs
- Thank people for their help

---

## Licensing

By contributing to this project, you agree that your contributions will be licensed under the **MIT License**.

### Third-Party Code

If your contribution includes third-party code:
- Ensure it's compatible with MIT License
- Include proper attribution
- Document the license in your PR

---

## Questions?

If you have questions about contributing:

1. Check existing [GitHub Discussions](https://github.com/transilienceai/communitytools/discussions)
2. Read through [closed issues](https://github.com/transilienceai/communitytools/issues?q=is%3Aissue+is%3Aclosed) for similar questions
3. Open a new [Discussion](https://github.com/transilienceai/communitytools/discussions/new) if your question is unanswered
4. Reach out to maintainers at [contact@transilience.ai](mailto:contact@transilience.ai)

---

## Thank You!

Your contributions make this project better for everyone in the security community. Whether you're fixing a typo, reporting a bug, or adding a major feature, we appreciate your effort and time.

**Happy Contributing!**

---

<div align="center">

**Made with love by the security community**

[Report Bug](https://github.com/transilienceai/communitytools/issues) · [Request Feature](https://github.com/transilienceai/communitytools/issues) · [Documentation](https://github.com/transilienceai/communitytools)

</div>
