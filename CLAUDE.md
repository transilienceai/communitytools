# Open Source Repository Manager - Claude Context

This skill provides git-workflow automation for contributing to the security skills repository.

## Key Principles

1. **User-Friendly**: Make git and open source contribution accessible to everyone
2. **Automated**: Minimize manual steps and potential errors
3. **Standardized**: Ensure consistent structure and conventions across all skills
4. **Complete**: Handle entire workflow from idea to merged PR

## When to Use This Skill

Use this skill whenever someone wants to:
- Contribute a new skill to the repository
- Enhance an existing skill with new features
- Fix bugs in existing skills
- Improve documentation
- Report issues

## Main Workflow: Contributing a New Skill

### User says something like:
- "I want to contribute a skill for..."
- "I need to add a new skill that..."
- "Can I create a skill for..."

### Agent should:
1. Use `contribute-skill` agent (the main orchestrator)
2. Gather skill information interactively
3. Create GitHub issue with `git-issue-creator`
4. Create branch with `git-branch-manager`
5. Generate skill structure with `skill-generator`
6. Commit and push changes
7. Create PR with `git-pr-creator`
8. Provide summary with all links

## Important Notes

### Always Follow This Sequence:
1. **Issue First** - Always create issue before PR
2. **Branch from Main** - Always create feature branches from main
3. **Conventional Commits** - Use proper commit message format
4. **Link Issues** - Always link PRs to issues with "Fixes #123"
5. **Validate Structure** - Ensure all required files exist

### Git Conventions:
- **Branch names**: `feature/skill-name`, `bugfix/description`, `docs/update`
- **Commit format**: `type(scope): description - Fixes #issue`
- **PR linking**: Use "Closes #123" or "Fixes #123" in PR description

### Skill Structure Requirements:
Every skill MUST have:
- SKILL.md with YAML frontmatter (---\nname: skill_name\ndescription: ...\n---)
- README.md with user documentation
- CLAUDE.md with additional context
- .claude/agents/ directory with at least one agent
- tools/__init__.py for Python package
- outputs/.gitkeep to preserve directory

### Naming Conventions:
- **Skill directories**: lowercase_with_underscores (e.g., `aws_cloudtrail_analyzer`)
- **Agent files**: lowercase-with-hyphens.md (e.g., `log-parser.md`)
- **Branch names**: lowercase-with-hyphens (e.g., `feature/aws-cloudtrail`)

## Error Handling

### If GitHub CLI not available:
- Check: `gh --version`
- Install instructions: https://cli.github.com/
- Authenticate: `gh auth login`

### If skill already exists:
- Ask user if they want to enhance existing skill instead
- Or suggest different skill name
- Don't overwrite without explicit confirmation

### If uncommitted changes detected:
- Warn user about uncommitted changes
- Ask: stash, commit, or discard?
- Don't proceed until resolved

## Tools Available

### Python Tools (in tools/):
1. **git_workflow_automation.py** - Git operations wrapper
   - Check prerequisites
   - Branch operations
   - Commit and push
   - GitHub issue/PR creation

2. **skill_scaffolder.py** - Skill generation
   - Validate names
   - Create directory structure
   - Generate files from templates
   - Populate with user data

### Templates (in templates/):
1. **issue_templates/** - GitHub issue templates
2. **skill_template/** - Complete skill structure
3. **pr_template.md** - Pull request template

## Agent Responsibilities

### contribute-skill (Main Orchestrator)
- Coordinates entire new skill contribution workflow
- Calls other agents as needed
- Provides user feedback at each step
- Returns final summary with links

### git-issue-creator
- Creates GitHub issues using templates
- Applies appropriate labels
- Returns issue number for linking

### git-branch-manager
- Creates branches with proper naming
- Validates branch names
- Handles uncommitted changes
- Switches branches safely

### skill-generator
- Validates skill names
- Creates directory structure
- Generates all required files
- Populates templates with user data

### git-pr-creator
- Creates pull requests
- Links to issues properly
- Applies labels
- Uses PR template

## Output Format

Always provide clear status updates:
```
’ Creating GitHub issue...
   Issue #123 created

’ Creating feature branch...
   Branch 'feature/skill-name' created

’ Generating skill structure...
   SKILL.md
   README.md
   Agent files

’ Creating PR...
   PR #124 created

 Complete!
  Issue: [URL]
  PR: [URL]
```

## Best Practices

1. **Interactive Prompts** - Ask questions to gather complete information
2. **Validate Early** - Check prerequisites before starting workflow
3. **Clear Feedback** - Show progress at each step with  or 
4. **Error Recovery** - Provide clear error messages with solutions
5. **Complete Information** - Return all relevant URLs and numbers
6. **Don't Assume** - Ask for clarification if user intent is unclear

## Validation Checklist

Before completing workflow, verify:
- [ ] GitHub issue created successfully
- [ ] Feature branch created from main
- [ ] All required files present (SKILL.md, README.md, CLAUDE.md, agents)
- [ ] SKILL.md has proper YAML frontmatter
- [ ] Directory structure follows conventions
- [ ] Commit message follows conventional format
- [ ] PR linked to issue with "Fixes #"
- [ ] User provided with all necessary links
