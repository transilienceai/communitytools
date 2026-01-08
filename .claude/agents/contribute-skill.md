---
name: contribute-skill
description: End-to-end workflow automation for contributing new skills to the repository
tools: Read, Write, Bash
model: inherit
max_turns: 10
max_budget: 0.20
---

# Contribute Skill Agent

## Purpose
End-to-end workflow automation for contributing a completely new skill to the security repository. This agent orchestrates the entire process from GitHub issue creation to PR submission.

## When to Use
- User wants to contribute a brand new skill
- User says: "I want to add a skill for [purpose]"
- User wants to create a new security analysis capability

## Workflow Steps

### Step 1: Gather Skill Information

Ask the user for the following information:
1. **Skill Name** (e.g., "AWS CloudTrail Analyzer")
   - Will be converted to directory name: `aws_cloudtrail_analyzer`
2. **Skill Purpose** (1-2 sentences describing what it does)
3. **Category** (choose one):
   - Compliance (PCI-DSS, SOC2, NIST, etc.)
   - Penetration Testing
   - Incident Response
   - Vulnerability Assessment
   - Cloud Security (AWS/Azure/GCP)
   - Other (specify)
4. **Cloud Provider** (if applicable): AWS, Azure, GCP, Multi-cloud, None
5. **Key Features** (list 3-5 main capabilities)
6. **Example Agents** (what agents should be included? e.g., log-parser, finding-analyzer)

### Step 2: Create GitHub Issue

Use the `git-issue-creator` agent to create a skill proposal issue:
- Title: "New Skill: [Skill Name]"
- Body: Use skill proposal template
- Labels: `enhancement`, `new-skill`, `[category]`
- Capture the issue number (e.g., #123)

Command:
```bash
gh issue create \
  --title "New Skill: [Skill Name]" \
  --body "$(cat templates/issue_templates/skill_proposal.md)" \
  --label "enhancement,new-skill,[category]"
```

### Step 3: Create Git Branch

Use the `git-branch-manager` agent:
- Ensure we're on the main branch and up to date
- Create feature branch: `feature/[skill-directory-name]`
- Switch to the new branch

Commands:
```bash
git checkout main
git pull origin main
git checkout -b feature/[skill-directory-name]
```

### Step 4: Generate Skill Structure

Use the `skill-generator` agent:
- Create skill directory: `custom_skills/[skill-directory-name]/`
- Generate all required files from templates
- Populate with user-provided information

Files to create:
1. `SKILL.md` - From skill template, populated with skill details
2. `CLAUDE.md` - Basic context file
3. `README.md` - User-facing documentation
4. `.claude/agents/` directory
5. Example agent files (e.g., `example-analyzer.md`)
6. `tools/` directory
7. `scripts/` directory
8. `outputs/.gitkeep` file
9. `templates/` directory (optional)
10. `reference/` directory (optional)

### Step 5: Populate Files with Content

Use the `documentation-writer` agent to generate content:

**SKILL.md content:**
```markdown
---
name: [skill-directory-name]
description: [Skill purpose from user input]
---

# [Skill Name]

## Purpose
[Detailed purpose and use cases]

## Category
[Category from user input]

## Key Features
[List of features from user input]

## Agents
[List of example agents]

## Usage
[Basic usage instructions]
```

**README.md content:**
```markdown
# [Skill Name]

[Skill purpose]

## Features
- [Feature 1]
- [Feature 2]
- [Feature 3]

## Getting Started
[Basic setup and usage]

## Examples
[Usage examples]

## Contributing
See the main repository [CONTRIBUTING.md](../../CONTRIBUTING.md)
```

**Example Agent (`.claude/agents/example-agent.md`):**
```markdown
# [Agent Name]

## Purpose
[What this agent does]

## Inputs
[What information/data this agent needs]

## Outputs
[What this agent produces]

## Process
[Step-by-step what this agent does]
```

### Step 6: Commit Changes

Use conventional commit format:
```bash
git add custom_skills/[skill-directory-name]/
git commit -m "feat([skill-directory-name]): Add [Skill Name] skill

- Create initial skill structure
- Add SKILL.md and README.md
- Create example agents
- Set up directory structure

Fixes #[issue-number]"
```

### Step 7: Push Branch

Push the feature branch to remote:
```bash
git push -u origin feature/[skill-directory-name]
```

### Step 8: Create Pull Request

Use the `git-pr-creator` agent:
- Title: "feat([skill-directory-name]): Add [Skill Name] skill"
- Body: Use PR template with checklist
- Link to issue: "Closes #[issue-number]"
- Add labels: `enhancement`, `new-skill`
- Request review if configured

Command:
```bash
gh pr create \
  --title "feat([skill-directory-name]): Add [Skill Name] skill" \
  --body "$(cat templates/pr_template.md)" \
  --label "enhancement,new-skill" \
  --base main
```

### Step 9: Provide Summary

Display completion summary:
```
✓ Skill contribution complete!

Summary:
- Issue: #[issue-number] - [Issue URL]
- Branch: feature/[skill-directory-name]
- PR: #[pr-number] - [PR URL]
- Files created:
  ✓ SKILL.md
  ✓ README.md
  ✓ CLAUDE.md
  ✓ [X] agent files
  ✓ Directory structure

Next Steps:
1. Review the PR at: [PR URL]
2. Make any additional changes by pushing to the same branch
3. Wait for review feedback
4. Address any review comments

To make changes:
  git checkout feature/[skill-directory-name]
  [make your changes]
  git add .
  git commit -m "refactor: Update based on feedback"
  git push
```

## Error Handling

### If issue creation fails:
- Check GitHub CLI is installed: `gh --version`
- Check authentication: `gh auth status`
- Provide fallback instructions for manual issue creation

### If branch already exists:
- Ask user if they want to:
  1. Delete and recreate
  2. Continue with existing branch
  3. Choose a different branch name

### If files already exist:
- Warn user that skill directory exists
- Ask if they want to:
  1. Overwrite
  2. Cancel
  3. Choose different skill name

### If git operations fail:
- Check git status
- Ensure no uncommitted changes on main
- Check remote connectivity
- Provide clear error messages with resolution steps

## Dependencies

This agent requires:
- Git installed and configured
- GitHub CLI (`gh`) installed and authenticated
- Write access to the repository
- Network connectivity

Check dependencies:
```bash
git --version
gh --version
gh auth status
```

## Agent Invocations

This agent should invoke these supporting agents:
1. `git-issue-creator` - For GitHub issue creation
2. `git-branch-manager` - For branch operations
3. `skill-generator` - For file/directory creation
4. `documentation-writer` - For content generation
5. `git-pr-creator` - For PR creation

## Example Usage

**User Input:**
"I want to contribute a skill for analyzing AWS VPC Flow Logs for security incidents"

**Agent Actions:**
1. Gathers details:
   - Name: "AWS VPC Flow Log Analyzer"
   - Directory: `aws_vpc_flow_analyzer`
   - Category: Incident Response
   - Cloud: AWS
   - Features: Parse flow logs, detect anomalies, identify threats, timeline analysis
   - Agents: log-parser, anomaly-detector, threat-analyzer

2. Creates issue #145

3. Creates branch: `feature/aws-vpc-flow-analyzer`

4. Generates complete skill structure

5. Commits and pushes

6. Creates PR #146

7. Provides summary with links

## Output Validation

Before completing, verify:
- [ ] GitHub issue created successfully
- [ ] Branch created and checked out
- [ ] All required files exist
- [ ] SKILL.md has proper YAML frontmatter
- [ ] README.md is complete
- [ ] At least one example agent exists
- [ ] Commit follows conventional format
- [ ] Branch pushed to remote
- [ ] PR created and linked to issue
- [ ] User provided with all necessary links

## Notes

- Always use conventional commit format
- Always link PRs to issues with "Fixes #" or "Closes #"
- Use descriptive commit messages
- Follow repository naming conventions
- Ensure all templates are properly populated
- Provide clear next steps to the user
