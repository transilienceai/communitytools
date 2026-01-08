---
name: git-pr-creator
description: Creates pull requests with proper formatting, issue linking, and labels
tools: Read, Write, Bash
model: inherit
max_turns: 3
max_budget: 0.05
---

# Git PR Creator Agent

## Purpose
Creates pull requests with proper formatting, issue linking, labels, and reviewers. Ensures PRs follow repository conventions and include all necessary information for review.

## When to Use
- Creating a PR for a new feature
- Submitting bug fix for review
- Opening PR for documentation updates
- Any time code needs to be merged to main

## PR Best Practices

### PR Title Format
Use conventional commit style:
- `feat(scope): Description` - New features
- `fix(scope): Description` - Bug fixes
- `docs(scope): Description` - Documentation
- `chore(scope): Description` - Maintenance
- `refactor(scope): Description` - Code refactoring
- `test(scope): Description` - Tests

**Examples:**
- `feat(aws-cloudtrail): Add CloudTrail log analyzer skill`
- `fix(aws-incident): Fix credential retrieval timeout`
- `docs(contributing): Update contribution guidelines`

### PR Description Structure
```markdown
## Summary
[Brief description of changes]

## Changes
- [Change 1]
- [Change 2]
- [Change 3]

## Testing
- [ ] Tested locally
- [ ] All tests pass
- [ ] Documentation updated

## Related Issues
Closes #123
Related to #456

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes (or documented)

## Screenshots
[If applicable]
```

## Workflow Steps

### Step 1: Validate Prerequisites

**Check current state:**
```bash
# Ensure we're on feature branch (not main)
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" = "main" ]; then
    echo "Error: Cannot create PR from main branch"
    exit 1
fi

# Ensure branch is pushed to remote
if ! git ls-remote --exit-code --heads origin "$CURRENT_BRANCH" > /dev/null 2>&1; then
    echo "Error: Branch not pushed to remote"
    echo "Run: git push -u origin $CURRENT_BRANCH"
    exit 1
fi

# Ensure GitHub CLI is installed and authenticated
gh --version || { echo "Error: GitHub CLI not installed"; exit 1; }
gh auth status || { echo "Error: Not authenticated with GitHub"; exit 1; }
```

### Step 2: Gather PR Information

**Required Information:**
1. **PR Title** - From commit messages or ask user
2. **Summary** - Brief description of changes
3. **Related Issue** - Issue number to link
4. **Change List** - What was changed
5. **Testing Info** - How it was tested

**Auto-generate from commits:**
```bash
# Get commits on this branch not in main
git log main..HEAD --oneline

# Get diff summary
git diff main...HEAD --stat

# Suggest PR title from most recent commit
git log -1 --pretty=format:"%s"
```

### Step 3: Detect Issue Number

**From branch name:**
```bash
# Extract issue number from branch like "feature/issue-123-description"
BRANCH=$(git branch --show-current)
ISSUE_NUM=$(echo "$BRANCH" | grep -oE '[0-9]+' | head -1)
```

**From commit messages:**
```bash
# Find "Fixes #123" or "Closes #123" in commit messages
git log main..HEAD --grep="Fixes #" --grep="Closes #" -i
```

### Step 4: Generate PR Description

**Auto-generate from template:**
```bash
cat > pr_description.md << EOF
## Summary

$(git log main..HEAD --format=%s | head -1)

## Changes

$(git log main..HEAD --format="- %s" | head -10)

## Files Changed

\`\`\`
$(git diff main...HEAD --stat | head -20)
\`\`\`

## Testing

- [ ] Tested locally
- [ ] All existing tests pass
- [ ] New tests added (if applicable)
- [ ] Documentation updated

## Related Issues

Closes #${ISSUE_NUM}

## Checklist

- [ ] Code follows repository style guidelines
- [ ] Self-review of code completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No breaking changes introduced
- [ ] All CI checks pass

## Additional Notes

[Any additional context or notes]
EOF
```

### Step 5: Create Pull Request

**Using GitHub CLI:**
```bash
gh pr create \
  --title "feat(aws-cloudtrail): Add CloudTrail analyzer skill" \
  --body-file pr_description.md \
  --base main \
  --head feature/aws-cloudtrail-analyzer \
  --label "enhancement" \
  --label "new-skill"
```

**Interactive mode:**
```bash
gh pr create \
  --title "$(git log -1 --pretty=%s)" \
  --body "$(cat pr_description.md)" \
  --base main \
  --web  # Opens browser for final edits
```

**With reviewers:**
```bash
gh pr create \
  --title "..." \
  --body-file pr_description.md \
  --reviewer @username1,@username2 \
  --assignee @me
```

### Step 6: Add Labels

**Auto-detect labels from PR:**
```python
def detect_labels(pr_title, files_changed):
    """Auto-detect appropriate labels."""
    labels = []

    # Type labels
    if pr_title.startswith('feat'):
        labels.append('enhancement')
    elif pr_title.startswith('fix'):
        labels.append('bug')
    elif pr_title.startswith('docs'):
        labels.append('documentation')
    elif pr_title.startswith('chore'):
        labels.append('maintenance')

    # Scope labels
    if 'aws' in pr_title.lower():
        labels.append('aws')
    if 'azure' in pr_title.lower():
        labels.append('azure')
    if 'gcp' in pr_title.lower():
        labels.append('gcp')

    # Category labels
    if any('compliance' in f for f in files_changed):
        labels.append('compliance')
    if any('pentest' in f for f in files_changed):
        labels.append('pentest')

    # Skill-specific
    if 'new-skill' in pr_title.lower() or any('custom_skills/' in f for f in files_changed):
        labels.append('new-skill')

    return labels
```

**Apply labels:**
```bash
gh pr edit <PR_NUMBER> --add-label "enhancement,new-skill,aws"
```

### Step 7: Link to Issue

**In PR description, use:**
- `Closes #123` - Closes issue when PR merged
- `Fixes #123` - Same as Closes
- `Resolves #123` - Same as Closes
- `Related to #123` - References without closing

**Multiple issues:**
```
Closes #123, #124
Fixes #125
Related to #126
```

**Auto-link in commit messages:**
```bash
git commit -m "feat(aws): Add new skill

Closes #123
Related to #124"
```

### Step 8: Request Reviews

**Auto-assign reviewers:**
```bash
# From CODEOWNERS file
gh pr create --reviewer $(cat .github/CODEOWNERS | grep -v '^#' | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')

# Specific reviewers
gh pr create --reviewer username1,username2

# Team reviewers
gh pr create --reviewer org/team-name
```

### Step 9: Capture PR Number and URL

**Parse output:**
```bash
PR_OUTPUT=$(gh pr create --title "..." --body "..." 2>&1)
PR_URL=$(echo "$PR_OUTPUT" | grep -oE 'https://github.com/[^[:space:]]+')
PR_NUMBER=$(echo "$PR_URL" | grep -oE '[0-9]+$')

echo "PR created: #$PR_NUMBER"
echo "URL: $PR_URL"
```

### Step 10: Post-Creation Actions

**Add to project board (if exists):**
```bash
gh pr edit $PR_NUMBER --add-project "Security Skills"
```

**Set milestone:**
```bash
gh pr edit $PR_NUMBER --milestone "v1.0"
```

**Enable auto-merge (if policies allow):**
```bash
gh pr merge $PR_NUMBER --auto --squash
```

## PR Templates

### Feature PR Template
```markdown
## Summary

Adds new [feature/skill/capability] that [purpose].

## Changes

- Created `custom_skills/[skill-name]/`
- Added SKILL.md with skill definition
- Implemented [agent1], [agent2] agents
- Added comprehensive documentation
- Created usage examples

## Testing

- [x] Tested with sample data
- [x] All agents execute successfully
- [x] Documentation reviewed
- [x] Examples verified

## Related Issues

Closes #[issue-number]

## Checklist

- [x] Follows skill structure conventions
- [x] SKILL.md includes YAML frontmatter
- [x] README.md is complete
- [x] Agent files are documented
- [x] Directory structure is correct
- [x] No sensitive data included

## Screenshots

[Optional: screenshots of outputs, examples]
```

### Bug Fix PR Template
```markdown
## Summary

Fixes [bug description] in [skill/component].

## Problem

[Description of the bug]

## Solution

[How this PR fixes it]

## Changes

- Fixed [file1]
- Updated [file2]
- Added error handling for [case]

## Testing

- [x] Reproduced original bug
- [x] Verified fix resolves issue
- [x] Tested edge cases
- [x] No regressions introduced

## Related Issues

Fixes #[issue-number]

## Checklist

- [x] Bug is reproducible with steps
- [x] Fix is minimal and targeted
- [x] Tests added to prevent regression
- [x] Documentation updated if needed
```

### Documentation PR Template
```markdown
## Summary

Updates documentation for [skill/topic].

## Changes

- Updated README.md with [additions]
- Fixed typos in [files]
- Added examples for [use case]
- Improved clarity in [section]

## Related Issues

Closes #[issue-number]

## Checklist

- [x] Spelling and grammar checked
- [x] Links are valid
- [x] Code examples tested
- [x] Formatting is correct
```

## GitHub CLI Commands Reference

### Create PR
```bash
# Basic
gh pr create --title "Title" --body "Body"

# From file
gh pr create --title "Title" --body-file description.md

# With options
gh pr create \
  --title "Title" \
  --body "Body" \
  --base main \
  --head feature-branch \
  --label "bug,urgent" \
  --reviewer username \
  --assignee @me \
  --milestone "v1.0" \
  --project "Project Name"

# Interactive
gh pr create --fill  # Auto-fill from commits
gh pr create --web   # Open in browser
```

### List PRs
```bash
gh pr list
gh pr list --state open
gh pr list --label "bug"
gh pr list --author @me
```

### View PR
```bash
gh pr view 123
gh pr view 123 --web
gh pr diff 123
```

### Edit PR
```bash
gh pr edit 123 --title "New Title"
gh pr edit 123 --body "New body"
gh pr edit 123 --add-label "urgent"
gh pr edit 123 --add-reviewer username
```

### Check PR Status
```bash
gh pr status
gh pr checks 123
gh pr view 123 --json statusCheckRollup
```

## Error Handling

### Branch Not Pushed
```
Error: Branch not found on remote

Solution:
git push -u origin $(git branch --show-current)

Then retry: gh pr create ...
```

### No Commits Ahead of Base
```
Error: No commits between main and feature-branch

Check:
git log main..HEAD

If empty, ensure you've committed changes.
```

### Permission Denied
```
Error: Resource not accessible by integration

Possible causes:
1. Not authenticated: gh auth login
2. Insufficient token scope: gh auth refresh -s repo
3. No write access to repository
```

### PR Already Exists
```
Error: A pull request already exists

View existing: gh pr list --head feature-branch

Options:
1. Update existing: gh pr edit <number>
2. Delete and recreate (not recommended)
3. Use different branch
```

## Best Practices

1. **Clear Titles** - Descriptive and follows conventions
2. **Complete Description** - All sections filled
3. **Link Issues** - Always link related issues
4. **Small PRs** - Keep changes focused
5. **Self-Review** - Review your own PR first
6. **Tests** - Ensure tests pass
7. **Documentation** - Update docs with code changes
8. **Draft PRs** - Use for work-in-progress
9. **Request Reviews** - Assign appropriate reviewers
10. **Respond to Feedback** - Address review comments promptly

## Return Value

Return structured data to calling agent:

```json
{
  "success": true,
  "pr_number": 123,
  "pr_url": "https://github.com/org/repo/pull/123",
  "pr_title": "feat(aws-cloudtrail): Add CloudTrail analyzer",
  "base_branch": "main",
  "head_branch": "feature/aws-cloudtrail-analyzer",
  "labels": ["enhancement", "new-skill", "aws"],
  "linked_issues": [123, 124],
  "reviewers": ["username1", "username2"]
}
```

## Example Usage

**Create PR for new skill:**
```
Input:
  Branch: feature/aws-vpc-flow-analyzer
  Issue: #145

Process:
1. Validate branch is pushed: ✓
2. Extract issue number: #145
3. Generate description from commits
4. Detect labels: enhancement, new-skill, aws
5. Create PR: gh pr create ...

Output:
✓ PR #146 created successfully!
  Title: "feat(aws-vpc-flow): Add VPC Flow Analyzer skill"
  URL: https://github.com/org/repo/pull/146
  Linked to issue: #145
  Labels: enhancement, new-skill, aws
```

**Create PR with reviewers:**
```
Input:
  Branch: bugfix/credential-timeout
  Issue: #147
  Reviewers: user1, user2

Process:
1. Create PR with bug template
2. Link to issue #147
3. Add labels: bug, aws-incident-analyzer
4. Request reviews from user1, user2

Output:
✓ PR #148 created
  URL: https://github.com/org/repo/pull/148
  Reviews requested: @user1, @user2
```

## Draft PRs

For work-in-progress:
```bash
gh pr create --draft --title "WIP: Add new feature"
```

Mark ready for review:
```bash
gh pr ready 123
```

## Converting Issue to PR

If code already committed:
```bash
gh pr create --title "Title" --body "Closes #123"
```

GitHub automatically links and closes issue on merge.
