---
model: sonnet
---

Create, update, or remove Claude Code skills using the `skiller` skill and `skiller` agent following Anthropic best practices.

**Instructions:**

1. **Invoke the skiller skill immediately**:
```bash
/skiller
```

2. **Determine operation** by asking user what they want to do:
   - **Create** a new skill from scratch
   - **Update** an existing skill (add features, fix issues, improve structure)
   - **Remove** a skill (delete with safety checks)

3. **For CREATE operations**:

   a. Ask user:
      - Skill name (gerund form: "processing-pdfs", "analyzing-data")
      - Purpose and description (WHAT it does, WHEN to use it)
      - Key features (3-5)
      - Will it need scripts? (Python tools)
      - Will it need reference files? (documentation)
      - Full GitHub workflow? (issue → branch → PR) or Quick generation?

   b. Use the skiller agent:
   ```
   Deploy skiller agent with operation: CREATE
   Skill name: [name]
   Features: [features]
   GitHub workflow: [yes/no]
   ```

   c. If GitHub workflow selected:
      - Create GitHub issue with feat label
      - Create feature branch
      - Generate skill files following `.claude/skills/skiller/SKILL.md`
      - Commit with conventional commit format
      - Push and create PR linking to issue

   d. If quick generation:
      - Generate skill files directly
      - No Git operations
      - User manually commits when ready

4. **For UPDATE operations**:

   a. Ask user:
      - Which skill to update? (list available skills if unclear)
      - What needs updating? (features, structure, documentation, validation)
      - Current issues or limitations?

   b. Check current skill structure:
   ```bash
   !ls -la .claude/skills/[skill-name]/
   !head -n 20 .claude/skills/[skill-name]/SKILL.md
   ```

   c. Use skiller agent:
   ```
   Deploy skiller agent with operation: UPDATE
   Skill: [skill-name]
   Changes needed: [description]
   ```

   d. Agent will:
      - Read current skill files
      - Analyze structure against best practices
      - Make targeted updates
      - Validate changes
      - Test with scenarios

5. **For REMOVE operations**:

   a. Ask user:
      - Which skill to remove?
      - Confirm deletion (safety check)

   b. Show what will be deleted:
   ```bash
   !find .claude/skills/[skill-name] -type f
   ```

   c. Confirm with user:
      - "This will delete [N] files in .claude/skills/[skill-name]/"
      - "Are you sure? (yes/no)"

   d. If confirmed, delete:
   ```bash
   !rm -rf .claude/skills/[skill-name]
   ```

   e. Check if skill referenced elsewhere:
   ```bash
   !grep -r "[skill-name]" .claude/ --exclude-dir=skills
   ```

   f. If references found, offer to update them or notify user

6. **Validation** (for CREATE and UPDATE):

   Run validation checks:
   ```bash
   # Frontmatter check
   !head -n 1 .claude/skills/[skill-name]/SKILL.md | grep -q "^---$" && echo "✓ Frontmatter valid" || echo "✗ Frontmatter invalid"

   # Size check
   !wc -l .claude/skills/[skill-name]/SKILL.md

   # File structure
   !test -f .claude/skills/[skill-name]/SKILL.md && echo "✓ SKILL.md exists"
   !test -f .claude/skills/[skill-name]/README.md && echo "✓ README.md exists"
   !test -f .claude/skills/[skill-name]/outputs/.gitkeep && echo "✓ outputs/.gitkeep exists"
   ```

7. **Testing** (for CREATE and UPDATE):

   Guide user through testing:
   - "Test the skill by invoking: /[skill-name]"
   - "Try 2-3 different scenarios"
   - "Verify workflows execute correctly"
   - "Check that skill activates on expected triggers"

8. **Summary**:

   Provide completion summary:
   ```
   ✓ Skill [operation] complete!

   Skill: [skill-name]
   Location: .claude/skills/[skill-name]/
   Files: [list files created/updated]
   [If GitHub workflow]
   - Issue: #[number]
   - Branch: [branch-name]
   - PR: #[number]

   Next steps:
   1. Test skill: /[skill-name]
   2. Try different scenarios
   3. [If PR] Review and merge PR
   ```

**Operation Flow Summary:**

```
User runs /skiller
  ↓
Invoke /skiller skill
  ↓
Ask: CREATE, UPDATE, or REMOVE?
  ↓
┌─────────────┬────────────────┬──────────────┐
│   CREATE    │    UPDATE      │   REMOVE     │
├─────────────┼────────────────┼──────────────┤
│ Get details │ Identify skill │ Confirm      │
│ Deploy agent│ Get changes    │ Show files   │
│ Generate    │ Deploy agent   │ Delete       │
│ Validate    │ Update files   │ Check refs   │
│ Test        │ Validate       │ Report       │
│ Summary     │ Test           │              │
│             │ Summary        │              │
└─────────────┴────────────────┴──────────────┘
```

**Guardrails:**

- **Always invoke /skiller skill first** - Contains critical workflow and best practices
- **Never skip validation** - Frontmatter, size, structure must be validated
- **Confirm before delete** - Double-check with user before removing skills
- **Follow Anthropic best practices** - Reference `.claude/skills/skiller/reference/`
- **Use skiller agent** - Don't generate manually, use the agent
- **Test before completing** - Guide user through testing scenarios
- **Conventional commits** - Use conventional commit format for Git operations
- **Link issues to PRs** - Always use "Fixes #123" or "Closes #123"

**Key Files to Reference:**

- `.claude/skills/skiller/SKILL.md` - Main workflow
- `.claude/skills/skiller/reference/FRONTMATTER.md` - YAML rules
- `.claude/skills/skiller/reference/STRUCTURE.md` - Directory structure
- `.claude/skills/skiller/reference/CONTENT.md` - Writing guidelines
- `.claude/agents/skiller.md` - Agent definition

**Example Usage:**

Create new skill:
```
User: /skiller
Assistant: I'll help you create, update, or remove a skill. What would you like to do?
User: Create a new skill
Assistant: [Invokes /skiller, asks for details, deploys skiller agent]
```

Update existing skill:
```
User: /skiller
Assistant: What would you like to do? (CREATE/UPDATE/REMOVE)
User: Update the pentest skill
Assistant: [Invokes skill, checks current structure, asks what to update, deploys agent]
```

Remove skill:
```
User: /skiller
Assistant: What would you like to do?
User: Remove the old-skill
Assistant: [Shows files, confirms, deletes, checks references]
```
