# Completion Report Schema

The completion report documents the final state of a solved HTB challenge. Written in step 11 of the workflow to `reports/completion-report.md`, this report serves as:
- Input for Slack completion notification (step 12)
- Archive for future reference
- Source for skill improvement feedback (via `/skill-update`)

---

## File Location & Metadata

**Path**: `{OUTPUT_DIR}/reports/completion-report.md`

**Timing**: After coordinator completes, before `/skill-update` runs (step 11)

**Source Data**:
- `challenge-meta.json` — Challenge metadata (difficulty, OS, category)
- `start_time.txt` — Challenge start timestamp (ISO 8601 UTC)
- `stats.json` — Experiment count, findings, agents spawned, duration
- `logs/mission-*.log` (NDJSON) — Activity timeline
- `findings/finding-NNN/` — Each vulnerability/flag found

---

## Document Structure

```markdown
# {Challenge Name} — Completion Report

## Challenge Metadata

| Field | Value |
|-------|-------|
| Platform | HackTheBox |
| Challenge | {Name} |
| Category | {Category} (e.g., Web, System, Crypto, etc.) |
| Difficulty | {Easy/Medium/Hard/Insane} |
| OS | {Linux/Windows/FreeBSD} |
| IP Address | {10.10.x.x} |

## Execution Summary

| Metric | Value |
|--------|-------|
| Status | ✅ PWNED / ❌ FAILED |
| Duration | HH:MM:SS |
| Started | YYYY-MM-DD HH:MM UTC |
| Completed | YYYY-MM-DD HH:MM UTC |
| User Flag | ✅ / ❌ |
| Root Flag | ✅ / ❌ |

## Statistics

- **Experiments**: N (test variations, payloads tried, exploitation attempts)
- **Findings**: M (distinct vulnerabilities, exploits, security issues discovered)
- **Agents Spawned**: K (executor agents, validators, researchers)
- **Time to First Finding**: HH:MM
- **Time to User Flag**: HH:MM (if achieved)
- **Time to Root Flag**: HH:MM (if achieved)

## Attack Chain

Write a **connected narrative** (3-8 sentences) describing the sequence of discoveries leading to the flags. Not bullet points—a story that flows logically.

**Example**:
> Initial reconnaissance via Nmap revealed a web application on port 80. The application was running a custom CMS with an unauthenticated SQL injection vulnerability in the search function. By exploiting this, we extracted user credentials and database contents. One credential granted access to an admin panel where a file upload feature existed. The upload validation could be bypassed using a double extension technique (.php.jpg), allowing arbitrary PHP execution. With RCE established, we read environment variables that contained database credentials for a second internal database. Using those credentials, we accessed the database and found the root flag stored in a notes table.

## Techniques Used

### By Category

#### Reconnaissance
- Technique 1: _brief context_
- Technique 2: _brief context_

#### Exploitation
- Technique 1: _brief context_
- Technique 2: _brief context_

#### Post-Exploitation / Privilege Escalation
- Technique 1: _brief context_

### Key Vulnerabilities Found

1. **Vulnerability Name** (CVSS 7.5)
   - **Type**: SQL Injection / RCE / IDOR / etc.
   - **Location**: /search endpoint, POST parameter `query`
   - **Impact**: Database read/write, authentication bypass
   - **Remediation**: Use prepared statements, input validation

2. **Vulnerability Name** (CVSS 6.2)
   - ...

## Lessons Learned

Document non-obvious insights that will improve future attempts on similar challenges:

- **Pattern**: When encountering file upload validations, check for extension-based filtering and try double extensions (.php.jpg, .jsp.txt, etc.)
- **Discovery**: CMS applications often have default admin paths; try /admin, /wp-admin, /administrator/
- **Blocker**: Initial password cracking via rockyou.txt failed; wordlist-based approach not viable for strong passwords—focus on logic flaws instead

## Failed Approaches

List what didn't work and why. Useful for skill improvement:

- Attempted SQL injection via UNION-based queries initially, but custom error handling prevented information disclosure
- Tried common default credentials on admin panel; all were changed
- Brute-force on SSH failed (correct behavior—moved to web layer)

## Tools & Resources Used

| Tool | Purpose | Outcome |
|------|---------|---------|
| Nmap | Port scanning | Discovered web service |
| SQLMap | SQLi testing | Confirmed vulnerability but too destructive for data extraction |
| Burp Suite | Traffic inspection | Identified filter bypass via encoding |
| Custom Python script | Automated payload generation | Successful RCE delivery |

## Artifacts Generated

- **Findings**: `/findings/finding-001/` (SQLi), `/findings/finding-002/` (RCE)
- **Activity Log**: `/logs/challenge.log` (NDJSON format)
- **Scripts**: `/artifacts/exploit.py`, `/artifacts/payload_encoder.py`

---

## Required Sections Checklist

✅ Challenge Metadata  
✅ Execution Summary  
✅ Statistics  
✅ Attack Chain (narrative, 3-8 sentences)  
✅ Techniques Used (by category)  
✅ Key Vulnerabilities  
✅ Lessons Learned  
✅ Failed Approaches  

---

## Usage in Workflow

### Step 11: Report Generation
```bash
# After coordinator completes
mkdir -p {OUTPUT_DIR}/reports

# Write completion-report.md from sources:
# - challenge-meta.json (metadata)
# - start_time.txt (timing)
# - stats.json (metrics)
# - findings/finding-NNN/ (techniques & vulnerabilities)
# - logs/ (activity timeline)
```

### Step 12: Slack Notification
```bash
# Extract these fields for Slack message:
# - Difficulty, OS, Duration (from Execution Summary)
# - Flag status (from Statistics)
# - Attack Chain (as narrative)
# - Techniques Used (as bullet list for "Key Techniques")
# - /skill-update output (for "Skills Updated")
```

### Step 10: Skill Update
The narrative attack chain and lessons learned inform which skills need updates. Pass to `/skill-update`:
- **Techniques** used → update relevant skill (e.g., injection, server-side)
- **Lessons** → add to cheat sheets / quickstart guides
- **Failed approaches** → document in skill reference (why they failed)

---

## Example Report

See `slack-notifications.md` for a full example of how this report flows into the Slack completion notification.

---

## Markdown Formatting Guidelines

- **Headers**: Use `#` for H1 (title), `##` for H2 (sections), `###` for H3 (subsections)
- **Tables**: Use pipes (`|`) for structured data (metadata, statistics, tools)
- **Lists**: Use `-` for bullets, `1.` for numbered
- **Emphasis**: `**bold**` for key terms, `_italic_` for context
- **Code**: Backticks for command names, URLs, file paths
- **Links**: `[text](url)` for internal references

---

## Timing Considerations

**When to write**: After coordinator returns but before `/skill-update` runs.

**Required inputs**:
- Challenge must be solved (both flags captured, or explicitly marked as failed)
- `stats.json` must exist (or recreate from logs)
- At least one finding documented in `findings/`

**If stats.json is missing**:
```bash
# Count from activity logs
agent_count=$(grep -c '"action":"spawn"' logs/challenge.log)
experiment_count=$(grep -c '"action":"probe"' logs/challenge.log)
finding_count=$(ls -d findings/finding-* 2>/dev/null | wc -l)
```

---

## Data Validation

Before submitting report to Slack:

- ✅ Duration calculated correctly (completed_time - start_time)
- ✅ All vulnerabilities have CVSS scores
- ✅ Attack chain is a narrative (not bullet list)
- ✅ Techniques section organized by exploitation phase
- ✅ At least one "Lesson Learned" documented
- ✅ Flag status matches actual findings (both ✅ or one ✅ + one ❌, etc.)
