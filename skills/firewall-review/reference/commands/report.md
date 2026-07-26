---
name: report
description: Render a consolidated customer-review Excel workbook, optional audit-grade PDF, and chain-of-custody manifest from approved findings. Gated on ≥1 approve in feedback.jsonl.
---

# /report — Render deliverables

No arguments. Operates on the most recent engagement.

**Implementation boundary:** this command is a reference workflow. The scripts it names are not shipped in `communitytools`; confirm an accessible compatible runtime before execution. See [`../IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md).

## What to do

### Step 1 — Preflight

- Check `findings.final.jsonl` exists. If not, error: "run /launch first".
- Check `feedback.jsonl` exists and has at least one `"decision":"approve"` entry.
  - If missing AND the operator has explicitly requested the report without running `/review` (e.g. asked for "the report now" / "skip review, render"), synthesize a batch-approve `feedback.jsonl` — one entry per finding with `decision: "approve"`, `decided_by: <engagement.lead_assessor>`, `mode: "batch-approve-at-report"`, and `reason` noting that interactive review was skipped by operator choice. This preserves the audit trail (the mode field makes the path explicit) and satisfies the `/report` gate. Print a one-line notice in chat so the operator sees it: "Synthesized batch-approve feedback.jsonl; audit trail records `mode: batch-approve-at-report`."
  - If missing AND the operator did NOT ask to skip `/review`, error: "run /review and approve at least one finding first".
- Verify `scoping-questionnaire.yaml` has non-empty `engagement.client`, `engagement.lead_assessor`, and `regulatory_overlay`. If any are empty, ASK the operator to fill them before rendering — these fields appear on the PDF cover page and in the appendix.

### Step 2 — Render deliverables

Run:

```bash
python3.11 scripts/render-pdf.py <engagement-dir>
python3.11 scripts/render-xlsx.py <engagement-dir>
```

These write:
- `deliverables/report.pdf` (10-section canonical audit layout; record the actual rendered page count)
- `deliverables/remediation-tracker.xlsx` (current base renderer: 28-column Findings & Action Plan plus 5 supporting tabs)
- `deliverables/manifest.json` (chain-of-custody: tool/skill versions + input SHA256s + engagement metadata)

### Customer-collaboration profile

When the customer requests all rule-review detail in one Excel file or supplies a network-team comment template, apply [`../reporting/network-team-review-workbook.md`](../reporting/network-team-review-workbook.md). The `.xlsx` becomes the primary handoff and the PDF is optional. Keep all supporting data as worksheets in the same workbook, place `Network Team Review` first, and preserve the base tracker content where it adds traceability.

Do not advertise a non-existent renderer flag. If the reference implementation does not yet produce this profile, build the profile from `findings.final.jsonl`, normalized rules, benchmark output, discarded items, and the manifest as a separate engagement reporting step; disclose that implementation gap in the handoff.

### Step 3 — Trigger learning loop

Run: `python3.11 scripts/propose-skills.py <engagement-dir>`

If ≥3 feedback entries share the same detector + proposed severity adjustment, the script writes a PendingCandidate YAML to `.claude/pending/<slug>.yaml` for curator review. Report the candidate count in chat.

### Step 4 — Confirm + open

Print:

```
✅ Deliverables rendered.

  PDF:       deliverables/report.pdf          (X KB, Y pages)
  Excel:     deliverables/remediation-tracker.xlsx
  Manifest:  deliverables/manifest.json

  Learning candidates proposed: N
    (review with /pending list, promote with /pending promote <id>)

Open:
  open <engagement-dir>/deliverables/report.pdf
  open <engagement-dir>/deliverables/remediation-tracker.xlsx
```

Attempt to open the PDF and Excel automatically via `bash -c "open <path>"` on macOS (or `xdg-open` on Linux). If the open command fails silently, give the operator the paths to open manually.

## Hard rules

- Do NOT render if the preflight fails. Missing approvals or missing engagement metadata = no deliverable ships.
- Every finding in the PDF must have: severity, title, detector, affected rule IDs, evidence (source file + line/offset when available + quoted rule text), impact, likelihood, recommendation, and ≥1 framework citation with version.
- The PDF's §10 Limitations must explicitly list findings in `held/` and `quarantine/` with counts — known unknowns are disclosed, never hidden.
- The manifest must include `input_sha256` for every original config file in `Pre-requisites/`, so the client can independently verify the inputs match what they provided.
- Every claim must comply with [`../validation/evidence-state-contract.md`](../validation/evidence-state-contract.md). Zero-hit, runtime reachability, environment-policy violations, ownership, upstream MFA, and central-manager assertions remain gaps unless their required evidence was supplied.
- The consolidated workbook must reconcile parsed-rule, enabled-rule, observation, severity, and evidence-gap counts before release. Customer-owned response fields remain blank or `Not provided`; never invent justifications, owners, hit counts, classifications, or closure dates.
