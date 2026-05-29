# Task 04 — Validation Regression Sweep

**Project**: attacks-validation (drift detection)
**Trigger**: Cron weekly — Mondays 02:00 UTC.
**Skill**: `regression-sweep`

## Inputs

- `OUTPUT_DIR`
- Optional `--since` ISO date to limit the sweep to findings validated after that date.

## Procedure

1. Load `skills/regression-sweep/SKILL.md`.
2. Glob `$OUTPUT_DIR/validated/*.json`. For each:
   - Resolve `FINDING_DIR = $OUTPUT_DIR/findings/{finding_id}/`.
   - Re-fire `python3 $FINDING_DIR/poc.py` with a 60s timeout. Capture stdout+stderr to `$FINDING_DIR/evidence/validation/regression-{YYYYWww}-rerun.txt`.
   - Diff against `evidence/validation/poc-rerun-output.txt` using the normalization rules in `skills/regression-sweep/reference/diff-normalization.md`.
   - Re-run `python3 tools/nvd-lookup.py <CVE>` to detect CVSS drift.
   - Classify as `still_valid | drift_severity | newly_invalid | newly_revalidated | inconclusive`.
3. Concurrency: max 5 parallel re-runs.
4. Write `$OUTPUT_DIR/artifacts/regression-{YYYYWww}.json` and the human MD report. Transitions are grouped under explicit headers in the MD report for analyst review.
5. Emit status JSON.

## Outputs

- `$OUTPUT_DIR/artifacts/regression-{YYYYWww}.json`
- `$OUTPUT_DIR/artifacts/regression-{YYYYWww}.md`
- Per-finding `evidence/validation/regression-{YYYYWww}-rerun.txt`

## Constraints — demonstrate, never disrupt

- **Re-firing PoCs is observation only.** Each `poc.py` is already constrained to demonstrate-only behavior at task-02 generation time and was confirmed safe by the Finding Validator at task-03. Re-running it here is an idempotent read.
- Timeouts → `inconclusive`, never `newly_invalid` (Rule 2 of `regression-sweep`).
- Idempotent within the same calendar week (Rule 5 of `regression-sweep`).
- 60-second hard timeout per PoC re-run.

## Status emit

```json
{"task": "regression-sweep", "status": "OK",
 "week": "2026W19",
 "counts": {"still_valid": 47, "drift_severity": 2, "newly_invalid": 5, "newly_revalidated": 1, "inconclusive": 3},
 "transitions": ["finding-018 → newly_invalid", "finding-024 → drift_severity"],
 "outputs": ["artifacts/regression-2026W19.json"],
 "next": [{"task": "task-08-exec-report", "reason": "regression-delta"}]}
```

The `transitions` array carries the rows that need analyst attention; the consuming runtime decides how to surface them (board ticket, dashboard, email — out of scope for this skill).
