# Task 03 — Exploitability Validation Run

**Project**: attacks-validation — **core deliverable** (the multi-stage confirmation gate)
**Trigger**: Prompt-invoked on a specific scope row, or a cron job (default every hour) that polls `{OUTPUT_DIR}/queue/` for `status: queued` rows whose PoC is ready.
**Skills**: `coordination` (full P0→P5 loop), all attack skills mounted by the coordinator on demand, `coordination/reference/validator-role.md` (Finding Validator 5-check).

## Inputs

- `OUTPUT_DIR`
- `--scope` path to a single `queue/scope-*.json`. Tasks are atomic per scope row.

## Procedure

This task wraps the existing single-target coordinator from `skills/coordination/SKILL.md`. The cloud-agent layer is the *batch scheduler*: it picks scope rows off the queue and fires one coordinator per row, respecting the **3-concurrent-coordinator cap** documented in `skills/coordination/reference/orchestrator.md`.

For the single row:

1. Read the scope row. Resolve `asset.url` and `cve` into a target spec.
2. Load `coordination/SKILL.md`. Set `attack-chain.md` initial theory from the scope row's `claim` and `nvd` summary.
3. Run the full coordinator loop:
   - P1 recon — `reconnaissance` skill against `asset.url`.
   - P2-P4 — spawn 1–2 executors per batch with the asset's PoC (`assets/{asset}/pocs/{cve}.py`) as the starting technique.
   - P5 — spawn the **Finding Validator** (blind, 5-check) per finding.
4. Mark the scope row `status: VALID | REJECTED | TIMEOUT` based on the validator verdict. Downstream tasks (stitcher, prioritiser, report) read from `validated/` and `false-positives/` directly — no further notification step is needed.

## Outputs

Per the standard coordination output discipline:

- `$OUTPUT_DIR/findings/finding-NNN/` — description, poc.py, poc_output.txt, evidence/raw-source.txt, evidence/validation/
- `$OUTPUT_DIR/validated/{id}.json` OR `$OUTPUT_DIR/false-positives/{id}.json` — read directly by downstream tasks.

### Required `validated/{id}.json` schema (downstream contract)

Every validated row MUST include these fields. `tools/chain-merger.py` enforces this and drops malformed rows with a stderr WARN — if you see drops, the validator is non-compliant and stitching will be incomplete.

```json
{
  "finding_id": "finding-018",
  "verdict": "VALID",
  "asset": "asset42",
  "cve": "CVE-2024-12345",
  "vuln_class": "ssrf | sqli | rce | xss | lfi | rfi | deserialization | auth_bypass | idor | ssti | xxe | path_traversal | ...",
  "scope_id": "scope-20260513T100000Z-asset42-CVE-2024-12345",
  "signal_id": "ti-2026-0042",
  "nvd": {"score": 9.8, "severity": "CRITICAL", "cwes": ["CWE-918"]},
  "checks": {
    "cvss": "PASS",
    "evidence_exists": "PASS",
    "poc_valid": "PASS",
    "claims_vs_evidence": "PASS",
    "log_phases": "PASS"
  },
  "validated_at": "2026-05-13T10:42:00Z"
}
```

Required: `finding_id`, `verdict`, `asset`. Recommended: all others (drives chain-merger's vuln-class-aware detectors and risk-prioritiser's `business_impact`).

Rejected findings (`false-positives/{id}.json`) follow the same shape with `verdict: "REJECTED"` and a `reasons` array detailing which of the 5 checks failed.

## Safety — demonstrate, never disrupt ("safe, automated attacker techniques")

This is the only task in the pipeline that executes attacker techniques against live targets. Safety is enforced here.

- **PoCs demonstrate, never exploit beyond proof.** Every PoC from task-02 must satisfy the 6 demonstrate-only constraints documented in [task-02-org-auto-poc.md](task-02-org-auto-poc.md) §Constraints. The validator's check #3 (PoC re-run) re-fires the PoC — replay MUST remain non-destructive.
- **No state mutation against the target.** Forbidden across executor and validator: `DROP`, `DELETE`, account creation, password resets, mass reads (>10 rows), service kills/restarts, sending emails/SMS, posting to external webhooks. The executor halts on any attempt; the coordinator records the halt as a failed experiment.
- **No DoS or brute-force.** Brute-force prohibition is enforced at all 4 levels (coordinator-spawn, coordinator, executor, validator). No request floods, no slowloris, no auth-loops.
- **Scope discipline.** PoCs fire only against the asset + endpoint declared in the scope row. Neighbours, internal pivots, and lateral targets are out of scope for this task — those are inferred later by the stitcher from confirmed findings, never by direct probing.
- **Evidence is observation.** `evidence/raw-source.txt` records the response body / headers / leaked content. It does NOT contain replayable destructive payloads. The validator may re-fire the PoC; safety must hold under replay.
- **Coordinator is autonomous.** Never calls `AskUserQuestion`. Missing creds → `status: BLOCKED` with `BLOCKED_REASON` (CLAUDE.md Rule 1).

## Operational caps

- Hard caps: 30 experiments per coordinator (Rule 5 of `coordination/SKILL.md`), 1 coordinator per scope row, 3 coordinators concurrent org-wide.
- Each PoC run ≤ 60 seconds wall-clock.

## Status emit

```json
{"task": "validation-run", "status": "OK",
 "scope": "queue/scope-20260513T100000Z-asset42-CVE-2024-12345.json",
 "verdict": "VALID",
 "finding_id": "finding-018",
 "outputs": ["validated/finding-018.json"],
 "next": [{"task": "task-06-attack-path-stitcher"}, {"task": "task-07-risk-prioritiser"}]}
```

`FAILED_partial` if the coordinator hit the experiment cap without a verdict (per coordination Rule 10, this is a temporary marker — re-queue with `--re-attempt` flag).
