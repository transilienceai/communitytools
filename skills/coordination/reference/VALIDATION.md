# Finding Validation Reference

Anti-hallucination validation for pentest findings. Every claim must be backed by raw evidence. **All checks must pass; a failure triggers cure-or-drop — an unproven finding never ships.**

## How Validation Works

Validation is **interleaved, strict per-finding** — NOT a separate one-shot pass after the search finishes. The coordinator validates each candidate **the instant it is materialized** (right after INTEGRATE writes it to the ledger — the earliest race-free point it has an id + dir — and before the next THINK/batch), driving it to a terminal verdict on **fresh blind agents** before search continues. A validator agent (spawned from `skills/coordination/reference/validator-role.md`) can read evidence, run PoCs, cross-reference claims against raw scan files, and detect fabrication via log timestamps.

| Step | Who | What |
|------|-----|------|
| Prepare | Executor | Author evidence (files exist, CVSS consistent) |
| INTEGRATE | Coordinator | Materialize the candidate (id + finding dir) — the sole ledger writer |
| Validate now | Coordinator | Run the per-finding convergence loop below on fresh blind agents, before the next batch |

### Per-finding convergence loop

For each newly-materialized candidate, before continuing the search:

1. **Checks** — one blind authoritative validator runs the checks below.
2. **Adversarial + reproduction lane (parallel, all blind to the coordinator's theory):** refuters (×3 — the raised quorum), an evidence-probe (stats the mandatory files on disk), and a separate blind reproducer (follows only the PoC recipe).
3. **Deterministic `computeVerdict`** (pure JS) folds the results into one verdict.
4. **Terminal routing:**
   - **CONFIRMED** (`VALID` / `REPAIRED`) → `artifacts/validated/` → the only findings that reach the report.
   - **REJECTED** (adversarial majority) → `artifacts/false-positives/` (audit only). "Reject and keep searching for something else."
   - **CURE** — close the *named* gaps (`failed_checks` / `missing_evidence`) via a scoped cure step, then **re-validate on fresh blind agents** the next round.
   - **DROPPED** — still uncured after `MAX_CURE_ROUNDS` → `artifacts/dropped/` (audit only).

**Drop-entirely policy:** only `VALID`/`REPAIRED` reach the report. There is **no gaps/assurance section** and no half-confirmed findings in the deliverable — REJECTED lives in `false-positives/` and uncured DROPPED in `dropped/`, both audit trails only.

## 5 Required Checks

### 1. CVSS Consistency

Severity label must match CVSS v3.1 score exactly:

| Severity | Range |
|----------|------:|
| CRITICAL | 9.0 - 10.0 |
| HIGH | 7.0 - 8.9 |
| MEDIUM | 4.0 - 6.9 |
| LOW | 0.1 - 3.9 |
| INFORMATIONAL | 0.0 |

CVSS 5.3 labeled "LOW" → REJECTED (should be MEDIUM).

### 2. Evidence Exists

```
finding-NNN/
├── description.md       (required)
├── poc.py               (required)
├── poc_output.txt       (required)
└── evidence/
    └── raw-source.txt   (required: raw tool output)
```

Missing any file → REJECTED.

### 3. PoC Validation

`poc.py` must parse via `ast.parse()`, reference the target (URL/IP/endpoint from finding), and — when safe — be re-run by the validator with output verified.

### 4. Claims Against Raw Evidence

Every extractable factual claim must appear in at least one raw scan file.

| Claim type | Pattern | Example |
|---|---|---|
| HTTP status | `HTTP/1.1 503` | curl/response output |
| Port state | `443/tcp open` | nmap output |
| TLS version | `TLSv1.2` | openssl output |
| Cert CN | `CN=vpn.example.com` | cert output |
| Cert SAN | `DNS:vpn.example.com` | cert output |
| CVE ID | `CVE-2024-3400` | scan output |
| Cipher | `TLS_RSA_WITH_AES_256_GCM_SHA384` | cipher enum |

Rule: ALL claims must be corroborated; one uncorroborated claim = REJECTED. A finding with no extractable claims is also REJECTED.

### 5. Log Corroboration

Executor log must show all 4 phases (`recon`, `experiment`, `test`, `verify`), with verify timestamps spaced ≥ 2s apart (no bulk-stamping).

### 6. Root-cause severity floor

The inverse of Check 1. REJECT a finding for UNDER-rating when its own `description.md` asserts a latent higher-impact outcome that follows from a CONFIRMED missing control (missing tenant/ownership filter, unauthenticated state-change, unvalidated server-fetched URL, etc.) yet scores CVSS C/I/A only on the demonstrated sub-impact because the higher impact was blocked by a TRANSIENT/REVERSIBLE condition (empty data, deleted records, IMDSv2, toggled-off feature). Recompute C/I/A from the root-cause-implied outcome per `formats/transilience-report-style/pentest-report.md` §7.1 and REJECT if the executor's band is more than one band below the recomputed band.

Check 1 stops inflation; Check 6 stops deflation. Apply ONLY when the description itself asserts the higher latent impact from a confirmed control gap — never invent impact the finding does not claim.

## Proof of Validation

Validators write to `{findings_dir}/finding-{id}/evidence/validation/`:

```
evidence/validation/
├── validation-summary.md      (mandatory)
├── poc-rerun-output.txt       (mandatory — even when execution skipped, with reason)
├── verification-script.py     (mandatory — independent reproduction)
├── cve-verification.md        (mandatory when the finding cites a CVE)
├── code-references.md         (mandatory when finding cites code/config/logic)
├── network-requests.json      (web: playwright_network_requests, when relevant)
├── console.json               (web: playwright_console_messages, when relevant)
└── screenshots/*.png          (mandatory when target has web/browser surface)
```

**Completeness rules**:
1. `validation-summary.md` — always.
2. `poc-rerun-output.txt` — always; if skipped, document why and what alternative verification was performed.
3. `verification-script.py` — always; **standalone, self-contained Python**. Must not import from executor's `poc.py` or `evidence/*`. Includes its own target refs, imports, output parsing. Lets a human reviewer reproduce with one script.
4. `code-references.md` — when claims cite source code/config/app logic. Each claim mapped to `file:line` with quoted snippet.
5. `screenshots/*.png` — when finding targets HTTP/HTTPS/web/browser surface. Must show exploitation or observable effect. Skip for raw TCP/UDP/DNS/SNMP/SSH banner findings.

### `poc` — the reproducible step-by-step, re-run by a separate blind agent

Every finding carries **one canonical reproducible PoC** (it merges what used to be the separate *evidence*,
*test/PoC*, and *screenshot* fields — there is no parallel `evidence_steps`). The `checks` stage authors `poc`
as an **ordered list of step objects**:

- Each step = `{description, command, image_url}`. **`description`** (required) — prose: what the step does /
  what you observe. **`command`** (optional) — the exact command/URL to run at that step, verbatim and runnable;
  omit for a pure-observation step. **`image_url`** (optional) — path (or URL) to a captured screenshot/output
  image for that step.
- **Step 1 MUST be an entry point** (open a terminal / open a browser / establish the initial connection — its
  `command` is that entry action). **The last step MUST be the actual observed result** that proves the finding
  (put the observed proof in its `description`). Fold any prerequisites into step 1's description.

A **separate, context-free reproduction agent** (`repro:*`) is then handed *only* the PoC steps + target — it may
not read the description, `poc.py`, evidence, chain, or any validator/refuter output. It follows the recipe
exactly (running each step's `command`), and **corrects it minimally until it reproduces** (or can't). This is a
distinct role from the refuters (which try to *doubt* the finding) and the evidence-probe (which stats files) —
it *follows the recipe*. Its `{reproduced, corrected_steps, observed_result}` is structured; the pure-JS
`computeVerdict()` gates on `reproduced` (no confirmation ⇒ **DEMOTED**, never a faked VALID), and `finalPoc()`
records the agent's corrected recipe when it perfected one. The `poc` list flows to **both** the interim verdict
JSON and the final `report_data.json`, where the PDF renders each step as prose + a code-styled command + an
embedded image.

### code / screenshot artifacts — the machine-checked file trail

**This contract is machine-checked, not advisory.** A one-job **evidence-probe** (`test -f`/`wc -c`) verifies
every mandatory file above actually exists and is non-empty on disk — the manifest is **branched** by finding
type (screenshots only for web-surface findings; `code-references.md` only for code-citing findings; `cve-
verification.md` only for CVE findings), so a raw TCP/DNS/SSH-banner finding is not penalised for lacking a
screenshot. The pure-JS `computeVerdict()` then requires all *applicable* mandatory artifacts present:

- present & non-empty + all gates pass → **VALID** (or **REPAIRED** if the PoC was regenerated),
- adversarially refuted (majority) → **REJECTED** (false-positive → `false-positives/`; never appears in any report),
- real but under-evidenced / infra error → **DEMOTED** — enter the cure loop; if still uncured after `MAX_CURE_ROUNDS` it is **DROPPED** to `artifacts/dropped/` (audit only), never the report and never a caveat.

Incomplete packages are cured-or-dropped, never silently passed and never surfaced as a gap in the deliverable; the coordinator submits only fully-confirmed findings.

### validation-summary.md template

```markdown
# Validation: {finding_id}

## Verdict: VALID / REJECTED

## Checks
- CVSS: {severity} matches {score} — PASS/FAIL
- Evidence: all files present — PASS/FAIL
- PoC: {ran/skipped}, output {matches/differs} — PASS/FAIL
- Claims: {N}/{N} corroborated — PASS/FAIL
- Log phases: all present, timestamps valid — PASS/FAIL
- Root-cause floor: {recomputed band} vs {executor band} — PASS/FAIL

## PoC Re-execution
{What happened. If skipped, why.}

## Claims Verified
{Each claim → raw file + line that corroborates it.}

## Notes
{Anything unusual.}

## Evidence Package
- verification-script.py: {generated / N/A reason}
- poc-rerun-output.txt: {succeeded/failed/skipped: reason}
- code-references.md: {generated / not applicable — no code claims}
- screenshots: {N captured / not applicable — non-web finding}
```

### Boundary

Validators write ONLY to `evidence/validation/`. Never modify executor files. **Exception**: if Check 2 fails (no finding directory), proof goes in the rejection JSON only.

## Coordinator: interleaved per-finding validation

The coordinator does not batch all validators at the end. Immediately after INTEGRATE materializes a candidate — before the next THINK/batch — it runs the convergence loop for that candidate on **fresh** blind agents:

```python
validator_role = Read("skills/coordination/reference/validator-role.md")

# Right after INTEGRATE produces THIS candidate — before the next batch:
Agent(prompt=f"{validator_role}\n\n"
             f"finding_id: {finding['id']}\n"
             f"finding_json_path: {findings_file}\n"
             f"raw_dir: {{OUTPUT_DIR}}/recon/\n"
             f"executor_log: {{OUTPUT_DIR}}/logs/{executor}.log\n"
             f"findings_dir: {{OUTPUT_DIR}}/findings/\n"
             f"output_dir: {{OUTPUT_DIR}}/artifacts/",
      run_in_background=True)
# → CONFIRMED | REJECTED | CURE (close named gaps, re-validate on fresh agents) | DROPPED
```

Per terminal verdict, the coordinator:
1. Routes CONFIRMED → `{OUTPUT_DIR}/artifacts/validated/{id}.json`, REJECTED → `false-positives/{id}.json`, uncured DROPPED → `dropped/{id}.json`.
2. Cross-executor dedupe (same URL + same CWE → drop duplicate).
3. **Coverage-by-VALID:** a class flips to `covered` only on a `VALID`/`REPAIRED` finding, a justified N/A, or a genuine negative. A class whose only candidates were REJECTED/DROPPED stays `pending`, so search continues — this is the verdict→search feedback edge.

## Output: Validated

`{OUTPUT_DIR}/artifacts/validated/{id}.json`:

```json
{
  "finding_id": "F-001",
  "valid": true,
  "proof_dir": "findings/finding-001/evidence/validation/",
  "checks": {
    "cvss_consistency": {"passed": true, "detail": "CRITICAL matches CVSS 9.1"},
    "evidence_exists": {"passed": true, "detail": "All required files present"},
    "poc_validation": {"passed": true, "detail": "Valid Python, target referenced, output matches", "proof_file": "poc-rerun-output.txt"},
    "claims_vs_raw": {"passed": true, "detail": "All 5 claims corroborated"},
    "log_corroboration": {"passed": true, "detail": "All 4 phases with distinct timestamps"},
    "rootcause_severity_floor": {"passed": true, "detail": "Recomputed band HIGH matches/within one band of executor band"}
  }
}
```

## Output: Rejected

`{OUTPUT_DIR}/artifacts/false-positives/{id}.json`:

```json
{
  "finding_id": "F-009",
  "finding_title": "Information Disclosure via Prelogin Response",
  "source_file": "{OUTPUT_DIR}/findings/executor-findings.json",
  "valid": false,
  "failed_checks": ["cvss_consistency", "evidence_exists", "log_corroboration"],
  "checks": {
    "cvss_consistency": {"passed": false, "detail": "Severity 'LOW' does not match CVSS 5.3 (expected MEDIUM)"},
    "evidence_exists":  {"passed": false, "detail": "No findings/F-009/ directory"},
    "poc_validation":   {"passed": true,  "detail": "Valid Python, target referenced"},
    "claims_vs_raw":    {"passed": true,  "detail": "All 2 claims corroborated"},
    "log_corroboration":{"passed": false, "detail": "Bulk verify timestamps detected"}
  },
  "original_finding": { "...full original..." }
}
```

Rejected findings do NOT appear in the final report — not in findings, appendix, or summary counts. The `false-positives/` directory is the sole record. Reviewers can override via inspection if a validator was wrong.

## What the Validator Catches

1. Severity mislabeling (CVSS 5.3 → LOW; should be MEDIUM)
2. Ghost findings (no per-finding directory with PoC and evidence)
3. Broken PoCs (syntax errors or no target reference)
4. Hallucinated claims (HTTP 503 with no raw scan output supporting it)
5. Fabricated port states (port "open" with no nmap output)
6. TLS inflation (TLS issues not in openssl output)
7. Unverified CVE references (CVE named without scan evidence)
8. Bulk fabrication (all findings "verified" at the same timestamp)
9. Incomplete workflow (missing recon/experiment/test/verify)
10. Unsubstantiated validation (validator passed but `validation-summary.md` missing/empty)
11. Incomplete evidence packages (no `verification-script.py`, missing screenshots for a web target)
