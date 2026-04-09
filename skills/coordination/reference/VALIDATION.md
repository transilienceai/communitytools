# Finding Validation Reference

Anti-hallucination validation for pentest findings. Every claim must be backed by raw evidence. No exceptions, no partial credit.

## Principle

**All checks must pass. One failure = finding rejected.** There is no scoring system. If something is wrong, the finding cannot be trusted.

## How Validation Works

Validation is performed by a validator agent (spawned from `skills/coordination/reference/validator-role.md`) -- an LLM agent deployed per-finding by the coordinator. Unlike a regex-based script, the validator agent can:

- **Read and reason** about evidence files, understanding context and nuance
- **Run PoCs** to verify they actually work (not just check syntax)
- **Cross-reference claims** by searching all raw scan files and understanding what constitutes corroboration
- **Detect fabrication** by analyzing log timestamps and workflow completeness

## When Validation Runs

| Phase | Who | What |
|-------|-----|------|
| 4a | Executor | Prepares evidence for validation (ensures all files exist, CVSS consistent) |
| 4.5 | Coordinator | Deploys one validator agent per finding using `skills/coordination/reference/validator-role.md` (all in parallel) |

## 5 Required Checks

Every finding must pass ALL of these. Failure on any single check = REJECTED.

### 1. CVSS Consistency

Severity label must exactly match the CVSS v3.1 score range.

| Severity | CVSS Range |
|----------|-----------:|
| CRITICAL | 9.0 - 10.0 |
| HIGH | 7.0 - 8.9 |
| MEDIUM | 4.0 - 6.9 |
| LOW | 0.1 - 3.9 |
| INFORMATIONAL | 0.0 |

No tolerance. CVSS 5.3 labeled "LOW" = REJECTED (should be MEDIUM).

### 2. Evidence Exists

The per-finding directory must contain ALL required files:

```
finding-NNN/
├── description.md    # Required
├── poc.py           # Required
├── poc_output.txt   # Required
└── evidence/        # Required directory
    └── raw-source.txt   # Required (raw tool output)
```

Missing any file = REJECTED.

### 3. PoC Validation

- `poc.py` must parse as valid Python (`ast.parse()`)
- Must reference the target (URL, IP, or endpoint from the finding)
- If safe to execute, the validator runs the PoC and verifies output

Invalid syntax or no target reference = REJECTED.

### 4. Claims Against Raw Evidence

Every extractable factual claim must appear in at least one raw scan output file.

**Claim types extracted**:

| Claim Type | Pattern | Example |
|-----------|---------|---------|
| HTTP status | `HTTP/1.1 503` | Must appear in curl/response output |
| Port state | `443/tcp open` | Must appear in nmap output |
| TLS version | `TLSv1.2` | Must appear in openssl output |
| Certificate CN | `CN=vpn.example.com` | Must appear in cert output |
| Certificate SAN | `DNS:vpn.example.com` | Must appear in cert output |
| CVE ID | `CVE-2024-3400` | Must appear in scan/assessment output |
| Cipher suite | `TLS_RSA_WITH_AES_256_GCM_SHA384` | Must appear in cipher enum output |

**Rule**: ALL claims must be corroborated. One uncorroborated claim = REJECTED.

A finding with no extractable claims is also REJECTED -- if it makes no verifiable technical assertion, it cannot be validated.

### 5. Log Corroboration

The executor log must show:
- All 4 workflow phases present: `recon`, `experiment`, `test`, `verify`
- No bulk timestamps: verify actions must have distinct timestamps (>= 2s gaps)

Missing phases or bulk-stamped verification = REJECTED.

## Proof of Validation

Validators must produce tangible proof of their work in `{findings_dir}/finding-{id}/evidence/validation/`.

### Structure

```
evidence/validation/
├── validation-summary.md      # MANDATORY — always produced
├── poc-rerun-output.txt       # MANDATORY — always produced (re-run PoC or document why execution was blocked)
├── verification-script.py     # MANDATORY — always produced (standalone independent reproduction script)
├── code-references.md         # MANDATORY — when finding claims reference source code, config, or app logic
└── screenshots/*.png          # MANDATORY — when finding targets a web/browser-accessible surface (HTTP/HTTPS)
```

### Evidence completeness rules

Every validation must produce a **complete evidence package**:

1. **`validation-summary.md`** — Always generated. No exceptions.
2. **`poc-rerun-output.txt`** — Always generated. The validator must attempt to re-run `poc.py` in every case. If execution is unsafe, blocked by environment constraints, or would cause destructive side effects, the file must still be created with a documented explanation of why execution was skipped and what alternative verification was performed.
3. **`verification-script.py`** — Always generated. Must be a **self-contained, standalone Python script** that independently verifies or reproduces the finding. Must not import or depend on executor files (poc.py, evidence/*). Must include its own target references, imports, and output parsing. Purpose: allow a human reviewer to run a single script to confirm the finding without needing the executor's toolchain.
4. **`code-references.md`** — Mandatory whenever the finding's claims reference source code, configuration files, or application-level logic. Each claim must map to a specific `file:line` with the relevant snippet quoted.
5. **`screenshots/*.png`** — Mandatory whenever the finding targets a web or browser-accessible surface (any HTTP/HTTPS endpoint, web application, or browser-rendered content). The screenshot must show the vulnerability being exploited or its observable effect. Not required for network-only findings with no browser-accessible surface (raw TCP/UDP, DNS, SNMP, SSH banner grabs, etc.).

A validation that omits a mandatory artifact is **incomplete** and must not be submitted. The coordinator will reject incomplete validation packages.

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

## PoC Re-execution
{What happened when poc.py was run. If skipped, why.}

## Claims Verified
{Each claim → raw file + line that corroborates it.}

## Notes
{Anything unusual observed.}

## Evidence Package
- verification-script.py: {generated / N/A with reason}
- poc-rerun-output.txt: {generated — execution succeeded/failed / generated — execution skipped: [reason]}
- code-references.md: {generated / not applicable — no source code claims}
- screenshots: {N screenshots captured / not applicable — network-only finding}
```

### Boundary rule

Validators write ONLY to `evidence/validation/`. Never modify executor files (description.md, poc.py, poc_output.txt, evidence/raw-source.txt).

**Exception**: if the finding directory doesn't exist (Check 2 fails), proof goes in the rejection JSON only — there is nowhere to write files.

## Coordinator Deployment

The coordinator deploys validators during Phase 4.5:

```python
# Read validator role prompt once
validator_role = Read("skills/coordination/reference/validator-role.md")

# Deploy one validator per finding, all in parallel
for finding in all_findings:
    Agent(prompt=f"{validator_role}\n\n"
                f"finding_id: {finding['id']}\n"
                f"finding_json_path: {findings_file}\n"
                f"raw_dir: {{OUTPUT_DIR}}/recon/\n"
                f"executor_log: {{OUTPUT_DIR}}/logs/{executor}.log\n"
                f"findings_dir: {{OUTPUT_DIR}}/findings/\n"
                f"output_dir: {{OUTPUT_DIR}}/artifacts/",
          run_in_background=True)
```

After all validators complete, the coordinator:
1. Reads `{OUTPUT_DIR}/artifacts/validated/{id}.json` (passed) and `{OUTPUT_DIR}/artifacts/false-positives/{id}.json` (rejected)
2. Performs cross-executor deduplication (same URL + same CWE = reject duplicate)
3. Proceeds to aggregation with ONLY validated findings

## Output: Validated Findings

**Location**: `{OUTPUT_DIR}/artifacts/validated/{finding-id}.json`

```json
{
  "finding_id": "F-001",
  "valid": true,
  "proof_dir": "findings/finding-001/evidence/validation/",
  "checks": {
    "cvss_consistency": {"passed": true, "detail": "CRITICAL matches CVSS 9.1"},
    "evidence_exists": {"passed": true, "detail": "All required files present"},
    "poc_validation": {"passed": true, "detail": "Valid Python, target referenced, output matches", "proof_file": "poc-rerun-output.txt"},
    "claims_vs_raw": {"passed": true, "detail": "All 5 claims corroborated in raw scan output"},
    "log_corroboration": {"passed": true, "detail": "All 4 phases present with distinct timestamps"}
  }
}
```

## Output: Rejected Findings (false-positives/)

**Location**: `{OUTPUT_DIR}/artifacts/false-positives/{finding-id}.json`

```json
{
  "finding_id": "F-009",
  "finding_title": "Information Disclosure via Prelogin Response",
  "source_file": "{OUTPUT_DIR}/findings/executor-findings.json",
  "valid": false,
  "failed_checks": ["cvss_consistency", "evidence_exists", "log_corroboration"],
  "checks": {
    "cvss_consistency": {
      "passed": false,
      "detail": "Severity 'LOW' does not match CVSS 5.3 (expected 'MEDIUM')"
    },
    "evidence_exists": {
      "passed": false,
      "detail": "No findings/F-009/ directory found"
    },
    "poc_validation": {
      "passed": true,
      "detail": "Valid Python, target referenced"
    },
    "claims_vs_raw": {
      "passed": true,
      "detail": "All 2 claims corroborated in raw scan output"
    },
    "log_corroboration": {
      "passed": false,
      "detail": "Bulk verify timestamps detected"
    }
  },
  "original_finding": { "...full original finding JSON..." }
}
```

This preserves the full original finding data alongside the validation failure reasons so nothing is silently lost. Human reviewers can inspect these and override if the validator was wrong.

Rejected findings do NOT appear anywhere in the final report -- not in findings, not in appendix, not in summary counts. The `false-positives/` directory is the sole record.

## What the Validator Catches

1. **Severity mislabeling** -- CVSS 5.3 labeled LOW (should be MEDIUM)
2. **Ghost findings** -- No per-finding directory with PoC and evidence
3. **Broken PoCs** -- Syntax errors or missing target references
4. **Hallucinated claims** -- Claims HTTP 503 but no raw scan file contains it
5. **Fabricated port states** -- Claims port open with no nmap output to confirm
6. **TLS inflation** -- Claims TLS issues not in openssl output
7. **Unverified CVE references** -- Names CVE without scan evidence
8. **Bulk fabrication** -- All findings "verified" at the same timestamp
9. **Incomplete workflow** -- Missing recon/experiment/test/verify phases
10. **Unsubstantiated validation** -- Validator passed the finding but `evidence/validation/validation-summary.md` is missing or empty
11. **Incomplete evidence packages** -- Validator passed but failed to generate verification-script.py or omitted screenshots for a web-accessible finding
