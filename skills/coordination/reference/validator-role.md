# Validator

Validates one finding against raw evidence. All checks must pass — one failure rejects.

## Input

`finding_id`, `FINDING_DIR`, `TARGET_URL`, `OUTPUT_DIR`

## Checks

1. **CVSS** — severity matches range (C:9-10, H:7-8.9, M:4-6.9, L:0.1-3.9, I:0). **If the finding references any CVE ID** (pattern `CVE-YYYY-NNNNN`), run `python3 tools/nvd-lookup.py <CVE-ID>` to fetch the authoritative CVSS score from NVD and cross-check against the executor's claimed severity. Include the NVD score in the validation summary. If NVD score and executor score diverge by >1.0, flag the discrepancy.
2. **Evidence exists** — description.md, poc.py, poc_output.txt, evidence/raw-source.txt
3. **PoC valid** — valid Python, references target, output matches poc_output.txt
4. **Claims vs evidence** — every factual claim in a raw scan file
5. **Log phases** — recon/experiment/test/verify present, timestamps >= 2s apart

## Output

- VALID → `{OUTPUT_DIR}/validated/{finding_id}.json`
- REJECTED → `{OUTPUT_DIR}/false-positives/{finding_id}.json` (include original finding + failure reasons)

## Proof

Write to `{FINDING_DIR}/evidence/validation/`:

1. `validation-summary.md` — MANDATORY. Verdict, each check with PASS/FAIL, what you verified. If CVE IDs were found, include the NVD risk score table (CVE ID, Score, Severity, CWE).
2. `poc-rerun-output.txt` — MANDATORY. Always re-run poc.py and capture full stdout/stderr. If execution is unsafe or impossible, document the specific reason in this file instead.
3. `verification-script.py` — MANDATORY. Generate a standalone Python script that independently reproduces or verifies the finding without relying on executor files. Must be self-contained (own imports, own target reference, own output parsing).
4. `code-references.md` — MANDATORY when claims reference source code, configuration files, or application logic. Quote file:line for each verified claim.
5. `screenshots/*.png` — MANDATORY for web/browser-accessible findings (HTTP/HTTPS targets, web apps, browser-rendered content). Capture the vulnerability being demonstrated. Not required for network-only findings (raw TCP/UDP, DNS, SNMP, etc.).

Exception: if finding dir doesn't exist (Check 2 fails), proof goes in rejection JSON only.

## Rules

- All pass or reject. No partial credit.
- Read all evidence first. Missing = rejected.
- Never modify executor files (description.md, poc.py, poc_output.txt, evidence/raw-source.txt). Write ONLY to `evidence/validation/`.
- Every validation MUST produce items 1, 2, and 3 from Proof. Items 4 and 5 are mandatory when their conditions apply (source code claims exist; finding targets a web/browser-accessible surface). Incomplete evidence packages = incomplete validation.
