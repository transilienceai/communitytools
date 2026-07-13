# Validator

Two validator classes. Both are blind reviews — independent of the coordinator's reasoning.

| Class | Spawned | Receives | Job |
|-------|---------|----------|-----|
| **Finding validator** | **Interleaved — the instant INTEGRATE materializes each candidate, before the next batch; re-spawned FRESH each cure round** | `finding_id`, `FINDING_DIR`, `TARGET_URL`, `OUTPUT_DIR`, frozen NVD/KEV snapshot | Drive one candidate to a terminal verdict (all-or-nothing checks) |
| **Engagement validator** | Once at loop end, over the interleaved `validated/` writes | `OUTPUT_DIR` only | Thoroughness check on the whole engagement |

Validation is **interleaved, strict per-finding** — a candidate is validated the moment it exists, not in a downstream one-shot pass. Mount only `reference/VALIDATION.md`. Do **not** mount the full attack skill — biases judgment. On every cure round the coordinator re-spawns a **fresh** validator that re-reads disk, so the blind contract holds across the whole convergence loop.

---

## Finding Validator

### Input

`finding_id`, `FINDING_DIR`, `TARGET_URL`, `OUTPUT_DIR`.

### Checks (all must PASS)

1. **CVSS** — severity matches band (C:9-10, H:7-8.9, M:4-6.9, L:0.1-3.9, I:0). If finding cites a CVE (`CVE-YYYY-NNNNN`), run `python3 tools/nvd-lookup.py <CVE-ID>`, include NVD score in summary, flag if executor's score diverges from NVD by >1.0.
2. **Evidence exists** — `description.md`, `poc.py`, `poc_output.txt`, `evidence/raw-source.txt`.
3. **PoC valid** — valid Python, references the target, output matches `poc_output.txt` after re-run.
4. **Claims vs evidence** — every factual claim in description.md corroborated by a raw scan/log file.
5. **Log phases** — recon / experiment / test / verify present, timestamps ≥ 2 s apart (catches templated bulk-stamp findings).

### Output (terminal routing)

- CONFIRMED (VALID / REPAIRED) → `{OUTPUT_DIR}/validated/{finding_id}.json` — the only findings that reach the report.
- REJECTED (adversarial majority) → `{OUTPUT_DIR}/false-positives/{finding_id}.json` (include original finding + failure reasons) — audit only.
- DEMOTED → **cure lane**: the coordinator spawns a scoped cure executor handed ONLY the `failed_checks` + `missing_evidence` (told *do not re-theorize*), then re-validates on a fresh blind agent. Still uncured after `MAX_CURE_ROUNDS` → `{OUTPUT_DIR}/dropped/{finding_id}.json` — audit only, never the report.

Drop-entirely: there is no gaps/assurance section — `validated/` is VALID/REPAIRED by construction.

### Proof artifacts in `{FINDING_DIR}/evidence/validation/`

1. `validation-summary.md` — verdict + each check PASS/FAIL + what you verified. NVD risk-score table if CVE IDs present.
2. `poc-rerun-output.txt` — re-run poc.py, capture full stdout/stderr. If unsafe to run, document the specific reason here.
3. `verification-script.py` — standalone Python that independently reproduces the finding (own imports, own target reference).
4. `code-references.md` — when claims reference source code / config; quote `file:line` per claim.
5. `screenshots/*.png` — for web/browser-accessible findings only.

### Rules

- All-or-nothing. One failure = REJECTED.
- Read all evidence first. Missing = rejected.
- Never modify executor files. Write only to `evidence/validation/`.
- Items 1, 2, 3 always required. 4 required when source-code claims exist. 5 required for web targets.

---

## Engagement Validator

Spawned once at loop end, after every candidate has already been validated inline to a terminal verdict. Reads the interleaved `validated/` writes and catches engagement-level gaps the per-finding validator can't see.

### Input

`OUTPUT_DIR` only. Read the directory tree; produce a thoroughness verdict.

### Checks (all must PASS for `engagement_status=THOROUGH`)

1. **Port coverage** — every open port in `recon/` has at least one `experiments.md` row. Additionally, a "no open ports / no external surface" conclusion FAILs (`port_coverage:FAIL` → `engagement_status:GAPS_FOUND`) unless (a) a full-range (all-65535) scan ran on the reachable hosts, AND (b) the conclusion names the ≥1 `logs/activity/source-ips.jsonl` vantage geographies it was derived from — a single-vantage "no surface" is never covered (an allowlisted host may be live from another geography).
2. **Share enumeration** — for AD/Windows targets: every share listed in `recon/smb_shares.txt` (or equivalent) has a corresponding spider/probe row in `tools/`. Both anonymous and guest probes attempted where applicable.
3. **Source-code coverage** — every file in `recon/source/` (or equivalent application source dump) referenced by at least one experiments row OR linked from attack-chain.md tested entries.
4. **Wildcard hypothesis** — at least 1 `[wildcard]`-tagged hypothesis appears in attack-chain.md and was tested (has an experiments row).
5. **Mandatory skeptic spawns** — `skeptic-brief-5.md`, `skeptic-brief-15.md`, `skeptic-brief-25.md` exist for the experiment counts the engagement reached.
6. **Time-to-first-finding** — `<= 0.3 * duration_seconds`. Late TTFF is a heuristic for skipped recon.
7. **No `AskUserQuestion` calls** — search any saved transcript / log for the call. Coordinator must have zero.
8. **Attack-class coverage (web/API/transport/network engagements) — DETERMINISTIC hard 100% gate** — run `python3 tools/coverage_gate.py --asset-dir OUTPUT_DIR` and read `OUTPUT_DIR/reports/coverage-matrix.json`. It code-enumerates the applicable `(surface-unit × attack-class)` cells from `recon/inventory/surface.json` / `host.json` and joins each to real on-disk evidence (a `covered` cell needs a `VALID`/`REPAIRED` finding whose `class_id` + `unit_refs` + `asset_tag` match; a `covered_negative` needs a corroborated probe / verified vantages). Set `coverage_ratio` from its output and FAIL (`engagement_status:GAPS_FOUND`) unless its `complete` is true (`coverage_ratio == 1.0`, no missing/extra/dangling/false-NA/surface-undercount), listing the `missing_cells` (`class_id @ scope_key`) in remediation. This replaces the old 0.80 soft bar. Skip as PASS-NA only for pure host/AD/binary targets with no HTTP/API/TLS surface (zero applicable cells → the gate returns `complete:true` gracefully).

### Output

`{OUTPUT_DIR}/artifacts/engagement-validation.json`:

```json
{
  "engagement_status": "THOROUGH" | "GAPS_FOUND",
  "checks": {
    "port_coverage": "PASS" | "FAIL — <ports skipped | single-vantage no-surface | full-range missing>",
    "share_enumeration": "PASS" | "FAIL — <shares skipped>",
    "source_coverage": "PASS" | "FAIL — <files skipped>",
    "wildcard_hypothesis": "PASS" | "FAIL",
    "skeptic_spawns": "PASS" | "FAIL — <missing>",
    "ttff_ratio": 0.27,
    "ask_user_count": 0,
    "attack_class_coverage": "PASS — 17/20 (0.85)" | "FAIL — 7/20 (0.35); pending: XC-CORS, ..."
  },
  "coverage_ratio": 0.85,
  "remediation": ["concrete next experiments to fill the gaps"]
}
```

Plus `{OUTPUT_DIR}/artifacts/engagement-validation-summary.md` (human-readable).

### Rules

- Blind to attack-chain reasoning and finding internals — judge from the directory state alone.
- A `GAPS_FOUND` verdict on an Easy-rated target blocks report generation; the coordinator must address the gaps and re-run validation.
- `attack_class_coverage:FAIL` forces `GAPS_FOUND` regardless of checks 1-7; the coordinator must cover-or-NA the named pending classes and re-validate before COMPLETE.
- Never write to `findings/` or `validated/` — engagement validator only writes to `artifacts/`.
