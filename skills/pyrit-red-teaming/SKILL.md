---
name: pyrit-red-teaming
description: Automated LLM red teaming with Microsoft PyRIT. Drives single- and multi-turn adversarial attacks (prompt injection, jailbreak, data disclosure, excessive agency) against an OpenAI-compatible chat target, scores each response for refusal, and writes OWASP-LLM-mapped findings into the standard engagement OUTPUT_DIR. Use for authorized AI security assessments.
---

# PyRIT AI Red Teaming

Wrap [Microsoft PyRIT](https://github.com/microsoft/PyRIT) (Python Risk
Identification Tool) to run repeatable, scored red-team campaigns against an
LLM application. This skill is the **automated-scanner** complement to
[`ai-threat-testing`](../ai-threat-testing/SKILL.md): PyRIT generates and grades
attacks at volume; `ai-threat-testing` supplies the manual OWASP LLM playbooks
and the exploitation depth. Run PyRIT first for breadth, then hand the
non-refused objectives to the matching `llm0X-*.md` playbook for confirmation
and PoC hardening.

## When to use

- You have an authorized LLM target (URL/API or local model) and want a broad,
  automated first pass for prompt injection, jailbreaks, information disclosure,
  insecure output, and excessive agency.
- You need scored, reproducible results in the engagement OUTPUT_DIR rather than
  ad-hoc chat transcripts.

## Quick start

```bash
# 1. Validate the pipeline with no PyRIT, no network, no API key:
python skills/pyrit-red-teaming/tools/pyrit_runner.py --dry-run --output-dir $OUTPUT_DIR/..

# 2. Install PyRIT into a Python 3.10-3.13 env (see reference/setup-and-targets.md):
pip install pyrit

# 3. Run against a real OpenAI-compatible target:
export OPENAI_API_KEY=sk-...
python skills/pyrit-red-teaming/tools/pyrit_runner.py \
    --endpoint https://api.openai.com/v1/chat/completions \
    --model gpt-4o-mini \
    --converters base64 \
    --output-dir $ENGAGEMENT_BASE
```

Each run creates a timestamped `OUTPUT_DIR` and prints its path. Findings are
the objectives the target **did not refuse**.

## Methodology

1. **Scope & authorize.** Confirm written authorization and that the endpoint is
   in scope. Never point this at a third-party model you are not cleared to test.
2. **Pick objectives.** Use the built-in starter set (6 objectives across
   LLM01/02/06/08/10) or pass `--objectives objectives.json` (a JSON list of
   `{owasp_llm, objective}`). Extend with PyRIT's own datasets
   (`pyrit.datasets`) for coverage.
3. **Pick an attack + converters.** `prompt_sending` (single-turn) is wired up.
   For multi-turn jailbreaks (`RedTeamingOrchestrator`, `CrescendoOrchestrator`)
   see [reference/pyrit-orchestrators.md](reference/pyrit-orchestrators.md).
   Converters (`base64`, `rot13`, `leetspeak`, …) stack to evade naive filters.
4. **Run & score.** Each objective is sent; the response is graded by PyRIT's
   `SelfAskRefusalScorer`. A non-refusal = a finding.
5. **Triage & confirm.** Open the matching `ai-threat-testing/reference/llm0X-*.md`
   playbook for each finding, confirm impact, and assign CVSS.

## Attack coverage (OWASP LLM Top 10, 2025)

| Objective category | OWASP LLM | Default severity |
|--------------------|-----------|------------------|
| Prompt injection / system-prompt leak | LLM01 | HIGH |
| Insecure output handling | LLM02 | HIGH |
| Sensitive information disclosure | LLM06 | HIGH |
| Excessive agency / unauthorized tool use | LLM08 | HIGH |
| Model theft / extraction | LLM10 | MEDIUM |

Severities are triage defaults — confirm and assign CVSS per finding.

## Tools

- [`tools/pyrit_runner.py`](tools/pyrit_runner.py) — CLI. Lazily imports PyRIT;
  all PyRIT calls are isolated in `_run_pyrit_async`. `--dry-run` exercises the
  whole pipeline with a local mock target (no PyRIT/network/key).
- [`tools/finding_writer.py`](tools/finding_writer.py) — converts normalized
  results into the standard OUTPUT_DIR tree + finding JSON. No PyRIT dependency;
  self-tested via `python tools/finding_writer.py --selftest`.
- [`tools/requirements.txt`](tools/requirements.txt) — `pyrit` (install
  separately; heavy, Python 3.10-3.13 only).

## Output

Conforms to [`output-discipline.md`](../coordination/reference/output-discipline.md)
and the finding schema in [`formats/data.md`](../../formats/data.md):

```
{OUTPUT_DIR}/
├── findings/finding-NNN/
│   ├── finding.json          # data.md schema (+ owasp_llm); poc_verified=true
│   ├── description.md         # prompt, response, score
│   └── evidence/conversation.txt
├── artifacts/pyrit-report.json   # aggregate, machine-readable
├── reports/pyrit-report.md       # human summary table
└── logs/attempts.ndjson          # every attempt, incl. refusals (append-only)
```

## Integration

- **`ai-threat-testing`** — PyRIT for breadth/scoring; its `llm0X-*.md` playbooks
  for manual confirmation and PoC. Feed PyRIT findings into the matching playbook.
- **`coordination`** — a coordinator can spawn this as an executor step; pass the
  engagement `OUTPUT_DIR` so findings land in the shared tree.
- **`hackerone` / pentest reporting** — `finding.json` carries the fields the
  validation/report tooling expects (CVSS to be assigned at triage).

## Critical rules

- **Written authorization REQUIRED** before testing any model.
- Stay within the declared endpoint/scope; do not test shared third-party models.
- This skill ships *behavioural objectives*, not operational attack payloads.
  Keep it that way — extend objectives, not weaponized exploits.
- Treat model output as untrusted: never auto-execute anything PyRIT elicits.
- PyRIT writes to its own memory DB; runs here use `IN_MEMORY` so nothing
  persists outside the OUTPUT_DIR.

## Usage

```bash
/pyrit-red-teaming <endpoint> [--model M] [--converters base64,rot13]
```
