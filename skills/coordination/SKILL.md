---
name: coordination
description: Pentest orchestration — runs inline, spawns executor/validator agents from role reference files. Entry point for all engagements.
---

# Coordination

Runs **inline** in main context. Read `reference/orchestrator-role.md` and follow its cyclic workflow.

## Spawning Pattern

```python
executor_role = Read("skills/coordination/reference/executor-role.md")
patt_ref = Read("skills/coordination/reference/patt-fetcher.md")

# Parallel executors — all in ONE message, background
Agent(prompt=f"{executor_role}\n\n{patt_ref}\n\nMISSION_ID: m-001\nOBJECTIVE: ...\nSKILL_FILES: ...\nOUTPUT_DIR: ...",
      description="SQLi /search", run_in_background=True)
Agent(prompt=f"{executor_role}\n\n{patt_ref}\n\nMISSION_ID: m-002\n...",
      description="SSTI /template", run_in_background=True)

# Validators — after executors, one per finding
validator_role = Read("skills/coordination/reference/validator-role.md")
Agent(prompt=f"{validator_role}\n\nfinding_id: F-001\n...", run_in_background=True)
```

## Workflow

1. **Recon** — deploy recon executors (see `reference/RECONNAISSANCE_OUTPUT.md`)
2. **Plan** — create test plan, proceed immediately
3. **Test** — deploy executors in parallel batches
4. **Validate** — deploy validators per-finding (see `reference/VALIDATION.md`)
5. **Report** — aggregate validated findings, generate PDF via `/transilience-report-style`

## Role References

| File | Purpose |
|------|---------|
| `orchestrator-role.md` | Cyclic workflow, context accumulation, parallelization |
| `executor-role.md` | Mission execution, escalation, output format |
| `validator-role.md` | 5-check finding validation |
| `script-generator-role.md` | Script generation + syntax validation |
| `patt-fetcher.md` | PayloadsAllTheThings URL map (bake into executor prompts) |

## Other References

`ATTACK_INDEX.md` · `OUTPUT_STRUCTURE.md` · `RECONNAISSANCE_OUTPUT.md` · `FINAL_REPORT.md` · `VALIDATION.md` · `TEST_PLAN_FORMAT.md` · `GIT_CONVENTIONS.md`
