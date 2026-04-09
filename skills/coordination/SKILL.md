---
name: coordination
description: Pentest coordination — orchestrates executor and validator agents with context-controlled spawning. Entry point for all engagements.
---

# Coordination

Inline. Holds context. Thinks before every action.

## Workflow

```
P0: Ingest scope
 ↓
P1: Recon + read source code → write attack-chain.md
 ↓
┌→ P2: Think — read chain, write next step + reasoning, design 1-2 experiments
│  P3: Execute — spawn 1-2 executors with CHAIN_CONTEXT
│  P4: Integrate — read results, update chain, revise theory
│      No progress 2 batches → P4b
│      Goal → P5
└─ loop (max 30 experiments)

P4b: Reset — re-read all recon + source + chain. Challenge assumptions. Fresh theory.
P5: Validate + Report
```

### Steps

1. **Recon + Source Code** — read all accessible source code (see `formats/reconnaissance.md`)
2. **Think** — write theory + next step to `attack-chain.md`
3. **Test** — 1-2 executors per batch, integrate before next
4. **Validate** — validators per-finding (see `skills/coordination/reference/VALIDATION.md`)
5. **Report** — validated findings in `{OUTPUT_DIR}/artifacts/validated/` → Transilience PDF via `formats/transilience-report-style/SKILL.md` (MANDATORY)

## attack-chain.md

At `{OUTPUT_DIR}/attack-chain.md`. Updated every batch. Sections: services, surface, theory, tested, next.

Keep it terse — bullet points, no prose.

## Spawning

Consult `reference/context-injection.md` before building any agent prompt.

```python
executor = Read("skills/coordination/reference/executor-role.md")
chain = Read(f"{output_dir}/attack-chain.md")

# 1-2 executors per batch — pass only relevant PATT_URL, not full map
Agent(prompt=f"{executor}\nMISSION_ID: m-001\nCHAIN_CONTEXT: {chain}\n"
      f"OBJECTIVE: ...\nSKILL_FILES: ...\nPATT_URL: ...\nOUTPUT_DIR: {output_dir}",
      description="Blind SQLi /search", run_in_background=True)

# Wait. Read results. Think. Update attack-chain.md. THEN next batch.

# Validators — one per finding (BLIND REVIEW — see context-injection.md)
validator = Read("skills/coordination/reference/validator-role.md")
Agent(prompt=f"{validator}\nfinding_id: F-001\n"
      f"FINDING_DIR: {output_dir}/findings/finding-001/\n"
      f"TARGET_URL: ...\nOUTPUT_DIR: {output_dir}/artifacts",
      run_in_background=True)

# After all validators complete:
# 1. Read artifacts/validated/ and artifacts/false-positives/
# 2. Verify each validated finding has findings/{id}/evidence/validation/validation-summary.md
# 3. Flag any finding that passed validation but has no proof
```

Pass only the relevant PATT_URL for this mission, not the full URL map.

## Roles

| Role | File | Context |
|------|------|---------|
| Executor | `reference/executor-role.md` | Full chain + skills |
| Validator | `reference/validator-role.md` | Evidence only (blind) |

See `reference/context-injection.md` for what each role receives and what is withheld.

## Rules

1. Autonomous. Never ask user.
2. Think before acting. Write reasoning to attack-chain.md before every batch.
3. Max 1-2 executors per batch. Recon can use more.
4. Source code first. Understanding beats guessing.
5. Pass chain context + specific PATT_URL to executors.
6. 30 experiment cap.
7. Stuck 2 batches → re-read everything, fresh theory.
8. All output to OUTPUT_DIR.
9. Report gate: validated findings exist → PDF report required. Read `formats/transilience-report-style/pentest-report.md`.
10. After validators complete, verify each validated finding has `evidence/validation/validation-summary.md`. Flag any that passed without proof.
11. Sequential flag progression. In multi-flag challenges (HTB machines), secure each flag before attempting the next. The user-flag path often provides the foothold needed for root.
12. 3-strike stuck detection. If the same technique fails 3 times with different errors, STOP. Write to attack-chain.md: (a) why it's failing, (b) is this path fundamentally blocked (check ACLs, PRP, group membership), (c) alternative paths. Do NOT continue retrying.
13. Read before calling library internals. Before writing Python against any library's internal API (Impacket, ldap3, pyasn1), read the relevant source file first. Never guess function signatures. Prefer CLI tools (secretsdump.py, ticketer.py, getST.py) over raw API calls.
14. Background command discipline. Before spawning a background command, state what specific result it will produce. No speculative tunnels, relays, or listeners without a concrete plan to use them.

## Token Discipline

- Internal output (chain, logs, reports): terse. Bullets, not paragraphs.
- Executor prompts: include only relevant skill files and PATT URL, not everything.
- Don't inject `patt-fetcher/SKILL.md` into executor prompts. Pass only the relevant PATT_URL.
- Don't inject skill files the executor won't use. Pick the 1-2 most relevant.
- attack-chain.md: max 50 lines. Prune old tested items to one-liners.
- User-facing output (reports, summaries): detailed and professional.

## References

`reference/ATTACK_INDEX.md` · `reference/OUTPUT_STRUCTURE.md` · `reference/VALIDATION.md` · `reference/GIT_CONVENTIONS.md` · `reference/context-injection.md` · `formats/INDEX.md`
