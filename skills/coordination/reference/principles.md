# Engagement Principles

Standing principles for any engagement. Referenced from every skill instead of being restated.

## Source code first

Read every accessible source — application code, configs, scripts, share contents, dumped binaries — before any executor batch. Every answer is in the data already collected. Guessing without reading is the most common failure mode.

## Three hypotheses, one wildcard

At every P2 Think, write three hypotheses to `attack-chain.md`. At least one tagged `[wildcard]` — an angle no mounted skill explicitly prescribes. Pick 1-2 to spawn. Record the rejected ones — they form the search-tree backlog and can be revisited at P4b.

## Depth over breadth

1-2 executors per batch (recon may use more). Integrate before next. Coordinator thinks between batches; executors don't speculate. The depth-first rhythm is the only way to keep context productive.

## Conceptual-goal stuck detection

Count failures toward the same conceptual *goal*, not the same technique string. Five different cert tools chasing "use this cert to authenticate" = five strikes against one goal. See `bookkeeping.md` Goal column. At three strikes on a goal: P4b reset, fresh theory, no retry on cosmetic variants.

## Pivot menu, not cookbook

When stuck, consult symptom-indexed pivot tables (`when X fails, try Y`) rather than archetype cookbooks. Cookbooks tell you what success looks like — useless when you don't see success. Pivot menus tell you the next move.

## Blind validators

Validators receive evidence only — never the coordinator's reasoning, never the attack-chain. Independent verification is the anti-hallucination firewall. Both finding-validator and engagement-validator are blind. See `role-matrix.md`.

## Append-only audit

`experiments.md` and `tools/{NNN}_*.md` are append-only. Never rewrite. Never prune. The trail proves thoroughness and lets the engagement-validator judge.

## CLI tools first, library APIs second

For Active Directory / Kerberos / SMB / LDAP work, prefer CLI tools (impacket secretsdump, ticketer, getST, getTGT, smbclient; bloodyAD; certipy) over writing custom Python against library internals. Only drop to Python when CLI can't do what you need — and read the library source first.

## Source for library internals

Before writing Python against any library API (impacket, ldap3, pyasn1), read the relevant source file. Never guess function signatures.

## Background command discipline

State the specific result a tunnel / relay / listener will produce *before* spawning it. No speculative listeners.

## Diagnose before retrying

When a tool fails, read the error message. Check permissions, prerequisites, config. Don't retry with cosmetic variations.

## CVE risk lookup

Whenever a CVE ID (`CVE-YYYY-NNNNN`) is mentioned or discovered, run `python3 tools/nvd-lookup.py <CVE-ID>` to fetch the authoritative CVSS, severity, and CWE. Include in any finding's evidence.

## No `AskUserQuestion` from coordinator

Coordinator is autonomous. Missing creds → run env-reader, terminate with `status=BLOCKED` if not set. Asking is the parent orchestrator's job. See `role-matrix.md`.

## No partial-as-success

A multi-flag engagement is incomplete until every flag submits. `status=FAILED_partial` is a temporary marker, never a final outcome. On Easy targets, restart from recon if no progress in 5 batches after foothold.

## Output discipline

All artifacts go under `OUTPUT_DIR`. Directory tree in `output-discipline.md`. Never write to repo root or working directory.
