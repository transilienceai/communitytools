# Routing — technique type → target file

Where a promoted learning belongs. The judge proposes a target; this table is the default
when it does not, and the tie-breaker when its proposal disagrees with the technique type.

| technique_type | Target |
|---|---|
| `injection` | `skills/injection/reference/<class>-quickstart.md` or `-cheat-sheet.md` |
| `auth` | `skills/authentication/reference/` |
| `traversal` | `skills/server-side/reference/scenarios/path-traversal/` |
| `ssrf` | `skills/server-side/reference/` |
| `client-side` | `skills/client-side/reference/` |
| `api` | `skills/api-security/reference/` |
| `recon` | `skills/reconnaissance/reference/` |
| `privesc` | `skills/system/reference/scenarios/` |
| `ad` | `skills/system/reference/` |
| `cloud` | `skills/cloud-containers/reference/` |
| `crypto` | `skills/cryptography/reference/` |
| `binary` | `skills/reverse-engineering/reference/` |
| `mobile` | `skills/mobile-security/reference/` |
| `dfir` | `skills/dfir/reference/` |
| `attack-chain` | `skills/coordination/reference/spawning-recipes.md` |
| `tooling` | the owning skill's `reference/`, or `skills/essential-tools/reference/` |
| `scenario` | `<skill>/reference/scenarios/<category>/` — self-contained, ≤400 lines |

Prefer **extending an existing entry** over a new section, and a new section over a new file.
A new file must be linked from its `SKILL.md` in the same change, or it is born an orphan.

## De-specialization

The same learning, before and after. The left column is what an engagement produces; the
right is what may enter the skill base.

| Raw observation | Reusable pattern |
|---|---|
| "On box-N the `id` param was injectable" | "When a numeric parameter feeds an ORDER BY clause, try a boolean-blind payload before UNION." |
| "`sqlmap` worked against 10.x.x.x:8080" | "When the app echoes a DB error, confirm the injection point manually before automating." |
| "The flag was in `/home/<svc-account>/user.txt`" | "When a service account owns the web root, check its home directory for credential reuse." |
| "Used the writeup's exploit for CVE-…" | "When a version banner matches a known advisory, verify the vulnerable code path is reachable before weaponizing." |

Use `<TARGET_IP>`, `<DC_FQDN>`, `<DOMAIN>`, `<USER>`, `<PORT>` in every command example. A
learning that needs a machine name, lab ID, target IP, challenge ID, preserved flag or writeup
attribution to make sense is lore, not a pattern — the workflow's machine scrub rejects it
before a judge ever sees it.

## Anti-Patterns

- Routing by where the learning was *found* rather than what it *is*.
- Creating a new file when an existing entry would host the learning in three lines.
- Batching unrelated learnings into one block so the placement fits.
