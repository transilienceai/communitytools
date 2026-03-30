# Community Security Tools Repository
This repo provides Claude Code skills for security testing, bug bounty hunting, and pentesting workflows. All orchestration, execution, and validation roles are defined as skill reference files — no separate agent definitions.

## Rules
- Be optimistic, don't loose hope
- Optimize, be efficient, when allocating tasks, writing files, modifying... 
- Be wary of committing secrets, credentials or .env files
- Move or save any file into the appropriate folder for the job. create one if necessary.
- Solutions requires investigation, research, creativity, keep that in mind
- Always use /skiller to perform skill improvements and learning patterns
- All skills follow standardized output formats. See `skills/coordination/reference/OUTPUT_STRUCTURE.md` for complete specification.
- Before executing a task, ensure to mount the right set of skills adapt for the task

## Security Testing Rules
- Never perform destructive operations
- Always document findings using standardized formats
- Follow responsible disclosure practices
- Generate complete evidence (screenshots, HTTP captures, videos)

## Directory Structure
**NEVER write any file to the project root or current working directory.** Every file an agent produces — tool output, downloads, scripts, ... MUST go into a structured subtree. **Create the full directory tree at the very start of any engagement/task before doing anything else:**

```bash
mkdir -p YYMMDD_hhmmss_<target-or-engagement>/{recon,findings,logs,artifacts,reports}
```

```
YYMMDD_hhmmss_<target-or-engagement>/
├── recon/              # Nmap, dirsearch, fingerprinting results
├── findings/           # Finding descriptions, PoCs, workflows
│   └── finding-NNN/
│       ├── description.md
│       ├── poc.py      # Script that demonstrates the finding
│       └── evidence/   # Screenshots, HTTP captures
├── logs/               # Agents Activity logs (NDJSON)
├── artifacts/          # ALL tool-generated files (.crt, .key, database dumps, configs, hashes, ...)
└── reports/            # Dirsearch, submission reports, final PDF, ...
```

## Credential & Environment Variable Loading

**MANDATORY**: Before using `AskUserQuestion` to ask the user for credentials, API keys, tokens, or any configuration value, ALWAYS read from `.env` first:

```bash
python3 .claude/tools/env-reader.py VAR1 VAR2 VAR3
```

Only ask the user if `env-reader.py` returns `NOT_SET` for the needed variable. This applies to ALL agents.

**NEVER** try to read `.env` files directly via `source .env`, `cat .env`, or `echo $VAR` in Bash — these will always fail because each Bash invocation is a fresh shell with no `.env` loaded. The `env-reader.py` tool parses `.env` files reliably via Python.


## Git Conventions
See `skills/coordination/reference/GIT_CONVENTIONS.md`
