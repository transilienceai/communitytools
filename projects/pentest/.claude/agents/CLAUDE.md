# Core Agents

5 agents: security testing orchestration + execution + validation + deep exploitation + bug bounty automation.

## Artifact Discipline (ALL AGENTS)

**NEVER write any file to the project root or current working directory.** Every file an agent produces — tool output, downloads, scripts, certificates, keys, tickets, captures, dumps, reports, evidence — MUST go into a structured `outputs/` subtree.

### Directory Structure

```
outputs/YYYYMMDD_<target-or-engagement>/
├── recon/              # Nmap, dirsearch, fingerprinting results
├── findings/           # Finding descriptions, PoCs, workflows
│   └── finding-NNN/
│       ├── description.md
│       ├── poc.py
│       └── evidence/
├── evidence/           # Screenshots, HTTP captures
├── logs/               # Activity logs (NDJSON)
├── artifacts/          # ALL tool-generated files
│   ├── certs/          # .crt, .key, .pfx, .pem, .csr, .p12
│   ├── tickets/        # .ccache, .kirbi (Kerberos)
│   ├── captures/       # .pcap, .cap network captures
│   └── loot/           # Downloaded files, database dumps, configs, hashes
└── reports/            # Dirsearch, submission reports, final PDF
```

### Enforcement Rules

1. **Before running any tool that generates output files** (certipy, impacket, openssl, nmap, secretsdump, bloodhound, sqlmap, dirsearch, etc.), either:
   - Use the tool's `-o`/`-out`/`-output`/`-oN` flag to write directly into the right subdirectory, OR
   - `cd` into the target subdirectory first, OR
   - `mv` the file immediately after generation
2. **Create directories on first use**: `mkdir -p outputs/YYYYMMDD_<target>/artifacts/{certs,tickets,captures,loot}`
3. **Naming convention**: Always prefix with date `YYYYMMDD_` (e.g., `outputs/20260319_pirate.htb/`, `outputs/20260319_10.129.9.51/`). If no target name is provided, derive from hostname/IP.
4. **Orchestrators/HTB agent**: create the full directory tree before spawning sub-agents, pass the output path in the prompt
5. **Applies to ALL file types**: certificates, keys, tickets, pcaps, wordlists, scripts, hash files, database dumps, downloaded source code, git dumps, screenshots — no exceptions

## Credential & Environment Variable Loading (ALL AGENTS)

**MANDATORY**: Before using `AskUserQuestion` to ask the user for credentials, API keys, tokens, or any configuration value, ALWAYS read from `.env` first:

```bash
python3 .claude/tools/env-reader.py VAR1 VAR2 VAR3
```

Only ask the user if `env-reader.py` returns `NOT_SET` for the needed variable. This applies to ALL agents.

**NEVER** try to read `.env` files directly via `source .env`, `cat .env`, or `echo $VAR` in Bash — these will always fail because each Bash invocation is a fresh shell with no `.env` loaded. The `env-reader.py` tool parses `.env` files reliably via Python.

## Agents

| Agent | Role | Delegates |
|-------|------|-----------|
| pentester-orchestrator | Coordinate pentests, plan & execute | pentester-executor, pentester-validator |
| pentester-executor | Execute specific vulnerability tests | None |
| pentester-validator | Validate individual findings against raw evidence | None |
| hackerone | Bug bounty automation, scope parsing, submission generation | pentester-orchestrator |
| script-generator | Generate optimized, validated scripts for other agents | None |

## Interaction Model

**Single asset**: User → Orchestrator (plans → executes) → Executors → Report

**Bug bounty**: User → HackerOne Hunter (parses scope → deploys per asset) → Orchestrators → Executors → Validated Submissions

**Environment**: Any agent → `python3 .claude/tools/env-reader.py VAR1 VAR2` (MANDATORY before AskUserQuestion for credentials/config)

**Script generation**: Any agent → script-generator (recommended for scripts >30 lines, parallel operations, or multi-library patterns)

**HackTheBox (Docker mode)**:
```
HTB Agent (host — Playwright for browser, VPN management)
  ├── Orchestrator (host, in-process Agent tool — coordinates)
  │     ├── Executor containers (Docker, parallel kali-agent)
  │     └── Validator containers (Docker, parallel kali-agent)
  └── Direct orchestrator (for simple challenges)
```
HTB agent stays on host (needs Playwright for tab management, flag submission).
Orchestrator stays on host (needs to spawn/monitor Docker containers).
Executors and validators run in isolated Kali containers with full tooling.

## Docker Mode (Isolated Kali Containers)

Each executor/validator can run in a separate Kali Linux Docker container with full pentest tooling and passwordless sudo. The orchestrator stays on the host as an interactive session.

**Architecture**:
```
Host (macOS/Linux)
├── Orchestrator (Claude Code, native — handles user interaction)
│   ├── docker run kali-agent → SQL Injection executor
│   ├── docker run kali-agent → XSS executor
│   └── docker run kali-agent → SSRF executor
└── Shared: outputs/ ←→ /workspace/outputs/ in containers
```

**Container features**: Kali rolling + kali-tools-web + kali-tools-exploitation, Node.js 20, Claude Code CLI, chromium, passwordless sudo, `--dangerously-skip-permissions`.

**Communication**: File-based via shared volume (same NDJSON logs + findings pattern). Executors write status to `outputs/status/{name}.json` for progress monitoring.

**Network auto-detection**:
- Docker container target → joins same network
- Localhost target → `host.docker.internal`
- Remote target → default bridge

**User input**: Containers run non-interactively (`-p` flag). All user interaction happens on the host BEFORE spawning containers. Executors are fully autonomous.

**Usage**: See `pentester-orchestrator.md` Mode B.

**CRITICAL**: Never pass `CLAUDECODE` env var to containers (kills nested Claude sessions).

**CRITICAL**: Docker mode requires `ANTHROPIC_API_KEY` env var (login-based auth doesn't work in containers). Containers run with `--privileged` for nmap raw sockets and exploit tools.

## Planning

Orchestrator creates test plan after reconnaissance (Phase 3), then runs **mandatory pre-testing phases**:
- **Phase 3.5: Cross-Endpoint Consistency Probe** — canary payloads across all endpoints to detect inconsistent WAF/validation coverage
- **Phase 3.6: JavaScript Bundle Analysis** — for SPA targets, extract secrets, disabled features, legacy endpoints, storage patterns

Then proceeds to executor deployment.

See `reference/TEST_PLAN_FORMAT.md` for test plan template.

## Output Standards

**Conforms to Component Generation Framework:**

**Activity logs**: `outputs/logs/{agent-name}.log` (NDJSON)
**Findings**: `outputs/processed/findings/finding-{NNN}/` (PoC + evidence) or `outputs/reports/appendix/finding-{NNN}/` (evidence)
**Reports**: `outputs/data/pentest-report.json` (JSON), `outputs/reports/Penetration-Test-Report.pdf` (Transilience branded PDF via `transilience-report-style` skill)

See `reference/OUTPUT_STRUCTURE.md` for formats.

## Executor Specializations (30+)

- **Injection** (6): SQL, NoSQL, Command, SSTI, XXE, LDAP
- **Client-Side** (6): XSS, CSRF, Clickjacking, CORS, Prototype Pollution, DOM
- **Server-Side** (6): SSRF, HTTP Smuggling, Path Traversal, File Upload, Deserialization, Host Header
- **Authentication** (4): Bypass, JWT, OAuth, Password Attacks
- **API** (4): GraphQL, REST, WebSocket, Web LLM
- **Business Logic** (6): Logic Flaws, Race Conditions, Access Control, Cache Poisoning, Cache Deception, Info Disclosure

Each: Mounts attack skill → 4-phase workflow (Recon → Experiment → Test → Verify) → Outputs activity log + findings

## Validator

Deployed per-finding by the orchestrator after all executors complete. Reads all evidence, runs PoCs, cross-references claims against raw scan data. ALL 5 checks must pass or finding is rejected. See `pentester-validator.md`.

## Reference

- `reference/OUTPUT_STRUCTURE.md` - Log/finding formats
- `reference/TEST_PLAN_FORMAT.md` - Test plan template
- `pentester-validator.md` - Finding validator agent definition
- `hackerone.md` - HackerOne Hunter agent definition
