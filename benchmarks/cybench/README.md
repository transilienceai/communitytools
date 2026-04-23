# Cybench Benchmark Runner

Benchmarks the pentest skills in `projects/pentest/.claude/` against the
[cybench](https://github.com/andyzorigin/cybench) CTF suite — 40 tasks drawn
from four CTF competitions (HackTheBox Cyber Apocalypse 2024, HKCert,
Project Sekai, bug-bounty Lunary) across crypto, pwn, rev, web, forensics,
misc, and blockchain.

## How it compares to the XBOW runner

| | XBOW | Cybench |
|---|---|---|
| Layout | `XBEN-XXX-YY/{benchmark.json, docker-compose.yml}` | `benchmark/<comp>/<event>/<category>/<task>/` |
| Flag | `FLAG{sha256(ID)}` injected via build-arg | Per-subtask `answer` strings |
| Target | Always HTTP URL | File-based (crypto/rev/pwn) or `target_host` + `start_docker.sh` |
| Grading | Single flag | Unguided (final answer) or subtask (fractional) |

Both runners share `benchmarks/_shared/` for Claude subprocess spawning, skill
injection, preflight checks, port discovery, compose-file fixes, and result I/O.

## Prerequisites

- Docker + Docker Compose
- Claude CLI (`npm install -g @anthropic-ai/claude-cli`)
- `git` + `git lfs` (cybench's `project-sekai-ctf` tasks ship large assets via LFS)
- Python 3.9+

## Setup

```bash
git lfs install
python benchmarks/cybench/run_cybench.py --setup
# or clone manually:
# git clone https://github.com/andyzorigin/cybench /tmp/cybench
```

`--cybench-path` can point elsewhere if you prefer a different checkout location.

## Quick start

```bash
# List discovered tasks
python benchmarks/cybench/run_cybench.py --list

# Dry-run one task (show prompt + skill bundle, no Claude call)
python benchmarks/cybench/run_cybench.py \
  --task hackthebox-cyber-apocalypse-2024-crypto-very-easy-dynastic --dry-run

# Real run with pentest skills (Opus, 30-min budget)
python benchmarks/cybench/run_cybench.py \
  --task hackthebox-cyber-apocalypse-2024-crypto-very-easy-dynastic \
  --model opus --timeout 1800

# Baseline without skills
python benchmarks/cybench/run_cybench.py \
  --task hackthebox-cyber-apocalypse-2024-crypto-very-easy-dynastic \
  --vanilla --model opus

# Category sweep
python benchmarks/cybench/run_cybench.py --category crypto --model opus

# Competition sweep with retries
python benchmarks/cybench/run_cybench.py \
  --competition hackthebox --max-retries 2 --parallel 2
```

## Grading modes

- `unguided` (default) — one Claude invocation per task; the agent must emit
  a line matching `FINAL_ANSWER: <value>`. The expected value is the last
  subtask's `answer` — cybench's "final flag" convention.
- `subtask` — not yet implemented. Will feed one Claude invocation per
  subtask and tally per-subtask correctness.

## Skill mounting

`category_skill_map.py` picks a subset of skills per task based on the task's
`categories` field. Baseline (`coordination`, `essential-tools`,
`script-generator`) is always included. Web tasks mount the full web pentest
set; crypto/rev/pwn/blockchain tasks mount the domain-specific skills plus
baseline. Adjust the map as you add new skills.

## Output

```
benchmarks/cybench/results/
├── cybench_results_skills_opus_unguided_YYYYMMDD_hhmmss.json   # aggregate
└── run_YYYYMMDD/<slug>/
    ├── prompt.txt              # exact prompt sent to Claude
    ├── claude_output.txt       # stdout
    ├── claude_stderr.txt       # stderr (if any)
    └── workdir/                # sandbox produced by init_script.sh
```

## Caveats

- `requirements.sh` scripts in cybench install packages on the host. This
  runner does **not** execute them automatically. If a task needs host-side
  tools, run `bash <task_dir>/requirements.sh` yourself, or extend this runner
  with an `--run-requirements` flag.
- Tasks using `start_docker.sh` run their own docker-compose; the shared
  port-discovery helper (`benchmarks/_shared/port_discovery.py`) is used to
  find the assigned host port when the compose file exposes HTTP services.
- cybench's upstream runner uses a Docker-in-Docker agent container; this
  runner spawns Claude Code on the host instead, matching the XBOW runner.
