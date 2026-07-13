# Output Type: Logs

All execution and activity logs in NDJSON format.

## Structure

```
logs/
├── pentester-coordinator.log      # Coordinator decisions (NDJSON)
├── {executor-name}.log            # Per-executor activity logs (NDJSON)
└── activity/                      # Deterministic audit logs (machine-written, append-only)
    ├── tool-invocations.jsonl     # One line per Bash call (PostToolUse hook)
    └── source-ips.jsonl           # One line per registered source/egress IP
```

## NDJSON Format

Each line is a standalone JSON object:

```json
{"timestamp": "2024-01-15T10:30:00Z", "level": "info", "agent": "coordinator", "action": "spawn_executor", "target": "sqli-search", "mission_id": "m-001"}
{"timestamp": "2024-01-15T10:30:05Z", "level": "info", "agent": "sqli-executor", "action": "test_payload", "endpoint": "/search", "result": "vulnerable"}
{"timestamp": "2024-01-15T10:31:00Z", "level": "info", "agent": "coordinator", "action": "spawn_validator", "finding_id": "F-001"}
```

## Rules

- One log file per coordinator
- One log file per executor (named after the executor)
- All logs use NDJSON format (one JSON object per line)
- Include `timestamp`, `level`, `agent`, and `action` fields minimum

## activity/ deterministic audit logs

Two machine-written, append-only JSONL files under `{OUTPUT_DIR}/logs/activity/`. First-class audit
artifacts, part of every deliverable.

### `tool-invocations.jsonl`

One JSON object per Bash command, written by the harness-run PostToolUse hook
(`tools/activity-logger.py`). The full command **string** of every Bash call is harness-guaranteed;
`bins` is best-effort parsing of that string. Command strings are REDACTED by default.

| Field | Type | Meaning |
|-------|------|---------|
| `ts` | string (ISO-8601) | When the command completed |
| `agent_id` | string | ID of the invoking agent |
| `agent_type` | string | Agent role (coordinator, executor, validator, …) |
| `asset` | string | In-scope asset the command targeted |
| `bins` | string[] | Tool binaries parsed from the command (best-effort) |
| `full_command` | string | The command string (REDACTED by default) |
| `cwd` | string | Working directory at invocation |
| `exit_code` | int | Process exit status |
| `source` | string | Emitter (`activity-logger`) |

```json
{"ts":"2026-01-15T10:30:00Z","agent_id":"exec-002","agent_type":"executor","asset":"app.example.com","bins":["nmap"],"full_command":"[REDACTED]","cwd":"/out/260115_eng","exit_code":0,"source":"activity-logger"}
```

### `source-ips.jsonl`

One JSON object per source/egress IP, written by `tools/register_source_ip.py`. The primary-runner IP
is guaranteed (registered by deterministic Setup code); non-primary egress is convention-enforced
(route provisioning through `tools/provision_vantage.sh`) and reconciliation-flagged. Auto-`detected`
rows are `verified:false` and never clear a coverage gap.

| Field | Type | Meaning |
|-------|------|---------|
| `ts` | string (ISO-8601) | When the IP was registered |
| `ip` | string | The source/egress IP address |
| `role` | enum | `primary-runner` \| `attack-vm` \| `proxy` \| `vpn` \| `socks` \| `detected` |
| `provider` | string | Hosting/network provider (e.g. GCP, local) |
| `region` | string | Provider region / geo of the vantage |
| `note` | string | Free-text context (why this vantage was used) |
| `source` | string | Emitter (`register_source_ip.py`, `provision_vantage.sh`, auto) |
| `verified` | bool | Whether the IP was confirmed (auto-`detected` = `false`) |

```json
{"ts":"2026-01-15T10:29:00Z","ip":"203.0.113.10","role":"primary-runner","provider":"local","region":"eu-west","note":"engagement runner","source":"register_source_ip.py","verified":true}
```

## experiments.md Format

Append-only markdown table at `{OUTPUT_DIR}/experiments.md`.

```markdown
# Experiments
| # | Batch | Technique | Target | Parameters | Result | Notes |
|---|-------|-----------|--------|------------|--------|-------|
| E-001 | B1 | nmap-full | 10.10.11.42 | -sC -sV -p- | done | 80,443 open |
```

**Columns**: #=sequential ID, Batch=coordinator batch, Technique=attack class, Target=endpoint/host, Parameters=key params, Result=pending/done/success/fail, Notes=one-liner summary.

**Rules**:
- Coordinator creates header at P1, appends rows at P2 with result=pending
- Executor updates its row on completion (result + notes)
- Never prune, never rewrite existing rows
- Same technique + target = skip unless parameters differ

## tools/ Format

One file per significant tool invocation at `{OUTPUT_DIR}/tools/`.

**Naming**: `{NNN}_{tool-name}.md` — NNN is zero-padded sequential (001, 002, ...).

**Template**:
```markdown
# {tool-name}
Experiment: E-NNN
Timestamp: ISO-8601

## Input
{exact command}

## Output
{raw output, truncated if > 200 lines}
```

**Rules**:
- Log security-relevant tools only: nmap, curl, sqlmap, ffuf, nuclei, python exploits, etc.
- Skip trivial commands: cd, ls, cat, echo
- Truncate output > 200 lines with `[truncated — N lines total]`
- Link to experiment via `Experiment: E-NNN` header
