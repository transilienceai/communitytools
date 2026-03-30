# Logging Specification

## Output Directory Structure

```
outputs/YYYYMMDD_<challenge-name>/
├── challenge-log.ndjson      # Master timeline (append-only)
├── challenge-meta.json       # Challenge metadata
├── recon/
│   ├── nmap-scan.txt         # Port/service scan results
│   ├── web-enum.txt          # Directory/endpoint enumeration
│   ├── tech-stack.json       # Identified technologies
│   └── notes.md              # Recon observations
├── exploits/
│   ├── exploit-001.py        # Exploit scripts (numbered)
│   ├── payload-001.txt       # Payloads used
│   └── notes.md              # What worked, what didn't
├── evidence/
│   ├── screenshots/          # Playwright screenshots
│   ├── http-captures/        # Request/response pairs
│   └── terminal-output/      # Command outputs
├── findings/
│   ├── vuln-001.md           # Vulnerability write-ups
│   └── attack-chain.md       # Full attack narrative
└── flag.txt                  # Captured flag(s)
```

## NDJSON Log Format

Each line in `challenge-log.ndjson`:

```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "phase": "recon|exploit|post-exploit|flag",
  "action": "nmap_scan|web_request|exploit_attempt|flag_submit",
  "tool": "nmap|curl|playwright|python|manual",
  "target": "10.10.11.50:80",
  "detail": "Description of what was done",
  "result": "success|failure|partial",
  "output_file": "recon/nmap-scan.txt",
  "notes": "Optional observations"
}
```

## Challenge Metadata

`challenge-meta.json`:
```json
{
  "name": "Challenge Name",
  "type": "machine|challenge|lab",
  "difficulty": "easy|medium|hard|insane",
  "target_ip": "10.10.11.50",
  "started_at": "2025-01-15T10:00:00Z",
  "completed_at": null,
  "flag": null,
  "techniques_used": [],
  "skills_invoked": []
}
```

## Logging Rules

1. **Log BEFORE executing**: Write intent before running commands
2. **Log AFTER executing**: Write result with output reference
3. **Log failures**: Failed attempts are valuable learning data
4. **No secrets in logs**: Redact credentials, use `[REDACTED]`
5. **Reference files**: Point to evidence files, don't inline large outputs
6. **Timestamp everything**: ISO 8601 format, UTC

## Writing Logs

```python
import json, datetime

def log_action(log_path, phase, action, tool, target, detail, result, output_file=None):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "phase": phase,
        "action": action,
        "tool": tool,
        "target": target,
        "detail": detail,
        "result": result,
    }
    if output_file:
        entry["output_file"] = output_file
    with open(log_path, "a") as f:
        f.write(json.dumps(entry) + "\n")
```
