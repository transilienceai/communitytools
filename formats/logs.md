# Output Type: Logs

All execution and activity logs in NDJSON format.

## Structure

```
logs/
├── pentester-coordinator.log      # Coordinator decisions (NDJSON)
├── {executor-name}.log            # Per-executor activity logs (NDJSON)
└── activity/                      # Alternative location
    └── *.log
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
