# Output Type: Data

All JSON data files — machine-readable exports, reconnaissance inventories, and structured findings.

## Structure

```
{OUTPUT_DIR}/
├── artifacts/
│   └── pentest-report.json        # Machine-readable report export
├── recon/                         # Phase 2 JSON inventories
│   ├── domains.json
│   ├── web-apps.json
│   ├── apis.json
│   ├── network.json
│   └── cloud.json
└── findings/                      # Structured finding data
    └── finding-NNN/
        └── finding.json
```

## pentest-report.json

```json
{
  "engagement": {
    "name": "{name}",
    "target": "{target}",
    "dates": "{start} to {end}",
    "status": "complete"
  },
  "findings": [
    {
      "id": "F-001",
      "title": "{title}",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "affected_url": "{url}",
      "description": "{description}",
      "impact": {
        "confidentiality": "HIGH",
        "integrity": "HIGH",
        "availability": "MEDIUM",
        "business_impact": "{impact}"
      },
      "poc_verified": true,
      "poc_steps": ["Step 1", "Step 2"],
      "remediation": {
        "priority": "Immediate (0-7 days)",
        "fix_description": "{fix}",
        "vulnerable_code": "{before}",
        "secure_code": "{after}",
        "references": ["CWE-89", "OWASP A03:2021"]
      },
      "suggestions": ["{suggestion1}", "{suggestion2}"],
      "remediation_status": "open"
    }
  ],
  "statistics": {
    "total": "{n}",
    "critical": "{n}",
    "high": "{n}",
    "medium": "{n}",
    "low": "{n}",
    "informational": "{n}"
  }
}
```

## Validated finding — attack-class coverage-join fields

The interim validated finding JSON (`{OUTPUT_DIR}/artifacts/validated/<id>.json`, the `verdict`-based shape `report_data_build.py` reads) additionally carries three fields that let `tools/coverage_gate.py` join a `covered` cell to its evidence. They are stamped by the coordinator loop **after** `buildInterim` (never inside it):

| Field | Type | Meaning |
|-------|------|---------|
| `class_id` | string \| null | the attack-class this finding covers (from the mission's `covers_cells`/`covers_class`); `null` for a pure wildcard/goal finding (covers no cell) |
| `unit_refs` | string[] | the `scope_key`s (unit_id / listener / asset_tag) this finding proves the class on |
| `asset_tag` | string | the owning asset (the OUTPUT_DIR basename); the gate requires `finding.asset_tag == cell.asset_tag` |

A cell is `covered` only when a `VALID`/`REPAIRED` finding matches on **all three** (`class_id` == cell class, cell `scope_key` ∈ `unit_refs`, `asset_tag` match). See `skills/coordination/reference/coverage-matrix.md`.

## Rules

- One JSON file per asset type in `{OUTPUT_DIR}/recon/`
- Finding JSON files live in `{OUTPUT_DIR}/findings/finding-NNN/`
- All JSON must be valid and parseable
- See `formats/reconnaissance.md` for detailed reconnaissance schemas
- See CLAUDE.md for the canonical `OUTPUT_DIR` directory structure
