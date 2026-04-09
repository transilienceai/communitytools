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

## Rules

- One JSON file per asset type in `{OUTPUT_DIR}/recon/`
- Finding JSON files live in `{OUTPUT_DIR}/findings/finding-NNN/`
- All JSON must be valid and parseable
- See `formats/reconnaissance.md` for detailed reconnaissance schemas
- See CLAUDE.md for the canonical `OUTPUT_DIR` directory structure
