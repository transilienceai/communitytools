# Sensitive Data Metadata Tracking for HackerOne Testing

**Purpose**: Track and document all credentials, tokens, API keys, and sensitive data discovered during penetration testing in a structured JSON format.

**Why This Matters**:
- Legal compliance (GDPR, CCPA) - document what data was accessed
- Security - track what sensitive information was exposed
- Reporting - provide complete evidence of vulnerability impact
- Remediation - help clients understand what was compromised
- Audit trail - prove responsible disclosure practices

---

## Overview

Every HackerOne bug bounty testing engagement generates a `sensitive_data_metadata.json` file that documents:
- All credentials discovered (usernames, passwords, API keys, tokens)
- Sensitive data accessed (PII, private keys, configuration data)
- Where data was found
- How data was used in exploitation
- When data was discovered (timestamps)
- Proof of discovery (evidence references)

---

## Directory Structure

```
outputs/<program_name>/<asset_identifier>/
├── findings/
│   ├── finding-001/
│   │   ├── report.md
│   │   ├── poc.py
│   │   ├── poc_output.txt
│   │   ├── workflow.md
│   │   ├── description.md
│   │   └── sensitive_data.json      ← NEW: Per-finding sensitive data
│   └── finding-002/
│       └── [same structure]
│
├── sensitive_data_metadata.json     ← NEW: Complete asset-level inventory
├── evidence/
│   ├── screenshots/
│   ├── http-captures/
│   └── videos/
│
└── reports/
    ├── findings-summary.md
    └── sensitive_data_report.md    ← NEW: Analysis of all sensitive data
```

---

## sensitive_data_metadata.json Structure

### Top-Level Schema

```json
{
  "program": "HackerOne Program Name",
  "program_handle": "program_handle",
  "asset_identifier": "https://example.com",
  "asset_type": "URL",
  "testing_date_start": "2025-01-16T10:00:00Z",
  "testing_date_end": "2025-01-16T14:30:00Z",
  "tester": "Pentester Agent",
  "sensitive_data_categories": {
    "credentials": [...],
    "api_keys_and_tokens": [...],
    "private_data": [...],
    "configuration_data": [...],
    "user_pii": [...],
    "other_sensitive": [...]
  },
  "summary": {
    "total_items_discovered": 12,
    "by_category": {...},
    "by_severity": {...},
    "highest_risk_finding": "finding-002"
  },
  "remediation_status": "pending"
}
```

---

## Data Categories

### 1. Credentials

```json
{
  "category": "credentials",
  "type": "username_password",
  "location": "SQL injection in search parameter",
  "finding_id": "finding-001",
  "discovered_date": "2025-01-16T10:35:00Z",
  "data": {
    "username": "[REDACTED]",
    "password_hash": "$2y$10$abc123...",
    "password_hash_algorithm": "bcrypt",
    "account_type": "admin",
    "privileges": "superuser"
  },
  "evidence": {
    "poc_script": "findings/finding-001/poc.py",
    "poc_output": "findings/finding-001/poc_output.txt",
    "screenshot": "evidence/screenshots/finding-001-credentials.png",
    "http_capture": "evidence/http-captures/finding-001-request.txt"
  },
  "impact_assessment": {
    "severity": "CRITICAL",
    "accounts_affected": 1,
    "access_level": "superuser",
    "potential_actions": ["account_takeover", "data_breach", "system_compromise"]
  },
  "remediation": "Rotate compromised credentials immediately",
  "status": "discovered"
}
```

### 2. API Keys and Tokens

```json
{
  "category": "api_keys_and_tokens",
  "type": "api_key",
  "token_type": "Bearer Token / JWT / OAuth",
  "location": "Hardcoded in JavaScript source",
  "finding_id": "finding-003",
  "discovered_date": "2025-01-16T11:20:00Z",
  "data": {
    "key_id": "[REDACTED]",
    "key_preview": "sk_live_****...1234",
    "scope": ["read:users", "write:data", "delete:projects"],
    "issued_date": "2024-12-01T00:00:00Z",
    "expiration_date": "2025-12-01T00:00:00Z"
  },
  "evidence": {
    "location_in_code": "https://example.com/assets/app.js line 1234",
    "screenshot": "evidence/screenshots/finding-003-api-key.png"
  },
  "impact_assessment": {
    "severity": "HIGH",
    "api_endpoints_accessible": 12,
    "data_accessible": ["user_profiles", "project_data", "payment_info"],
    "potential_actions": ["data_exfiltration", "data_modification", "resource_deletion"]
  },
  "remediation": "Revoke token immediately and rotate secrets",
  "status": "discovered"
}
```

### 3. Private Data

```json
{
  "category": "private_data",
  "type": "private_key",
  "key_type": "RSA / EC / SSH",
  "location": "Exposed in .git directory",
  "finding_id": "finding-005",
  "discovered_date": "2025-01-16T12:15:00Z",
  "data": {
    "key_format": "PEM",
    "key_length": 2048,
    "key_fingerprint": "[REDACTED]",
    "purpose": "SSH access to production servers",
    "associated_user": "deploy_user"
  },
  "evidence": {
    "location": ".git/config private key",
    "screenshot": "evidence/screenshots/finding-005-private-key.png"
  },
  "impact_assessment": {
    "severity": "CRITICAL",
    "systems_accessible": ["production-db-01", "prod-api-server"],
    "potential_actions": ["server_access", "data_exfiltration", "malware_deployment"]
  },
  "remediation": "Revoke key, rotate all dependent credentials, audit access logs",
  "status": "discovered"
}
```

### 4. Configuration Data

```json
{
  "category": "configuration_data",
  "type": "database_connection_string",
  "location": "Environment variables exposed via YAML parsing",
  "finding_id": "finding-002",
  "discovered_date": "2025-01-16T11:00:00Z",
  "data": {
    "database_host": "[REDACTED]",
    "database_port": 5432,
    "database_name": "production_db",
    "connection_string_preview": "postgresql://user:****@db.internal:5432/prod_db"
  },
  "evidence": {
    "poc_script": "findings/finding-002/poc.py",
    "poc_output": "findings/finding-002/poc_output.txt"
  },
  "impact_assessment": {
    "severity": "CRITICAL",
    "databases_affected": 1,
    "records_accessible": "millions of user records",
    "data_types": ["PII", "payment_info", "health_data"]
  },
  "remediation": "Rotate database credentials, restrict network access, enable encryption",
  "status": "discovered"
}
```

### 5. User PII

```json
{
  "category": "user_pii",
  "type": "personal_information",
  "data_type": ["name", "email", "phone", "address", "ssn"],
  "location": "Database accessible via SQL injection",
  "finding_id": "finding-001",
  "discovered_date": "2025-01-16T10:40:00Z",
  "data": {
    "records_accessed": 2547,
    "data_fields_exposed": ["email", "phone", "home_address", "date_of_birth"],
    "sample_record": {
      "email": "[REDACTED]",
      "phone": "[REDACTED]",
      "address": "[REDACTED]"
    }
  },
  "evidence": {
    "sample_screenshot": "evidence/screenshots/finding-001-pii.png",
    "data_export": "evidence/http-captures/finding-001-db-dump.txt"
  },
  "impact_assessment": {
    "severity": "CRITICAL",
    "records_exposed": 2547,
    "privacy_violation": "GDPR Article 32 - Personal Data Security",
    "affected_jurisdictions": ["EU", "CCPA"],
    "potential_harm": ["identity_theft", "fraud", "harassment"]
  },
  "remediation": "Notify affected users per GDPR requirements (72 hours), implement access controls",
  "status": "discovered"
}
```

### 6. Other Sensitive Data

```json
{
  "category": "other_sensitive",
  "type": "internal_ip_addresses",
  "location": "Exposed in error messages",
  "finding_id": "finding-004",
  "discovered_date": "2025-01-16T11:45:00Z",
  "data": {
    "items": [
      "192.168.1.10",
      "10.0.0.5",
      "172.16.0.20"
    ],
    "description": "Internal network infrastructure"
  },
  "evidence": {
    "screenshot": "evidence/screenshots/finding-004-error-message.png"
  },
  "impact_assessment": {
    "severity": "MEDIUM",
    "risk": "Enables network reconnaissance and targeted attacks",
    "potential_actions": ["network_mapping", "further_targeting"]
  },
  "remediation": "Implement proper error handling, remove internal IPs from error messages",
  "status": "discovered"
}
```

---

## Per-Finding sensitive_data.json

Each finding folder can include a focused `sensitive_data.json`:

```json
{
  "finding_id": "finding-001",
  "finding_title": "SQL Injection in Search Parameter",
  "finding_severity": "CRITICAL",
  "sensitive_data_discovered": [
    {
      "category": "credentials",
      "count": 5,
      "types": ["admin_credentials", "api_keys"]
    },
    {
      "category": "user_pii",
      "count": 2547,
      "types": ["email", "phone", "address"]
    }
  ],
  "total_sensitive_items": 2552,
  "highest_severity_data": "admin_credentials",
  "evidence_files": [
    "poc.py",
    "poc_output.txt",
    "evidence/screenshots/finding-001-credentials.png"
  ]
}
```

---

## Summary Report: sensitive_data_report.md

```markdown
# Sensitive Data Discovery Report

**Program**: HackerOne Program Name
**Asset**: https://example.com
**Testing Period**: 2025-01-16 10:00 AM - 2:30 PM UTC
**Tester**: Pentester Agent

## Executive Summary

During penetration testing, **12 instances of sensitive data** were discovered across **4 vulnerability findings**. This data includes:
- Admin credentials (5 items)
- API keys and tokens (3 items)
- Private keys (1 item)
- Database connection strings (1 item)
- User PII (2547 records)
- Internal IP addresses (3 items)

**Immediate Action Required**: Sensitive data must be rotated/reset immediately.

## Data Discovered by Category

### Credentials (5 items)
- 1x Admin account credentials
- 4x Service account credentials

**Severity**: CRITICAL
**Impact**: Full account takeover possible
**Status**: Discovered via finding-001 (SQL injection)

### API Keys & Tokens (3 items)
- API Key: sk_live_... (found in JavaScript)
- Bearer Token: (found in localStorage)
- OAuth token: (found in session storage)

**Severity**: HIGH
**Impact**: 12 API endpoints accessible, data exfiltration possible
**Status**: Discovered via finding-003

### Private Keys (1 item)
- RSA 2048-bit SSH key for production deployment

**Severity**: CRITICAL
**Impact**: Direct server access, complete system compromise possible
**Status**: Discovered via finding-005

### Database Credentials (1 item)
- PostgreSQL connection string with credentials

**Severity**: CRITICAL
**Impact**: 2.5M+ user records accessible
**Status**: Discovered via finding-002

### User PII (2547 records)
- Email addresses, phone numbers, home addresses, DOB

**Severity**: CRITICAL
**Impact**: GDPR violation, fraud risk, identity theft
**Status**: Discovered via finding-001

### Other Sensitive Data (3 items)
- Internal IP addresses
- System architecture information
- Service discovery information

**Severity**: MEDIUM
**Impact**: Enables further reconnaissance
**Status**: Discovered via finding-004

## Remediation Timeline

### IMMEDIATE (0-1 hour)
- [ ] Revoke all discovered credentials
- [ ] Rotate all API keys and tokens
- [ ] Disable compromised SSH keys
- [ ] Change database credentials
- [ ] Lock affected user accounts

### SHORT-TERM (1-24 hours)
- [ ] Audit access logs for all compromised credentials
- [ ] Identify what data was accessed by attackers
- [ ] Notify affected users per GDPR/CCPA requirements
- [ ] Implement WAF rules to prevent SQL injection
- [ ] Remove sensitive data from error messages

### LONG-TERM (1-30 days)
- [ ] Implement secrets management system
- [ ] Add HSTS, CSP, and security headers
- [ ] Enable encryption at rest and in transit
- [ ] Implement access controls and authentication
- [ ] Conduct security awareness training

## Legal & Compliance Notes

**GDPR Impact**:
- Article 33: Breach notification (72-hour requirement)
- Article 34: User notification (if high risk)
- Article 32: Security measures inadequate

**Next Steps**:
- Notify supervisory authority (DPA)
- Notify affected individuals
- Document breach response
- File incident report

---
```

---

## Implementation in HackerOne Agent

### Phase 1: Initialize Tracking

At testing start:

```python
import json
from datetime import datetime

def initialize_sensitive_data_tracking(program_name, asset_identifier):
    """Initialize sensitive data metadata"""

    metadata = {
        "program": program_name,
        "asset_identifier": asset_identifier,
        "testing_date_start": datetime.now().isoformat() + "Z",
        "testing_date_end": None,
        "tester": "Pentester Agent",
        "sensitive_data_categories": {
            "credentials": [],
            "api_keys_and_tokens": [],
            "private_data": [],
            "configuration_data": [],
            "user_pii": [],
            "other_sensitive": []
        },
        "summary": {
            "total_items_discovered": 0,
            "by_category": {},
            "by_severity": {}
        }
    }

    return metadata
```

### Phase 2: Track Discoveries

When sensitive data is found:

```python
def log_sensitive_data(metadata, category, data_item, finding_id,
                       location, severity, impact):
    """Log discovered sensitive data"""

    item = {
        "category": category,
        "location": location,
        "finding_id": finding_id,
        "discovered_date": datetime.now().isoformat() + "Z",
        "data": data_item,
        "severity": severity,
        "impact_assessment": impact,
        "status": "discovered"
    }

    # Add to appropriate category
    metadata["sensitive_data_categories"][category].append(item)

    # Update summary
    metadata["summary"]["total_items_discovered"] += 1

    # Save immediately
    save_metadata(metadata)
```

### Phase 3: Generate Report

Upon completion:

```python
def generate_sensitive_data_report(metadata, output_path):
    """Generate sensitive data analysis report"""

    # Save JSON metadata
    with open(f"{output_path}/sensitive_data_metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2)

    # Generate markdown report
    report = generate_markdown_report(metadata)

    with open(f"{output_path}/sensitive_data_report.md", 'w') as f:
        f.write(report)

    print(f"[+] Sensitive data report generated: {output_path}")
```

---

## Data Redaction Policies

### Redaction Rules

All sensitive data should be redacted in reports using these rules:

```json
{
  "redaction_rules": {
    "passwords": "[REDACTED]",
    "api_keys": "****...last_4_chars",
    "tokens": "[REDACTED]",
    "private_keys": "[REDACTED]",
    "credit_cards": "****-****-****-last_4",
    "ssn": "***-**-last_4",
    "phone": "[REDACTED]",
    "email": "[REDACTED]"
  }
}
```

### When to Redact

**Always Redact**:
- Actual passwords
- Full API keys
- Private keys
- Credit card numbers
- Full SSNs
- Full phone numbers

**Safe to Show**:
- Key ID / fingerprint
- Last 4 characters of secrets
- Key type and algorithm
- Issue/expiration dates
- Key scope/permissions
- Account type/privileges

---

## Quality Checklist

Before submitting HackerOne report, verify:

- [ ] `sensitive_data_metadata.json` generated
- [ ] All sensitive data items categorized
- [ ] Evidence files referenced for each item
- [ ] Impact assessment completed for each item
- [ ] Remediation guidance provided
- [ ] Data properly redacted in reports
- [ ] Timestamps captured for all discoveries
- [ ] Severity levels assigned correctly
- [ ] GDPR/privacy compliance noted
- [ ] User notification requirements identified

---

## Privacy & Legal Notes

**Important**:
- Only collect data necessary to demonstrate vulnerability impact
- Minimize PII exposure in reports
- Follow responsible disclosure practices
- Notify program of sensitive data found
- Comply with privacy regulations (GDPR, CCPA, etc.)
- Secure all sensitive data during testing and storage

---

## References

- OWASP: https://owasp.org/
- GDPR: https://gdpr-info.eu/
- CCPA: https://oag.ca.gov/privacy/ccpa
- Responsible Disclosure: https://www.bugcrowd.com/resource/the-basics-of-responsible-disclosure/

---
