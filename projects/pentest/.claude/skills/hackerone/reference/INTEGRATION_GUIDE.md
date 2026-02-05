# Sensitive Data Metadata Integration Guide

This guide explains how to integrate sensitive data tracking into HackerOne testing workflows.

## Quick Start

### 1. Initialize Tracker

```python
from tools.sensitive_data_tracker import SensitiveDataTracker

# At the start of testing
tracker = SensitiveDataTracker(
    program_name="ACME Corp Bug Bounty",
    asset_identifier="https://api.example.com",
    output_dir="outputs/acme_corp/api.example.com"
)
```

### 2. Log Discoveries

```python
# When credentials are found
tracker.add_credentials(
    username="admin",
    password_hash="$2y$10$abc123...",
    account_type="admin",
    location="SQL injection in /search endpoint",
    finding_id="finding-001",
    hash_algorithm="bcrypt",
    evidence={
        "poc_script": "findings/finding-001/poc.py",
        "screenshot": "evidence/screenshots/finding-001-admin-panel.png"
    }
)

# When API key is found
tracker.add_api_key(
    key_id="sk_live_abc123xyz",
    key_preview="sk_live_****...xyz",
    scope=["read:users", "write:data", "admin"],
    location="Hardcoded in React app.js",
    finding_id="finding-003",
    token_type="Stripe API Key"
)

# When private key is found
tracker.add_private_key(
    key_type="RSA",
    key_length=2048,
    purpose="AWS EC2 key pair for production",
    location=".git/config in repository",
    finding_id="finding-005",
    systems_accessible=["prod-api", "prod-db", "prod-cache"]
)

# When database credentials found
tracker.add_database_credentials(
    database_type="PostgreSQL",
    host="db.internal.company.com",
    port=5432,
    database_name="production_users",
    location="Config file accessible via path traversal",
    finding_id="finding-002",
    records_affected=2547,
    evidence={
        "poc_script": "findings/finding-002/poc.py",
        "data_sample": "evidence/http-captures/finding-002-db-dump.txt"
    }
)

# When PII is accessed
tracker.add_user_pii(
    pii_types=["email", "phone", "home_address", "dob"],
    records_affected=2547,
    location="Database accessible via SQL injection",
    finding_id="finding-001",
    affected_jurisdictions=["EU", "California"],
    evidence={
        "sample_record": "evidence/screenshots/finding-001-pii-sample.png",
        "count_proof": "evidence/http-captures/finding-001-record-count.txt"
    }
)
```

### 3. Finalize & Export

```python
# At end of testing
tracker.finalize()

# Generate markdown report
report_path = tracker.export_summary()
print(f"Report saved to: {report_path}")

# JSON metadata automatically saved to:
# outputs/<program>/<asset>/sensitive_data_metadata.json
```

---

## Integration Points

### In HackerOne Hunter Agent

```python
# Phase 1: Initialize
tracker = SensitiveDataTracker(
    program_name=program_name,
    asset_identifier=asset["identifier"],
    output_dir=f"outputs/{program_handle}/{asset['identifier']}"
)

# Phase 2: During testing
# When Pentester agents discover sensitive data, they report back
# findings that include sensitive data indicators

def process_finding(finding_data, tracker):
    """Process finding and extract sensitive data indicators"""

    # Check for credentials in finding
    if "credentials_found" in finding_data:
        for cred in finding_data["credentials_found"]:
            tracker.add_credentials(
                username=cred["username"],
                password_hash=cred["password_hash"],
                account_type=cred["type"],
                location=cred["location"],
                finding_id=finding_data["finding_id"]
            )

    # Check for API keys
    if "api_keys_found" in finding_data:
        for key in finding_data["api_keys_found"]:
            tracker.add_api_key(
                key_id=key["key_id"],
                key_preview=key["preview"],
                scope=key["scope"],
                location=key["location"],
                finding_id=finding_data["finding_id"],
                token_type=key["type"]
            )

    # ... handle other sensitive data types

# Phase 3: Finalize
tracker.finalize()
tracker.export_summary()
```

### In Pentester Agent

When Pentester deploys specialized agents, collect sensitive data indicators:

```python
def collect_sensitive_data_indicators(finding):
    """Extract sensitive data from vulnerability finding"""

    indicators = {
        "credentials_found": [],
        "api_keys_found": [],
        "private_keys_found": [],
        "database_credentials": [],
        "user_pii_accessed": [],
        "config_data_exposed": []
    }

    # Check PoC output for credentials
    with open(finding["poc_output.txt"]) as f:
        poc_output = f.read()

    # Regex patterns for detection
    if re.search(r"username[:\s]+\w+", poc_output):
        indicators["credentials_found"].append({
            "detected_in": "poc_output",
            "type": "username"
        })

    # Check for API key patterns
    if re.search(r"(sk_live|pk_test|Bearer|Authorization)", poc_output):
        indicators["api_keys_found"].append({
            "detected_in": "poc_output",
            "type": "api_key"
        })

    # Check for private key patterns
    if re.search(r"-----BEGIN.*PRIVATE KEY-----", poc_output):
        indicators["private_keys_found"].append({
            "detected_in": "poc_output",
            "type": "private_key"
        })

    return indicators
```

---

## Sensitive Data Detection Patterns

### Credentials
```python
CREDENTIAL_PATTERNS = [
    r"username[:\s]+(['\"]?)(\w+)\1",
    r"password[:\s]+(['\"]?)(.+?)\1",
    r"user[:\s]+(['\"]?)(\w+)\1",
    r"pass[:\s]+(['\"]?)(.+?)\1",
    r"admin[:\s]+(['\"]?)(\w+)\1"
]
```

### API Keys
```python
API_KEY_PATTERNS = [
    r"(sk_live|sk_test)_[A-Za-z0-9]{20,}",
    r"(pk_live|pk_test)_[A-Za-z0-9]{20,}",
    r"Bearer\s+[A-Za-z0-9._\-]+",
    r"Authorization[:\s]+Bearer\s+\S+",
    r"api[_-]?key[:\s]+(['\"]?)([A-Za-z0-9_\-]+)\1"
]
```

### Private Keys
```python
PRIVATE_KEY_PATTERNS = [
    r"-----BEGIN\s+(?:RSA\s+)?PRIVATE KEY-----",
    r"-----BEGIN\s+EC\s+PRIVATE KEY-----",
    r"-----BEGIN\s+OPENSSH PRIVATE KEY-----",
    r"-----BEGIN\s+PGP PRIVATE KEY BLOCK-----"
]
```

### Database Credentials
```python
DB_CREDENTIAL_PATTERNS = [
    r"(mongodb|postgres|mysql|mssql)://([^:]+):([^@]+)@",
    r"db[_-]?(user|pass)[:\s]+(['\"]?)(.+?)\2",
    r"database[_-]?(url|connection)[:\s]+(['\"]?)(.+?)\3",
    r"jdbc:.*://(.*):(.*)@"
]
```

### PII
```python
PII_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone": r"\+?1?\s*\(?(\d{3})\)?[\s.-]?(\d{3})[\s.-]?(\d{4})",
    "ssn": r"\d{3}-\d{2}-\d{4}",
    "credit_card": r"\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"
}
```

---

## Output Examples

### sensitive_data_metadata.json

```json
{
  "program": "ACME Corp",
  "asset_identifier": "https://api.example.com",
  "testing_date_start": "2025-01-16T10:00:00Z",
  "testing_date_end": "2025-01-16T14:30:00Z",
  "sensitive_data_categories": {
    "credentials": [
      {
        "type": "username_password",
        "location": "SQL injection in /search",
        "finding_id": "finding-001",
        "discovered_date": "2025-01-16T10:35:00Z",
        "severity": "CRITICAL",
        "status": "discovered"
      }
    ],
    "api_keys_and_tokens": [
      {
        "type": "api_key",
        "location": "Hardcoded in React app",
        "finding_id": "finding-003",
        "severity": "HIGH",
        "status": "discovered"
      }
    ]
  },
  "summary": {
    "total_items_discovered": 12,
    "by_category": {
      "credentials": 1,
      "api_keys_and_tokens": 2,
      "private_data": 1,
      "configuration_data": 2,
      "user_pii": 1,
      "other_sensitive": 5
    },
    "by_severity": {
      "CRITICAL": 4,
      "HIGH": 5,
      "MEDIUM": 3,
      "LOW": 0,
      "INFO": 0
    },
    "highest_risk_finding": "finding-001"
  }
}
```

### sensitive_data_report.md

```markdown
# Sensitive Data Discovery Report

**Program**: ACME Corp
**Asset**: https://api.example.com
**Testing Period**: 2025-01-16 10:00 AM - 2:30 PM UTC
**Total Items Discovered**: 12

## Summary by Severity

### CRITICAL (4 items)
- 1x Admin credentials (SQL injection)
- 1x Database connection string (Path traversal)
- 1x SSH private key (.git exposure)
- 2547 user records with PII (Database access)

### HIGH (5 items)
- 2x API keys (JavaScript hardcoding)
- 1x OAuth tokens (localStorage)
- 2x Service account credentials

### MEDIUM (3 items)
- 3x Internal IP addresses (Error messages)

## Immediate Actions Required

- [ ] Rotate all discovered credentials
- [ ] Revoke API keys and tokens
- [ ] Disable SSH private key
- [ ] Change database credentials
- [ ] Lock affected user accounts
- [ ] Notify 2547 affected users per GDPR
- [ ] Audit access logs for each credential

## Remediation Timeline

**0-1 hour**: Emergency credential revocation
**1-24 hours**: Access audit and user notification
**1-7 days**: Implementation of security fixes
**30+ days**: Long-term architectural improvements
```

---

## Privacy & Data Handling

### Redaction Rules

All sensitive data should be redacted in reports using these rules:

```python
REDACTION_RULES = {
    "passwords": "[REDACTED]",
    "api_keys": "****...last_4_chars",
    "tokens": "[REDACTED]",
    "private_keys": "[REDACTED]",
    "credit_cards": "****-****-****-last_4",
    "ssn": "***-**-last_4",
    "phone": "[REDACTED]",
    "email": "[REDACTED]",
    "ip_address": "redacted",
    "database_host": "[REDACTED]"
}
```

### Legal Compliance

**GDPR Requirements**:
- Document what personal data was accessed
- Notify supervisory authority within 72 hours if high risk
- Notify individuals if their data was breached
- File incident report with national DPA

**CCPA Requirements**:
- Document what California residents' data was accessed
- Provide individuals with right to access/delete
- File breach notification if personal information involved

**General Best Practices**:
- Minimize PII exposure in reports
- Secure all sensitive data during testing
- Use secure channels for sensitive communications
- Implement least-privilege access
- Follow responsible disclosure timeline

---

## Validation Checklist

Before submitting to HackerOne, verify:

- [ ] `sensitive_data_metadata.json` generated
- [ ] All discovered sensitive data items documented
- [ ] Each item has `discovered_date` timestamp
- [ ] Evidence references link to PoC/screenshots
- [ ] Impact assessment completed
- [ ] Severity levels assigned correctly
- [ ] Remediation guidance provided
- [ ] Data properly redacted in markdown reports
- [ ] GDPR/CCPA implications noted if PII found
- [ ] Highest risk findings identified
- [ ] `sensitive_data_report.md` generated

---

## Troubleshooting

### Q: Sensitive data not being tracked
A: Ensure tracker is initialized at start of testing and discoveries are logged immediately when found

### Q: JSON metadata incomplete
A: Check that `tracker.finalize()` is called at end of testing before exporting

### Q: Report not generated
A: Run `tracker.export_summary()` after finalize, verify output directory exists

### Q: Unsure what data to track
A: Reference SENSITIVE_DATA_METADATA.md for all 6 categories and examples

---

## References

- `.claude/skills/hackerone/reference/SENSITIVE_DATA_METADATA.md` - Complete standards
- `.claude/skills/hackerone/tools/sensitive_data_tracker.py` - Implementation tool
- GDPR: https://gdpr-info.eu/
- CCPA: https://oag.ca.gov/privacy/ccpa
- HackerOne: https://www.hackerone.com/

---
