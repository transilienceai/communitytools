# HackerOne Skill Reference Documentation

Comprehensive reference materials for HackerOne bug bounty hunting automation.

## Quick Navigation

### Core Documentation

**SKILL.md** - Main skill definition
- Program selection criteria
- CSV parsing format
- Agent deployment
- PoC validation
- Report generation

**CLAUDE.md** - Auto-loaded context
- Workflows and methodology
- Output formats
- CSV specifications
- Report quality standards

### Reference Guides

#### 1. **SENSITIVE_DATA_METADATA.md** ← NEW
Comprehensive guide for tracking sensitive data discovered during testing

**What it covers**:
- Why sensitive data tracking matters
- Directory structure with JSON files
- Complete JSON schema documentation
- 6 data categories with examples
- Per-finding metadata structure
- Summary report templates
- Implementation guidance
- Data redaction policies
- Privacy & legal compliance
- Quality checklist

**When to use**: Understanding sensitive data tracking requirements

**Size**: ~16 KB - Complete reference

---

#### 2. **INTEGRATION_GUIDE.md** ← NEW
Practical guide for integrating sensitive data tracking into workflows

**What it covers**:
- Quick start (3-step process)
- Integration points in HackerOne Hunter Agent
- Integration points in Pentester Agent
- Sensitive data detection patterns (regex)
- Complete output examples
- Privacy & data handling
- Validation checklist
- Troubleshooting

**When to use**: Implementing sensitive data tracking

**Size**: ~15 KB - Implementation reference

---

### Sensitive Data Types

The system tracks 6 categories of sensitive data:

1. **Credentials** - Usernames, passwords, hashes
2. **API Keys & Tokens** - Bearer tokens, API keys, OAuth tokens
3. **Private Data** - Private keys, certificates, SSH keys
4. **Configuration Data** - Database connection strings, config files
5. **User PII** - Email, phone, address, SSN, date of birth
6. **Other Sensitive** - Internal IPs, architecture info, etc.

---

## File Structure

```
.claude/skills/hackerone/
├── SKILL.md                          # Main skill definition
├── README.md                         # User documentation
├── CLAUDE.md                         # Auto-loaded context (updated)
│
├── reference/
│   ├── README.md                     # This file
│   ├── SENSITIVE_DATA_METADATA.md    # NEW: Sensitive data standards
│   └── INTEGRATION_GUIDE.md          # NEW: Implementation guide
│
├── tools/
│   ├── csv_parser.py                 # Parse HackerOne CSV files
│   ├── report_validator.py           # Validate report quality
│   └── sensitive_data_tracker.py     # NEW: Track sensitive data
│
└── outputs/
    └── .gitkeep
```

---

## Key Features

### Sensitive Data Tracking (NEW)

✓ **Structured JSON metadata** - Machine-readable inventory of all sensitive data
✓ **Per-finding tracking** - Know what sensitive data led to each vulnerability
✓ **Asset-level inventory** - Complete picture of sensitive exposure
✓ **Markdown reports** - Executive summaries and remediation guidance
✓ **Evidence linking** - Track proof of each discovery (PoC, screenshot, etc.)
✓ **Impact assessment** - Business impact analysis for each item
✓ **Severity tracking** - CRITICAL to INFO categorization
✓ **Legal compliance** - GDPR/CCPA implications documented
✓ **Remediation guidance** - Immediate, short-term, and long-term fixes

---

## Quick Start

### 1. Initialize Tracker

```python
from tools.sensitive_data_tracker import SensitiveDataTracker

tracker = SensitiveDataTracker(
    program_name="ACME Corp",
    asset_identifier="https://api.example.com",
    output_dir="outputs/acme/api"
)
```

### 2. Log Discoveries

```python
# When credentials found
tracker.add_credentials(
    username="admin",
    password_hash="$2y$10$...",
    account_type="admin",
    location="SQL injection in /search",
    finding_id="finding-001"
)

# When API key found
tracker.add_api_key(
    key_id="sk_live_...",
    key_preview="sk_live_****...1234",
    scope=["read:users", "write:data"],
    location="Hardcoded in app.js",
    finding_id="finding-003"
)

# ... other sensitive data types
```

### 3. Finalize & Export

```python
tracker.finalize()
tracker.export_summary()

# Generates:
# - outputs/acme/api/sensitive_data_metadata.json
# - outputs/acme/api/sensitive_data_report.md
```

---

## Output Files Generated

### 1. sensitive_data_metadata.json
Machine-readable inventory with complete details:
- All sensitive data items discovered
- Discovery date/time with timestamps
- Location where found
- Associated finding ID
- Evidence file references
- Impact assessment (severity, affected systems)
- Remediation guidance
- Current status

### 2. sensitive_data_report.md
Executive summary in markdown:
- Program and asset information
- Testing period
- Summary by severity and category
- List of immediate actions required
- Remediation timeline
- Legal/compliance implications

### 3. Per-Finding sensitive_data.json (optional)
Focused metadata per vulnerability:
- Finding ID and title
- Sensitive data categories found
- Count by type
- Evidence file references

---

## Data Categories

### 1. Credentials
```json
{
  "type": "username_password",
  "location": "SQL injection in search parameter",
  "data": {
    "username": "[REDACTED]",
    "password_hash": "$2y$10$...",
    "account_type": "admin"
  },
  "severity": "CRITICAL"
}
```

### 2. API Keys & Tokens
```json
{
  "type": "api_key",
  "location": "Hardcoded in JavaScript",
  "data": {
    "key_id": "[REDACTED]",
    "key_preview": "sk_live_****...1234",
    "scope": ["read:users", "write:data"],
    "expiration": "2025-12-01"
  },
  "severity": "HIGH"
}
```

### 3. Private Keys
```json
{
  "type": "private_key",
  "location": "Exposed in .git directory",
  "data": {
    "key_type": "RSA",
    "key_length": 2048,
    "purpose": "SSH production access"
  },
  "severity": "CRITICAL"
}
```

### 4. Configuration Data
```json
{
  "type": "database_credentials",
  "location": "Environment variables via YAML parsing",
  "data": {
    "database_type": "PostgreSQL",
    "host": "[REDACTED]",
    "records_accessible": 2547000
  },
  "severity": "CRITICAL"
}
```

### 5. User PII
```json
{
  "type": "personal_information",
  "location": "Database via SQL injection",
  "data": {
    "pii_types": ["email", "phone", "address", "dob"],
    "records_affected": 2547,
    "affected_jurisdictions": ["EU", "California"]
  },
  "severity": "CRITICAL"
}
```

### 6. Other Sensitive
```json
{
  "type": "internal_ip_addresses",
  "location": "Exposed in error messages",
  "data": {
    "items": ["192.168.1.10", "10.0.0.5"],
    "description": "Internal network infrastructure"
  },
  "severity": "MEDIUM"
}
```

---

## Privacy & Compliance

### Data Redaction

All reports properly redact sensitive information:
- Actual passwords → `[REDACTED]`
- Full API keys → `****...last_4_chars`
- Full private keys → `[REDACTED]`
- Exact emails → `[REDACTED]`
- Exact phone numbers → `[REDACTED]`

### Legal Compliance

**GDPR Requirements**:
- [ ] Document personal data accessed
- [ ] Notify supervisory authority within 72 hours
- [ ] Notify individuals if data was breached
- [ ] Implement security measures

**CCPA Requirements**:
- [ ] Document California resident data accessed
- [ ] Provide individuals right to access/delete
- [ ] File breach notification if applicable

---

## Integration Points

### In HackerOne Hunter Agent
- Initialize tracker at asset testing start
- Update tracker as each finding is discovered
- Finalize and export at completion

### In Pentester Agent
- Detect sensitive data indicators in PoC output
- Report findings back to HackerOne Hunter
- Include evidence file references

### In Specialized Vulnerability Agents
- Log any credentials/keys found during exploitation
- Include in finding evidence
- Report to parent agent for metadata tracking

---

## Tools & Utilities

### tools/sensitive_data_tracker.py
Python class for tracking sensitive data:

```python
tracker = SensitiveDataTracker(program, asset, output_dir)

# Add methods for each data type:
tracker.add_credentials(...)
tracker.add_api_key(...)
tracker.add_private_key(...)
tracker.add_database_credentials(...)
tracker.add_user_pii(...)
tracker.add_configuration_data(...)
tracker.add_other_sensitive_data(...)

# Finalize and export:
tracker.finalize()
tracker.export_summary()
```

---

## Validation Checklist

Before submitting to HackerOne:

- [ ] `sensitive_data_metadata.json` generated
- [ ] `sensitive_data_report.md` generated
- [ ] All discovered items documented with timestamps
- [ ] Evidence files referenced for each item
- [ ] Impact assessments completed
- [ ] Severity levels assigned correctly
- [ ] Data properly redacted in markdown reports
- [ ] GDPR/CCPA implications noted if PII found
- [ ] Highest risk findings clearly identified
- [ ] Remediation timeline provided

---

## Example Outputs

### Console Output During Testing
```
[+] Logged credentials/username_password (severity: CRITICAL)
[+] Logged api_keys_and_tokens/api_key (severity: HIGH)
[+] Logged private_data/private_key (severity: CRITICAL)
[+] Logged configuration_data/database_credentials (severity: CRITICAL)
[+] Logged user_pii/personal_information (severity: CRITICAL)
[+] Logged other_sensitive/internal_ip_addresses (severity: MEDIUM)

[+] Report saved to: outputs/acme/api/sensitive_data_report.md
[+] Metadata saved to: outputs/acme/api/sensitive_data_metadata.json
```

### JSON Output (sensitive_data_metadata.json)
Complete structured inventory of all sensitive data with full details, timestamps, evidence references, and impact assessments.

### Markdown Output (sensitive_data_report.md)
Executive summary with immediate action items, remediation timeline, and legal/compliance implications.

---

## Common Questions

**Q: What sensitive data should I track?**
A: See SENSITIVE_DATA_METADATA.md for all 6 categories and examples

**Q: How do I integrate this into my testing?**
A: See INTEGRATION_GUIDE.md for step-by-step implementation

**Q: What about privacy?**
A: All sensitive data is redacted in reports. See SENSITIVE_DATA_METADATA.md for redaction rules

**Q: Is this GDPR compliant?**
A: Yes, with proper implementation. See SENSITIVE_DATA_METADATA.md legal section

**Q: Can I customize the tool?**
A: Yes, tools/sensitive_data_tracker.py is fully customizable Python code

---

## References

- **SENSITIVE_DATA_METADATA.md** - Complete standards and examples
- **INTEGRATION_GUIDE.md** - Implementation details and code examples
- **tools/sensitive_data_tracker.py** - Python implementation
- **CLAUDE.md** - Auto-loaded context (updated with new features)
- GDPR: https://gdpr-info.eu/
- CCPA: https://oag.ca.gov/privacy/ccpa

---

**Status**: Ready for use
**Version**: 1.0
**Created**: 2025-01-16
