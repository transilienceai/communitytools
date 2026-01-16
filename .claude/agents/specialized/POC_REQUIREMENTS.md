# PoC Verification Requirements for Specialized Agents

**CRITICAL**: All specialized security testing agents MUST follow these PoC verification requirements.

## Overview

A vulnerability is **NOT VERIFIED** and **MUST NOT BE REPORTED** unless it has a working, tested Proof-of-Concept (PoC) script that successfully demonstrates exploitation.

## Mandatory PoC Components

For each discovered vulnerability, create `findings/finding-NNN/` folder containing:

### 1. poc.py (or poc.sh)

**Requirements**:
- Self-contained, executable script
- Clear command-line interface with argparse
- Proper error handling and informative output
- Comments explaining each exploitation step
- Returns exit code 0 on success, 1 on failure

**Template**:
```python
#!/usr/bin/env python3
"""
PoC for [VULNERABILITY_NAME]
Vulnerability ID: finding-NNN
Target: [TARGET_URL_OR_SYSTEM]
Vulnerability Type: [SQLi/XSS/SSRF/XXE/SSTI/etc.]
Severity: CVSS [SCORE] ([CRITICAL/HIGH/MEDIUM/LOW])
Author: [AGENT_NAME]
Date: [TIMESTAMP]
"""

import requests
import sys
import argparse
from datetime import datetime

def banner():
    """Display banner with vulnerability information"""
    print("="*60)
    print("PoC for [VULNERABILITY_NAME]")
    print("="*60)
    print(f"Vulnerability Type: [TYPE]")
    print(f"Severity: [CVSS_SCORE]")
    print(f"Testing started: {datetime.now().isoformat()}")
    print("="*60)

def exploit(target, **kwargs):
    """
    Execute the exploit against the target

    Args:
        target: Target URL or system identifier
        **kwargs: Additional parameters (param_name, custom payloads, etc.)

    Returns:
        dict: Exploitation results with success status and evidence
    """
    print(f"\n[*] Target: {target}")
    print(f"[*] Starting exploitation...")

    # Step 1: [DESCRIBE STEP]
    print("\n[*] Step 1: [DESCRIPTION]")
    # Implementation here

    # Step 2: [DESCRIBE STEP]
    print("[*] Step 2: [DESCRIPTION]")
    # Implementation here

    # Step 3: Verify exploitation
    print("[*] Step 3: Verifying exploitation...")
    # Verification logic here

    # Check for success
    if success_condition:
        print("\n[+] SUCCESS! Vulnerability confirmed and exploited")
        print(f"[+] Evidence: {evidence_data}")
        return {
            "success": True,
            "evidence": evidence_data,
            "extracted_data": extracted_data,
            "timestamp": datetime.now().isoformat()
        }
    else:
        print("\n[-] FAILED: Exploitation unsuccessful")
        return {
            "success": False,
            "error": "Description of failure",
            "timestamp": datetime.now().isoformat()
        }

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description='PoC for [VULNERABILITY_NAME]',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example Usage:
  python3 poc.py --target https://target.com --param search
  python3 poc.py --target https://target.com --verbose
        '''
    )

    parser.add_argument('--target', required=True,
                       help='Target URL or system')
    parser.add_argument('--param',
                       help='Vulnerable parameter name')
    parser.add_argument('--payload',
                       help='Custom payload (optional)')
    parser.add_argument('--verbose', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    banner()

    # Execute exploitation
    result = exploit(
        target=args.target,
        param=args.param,
        payload=args.payload,
        verbose=args.verbose
    )

    # Print summary
    print("\n" + "="*60)
    print("EXPLOITATION SUMMARY")
    print("="*60)
    print(f"Success: {result['success']}")
    if result['success']:
        print(f"Evidence: {result['evidence']}")
        print("\n[+] Vulnerability VERIFIED and exploitable")
    else:
        print(f"Error: {result.get('error', 'Unknown')}")
        print("\n[-] Vulnerability NOT verified")
    print("="*60)

    # Exit with appropriate code
    sys.exit(0 if result['success'] else 1)

if __name__ == "__main__":
    main()
```

### 2. poc_output.txt

**Requirements**:
- Complete terminal output from PoC execution
- Timestamp showing when test was performed
- Clear evidence of successful exploitation
- Any extracted data or proof of access

**Format**:
```
================================================================
PoC Execution Output
================================================================
Timestamp: 2025-01-16T10:30:45Z
Target: https://target.com
Command: python3 poc.py --target https://target.com --param search
================================================================

[*] Target: https://target.com
[*] Starting exploitation...

[*] Step 1: Testing for vulnerability...
[+] Vulnerability indicator detected

[*] Step 2: Crafting exploit payload...
[+] Payload: ' UNION SELECT username,password FROM users--

[*] Step 3: Executing exploit...
[+] Response received: 200 OK

[*] Step 4: Verifying exploitation...
[+] SUCCESS! Data extracted

[+] Extracted data:
    - username: admin
    - password_hash: $2y$10$abc123...
    - username: user1
    - password_hash: $2y$10$def456...

================================================================
EXPLOITATION SUMMARY
================================================================
Success: True
Evidence: Successfully extracted 2 user records
Vulnerability VERIFIED and exploitable
================================================================
```

### 3. workflow.md

**Requirements**:
- Step-by-step manual exploitation process
- Each step with clear explanation
- Expected output at each step
- Troubleshooting tips

**Template**:
```markdown
# Exploitation Workflow: [VULNERABILITY_NAME]

## Overview
Brief description of the vulnerability and what will be achieved.

## Prerequisites
- Tools required: Burp Suite, curl, Python 3, etc.
- Access level: Authenticated/Unauthenticated
- Target information needed

## Manual Exploitation Steps

### Step 1: [First Step Name]
**Objective**: What this step achieves

**Action**:
- Detailed instructions
- Commands to run
- Parameters to modify

**Expected Output**:
```
Show what you should see
```

**Verification**: How to confirm this step worked

---

### Step 2: [Second Step Name]
**Objective**: What this step achieves

**Action**:
[Instructions]

**Expected Output**:
```
[Output]
```

**Verification**: [How to verify]

---

[Continue for all steps]

## Troubleshooting

### Issue 1: [Common Problem]
**Symptoms**: What you see when this happens
**Solution**: How to fix it

### Issue 2: [Another Problem]
**Symptoms**: [Description]
**Solution**: [Fix]

## Verification
How to confirm the vulnerability was successfully exploited:
- [ ] Indicator 1
- [ ] Indicator 2
- [ ] Indicator 3

## Cleanup
Steps to remove any artifacts left by testing (if applicable)
```

### 4. description.md

**Requirements**:
- Clear explanation of the attack
- Technical details of the vulnerability
- Root cause analysis
- Impact scenarios

**Template**:
```markdown
# Vulnerability Description: [VULNERABILITY_NAME]

## Attack Overview
High-level explanation of what this attack does and why it's dangerous.

## Technical Details

### Vulnerability Type
[SQLi/XSS/SSRF/XXE/SSTI/RCE/etc.]

### Root Cause
Detailed explanation of why this vulnerability exists in the target:
- Code-level issues
- Configuration problems
- Missing security controls
- Architecture weaknesses

### Exploitation Mechanism
How the attack works technically:
1. First, the attacker [action]
2. This causes [system behavior]
3. Which allows [access/extraction/manipulation]
4. Resulting in [impact]

### Attack Vector
- Entry point: [Location where attacker injects payload]
- Payload: [What is injected]
- Execution context: [Where/how payload executes]
- Result: [What attacker gains]

## Real-World Impact Scenarios

### Scenario 1: [Impact Description]
Detailed example of how this could be exploited in practice

### Scenario 2: [Impact Description]
Another realistic attack scenario

## Affected Components
- Component 1: [How it's affected]
- Component 2: [How it's affected]

## Defense Evasion Techniques (if applicable)
Techniques used to bypass security controls:
- WAF bypass: [Method]
- Input validation bypass: [Method]
- Encoding techniques: [Method]

## References
- [OWASP Article]
- [CWE Definition]
- [Research Papers]
- [Similar CVEs]
```

### 5. report.md

**Requirements**:
- Comprehensive vulnerability report
- CVSS scoring and risk analysis
- Business impact assessment
- Remediation guidance

**Template**:
```markdown
# Vulnerability Report: [TITLE]

## Executive Summary
2-3 sentence summary suitable for non-technical stakeholders.

## Vulnerability Details

**ID**: finding-NNN
**Title**: [Vulnerability Title]
**Severity**: [CRITICAL/HIGH/MEDIUM/LOW]
**CVSS v3.1 Score**: [X.X]
**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
**CWE**: CWE-XXX - [CWE Name]
**OWASP**: [OWASP Category]

## Location
- **URL**: https://target.com/path
- **Parameter**: param_name
- **Method**: GET/POST
- **Component**: [Affected component]

## Proof of Concept

### Automated PoC
See `poc.py` for automated exploitation script.

**Execution**:
```bash
python3 poc.py --target https://target.com --param search
```

**Output**: See `poc_output.txt` for complete execution output.

### Manual Exploitation
See `workflow.md` for step-by-step manual exploitation guide.

### Evidence
- Screenshot 1: Initial vulnerability detection
- Screenshot 2: Payload execution
- Screenshot 3: Successful exploitation
- HTTP Request/Response: See evidence/requests/

## Technical Analysis
See `description.md` for complete technical analysis.

## Business Impact

### Confidentiality Impact
[HIGH/MEDIUM/LOW] - Description of data exposure risk

### Integrity Impact
[HIGH/MEDIUM/LOW] - Description of data modification risk

### Availability Impact
[HIGH/MEDIUM/LOW] - Description of service disruption risk

### Realistic Attack Scenarios
1. **Scenario 1**: [Description of potential attack]
2. **Scenario 2**: [Another potential attack]

### Financial Impact
- Estimated cost of breach
- Regulatory compliance implications
- Reputational damage potential

## Remediation

### Immediate Actions (0-24 hours)
1. [Critical immediate fix]
2. [Temporary mitigation]

### Short-Term Fixes (1-7 days)
1. [Code-level fix]
2. [Configuration change]

### Long-Term Solutions (30+ days)
1. [Architectural improvements]
2. [Security controls]
3. [Process changes]

### Code Example

**Vulnerable Code**:
```python
# Example of vulnerable code
```

**Fixed Code**:
```python
# Example of secure code
```

## Validation

**PoC Verification**:
- [x] PoC script developed (poc.py)
- [x] PoC tested successfully (poc_output.txt)
- [x] Manual workflow documented (workflow.md)
- [x] Technical description complete (description.md)
- [x] Evidence captured (screenshots, HTTP logs)

## References
- [Relevant documentation]
- [Security advisories]
- [Industry standards]
```

## PoC Development Workflow

### Phase 1: Discovery
1. Identify potential vulnerability through reconnaissance
2. Develop hypothesis about exploitability

### Phase 2: PoC Development
1. Write initial PoC script based on vulnerability type
2. Implement exploitation logic
3. Add error handling and output formatting

### Phase 3: Testing & Verification
1. Execute PoC against target
2. Capture complete terminal output
3. Verify exploitation was successful
4. Document evidence of success

### Phase 4: Iteration (if needed)
If PoC fails:
1. Analyze failure reason
2. Try alternative payloads/techniques
3. Refine PoC script
4. Re-test until working or conclude not exploitable

### Phase 5: Documentation
Once PoC succeeds:
1. Create finding folder: `findings/finding-NNN/`
2. Save PoC script: `poc.py`
3. Save execution output: `poc_output.txt`
4. Write manual workflow: `workflow.md`
5. Write technical description: `description.md`
6. Write comprehensive report: `report.md`

## Quality Checklist

Before reporting a vulnerability, verify:

- [ ] PoC script is self-contained and executable
- [ ] PoC includes proper argument parsing
- [ ] PoC has clear output messages
- [ ] PoC was tested and succeeded
- [ ] poc_output.txt captured with timestamp
- [ ] workflow.md provides manual steps
- [ ] description.md explains the attack
- [ ] report.md includes all required sections
- [ ] All evidence files captured
- [ ] CVSS score calculated correctly
- [ ] CWE and OWASP mappings accurate
- [ ] Remediation guidance is actionable

## Rejection Criteria

Do NOT report if:
- ❌ PoC script doesn't exist
- ❌ PoC wasn't tested (no poc_output.txt)
- ❌ PoC execution failed
- ❌ No evidence of successful exploitation
- ❌ Theoretical vulnerability without proof
- ❌ Missing required documentation files

## Examples by Vulnerability Type

### SQL Injection PoC Structure
```python
def exploit_sqli(target, param):
    # Step 1: Detect SQL injection
    # Step 2: Fingerprint database
    # Step 3: Extract data
    # Step 4: Verify extraction
    return results
```

### XSS PoC Structure
```python
def exploit_xss(target, param):
    # Step 1: Test reflection
    # Step 2: Bypass filters
    # Step 3: Execute JavaScript
    # Step 4: Demonstrate impact (cookie theft, etc.)
    return results
```

### SSRF PoC Structure
```python
def exploit_ssrf(target, param):
    # Step 1: Test outbound requests
    # Step 2: Target internal resources
    # Step 3: Extract sensitive data
    # Step 4: Verify access
    return results
```

## Additional Notes

- **Python 3 Required**: All PoCs should use Python 3.7+
- **Dependencies**: Use only standard library or document requirements.txt
- **Portable**: PoCs should work on Linux, macOS, and Windows
- **Safe**: No destructive actions, minimal data extraction
- **Ethical**: Respect authorization boundaries
