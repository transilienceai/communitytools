# PoC Methodology Reference

Detailed methodology for CVE research, PoC script generation, and vulnerability report writing.

## 1. Research Process

### NVD API v2.0 Query

Query the NVD REST API to retrieve CVE data:

```
GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXXX
```

**Fields to extract from response**:

| JSON Path | Field | Required |
|-----------|-------|----------|
| `vulnerabilities[0].cve.id` | CVE ID | Yes |
| `vulnerabilities[0].cve.descriptions[0].value` | Description | Yes |
| `vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore` | CVSS Score | Yes |
| `vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.vectorString` | CVSS Vector | Yes |
| `vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseSeverity` | Severity | Yes |
| `vulnerabilities[0].cve.weaknesses[0].description[0].value` | CWE ID | Yes |
| `vulnerabilities[0].cve.configurations[0].nodes[*].cpeMatch` | CPE Matches | Yes |
| `vulnerabilities[0].cve.references` | Advisory URLs | Yes |
| `vulnerabilities[0].cve.published` | Published Date | Yes |
| `vulnerabilities[0].cve.lastModified` | Last Modified | Yes |

**Fallback**: If CVSS v3.1 is unavailable, check `cvssMetricV31` then `cvssMetricV30` then `cvssMetricV2`. Note the version used in the report.

### Advisory Deep-Dive Procedure

After NVD lookup, research these sources in order:

1. **Vendor advisories** - Follow URLs from NVD references tagged `Vendor Advisory`
2. **GitHub Security Advisories** - Search `https://github.com/advisories?query=CVE-XXXX-XXXXX`
3. **Exploit-DB** - Search `https://www.exploit-db.com/search?cve=XXXX-XXXXX`
4. **Published write-ups** - Search for technical blog posts, conference presentations
5. **Patch commits** - Find the fix commit to understand the root cause

**For each source, extract**:
- Root cause (code-level explanation)
- Attack prerequisites (authentication, network position, configuration)
- Affected version ranges (exact version boundaries)
- Exploit complexity and reliability
- Public exploit availability

**CTF/HTB-specific**: When a CVE is recent (< 30 days old) and matches the challenge context, search GitHub for the CVE ID + challenge/machine creator usernames. Machine creators often publish reference exploits on their GitHub profiles. Also check the Qualys advisory text files at `https://cdn2.qualys.com/advisory/YYYY/MM/DD/` for detailed exploitation steps.

## 2. PoC Script Standards

### Safety Constraints

| Constraint | Requirement |
|------------|-------------|
| **No destruction** | Never delete, modify, or corrupt target data |
| **No persistence** | Never install backdoors, shells, or implants |
| **No lateral movement** | Never pivot to other systems |
| **No exfiltration** | Never send data to external servers |
| **Read-only default** | Default behavior must be non-destructive verification |
| **Confirm flag** | Any write/modify action requires explicit `--confirm` |
| **Timeout** | All network operations must have timeouts (default: 10s) |
| **Target only** | Only interact with the specified target |

### Python Script Template

```python
#!/usr/bin/env python3
"""
CVE-XXXX-XXXXX - [Short vulnerability title]

[One-line description of the vulnerability]

Author: Pentest Framework (auto-generated)
Date: YYYY-MM-DD
References:
    - https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX
    - [vendor advisory URL]
"""

import argparse
import sys
import requests

# Disable SSL warnings for testing (target may use self-signed certs)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10


def check_vulnerable(target: str, **kwargs) -> dict:
    """
    Check if the target is vulnerable to CVE-XXXX-XXXXX.

    Args:
        target: Base URL or host of the target system.

    Returns:
        dict with keys:
            - vulnerable (bool): Whether the target appears vulnerable.
            - details (str): Human-readable explanation.
            - evidence (dict): Supporting data (headers, responses, versions).
    """
    result = {
        "vulnerable": False,
        "details": "",
        "evidence": {}
    }

    try:
        # --- Vulnerability check logic here ---
        # 1. Fingerprint the target (version detection)
        # 2. Send benign probe to detect vulnerability
        # 3. Analyze response for vulnerability indicators
        pass

    except requests.exceptions.ConnectionError:
        result["details"] = "Connection failed - target unreachable"
    except requests.exceptions.Timeout:
        result["details"] = "Connection timed out"
    except Exception as e:
        result["details"] = f"Error during check: {e}"

    return result


def main():
    parser = argparse.ArgumentParser(
        description="CVE-XXXX-XXXXX - [Short title]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s https://target.example.com
    %(prog)s https://target.example.com --verbose
    %(prog)s https://target.example.com --confirm
        """
    )
    parser.add_argument("target", help="Target URL or host")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("--confirm", action="store_true",
                        help="Confirm potentially impactful actions")
    parser.add_argument("--timeout", type=int, default=TIMEOUT,
                        help=f"Request timeout in seconds (default: {TIMEOUT})")
    parser.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    args = parser.parse_args()

    global TIMEOUT
    TIMEOUT = args.timeout

    print(f"[*] CVE-XXXX-XXXXX PoC")
    print(f"[*] Target: {args.target}")
    print()

    result = check_vulnerable(args.target, verbose=args.verbose,
                               proxy=args.proxy, confirm=args.confirm)

    if result["vulnerable"]:
        print(f"[+] VULNERABLE - {result['details']}")
        if args.verbose and result["evidence"]:
            print(f"[+] Evidence:")
            for key, value in result["evidence"].items():
                print(f"    {key}: {value}")
        sys.exit(0)
    else:
        print(f"[-] NOT VULNERABLE - {result['details']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Target is vulnerable |
| `1` | Target is not vulnerable |
| `2` | Error during execution |

### Output Prefixes

| Prefix | Meaning |
|--------|---------|
| `[*]` | Informational message |
| `[+]` | Positive result (vulnerable, success) |
| `[-]` | Negative result (not vulnerable, failure) |
| `[!]` | Warning or important notice |

## 3. Report Template

The vulnerability report follows this markdown structure:

```markdown
# CVE-XXXX-XXXXX: [Vulnerability Title]

## Metadata

| Field | Value |
|-------|-------|
| **CVE ID** | CVE-XXXX-XXXXX |
| **CVSS v3.1 Score** | X.X (SEVERITY) |
| **CVSS Vector** | CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X |
| **CWE** | CWE-XXX: [CWE Name] |
| **Published** | YYYY-MM-DD |
| **Last Modified** | YYYY-MM-DD |
| **Affected Products** | [Product names and version ranges] |
| **Patch Available** | Yes/No - [link if available] |

## Description

[2-3 paragraph description of the vulnerability from NVD and advisories.
Include what the vulnerability is, how it can be exploited, and what
impact it has.]

## Root Cause Analysis

[Technical explanation of the underlying code flaw. Reference specific
code patterns, functions, or components. Cite the patch commit if available.]

### Vulnerable Code Pattern

[Code snippet or pseudocode showing the vulnerable pattern, if known from
advisories or patch diffs.]

### Fix

[Code snippet or description showing how the vulnerability was fixed,
if patch is available.]

## Attack Vector

**Prerequisites**:
- [Authentication required? What level?]
- [Network position required?]
- [Configuration required?]

**Attack Complexity**: [Low/High - explanation]

**User Interaction**: [None/Required - explanation]

## Affected Products

| Product | Vulnerable Versions | Fixed Version |
|---------|-------------------|---------------|
| [Name] | [Range] | [Version] |

## Proof of Concept

### Usage

    python3 poc.py <target-url> [options]

### Options

| Flag | Description |
|------|-------------|
| `--verbose` | Show detailed output |
| `--confirm` | Confirm impactful actions |
| `--timeout N` | Set request timeout (default: 10s) |
| `--proxy URL` | Route through HTTP proxy |

### Expected Output (Vulnerable)

    [*] CVE-XXXX-XXXXX PoC
    [*] Target: https://target.example.com

    [+] VULNERABLE - [description of finding]

### Expected Output (Not Vulnerable)

    [*] CVE-XXXX-XXXXX PoC
    [*] Target: https://target.example.com

    [-] NOT VULNERABLE - [reason]

## Risk Assessment

| Factor | Rating | Justification |
|--------|--------|---------------|
| **Exploitability** | Low/Medium/High | [explanation] |
| **Impact** | Low/Medium/High/Critical | [explanation] |
| **Public Exploit** | Yes/No | [source if yes] |
| **Active Exploitation** | Yes/No/Unknown | [source if yes] |
| **Patch Available** | Yes/No | [link if yes] |

## Remediation

### Immediate Actions

1. [First priority action]
2. [Second priority action]

### Long-Term Recommendations

1. [Strategic recommendation]
2. [Process improvement]

### Workarounds

[If no patch is available, describe temporary mitigations such as
WAF rules, configuration changes, or network segmentation.]

## References

1. [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX)
2. [Vendor Advisory](URL)
3. [Additional references]

## Timeline

| Date | Event |
|------|-------|
| YYYY-MM-DD | Vulnerability published |
| YYYY-MM-DD | Patch released |
| YYYY-MM-DD | PoC generated |
```

## 4. CWE-Specific PoC Patterns

Safe exploitation approaches organized by vulnerability category.

### CWE-89: SQL Injection

- **Detection**: Inject time-based payloads (`SLEEP()`, `pg_sleep()`) or boolean-based payloads that produce observable response differences
- **Safe approach**: Use time delays or conditional responses. Never `DROP`, `DELETE`, `UPDATE`, or extract sensitive data
- **Probe example**: `' OR SLEEP(5)-- -` and measure response time delta

### CWE-79: Cross-Site Scripting (XSS)

- **Detection**: Inject a unique canary string and check if it appears unescaped in the response
- **Safe approach**: Reflect a harmless marker (e.g., `<xss-test-RANDOM>`) rather than executing JavaScript
- **Probe example**: Submit `"><xss-canary-abc123>` and check raw response for unescaped output

### CWE-22: Path Traversal

- **Detection**: Request a known file (e.g., `/etc/passwd` on Linux, `win.ini` on Windows) via traversal sequences
- **Safe approach**: Read a non-sensitive, predictable file to confirm traversal. Never write files
- **Probe example**: `....//....//etc/passwd` and check for `root:` in response

### CWE-918: Server-Side Request Forgery (SSRF)

- **Detection**: Trigger a request to a controlled listener or a distinguishable internal endpoint
- **Safe approach**: Use a DNS-only callback or request a predictable internal resource. Never access cloud metadata unless explicitly authorized
- **Probe example**: Provide a URL pointing to a unique Burp Collaborator / webhook.site endpoint and check for callback

### CWE-502: Insecure Deserialization

- **Detection**: Send a crafted serialized object that triggers a measurable side effect (DNS lookup, time delay)
- **Safe approach**: Use `ysoserial` or equivalent for a DNS/sleep gadget chain. Never use command execution gadgets
- **Probe example**: Java `URLDNS` gadget chain pointing to a controlled DNS resolver

### CWE-287: Authentication Bypass

- **Detection**: Attempt to access authenticated resources without valid credentials or with manipulated tokens
- **Safe approach**: Verify access to a non-sensitive authenticated endpoint. Never modify user data or escalate privileges
- **Probe example**: Remove or modify JWT signature, change `role` claim, or skip authentication headers

### CWE-94: Code Injection

- **Detection**: Inject a payload that produces a calculable result (e.g., math expression) without side effects
- **Safe approach**: Use arithmetic canaries (`7*7` expecting `49`) or string concatenation probes
- **Probe example**: `${7*7}` in template context, check response for `49`

### CWE-400: Denial of Service (Resource Exhaustion)

- **Detection**: Send a single request designed to consume measurably more resources than normal
- **Safe approach**: Measure response time for a single amplified request vs. baseline. Never flood or repeat
- **Probe example**: Send a single regex bomb input or deeply nested JSON and compare response time to baseline

## 5. Quality Checklist

Verify each item before producing output:

### Research Quality
- [ ] CVE ID is valid and exists in NVD
- [ ] CVSS score and vector are copied exactly from NVD (not estimated)
- [ ] CWE ID is from NVD (not guessed from description)
- [ ] All CPE matches are listed with version ranges
- [ ] At least 2 advisory sources were consulted beyond NVD
- [ ] Root cause is supported by advisory or patch analysis

### PoC Quality
- [ ] Script runs standalone with only `requests` as external dependency
- [ ] `check_vulnerable()` function returns the standard result dict
- [ ] All network calls have timeout set
- [ ] No destructive operations without `--confirm`
- [ ] Exit codes follow the standard (0=vuln, 1=not vuln, 2=error)
- [ ] Output uses correct prefixes (`[*]`, `[+]`, `[-]`, `[!]`)
- [ ] Docstring includes CVE ID, description, and reference URLs
- [ ] argparse with help text and examples

### Report Quality
- [ ] Metadata table has all required fields
- [ ] Description cites NVD and advisory sources
- [ ] Root cause analysis is technical and specific
- [ ] Affected products table includes version boundaries
- [ ] PoC usage section matches actual script arguments
- [ ] Risk assessment matrix is complete
- [ ] Remediation includes both immediate and long-term actions
- [ ] All references are real, accessible URLs
- [ ] No emoji anywhere in the report
- [ ] Timeline section is accurate
