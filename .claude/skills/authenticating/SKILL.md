---
name: authenticating
description: Authentication testing skill for authorized penetration testing - automates signup, login, 2FA bypass, CAPTCHA solving, and bot detection evasion using Playwright MCP. Tests authentication security controls on systems with explicit permission. Includes behavioral biometrics simulation, OTP handling, and automated account creation for security assessments.
---

# Authentication Testing

Automated authentication security testing: signup, login, 2FA/OTP bypass, CAPTCHA, bot detection using Playwright.

## Quick Start

```
1. Verify authorization
2. Initialize Playwright
3. Test: signup → login → 2FA → CAPTCHA → bot detection
4. Document findings with evidence
```

## Core Workflows

**Account Registration**: Navigate → analyze form → generate password (PasswordGenerator) → create account → store credentials (CredentialManager)

**Login Security**: Test bypasses → credential validation → session tokens → fixation/hijacking

**2FA/OTP Bypass**: Enable 2FA → test vectors (response manipulation, direct access, parameter removal, code reuse, brute force) → extract OTP from email

**CAPTCHA Assessment**: Identify type → test server-side validation, token expiration, reusability → bypass vectors

**Bot Detection**: Stealth mode → human-like behavior (natural mouse, variable typing, random pauses) → test detection

## Credential Tools

**PasswordGenerator** (`tools/password_generator.py`):
```python
from tools.password_generator import generate_password
password = generate_password(hint_text="8-16 chars, uppercase, lowercase, numbers")
```

**CredentialManager** (`tools/credential_manager.py`):
```python
from tools.credential_manager import CredentialManager
mgr = CredentialManager()
cred_id = mgr.store_credential(target="example.com", username="test", password="pass")
cred = mgr.get_credential("example.com")
```

See `reference/PASSWORD_CREDENTIAL_MANAGEMENT.md`.

## Playwright Automation

**REQUIRED**: All browser automation via Playwright MCP.

**Human-like**: Natural mouse, realistic typing (80-200ms delays), random pauses (500-2000ms), smooth scrolling
**Evidence**: Screenshots before/after, network logs, console output
**Stealth**: Hide webdriver, add chrome object, randomize fingerprints

## Testing Techniques

**CAPTCHA Bypass** (11 techniques - `reference/CAPTCHA_BYPASS.md`):
Missing server validation, empty field, reusable tokens, HTTP header manipulation, content-type conversion, request method, parameter manipulation, OCR, response interception, token expiration, session persistence

**2FA Bypass** (10 methods - `reference/2FA_BYPASS.md`):
Response manipulation, direct endpoint access, OTP parameter removal, code reusability, brute force, predictable codes, session persistence pre-2FA, backup code abuse, race condition, OTP leakage

**Bot Detection Evasion** (`reference/BOT_DETECTION.md`):
Behavioral biometrics, fingerprint randomization, User-Agent rotation, WebDriver hiding, natural timing, request patterns

## Output Structure

```
outputs/authenticating/<target>/
├── signup/account_created.json + evidence/
├── login/session_tokens.json + evidence/
├── 2fa/bypass_attempts.json + otp_codes.txt + evidence/
├── captcha/bypass_methods.json + evidence/
├── bot_detection/detection_tests.json + behavioral_patterns.md
└── findings/vulnerabilities.json + authentication_report.md + poc_scripts/
```

## Common Vulnerabilities

**Critical**: Missing 2FA server validation, reusable OTP, direct access without 2FA, client-side CAPTCHA
**High**: Weak OTP generation, no rate limiting, CAPTCHA token reuse, session persistence pre-2FA
**Medium**: Weak bot detection, account enumeration, timing attacks, info disclosure

## Testing Checklist

**Pre**: Scope, test accounts, Playwright configured, email access
**During**: Signup, login, 2FA, CAPTCHA, bot detection, evidence
**Post**: Findings documented, PoC scripts, CVSS scores, remediation, cleanup

## Critical Rules

**Always**: Test accounts only, document scope, responsible disclosure, clean up
**Never**: Exceed scope, cause disruption, expose findings before remediation

## Tools

Playwright MCP, PasswordGenerator, CredentialManager, Email APIs (IMAP, Gmail), OCR (Tesseract)

## Commands

```bash
/authenticating                  # Full test
/authenticating --test=2fa       # Specific area
/authenticating --report         # Generate report
```

## Reference

- [CAPTCHA_BYPASS.md](reference/CAPTCHA_BYPASS.md) - 11 CAPTCHA techniques
- [2FA_BYPASS.md](reference/2FA_BYPASS.md) - 10 2FA/OTP methods
- [BOT_DETECTION.md](reference/BOT_DETECTION.md) - Bot evasion
- [SIGNUP_TESTING.md](reference/SIGNUP_TESTING.md) - Registration
- [LOGIN_TESTING.md](reference/LOGIN_TESTING.md) - Login analysis
- [PASSWORD_CREDENTIAL_MANAGEMENT.md](reference/PASSWORD_CREDENTIAL_MANAGEMENT.md) - Tool usage
