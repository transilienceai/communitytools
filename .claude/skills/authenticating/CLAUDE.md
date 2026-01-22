# Authenticating Skill - Claude Context

Auto-loaded context when working with authentication testing skill.

## Purpose

Automated authentication security testing for authorized penetration testing: signup flow testing, login security, 2FA/OTP bypass, CAPTCHA testing, and bot detection evasion using Playwright MCP.

## Key Files

### Core Documentation
- **SKILL.md** - Main workflows, quick start, testing methodologies
- **README.md** - User documentation, installation, usage examples
- **CLAUDE.md** - This file (auto-loaded working context)

### Reference Guides (reference/)
- **CAPTCHA_BYPASS.md** - 11 CAPTCHA bypass techniques with code examples
- **2FA_BYPASS.md** - 10 2FA/OTP bypass methods with implementations
- **BOT_DETECTION.md** - Behavioral biometrics and stealth techniques
- **SIGNUP_TESTING.md** - Account registration security testing
- **LOGIN_TESTING.md** - Login mechanism analysis

## Core Workflows

### Workflow 1: Complete Authentication Test
```
1. Setup Playwright with stealth mode
2. Test signup flow
3. Test login mechanism
4. Test 2FA/OTP bypass vectors
5. Test CAPTCHA implementation
6. Test bot detection
7. Document findings with evidence
8. Generate PoC scripts
9. Create professional report
```

### Workflow 2: Targeted 2FA Testing
```
1. Enable 2FA on test account
2. Trigger OTP generation
3. Test bypass vectors:
   - Response manipulation
   - Direct endpoint access
   - Parameter removal
   - Code reusability
   - Brute force (if no rate limit)
4. Extract OTP from email (if needed)
5. Document vulnerabilities
```

### Workflow 3: CAPTCHA Security Assessment
```
1. Identify CAPTCHA type (reCAPTCHA, hCaptcha, custom)
2. Test implementation:
   - Server-side validation
   - Token expiration
   - Reusability
   - Parameter manipulation
3. Test bypass vectors
4. Document weaknesses
```

## Playwright MCP Integration

**REQUIRED**: All browser automation uses Playwright MCP server.

### Human-Like Automation

```javascript
// Natural mouse movement (not straight lines)
await playwright_hover({ element: 'field', ref: '#username' });

// Realistic typing with variable delays
await playwright_type({
  element: 'field',
  ref: '#username',
  text: 'testuser',
  slowly: true  // 80-200ms between keystrokes
});

// Random delays (human thinking time)
await playwright_wait_for({ time: 500 + Math.random() * 1500 });

// Natural scrolling
await playwright_run_code({
  code: `async (page) => {
    await page.evaluate(() => window.scrollTo({top: 500, behavior: 'smooth'}));
  }`
});
```

### Evidence Capture

```javascript
// Screenshot before/after
await playwright_take_screenshot({ filename: 'before-action.png' });
// ... perform action ...
await playwright_take_screenshot({ filename: 'after-action.png' });

// Network monitoring
const requests = await playwright_network_requests();

// Console logs (errors/warnings)
const logs = await playwright_console_messages({ level: 'error' });
```

## Common Testing Patterns

### Pattern 1: CAPTCHA Bypass Test

```javascript
// Navigate to form
await playwright_navigate({ url: 'https://target.com/signup' });

// Fill form
await playwright_type({ element: 'username', ref: '#username', text: 'test' });

// Remove CAPTCHA field (test if server validates)
await playwright_evaluate({
  function: `() => document.querySelector('[name="captcha"]').remove()`
});

// Submit
await playwright_click({ element: 'submit', ref: 'button[type="submit"]' });

// Check if bypassed
const snapshot = await playwright_snapshot();
```

### Pattern 2: 2FA Response Manipulation

```javascript
// Login
await playwright_type({ element: 'username', ref: '#username', text: 'test' });
await playwright_type({ element: 'password', ref: '#password', text: 'test123' });
await playwright_click({ element: 'login', ref: 'button[type="submit"]' });

// Intercept 2FA response
await playwright_run_code({
  code: `async (page) => {
    await page.route('**/verify-2fa', route => {
      route.fulfill({
        status: 200,
        body: JSON.stringify({success: true, authenticated: true})
      });
    });
  }`
});

// Skip 2FA - go to dashboard
await playwright_navigate({ url: 'https://target.com/dashboard' });
```

### Pattern 3: Behavioral Biometrics

```javascript
// Stealth mode setup
await playwright_run_code({
  code: `async (page) => {
    // Hide webdriver flag
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined
      });
    });

    // Add chrome object
    await page.evaluateOnNewDocument(() => {
      window.chrome = { runtime: {} };
    });
  }`
});

// Natural mouse movement
await moveMouseNaturally(page, 100, 100, 500, 300);

// Variable typing speed
await typeWithHumanTiming('testuser', '#username');

// Random thinking pauses
if (Math.random() < 0.2) {
  await sleep(2000 + Math.random() * 3000);
}
```

## OTP/Email Handling

### Extract OTP from Email

```python
import imaplib
import email
import re

def get_otp_from_email(email_addr, password, from_sender):
    """Extract 6-digit OTP from email"""
    mail = imaplib.IMAP4_SSL('imap.gmail.com')
    mail.login(email_addr, password)
    mail.select('inbox')

    # Search recent emails
    _, messages = mail.search(None, f'FROM "{from_sender}"')
    latest_id = messages[0].split()[-1]
    _, msg = mail.fetch(latest_id, '(RFC822)')

    # Parse email
    email_msg = email.message_from_bytes(msg[0][1])
    body = email_msg.get_payload(decode=True).decode()

    # Extract OTP (6-digit pattern)
    otp = re.search(r'\b\d{6}\b', body)

    mail.logout()
    return otp.group(0) if otp else None
```

## Quick Reference

### CAPTCHA Techniques
1. Missing server-side validation
2. Empty field submission
3. Reusable tokens
4. HTTP header manipulation (X-Forwarded-For)
5. Content-type conversion
6. Request method modification
7. Parameter manipulation
8. OCR for image-based

### 2FA Bypass Techniques
1. Response manipulation (status code change)
2. Direct endpoint access
3. OTP parameter removal
4. Code reusability
5. Brute force (4-6 digit codes)
6. Predictable code generation
7. Session persistence pre-2FA
8. Backup code abuse
9. Race condition
10. OTP leakage

### Bot Detection Evasion
1. Behavioral biometrics (mouse, keyboard, scroll)
2. Canvas/WebGL fingerprint randomization
3. User-Agent rotation
4. WebDriver detection hiding
5. Natural timing and delays
6. Request pattern variation

## Output Format

```
outputs/authenticating/<target>/
├── signup/
│   ├── account_created.json
│   ├── evidence/screenshots/
├── login/
│   ├── session_tokens.json
│   ├── evidence/
├── 2fa/
│   ├── bypass_attempts.json
│   ├── otp_codes.txt
│   ├── evidence/
├── captcha/
│   ├── bypass_methods.json
│   ├── evidence/
├── bot_detection/
│   ├── detection_tests.json
│   ├── behavioral_patterns.md
└── findings/
    ├── vulnerabilities.json
    ├── authentication_report.md
    └── poc_scripts/
```

## Testing Checklist

**Pre-Test**:
- [ ] Scope defined
- [ ] Test accounts created
- [ ] Playwright MCP configured
- [ ] Email access setup (for OTP)

**During Test**:
- [ ] Signup flow tested
- [ ] Login security tested
- [ ] 2FA bypass vectors tested
- [ ] CAPTCHA tested
- [ ] Bot detection tested
- [ ] Evidence captured (screenshots, logs)

**Post-Test**:
- [ ] Findings documented
- [ ] PoC scripts created
- [ ] CVSS scores assigned
- [ ] Remediation recommendations provided
- [ ] Test accounts cleaned up

## Common Vulnerabilities Found

**Critical**:
- Missing 2FA server-side validation
- Reusable OTP codes
- Direct endpoint access without 2FA
- CAPTCHA client-side only

**High**:
- Weak OTP generation (predictable)
- No rate limiting on authentication
- CAPTCHA token reusability
- Session persistence pre-2FA

**Medium**:
- Weak bot detection
- Account enumeration
- Timing attacks
- Information disclosure

## Tools Available

- **Playwright MCP** - Browser automation with stealth
- **Email APIs** - IMAP, Gmail API, disposable services
- **OCR** - Tesseract, pytesseract (image CAPTCHA)
- **Proxies** - IP rotation for rate limit testing

## Success Criteria

Testing is successful when:
- All authentication flows tested systematically
- Bypass vectors identified and documented
- Working PoC scripts created for findings
- Evidence captured (screenshots, network logs)
- Professional report generated with CVSS scores
- Remediation recommendations provided

## Ethical Guidelines

**Always**:
- ✅ Use test accounts only
- ✅ Document scope clearly
- ✅ Report findings responsibly
- ✅ Follow disclosure timelines
- ✅ Clean up after testing

**Never**:
- ❌ Exceed defined scope
- ❌ Cause service disruption
- ❌ Expose findings publicly before remediation

## Troubleshooting

**Issue**: Playwright not connecting
**Solution**: Check MCP server status, verify configuration

**Issue**: CAPTCHA always fails
**Solution**: Increase delays, improve behavioral simulation

**Issue**: 2FA codes not received
**Solution**: Check email config, verify IMAP settings, check spam

**Issue**: Bot detection triggers
**Solution**: Add more natural patterns, increase delays, randomize fingerprints

**Issue**: Session issues
**Solution**: Clear cookies between tests, check session storage

## Quick Commands

```bash
# Initialize testing
/authenticating

# Test specific area
/authenticating --test=2fa
/authenticating --test=captcha
/authenticating --test=bot-detection

# Generate report
/authenticating --report
```

## References

**Internal**:
- SKILL.md - Complete workflows
- reference/CAPTCHA_BYPASS.md - CAPTCHA techniques
- reference/2FA_BYPASS.md - 2FA testing
- reference/BOT_DETECTION.md - Bot evasion

**External**:
- OWASP Auth Testing Guide
- HackTricks 2FA/CAPTCHA guides
- Playwright documentation
- Bot detection research papers
