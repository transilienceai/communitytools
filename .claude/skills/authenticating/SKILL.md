---
name: authenticating
description: Authentication testing skill for authorized penetration testing - automates signup, login, 2FA bypass, CAPTCHA solving, and bot detection evasion using Playwright MCP. Tests authentication security controls on systems with explicit permission. Includes behavioral biometrics simulation, OTP handling, and automated account creation for security assessments.
---

# Authentication Testing Skill

Comprehensive authentication testing framework for authorized penetration testing engagements. Tests signup flows, login mechanisms, 2FA/OTP handling, CAPTCHA implementations, and bot detection systems using Playwright automation.

## Quick Start

```
Authentication Testing Workflow:
- [ ] Verify authorization and scope
- [ ] Initialize Playwright browser session
- [ ] Test signup flow (account creation)
- [ ] Test login mechanism (authentication)
- [ ] Test 2FA/OTP bypass vectors
- [ ] Test CAPTCHA implementation
- [ ] Test bot detection evasion
- [ ] Document findings and evidence
```

## When to Use

Invoke during authorized penetration testing when testing:
- Authentication and authorization controls
- Account creation and registration flows
- Multi-factor authentication (MFA/2FA) implementations
- CAPTCHA and anti-bot protections
- Session management and token handling
- Behavioral biometrics and bot detection

## Core Workflows

### Workflow 1: Account Registration Testing

**Objective**: Test signup flows and account creation mechanisms

```
Steps:
1. Navigate to registration page
2. Analyze form fields and validation
3. Test with valid credentials
4. Test with random/generated data
5. Check for verification requirements
6. Document registration vulnerabilities
```

**Common Test Vectors**:
- Email verification bypass
- Weak password policy
- Missing rate limiting
- Duplicate account creation
- Parameter manipulation

See [SIGNUP_TESTING.md](reference/SIGNUP_TESTING.md) for detailed techniques.

### Workflow 2: Login Mechanism Testing

**Objective**: Test authentication flows and credential validation

```
Steps:
1. Navigate to login page
2. Test with valid credentials
3. Test credential reuse
4. Check session handling
5. Test account enumeration
6. Analyze authentication tokens
```

**Test Scenarios**:
- Broken authentication
- Session fixation
- Insecure session management
- Account enumeration
- Timing attacks

See [LOGIN_TESTING.md](reference/LOGIN_TESTING.md) for comprehensive guide.

### Workflow 3: 2FA/OTP Bypass Testing

**Objective**: Test multi-factor authentication implementations

```
Steps:
1. Enable 2FA on test account
2. Trigger OTP/2FA code generation
3. Test bypass vectors:
   - Response manipulation
   - Direct endpoint access
   - Code reusability
   - Brute force (rate limiting)
   - Predictable code generation
   - Session persistence
4. Document findings
```

**Bypass Techniques**:
- Response manipulation (status code changes)
- OTP parameter removal
- Direct API endpoint access
- Code reuse without expiration
- Brute force 4-digit codes
- Session hijacking pre-2FA

See [2FA_BYPASS.md](reference/2FA_BYPASS.md) for all techniques.

### Workflow 4: CAPTCHA Testing

**Objective**: Test CAPTCHA implementation and bypass vectors

```
Steps:
1. Identify CAPTCHA type (reCAPTCHA, hCaptcha, image-based)
2. Test bypass techniques:
   - Missing server-side validation
   - Parameter removal
   - Reusable tokens
   - Empty field submission
   - HTTP header manipulation
   - Content-type conversion
   - Request method modification
3. Test OCR/automation (if image-based)
4. Document weaknesses
```

**CAPTCHA Types**:
- Google reCAPTCHA v2/v3
- hCaptcha
- Image-based puzzles
- Text-based challenges
- Behavioral CAPTCHAs

See [CAPTCHA_BYPASS.md](reference/CAPTCHA_BYPASS.md) for detailed methods.

### Workflow 5: Bot Detection Evasion

**Objective**: Test behavioral biometrics and anti-bot systems

```
Steps:
1. Identify bot detection mechanisms
2. Simulate human behavioral patterns:
   - Mouse movements (natural curves, pauses)
   - Keystroke dynamics (varied timing)
   - Scroll patterns (realistic acceleration)
   - Touch interactions (mobile)
   - Random delays between actions
3. Test detection bypass:
   - User-Agent rotation
   - Fingerprint randomization
   - Browser automation detection evasion
   - Behavioral biometric mimicry
4. Measure detection rates
```

**Detection Systems**:
- Behavioral biometrics
- Canvas fingerprinting
- WebGL fingerprinting
- Browser automation detection
- Mouse/touch pattern analysis

See [BOT_DETECTION.md](reference/BOT_DETECTION.md) for evasion techniques.

## Playwright Integration

**CRITICAL**: Use Playwright MCP server for all browser automation.

### Initialize Browser

```javascript
// Navigate to target
await playwright_navigate({ url: "https://target.com/login" });

// Take snapshot
await playwright_snapshot();
```

### Human-Like Interactions

```javascript
// Natural mouse movement to element
await playwright_hover({
  element: "username field",
  ref: "input#username"
});

// Realistic typing with delays
await playwright_type({
  element: "username field",
  ref: "input#username",
  text: "testuser",
  slowly: true  // Types one character at a time
});

// Random delay (50-150ms)
await playwright_evaluate({
  function: "() => new Promise(r => setTimeout(r, Math.random() * 100 + 50))"
});
```

### Capture Evidence

```javascript
// Screenshot before action
await playwright_take_screenshot({
  filename: "before-login.png"
});

// Perform action
await playwright_click({
  element: "login button",
  ref: "button[type='submit']"
});

// Screenshot after action
await playwright_take_screenshot({
  filename: "after-login.png"
});

// Check console for errors
await playwright_console_messages({ level: "error" });

// Check network requests
await playwright_network_requests();
```

## Behavioral Biometrics Simulation

### Mouse Movement Patterns

```javascript
// Simulate natural mouse trajectory
function simulateNaturalMovement(start, end, steps = 50) {
  const points = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    // Add Bezier curve for natural path
    const x = start.x + (end.x - start.x) * easeInOutQuad(t);
    const y = start.y + (end.y - start.y) * easeInOutQuad(t);
    // Add slight randomness
    const noise = {
      x: (Math.random() - 0.5) * 2,
      y: (Math.random() - 0.5) * 2
    };
    points.push({ x: x + noise.x, y: y + noise.y });
  }
  return points;
}
```

### Keystroke Dynamics

```javascript
// Variable typing speed (80-200ms between keys)
async function typeWithHumanTiming(text, element) {
  for (const char of text) {
    await playwright_type({
      element: element,
      ref: elementRef,
      text: char,
      slowly: true
    });
    // Random delay between keystrokes
    const delay = 80 + Math.random() * 120;
    await sleep(delay);
  }
}
```

### Scroll Behavior

```javascript
// Natural scrolling with acceleration/deceleration
await playwright_evaluate({
  function: `() => {
    window.scrollTo({
      top: ${targetY},
      behavior: 'smooth'
    });
    // Add micro-pauses during scroll
    return new Promise(resolve => {
      setTimeout(resolve, 500 + Math.random() * 500);
    });
  }`
});
```

## OTP/Email Handling

### Access Email for 2FA Codes

**Requirements**:
- Email access (IMAP, API, or test email service)
- OTP extraction pattern matching

```python
# Example: Extract OTP from email
import imaplib
import re

def get_otp_from_email(email, password, from_address):
    mail = imaplib.IMAP4_SSL('imap.gmail.com')
    mail.login(email, password)
    mail.select('inbox')

    # Search for recent emails from service
    _, messages = mail.search(None, f'FROM "{from_address}"')

    # Get latest email
    latest_email_id = messages[0].split()[-1]
    _, msg = mail.fetch(latest_email_id, '(RFC822)')

    # Extract OTP (6-digit code pattern)
    body = msg[0][1].decode('utf-8')
    otp_match = re.search(r'\b\d{6}\b', body)

    return otp_match.group(0) if otp_match else None
```

**Note**: For testing, use disposable email services or dedicated test accounts.

## Common Authentication Vulnerabilities

### Critical Findings

**Broken Authentication**:
- Weak password policies
- Credential stuffing vulnerabilities
- Session fixation
- Insecure password reset

**2FA Bypass**:
- Missing server-side validation
- Predictable OTP codes
- Code reusability
- Direct endpoint access

**CAPTCHA Bypass**:
- Client-side only validation
- Reusable tokens
- Missing rate limiting
- OCR-vulnerable images

**Bot Detection Bypass**:
- Weak behavioral checks
- Fingerprint detection failures
- Automation detection bypass

## Output Format

```
outputs/authenticating/<target>/
├── signup/
│   ├── account_created.json
│   ├── registration_flow.md
│   └── evidence/
│       ├── signup-form.png
│       └── email-verification.png
├── login/
│   ├── session_tokens.json
│   ├── authentication_flow.md
│   └── evidence/
├── 2fa/
│   ├── bypass_attempts.json
│   ├── otp_codes.txt
│   └── evidence/
├── captcha/
│   ├── bypass_methods.json
│   ├── captcha_tokens.txt
│   └── evidence/
└── findings/
    ├── vulnerabilities.json
    ├── authentication_report.md
    └── poc_scripts/
```

## Testing Checklist

### Pre-Test

- [ ] Scope defined and documented
- [ ] Test accounts created (not real users)
- [ ] Playwright MCP server configured
- [ ] Email access configured (for OTP)

### During Test

- [ ] Signup flow tested
- [ ] Login mechanism tested
- [ ] 2FA bypass vectors tested
- [ ] CAPTCHA implementation tested
- [ ] Bot detection tested
- [ ] Session management tested
- [ ] Evidence captured (screenshots, network logs)

### Post-Test

- [ ] Findings documented
- [ ] PoC scripts created
- [ ] Vulnerabilities categorized (CVSS)
- [ ] Remediation recommendations provided
- [ ] Test accounts cleaned up

## Tools & Resources

**Playwright MCP** - Browser automation
**Email APIs** - OTP extraction (IMAP, Gmail API, test services)
**Proxy/VPN** - IP rotation for rate limit testing
**OCR Tools** - Image-based CAPTCHA solving
**Fingerprint Generators** - Canvas/WebGL randomization

## Remediation Guidance

**For Defenders**:
- Implement server-side validation for all authentication steps
- Use strong CAPTCHA (reCAPTCHA v3 with scoring)
- Implement rate limiting on authentication endpoints
- Use cryptographically secure OTP generation
- Enforce OTP expiration and one-time use
- Implement behavioral biometrics with ML
- Monitor for automation patterns
- Use device fingerprinting
- Implement account lockout policies

## Legal & Ethical Considerations

**Authorization Documentation**:
- Maintain written permission for all testing
- Document scope boundaries
- Log all testing activities
- Report findings responsibly

**Test Account Management**:
- Create dedicated test accounts if necessary
- Clean up test accounts after testing
- Minimize data exposure

**Responsible Disclosure**:
- Report findings to system owner
- Allow reasonable remediation time
- Follow coordinated disclosure timeline
- Respect confidentiality agreements

## Troubleshooting

**Playwright not connecting**: Verify MCP server running and configured
**CAPTCHA always failing**: May have strong bot detection, try behavioral simulation
**2FA codes not received**: Check email configuration and spam folder
**Bot detection triggering**: Increase delays, use better behavioral patterns
**Session persistence issues**: Clear cookies between test runs

## References

- [CAPTCHA Bypass Techniques](https://medium.com/@mtsboysquad001/captcha-bypass-28de7279865b)
- [2FA Bypass Methods](https://github.com/EmadYaY/2FA-Bypass-Techniques)
- [Behavioral Biometrics Research](https://www.researchgate.net/publication/336270420_A_Deep_Learning_Approach_to_Web_Bot_Detection_Using_Mouse_Behavioral_Biometrics)
- [Bot Detection in 2026](https://www.biometricupdate.com/202508/roundtable-launches-system-to-detect-bots-using-behavioral-biometrics)
- [Pentesting 2FA](https://book.hacktricks.xyz/pentesting-web/2fa-bypass)

---

**For detailed techniques, see reference/ directory**:
- SIGNUP_TESTING.md
- LOGIN_TESTING.md
- 2FA_BYPASS.md
- CAPTCHA_BYPASS.md
- BOT_DETECTION.md
- BEHAVIORAL_BIOMETRICS.md
