# Authentication Testing Skill

Comprehensive authentication security testing framework for authorized penetration testing engagements.

## Overview

The `authenticating` skill provides automated testing capabilities for authentication mechanisms, including:

- **Account Registration** - Signup flow testing and validation bypass
- **Login Security** - Authentication mechanism testing
- **2FA/OTP Bypass** - Multi-factor authentication testing
- **CAPTCHA Testing** - CAPTCHA implementation analysis
- **Bot Detection** - Anti-bot system evasion testing
- **Behavioral Biometrics** - Human behavior simulation

## Quick Start

### 1. Verify Authorization

Ensure you have written permission and documented scope before proceeding.

### 2. Generate Compliant Password

```python
from tools.password_generator import generate_password

# Analyze password requirements from signup form
password = generate_password(
    hint_text="Password must be 8-16 characters with uppercase, lowercase, and numbers",
    length=12
)
# Result: Properly randomized password like "Xy7mK9Pq2zAb"
```

### 3. Initialize Playwright

```javascript
// Playwright MCP server must be running
await playwright_navigate({ url: 'https://authorized-target.com' });
```

### 4. Test Authentication Flow with Credential Management

```python
from tools.credential_manager import CredentialManager, store_test_credential, get_test_credential

# After signup - store credentials
credential_id = store_test_credential(
    target="authorized-target.com",
    username="testuser123",
    password=password,
    email="test@example.com",
    account_type="test"
)

# For login - retrieve stored credentials
cred = get_test_credential(target="authorized-target.com", account_type="test")

# Use in Playwright
await playwright_type({
    element: "username",
    ref: "input[name='username']",
    text: cred["username"],
    slowly: true
})

await playwright_type({
    element: "password",
    ref: "input[name='password']",
    text: cred["password"],
    slowly: true
})

// Test 2FA
await authenticating_test_2fa_bypass();

// Test CAPTCHA
await authenticating_test_captcha();

// Test bot detection
await authenticating_test_bot_detection();

# Cleanup after testing
mgr = CredentialManager()
mgr.cleanup_target("authorized-target.com")
```

## Key Features

### Smart Password Generation
- **Policy-aware generation**: Analyzes password requirements from form text
- **Proper randomization**: Cryptographically secure random passwords
- **Restriction compliance**: No repeating chars, no sequential patterns
- **Custom character sets**: Supports specific special character requirements
- **Flexible constraints**: Min/max length, character type requirements

### Credential Management
- **Persistent storage**: `.credentials` file for credential reuse
- **Automatic gitignore**: Credentials never committed to version control
- **Metadata support**: Store 2FA secrets, session tokens, API keys
- **Secure permissions**: File permissions set to 600 on Unix systems
- **Easy cleanup**: Simple credential lifecycle management
- **Cross-session reuse**: Access credentials across testing sessions

### Signup Testing
- Account creation flow analysis
- Policy-compliant password generation
- Credential storage and reuse
- Email verification bypass testing
- Parameter manipulation
- Rate limit testing
- Duplicate account creation

### Login Testing
- Credential validation testing
- Session management analysis
- Account enumeration detection
- Authentication bypass vectors
- Timing attack testing

### 2FA/OTP Testing
- Response manipulation
- Direct endpoint access
- Code reusability testing
- Brute force detection
- Predictable code analysis
- Session persistence testing
- OTP extraction from email

### CAPTCHA Testing
- Missing server-side validation
- Token reusability
- Parameter manipulation
- Content-type conversion
- Request method modification
- OCR for image-based CAPTCHAs
- reCAPTCHA v2/v3 testing

### Bot Detection Testing
- Behavioral biometrics simulation
- Mouse movement patterns
- Keystroke dynamics
- Scroll behavior
- Canvas/WebGL fingerprint randomization
- WebDriver detection evasion
- Request pattern variation

## Usage

### Via Slash Command

```bash
/authenticating
```

### Programmatic Usage

```javascript
const { authenticating } = require('.claude/skills/authenticating');

// Setup
await authenticating.setup({
  target: 'https://authorized-target.com',
  authorization: 'written permission on file',
  scope: 'authentication endpoints only'
});

// Run tests
const results = await authenticating.runTests({
  signup: true,
  login: true,
  twoFactor: true,
  captcha: true,
  botDetection: true
});

// Generate report
await authenticating.generateReport(results);
```

## Documentation

### Core Documentation
- **SKILL.md** - Main skill definition with workflows
- **README.md** - This file (user documentation)
- **CLAUDE.md** - Auto-loaded context for Claude

### Reference Guides
- **CAPTCHA_BYPASS.md** - Complete CAPTCHA testing guide
- **2FA_BYPASS.md** - 2FA/OTP testing techniques
- **BOT_DETECTION.md** - Bot detection evasion methods
- **BEHAVIORAL_BIOMETRICS.md** - Human behavior simulation
- **SIGNUP_TESTING.md** - Account registration testing
- **LOGIN_TESTING.md** - Login mechanism testing

## Playwright Integration

This skill requires Playwright MCP server for browser automation.

### Key Capabilities

**Human-Like Interactions**:
```javascript
// Natural mouse movement
await playwright_hover({ element: 'field', ref: '#username' });

// Realistic typing with delays
await playwright_type({
  element: 'field',
  ref: '#username',
  text: 'testuser',
  slowly: true  // Types one char at a time
});

// Random delays between actions
await playwright_wait_for({ time: Math.random() * 1000 + 500 });
```

**Evidence Capture**:
```javascript
// Screenshots
await playwright_take_screenshot({ filename: 'before-login.png' });

// Network monitoring
const requests = await playwright_network_requests();

// Console logs
const logs = await playwright_console_messages({ level: 'error' });
```

## Output Structure

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
├── bot_detection/
│   ├── detection_tests.json
│   ├── behavioral_patterns.md
│   └── evidence/
└── findings/
    ├── vulnerabilities.json
    ├── authentication_report.md
    ├── executive_summary.md
    └── poc_scripts/
```

## Common Test Scenarios

### Scenario 1: Registration Flow Testing

```javascript
// Test account creation with various inputs
await test_signup_with_valid_data();
await test_signup_with_random_data();
await test_duplicate_account_creation();
await test_email_verification_bypass();
await test_registration_rate_limiting();
```

### Scenario 2: 2FA Bypass Testing

```javascript
// Test various 2FA bypass vectors
await test_response_manipulation();
await test_direct_endpoint_access();
await test_otp_parameter_removal();
await test_code_reusability();
await test_otp_brute_force();
```

### Scenario 3: CAPTCHA Implementation Testing

```javascript
// Test CAPTCHA weaknesses
await test_missing_server_validation();
await test_token_reusability();
await test_parameter_manipulation();
await test_content_type_conversion();
await test_ocr_vulnerability();
```

## Legal & Ethical Considerations

### Authorization Documentation
- Maintain written permission for all testing activities
- Clearly document scope boundaries and limitations
- Log all testing activities with timestamps
- Report findings responsibly through proper channels

### Test Account Management
- Create dedicated test accounts for all testing
- Never use or access real user credentials
- Clean up all test accounts after testing completes
- Minimize data exposure during testing

### Responsible Disclosure
- Report findings promptly to system owner
- Allow reasonable time for remediation (typically 90 days)
- Follow coordinated disclosure timeline
- Respect confidentiality agreements

## Troubleshooting

**Playwright not responding**:
- Verify MCP server is running
- Check browser launch configuration
- Review console for error messages

**CAPTCHA always blocking**:
- Increase behavioral simulation delays
- Improve mouse movement naturalness
- Rotate User-Agent strings
- Try different fingerprint randomization

**2FA codes not received**:
- Verify email configuration (IMAP settings)
- Check spam/junk folders
- Confirm disposable email service is working
- Check OTP extraction regex patterns

**Bot detection triggering**:
- Add more realistic behavioral patterns
- Increase delays between actions
- Improve mouse movement curves
- Add thinking pauses randomly

## Requirements

- Node.js 18+ or Python 3.9+
- Playwright MCP Server
- Email access (IMAP or API) for OTP testing
- Written authorization for target system

## Installation

```bash
# Install dependencies (if using standalone)
npm install playwright
npm install imap
npm install tesseract.js  # For OCR

# Or with Python
pip install playwright
pip install imapclient
pip install pytesseract
```

## Contributing

To improve this skill:
1. Test on authorized systems
2. Document new bypass techniques discovered
3. Add examples and test cases
4. Submit improvements via pull request

## Support

**Issues**: Report issues via GitHub
**Questions**: Security testing questions → Security community forums
**Updates**: Check changelog for latest techniques

## References

- [OWASP Authentication Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CAPTCHA Bypass Techniques (Medium)](https://medium.com/@mtsboysquad001/captcha-bypass-28de7279865b)
- [2FA Bypass Methods (GitHub)](https://github.com/EmadYaY/2FA-Bypass-Techniques)
- [Bot Detection Research (ResearchGate)](https://www.researchgate.net/publication/336270420_A_Deep_Learning_Approach_to_Web_Bot_Detection_Using_Mouse_Behavioral_Biometrics)
- [HackTricks Authentication](https://book.hacktricks.xyz/pentesting-web/2fa-bypass)
