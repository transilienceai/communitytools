# Password Generation & Credential Management

Complete guide to smart password generation and credential management for authentication testing.

---

## Overview

Two critical utilities for authentication testing:

1. **PasswordGenerator** - Generate policy-compliant, properly randomized passwords
2. **CredentialManager** - Store and reuse test credentials securely

Both are essential for professional penetration testing workflows.

---

## PasswordGenerator

### Purpose

Generate passwords that:
- Follow website-specific requirements
- Are properly randomized (cryptographically secure)
- Avoid predictable patterns
- Support custom restrictions

### Basic Usage

```python
from tools.password_generator import generate_password

# Quick generation with hint text
password = generate_password(
    hint_text="Password must be 8-16 characters with uppercase, lowercase, and numbers"
)
# Result: "Xy7mK9Pq2zAb" (example)

# Explicit requirements
password = generate_password(
    length=12,
    require_uppercase=True,
    require_lowercase=True,
    require_digits=True,
    require_special=True
)
# Result: "Ab3#Xy9@Mq7!"

# Simple password (no special chars)
password = generate_password(
    length=10,
    require_special=False
)
# Result: "Xy7mK9Pq2z"
```

### Advanced Usage

```python
from tools.password_generator import PasswordGenerator

# Analyze complex requirements
requirements = PasswordGenerator.analyze_requirements(
    hint_text="Password must be 12-20 characters, include special characters (!@#$% only), no repeating characters",
    no_repeating=True
)

# Generate with analyzed requirements
password = PasswordGenerator.generate(requirements, length=16)

# Custom special characters
password = generate_password(
    length=14,
    require_special=True,
    allowed_special_chars="!@#$%",  # Only these special chars
    no_repeating=True,
    no_sequential=True
)
```

### Parsing Form Requirements

The generator can parse natural language password requirements:

```python
# Example 1: Standard requirements
hint = "Password must be at least 8 characters with uppercase and lowercase letters"
password = generate_password(hint_text=hint)

# Example 2: Length range
hint = "8 to 16 characters"
password = generate_password(hint_text=hint, length=12)

# Example 3: Special character restrictions
hint = "Must include special characters: !@#$%^&*()"
password = generate_password(hint_text=hint)

# Example 4: No repeating characters
hint = "No consecutive repeating characters allowed"
password = generate_password(hint_text=hint)
```

### Supported Requirements

**Length**:
- `min_length`: Minimum password length (default: 8)
- `max_length`: Maximum password length (default: 128)

**Character Types**:
- `require_uppercase`: Require uppercase letters (default: True)
- `require_lowercase`: Require lowercase letters (default: True)
- `require_digits`: Require numbers (default: True)
- `require_special`: Require special characters (default: False)

**Character Sets**:
- `allowed_special_chars`: Allowed special characters (default: `!@#$%^&*()_+-=[]{}|;:,.<>?`)
- `disallowed_chars`: Characters to exclude

**Restrictions**:
- `no_repeating`: No consecutive repeating characters (e.g., "aa", "11")
- `no_sequential`: No sequential characters (e.g., "abc", "123")

### Patterns Detected in Hint Text

The analyzer detects:

**Length patterns**:
- "8-16 characters"
- "at least 8 characters"
- "minimum 8 characters"
- "max 20 characters"

**Character type patterns**:
- "uppercase" / "capital letter"
- "lowercase" / "lower case"
- "number" / "digit" / "numeric"
- "special character" / "symbol"

**Restriction patterns**:
- "no repeating" / "no repeated"
- "no sequential" / "no sequence"
- "no consecutive"

**Special character patterns**:
- "special characters: !@#$%"
- Extracts specific allowed characters

---

## CredentialManager

### Purpose

Manage test credentials with:
- Persistent storage across sessions
- Automatic gitignore management
- Metadata storage (2FA secrets, tokens)
- Secure file permissions
- Easy cleanup

### Basic Usage

```python
from tools.credential_manager import (
    CredentialManager,
    store_test_credential,
    get_test_credential
)

# Quick storage
credential_id = store_test_credential(
    target="example.com",
    username="testuser123",
    password="Gen3rated!Pass",
    email="test@example.com"
)

# Quick retrieval
cred = get_test_credential(target="example.com")
username = cred["username"]
password = cred["password"]
```

### Advanced Usage

```python
from tools.credential_manager import CredentialManager

# Initialize manager
mgr = CredentialManager()  # Uses .credentials file by default
# Or custom file:
mgr = CredentialManager(credentials_file="test-accounts.credentials")

# Store with metadata
credential_id = mgr.store_credential(
    target="example.com",
    username="testuser123",
    password="Gen3rated!Pass",
    email="test@example.com",
    account_type="test",
    metadata={
        "signup_date": "2026-01-29",
        "2fa_enabled": False,
        "account_role": "user"
    }
)

# Retrieve by ID
cred = mgr.get_credential(target="example.com", credential_id=credential_id)

# Retrieve by account type
cred = mgr.get_credential(target="example.com", account_type="test")

# Retrieve latest (most recently created)
cred = mgr.get_credential(target="example.com")

# Update metadata (e.g., after enabling 2FA)
mgr.update_metadata(
    target="example.com",
    credential_id=credential_id,
    metadata={
        "2fa_enabled": True,
        "2fa_secret": "JBSWY3DPEHPK3PXP",
        "backup_codes": ["12345678", "87654321"]
    }
)

# List all credentials
all_creds = mgr.list_credentials()
# Returns: {"example.com": [cred1, cred2], "other.com": [cred3]}

# List for specific target
target_creds = mgr.list_credentials(target="example.com")

# Delete specific credential
mgr.delete_credential(target="example.com", credential_id=credential_id)

# Cleanup all credentials for target
mgr.cleanup_target("example.com")
```

### Credential Structure

Stored credentials have this structure:

```json
{
  "example.com": {
    "accounts": {
      "abc123def456": {
        "username": "testuser123",
        "password": "Gen3rated!Pass",
        "email": "test@example.com",
        "account_type": "test",
        "created": "2026-01-29T10:30:00Z",
        "last_used": "2026-01-29T14:45:00Z",
        "metadata": {
          "2fa_enabled": true,
          "2fa_secret": "JBSWY3DPEHPK3PXP",
          "session_token": "eyJhbGc..."
        }
      }
    },
    "metadata": {
      "created": "2026-01-29T10:00:00Z",
      "last_updated": "2026-01-29T14:45:00Z"
    }
  }
}
```

### Export for Tools

```python
# Export credential in simple format
cred_data = mgr.export_for_tools(target="example.com")
# Returns:
# {
#   "username": "testuser123",
#   "password": "Gen3rated!Pass",
#   "email": "test@example.com",
#   "metadata": {...}
# }

# Use directly in Playwright
await playwright_type({
    element: "username",
    ref: "input[name='username']",
    text: cred_data["username"]
})
```

---

## Complete Workflow Examples

### Example 1: Account Creation with Credential Storage

```python
from tools.password_generator import generate_password
from tools.credential_manager import store_test_credential
import random
import string

# Step 1: Generate username and email
username = f"test_{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"
email = f"{username}@example.com"

# Step 2: Analyze password requirements from signup form
# (Assuming you've captured the form text via Playwright snapshot)
password_hint = "Password must be 8-16 characters with uppercase, lowercase, numbers, and special characters"

# Step 3: Generate compliant password
password = generate_password(
    hint_text=password_hint,
    length=12
)

# Step 4: Use Playwright to fill signup form
await playwright_type({
    element: "username",
    ref: "input[name='username']",
    text: username,
    slowly: True
})

await playwright_type({
    element: "email",
    ref: "input[name='email']",
    text: email,
    slowly: True
})

await playwright_type({
    element: "password",
    ref: "input[name='password']",
    text: password,
    slowly: True
})

await playwright_click({
    element: "submit",
    ref: "button[type='submit']"
})

# Step 5: Store credentials
credential_id = store_test_credential(
    target="example.com",
    username=username,
    password=password,
    email=email,
    account_type="test",
    signup_date="2026-01-29",
    password_hint=password_hint
)

print(f"Account created and stored: {credential_id}")
```

### Example 2: Login with Stored Credentials

```python
from tools.credential_manager import get_test_credential

# Retrieve credential
cred = get_test_credential(target="example.com", account_type="test")

if not cred:
    print("No credentials found for example.com")
    exit(1)

# Navigate to login page
await playwright_navigate({ url: "https://example.com/login" })

# Fill login form
await playwright_type({
    element: "username",
    ref: "input[name='username']",
    text: cred["username"],
    slowly: True
})

await playwright_type({
    element: "password",
    ref: "input[name='password']",
    text: cred["password"],
    slowly: True
})

await playwright_click({
    element: "login button",
    ref: "button[type='submit']"
})

print(f"Logged in with: {cred['username']}")
```

### Example 3: 2FA Setup with Metadata Storage

```python
from tools.credential_manager import CredentialManager

# Get credential
mgr = CredentialManager()
cred = mgr.get_credential(target="example.com", account_type="test")
credential_id = # ... get from previous storage

# Enable 2FA via UI
await playwright_navigate({ url: "https://example.com/settings/2fa" })
await playwright_click({ element: "enable 2FA", ref: "button#enable-2fa" })

# Extract 2FA secret from QR code or text
# (Use Playwright to read the secret)
twofa_secret = "JBSWY3DPEHPK3PXP"

# Store 2FA secret in credential metadata
mgr.update_metadata(
    target="example.com",
    credential_id=credential_id,
    metadata={
        "2fa_enabled": True,
        "2fa_secret": twofa_secret,
        "2fa_setup_date": "2026-01-29"
    }
)

print(f"2FA enabled and secret stored")
```

### Example 4: Cleanup After Testing

```python
from tools.credential_manager import CredentialManager

mgr = CredentialManager()

# List all credentials for target
creds = mgr.list_credentials(target="example.com")

print(f"Found {len(creds['example.com'])} credentials for example.com")

# Delete accounts via UI (if needed)
for cred in creds["example.com"]:
    # Login and delete account via Playwright
    # ...
    pass

# Cleanup credential storage
mgr.cleanup_target("example.com")

print("Cleanup complete")
```

---

## Security Considerations

### Password Generation Security

**DO**:
- ✅ Use `generate_password()` for all test accounts
- ✅ Ensure proper randomization (no hardcoded passwords)
- ✅ Follow website requirements exactly
- ✅ Use unique passwords per account

**DON'T**:
- ❌ Use predictable passwords (e.g., "Password123")
- ❌ Reuse passwords across targets
- ❌ Ignore password requirements (causes signup failures)

### Credential Storage Security

**DO**:
- ✅ Store credentials in `.credentials` files (gitignored)
- ✅ Use secure file permissions (600 on Unix)
- ✅ Clean up credentials after testing
- ✅ Store only test account credentials

**DON'T**:
- ❌ Commit `.credentials` files to version control
- ❌ Store real user credentials
- ❌ Share credentials files publicly
- ❌ Leave credentials behind after testing

### File Permissions

On Unix systems, the CredentialManager automatically sets file permissions to 600:

```bash
# Verify permissions
ls -la .credentials
# Should show: -rw------- (600)
```

### Gitignore Management

The CredentialManager automatically adds `.credentials` patterns to `.gitignore`:

```gitignore
# Added automatically
.credentials
*.credentials
```

Verify with:
```bash
git check-ignore .credentials
# Should output: .credentials
```

---

## Troubleshooting

### Password Generation Issues

**Problem**: Password rejected by website
**Solution**:
- Capture exact password requirements from form
- Use `hint_text` parameter with complete requirement text
- Check for hidden requirements (special char whitelist)

**Problem**: Password too predictable
**Solution**:
- Increase length (use 12-16 characters)
- Ensure `random` module is properly seeded (handled automatically)

### Credential Storage Issues

**Problem**: `.credentials` file committed to git
**Solution**:
- Verify gitignore with: `git check-ignore .credentials`
- If missing, run: `echo ".credentials" >> .gitignore`
- Remove from git: `git rm --cached .credentials`

**Problem**: Permission denied reading `.credentials`
**Solution**:
- Check file permissions: `ls -la .credentials`
- Fix permissions: `chmod 600 .credentials`

**Problem**: Credential not found
**Solution**:
- List all credentials: `mgr.list_credentials()`
- Verify target name matches exactly
- Check account_type filter

---

## API Reference

### PasswordGenerator Methods

**`analyze_requirements(hint_text, min_length, max_length, **kwargs)`**
- Analyze password requirements from text or parameters
- Returns: Dict of requirements

**`generate(requirements, length, **kwargs)`**
- Generate password following requirements
- Returns: String password

**`generate_from_form_hints(form_text, length)`**
- Generate from HTML form text
- Returns: String password

### CredentialManager Methods

**`store_credential(target, username, password, email, account_type, metadata)`**
- Store a credential
- Returns: Credential ID (string)

**`get_credential(target, credential_id, account_type)`**
- Retrieve a credential
- Returns: Dict or None

**`list_credentials(target)`**
- List credentials
- Returns: Dict[str, List[Dict]]

**`delete_credential(target, credential_id)`**
- Delete a credential
- Returns: Bool

**`cleanup_target(target)`**
- Remove all credentials for target
- Returns: Bool

**`update_metadata(target, credential_id, metadata)`**
- Update credential metadata
- Returns: Bool

**`export_for_tools(target, credential_id)`**
- Export for automation tools
- Returns: Dict or None

---

## Best Practices

### Password Generation

1. **Always analyze requirements first**
   ```python
   # Good
   password = generate_password(hint_text=form_text)

   # Bad
   password = "Password123!"  # Hardcoded
   ```

2. **Use appropriate length**
   - Default: 12 characters (good balance)
   - High security: 16+ characters
   - Minimum: Follow site requirements

3. **Handle restrictions properly**
   ```python
   # For sites with strict rules
   password = generate_password(
       hint_text=hint,
       no_repeating=True,
       no_sequential=True
   )
   ```

### Credential Management

1. **Store immediately after account creation**
   ```python
   # Right after successful signup
   credential_id = store_test_credential(...)
   ```

2. **Update metadata as you test**
   ```python
   # After enabling 2FA
   mgr.update_metadata(target, credential_id, {
       "2fa_enabled": True,
       "2fa_secret": secret
   })
   ```

3. **Clean up after testing**
   ```python
   # At end of test session
   mgr.cleanup_target(target)
   ```

4. **Use descriptive metadata**
   ```python
   # Helpful for later reference
   store_test_credential(
       ...,
       metadata={
           "purpose": "XSS testing",
           "created_by": "pentest_2026_01",
           "test_phase": "authentication"
       }
   )
   ```

---

## Integration with Other Tools

### Playwright Integration

```python
# Complete flow
cred = get_test_credential(target)

await playwright_type({
    element: "username",
    ref: "input[name='username']",
    text: cred["username"],
    slowly: True
})

await playwright_type({
    element: "password",
    ref: "input[name='password']",
    text: cred["password"],
    slowly: True
})
```

### OTP/2FA Integration

```python
import pyotp

# Get stored 2FA secret
cred = mgr.get_credential(target)
secret = cred["metadata"]["2fa_secret"]

# Generate OTP
totp = pyotp.TOTP(secret)
otp_code = totp.now()

# Use in form
await playwright_type({
    element: "2FA code",
    ref: "input[name='otp']",
    text: otp_code
})
```

### Email OTP Integration

```python
from tools.credential_manager import get_test_credential

# Get email from credential
cred = get_test_credential(target)
email = cred["email"]

# Use email for OTP extraction
otp = extract_otp_from_email(
    email=email,
    password=email_password  # Store separately
)
```

---

## Summary

**PasswordGenerator**: Smart, compliant, randomized password generation
**CredentialManager**: Secure, persistent credential storage and reuse

Both tools are essential for professional authentication testing workflows.
