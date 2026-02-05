# JWT Security Resources - References and Best Practices

This comprehensive resource guide covers OWASP documentation, CVE examples, security tools, research papers, and secure coding practices for JWT implementation and testing.

---

## Table of Contents

1. [OWASP Documentation](#owasp-documentation)
2. [CVE Examples and Advisories](#cve-examples-and-advisories)
3. [Security Testing Tools](#security-testing-tools)
4. [Research Papers and Technical Articles](#research-papers-and-technical-articles)
5. [Standards and Specifications](#standards-and-specifications)
6. [Secure Coding Practices](#secure-coding-practices)
7. [Security Guidelines by Framework](#security-guidelines-by-framework)
8. [Training and Learning Resources](#training-and-learning-resources)

---

## OWASP Documentation

### OWASP JWT Cheat Sheet

**Primary Resource:**
- **URL**: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- **Focus**: Java-specific JWT security best practices
- **Coverage**: Token generation, validation, storage, and common pitfalls

**Key Recommendations:**

#### Token Storage
- Store tokens in memory only when possible
- Avoid localStorage (vulnerable to XSS)
- Use httpOnly, Secure cookies with SameSite attribute
- Implement CSRF protection if using cookies

#### Signature Verification
- Always verify signatures before trusting claims
- Use `verify()` not `decode()` functions
- Validate algorithm matches expected value
- Reject "none" algorithm explicitly

#### Token Expiration
- Use short expiration times (minutes to hours)
- Implement refresh token mechanism
- Follow OAuth 2.0 standards for revocation
- Monitor for expired token usage attempts

#### Secure Transmission
- Always use HTTPS/TLS for token transmission
- Never log tokens in plain text
- Sanitize tokens from error messages
- Implement rate limiting on authentication endpoints

### OWASP Web Security Testing Guide - JWT Testing

**URL**: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens

**Testing Methodology:**

#### 1. Signature Verification Testing
```
Test Case: Modify token claims without re-signing
Expected: Token should be rejected
Common Failure: Application decodes without verification
```

#### 2. Algorithm Testing
```
Test Case: Change algorithm to "none"
Expected: Token should be rejected
Common Failure: Server accepts unsigned tokens
```

#### 3. Secret Strength Testing
```
Test Case: Brute force HMAC secret
Expected: Strong secret should resist attack
Common Failure: Weak/default secrets (e.g., "secret")
```

#### 4. Header Parameter Testing
```
Test Case: Inject malicious values in kid, jku, jwk
Expected: Parameters should be validated/rejected
Common Failure: Direct use in file paths or SQL queries
```

#### 5. Token Expiration Testing
```
Test Case: Use expired token
Expected: Token should be rejected
Common Failure: Expiration not checked
```

### OWASP REST Security Cheat Sheet

**URL**: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html

**JWT-Specific Guidance:**

- Use JWT for stateless authentication in REST APIs
- Include all necessary claims (exp, iat, iss, aud)
- Validate audience (aud) claim matches API
- Implement proper error handling without leaking information
- Use HTTPS for all API endpoints
- Implement rate limiting and throttling

### OWASP Authentication Cheat Sheet

**URL**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

**JWT Context:**

- JWT is suitable for stateless authentication
- Not recommended for session management requiring immediate revocation
- Combine with refresh tokens for better security
- Implement logout mechanism (blacklist or token versioning)
- Monitor for suspicious authentication patterns

---

## CVE Examples and Advisories

### Critical JWT Vulnerabilities

#### CVE-2022-21449 - "Psychic Signatures in Java"

**Description**: Java's ECDSA signature verification accepted signatures where both r and s values equal 0, allowing any JWT to appear valid.

**Affected Versions**:
- Java SE: 15.0.0-15.0.6, 16.0.0-16.0.1, 17.0.0-17.0.2, 18.0.0
- Oracle GraalVM: 21.3.0-21.3.1, 22.0.0
- Oracle Java SE Embedded: 8u321

**Severity**: CVSS 7.5 (High)

**Impact**:
- Complete authentication bypass
- Remote code execution potential
- No secret knowledge required

**Exploitation**:
```python
# ECDSA signature with r=0, s=0 accepted as valid
signature = bytes([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00])
```

**Remediation**:
- Upgrade to Java 15.0.7+, 16.0.2+, 17.0.3+, 18.0.1+
- Update all ECDSA-based JWT implementations
- Consider algorithm migration to RS256 if ECDSA not required

**References**:
- https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/
- https://nvd.nist.gov/vuln/detail/CVE-2022-21449

---

#### CVE-2022-23529 - JWT Secret Poisoning

**Description**: Vulnerability in jsonwebtoken package allowing remote code execution through malicious JWT verification requests.

**Affected Versions**:
- jsonwebtoken < 9.0.0 (Node.js)

**Severity**: CVSS 7.6 (High)

**Impact**:
- Remote code execution on verification server
- Secret key exposure
- Complete system compromise

**Attack Vector**:
```javascript
// Malicious JWT with crafted payload
// Exploits object injection in verify function
```

**Remediation**:
- Update jsonwebtoken to version 9.0.0 or later
- Implement input validation on JWT strings
- Use security linters (npm audit, Snyk)

**References**:
- https://github.com/advisories/GHSA-8cf7-32gw-wr33
- https://unit42.paloaltonetworks.com/jsonwebtoken-vulnerability-cve-2022-23529/

---

#### CVE-2018-0114 - PyJWT Algorithm Confusion

**Description**: PyJWT library vulnerable to algorithm confusion attack, accepting HMAC-signed tokens when RSA expected.

**Affected Versions**:
- PyJWT < 1.5.0

**Severity**: CVSS 7.5 (High)

**Impact**:
- Authentication bypass
- Privilege escalation
- Token forgery using public key

**Exploitation**:
```python
# Change RS256 to HS256
# Sign with public key as HMAC secret
token = jwt.encode(payload, public_key, algorithm='HS256')
```

**Remediation**:
- Update PyJWT to version 1.5.0+
- Explicitly specify allowed algorithms in verify()
- Never use decode() without signature verification

**References**:
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-0114
- https://github.com/jpadilla/pyjwt/pull/277

---

#### CVE-2023-48223 - Algorithm Confusion in fast-jwt

**Description**: The publicKeyPemMatcher in fast-jwt did not properly match all common PEM formats for public keys.

**Affected Versions**:
- fast-jwt < 3.3.2

**Severity**: CVSS 6.5 (Medium)

**Impact**:
- Algorithm confusion attack possible
- HS256 signature accepted with RSA public key
- Authentication bypass

**Attack Scenario**:
```
// Public key with "BEGIN RSA PUBLIC KEY" header vulnerable
// Attacker signs with HS256 using this public key
```

**Remediation**:
- Update fast-jwt to version 3.3.2+
- Validate PEM format strictly
- Use algorithm whitelisting

**References**:
- https://github.com/advisories/GHSA-c2ff-88x2-x9pg
- https://nvd.nist.gov/vuln/detail/CVE-2023-48223

---

#### CVE-2015-2951 - Auth0 node-jsonwebtoken Algorithm Confusion

**Description**: Auth0's node-jsonwebtoken library vulnerable to algorithm confusion, accepting HS256 when RS256 expected.

**Affected Versions**:
- node-jsonwebtoken < 5.0.0

**Severity**: High

**Impact**:
- Complete authentication bypass
- Widespread adoption amplified impact
- Affected multiple downstream projects

**Remediation**:
- Update to version 5.0.0+
- Specify algorithms array in verify()
- Audit all JWT verification code

**References**:
- https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
- https://www.cvedetails.com/cve/CVE-2015-2951/

---

#### CVE-2016-10555 - PyJWT Key Confusion

**Description**: PyJWT accepted tokens with algorithm "none" when signature verification expected.

**Affected Versions**:
- PyJWT < 1.5.0

**Severity**: High

**Impact**:
- Unsigned tokens accepted
- Complete authentication bypass
- No secret knowledge needed

**Remediation**:
- Update PyJWT
- Explicitly reject "none" algorithm
- Use verify_signature=True (default)

---

#### CVE-2025-30144 - Recent Library Bypass

**Description**: Recent vulnerability in popular JWT library allowing authentication bypass through improper validation.

**Status**: Recently disclosed (2025)

**Impact**:
- Millions of applications potentially affected
- Critical remote code execution risk
- Active exploitation in the wild

**Mitigation**:
- Apply vendor patches immediately
- Review JWT implementation
- Implement additional validation layers

---

### Vulnerability Database Resources

**CVE Details - JWT:**
- https://www.cvedetails.com/vulnerability-list/vendor_id-16053/product_id-35664/Jwt-Project-JWT.html

**NIST NVD:**
- Search: "JSON Web Token" or "JWT"
- https://nvd.nist.gov/

**GitHub Advisory Database:**
- https://github.com/advisories?query=jwt

**Snyk Vulnerability Database:**
- https://security.snyk.io/

---

## Security Testing Tools

### JWT-Specific Tools

#### 1. jwt_tool - The JWT Swiss Army Knife

**Description**: Comprehensive JWT testing toolkit

**Repository**: https://github.com/ticarpi/jwt_tool

**Features**:
- Decode and analyze tokens
- Fuzz and test all common attacks
- Brute force secrets
- Algorithm confusion attacks
- Header parameter injection
- Automated scanning

**Installation**:
```bash
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
pip3 install -r requirements.txt
```

**Usage Examples**:
```bash
# Decode token
python3 jwt_tool.py <JWT>

# Scan for vulnerabilities
python3 jwt_tool.py <JWT> -M at -t "https://target.com/api"

# Crack secret
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# Algorithm confusion
python3 jwt_tool.py <JWT> -X a

# JWK injection
python3 jwt_tool.py <JWT> -X i

# Kid injection
python3 jwt_tool.py <JWT> -X k

# Forge token
python3 jwt_tool.py <JWT> -T -S hs256 -p "secret"
```

---

#### 2. JWTAuditor

**Description**: Professional-grade JWT security testing tool

**Website**: https://jwtauditor.com/

**Features**:
- 100% client-side (privacy-focused)
- Decode and analyze
- Vulnerability assessment
- Secret brute-forcing
- Token generation
- Browser-based interface

**Use Cases**:
- Quick token analysis
- No installation required
- Offline capability
- Educational purposes

---

#### 3. jwtXploiter

**Description**: Automated JWT exploitation tool

**Repository**: https://github.com/DontPanicO/jwtXploiter

**Features**:
- Test against all known CVEs
- Payload tampering
- Signature verification bypass
- Automated exploitation
- Report generation

**Installation**:
```bash
git clone https://github.com/DontPanicO/jwtXploiter
cd jwtXploiter
pip3 install -r requirements.txt
```

**Usage**:
```bash
python3 jwtXploiter.py -t <target> -c <JWT>
```

---

#### 4. Burp Suite Extensions

**JWT Editor**:
- **BApp Store**: JWT Editor
- **Features**:
  - Visual JWT editing
  - Key management
  - Signing and verification
  - Attack automation
  - Integration with Burp workflow

**Installation**: Extender > BApp Store > JWT Editor

**JSON Web Token Attacker**:
- Automated attack testing
- Common vulnerability scanning
- Custom attack payloads

---

#### 5. jwt-hack (jwt-cracker)

**Description**: Fast JWT secret cracker

**Repository**: https://github.com/brendan-rius/c-jwt-cracker

**Features**:
- Multi-threaded
- C implementation (fast)
- Simple interface

**Installation**:
```bash
git clone https://github.com/brendan-rius/c-jwt-cracker
cd c-jwt-cracker
make
```

**Usage**:
```bash
./jwtcrack <JWT> [alphabet] [max-length]
./jwtcrack eyJhbG... abcdefghijklmnopqrstuvwxyz 6
```

---

#### 6. hashcat

**Description**: World's fastest password cracker

**Modes for JWT**:
- 16500: JWT (HS256)
- 16511: JWT (HS384)
- 16512: JWT (HS512)

**Installation**:
```bash
# Ubuntu/Debian
apt-get install hashcat

# macOS
brew install hashcat

# Or download from https://hashcat.net/hashcat/
```

**Usage**:
```bash
# Dictionary attack
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# Brute force
hashcat -a 3 -m 16500 jwt.txt ?l?l?l?l?l?l?l?l

# With rules
hashcat -a 0 -m 16500 jwt.txt wordlist.txt -r rules/best64.rule

# GPU acceleration
hashcat -a 0 -m 16500 jwt.txt wordlist.txt -w 3 -O
```

---

#### 7. John the Ripper

**Description**: Password cracking tool with JWT support

**Installation**:
```bash
# Ubuntu/Debian
apt-get install john

# macOS
brew install john

# Or compile from source: https://www.openwall.com/john/
```

**Usage**:
```bash
# Create input file
echo "<JWT>" > jwt.txt

# Crack
john --wordlist=wordlist.txt --format=HMAC-SHA256 jwt.txt

# Show results
john --show jwt.txt
```

---

### General Security Testing Tools

#### Fuzzers

**ffuf** (Web Fuzzer):
```bash
# Fuzz JWT claims
ffuf -w payloads.txt -u https://api.target.com/endpoint \
     -H "Authorization: Bearer eyJ...FUZZ...xyz"
```

**wfuzz**:
```bash
wfuzz -w payloads.txt -H "Authorization: Bearer FUZZ" \
      https://api.target.com/endpoint
```

#### Proxies

**Burp Suite Professional**:
- Intercept and modify JWTs
- Automated scanning
- Extension support

**OWASP ZAP**:
- JWT add-on available
- Automated security testing
- API testing capabilities

---

### Development and Testing Libraries

#### Python Libraries

**PyJWT** (Production):
```python
import jwt

# Secure implementation
token = jwt.encode({"sub": "user"}, secret, algorithm="HS256")
payload = jwt.decode(token, secret, algorithms=["HS256"])
```

**python-jose** (Alternative):
```python
from jose import jwt

token = jwt.encode({"sub": "user"}, secret, algorithm="HS256")
```

**jwcrypto** (Advanced):
```python
from jwcrypto import jwt, jwk

key = jwk.JWK.generate(kty='RSA', size=2048)
token = jwt.JWT(header={"alg": "RS256"}, claims={"sub": "user"})
token.make_signed_token(key)
```

#### JavaScript/Node.js Libraries

**jsonwebtoken**:
```javascript
const jwt = require('jsonwebtoken');

const token = jwt.sign({sub: 'user'}, secret, {algorithm: 'HS256'});
const payload = jwt.verify(token, secret, {algorithms: ['HS256']});
```

**jose**:
```javascript
const { SignJWT, jwtVerify } = require('jose');

const token = await new SignJWT({ sub: 'user' })
  .setProtectedHeader({ alg: 'HS256' })
  .sign(secret);
```

#### Java Libraries

**java-jwt** (Auth0):
```java
Algorithm algorithm = Algorithm.HMAC256("secret");
String token = JWT.create()
    .withSubject("user")
    .sign(algorithm);
```

**jjwt** (JSON Web Token for Java):
```java
String token = Jwts.builder()
    .setSubject("user")
    .signWith(SignatureAlgorithm.HS256, secret)
    .compact();
```

---

## Research Papers and Technical Articles

### Academic Research

#### 1. "Practical Approaches for Testing and Breaking JWT Authentication"

**Author**: Mazin Ahmed
**URL**: https://mazinahmed.net/blog/breaking-jwt/

**Key Topics**:
- Comprehensive JWT attack taxonomy
- Real-world exploitation examples
- Defense strategies
- Case studies

**Key Findings**:
- 60%+ of implementations have vulnerabilities
- Algorithm confusion most common
- Weak secrets in 30% of cases

---

#### 2. "JWTForge: A JWT Vending Service for Testing, Fuzzing, and Security Research"

**Authors**: Abhishek Tiwari
**URL**: https://www.abhishek-tiwari.com/pdf/jwtforge-a-jwt-vending-service-for-testing-fuzzing-and-security-research-of-oauth2-oidc-implementations.pdf

**Abstract**: Framework for generating realistic, customizable JWT tokens for OAuth2/OIDC testing.

**Contributions**:
- Automated testing framework
- Fuzzing methodology
- Vulnerability discovery techniques
- Industry case studies

---

#### 3. "Comprehensive Empirical Study of Python JWT Libraries"

**Published**: ScienceDirect, 2024
**URL**: https://www.sciencedirect.com/science/article/pii/S1877050924013358

**Focus**: Analysis of Python JWT library implementations

**Findings**:
- Inconsistent security practices
- API design impacts security
- Performance vs. security tradeoffs
- Recommendations for library selection

---

#### 4. "Impact of Performance on Security: JWT Token"

**Source**: CSU ScholarWorks
**URL**: https://scholarworks.calstate.edu/downloads/s4655q85w

**Research Question**: How does JWT token validation impact application performance?

**Findings**:
- JWT validation overhead: ~9%
- Security vs. performance balance
- Optimization strategies
- Caching considerations

---

### Industry Technical Articles

#### PortSwigger Research

**"JWT attacks"**
**URL**: https://portswigger.net/web-security/jwt

**Coverage**:
- Attack techniques
- Lab exercises
- Exploitation methodology
- Prevention strategies

---

#### Auth0 Blog

**"Critical Vulnerabilities in JSON Web Token Libraries"**
**URL**: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

**Topics**:
- Algorithm confusion details
- Library-specific vulnerabilities
- Responsible disclosure
- Remediation guidance

---

#### PentesterLab

**"The Ultimate Guide to JWT Vulnerabilities and Attacks"**
**URL**: https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide

**Content**:
- Comprehensive attack guide
- Hands-on exploitation examples
- Tool usage tutorials
- Real-world scenarios

---

#### HackTricks

**"JWT Vulnerabilities (Json Web Tokens)"**
**URL**: https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens

**Features**:
- Attack cheat sheet
- Payload collections
- Tool references
- Quick exploitation guides

---

### Vulnerability Research Reports

#### Red Sentry

**"JWT Vulnerabilities List: 2026 Security Risks & Mitigation Guide"**
**URL**: https://redsentry.com/resources/blog/jwt-vulnerabilities-list-2026-security-risks-mitigation-guide

**Coverage**:
- Current threat landscape
- Emerging vulnerabilities
- Mitigation strategies
- Industry statistics

---

#### Vaadata Security

**"JWT: Vulnerabilities, Attacks & Security Best Practices"**
**URL**: https://www.vaadata.com/blog/jwt-json-web-token-vulnerabilities-common-attacks-and-security-best-practices/

**Topics**:
- Common vulnerabilities
- Attack vectors
- Best practices
- Implementation guidelines

---

## Standards and Specifications

### RFC Documents

#### RFC 7519 - JSON Web Token (JWT)

**URL**: https://tools.ietf.org/html/rfc7519

**Status**: Proposed Standard

**Summary**: Defines JWT format, structure, and claims.

**Key Sections**:
- Token structure
- Claim definitions
- Validation requirements
- Security considerations

---

#### RFC 7515 - JSON Web Signature (JWS)

**URL**: https://tools.ietf.org/html/rfc7515

**Summary**: Defines digital signature and MAC for JWT.

**Key Topics**:
- Signature algorithms
- Header parameters
- Serialization formats

---

#### RFC 7516 - JSON Web Encryption (JWE)

**URL**: https://tools.ietf.org/html/rfc7516

**Summary**: Defines encryption for JWTs.

**Features**:
- Content encryption
- Key encryption
- Compact serialization

---

#### RFC 7517 - JSON Web Key (JWK)

**URL**: https://tools.ietf.org/html/rfc7517

**Summary**: JSON representation of cryptographic keys.

**Use Cases**:
- Key distribution
- JWKS endpoints
- Key management

---

#### RFC 7518 - JSON Web Algorithms (JWA)

**URL**: https://tools.ietf.org/html/rfc7518

**Summary**: Cryptographic algorithms for JWS and JWE.

**Algorithms**:
- HMAC: HS256, HS384, HS512
- RSA: RS256, RS384, RS512, PS256, PS384, PS512
- ECDSA: ES256, ES384, ES512

---

#### RFC 8725 - JSON Web Token Best Current Practices

**URL**: https://tools.ietf.org/html/rfc8725

**Status**: Best Current Practice

**Critical Recommendations**:

1. **Perform Algorithm Verification**
```
Explicitly verify the alg parameter matches expected value
```

2. **Use Appropriate Algorithms**
```
Avoid "none" algorithm
Prefer asymmetric algorithms when possible
```

3. **Validate All Cryptographic Operations**
```
Always verify signatures
Validate encryption
Check key parameters
```

4. **Use Short-Lived Tokens**
```
Implement exp claim
Use reasonable expiration times
Implement refresh token mechanism
```

5. **Ensure Adequate Key Entropy**
```
Minimum 128 bits for HMAC secrets
2048+ bits for RSA keys
Use cryptographically secure random generation
```

---

### OpenID Connect Specifications

**OpenID Connect Core 1.0**
**URL**: https://openid.net/specs/openid-connect-core-1_0.html

**JWT Usage**:
- ID Tokens (JWT format)
- UserInfo endpoint
- Token validation
- Claims standardization

---

### OAuth 2.0 Specifications

**OAuth 2.0 Framework (RFC 6749)**
**URL**: https://tools.ietf.org/html/rfc6749

**OAuth 2.0 JWT Profile (RFC 7523)**
**URL**: https://tools.ietf.org/html/rfc7523

---

## Secure Coding Practices

### General Principles

#### 1. Always Verify Signatures

**WRONG**:
```python
# VULNERABLE - decode without verification
payload = jwt.decode(token, options={"verify_signature": False})
```

**CORRECT**:
```python
# SECURE - verify signature
payload = jwt.decode(token, secret, algorithms=["HS256"])
```

---

#### 2. Explicit Algorithm Specification

**WRONG**:
```javascript
// VULNERABLE - trusts token's algorithm
const payload = jwt.verify(token, secret);
```

**CORRECT**:
```javascript
// SECURE - explicit algorithm whitelist
const payload = jwt.verify(token, secret, {algorithms: ['HS256']});
```

---

#### 3. Strong Secret Generation

**WRONG**:
```python
secret = "secret"  # VULNERABLE - weak secret
```

**CORRECT**:
```python
import secrets

# SECURE - cryptographically random secret
secret = secrets.token_bytes(32)  # 256 bits
```

---

#### 4. Reject "none" Algorithm

**WRONG**:
```python
# VULNERABLE - might accept none
algorithms = ['HS256', 'RS256', 'none']
```

**CORRECT**:
```python
# SECURE - explicit rejection
ALLOWED_ALGORITHMS = ['HS256', 'RS256']  # never include 'none'

if header['alg'].lower() == 'none':
    raise ValueError("None algorithm not permitted")
```

---

#### 5. Validate All Claims

**WRONG**:
```python
# VULNERABLE - only checks sub
if payload['sub'] == 'admin':
    grant_access()
```

**CORRECT**:
```python
# SECURE - comprehensive validation
import time

current_time = int(time.time())

# Verify expiration
if 'exp' not in payload or payload['exp'] < current_time:
    raise ValueError("Token expired")

# Verify not-before
if 'nbf' in payload and payload['nbf'] > current_time:
    raise ValueError("Token not yet valid")

# Verify issuer
if payload.get('iss') != 'https://trusted-issuer.com':
    raise ValueError("Invalid issuer")

# Verify audience
if payload.get('aud') != 'https://my-api.com':
    raise ValueError("Invalid audience")

# Then check claims
if payload['sub'] == 'admin':
    grant_access()
```

---

#### 6. Secure Key Storage

**WRONG**:
```python
# VULNERABLE - hardcoded secret
secret = "my-secret-key"
```

**CORRECT**:
```python
# SECURE - environment variable or key management
import os

secret = os.environ.get('JWT_SECRET')
if not secret:
    raise ValueError("JWT_SECRET not configured")

# Or use key management service
from azure.keyvault.secrets import SecretClient
secret = key_vault_client.get_secret("jwt-secret").value
```

---

#### 7. Sanitize Header Parameters

**WRONG**:
```python
# VULNERABLE - direct file path usage
def load_key(kid):
    return open(f"/keys/{kid}").read()
```

**CORRECT**:
```python
# SECURE - whitelist validation
ALLOWED_KEYS = {
    'key-1': '/keys/key-1.pem',
    'key-2': '/keys/key-2.pem'
}

def load_key(kid):
    if kid not in ALLOWED_KEYS:
        raise ValueError("Invalid key ID")

    # Additional path validation
    key_path = Path(ALLOWED_KEYS[kid]).resolve()
    if not str(key_path).startswith('/keys/'):
        raise ValueError("Invalid key path")

    with open(key_path, 'r') as f:
        return f.read()
```

---

### Language-Specific Best Practices

#### Python (PyJWT)

```python
import jwt
import os
from datetime import datetime, timedelta

class JWTHandler:
    def __init__(self):
        self.secret = os.environ['JWT_SECRET']
        self.algorithm = 'HS256'
        self.expiration_minutes = 30

    def create_token(self, user_id: str, claims: dict = None) -> str:
        """Create a secure JWT token"""
        payload = {
            'sub': user_id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(minutes=self.expiration_minutes),
            'iss': 'https://my-app.com',
            'aud': 'https://my-api.com'
        }

        if claims:
            payload.update(claims)

        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def verify_token(self, token: str) -> dict:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],  # Explicit whitelist
                audience='https://my-api.com',
                issuer='https://my-app.com',
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'verify_iss': True,
                    'verify_aud': True,
                    'require_exp': True,
                    'require_iat': True
                }
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {str(e)}")
```

---

#### JavaScript/Node.js (jsonwebtoken)

```javascript
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

class JWTHandler {
    constructor() {
        this.secret = process.env.JWT_SECRET;
        if (!this.secret) {
            throw new Error('JWT_SECRET environment variable not set');
        }
        this.algorithm = 'HS256';
        this.expiresIn = '30m';
    }

    createToken(userId, claims = {}) {
        const payload = {
            sub: userId,
            iat: Math.floor(Date.now() / 1000),
            iss: 'https://my-app.com',
            aud: 'https://my-api.com',
            ...claims
        };

        return jwt.sign(payload, this.secret, {
            algorithm: this.algorithm,
            expiresIn: this.expiresIn
        });
    }

    verifyToken(token) {
        try {
            return jwt.verify(token, this.secret, {
                algorithms: [this.algorithm],  // Explicit whitelist
                audience: 'https://my-api.com',
                issuer: 'https://my-app.com',
                clockTolerance: 0  // No clock skew tolerance
            });
        } catch (error) {
            if (error instanceof jwt.TokenExpiredError) {
                throw new Error('Token has expired');
            }
            if (error instanceof jwt.JsonWebTokenError) {
                throw new Error(`Invalid token: ${error.message}`);
            }
            throw error;
        }
    }
}

// Generate secure secret (run once, store in env)
function generateSecret() {
    return crypto.randomBytes(64).toString('hex');
}

module.exports = { JWTHandler, generateSecret };
```

---

#### Java (jjwt)

```java
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;

public class JWTHandler {
    private final Key secret;
    private final long expirationMs = 1800000; // 30 minutes

    public JWTHandler(String secretString) {
        // Generate secure key from secret
        this.secret = Keys.hmacShaKeyFor(secretString.getBytes());
    }

    public String createToken(String userId) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .setIssuer("https://my-app.com")
                .setAudience("https://my-api.com")
                .signWith(secret, SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims verifyToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secret)
                    .requireIssuer("https://my-app.com")
                    .requireAudience("https://my-api.com")
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("Token has expired");
        } catch (JwtException e) {
            throw new RuntimeException("Invalid token: " + e.getMessage());
        }
    }
}
```

---

### Token Storage Best Practices

#### Browser Storage

**Avoid localStorage/sessionStorage**:
```javascript
// INSECURE - vulnerable to XSS
localStorage.setItem('token', jwt);
```

**Use httpOnly Cookies**:
```javascript
// Server-side (Node.js/Express)
res.cookie('token', jwt, {
    httpOnly: true,      // Prevents JavaScript access
    secure: true,        // HTTPS only
    sameSite: 'strict',  // CSRF protection
    maxAge: 1800000      // 30 minutes
});
```

#### Mobile Applications

**iOS (Keychain)**:
```swift
// Store in Keychain (secure)
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "jwt_token",
    kSecValueData as String: token.data(using: .utf8)!
]
SecItemAdd(query as CFDictionary, nil)
```

**Android (EncryptedSharedPreferences)**:
```java
// Use EncryptedSharedPreferences
EncryptedSharedPreferences.create(
    "secure_prefs",
    masterKey,
    context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
).edit()
.putString("jwt_token", token)
.apply();
```

---

## Security Guidelines by Framework

### Spring Boot (Java)

**Dependencies**:
```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>
```

**Configuration**:
```java
@Configuration
public class JWTConfig {
    @Value("${jwt.secret}")
    private String secret;

    @Bean
    public Key signingKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }
}
```

**Security Filter**:
```java
public class JWTAuthenticationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain) {
        String token = extractToken(request);
        if (token != null && validateToken(token)) {
            // Set authentication
        }
        filterChain.doFilter(request, response);
    }
}
```

---

### Django (Python)

**Package**: djangorestframework-simplejwt

**Installation**:
```bash
pip install djangorestframework-simplejwt
```

**Settings**:
```python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
}
```

---

### Express.js (Node.js)

**Package**: express-jwt

**Installation**:
```bash
npm install express-jwt jsonwebtoken
```

**Middleware**:
```javascript
const jwt = require('express-jwt');

app.use(jwt({
    secret: process.env.JWT_SECRET,
    algorithms: ['HS256'],
    credentialsRequired: true,
    getToken: (req) => {
        if (req.headers.authorization?.startsWith('Bearer ')) {
            return req.headers.authorization.substring(7);
        }
        return null;
    }
}));
```

---

### ASP.NET Core (C#)

**Configuration**:
```csharp
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = Configuration["Jwt:Issuer"],
            ValidAudience = Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(Configuration["Jwt:Secret"])
            ),
            ClockSkew = TimeSpan.Zero
        };
    });
```

---

## Training and Learning Resources

### Online Courses

**PortSwigger Web Security Academy**
- **URL**: https://portswigger.net/web-security
- **Cost**: Free
- **Labs**: Hands-on JWT exploitation
- **Certificate**: Available upon completion

**PentesterLab**
- **URL**: https://pentesterlab.com/
- **Cost**: Subscription
- **Content**: JWT-specific exercises

**HackTheBox**
- **URL**: https://www.hackthebox.com/
- **Focus**: Practical exploitation scenarios
- **Difficulty**: Various levels

---

### Practice Platforms

**Damn Vulnerable Web Application (DVWA)**
- JWT implementation vulnerabilities
- Practice environment

**WebGoat**
- OWASP educational platform
- JWT lesson modules

**Juice Shop**
- Modern vulnerable application
- JWT challenges included

---

### Conference Talks and Presentations

**"Attacking and Securing JWT" - OWASP Vancouver**
- **URL**: https://owasp.org/www-chapter-vancouver/assets/presentations/2020-01_Attacking_and_Securing_JWT.pdf
- **Topics**: Complete attack surface analysis

**"JWT Security Best Practices" - OWASP Belgium**
- **URL**: https://owasp.org/www-chapter-belgium/assets/2021/2021-02-18/JWT-Security.pdf
- **Focus**: Implementation security

---

### Books

**"Web Application Security" by Andrew Hoffman**
- Chapter on JWT security
- Practical examples

**"The Web Application Hacker's Handbook" by Dafydd Stuttard**
- Token-based authentication section
- Exploitation techniques

---

## Conclusion

This comprehensive resource guide provides:

1. **Official Standards**: RFCs and specifications
2. **Vulnerability Intelligence**: CVEs and advisories
3. **Testing Tools**: Comprehensive toolkit
4. **Research**: Academic and industry papers
5. **Best Practices**: Secure coding guidelines
6. **Framework Guidance**: Platform-specific security
7. **Learning Resources**: Training and practice

For security professionals conducting authorized testing, these resources enable:
- Comprehensive vulnerability assessment
- Exploitation of identified weaknesses
- Validation of security controls
- Development of secure implementations

**Always obtain proper authorization before testing any system.**
