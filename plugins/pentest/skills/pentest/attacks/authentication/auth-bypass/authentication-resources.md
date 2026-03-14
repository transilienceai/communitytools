# Authentication Security - Complete Resources Guide

## Table of Contents
1. [OWASP Documentation](#owasp-documentation)
2. [Industry Standards](#industry-standards)
3. [CVE Examples and Advisories](#cve-examples-and-advisories)
4. [Tools and Frameworks](#tools-and-frameworks)
5. [Research Papers and Articles](#research-papers-and-articles)
6. [Secure Coding Practices](#secure-coding-practices)
7. [Training Platforms](#training-platforms)
8. [Bug Bounty Programs](#bug-bounty-programs)
9. [Books and Guides](#books-and-guides)

---

## OWASP Documentation

### Core Resources

**OWASP Top 10**
- URL: https://owasp.org/www-project-top-ten/
- Broken Authentication was #2 in OWASP Top 10:2017
- Merged into "Identification and Authentication Failures" in 2021
- Critical security risk affecting millions of applications

**OWASP Authentication Cheat Sheet**
- URL: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- Comprehensive authentication implementation guidelines
- Password storage best practices
- Multi-factor authentication recommendations
- Session management security

**OWASP Session Management Cheat Sheet**
- URL: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- Session ID properties
- Secure cookie configuration
- Session lifecycle management
- Protection mechanisms

**OWASP Testing Guide - Authentication Testing**
- URL: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/
- WSTG-ATHN-01: Testing for Credentials Transported over Encrypted Channel
- WSTG-ATHN-02: Testing for Default Credentials
- WSTG-ATHN-03: Testing for Weak Lock Out Mechanism
- WSTG-ATHN-04: Testing for Bypassing Authentication Schema
- WSTG-ATHN-05: Testing for Vulnerable Remember Password
- WSTG-ATHN-06: Testing for Browser Cache Weaknesses
- WSTG-ATHN-07: Testing for Weak Password Policy
- WSTG-ATHN-08: Testing for Weak Security Question/Answer
- WSTG-ATHN-09: Testing for Weak Password Change or Reset
- WSTG-ATHN-10: Testing for Weaker Authentication in Alternative Channel

**OWASP Password Storage Cheat Sheet**
- URL: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Hashing algorithms (Argon2, bcrypt, scrypt, PBKDF2)
- Salting requirements
- Pepper usage
- Legacy system migration

**OWASP Forgot Password Cheat Sheet**
- URL: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- Token generation best practices
- URL vs form-based reset
- Security questions considerations

**OWASP Credential Stuffing Prevention**
- URL: https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html
- Multi-factor authentication
- Device fingerprinting
- CAPTCHA implementation
- IP blacklisting

### OWASP Projects

**OWASP ASVS (Application Security Verification Standard)**
- URL: https://owasp.org/www-project-application-security-verification-standard/
- V2: Authentication Verification Requirements
- V3: Session Management Verification Requirements
- Three levels: L1 (opportunistic), L2 (standard), L3 (advanced)

**OWASP Mobile Security Testing Guide**
- URL: https://owasp.org/www-project-mobile-security-testing-guide/
- MSTG-AUTH-1 through MSTG-AUTH-12
- Mobile-specific authentication challenges
- Biometric authentication testing

**OWASP ZAP (Zed Attack Proxy)**
- URL: https://www.zaproxy.org/
- Authentication testing automation
- Session management testing
- Built-in authentication scanner

---

## Industry Standards

### NIST (National Institute of Standards and Technology)

**NIST SP 800-63B: Digital Identity Guidelines - Authentication**
- URL: https://pages.nist.gov/800-63-3/sp800-63b.html
- Authenticator types and levels
- Password requirements (removed complexity requirements)
- Biometric authentication guidelines
- Federation and assertions

**Key Recommendations:**
- Minimum 8-character passwords
- No composition rules (e.g., requiring special characters)
- Allow all printable ASCII and Unicode characters
- Check against breach databases
- Rate limiting on authentication attempts
- Multi-factor authentication for sensitive operations

**NIST SP 800-63C: Federation and Assertions**
- URL: https://pages.nist.gov/800-63-3/sp800-63c.html
- OAuth 2.0 implementation
- OpenID Connect
- SAML 2.0 guidance

### PCI DSS (Payment Card Industry Data Security Standard)

**Requirement 8: Identify and Authenticate Access**
- URL: https://www.pcisecuritystandards.org/
- Multi-factor authentication for all access
- Strong password policies
- Lockout after failed attempts
- Session timeout requirements
- Secure transmission of authentication data

**Key Requirements:**
- 8.1: Define and implement policies for user identification
- 8.2: Strong authentication for all users
- 8.3: Multi-factor authentication for remote access
- 8.5: Do not use group, shared, or generic IDs
- 8.6: Use of other authentication mechanisms (tokens, biometrics)

### ISO/IEC 27001 and 27002

**ISO 27001:2022 - Information Security Management**
- Authentication and access control requirements
- Annex A.9: Access Control
- User access management
- User authentication requirements

**ISO 27002:2022 - Code of Practice**
- A.9.2: User access management
- A.9.4: System and application access control
- Authentication mechanisms
- Password management systems

### CIS Controls

**CIS Control 6: Access Control Management**
- URL: https://www.cisecurity.org/controls
- 6.1: Establish an Access Granting Process
- 6.2: Establish an Access Revoking Process
- 6.3: Require MFA
- 6.4: Require MFA for Remote Network Access
- 6.5: Require MFA for Administrative Access

---

## CVE Examples and Advisories

### Critical Authentication Bypass Vulnerabilities (2024-2025)

**CVE-2025-0282 - Ivanti Connect Secure VPN Authentication Bypass**
- CVSS: 9.0 (Critical)
- Type: Authentication bypass
- Impact: Remote attackers can bypass authentication
- Exploited: Active exploitation in the wild
- Affected: Ivanti Connect Secure VPN appliances
- Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**CVE-2025-61882 - Oracle E-Business Suite Authentication Bypass**
- CVSS: 9.8 (Critical)
- Type: Zero-day authentication bypass
- Impact: Unauthenticated remote code execution
- Exploited: By Clop ransomware gang
- Affected: Oracle EBS installations
- Organizations impacted: GlobalLogic, Barts Health NHS
- Source: https://socradar.io/blog/top-10-cves-of-2025-vulnerabilities-trends/

**CVE-2025-10035 - FortiWeb Authentication Bypass via Path Traversal**
- CVSS: 9.8 (Critical)
- Type: Authentication bypass through path traversal
- Impact: Complete system compromise
- Status: Actively exploited, CISA KEV listed
- Affected: FortiWeb appliances
- Source: https://www.cyberinfos.in/top-16-most-exploited-cves-of-2025/

**CVE-2024-3400 - Palo Alto PAN-OS Command Injection**
- CVSS: 10.0 (Critical)
- Type: Authentication bypass leading to RCE
- Impact: Full system compromise
- Exploited: By nation-state actors
- Affected: PAN-OS versions with GlobalProtect
- Source: Multiple security advisories

### OAuth and SSO Vulnerabilities

**CVE-2020-28196 - Kraken Kratos OAuth Flow Bypass**
- Type: OAuth 2.0 implementation flaw
- Impact: Account takeover via redirect_uri manipulation
- Affected: Ory Kratos identity server
- Lesson: Improper redirect_uri validation

**CVE-2019-11510 - Pulse Secure VPN Pre-Auth File Read**
- CVSS: 10.0 (Critical)
- Type: Authentication bypass + arbitrary file read
- Impact: Full VPN credential disclosure
- Exploited: Widely exploited, led to multiple breaches
- Source: https://nvd.nist.gov/vuln/detail/CVE-2019-11510

**CVE-2021-22893 - Pulse Secure Authentication Bypass**
- CVSS: 10.0 (Critical)
- Type: Complete authentication bypass
- Impact: Unauthenticated access to admin interface
- Exploited: Active exploitation by APT groups

### JWT and Token Vulnerabilities

**CVE-2018-1000531 - Tendermint JWT Authentication Bypass**
- Type: JWT signature verification bypass
- Impact: Authentication bypass via 'none' algorithm
- Lesson: Always validate JWT algorithm

**CVE-2020-8912 - AWS S3 Crypto SDK Authentication Bypass**
- Type: Authentication tag bypass
- Impact: Decryption of encrypted S3 objects
- Lesson: Proper cryptographic implementation critical

### Password Reset Vulnerabilities

**CVE-2020-5902 - F5 BIG-IP TMUI RCE**
- CVSS: 10.0 (Critical)
- Type: Authentication bypass via directory traversal
- Impact: Remote code execution without authentication
- Lesson: Validate all user input in authentication flows

**CVE-2019-8446 - Apache Airflow Authentication Bypass**
- Type: Default credentials + authentication bypass
- Impact: Full system access
- Lesson: Never ship default credentials

### Multi-Factor Authentication Bypasses

**CVE-2024-47575 - FortiManager Missing Authentication**
- CVSS: 9.8 (Critical)
- Type: Missing authentication check
- Impact: Remote code execution
- Exploited: Active exploitation observed
- Source: CISA KEV catalog

**CVE-2023-46747 - F5 BIG-IP Configuration Utility Auth Bypass**
- CVSS: 9.8 (Critical)
- Type: Authentication bypass
- Impact: Arbitrary system commands
- Status: Actively exploited

### Real-World Authentication Breaches

**Oracle Cloud Single Sign-On Breach (2025)**
- Records: ~6 million
- Method: Compromise of SSO and LDAP systems
- Data: Java KeyStore files, encrypted passwords, key files
- Impact: Massive credential exposure
- Source: https://strobes.co/blog/top-data-breaches-in-2025-month-wise/

**Internet Archive Breach (2024)**
- Records: 31+ million user accounts
- Method: Exposed GitLab configuration file
- Data: Emails, usernames, Bcrypt-hashed passwords
- Size: 6.4 GB database
- Lesson: Configuration security critical

**Jaguar Land Rover Breach (2025)**
- Method: Single stolen employee credential from stealer log
- Impact: Access to engineering databases and code repositories
- Date: August 31, 2025
- Lesson: Single credential can compromise entire network

**Cleo File Transfer Platform Attacks (2024)**
- Attacker: Clop ransomware gang
- Method: Zero-day authentication bypass
- Organizations: Multiple, including Hertz (1M+ individuals)
- Lesson: Supply chain security critical

### Government Advisories

**CISA Known Exploited Vulnerabilities (KEV) Catalog**
- URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Continuously updated list of exploited vulnerabilities
- Many authentication-related CVEs
- Required remediation for federal agencies

**NSA Cybersecurity Advisories**
- URL: https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/
- Multi-factor authentication guidance
- Password security recommendations
- Zero Trust architecture

---

## Tools and Frameworks

### Burp Suite Extensions

**Authentication Tools**
- **Autorize**: https://github.com/Quitten/Autorize
  - Automatic authorization testing
  - Detect broken access control
  - Test authentication bypass

- **AuthMatrix**: https://github.com/SecurityInnovation/AuthMatrix
  - Role-based access control testing
  - Multi-user authentication testing
  - Visual matrix of permissions

- **Turbo Intruder**: https://github.com/PortSwigger/turbo-intruder
  - High-speed brute-force attacks
  - Custom Python scripts
  - Race condition testing

- **JSON Web Tokens**: https://github.com/portswigger/json-web-tokens
  - JWT manipulation and testing
  - Algorithm confusion attacks
  - Signature verification bypass

- **SessionAuth**: https://github.com/PortSwigger/session-auth
  - Session management testing
  - Authentication flow analysis
  - Cookie security analysis

### Command-Line Tools

**Hydra - Network Login Cracker**
```bash
# Installation
sudo apt install hydra

# Examples
hydra -L users.txt -P passwords.txt https-post-form://target.com/login:"username=^USER^&password=^PASS^:Invalid"
hydra -l admin -P rockyou.txt ssh://target.com
hydra -l user@domain.com -P passwords.txt imap://mail.server.com
```
- URL: https://github.com/vanhauser-thc/thc-hydra
- Protocols: HTTP(S), FTP, SSH, IMAP, SMB, etc.
- Parallel brute-forcing
- Flexible login patterns

**Patator - Multi-Purpose Brute-Forcer**
```bash
# Installation
pip install patator

# HTTP form
patator http_fuzz url=http://target.com/login method=POST \
  body='username=FILE0&password=FILE1' 0=users.txt 1=passwords.txt \
  -x ignore:fgrep='Invalid'

# SSH
patator ssh_login host=target.com user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt
```
- URL: https://github.com/lanjelot/patator
- Modular design
- Multiple protocols
- Custom response analysis

**CrackMapExec - Network Authentication Testing**
```bash
# Installation
sudo apt install crackmapexec

# Examples
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt
crackmapexec winrm 192.168.1.100 -u admin -p passwords.txt
crackmapexec ssh 192.168.1.0/24 -u root -p passwords.txt
```
- URL: https://github.com/byt3bl33d3r/CrackMapExec
- Active Directory enumeration
- Password spraying
- Credential validation

**Medusa - Parallel Network Login Brute-Forcer**
```bash
# Installation
sudo apt install medusa

# Examples
medusa -h target.com -u admin -P passwords.txt -M http
medusa -H hosts.txt -U users.txt -P passwords.txt -M ssh
```
- URL: https://github.com/jmk-foofus/medusa
- Parallel testing
- Multiple protocols
- Module-based architecture

**OAuth0 - OAuth 2.0 Testing**
```bash
# Installation
npm install -g oauth0

# Test OAuth flow
oauth0 --client-id CLIENT_ID --auth-url https://oauth-server.com/auth
```
- OAuth 2.0 flow testing
- Token manipulation
- Flow visualization

### Password Analysis

**zxcvbn - Password Strength Estimator**
```javascript
// JavaScript
const zxcvbn = require('zxcvbn');
const result = zxcvbn('password123');
console.log(result.score); // 0-4
console.log(result.feedback);
```
- URL: https://github.com/dropbox/zxcvbn
- Realistic password strength
- Pattern matching
- User feedback

**Have I Been Pwned API**
```python
import hashlib
import requests

def check_password(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    return suffix in response.text
```
- URL: https://haveibeenpwned.com/API/v3
- Check for breached passwords
- k-anonymity model
- Free API access

### JWT Tools

**jwt_tool - JWT Security Testing**
```bash
# Installation
pip install pyjwt

# Test JWT
python3 jwt_tool.py <JWT> -X a  # All attacks
python3 jwt_tool.py <JWT> -X s  # Signature tests
python3 jwt_tool.py <JWT> -T    # Tamper
```
- URL: https://github.com/ticarpi/jwt_tool
- Comprehensive JWT testing
- Automated attacks
- Token manipulation

**JWT.io Debugger**
- URL: https://jwt.io/
- Online JWT decoder
- Signature verification
- Token generation

### Framework-Specific Tools

**Django Debug Toolbar**
- Session analysis
- Authentication backend inspection
- Security warnings

**Rails Session Cookie Manager**
- Session decoding
- Cookie manipulation
- CSRF token analysis

**Spring Security Test**
- Authentication testing
- Method security testing
- Mock authentication

---

## Research Papers and Articles

### Seminal Research

**"The Quest to Replace Passwords" - Joseph Bonneau et al. (2012)**
- URL: https://www.cl.cam.ac.uk/~fms27/papers/2012-BonneauHerOorSta-password--Oakland.pdf
- Comprehensive analysis of authentication schemes
- Usability vs security trade-offs
- Evaluation framework

**"Authentication in an Internet Banking Environment" (2000)**
- Early analysis of online banking authentication
- Multi-factor authentication necessity
- Risk-based authentication

**"Passwords and the Evolution of Imperfect Authentication" (2015)**
- URL: https://cacm.acm.org/magazines/2015/7/188829-passwords-and-the-evolution-of-imperfect-authentication/
- History of password authentication
- Future of authentication
- Biometric considerations

### OAuth and Federation

**"OAuth 2.0 Security Best Current Practice" - IETF Draft**
- URL: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
- Known attack vectors
- Mitigation strategies
- Implementation guidance

**"An Extensive Formal Security Analysis of the OpenID Financial-Grade API" (2021)**
- Formal verification of FAPI
- Security proofs
- Attack scenarios

**"The Devil is in the (Implementation) Details: An Empirical Analysis of OAuth SSO Systems" (2016)**
- Real-world OAuth vulnerabilities
- Common implementation mistakes
- Case studies of major providers

### Multi-Factor Authentication

**"Secrets, Lies, and Account Recovery: Lessons from the Use of Personal Knowledge Questions at Google" (2015)**
- URL: https://research.google/pubs/pub43783/
- Security question weakness
- Real-world attack success rates
- Better alternatives

**"Security Analysis of Account Recovery in Mobile Banking Apps" (2021)**
- Mobile-specific authentication challenges
- SMS-based 2FA vulnerabilities
- Recommendations

**"Two-Factor Authentication: Practical Experience" (2020)**
- Large-scale 2FA deployment
- User adoption challenges
- Security improvements

### Password Security

**"Fast Dictionary Attacks on Passwords Using Time-Space Tradeoff" (2005)**
- Rainbow table attacks
- Salting necessity
- Computational requirements

**"On the Security of Password Manager Database Formats" (2014)**
- Password manager security analysis
- Master password vulnerabilities
- Best practices

**"The Tangled Web of Password Reuse" (2014)**
- Credential stuffing analysis
- Password reuse statistics
- User behavior patterns

### Biometric Authentication

**"Biometric Authentication on iPhone and Android: Usability, Perceptions, and Influences on Adoption" (2019)**
- Mobile biometric adoption
- User trust and concerns
- Security vs usability

**"SoK: Making Sense of Biometric Image Preprocessing" (2021)**
- Biometric template attacks
- Liveness detection
- Spoofing techniques

### Industry Reports

**Verizon Data Breach Investigations Report (Annual)**
- URL: https://www.verizon.com/business/resources/reports/dbir/
- Credential theft statistics
- Attack patterns and trends
- Real-world case studies

**Microsoft Security Intelligence Report**
- Password spray attacks
- Credential phishing
- MFA effectiveness statistics

**Google Security Blog - Authentication Research**
- URL: https://security.googleblog.com/
- Real-world attack data
- Security key effectiveness
- User behavior studies

---

## Secure Coding Practices

### General Principles

**Never Trust User Input**
```python
# Bad - Direct string concatenation
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

# Good - Parameterized queries
query = "SELECT * FROM users WHERE username=? AND password=?"
cursor.execute(query, (username, password_hash))
```

**Defense in Depth**
- Multiple layers of security
- Assume each layer can be bypassed
- Redundant controls

**Principle of Least Privilege**
- Minimal permissions by default
- Grant additional access only when needed
- Regular access reviews

**Fail Securely**
```python
# Bad - Fails open
try:
    if authenticate(user, password):
        return True
except:
    return True  # Dangerous!

# Good - Fails closed
try:
    if authenticate(user, password):
        return True
except:
    log_security_event("Authentication error")
    return False
```

### Password Storage

**Use Strong Hashing Algorithms**
```python
import hashlib
import os

# Bad - MD5/SHA1 (too fast)
password_hash = hashlib.md5(password.encode()).hexdigest()

# Good - Argon2 (recommended)
from argon2 import PasswordHasher
ph = PasswordHasher()
password_hash = ph.hash(password)
verified = ph.verify(password_hash, password)

# Good - bcrypt
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
verified = bcrypt.checkpw(password.encode(), password_hash)

# Good - scrypt
from hashlib import scrypt
salt = os.urandom(16)
password_hash = scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
```

**Always Use Salt**
```python
import os
import hashlib

# Bad - No salt (rainbow table attack)
password_hash = hashlib.sha256(password.encode()).hexdigest()

# Good - Random salt per user
salt = os.urandom(32)
password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

# Store both salt and hash
db.store(username=username, salt=salt, password_hash=password_hash)
```

**Consider Using Pepper**
```python
# Additional secret stored separately from database
PEPPER = os.environ.get('PASSWORD_PEPPER')  # From environment

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode() + PEPPER.encode(),
        salt,
        100000
    )
```

### Session Management

**Secure Cookie Configuration**
```python
# Flask
app.config.update(
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # No JavaScript access
    SESSION_COOKIE_SAMESITE='Strict', # CSRF protection
    PERMANENT_SESSION_LIFETIME=3600   # 1 hour timeout
)

# Django
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 3600
```

**Session ID Generation**
```python
import secrets

# Bad - Predictable
session_id = str(int(time.time()))

# Good - Cryptographically random
session_id = secrets.token_urlsafe(32)  # 256 bits
```

**Session Fixation Prevention**
```python
# Regenerate session ID after login
def login(username, password):
    if verify_credentials(username, password):
        old_session_id = session.sid
        session.regenerate()  # New session ID
        log_security_event(f"Session regenerated: {old_session_id} -> {session.sid}")
        return True
    return False
```

### Multi-Factor Authentication

**TOTP Implementation**
```python
import pyotp

# Generate secret (during enrollment)
secret = pyotp.random_base32()

# Generate QR code for user
provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
    name=username,
    issuer_name='YourApp'
)

# Verify code (during login)
totp = pyotp.TOTP(secret)
if totp.verify(user_code, valid_window=1):  # Allow 30s window
    print("Valid code")
else:
    print("Invalid code")
```

**Backup Codes**
```python
import secrets

def generate_backup_codes(count=10):
    codes = []
    for _ in range(count):
        code = '-'.join([secrets.token_hex(4) for _ in range(2)])
        codes.append(code)
    return codes

# Hash codes before storing
hashed_codes = [hashlib.sha256(code.encode()).hexdigest() for code in codes]
db.store(user_id=user_id, backup_codes=hashed_codes)
```

### OAuth Implementation

**State Parameter (CSRF Protection)**
```python
import secrets
from flask import session, redirect

@app.route('/oauth/authorize')
def oauth_authorize():
    # Generate and store state
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state

    # Build authorization URL
    auth_url = f"https://oauth-provider.com/auth?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state={state}"
    return redirect(auth_url)

@app.route('/oauth/callback')
def oauth_callback():
    # Verify state
    received_state = request.args.get('state')
    expected_state = session.get('oauth_state')

    if not secrets.compare_digest(received_state, expected_state):
        abort(403, "Invalid state parameter")

    # Continue with OAuth flow
```

**redirect_uri Validation**
```python
ALLOWED_REDIRECTS = [
    "https://app.example.com/oauth/callback",
    "https://mobile.example.com/oauth/callback"
]

def validate_redirect_uri(redirect_uri):
    # Exact match only
    if redirect_uri not in ALLOWED_REDIRECTS:
        raise ValueError("Invalid redirect_uri")

    # Additional checks
    parsed = urllib.parse.urlparse(redirect_uri)

    # Must be HTTPS
    if parsed.scheme != 'https':
        raise ValueError("redirect_uri must use HTTPS")

    # Must be our domain
    if not parsed.netloc.endswith('.example.com'):
        raise ValueError("redirect_uri must be example.com domain")

    return True
```

### Password Reset

**Secure Token Generation**
```python
import secrets
import hashlib
from datetime import datetime, timedelta

def generate_reset_token(user_id):
    # Generate cryptographically secure token
    token = secrets.token_urlsafe(32)

    # Hash before storing
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    # Store with expiration
    expiry = datetime.now() + timedelta(hours=1)
    db.store_reset_token(
        user_id=user_id,
        token_hash=token_hash,
        expiry=expiry
    )

    return token  # Send to user via email

def verify_reset_token(token, user_id):
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    record = db.get_reset_token(token_hash=token_hash)

    if not record:
        return False

    # Verify user ID
    if record.user_id != user_id:
        return False

    # Check expiration
    if datetime.now() > record.expiry:
        db.delete_reset_token(token_hash)
        return False

    # Delete token after use (single-use)
    db.delete_reset_token(token_hash)
    return True
```

**Host Header Validation**
```python
ALLOWED_HOSTS = ['app.example.com', 'www.example.com']

def generate_reset_url(token):
    # Use configured base URL, not Host header
    base_url = app.config['BASE_URL']  # From configuration
    return f"{base_url}/reset-password?token={token}"

def validate_host_header(request):
    host = request.headers.get('Host')

    if host not in ALLOWED_HOSTS:
        abort(400, "Invalid Host header")

    return True
```

### Framework-Specific Examples

**Django**
```python
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})

    return render(request, 'login.html')

@login_required
def protected_view(request):
    return render(request, 'protected.html')
```

**Flask**
```python
from flask import Flask, session, redirect, url_for
from flask_login import LoginManager, login_user, login_required, current_user
from werkzeug.security import check_password_hash

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        login_user(user)
        return redirect(url_for('dashboard'))

    return render_template('login.html', error='Invalid credentials')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')
```

**Express.js**
```javascript
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,      // HTTPS only
        httpOnly: true,    // No JavaScript access
        sameSite: 'strict', // CSRF protection
        maxAge: 3600000    // 1 hour
    }
}));

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await db.getUserByUsername(username);

    if (user && await bcrypt.compare(password, user.password_hash)) {
        req.session.regenerate((err) => {
            if (err) return res.status(500).send('Error');

            req.session.userId = user.id;
            res.redirect('/dashboard');
        });
    } else {
        res.render('login', { error: 'Invalid credentials' });
    }
});

function requireAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

app.get('/dashboard', requireAuth, (req, res) => {
    res.render('dashboard');
});
```

### Input Validation

**Username Validation**
```python
import re

def validate_username(username):
    # Length check
    if not 3 <= len(username) <= 30:
        raise ValueError("Username must be 3-30 characters")

    # Character whitelist
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        raise ValueError("Username contains invalid characters")

    # Reserved names
    RESERVED_NAMES = ['admin', 'root', 'system', 'administrator']
    if username.lower() in RESERVED_NAMES:
        raise ValueError("Username is reserved")

    return True
```

**Password Validation**
```python
import zxcvbn

def validate_password(password, user_inputs=[]):
    # Minimum length
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")

    # Maximum length (prevent DoS via bcrypt)
    if len(password) > 128:
        raise ValueError("Password too long")

    # Check against breached passwords
    if is_password_breached(password):
        raise ValueError("Password has been exposed in a data breach")

    # Strength check
    result = zxcvbn.zxcvbn(password, user_inputs=user_inputs)
    if result['score'] < 3:
        raise ValueError(f"Password too weak: {result['feedback']['warning']}")

    return True
```

---

## Training Platforms

### Interactive Labs

**PortSwigger Web Security Academy**
- URL: https://portswigger.net/web-security
- Free interactive labs
- Authentication section with 21+ labs
- Progressive difficulty (Apprentice → Practitioner → Expert)
- Real-world scenarios
- Detailed solutions and explanations

**OWASP WebGoat**
- URL: https://owasp.org/www-project-webgoat/
- Open-source learning platform
- Authentication lessons
- Hands-on challenges
- Self-paced learning

**DVWA (Damn Vulnerable Web Application)**
- URL: https://github.com/digininja/DVWA
- Deliberately vulnerable PHP/MySQL application
- Brute-force challenges
- Authentication bypass scenarios
- Different difficulty levels

**bWAPP (Buggy Web Application)**
- URL: http://www.itsecgames.com/
- 100+ vulnerabilities
- Authentication challenges
- Session management issues
- OAuth vulnerabilities

**HackTheBox**
- URL: https://www.hackthebox.com/
- Vulnerable machines and challenges
- Authentication-focused boxes
- Active community
- Certification program (CPTS)

**TryHackMe**
- URL: https://tryhackme.com/
- Guided learning paths
- Authentication security room
- Web application security
- Beginner-friendly

**PentesterLab**
- URL: https://pentesterlab.com/
- Professional pentesting training
- Web authentication exercises
- OAuth security course
- JWT exploitation

**Hack The Box Academy**
- URL: https://academy.hackthebox.com/
- Structured learning paths
- Authentication modules
- Certification prep
- Industry-recognized skills

### Certification Preparation

**Burp Suite Certified Practitioner (BSCP)**
- URL: https://portswigger.net/web-security/certification
- Focus: Web application security
- Requires: All Apprentice and Practitioner labs
- Format: Practical exam
- Duration: 4 hours
- Authentication testing: Critical skill area

**Offensive Security Web Expert (OSWE)**
- URL: https://www.offensive-security.com/awae-oswe/
- Advanced web application testing
- Source code analysis
- Custom exploit development
- Authentication bypass techniques

**Certified Ethical Hacker (CEH)**
- URL: https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/
- Broad security knowledge
- Password cracking
- Session hijacking
- Authentication testing

**GIAC Web Application Penetration Tester (GWAPT)**
- URL: https://www.giac.org/certifications/web-application-penetration-tester-gwapt/
- Web application security focus
- Authentication testing
- Session management
- Detailed technical knowledge

---

## Bug Bounty Programs

### Major Platforms

**HackerOne**
- URL: https://www.hackerone.com/
- Largest bug bounty platform
- Authentication vulnerabilities: Common finding
- Severity ratings: Critical to Low
- Average payout: $1,000-$10,000 for auth bypasses

**Bugcrowd**
- URL: https://www.bugcrowd.com/
- Global platform
- Authentication issues: High priority
- Disclosure coordination
- Training resources

**Synack**
- URL: https://www.synack.com/
- Vetted researchers only
- Government and enterprise clients
- Authentication testing: Core skill
- Consistent payouts

**Intigriti**
- URL: https://www.intigriti.com/
- European focus
- Authentication vulnerabilities accepted
- Quick triage
- Educational resources

### Company Programs

**Google Vulnerability Reward Program (VRP)**
- URL: https://bughunters.google.com/
- Maximum payout: $31,337+ for auth bypass
- Scope: Gmail, Google Cloud, Android, Chrome
- Authentication issues: Frequently rewarded

**Facebook Bug Bounty**
- URL: https://www.facebook.com/whitehat
- Historical authentication findings: $10,000-$40,000
- OAuth vulnerabilities: High value
- Fast response times

**Microsoft Bug Bounty Programs**
- URL: https://www.microsoft.com/en-us/msrc/bounty
- Multiple programs: Azure, Office 365, Windows
- Identity and authentication bounties
- Up to $100,000 for critical findings

**Apple Security Bounty**
- URL: https://support.apple.com/en-us/HT201220
- Authentication bypass: Up to $100,000
- iCloud, Apple ID security
- iOS and macOS authentication

**GitHub Security Bug Bounty**
- URL: https://bounty.github.com/
- Authentication vulnerabilities: High priority
- OAuth implementation focus
- $500-$30,000 range

### Authentication-Specific Findings

**Common High-Value Reports:**
- OAuth authentication bypass: $5,000-$25,000
- 2FA bypass: $5,000-$20,000
- Password reset token manipulation: $3,000-$10,000
- Session fixation: $1,000-$5,000
- Username enumeration: $500-$2,000 (if impactful)

**Writing Effective Reports:**
1. Clear vulnerability description
2. Step-by-step reproduction steps
3. Proof-of-concept code or screenshots
4. Impact assessment
5. Suggested remediation
6. Test environment details

---

## Books and Guides

### Essential Reading

**"The Web Application Hacker's Handbook" (2nd Edition)**
- Authors: Dafydd Stuttard, Marcus Pinto
- Publisher: Wiley
- ISBN: 978-1118026472
- Chapters 6-7: Authentication
- Comprehensive attack techniques
- Real-world examples

**"OWASP Testing Guide v4"**
- URL: https://owasp.org/www-project-web-security-testing-guide/
- Free online resource
- Authentication testing methodology
- Detailed test cases
- Tool recommendations

**"Security Engineering" (3rd Edition)**
- Author: Ross Anderson
- Publisher: Wiley
- ISBN: 978-1119642787
- Chapter 3: Passwords
- Authentication protocols
- Theoretical foundations

**"Real-World Bug Hunting"**
- Author: Peter Yaworski
- Publisher: No Starch Press
- ISBN: 978-1593278618
- Authentication bypass case studies
- Bug bounty perspectives
- Practical techniques

**"Web Security Testing Cookbook"**
- Authors: Paco Hope, Ben Walther
- Publisher: O'Reilly
- ISBN: 978-0596514839
- Authentication testing recipes
- Session management
- Tool usage

**"Bulletproof SSL and TLS"**
- Author: Ivan Ristić
- Publisher: Feisty Duck
- ISBN: 978-1907117046
- Secure authentication transmission
- TLS configurations
- Certificate validation

### OAuth and Federation

**"OAuth 2.0 Simplified"**
- Author: Aaron Parecki
- URL: https://oauth2simplified.com/
- Clear OAuth explanations
- Implementation examples
- Security best practices

**"OAuth 2 in Action"**
- Authors: Justin Richer, Antonio Sanso
- Publisher: Manning
- ISBN: 978-1617293276
- In-depth OAuth coverage
- Real-world scenarios
- OpenID Connect

### Password Security

**"Password Security: A Case History"**
- Author: Robert Morris, Ken Thompson
- Classic UNIX password paper
- Historical perspective
- Cryptographic approach

**"The Science of Guessing: Analyzing an Anonymized Corpus of 70 Million Passwords"**
- Authors: Joseph Bonneau et al.
- Research paper
- Password distribution analysis
- Attack effectiveness

---

## Community Resources

### Forums and Communities

**PortSwigger Forum**
- URL: https://forum.portswigger.net/
- Lab discussions
- Technique sharing
- Expert guidance

**OWASP Slack**
- URL: https://owasp.org/slack/invite
- Real-time discussions
- Project channels
- Global community

**Reddit**
- r/netsec: https://reddit.com/r/netsec
- r/websecurity: https://reddit.com/r/websecurity
- r/bugbounty: https://reddit.com/r/bugbounty
- r/AskNetsec: https://reddit.com/r/AskNetsec

**Discord Servers**
- Bug Bounty Forum
- HackTheBox
- TryHackMe
- Nahamsec's Discord

### Twitter Security Community

**Key Accounts to Follow:**
- @PortSwiggerNet - PortSwigger updates
- @OWASP - OWASP Foundation
- @NahamSec - Bug bounty tips
- @stokfredrik - Web security research
- @albinowax - Burp Suite research lead
- @samwcyo - Authentication research
- @avlidienbrunn - XSS and auth research

### YouTube Channels

**IppSec**
- HackTheBox walkthroughs
- Authentication exploit examples
- Detailed explanations

**LiveOverflow**
- Web security concepts
- Authentication mechanism analysis
- CTF walkthroughs

**STÖK**
- Bug bounty hunting
- Authentication bypass techniques
- Hacker interviews

**Nahamsec**
- Web application security
- Authentication testing
- Tool demonstrations

**John Hammond**
- Security challenges
- Authentication exploits
- Educational content

---

## Quick Reference Links

### Official Documentation
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- NIST Guidelines: https://pages.nist.gov/800-63-3/
- OAuth 2.0 RFC: https://tools.ietf.org/html/rfc6749
- OpenID Connect: https://openid.net/connect/
- JWT RFC: https://tools.ietf.org/html/rfc7519

### Lab Platforms
- PortSwigger Academy: https://portswigger.net/web-security
- OWASP WebGoat: https://owasp.org/www-project-webgoat/
- HackTheBox: https://www.hackthebox.com/
- TryHackMe: https://tryhackme.com/

### Tools
- Burp Suite: https://portswigger.net/burp
- OWASP ZAP: https://www.zaproxy.org/
- Hydra: https://github.com/vanhauser-thc/thc-hydra
- SecLists: https://github.com/danielmiessler/SecLists

### Vulnerability Databases
- CVE Database: https://cve.mitre.org/
- NVD: https://nvd.nist.gov/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Exploit-DB: https://www.exploit-db.com/

---

*Comprehensive resource guide for mastering authentication security*
*Updated January 2026*
