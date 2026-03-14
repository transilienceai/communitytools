# OAuth Authentication - Resources and References

## Table of Contents
1. [OWASP Documentation](#owasp-documentation)
2. [Industry Standards](#industry-standards)
3. [CVE Database & Security Advisories](#cve-database--security-advisories)
4. [Tools & Frameworks](#tools--frameworks)
5. [Research Papers & Technical Articles](#research-papers--technical-articles)
6. [Secure Coding Practices](#secure-coding-practices)
7. [Training Platforms](#training-platforms)
8. [Bug Bounty Programs](#bug-bounty-programs)

---

## OWASP Documentation

### OAuth 2.0 Security Cheat Sheet
**URL**: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html

**Key Topics**:
- OAuth 2.0 security best practices
- Authorization code flow with PKCE implementation
- Token management and validation
- Redirect URI validation requirements
- State parameter usage for CSRF protection
- Scope validation and least privilege
- Audience restriction for access tokens

**Critical Recommendations**:
- Use authorization code flow with PKCE for all client types
- Never use implicit flow for new implementations
- Implement sender-constrained access tokens (mTLS or DPoP)
- Use short-lived access tokens with refresh token rotation
- Validate state parameter on every authorization request
- Restrict redirect_uri to exact matches only

---

### OWASP OAuth Weaknesses Testing Guide
**URL**: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses

**Testing Areas**:
1. **Authorization Code Interception**
   - redirect_uri manipulation
   - Open redirect vulnerabilities
   - Authorization code replay attacks

2. **CSRF Attacks**
   - Missing state parameter
   - Weak state generation
   - State not bound to session

3. **Token Leakage**
   - Implicit flow vulnerabilities
   - Token exposure in logs
   - Referer header leakage

4. **Client Impersonation**
   - Weak client authentication
   - Client secret exposure
   - Client ID enumeration

5. **Scope Manipulation**
   - Scope escalation
   - Insufficient scope validation
   - Scope downgrade attacks

**Testing Methodology**:
```
1. Information Gathering
   - Identify OAuth endpoints
   - Map OAuth flow type
   - Document parameters

2. Configuration Testing
   - Test redirect_uri validation
   - Check state parameter presence
   - Verify PKCE implementation

3. Vulnerability Testing
   - Authorization code theft
   - Token leakage scenarios
   - CSRF attacks
   - Scope manipulation

4. Client Security
   - Client secret protection
   - Client authentication strength
   - Dynamic registration vulnerabilities
```

---

### OWASP Authentication Cheat Sheet
**URL**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

**OAuth-Specific Guidance**:
- Use OAuth 2.0 and OpenID Connect for authentication
- Implement proper token validation
- Secure token storage mechanisms
- Session management with OAuth tokens
- Multi-factor authentication integration

---

## Industry Standards

### OAuth 2.0 Framework (RFC 6749)
**URL**: https://tools.ietf.org/html/rfc6749

**Core Specifications**:
- Authorization code grant
- Implicit grant (deprecated)
- Resource owner password credentials grant
- Client credentials grant
- Extension grants

**Key Security Considerations**:
- Section 10: Security Considerations
  - Client authentication
  - Token endpoint security
  - Refresh token protection
  - Authorization code security

---

### OAuth 2.0 Security Best Current Practice (RFC 9700)
**URL**: https://datatracker.ietf.org/doc/html/rfc9700

**Updated Recommendations (2024)**:
- **PKCE is mandatory** for all OAuth clients (public and confidential)
- **Implicit grant is deprecated** - do not use
- **Resource Owner Password Credentials grant is deprecated**
- Exact redirect URI matching required
- Sender-constrained tokens recommended
- Short-lived access tokens (seconds to minutes)
- Refresh token rotation for public clients

**Browser-Based Apps**:
- Use authorization code flow with PKCE
- Store tokens in memory only (not localStorage)
- Backend-for-frontend pattern for sensitive operations
- Implement token binding where possible

---

### PKCE for OAuth Public Clients (RFC 7636)
**URL**: https://tools.ietf.org/html/rfc7636

**Proof Key for Code Exchange**:
- Protects against authorization code interception
- Required for public clients (mobile, SPA)
- Recommended for confidential clients

**Implementation**:
```python
# code_verifier: random string (43-128 characters)
code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')

# code_challenge: BASE64URL(SHA256(code_verifier))
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode('utf-8')).digest()
).decode('utf-8').rstrip('=')

# Authorization request includes:
# code_challenge=CHALLENGE&code_challenge_method=S256

# Token request includes:
# code_verifier=VERIFIER
```

---

### OAuth 2.1 Authorization Framework (Draft)
**URL**: https://oauth.net/2.1/

**Consolidates Best Practices**:
- Incorporates security best practices
- Makes PKCE mandatory
- Removes implicit grant
- Removes password grant
- Requires exact redirect_uri matching
- Mandates short token lifetimes

**Timeline**: Expected to replace RFC 6749/6750 when finalized

---

### OpenID Connect Core 1.0
**URL**: https://openid.net/specs/openid-connect-core-1_0.html

**Identity Layer on OAuth 2.0**:
- ID tokens (JWT format)
- UserInfo endpoint
- Standard claims
- Multiple authentication flows

**Security Features**:
- `nonce` parameter for replay protection
- `at_hash` for token validation
- `c_hash` for code validation
- Session management specifications

---

### OAuth for Native Apps (RFC 8252)
**URL**: https://tools.ietf.org/html/rfc8252

**Mobile App Best Practices**:
- Use system browser (not embedded WebView)
- Custom URI schemes with claimed HTTPS schemes
- Implement PKCE
- Protect redirect URIs
- Secure token storage (keychain/keystore)

---

### OAuth 2.0 Mutual-TLS Client Authentication (RFC 8705)
**URL**: https://tools.ietf.org/html/rfc8705

**Sender-Constrained Tokens**:
- Bind tokens to TLS client certificates
- Prevents token theft attacks
- Stronger client authentication
- Mitigates token replay

---

### OAuth 2.0 Demonstration of Proof-of-Possession (DPoP)
**URL**: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop

**Alternative to mTLS**:
- Token binding using cryptographic proof
- Public/private key pairs
- Signed JWT proof
- Works without client certificates

---

## CVE Database & Security Advisories

### National Vulnerability Database (NVD)
**URL**: https://nvd.nist.gov/

**Search Queries**:
- `OAuth 2.0`
- `OpenID Connect`
- `OAuth redirect_uri`
- `OAuth authorization code`

---

### Notable OAuth CVEs

#### CVE-2023-28131 - Expo OAuth Framework
**Severity**: Critical (CVSS 9.8)
**Affected**: Expo framework's expo-auth-session library
**Vulnerability**: Authorization code interception
**Impact**: Hundreds of mobile applications affected
**Fix**: Updated to version with proper redirect_uri validation
**Reference**: https://salt.security/blog/a-new-oauth-vulnerability-that-may-impact-hundreds-of-online-services

---

#### CVE-2022-24785 - GitHub Enterprise OAuth
**Severity**: Critical
**Affected**: GitHub Enterprise Server
**Vulnerability**: SSH key disclosure via OAuth flow
**Impact**: Unauthorized SSH access to repositories
**Fix**: Patched in GHES 3.1.19, 3.2.11, 3.3.6, 3.4.1
**Reference**: https://github.blog/2022-04-12-git-security-vulnerabilities-announced/

---

#### CVE-2021-22573 - Google OAuth
**Severity**: High
**Affected**: Google OAuth service
**Vulnerability**: OAuth token theft via open redirect
**Impact**: Account takeover potential
**Fix**: Strengthened redirect_uri validation
**Reference**: https://bugs.chromium.org/p/project-zero/issues/detail?id=2229

---

#### CVE-2020-7741 - node-oauth2-server
**Severity**: High (CVSS 7.5)
**Affected**: node-oauth2-server through version 3.1.1
**Vulnerability**: XSS via redirect_uri parameter
**Impact**: Malicious JavaScript execution
**Fix**: Upgrade to version 3.1.2+
**Reference**: https://www.cvedetails.com/cve/CVE-2020-7741/

---

#### CVE-2020-7692 - node-oauth2-server
**Severity**: Critical (CVSS 9.8)
**Affected**: node-oauth2-server through version 3.1.1
**Vulnerability**: Authorization code injection (no PKCE)
**Impact**: Account takeover
**Fix**: Upgrade to version 3.1.2+, implement PKCE
**Reference**: https://www.cvedetails.com/cve/CVE-2020-7692/

---

#### CVE-2019-11510 - Pulse Secure VPN
**Severity**: Critical (CVSS 10.0)
**Affected**: Pulse Secure VPN
**Vulnerability**: Pre-authentication OAuth bypass
**Impact**: Complete system compromise, credential theft
**Fix**: Emergency patches released
**Real-World**: Exploited in widespread attacks, ransomware campaigns
**Reference**: https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101/

---

#### CVE-2019-9074 - GitLab OAuth
**Severity**: Critical
**Affected**: GitLab CE/EE
**Vulnerability**: Race condition in OAuth account linking
**Impact**: Account takeover
**Fix**: Patched in GitLab 11.8.1
**Reference**: https://about.gitlab.com/releases/2019/03/04/security-release-gitlab-11-dot-8-dot-1-released/

---

### OAuth 2.0 Threat Model
**IETF Document**: https://tools.ietf.org/html/rfc6819

**Documented Threats**:
1. **Client Impersonation**: CVE examples with client secret theft
2. **Authorization Code Interception**: Open redirect chains
3. **Access Token Disclosure**: Referer leakage, logs, analytics
4. **Phishing Attacks**: Fake authorization pages
5. **CSRF**: Missing state parameter vulnerabilities

---

## Tools & Frameworks

### Testing Tools

#### Burp Suite Professional
**URL**: https://portswigger.net/burp
**Features**:
- OAuth flow analysis
- Automatic parameter detection
- Collaborator for SSRF testing
- Repeater for manual testing
- Intruder for fuzzing
- Extensions marketplace

**OAuth-Specific Extensions**:
- **OAuth Scanner**: Automated OAuth vulnerability detection
- **AuthMatrix**: Authorization testing matrix
- **Autorize**: Access control testing
- **JWT Editor**: JWT manipulation and validation

**Usage**:
```
1. Proxy → Intercept OAuth flows
2. Repeater → Test redirect_uri validation
3. Intruder → Fuzz parameters
4. Collaborator → Detect SSRF
5. Scanner → Automated vulnerability detection
```

---

#### OWASP ZAP (Zed Attack Proxy)
**URL**: https://www.zaproxy.org/
**Features**:
- Free and open source
- Automated scanning
- Manual testing tools
- Fuzzing capabilities
- OAuth/JWT add-ons

**OAuth Testing Add-ons**:
- **JWT Support**: JWT parsing and manipulation
- **Access Control Testing**: Authorization testing
- **Authentication Helper**: OAuth flow automation

---

#### OAuth.tools
**URL**: https://oauth.tools/
**Features**:
- OAuth flow simulator
- Token decoder
- Request builder
- Response analyzer
- Educational tool for learning OAuth

**Use Cases**:
- Test OAuth implementations
- Debug authorization flows
- Validate tokens
- Learn OAuth mechanics

---

#### JWT.io
**URL**: https://jwt.io/
**Features**:
- JWT decoder
- Signature verification
- Algorithm tester
- Library documentation
- Online debugging

**Testing Capabilities**:
- Decode ID tokens
- Verify signatures
- Test algorithm confusion
- Validate claims

---

#### OAuth 2.0 Playground
**URL**: https://www.oauth.com/playground/
**Features**:
- Interactive OAuth flows
- Authorization code flow
- PKCE implementation
- Client credentials flow
- Token refresh testing

---

### Development Libraries

#### Authlib (Python)
**URL**: https://authlib.org/
**Features**:
- OAuth 1.0 and 2.0
- OpenID Connect
- JWT support
- Flask/Django integration
- PKCE implementation

**Example**:
```python
from authlib.integrations.flask_client import OAuth

oauth = OAuth(app)
oauth.register(
    'example',
    client_id='CLIENT_ID',
    client_secret='CLIENT_SECRET',
    authorize_url='https://oauth.example.com/auth',
    access_token_url='https://oauth.example.com/token',
    client_kwargs={'scope': 'openid profile email'},
)
```

---

#### Passport.js (Node.js)
**URL**: http://www.passportjs.org/
**Features**:
- 500+ authentication strategies
- OAuth 1.0/2.0 support
- OpenID Connect
- Express integration
- Extensive middleware

**Example**:
```javascript
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');

passport.use(new OAuth2Strategy({
    authorizationURL: 'https://oauth.example.com/auth',
    tokenURL: 'https://oauth.example.com/token',
    clientID: 'CLIENT_ID',
    clientSecret: 'CLIENT_SECRET',
    callbackURL: 'https://app.com/callback'
  },
  function(accessToken, refreshToken, profile, cb) {
    // Verify user
  }
));
```

---

#### Spring Security OAuth (Java)
**URL**: https://spring.io/projects/spring-security-oauth
**Features**:
- Spring Boot integration
- OAuth 2.0 client and resource server
- JWT support
- Authorization server
- Extensive configuration options

---

#### django-oauth-toolkit (Python/Django)
**URL**: https://django-oauth-toolkit.readthedocs.io/
**Features**:
- OAuth 2.0 provider
- OAuth 2.0 consumer
- Django REST framework integration
- Token management
- Scope-based permissions

---

### Security Testing Tools

#### BurpSuite Extensions for OAuth

**JWT Editor**
- Decode and modify JWTs
- Algorithm confusion testing
- Signature verification bypass
- Claims manipulation

**OAuth Scanner**
- Automated OAuth vulnerability detection
- redirect_uri validation testing
- State parameter checks
- Scope validation

**AuthMatrix**
- Cross-user authorization testing
- Permission matrix builder
- Role-based testing
- Horizontal/vertical privilege escalation

---

#### Custom Scripts

**Python OAuth Tester**:
```python
import requests
from urllib.parse import urlencode, parse_qs, urlparse

class OAuthTester:
    def __init__(self, base_url, client_id):
        self.base_url = base_url
        self.client_id = client_id

    def test_redirect_uri(self, malicious_uri):
        """Test redirect_uri validation"""
        params = {
            'client_id': self.client_id,
            'redirect_uri': malicious_uri,
            'response_type': 'code',
            'scope': 'openid profile email'
        }

        response = requests.get(
            f'{self.base_url}/auth',
            params=params,
            allow_redirects=False
        )

        if response.status_code == 302:
            location = response.headers.get('Location', '')
            if malicious_uri in location:
                return True, f"redirect_uri accepted: {malicious_uri}"

        return False, f"redirect_uri rejected: {malicious_uri}"

    def test_state_parameter(self):
        """Test for missing state parameter"""
        params = {
            'client_id': self.client_id,
            'redirect_uri': 'https://app.com/callback',
            'response_type': 'code',
            'scope': 'openid profile email'
            # Intentionally omit state parameter
        }

        response = requests.get(
            f'{self.base_url}/auth',
            params=params,
            allow_redirects=False
        )

        # If request succeeds without state, it's vulnerable
        return response.status_code == 302

# Usage
tester = OAuthTester('https://oauth.example.com', 'CLIENT_ID')

# Test redirect_uri bypasses
bypasses = [
    'https://attacker.com',
    'https://app.com.attacker.com',
    'https://app.com/callback/../evil',
]

for bypass in bypasses:
    result, message = tester.test_redirect_uri(bypass)
    print(f"[{'VULN' if result else 'SAFE'}] {message}")

# Test state parameter
if tester.test_state_parameter():
    print("[VULN] State parameter not required - CSRF vulnerable")
else:
    print("[SAFE] State parameter required")
```

---

## Research Papers & Technical Articles

### Academic Research

#### "A Comprehensive Formal Security Analysis of OAuth 2.0" (2016)
**Authors**: Daniel Fett, Ralf Küsters, Guido Schmitz
**Conference**: ACM CCS 2016
**URL**: https://dl.acm.org/doi/10.1145/2976749.2978385

**Key Findings**:
- Formal model of OAuth 2.0 in expressive web model
- Four new attacks discovered affecting OAuth and OpenID Connect
- Attacks exploitable in practice on major providers
- Importance of HTTPS and redirect_uri validation
- Scope validation vulnerabilities

**Impact**: Influenced OAuth 2.1 security improvements

---

#### "OAuth Demystified for Mobile Application Developers" (2014)
**Authors**: Eric Chen, Yutong Pei, Shuo Chen, Yuan Tian, Robert Kotcher, Patrick Tague
**Conference**: ACM CCS 2014
**URL**: https://dl.acm.org/doi/10.1145/2660267.2660323

**Focus**: Mobile OAuth vulnerabilities
**Findings**:
- Implicit flow insecure for mobile apps
- Custom URI schemes vulnerable to interception
- Authorization code theft via malicious apps
- Recommendations for mobile OAuth implementation

---

#### "Enhanced Threat Modeling and Attack Scenario Generation for OAuth 2.0" (2025)
**Authors**: Various
**Conference**: ACM CODASPY 2025
**URL**: https://dl.acm.org/doi/10.1145/3714393.3726005

**Contributions**:
- Enhanced threat modeling for OAuth implementations
- Automated attack scenario generation
- Tool: OAuch benchmark improvements
- Comprehensive vulnerability classification

---

### Industry Research

#### "Hidden OAuth Attack Vectors" - PortSwigger Research
**Author**: James Kettle
**URL**: https://portswigger.net/research/hidden-oauth-attack-vectors

**Topics**:
- Novel OAuth exploitation techniques
- redirect_uri validation bypasses
- Pre-account takeover attacks
- Practical attack demonstrations

---

#### "The Most Common OAuth 2.0 Hacks" - OAuth.com
**URL**: https://www.oauth.com/oauth2-servers/oauth-2-0-hacks/

**Coverage**:
- Authorization code interception
- CSRF attacks
- Token theft
- Client impersonation
- Real-world examples

---

### Technical Blog Posts

#### "Top 10 OAuth 2.0 Hacking Techniques" - Medium
**Author**: Itamar Yochpaz
**URL**: https://medium.com/@itamar.yochpaz/top-10-oauth-2-0-hacking-techniques-part-2-a45504ee373b

**Techniques Covered**:
1. Authorization code interception
2. redirect_uri manipulation
3. State parameter bypass
4. Scope escalation
5. Pre-account takeover
6. Client impersonation
7. Token leakage
8. Open redirect chains
9. SSRF via client registration
10. Implicit flow exploits

---

#### "Attacking and Defending OAuth 2.0" - Praetorian
**URL**: https://www.praetorian.com/blog/attacking-and-defending-oauth-2-0-part-1/

**Two-Part Series**:
- Part 1: OAuth fundamentals, threats, best practices
- Part 2: Advanced attacks, real-world case studies

---

#### "Common OAuth Vulnerabilities" - Doyensec Blog (2025)
**URL**: https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html

**Recent Coverage**:
- Latest OAuth attack patterns
- Real-world vulnerability analysis
- Comprehensive attack/defense cheat sheet
- Developer-focused recommendations

---

#### "OAuth 2.0 Security and Vulnerabilities" - IBM PTC Security
**URL**: https://medium.com/@ibm_ptc_security/oauth-2-0-security-and-vulnerabilities-86e64c22b03d

**Enterprise Focus**:
- Enterprise OAuth deployment
- Security architecture
- Threat modeling
- Incident response

---

## Secure Coding Practices

### redirect_uri Validation

**Vulnerable Code (Python)**:
```python
# ❌ BAD - Prefix matching
if redirect_uri.startswith('https://app.com'):
    return True
# Vulnerable to: https://app.com.attacker.com
```

**Secure Code (Python)**:
```python
# ✅ GOOD - Exact matching
ALLOWED_REDIRECTS = {
    'https://app.com/oauth-callback',
    'https://app.com/oauth-callback/',
}

from urllib.parse import urlparse

def validate_redirect_uri(redirect_uri):
    # Parse and normalize
    parsed = urlparse(redirect_uri)

    # Reconstruct without query/fragment
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # Remove trailing slash for comparison
    normalized = normalized.rstrip('/')

    # Exact match against whitelist
    return normalized in [r.rstrip('/') for r in ALLOWED_REDIRECTS]
```

---

### State Parameter Implementation

**Vulnerable Code (JavaScript)**:
```javascript
// ❌ BAD - Predictable state
const state = '12345';
sessionStorage.setItem('oauth_state', state);
```

**Secure Code (JavaScript)**:
```javascript
// ✅ GOOD - Cryptographically random state
function generateState() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode.apply(null, array))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

const state = generateState();
sessionStorage.setItem('oauth_state', state);

// Validation
const receivedState = new URLSearchParams(window.location.search).get('state');
const expectedState = sessionStorage.getItem('oauth_state');

if (receivedState !== expectedState) {
    throw new Error('State mismatch - CSRF attempt detected');
}

sessionStorage.removeItem('oauth_state'); // One-time use
```

---

### PKCE Implementation

**Secure Code (Python)**:
```python
import secrets
import hashlib
import base64

def generate_pkce():
    # Generate code_verifier (43-128 characters)
    code_verifier = base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).decode('utf-8').rstrip('=')

    # Generate code_challenge (SHA256)
    challenge_bytes = hashlib.sha256(
        code_verifier.encode('utf-8')
    ).digest()

    code_challenge = base64.urlsafe_b64encode(
        challenge_bytes
    ).decode('utf-8').rstrip('=')

    return code_verifier, code_challenge

# Store verifier securely
verifier, challenge = generate_pkce()
session['code_verifier'] = verifier

# Authorization URL includes challenge
auth_url = (
    f"https://oauth.com/auth?"
    f"client_id={CLIENT_ID}&"
    f"redirect_uri={REDIRECT_URI}&"
    f"response_type=code&"
    f"code_challenge={challenge}&"
    f"code_challenge_method=S256"
)

# Token exchange includes verifier
token_data = {
    'grant_type': 'authorization_code',
    'code': authorization_code,
    'redirect_uri': REDIRECT_URI,
    'client_id': CLIENT_ID,
    'code_verifier': session.pop('code_verifier')
}
```

---

### Token Validation

**Vulnerable Code (Node.js)**:
```javascript
// ❌ BAD - Trust client-supplied data
app.post('/authenticate', (req, res) => {
    const { email, token } = req.body;
    // No validation - trust email from client
    const user = getUserByEmail(email);
    req.session.userId = user.id;
});
```

**Secure Code (Node.js)**:
```javascript
// ✅ GOOD - Validate token with OAuth provider
app.post('/authenticate', async (req, res) => {
    const { email, token } = req.body;

    // Validate token with OAuth provider
    const response = await fetch('https://oauth.com/userinfo', {
        headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!response.ok) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    const userInfo = await response.json();

    // Verify email matches token
    if (userInfo.email !== email) {
        return res.status(403).json({ error: 'Email mismatch' });
    }

    // Check email verification
    if (!userInfo.email_verified) {
        return res.status(403).json({ error: 'Email not verified' });
    }

    // Create session
    const user = await getOrCreateUser(userInfo.sub, userInfo.email);
    req.session.userId = user.id;

    res.json({ success: true });
});
```

---

### SSRF Prevention

**Vulnerable Code (Java)**:
```java
// ❌ BAD - No validation
@PostMapping("/reg")
public ClientRegistration register(@RequestBody ClientRegistration reg) {
    String logoUri = reg.getLogoUri();
    byte[] logo = fetchUrl(logoUri); // No validation!
    return saveClient(reg, logo);
}
```

**Secure Code (Java)**:
```java
// ✅ GOOD - Comprehensive validation
@PostMapping("/reg")
public ClientRegistration register(@RequestBody ClientRegistration reg) {
    String logoUri = reg.getLogoUri();

    // Validate URL
    validateLogoUri(logoUri);

    // Fetch with restrictions
    byte[] logo = fetchLogoSecurely(logoUri);

    return saveClient(reg, logo);
}

private void validateLogoUri(String uri) throws ValidationException {
    try {
        URL url = new URL(uri);

        // Check scheme
        if (!"https".equals(url.getProtocol())) {
            throw new ValidationException("Only HTTPS allowed");
        }

        // Resolve hostname to IP
        InetAddress address = InetAddress.getByName(url.getHost());

        // Check for private IPs
        if (address.isLoopbackAddress() ||
            address.isLinkLocalAddress() ||
            address.isSiteLocalAddress()) {
            throw new ValidationException("Private IP not allowed");
        }

        // Check for AWS metadata
        if ("169.254.169.254".equals(address.getHostAddress())) {
            throw new ValidationException("AWS metadata access denied");
        }

    } catch (MalformedURLException | UnknownHostException e) {
        throw new ValidationException("Invalid URL", e);
    }
}

private byte[] fetchLogoSecurely(String uri) {
    RequestConfig config = RequestConfig.custom()
        .setConnectTimeout(5000)
        .setConnectionRequestTimeout(5000)
        .setSocketTimeout(5000)
        .setRedirectsEnabled(false)
        .build();

    HttpGet request = new HttpGet(uri);
    request.setConfig(config);

    try (CloseableHttpResponse response = httpClient.execute(request)) {
        // Validate content type
        String contentType = response.getEntity().getContentType().getValue();
        if (!contentType.startsWith("image/")) {
            throw new ValidationException("Invalid content type");
        }

        // Limit size
        byte[] content = EntityUtils.toByteArray(response.getEntity());
        if (content.length > 5 * 1024 * 1024) { // 5MB
            throw new ValidationException("Image too large");
        }

        return content;
    }
}
```

---

## Training Platforms

### PortSwigger Web Security Academy
**URL**: https://portswigger.net/web-security

**OAuth Labs**:
- Authentication bypass via OAuth implicit flow
- Forced OAuth profile linking
- OAuth account hijacking via redirect_uri
- Stealing OAuth access tokens via a proxy page
- Stealing OAuth access tokens via an open redirect
- SSRF via OpenID dynamic client registration

**Features**:
- Free interactive labs
- Step-by-step solutions
- Video walkthroughs
- Certification: Burp Suite Certified Practitioner

---

### PentesterLab
**URL**: https://pentesterlab.com/

**OAuth Exercises**:
- OAuth Fundamentals
- OAuth Bypass Techniques
- OpenID Connect Security
- Token Manipulation

**Subscription**: $20/month (Pro)

---

### HackTheBox
**URL**: https://www.hackthebox.com/

**OAuth Challenges**:
- Web challenges with OAuth
- Real-world scenarios
- CTF competitions
- Pro Labs with OAuth targets

---

### TryHackMe
**URL**: https://tryhackme.com/

**OAuth Rooms**:
- OAuth 2.0 Security
- Authentication Bypass
- Web Application Security

**Format**: Guided learning paths

---

### OWASP WebGoat
**URL**: https://owasp.org/www-project-webgoat/

**OAuth Module**:
- Interactive lessons
- Hands-on exercises
- Vulnerability exploitation
- Remediation guidance

**Free**: Self-hosted

---

## Bug Bounty Programs

### Programs with OAuth Scope

#### HackerOne
**URL**: https://hackerone.com/

**Notable Programs**:
- Facebook OAuth
- GitHub OAuth
- Dropbox Authentication
- Shopify OAuth

**OAuth Bounty Range**: $500 - $40,000+

**Example Reports**:
- OAuth redirect_uri bypasses: $5,000 - $20,000
- Account takeover via OAuth: $10,000 - $40,000
- SSRF via client registration: $5,000 - $15,000

---

#### Bugcrowd
**URL**: https://www.bugcrowd.com/

**OAuth-Heavy Programs**:
- Atlassian (Jira, Confluence OAuth)
- Salesforce OAuth
- Zendesk Authentication

**Typical Payouts**:
- P1 (Critical): $3,000 - $10,000+
- P2 (High): $1,000 - $3,000
- P3 (Medium): $500 - $1,000

---

#### Synack
**URL**: https://www.synack.com/

**Private Programs**: Invite-only
**Focus**: Enterprise OAuth implementations
**Higher Payouts**: $10,000 - $50,000 for critical OAuth bugs

---

#### Intigriti
**URL**: https://www.intigriti.com/

**European Focus**: EU-based companies
**OAuth Targets**: SaaS providers, fintech
**Payouts**: €500 - €25,000

---

### OAuth Bug Bounty Tips

**High-Value Targets**:
1. **redirect_uri Validation Bypass**
   - Critical severity
   - Leads to account takeover
   - Test thoroughly

2. **State Parameter Missing (CSRF)**
   - Medium to High severity
   - Easy to find
   - Requires valid PoC

3. **SSRF via Client Registration**
   - Critical if cloud metadata accessible
   - High if internal network access
   - Demonstrate impact

4. **Authorization Code Theft**
   - Critical severity
   - Requires demonstrable exploit chain
   - Must show account takeover

5. **Token Leakage**
   - Severity depends on exposure vector
   - Implicit flow issues: Medium
   - Server log leakage: High

**Report Writing Tips**:
```
1. Clear Title
   - "OAuth redirect_uri Validation Bypass Leading to Account Takeover"

2. Impact Statement
   - Explain attack scenario
   - Show affected users
   - Demonstrate exploitability

3. Reproduction Steps
   - Detailed, numbered steps
   - Include all HTTP requests
   - Provide working PoC

4. Remediation
   - Specific fix recommendations
   - Reference OWASP/RFC standards
   - Code examples if applicable

5. Evidence
   - Screenshots
   - Video demonstration
   - HTTP request/response logs
```

---

## Conclusion

This comprehensive resource collection provides:

✅ **Authoritative Standards**: OWASP, IETF RFCs, OAuth 2.1
✅ **Real-World CVEs**: Historical vulnerabilities with impact analysis
✅ **Security Tools**: Burp Suite, OWASP ZAP, OAuth-specific extensions
✅ **Research Papers**: Academic and industry security research
✅ **Secure Coding**: Language-specific implementation examples
✅ **Training Platforms**: Hands-on learning environments
✅ **Bug Bounty Programs**: Monetize OAuth security skills

**Continuous Learning**:
- Follow OAuth working group updates
- Monitor CVE databases for new OAuth vulnerabilities
- Read bug bounty write-ups for novel techniques
- Practice on training platforms regularly
- Contribute to open-source OAuth libraries
- Participate in security conferences (Black Hat, DEF CON, OWASP)

**Stay Updated**:
- OAuth.net for specification updates
- PortSwigger Research blog
- OWASP Cheat Sheets (regularly updated)
- Security mailing lists (oss-security, full-disclosure)
- Twitter/X: Security researchers sharing OAuth findings

For complete lab walkthroughs, see `oauth-portswigger-labs-complete.md`. For quick exploitation techniques, see `oauth-quickstart.md`. For comprehensive testing methodology, see `oauth-cheat-sheet.md`.
