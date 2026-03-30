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
# Enumerate shares
smbclient -L //target -N
enum4linux -a target

# Null session
rpcclient -U "" -N target

# CrackMapExec
crackmapexec smb target -u '' -p '' --shares

# NTLM relay
ntlmrelayx.py -t target -smb2support
```

## Methodology
1. Discover SMB/NetBIOS services (ports 139, 445)
2. Test null session access
3. Enumerate users, groups, shares
4. Check for relay opportunities
5. Test for known SMB vulnerabilities

**MITRE**: T1021.002 | **CWE**: CWE-287 | **CAPEC**: CAPEC-555
