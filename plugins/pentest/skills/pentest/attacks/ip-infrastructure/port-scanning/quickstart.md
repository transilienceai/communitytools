# Port Scanning & Enumeration

Systematically probing targets to identify open ports, services, and vulnerabilities.

## Scan Types
- **TCP SYN**: Stealth half-open (`-sS`)
- **TCP Connect**: Full handshake (`-sT`)
- **UDP**: Connectionless (`-sU`)
- **FIN/NULL/Xmas**: Firewall evasion
- **ACK**: Firewall rule detection

## Tools
- Nmap, Masscan, RustScan, Zmap

## Quick Commands
```bash
# Fast comprehensive scan
nmap -sS -sV -sC -oA results target.com
nmap -p- --min-rate 10000 target.com

# UDP top ports
nmap -sU --top-ports 100 target.com

# Masscan (fast full range)
masscan -p1-65535 --rate=10000 10.0.0.0/8

# Service/OS detection
nmap -sV --version-intensity 9 target.com
nmap -O target.com

# Vulnerability scanning
nmap --script vuln target.com
```

## Methodology
1. Initial reconnaissance
2. Port scan target ranges
3. Service version detection
4. OS fingerprinting
5. NSE script scanning
6. Banner grabbing

## Detection/Remediation
- Minimize exposed services
- Use firewall rules & rate limiting
- Deploy IDS/IPS
- Port knocking for sensitive services

**MITRE**: T1046 | **CAPEC**: CAPEC-300
