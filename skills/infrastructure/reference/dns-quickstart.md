# DNS Attacks

Exploiting DNS infrastructure for information gathering and manipulation.

## Techniques
- **Zone Transfers**: AXFR requests to extract DNS records
- **Cache Poisoning**: Injecting forged DNS responses
- **Subdomain Takeover**: Claiming abandoned DNS entries
- **DNS Rebinding**: Bypassing same-origin policy via DNS

## Tools
- dig, nslookup, host, dnsrecon, dnsenum, fierce

## Quick Commands
```bash
# Zone transfer
dig axfr @ns.target.com target.com

# DNS enumeration
dnsrecon -d target.com -t std
dnsenum target.com

# Subdomain brute force
fierce --domain target.com --wordlist subdomains.txt
```

## Methodology
1. Enumerate DNS records (A, AAAA, MX, NS, TXT, CNAME)
2. Attempt zone transfers on all nameservers
3. Test for DNS cache poisoning
4. Check for subdomain takeover candidates
5. Document all discovered records

**MITRE**: T1071.004 | **CWE**: CWE-350 | **CAPEC**: CAPEC-142
