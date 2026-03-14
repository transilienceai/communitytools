# Denial of Service (DoS/DDoS)

Overwhelming systems or networks to disrupt service availability.

**CRITICAL**: Only perform in authorized testing environments with explicit permission.

## Attack Types
- **SYN Flood**: TCP half-open connections
- **UDP Flood**: High volume UDP packets
- **HTTP Flood**: Application layer DoS
- **Amplification**: DNS, NTP, SSDP reflection
- **Slowloris**: Slow HTTP attacks

## Tools
- hping3, Slowloris, GoldenEye

## Quick Commands
```bash
# SYN flood (hping3)
hping3 -S -p 80 --flood target.com

# Slowloris
slowloris -s 500 target.com

# Note: Only use in authorized testing environments
```

## Methodology
1. Baseline normal traffic patterns
2. Perform controlled stress testing
3. Test rate limiting mechanisms
4. Verify DDoS mitigation services
5. Document impact thresholds

## Remediation
- Implement rate limiting
- Use DDoS mitigation services (Cloudflare, Akamai)
- Deploy load balancers
- SYN cookies
- CDN services
- Configure proper timeouts & connection limits

**MITRE**: T1498 | **CWE**: CWE-400 | **CAPEC**: CAPEC-125, CAPEC-488
