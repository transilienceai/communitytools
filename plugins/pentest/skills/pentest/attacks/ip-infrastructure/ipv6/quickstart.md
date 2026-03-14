# IPv6 Attacks

Exploiting IPv6 protocol features and implementation issues.

## Attack Types
- **Router Advertisement Flooding**
- **Neighbor Discovery Protocol Spoofing**
- **DHCPv6 Spoofing**
- **IPv6 Tunneling for Evasion**

## Tools
- THC-IPv6 toolkit, Scapy, Chiron, atear6, parasite6

## Quick Commands
```bash
# IPv6 alive detection
alive6 eth0

# Router Advertisement flooding
atear6 eth0

# Fake router advertisement
fake_router6 eth0 2001:db8::1/64

# IPv6 MitM
parasite6 eth0
```

## Methodology
1. Check IPv6 enablement
2. IPv6 neighbor discovery
3. Test RA flooding vulnerability
4. Attempt DHCPv6 spoofing
5. Test IPv6 tunneling
6. MitM via NDP spoofing

## Remediation
- Disable IPv6 if not needed
- IPv6 first-hop security
- RA Guard & DHCPv6 Guard
- IPv6 ACLs
- Monitor IPv6 traffic

**MITRE**: T1557 | **CWE**: CWE-300 | **RFC**: RFC 7113 | **CAPEC**: CAPEC-603
