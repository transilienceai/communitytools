# Network Sniffing

Capturing and analyzing network traffic to extract sensitive information.

## Capture Targets
- Credentials (plaintext protocols)
- Session tokens
- Sensitive data
- Network topology
- Traffic patterns

## Tools
- Wireshark, tcpdump, tshark, Ettercap, NetworkMiner

## Quick Commands
```bash
# tcpdump basic
tcpdump -i eth0 -w capture.pcap
tcpdump -i eth0 'port 80 or port 443'
tcpdump -i eth0 -A 'tcp port 21'  # FTP

# tshark
tshark -i eth0 -f "tcp port 80" -Y "http.request"
tshark -r capture.pcap -Y "http.request.method == POST"

# Extract HTTP credentials
tshark -r capture.pcap -Y "http.authbasic" -T fields -e http.authbasic
```

## Methodology
1. Promiscuous mode
2. Capture network traffic
3. Filter protocols (HTTP, FTP, Telnet)
4. Extract credentials & sensitive data
5. Reconstruct sessions
6. Analyze patterns

## Remediation
- Use encrypted protocols (HTTPS, SSH, SFTP, VPN)
- Network segmentation
- Switched networks (not hubs)
- Port security
- Monitor for promiscuous interfaces

**MITRE**: T1040 | **CWE**: CWE-319 | **CAPEC**: CAPEC-158
