# Port Scanning

Network service discovery and enumeration.

## Techniques
- **SYN Scan**: Half-open scanning (fast, stealthy)
- **TCP Connect**: Full connection scan
- **UDP Scan**: UDP service discovery
- **Service Detection**: Banner grabbing and version identification

## Tools
- nmap, masscan, Rustscan, unicornscan

## Quick Commands
```bash
# Quick SYN scan
nmap -sS -T4 target

# Full port scan with version detection
nmap -sS -sV -p- -T4 target

# Fast scan with masscan
masscan target -p0-65535 --rate=1000

# Service enumeration
nmap -sC -sV -p 80,443,22,21 target
```

## Reporting Semantics

Be precise in reports:

- Use `confirmed open` only when the scanner observed a listener (`syn-ack`, completed TCP connect, or service data).
- For unlisted TCP ports, say `no TCP listener accepted a connection during the scan window` instead of `closed`, unless the tool specifically returned a closed/RST state and that distinction matters.
- Treat `filtered`, `dropped`, timeouts, geofencing, source allowlists, and temporary outages as separate from "closed".
- State whether the scan was SYN (`-sS`) or TCP connect (`-sT`); non-root runners often fall back to `-sT`.
- State UDP coverage separately. If UDP was not run because root privileges were unavailable, say so.
- If a `standard` profile overlaps with a later full/high-port pass, distinguish unique coverage from total attempts.

Example wording:

```text
Every TCP port 1-65535 was attempted for each supplied IP. Ports not listed as open did not accept a TCP connection from the scanner during the test window. This does not prove the ports are permanently closed; filtered, source-restricted, or temporarily unavailable services can appear the same externally. UDP was not assessed from this runner.
```

For NETWORK-mode reports, also include an open-service matrix, no-response watchlist, DNS reconciliation, tool limitations, and safe remediation verification commands. See `../../pentest-engagement/reference/network-exposure-reporting.md`.

## Methodology
1. Host discovery (ping sweep, ARP scan)
2. Port scanning (top 1000, then full)
3. Service and version detection
4. OS fingerprinting
5. Script scanning for known vulnerabilities

See also: `syn-scan.md`, `udp-scan.md`, `service-enum.md`, `os-fingerprint.md`, `firewall-detection.md`

**MITRE**: T1046 | **CWE**: N/A | **CAPEC**: CAPEC-300
