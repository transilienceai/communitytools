# DFIR — Digital Forensics & Incident Response

Investigate security incidents by analyzing Windows event logs, network captures, and filesystem artifacts. Focused on Active Directory attack detection and timeline reconstruction.

## Capabilities

- **Windows Event Log Analysis** — Parse EVTX files for Kerberoasting, AS-REP roasting, NTDS dump, NTLM relay, and lateral movement
- **Network Forensics** — PCAP analysis for LLMNR poisoning, NTLM credential extraction, relay detection, NTLMv2 hash cracking
- **Filesystem Forensics** — MFT parsing for file creation/paths, Prefetch for execution times, VSS artifact recovery
- **Timeline Correlation** — Cross-source event correlation using timestamps, LogonIDs, PIDs, and IP addresses

## Prerequisites

```bash
pip install python-evtx analyzeMFT
brew install wireshark p7zip hashcat
# Optional: pip install dissect.util (for Win10 prefetch decompression on macOS)
```

## Usage

Triggered automatically when investigating security incidents or analyzing forensic evidence (Sherlocks, CTF challenges, IR engagements).

## Reference Files

| File | Content |
|------|---------|
| `reference/windows-event-analysis.md` | EVTX parsing, AD attack Event ID patterns |
| `reference/network-forensics.md` | tshark filters, NTLM extraction, hash construction |
| `reference/filesystem-forensics.md` | MFT parsing, Prefetch analysis, VSS artifacts |
