# DFIR Reference Index

Top-level docs:

- [dfir-principles.md](dfir-principles.md) — decision tree, correlation keys, output discipline
- [windows-event-analysis.md](windows-event-analysis.md) — EVTX parsing patterns, AD attack event IDs, NTDS dump tells
- [network-forensics.md](network-forensics.md) — PCAP NTLM/LLMNR/relay extraction, NTLMv2 hash construction
- [filesystem-forensics.md](filesystem-forensics.md) — MFT, Prefetch (legacy), VSS, Linux persistence
- [c2-traffic-decryption.md](c2-traffic-decryption.md) — Covenant/SharPyShell/Empire/tsh/NimPlant key recovery

## Scenarios

### PCAP — `scenarios/pcap/`
- [tcp-stream-extraction.md](scenarios/pcap/tcp-stream-extraction.md) — Wireshark Follow Stream / tshark / scapy
- [tls-decryption.md](scenarios/pcap/tls-decryption.md) — `SSLKEYLOGFILE`, server RSA key
- [http-objects-export.md](scenarios/pcap/http-objects-export.md) — `--export-objects http,DIR`
- [dns-tunneling-detection.md](scenarios/pcap/dns-tunneling-detection.md) — iodine/dnscat2/DET fingerprints
- [c2-traffic-decryption.md](scenarios/pcap/c2-traffic-decryption.md) — framework-specific decryption (mirrors top-level)
- [credential-extraction.md](scenarios/pcap/credential-extraction.md) — basic-auth, FTP, telnet, SMTP, NTLMv2 hash

### Memory — `scenarios/memory/`
- [volatility-process-analysis.md](scenarios/memory/volatility-process-analysis.md) — pslist, psscan, pstree, cmdline, dlllist
- [memory-credential-extraction.md](scenarios/memory/memory-credential-extraction.md) — pypykatz / mimikatz / Volatility hashdump
- [injected-code-detection.md](scenarios/memory/injected-code-detection.md) — malfind, hollowing, reflective DLLs
- [network-artifacts-from-mem.md](scenarios/memory/network-artifacts-from-mem.md) — netscan, sockets, DNS cache

### Filesystem — `scenarios/filesystem/`
- [timeline-creation.md](scenarios/filesystem/timeline-creation.md) — plaso/log2timeline super-timeline
- [ntfs-mft-analysis.md](scenarios/filesystem/ntfs-mft-analysis.md) — analyzeMFT / MFTECmd, $SI vs $FN
- [prefetch-analysis.md](scenarios/filesystem/prefetch-analysis.md) — Win10 MAM, run count, file refs
- [shellbags-userassist.md](scenarios/filesystem/shellbags-userassist.md) — folder browse + GUI execution
- [lnk-file-analysis.md](scenarios/filesystem/lnk-file-analysis.md) — phishing LNKs, USB tracking, machine attribution

### Log analysis — `scenarios/log-analysis/`
- [windows-event-logs.md](scenarios/log-analysis/windows-event-logs.md) — 4624/4625/4688/4720/4768 patterns
- [sysmon-rules.md](scenarios/log-analysis/sysmon-rules.md) — EIDs 1/3/7/10/11/22, LOLBIN hunting
- [linux-auth-logs.md](scenarios/log-analysis/linux-auth-logs.md) — sshd, sudo, auditd
- [webserver-logs.md](scenarios/log-analysis/webserver-logs.md) — Apache/nginx, webshell + SQLi patterns
- [splunk-spl-queries.md](scenarios/log-analysis/splunk-spl-queries.md) — common SPL detections

### AD attack detection — `scenarios/ad-attack-detection/`
- [kerberos-roast-detection.md](scenarios/ad-attack-detection/kerberos-roast-detection.md) — 4769 RC4, 4768 PreAuth=0
- [dcsync-detection.md](scenarios/ad-attack-detection/dcsync-detection.md) — 4662 replication GUIDs
- [golden-ticket-detection.md](scenarios/ad-attack-detection/golden-ticket-detection.md) — TGS without AS-REQ, lifetime
- [lateral-movement-indicators.md](scenarios/ad-attack-detection/lateral-movement-indicators.md) — 4624/7045/5145/Sysmon

## Selection cheat sheet

- Memory + Windows AD → `volatility-process-analysis` + `memory-credential-extraction` + `windows-event-logs` + `kerberos-roast-detection`
- PCAP-only → `tcp-stream-extraction` → choose by protocol
- Disk image → `timeline-creation` first, then specific filesystem scenarios
- SIEM access → `splunk-spl-queries` plus the AD-attack-detection set
