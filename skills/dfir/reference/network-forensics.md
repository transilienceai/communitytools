# Network Forensics

## PCAP Analysis with tshark

### LLMNR Poisoning Detection

```bash
# Show LLMNR queries and responses — rogue device responds to multicast queries
tshark -r capture.pcap -Y "llmnr" -T fields -e ip.src -e ip.dst -e dns.qry.name -e dns.a

# Pattern: victim queries 224.0.0.252, rogue IP responds with its own address
# The queried name is typically a typo (e.g., "DCC01" instead of "DC01")
```

**Indicators**:
- LLMNR response from non-DC IP resolving to itself
- Victim then initiates SMB/NTLM to the rogue IP
- DHCP hostname of rogue device often reveals attacker OS (e.g., "kali")

```bash
# Find rogue machine hostname via DHCP
tshark -r capture.pcap -Y "dhcp.option.hostname" -T fields -e ip.src -e dhcp.option.hostname
```

### NTLM Authentication Extraction

```bash
# Extract all NTLM auth events (negotiate=1, challenge=2, authenticate=3)
tshark -r capture.pcap -Y "ntlmssp" -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e ntlmssp.messagetype \
  -e ntlmssp.auth.username -e ntlmssp.auth.domain \
  -e ntlmssp.ntlmserverchallenge \
  -e ntlmssp.ntlmv2_response.ntproofstr

# Note: NTLM may travel over IPv6 — check ipv6.src/ipv6.dst if ip fields are empty
tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000001" -T fields \
  -e ipv6.src -e ipv6.dst -e eth.src -e eth.dst
```

### NTLMv2 Hash Construction for Cracking

Extract from the **first** NTLM exchange (Type 2 challenge + Type 3 authenticate):

```bash
# 1. Get server challenge (from Type 2 message)
CHALLENGE=$(tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000002" -T fields \
  -e ntlmssp.ntlmserverchallenge -c 1)

# 2. Get username, domain, full NTLMv2 response, NTProofStr (from Type 3 message)
tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000003" -T fields \
  -e ntlmssp.auth.username -e ntlmssp.auth.domain \
  -e ntlmssp.ntlmv2_response -e ntlmssp.ntlmv2_response.ntproofstr -c 1
```

**Hash format** (hashcat mode 5600):
```
username::domain:server_challenge:NTProofStr:blob_after_NTProofStr
```

Where `blob_after_NTProofStr` = full NTLMv2 response with first 32 hex chars (NTProofStr) removed:
```bash
FULL_RESPONSE="<ntlmv2_response hex>"
NTPROOFSTR="${FULL_RESPONSE:0:32}"
BLOB="${FULL_RESPONSE:32}"
echo "${USERNAME}::${DOMAIN}:${CHALLENGE}:${NTPROOFSTR}:${BLOB}" > hash.txt
hashcat -m 5600 hash.txt /path/to/wordlist
```

### NTLM Relay Detection

**Pattern**: Three-party NTLM exchange across IPs:
1. Victim (A) → Attacker (B): NTLM Negotiate + Authenticate
2. Attacker (B) → Target (C): Relayed NTLM Negotiate + Authenticate
3. Target (C) → Attacker (B): NTLM Challenge (forwarded back to victim)

```bash
# Identify relay by checking NTLM auth destinations
tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000003" -T fields \
  -e frame.time -e ip.src -e ip.dst -e ntlmssp.auth.username

# Check SMB tree connects to see relay target shares
tshark -r capture.pcap -Y "smb2.cmd == 3" -T fields \
  -e frame.time -e ip.src -e ip.dst -e smb2.tree
```

**Key indicator**: Same username authenticating to attacker IP AND from attacker IP to a different target within milliseconds.

### SMB Share Access

```bash
# All SMB2 tree connect requests (share access)
tshark -r capture.pcap -Y "smb2.cmd == 3 && ip.src == <victim_ip>" -T fields \
  -e frame.time -e ip.dst -e smb2.tree
```

## Timestamp Handling

**pcap timestamps** include timezone offset (e.g., `+0200`). Always convert to UTC:
- `13:18:30+0200` → `11:18:30 UTC`
- Check `frame.time_epoch` for unambiguous UTC timestamps

**EVTX timestamps** are already UTC (`SystemTime` attribute).
